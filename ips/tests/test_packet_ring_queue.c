/**
 * @file test_packet_ring_queue.c
 * @brief packet ring queue 동작 단위 테스트
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "packet_ring.h"

#define CHECK(cond, msg)                          \
    do {                                          \
        if (!(cond)) {                            \
            fprintf(stderr, "FAIL: %s\n", (msg)); \
            return 1;                             \
        }                                         \
    } while (0)

typedef struct delayed_deq_arg {
    packet_ring_t *ring;
    int            rc;
    uint8_t        out[8];
    uint32_t       out_len;
    uint64_t       out_ts_ns;
} delayed_deq_arg_t;

static uint64_t now_ns(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static void *delayed_deq_thread(void *arg) {
    delayed_deq_arg_t *ctx = (delayed_deq_arg_t *)arg;

    usleep(20000);
    ctx->rc = packet_ring_deq(ctx->ring, ctx->out, sizeof(ctx->out),
                              &ctx->out_len, &ctx->out_ts_ns);
    return NULL;
}

static int test_drop_full_counts_real_drop_only(void) {
    packet_ring_t ring;
    const uint8_t pkt_a[] = {0x01};
    const uint8_t pkt_b[] = {0x02};
    const uint8_t pkt_c[] = {0x03};

    CHECK(packet_ring_init(&ring, 2, 0) == 0, "packet_ring_init failed");

    CHECK(packet_ring_enq(&ring, pkt_a, sizeof(pkt_a), 1) == 0,
          "first enqueue failed");
    CHECK(packet_ring_enq(&ring, pkt_b, sizeof(pkt_b), 2) == 0,
          "second enqueue failed");
    CHECK(packet_ring_enq(&ring, pkt_c, sizeof(pkt_c), 3) == EAGAIN,
          "full nonblocking enqueue should return EAGAIN");
    CHECK(ring.stats.drop_full == 1, "drop_full should count failed enqueue");
    CHECK(ring.stats.wait_full == 0,
          "wait_full should stay zero for nonblocking ring");

    fprintf(stderr,
            "[test_packet_ring_queue] case=drop_full rc=EAGAIN enq_ok=%llu "
            "drop_full=%llu wait_full=%llu slot_count=%u\n",
            (unsigned long long)ring.stats.enq_ok,
            (unsigned long long)ring.stats.drop_full,
            (unsigned long long)ring.stats.wait_full, ring.slot_count);

    packet_ring_destroy(&ring);
    return 0;
}

static int test_wait_full_counts_blocking_wait(void) {
    packet_ring_t     ring;
    delayed_deq_arg_t arg;
    pthread_t         tid;
    const uint8_t     pkt_a[] = {0x11};
    const uint8_t     pkt_b[] = {0x22};
    uint64_t          start_ns;
    uint64_t          end_ns;
    double            elapsed_ms;

    memset(&arg, 0, sizeof(arg));
    CHECK(packet_ring_init(&ring, 1, 1) == 0, "packet_ring_init failed");
    CHECK(packet_ring_enq(&ring, pkt_a, sizeof(pkt_a), 10) == 0,
          "initial enqueue failed");
    arg.ring = &ring;

    CHECK(pthread_create(&tid, NULL, delayed_deq_thread, &arg) == 0,
          "pthread_create failed");
    start_ns = now_ns();
    CHECK(packet_ring_enq(&ring, pkt_b, sizeof(pkt_b), 20) == 0,
          "blocking enqueue should succeed after dequeue");
    end_ns = now_ns();
    CHECK(pthread_join(tid, NULL) == 0, "pthread_join failed");

    CHECK(arg.rc == 0, "delayed dequeue failed");
    CHECK(arg.out_len == sizeof(pkt_a), "delayed dequeue length mismatch");
    CHECK(arg.out[0] == pkt_a[0], "delayed dequeue payload mismatch");
    CHECK(ring.stats.drop_full == 0,
          "drop_full should not count blocking waits");
    CHECK(ring.stats.wait_full >= 1, "wait_full should count blocking wait");

    elapsed_ms = (double)(end_ns - start_ns) / 1000000.0;
    fprintf(stderr,
            "[test_packet_ring_queue] case=wait_full elapsed_ms=%.3f "
            "deq_len=%u deq_ts_ns=%llu enq_ok=%llu deq_ok=%llu drop_full=%llu "
            "wait_full=%llu\n",
            elapsed_ms, arg.out_len, (unsigned long long)arg.out_ts_ns,
            (unsigned long long)ring.stats.enq_ok,
            (unsigned long long)ring.stats.deq_ok,
            (unsigned long long)ring.stats.drop_full,
            (unsigned long long)ring.stats.wait_full);

    packet_ring_destroy(&ring);
    return 0;
}

int main(void) {
    if (test_drop_full_counts_real_drop_only() != 0) {
        return 1;
    }
    if (test_wait_full_counts_blocking_wait() != 0) {
        return 1;
    }

    printf("ok: test_packet_ring_queue\n");
    return 0;
}

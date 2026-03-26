/**
 * @file test_packet_ring_spsc.c
 * @brief packet ring SPSC 동작 검증 테스트
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "packet_ring.h"

#define CHECK(cond, msg)                          \
    do {                                          \
        if (!(cond)) {                            \
            fprintf(stderr, "FAIL: %s\n", (msg)); \
            return 1;                             \
        }                                         \
    } while (0)

#define TEST_PACKET_COUNT 2048U

typedef struct ring_thread_arg {
    packet_ring_t *ring;
    int            rc;
} ring_thread_arg_t;

static uint64_t now_ns(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static void *producer_thread(void *arg) {
    ring_thread_arg_t *ctx = (ring_thread_arg_t *)arg;

    for (uint32_t i = 0; i < TEST_PACKET_COUNT; i++) {
        uint32_t payload = i;
        int      rc      = packet_ring_enq(ctx->ring, (const uint8_t *)&payload,
                                           sizeof(payload), (uint64_t)(1000U + i));
        if (0 != rc) {
            ctx->rc = rc;
            return NULL;
        }
    }

    ctx->rc = 0;
    return NULL;
}

static void *consumer_thread(void *arg) {
    ring_thread_arg_t *ctx = (ring_thread_arg_t *)arg;

    for (uint32_t i = 0; i < TEST_PACKET_COUNT; i++) {
        uint32_t payload = 0;
        uint32_t len     = 0;
        uint64_t ts_ns   = 0;
        int      rc      = packet_ring_deq(ctx->ring, (uint8_t *)&payload,
                                           sizeof(payload), &len, &ts_ns);
        if (0 != rc) {
            ctx->rc = rc;
            return NULL;
        }
        if (sizeof(payload) != len) {
            ctx->rc = -2;
            return NULL;
        }
        if (i != payload) {
            ctx->rc = -3;
            return NULL;
        }
        if ((uint64_t)(1000U + i) != ts_ns) {
            ctx->rc = -4;
            return NULL;
        }
    }

    ctx->rc = 0;
    return NULL;
}

static int test_spsc_roundtrip_preserves_order(void) {
    packet_ring_t     ring;
    pthread_t         producer;
    pthread_t         consumer;
    ring_thread_arg_t producer_arg;
    ring_thread_arg_t consumer_arg;
    uint64_t          start_ns;
    uint64_t          end_ns;
    double            elapsed_ms;
    double            packets_per_sec;

    memset(&producer_arg, 0, sizeof(producer_arg));
    memset(&consumer_arg, 0, sizeof(consumer_arg));

    CHECK(0 == packet_ring_init(&ring, 64, 1), "packet_ring_init failed");

    producer_arg.ring = &ring;
    consumer_arg.ring = &ring;

    start_ns = now_ns();
    CHECK(0 == pthread_create(&producer, NULL, producer_thread, &producer_arg),
          "producer pthread_create failed");
    CHECK(0 == pthread_create(&consumer, NULL, consumer_thread, &consumer_arg),
          "consumer pthread_create failed");
    CHECK(0 == pthread_join(producer, NULL), "producer pthread_join failed");
    CHECK(0 == pthread_join(consumer, NULL), "consumer pthread_join failed");

    CHECK(0 == producer_arg.rc, "producer thread failed");
    CHECK(0 == consumer_arg.rc, "consumer thread failed");
    CHECK(TEST_PACKET_COUNT == ring.stats.enq_ok, "enq_ok mismatch");
    CHECK(TEST_PACKET_COUNT == ring.stats.deq_ok, "deq_ok mismatch");

    end_ns          = now_ns();
    elapsed_ms      = (double)(end_ns - start_ns) / 1000000.0;
    packets_per_sec = ((double)TEST_PACKET_COUNT * 1000000000.0) /
                      (double)(end_ns - start_ns);
    fprintf(stderr,
            "[test_packet_ring_spsc] case=spsc_roundtrip packets=%u "
            "elapsed_ms=%.3f pps=%.0f enq_ok=%llu deq_ok=%llu drop_full=%llu "
            "wait_full=%llu\n",
            TEST_PACKET_COUNT, elapsed_ms, packets_per_sec,
            (unsigned long long)ring.stats.enq_ok,
            (unsigned long long)ring.stats.deq_ok,
            (unsigned long long)ring.stats.drop_full,
            (unsigned long long)ring.stats.wait_full);

    packet_ring_destroy(&ring);
    return 0;
}

static int test_queue_set_init_allocates_all_rings(void) {
    packet_queue_set_t set;

    CHECK(0 == packet_queue_set_init(&set, 3, 8, 0),
          "packet_queue_set_init failed");
    CHECK(3 == set.qcount, "qcount mismatch");
    CHECK(NULL != set.q, "queue array missing");
    CHECK(8 == set.q[0].slot_count, "slot_count mismatch");
    CHECK(7 == set.q[0].mask, "mask mismatch");

    fprintf(
        stderr,
        "[test_packet_ring_spsc] case=queue_set_init qcount=%u slot_count=%u "
        "mask=%u use_blocking=%d\n",
        set.qcount, set.q[0].slot_count, set.q[0].mask,
        atomic_load_explicit(&set.q[0].use_blocking, memory_order_relaxed));

    packet_queue_set_destroy(&set);
    return 0;
}

int main(void) {
    if (0 != test_spsc_roundtrip_preserves_order()) {
        return 1;
    }
    if (0 != test_queue_set_init_allocates_all_rings()) {
        return 1;
    }

    printf("ok: test_packet_ring_spsc\n");
    return 0;
}

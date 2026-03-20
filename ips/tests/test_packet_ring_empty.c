/**
 * @file test_packet_ring_empty.c
 * @brief 프로듀서를 늦춰서 컨슈머가 빈 큐를 자주 만나게 함, cpu spin이 심하지 않은지 체크
 * 
 * @copyright Copyright (c) 2026
 * 
 */
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
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

typedef struct empty_wait_arg {
    packet_ring_t *ring;
    int            rc;
    uint32_t       out_len;
    uint64_t       out_ts_ns;
} empty_wait_arg_t;

static uint64_t now_ns(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static void *empty_wait_thread(void *arg) {
    empty_wait_arg_t *ctx = (empty_wait_arg_t *)arg;

    ctx->rc = packet_ring_deq(ctx->ring, NULL, 0, &ctx->out_len,
                              &ctx->out_ts_ns);
    return NULL;
}

static int test_nonblocking_empty_returns_failure(void) {
    packet_ring_t ring;
    uint32_t      out_len = 0;
    uint64_t      out_ts_ns = 0;
    uint64_t      start_ns;
    uint64_t      end_ns;
    double        elapsed_ms;

    CHECK(0 == packet_ring_init(&ring, 4, 0), "packet_ring_init failed");
    start_ns = now_ns();
    CHECK(-1 == packet_ring_deq(&ring, NULL, 0, &out_len, &out_ts_ns),
          "empty nonblocking dequeue should return -1");
    end_ns = now_ns();
    elapsed_ms = (double)(end_ns - start_ns) / 1000000.0;
    fprintf(stderr,
            "[test_packet_ring_empty] case=nonblocking_empty elapsed_ms=%.6f "
            "rc=-1 out_len=%u out_ts_ns=%llu\n",
            elapsed_ms, out_len, (unsigned long long)out_ts_ns);
    packet_ring_destroy(&ring);
    return 0;
}

static int test_blocking_empty_can_be_cancelled(void) {
    packet_ring_t ring;
    pthread_t       tid;
    empty_wait_arg_t arg;
    uint64_t        start_ns;
    uint64_t        end_ns;
    double          elapsed_ms;

    memset(&arg, 0, sizeof(arg));
    CHECK(0 == packet_ring_init(&ring, 4, 1), "packet_ring_init failed");

    arg.ring = &ring;

    start_ns = now_ns();
    CHECK(0 == pthread_create(&tid, NULL, empty_wait_thread, &arg),
          "pthread_create failed");

    usleep(20000);
    atomic_store_explicit(&ring.use_blocking, 0, memory_order_release);

    CHECK(0 == pthread_join(tid, NULL), "pthread_join failed");
    CHECK(-1 == arg.rc, "cancelled blocking dequeue should return -1");
    end_ns = now_ns();
    elapsed_ms = (double)(end_ns - start_ns) / 1000000.0;

    fprintf(stderr,
            "[test_packet_ring_empty] case=blocking_cancel elapsed_ms=%.3f "
            "rc=%d out_len=%u out_ts_ns=%llu use_blocking=%d\n",
            elapsed_ms, arg.rc, arg.out_len,
            (unsigned long long)arg.out_ts_ns,
            atomic_load_explicit(&ring.use_blocking, memory_order_relaxed));

    packet_ring_destroy(&ring);
    return 0;
}

int main(void) {
    if (0 != test_nonblocking_empty_returns_failure()) {
        return 1;
    }
    if (0 != test_blocking_empty_can_be_cancelled()) {
        return 1;
    }

    printf("ok: test_packet_ring_empty\n");
    return 0;
}

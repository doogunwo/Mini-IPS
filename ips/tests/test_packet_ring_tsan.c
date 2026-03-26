/**
 * @file test_packet_ring_tsan.c
 * @brief  TSAN 검증용 테스트 코드
 * data race  탐지가 목적이다.
 *
 */
#include <pthread.h>
#include <stdatomic.h>
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

#define TSAN_ITERATIONS 200000U
#define TSAN_SLOT_COUNT 64U

typedef struct tsan_thread_arg {
    packet_ring_t *ring;
    _Atomic int   *stop;
    uint32_t       iterations;
    int            rc;
} tsan_thread_arg_t;

static uint64_t now_ns(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static void *tsan_producer_thread(void *arg) {
    tsan_thread_arg_t *ctx = (tsan_thread_arg_t *)arg;

    for (uint32_t i = 0; i < ctx->iterations; i++) {
        uint32_t payload = i;
        int      rc      = packet_ring_enq(ctx->ring, (const uint8_t *)&payload,
                                           sizeof(payload), (uint64_t)i);
        if (0 != rc) {
            ctx->rc = rc;
            return NULL;
        }
    }

    ctx->rc = 0;
    return NULL;
}

static void *tsan_consumer_thread(void *arg) {
    tsan_thread_arg_t *ctx = (tsan_thread_arg_t *)arg;

    for (uint32_t i = 0; i < ctx->iterations; i++) {
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
        if ((uint64_t)i != ts_ns) {
            ctx->rc = -4;
            return NULL;
        }
    }

    ctx->rc = 0;
    return NULL;
}

static void *tsan_observer_thread(void *arg) {
    tsan_thread_arg_t *ctx  = (tsan_thread_arg_t *)arg;
    packet_ring_t     *ring = ctx->ring;

    while (0 == atomic_load_explicit(ctx->stop, memory_order_acquire)) {
        (void)atomic_load_explicit(&ring->head, memory_order_relaxed);
        (void)atomic_load_explicit(&ring->tail, memory_order_relaxed);
        (void)atomic_load_explicit(&ring->use_blocking, memory_order_relaxed);
        (void)ring->stats.enq_ok;
        (void)ring->stats.deq_ok;
        (void)ring->stats.drop_full;
        (void)ring->stats.wait_full;
    }

    ctx->rc = 0;
    return NULL;
}

int main(void) {
    packet_ring_t     ring;
    pthread_t         producer_tid;
    pthread_t         consumer_tid;
    pthread_t         observer_tid;
    _Atomic int       stop = 0;
    tsan_thread_arg_t producer_arg;
    tsan_thread_arg_t consumer_arg;
    tsan_thread_arg_t observer_arg;
    uint64_t          start_ns;
    uint64_t          end_ns;
    double            elapsed_ms;

    memset(&producer_arg, 0, sizeof(producer_arg));
    memset(&consumer_arg, 0, sizeof(consumer_arg));
    memset(&observer_arg, 0, sizeof(observer_arg));

    CHECK(0 == packet_ring_init(&ring, TSAN_SLOT_COUNT, 1),
          "packet_ring_init failed");

    producer_arg.ring       = &ring;
    producer_arg.stop       = &stop;
    producer_arg.iterations = TSAN_ITERATIONS;

    consumer_arg.ring       = &ring;
    consumer_arg.stop       = &stop;
    consumer_arg.iterations = TSAN_ITERATIONS;

    observer_arg.ring       = &ring;
    observer_arg.stop       = &stop;
    observer_arg.iterations = TSAN_ITERATIONS;

    start_ns = now_ns();
    CHECK(0 == pthread_create(&producer_tid, NULL, tsan_producer_thread,
                              &producer_arg),
          "producer pthread_create failed");
    CHECK(0 == pthread_create(&consumer_tid, NULL, tsan_consumer_thread,
                              &consumer_arg),
          "consumer pthread_create failed");
    CHECK(0 == pthread_create(&observer_tid, NULL, tsan_observer_thread,
                              &observer_arg),
          "observer pthread_create failed");

    CHECK(0 == pthread_join(producer_tid, NULL),
          "producer pthread_join failed");
    CHECK(0 == pthread_join(consumer_tid, NULL),
          "consumer pthread_join failed");

    atomic_store_explicit(&stop, 1, memory_order_release);
    CHECK(0 == pthread_join(observer_tid, NULL),
          "observer pthread_join failed");

    CHECK(0 == producer_arg.rc, "producer failed");
    CHECK(0 == consumer_arg.rc, "consumer failed");
    CHECK(0 == observer_arg.rc, "observer failed");

    end_ns     = now_ns();
    elapsed_ms = (double)(end_ns - start_ns) / 1000000.0;
    fprintf(stderr,
            "[test_packet_ring_tsan] iterations=%u elapsed_ms=%.3f "
            "enq_ok=%llu deq_ok=%llu drop_full=%llu wait_full=%llu "
            "note=build_with_tsan_for_race_reports\n",
            TSAN_ITERATIONS, elapsed_ms, (unsigned long long)ring.stats.enq_ok,
            (unsigned long long)ring.stats.deq_ok,
            (unsigned long long)ring.stats.drop_full,
            (unsigned long long)ring.stats.wait_full);

    packet_ring_destroy(&ring);
    printf("ok: test_packet_ring_tsan\n");
    return 0;
}

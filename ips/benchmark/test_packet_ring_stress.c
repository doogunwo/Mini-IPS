/**
 * @file test_packet_ring_stress.c
 * @brief producer 1개 / consumer 1개, 패킷 반복 테스트
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

#define STRESS_ITERATIONS 1000000U
#define STRESS_SLOT_COUNT 64U

typedef struct stress_thread_arg {
    packet_ring_t *ring;
    uint32_t       iterations;
    int            rc;
    uint64_t       start_ns;
    uint64_t       end_ns;
    uint64_t       cpu_start_ns;
    uint64_t       cpu_end_ns;
} stress_thread_arg_t;

static uint64_t now_ns(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static uint64_t now_process_cpu_ns(void) {
    struct timespec ts;

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static uint64_t now_thread_cpu_ns(void) {
    struct timespec ts;

    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static void table_line(void) {
    puts("+----------------------+----------------------+");
}

static void table_row_str(const char *metric, const char *value) {
    printf("| %-20s | %20s |\n", metric, value);
}

static void table_row_u64(const char *metric, unsigned long long value) {
    char buf[32];

    snprintf(buf, sizeof(buf), "%llu", value);
    table_row_str(metric, buf);
}

static void table_row_f64(const char *metric, double value,
                          const char *suffix) {
    char buf[64];

    if (suffix != NULL && suffix[0] != '\0') {
        snprintf(buf, sizeof(buf), "%.3f %s", value, suffix);
    } else {
        snprintf(buf, sizeof(buf), "%.3f", value);
    }
    table_row_str(metric, buf);
}

static void *stress_producer_thread(void *arg) {
    stress_thread_arg_t *ctx = (stress_thread_arg_t *)arg;

    ctx->start_ns = now_ns();
    ctx->cpu_start_ns = now_thread_cpu_ns();

    for (uint32_t i = 0; i < ctx->iterations; i++) {
        uint32_t payload = i;
        int rc = packet_ring_enq(ctx->ring, (const uint8_t *)&payload,
                                 sizeof(payload), (uint64_t)(1000000U + i));
        if (0 != rc) {
            ctx->rc = rc;
            ctx->end_ns = now_ns();
            ctx->cpu_end_ns = now_thread_cpu_ns();
            return NULL;
        }
    }

    ctx->end_ns = now_ns();
    ctx->cpu_end_ns = now_thread_cpu_ns();
    ctx->rc = 0;
    return NULL;
}

static void *stress_consumer_thread(void *arg) {
    stress_thread_arg_t *ctx = (stress_thread_arg_t *)arg;

    ctx->start_ns = now_ns();
    ctx->cpu_start_ns = now_thread_cpu_ns();

    for (uint32_t i = 0; i < ctx->iterations; i++) {
        uint32_t payload = 0;
        uint32_t len = 0;
        uint64_t ts_ns = 0;
        int rc = packet_ring_deq(ctx->ring, (uint8_t *)&payload,
                                 sizeof(payload), &len, &ts_ns);
        if (0 != rc) {
            ctx->rc = rc;
            ctx->end_ns = now_ns();
            ctx->cpu_end_ns = now_thread_cpu_ns();
            return NULL;
        }
        if (sizeof(payload) != len) {
            ctx->rc = -2;
            ctx->end_ns = now_ns();
            ctx->cpu_end_ns = now_thread_cpu_ns();
            return NULL;
        }
        if (i != payload) {
            ctx->rc = -3;
            ctx->end_ns = now_ns();
            ctx->cpu_end_ns = now_thread_cpu_ns();
            return NULL;
        }
        if ((uint64_t)(1000000U + i) != ts_ns) {
            ctx->rc = -4;
            ctx->end_ns = now_ns();
            ctx->cpu_end_ns = now_thread_cpu_ns();
            return NULL;
        }
    }

    ctx->end_ns = now_ns();
    ctx->cpu_end_ns = now_thread_cpu_ns();
    ctx->rc = 0;
    return NULL;
}

int main(void) {
    packet_ring_t     ring;
    pthread_t         producer_tid;
    pthread_t         consumer_tid;
    stress_thread_arg_t producer_arg;
    stress_thread_arg_t consumer_arg;
    uint64_t          start_ns;
    uint64_t          end_ns;
    uint64_t          process_cpu_start_ns;
    uint64_t          process_cpu_end_ns;
    double            elapsed_ms;
    double            producer_ms;
    double            consumer_ms;
    double            producer_cpu_ms;
    double            consumer_cpu_ms;
    double            process_cpu_ms;
    double            packets_per_sec;
    double            producer_cpu_pct;
    double            consumer_cpu_pct;
    double            process_cpu_pct;

    memset(&producer_arg, 0, sizeof(producer_arg));
    memset(&consumer_arg, 0, sizeof(consumer_arg));

    CHECK(0 == packet_ring_init(&ring, STRESS_SLOT_COUNT, 1),
          "packet_ring_init failed");

    producer_arg.ring = &ring;
    producer_arg.iterations = STRESS_ITERATIONS;

    consumer_arg.ring = &ring;
    consumer_arg.iterations = STRESS_ITERATIONS;

    start_ns = now_ns();
    process_cpu_start_ns = now_process_cpu_ns();
    CHECK(0 == pthread_create(&producer_tid, NULL, stress_producer_thread,
                              &producer_arg),
          "producer pthread_create failed");
    CHECK(0 == pthread_create(&consumer_tid, NULL, stress_consumer_thread,
                              &consumer_arg),
          "consumer pthread_create failed");

    CHECK(0 == pthread_join(producer_tid, NULL), "producer pthread_join failed");
    CHECK(0 == pthread_join(consumer_tid, NULL), "consumer pthread_join failed");

    CHECK(0 == producer_arg.rc, "producer failed");
    CHECK(0 == consumer_arg.rc, "consumer failed");
    CHECK((uint64_t)STRESS_ITERATIONS == ring.stats.enq_ok,
          "enq_ok mismatch");
    CHECK((uint64_t)STRESS_ITERATIONS == ring.stats.deq_ok,
          "deq_ok mismatch");
    CHECK(0 == ring.stats.drop_full, "drop_full should stay zero");

    end_ns = now_ns();
    process_cpu_end_ns = now_process_cpu_ns();
    elapsed_ms = (double)(end_ns - start_ns) / 1000000.0;
    producer_ms = (double)(producer_arg.end_ns - producer_arg.start_ns) /
                  1000000.0;
    consumer_ms = (double)(consumer_arg.end_ns - consumer_arg.start_ns) /
                  1000000.0;
    producer_cpu_ms =
        (double)(producer_arg.cpu_end_ns - producer_arg.cpu_start_ns) /
        1000000.0;
    consumer_cpu_ms =
        (double)(consumer_arg.cpu_end_ns - consumer_arg.cpu_start_ns) /
        1000000.0;
    process_cpu_ms =
        (double)(process_cpu_end_ns - process_cpu_start_ns) / 1000000.0;
    packets_per_sec =
        ((double)STRESS_ITERATIONS * 1000000000.0) /
        (double)(end_ns - start_ns);
    producer_cpu_pct =
        100.0 * (double)(producer_arg.cpu_end_ns - producer_arg.cpu_start_ns) /
        (double)(producer_arg.end_ns - producer_arg.start_ns);
    consumer_cpu_pct =
        100.0 * (double)(consumer_arg.cpu_end_ns - consumer_arg.cpu_start_ns) /
        (double)(consumer_arg.end_ns - consumer_arg.start_ns);
    process_cpu_pct =
        100.0 * (double)(process_cpu_end_ns - process_cpu_start_ns) /
        (double)(end_ns - start_ns);

    puts("[test_packet_ring_stress]");
    table_line();
    table_row_str("metric", "value");
    table_line();
    table_row_u64("iterations", STRESS_ITERATIONS);
    table_row_u64("slot_count", STRESS_SLOT_COUNT);
    table_row_f64("total_ms", elapsed_ms, "ms");
    table_row_f64("producer_ms", producer_ms, "ms");
    table_row_f64("consumer_ms", consumer_ms, "ms");
    table_row_f64("producer_cpu_ms", producer_cpu_ms, "ms");
    table_row_f64("consumer_cpu_ms", consumer_cpu_ms, "ms");
    table_row_f64("process_cpu_ms", process_cpu_ms, "ms");
    table_row_f64("producer_cpu_pct", producer_cpu_pct, "%");
    table_row_f64("consumer_cpu_pct", consumer_cpu_pct, "%");
    table_row_f64("process_cpu_pct", process_cpu_pct, "%");
    table_row_f64("pipeline_pps", packets_per_sec, "pps");
    table_row_u64("enq_ok", (unsigned long long)ring.stats.enq_ok);
    table_row_u64("deq_ok", (unsigned long long)ring.stats.deq_ok);
    table_row_u64("drop_full", (unsigned long long)ring.stats.drop_full);
    table_row_u64("wait_full", (unsigned long long)ring.stats.wait_full);
    table_line();

    packet_ring_destroy(&ring);
    printf("ok: test_packet_ring_stress\n");
    return 0;
}

/**
 * @file test_packet_ring_bench.c
 * @brief packet ring producer/consumer 처리량 및 큐 지연 측정 벤치마크
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

#define BENCH_ITERATIONS 1000000U
#define BENCH_SLOT_COUNT 1024U
#define BENCH_PAYLOAD_LEN 1500U

typedef struct bench_thread_arg {
    packet_ring_t *ring;
    uint32_t       iterations;
    uint32_t       payload_len;
    int            rc;
    uint64_t       start_ns;
    uint64_t       end_ns;
    uint64_t       cpu_start_ns;
    uint64_t       cpu_end_ns;
    uint64_t       latency_sum_ns;
    uint64_t       latency_max_ns;
} bench_thread_arg_t;

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

static void payload_set_seq(uint8_t *buf, uint32_t seq, uint32_t len) {
    memset(buf, 0xA5, len);
    memcpy(buf, &seq, sizeof(seq));
}

static uint32_t payload_get_seq(const uint8_t *buf) {
    uint32_t seq = 0;

    memcpy(&seq, buf, sizeof(seq));
    return seq;
}

static void *bench_producer_thread(void *arg) {
    bench_thread_arg_t *ctx = (bench_thread_arg_t *)arg;
    uint8_t             payload[BENCH_PAYLOAD_LEN];

    ctx->start_ns = now_ns();
    ctx->cpu_start_ns = now_thread_cpu_ns();

    for (uint32_t i = 0; i < ctx->iterations; i++) {
        int rc;

        payload_set_seq(payload, i, ctx->payload_len);
        rc = packet_ring_enq(ctx->ring, payload, ctx->payload_len, now_ns());
        if (0 != rc) {
            ctx->rc = rc;
            ctx->end_ns = now_ns();
            return NULL;
        }
    }

    ctx->end_ns = now_ns();
    ctx->cpu_end_ns = now_thread_cpu_ns();
    ctx->rc = 0;
    return NULL;
}

static void *bench_consumer_thread(void *arg) {
    bench_thread_arg_t *ctx = (bench_thread_arg_t *)arg;
    uint8_t             out[PACKET_MAX_BYTES];

    ctx->start_ns = now_ns();
    ctx->cpu_start_ns = now_thread_cpu_ns();

    for (uint32_t i = 0; i < ctx->iterations; i++) {
        uint32_t len = 0;
        uint64_t ts_ns = 0;
        uint64_t dequeue_ns;
        uint64_t latency_ns;
        uint32_t seq;
        int rc;

        rc = packet_ring_deq(ctx->ring, out, sizeof(out), &len, &ts_ns);
        if (0 != rc) {
            ctx->rc = rc;
            ctx->end_ns = now_ns();
            ctx->cpu_end_ns = now_thread_cpu_ns();
            return NULL;
        }
        if (ctx->payload_len != len) {
            ctx->rc = -2;
            ctx->end_ns = now_ns();
            ctx->cpu_end_ns = now_thread_cpu_ns();
            return NULL;
        }

        seq = payload_get_seq(out);
        if (i != seq) {
            ctx->rc = -3;
            ctx->end_ns = now_ns();
            ctx->cpu_end_ns = now_thread_cpu_ns();
            return NULL;
        }

        dequeue_ns = now_ns();
        latency_ns = dequeue_ns - ts_ns;
        ctx->latency_sum_ns += latency_ns;
        if (latency_ns > ctx->latency_max_ns) {
            ctx->latency_max_ns = latency_ns;
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
    bench_thread_arg_t producer_arg;
    bench_thread_arg_t consumer_arg;
    uint64_t          total_start_ns;
    uint64_t          total_end_ns;
    uint64_t          process_cpu_start_ns;
    uint64_t          process_cpu_end_ns;
    uint64_t          total_bytes;
    double            producer_ms;
    double            consumer_ms;
    double            total_ms;
    double            producer_cpu_ms;
    double            consumer_cpu_ms;
    double            process_cpu_ms;
    double            producer_pps;
    double            consumer_pps;
    double            pipeline_pps;
    double            throughput_mib_s;
    double            avg_queue_latency_us;
    double            max_queue_latency_us;
    double            producer_cpu_pct;
    double            consumer_cpu_pct;
    double            process_cpu_pct;

    CHECK(BENCH_PAYLOAD_LEN <= PACKET_MAX_BYTES,
          "BENCH_PAYLOAD_LEN exceeds PACKET_MAX_BYTES");

    memset(&producer_arg, 0, sizeof(producer_arg));
    memset(&consumer_arg, 0, sizeof(consumer_arg));

    CHECK(0 == packet_ring_init(&ring, BENCH_SLOT_COUNT, 1),
          "packet_ring_init failed");

    producer_arg.ring = &ring;
    producer_arg.iterations = BENCH_ITERATIONS;
    producer_arg.payload_len = BENCH_PAYLOAD_LEN;

    consumer_arg.ring = &ring;
    consumer_arg.iterations = BENCH_ITERATIONS;
    consumer_arg.payload_len = BENCH_PAYLOAD_LEN;

    total_start_ns = now_ns();
    process_cpu_start_ns = now_process_cpu_ns();

    CHECK(0 == pthread_create(&producer_tid, NULL, bench_producer_thread,
                              &producer_arg),
          "producer pthread_create failed");
    CHECK(0 == pthread_create(&consumer_tid, NULL, bench_consumer_thread,
                              &consumer_arg),
          "consumer pthread_create failed");

    CHECK(0 == pthread_join(producer_tid, NULL), "producer pthread_join failed");
    CHECK(0 == pthread_join(consumer_tid, NULL), "consumer pthread_join failed");

    total_end_ns = now_ns();
    process_cpu_end_ns = now_process_cpu_ns();

    CHECK(0 == producer_arg.rc, "producer failed");
    CHECK(0 == consumer_arg.rc, "consumer failed");
    CHECK((uint64_t)BENCH_ITERATIONS == ring.stats.enq_ok, "enq_ok mismatch");
    CHECK((uint64_t)BENCH_ITERATIONS == ring.stats.deq_ok, "deq_ok mismatch");

    total_bytes = (uint64_t)BENCH_ITERATIONS * (uint64_t)BENCH_PAYLOAD_LEN;
    producer_ms =
        (double)(producer_arg.end_ns - producer_arg.start_ns) / 1000000.0;
    consumer_ms =
        (double)(consumer_arg.end_ns - consumer_arg.start_ns) / 1000000.0;
    total_ms = (double)(total_end_ns - total_start_ns) / 1000000.0;
    producer_cpu_ms =
        (double)(producer_arg.cpu_end_ns - producer_arg.cpu_start_ns) /
        1000000.0;
    consumer_cpu_ms =
        (double)(consumer_arg.cpu_end_ns - consumer_arg.cpu_start_ns) /
        1000000.0;
    process_cpu_ms =
        (double)(process_cpu_end_ns - process_cpu_start_ns) / 1000000.0;
    producer_pps =
        ((double)BENCH_ITERATIONS * 1000000000.0) /
        (double)(producer_arg.end_ns - producer_arg.start_ns);
    consumer_pps =
        ((double)BENCH_ITERATIONS * 1000000000.0) /
        (double)(consumer_arg.end_ns - consumer_arg.start_ns);
    pipeline_pps =
        ((double)BENCH_ITERATIONS * 1000000000.0) /
        (double)(total_end_ns - total_start_ns);
    throughput_mib_s =
        ((double)total_bytes * 1000000000.0) /
        ((double)(total_end_ns - total_start_ns) * 1024.0 * 1024.0);
    avg_queue_latency_us =
        ((double)consumer_arg.latency_sum_ns / (double)BENCH_ITERATIONS) /
        1000.0;
    max_queue_latency_us = (double)consumer_arg.latency_max_ns / 1000.0;
    producer_cpu_pct =
        100.0 * (double)(producer_arg.cpu_end_ns - producer_arg.cpu_start_ns) /
        (double)(producer_arg.end_ns - producer_arg.start_ns);
    consumer_cpu_pct =
        100.0 * (double)(consumer_arg.cpu_end_ns - consumer_arg.cpu_start_ns) /
        (double)(consumer_arg.end_ns - consumer_arg.start_ns);
    process_cpu_pct =
        100.0 * (double)(process_cpu_end_ns - process_cpu_start_ns) /
        (double)(total_end_ns - total_start_ns);

    puts("[test_packet_ring_bench]");
    table_line();
    table_row_str("metric", "value");
    table_line();
    table_row_u64("iterations", BENCH_ITERATIONS);
    table_row_u64("slot_count", BENCH_SLOT_COUNT);
    table_row_u64("payload_len", BENCH_PAYLOAD_LEN);
    table_row_f64("producer_ms", producer_ms, "ms");
    table_row_f64("consumer_ms", consumer_ms, "ms");
    table_row_f64("total_ms", total_ms, "ms");
    table_row_f64("producer_cpu_ms", producer_cpu_ms, "ms");
    table_row_f64("consumer_cpu_ms", consumer_cpu_ms, "ms");
    table_row_f64("process_cpu_ms", process_cpu_ms, "ms");
    table_row_f64("producer_cpu_pct", producer_cpu_pct, "%");
    table_row_f64("consumer_cpu_pct", consumer_cpu_pct, "%");
    table_row_f64("process_cpu_pct", process_cpu_pct, "%");
    table_row_f64("producer_pps", producer_pps, "pps");
    table_row_f64("consumer_pps", consumer_pps, "pps");
    table_row_f64("pipeline_pps", pipeline_pps, "pps");
    table_row_f64("throughput_mib_s", throughput_mib_s, "MiB/s");
    table_row_f64("avg_queue_lat_us", avg_queue_latency_us, "us");
    table_row_f64("max_queue_lat_us", max_queue_latency_us, "us");
    table_row_u64("enq_ok", (unsigned long long)ring.stats.enq_ok);
    table_row_u64("deq_ok", (unsigned long long)ring.stats.deq_ok);
    table_row_u64("drop_full", (unsigned long long)ring.stats.drop_full);
    table_row_u64("wait_full", (unsigned long long)ring.stats.wait_full);
    table_line();

    packet_ring_destroy(&ring);
    return 0;
}

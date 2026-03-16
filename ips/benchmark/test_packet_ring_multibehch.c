/**
 * @file test_packet_ring_multibehch.c
 * @brief producer 1개와 consumer 여러 개를 사용해 worker_count 확장 효과를 측정한다.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

#define DEFAULT_WORKER_COUNT 4U
#define DEFAULT_ITERATIONS_PER_WORKER 250000U
#define DEFAULT_BENCH_SLOT_COUNT 1024U
#define DEFAULT_PAYLOAD_LEN 1500U
#define BENCH_META_BYTES 8U

typedef struct dispatch_flow {
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    uint8_t  proto;
    uint32_t worker_idx;
} dispatch_flow_t;

typedef struct producer_arg {
    packet_queue_set_t *queues;
    dispatch_flow_t    *flows;
    uint32_t            worker_count;
    uint32_t            iterations_per_worker;
    uint32_t            payload_len;
    int                 rc;
    uint64_t            wall_start_ns;
    uint64_t            wall_end_ns;
    uint64_t            cpu_start_ns;
    uint64_t            cpu_end_ns;
} producer_arg_t;

typedef struct consumer_arg {
    packet_ring_t *ring;
    uint32_t       worker_idx;
    uint32_t       iterations;
    uint32_t       payload_len;
    int            rc;
    uint64_t       wall_start_ns;
    uint64_t       wall_end_ns;
    uint64_t       cpu_start_ns;
    uint64_t       cpu_end_ns;
    uint64_t       latency_sum_ns;
    uint64_t       latency_max_ns;
    uint64_t       bytes;
} consumer_arg_t;

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

static int parse_u32_arg(const char *text, uint32_t *out) {
    char         *end = NULL;
    unsigned long value;

    if (NULL == text || NULL == out) {
        return -1;
    }

    value = strtoul(text, &end, 10);
    if ('\0' != text[0] && NULL != end && '\0' == *end && value > 0UL &&
        value <= 0xFFFFFFFFUL) {
        *out = (uint32_t)value;
        return 0;
    }

    return -1;
}

static void table_line(void) {
    puts("+------------------------+----------------------+");
}

static void table_row_str(const char *metric, const char *value) {
    printf("| %-22s | %20s |\n", metric, value);
}

static void table_row_u64(const char *metric, unsigned long long value) {
    char buf[32];

    snprintf(buf, sizeof(buf), "%llu", value);
    table_row_str(metric, buf);
}

static void table_row_f64(const char *metric, double value,
                          const char *suffix) {
    char buf[64];

    if (NULL != suffix && '\0' != suffix[0]) {
        snprintf(buf, sizeof(buf), "%.3f %s", value, suffix);
    } else {
        snprintf(buf, sizeof(buf), "%.3f", value);
    }
    table_row_str(metric, buf);
}

static int endpoint_cmp(uint32_t a_ip, uint16_t a_port, uint32_t b_ip,
                        uint16_t b_port) {
    if (a_ip < b_ip) {
        return -1;
    }
    if (a_ip > b_ip) {
        return 1;
    }
    if (a_port < b_port) {
        return -1;
    }
    if (a_port > b_port) {
        return 1;
    }
    return 0;
}

static uint32_t benchmark_flow_hash_5tuple(uint32_t sip, uint32_t dip,
                                           uint16_t sport, uint16_t dport,
                                           uint8_t proto) {
    uint32_t h = 2166136261u;

    if (endpoint_cmp(sip, sport, dip, dport) > 0) {
        uint32_t tmp_ip = sip;
        uint16_t tmp_port = sport;

        sip = dip;
        sport = dport;
        dip = tmp_ip;
        dport = tmp_port;
    }

    h ^= sip;
    h *= 16777619u;
    h ^= dip;
    h *= 16777619u;
    h ^= ((uint32_t)sport << 16) | dport;
    h *= 16777619u;
    h ^= proto;
    h *= 16777619u;
    return h;
}

static int build_dispatch_flows(dispatch_flow_t *flows, uint32_t worker_count) {
    uint32_t attempts = 0;
    uint32_t filled = 0;

    if (NULL == flows || 0U == worker_count) {
        return -1;
    }

    while (filled < worker_count) {
        dispatch_flow_t flow;
        uint32_t        worker_idx;
        int             duplicate = 0;

        flow.sip = 0x0A000001u + attempts;
        flow.dip = 0x0A100001u + attempts;
        flow.sport = (uint16_t)(10000U + attempts);
        flow.dport = (uint16_t)(20000U + attempts);
        flow.proto = 6U;

        worker_idx = benchmark_flow_hash_5tuple(flow.sip, flow.dip, flow.sport,
                                                flow.dport, flow.proto) %
                     worker_count;
        for (uint32_t i = 0; i < filled; i++) {
            if (flows[i].worker_idx == worker_idx) {
                duplicate = 1;
                break;
            }
        }
        if (0 == duplicate) {
            flow.worker_idx = worker_idx;
            flows[filled] = flow;
            filled++;
        }

        attempts++;
        if (attempts > 1000000U) {
            return -1;
        }
    }

    return 0;
}

static void payload_set_meta(uint8_t *buf, uint32_t worker_idx, uint32_t seq,
                             uint32_t len) {
    memset(buf, 0xA5, len);
    memcpy(buf, &worker_idx, sizeof(worker_idx));
    memcpy(buf + sizeof(worker_idx), &seq, sizeof(seq));
}

static uint32_t payload_get_worker(const uint8_t *buf) {
    uint32_t worker_idx = 0;

    memcpy(&worker_idx, buf, sizeof(worker_idx));
    return worker_idx;
}

static uint32_t payload_get_seq(const uint8_t *buf) {
    uint32_t seq = 0;

    memcpy(&seq, buf + sizeof(uint32_t), sizeof(seq));
    return seq;
}

static void *producer_thread(void *arg) {
    producer_arg_t *ctx = (producer_arg_t *)arg;
    uint8_t         payload[PACKET_MAX_BYTES];
    uint32_t       *seq_per_worker;
    uint32_t        total_packets;

    seq_per_worker =
        (uint32_t *)calloc(ctx->worker_count, sizeof(*seq_per_worker));
    if (NULL == seq_per_worker) {
        ctx->rc = -1;
        return NULL;
    }

    total_packets = ctx->worker_count * ctx->iterations_per_worker;
    ctx->wall_start_ns = now_ns();
    ctx->cpu_start_ns = now_thread_cpu_ns();

    for (uint32_t i = 0; i < total_packets; i++) {
        const dispatch_flow_t *flow = &ctx->flows[i % ctx->worker_count];
        uint32_t               worker_idx = flow->worker_idx;
        uint32_t               seq = seq_per_worker[worker_idx]++;
        int      rc;

        payload_set_meta(payload, worker_idx, seq, ctx->payload_len);
        rc = packet_ring_enq(&ctx->queues->q[worker_idx], payload,
                             ctx->payload_len, now_ns());
        if (0 != rc) {
            ctx->rc = rc;
            ctx->wall_end_ns = now_ns();
            ctx->cpu_end_ns = now_thread_cpu_ns();
            free(seq_per_worker);
            return NULL;
        }
    }

    ctx->wall_end_ns = now_ns();
    ctx->cpu_end_ns = now_thread_cpu_ns();
    ctx->rc = 0;
    free(seq_per_worker);
    return NULL;
}

static void *consumer_thread(void *arg) {
    consumer_arg_t *ctx = (consumer_arg_t *)arg;
    uint8_t         out[PACKET_MAX_BYTES];

    ctx->wall_start_ns = now_ns();
    ctx->cpu_start_ns = now_thread_cpu_ns();

    for (uint32_t expected_seq = 0; expected_seq < ctx->iterations;
         expected_seq++) {
        uint32_t len = 0;
        uint64_t ts_ns = 0;
        uint64_t dequeue_ns;
        uint64_t latency_ns;
        uint32_t worker_idx;
        uint32_t seq;
        int      rc;

        rc = packet_ring_deq(ctx->ring, out, sizeof(out), &len, &ts_ns);
        if (0 != rc) {
            ctx->rc = rc;
            ctx->wall_end_ns = now_ns();
            ctx->cpu_end_ns = now_thread_cpu_ns();
            return NULL;
        }
        if (ctx->payload_len != len) {
            ctx->rc = -2;
            ctx->wall_end_ns = now_ns();
            ctx->cpu_end_ns = now_thread_cpu_ns();
            return NULL;
        }

        worker_idx = payload_get_worker(out);
        seq = payload_get_seq(out);
        if (ctx->worker_idx != worker_idx) {
            ctx->rc = -3;
            ctx->wall_end_ns = now_ns();
            ctx->cpu_end_ns = now_thread_cpu_ns();
            return NULL;
        }
        if (expected_seq != seq) {
            ctx->rc = -4;
            ctx->wall_end_ns = now_ns();
            ctx->cpu_end_ns = now_thread_cpu_ns();
            return NULL;
        }

        dequeue_ns = now_ns();
        latency_ns = dequeue_ns - ts_ns;
        ctx->latency_sum_ns += latency_ns;
        if (latency_ns > ctx->latency_max_ns) {
            ctx->latency_max_ns = latency_ns;
        }
        ctx->bytes += len;
    }

    ctx->wall_end_ns = now_ns();
    ctx->cpu_end_ns = now_thread_cpu_ns();
    ctx->rc = 0;
    return NULL;
}

int main(int argc, char **argv) {
    packet_queue_set_t queues;
    pthread_t          producer_tid;
    pthread_t         *consumer_tids = NULL;
    producer_arg_t     producer_arg;
    consumer_arg_t    *consumer_args = NULL;
    dispatch_flow_t   *dispatch_flows = NULL;
    uint32_t           worker_count = DEFAULT_WORKER_COUNT;
    uint32_t           iterations_per_worker = DEFAULT_ITERATIONS_PER_WORKER;
    uint32_t           slot_count = DEFAULT_BENCH_SLOT_COUNT;
    uint32_t           payload_len = DEFAULT_PAYLOAD_LEN;
    uint64_t           total_start_ns;
    uint64_t           total_end_ns;
    uint64_t           process_cpu_start_ns;
    uint64_t           process_cpu_end_ns;
    uint64_t           total_packets;
    uint64_t           total_bytes = 0;
    uint64_t           total_latency_ns = 0;
    uint64_t           max_latency_ns = 0;
    uint64_t           total_enq_ok = 0;
    uint64_t           total_deq_ok = 0;
    uint64_t           total_drop_full = 0;
    uint64_t           total_wait_full = 0;
    double             total_ms;
    double             process_cpu_ms;
    double             producer_ms;
    double             producer_cpu_ms;
    double             producer_cpu_pct;
    double             process_cpu_pct;
    double             pipeline_pps;
    double             throughput_mib_s;
    double             avg_latency_us;
    int                rc;

    memset(&queues, 0, sizeof(queues));
    memset(&producer_arg, 0, sizeof(producer_arg));

    if (argc > 1 && 0 != parse_u32_arg(argv[1], &worker_count)) {
        fprintf(stderr, "invalid worker_count: %s\n", argv[1]);
        return 1;
    }
    if (argc > 2 && 0 != parse_u32_arg(argv[2], &iterations_per_worker)) {
        fprintf(stderr, "invalid iterations_per_worker: %s\n", argv[2]);
        return 1;
    }
    if (argc > 3 && 0 != parse_u32_arg(argv[3], &payload_len)) {
        fprintf(stderr, "invalid payload_len: %s\n", argv[3]);
        return 1;
    }
    if (argc > 4 && 0 != parse_u32_arg(argv[4], &slot_count)) {
        fprintf(stderr, "invalid slot_count: %s\n", argv[4]);
        return 1;
    }

    if (worker_count < MIN_QUEUE_COUNT || worker_count > MAX_QUEUE_COUNT) {
        fprintf(stderr, "worker_count must be between %d and %d\n",
                MIN_QUEUE_COUNT, MAX_QUEUE_COUNT);
        return 1;
    }
    if (payload_len < BENCH_META_BYTES || payload_len > PACKET_MAX_BYTES) {
        fprintf(stderr, "payload_len must be between %u and %u\n",
                BENCH_META_BYTES, PACKET_MAX_BYTES);
        return 1;
    }

    rc = packet_queue_set_init(&queues, worker_count, slot_count, 1);
    CHECK(0 == rc, "packet_queue_set_init failed");

    consumer_tids =
        (pthread_t *)calloc(worker_count, sizeof(*consumer_tids));
    consumer_args =
        (consumer_arg_t *)calloc(worker_count, sizeof(*consumer_args));
    dispatch_flows =
        (dispatch_flow_t *)calloc(worker_count, sizeof(*dispatch_flows));
    CHECK(NULL != consumer_tids, "consumer_tids alloc failed");
    CHECK(NULL != consumer_args, "consumer_args alloc failed");
    CHECK(NULL != dispatch_flows, "dispatch_flows alloc failed");
    CHECK(0 == build_dispatch_flows(dispatch_flows, worker_count),
          "build_dispatch_flows failed");

    producer_arg.queues = &queues;
    producer_arg.flows = dispatch_flows;
    producer_arg.worker_count = worker_count;
    producer_arg.iterations_per_worker = iterations_per_worker;
    producer_arg.payload_len = payload_len;

    total_packets = (uint64_t)worker_count * (uint64_t)iterations_per_worker;

    for (uint32_t i = 0; i < worker_count; i++) {
        consumer_args[i].ring = &queues.q[i];
        consumer_args[i].worker_idx = i;
        consumer_args[i].iterations = iterations_per_worker;
        consumer_args[i].payload_len = payload_len;
    }

    total_start_ns = now_ns();
    process_cpu_start_ns = now_process_cpu_ns();

    for (uint32_t i = 0; i < worker_count; i++) {
        CHECK(0 == pthread_create(&consumer_tids[i], NULL, consumer_thread,
                                  &consumer_args[i]),
              "consumer pthread_create failed");
    }
    CHECK(0 == pthread_create(&producer_tid, NULL, producer_thread,
                              &producer_arg),
          "producer pthread_create failed");

    CHECK(0 == pthread_join(producer_tid, NULL), "producer pthread_join failed");
    for (uint32_t i = 0; i < worker_count; i++) {
        CHECK(0 == pthread_join(consumer_tids[i], NULL),
              "consumer pthread_join failed");
    }

    total_end_ns = now_ns();
    process_cpu_end_ns = now_process_cpu_ns();

    CHECK(0 == producer_arg.rc, "producer failed");
    for (uint32_t i = 0; i < worker_count; i++) {
        CHECK(0 == consumer_args[i].rc, "consumer failed");
    }

    for (uint32_t i = 0; i < worker_count; i++) {
        total_bytes += consumer_args[i].bytes;
        total_latency_ns += consumer_args[i].latency_sum_ns;
        if (consumer_args[i].latency_max_ns > max_latency_ns) {
            max_latency_ns = consumer_args[i].latency_max_ns;
        }
        total_enq_ok += queues.q[i].stats.enq_ok;
        total_deq_ok += queues.q[i].stats.deq_ok;
        total_drop_full += queues.q[i].stats.drop_full;
        total_wait_full += queues.q[i].stats.wait_full;
    }

    CHECK(total_packets == total_enq_ok, "total_enq_ok mismatch");
    CHECK(total_packets == total_deq_ok, "total_deq_ok mismatch");

    total_ms = (double)(total_end_ns - total_start_ns) / 1000000.0;
    process_cpu_ms =
        (double)(process_cpu_end_ns - process_cpu_start_ns) / 1000000.0;
    producer_ms =
        (double)(producer_arg.wall_end_ns - producer_arg.wall_start_ns) /
        1000000.0;
    producer_cpu_ms =
        (double)(producer_arg.cpu_end_ns - producer_arg.cpu_start_ns) /
        1000000.0;
    producer_cpu_pct =
        100.0 * (double)(producer_arg.cpu_end_ns - producer_arg.cpu_start_ns) /
        (double)(producer_arg.wall_end_ns - producer_arg.wall_start_ns);
    process_cpu_pct =
        100.0 * (double)(process_cpu_end_ns - process_cpu_start_ns) /
        (double)(total_end_ns - total_start_ns);
    pipeline_pps =
        ((double)total_packets * 1000000000.0) /
        (double)(total_end_ns - total_start_ns);
    throughput_mib_s =
        ((double)total_bytes * 1000000000.0) /
        ((double)(total_end_ns - total_start_ns) * 1024.0 * 1024.0);
    avg_latency_us =
        ((double)total_latency_ns / (double)total_packets) / 1000.0;

    puts("[test_packet_ring_multibehch]");
    table_line();
    table_row_str("metric", "value");
    table_line();
    table_row_u64("worker_count", worker_count);
    table_row_u64("iterations_worker", iterations_per_worker);
    table_row_u64("total_packets", total_packets);
    table_row_u64("slot_count", slot_count);
    table_row_u64("payload_len", payload_len);
    table_row_str("dispatch_mode", "flow_hash_5tuple");
    table_row_f64("total_ms", total_ms, "ms");
    table_row_f64("producer_ms", producer_ms, "ms");
    table_row_f64("producer_cpu_ms", producer_cpu_ms, "ms");
    table_row_f64("process_cpu_ms", process_cpu_ms, "ms");
    table_row_f64("producer_cpu_pct", producer_cpu_pct, "%");
    table_row_f64("process_cpu_pct", process_cpu_pct, "%");
    table_row_f64("pipeline_pps", pipeline_pps, "pps");
    table_row_f64("throughput_mib_s", throughput_mib_s, "MiB/s");
    table_row_f64("avg_queue_lat_us", avg_latency_us, "us");
    table_row_f64("max_queue_lat_us", (double)max_latency_ns / 1000.0, "us");
    table_row_u64("total_enq_ok", total_enq_ok);
    table_row_u64("total_deq_ok", total_deq_ok);
    table_row_u64("total_drop_full", total_drop_full);
    table_row_u64("total_wait_full", total_wait_full);
    table_line();

    puts("| worker | wall_ms  | cpu_ms   | cpu_pct | avg_lat_us | max_lat_us |");
    puts("+--------+----------+----------+---------+------------+------------+");
    for (uint32_t i = 0; i < worker_count; i++) {
        double worker_ms =
            (double)(consumer_args[i].wall_end_ns - consumer_args[i].wall_start_ns) /
            1000000.0;
        double worker_cpu_ms =
            (double)(consumer_args[i].cpu_end_ns - consumer_args[i].cpu_start_ns) /
            1000000.0;
        double worker_cpu_pct =
            100.0 *
            (double)(consumer_args[i].cpu_end_ns - consumer_args[i].cpu_start_ns) /
            (double)(consumer_args[i].wall_end_ns - consumer_args[i].wall_start_ns);
        double worker_avg_lat_us =
            ((double)consumer_args[i].latency_sum_ns /
             (double)consumer_args[i].iterations) /
            1000.0;
        double worker_max_lat_us =
            (double)consumer_args[i].latency_max_ns / 1000.0;

        printf("| %6u | %8.3f | %8.3f | %7.3f | %10.3f | %10.3f |\n",
               i, worker_ms, worker_cpu_ms, worker_cpu_pct, worker_avg_lat_us,
               worker_max_lat_us);
    }
    puts("+--------+----------+----------+---------+------------+------------+");

    packet_queue_set_destroy(&queues);
    free(dispatch_flows);
    free(consumer_tids);
    free(consumer_args);
    return 0;
}

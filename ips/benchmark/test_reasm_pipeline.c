/**
 * @file test_reasm_pipeline.c
 * @brief TCP 재조립 + HTTP 파싱 경로 처리량 및 요청 완성 지연 측정
 */
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "httgw.h"
#include "net_compat.h"
#include "pipeline_bench_common.h"

#define CHECK(cond, msg)                          \
    do {                                          \
        if (!(cond)) {                            \
            fprintf(stderr, "FAIL: %s\n", (msg)); \
            return 1;                             \
        }                                         \
    } while (0)

#define DEFAULT_REQUEST_COUNT 10000U
#define DEFAULT_URI_PAD_LEN 1460U
#define DEFAULT_SEGMENT_BYTES 1460U
#define DEFAULT_RING_SLOT_COUNT 1024U

/**
 * @brief 재조립 벤치마크 누적 결과를 저장하는 컨텍스트
 */
typedef struct reasm_ctx {
    uint64_t request_count;
    uint64_t stream_error_count;
    uint64_t current_request_start_ns;
    uint64_t total_reasm_ns;
    uint64_t max_reasm_ns;
} reasm_ctx_t;

/**
 * @brief synthetic TCP 패킷 생성에 필요한 필드 묶음
 */
typedef struct tcp_pkt_spec {
    uint32_t       sip;
    uint16_t       sport;
    uint32_t       dip;
    uint16_t       dport;
    uint32_t       seq;
    uint32_t       ack;
    uint8_t        flags;
    uint16_t       win;
    const uint8_t *payload;
    uint32_t       payload_len;
} tcp_pkt_spec_t;

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

    if (NULL != suffix && '\0' != suffix[0]) {
        snprintf(buf, sizeof(buf), "%.3f %s", value, suffix);
    } else {
        snprintf(buf, sizeof(buf), "%.3f", value);
    }
    table_row_str(metric, buf);
}

static uint16_t checksum16(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t       sum = 0;

    while (len > 1U) {
        sum += (uint16_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }
    if (1U == len) {
        sum += (uint16_t)(p[0] << 8);
    }

    while ((sum >> 16) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

static uint16_t tcp_checksum_ipv4(const IPHDR *ip, const TCPHDR *tcp,
                                  const uint8_t *payload,
                                  uint32_t       payload_len) {
    struct {
        uint32_t saddr;
        uint32_t daddr;
        uint8_t  zero;
        uint8_t  proto;
        uint16_t tcp_len;
    } ph;
    uint32_t       sum = 0;
    const uint8_t *p;
    size_t         len;
    uint16_t       tcp_len = (uint16_t)(TCP_HDR_SIZE + payload_len);

    memset(&ph, 0, sizeof(ph));
    ph.saddr   = IP_SADDR(ip);
    ph.daddr   = IP_DADDR(ip);
    ph.proto   = IPPROTO_TCP;
    ph.tcp_len = htons(tcp_len);

    p = (const uint8_t *)&ph;
    len = sizeof(ph);
    while (len > 1U) {
        sum += (uint16_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }

    p = (const uint8_t *)tcp;
    len = TCP_HDR_SIZE;
    while (len > 1U) {
        sum += (uint16_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }

    p = payload;
    len = payload_len;
    while (len > 1U) {
        sum += (uint16_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }
    if (1U == len) {
        sum += (uint16_t)(p[0] << 8);
    }

    while ((sum >> 16) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

/**
 * @brief synthetic Ethernet+IPv4+TCP 패킷을 생성한다.
 *
 * @param out 결과 패킷 버퍼
 * @param out_cap 결과 버퍼 크기
 * @param sp 패킷 필드 입력값
 * @param out_len 생성된 패킷 길이를 돌려받을 포인터
 * @return int 0=성공, 음수=실패
 */
static int build_tcp_packet(uint8_t *out, size_t out_cap,
                            const tcp_pkt_spec_t *sp, uint32_t *out_len) {
    struct ether_header *eth;
    IPHDR               *ip;
    TCPHDR              *tcp;
    size_t               total;

    if (NULL == out || NULL == sp || NULL == out_len) {
        return -1;
    }

    total = sizeof(struct ether_header) + IP_HDR_SIZE + TCP_HDR_SIZE +
            sp->payload_len;
    if (out_cap < total) {
        return -1;
    }

    memset(out, 0, total);

    eth = (struct ether_header *)out;
    eth->ether_type = htons(ETHERTYPE_IP);

    ip = (IPHDR *)(out + sizeof(struct ether_header));
    IP_VER(ip) = 4;
    IP_IHL(ip) = 5;
    IP_TTL_FIELD(ip) = 64;
    IP_PROTO(ip) = IPPROTO_TCP;
    IP_TOTLEN(ip) =
        htons((uint16_t)(IP_HDR_SIZE + TCP_HDR_SIZE + sp->payload_len));
    IP_SADDR(ip) = htonl(sp->sip);
    IP_DADDR(ip) = htonl(sp->dip);
    IP_CHECK(ip) = checksum16(ip, sizeof(*ip));

    tcp = (TCPHDR *)((uint8_t *)ip + IP_HDR_SIZE);
    TCP_SPORT(tcp) = htons(sp->sport);
    TCP_DPORT(tcp) = htons(sp->dport);
    TCP_SEQ(tcp) = htonl(sp->seq);
    TCP_ACK(tcp) = htonl(sp->ack);
    TCP_DOFF(tcp) = 5;
    TCP_WIN(tcp) = htons(sp->win);
    TCP_SET_FLAGS(tcp, sp->flags);

    if (0U != sp->payload_len && NULL != sp->payload) {
        memcpy((uint8_t *)tcp + TCP_HDR_SIZE, sp->payload, sp->payload_len);
    }

    TCP_CHECK(tcp) = tcp_checksum_ipv4(
        ip, tcp, (const uint8_t *)tcp + TCP_HDR_SIZE, sp->payload_len);

    *out_len = (uint32_t)total;
    return 0;
}

/**
 * @brief HTTP 요청 완성 시 호출되는 콜백
 * 요청 완성까지 걸린 시간을 재조립 지연으로 누적한다.
 *
 * @param flow
 * @param dir
 * @param msg
 * @param query
 * @param query_len
 * @param user reasm_ctx_t*
 */
static void on_request_cb(const flow_key_t *flow, tcp_dir_t dir,
                          const http_message_t *msg, const char *query,
                          size_t query_len, void *user) {
    reasm_ctx_t *ctx = (reasm_ctx_t *)user;
    uint64_t     done_ns;
    uint64_t     reasm_ns;

    (void)flow;
    (void)dir;
    (void)msg;
    (void)query;
    (void)query_len;

    done_ns = now_ns();
    ctx->request_count++;
    if (0U != ctx->current_request_start_ns &&
        done_ns >= ctx->current_request_start_ns) {
        reasm_ns = done_ns - ctx->current_request_start_ns;
        ctx->total_reasm_ns += reasm_ns;
        if (reasm_ns > ctx->max_reasm_ns) {
            ctx->max_reasm_ns = reasm_ns;
        }
    }
}

/**
 * @brief 재조립 또는 HTTP 파싱 오류를 누적 기록하는 콜백
 *
 * @param stage
 * @param detail
 * @param user reasm_ctx_t*
 */
static void on_error_cb(const char *stage, const char *detail, void *user) {
    reasm_ctx_t *ctx = (reasm_ctx_t *)user;

    (void)stage;
    (void)detail;
    ctx->stream_error_count++;
}

/**
 * @brief HTTP 요청 하나를 여러 TCP 세그먼트로 나눠 httgw에 투입한다.
 *
 * @param gw HTTP 게이트웨이 인스턴스
 * @param ctx 재조립 측정 컨텍스트
 * @param request 요청 원문 버퍼
 * @param request_len 요청 길이
 * @param segment_payload_len 세그먼트당 payload 크기
 * @param base_seq 시작 sequence 번호
 * @param ts_ms 패킷 타임스탬프 누적값
 * @param packet_count 투입 패킷 수 누적값
 * @return int 0=성공, 음수=실패
 */
static int feed_request(packet_ring_t *ring, httgw_t *gw, reasm_ctx_t *ctx,
                        const uint8_t *request, size_t request_len,
                        uint32_t segment_payload_len, uint32_t base_seq,
                        uint64_t *ts_ms,
                        uint64_t *packet_count) {
    tcp_pkt_spec_t sp;
    uint8_t        pkt[2048];
    uint32_t       pkt_len;
    size_t         off = 0;

    memset(&sp, 0, sizeof(sp));
    sp.sip = 0x0A000001;
    sp.sport = 12345;
    sp.dip = 0x0A000002;
    sp.dport = 8080;
    sp.ack = 1;
    sp.win = 502;

    ctx->current_request_start_ns = now_ns();

    while (off < request_len) {
        size_t chunk = request_len - off;
        int    rc;

        if (chunk > segment_payload_len) {
            chunk = segment_payload_len;
        }

        sp.seq = base_seq + (uint32_t)off;
        sp.flags = (off + chunk == request_len) ? (TCP_ACK | TCP_PSH)
                                                : TCP_ACK;
        sp.payload = request + off;
        sp.payload_len = (uint32_t)chunk;

        if (build_tcp_packet(pkt, sizeof(pkt), &sp, &pkt_len) != 0) {
            return -1;
        }

        rc = ingest_packet_via_ring(ring, gw, pkt, pkt_len, *ts_ms);
        if (1 != rc) {
            return -1;
        }

        (*packet_count)++;
        (*ts_ms)++;
        off += chunk;
    }

    return 0;
}

/**
 * @brief 재조립 + HTTP 파싱 경로 처리량과 요청 완성 지연을 측정하는 메인 함수
 *
 * @param argc
 * @param argv argv[1]=request_count argv[2]=uri_pad_len argv[3]=segment_payload_len
 * @return int
 */
int main(int argc, char **argv) {
    uint32_t          request_count = DEFAULT_REQUEST_COUNT;
    uint32_t          uri_pad_len = DEFAULT_URI_PAD_LEN;
    uint32_t          segment_payload_len = DEFAULT_SEGMENT_BYTES;
    reasm_ctx_t       ctx;
    httgw_cfg_t       hcfg;
    httgw_callbacks_t cbs;
    httgw_t          *gw = NULL;
    packet_ring_t     ring;
    char             *request = NULL;
    size_t            request_len = 0;
    size_t            segments_per_request;
    uint64_t          total_start_ns;
    uint64_t          total_end_ns;
    uint64_t          process_cpu_start_ns;
    uint64_t          process_cpu_end_ns;
    uint64_t          ts_ms = 1;
    uint64_t          total_packets = 0;
    uint32_t          next_seq = 1;
    double            total_ms;
    double            process_cpu_ms;
    double            process_cpu_pct;
    double            packet_pps;
    double            request_rps;
    double            payload_mib_s;
    double            avg_reasm_us;

    if (argc > 1 && 0 != parse_u32_arg(argv[1], &request_count)) {
        fprintf(stderr, "invalid request_count: %s\n", argv[1]);
        return 1;
    }
    if (argc > 2 && 0 != parse_u32_arg(argv[2], &uri_pad_len)) {
        fprintf(stderr, "invalid uri_pad_len: %s\n", argv[2]);
        return 1;
    }
    if (argc > 3 && 0 != parse_u32_arg(argv[3], &segment_payload_len)) {
        fprintf(stderr, "invalid segment_payload_len: %s\n", argv[3]);
        return 1;
    }
    if (0U == segment_payload_len) {
        fprintf(stderr, "segment_payload_len must be > 0\n");
        return 1;
    }

    memset(&ctx, 0, sizeof(ctx));
    memset(&hcfg, 0, sizeof(hcfg));
    memset(&cbs, 0, sizeof(cbs));
    memset(&ring, 0, sizeof(ring));

    hcfg.max_buffer_bytes = 12U * 1024U * 1024U;
    hcfg.max_body_bytes = 12U * 1024U * 1024U;
    hcfg.reasm_mode = REASM_MODE_LATE_START;
    cbs.on_request = on_request_cb;
    cbs.on_error = on_error_cb;

    gw = httgw_create(&hcfg, &cbs, &ctx);
    CHECK(NULL != gw, "httgw_create failed");
    CHECK(0 == packet_ring_init(&ring, DEFAULT_RING_SLOT_COUNT, 0),
          "packet_ring_init failed");

    request = build_pipeline_http_request(uri_pad_len, &request_len);
    CHECK(NULL != request, "build_pipeline_http_request failed");

    segments_per_request =
        (request_len + (size_t)segment_payload_len - 1U) /
        (size_t)segment_payload_len;

    total_start_ns = now_ns();
    process_cpu_start_ns = now_process_cpu_ns();

    for (uint32_t i = 0; i < request_count; i++) {
        if (0 != feed_request(&ring, gw, &ctx, (const uint8_t *)request,
                              request_len,
                              segment_payload_len, next_seq, &ts_ms,
                              &total_packets)) {
            fprintf(stderr, "feed_request failed at request=%u\n", i);
            free(request);
            packet_ring_destroy(&ring);
            httgw_destroy(gw);
            return 1;
        }
        next_seq += (uint32_t)request_len;
    }

    total_end_ns = now_ns();
    process_cpu_end_ns = now_process_cpu_ns();

    CHECK(ctx.request_count == request_count, "request_count mismatch");

    total_ms = (double)(total_end_ns - total_start_ns) / 1000000.0;
    process_cpu_ms =
        (double)(process_cpu_end_ns - process_cpu_start_ns) / 1000000.0;
    process_cpu_pct =
        100.0 * (double)(process_cpu_end_ns - process_cpu_start_ns) /
        (double)(total_end_ns - total_start_ns);
    packet_pps =
        ((double)total_packets * 1000000000.0) /
        (double)(total_end_ns - total_start_ns);
    request_rps =
        ((double)request_count * 1000000000.0) /
        (double)(total_end_ns - total_start_ns);
    payload_mib_s =
        ((double)request_len * (double)request_count * 1000000000.0) /
        ((double)(total_end_ns - total_start_ns) * 1024.0 * 1024.0);
    avg_reasm_us = (0U == ctx.request_count)
                       ? 0.0
                       : ((double)ctx.total_reasm_ns /
                          (double)ctx.request_count) /
                             1000.0;

    puts("[benchmark_ring_reasm]");
    table_line();
    table_row_str("metric", "value");
    table_line();
    table_row_u64("requests", request_count);
    table_row_u64("request_len", (unsigned long long)request_len);
    table_row_u64("segments_per_req", (unsigned long long)segments_per_request);
    table_row_u64("segment_bytes", segment_payload_len);
    table_row_u64("ring_slot_count", ring.slot_count);
    table_row_u64("total_packets", total_packets);
    table_row_f64("total_ms", total_ms, "ms");
    table_row_f64("process_cpu_ms", process_cpu_ms, "ms");
    table_row_f64("process_cpu_pct", process_cpu_pct, "%");
    table_row_f64("packet_pps", packet_pps, "pps");
    table_row_f64("request_rps", request_rps, "rps");
    table_row_f64("payload_mib_s", payload_mib_s, "MiB/s");
    table_row_f64("avg_reasm_us", avg_reasm_us, "us");
    table_row_f64("max_reasm_us", (double)ctx.max_reasm_ns / 1000.0, "us");
    table_row_u64("ring_enq_ok", ring.stats.enq_ok);
    table_row_u64("ring_deq_ok", ring.stats.deq_ok);
    table_row_u64("ring_drop_full", ring.stats.drop_full);
    table_row_u64("ring_wait_full", ring.stats.wait_full);
    table_row_u64("request_seen", ctx.request_count);
    table_row_u64("stream_errors", ctx.stream_error_count);
    table_line();

    free(request);
    packet_ring_destroy(&ring);
    httgw_destroy(gw);
    return 0;
}

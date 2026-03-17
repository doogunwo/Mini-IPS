/**
 * @file test_httgw_reasm_sizes.c
 * @brief URI 크기와 세그먼트 크기 변화에 따른 재조립 단위 테스트
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

#define CHECK(cond, msg)                          \
    do {                                          \
        if (!(cond)) {                            \
            fprintf(stderr, "FAIL: %s\n", (msg)); \
            return 1;                             \
        }                                         \
    } while (0)

/**
 * @brief 요청 수와 에러 수를 기록하는 테스트 컨텍스트
 */
typedef struct {
    int    req_count;
    int    err_count;
    size_t last_uri_len;
    char   first_method[16];
} test_ctx_t;

/**
 * @brief synthetic TCP 세그먼트 생성용 입력 필드 묶음
 */
typedef struct {
    uint32_t       sip;
    uint16_t       sport;
    uint32_t       dip;
    uint16_t       dport;
    uint32_t       seq;
    uint32_t       ack;
    uint8_t        flags;
    const uint8_t *payload;
    uint32_t       payload_len;
} tcp_pkt_spec_t;

static const size_t g_uri_sizes[] = {900U, 1800U, 3600U, 7200U, 131072U};

static const size_t g_segment_sizes[] = {256U, 1024U, 1460U};

static uint64_t now_ns(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

/**
 * @brief HTTP 요청 완성 시 호출되는 테스트 콜백
 *
 * @param flow
 * @param dir
 * @param msg
 * @param query
 * @param query_len
 * @param user test_ctx_t*
 */
static void on_request_cb(const flow_key_t *flow, tcp_dir_t dir,
                          const http_message_t *msg, const char *query,
                          size_t query_len, void *user) {
    test_ctx_t *ctx = (test_ctx_t *)user;
    (void)flow;
    (void)dir;
    (void)query;
    (void)query_len;

    ctx->req_count++;
    ctx->last_uri_len = strlen(msg->uri);
    snprintf(ctx->first_method, sizeof(ctx->first_method), "%.15s",
             msg->method);
}

/**
 * @brief 재조립 또는 파싱 오류를 기록하는 테스트 콜백
 *
 * @param stage
 * @param detail
 * @param user test_ctx_t*
 */
static void on_error_cb(const char *stage, const char *detail, void *user) {
    test_ctx_t *ctx = (test_ctx_t *)user;
    (void)stage;
    (void)detail;
    ctx->err_count++;
}

static int build_tcp_packet(const tcp_pkt_spec_t *sp, uint8_t **out_pkt,
                            uint32_t *out_len) {
    struct ether_header *eth;
    IPHDR               *ip;
    TCPHDR              *tcp;
    uint8_t             *pkt;
    size_t               total;

    if (sp == NULL || out_pkt == NULL || out_len == NULL) {
        return -1;
    }

    total = sizeof(struct ether_header) + IP_HDR_SIZE + TCP_HDR_SIZE +
            sp->payload_len;
    pkt = (uint8_t *)calloc(1, total);
    if (pkt == NULL) {
        return -1;
    }

    eth             = (struct ether_header *)pkt;
    eth->ether_type = htons(ETHERTYPE_IP);

    ip               = (IPHDR *)(pkt + sizeof(struct ether_header));
    IP_VER(ip)       = 4;
    IP_IHL(ip)       = 5;
    IP_TTL_FIELD(ip) = 64;
    IP_PROTO(ip)     = IPPROTO_TCP;
    IP_TOTLEN(ip) =
        htons((uint16_t)(IP_HDR_SIZE + TCP_HDR_SIZE + sp->payload_len));
    IP_SADDR(ip) = htonl(sp->sip);
    IP_DADDR(ip) = htonl(sp->dip);

    tcp            = (TCPHDR *)((uint8_t *)ip + IP_HDR_SIZE);
    TCP_SPORT(tcp) = htons(sp->sport);
    TCP_DPORT(tcp) = htons(sp->dport);
    TCP_SEQ(tcp)   = htonl(sp->seq);
    TCP_ACK(tcp)   = htonl(sp->ack);
    TCP_DOFF(tcp)  = 5;
    TCP_SET_FLAGS(tcp, sp->flags);
    TCP_WIN(tcp) = htons(502);

    if (sp->payload_len > 0U && sp->payload != NULL) {
        memcpy((uint8_t *)tcp + TCP_HDR_SIZE, sp->payload, sp->payload_len);
    }

    *out_pkt = pkt;
    *out_len = (uint32_t)total;
    return 0;
}

static int feed_segment(httgw_t *gw, const tcp_pkt_spec_t *sp, uint64_t ts_ms) {
    uint8_t *pkt     = NULL;
    uint32_t pkt_len = 0;
    int      rc;

    if (build_tcp_packet(sp, &pkt, &pkt_len) != 0) {
        return -1;
    }

    rc = httgw_ingest_packet(gw, pkt, pkt_len, ts_ms);
    free(pkt);
    return rc;
}

static char *build_http_request(size_t uri_len, size_t *out_len) {
    const char *prefix = "/bench?x=";
    const char *suffix = "%27%20union%20select%201%2C2%2C3%20from%20dual--";
    const char *head_a = "GET ";
    const char *head_b =
        " HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: reasm-size-test\r\n"
        "Connection: keep-alive\r\n"
        "\r\n";
    size_t prefix_len = strlen(prefix);
    size_t suffix_len = strlen(suffix);
    size_t pad_len;
    size_t total_len;
    char  *req;
    char  *p;

    if (uri_len <= prefix_len + suffix_len || out_len == NULL) {
        return NULL;
    }

    pad_len   = uri_len - prefix_len - suffix_len;
    total_len = strlen(head_a) + uri_len + strlen(head_b);
    req       = (char *)malloc(total_len + 1U);
    if (req == NULL) {
        return NULL;
    }

    p = req;
    memcpy(p, head_a, strlen(head_a));
    p += strlen(head_a);
    memcpy(p, prefix, prefix_len);
    p += prefix_len;
    memset(p, 'A', pad_len);
    p += pad_len;
    memcpy(p, suffix, suffix_len);
    p += suffix_len;
    memcpy(p, head_b, strlen(head_b));
    p += strlen(head_b);
    *p = '\0';

    *out_len = total_len;
    return req;
}

static void init_gateway(httgw_cfg_t *cfg, httgw_callbacks_t *cbs,
                         test_ctx_t *ctx) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->max_buffer_bytes = 12U * 1024U * 1024U;
    cfg->max_body_bytes   = 12U * 1024U * 1024U;
    cfg->reasm_mode       = REASM_MODE_LATE_START;

    memset(cbs, 0, sizeof(*cbs));
    cbs->on_request = on_request_cb;
    cbs->on_error   = on_error_cb;

    memset(ctx, 0, sizeof(*ctx));
}

static int run_reasm_case(size_t uri_len, size_t seg_len) {
    httgw_cfg_t       cfg;
    httgw_callbacks_t cbs;
    httgw_t          *gw;
    test_ctx_t        ctx;
    tcp_pkt_spec_t    sp;
    char             *req;
    size_t            req_len;
    size_t            off   = 0;
    uint32_t          seq0  = 1000;
    uint64_t          ts_ms = 1;
    uint64_t          start_ns;
    uint64_t          end_ns;
    double            elapsed_ms;

    init_gateway(&cfg, &cbs, &ctx);
    gw = httgw_create(&cfg, &cbs, &ctx);
    CHECK(gw != NULL, "httgw_create failed");

    req = build_http_request(uri_len, &req_len);
    if (req == NULL) {
        httgw_destroy(gw);
        CHECK(0, "build_http_request failed");
    }

    memset(&sp, 0, sizeof(sp));
    sp.sip   = 0xAC1F003A;
    sp.sport = 40000;
    sp.dip   = 0xAC1F003C;
    sp.dport = 8080;
    sp.ack   = 1;
    sp.flags = TCP_ACK | TCP_PSH;

    start_ns = now_ns();
    while (off < req_len) {
        size_t chunk = req_len - off;

        if (chunk > seg_len) {
            chunk = seg_len;
        }

        sp.seq         = seq0 + (uint32_t)off;
        sp.payload     = (const uint8_t *)req + off;
        sp.payload_len = (uint32_t)chunk;
        CHECK(feed_segment(gw, &sp, ts_ms++) == 1, "feed_segment failed");
        off += chunk;
    }

    CHECK(ctx.req_count == 1, "expected exactly one request callback");
    CHECK(ctx.err_count == 0, "unexpected error callback");
    CHECK(strcmp(ctx.first_method, "GET") == 0, "method mismatch");
    CHECK(ctx.last_uri_len == uri_len, "uri length mismatch");

    end_ns = now_ns();
    elapsed_ms = (double)(end_ns - start_ns) / 1000000.0;
    fprintf(stderr,
            "[test_httgw_reasm_sizes] uri_len=%zu req_len=%zu seg_len=%zu "
            "segments=%zu req_count=%d err_count=%d method=%s "
            "elapsed_ms=%.3f\n",
            uri_len, req_len, seg_len, (req_len + seg_len - 1U) / seg_len,
            ctx.req_count, ctx.err_count, ctx.first_method, elapsed_ms);

    free(req);
    httgw_destroy(gw);
    return 0;
}

int main(void) {
    size_t i;
    size_t j;

    for (i = 0; i < sizeof(g_uri_sizes) / sizeof(g_uri_sizes[0]); i++) {
        for (j = 0; j < sizeof(g_segment_sizes) / sizeof(g_segment_sizes[0]);
             j++) {
            if (run_reasm_case(g_uri_sizes[i], g_segment_sizes[j]) != 0) {
                fprintf(stderr, "failed: uri=%zu seg=%zu\n", g_uri_sizes[i],
                        g_segment_sizes[j]);
                return 1;
            }
        }
    }

    printf("ok: test_httgw_reasm_sizes\n");
    return 0;
}

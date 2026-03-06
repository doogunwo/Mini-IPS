/**
 * @file test_ingest.c
 * @brief HTTP 게이트웨이 ingest 단위 테스트
 */
#define _DEFAULT_SOURCE
#include "httgw.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include "net_compat.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\\n", (msg)); \
        return 1; \
    } \
} while (0)

typedef struct {
    int req_count;
    int err_count;
    char last_uri[128];
} test_ctx_t;

static void on_request_cb(
    const flow_key_t *flow,
    tcp_dir_t dir,
    const http_message_t *msg,
    const char *query,
    size_t query_len,
    void *user)
{
    test_ctx_t *ctx = (test_ctx_t *)user;
    (void)flow;
    (void)dir;
    (void)query;
    (void)query_len;

    ctx->req_count++;
    snprintf(ctx->last_uri, sizeof(ctx->last_uri), "%.127s", msg->uri);
}

static void on_error_cb(const char *stage, const char *detail, void *user)
{
    test_ctx_t *ctx = (test_ctx_t *)user;
    (void)stage;
    (void)detail;
    ctx->err_count++;
}

static int build_tcp_packet(
    uint8_t *out,
    size_t out_cap,
    uint32_t sip,
    uint16_t sport,
    uint32_t dip,
    uint16_t dport,
    uint32_t seq,
    uint32_t ack,
    uint8_t flags,
    const uint8_t *payload,
    uint32_t payload_len,
    uint32_t *out_len)
{
    struct ether_header *eth;
    IPHDR *ip;
    TCPHDR *tcp;
    size_t total = sizeof(struct ether_header) + IP_HDR_SIZE + TCP_HDR_SIZE + payload_len;

    if (out_cap < total)
        return -1;

    memset(out, 0, total);

    eth = (struct ether_header *)out;
    eth->ether_type = htons(ETHERTYPE_IP);

    ip = (IPHDR *)(out + sizeof(struct ether_header));
    IP_VER(ip) = 4;
    IP_IHL(ip) = 5;
    IP_TTL_FIELD(ip) = 64;
    IP_PROTO(ip) = IPPROTO_TCP;
    IP_TOTLEN(ip) = htons((uint16_t)(IP_HDR_SIZE + TCP_HDR_SIZE + payload_len));
    IP_SADDR(ip) = htonl(sip);
    IP_DADDR(ip) = htonl(dip);

    tcp = (TCPHDR *)((uint8_t *)ip + IP_HDR_SIZE);
    TCP_SPORT(tcp) = htons(sport);
    TCP_DPORT(tcp) = htons(dport);
    TCP_SEQ(tcp) = htonl(seq);
    TCP_ACK(tcp) = htonl(ack);
    TCP_DOFF(tcp) = 5;
    TCP_SET_FLAGS(tcp, flags);

    if (payload_len > 0 && payload)
    {
        memcpy((uint8_t *)tcp + TCP_HDR_SIZE, payload, payload_len);
    }

    *out_len = (uint32_t)total;
    return 0;
}

static int test_ingest_single_request_with_duplicate_segment(void)
{
    httgw_cfg_t cfg;
    httgw_callbacks_t cbs;
    httgw_t *gw;
    test_ctx_t ctx;
    uint8_t pkt[2048];
    uint32_t pkt_len;
    const char *p1 = "GET /a?x=1 HTTP/1.1\r\nHost: localhost\r\n";
    const char *p2 = "\r\n";
    uint32_t seq0 = 1000;

    memset(&cfg, 0, sizeof(cfg));
    cfg.max_buffer_bytes = 4096;
    cfg.max_body_bytes = 1024;
    cfg.reasm_mode = REASM_MODE_LATE_START;

    memset(&cbs, 0, sizeof(cbs));
    cbs.on_request = on_request_cb;
    cbs.on_error = on_error_cb;

    memset(&ctx, 0, sizeof(ctx));
    gw = httgw_create(&cfg, &cbs, &ctx);
    CHECK(gw != NULL, "httgw_create failed");

    CHECK(build_tcp_packet(pkt, sizeof(pkt), 0x0A000001, 12345, 0x0A000002, 80,
                           seq0, 0, TCP_ACK | TCP_PSH,
                           (const uint8_t *)p1, (uint32_t)strlen(p1), &pkt_len) == 0,
          "build packet #1 failed");
    CHECK(httgw_ingest_packet(gw, pkt, pkt_len, 1) == 1, "ingest packet #1 failed");

    CHECK(httgw_ingest_packet(gw, pkt, pkt_len, 2) == 1, "ingest duplicate packet failed");

    CHECK(build_tcp_packet(pkt, sizeof(pkt), 0x0A000001, 12345, 0x0A000002, 80,
                           seq0 + (uint32_t)strlen(p1), 0, TCP_ACK | TCP_PSH,
                           (const uint8_t *)p2, (uint32_t)strlen(p2), &pkt_len) == 0,
          "build packet #2 failed");
    CHECK(httgw_ingest_packet(gw, pkt, pkt_len, 3) == 1, "ingest packet #2 failed");

    CHECK(ctx.req_count == 1, "expected exactly one request callback");
    CHECK(strcmp(ctx.last_uri, "/a?x=1") == 0, "request URI mismatch");

    httgw_destroy(gw);
    return 0;
}

static int test_ingest_malformed_request_increments_parse_err(void)
{
    httgw_cfg_t cfg;
    httgw_callbacks_t cbs;
    httgw_t *gw;
    test_ctx_t ctx;
    uint8_t pkt[1024];
    uint32_t pkt_len;
    const char *bad = "GET /oops HTTP/1.1\r\nHost localhost\r\n\r\n";
    const httgw_stats_t *st;

    memset(&cfg, 0, sizeof(cfg));
    cfg.max_buffer_bytes = 4096;
    cfg.max_body_bytes = 1024;
    cfg.reasm_mode = REASM_MODE_LATE_START;

    memset(&cbs, 0, sizeof(cbs));
    cbs.on_request = on_request_cb;
    cbs.on_error = on_error_cb;

    memset(&ctx, 0, sizeof(ctx));
    gw = httgw_create(&cfg, &cbs, &ctx);
    CHECK(gw != NULL, "httgw_create failed");

    CHECK(build_tcp_packet(pkt, sizeof(pkt), 0x0A000001, 22222, 0x0A000002, 80,
                           5000, 0, TCP_ACK | TCP_PSH,
                           (const uint8_t *)bad, (uint32_t)strlen(bad), &pkt_len) == 0,
          "build malformed packet failed");
    CHECK(httgw_ingest_packet(gw, pkt, pkt_len, 10) == 1, "ingest malformed packet failed");

    st = httgw_stats(gw);
    CHECK(st != NULL, "stats pointer is null");
    CHECK(st->parse_errs == 1, "expected parse_errs == 1");

    httgw_destroy(gw);
    return 0;
}

int main(void)
{
    if (test_ingest_single_request_with_duplicate_segment() != 0)
        return 1;
    if (test_ingest_malformed_request_increments_parse_err() != 0)
        return 1;

    printf("ok: test_ingest\\n");
    return 0;
}

/**
 * @file test_httgw_multi_sessions.c
 * @brief multiple TCP sessions ingest test
 */
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "httgw.h"
#include "net_compat.h"

#define CHECK(cond, msg)                          \
    do {                                          \
        if (!(cond)) {                            \
            fprintf(stderr, "FAIL: %s\n", (msg)); \
            return 1;                             \
        }                                         \
    } while (0)

typedef struct {
    int  req_count;
    int  err_count;
    int *seen;
    int  seen_cap;
} test_ctx_t;

static int parse_uri_index(const char *uri, int *out_idx) {
    if (!uri || !out_idx) {
        return -1;
    }
    if (strncmp(uri, "/s", 2) != 0) {
        return -1;
    }
    char *end = NULL;
    long  v   = strtol(uri + 2, &end, 10);
    if (end == uri + 2 || *end != '\0' || v < 0) {
        return -1;
    }
    *out_idx = (int)v;
    return 0;
}

static void on_request_cb(const flow_key_t *flow, tcp_dir_t dir,
                          const http_message_t *msg, const char *query,
                          size_t query_len, void *user) {
    test_ctx_t *ctx = (test_ctx_t *)user;
    (void)flow;
    (void)dir;
    (void)query;
    (void)query_len;

    ctx->req_count++;
    if (msg && msg->uri[0] != '\0') {
        int idx = -1;
        if (parse_uri_index(msg->uri, &idx) == 0 && idx < ctx->seen_cap) {
            ctx->seen[idx] = 1;
        }
    }
}

static void on_error_cb(const char *stage, const char *detail, void *user) {
    test_ctx_t *ctx = (test_ctx_t *)user;
    (void)stage;
    (void)detail;
    ctx->err_count++;
}

static int build_tcp_packet(uint8_t *out, size_t out_cap, uint32_t sip,
                            uint16_t sport, uint32_t dip, uint16_t dport,
                            uint32_t seq, uint32_t ack, uint8_t flags,
                            const uint8_t *payload, uint32_t payload_len,
                            uint32_t *out_len) {
    struct ether_header *eth;
    IPHDR               *ip;
    TCPHDR              *tcp;
    size_t               total =
        sizeof(struct ether_header) + IP_HDR_SIZE + TCP_HDR_SIZE + payload_len;

    if (out_cap < total) {
        return -1;
    }

    memset(out, 0, total);

    eth             = (struct ether_header *)out;
    eth->ether_type = htons(ETHERTYPE_IP);

    ip               = (IPHDR *)(out + sizeof(struct ether_header));
    IP_VER(ip)       = 4;
    IP_IHL(ip)       = 5;
    IP_TTL_FIELD(ip) = 64;
    IP_PROTO(ip)     = IPPROTO_TCP;
    IP_TOTLEN(ip) = htons((uint16_t)(IP_HDR_SIZE + TCP_HDR_SIZE + payload_len));
    IP_SADDR(ip)  = htonl(sip);
    IP_DADDR(ip)  = htonl(dip);

    tcp            = (TCPHDR *)((uint8_t *)ip + IP_HDR_SIZE);
    TCP_SPORT(tcp) = htons(sport);
    TCP_DPORT(tcp) = htons(dport);
    TCP_SEQ(tcp)   = htonl(seq);
    TCP_ACK(tcp)   = htonl(ack);
    TCP_DOFF(tcp)  = 5;
    TCP_SET_FLAGS(tcp, flags);

    if (payload_len > 0 && payload) {
        memcpy((uint8_t *)tcp + TCP_HDR_SIZE, payload, payload_len);
    }

    *out_len = (uint32_t)total;
    return 0;
}

static int test_multiple_sessions_interleaved(void) {
    const int         flow_count = 16;
    httgw_cfg_t       cfg;
    httgw_callbacks_t cbs;
    httgw_t          *gw;
    test_ctx_t        ctx;
    uint8_t           pkt[2048];
    uint32_t          pkt_len;
    uint32_t          base_seq = 1000;

    memset(&cfg, 0, sizeof(cfg));
    cfg.max_buffer_bytes = 4096;
    cfg.max_body_bytes   = 1024;
    cfg.reasm_mode       = REASM_MODE_LATE_START;

    memset(&cbs, 0, sizeof(cbs));
    cbs.on_request = on_request_cb;
    cbs.on_error   = on_error_cb;

    memset(&ctx, 0, sizeof(ctx));
    ctx.seen_cap = flow_count;
    ctx.seen     = (int *)calloc(flow_count, sizeof(int));
    if (!ctx.seen) {
        return 1;
    }

    gw = httgw_create(&cfg, &cbs, &ctx);
    if (!gw) {
        free(ctx.seen);
        return 1;
    }

    for (int i = 0; i < flow_count; i++) {
        char        p1[128];
        const char *p2    = "\r\n";
        uint32_t    sip   = 0x0a000001u + (uint32_t)i;
        uint32_t    dip   = 0x0a000100u;
        uint16_t    sport = (uint16_t)(10000 + i);
        uint16_t    dport = 80;
        uint32_t    seq   = base_seq + (uint32_t)(i * 100);

        snprintf(p1, sizeof(p1), "GET /s%d HTTP/1.1\r\nHost: x\r\n", i);
        if (build_tcp_packet(pkt, sizeof(pkt), sip, sport, dip, dport, seq, 0,
                             TCP_ACK, (const uint8_t *)p1, (uint32_t)strlen(p1),
                             &pkt_len) != 0) {
            httgw_destroy(gw);
            free(ctx.seen);
            return 1;
        }
        httgw_ingest_packet(gw, pkt, pkt_len, 10);

        if (build_tcp_packet(pkt, sizeof(pkt), sip, sport, dip, dport,
                             seq + (uint32_t)strlen(p1), 0, TCP_ACK,
                             (const uint8_t *)p2, (uint32_t)strlen(p2),
                             &pkt_len) != 0) {
            httgw_destroy(gw);
            free(ctx.seen);
            return 1;
        }
        httgw_ingest_packet(gw, pkt, pkt_len, 20);
    }

    CHECK(ctx.err_count == 0, "unexpected errors during ingest");
    CHECK(ctx.req_count == flow_count, "request count mismatch");
    for (int i = 0; i < flow_count; i++) {
        if (ctx.seen[i] != 1) {
            fprintf(stderr, "FAIL: missing flow index %d\n", i);
            httgw_destroy(gw);
            free(ctx.seen);
            return 1;
        }
    }

    fprintf(stderr,
            "[test_httgw_multi_sessions] flow_count=%d req_count=%d "
            "err_count=%d first_port=%u last_port=%u\n",
            flow_count, ctx.req_count, ctx.err_count, 10000U,
            (unsigned int)(10000 + flow_count - 1));

    httgw_destroy(gw);
    free(ctx.seen);
    return 0;
}

int main(void) {
    if (test_multiple_sessions_interleaved() != 0) {
        return 1;
    }
    printf("ok: test_httgw_multi_sessions\n");
    return 0;
}

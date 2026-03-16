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
    char last_uri[128];
} test_ctx_t;

typedef struct {
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

static void on_request_cb(const flow_key_t *flow, tcp_dir_t dir,
                          const http_message_t *msg, const char *query,
                          size_t query_len, void *user) {
    test_ctx_t *ctx = (test_ctx_t *)user;
    (void)flow;
    (void)dir;
    (void)query;
    (void)query_len;

    ctx->req_count++;
    snprintf(ctx->last_uri, sizeof(ctx->last_uri), "%.127s", msg->uri);
}

static void on_error_cb(const char *stage, const char *detail, void *user) {
    test_ctx_t *ctx = (test_ctx_t *)user;
    (void)stage;
    (void)detail;
    ctx->err_count++;
}

static uint16_t checksum16(const void *data, size_t len) {
    const uint8_t *p   = (const uint8_t *)data;
    uint32_t       sum = 0;

    while (len > 1) {
        sum += (uint16_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }
    if (len == 1) {
        sum += (uint16_t)(p[0] << 8);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
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

    p   = (const uint8_t *)&ph;
    len = sizeof(ph);
    while (len > 1) {
        sum += (uint16_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }

    p   = (const uint8_t *)tcp;
    len = TCP_HDR_SIZE;
    while (len > 1) {
        sum += (uint16_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }

    p   = payload;
    len = payload_len;
    while (len > 1) {
        sum += (uint16_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }
    if (len == 1) {
        sum += (uint16_t)(p[0] << 8);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

static int build_tcp_packet(uint8_t *out, size_t out_cap,
                            const tcp_pkt_spec_t *sp, uint32_t *out_len) {
    struct ether_header *eth;
    IPHDR               *ip;
    TCPHDR              *tcp;
    size_t               total;

    if (out == NULL || sp == NULL || out_len == NULL) {
        return -1;
    }

    total = sizeof(struct ether_header) + IP_HDR_SIZE + TCP_HDR_SIZE +
            sp->payload_len;
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
    IP_TOTLEN(ip) =
        htons((uint16_t)(IP_HDR_SIZE + TCP_HDR_SIZE + sp->payload_len));
    IP_SADDR(ip) = htonl(sp->sip);
    IP_DADDR(ip) = htonl(sp->dip);
    IP_CHECK(ip) = checksum16(ip, sizeof(*ip));

    tcp            = (TCPHDR *)((uint8_t *)ip + IP_HDR_SIZE);
    TCP_SPORT(tcp) = htons(sp->sport);
    TCP_DPORT(tcp) = htons(sp->dport);
    TCP_SEQ(tcp)   = htonl(sp->seq);
    TCP_ACK(tcp)   = htonl(sp->ack);
    TCP_DOFF(tcp)  = 5;
    TCP_WIN(tcp)   = htons(sp->win ? sp->win : 502);
    TCP_SET_FLAGS(tcp, sp->flags);

    if (sp->payload_len > 0 && sp->payload != NULL) {
        memcpy((uint8_t *)tcp + TCP_HDR_SIZE, sp->payload, sp->payload_len);
    }

    TCP_CHECK(tcp) = tcp_checksum_ipv4(
        ip, tcp, (const uint8_t *)tcp + TCP_HDR_SIZE, sp->payload_len);

    *out_len = (uint32_t)total;
    return 0;
}

static int feed_seg(httgw_t *gw, const tcp_pkt_spec_t *sp, uint64_t ts_ms) {
    uint8_t  pkt[2048];
    uint32_t pkt_len = 0;

    if (gw == NULL || sp == NULL) {
        return -1;
    }
    if (build_tcp_packet(pkt, sizeof(pkt), sp, &pkt_len) != 0) {
        return -1;
    }
    return httgw_ingest_packet(gw, pkt, pkt_len, ts_ms);
}

static void init_common(httgw_cfg_t *cfg, httgw_callbacks_t *cbs,
                        test_ctx_t *ctx, reasm_mode_t mode) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->max_buffer_bytes = 4096;
    cfg->max_body_bytes   = 1024;
    cfg->reasm_mode       = mode;

    memset(cbs, 0, sizeof(*cbs));
    cbs->on_request = on_request_cb;
    cbs->on_error   = on_error_cb;

    memset(ctx, 0, sizeof(*ctx));
}

static void init_spec(tcp_pkt_spec_t *sp) {
    memset(sp, 0, sizeof(*sp));
    sp->sip   = 0x0A000001;
    sp->sport = 12345;
    sp->dip   = 0x0A000002;
    sp->dport = 8080;
    sp->win   = 502;
}

static int test_late_start_accepts_http_without_syn(void) {
    httgw_cfg_t       cfg;
    httgw_callbacks_t cbs;
    httgw_t          *gw;
    test_ctx_t        ctx;
    tcp_pkt_spec_t    sp;
    const char       *req = "GET /late HTTP/1.1\r\nHost: x\r\n\r\n";

    init_common(&cfg, &cbs, &ctx, REASM_MODE_LATE_START);
    gw = httgw_create(&cfg, &cbs, &ctx);
    CHECK(gw != NULL, "httgw_create failed");

    init_spec(&sp);
    sp.seq         = 1000;
    sp.flags       = TCP_ACK | TCP_PSH;
    sp.payload     = (const uint8_t *)req;
    sp.payload_len = (uint32_t)strlen(req);

    CHECK(feed_seg(gw, &sp, 1) == 1, "late-start payload ingest failed");
    CHECK(ctx.req_count == 1, "late-start should parse HTTP without SYN");
    CHECK(strcmp(ctx.last_uri, "/late") == 0, "late-start uri mismatch");
    CHECK(ctx.err_count == 0, "late-start unexpected error");

    fprintf(stderr,
            "[test_httgw_reasm_modes] case=late_start_no_syn req_count=%d "
            "err_count=%d uri=%s mode=%d\n",
            ctx.req_count, ctx.err_count, ctx.last_uri, cfg.reasm_mode);

    httgw_destroy(gw);
    return 0;
}

static int test_strict_syn_ignores_http_without_syn(void) {
    httgw_cfg_t       cfg;
    httgw_callbacks_t cbs;
    httgw_t          *gw;
    test_ctx_t        ctx;
    tcp_pkt_spec_t    sp;
    const char       *req = "GET /strict-nosyn HTTP/1.1\r\nHost: x\r\n\r\n";

    init_common(&cfg, &cbs, &ctx, REASM_MODE_STRICT_SYN);
    gw = httgw_create(&cfg, &cbs, &ctx);
    CHECK(gw != NULL, "httgw_create failed");

    init_spec(&sp);
    sp.seq         = 2000;
    sp.flags       = TCP_ACK | TCP_PSH;
    sp.payload     = (const uint8_t *)req;
    sp.payload_len = (uint32_t)strlen(req);

    CHECK(feed_seg(gw, &sp, 1) == 1, "strict-nosyn payload ingest failed");
    CHECK(ctx.req_count == 0,
          "strict-syn must ignore first payload without SYN");
    CHECK(ctx.err_count == 0, "strict-syn unexpected error without SYN");

    fprintf(stderr,
            "[test_httgw_reasm_modes] case=strict_syn_no_syn req_count=%d "
            "err_count=%d mode=%d\n",
            ctx.req_count, ctx.err_count, cfg.reasm_mode);

    httgw_destroy(gw);
    return 0;
}

static int test_strict_syn_accepts_after_syn(void) {
    httgw_cfg_t       cfg;
    httgw_callbacks_t cbs;
    httgw_t          *gw;
    test_ctx_t        ctx;
    tcp_pkt_spec_t    sp;
    const char       *req  = "GET /strict-ok HTTP/1.1\r\nHost: x\r\n\r\n";
    uint32_t          seq0 = 3000;

    init_common(&cfg, &cbs, &ctx, REASM_MODE_STRICT_SYN);
    gw = httgw_create(&cfg, &cbs, &ctx);
    CHECK(gw != NULL, "httgw_create failed");

    init_spec(&sp);
    sp.seq         = seq0;
    sp.flags       = TCP_SYN;
    sp.payload     = NULL;
    sp.payload_len = 0;
    CHECK(feed_seg(gw, &sp, 1) == 1, "strict-syn initial SYN ingest failed");

    sp.seq         = seq0 + 1;
    sp.flags       = TCP_ACK | TCP_PSH;
    sp.payload     = (const uint8_t *)req;
    sp.payload_len = (uint32_t)strlen(req);
    CHECK(feed_seg(gw, &sp, 2) == 1, "strict-syn payload after SYN failed");

    CHECK(ctx.req_count == 1, "strict-syn should parse payload after SYN");
    CHECK(strcmp(ctx.last_uri, "/strict-ok") == 0, "strict-syn uri mismatch");
    CHECK(ctx.err_count == 0, "strict-syn unexpected error after SYN");

    fprintf(stderr,
            "[test_httgw_reasm_modes] case=strict_syn_after_syn req_count=%d "
            "err_count=%d uri=%s mode=%d\n",
            ctx.req_count, ctx.err_count, ctx.last_uri, cfg.reasm_mode);

    httgw_destroy(gw);
    return 0;
}

int main(void) {
    CHECK(test_late_start_accepts_http_without_syn() == 0,
          "late-start mode case failed");
    CHECK(test_strict_syn_ignores_http_without_syn() == 0,
          "strict-syn no-syn case failed");
    CHECK(test_strict_syn_accepts_after_syn() == 0,
          "strict-syn with-syn case failed");

    printf("ok: test_httgw_reasm_modes\n");
    return 0;
}

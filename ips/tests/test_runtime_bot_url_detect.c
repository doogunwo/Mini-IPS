/**
 * @file test_runtime_bot_url_detect.c
 * @brief bot-like URL 요청 재조립 및 탐지 통합 단위 테스트
 */
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "detect.h"
#include "engine.h"
#include "httgw.h"
#include "logging.h"
#include "net_compat.h"

#define CHECK(cond, msg)                          \
    do {                                          \
        if (!(cond)) {                            \
            fprintf(stderr, "FAIL: %s\n", (msg)); \
            return 1;                             \
        }                                         \
    } while (0)

#define TEST_RULES_PATH "rules/generated/rules.jsonl"
// #define TEST_SEGMENT_SIZE 1500U // MTU = 1500
#define TEST_SEGMENT_SIZE 1460U  // MSS = 1460

/**
 * @brief 탐지 결과와 파싱 오류를 기록하는 테스트 컨텍스트
 */
typedef struct {
    detect_engine_t *det;
    int              req_count;
    int              detect_count;
    int              detect_score;
    int              detect_rc;
    int              detect_err_count;
    int              parse_err_count;
    char             last_uri[256];
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
    uint16_t       win;
    const uint8_t *payload;
    uint32_t       payload_len;
} tcp_pkt_spec_t;

/**
 * @brief HTTP 요청 완성 시 run_detect를 수행하는 테스트 콜백
 *
 * @param flow
 * @param dir
 * @param msg 완성된 HTTP 메시지
 * @param query
 * @param query_len
 * @param user test_ctx_t*
 */
static void on_request_cb(const flow_key_t *flow, tcp_dir_t dir,
                          const http_message_t *msg, const char *query,
                          size_t query_len, void *user) {
    test_ctx_t          *ctx  = (test_ctx_t *)user;
    const IPS_Signature *rule = NULL;
    detect_match_list_t  matches;
    uint64_t             detect_us = 0;
    int                  rc;

    (void)flow;
    (void)dir;
    (void)query;
    (void)query_len;

    ctx->req_count++;
    snprintf(ctx->last_uri, sizeof(ctx->last_uri), "%.255s", msg->uri);

    detect_match_list_init(&matches);
    rc = run_detect(ctx->det, msg, &ctx->detect_score, &rule, &matches,
                    &detect_us);
    ctx->detect_rc = rc;
    if (rc < 0) {
        ctx->detect_err_count++;
    } else if (ctx->detect_score >= APP_DETECT_THRESHOLD) {
        ctx->detect_count++;
    }
    detect_match_list_free(&matches);
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
    ctx->parse_err_count++;
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

static int is_unreserved_uri_char(unsigned char c) {
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
            c == '~');
}

static char *url_encode_component(const char *src) {
    static const char hex[] = "0123456789ABCDEF";
    size_t            i;
    size_t            len;
    size_t            out_len = 0;
    char             *out;
    char             *p;

    if (src == NULL) {
        return NULL;
    }

    len = strlen(src);
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)src[i];
        out_len += is_unreserved_uri_char(c) ? 1 : 3;
    }

    out = (char *)malloc(out_len + 1U);
    if (out == NULL) {
        return NULL;
    }

    p = out;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)src[i];
        if (is_unreserved_uri_char(c)) {
            *p++ = (char)c;
        } else {
            *p++ = '%';
            *p++ = hex[(c >> 4) & 0x0F];
            *p++ = hex[c & 0x0F];
        }
    }
    *p = '\0';
    return out;
}

static char *build_bot_like_value(size_t target_size) {
    const char *suffix     = "' OR 1=1 --";
    size_t      suffix_len = strlen(suffix);
    size_t      fill_len   = 0;
    char       *buf;

    if (target_size > suffix_len) {
        fill_len = target_size - suffix_len;
    }

    buf = (char *)malloc(fill_len + suffix_len + 1U);
    if (buf == NULL) {
        return NULL;
    }

    memset(buf, 'A', fill_len);
    memcpy(buf + fill_len, suffix, suffix_len);
    buf[fill_len + suffix_len] = '\0';
    return buf;
}

static char *build_bot_like_url_request(size_t uri_size) {
    char  *value   = build_bot_like_value(uri_size);
    char  *encoded = NULL;
    char  *req     = NULL;
    size_t needed;

    if (value == NULL) {
        return NULL;
    }

    encoded = url_encode_component(value);
    free(value);
    if (encoded == NULL) {
        return NULL;
    }

    needed = snprintf(NULL, 0,
                      "GET /bench?x=%s HTTP/1.1\r\n"
                      "Host: localhost\r\n"
                      "User-Agent: Mini-IPS bench agent\r\n"
                      "Connection: keep-alive\r\n"
                      "\r\n",
                      encoded);
    req    = (char *)malloc(needed + 1U);
    if (req != NULL) {
        snprintf(req, needed + 1U,
                 "GET /bench?x=%s HTTP/1.1\r\n"
                 "Host: localhost\r\n"
                 "User-Agent: Mini-IPS bench agent\r\n"
                 "Connection: keep-alive\r\n"
                 "\r\n",
                 encoded);
    }

    free(encoded);
    return req;
}

static int feed_request_in_segments(httgw_t *gw, const char *req,
                                    size_t req_len, uint32_t base_seq,
                                    uint32_t seg_size, uint64_t ts_base) {
    tcp_pkt_spec_t sp;
    uint8_t        pkt[2048];
    uint32_t       pkt_len = 0;
    size_t         off     = 0;
    uint64_t       ts      = ts_base;

    memset(&sp, 0, sizeof(sp));
    sp.sip   = 0x0A000001;
    sp.sport = 12345;
    sp.dip   = 0x0A000002;
    sp.dport = 8080;
    sp.ack   = 0;
    sp.flags = TCP_ACK | TCP_PSH;
    sp.win   = 502;

    while (off < req_len) {
        size_t chunk = req_len - off;
        if (chunk > seg_size) {
            chunk = seg_size;
        }

        sp.seq         = base_seq + (uint32_t)off;
        sp.payload     = (const uint8_t *)req + off;
        sp.payload_len = (uint32_t)chunk;

        if (build_tcp_packet(pkt, sizeof(pkt), &sp, &pkt_len) != 0) {
            return -1;
        }
        if (httgw_ingest_packet(gw, pkt, pkt_len, ts++) != 0) {
            return -1;
        }
        off += chunk;
    }

    return 0;
}

static int feed_request_two_segments_out_of_order(httgw_t *gw, const char *req,
                                                  size_t   req_len,
                                                  uint32_t base_seq,
                                                  size_t   first_len,
                                                  uint64_t ts_base) {
    tcp_pkt_spec_t sp;
    uint8_t        pkt[4096];
    uint32_t       pkt_len = 0;
    size_t         second_len;

    if (first_len == 0 || first_len >= req_len) {
        return -1;
    }

    second_len = req_len - first_len;

    memset(&sp, 0, sizeof(sp));
    sp.sip   = 0x0A000001;
    sp.sport = 12345;
    sp.dip   = 0x0A000002;
    sp.dport = 8080;
    sp.ack   = 0;
    sp.flags = TCP_ACK | TCP_PSH;
    sp.win   = 502;

    sp.seq         = base_seq + (uint32_t)first_len;
    sp.payload     = (const uint8_t *)req + first_len;
    sp.payload_len = (uint32_t)second_len;
    if (build_tcp_packet(pkt, sizeof(pkt), &sp, &pkt_len) != 0) {
        return -1;
    }
    if (httgw_ingest_packet(gw, pkt, pkt_len, ts_base) != 0) {
        return -1;
    }

    sp.seq         = base_seq;
    sp.payload     = (const uint8_t *)req;
    sp.payload_len = (uint32_t)first_len;
    if (build_tcp_packet(pkt, sizeof(pkt), &sp, &pkt_len) != 0) {
        return -1;
    }
    if (httgw_ingest_packet(gw, pkt, pkt_len, ts_base + 1U) != 0) {
        return -1;
    }

    return 0;
}

/*
 * Send a synthetic 3-packet flow:
 * 1) bare ACK with no payload
 * 2) second request segment first
 * 3) first request segment last
 *
 * This mimics a capture that missed the SYN and observed the request out of
 * order.
 */
static int feed_no_syn_two_segments_out_of_order(httgw_t *gw, const char *req,
                                                 size_t   req_len,
                                                 uint32_t base_seq,
                                                 size_t   first_len,
                                                 uint64_t ts_base) {
    tcp_pkt_spec_t sp;
    uint8_t        pkt[4096];
    uint32_t       pkt_len = 0;
    size_t         second_len;

    if (first_len == 0 || first_len >= req_len) {
        return -1;
    }

    second_len = req_len - first_len;

    memset(&sp, 0, sizeof(sp));
    sp.sip         = 0x0A000001;
    sp.sport       = 12345;
    sp.dip         = 0x0A000002;
    sp.dport       = 8080;
    sp.ack         = 0;
    sp.flags       = TCP_ACK;
    sp.win         = 502;
    sp.seq         = base_seq;
    sp.payload     = NULL;
    sp.payload_len = 0;

    if (build_tcp_packet(pkt, sizeof(pkt), &sp, &pkt_len) != 0) {
        return -1;
    }
    if (httgw_ingest_packet(gw, pkt, pkt_len, ts_base) != 0) {
        return -1;
    }

    sp.flags       = TCP_ACK | TCP_PSH;
    sp.seq         = base_seq + (uint32_t)first_len;
    sp.payload     = (const uint8_t *)req + first_len;
    sp.payload_len = (uint32_t)second_len;
    if (build_tcp_packet(pkt, sizeof(pkt), &sp, &pkt_len) != 0) {
        return -1;
    }
    if (httgw_ingest_packet(gw, pkt, pkt_len, ts_base + 1U) != 0) {
        return -1;
    }

    sp.seq         = base_seq;
    sp.payload     = (const uint8_t *)req;
    sp.payload_len = (uint32_t)first_len;
    if (build_tcp_packet(pkt, sizeof(pkt), &sp, &pkt_len) != 0) {
        return -1;
    }
    if (httgw_ingest_packet(gw, pkt, pkt_len, ts_base + 2U) != 0) {
        return -1;
    }

    return 0;
}

/* Build a realistic Mini-IPS bot URL request and feed it in-order by fixed-size
 * segments. */
static int run_case(size_t uri_size, uint32_t seg_size) {
    httgw_cfg_t       cfg;
    httgw_callbacks_t cbs;
    httgw_t          *gw = NULL;
    test_ctx_t        ctx;
    char             *req = NULL;

    memset(&cfg, 0, sizeof(cfg));
    cfg.max_buffer_bytes = 12U * 1024U * 1024U;
    cfg.max_body_bytes   = 12U * 1024U * 1024U;
    cfg.reasm_mode       = REASM_MODE_LATE_START;

    memset(&cbs, 0, sizeof(cbs));
    cbs.on_request = on_request_cb;
    cbs.on_error   = on_error_cb;

    memset(&ctx, 0, sizeof(ctx));
    ctx.det = detect_engine_create("ALL", DETECT_JIT_AUTO);
    if (ctx.det == NULL) {
        fprintf(stderr, "detect_engine_create failed\n");
        return 1;
    }

    gw = httgw_create(&cfg, &cbs, &ctx);
    if (gw == NULL) {
        fprintf(stderr, "httgw_create failed\n");
        detect_engine_destroy(ctx.det);
        return 1;
    }

    req = build_bot_like_url_request(uri_size);
    if (req == NULL) {
        fprintf(stderr, "build_bot_like_url_request failed: uri_size=%zu\n",
                uri_size);
        httgw_destroy(gw);
        detect_engine_destroy(ctx.det);
        return 1;
    }

    if (feed_request_in_segments(gw, req, strlen(req), 1000U, seg_size, 1U) !=
        0) {
        fprintf(stderr,
                "feed_request_in_segments failed: uri_size=%zu seg_size=%u\n",
                uri_size, seg_size);
        free(req);
        httgw_destroy(gw);
        detect_engine_destroy(ctx.det);
        return 1;
    }

    printf(
        "uri_size=%zu req_len=%zu seg_size=%u req_count=%d detect_count=%d "
        "detect_score=%d parse_err=%d detect_err=%d uri_len=%zu\n",
        uri_size, strlen(req), seg_size, ctx.req_count, ctx.detect_count,
        ctx.detect_score, ctx.parse_err_count, ctx.detect_err_count,
        strlen(ctx.last_uri));

    CHECK(ctx.req_count == 1, "expected exactly one request callback");
    CHECK(ctx.detect_err_count == 0, "detect engine error occurred");
    CHECK(ctx.parse_err_count == 0, "unexpected parse error");
    CHECK(ctx.detect_score > 0, "expected positive SQLi score");
    CHECK(ctx.detect_count ==
              ((ctx.detect_score >= APP_DETECT_THRESHOLD) ? 1 : 0),
          "unexpected threshold/blocking decision");

    free(req);
    httgw_destroy(gw);
    detect_engine_destroy(ctx.det);
    return 0;
}

/* Split the request in half and feed the tail segment before the head segment.
 */
static int run_two_segment_ooo_case(size_t uri_size) {
    httgw_cfg_t       cfg;
    httgw_callbacks_t cbs;
    httgw_t          *gw = NULL;
    test_ctx_t        ctx;
    char             *req = NULL;
    size_t            req_len;

    memset(&cfg, 0, sizeof(cfg));
    cfg.max_buffer_bytes = 12U * 1024U * 1024U;
    cfg.max_body_bytes   = 12U * 1024U * 1024U;
    cfg.reasm_mode       = REASM_MODE_LATE_START;

    memset(&cbs, 0, sizeof(cbs));
    cbs.on_request = on_request_cb;
    cbs.on_error   = on_error_cb;

    memset(&ctx, 0, sizeof(ctx));
    ctx.det = detect_engine_create("ALL", DETECT_JIT_AUTO);
    if (ctx.det == NULL) {
        fprintf(stderr, "detect_engine_create failed\n");
        return 1;
    }

    gw = httgw_create(&cfg, &cbs, &ctx);
    if (gw == NULL) {
        fprintf(stderr, "httgw_create failed\n");
        detect_engine_destroy(ctx.det);
        return 1;
    }

    req = build_bot_like_url_request(uri_size);
    if (req == NULL) {
        fprintf(stderr, "build_bot_like_url_request failed: uri_size=%zu\n",
                uri_size);
        httgw_destroy(gw);
        detect_engine_destroy(ctx.det);
        return 1;
    }

    req_len = strlen(req);
    if (feed_request_two_segments_out_of_order(gw, req, req_len, 5000U,
                                               req_len / 2U, 100U) != 0) {
        fprintf(stderr,
                "feed_request_two_segments_out_of_order failed: uri_size=%zu\n",
                uri_size);
        free(req);
        httgw_destroy(gw);
        detect_engine_destroy(ctx.det);
        return 1;
    }

    printf(
        "ooo uri_size=%zu req_len=%zu split=%zu req_count=%d detect_count=%d "
        "detect_score=%d parse_err=%d detect_err=%d uri_len=%zu\n",
        uri_size, req_len, req_len / 2U, ctx.req_count, ctx.detect_count,
        ctx.detect_score, ctx.parse_err_count, ctx.detect_err_count,
        strlen(ctx.last_uri));

    CHECK(ctx.req_count == 1,
          "expected exactly one request callback in out-of-order case");
    CHECK(ctx.detect_err_count == 0,
          "detect engine error occurred in out-of-order case");
    CHECK(ctx.parse_err_count == 0,
          "unexpected parse error in out-of-order case");
    CHECK(ctx.detect_score > 0,
          "expected positive SQLi score in out-of-order case");
    CHECK(ctx.detect_count ==
              ((ctx.detect_score >= APP_DETECT_THRESHOLD) ? 1 : 0),
          "unexpected threshold/blocking decision in out-of-order case");

    free(req);
    httgw_destroy(gw);
    detect_engine_destroy(ctx.det);
    return 0;
}

/*
 * Emulate a sniffed flow where the SYN is missing and the first visible data
 * is the latter half of the HTTP request. Late-start mode should still recover
 * once the leading segment arrives.
 */
static int run_no_syn_two_segment_ooo_case(size_t uri_size) {
    httgw_cfg_t       cfg;
    httgw_callbacks_t cbs;
    httgw_t          *gw = NULL;
    test_ctx_t        ctx;
    char             *req = NULL;
    size_t            req_len;

    memset(&cfg, 0, sizeof(cfg));
    cfg.max_buffer_bytes = 12U * 1024U * 1024U;
    cfg.max_body_bytes   = 12U * 1024U * 1024U;
    cfg.reasm_mode       = REASM_MODE_LATE_START;

    memset(&cbs, 0, sizeof(cbs));
    cbs.on_request = on_request_cb;
    cbs.on_error   = on_error_cb;

    memset(&ctx, 0, sizeof(ctx));
    ctx.det = detect_engine_create("ALL", DETECT_JIT_AUTO);
    if (ctx.det == NULL) {
        fprintf(stderr, "detect_engine_create failed\n");
        return 1;
    }

    gw = httgw_create(&cfg, &cbs, &ctx);
    if (gw == NULL) {
        fprintf(stderr, "httgw_create failed\n");
        detect_engine_destroy(ctx.det);
        return 1;
    }

    req = build_bot_like_url_request(uri_size);
    if (req == NULL) {
        fprintf(stderr, "build_bot_like_url_request failed: uri_size=%zu\n",
                uri_size);
        httgw_destroy(gw);
        detect_engine_destroy(ctx.det);
        return 1;
    }

    req_len = strlen(req);
    if (feed_no_syn_two_segments_out_of_order(gw, req, req_len, 9000U,
                                              req_len / 2U, 200U) != 0) {
        fprintf(stderr,
                "feed_no_syn_two_segments_out_of_order failed: uri_size=%zu\n",
                uri_size);
        free(req);
        httgw_destroy(gw);
        detect_engine_destroy(ctx.det);
        return 1;
    }

    printf(
        "no_syn_ooo uri_size=%zu req_len=%zu split=%zu req_count=%d "
        "detect_count=%d detect_score=%d parse_err=%d detect_err=%d "
        "uri_len=%zu\n",
        uri_size, req_len, req_len / 2U, ctx.req_count, ctx.detect_count,
        ctx.detect_score, ctx.parse_err_count, ctx.detect_err_count,
        strlen(ctx.last_uri));

    CHECK(ctx.req_count == 1,
          "expected exactly one request callback in no-syn out-of-order case");
    CHECK(ctx.detect_err_count == 0,
          "detect engine error occurred in no-syn out-of-order case");
    CHECK(ctx.parse_err_count == 0,
          "unexpected parse error in no-syn out-of-order case");
    CHECK(ctx.detect_score > 0,
          "expected positive SQLi score in no-syn out-of-order case");
    CHECK(ctx.detect_count ==
              ((ctx.detect_score >= APP_DETECT_THRESHOLD) ? 1 : 0),
          "unexpected threshold/blocking decision in no-syn out-of-order case");

    free(req);
    httgw_destroy(gw);
    detect_engine_destroy(ctx.det);
    return 0;
}

int main(void) {
    if (regex_signatures_load(TEST_RULES_PATH) != 0) {
        fprintf(stderr, "regex_signatures_load failed: %s\n", TEST_RULES_PATH);
        return 1;
    }

    CHECK(run_case(1800U, TEST_SEGMENT_SIZE) == 0,
          "1800-byte bot-like URL request case failed");
    CHECK(run_case(3600U, TEST_SEGMENT_SIZE) == 0,
          "3600-byte bot-like URL request case failed");
    CHECK(run_two_segment_ooo_case(1800U) == 0,
          "1800-byte out-of-order bot-like URL request case failed");
    CHECK(run_two_segment_ooo_case(3600U) == 0,
          "3600-byte out-of-order bot-like URL request case failed");
    CHECK(run_no_syn_two_segment_ooo_case(1800U) == 0,
          "1800-byte no-syn out-of-order bot-like URL request case failed");
    CHECK(run_no_syn_two_segment_ooo_case(3600U) == 0,
          "3600-byte no-syn out-of-order bot-like URL request case failed");

    printf("ok: test_runtime_bot_url_detect\n");
    return 0;
}

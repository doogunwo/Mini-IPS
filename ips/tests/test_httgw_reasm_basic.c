/**
 * @file test_httgw_reasm_basic.c
 * @brief HTTP 재조립 단위 테스트
 *
 */
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "httgw.h"
#include "net_compat.h"
/**
 * @brief 테스트 검증용 매크로
 * 조건이 틀리면 메시지 찍고, 테스트를 실패시키는 assert-like 매크로
 */
#define CHECK(cond, msg)                          \
    do {                                          \
        if (!(cond)) {                            \
            fprintf(stderr, "FAIL: %s\n", (msg)); \
            return 1;                             \
        }                                         \
    } while (0)

/**
 * @brief 테스트 실행결과 기록 컨텍스트
 * 콜백이 몇번?, 마지막으로 어떤 URI?, 에러 콜백이 발생했는지?
 */
typedef struct {
    int  req_count;
    int  err_count;
    char last_uri[128];
} test_ctx_t;

/**
 * @brief 테스트용 TCP 패킷 생성용 구조체 역할
 * build_tcp_packet()함수에서 가짜 패킷을 만들기 위해 필요한 입력값 묶음이다.
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
 * @brief 파싱된 HTTP 요청 결과를 테스트 컨텍스트에 기록
 * @details 게이트웨이에서 요청 메시지를 정상적으로 완성하면 호출되며,
 *          요청 콜백 호출 횟수와 마지막 요청 URI를 테스트 검증용으로 저장한다.
 *
 * @param flow 요청이 속한 TCP 5-튜플 흐름 정보
 * @param dir 요청이 수신된 TCP 방향 정보
 * @param msg 파싱이 완료된 HTTP 메시지
 * @param query 요청 URI에서 추출된 query 문자열 시작 주소
 * @param query_len query 문자열 길이
 * @param user 테스트 컨텍스트 포인터
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

    if (!out || !sp || !out_len) {
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

    if (sp->payload_len > 0 && sp->payload) {
        memcpy((uint8_t *)tcp + TCP_HDR_SIZE, sp->payload, sp->payload_len);
    }

    TCP_CHECK(tcp) = tcp_checksum_ipv4(
        ip, tcp, (const uint8_t *)tcp + TCP_HDR_SIZE, sp->payload_len);

    *out_len = (uint32_t)total;
    return 0;
}

static int feed_seg(httgw_t *gw, const tcp_pkt_spec_t *sp, uint64_t ts_ms) {
    uint8_t  pkt[2048];
    uint32_t pkt_len;

    if (!gw || !sp) {
        return 0;
    }
    if (build_tcp_packet(pkt, sizeof(pkt), sp, &pkt_len) != 0) {
        return 0;
    }
    return httgw_ingest_packet(gw, pkt, pkt_len, ts_ms);
}

static void init_common(httgw_cfg_t *cfg, httgw_callbacks_t *cbs,
                        test_ctx_t *ctx) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->max_buffer_bytes = 4096;
    cfg->max_body_bytes   = 1024;
    cfg->reasm_mode       = REASM_MODE_LATE_START;

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
    sp->ack   = 0;
    sp->flags = TCP_ACK | TCP_PSH;
    sp->win   = 502;
}

static int test_gap_then_fill(void) {
    httgw_cfg_t       cfg;
    httgw_callbacks_t cbs;
    httgw_t          *gw;
    test_ctx_t        ctx;
    tcp_pkt_spec_t    sp;
    const char       *p1    = "GET /a HTTP/1.1\r\n";
    const char       *pmiss = "Host: ";
    const char       *p2    = "x\r\n\r\n";
    uint32_t          seq0  = 1000;

    init_common(&cfg, &cbs, &ctx);
    gw = httgw_create(&cfg, &cbs, &ctx);
    CHECK(gw != NULL, "httgw_create failed");
    init_spec(&sp);

    sp.seq         = seq0;
    sp.payload     = (const uint8_t *)p1;
    sp.payload_len = (uint32_t)strlen(p1);
    CHECK(feed_seg(gw, &sp, 1) == 0, "feed p1 failed");
    CHECK(ctx.req_count == 0, "request must not flush after p1");

    sp.seq         = seq0 + (uint32_t)strlen(p1) + (uint32_t)strlen(pmiss);
    sp.payload     = (const uint8_t *)p2;
    sp.payload_len = (uint32_t)strlen(p2);
    CHECK(feed_seg(gw, &sp, 2) == 0, "feed p2 failed");
    CHECK(ctx.req_count == 0, "request must not flush while gap exists");

    sp.seq         = seq0 + (uint32_t)strlen(p1);
    sp.payload     = (const uint8_t *)pmiss;
    sp.payload_len = (uint32_t)strlen(pmiss);
    CHECK(feed_seg(gw, &sp, 3) == 0, "feed missing gap failed");

    CHECK(ctx.req_count == 1, "expected exactly one request_fill");
    CHECK(strcmp(ctx.last_uri, "/a") == 0, "uri mismatch");
    CHECK(ctx.err_count == 0, "unexpected error callback");

    fprintf(stderr,
            "[test_httgw_reasm_basic] case=gap_then_fill req_count=%d "
            "err_count=%d uri=%s\n",
            ctx.req_count, ctx.err_count, ctx.last_uri);

    httgw_destroy(gw);
    return 0;
}

static int test_header_split_across_segments(void) {
    httgw_cfg_t       cfg;
    httgw_callbacks_t cbs;
    httgw_t          *gw;
    test_ctx_t        ctx;
    tcp_pkt_spec_t    sp;
    const char       *p1   = "GET /split HTTP/1.1\r\nHost: x\r\n\r";
    const char       *p2   = "\n";
    uint32_t          seq0 = 2000;

    init_common(&cfg, &cbs, &ctx);
    gw = httgw_create(&cfg, &cbs, &ctx);
    CHECK(gw != NULL, "httgw_create failed");
    init_spec(&sp);

    sp.seq         = seq0;
    sp.payload     = (const uint8_t *)p1;
    sp.payload_len = (uint32_t)strlen(p1);
    CHECK(feed_seg(gw, &sp, 1) == 0, "feed first split segment failed");
    CHECK(ctx.req_count == 0,
          "request must not flush before header terminator completes");

    sp.seq         = seq0 + (uint32_t)strlen(p1);
    sp.payload     = (const uint8_t *)p2;
    sp.payload_len = (uint32_t)strlen(p2);
    CHECK(feed_seg(gw, &sp, 2) == 0, "feed second split segment failed");

    CHECK(ctx.req_count == 1, "expected exactly one request_header_split");
    CHECK(strcmp(ctx.last_uri, "/split") == 0, "uri mismatch");
    CHECK(ctx.err_count == 0, "unexpected error callback");

    fprintf(stderr,
            "[test_httgw_reasm_basic] case=header_split req_count=%d "
            "err_count=%d uri=%s\n",
            ctx.req_count, ctx.err_count, ctx.last_uri);

    httgw_destroy(gw);
    return 0;
}

static int test_cl_te_conflict(void) {
    httgw_cfg_t       cfg;
    httgw_callbacks_t cbs;
    httgw_t          *gw;
    test_ctx_t        ctx;
    tcp_pkt_spec_t    sp;
    const char       *req =
        "POST /mix HTTP/1.1\r\n"
        "Host: x\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "4\r\n"
        "test\r\n"
        "0\r\n"
        "\r\n";

    init_common(&cfg, &cbs, &ctx);
    gw = httgw_create(&cfg, &cbs, &ctx);
    CHECK(gw != NULL, "httgw_create failed");
    init_spec(&sp);

    sp.seq         = 3000;
    sp.payload     = (const uint8_t *)req;
    sp.payload_len = (uint32_t)strlen(req);
    CHECK(feed_seg(gw, &sp, 1) == 0, "feed CL+TE conflict request failed");

    CHECK(ctx.req_count == 0,
          "CL+TE conflict should not produce request callback");
    CHECK(ctx.err_count == 1, "CL+TE conflict should produce one parse error");

    fprintf(stderr,
            "[test_httgw_reasm_basic] case=cl_te_conflict req_count=%d "
            "err_count=%d\n",
            ctx.req_count, ctx.err_count);

    httgw_destroy(gw);
    return 0;
}

static int test_out_of_order(void) {
    httgw_cfg_t       cfg;
    httgw_callbacks_t cbs;
    httgw_t          *gw;
    test_ctx_t        ctx;
    tcp_pkt_spec_t    sp;
    const char       *p1   = "GET /a HTTP/1.1\r\n";
    const char       *p2   = "Host: x\r\n\r\n";
    uint32_t          seq0 = 1000;

    init_common(&cfg, &cbs, &ctx);
    gw = httgw_create(&cfg, &cbs, &ctx);
    CHECK(gw != NULL, "httgw_create failed");
    init_spec(&sp);

    sp.seq         = seq0 + (uint32_t)strlen(p1);
    sp.payload     = (const uint8_t *)p2;
    sp.payload_len = (uint32_t)strlen(p2);
    CHECK(feed_seg(gw, &sp, 1) == 0, "feed tail failed");
    CHECK(ctx.req_count == 0, "request must not flush before missing prefix");

    sp.seq         = seq0;
    sp.payload     = (const uint8_t *)p1;
    sp.payload_len = (uint32_t)strlen(p1);
    CHECK(feed_seg(gw, &sp, 2) == 0, "feed head failed");

    CHECK(ctx.req_count == 1,
          "expected exactly one request_out_of_order");  // "late-start reasm
                                                         // should not recover
                                                         // missing prefix"
    CHECK(strcmp(ctx.last_uri, "/a") == 0, "uri mismatch");
    CHECK(ctx.err_count == 0, "unexpected error callback");

    fprintf(stderr,
            "[test_httgw_reasm_basic] case=out_of_order req_count=%d "
            "err_count=%d uri=%s\n",
            ctx.req_count, ctx.err_count, ctx.last_uri);

    httgw_destroy(gw);
    return 0;
}
// 1. In-order (정상 순서)
static int test_in_order(void) {
    httgw_cfg_t       cfg;
    httgw_callbacks_t cbs;
    httgw_t          *gw;
    test_ctx_t        ctx;
    tcp_pkt_spec_t    sp;

    const char *p1   = "GET /inorder HTTP/1.1\r\n";
    const char *p2   = "Host: localhost\r\n\r\n";
    uint32_t    seq0 = 1000;

    init_common(&cfg, &cbs, &ctx);
    gw = httgw_create(&cfg, &cbs, &ctx);
    CHECK(gw != NULL, "httgw_create_failed");
    init_spec(&sp);

    // Segment 1
    sp.seq         = seq0;
    sp.payload     = (const uint8_t *)p1;
    sp.payload_len = (uint32_t)strlen(p1);
    feed_seg(gw, &sp, 1);

    // Segment 2
    sp.seq         = seq0 + (uint32_t)strlen(p1);
    sp.payload     = (const uint8_t *)p2;
    sp.payload_len = (uint32_t)strlen(p2);
    feed_seg(gw, &sp, 1);

    CHECK(ctx.req_count == 1, "Should flush immediately");
    CHECK(strcmp(ctx.last_uri, "/inorder") == 0, "URI mismatch");

    fprintf(stderr,
            "[test_httgw_reasm_basic] case=in_order req_count=%d err_count=%d "
            "uri=%s\n",
            ctx.req_count, ctx.err_count, ctx.last_uri);

    httgw_destroy(gw);
    return 0;
}

// 2. Duplicate & Overlap Same (중복 및 동일 데이터 겹침)
static int test_overlap_same(void) {
    httgw_cfg_t       cfg;
    httgw_callbacks_t cbs;
    httgw_t          *gw;
    test_ctx_t        ctx;
    tcp_pkt_spec_t    sp;

    const char *p1   = "GET /overlap HTTP/1.1\r\n";
    uint32_t    seq0 = 1000;

    init_common(&cfg, &cbs, &ctx);
    gw = httgw_create(&cfg, &cbs, &ctx);
    CHECK(gw != NULL, "httgw_create_failed");
    init_spec(&sp);

    // 1. 전체 데이터 전송
    sp.seq         = seq0;
    sp.payload     = (const uint8_t *)p1;
    sp.payload_len = (uint32_t)strlen(p1);
    feed_seg(gw, &sp, 1);

    // 2. 중간부터 겹치는 동일 데이터 재전송
    sp.seq         = seq0 + 4;
    sp.payload     = (const uint8_t *)(p1 + 4);
    sp.payload_len = (uint32_t)strlen(p1) - 4;
    feed_seg(gw, &sp, 1);

    CHECK(ctx.req_count == 0, "Duplicate should not trigger anything");
    CHECK(ctx.err_count == 0, "Duplicate is not an error");

    fprintf(stderr,
            "[test_httgw_reasm_basic] case=overlap_same req_count=%d "
            "err_count=%d\n",
            ctx.req_count, ctx.err_count);

    httgw_destroy(gw);
    return 0;
}

// 3. Gap then Fill (빠진 조각 채우기)
static int test_gap_fill(void) {
    httgw_cfg_t       cfg;
    httgw_callbacks_t cbs;
    httgw_t          *gw;
    test_ctx_t        ctx;
    tcp_pkt_spec_t    sp;

    const char *p1   = "GET /gap ";
    const char *p2   = "HTTP/1.1\r\n";
    const char *p3   = "Host: x\r\n\r\n";
    uint32_t    seq0 = 1000;

    init_common(&cfg, &cbs, &ctx);
    gw = httgw_create(&cfg, &cbs, &ctx);
    CHECK(gw != NULL, "httgw_create_failed");
    init_spec(&sp);

    // 1. 첫 조각 전송
    sp.seq         = seq0;
    sp.payload     = (const uint8_t *)p1;
    sp.payload_len = (uint32_t)strlen(p1);
    feed_seg(gw, &sp, 1);

    // 2. 세 번째 조각 먼저 전송 (Gap 발생)
    sp.seq         = seq0 + (uint32_t)strlen(p1) + (uint32_t)strlen(p2);
    sp.payload     = (const uint8_t *)p3;
    sp.payload_len = (uint32_t)strlen(p3);
    feed_seg(gw, &sp, 1);
    CHECK(ctx.req_count == 0, "Gap exists, should not flush");

    // 3. 비어있던 두 번째 조각 전송
    sp.seq         = seq0 + (uint32_t)strlen(p1);
    sp.payload     = (const uint8_t *)p2;
    sp.payload_len = (uint32_t)strlen(p2);
    feed_seg(gw, &sp, 1);

    CHECK(ctx.req_count == 1, "Gap filled, request should be complete");

    fprintf(
        stderr,
        "[test_httgw_reasm_basic] case=gap_fill req_count=%d err_count=%d\n",
        ctx.req_count, ctx.err_count);

    httgw_destroy(gw);
    return 0;
}

// 4. Header / Body Split (헤더와 바디 분리)
static int test_header_body_split(void) {
    httgw_cfg_t       cfg;
    httgw_callbacks_t cbs;
    httgw_t          *gw;
    test_ctx_t        ctx;
    tcp_pkt_spec_t    sp;

    const char *header = "POST /b HTTP/1.1\r\nContent-Length: 4\r\n\r\n";
    const char *body   = "DATA";
    uint32_t    seq0   = 1000;

    init_common(&cfg, &cbs, &ctx);
    gw = httgw_create(&cfg, &cbs, &ctx);
    CHECK(gw != NULL, "httgw_create_failed");
    init_spec(&sp);

    // 1. 헤더 세그먼트
    sp.seq         = seq0;
    sp.payload     = (const uint8_t *)header;
    sp.payload_len = (uint32_t)strlen(header);
    feed_seg(gw, &sp, 1);
    CHECK(ctx.req_count == 0, "Waiting for body");

    // 2. 바디 세그먼트
    sp.seq         = seq0 + (uint32_t)strlen(header);
    sp.payload     = (const uint8_t *)body;
    sp.payload_len = (uint32_t)strlen(body);
    feed_seg(gw, &sp, 1);

    CHECK(ctx.req_count == 1, "Post request complete");

    fprintf(stderr,
            "[test_httgw_reasm_basic] case=header_body_split req_count=%d "
            "err_count=%d\n",
            ctx.req_count, ctx.err_count);

    httgw_destroy(gw);
    return 0;
}

int main(void) {
    if (test_gap_then_fill() != 0) {
        return 1;
    }
    if (test_header_split_across_segments() != 0) {
        return 1;
    }
    if (test_cl_te_conflict() != 0) {
        return 1;
    }
    if (test_in_order() != 0) {
        return 1;
    }
    if (test_overlap_same() != 0) {
        return 1;
    }
    if (test_gap_fill() != 0) {
        return 1;
    }
    if (test_header_body_split() != 0) {
        return 1;
    }
    if (test_out_of_order() != 0) {
        return 1;
    }

    printf("ok: test_httgw_reasm_basic\n");
    return 0;
}

/**
 * @file test_httgw_live_reasm.c
 * @brief live-like 재조립 시나리오 단위 테스트
 */
#include <arpa/inet.h>
#include <assert.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "httgw.h"
#include "net_compat.h"

/**
 * @brief 요청 수와 마지막 파싱 결과를 기록하는 테스트 컨텍스트
 */
typedef struct {
    int    req_count;
    int    err_count;
    size_t last_uri_len;
    char   last_method[16];
} test_ctx_t;

/**
 * @brief synthetic TCP 패킷 생성에 필요한 필드 묶음
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

/**
 * @brief HTTP 요청 완성 시 호출되는 테스트 콜백
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
    test_ctx_t *ctx = (test_ctx_t *)user;
    (void)flow;
    (void)dir;
    (void)query;
    (void)query_len;

    ctx->req_count++;
    ctx->last_uri_len = strlen(msg->uri);
    snprintf(ctx->last_method, sizeof(ctx->last_method), "%.15s", msg->method);
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

/**
 * @brief synthetic TCP 세그먼트를 Ethernet 프레임 형태로 생성한다.
 *
 * @param sp 패킷 필드 입력값
 * @param out_pkt 결과 패킷 버퍼 주소를 돌려받을 포인터
 * @param out_len 생성된 패킷 길이를 돌려받을 포인터
 * @return int 0=성공, 음수=실패
 */
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

static char *build_http_request(size_t uri_pad_len, size_t *out_len) {
    const char *prefix = "/bench?x=";
    const char *suffix = "%27%20union%20select%201%2C2%2C3%20from%20dual--";
    const char *head_a = "GET ";
    const char *head_b =
        " HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Connection: keep-alive\r\n"
        "\r\n";
    size_t total_len;
    char  *req;
    char  *p;

    if (out_len == NULL) {
        return NULL;
    }

    total_len = strlen(head_a) + strlen(prefix) + uri_pad_len + strlen(suffix) +
                strlen(head_b);
    req = (char *)malloc(total_len + 1U);
    if (req == NULL) {
        return NULL;
    }

    p = req;
    memcpy(p, head_a, strlen(head_a));
    p += strlen(head_a);
    memcpy(p, prefix, strlen(prefix));
    p += strlen(prefix);
    memset(p, 'A', uri_pad_len);
    p += uri_pad_len;
    memcpy(p, suffix, strlen(suffix));
    p += strlen(suffix);
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

static void test_large_request_two_segments(void) {
    httgw_cfg_t       cfg;
    httgw_callbacks_t cbs;
    test_ctx_t        ctx;
    httgw_t          *gw;
    tcp_pkt_spec_t    sp;
    char             *req;
    size_t            req_len;
    size_t            cut;

    init_gateway(&cfg, &cbs, &ctx);
    gw = httgw_create(&cfg, &cbs, &ctx);
    assert(gw != NULL);

    req = build_http_request(3600U, &req_len);
    assert(req != NULL);
    cut = req_len / 2U;
    assert(cut > 0U);

    memset(&sp, 0, sizeof(sp));
    sp.sip   = 0xAC1F003A;
    sp.sport = 43886;
    sp.dip   = 0xAC1F003C;
    sp.dport = 8080;
    sp.ack   = 1;
    sp.flags = TCP_ACK | TCP_PSH;

    sp.seq         = 1;
    sp.payload     = (const uint8_t *)req;
    sp.payload_len = (uint32_t)cut;
    assert(feed_segment(gw, &sp, 1000) == 0);

    sp.seq         = 1U + (uint32_t)cut;
    sp.payload     = (const uint8_t *)req + cut;
    sp.payload_len = (uint32_t)(req_len - cut);
    assert(feed_segment(gw, &sp, 1001) == 0);

    assert(ctx.err_count == 0);
    assert(ctx.req_count == 1);
    assert(strcmp(ctx.last_method, "GET") == 0);
    assert(ctx.last_uri_len > 3600U);

    fprintf(stderr,
            "[test_httgw_live_reasm] case=two_segments req_count=%d "
            "err_count=%d method=%s uri_len=%zu req_len=%zu cut=%zu\n",
            ctx.req_count, ctx.err_count, ctx.last_method, ctx.last_uri_len,
            req_len, cut);

    free(req);
    httgw_destroy(gw);
}

static void test_keepalive_two_large_requests(void) {
    httgw_cfg_t       cfg;
    httgw_callbacks_t cbs;
    test_ctx_t        ctx;
    httgw_t          *gw;
    tcp_pkt_spec_t    sp;
    char             *req1;
    char             *req2;
    size_t            len1;
    size_t            len2;
    uint32_t          seq = 1;
    size_t            cut1;
    size_t            cut2;

    init_gateway(&cfg, &cbs, &ctx);
    gw = httgw_create(&cfg, &cbs, &ctx);
    assert(gw != NULL);

    req1 = build_http_request(3600U, &len1);
    req2 = build_http_request(7200U, &len2);
    assert(req1 != NULL);
    assert(req2 != NULL);
    cut1 = len1 / 2U;
    cut2 = len2 / 2U;
    assert(cut1 > 0U);
    assert(cut2 > 0U);

    memset(&sp, 0, sizeof(sp));
    sp.sip   = 0xAC1F003A;
    sp.sport = 43886;
    sp.dip   = 0xAC1F003C;
    sp.dport = 8080;
    sp.ack   = 1;
    sp.flags = TCP_ACK | TCP_PSH;

    sp.seq         = seq;
    sp.payload     = (const uint8_t *)req1;
    sp.payload_len = (uint32_t)cut1;
    assert(feed_segment(gw, &sp, 1000) == 0);
    seq += (uint32_t)cut1;

    sp.seq         = seq;
    sp.payload     = (const uint8_t *)req1 + cut1;
    sp.payload_len = (uint32_t)(len1 - cut1);
    assert(feed_segment(gw, &sp, 1001) == 0);
    seq += (uint32_t)(len1 - cut1);

    sp.seq         = seq;
    sp.payload     = (const uint8_t *)req2;
    sp.payload_len = (uint32_t)cut2;
    assert(feed_segment(gw, &sp, 1002) == 0);
    seq += (uint32_t)cut2;

    sp.seq         = seq;
    sp.payload     = (const uint8_t *)req2 + cut2;
    sp.payload_len = (uint32_t)(len2 - cut2);
    assert(feed_segment(gw, &sp, 1003) == 0);

    assert(ctx.err_count == 0);
    assert(ctx.req_count == 2);

    fprintf(stderr,
            "[test_httgw_live_reasm] case=keepalive_two_requests req_count=%d "
            "err_count=%d len1=%zu len2=%zu cut1=%zu cut2=%zu\n",
            ctx.req_count, ctx.err_count, len1, len2, cut1, cut2);

    free(req1);
    free(req2);
    httgw_destroy(gw);
}

static void test_duplicate_segments_single_request(void) {
    httgw_cfg_t       cfg;
    httgw_callbacks_t cbs;
    test_ctx_t        ctx;
    httgw_t          *gw;
    tcp_pkt_spec_t    sp;
    char             *req;
    size_t            req_len;
    size_t            cut;

    init_gateway(&cfg, &cbs, &ctx);
    gw = httgw_create(&cfg, &cbs, &ctx);
    assert(gw != NULL);

    req = build_http_request(3600U, &req_len);
    assert(req != NULL);
    cut = req_len / 2U;
    assert(cut > 0U);

    memset(&sp, 0, sizeof(sp));
    sp.sip   = 0xAC1F003A;
    sp.sport = 43886;
    sp.dip   = 0xAC1F003C;
    sp.dport = 8080;
    sp.ack   = 1;
    sp.flags = TCP_ACK | TCP_PSH;

    /* first segment */
    sp.seq         = 1;
    sp.payload     = (const uint8_t *)req;
    sp.payload_len = (uint32_t)cut;
    assert(feed_segment(gw, &sp, 2000) == 0);

    /* duplicate first segment */
    assert(feed_segment(gw, &sp, 2001) == 0);

    /* second segment */
    sp.seq         = 1U + (uint32_t)cut;
    sp.payload     = (const uint8_t *)req + cut;
    sp.payload_len = (uint32_t)(req_len - cut);
    assert(feed_segment(gw, &sp, 2002) == 0);

    /* duplicate second segment */
    assert(feed_segment(gw, &sp, 2003) == 0);

    assert(ctx.err_count == 0);
    assert(ctx.req_count == 1);
    assert(strcmp(ctx.last_method, "GET") == 0);
    assert(ctx.last_uri_len > 3600U);

    fprintf(stderr,
            "[test_httgw_live_reasm] case=duplicate_segments req_count=%d "
            "err_count=%d method=%s uri_len=%zu req_len=%zu\n",
            ctx.req_count, ctx.err_count, ctx.last_method, ctx.last_uri_len,
            req_len);

    free(req);
    httgw_destroy(gw);
}

static void test_out_of_order_segments_single_request(void) {
    httgw_cfg_t       cfg;
    httgw_callbacks_t cbs;
    test_ctx_t        ctx;
    httgw_t          *gw;
    tcp_pkt_spec_t    sp;
    char             *req;
    size_t            req_len;
    size_t            cut;

    init_gateway(&cfg, &cbs, &ctx);
    gw = httgw_create(&cfg, &cbs, &ctx);
    assert(gw != NULL);

    req = build_http_request(3600U, &req_len);
    assert(req != NULL);
    cut = req_len / 2U;
    assert(cut > 0U);

    memset(&sp, 0, sizeof(sp));
    sp.sip   = 0xAC1F003A;
    sp.sport = 43886;
    sp.dip   = 0xAC1F003C;
    sp.dport = 8080;
    sp.ack   = 1;
    sp.flags = TCP_ACK | TCP_PSH;

    /* second segment first */
    sp.seq         = 1U + (uint32_t)cut;
    sp.payload     = (const uint8_t *)req + cut;
    sp.payload_len = (uint32_t)(req_len - cut);
    assert(feed_segment(gw, &sp, 3000) == 0);

    /* then first segment */
    sp.seq         = 1;
    sp.payload     = (const uint8_t *)req;
    sp.payload_len = (uint32_t)cut;
    assert(feed_segment(gw, &sp, 3001) == 0);

    assert(ctx.err_count == 0);
    assert(ctx.req_count == 1);
    assert(strcmp(ctx.last_method, "GET") == 0);
    assert(ctx.last_uri_len > 3600U);

    fprintf(stderr,
            "[test_httgw_live_reasm] case=out_of_order req_count=%d "
            "err_count=%d method=%s uri_len=%zu req_len=%zu cut=%zu\n",
            ctx.req_count, ctx.err_count, ctx.last_method, ctx.last_uri_len,
            req_len, cut);

    free(req);
    httgw_destroy(gw);
}

static void test_interleaved_server_reply_between_request_segments(void) {
    httgw_cfg_t       cfg;
    httgw_callbacks_t cbs;
    test_ctx_t        ctx;
    httgw_t          *gw;
    tcp_pkt_spec_t    sp;
    char             *req;
    const char       *resp =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 2\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "OK";
    size_t req_len;
    size_t cut;

    init_gateway(&cfg, &cbs, &ctx);
    gw = httgw_create(&cfg, &cbs, &ctx);
    assert(gw != NULL);

    req = build_http_request(3600U, &req_len);
    assert(req != NULL);
    cut = req_len / 2U;
    assert(cut > 0U);

    memset(&sp, 0, sizeof(sp));

    /* 1) client request seg1 */
    sp.sip         = 0xAC1F003A;
    sp.sport       = 43886;
    sp.dip         = 0xAC1F003C;
    sp.dport       = 8080;
    sp.seq         = 1;
    sp.ack         = 1;
    sp.flags       = TCP_ACK | TCP_PSH;
    sp.payload     = (const uint8_t *)req;
    sp.payload_len = (uint32_t)cut;
    assert(feed_segment(gw, &sp, 4000) == 0);

    /* 2) server response payload */
    sp.sip         = 0xAC1F003C;
    sp.sport       = 8080;
    sp.dip         = 0xAC1F003A;
    sp.dport       = 43886;
    sp.seq         = 1;
    sp.ack         = 1U + (uint32_t)cut;
    sp.flags       = TCP_ACK | TCP_PSH;
    sp.payload     = (const uint8_t *)resp;
    sp.payload_len = (uint32_t)strlen(resp);
    assert(feed_segment(gw, &sp, 4001) == 0);

    /* 3) client ACK */
    sp.sip         = 0xAC1F003A;
    sp.sport       = 43886;
    sp.dip         = 0xAC1F003C;
    sp.dport       = 8080;
    sp.seq         = 1U + (uint32_t)cut;
    sp.ack         = 1U + (uint32_t)strlen(resp);
    sp.flags       = TCP_ACK;
    sp.payload     = NULL;
    sp.payload_len = 0;
    assert(feed_segment(gw, &sp, 4002) == 0);

    /* 4) client request seg2 */
    sp.seq         = 1U + (uint32_t)cut;
    sp.ack         = 1U + (uint32_t)strlen(resp);
    sp.flags       = TCP_ACK | TCP_PSH;
    sp.payload     = (const uint8_t *)req + cut;
    sp.payload_len = (uint32_t)(req_len - cut);
    assert(feed_segment(gw, &sp, 4003) == 0);

    assert(ctx.err_count == 0);
    assert(ctx.req_count == 1);
    assert(strcmp(ctx.last_method, "GET") == 0);
    assert(ctx.last_uri_len > 3600U);

    fprintf(stderr,
            "[test_httgw_live_reasm] case=interleaved_reply req_count=%d "
            "err_count=%d method=%s uri_len=%zu req_len=%zu cut=%zu "
            "resp_len=%zu\n",
            ctx.req_count, ctx.err_count, ctx.last_method, ctx.last_uri_len,
            req_len, cut, strlen(resp));

    free(req);
    httgw_destroy(gw);
}

int main(void) {
    test_large_request_two_segments();
    test_keepalive_two_large_requests();
    test_duplicate_segments_single_request();
    test_out_of_order_segments_single_request();
    test_interleaved_server_reply_between_request_segments();
    puts("ok: test_httgw_live_reasm");
    return 0;
}

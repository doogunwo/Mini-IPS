#define main inline_ips_main
#include "../../src/inline/main.c"
#undef main

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../common/unit_test.h"

static int resolve_ruleset_dir(char *out, size_t out_sz) {
    if (NULL == out || out_sz == 0U) {
        return -1;
    }

    if (NULL != realpath("rules", out)) {
        return 0;
    }

    if (NULL != realpath("ips/rules", out)) {
        return 0;
    }

    return -1;
}

static mini_ips_session_t *allocate_test_session(mini_ips_ctx_t *ctx,
                                                 uint32_t        session_id,
                                                 int             client_fd,
                                                 int             upstream_fd) {
    size_t i;

    if (NULL == ctx) {
        return NULL;
    }

    for (i = 0; i < MINI_IPS_MAX_SESSIONS; i++) {
        mini_ips_session_t *session;

        session = &ctx->sessions[i];
        if (session->in_use) {
            continue;
        }

        memset(session, 0, sizeof(*session));
        session->in_use = 1;
        session->session_id = session_id;
        session->client_fd = client_fd;
        session->upstream_fd = upstream_fd;
        session->blocked = 0;
        return session;
    }

    return NULL;
}

static int verify_attack_detect_and_block(mini_ips_ctx_t *ctx,
                                          const char     *attack_req) {
    http_message_t   msg;
    detect_result_t  result;
    block_decision_t decision;
    blocking_ctx_t   block_ctx;
    char             response_buf[512];
    size_t           response_len;
    int              rc;

    if (NULL == ctx || NULL == attack_req) {
        return -1;
    }

    memset(&msg, 0, sizeof(msg));
    memset(&result, 0, sizeof(result));
    memset(&decision, 0, sizeof(decision));
    memset(&block_ctx, 0, sizeof(block_ctx));

    rc = http_parser_try((const uint8_t *)attack_req, strlen(attack_req), &msg);
    EXPECT_INT_EQ("main_pipeline.http_parser_try", 1, rc);

    rc = detect_run(ctx->engine, &msg, &result, NULL);
    EXPECT_INT_EQ("main_pipeline.detect_run", 0, rc);
    EXPECT_INT_EQ("main_pipeline.detect_run", 1, result.matched);
    EXPECT_INT_EQ("main_pipeline.detect_run", 1,
                  result.matched_directory_traversal);
    EXPECT_TRUE("main_pipeline.detect_run", "xss or traversal score present",
                result.directory_traversal_score > 0 || result.xss_score > 0);

    response_buf[0] = '\0';
    response_len = 0U;
    block_ctx.rs = &result;
    block_ctx.dc = &decision;
    block_ctx.res_buf = response_buf;
    block_ctx.res_buf_sz = sizeof(response_buf);
    block_ctx.rs_len = &response_len;

    rc = blocking_request(&block_ctx);
    EXPECT_INT_EQ("main_pipeline.blocking_request", 1, rc);
    EXPECT_INT_EQ("main_pipeline.blocking_request", 1, decision.is_blocked);
    EXPECT_INT_EQ("main_pipeline.blocking_request", 403, decision.status_code);
    EXPECT_TRUE("main_pipeline.blocking_request", "403 response built",
                response_len > 0U &&
                    NULL != strstr(response_buf, "HTTP/1.1 403 Forbidden"));

    http_parser_free(&msg);
    return 0;
}

static int verify_uri_xss_detect_and_block(mini_ips_ctx_t *ctx,
                                           const char     *attack_req) {
    http_message_t   msg;
    detect_result_t  result;
    block_decision_t decision;
    blocking_ctx_t   block_ctx;
    char             response_buf[512];
    size_t           response_len;
    int              rc;

    if (NULL == ctx || NULL == attack_req) {
        return -1;
    }

    memset(&msg, 0, sizeof(msg));
    memset(&result, 0, sizeof(result));
    memset(&decision, 0, sizeof(decision));
    memset(&block_ctx, 0, sizeof(block_ctx));

    rc = http_parser_try((const uint8_t *)attack_req, strlen(attack_req), &msg);
    EXPECT_INT_EQ("main_pipeline.http_parser_try.uri_xss", 1, rc);

    rc = detect_run(ctx->engine, &msg, &result, NULL);
    EXPECT_INT_EQ("main_pipeline.detect_run.uri_xss", 0, rc);
    EXPECT_INT_EQ("main_pipeline.detect_run.uri_xss", 1, result.matched);
    EXPECT_INT_EQ("main_pipeline.detect_run.uri_xss", 1, result.matched_xss);
    EXPECT_TRUE("main_pipeline.detect_run.uri_xss", "xss score present",
                result.xss_score > 0);

    response_buf[0] = '\0';
    response_len = 0U;
    block_ctx.rs = &result;
    block_ctx.dc = &decision;
    block_ctx.res_buf = response_buf;
    block_ctx.res_buf_sz = sizeof(response_buf);
    block_ctx.rs_len = &response_len;

    rc = blocking_request(&block_ctx);
    EXPECT_INT_EQ("main_pipeline.blocking_request.uri_xss", 1, rc);
    EXPECT_INT_EQ("main_pipeline.blocking_request.uri_xss", 1,
                  decision.is_blocked);
    EXPECT_INT_EQ("main_pipeline.blocking_request.uri_xss", 403,
                  decision.status_code);
    EXPECT_STR_EQ("main_pipeline.blocking_request.uri_xss",
                  "request blocked : xss", decision.reason);
    EXPECT_TRUE("main_pipeline.blocking_request.uri_xss",
                "403 response built",
                response_len > 0U &&
                    NULL != strstr(response_buf, "HTTP/1.1 403 Forbidden"));

    http_parser_free(&msg);
    return 0;
}

int main(void) {
    mini_ips_ctx_t ctx;
    pthread_t      worker;
    void          *worker_ret;
    char           rules_dir[PATH_MAX];
    const char    *req_probe;
    const char    *res_probe;
    const char    *attack_req;
    uint8_t        scratch[PACKET_MAX_BYTES];
    uint32_t       out_len;
    uint32_t       session_id;
    int            sockets[2];
    char           block_recv[512];
    ssize_t        block_n;
    int            rc;

    EXPECT_INT_EQ("resolve_ruleset_dir", 0,
                  resolve_ruleset_dir(rules_dir, sizeof(rules_dir)));
    EXPECT_INT_EQ("setenv", 0, setenv(MINI_IPS_RULESET_ENV, rules_dir, 1));

    rc = mini_ips_set(&ctx);
    EXPECT_INT_EQ("mini_ips_set", 0, rc);

    req_probe = "GET /health HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n";
    rc = packet_ring_enq(&ctx.req_ring, (const uint8_t *)req_probe,
                         (uint32_t)strlen(req_probe), 10);
    EXPECT_INT_EQ("main_pipeline.req_ring_enq", 0, rc);

    out_len = 0U;
    rc = packet_ring_deq(&ctx.req_ring, scratch, sizeof(scratch), &out_len,
                         &session_id);
    EXPECT_INT_EQ("main_pipeline.req_ring_deq", 0, rc);
    EXPECT_SIZE_EQ("main_pipeline.req_ring_deq", strlen(req_probe), out_len);
    EXPECT_MEM_EQ("main_pipeline.req_ring_deq", req_probe, scratch, out_len);
    EXPECT_INT_EQ("main_pipeline.req_ring_session_id", 10, session_id);

    res_probe = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    rc = packet_ring_enq(&ctx.res_ring, (const uint8_t *)res_probe,
                         (uint32_t)strlen(res_probe), 20);
    EXPECT_INT_EQ("main_pipeline.res_ring_enq", 0, rc);

    out_len = 0U;
    rc = packet_ring_deq(&ctx.res_ring, scratch, sizeof(scratch), &out_len,
                         &session_id);
    EXPECT_INT_EQ("main_pipeline.res_ring_deq", 0, rc);
    EXPECT_SIZE_EQ("main_pipeline.res_ring_deq", strlen(res_probe), out_len);
    EXPECT_MEM_EQ("main_pipeline.res_ring_deq", res_probe, scratch, out_len);
    EXPECT_INT_EQ("main_pipeline.res_ring_session_id", 20, session_id);

    attack_req =
        "GET /../../admin HTTP/1.1\r\n"
        "Host: a\r\n"
        "X-Test: <script>\r\n"
        "Content-Length: 0\r\n\r\n";
    if (0 != verify_attack_detect_and_block(&ctx, attack_req)) {
        mini_ips_destroy(&ctx);
        unsetenv(MINI_IPS_RULESET_ENV);
        g_ctx = NULL;
        return 1;
    }

    attack_req =
        "GET /?1a681bb9ca=<script>alert('union%20select%20password%20from%20users')</script> "
        "HTTP/1.1\r\n"
        "Host: a\r\n"
        "Content-Length: 0\r\n\r\n";
    if (0 != verify_uri_xss_detect_and_block(&ctx, attack_req)) {
        mini_ips_destroy(&ctx);
        unsetenv(MINI_IPS_RULESET_ENV);
        g_ctx = NULL;
        return 1;
    }

    g_stop = 0;
    g_ctx = &ctx;
    ctx.stop = 0;

    rc = pthread_create(&worker, NULL, worker_main, &ctx);
    EXPECT_INT_EQ("main_pipeline.pthread_create", 0, rc);

    EXPECT_INT_EQ("main_pipeline.socketpair", 0,
                  socketpair(AF_UNIX, SOCK_STREAM, 0, sockets));
    EXPECT_PTR_NOT_NULL("main_pipeline.allocate_test_session",
                        allocate_test_session(&ctx, 777U, sockets[0], -1));

    rc = packet_ring_enq(&ctx.req_ring, (const uint8_t *)attack_req,
                         (uint32_t)strlen(attack_req), 777U);
    EXPECT_INT_EQ("main_pipeline.worker_req_enq", 0, rc);

    rc = packet_ring_enq(&ctx.res_ring, (const uint8_t *)res_probe,
                         (uint32_t)strlen(res_probe), 777U);
    EXPECT_INT_EQ("main_pipeline.worker_res_enq", 0, rc);

    usleep(100000);
    memset(block_recv, 0, sizeof(block_recv));
    block_n = recv(sockets[1], block_recv, sizeof(block_recv), MSG_DONTWAIT);
    EXPECT_TRUE("main_pipeline.worker_block_recv", "403 delivered by worker",
                block_n > 0 &&
                    NULL != strstr(block_recv, "HTTP/1.1 403 Forbidden"));

    handle_signal(SIGTERM);

    EXPECT_INT_EQ("main_pipeline.signal_ctx_stop", 1, ctx.stop);
    EXPECT_INT_EQ("main_pipeline.signal_global_stop", 1, g_stop);

    rc = pthread_join(worker, &worker_ret);
    EXPECT_INT_EQ("main_pipeline.pthread_join", 0, rc);
    EXPECT_INT_EQ("main_pipeline.worker_main", 0, (int)(intptr_t)worker_ret);

    out_len = 0U;
    rc = packet_ring_deq(&ctx.req_ring, scratch, sizeof(scratch), &out_len,
                         &session_id);
    EXPECT_INT_EQ("main_pipeline.req_ring_empty_after_worker", -1, rc);

    out_len = 0U;
    rc = packet_ring_deq(&ctx.res_ring, scratch, sizeof(scratch), &out_len,
                         &session_id);
    EXPECT_INT_EQ("main_pipeline.res_ring_empty_after_worker", -1, rc);

    close(sockets[0]);
    close(sockets[1]);
    mini_ips_destroy(&ctx);
    unsetenv(MINI_IPS_RULESET_ENV);
    g_ctx = NULL;
    g_stop = 0;
    return 0;
}

#include "blocking.h"
#include "../../src/inline/detect.h"

#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

#include "../common/unit_test.h"

static int test_blocking_send(void) {
    int        sockets[2];
    const char payload[] = "HTTP/1.1 403 Forbidden\r\n\r\n";
    char       recv_buf[64];
    ssize_t    n;

    EXPECT_INT_EQ("blocking_send.invalid_fd", -1,
                  blocking_send(-1, payload, sizeof(payload) - 1U));

    EXPECT_INT_EQ("socketpair", 0, socketpair(AF_UNIX, SOCK_STREAM, 0, sockets));

    EXPECT_INT_EQ("blocking_send.success", 0,
                  blocking_send(sockets[0], payload, sizeof(payload) - 1U));

    memset(recv_buf, 0, sizeof(recv_buf));
    n = recv(sockets[1], recv_buf, sizeof(recv_buf), 0);
    EXPECT_INT_EQ("blocking_send.recv", (int)(sizeof(payload) - 1U), (int)n);
    EXPECT_MEM_EQ("blocking_send.recv", payload, recv_buf, sizeof(payload) - 1U);

    close(sockets[0]);
    close(sockets[1]);
    return 0;
}

static int test_null_ctx(void) {
    EXPECT_INT_EQ("blocking_request.null_ctx", -1, blocking_request(NULL));
    return 0;
}

static int test_allow_request(void) {
    detect_result_t  result;
    block_decision_t decision;
    char             response[256];
    size_t           response_len;
    blocking_ctx_t   ctx;
    int              rc;

    memset(&result, 0, sizeof(result));
    memset(&decision, 0x7F, sizeof(decision));
    memset(response, 'X', sizeof(response));
    response_len = 123U;

    ctx.rs         = &result;
    ctx.dc         = &decision;
    ctx.res_buf    = response;
    ctx.res_buf_sz = sizeof(response);
    ctx.rs_len     = &response_len;

    rc = blocking_request(&ctx);
    EXPECT_INT_EQ("blocking_request.allow", 0, rc);
    EXPECT_INT_EQ("blocking_request.allow", 0, decision.is_blocked);
    EXPECT_INT_EQ("blocking_request.allow", 0, decision.status_code);
    EXPECT_INT_EQ("blocking_request.allow", 0, response[0]);
    EXPECT_SIZE_EQ("blocking_request.allow", 0, response_len);
    return 0;
}

static int test_block_rce(void) {
    detect_result_t  result;
    block_decision_t decision;
    char             response[256];
    size_t           response_len;
    blocking_ctx_t   ctx;
    int              rc;

    memset(&result, 0, sizeof(result));
    memset(&decision, 0, sizeof(decision));
    memset(response, 0, sizeof(response));
    response_len = 0U;

    result.matched_rce = 1;

    ctx.rs         = &result;
    ctx.dc         = &decision;
    ctx.res_buf    = response;
    ctx.res_buf_sz = sizeof(response);
    ctx.rs_len     = &response_len;

    rc = blocking_request(&ctx);
    EXPECT_INT_EQ("blocking_request.rce", 1, rc);
    EXPECT_INT_EQ("blocking_request.rce", 1, decision.is_blocked);
    EXPECT_INT_EQ("blocking_request.rce", 403, decision.status_code);
    EXPECT_STR_EQ("blocking_request.rce", "request blocked : rce",
                  decision.reason);
    EXPECT_TRUE("blocking_request.rce", "response contains 403",
                NULL != strstr(response, "HTTP/1.1 403 Forbidden"));
    EXPECT_TRUE("blocking_request.rce", "response contains reason",
                NULL != strstr(response, "request blocked : rce"));
    EXPECT_TRUE("blocking_request.rce", "response length > 0",
                response_len > 0U);
    return 0;
}

static int test_block_sqli(void) {
    detect_result_t  result;
    block_decision_t decision;
    char             response[256];
    size_t           response_len;
    blocking_ctx_t   ctx;
    int              rc;

    memset(&result, 0, sizeof(result));
    memset(&decision, 0, sizeof(decision));
    memset(response, 0, sizeof(response));
    response_len = 0U;

    result.matched_sqli = 1;

    ctx.rs         = &result;
    ctx.dc         = &decision;
    ctx.res_buf    = response;
    ctx.res_buf_sz = sizeof(response);
    ctx.rs_len     = &response_len;

    rc = blocking_request(&ctx);
    EXPECT_INT_EQ("blocking_request.sqli", 1, rc);
    EXPECT_INT_EQ("blocking_request.sqli", 1, decision.is_blocked);
    EXPECT_INT_EQ("blocking_request.sqli", 403, decision.status_code);
    EXPECT_STR_EQ("blocking_request.sqli", "request blocked : sqli",
                  decision.reason);
    EXPECT_TRUE("blocking_request.sqli", "response contains reason",
                NULL != strstr(response, "request blocked : sqli"));
    return 0;
}

static int test_block_xss_and_directory_priority(void) {
    detect_result_t  result;
    block_decision_t decision;
    char             response[256];
    size_t           response_len;
    blocking_ctx_t   ctx;
    int              rc;

    memset(&result, 0, sizeof(result));
    memset(&decision, 0, sizeof(decision));
    memset(response, 0, sizeof(response));
    response_len = 0U;

    result.matched_xss = 1;
    result.matched_directory_traversal = 1;

    ctx.rs         = &result;
    ctx.dc         = &decision;
    ctx.res_buf    = response;
    ctx.res_buf_sz = sizeof(response);
    ctx.rs_len     = &response_len;

    rc = blocking_request(&ctx);
    EXPECT_INT_EQ("blocking_request.xss_priority", 1, rc);
    EXPECT_INT_EQ("blocking_request.xss_priority", 1, decision.is_blocked);
    EXPECT_STR_EQ("blocking_request.xss_priority", "request blocked : xss",
                  decision.reason);
    EXPECT_TRUE("blocking_request.xss_priority", "response contains xss reason",
                NULL != strstr(response, "request blocked : xss"));
    return 0;
}

int main(void) {
    if (test_blocking_send()) {
        return 1;
    }
    if (test_null_ctx()) {
        return 1;
    }
    if (test_allow_request()) {
        return 1;
    }
    if (test_block_rce()) {
        return 1;
    }
    if (test_block_sqli()) {
        return 1;
    }
    if (test_block_xss_and_directory_priority()) {
        return 1;
    }
    return 0;
}

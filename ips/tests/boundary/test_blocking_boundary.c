#include "blocking.h"
#include "../../src/inline/detect.h"

#include <string.h>

#include "../common/unit_test.h"

static int test_blocked_with_zero_buffer_size(void) {
    detect_result_t  result;
    block_decision_t decision;
    char             response[8];
    size_t           response_len;
    blocking_ctx_t   ctx;
    int              rc;

    memset(&result, 0, sizeof(result));
    memset(&decision, 0, sizeof(decision));
    memset(response, 0, sizeof(response));
    response_len = 99U;

    result.matched_rce = 1;

    ctx.rs         = &result;
    ctx.dc         = &decision;
    ctx.res_buf    = response;
    ctx.res_buf_sz = 0U;
    ctx.rs_len     = &response_len;

    rc = blocking_request(&ctx);
    EXPECT_INT_EQ("blocking_boundary.zero_buf_sz", -1, rc);
    EXPECT_INT_EQ("blocking_boundary.zero_buf_sz", 1, decision.is_blocked);
    EXPECT_INT_EQ("blocking_boundary.zero_buf_sz", 403, decision.status_code);
    return 0;
}

static int test_blocked_with_missing_response_len(void) {
    detect_result_t  result;
    block_decision_t decision;
    char             response[128];
    blocking_ctx_t   ctx;
    int              rc;

    memset(&result, 0, sizeof(result));
    memset(&decision, 0, sizeof(decision));
    memset(response, 0, sizeof(response));

    result.matched_directory_traversal = 1;

    ctx.rs         = &result;
    ctx.dc         = &decision;
    ctx.res_buf    = response;
    ctx.res_buf_sz = sizeof(response);
    ctx.rs_len     = NULL;

    rc = blocking_request(&ctx);
    EXPECT_INT_EQ("blocking_boundary.null_len", -1, rc);
    EXPECT_INT_EQ("blocking_boundary.null_len", 1, decision.is_blocked);
    EXPECT_STR_EQ("blocking_boundary.null_len",
                  "request blocked : directory traversal", decision.reason);
    return 0;
}

int main(void) {
    if (test_blocked_with_zero_buffer_size()) {
        return 1;
    }
    if (test_blocked_with_missing_response_len()) {
        return 1;
    }
    return 0;
}

#include "../../src/inline/blocking.h"
#include "../../src/inline/detect.h"

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../common/unit_test.h"

int main(void) {
    detect_result_t rs;
    block_decision_t dc;
    blocking_ctx_t ctx;
    char response[256];
    char recv_buf[256];
    size_t response_len;
    int socks[2];
    ssize_t nread;

    memset(&rs, 0, sizeof(rs));
    memset(&dc, 0, sizeof(dc));
    memset(&ctx, 0, sizeof(ctx));

    EXPECT_INT_EQ("blocking_request.null", -1, blocking_request(NULL));
    EXPECT_INT_EQ("blocking_send.invalid_fd", -1,
                  blocking_send(-1, "abc", 3U));

    rs.matched_xss = 1;
    ctx.rs = &rs;
    ctx.dc = &dc;
    ctx.res_buf = response;
    ctx.res_buf_sz = sizeof(response);
    ctx.rs_len = &response_len;

    EXPECT_INT_EQ("blocking_request.block", 1, blocking_request(&ctx));
    EXPECT_INT_EQ("blocking_request.status_code", 403, dc.status_code);
    EXPECT_STR_EQ("blocking_request.reason", "request blocked : xss",
                  dc.reason);
    EXPECT_TRUE("blocking_request.response", "contains 403",
                NULL != strstr(response, "403 Forbidden"));

    EXPECT_INT_EQ("socketpair", 0,
                  socketpair(AF_UNIX, SOCK_STREAM, 0, socks));
    EXPECT_INT_EQ("blocking_send.success", 0,
                  blocking_send(socks[0], response, response_len));
    nread = read(socks[1], recv_buf, sizeof(recv_buf));
    EXPECT_TRUE("blocking_send.read", "read positive bytes", nread > 0);
    EXPECT_TRUE("blocking_send.payload", "contains blocked reason",
                NULL != strstr(recv_buf, "request blocked : xss"));

    close(socks[0]);
    close(socks[1]);
    return 0;
}

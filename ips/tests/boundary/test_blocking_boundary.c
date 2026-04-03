#include "../../src/inline/blocking.h"
#include "../../src/inline/detect.h"

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../common/unit_test.h"

int main(void) {
    detect_result_t result;
    block_decision_t decision;
    blocking_ctx_t ctx;
    int fds[2];

    memset(&result, 0, sizeof(result));
    memset(&decision, 0, sizeof(decision));
    memset(&ctx, 0, sizeof(ctx));

    EXPECT_INT_EQ("blocking_request.null", -1, blocking_request(NULL));
    EXPECT_INT_EQ("blocking_send.invalid_fd", -1,
                  blocking_send(-1, "HTTP/1.1 403\r\n\r\n", 16U));

    ctx.rs = &result;
    ctx.dc = &decision;
    EXPECT_INT_EQ("blocking_request.no_buffers", 0, blocking_request(&ctx));

    EXPECT_INT_EQ("socketpair", 0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
    EXPECT_INT_EQ("blocking_send.zero_len", -1,
                  blocking_send(fds[0], "x", 0U));
    close(fds[0]);
    close(fds[1]);

    return 0;
}

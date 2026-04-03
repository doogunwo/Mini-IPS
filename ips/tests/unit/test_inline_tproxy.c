#include "../../src/inline/tproxy.h"

#include <errno.h>
#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    struct sockaddr_in addr;
    int fd;

    memset(&addr, 0, sizeof(addr));
    fd = -1;

    EXPECT_PTR_NOT_NULL("tproxy_create.null_cfg",
                        NULL == tproxy_create(NULL) ? (void *)1 : NULL);
    EXPECT_INT_EQ("tproxy_accept_client.null", -1,
                  tproxy_accept_client(NULL, &addr, &addr, &fd));
    EXPECT_INT_EQ("upstream_connect.null", -1, upstream_connect(NULL, &fd));
    EXPECT_INT_EQ("tproxy_relay_loop.invalid", -1,
                  tproxy_relay_loop(NULL, -1, -1));

    return 0;
}

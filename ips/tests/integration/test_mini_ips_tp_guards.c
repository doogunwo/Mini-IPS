#include "../../src/inline/mini_ips.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    mini_ips_ctx_t ctx;
    tproxy_t       fake_tp;
    int            rc;

    rc = mini_ips_run_tp(NULL);
    EXPECT_INT_EQ("mini_ips_run_tp.null_ctx", -1, rc);

    memset(&ctx, 0, sizeof(ctx));
    rc = mini_ips_run_tp(&ctx);
    EXPECT_INT_EQ("mini_ips_run_tp.uninitialized", -1, rc);

    memset(&ctx, 0, sizeof(ctx));
    memset(&fake_tp, 0, sizeof(fake_tp));
    ctx.initialized = 1;
    ctx.stop = 1;
    ctx.tp = &fake_tp;

    rc = mini_ips_run_tp(&ctx);
    EXPECT_INT_EQ("mini_ips_run_tp.stop_short_circuit", 0, rc);

    memset(&ctx, 0, sizeof(ctx));
    memset(&fake_tp, 0, sizeof(fake_tp));
    fake_tp.listen_fd = -1;
    ctx.initialized = 1;
    ctx.tp = &fake_tp;

    rc = mini_ips_run_tp(&ctx);
    EXPECT_INT_EQ("mini_ips_run_tp.invalid_listener", -1, rc);

    return 0;
}

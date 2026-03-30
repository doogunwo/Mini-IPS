#include "../../src/inline/mini_ips.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int main(void) {
    mini_ips_ctx_t ctx;
    char           rules_dir[PATH_MAX];
    int            rc;

    mini_ips_destroy(NULL);

    EXPECT_INT_EQ("resolve_ruleset_dir", 0,
                  resolve_ruleset_dir(rules_dir, sizeof(rules_dir)));
    EXPECT_INT_EQ("setenv", 0, setenv(MINI_IPS_RULESET_ENV, rules_dir, 1));

    rc = mini_ips_set(&ctx);
    EXPECT_INT_EQ("mini_ips_set", 0, rc);
    EXPECT_PTR_NOT_NULL("mini_ips_set", ctx.engine);
    EXPECT_TRUE("mini_ips_set", "rings allocated",
                NULL != ctx.req_ring.slots && NULL != ctx.res_ring.slots);

    mini_ips_destroy(&ctx);

    EXPECT_TRUE("mini_ips_destroy", "engine cleared", NULL == ctx.engine);
    EXPECT_TRUE("mini_ips_destroy", "tp cleared", NULL == ctx.tp);
    EXPECT_TRUE("mini_ips_destroy", "ruleset cleared", NULL == ctx.ruleset_path);
    EXPECT_INT_EQ("mini_ips_destroy", 0, ctx.initialized);
    EXPECT_INT_EQ("mini_ips_destroy", 0, ctx.stop);
    EXPECT_INT_EQ("mini_ips_destroy", 0, ctx.ring_enabled);
    EXPECT_TRUE("mini_ips_destroy", "req ring freed", NULL == ctx.req_ring.slots);
    EXPECT_TRUE("mini_ips_destroy", "res ring freed", NULL == ctx.res_ring.slots);

    unsetenv(MINI_IPS_RULESET_ENV);
    return 0;
}

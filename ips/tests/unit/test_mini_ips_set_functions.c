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

    rc = mini_ips_set(NULL);
    EXPECT_INT_EQ("mini_ips_set.null_ctx", -1, rc);

    unsetenv(MINI_IPS_RULESET_ENV);
    memset(&ctx, 0x5A, sizeof(ctx));
    rc = mini_ips_set(&ctx);
    EXPECT_INT_EQ("mini_ips_set.missing_env", -1, rc);

    EXPECT_INT_EQ("resolve_ruleset_dir", 0,
                  resolve_ruleset_dir(rules_dir, sizeof(rules_dir)));
    EXPECT_INT_EQ("setenv", 0, setenv(MINI_IPS_RULESET_ENV, rules_dir, 1));

    rc = mini_ips_set(&ctx);
    EXPECT_INT_EQ("mini_ips_set.success", 0, rc);
    EXPECT_STR_EQ("mini_ips_set.success", rules_dir, ctx.ruleset_path);
    EXPECT_INT_EQ("mini_ips_set.success", 1, ctx.initialized);
    EXPECT_INT_EQ("mini_ips_set.success", 1, ctx.ring_enabled);
    EXPECT_PTR_NOT_NULL("mini_ips_set.success", ctx.engine);
    EXPECT_SIZE_EQ("mini_ips_set.success", MINI_IPS_RING_SLOT_COUNT,
                   ctx.req_ring.slot_count);
    EXPECT_SIZE_EQ("mini_ips_set.success", MINI_IPS_RING_SLOT_COUNT,
                   ctx.res_ring.slot_count);
    EXPECT_TRUE("mini_ips_set.success", "db tables loaded",
                    ctx.db.sqli.count > 0U && ctx.db.xss.count > 0U &&
                    ctx.db.rce.count > 0U &&
                    ctx.db.directory_traversal.count > 0U);

    mini_ips_destroy(&ctx);
    unsetenv(MINI_IPS_RULESET_ENV);
    return 0;
}

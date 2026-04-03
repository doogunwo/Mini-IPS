#include "../../src/inline/mini_ips_hs.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "../common/unit_test.h"

static int resolve_ruleset_dir(char *out, size_t out_sz) {
    if (NULL == out || 0U == out_sz) {
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
    char rules_dir[PATH_MAX];
    int rc;

    unsetenv(MINI_IPS_RULESET_ENV);
    memset(&ctx, 0, sizeof(ctx));
    EXPECT_INT_EQ("mini_ips_set.missing_env", -1, mini_ips_set(&ctx));

    EXPECT_INT_EQ("resolve_ruleset_dir", 0,
                  resolve_ruleset_dir(rules_dir, sizeof(rules_dir)));
    EXPECT_INT_EQ("setenv", 0, setenv(MINI_IPS_RULESET_ENV, rules_dir, 1));

    rc = mini_ips_set(&ctx);
    EXPECT_INT_EQ("mini_ips_set.success", 0, rc);
    EXPECT_PTR_NOT_NULL("mini_ips_set.engine", ctx.engine);
    EXPECT_INT_EQ("mini_ips_set.initialized", 1, ctx.initialized);
    EXPECT_TRUE("mini_ips_set.hs_db_loaded", "non-empty xss table",
                ctx.db.xss.count > 0U);

    mini_ips_destroy(&ctx);
    unsetenv(MINI_IPS_RULESET_ENV);
    return 0;
}

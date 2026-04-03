#include "../../src/inline/regex.h"

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
    regex_db_t db;
    char rules_dir[PATH_MAX];

    memset(&db, 0, sizeof(db));

    EXPECT_INT_EQ("resolve_ruleset_dir", 0,
                  resolve_ruleset_dir(rules_dir, sizeof(rules_dir)));
    EXPECT_INT_EQ("regex_signatures_load", 0,
                  regex_signatures_load(&db, rules_dir));
    EXPECT_TRUE("regex_signatures_load.sqli", "non-empty", db.sqli.count > 0U);
    EXPECT_TRUE("regex_signatures_load.xss", "non-empty", db.xss.count > 0U);
    EXPECT_TRUE("regex_signatures_load.rce", "non-empty", db.rce.count > 0U);
    EXPECT_TRUE("regex_signatures_load.dir", "non-empty",
                db.directory_traversal.count > 0U);

    regex_signatures_free(&db);
    EXPECT_SIZE_EQ("regex_signatures_free.sqli", 0U, db.sqli.count);
    EXPECT_SIZE_EQ("regex_signatures_free.xss", 0U, db.xss.count);
    EXPECT_SIZE_EQ("regex_signatures_free.rce", 0U, db.rce.count);
    EXPECT_SIZE_EQ("regex_signatures_free.dir", 0U,
                   db.directory_traversal.count);
    return 0;
}

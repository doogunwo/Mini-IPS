#include "../../src/inline/engine.h"
#include "../../src/inline/http_parser.h"
#include "../../src/inline/regex.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
    detect_engine_t *engine;
    http_message_t msg;
    detect_match_info_t info;
    char rules_dir[PATH_MAX];
    size_t matches;
    int score;
    int errors;
    int rc;

    memset(&db, 0, sizeof(db));
    memset(&msg, 0, sizeof(msg));

    EXPECT_INT_EQ("resolve_ruleset_dir", 0,
                  resolve_ruleset_dir(rules_dir, sizeof(rules_dir)));
    EXPECT_INT_EQ("regex_signatures_load", 0,
                  regex_signatures_load(&db, rules_dir));

    engine = engine_regex_create(&db);
    EXPECT_PTR_NOT_NULL("engine_regex_create", engine);
    EXPECT_PTR_NOT_NULL("engine_regex_create.sqli_runtime", engine->sqli_runtime);
    EXPECT_PTR_NOT_NULL("engine_regex_create.xss_runtime", engine->xss_runtime);
    EXPECT_PTR_NOT_NULL("engine_regex_create.rce_runtime", engine->rce_runtime);
    EXPECT_PTR_NOT_NULL("engine_regex_create.dir_traversal_runtime",
                        engine->dir_traversal_runtime);

    rc = engine_match_runtime(NULL, &msg, &matches, &score, &errors, &info);
    EXPECT_INT_EQ("engine_match_runtime.null_runtime", 0, rc);
    EXPECT_INT_EQ("engine_match_runtime.null_runtime.errors", 1, errors);

    msg.type = 1;
    msg.uri = "/a/../admin";
    msg.headers = "Host: a\r\n";
    msg.body = (uint8_t *)"x=<script>";
    msg.body_len = strlen((const char *)msg.body);

    rc = engine_match_runtime(engine->dir_traversal_runtime, &msg, &matches,
                              &score, &errors, &info);
    EXPECT_INT_EQ("engine_match_runtime.dir", 0, rc);
    EXPECT_TRUE("engine_match_runtime.dir", "matches nonzero", matches > 0U);

    rc = engine_match_runtime(engine->xss_runtime, &msg, &matches, &score,
                              &errors, &info);
    EXPECT_INT_EQ("engine_match_runtime.xss", 0, rc);
    EXPECT_TRUE("engine_match_runtime.xss", "score nonnegative", score >= 0);

    engine_regex_destroy(engine);
    regex_signatures_free(&db);
    return 0;
}

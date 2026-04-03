#include "../../src/inline/detect.h"
#include "../../src/inline/engine.h"
#include "../../src/inline/http_parser.h"
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
    detect_engine_t *engine;
    http_message_t msg;
    detect_result_t result;
    char rules_dir[PATH_MAX];
    const char *res;

    memset(&db, 0, sizeof(db));
    memset(&msg, 0, sizeof(msg));

    EXPECT_INT_EQ("resolve_ruleset_dir", 0,
                  resolve_ruleset_dir(rules_dir, sizeof(rules_dir)));
    EXPECT_INT_EQ("regex_signatures_load", 0,
                  regex_signatures_load(&db, rules_dir));

    engine = engine_regex_create(&db);
    EXPECT_PTR_NOT_NULL("engine_regex_create", engine);

    res = "HTTP/1.1 200 OK\r\nContent-Length: 25\r\n\r\n<script>alert(1)</script>";
    EXPECT_INT_EQ("http_parser_try", 1,
                  http_parser_try((const uint8_t *)res, strlen(res), &msg));
    EXPECT_INT_EQ("detect_run", 0, detect_run(engine, &msg, &result, NULL));
    EXPECT_INT_EQ("detect_run.matched", 0, result.matched);
    EXPECT_INT_EQ("detect_run.xss", 0, result.matched_xss);

    EXPECT_INT_EQ("http_parser_free", 1, http_parser_free(&msg));
    engine_regex_destroy(engine);
    regex_signatures_free(&db);
    return 0;
}

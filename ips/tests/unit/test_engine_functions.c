#include "../../src/inline/engine.h"
#include "../../src/inline/regex.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    regex_db_t       db;
    detect_engine_t *engine;

    memset(&db, 0, sizeof(db));

    EXPECT_INT_EQ("regex_signatures_load", 0,
                  regex_signatures_load(&db, "rules"));
    EXPECT_TRUE("regex_signatures_load", "non-empty sqli table",
                db.sqli.count > 0U);
    EXPECT_TRUE("regex_signatures_load", "non-empty xss table",
                db.xss.count > 0U);
    EXPECT_TRUE("regex_signatures_load", "non-empty rce table",
                db.rce.count > 0U);
    EXPECT_TRUE("regex_signatures_load", "non-empty directory traversal table",
                db.directory_traversal.count > 0U);

    engine = engine_regex_create(&db);
    EXPECT_PTR_NOT_NULL("engine_regex_create", engine);
    EXPECT_PTR_NOT_NULL("engine_regex_create.sqli_runtime",
                        NULL != engine ? engine->sqli_runtime : NULL);
    EXPECT_PTR_NOT_NULL("engine_regex_create.xss_runtime",
                        NULL != engine ? engine->xss_runtime : NULL);
    EXPECT_PTR_NOT_NULL("engine_regex_create.rce_runtime",
                        NULL != engine ? engine->rce_runtime : NULL);
    EXPECT_PTR_NOT_NULL("engine_regex_create.dir_traversal_runtime",
                        NULL != engine ? engine->dir_traversal_runtime : NULL);
    EXPECT_INT_EQ("engine_regex_create.compile_errors", 0,
                  NULL != engine ? engine->compile_errors : -1);

    engine_regex_destroy(engine);
    regex_signatures_free(&db);
    return 0;
}

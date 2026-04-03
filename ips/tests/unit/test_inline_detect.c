#include "../../src/inline/detect.h"
#include "../../src/inline/engine.h"
#include "../../src/inline/http_parser.h"
#include "../../src/inline/regex.h"

#include <stdlib.h>
#include <string.h>

#include "../common/unit_test.h"

static char *dup_text(const char *s) {
    size_t len;
    char *copy;

    len = strlen(s);
    copy = (char *)malloc(len + 1U);
    if (NULL == copy) {
        return NULL;
    }
    memcpy(copy, s, len + 1U);
    return copy;
}

static void free_regex_db(regex_db_t *db) {
    regex_table_t *tables[4];
    size_t i;
    size_t j;

    tables[0] = &db->sqli;
    tables[1] = &db->directory_traversal;
    tables[2] = &db->rce;
    tables[3] = &db->xss;

    for (i = 0; i < 4U; i++) {
        for (j = 0; j < tables[i]->count; j++) {
            free(tables[i]->items[j].pattern);
        }
        free(tables[i]->items);
        tables[i]->items = NULL;
        tables[i]->count = 0U;
    }
}

int main(void) {
    regex_db_t db;
    detect_engine_t *engine;
    http_message_t msg;
    detect_result_t result;
    uint8_t body[] = "x=<script>";
    int rc;

    memset(&db, 0, sizeof(db));
    memset(&msg, 0, sizeof(msg));

    db.sqli.items = (regex_signature_t *)malloc(sizeof(*db.sqli.items));
    db.directory_traversal.items =
        (regex_signature_t *)malloc(sizeof(*db.directory_traversal.items));
    db.rce.items = (regex_signature_t *)malloc(sizeof(*db.rce.items));
    db.xss.items = (regex_signature_t *)malloc(sizeof(*db.xss.items));
    EXPECT_TRUE("malloc", "allocated rule tables",
                NULL != db.sqli.items && NULL != db.directory_traversal.items &&
                    NULL != db.rce.items && NULL != db.xss.items);

    db.sqli.count = 1U;
    db.sqli.items[0].pattern = dup_text("union select");
    db.sqli.items[0].priority = 10;
    db.sqli.items[0].context = 1;

    db.directory_traversal.count = 1U;
    db.directory_traversal.items[0].pattern = dup_text("../");
    db.directory_traversal.items[0].priority = 9;
    db.directory_traversal.items[0].context = 1;

    db.rce.count = 1U;
    db.rce.items[0].pattern = dup_text("cmd=");
    db.rce.items[0].priority = 8;
    db.rce.items[0].context = 2;

    db.xss.count = 1U;
    db.xss.items[0].pattern = dup_text("<script>");
    db.xss.items[0].priority = 7;
    db.xss.items[0].context = 3;

    msg.type = 1;
    msg.method = dup_text("GET");
    msg.uri = dup_text("/a/../login?x=1 union select");
    msg.headers = dup_text("Host: a\r\nX-Cmd: cmd=whoami\r\n");
    msg.body = body;
    msg.body_len = sizeof(body) - 1U;

    engine = engine_regex_create(&db);
    EXPECT_PTR_NOT_NULL("engine_regex_create", engine);

    EXPECT_INT_EQ("detect_run.null_msg", -1,
                  detect_run(engine, NULL, &result, NULL));

    rc = detect_run(engine, &msg, &result, NULL);
    EXPECT_INT_EQ("detect_run.request", 0, rc);
    EXPECT_INT_EQ("detect_run.request.matched", 1, result.matched);
    EXPECT_INT_EQ("detect_run.request.sqli", 1, result.matched_sqli);
    EXPECT_INT_EQ("detect_run.request.directory_traversal", 1,
                  result.matched_directory_traversal);
    EXPECT_INT_EQ("detect_run.request.rce", 1, result.matched_rce);
    EXPECT_INT_EQ("detect_run.request.xss", 1, result.matched_xss);
    EXPECT_SIZE_EQ("detect_run.request.total_matches", 4U, result.total_matches);
    EXPECT_INT_EQ("detect_run.request.total_score", 34, result.total_score);

    engine_regex_destroy(engine);
    free(msg.method);
    free(msg.uri);
    free(msg.headers);
    free_regex_db(&db);
    return 0;
}

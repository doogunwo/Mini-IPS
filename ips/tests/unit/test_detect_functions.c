#include "../../src/inline/detect.h"
#include "../../src/inline/engine.h"
#include "../../src/inline/http_parser.h"
#include "../../src/inline/regex.h"

#include <stdlib.h>
#include <string.h>

#include "../common/unit_test.h"

static char *dup_text(const char *s) {
    size_t len;
    char  *copy;

    if (NULL == s) {
        return NULL;
    }

    len  = strlen(s);
    copy = (char *)malloc(len + 1U);
    if (NULL == copy) {
        return NULL;
    }
    memcpy(copy, s, len + 1U);
    return copy;
}

static void free_regex_db(regex_db_t *db) {
    regex_table_t *tables[4];
    size_t         i;
    size_t         j;

    if (NULL == db) {
        return;
    }

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
        tables[i]->count = 0;
    }
}

int main(void) {
    regex_db_t      db;
    detect_engine_t *engine;
    http_message_t  req_msg;
    http_message_t  res_msg;
    detect_result_t result;
    uint8_t         req_body[] = "name=%3cscript%3e";
    uint8_t         res_body[] = "<script>alert(1)</script>";
    int             rc;

    memset(&db, 0, sizeof(db));
    memset(&req_msg, 0, sizeof(req_msg));
    memset(&res_msg, 0, sizeof(res_msg));

    db.sqli.items = (regex_signature_t *)malloc(sizeof(*db.sqli.items));
    db.xss.items = (regex_signature_t *)malloc(sizeof(*db.xss.items));
    db.directory_traversal.items =
        (regex_signature_t *)malloc(sizeof(*db.directory_traversal.items));
    db.rce.items = (regex_signature_t *)malloc(sizeof(*db.rce.items));
    EXPECT_TRUE("malloc", "allocated rule tables",
                NULL != db.sqli.items && NULL != db.xss.items &&
                    NULL != db.directory_traversal.items &&
                    NULL != db.rce.items);

    db.sqli.count                  = 1;
    db.sqli.items[0].pattern       = dup_text("union select");
    db.sqli.items[0].priority      = 10;
    db.sqli.items[0].context       = 1;
    db.directory_traversal.count   = 1;
    db.directory_traversal.items[0].pattern = dup_text("../");
    db.directory_traversal.items[0].priority = 9;
    db.directory_traversal.items[0].context = 1;
    db.rce.count                   = 1;
    db.rce.items[0].pattern        = dup_text("cmd=");
    db.rce.items[0].priority       = 8;
    db.rce.items[0].context        = 2;
    db.xss.count                   = 2;
    free(db.xss.items);
    db.xss.items = (regex_signature_t *)malloc(2U * sizeof(*db.xss.items));
    EXPECT_PTR_NOT_NULL("malloc", db.xss.items);
    db.xss.items[0].pattern        = dup_text("%3cscript%3e");
    db.xss.items[0].priority       = 7;
    db.xss.items[0].context        = 3;
    db.xss.items[1].pattern        = dup_text("<script>");
    db.xss.items[1].priority       = 6;
    db.xss.items[1].context        = 4;

    req_msg.type     = 1;
    req_msg.method   = dup_text("GET");
    req_msg.uri      = dup_text("/a/../login?x=1 union select");
    req_msg.headers  = dup_text("Host: a\r\nX-Cmd: cmd=whoami\r\n");
    req_msg.body     = req_body;
    req_msg.body_len = sizeof(req_body) - 1U;

    res_msg.type        = 0;
    res_msg.status_code = 200;
    res_msg.headers     = dup_text("Content-Type: text/html\r\n");
    res_msg.body        = res_body;
    res_msg.body_len    = sizeof(res_body) - 1U;

    engine = engine_regex_create(&db);
    EXPECT_PTR_NOT_NULL("engine_regex_create", engine);

    rc = detect_run(engine, NULL, &result);
    EXPECT_INT_EQ("detect_run.null_msg", -1, rc);

    rc = detect_run(engine, &req_msg, &result);
    EXPECT_INT_EQ("detect_run.request", 0, rc);
    EXPECT_INT_EQ("detect_run.request", 1, result.matched);
    EXPECT_INT_EQ("detect_run.request", 1, result.matched_sqli);
    EXPECT_INT_EQ("detect_run.request", 1, result.matched_directory_traversal);
    EXPECT_INT_EQ("detect_run.request", 1, result.matched_rce);
    EXPECT_INT_EQ("detect_run.request", 1, result.matched_xss);
    EXPECT_SIZE_EQ("detect_run.request", 4, result.total_matches);
    EXPECT_INT_EQ("detect_run.request", 10, result.sqli_score);
    EXPECT_INT_EQ("detect_run.request", 9,
                  result.directory_traversal_score);
    EXPECT_INT_EQ("detect_run.request", 8, result.rce_score);
    EXPECT_INT_EQ("detect_run.request", 7, result.xss_score);
    EXPECT_INT_EQ("detect_run.request", 34, result.total_score);
    EXPECT_INT_EQ("detect_run.request", 0, result.total_errors);

    rc = detect_run(engine, &res_msg, &result);
    EXPECT_INT_EQ("detect_run.response", 0, rc);
    EXPECT_INT_EQ("detect_run.response", 1, result.matched);
    EXPECT_INT_EQ("detect_run.response", 0, result.matched_sqli);
    EXPECT_INT_EQ("detect_run.response", 0,
                  result.matched_directory_traversal);
    EXPECT_INT_EQ("detect_run.response", 0, result.matched_rce);
    EXPECT_INT_EQ("detect_run.response", 1, result.matched_xss);
    EXPECT_SIZE_EQ("detect_run.response", 1, result.total_matches);
    EXPECT_INT_EQ("detect_run.response", 0, result.sqli_score);
    EXPECT_INT_EQ("detect_run.response", 0,
                  result.directory_traversal_score);
    EXPECT_INT_EQ("detect_run.response", 0, result.rce_score);
    EXPECT_INT_EQ("detect_run.response", 6, result.xss_score);
    EXPECT_INT_EQ("detect_run.response", 6, result.total_score);
    EXPECT_INT_EQ("detect_run.response", 0, result.total_errors);

    engine_regex_destroy(engine);
    free(req_msg.method);
    free(req_msg.uri);
    free(req_msg.headers);
    free(res_msg.headers);
    free_regex_db(&db);
    return 0;
}

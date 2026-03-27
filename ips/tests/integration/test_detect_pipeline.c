#include "../../src/inline/decoding.h"
#include "../../src/inline/detect.h"
#include "../../src/inline/engine.h"
#include "../../src/inline/http_parser.h"
#include "../../src/inline/normalization.h"
#include "../../src/inline/regex.h"

#include <stdlib.h>
#include <string.h>

#include "../common/unit_test.h"

static char *dup_text(const char *s) {
    size_t len;
    char  *copy;

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
    const char      *req;
    regex_db_t       db;
    detect_engine_t *engine;
    http_message_t   msg;
    detect_result_t  result;
    char             decoded_uri[256];
    char             normalized_uri[256];
    uint8_t          decoded_body[256];
    size_t           decoded_body_len;
    int              rc;

    memset(&db, 0, sizeof(db));

    db.directory_traversal.items =
        (regex_signature_t *)malloc(sizeof(*db.directory_traversal.items));
    db.xss.items = (regex_signature_t *)malloc(sizeof(*db.xss.items));
    EXPECT_TRUE("malloc", "allocated detect pipeline tables",
                NULL != db.directory_traversal.items && NULL != db.xss.items);

    db.directory_traversal.count            = 1;
    db.directory_traversal.items[0].pattern = dup_text("/admin");
    db.directory_traversal.items[0].priority = 9;
    db.directory_traversal.items[0].context  = 1;
    db.xss.count                            = 1;
    db.xss.items[0].pattern                 = dup_text("<script>");
    db.xss.items[0].priority                = 7;
    db.xss.items[0].context                 = 3;

    engine = engine_regex_create(&db);
    EXPECT_PTR_NOT_NULL("engine_regex_create", engine);

    req = "POST /%252e%252e/%252fadmin HTTP/1.1\r\n"
          "Host: a\r\nContent-Length: 16\r\n\r\n"
          "%253cscript%253e";
    rc = http_parser_try((const uint8_t *)req, strlen(req), &msg);
    CHECK(1 == rc, "detect pipeline parse");

    rc = http_decode_percent_recursive(decoded_uri, sizeof(decoded_uri), msg.uri,
                                       3);
    CHECK(1 == rc, "detect pipeline decode uri");
    rc = http_normalize_uri(normalized_uri, sizeof(normalized_uri), decoded_uri);
    CHECK(1 == rc, "detect pipeline normalize uri");
    free(msg.uri);
    msg.uri = dup_text(normalized_uri);
    EXPECT_PTR_NOT_NULL("dup_text", msg.uri);

    rc = http_body_decode_percent_recursive(decoded_body, sizeof(decoded_body),
                                            msg.body, msg.body_len, 3,
                                            &decoded_body_len);
    CHECK(1 == rc, "detect pipeline decode body");
    free(msg.body);
    msg.body = (uint8_t *)malloc(decoded_body_len);
    EXPECT_PTR_NOT_NULL("malloc", msg.body);
    memcpy(msg.body, decoded_body, decoded_body_len);
    msg.body_len = decoded_body_len;

    rc = detect_run(engine, &msg, &result);
    EXPECT_INT_EQ("detect_run", 0, rc);
    EXPECT_INT_EQ("detect_run", 1, result.matched);
    EXPECT_INT_EQ("detect_run", 1, result.matched_directory_traversal);
    EXPECT_INT_EQ("detect_run", 1, result.matched_xss);
    EXPECT_SIZE_EQ("detect_run", 2, result.total_matches);
    EXPECT_INT_EQ("detect_run", 16, result.total_score);

    engine_regex_destroy(engine);
    http_parser_free(&msg);
    free_regex_db(&db);
    return 0;
}

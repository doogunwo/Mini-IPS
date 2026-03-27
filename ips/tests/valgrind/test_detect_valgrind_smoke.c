#include "../../src/inline/decoding.h"
#include "../../src/inline/detect.h"
#include "../../src/inline/engine.h"
#include "../../src/inline/http_parser.h"
#include "../../src/inline/normalization.h"
#include "../../src/inline/regex.h"

#include <stdlib.h>
#include <string.h>

#include "../common/unit_test.h"

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

    req = "POST /%252e%252e/%252fadmin HTTP/1.1\r\n"
          "Host: a\r\nContent-Length: 16\r\n\r\n"
          "%253cscript%253e";

    rc = regex_signatures_load(&db, "rules");
    EXPECT_INT_EQ("regex_signatures_load", 0, rc);

    engine = engine_regex_create(&db);
    EXPECT_PTR_NOT_NULL("engine_regex_create", engine);

    rc = http_parser_try((const uint8_t *)req, strlen(req), &msg);
    EXPECT_INT_EQ("http_parser_try", 1, rc);

    rc = http_decode_percent_recursive(decoded_uri, sizeof(decoded_uri), msg.uri,
                                       3);
    EXPECT_INT_EQ("http_decode_percent_recursive", 1, rc);

    rc = http_normalize_uri(normalized_uri, sizeof(normalized_uri), decoded_uri);
    EXPECT_INT_EQ("http_normalize_uri", 1, rc);

    free(msg.uri);
    msg.uri = strdup(normalized_uri);
    EXPECT_PTR_NOT_NULL("strdup", msg.uri);

    rc = http_body_decode_percent_recursive(decoded_body, sizeof(decoded_body),
                                            msg.body, msg.body_len, 3,
                                            &decoded_body_len);
    EXPECT_INT_EQ("http_body_decode_percent_recursive", 1, rc);

    free(msg.body);
    msg.body = (uint8_t *)malloc(decoded_body_len);
    EXPECT_PTR_NOT_NULL("malloc", msg.body);
    memcpy(msg.body, decoded_body, decoded_body_len);
    msg.body_len = decoded_body_len;

    rc = detect_run(engine, &msg, &result);
    EXPECT_INT_EQ("detect_run", 0, rc);
    EXPECT_INT_EQ("detect_run", 1, result.matched);
    EXPECT_TRUE("detect_run", "total_matches > 0", result.total_matches > 0U);

    http_parser_free(&msg);
    engine_regex_destroy(engine);
    regex_signatures_free(&db);
    return 0;
}

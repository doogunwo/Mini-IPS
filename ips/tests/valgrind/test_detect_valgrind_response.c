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
    const char      *res;
    regex_db_t       db;
    detect_engine_t *engine;
    http_message_t   msg;
    detect_result_t  result;
    uint8_t          decoded_body[256];
    size_t           decoded_body_len;
    int              rc;

    memset(&db, 0, sizeof(db));

    res = "HTTP/1.1 302 Found\r\n"
          "Location: javascript:alert(1)\r\n"
          "Content-Length: 16\r\n\r\n"
          "%253cscript%253e";

    rc = regex_signatures_load(&db, "rules");
    EXPECT_INT_EQ("regex_signatures_load", 0, rc);

    engine = engine_regex_create(&db);
    EXPECT_PTR_NOT_NULL("engine_regex_create", engine);

    rc = http_parser_try((const uint8_t *)res, strlen(res), &msg);
    EXPECT_INT_EQ("http_parser_try", 1, rc);
    EXPECT_INT_EQ("http_parser_try", 0, msg.type);

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
    EXPECT_INT_EQ("detect_run", 1, result.matched_xss);
    EXPECT_TRUE("detect_run", "total_matches > 0", result.total_matches > 0U);

    http_parser_free(&msg);
    engine_regex_destroy(engine);
    regex_signatures_free(&db);
    return 0;
}

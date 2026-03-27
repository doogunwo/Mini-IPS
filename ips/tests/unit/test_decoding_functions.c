#include "decoding.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    char    text[256];
    uint8_t body[256];
    size_t  out_len;
    int     rc;

    rc = http_decode_percent(text, sizeof(text), "/a%2fb");
    EXPECT_INT_EQ("http_decode_percent", 1, rc);
    EXPECT_STR_EQ("http_decode_percent", "/a/b", text);

    rc = http_decode_percent(text, sizeof(text), "/plain/path");
    EXPECT_INT_EQ("http_decode_percent", 0, rc);
    EXPECT_STR_EQ("http_decode_percent", "/plain/path", text);

    rc = http_decode_percent_recursive(text, sizeof(text), "%252fadmin", 3);
    EXPECT_INT_EQ("http_decode_percent_recursive", 1, rc);
    EXPECT_STR_EQ("http_decode_percent_recursive", "/admin", text);

    rc = http_decode_plus_as_space(text, sizeof(text), "a+b+c");
    EXPECT_INT_EQ("http_decode_plus_as_space", 1, rc);
    EXPECT_STR_EQ("http_decode_plus_as_space", "a b c", text);

    rc = http_decode_html_entity(text, sizeof(text), "&lt;ok&gt;&amp;");
    EXPECT_INT_EQ("http_decode_html_entity", 1, rc);
    EXPECT_STR_EQ("http_decode_html_entity", "<ok>&", text);

    rc = http_decode_escape_sequence(text, sizeof(text), "\\x41\\n\\u003c");
    EXPECT_INT_EQ("http_decode_escape_sequence", 1, rc);
    EXPECT_STR_EQ("http_decode_escape_sequence", "A\n<", text);

    rc = http_has_invalid_percent_encoding("%ZZ");
    EXPECT_INT_EQ("http_has_invalid_percent_encoding", 1, rc);
    rc = http_has_invalid_percent_encoding("%41");
    EXPECT_INT_EQ("http_has_invalid_percent_encoding", 0, rc);

    rc = http_body_decode_percent(body, sizeof(body), (const uint8_t *)"A%42", 4,
                                  &out_len);
    EXPECT_INT_EQ("http_body_decode_percent", 1, rc);
    EXPECT_SIZE_EQ("http_body_decode_percent", 2, out_len);
    EXPECT_TRUE("http_body_decode_percent", "body bytes are A,B",
                'A' == body[0] && 'B' == body[1]);

    rc = http_body_decode_percent_recursive(body, sizeof(body),
                                            (const uint8_t *)"%253c", 5, 3,
                                            &out_len);
    EXPECT_INT_EQ("http_body_decode_percent_recursive", 1, rc);
    EXPECT_TRUE("http_body_decode_percent_recursive", "decoded body is <",
                1 == out_len && '<' == body[0]);

    rc = http_body_decode_html_entity(body, sizeof(body),
                                      (const uint8_t *)"&lt;A&gt;", 9, &out_len);
    EXPECT_INT_EQ("http_body_decode_html_entity", 1, rc);
    EXPECT_SIZE_EQ("http_body_decode_html_entity", 3, out_len);
    EXPECT_MEM_EQ("http_body_decode_html_entity", "<A>", body, 3);

    rc = http_body_decode_escape_sequence(body, sizeof(body),
                                          (const uint8_t *)"\\x41\\n", 6,
                                          &out_len);
    EXPECT_INT_EQ("http_body_decode_escape_sequence", 1, rc);
    EXPECT_SIZE_EQ("http_body_decode_escape_sequence", 2, out_len);
    EXPECT_TRUE("http_body_decode_escape_sequence",
                "body bytes are A and newline",
                'A' == body[0] && '\n' == body[1]);

    rc = http_body_has_invalid_percent_encoding((const uint8_t *)"%2G", 3);
    EXPECT_INT_EQ("http_body_has_invalid_percent_encoding", 1, rc);

    return 0;
}

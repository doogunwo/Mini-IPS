#include "../../src/inline/decoding.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    char text[512];
    uint8_t body_out[512];
    size_t out_len;
    int rc;
    const uint8_t body_src[] = "name=%3Cscript%3E";

    rc = http_decode_percent(text, sizeof(text), "/a%2fb");
    EXPECT_INT_EQ("http_decode_percent", 1, rc);
    EXPECT_STR_EQ("http_decode_percent", "/a/b", text);

    rc = http_decode_html_entity(text, sizeof(text), "&lt;tag&gt;");
    EXPECT_INT_EQ("http_decode_html_entity", 1, rc);
    EXPECT_STR_EQ("http_decode_html_entity", "<tag>", text);

    rc = http_decode_escape_sequence(text, sizeof(text), "\\u003cscript\\u003e");
    EXPECT_INT_EQ("http_decode_escape_sequence", 1, rc);
    EXPECT_STR_EQ("http_decode_escape_sequence", "<script>", text);

    rc = http_uri_canonicalize(text, sizeof(text), "/%252e%252e/%252fadmin", 3);
    EXPECT_INT_EQ("http_uri_canonicalize", 1, rc);
    EXPECT_TRUE("http_uri_canonicalize", "decoded path present",
                NULL != strstr(text, "../"));

    rc = http_body_canonicalize(body_out, sizeof(body_out), body_src,
                                sizeof(body_src) - 1U, 3, &out_len);
    EXPECT_INT_EQ("http_body_canonicalize", 1, rc);
    EXPECT_MEM_EQ("http_body_canonicalize", "name=<script>", body_out,
                  strlen("name=<script>"));
    EXPECT_SIZE_EQ("http_body_canonicalize", strlen("name=<script>"), out_len);

    EXPECT_INT_EQ("http_has_invalid_percent_encoding", 1,
                  http_has_invalid_percent_encoding("%2G"));
    EXPECT_INT_EQ("http_body_has_invalid_percent_encoding", 1,
                  http_body_has_invalid_percent_encoding(
                      (const uint8_t *)"%2G", 3U));

    return 0;
}

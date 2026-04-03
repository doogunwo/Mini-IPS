#include "../../src/inline/normalization.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    char text[256];
    uint8_t body_out[256];
    size_t out_len;
    int rc;
    const uint8_t body_src[] = "AbC";

    rc = http_normalize_uri(text, sizeof(text), "/a//../admin?x=1");
    EXPECT_INT_EQ("http_normalize_uri", 1, rc);
    EXPECT_TRUE("http_normalize_uri", "contains normalized admin",
                NULL != strstr(text, "/admin"));

    rc = http_normalize_spaces(text, sizeof(text), "  a   b\tc  ");
    EXPECT_INT_EQ("http_normalize_spaces", 1, rc);
    EXPECT_STR_EQ("http_normalize_spaces", "a b c", text);

    rc = http_normalize_line_endings(text, sizeof(text), "a\r\nb\r\n");
    EXPECT_INT_EQ("http_normalize_line_endings", 1, rc);
    EXPECT_STR_EQ("http_normalize_line_endings", "a\nb\n", text);

    rc = http_body_normalize_lowercase(body_out, sizeof(body_out), body_src,
                                       sizeof(body_src) - 1U, &out_len);
    EXPECT_INT_EQ("http_body_normalize_lowercase", 1, rc);
    EXPECT_MEM_EQ("http_body_normalize_lowercase", "abc", body_out, 3U);
    EXPECT_SIZE_EQ("http_body_normalize_lowercase", 3U, out_len);

    return 0;
}

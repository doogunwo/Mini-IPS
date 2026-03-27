#include "normalization.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    char    text[256];
    uint8_t body[256];
    size_t  out_len;
    int     rc;

    rc = http_normalize_slashes(text, sizeof(text), "\\a//b///c");
    EXPECT_INT_EQ("http_normalize_slashes", 1, rc);
    EXPECT_STR_EQ("http_normalize_slashes", "/a/b/c", text);

    rc = http_remove_dot_segments(text, sizeof(text), "/a/b/../c/./");
    EXPECT_INT_EQ("http_remove_dot_segments", 1, rc);
    EXPECT_STR_EQ("http_remove_dot_segments", "/a/c/", text);

    rc = http_normalize_path(text, sizeof(text), "/a//b/../c");
    EXPECT_INT_EQ("http_normalize_path", 1, rc);
    EXPECT_STR_EQ("http_normalize_path", "/a/c", text);

    rc = http_normalize_query(text, sizeof(text), "  a=1   b=2  ");
    EXPECT_INT_EQ("http_normalize_query", 1, rc);
    EXPECT_STR_EQ("http_normalize_query", "a=1 b=2", text);

    rc = http_normalize_header_name(text, sizeof(text), "  Content-Type  ");
    EXPECT_INT_EQ("http_normalize_header_name", 1, rc);
    EXPECT_STR_EQ("http_normalize_header_name", "content-type", text);

    rc = http_normalize_host(text, sizeof(text), "  ExAmPle.COM. ");
    EXPECT_INT_EQ("http_normalize_host", 1, rc);
    EXPECT_STR_EQ("http_normalize_host", "example.com", text);

    rc = http_normalize_spaces(text, sizeof(text), " a \t b \n c ");
    EXPECT_INT_EQ("http_normalize_spaces", 1, rc);
    EXPECT_STR_EQ("http_normalize_spaces", "a b c", text);

    rc = http_normalize_line_endings(text, sizeof(text), "a\r\nb\rc");
    EXPECT_INT_EQ("http_normalize_line_endings", 1, rc);
    EXPECT_STR_EQ("http_normalize_line_endings", "a\nb\nc", text);

    rc = http_normalize_lowercase(text, sizeof(text), "AbC");
    EXPECT_INT_EQ("http_normalize_lowercase", 1, rc);
    EXPECT_STR_EQ("http_normalize_lowercase", "abc", text);

    rc = http_body_normalize_spaces(body, sizeof(body),
                                    (const uint8_t *)"  a \t b \n", 9,
                                    &out_len);
    EXPECT_INT_EQ("http_body_normalize_spaces", 1, rc);
    EXPECT_SIZE_EQ("http_body_normalize_spaces", 3, out_len);
    EXPECT_MEM_EQ("http_body_normalize_spaces", "a b", body, 3);

    rc = http_body_normalize_line_endings(body, sizeof(body),
                                          (const uint8_t *)"a\r\nb\rc", 6,
                                          &out_len);
    EXPECT_INT_EQ("http_body_normalize_line_endings", 1, rc);
    EXPECT_SIZE_EQ("http_body_normalize_line_endings", 5, out_len);
    EXPECT_MEM_EQ("http_body_normalize_line_endings", "a\nb\nc", body, 5);

    rc = http_body_normalize_lowercase(body, sizeof(body),
                                       (const uint8_t *)"AbC!", 4, &out_len);
    EXPECT_INT_EQ("http_body_normalize_lowercase", 1, rc);
    EXPECT_SIZE_EQ("http_body_normalize_lowercase", 4, out_len);
    EXPECT_MEM_EQ("http_body_normalize_lowercase", "abc!", body, 4);

    return 0;
}

#include "../../src/inline/normalization.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    char text[8];
    uint8_t body_out[2];
    size_t out_len;

    EXPECT_INT_EQ("http_normalize_uri.null_dst", -1,
                  http_normalize_uri(NULL, sizeof(text), "/a"));
    EXPECT_INT_EQ("http_normalize_uri.small_buffer", -1,
                  http_normalize_uri(text, 1U, "/admin"));
    EXPECT_INT_EQ("http_remove_dot_segments.null_src", -1,
                  http_remove_dot_segments(text, sizeof(text), NULL));
    EXPECT_INT_EQ("http_normalize_spaces.zero_cap", -1,
                  http_normalize_spaces(text, 0U, "a"));
    EXPECT_INT_EQ("http_body_normalize_lowercase.small_buffer", -1,
                  http_body_normalize_lowercase(body_out, sizeof(body_out),
                                                (const uint8_t *)"ABC", 3U,
                                                &out_len));
    EXPECT_INT_EQ("http_body_normalize_line_endings.null_out_len", -1,
                  http_body_normalize_line_endings(body_out, sizeof(body_out),
                                                   (const uint8_t *)"A", 1U,
                                                   NULL));

    return 0;
}

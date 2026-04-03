#include "../../src/inline/decoding.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    char text[8];
    uint8_t body_out[8];
    size_t out_len;

    EXPECT_INT_EQ("http_decode_percent.null_dst", -1,
                  http_decode_percent(NULL, sizeof(text), "%41"));
    EXPECT_INT_EQ("http_decode_percent.small_buffer", -1,
                  http_decode_percent(text, 1U, "%41"));
    EXPECT_INT_EQ("http_text_canonicalize.zero_rounds", -1,
                  http_text_canonicalize(text, sizeof(text), "%41", 0));
    EXPECT_INT_EQ("http_uri_canonicalize.empty_cap", -1,
                  http_uri_canonicalize(text, 0U, "/a", 2));
    EXPECT_INT_EQ("http_body_canonicalize.null_out_len", -1,
                  http_body_canonicalize(body_out, sizeof(body_out),
                                         (const uint8_t *)"A", 1U, 2, NULL));
    EXPECT_INT_EQ("http_body_decode_percent.small_buffer", -1,
                  http_body_decode_percent(body_out, 0U, (const uint8_t *)"%41",
                                           3U, &out_len));
    EXPECT_INT_EQ("http_has_invalid_percent_encoding.short", 1,
                  http_has_invalid_percent_encoding("%"));

    return 0;
}

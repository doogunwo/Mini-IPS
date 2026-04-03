#include "../../src/inline/decoding.h"
#include "../../src/inline/http_parser.h"
#include "../../src/inline/normalization.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    char uri[4096];
    char normalized[4096];
    http_message_t msg;
    size_t i;
    int rc;

    memset(&msg, 0, sizeof(msg));

    uri[0] = '/';
    for (i = 1; i < sizeof(uri) - 1U; i++) {
        uri[i] = 'A';
    }
    uri[sizeof(uri) - 1U] = '\0';

    rc = http_uri_canonicalize(normalized, sizeof(normalized), uri, 2);
    EXPECT_INT_EQ("http_uri_canonicalize.large_input", 0, rc);
    EXPECT_STR_EQ("http_uri_canonicalize.large_input", uri, normalized);

    rc = http_normalize_uri(normalized, sizeof(normalized), uri);
    EXPECT_INT_EQ("http_normalize_uri.large_input", 0, rc);

    rc = http_parser_try((const uint8_t *)"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\nx",
                         strlen("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\nx"),
                         &msg);
    EXPECT_INT_EQ("http_parser_try.small_smoke", 1, rc);
    EXPECT_INT_EQ("http_parser_free.small_smoke", 1, http_parser_free(&msg));

    return 0;
}

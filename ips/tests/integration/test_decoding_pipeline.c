#include "decoding.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    char text_a[256];
    char text_b[256];
    char text_c[256];
    int  rc;

    rc = http_decode_percent_recursive(text_a, sizeof(text_a),
                                       "/%252e%252e/%253cadmin%253e", 3);
    CHECK(1 == rc, "uri recursive decode");

    rc = http_decode_plus_as_space(text_b, sizeof(text_b), "q=hello+world");
    CHECK(1 == rc, "plus decode integration");

    rc = http_decode_html_entity(text_c, sizeof(text_c), "&lt;tag&gt;");
    CHECK(1 == rc, "html decode integration");
    CHECK(0 == strcmp(text_c, "<tag>"), "html decode integration result");

    CHECK(0 == strcmp(text_a, "/../<admin>"), "uri integration result");
    CHECK(0 == strcmp(text_b, "q=hello world"), "plus integration result");
    return 0;
}

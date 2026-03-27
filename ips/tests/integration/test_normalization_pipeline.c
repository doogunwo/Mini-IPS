#include "decoding.h"
#include "normalization.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    char decoded[256];
    char normalized[256];
    int  rc;

    rc = http_decode_percent_recursive(decoded, sizeof(decoded),
                                       "/a/%2e%2e//Admin%2fPanel", 2);
    CHECK(1 == rc, "decode integration");

    rc = http_normalize_uri(normalized, sizeof(normalized), decoded);
    CHECK(1 == rc, "normalize uri integration");
    CHECK(0 == strcmp(normalized, "/Admin/Panel"), "normalized uri result");

    rc = http_normalize_host(normalized, sizeof(normalized), " WWW.Example.COM. ");
    CHECK(1 == rc, "normalize host integration");
    CHECK(0 == strcmp(normalized, "www.example.com"), "normalized host result");

    return 0;
}

#include "normalization.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    char    text[8];
    uint8_t body[8];
    size_t  out_len;
    int     rc;

    rc = http_normalize_host(text, 4, "A.");
    CHECK(1 == rc, "normalize host exact-fit buffer");
    CHECK(0 == strcmp(text, "a"), "normalize host exact-fit result");

    rc = http_normalize_path(text, sizeof(text), "");
    CHECK(0 == rc, "normalize empty path unchanged");
    CHECK(0 == strcmp(text, ""), "normalize empty path result");

    rc = http_normalize_path(text, sizeof(text), "/");
    CHECK(0 == rc, "normalize slash-only path unchanged");
    CHECK(0 == strcmp(text, "/"), "normalize slash-only path result");

    rc = http_normalize_spaces(text, 2, " a ");
    CHECK(1 == rc, "normalize spaces exact-fit buffer");
    CHECK(0 == strcmp(text, "a"), "normalize spaces exact-fit result");

    rc = http_normalize_path(text, 4, "/a/");
    CHECK(0 == rc, "normalize path exact-fit unchanged");
    CHECK(0 == strcmp(text, "/a/"), "normalize path exact-fit result");

    rc = http_body_normalize_lowercase(body, 3, (const uint8_t *)"Ab", 2, &out_len);
    CHECK(1 == rc, "body lowercase exact-fit buffer");
    CHECK(2 == out_len && 0 == memcmp(body, "ab", 2),
          "body lowercase exact-fit result");

    rc = http_body_normalize_lowercase(body, 1, (const uint8_t *)"Ab", 2, &out_len);
    CHECK(-1 == rc, "body lowercase too-small buffer");

    return 0;
}

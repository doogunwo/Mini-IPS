#include "decoding.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    char    text[8];
    uint8_t body[8];
    size_t  out_len;
    int     rc;

    rc = http_decode_percent(text, 4, "%41");
    CHECK(1 == rc, "percent decode exact-fit buffer");
    CHECK(0 == strcmp(text, "A"), "percent decode exact-fit result");

    rc = http_decode_percent(text, 1, "%41");
    CHECK(-1 == rc, "percent decode too-small buffer");

    rc = http_body_decode_percent(body, 1, (const uint8_t *)"%41", 3, &out_len);
    CHECK(1 == rc, "body percent decode exact-fit buffer");
    CHECK(1 == out_len && 'A' == body[0], "body percent exact-fit result");

    rc = http_body_decode_percent(body, 0, (const uint8_t *)"%41", 3, &out_len);
    CHECK(-1 == rc, "body percent decode zero-sized buffer");

    rc = http_body_decode_percent(body, sizeof(body),
                                  (const uint8_t *)"A%00B", 5, &out_len);
    CHECK(1 == rc, "body percent decode binary nul");
    CHECK(3 == out_len, "body percent decode binary nul len");
    CHECK('A' == body[0] && 0 == body[1] && 'B' == body[2],
          "body percent decode binary nul result");

    rc = http_decode_percent(text, sizeof(text), "%");
    CHECK(-1 == rc, "percent decode lone percent");

    rc = http_decode_percent(text, sizeof(text), "%4");
    CHECK(-1 == rc, "percent decode short percent");

    rc = http_decode_percent(text, sizeof(text), "%GG");
    CHECK(-1 == rc, "percent decode invalid hex");

    rc = http_body_decode_percent(body, sizeof(body), (const uint8_t *)"%", 1,
                                  &out_len);
    CHECK(-1 == rc, "body percent decode lone percent");

    rc = http_body_decode_percent(body, sizeof(body), (const uint8_t *)"%4", 2,
                                  &out_len);
    CHECK(-1 == rc, "body percent decode short percent");

    rc = http_body_decode_percent(body, sizeof(body), (const uint8_t *)"%GG", 3,
                                  &out_len);
    CHECK(-1 == rc, "body percent decode invalid hex");

    return 0;
}

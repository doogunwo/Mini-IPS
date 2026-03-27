#include "decoding.h"
#include "http_parser.h"
#include "normalization.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    const char    *bad_chunk_req;
    const char    *dup_cl_conflict_req;
    char           decoded[256];
    char           normalized[256];
    char           header_name[64];
    uint8_t        body[256];
    size_t         out_len;
    http_message_t msg;
    int            rc;

    rc = http_decode_percent_recursive(decoded, sizeof(decoded),
                                       "/a/%2e%2e//admin", 2);
    CHECK(1 == rc, "evasion uri decode single layer");
    rc = http_normalize_uri(normalized, sizeof(normalized), decoded);
    CHECK(1 == rc, "evasion uri normalize single layer");
    CHECK(0 == strcmp(normalized, "/admin"),
          "evasion uri normalized single layer result");

    rc = http_decode_percent_recursive(decoded, sizeof(decoded),
                                       "/%252e%252e/%252fadmin", 3);
    CHECK(1 == rc, "evasion uri decode double layer");
    rc = http_normalize_uri(normalized, sizeof(normalized), decoded);
    CHECK(1 == rc, "evasion uri normalize double layer");
    CHECK(0 == strcmp(normalized, "/admin"),
          "evasion uri normalized double layer result");

    bad_chunk_req =
        "POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"
        "1\r\naX\r\n0\r\n\r\n";
    rc = http_parser_try((const uint8_t *)bad_chunk_req, strlen(bad_chunk_req),
                         &msg);
    CHECK(-1 == rc, "evasion malformed chunk terminator");

    dup_cl_conflict_req =
        "POST /dup HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n"
        "Content-Length: 4\r\n\r\nabc";
    rc = http_parser_try((const uint8_t *)dup_cl_conflict_req,
                         strlen(dup_cl_conflict_req), &msg);
    CHECK(-1 == rc, "evasion duplicate content-length conflict");

    rc = http_normalize_header_name(header_name, sizeof(header_name), "Host ");
    CHECK(1 == rc, "evasion spaced header name normalize");
    CHECK(0 == strcmp(header_name, "host"),
          "evasion spaced header name normalize result");

    rc = http_body_decode_percent(body, sizeof(body),
                                  (const uint8_t *)"%3cscript%3e", 12,
                                  &out_len);
    CHECK(1 == rc, "evasion body percent decode");
    CHECK(8 == out_len && 0 == memcmp(body, "<script>", 8),
          "evasion body percent decode result");

    rc = http_body_decode_escape_sequence(body, sizeof(body),
                                          (const uint8_t *)"\\x3cscript\\x3e",
                                          14, &out_len);
    CHECK(1 == rc, "evasion body escape decode");
    CHECK(8 == out_len && 0 == memcmp(body, "<script>", 8),
          "evasion body escape decode result");

    rc = http_body_decode_html_entity(body, sizeof(body),
                                      (const uint8_t *)"&lt;script&gt;", 14,
                                      &out_len);
    CHECK(1 == rc, "evasion body html entity decode");
    CHECK(8 == out_len && 0 == memcmp(body, "<script>", 8),
          "evasion body html entity decode result");

    return 0;
}

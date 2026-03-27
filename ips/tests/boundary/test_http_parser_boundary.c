#include "http_parser.h"
#include "normalization.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    const char    *minimal_req;
    const char    *zero_len_req;
    const char    *chunked_empty_req;
    const char    *dup_cl_same_req;
    const char    *dup_cl_conflict_req;
    const char    *truncated_body_req;
    uint8_t        binary_req[] =
        "POST /bin HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n"
        "\0"
        "A"
        "\xff"
        "\n"
        "\x7f";
    uint8_t        normalized_body[16];
    size_t         normalized_len;
    http_message_t msg;
    int            rc;

    minimal_req = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    rc = http_parser_try((const uint8_t *)minimal_req, strlen(minimal_req), &msg);
    CHECK(1 == rc, "http parser boundary minimal request");
    CHECK(1 == msg.type, "http parser boundary request type");
    CHECK(0 == strcmp(msg.method, "GET"), "http parser boundary method");
    CHECK(0 == strcmp(msg.uri, "/"), "http parser boundary uri");
    CHECK(0 == msg.body_len, "http parser boundary no body");
    CHECK(1 == http_parser_free(&msg), "http parser boundary free minimal request");

    zero_len_req =
        "POST /zero HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n";
    rc = http_parser_try((const uint8_t *)zero_len_req, strlen(zero_len_req), &msg);
    CHECK(1 == rc, "http parser boundary content-length zero");
    CHECK(1 == msg.type, "http parser boundary zero content request type");
    CHECK(0 == strcmp(msg.method, "POST"), "http parser boundary zero content method");
    CHECK(0 == msg.body_len, "http parser boundary zero content body len");
    CHECK(1 == http_parser_free(&msg), "http parser boundary free zero content");

    chunked_empty_req =
        "POST /chunk HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"
        "0\r\n\r\n";
    rc = http_parser_try((const uint8_t *)chunked_empty_req,
                         strlen(chunked_empty_req), &msg);
    CHECK(1 == rc, "http parser boundary empty chunked request");
    CHECK(1 == msg.type, "http parser boundary empty chunked type");
    CHECK(0 == msg.body_len, "http parser boundary empty chunked body len");
    CHECK(1 == http_parser_free(&msg), "http parser boundary free empty chunked");

    dup_cl_same_req =
        "POST /dup HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n"
        "Content-Length: 3\r\n\r\nabc";
    rc = http_parser_try((const uint8_t *)dup_cl_same_req,
                         strlen(dup_cl_same_req), &msg);
    CHECK(1 == rc, "http parser boundary duplicate content-length same value");
    CHECK(3 == msg.body_len, "http parser boundary duplicate same body len");
    CHECK(0 == memcmp(msg.body, "abc", 3), "http parser boundary duplicate same body");
    CHECK(1 == http_parser_free(&msg), "http parser boundary free duplicate same");

    dup_cl_conflict_req =
        "POST /dup HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n"
        "Content-Length: 4\r\n\r\nabc";
    rc = http_parser_try((const uint8_t *)dup_cl_conflict_req,
                         strlen(dup_cl_conflict_req), &msg);
    CHECK(-1 == rc, "http parser boundary duplicate content-length conflict");

    truncated_body_req =
        "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nabc";
    rc = http_parser_try((const uint8_t *)truncated_body_req,
                         strlen(truncated_body_req), &msg);
    CHECK(0 == rc, "http parser boundary truncated body should need more");

    rc = http_parser_try(binary_req, sizeof(binary_req) - 1U, &msg);
    CHECK(1 == rc, "http parser boundary binary body");
    CHECK(5 == msg.body_len, "http parser boundary binary body len");
    CHECK(0 == msg.body[0] && 'A' == msg.body[1] && 0xFF == msg.body[2] &&
              '\n' == msg.body[3] && 0x7F == msg.body[4],
          "http parser boundary binary body result");
    rc = http_body_normalize_lowercase(normalized_body, sizeof(normalized_body),
                                       msg.body, msg.body_len, &normalized_len);
    CHECK(1 == rc, "http parser boundary binary body lowercase");
    CHECK(5 == normalized_len, "http parser boundary binary body lowercase len");
    CHECK(0 == normalized_body[0] && 'a' == normalized_body[1] &&
              0xFF == normalized_body[2] && '\n' == normalized_body[3] &&
              0x7F == normalized_body[4],
          "http parser boundary binary body lowercase result");
    CHECK(1 == http_parser_free(&msg), "http parser boundary free binary body");

    return 0;
}

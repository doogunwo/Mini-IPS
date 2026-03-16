/**
 * @file test_http_stream_parser.c
 * @brief HTTP 스트림 파서 단위 테스트
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "http_stream.h"

#define CHECK(cond, msg)                           \
    do {                                           \
        if (!(cond)) {                             \
            fprintf(stderr, "FAIL: %s\\n", (msg)); \
            return 1;                              \
        }                                          \
    } while (0)

static int test_content_length_request(void) {
    http_stream_cfg_t cfg = {0};
    http_stream_t    *s;
    http_message_t    m;
    const char       *req =
        "POST /p?q=1 HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello";

    cfg.max_buffer_bytes = 4096;
    cfg.max_body_bytes   = 1024;

    s = http_stream_create(&cfg);
    CHECK(s != NULL, "http_stream_create failed");

    CHECK(http_stream_feed(s, (const uint8_t *)req, strlen(req)) ==
              HTTP_STREAM_OK,
          "feed content-length request failed");
    CHECK(http_stream_poll_message(s, &m) == HTTP_STREAM_OK,
          "poll content-length request failed");

    CHECK(m.is_request == 1, "expected request message");
    CHECK(strcmp(m.method, "POST") == 0, "method mismatch");
    CHECK(strcmp(m.uri, "/p?q=1") == 0, "uri mismatch");
    CHECK(m.body_len == 5, "body length mismatch");
    CHECK(memcmp(m.body, "hello", 5) == 0, "body content mismatch");

    fprintf(stderr,
            "[test_http_stream_parser] case=content_length method=%s uri=%s "
            "body_len=%zu\n",
            m.method, m.uri, m.body_len);

    http_message_free(&m);
    http_stream_destroy(s);
    return 0;
}

static int test_chunked_request(void) {
    http_stream_cfg_t cfg = {0};
    http_stream_t    *s;
    http_message_t    m;
    const char       *req =
        "POST /chunk HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "4\r\n"
        "Wiki\r\n"
        "5\r\n"
        "pedia\r\n"
        "0\r\n"
        "\r\n";

    cfg.max_buffer_bytes = 4096;
    cfg.max_body_bytes   = 1024;
    s                    = http_stream_create(&cfg);
    CHECK(s != NULL, "http_stream_create failed");

    CHECK(http_stream_feed(s, (const uint8_t *)req, strlen(req)) ==
              HTTP_STREAM_OK,
          "feed chunked request failed");
    CHECK(http_stream_poll_message(s, &m) == HTTP_STREAM_OK,
          "poll chunked request failed");

    CHECK(m.chunked == 1, "expected chunked message");
    CHECK(m.body_len == 9, "chunked body length mismatch");
    CHECK(memcmp(m.body, "Wikipedia", 9) == 0, "chunked body mismatch");

    fprintf(stderr,
            "[test_http_stream_parser] case=chunked uri=%s chunked=%d "
            "body_len=%zu\n",
            m.uri, m.chunked, m.body_len);

    http_message_free(&m);
    http_stream_destroy(s);
    return 0;
}

static int test_malformed_header_and_reset(void) {
    http_stream_t *s = http_stream_create(NULL);
    const char    *bad =
        "GET / HTTP/1.1\r\n"
        "Host localhost\r\n"
        "\r\n";
    const char *good =
        "GET /ok HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "\r\n";
    http_stream_rc_t rc;
    http_message_t   m;

    CHECK(s != NULL, "http_stream_create failed");

    rc = http_stream_feed(s, (const uint8_t *)bad, strlen(bad));
    CHECK(rc == HTTP_STREAM_EPROTO, "malformed header should return EPROTO");
    CHECK(strcmp(http_stream_last_error(s), "HTTP parse error") == 0,
          "last_error mismatch after malformed header");

    http_stream_reset(s);

    CHECK(http_stream_feed(s, (const uint8_t *)good, strlen(good)) ==
              HTTP_STREAM_OK,
          "feed after reset failed");
    CHECK(http_stream_poll_message(s, &m) == HTTP_STREAM_OK,
          "poll after reset failed");
    CHECK(strcmp(m.uri, "/ok") == 0, "uri mismatch after reset");

    fprintf(stderr,
            "[test_http_stream_parser] case=malformed_reset first_rc=%d "
            "last_error=%s recovered_uri=%s\n",
            rc, http_stream_last_error(s), m.uri);

    http_message_free(&m);
    http_stream_destroy(s);
    return 0;
}

int main(void) {
    if (test_content_length_request() != 0) {
        return 1;
    }
    if (test_chunked_request() != 0) {
        return 1;
    }
    if (test_malformed_header_and_reset() != 0) {
        return 1;
    }

    printf("ok: test_http_stream_parser\\n");
    return 0;
}

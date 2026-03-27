#include "decoding.h"
#include "http_parser.h"
#include "normalization.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    const char    *req;
    const char    *host_value;
    const char    *host_end;
    http_message_t msg;
    char           decoded_uri[256];
    char           normalized_uri[256];
    char           normalized_host[256];
    char           host_raw[256];
    uint8_t        decoded_body[256];
    size_t         decoded_body_len;
    int            rc;

    req = "POST /%252e%252e/%252fadmin HTTP/1.1\r\n"
          "Host: ExAmPle.COM.\r\n"
          "Content-Length: 16\r\n\r\n"
          "%253cscript%253e";

    rc = http_parser_try((const uint8_t *)req, strlen(req), &msg);
    CHECK(1 == rc, "scenario parse request");
    CHECK(1 == msg.type, "scenario request type");

    rc = http_decode_percent_recursive(decoded_uri, sizeof(decoded_uri), msg.uri,
                                       3);
    CHECK(1 == rc, "scenario decode uri");
    rc = http_normalize_uri(normalized_uri, sizeof(normalized_uri), decoded_uri);
    CHECK(1 == rc, "scenario normalize uri");
    CHECK(0 == strcmp(normalized_uri, "/admin"),
          "scenario normalized uri result");

    host_value = strstr(msg.headers, "Host:");
    CHECK(NULL != host_value, "scenario host header present");
    host_value += 5;
    while (' ' == *host_value) {
        host_value++;
    }
    host_end = strstr(host_value, "\r\n");
    CHECK(NULL != host_end, "scenario host line end");
    CHECK((size_t)(host_end - host_value) < sizeof(host_raw),
          "scenario host raw length");
    memcpy(host_raw, host_value, (size_t)(host_end - host_value));
    host_raw[host_end - host_value] = '\0';

    rc = http_normalize_host(normalized_host, sizeof(normalized_host), host_raw);
    CHECK(1 == rc, "scenario normalize host");
    CHECK(0 == strcmp(normalized_host, "example.com"),
          "scenario normalized host result");

    rc = http_body_decode_percent_recursive(decoded_body, sizeof(decoded_body),
                                            msg.body, msg.body_len, 3,
                                            &decoded_body_len);
    CHECK(1 == rc, "scenario decode body");
    CHECK(8 == decoded_body_len && 0 == memcmp(decoded_body, "<script>", 8),
          "scenario decoded body result");

    CHECK(1 == http_parser_free(&msg), "scenario free request");
    return 0;
}

#include "decoding.h"
#include "http_parser.h"
#include "normalization.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    const char    *req;
    http_message_t msg;
    char           decoded_uri[256];
    char           normalized_uri[256];
    char           normalized_host[256];
    char           host_raw[256];
    const char    *host_value;
    const char    *host_end;
    int            rc;

    req = "GET /a/%2e%2e//Admin%2fPanel?q=1 HTTP/1.1\r\n"
          "Host: ExAmPle.COM.\r\n"
          "Transfer-Encoding: chunked\r\n\r\n"
          "4\r\nWiki\r\n0\r\n\r\n";

    rc = http_parser_try((const uint8_t *)req, strlen(req), &msg);
    CHECK(1 == rc, "http parser integration parse");
    CHECK(1 == msg.type, "http parser integration request type");
    CHECK(4 == msg.body_len && 0 == memcmp(msg.body, "Wiki", 4),
          "http parser integration body");

    rc = http_decode_percent_recursive(decoded_uri, sizeof(decoded_uri), msg.uri, 3);
    CHECK(rc >= 0, "http parser integration decode uri");
    rc = http_normalize_uri(normalized_uri, sizeof(normalized_uri), decoded_uri);
    CHECK(rc >= 0, "http parser integration normalize uri");
    CHECK(0 == strcmp(normalized_uri, "/Admin/Panel?q=1"),
          "http parser integration normalized uri");

    host_value = strstr(msg.headers, "Host:");
    CHECK(NULL != host_value, "http parser integration host present");
    host_value += 5;
    while (' ' == *host_value) {
        host_value++;
    }
    host_end = strstr(host_value, "\r\n");
    CHECK(NULL != host_end, "http parser integration host line end");
    CHECK((size_t)(host_end - host_value) < sizeof(host_raw),
          "http parser integration host length");
    memcpy(host_raw, host_value, (size_t)(host_end - host_value));
    host_raw[host_end - host_value] = '\0';

    rc = http_normalize_host(normalized_host, sizeof(normalized_host), host_raw);
    CHECK(rc >= 0, "http parser integration normalize host");
    CHECK(0 == strcmp(normalized_host, "example.com"),
          "http parser integration normalized host");

    CHECK(1 == http_parser_free(&msg), "http parser integration free");
    return 0;
}

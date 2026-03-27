#include "decoding.h"
#include "http_parser.h"
#include "normalization.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    char          *encoded;
    char          *decoded;
    char          *long_uri;
    char          *normalized_uri;
    uint8_t       *request;
    uint8_t       *body;
    http_message_t msg;
    size_t         encoded_len;
    size_t         body_len;
    size_t         uri_len;
    size_t         request_len;
    int            header_len;
    int            rc;
    size_t         i;

    encoded_len = 256U * 3U;
    encoded     = (char *)malloc(encoded_len + 1U);
    decoded     = (char *)malloc(256U + 1U);
    long_uri    = (char *)malloc(2048U + 1U);
    normalized_uri = (char *)malloc(2048U + 1U);
    body        = (uint8_t *)malloc(4096U);
    request     = (uint8_t *)malloc(8192U);
    CHECK(NULL != encoded && NULL != decoded && NULL != long_uri &&
              NULL != normalized_uri && NULL != body && NULL != request,
          "large boundary allocations");

    for (i = 0; i < 256U; i++) {
        encoded[i * 3U]         = '%';
        encoded[i * 3U + 1U]    = '4';
        encoded[i * 3U + 2U]    = '1';
        decoded[i]              = '\0';
    }
    encoded[encoded_len] = '\0';

    rc = http_decode_percent(decoded, 257U, encoded);
    CHECK(1 == rc, "large boundary long percent decode");
    CHECK(256U == strlen(decoded), "large boundary long percent len");
    for (i = 0; i < 256U; i++) {
        CHECK('A' == decoded[i], "large boundary long percent content");
    }

    long_uri[0] = '/';
    for (i = 1; i < 2048U; i++) {
        long_uri[i] = 'a';
    }
    long_uri[2048U] = '\0';
    rc = http_normalize_uri(normalized_uri, 2049U, long_uri);
    CHECK(0 == rc, "large boundary normalize uri exact fit unchanged");
    CHECK(0 == strcmp(normalized_uri, long_uri),
          "large boundary normalize uri exact fit result");

    body_len = 4096U;
    for (i = 0; i < body_len; i++) {
        body[i] = (uint8_t)(i & 0xFFU);
    }

    uri_len = 1024U;
    memset(long_uri, 'b', uri_len);
    long_uri[0]      = '/';
    long_uri[uri_len] = '\0';

    header_len = snprintf((char *)request, 4096U,
                          "POST %s HTTP/1.1\r\nHost: a\r\nContent-Length: %zu\r\n\r\n",
                          long_uri, body_len);
    CHECK(header_len > 0, "large boundary header build");
    request_len = (size_t)header_len + body_len;
    memcpy(request + (size_t)header_len, body, body_len);

    rc = http_parser_try(request, request_len, &msg);
    CHECK(1 == rc, "large boundary parse long request");
    CHECK(1 == msg.type, "large boundary parse long request type");
    CHECK(uri_len == strlen(msg.uri), "large boundary parsed uri len");
    CHECK(body_len == msg.body_len, "large boundary parsed body len");
    CHECK(0 == memcmp(msg.body, body, body_len), "large boundary parsed body");
    CHECK(1 == http_parser_free(&msg), "large boundary free request");

    free(encoded);
    free(decoded);
    free(long_uri);
    free(normalized_uri);
    free(body);
    free(request);
    return 0;
}

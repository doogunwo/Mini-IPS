#include "../../src/inline/http_parser.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    const char *req;
    const char *res;
    http_message_t msg;
    int rc;

    memset(&msg, 0, sizeof(msg));

    req = "POST /login?a=1 HTTP/1.1\r\n"
          "Host: example\r\n"
          "Content-Length: 4\r\n\r\n"
          "body";
    rc = http_parser_try((const uint8_t *)req, strlen(req), &msg);
    EXPECT_INT_EQ("http_parser_try.request", 1, rc);
    EXPECT_INT_EQ("http_parser_try.request.type", 1, msg.type);
    EXPECT_STR_EQ("http_parser_try.request.method", "POST", msg.method);
    EXPECT_STR_EQ("http_parser_try.request.uri", "/login?a=1", msg.uri);
    EXPECT_TRUE("http_parser_try.request.headers", "host present",
                NULL != strstr(msg.headers, "Host: example"));
    EXPECT_SIZE_EQ("http_parser_try.request.body_len", 4U, msg.body_len);
    EXPECT_MEM_EQ("http_parser_try.request.body", "body", msg.body, 4U);
    EXPECT_INT_EQ("http_parser_free.request", 1, http_parser_free(&msg));

    memset(&msg, 0, sizeof(msg));
    res = "HTTP/1.1 404 Not Found\r\n"
          "Content-Length: 2\r\n\r\nOK";
    rc = http_parser_try((const uint8_t *)res, strlen(res), &msg);
    EXPECT_INT_EQ("http_parser_try.response", 1, rc);
    EXPECT_INT_EQ("http_parser_try.response.type", 0, msg.type);
    EXPECT_INT_EQ("http_parser_try.response.status_code", 404, msg.status_code);
    EXPECT_SIZE_EQ("http_parser_try.response.body_len", 2U, msg.body_len);
    EXPECT_MEM_EQ("http_parser_try.response.body", "OK", msg.body, 2U);
    EXPECT_INT_EQ("http_parser_free.response", 1, http_parser_free(&msg));

    return 0;
}

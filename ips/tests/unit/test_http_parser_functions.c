#include "http_parser.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    const char    *req;
    const char    *resp;
    http_message_t msg;
    int            rc;

    req = "GET /abc HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello";
    rc = http_parser_try((const uint8_t *)req, strlen(req), &msg);
    EXPECT_INT_EQ("http_parser_try", 1, rc);
    EXPECT_INT_EQ("http_parser_try", 1, msg.type);
    EXPECT_STR_EQ("http_parser_try", "GET", msg.method);
    EXPECT_STR_EQ("http_parser_try", "/abc", msg.uri);
    EXPECT_SIZE_EQ("http_parser_try", 5, msg.body_len);
    EXPECT_MEM_EQ("http_parser_try", "hello", msg.body, 5);
    EXPECT_INT_EQ("http_parser_free", 1, http_parser_free(&msg));

    resp =
        "HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nbad";
    rc = http_parser_try((const uint8_t *)resp, strlen(resp), &msg);
    EXPECT_INT_EQ("http_parser_try", 1, rc);
    EXPECT_INT_EQ("http_parser_try", 0, msg.type);
    EXPECT_INT_EQ("http_parser_try", 404, msg.status_code);
    EXPECT_SIZE_EQ("http_parser_try", 3, msg.body_len);
    EXPECT_MEM_EQ("http_parser_try", "bad", msg.body, 3);
    EXPECT_INT_EQ("http_parser_free", 1, http_parser_free(&msg));

    rc = http_parser_try(NULL, 0, &msg);
    EXPECT_INT_EQ("http_parser_try", -1, rc);

    return 0;
}

#include "../../src/inline/http_parser.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    http_message_t msg;
    const char *partial_req;
    const char *bad_req;

    memset(&msg, 0, sizeof(msg));

    EXPECT_INT_EQ("http_parser_try.null_data", -1,
                  http_parser_try(NULL, 1U, &msg));
    EXPECT_INT_EQ("http_parser_try.null_out", -1,
                  http_parser_try((const uint8_t *)"GET / HTTP/1.1\r\n\r\n",
                                  18U, NULL));

    partial_req = "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nbo";
    EXPECT_INT_EQ("http_parser_try.partial_body", 0,
                  http_parser_try((const uint8_t *)partial_req,
                                  strlen(partial_req), &msg));

    bad_req = "BROKEN\r\n\r\n";
    EXPECT_INT_EQ("http_parser_try.bad_start_line", 0,
                  http_parser_try((const uint8_t *)bad_req, strlen(bad_req),
                                  &msg));

    EXPECT_INT_EQ("http_parser_free.null", -1, http_parser_free(NULL));

    return 0;
}

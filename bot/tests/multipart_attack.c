#include "multipart_attack.h"

static const test_case_t multipart_cases[] = {

    /* TEST 1: expect 922100 */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: */*\r\n"
        "Content-Type: multipart/form-data; boundary=boundary\r\n"
        "Content-Length: 206\r\n"
        "\r\n"
        "--boundary\r\n"
        "Content-disposition: form-data; name=\"_charset_\"\r\n"
        "\r\n"
        "utf-7\r\n"
        "--boundary\r\n"
        "Content-disposition: form-data; name=\"positive\"\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Let me see if I can use utf-7.\r\n"
        "--boundary--\r\n",
        EXPECT_MATCH,
        922100
    },

    /* TEST 2: no_expect 922100 */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: */*\r\n"
        "Content-Type: multipart/form-data; boundary=boundary\r\n"
        "Content-Length: 228\r\n"
        "\r\n"
        "--boundary\r\n"
        "Content-disposition: form-data; name=\"_charset_\"\r\n"
        "\r\n"
        "utf-8\r\n"
        "--boundary\r\n"
        "Content-disposition: form-data; name=\"negative\"\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "This should be good as we use utf-8 that is allowed.\r\n"
        "--boundary--\r\n",
        EXPECT_NO_MATCH,
        922100
    },

    /* TEST 3: expect 922100 */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: */*\r\n"
        "Content-Type: multipart/form-data; boundary=boundary\r\n"
        "Content-Length: 213\r\n"
        "\r\n"
        "--boundary\r\n"
        "Content-disposition: form-data; name=\"_charset_\"\r\n"
        "\r\n"
        "utf-\r\n"
        "--boundary\r\n"
        "Content-disposition: form-data; name=\"negative\"\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "utf-8 is valid but utf- should not be.\r\n"
        "--boundary--\r\n",
        EXPECT_MATCH,
        922100
    },
};


static const int multipart_cases_count =
    (int)(sizeof(multipart_cases)) / sizeof(multipart_cases[0]);

int multipart_get_count(void)
{
    return multipart_cases_count;
}

const test_case_t *multipart_get_case(int index)
{
    if(index < 0 || index >= multipart_cases_count)
        return (const test_case_t *)0;

    return &multipart_cases[index];
}

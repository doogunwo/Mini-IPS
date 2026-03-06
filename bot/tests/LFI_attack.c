#include "LFI_attack.h"

/* Rule 930100 - LFI / Path Traversal */
static const test_case_t LFI_cases[] = {

    /* TEST 1: Path Traversal encoded header */
    {
        "GET /get HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "FoobarHeader: 0x5c0x2e.%00/\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        930100
    },

    /* TEST 2: Triple dot traversal */
    {
        "GET /get?foo=.../.../WINDOWS/win.ini HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        930100
    },

    /* TEST 3: Encoded traversal */
    {
        "GET /get?foo=0x2e.%000x2f0x2e.%00/WINDOWS/win.ini HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        930100
    },

    /* TEST 4: Partially encoded backslash traversal */
    {
        "GET /get HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "FoobarHeader: 0x5c0x2e./\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        930100
    }
};

static const int LFI_cases_count =
    (int)(sizeof(LFI_cases)) / sizeof(LFI_cases[0]);

int LFI_get_count(void)
{
    return LFI_cases_count;
}

const test_case_t *LFI_get_case(int index)
{
    if(index < 0 || index >= LFI_cases_count)
        return (const test_case_t *)0;
    
    return &LFI_cases[index];
}

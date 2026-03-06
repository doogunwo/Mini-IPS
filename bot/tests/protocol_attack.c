#include "protocol_attack.h"

static const test_case_t protocol_cases[] = {
    /* ---------------- Rule 921110 ---------------- */

    /* TEST 1: expect */
    {
        "POST / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Cache-Control: no-cache, no-store, must-revalidate\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 22\r\n"
        "\r\n"
        "var=%0aPOST / HTTP/1.1",
        EXPECT_MATCH,
        921110
    },

    /* TEST 2: expect */
    {
        "POST / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Cache-Control: no-cache, no-store, must-revalidate\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 24\r\n"
        "\r\n"
        "var=aaa%0aGET+/+HTTP/1.1",
        EXPECT_MATCH,
        921110
    },

    /* TEST 3: expect */
    {
        "POST / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Cache-Control: no-cache, no-store, must-revalidate\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 43\r\n"
        "\r\n"
        "var=aaa%0dHEAD+http://example.com/+HTTP/1.1",
        EXPECT_MATCH,
        921110
    },

    /* TEST 4: no_expect */
    {
        "POST / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Cache-Control: no-cache, no-store, must-revalidate\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 24\r\n"
        "\r\n"
        "var=aaa%0d%0aGet+/foo%0d",
        EXPECT_NO_MATCH,
        921110
    },

    /* TEST 5: no_expect */
    {
        "POST / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Cache-Control: no-cache, no-store, must-revalidate\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 24\r\n"
        "\r\n"
        "var=aaa%0d%0aGet+foo+bar",
        EXPECT_NO_MATCH,
        921110
    },

    /* TEST 6: expect */
    {
        "POST / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 105\r\n"
        "\r\n"
        "barGET /a.html HTTP/1.1\r\n"
        "Something: GET /b.html HTTP/1.1\r\n"
        "Host: foo.com\r\n"
        "User-Agent: foo\r\n"
        "Accept: */*\r\n"
        "\r\n",
        EXPECT_MATCH,
        921110
    },

    /* TEST 7: expect */
    {
        "GET /?arg1=GET%20http%3A%2F%2Fwww.foo.bar%20HTTP%2F1.2 HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        921110
    },

    /* TEST 8: expect */
    {
        "GET /?arg1=GET%20http%3A%2F%2Fwww.foo.bar%20HTTP%2F3.2 HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        921110
    },

    /* TEST 9: no_expect */
    {
        "POST / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 30\r\n"
        "\r\n"
        "var=soundtrack Gympl\r\nanything",
        EXPECT_NO_MATCH,
        921110
    },

    /* TEST 10: no_expect */
    {
        "POST / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 22\r\n"
        "\r\n"
        "var=budget foo)</bar>\n",
        EXPECT_NO_MATCH,
        921110
    },

    /* TEST 11: no_expect */
    {
        "POST / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 11\r\n"
        "\r\n"
        "var=get it\n",
        EXPECT_NO_MATCH,
        921110
    },

    /* ---------------- Rule 921422 ---------------- */

    /* TEST 12: expect */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/x-www-form-urlencoded;boundary=\"application/json\"\r\n"
        "Content-Length: 0\r\n"
        "\r\n",
        EXPECT_MATCH,
        921422
    },

    /* TEST 13: expect */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/x-www-form-urlencoded;boundary=\"application/vnd.mycompany.myapp.customer-v2+json\"\r\n"
        "Content-Length: 0\r\n"
        "\r\n",
        EXPECT_MATCH,
        921422
    },

    /* TEST 14: no_expect */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 0\r\n"
        "\r\n",
        EXPECT_NO_MATCH,
        921422
    },

    /* TEST 15: no_expect */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Content-Length: 0\r\n"
        "\r\n",
        EXPECT_NO_MATCH,
        921422
    },

    /* TEST 16: no_expect */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: multipart/form-data; boundary=something\r\n"
        "Content-Length: 0\r\n"
        "\r\n",
        EXPECT_NO_MATCH,
        921422
    },

    /* TEST 17: no_expect */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: multipart/form-data; boundary=----webkitformboundary12w4lszoxn26vnd\r\n"
        "Content-Length: 0\r\n"
        "\r\n",
        EXPECT_NO_MATCH,
        921422
    },
};

static const int protocol_cases_count =
    (int)(sizeof(protocol_cases) / sizeof(protocol_cases[0]));

int protocol_get_count(void)
{
    return protocol_cases_count;
}

const test_case_t *protocol_get_case(int index)
{
    if (index < 0 || index >= protocol_cases_count)
        return (const test_case_t *)0;
    return &protocol_cases[index];
}

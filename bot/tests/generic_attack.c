#include "generic_attack.h"

/* Rule 934100 */
static const test_case_t generic_cases[] = {

    /* TEST 1 */
    {
        "GET /get?foo=_%24%24ND_FUNC%24%24_ HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        934100
    },

    /* TEST 2 */
    {
        "GET /get?foo=__js_function HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        934100
    },

    /* TEST 3 */
    {
        "GET /get?foo=eval%28String.fromCharCode HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        934100
    },

    /* TEST 4 */
    {
        "GET /get?foo=function%28%29+%7B HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        934100
    },

    /* TEST 5 */
    {
        "GET /get?foo=new+Function+%28 HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        934100
    },

    /* TEST 6 */
    {
        "GET /get?foo=this.constructor.constructor HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        934100
    },

    /* TEST 1: SSRF - scheme-less localhost */
    {
        "GET /get/test?url=localhost/ HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        934190
    },

    /* TEST 7: SSRF - scheme-less host.docker.internal (Docker) */
    {
        "GET /get/test?url=host.docker.internal/ HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        934190
    },

    /* TEST 11: SSRF - scheme-less kubernetes.default.svc.cluster.local (K8s) */
    {
        "GET /get/test?url=kubernetes.default.svc.cluster.local/ HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        934190
    },

    /* TEST 15: SSRF - scheme-less localhost in POST body */
    {
        "POST /post/test HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 16\r\n"
        "\r\n"
        "url=localhost%2F",
        EXPECT_MATCH,
        934190
    },

    /* TEST 16: SSRF - scheme-less host.docker.internal in cookie */
    {
        "GET /get/test HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Cookie: redirect=host.docker.internal/\r\n"
        "\r\n",
        EXPECT_MATCH,
        934190
    },

    /* TEST 17: SSRF - localhost with scheme (overlaps with 934110) */
    {
        "GET /get/test?url=http%3A%2F%2Flocalhost%2F HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        934190
    },

    /* TEST 18: Negative test - legitimate domain */
    {
        "GET /get/test?url=example.com/ HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_NO_MATCH,
        934190    },

    /* TEST 19: Negative test - word containing localhost */
    {
        "GET /get/test?server=mylocalhost HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_NO_MATCH,
        934190
    },

    /* TEST 20: Negative test - localhost without trailing slash */
    {
        "GET /get/test?server=localhost HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_NO_MATCH,
        934190
    },

    /* TEST 44: Negative test - JSON array (Should NOT match) */
    {
        "GET /get?x=%7B%22array%22%3A%5B1%2C2%2C3%5D%7D HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_NO_MATCH,
        934140
    },

    /* TEST 46: Negative test - Email address with @ (Should NOT match) */
    {
        "GET /get?email=user%40example.com HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_NO_MATCH,
        934140
    }

};

static const int generic_cases_count = 
    (int)(sizeof(generic_cases)) / sizeof(generic_cases[0]);

int generic_get_count(void)
{
    return generic_cases_count;
}

const test_case_t *generic_get_case(int index)
{
    if (index < 0 || index >= generic_cases_count)
        return (const test_case_t *)0;
    return &generic_cases[index];
}

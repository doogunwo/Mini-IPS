#include "session_fixation_attack.h"

static const test_case_t session_fixation_cases[] = {

    /* TEST 1: Session Fixation via <script> tag injecting document.cookie */
    {
        "GET /get/foo.php?bar=blah<script>document.cookie=\"sessionid=1234;%20domain=.example.dom\";</script> HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Accept-Encoding: gzip, deflate\r\n"
        "Accept-Language: zh-sg\r\n"
        "Keep-Alive: 300\r\n"
        "Proxy-Connection: keep-alive\r\n"
        "Referer: http\r\n"
        "\r\n",
        EXPECT_MATCH,
        943100
    },

    /* TEST 2: Session Fixation attempt via cookie value setting in ARGS */
    {
        "GET /get/foo.php?test=.cookie;expires= HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Accept-Encoding: gzip, deflate\r\n"
        "Accept-Language: zh-sg\r\n"
        "\r\n",
        EXPECT_MATCH,
        943100
    }
};

static const int session_fixation_cases_count =
    (int)(sizeof(session_fixation_cases) / sizeof(session_fixation_cases[0]));

int session_fixation_get_count(void)
{
    return session_fixation_cases_count;
}

const test_case_t *session_fixation_get_case(int index) 
{
    if (index < 0 || index >= session_fixation_cases_count)
        return (const test_case_t *)0;
    return &session_fixation_cases[index];
}

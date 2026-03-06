#include "RCE_attack.h"

/* Auto-generated from REQUEST-932-APPLICATION-ATTACK-RCE.yaml */
static const test_case_t RCE_cases[] = {

    /* TEST 1: for % */
    {
        "GET /get?foo=for%20%25variable%20in%20%28set%29%20do%20command HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 2: for %% */
    {
        "GET /get?foo=for%20%25%25variable%20in%20%28set%29%20do%20command HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 3: for /d */
    {
        "GET /get?foo=for%20%2fd%20%25variable%20in%20%28set%29%20do%20command HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 4: for /r */
    {
        "GET /get?foo=for%20%2fr%20c%3a%5c%20%25variable%20in%20%28set%29%20do%20command HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 5: for /l */
    {
        "GET /get?foo=for%20%2fl%20%25variable%20in%20%281%2c1%2c2%29%20do%20command HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 6: for /f .. fileset */
    {
        "GET /get?foo=for%20%2ff%20%25variable%20in%20%28fileset%29%20do%20command HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 7: for /f .. "string" */
    {
        "GET /get?foo=for%20%2ff%20%25variable%20in%20%28%22string%22%29%20do%20command HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 8: for /f .. 'command' */
    {
        "GET /get?foo=for%20%2ff%20%25variable%20in%20%28%27command%27%29%20do%20command HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 9: for /f .. `command` */
    {
        "GET /get?foo=for%20%2ff%20%22usebackq%22%20%25variable%20in%20%28%60command%60%29%20do%20command HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 10: imported test */
    {
        "GET /get?foo=%7Cfor+%2Ff+%22delims%3D%22+%25i+in+%28%27cmd+%2Fc+%22powershell.exe+-InputFormat+none+write+%27FJQPVY%27.length%22%27%29+do+if+%25i%3D%3D6+%28cmd+%2Fc+%22powershell.exe+-InputFormat+none+Start-Sleep+-s+2%22%29 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 11: imported test */
    {
        "GET /get?foo=FOR++++++++++++++%25a+IN+%28set%29+DO+abc HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 12: imported test */
    {
        "GET /get?foo=FOR+%2FD+++++++++++%25a+IN+%28dirs%29+DO+abc HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 13: imported test */
    {
        "GET /get?foo=FOR+%2FD+%2FD++++++++%25a+IN+%28dirs%29+DO+abc HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 14: imported test */
    {
        "GET /get?foo=FOR+%2FF+%22options%22+%25a+IN+%28text%29+DO+abc HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 15: imported test */
    {
        "GET /get?foo=FOR+%2FF+%22options%22+%25a+IN+%28%22text%22%29+DO+abc HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 16: imported test */
    {
        "GET /get?foo=FOR+%2FL+++++++++++%25a+IN+%28start%2Cstep%2Cend%29+DO+abc HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 17: imported test */
    {
        "GET /get?foo=FOR+%2FL+%2FL+%2FL+++++%25a+IN+%28start%2Cstep%2Cend%29+DO+abc HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 18: imported test */
    {
        "GET /get?foo=FOR+%2FR+C%3A%5Cbla++++%25A+IN+%28set%29+DO+abc HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 19: imported test */
    {
        "GET /get?foo=%26+for+%25a+in+%28a%2Cb%2Cc%29+do+cmd HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 20: imported test */
    {
        "GET /get?foo=%26+FOR+%25%25a+IN+%28a%2Cb%2Cc%29+DO+cmd HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 21: imported test */
    {
        "GET /get?foo=%26+FOR+%25_+IN+%28a%2Cb%2Cc%29+DO+cmd HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 22: imported test */
    {
        "GET /get?foo=%26+FOR+%252+IN+%28a%2Cb%2Cc%29+DO+cmd HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 23: imported test */
    {
        "GET /get?foo=%26+FOR+%25-+IN+%28a%2Cb%2Cc%29+DO+cmd HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 24: imported test */
    {
        "GET /get?foo=%26+FOR+%25%2F+IN+%28a%2Cb%2Cc%29+DO+cmd HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 25: imported test */
    {
        "GET /get?foo=%26+FOR+%25%40+IN+%28a%2Cb%2Cc%29DO+cmd HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 26: imported test */
    {
        "GET /get?foo=%26+FOR+%25%5B+IN+%28a%2Cb%2Cc%29DO+cmd HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 27: imported test */
    {
        "GET /get?foo=%26+FOR+%25%5D+IN+%28a%2Cb%2Cc%29DO+cmd HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 28: imported test */
    {
        "GET /get?foo=%26+FOR+%25%7E+IN+%28a%2Cb%2Cc%29DO+cmd HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 29: imported test */
    {
        "GET /get?foo=%26+FOR+%2FF+%22tokens%3D1-3%22+%25A+IN+%28%22jejeje+brbr%22%29+DO+%40echo+pwnd HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 30: imported test */
    {
        "GET /get?foo=%26+FOR+%2FF+%22tokens%3D1-3%22+%25%25A+IN+++%28%22jejeje+brbr%22%29+DO+%40echo+pwnd HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 31: imported test */
    {
        "GET /get?foo=%26+FOR+%2FF+%22delims%3D%22+%25G+IN+%28%27SET%27%29+DO+%40Echo+%25G HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 32: imported test */
    {
        "GET /get?foo=%26+FOR+%2FF+%22delims%3D%22+%25G+IN+++%28%27ECHO+foo%27%29DO+%40Echo+%25G HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 33: imported test */
    {
        "GET /get?foo=%26+FOR+%2FF+%22delims%3D%22+%25%7E+IN+++%28%27ECHO+foo%27%29DO+%40Echo+%25G HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 34: imported test */
    {
        "GET /get?foo=For+%2FR+C%3A%5Ctemp%5C+%25G+IN+%28%2A.bak%29+do+Echo+del+%22%25G%22 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 35: imported test */
    {
        "GET /get?foo=For+%2FR+C%3A%5Ctemp%5C+%25%25G+IN+%28%2A.bak%29+do+Echo+del+%22%25%25G%22 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 36: imported test */
    {
        "GET /get?foo=FOR+%2Ff+%22tokens%3D%2A%22+%25G+IN+%28%27dir+%2Fb%27%29+DO+%28call+%3Asubroutine+%22%25G%22%29 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 37: imported test */
    {
        "GET /get?foo=FOR+%2Ff+%22tokens%3D%2A%22+%25%25G+IN+%28%27dir+%2Fb%27%29+DO+%28call+%3Asubroutine+%22%25%25G%22%29 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 38: imported test */
    {
        "GET /get?foo=FOR+%2FF+%22tokens%3D1-5%22+%25A+IN+%28%22This+is+a+short+sentence%22%29+DO+%40echo+%25A+%25B+%25D HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 39: imported test */
    {
        "GET /get?foo=FOR+%2FF+%22tokens%3D1-5%22+%25%25A+IN+%28%22This+is+a+short+sentence%22%29+DO+%40echo+%25%25A+%25%25B+%25%25D HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 40: imported test */
    {
        "GET /get?foo=FOR+%25G+IN+%28a%2Cb%2Cc%2Cd%2Ce%2Cf%2Cg%2Ch%2Ci%2Cj%2Ck%2Cl%2Cm%2Cn%2Co%2Cp%2Cq%2Cr%2Cs%2Ct%2Cu%2Cv%2Cw%2Cx%2Cy%2Cz%29+DO+%28md+C%3A%5Cdemo%5C%25G%29 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 41: imported test */
    {
        "GET /get?foo=FOR+%25%25G+IN+%28a%2Cb%2Cc%2Cd%2Ce%2Cf%2Cg%2Ch%2Ci%2Cj%2Ck%2Cl%2Cm%2Cn%2Co%2Cp%2Cq%2Cr%2Cs%2Ct%2Cu%2Cv%2Cw%2Cx%2Cy%2Cz%29+DO+%28md+C%3A%5Cdemo%5C%25%25G%29 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 42: imported test */
    {
        "GET /get?foo=FOR+%2FL+%25G+IN+%281%2C1%2C5%29+DO+echo+%25G HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 43: imported test */
    {
        "GET /get?foo=FOR+%2FL+%25%25G+IN+%281%2C1%2C5%29+DO+echo+%25%25G HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 44: imported test */
    {
        "GET /get?foo=FOR+%25G+IN+%28Sun+Mon+Tue+Wed+Thur+Fri+Sat%29+DO+echo+%25G HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 45: imported test */
    {
        "GET /get?foo=FOR+%25%25G+IN+%28Sun+Mon+Tue+Wed+Thur+Fri+Sat%29+DO+echo+%25%25G HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 46: imported test */
    {
        "GET /get?foo=for+%2Ff+%22tokens%3D%2A%22+%25G+in+%28%27dir+%2Fb+%2Fs+%2Fa%3Ad+%22C%3A%5CWork%5Creports%2A%22%27%29+do+echo+Found+%25G HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 47: imported test */
    {
        "GET /get?foo=for+%2Ff+%22tokens%3D%2A%22+%25%25G+in+%28%27dir+%2Fb+%2Fs+%2Fa%3Ad+%22C%3A%5CWork%5Creports%2A%22%27%29+do+echo+Found+%25%25G HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 48: imported test */
    {
        "GET /get?foo=FOR+%2FD+%2Fr+%25G+in+%28%22User%2A%22%29+DO+Echo+We+found+%25G HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 49: imported test */
    {
        "GET /get?foo=FOR+%2FF+%22tokens%3D1%2C3+delims%3D%2C%22+%25%25G+IN+%28weather.txt%29+DO+%40echo+%25%25G+%25%25H HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 50: imported test */
    {
        "GET /get?foo=FOR+%2FF+%22tokens%3D4+delims%3D%2C%22+%25%25G+IN+%28%22deposit%2C%244500%2C123.4%2C12-AUG-09%22%29+DO+%40echo+Date+paid+%25%25G HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 51: imported test */
    {
        "GET /get?foo=FOR+%2FF+%25G+IN+%28%27%22C%3A%5Cprogram+Files%5Ccommand.exe%22%27%29+DO+ECHO+%25G HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 52: imported test */
    {
        "GET /get?foo=FOR+%2FF+%25%25G+IN+%28%27%22C%3A%5Cprogram+Files%5Ccommand.exe%22%27%29+DO+ECHO+%25%25G HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 53: imported test */
    {
        "GET /get?foo=FOR+%2FF+%22tokens%3D1%2C2%2A+delims%3D%2C%22+%25%25+IN+%28C%3A%5CMyDocu%7E1%5Cmytex%7E1.txt%29+DO+ECHO+%25%25 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 54: imported test */
    {
        "GET /get?foo=FOR+%2FF+%22tokens%3D1%2C2%2A+delims%3D%2C%22+%25%25G+IN+%28C%3A%5CMyDocu%7E1%5Cmytex%7E1.txt%29+DO+ECHO+%25%25G HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 55: imported test */
    {
        "GET /get?foo=FOR+%2FF+%22usebackq+tokens%3D1%2C2%2A+delims%3D%2C%22+%25G+IN+%28%22C%3A%5CMy+Documents%5Cmy+textfile.txt%22%29+DO+ECHO+%25G HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 56: imported test */
    {
        "GET /get?foo=FOR+%2FF+%22usebackq+tokens%3D1%2C2%2A+delims%3D%2C%22+%25%25G+IN+%28%22C%3A%5CMy+Documents%5Cmy+textfile.txt%22%29+DO+ECHO+%25%25G HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 57: imported test */
    {
        "GET /get?foo=%26+for+%2Ff+%5C%22delims%3D%5C%22+%25i+in+%28%27cmd+%2Fc+%5C%22set+%2Fa+%2863%2B21%29%5C%22%27%29+do+%40set+%2Fp+%3D+PDVQIS%25iPDVQISPDVQIS%3C+nul HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 58: imported test */
    {
        "GET /get?foo=%3Bfor+%2Ff+%5C%22delims%3D%5C%22+%25i+in+%28%27cmd+%2Fc+%5C%22set+%2Fa+%2835%2B66%29%5C%22%27%29+do+%40set+%2Fp+%3D+LZEUZE%25iLZEUZELZEUZE%3C+nul%27 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 59: imported test */
    {
        "GET /get?foo=for+%2Ff+%22tokens%3D%2A+delims%3D0%22+%25%25A+in+%28%22%25n1%25%22%29+do+set+%22n1%3D%25%25A%22 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 60: imported test */
    {
        "GET /get?foo=for+%25i+in+%28%2A%29+do+set+LIST%3D+%25i HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 61: imported test */
    {
        "GET /get?foo=for+%25i+in+%28%2A%29+do+set+LIST%3D%21LIST%21+%25i HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 62: imported test */
    {
        "GET /get?foo=for+%2Fl+%25%25I+in+%280%2C1%2C5%29+do+call+echo+%25%25RANDOM%25%25 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 63: imported test */
    {
        "GET /get?foo=for+%25%25d+in+%28A%2CC%2CD%29+do+DIR+%25%25d+%2A.%2A HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 64: imported test */
    {
        "GET /get?foo=for+%25%25f+in+%28%2A.TXT+%2A.BAT+%2A.DOC%29+do+TYPE+%25%25f HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 65: imported test */
    {
        "GET /get?foo=for+%25%25P+in+%28%25PATH%25%29+do+if+exist+%25%25P%5C%2A.BAT+COPY+%25%25P%5C%2A.BAT+C%3A%5CBAT HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 66: imported test */
    {
        "GET /get?foo=IF++++++++EXIST+filename.txt+++++%28 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 67: imported test */
    {
        "GET /get?foo=IF++++++++EXIST+filename+++++++++CMD HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 68: imported test */
    {
        "GET /get?foo=IF++++++++EXIST+filename+++++++++%28CMD%29 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 69: imported test */
    {
        "GET /get?foo=IF++++++++EXIST+data.xls+++++++++Echo+The+file+was+found. HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 70: imported test */
    {
        "GET /get?foo=IF++++++++EXIST+MyFile.txt+++++++%28ECHO+Some%5Bmore%5DPotatoes%29 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 71: imported test */
    {
        "GET /get?foo=IF++++++++EXIST+C%3A%5Cpagefile.sys++CMD HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 72: imported test */
    {
        "GET /get?foo=IF++++++++EXIST+C%3A%5Cpagefile.sys++%28CMD%29+ELSE+%28CMD%29 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 73: imported test */
    {
        "GET /get?foo=IF++++NOT+EXIST+C%3A%5Cnonexistent+++CMD HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 74: imported test */
    {
        "GET /get?foo=IF+%2FI+NOT+EXIST+C%3A%5Cnonexistent+++echo+hey HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 75: imported test */
    {
        "GET /get?foo=IF+++%2FI+++NOT+++EXIST+++C%3A%5Cnonexistent+++echo+hey HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 76: imported test */
    {
        "GET /get?foo=IF++++NOT+EXIST+C%3A%5Cnonexistent+++%28CMD%29+ELSE+%28CMD%29 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 77: imported test */
    {
        "GET /get?foo=IF++++NOT+EXIST+%28C%3A%5Cnonexistent%29+ECHO+pwnt HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 78: imported test */
    {
        "GET /get?foo=IF++++++++DEFINED+variable+++++++CMD HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 79: imported test */
    {
        "GET /get?foo=IF++++NOT+DEFINED+_example+++++++ECHO+Value+Missing HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 80: imported test */
    {
        "GET /get?foo=IF++++++++ERRORLEVEL+0+++++++++++CMD HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 81: imported test */
    {
        "GET /get?foo=IF++++NOT+ERRORLEVEL+0+++++++++++CMD HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 82: imported test */
    {
        "GET /get?foo=IF++++++++CMDEXTVERSION+1++++++++GOTO+start_process HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 83: imported test */
    {
        "GET /get?foo=IF++++++++2++++++++++++GEQ+15++++echo+%22bigger%22 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 84: imported test */
    {
        "GET /get?foo=IF++++++++%222%22++++++++++GEQ+%2215%22++echo+%22bigger%22 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 85: imported test */
    {
        "GET /get?foo=IF++++++++%25ERRORLEVEL%25+EQU+2+++++goto+sub_problem2 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 86: imported test */
    {
        "GET /get?foo=IF++++++++%25ERRORLEVEL%25+NEQ+0+++++echo+test HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 87: imported test */
    {
        "GET /get?foo=IF++++++++%25ERRORLEVEL%25+LEQ+2+++++echo+test HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 88: imported test */
    {
        "GET /get?foo=IF++++++++%25ERRORLEVEL%25+GTR+2+++++echo+test HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 89: imported test */
    {
        "GET /get?foo=IF++++++++%25ERRORLEVEL%25+GEQ+2+++++echo+test HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 90: imported test */
    {
        "GET /get?foo=IF++++++++%25VARIABLE%25+++GTR+0+++++Echo+An+error+was+found HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 91: imported test */
    {
        "GET /get?foo=IF++++++++%25VARIABLE%25+++LSS+0+++++Echo+An+error+was+found HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 92: imported test */
    {
        "GET /get?foo=IF++++++++%25VARIABLE%25+++EQU+0+++++Echo+An+error+was+found HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 93: imported test */
    {
        "GET /get?foo=IF+%2FI+++++item1%3D%3Ditem2+++++++++++CMD HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 94: imported test */
    {
        "GET /get?foo=IF+%2FI+NOT+item1%3D%3Ditem2+++++++++++CMD HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 95: imported test */
    {
        "GET /get?foo=IF+%2FI+NOT+1%3D%3D2+++++++++++++++++++CMD HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 96: imported test */
    {
        "GET /get?foo=IF++++++++%25_prefix%25%3D%3DSS6+++++++++GOTO+they_matched HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 97: imported test */
    {
        "GET /get?foo=IF++++++++%5B%251%5D%3D%3D%5B%5D+++++++++++++++ECHO+Value+Missing HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 98: imported test */
    {
        "GET /get?foo=IF++++++++%5B%251%5D+EQU+%5B%5D++++++++++++ECHO+Value+Missing HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 99: imported test */
    {
        "GET /get?foo=IF++++++++%282+GEQ+15%29+++++++++++++echo+%22bigger%22 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 100: imported test */
    {
        "GET /get?foo=IF++++++++red%3D%3Dred+++++++++++++++echo+test HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 101: imported test */
    {
        "GET /get?foo=IF++++NOT+red%3D%3D%3Dred++++++++++++++echo+test HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 102: imported test */
    {
        "GET /get?foo=IF+%2FI+++++Red%3D%3Dred+++++++++++++++echo+test HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 103: imported test */
    {
        "GET /get?foo=if+%281%29+equ+%281%29+echo+hey HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 104: imported test */
    {
        "GET /get?foo=if+not+%282+equ+2%29+echo+hey HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 105: imported test */
    {
        "GET /get?foo=if+%22%25VAR%25%22%3D%3D%25%25A+do+echo+true HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 106: imported test */
    {
        "GET /get?foo=IF+%22%25%7E1%22+%3D%3D+%22%25%7E2%22+%28EXIT+%2FB+0%29+ELSE+%28EXIT+%2FB+1%29 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 107: imported test */
    {
        "GET /get?foo=if+%25n1%25+gtr+%25n2%25+echo+%25n1%25+is+greater+than+%25n2%25 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 108: imported test */
    {
        "GET /get?foo=if+%25n1%25+lss+%25n2%25+echo+%25n1%25+is+less+than+%25n2%25 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 109: imported test */
    {
        "GET /get?foo=if+%25n1%25+equ+%25n2%25+echo+%25n1%25+is+equal+to+%25n2%25 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 110: imported test */
    {
        "GET /get?foo=if+%22%25n1%25%22+gtr+%22%25n2%25%22+echo+%22%25n1%25%22+is+greater+than+%22%25n2%25%22 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 111: imported test */
    {
        "GET /get?foo=if+%22%25n1%25%22+lss+%22%25n2%25%22+echo+%22%25n1%25%22+is+less+than+%22%25n2%25%22 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 112: imported test */
    {
        "GET /get?foo=if+%22%25n1%25%22+equ+%22%25n2%25%22+echo+%22%25n1%25%22+is+equal+to+%22%25n2%25%22 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 113: imported test */
    {
        "GET /get?foo=if+not+defined+n1+set+%22n1%3D0%22 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 114: imported test */
    {
        "GET /get?foo=IF+X%251%3D%3DX%2F%3F+GOTO+Helpscreen HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 115: imported test */
    {
        "GET /get?foo=IF+%22%251%22%3D%3D%22%2F%3F%22+... HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 116: imported test */
    {
        "GET /get?foo=IF+%5B%251%5D%3D%3D%5B%2F%3F%5D+... HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 117: imported test */
    {
        "GET /get?foo=IF+%22%25%7E1%22%3D%3D%22%2F%3F%22+... HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 118: imported test */
    {
        "GET /get?foo=IF+ERRORLEVEL+3+IF+NOT+ERRORLEVEL+4+... HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 119: imported test */
    {
        "GET /get?foo=IF+NOT+DEFINED+BAR+%28 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 120: imported test */
    {
        "GET /get?foo=if+%22%25VAR%25%22+%3D%3D+%22before%22+%28 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 121: imported test */
    {
        "GET /get?foo=if+%22%25VAR%25%22+%3D%3D+%22after%22+%40echo+ok HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 122: imported test */
    {
        "GET /get?foo=if+%22%21VAR%21%22+%3D%3D+%22after%22+%40echo+ok HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 123: imported test */
    {
        "GET /get?foo=if+not+defined+BAR+set+FOO%3D1%26+echo+FOO%3A+%25FOO%25 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 124: imported test */
    {
        "GET /get?foo=if+%28%251%29%3D%3D%28LTRS%29+CD+C%3A%5CWORD%5CLTRS HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 125: imported test */
    {
        "GET /get?foo=if+%22%251%22%3D%3D%22%22+goto+ERROR HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 126: imported test */
    {
        "GET /get?foo=if+%28AA%29+%3D%3D+%28AA%29+echo+same HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 127: imported test */
    {
        "GET /get?foo=if+%5BAA%5D+%3D%3D+%5BAA%5D+echo+same HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 128: imported test */
    {
        "GET /get?foo=if+%22A+A%22+%3D%3D+%22A+A%22+echo+same HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 129: imported test */
    {
        "GET /get?foo=IF+%25_prog%3A%7E-1%25+NEQ+%5C+%28Set+_prog%3D%25_prog%25%5C%29 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 130: imported test */
    {
        "GET /get?foo=IF+EXIST+%22temp.txt%22+ECHO+found HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 131: imported test */
    {
        "GET /get?foo=IF+NOT+EXIST+%22temp.txt%22+ECHO+not+found HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 132: imported test */
    {
        "GET /get?foo=IF+%22%25var%25%22%3D%3D%22%22+%28SET+var%3Ddefault+value%29 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 133: imported test */
    {
        "GET /get?foo=IF+NOT+DEFINED+var+%28SET+var%3Ddefault+value%29 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 134: imported test */
    {
        "GET /get?foo=IF+%22%25var%25%22%3D%3D%22Hello%2C+World%21%22+%28ECHO+found%29 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 135: imported test */
    {
        "GET /get?foo=IF+%2FI+%22%25var%25%22%3D%3D%22hello%2C+world%21%22+%28+ECHO+found+%29 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 136: imported test */
    {
        "GET /get?foo=IF+%2FI+%22%25var%25%22+EQU+%221%22+ECHO+equality+with+1 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 137: imported test */
    {
        "GET /get?foo=IF+%2FI+%22%25var%25%22+NEQ+%220%22+ECHO+inequality+with+0 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 138: imported test */
    {
        "GET /get?foo=IF+%2FI+%22%25var%25%22+GEQ+%221%22+ECHO+greater+than+or+equal+to+1 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 139: imported test */
    {
        "GET /get?foo=IF+%2FI+%22%25var%25%22+LEQ+%221%22+ECHO+less+than+or+equal+to+1 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 140: imported test */
    {
        "GET /get?foo=IF+%2FI+%22%25ERRORLEVEL%25%22+NEQ+%220%22+%28ECHO+execution+failed%29 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 141: imported test */
    {
        "GET /get?foo=if+not+%251+%3D%3D+%22%22+%28 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 142: imported test */
    {
        "GET /get?foo=if+not+%22%251%22+%3D%3D+%22%22+%28 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 143: imported test */
    {
        "GET /get?foo=if+not+%7B%251%7D+%3D%3D+%7B%7D HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 144: imported test */
    {
        "GET /get?foo=if+not+%22A%251%22+%3D%3D+%22A%22+%28 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 145: imported test */
    {
        "GET /get?foo=IF+DEFINED+ARG+%28echo+%22It+is+defined%3A+%251%22%29+ELSE+%28echo+%22%25%251+is+not+defined%22%29 HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 146: imported test */
    {
        "GET /get?foo=if3q+hfy6e8egfxsjtewc838gsfbhwvw9qzfty3gjs86syg7y6mrpwgw4ekureakjpk6%2Flyghe9pnfekpw2yt8svzseinhs1rbkuu%2Fzq15u5wh8nj8dd+fn86qcdwzv3s9hw35e14pxgcv34dhmt1mwbxnicwudjawfqz+fphmr5vlnufdihoffpuvqwkcmom61i3lisyxg65fx+rgbnrs6e4pmbvy2xl+vwb8oct23cyypregi638dkychllvvw5kq7rolfbhk3hojxz9tthunqky9dodqbb6u8roh+firwx8kuf1dfgewcto9eljhuaoqgdk4qwxlziktaf1mw2atcmw7jvzsh1s0kngiepps54lj4wtcbfzfvbqb7y3caffhnvfrm3tbjxlywqakfqxoprh7yooguat5flg2ozx5%2Fafn7w%3D%3D HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_NO_MATCH,
        932140
    },

    /* TEST 147: imported test */
    {
        "GET /get?foo=if+a%3D%3Db+foo HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 148: imported test */
    {
        "GET /get?foo=if%2Fi+a%3D%3Db+foo HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 149: imported test */
    {
        "GET /get?foo=if+%2Fi+a%3D%3Db+foo HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 150: imported test */
    {
        "GET /get?foo=if+%2Fi+%22a%22%3D%3D%22b%22++foo HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 151: imported test */
    {
        "GET /get?foo=if+%2Fi+not++%22a%22%3D%3D%22b%22++foo HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 152: imported test */
    {
        "GET /get?foo=if+++exist+StorageServer.port+echo+yay HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 153: imported test */
    {
        "GET /get?foo=if+%2Fi+exist+StorageServer.port+echo+yay HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        932140
    },

    /* TEST 154: imported test */
    {
        "GET /get?foo=ifq+a%3D%3Db+foo HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_NO_MATCH,
        932140
    },

    /* TEST 155: imported test */
    {
        "GET /get?foo=iffoo+a%3D%3Db+foo HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_NO_MATCH,
        932140
    },

    /* TEST 156: imported test */
    {
        "GET /get?foo=if3+a%3D%3Db+foo HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_NO_MATCH,
        932140
    },

    /* TEST 157: imported test */
    {
        "GET /get?foo=if3q+a%3D%3Db+foo HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_NO_MATCH,
        932140
    },

    /* TEST 158: FP when using `t:urlDecodeUni`.
Using `t:urlDecodeUni` removes the `+` from the encoded value in the XML document,
which produced a false positive match.
See https://github.com/coreruleset/coreruleset/issues/1785 */
    {
        "POST /post HTTP/1.1\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/xml\r\n"
        "Content-Length: 70\r\n"
        "\r\n"
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><note><pdf>if+foo==</pdf></note>",
        EXPECT_NO_MATCH,
        932140
    },

};

static const int RCE_cases_count = 
    (int)(sizeof(RCE_cases)) / sizeof(RCE_cases[0]);

int RCE_get_count(void)
{
    return RCE_cases_count;
}

const test_case_t *RCE_get_case(int index)
{
    if(index < 0 || index >= RCE_cases_count)
        return (const test_case_t *)0;
    return &RCE_cases[index];
}
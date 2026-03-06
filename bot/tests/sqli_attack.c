#include "sqli_attack.h"

static const test_case_t sqli_cases[] = {

    /* TEST 1: Simple SQL Injection - OR 1=1 */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 15\r\n"
        "\r\n"
        "var=1234 OR 1=1",
        EXPECT_MATCH,
        942100
    },

    /* TEST 2: Simple SQL injection - Single quote evasion */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 20\r\n"
        "\r\n"
        "var=-1839' or '1'='1",
        EXPECT_MATCH,
        942100
    },

    /* TEST 3: Simple SQL injection - Double quote evasion */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 20\r\n"
        "\r\n"
        "var=-1839\" or \"1\"=\"2",
        EXPECT_MATCH,
        942100
    },

    /* TEST 4: Time-based SQLi - sleep() with Ruby-style evasion */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 32\r\n"
        "\r\n"
        "var=2010-01-01'+sleep(20.to_i)+'",
        EXPECT_MATCH,
        942100
    },

    /* TEST 6: UNION ALL select NULL */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 34\r\n"
        "\r\n"
        "var=foo') UNION ALL select NULL --",
        EXPECT_MATCH,
        942100
    },

    /* TEST 10: Advanced SQL Injection + XXE (extractvalue) */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 147\r\n"
        "\r\n"
        "1'||(select extractvalue(xmltype('<?xml version=\"1.1\" encoding=\"UTF-8\"?><!DOCTYPE root [ <!ENTITY % toyop SYSTEM \"https://coreruleset.org/\">%toyop;",
        EXPECT_MATCH,
        942100
    },

    /* TEST 11: Simple function call - sleep(20) */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 13\r\n"
        "\r\n"
        "var=sleep(20)",
        EXPECT_MATCH,
        942100
    },

    /* TEST 13: Command Injection style within SQLi context */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 42\r\n"
        "\r\n"
        "var=\" | type %SystemDrive%\\\\config.ini | \"",
        EXPECT_MATCH,
        942100
    },

    /* TEST 14: Complex Time-based Blind SQLi */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 74\r\n"
        "\r\n"
        "var=\"unittests@coreruleset.org\"')) and (select*from(select(sleep(5)))x) --",
        EXPECT_MATCH,
        942100
    },
    
    /* TEST 15: Detects SQL benchmark - SELECT BENCHMARK(1000000,1+1); */
    {
        "GET /get?var=SELECT%20BENCHMARK%281000000%2C1%2B1%29%3B HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        942170
    },

    /* TEST 16: SQL sleep injection attempt - ; sleep(0) */
    {
        "GET /get?var=%3B%20sleep%280%29 HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        942170
    },

    /* TEST 17: Negative test - legitimate use of 'sleep' word */
    {
        "GET /get?var=I%20sleep%20well%21 HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_NO_MATCH,
        942170
    },

    /* TEST 18: SQL injection test with conditional - select if(x */
    {
        "GET /get?test=select+if(x HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        942170
    },

    /* TEST 1: Basic SQL authentication bypass - in ( select * from */
    {
        "GET /get?var=in%20%28%20select%20%2a%20from HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        942340
    },

    /* TEST 2: SQLite auth bypass - except select with tab character */
    {
        "GET /get?var=except%20%09select.1%2C2 HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        942340
    },

    /* TEST 3: SQLite auth bypass - except values */
    {
        "GET /get?var=except%20values(1%2C2) HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        942340
    },

    /* TEST 4: Negative test - 'except selecting' (legitimate word) */
    {
        "GET /get?var=except%20selecting HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_NO_MATCH,
        942340
    },

    /* TEST 5: Auth bypass via array check - is not null */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 45\r\n"
        "\r\n"
        "email=x'%20or%20array[id]%20is%20not%20null--",
        EXPECT_MATCH,
        942340
    },

    /* TEST 6: Advanced bypass - email~all(array[email]);analyze */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 49\r\n"
        "\r\n"
        "email=x'%20or%20email~all(array[email]);analyze--",
        EXPECT_MATCH,
        942340
    },

    /* TEST 8-1: Basic auth bypass - ' or true; foo */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 26\r\n"
        "\r\n"
        "email='%20or%20true;%20foo",
        EXPECT_MATCH,
        942340
    },

    /* TEST 9: Operator-based bypass without whitespace - '||true */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 13\r\n"
        "\r\n"
        "email='||true",
        EXPECT_MATCH,
        942340
    },

    /* TEST 10: Negative test - invalid operator concatenation 'ortrue */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 13\r\n"
        "\r\n"
        "email='ortrue",
        EXPECT_NO_MATCH,
        942340
    },

    /* TEST 1: Basic SQL injection with many hyphens (6+) */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 37\r\n"
        "\r\n"
        "var=-------------------&var2=whatever",
        EXPECT_MATCH,
        942431
    },

    /* TEST 2: Negative test - Array brackets should not trigger anomaly */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 44\r\n"
        "\r\n"
        "order%5bfilters%5d%5bdate_add%5d%5bfrom%5d=1",
        EXPECT_NO_MATCH,
        942431
    },

    /* TEST 4: SQLi with UTF-8 smart quotes and other chars */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 46\r\n"
        "\r\n"
        "id=%E2%80%99%20OR%20%E2%80%991%3d1%23%3b%2d%2d",
        EXPECT_MATCH,
        942431
    },

    /* TEST 5: Edge case - Exactly 6 special characters (Threshold hit) */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 18\r\n"
        "\r\n"
        "var=%21%40%23%24%25%5e", // !@#$%^
        EXPECT_MATCH,
        942431
    },

    /* TEST 6: Negative test - Only 5 special characters (Below threshold) */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 15\r\n"
        "\r\n"
        "var=%21%40%23%24%25", // !@#$%
        EXPECT_NO_MATCH,
        942431
    },

    /* TEST 7: Negative test - Chinese characters (Multi-byte check) */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 44\r\n"
        "\r\n"
        "comment=%e4%bd%a0%e5%a5%bd%e4%b8%96%e7%95%8c",
        EXPECT_NO_MATCH,
        942431
    },

    /* TEST 9: Mixed SQL special characters */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 17\r\n"
        "\r\n"
        "q=%27%3b%40%40%23%2d%2d", // ';@@#--
        EXPECT_MATCH,
        942431
    },
    /* TEST 1: PostgreSQL JSONB containment operator bypass (ARGS) */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 105\r\n"
        "\r\n"
        "id=OR%20%27%7B%22b%22%3A2%7D%27%3A%3Ajsonb%20%3C%40%20%27%7B%22a%22%3A1%2C%20%22b%22%3A2%7D%27%3A%3Ajsonb",
        EXPECT_MATCH,
        942550
    },

    /* TEST 2: JSON in SQL via REQUEST_FILENAME (URI Path) */
    {
        "GET /get/OR%20%27%7B%22b%22%3A2%7D%27%3A%3Ajsonb%20%3C%40%20%27%7B%22a%22%3A1%2C%20%22b%22%3A2%7D%27%3A%3Ajsonb HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        942550
    },

    /* TEST 17: JSON extraction operator (->) with assignment */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 115\r\n"
        "\r\n"
        "id=OR%20%27%7B%22a%22%3A2%2C%22c%22%3A%5B4%2C5%2C%7B%22f%22%3A7%7D%5D%7D%27%20-%3E%20%27%24.c%5B2%5D.f%27%20%3D%207",
        EXPECT_MATCH,
        942550
    },

    /* TEST 19: MySQL/SQLite json_extract function call */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 131\r\n"
        "\r\n"
        "id=OR%20json_extract%28%27%7B%22id%22%3A%2014%2C%20%22name%22%3A%20%22Aztalan%22%7D%27%2C%20%27%24.name%27%29%20%3D%20%27Aztalan%27",
        EXPECT_MATCH,
        942550
    },

    /* TEST 35: SQL Comment Evasion within JSON operators */
    {
        "GET /get?q=OR%20%27%7B%22a%22%3A1%7D%27%3A%3Ajsonb%20%23%3E%20%2F%2A%20Some%20%2A%20comment%20%2A%2F%27%7Ba%2Cb%7D%27%20%3F%20%27c%27 HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        942550
    },

    /* TEST 38: FP Test (Negative) - Natural English question mark */
    {
        "GET /get?q=how%20was%20your%20day%20today? HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_NO_MATCH,
        942550
    },

    /* TEST 42: MySQL specific evasion with comments and whitespace */
    {
        "GET /get?q=SELECT%20id%20FROM%20users%20WHERE%20id=JsoN_EXTraCT/**/(/**/'%20%20%7B%22a%22:1%7D%20%20'/**/,/**/'%20$.a%20'/**/); HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_MATCH,
        942550
    },

    /* TEST 44: FP Test (Negative) - Arrow used in legitimate text */
    {
        "GET /get?message=Find%20your%20solution%20here%20-%3E%20link HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_NO_MATCH,
        942550
    }
    
};

static const int sqli_cases_count = 
    (int)sizeof(sqli_cases) / sizeof(sqli_cases[0]);

int sqli_get_count()
{
    return sqli_cases_count;
}

const test_case_t *sqli_get_case(int index)
{
    if(index < 0 || index >= sqli_cases_count)
        return (const test_case_t *)0;
    return &sqli_cases[index];
}

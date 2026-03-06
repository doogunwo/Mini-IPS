#include "php_attack.h"

static const test_case_t php_upload_cases[] = {

    /* TEST 1: test.php.jpg */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryoRWIb3busvBrbttO\r\n"
        "Content-Length: 221\r\n"
        "\r\n"
        "------WebKitFormBoundaryoRWIb3busvBrbttO\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"test.php.jpg\"\r\n"
        "Content-Type: image/jpeg\r\n"
        "\r\n"
        "<?php @eval($_POST[\"hacker\"]); ?>\r\n"
        "\r\n"
        "------WebKitFormBoundaryoRWIb3busvBrbttO--\r\n",
        EXPECT_MATCH,
        933111
    },

    /* TEST 2: test.php7.gif */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryoRWIb3busvBrbttO\r\n"
        "Content-Length: 239\r\n"
        "\r\n"
        "------WebKitFormBoundaryoRWIb3busvBrbttO\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"test.php7.gif\"\r\n"
        "Content-Type: image/gif\r\n"
        "\r\n"
        "<?php @eval(base64_decode($_COOKIE[\"payload\"])); ?>\r\n"
        "\r\n"
        "------WebKitFormBoundaryoRWIb3busvBrbttO--\r\n",
        EXPECT_MATCH,
        933111
    },

    /* TEST 3: test.phar.png */
    {
        "POST /post HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
        "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryoRWIb3busvBrbttO\r\n"
        "Content-Length: 239\r\n"
        "\r\n"
        "------WebKitFormBoundaryoRWIb3busvBrbttO\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"test.phar.png\"\r\n"
        "Content-Type: image/png\r\n"
        "\r\n"
        "<?php @eval(base64_decode($_COOKIE[\"payload\"])); ?>\r\n"
        "\r\n"
        "------WebKitFormBoundaryoRWIb3busvBrbttO--\r\n",
        EXPECT_MATCH,
        933111
    },
};

static const int php_cases_count =
    (int)(sizeof(php_upload_cases)) / sizeof(php_upload_cases[0]);

int php_get_count(void)
{
    return php_cases_count;
}

const test_case_t *php_get_case(int index)
{
    if (index < 0 || index >= php_cases_count)
        return (const test_case_t *)0;
    return &php_upload_cases[index];
}

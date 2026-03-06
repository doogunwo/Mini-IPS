#include "java_attack.h"

static const test_case_t java_cases[] = {
    /* TEST 1: javax.servlet.ServletException leakage */
    {
        "POST /reflect HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 84\r\n"
        "\r\n"
        "{\"body\": \"javax.servlet.ServletException: Error occurred during request processing\"}",
        EXPECT_MATCH,
        952110
    },

    /* TEST 2: Spring Framework exception leakage */
    {
        "POST /reflect HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 84\r\n"
        "\r\n"
        "{\"body\": \"org.springframework.web.client.HttpClientErrorException: 400 Bad Request\"}",
        EXPECT_MATCH,
        952110
    },

    /* TEST 3: Hibernate exception leakage */
    {
        "POST /reflect HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 93\r\n"
        "\r\n"
        "{\"body\": \"org.hibernate.exception.ConstraintViolationException: could not execute statement\"}",
        EXPECT_MATCH,
        952110
    },

    /* TEST 6: java.lang.NullPointerException (NPE) leakage */
    {
        "POST /reflect HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 42\r\n"
        "\r\n"
        "{\"body\": \"java.lang.NullPointerException\"}",
        EXPECT_MATCH,
        952110
    },

    /* TEST 7: Jackson Databind Exception (JSON parsing error) */
    {
        "POST /reflect HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 130\r\n"
        "\r\n"
        "{\"body\": \"com.fasterxml.jackson.databind.JsonMappingException: Unexpected character ('}' (code 125)): was expecting double-quote\"}",
        EXPECT_MATCH,
        952110
    },

    /* TEST 10: FP Test (Negative) - Legitimate phrase containing 'at com' context */
    {
        "POST /reflect HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 91\r\n"
        "\r\n"
        "{\"body\": \"Clicking on the date/time link will take you to that comment on your live site.\"}",
        EXPECT_NO_MATCH,
        952110
    }
};

static const int java_cases_count = 
    (int)sizeof(java_cases) / sizeof(java_cases[0]);

int java_get_count(void)
{
    return java_cases_count;
}

const test_case_t *java_get_case(int index)
{
    if (index < 0 || index >= java_cases_count)
        return (const test_case_t *)0;
    return &java_cases[index];
}

#include "response_data.h"

static const test_case_t response_data_cases[] = {

    /* TEST 1: ASP.NET ViewStateException leakage */
    {
        "POST /reflect HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 59\r\n"
        "\r\n"
        "{\"body\": \"ViewStateException: Invalid viewstate detected.\"}",
        EXPECT_MATCH,
        950150
    },

    /* TEST 2: ASP.NET HttpRequestValidationException leakage */
    {
        "POST /reflect HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 100\r\n"
        "\r\n"
        "{\"body\": \"HttpRequestValidationException: A potentially dangerous Request.Form value was detected.\"}",
        EXPECT_MATCH,
        950150
    },

    /* TEST 3: ASP.NET HttpCompileException leakage */
    {
        "POST /reflect HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 90\r\n"
        "\r\n"
        "{\"body\": \"HttpCompileException: Compilation error occurred while processing the request.\"}",
        EXPECT_MATCH,
        950150
    },

    /* TEST 4: ASP.NET HttpParseException leakage */
    {
        "POST /reflect HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 63\r\n"
        "\r\n"
        "{\"body\": \"HttpParseException: Error parsing the HTTP request.\"}",
        EXPECT_MATCH,
        950150
    },

    /* TEST 5: ASP.NET HttpUnhandledException leakage */
    {
        "POST /reflect HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 65\r\n"
        "\r\n"
        "{\"body\": \"HttpUnhandledException: An unexpected error occurred.\"}",
        EXPECT_MATCH,
        950150
    },

    /* TEST 6: ASP.NET HttpRequestWrapper leakage */
    {
        "POST /reflect HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 68\r\n"
        "\r\n"
        "{\"body\": \"HttpRequestWrapper: Error handling HTTP request wrapper.\"}",
        EXPECT_MATCH,
        950150
    },

    /* TEST 7: ASP.NET HttpServerUtilityWrapper leakage */
    {
        "POST /reflect HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 76\r\n"
        "\r\n"
        "{\"body\": \"HttpServerUtilityWrapper: Error handling server utility wrapper.\"}",
        EXPECT_MATCH,
        950150
    },

    /* TEST 8: ASP.NET HttpSessionStateWrapper leakage */
    {
        "POST /reflect HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 74\r\n"
        "\r\n"
        "{\"body\": \"HttpSessionStateWrapper: Error handling session state wrapper.\"}",
        EXPECT_MATCH,
        950150
    },

    /* TEST 9: ASP.NET HttpStaticObjectsCollectionWrapper leakage */
    {
        "POST /reflect HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: OWASP CRS test agent\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 97\r\n"
        "\r\n"
        "{\"body\": \"HttpStaticObjectsCollectionWrapper: Error handling static objects collection wrapper.\"}",
        EXPECT_MATCH,
        950150
    }
};

static const int response_data_cases_count =
    (int)(sizeof(response_data_cases)) / sizeof(response_data_cases[0]);

int response_data_get_count(void)
{
    return response_data_cases_count;
}

const test_case_t *response_data_get_case(int index)
{
    if (index < 0 || index >= response_data_cases_count)
        return (const test_case_t *)0;
    return &response_data_cases[index];
}

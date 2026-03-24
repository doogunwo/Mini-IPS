/**
 * @file test_runtime_detect_invocations.c
 * @brief 하드코딩된 HTTP 메시지별 탐지 호출 수 출력 테스트
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "detect.h"
#include "logging.h"

#define TEST_RULES_PATH "rules"

#define CHECK(cond, msg)                          \
    do {                                          \
        if (!(cond)) {                            \
            fprintf(stderr, "FAIL: %s\n", (msg)); \
            return 1;                             \
        }                                         \
    } while (0)

typedef struct {
    const char *label;
    const char *uri;
    const char *headers_raw;
    const char *content_type;
    const char *body;
} detect_case_t;

static void init_msg(http_message_t *msg, const detect_case_t *tc) {
    memset(msg, 0, sizeof(*msg));
    msg->is_request      = 1;
    msg->headers_raw     = (uint8_t *)(tc->headers_raw ? tc->headers_raw : "");
    msg->headers_raw_len = tc->headers_raw ? strlen(tc->headers_raw) : 0U;
    msg->body            = (uint8_t *)(tc->body ? tc->body : "");
    msg->body_len        = tc->body ? strlen(tc->body) : 0U;
    if (tc->uri) {
        snprintf(msg->uri, sizeof(msg->uri), "%s", tc->uri);
    }
    if (tc->content_type) {
        snprintf(msg->content_type, sizeof(msg->content_type), "%s",
                 tc->content_type);
    }
}

static int run_case(detect_engine_t *det, const detect_case_t *tc) {
    http_message_t       msg;
    detect_match_list_t  matches;
    run_detect_metrics_t metrics;
    uint64_t             detect_us = 0;
    int                  score     = 0;
    int                  rc;

    init_msg(&msg, tc);

    detect_match_list_init(&matches);
    run_detect_metrics_reset();
    rc = run_detect(det, &msg, &score, NULL, 0, NULL, &matches, &detect_us);
    detect_match_list_free(&matches);
    CHECK(rc == 0, "run_detect failed");

    run_detect_metrics_get(&metrics);

    printf("%-20s | total=%2llu | uri=%llu | args_name=%llu | args=%llu | "
           "headers=%llu | body=%llu | score=%d\n",
           tc->label, (unsigned long long)metrics.total_collect_calls,
           (unsigned long long)metrics.uri_calls,
           (unsigned long long)metrics.args_names_calls,
           (unsigned long long)metrics.args_calls,
           (unsigned long long)metrics.headers_calls,
           (unsigned long long)metrics.body_calls, score);

    return 0;
}

int main(void) {
    static const char common_headers[] =
        "Host: example.com\r\n"
        "User-Agent: detect-test\r\n";
    static const char form_headers[] =
        "Host: example.com\r\n"
        "User-Agent: detect-test\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n";
    static const detect_case_t cases[] = {
        {"uri only", "/t", common_headers, NULL, NULL},
        {"query 1 pair", "/t?a=1", common_headers, NULL, NULL},
        {"query 2 pairs", "/t?a=1&b=2", common_headers, NULL, NULL},
        {"query 3 pairs", "/t?a=1&b=2&c=3", common_headers, NULL, NULL},
        {"query names only", "/t?a&b&c", common_headers, NULL, NULL},
        {"query mixed", "/t?a=1&b&c=3", common_headers, NULL, NULL},
        {"form 1 pair", "/submit", form_headers,
         "application/x-www-form-urlencoded", "a=1"},
        {"form 3 pairs", "/submit", form_headers,
         "application/x-www-form-urlencoded", "a=1&b=2&c=3"},
        {"form names only", "/submit", form_headers,
         "application/x-www-form-urlencoded", "a&b&c"},
        {"query+form 3+3", "/submit?a=1&b=2&c=3", form_headers,
         "application/x-www-form-urlencoded", "x=7&y=8&z=9"},
    };

    detect_engine_t *det;
    size_t           i;

    CHECK(setenv("IPS_RULES_FILE", TEST_RULES_PATH, 1) == 0,
          "setenv IPS_RULES_FILE failed");

    det = detect_engine_create("ALL", DETECT_JIT_AUTO);
    CHECK(det != NULL, "detect_engine_create failed");

    printf("case                 | total | uri | args_name | args | headers | "
           "body | score\n");
    printf("----------------------------------------------------------------"
           "-----------\n");

    for (i = 0; i < (sizeof(cases) / sizeof(cases[0])); i++) {
        CHECK(run_case(det, &cases[i]) == 0, "case execution failed");
    }

    detect_engine_destroy(det);
    return 0;
}

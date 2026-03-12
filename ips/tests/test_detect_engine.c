#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "logging.h"
#include "detect.h"
#include "engine.h"
#include "http_stream.h"
#include "regex.h"

#define TEST_RULES_PATH "rules/generated/rules.jsonl"
#define TEST_URI_LEN 900U
#define TEST_ITERATIONS 100U
#define ERRBUF_SIZE 256U

static const size_t g_uri_sizes[] = {
    900U,
    1800U,
    3600U,
    7200U,
    131072U
};

static int alloc_copy(uint8_t **dst, size_t *dst_len, const char *src)
{
    size_t len;

    if (dst == NULL || dst_len == NULL || src == NULL) {
        return -1;
    }

    len = strlen(src);
    *dst = (uint8_t *)malloc(len + 1U);
    if (*dst == NULL) {
        return -1;
    }

    memcpy(*dst, src, len + 1U);
    *dst_len = len;
    return 0;
}

static int build_test_uri(char *uri, size_t uri_size, size_t target_len)
{
    const char *prefix = "/bench?x=";
    const char *payload = "%27%20union%20select%201,2,3%20from%20dual--";
    size_t prefix_len;
    size_t payload_len;
    size_t pad_len;

    if (uri == NULL || uri_size <= target_len) {
        return -1;
    }

    prefix_len = strlen(prefix);
    payload_len = strlen(payload);
    if (prefix_len + payload_len > target_len) {
        return -1;
    }

    pad_len = target_len - prefix_len - payload_len;
    memcpy(uri, prefix, prefix_len);
    memset(uri + prefix_len, 'A', pad_len);
    memcpy(uri + prefix_len + pad_len, payload, payload_len);
    uri[target_len] = '\0';
    return 0;
}

static int prepare_message(http_message_t *msg, size_t uri_len)
{
    const char *headers = "Host: localhost\r\n"
                          "User-Agent: detect-engine-test\r\n"
                          "Accept: */*\r\n"
                          "X-Attack: ' union select 1,2,3 from dual--\r\n";
    const char *body = "user=admin&mode=normal&payload=%27+union+select+1,2,3+from+dual--";

    if (msg == NULL) {
        return -1;
    }

    memset(msg, 0, sizeof(*msg));
    msg->is_request = 1;
    snprintf(msg->method, sizeof(msg->method), "%s", "POST");
    snprintf(msg->version, sizeof(msg->version), "%s", "HTTP/1.1");
    snprintf(msg->content_type, sizeof(msg->content_type),
             "%s", "application/x-www-form-urlencoded");
    if (build_test_uri(msg->uri, sizeof(msg->uri), uri_len) != 0) {
        return -1;
    }

    if (alloc_copy(&msg->headers_raw, &msg->headers_raw_len, headers) != 0) {
        return -1;
    }
    if (alloc_copy(&msg->body, &msg->body_len, body) != 0) {
        http_message_free(msg);
        return -1;
    }
    return 0;
}

static int run_backend(const char *backend_name,
                       const http_message_t *msg,
                       unsigned int iterations,
                       size_t uri_len)
{
    char errbuf[ERRBUF_SIZE];
    detect_engine_t *det;
    detect_match_list_t last_matches;
    const IPS_Signature *last_rule = NULL;
    uint64_t total_detect_us = 0;
    unsigned int detected_count = 0;
    unsigned int i;
    int last_rc = 0;
    int last_score = 0;

    memset(errbuf, 0, sizeof(errbuf));
    detect_match_list_init(&last_matches);

    if (engine_set_backend_name(backend_name, errbuf, sizeof(errbuf)) != 0) {
        fprintf(stderr, "engine_set_backend_name(%s) failed: %s\n",
                backend_name, errbuf);
        return -1;
    }

    det = detect_engine_create("ALL", DETECT_JIT_AUTO);
    if (det == NULL) {
        fprintf(stderr, "detect_engine_create(%s) failed\n", backend_name);
        return -1;
    }

    for (i = 0; i < iterations; i++) {
        detect_match_list_t matches;
        uint64_t detect_us = 0;

        detect_match_list_init(&matches);
        last_rule = NULL;
        last_score = 0;

        last_rc = run_detect(det,
                             msg,
                             &last_score,
                             &last_rule,
                             &matches,
                             &detect_us);
        if (last_rc < 0) {
            fprintf(stderr, "run_detect(%s) failed at iter %u: %s\n",
                    backend_name, i, detect_engine_last_error(det));
            detect_match_list_free(&matches);
            detect_match_list_free(&last_matches);
            detect_engine_destroy(det);
            return -1;
        }

        total_detect_us += detect_us;
        if (last_rc > 0) {
            detected_count++;
        }

        detect_match_list_free(&last_matches);
        last_matches = matches;
    }

    printf("%s uri=%zu score=%d matched_rule=%s detect_avg_ms=%.6f detected=%u/%u\n",
           backend_name,
           uri_len,
           last_score,
           last_rule != NULL ? last_rule->policy_name : "-",
           ((double)total_detect_us / (double)iterations) / 1000.0,
           detected_count,
           iterations);

    detect_match_list_free(&last_matches);
    detect_engine_destroy(det);
    return 0;
}

int main(int argc, char **argv)
{
    unsigned int iterations = TEST_ITERATIONS;
    size_t i;

    if (argc > 1) {
        iterations = (unsigned int)strtoul(argv[1], NULL, 10);
        if (iterations == 0U) {
            fprintf(stderr, "invalid iterations: %s\n", argv[1]);
            return 1;
        }
    }

    if (regex_load_signatures(TEST_RULES_PATH) != 0) {
        fprintf(stderr, "regex_load_signatures failed: %s\n", TEST_RULES_PATH);
        return 1;
    }

    printf("rules: %s\n", TEST_RULES_PATH);
    printf("iterations: %u\n", iterations);

    for (i = 0; i < sizeof(g_uri_sizes) / sizeof(g_uri_sizes[0]); i++) {
        http_message_t msg;
        size_t uri_len = g_uri_sizes[i];

        if (prepare_message(&msg, uri_len) != 0) {
            fprintf(stderr, "prepare_message failed: uri=%zu\n", uri_len);
            return 1;
        }

        if (run_backend("pcre2", &msg, iterations, uri_len) != 0) {
            http_message_free(&msg);
            return 1;
        }

        if (run_backend("hs", &msg, iterations, uri_len) != 0) {
            http_message_free(&msg);
            return 1;
        }

        http_message_free(&msg);
    }

    return 0;
}

#include "logging.h"

#include "detect.h"
#include "http_parser.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int mini_ips_debug_flow_cached = -1;
static FILE *mini_ips_detect_log_fp = NULL;
static FILE *mini_ips_detect_time_log_fp = NULL;
static FILE *mini_ips_response_log_fp = NULL;
static pthread_mutex_t mini_ips_detect_log_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mini_ips_detect_time_log_lock =
    PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mini_ips_response_log_lock = PTHREAD_MUTEX_INITIALIZER;

static FILE *mini_ips_detect_log_file(void) {
    const char *path;

    if (NULL != mini_ips_detect_log_fp) {
        return mini_ips_detect_log_fp;
    }

    path = getenv("MINI_IPS_DETECT_LOG_FILE");
    if (NULL == path || '\0' == path[0]) {
        return NULL;
    }

    mini_ips_detect_log_fp = fopen(path, "a");
    if (NULL != mini_ips_detect_log_fp) {
        setvbuf(mini_ips_detect_log_fp, NULL, _IOLBF, 0);
    }

    return mini_ips_detect_log_fp;
}

static FILE *mini_ips_response_log_file(void) {
    const char *path;

    if (NULL != mini_ips_response_log_fp) {
        return mini_ips_response_log_fp;
    }

    path = getenv("MINI_IPS_RESPONSE_LOG_FILE");
    if (NULL == path || '\0' == path[0]) {
        return NULL;
    }

    mini_ips_response_log_fp = fopen(path, "a");
    if (NULL != mini_ips_response_log_fp) {
        setvbuf(mini_ips_response_log_fp, NULL, _IOLBF, 0);
    }

    return mini_ips_response_log_fp;
}

static FILE *mini_ips_detect_time_log_file(void) {
    const char *path;

    if (NULL != mini_ips_detect_time_log_fp) {
        return mini_ips_detect_time_log_fp;
    }

    path = getenv("MINI_IPS_DETECT_TIME_LOG_FILE");
    if (NULL == path || '\0' == path[0]) {
        return NULL;
    }

    mini_ips_detect_time_log_fp = fopen(path, "a");
    if (NULL != mini_ips_detect_time_log_fp) {
        setvbuf(mini_ips_detect_time_log_fp, NULL, _IOLBF, 0);
    }

    return mini_ips_detect_time_log_fp;
}

static void mini_ips_detect_log_timestamp(char *buf, size_t buf_sz) {
    time_t now;
    struct tm tm_now;

    if (NULL == buf || 0U == buf_sz) {
        return;
    }

    now = time(NULL);
    memset(&tm_now, 0, sizeof(tm_now));
    if (0 == gmtime_r(&now, &tm_now)) {
        snprintf(buf, buf_sz, "1970-01-01T00:00:00Z");
        return;
    }

    strftime(buf, buf_sz, "%Y-%m-%dT%H:%M:%SZ", &tm_now);
}

int mini_ips_debug_flow_enabled(void) {
    const char *env;

    if (mini_ips_debug_flow_cached >= 0) {
        return mini_ips_debug_flow_cached;
    }

    env = getenv("MINI_IPS_DEBUG_FLOW");
    if (NULL != env && '\0' != env[0] && 0 != strcmp(env, "0")) {
        mini_ips_debug_flow_cached = 1;
    } else {
        mini_ips_debug_flow_cached = 0;
    }

    return mini_ips_debug_flow_cached;
}

void mini_ips_log_errno(const char *scope, const char *detail, int errnum) {
    (void)scope;
    (void)detail;
    (void)errnum;
}

void mini_ips_log_message(const char *scope, const char *detail) {
    (void)scope;
    (void)detail;
}

void mini_ips_log_parser_incomplete(uint32_t session_id, size_t raw_len,
                                    size_t reasm_len) {
    (void)session_id;
    (void)raw_len;
    (void)reasm_len;
}

void mini_ips_log_detect_result(uint32_t session_id,
                                const detect_result_t *result, int blocked,
                                const char *reason) {
    FILE *fp;
    char ts[32];

    if (NULL == result) {
        return;
    }

    fp = mini_ips_detect_log_file();
    if (NULL == fp) {
        return;
    }

    mini_ips_detect_log_timestamp(ts, sizeof(ts));

    pthread_mutex_lock(&mini_ips_detect_log_lock);
    fprintf(fp,
            "ts=%s session_id=%u matched=%d blocked=%d total_score=%d total_matches=%zu "
            "sqli=%d/%d dir=%d/%d rce=%d/%d xss=%d/%d reason=\"%s\"\n",
            ts, session_id, result->matched, blocked, result->total_score,
            result->total_matches, result->matched_sqli, result->sqli_score,
            result->matched_directory_traversal,
            result->directory_traversal_score, result->matched_rce,
            result->rce_score, result->matched_xss, result->xss_score,
            NULL != reason ? reason : "");
    fflush(fp);
    pthread_mutex_unlock(&mini_ips_detect_log_lock);
}

void mini_ips_log_detect_time(uint32_t session_id, uint64_t detect_us,
                              long detect_ms, size_t request_len) {
    FILE *fp;
    char ts[32];

    fp = mini_ips_detect_time_log_file();
    if (NULL == fp) {
        return;
    }

    mini_ips_detect_log_timestamp(ts, sizeof(ts));

    pthread_mutex_lock(&mini_ips_detect_time_log_lock);
    fprintf(fp,
            "ts=%s session_id=%u detect_us=%llu detect_ms=%ld request_len=%zu\n",
            ts, session_id, (unsigned long long)detect_us, detect_ms,
            request_len);
    fflush(fp);
    pthread_mutex_unlock(&mini_ips_detect_time_log_lock);
}

void mini_ips_log_allow_message(uint32_t session_id,
                                const http_message_t *msg) {
    (void)session_id;
    (void)msg;
}

void mini_ips_log_response_to_client(uint32_t session_id, const char *kind,
                                     size_t len, const char *detail) {
    FILE *fp;
    char ts[32];

    fp = mini_ips_response_log_file();
    if (NULL == fp) {
        return;
    }

    mini_ips_detect_log_timestamp(ts, sizeof(ts));

    pthread_mutex_lock(&mini_ips_response_log_lock);
    fprintf(fp,
            "ts=%s event=response_to_client session_id=%u kind=%s len=%zu detail=\"%s\"\n",
            ts, session_id, NULL != kind ? kind : "", len,
            NULL != detail ? detail : "");
    fflush(fp);
    pthread_mutex_unlock(&mini_ips_response_log_lock);
}

void mini_ips_log_debug_flow(uint32_t session_id, int step,
                             const char *detail) {
    (void)session_id;
    (void)step;
    (void)detail;
}

void mini_ips_log_debug_flowf(uint32_t session_id, int step,
                              const char *fmt, ...) {
    (void)session_id;
    (void)step;
    (void)fmt;
}

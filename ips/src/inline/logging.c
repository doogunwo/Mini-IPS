#include "logging.h"

#include "detect.h"
#include "engine.h"
#include "http_parser.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

static int mini_ips_debug_flow_cached = -1;

static FILE *mini_ips_log_fp = NULL;
static FILE *mini_ips_monitor_log_fp = NULL;
static FILE *mini_ips_detect_log_fp = NULL;
static FILE *mini_ips_detect_time_log_fp = NULL;
static FILE *mini_ips_response_log_fp = NULL;

static pthread_mutex_t mini_ips_log_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mini_ips_monitor_log_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mini_ips_detect_log_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mini_ips_detect_time_log_lock =
    PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mini_ips_response_log_lock = PTHREAD_MUTEX_INITIALIZER;

static atomic_uint_fast64_t mini_ips_event_seq = 1U;
static atomic_uint_fast64_t mini_ips_packet_count = 0U;
static atomic_uint_fast64_t mini_ips_req_count = 0U;
static atomic_uint_fast64_t mini_ips_detect_count = 0U;
static atomic_uint_fast64_t mini_ips_monitor_last_emit_ms = 0U;

static uint64_t mini_ips_monitor_prev_packets = 0U;
static uint64_t mini_ips_monitor_prev_reqs = 0U;
static uint64_t mini_ips_monitor_prev_detects = 0U;

static void make_log_timestamp(char *out, size_t out_sz) {
    struct timespec ts;
    struct tm       tm_now;
    int             ms;
    size_t          n;

    if (NULL == out || 0U == out_sz) {
        return;
    }

    if (0 != clock_gettime(CLOCK_REALTIME, &ts)) {
        snprintf(out, out_sz, "1970-01-01T00:00:00.000");
        return;
    }

    localtime_r(&ts.tv_sec, &tm_now);
    ms = (int)(ts.tv_nsec / 1000000L);
    n = strftime(out, out_sz, "%Y-%m-%dT%H:%M:%S", &tm_now);
    if (0U == n || n + 6U >= out_sz) {
        snprintf(out, out_sz, "1970-01-01T00:00:00.000");
        return;
    }

    snprintf(out + n, out_sz - n, ".%03d", ms);
}

static uint64_t monotonic_ms_now(void) {
    struct timespec ts;

    if (0 != clock_gettime(CLOCK_MONOTONIC, &ts)) {
        return 0U;
    }

    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

static void write_log_line_locked(FILE *fp, const char *ts, const char *level,
                                  const char *body) {
    if (NULL == fp || NULL == ts || NULL == level || NULL == body) {
        return;
    }

    fprintf(fp, "ts=%s level=%s %s\n", ts, level, body);
    fflush(fp);
}

static int ensure_parent_dir(const char *path) {
    char dir_path[256];
    char *slash;
    int   ret;

    if (NULL == path || '\0' == path[0]) {
        return -1;
    }

    snprintf(dir_path, sizeof(dir_path), "%s", path);
    slash = strrchr(dir_path, '/');
    if (NULL == slash) {
        ret = mkdir(".", 0755);
        if (0 != ret && EEXIST != errno) {
            return -1;
        }
        return 0;
    }

    if (slash == dir_path) {
        ret = mkdir("/", 0755);
        if (0 != ret && EEXIST != errno) {
            return -1;
        }
        return 0;
    }

    *slash = '\0';
    ret = mkdir(dir_path, 0755);
    if (0 != ret && EEXIST != errno) {
        return -1;
    }
    return 0;
}

static char *log_escape_dup(const char *s) {
    size_t src_len;
    size_t cap;
    char  *out;
    size_t i;
    size_t j;

    if (NULL == s) {
        s = "";
    }

    src_len = strlen(s);
    cap = (src_len * 4U) + 1U;
    out = (char *)malloc(cap);
    if (NULL == out) {
        return NULL;
    }

    j = 0U;
    for (i = 0U; i < src_len; i++) {
        unsigned char c;

        c = (unsigned char)s[i];
        if ('"' == c || '\\' == c) {
            out[j++] = '\\';
            out[j++] = (char)c;
            continue;
        }
        if ('\n' == c || '\r' == c || '\t' == c) {
            out[j++] = ' ';
            continue;
        }
        if (0 == isprint(c)) {
            int written;

            written = snprintf(out + j, cap - j, "\\x%02X", c);
            if (written < 0) {
                free(out);
                return NULL;
            }
            j += (size_t)written;
            continue;
        }
        out[j++] = (char)c;
    }

    out[j] = '\0';
    return out;
}

static void format_peer(const struct sockaddr_in *peer, char *ip,
                        size_t ip_sz, uint16_t *port) {
    if (NULL != port) {
        *port = 0U;
    }

    if (NULL == ip || 0U == ip_sz) {
        return;
    }

    snprintf(ip, ip_sz, "unknown");
    if (NULL == peer) {
        return;
    }

    if (NULL == inet_ntop(AF_INET, &peer->sin_addr, ip, ip_sz)) {
        snprintf(ip, ip_sz, "unknown");
    }
    if (NULL != port) {
        *port = ntohs(peer->sin_port);
    }
}

static int open_file_line_buffered(FILE **slot, const char *path,
                                   const char *mode) {
    FILE *fp;

    if (NULL == slot || NULL == path || '\0' == path[0] || NULL == mode) {
        return -1;
    }

    if (0 != ensure_parent_dir(path)) {
        return -1;
    }

    fp = fopen(path, mode);
    if (NULL == fp) {
        return -1;
    }
    setvbuf(fp, NULL, _IOLBF, 0);
    *slot = fp;
    return 0;
}

static FILE *mini_ips_log_file(void) {
    return mini_ips_log_fp;
}

static FILE *mini_ips_monitor_log_file(void) {
    return mini_ips_monitor_log_fp;
}

static FILE *mini_ips_detect_log_file(void) {
    return mini_ips_detect_log_fp;
}

static FILE *mini_ips_response_log_file(void) {
    return mini_ips_response_log_fp;
}

static FILE *mini_ips_detect_time_log_file(void) {
    return mini_ips_detect_time_log_fp;
}

static void mini_ips_detect_log_timestamp(char *buf, size_t buf_sz) {
    make_log_timestamp(buf, buf_sz);
}

static int mini_ips_make_event_id(char *out, size_t out_sz) {
    uint64_t seq;

    if (NULL == out || 0U == out_sz) {
        return -1;
    }

    seq = atomic_fetch_add_explicit(&mini_ips_event_seq, 1U,
                                    memory_order_relaxed);
    snprintf(out, out_sz, "inline-%llu", (unsigned long long)seq);
    return 0;
}

static const detect_match_info_t *pick_match_info(const detect_result_t *result,
                                                  const char **attack_name) {
    if (NULL != attack_name) {
        *attack_name = "unknown";
    }

    if (NULL == result) {
        return NULL;
    }

    if (result->matched_rce) {
        if (NULL != attack_name) {
            *attack_name = "rce";
        }
        return &result->rce_info;
    }
    if (result->matched_sqli) {
        if (NULL != attack_name) {
            *attack_name = "sqli";
        }
        return &result->sqli_info;
    }
    if (result->matched_xss) {
        if (NULL != attack_name) {
            *attack_name = "xss";
        }
        return &result->xss_info;
    }
    if (result->matched_directory_traversal) {
        if (NULL != attack_name) {
            *attack_name = "directory_traversal";
        }
        return &result->directory_traversal_info;
    }

    return NULL;
}

int mini_ips_log_open(void) {
    const char *path;

    if (NULL == mini_ips_log_fp) {
        path = getenv("LOG_FILE");
        if (NULL == path || '\0' == path[0]) {
            path = "logs/ips.log";
        }
        if (0 != open_file_line_buffered(&mini_ips_log_fp, path, "a")) {
            return -1;
        }
    }

    if (NULL == mini_ips_monitor_log_fp) {
        path = getenv("MONITOR_LOG_FILE");
        if (NULL == path || '\0' == path[0]) {
            path = "logs/monitor.log";
        }
        if (0 != open_file_line_buffered(&mini_ips_monitor_log_fp, path, "w")) {
            return -1;
        }
    }

    if (NULL == mini_ips_detect_log_fp) {
        path = getenv("MINI_IPS_DETECT_LOG_FILE");
        if (NULL != path && '\0' != path[0]) {
            if (0 != open_file_line_buffered(&mini_ips_detect_log_fp, path, "a")) {
                return -1;
            }
        }
    }

    if (NULL == mini_ips_detect_time_log_fp) {
        path = getenv("MINI_IPS_DETECT_TIME_LOG_FILE");
        if (NULL != path && '\0' != path[0]) {
            if (0 != open_file_line_buffered(&mini_ips_detect_time_log_fp,
                                             path, "a")) {
                return -1;
            }
        }
    }

    if (NULL == mini_ips_response_log_fp) {
        path = getenv("MINI_IPS_RESPONSE_LOG_FILE");
        if (NULL != path && '\0' != path[0]) {
            if (0 != open_file_line_buffered(&mini_ips_response_log_fp, path,
                                             "a")) {
                return -1;
            }
        }
    }

    return 0;
}

void mini_ips_log_close(void) {
    if (NULL != mini_ips_log_fp) {
        fclose(mini_ips_log_fp);
        mini_ips_log_fp = NULL;
    }
    if (NULL != mini_ips_monitor_log_fp) {
        fclose(mini_ips_monitor_log_fp);
        mini_ips_monitor_log_fp = NULL;
    }
    if (NULL != mini_ips_detect_log_fp) {
        fclose(mini_ips_detect_log_fp);
        mini_ips_detect_log_fp = NULL;
    }
    if (NULL != mini_ips_detect_time_log_fp) {
        fclose(mini_ips_detect_time_log_fp);
        mini_ips_detect_time_log_fp = NULL;
    }
    if (NULL != mini_ips_response_log_fp) {
        fclose(mini_ips_response_log_fp);
        mini_ips_response_log_fp = NULL;
    }
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
    FILE *fp;
    char ts[40];
    char body[1024];
    char *detail_esc;

    if (0 != mini_ips_log_open()) {
        return;
    }

    fp = mini_ips_log_file();
    if (NULL == fp) {
        return;
    }

    detail_esc = log_escape_dup(detail);
    if (NULL == detail_esc) {
        return;
    }

    make_log_timestamp(ts, sizeof(ts));
    snprintf(body, sizeof(body),
             "event=runtime_error scope=%s detail=\"%s\" errno=%d error=\"%s\"",
             NULL != scope ? scope : "unknown", detail_esc, errnum,
             strerror(errnum));

    pthread_mutex_lock(&mini_ips_log_lock);
    write_log_line_locked(fp, ts, "ERROR", body);
    pthread_mutex_unlock(&mini_ips_log_lock);
    free(detail_esc);
}

void mini_ips_log_message(const char *scope, const char *detail) {
    FILE *fp;
    char ts[40];
    char body[1024];
    char *detail_esc;

    if (0 != mini_ips_log_open()) {
        return;
    }

    fp = mini_ips_log_file();
    if (NULL == fp) {
        return;
    }

    detail_esc = log_escape_dup(detail);
    if (NULL == detail_esc) {
        return;
    }

    make_log_timestamp(ts, sizeof(ts));
    snprintf(body, sizeof(body), "event=runtime_info scope=%s detail=\"%s\"",
             NULL != scope ? scope : "unknown", detail_esc);

    pthread_mutex_lock(&mini_ips_log_lock);
    write_log_line_locked(fp, ts, "INFO", body);
    pthread_mutex_unlock(&mini_ips_log_lock);
    free(detail_esc);
}

void mini_ips_log_parser_incomplete(uint32_t session_id, size_t raw_len,
                                    size_t reasm_len) {
    FILE *fp;
    char ts[40];
    char body[256];

    if (0 != mini_ips_log_open()) {
        return;
    }

    fp = mini_ips_log_file();
    if (NULL == fp || !mini_ips_debug_flow_enabled()) {
        return;
    }

    make_log_timestamp(ts, sizeof(ts));
    snprintf(body, sizeof(body),
             "event=parser_incomplete session_id=%u raw_len=%zu reasm_len=%zu",
             session_id, raw_len, reasm_len);

    pthread_mutex_lock(&mini_ips_log_lock);
    write_log_line_locked(fp, ts, "INFO", body);
    pthread_mutex_unlock(&mini_ips_log_lock);
}

void mini_ips_log_detect_result(uint32_t session_id,
                                const detect_result_t *result,
                                const struct sockaddr_in *peer, int blocked,
                                const char *reason, uint64_t detect_us,
                                long detect_ms) {
    FILE                      *fp;
    FILE                      *detect_fp;
    char                       ts[40];
    char                       event_id[64];
    char                       ip[INET_ADDRSTRLEN];
    uint16_t                   port;
    const detect_match_info_t *info;
    const char                *attack;
    char                      *reason_esc;
    char                      *rule_esc;
    char                      *text_esc;

    if (NULL == result) {
        return;
    }

    if (0 != mini_ips_log_open()) {
        return;
    }

    detect_fp = mini_ips_detect_log_file();
    if (NULL != detect_fp) {
        mini_ips_detect_log_timestamp(ts, sizeof(ts));

        pthread_mutex_lock(&mini_ips_detect_log_lock);
        fprintf(detect_fp,
                "ts=%s session_id=%u matched=%d blocked=%d total_score=%d total_matches=%zu "
                "sqli=%d/%d dir=%d/%d rce=%d/%d xss=%d/%d reason=\"%s\"\n",
                ts, session_id, result->matched, blocked, result->total_score,
                result->total_matches, result->matched_sqli, result->sqli_score,
                result->matched_directory_traversal,
                result->directory_traversal_score, result->matched_rce,
                result->rce_score, result->matched_xss, result->xss_score,
                NULL != reason ? reason : "");
        fflush(detect_fp);
        pthread_mutex_unlock(&mini_ips_detect_log_lock);
    }

    if (!blocked || !result->matched) {
        return;
    }

    fp = mini_ips_log_file();
    if (NULL == fp) {
        return;
    }

    info = pick_match_info(result, &attack);
    format_peer(peer, ip, sizeof(ip), &port);
    mini_ips_make_event_id(event_id, sizeof(event_id));
    make_log_timestamp(ts, sizeof(ts));

    reason_esc = log_escape_dup(NULL != reason ? reason : "");
    rule_esc = log_escape_dup((NULL != info) ? info->pattern : "");
    text_esc = log_escape_dup((NULL != info) ? info->text : "");
    if (NULL == reason_esc || NULL == rule_esc || NULL == text_esc) {
        free(reason_esc);
        free(rule_esc);
        free(text_esc);
        return;
    }

    pthread_mutex_lock(&mini_ips_log_lock);
    fprintf(fp,
            "ts=%s level=WARN event=detect event_id=%s attack=%s where=request "
            "src_ip=%s src_port=%u score=%d threshold=%d match_count=%zu "
            "matched=\"%s\" matched_rules=\"%s\" matched_texts=\"%s\" "
            "detect_us=%llu detect_ms=%ld detail=\"%s\"\n",
            ts, event_id, attack, ip, (unsigned int)port, result->total_score,
            1, result->total_matches, rule_esc, rule_esc, text_esc,
            (unsigned long long)detect_us, detect_ms, reason_esc);
    fflush(fp);
    pthread_mutex_unlock(&mini_ips_log_lock);

    atomic_fetch_add_explicit(&mini_ips_detect_count, 1U, memory_order_relaxed);
    free(reason_esc);
    free(rule_esc);
    free(text_esc);
}

void mini_ips_log_detect_time(uint32_t session_id, uint64_t detect_us,
                              long detect_ms, size_t request_len) {
    FILE *fp;
    char ts[40];

    if (0 != mini_ips_log_open()) {
        return;
    }

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

void mini_ips_log_allow_message(uint32_t session_id, const http_message_t *msg) {
    FILE *fp;
    char ts[40];
    char *method_esc;
    char *uri_esc;

    if (NULL == msg) {
        return;
    }

    if (0 != mini_ips_log_open()) {
        return;
    }

    fp = mini_ips_log_file();
    if (NULL == fp) {
        return;
    }

    method_esc = log_escape_dup(NULL != msg->method ? msg->method : "");
    uri_esc = log_escape_dup(NULL != msg->uri ? msg->uri : "");
    if (NULL == method_esc || NULL == uri_esc) {
        free(method_esc);
        free(uri_esc);
        return;
    }

    make_log_timestamp(ts, sizeof(ts));
    pthread_mutex_lock(&mini_ips_log_lock);
    fprintf(fp,
            "ts=%s level=INFO event=http_pass session_id=%u method=\"%s\" uri=\"%s\"\n",
            ts, session_id, method_esc, uri_esc);
    fflush(fp);
    pthread_mutex_unlock(&mini_ips_log_lock);

    free(method_esc);
    free(uri_esc);
}

void mini_ips_log_response_to_client(uint32_t session_id,
                                     const struct sockaddr_in *peer,
                                     const char *kind, size_t len,
                                     const char *detail) {
    FILE *fp;
    FILE *main_fp;
    char ts[40];
    char ip[INET_ADDRSTRLEN];
    uint16_t port;
    char *detail_esc;

    if (0 != mini_ips_log_open()) {
        return;
    }

    detail_esc = log_escape_dup(detail);
    if (NULL == detail_esc) {
        return;
    }

    fp = mini_ips_response_log_file();
    if (NULL != fp) {
        mini_ips_detect_log_timestamp(ts, sizeof(ts));

        pthread_mutex_lock(&mini_ips_response_log_lock);
        fprintf(fp,
                "ts=%s event=response_to_client session_id=%u kind=%s len=%zu detail=\"%s\"\n",
                ts, session_id, NULL != kind ? kind : "", len, detail_esc);
        fflush(fp);
        pthread_mutex_unlock(&mini_ips_response_log_lock);
    }

    main_fp = mini_ips_log_file();
    if (NULL != main_fp && NULL != kind && 0 == strcmp(kind, "block_403")) {
        make_log_timestamp(ts, sizeof(ts));
        format_peer(peer, ip, sizeof(ip), &port);
        pthread_mutex_lock(&mini_ips_log_lock);
        fprintf(main_fp,
                "ts=%s level=WARN event=block_page_send action=inline_403 "
                "src_ip=%s src_port=%u detail=\"%s\" session_id=%u response_len=%zu\n",
                ts, ip, (unsigned int)port, detail_esc, session_id, len);
        fflush(main_fp);
        pthread_mutex_unlock(&mini_ips_log_lock);
    }

    free(detail_esc);
}

void mini_ips_log_note_packet(void) {
    atomic_fetch_add_explicit(&mini_ips_packet_count, 1U, memory_order_relaxed);
}

void mini_ips_log_note_request(void) {
    atomic_fetch_add_explicit(&mini_ips_req_count, 1U, memory_order_relaxed);
}

void mini_ips_log_emit_monitor(size_t queue_depth) {
    uint64_t      ts_ms;
    uint64_t      last_emit_ms;
    uint64_t      expected;
    uint64_t      interval_ms;
    uint64_t      packets;
    uint64_t      reqs;
    uint64_t      detects;
    uint64_t      pps;
    uint64_t      req_ps;
    uint64_t      detect_ps;
    FILE         *fp;
    char          ts[40];

    if (0 != mini_ips_log_open()) {
        return;
    }

    fp = mini_ips_monitor_log_file();
    if (NULL == fp) {
        return;
    }

    ts_ms = monotonic_ms_now();
    last_emit_ms = atomic_load_explicit(&mini_ips_monitor_last_emit_ms,
                                        memory_order_relaxed);
    if (0U != last_emit_ms && 1000ULL > (ts_ms - last_emit_ms)) {
        return;
    }

    expected = last_emit_ms;
    if (!atomic_compare_exchange_strong_explicit(
            &mini_ips_monitor_last_emit_ms, &expected, ts_ms,
            memory_order_relaxed, memory_order_relaxed)) {
        return;
    }

    interval_ms = (0U != last_emit_ms && ts_ms > last_emit_ms)
                      ? (ts_ms - last_emit_ms)
                      : 1000ULL;

    packets = atomic_load_explicit(&mini_ips_packet_count, memory_order_relaxed);
    reqs = atomic_load_explicit(&mini_ips_req_count, memory_order_relaxed);
    detects = atomic_load_explicit(&mini_ips_detect_count, memory_order_relaxed);

    pps = ((packets - mini_ips_monitor_prev_packets) * 1000ULL) / interval_ms;
    req_ps = ((reqs - mini_ips_monitor_prev_reqs) * 1000ULL) / interval_ms;
    detect_ps =
        ((detects - mini_ips_monitor_prev_detects) * 1000ULL) / interval_ms;

    pthread_mutex_lock(&mini_ips_monitor_log_lock);
    make_log_timestamp(ts, sizeof(ts));
    fprintf(fp,
            "ts=%s level=INFO event=stats interval_ms=%llu worker_count=1 "
            "pps=%llu req_ps=%llu detect_ps=%llu queue_depth=%zu "
            "reasm_in_order_ps=0 reasm_out_of_order_ps=0 reasm_trimmed_ps=0 "
            "total_packets=%llu total_reqs=%llu total_detect=%llu "
            "total_reasm_in_order=0 total_reasm_out_of_order=0 "
            "total_reasm_trimmed=0\n",
            ts, (unsigned long long)interval_ms, (unsigned long long)pps,
            (unsigned long long)req_ps, (unsigned long long)detect_ps,
            queue_depth, (unsigned long long)packets, (unsigned long long)reqs,
            (unsigned long long)detects);
    fflush(fp);
    pthread_mutex_unlock(&mini_ips_monitor_log_lock);

    mini_ips_monitor_prev_packets = packets;
    mini_ips_monitor_prev_reqs = reqs;
    mini_ips_monitor_prev_detects = detects;
}

void mini_ips_log_debug_flow(uint32_t session_id, int step,
                             const char *detail) {
    FILE *fp;
    char ts[40];
    char *detail_esc;

    if (!mini_ips_debug_flow_enabled()) {
        return;
    }

    if (0 != mini_ips_log_open()) {
        return;
    }

    fp = mini_ips_log_file();
    if (NULL == fp) {
        return;
    }

    detail_esc = log_escape_dup(detail);
    if (NULL == detail_esc) {
        return;
    }

    make_log_timestamp(ts, sizeof(ts));
    pthread_mutex_lock(&mini_ips_log_lock);
    fprintf(fp,
            "ts=%s level=INFO event=debug_flow session_id=%u step=%d detail=\"%s\"\n",
            ts, session_id, step, detail_esc);
    fflush(fp);
    pthread_mutex_unlock(&mini_ips_log_lock);
    free(detail_esc);
}

void mini_ips_log_debug_flowf(uint32_t session_id, int step,
                              const char *fmt, ...) {
    va_list ap;
    char    buf[1024];

    if (NULL == fmt) {
        return;
    }

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    mini_ips_log_debug_flow(session_id, step, buf);
}

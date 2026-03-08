/**
 * @mainpage 첫 페이지
 * @section intro 소개
 * libpcap 기반 IDS 프로그램 with RST 패킷 공격 
 * @section developer 개발자
 * 도건우 (gunwoo.do@monitorapp.com)
 * @section history 역사
 * 이 프로젝트는 2026년 2월 시작되었다.
 */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <stdatomic.h>
#include <ctype.h>
#include "net_compat.h"
#include "detect.h"
#include "driver.h"
#include "httgw.h"

#define THREADHOLD 5

typedef struct rst_log_cache
{
    flow_key_t flow;
    httgw_sess_snapshot_t snap;
    uint64_t expires_ms;
    int valid;
} rst_log_cache_t;

typedef struct app_shared
{
    FILE *log_fp;
    char log_path[256];
    pthread_mutex_t log_mu;
    int pass_log_enabled;
    int debug_log_enabled;
    atomic_uint_fast64_t http_msgs;
    atomic_uint_fast64_t reqs;
    atomic_uint_fast64_t resps;
    atomic_uint_fast64_t reasm_errs;
    atomic_uint_fast64_t parse_errs;
} app_shared_t;

typedef struct app_ctx
{
    httgw_t *gw;
    detect_engine_t *det;
    httgw_mode_t mode;
    tx_ctx_t rst_tx;
    app_shared_t *shared;
    rst_log_cache_t rst_cache;
} app_ctx_t;

static volatile sig_atomic_t g_stop = 0;
static void ip4_to_str(uint32_t ip, char *out, size_t out_sz);
static int env_flag_enabled(const char *name, int default_value);
static const char *ctx_name(ips_context_t ctx);

typedef struct
{
    char *buf;
    size_t len;
    size_t cap;
} strbuf_t;

/**
 * @brief 현재 시각을 로그 출력용 문자열로 변환한다.
 * @param out 결과 문자열 버퍼
 * @param out_sz 버퍼 크기
 */
static void make_log_timestamp(char *out, size_t out_sz)
{
    struct timespec ts;
    struct tm tm_now;
    int ms;
    size_t n;

    if (!out || out_sz == 0)
        return;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
    {
        snprintf(out, out_sz, "1970-01-01T00:00:00.000Z");
        return;
    }

    gmtime_r(&ts.tv_sec, &tm_now);
    ms = (int)(ts.tv_nsec / 1000000L);
    n = strftime(out, out_sz, "%Y-%m-%dT%H:%M:%S", &tm_now);
    if (n == 0 || n + 6 >= out_sz)
    {
        snprintf(out, out_sz, "1970-01-01T00:00:00.000Z");
        return;
    }
    snprintf(out + n, out_sz - n, ".%03dZ", ms);
}

static int env_flag_enabled(const char *name, int default_value)
{
    const char *val;

    if (!name)
        return default_value;

    val = getenv(name);
    if (!val || !*val)
        return default_value;

    if (strcmp(val, "1") == 0 ||
        strcmp(val, "true") == 0 ||
        strcmp(val, "TRUE") == 0 ||
        strcmp(val, "yes") == 0 ||
        strcmp(val, "YES") == 0 ||
        strcmp(val, "on") == 0 ||
        strcmp(val, "ON") == 0)
        return 1;

    if (strcmp(val, "0") == 0 ||
        strcmp(val, "false") == 0 ||
        strcmp(val, "FALSE") == 0 ||
        strcmp(val, "no") == 0 ||
        strcmp(val, "NO") == 0 ||
        strcmp(val, "off") == 0 ||
        strcmp(val, "OFF") == 0)
        return 0;

    return default_value;
}

static void strbuf_free(strbuf_t *sb)
{
    if (!sb)
        return;
    free(sb->buf);
    sb->buf = NULL;
    sb->len = 0;
    sb->cap = 0;
}

static int strbuf_reserve(strbuf_t *sb, size_t need)
{
    char *next;
    size_t next_cap;

    if (!sb)
        return -1;
    if (need <= sb->cap)
        return 0;
    next_cap = sb->cap ? sb->cap : 256U;
    while (next_cap < need)
        next_cap *= 2U;
    next = (char *)realloc(sb->buf, next_cap);
    if (!next)
        return -1;
    sb->buf = next;
    sb->cap = next_cap;
    return 0;
}

static int strbuf_append_char(strbuf_t *sb, char c)
{
    if (strbuf_reserve(sb, sb->len + 2U) != 0)
        return -1;
    sb->buf[sb->len++] = c;
    sb->buf[sb->len] = '\0';
    return 0;
}

static int strbuf_append_str(strbuf_t *sb, const char *s)
{
    size_t n;

    if (!s)
        s = "";
    n = strlen(s);
    if (strbuf_reserve(sb, sb->len + n + 1U) != 0)
        return -1;
    memcpy(sb->buf + sb->len, s, n);
    sb->len += n;
    sb->buf[sb->len] = '\0';
    return 0;
}

static int strbuf_append_escaped(strbuf_t *sb, const char *s)
{
    size_t i;
    unsigned char c;
    char hex[5];

    if (!s)
        return strbuf_append_str(sb, "");

    for (i = 0; s[i] != '\0'; i++)
    {
        c = (unsigned char)s[i];
        if (c == '"' || c == '\\')
        {
            if (strbuf_append_char(sb, '\\') != 0 || strbuf_append_char(sb, (char)c) != 0)
                return -1;
            continue;
        }
        if (c == '\n' || c == '\r' || c == '\t')
        {
            if (strbuf_append_char(sb, ' ') != 0)
                return -1;
            continue;
        }
        if (!isprint(c))
        {
            snprintf(hex, sizeof(hex), "\\x%02X", c);
            if (strbuf_append_str(sb, hex) != 0)
                return -1;
            continue;
        }
        if (strbuf_append_char(sb, (char)c) != 0)
            return -1;
    }
    return 0;
}

static const char *ctx_name(ips_context_t ctx)
{
    switch (ctx)
    {
        case IPS_CTX_REQUEST_URI:
            return "REQUEST_URI";
        case IPS_CTX_ARGS:
            return "ARGS";
        case IPS_CTX_ARGS_NAMES:
            return "ARGS_NAMES";
        case IPS_CTX_REQUEST_HEADERS:
            return "REQUEST_HEADERS";
        case IPS_CTX_REQUEST_BODY:
            return "REQUEST_BODY";
        case IPS_CTX_ALL:
        default:
            return "ALL";
    }
}

static int append_match_strings(const detect_match_list_t *matches, strbuf_t *rules, strbuf_t *texts)
{
    size_t i;

    if (!matches)
        return 0;
    for (i = 0; i < matches->count; i++)
    {
        const detect_match_t *m = &matches->items[i];
        if (i > 0)
        {
            if (strbuf_append_str(rules, "; ") != 0 || strbuf_append_str(texts, "; ") != 0)
                return -1;
        }
        if (strbuf_append_str(rules, ctx_name(m->context)) != 0 ||
            strbuf_append_char(rules, '|') != 0 ||
            strbuf_append_str(rules, (m->rule && m->rule->policy_name) ? m->rule->policy_name : "unknown") != 0 ||
            strbuf_append_char(rules, '|') != 0 ||
            strbuf_append_str(rules, (m->rule && m->rule->pattern) ? m->rule->pattern : "unknown") != 0)
            return -1;
        if (strbuf_append_str(texts, ctx_name(m->context)) != 0 ||
            strbuf_append_char(texts, '|') != 0 ||
            strbuf_append_escaped(texts, m->matched_text ? m->matched_text : "") != 0)
            return -1;
    }
    return 0;
}

/**
 * @brief 로그 디렉터리와 파일을 준비한다.
 * @param app 애플리케이션 컨텍스트
 * @return 성공 시 0, 실패 시 -1
 */
static int app_log_open(app_shared_t *shared)
{
    if (!shared)
        return -1;

    if (mkdir("/logs", 0755) != 0 && errno != EEXIST)
        return -1;

    snprintf(shared->log_path, sizeof(shared->log_path), "/logs/ips.log");
    shared->log_fp = fopen(shared->log_path, "a");
    if (!shared->log_fp)
        return -1;

    pthread_mutex_init(&shared->log_mu, NULL);
    return 0;
}

/**
 * @brief 열린 로그 파일을 정리한다.
 * @param app 애플리케이션 컨텍스트
 */
static void app_log_close(app_shared_t *shared)
{
    if (!shared || !shared->log_fp)
        return;
    fclose(shared->log_fp);
    shared->log_fp = NULL;
    pthread_mutex_destroy(&shared->log_mu);
}

/**
 * @brief 공통 런타임 로그를 파일에 기록한다.
 * @param app 애플리케이션 컨텍스트
 * @param category 로그 분류
 * @param fmt 본문 포맷 문자열
 */
static void app_log_write(app_shared_t *shared, const char *category, const char *fmt, ...)
{
    va_list ap;
    char ts[40];

    if (!shared || !shared->log_fp || !fmt)
        return;

    make_log_timestamp(ts, sizeof(ts));
    pthread_mutex_lock(&shared->log_mu);
    fprintf(shared->log_fp, "ts=%s level=%s ", ts, category ? category : "INFO");

    va_start(ap, fmt);
    vfprintf(shared->log_fp, fmt, ap);
    va_end(ap);

    fputc('\n', shared->log_fp);
    fflush(shared->log_fp);
    pthread_mutex_unlock(&shared->log_mu);
}

/**
 * @brief 공격 탐지 로그를 스타일 규칙에 맞춰 파일에 기록한다.
 * @param app 애플리케이션 컨텍스트
 * @param attack 공격 정책 이름
 * @param where 탐지 위치
 * @param from 요청/응답 출처 정보
 * @param detected 탐지 결과 상태
 * @param ip 대상 IP 문자열
 * @param port 대상 포트
 * @param detect_ms 탐지 소요 시간(ms)
 */
static void app_log_attack(app_shared_t *shared,
                           const char *attack,
                           const char *where,
                           const char *from,
                           const char *detected,
                           const char *matched_rules,
                           const char *matched_texts,
                           const char *ip,
                           uint16_t port,
                           int score,
                           int threshold,
                           size_t match_count,
                           uint64_t detect_us,
                           long detect_ms)
{
    char ts[40];

    if (!shared || !shared->log_fp)
        return;

    make_log_timestamp(ts, sizeof(ts));
    pthread_mutex_lock(&shared->log_mu);
    fprintf(shared->log_fp,
            "ts=%s level=WARN event=detect attack=%s where=%s from=\"%s\" matched=\"%s\" score=%d threshold=%d match_count=%zu matched_rules=\"%s\" matched_texts=\"%s\" src_ip=%s src_port=%u detect_us=%llu detect_ms=%ld\n",
            ts,
            attack ? attack : "unknown",
            where ? where : "unknown",
            from ? from : "unknown",
            detected ? detected : "unknown",
            score,
            threshold,
            match_count,
            matched_rules ? matched_rules : "",
            matched_texts ? matched_texts : "",
            ip ? ip : "unknown",
            (unsigned int)port,
            (unsigned long long)detect_us,
            detect_ms);
    fflush(shared->log_fp);
    pthread_mutex_unlock(&shared->log_mu);
}

/**
 * @brief 단조 시계를 기준으로 현재 시각(us)을 계산한다.
 * @return 현재 시각(us)
 */
static uint64_t monotonic_us(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

static void on_sigint(int signo)
{
    (void)signo;
    g_stop = 1;
}

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int endpoint_cmp(uint32_t a_ip, uint16_t a_port, uint32_t b_ip, uint16_t b_port)
{
    if (a_ip < b_ip)
        return -1;
    if (a_ip > b_ip)
        return 1;
    if (a_port < b_port)
        return -1;
    if (a_port > b_port)
        return 1;
    return 0;
}

static void normalize_flow(
    uint32_t sip, uint16_t sport,
    uint32_t dip, uint16_t dport,
    flow_key_t *key, tcp_dir_t *dir)
{
    int c = endpoint_cmp(sip, sport, dip, dport);
    memset(key, 0, sizeof(*key));
    key->proto = 6;
    if (c <= 0)
    {
        key->src_ip = sip;
        key->src_port = sport;
        key->dst_ip = dip;
        key->dst_port = dport;
        *dir = DIR_AB;
    }
    else
    {
        key->src_ip = dip;
        key->src_port = dport;
        key->dst_ip = sip;
        key->dst_port = sport;
        *dir = DIR_BA;
    }
}

static int parse_flow_dir_and_flags(
    const uint8_t *data,
    uint32_t len,
    flow_key_t *flow,
    tcp_dir_t *dir,
    uint8_t *flags)
{
    const uint8_t *p = data;
    uint32_t n;
    uint16_t eth_type;
    uint32_t ihl;
    uint16_t total_len;
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;

    if (!data || len < 14 + 20 + 20)
        return 0;

    eth_type = be16(p + 12);
    p += 14;
    n = len - 14;

    if (eth_type == 0x8100 || eth_type == 0x88A8)
    {
        if (n < 4)
            return 0;
        eth_type = be16(p + 2);
        p += 4;
        n -= 4;
    }
    if (eth_type != 0x0800 || n < 20)
        return 0;
    if ((p[0] >> 4) != 4)
        return 0;

    ihl = (uint32_t)(p[0] & 0x0F) * 4U;
    if (ihl < 20 || n < ihl)
        return 0;
    total_len = be16(p + 2);
    if (total_len < ihl || n < total_len)
        return 0;
    if (p[9] != IPPROTO_TCP)
        return 0;

    sip = be32(p + 12);
    dip = be32(p + 16);
    p += ihl;
    if ((uint32_t)(total_len - ihl) < 20)
        return 0;

    sport = be16(p + 0);
    dport = be16(p + 2);
    if (flags)
        *flags = p[13];
    normalize_flow(sip, sport, dip, dport, flow, dir);
    return 1;
}

static int flow_eq(const flow_key_t *a, const flow_key_t *b)
{
    return a && b &&
           a->src_ip == b->src_ip &&
           a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port &&
           a->dst_port == b->dst_port &&
           a->proto == b->proto;
}

static void rst_log_cache_put(app_ctx_t *app, const flow_key_t *flow, const httgw_sess_snapshot_t *snap, uint64_t now_ms)
{
    if (!app || !flow || !snap)
        return;
    app->rst_cache.flow = *flow;
    app->rst_cache.snap = *snap;
    app->rst_cache.expires_ms = (now_ms == 0) ? UINT64_MAX : (now_ms + 3000ULL);
    app->rst_cache.valid = 1;
}

static const httgw_sess_snapshot_t *rst_log_cache_get(app_ctx_t *app, const flow_key_t *flow, uint64_t now_ms)
{
    if (!app || !app->rst_cache.valid)
        return NULL;
    if (app->rst_cache.expires_ms <= now_ms)
    {
        app->rst_cache.valid = 0;
        return NULL;
    }
    if (!flow_eq(&app->rst_cache.flow, flow))
        return NULL;
    return &app->rst_cache.snap;
}

static int parse_ts_option(const uint8_t *opts, uint32_t opt_len, uint32_t *tsval, uint32_t *tsecr)
{
    uint32_t i = 0;
    while (i < opt_len)
    {
        uint8_t kind = opts[i];
        if (kind == 0)
            break;
        if (kind == 1)
        {
            i++;
            continue;
        }
        if (i + 1 >= opt_len)
            break;
        uint8_t len = opts[i + 1];
        if (len < 2 || i + len > opt_len)
            break;
        if (kind == 8 && len == 10)
        {
            *tsval = be32(opts + i + 2);
            *tsecr = be32(opts + i + 6);
            return 1;
        }
        i += len;
    }
    return 0;
}

static void log_tcp_packet_line(
    const app_ctx_t *app,
    const uint8_t *data,
    uint32_t len,
    const httgw_sess_snapshot_t *fallback_snap)
{
    if (!app || !app->shared || !app->shared->debug_log_enabled)
        return;

    if (!data || len < 14 + 20 + 20)
        return;

    const uint8_t *p = data;
    uint16_t eth_type = be16(p + 12);
    p += 14;
    uint32_t n = len - 14;

    if (eth_type == 0x8100 || eth_type == 0x88A8)
    {
        if (n < 4)
            return;
        eth_type = be16(p + 2);
        p += 4;
        n -= 4;
    }
    if (eth_type != 0x0800 || n < 20)
        return;
    if ((p[0] >> 4) != 4)
        return;

    uint32_t ihl = (uint32_t)(p[0] & 0x0F) * 4U;
    if (ihl < 20 || n < ihl)
        return;
    uint16_t total_len = be16(p + 2);
    if (total_len < ihl || n < total_len)
        return;
    if (p[9] != IPPROTO_TCP)
        return;

    uint32_t sip = be32(p + 12);
    uint32_t dip = be32(p + 16);
    const uint8_t *tcp = p + ihl;
    uint32_t ip_payload_len = (uint32_t)total_len - ihl;
    if (ip_payload_len < 20)
        return;

    uint16_t sport = be16(tcp + 0);
    uint16_t dport = be16(tcp + 2);
    uint32_t seq = be32(tcp + 4);
    uint32_t ack = be32(tcp + 8);
    uint32_t thl = (uint32_t)((tcp[12] >> 4) & 0x0F) * 4U;
    if (thl < 20 || ip_payload_len < thl)
        return;
    uint16_t win = be16(tcp + 14);
    uint32_t payload_len = ip_payload_len - thl;

    uint32_t tsval = 0, tsecr = 0;
    int has_ts = 0;
    uint32_t rel_seq = seq;
    uint32_t rel_ack = ack;
    uint32_t rel_end = seq + payload_len;
    flow_key_t flow;
    tcp_dir_t dir = DIR_AB;
    httgw_sess_snapshot_t snap;
    int have_snap = 0;
    if (thl > 20)
        has_ts = parse_ts_option(tcp + 20, thl - 20, &tsval, &tsecr);

    char src_ip[32], dst_ip[32], opts[96];
    ip4_to_str(sip, src_ip, sizeof(src_ip));
    ip4_to_str(dip, dst_ip, sizeof(dst_ip));

    normalize_flow(sip, sport, dip, dport, &flow, &dir);
    if (app && app->gw && httgw_get_session_snapshot(app->gw, &flow, &snap) == 0)
    {
        have_snap = 1;
        if (dir == DIR_AB)
        {
            rel_seq = seq - snap.base_seq_ab;
            rel_end = rel_seq + payload_len;
            if (ack != 0 && snap.seen_ba)
                rel_ack = ack - snap.base_seq_ba;
        }
        else
        {
            rel_seq = seq - snap.base_seq_ba;
            rel_end = rel_seq + payload_len;
            if (ack != 0 && snap.seen_ab)
                rel_ack = ack - snap.base_seq_ab;
        }
    }
    else if (fallback_snap)
    {
        snap = *fallback_snap;
        have_snap = 1;
        if (dir == DIR_AB)
        {
            rel_seq = seq - snap.base_seq_ab;
            rel_end = rel_seq + payload_len;
            if (ack != 0 && snap.seen_ba)
                rel_ack = ack - snap.base_seq_ba;
        }
        else
        {
            rel_seq = seq - snap.base_seq_ba;
            rel_end = rel_seq + payload_len;
            if (ack != 0 && snap.seen_ab)
                rel_ack = ack - snap.base_seq_ab;
        }
    }

    if (has_ts)
        snprintf(opts, sizeof(opts), "options [TS val %u ecr %u]", tsval, tsecr);
    else
        snprintf(opts, sizeof(opts), "options []");

    fprintf(stderr,
            have_snap
                ? "[TCP] IP %s.%u > %s.%u, rel_seq %u:%u, rel_ack %u, win %u, %s, length %u\n"
                : "[TCP] IP %s.%u > %s.%u, seq %u:%u, ack %u, win %u, %s, length %u\n",
            src_ip, sport, dst_ip, dport,
            have_snap ? rel_seq : seq,
            have_snap ? rel_end : seq + payload_len,
            have_snap ? rel_ack : ack,
            win, opts, payload_len);
}

static void ip4_to_str(uint32_t ip, char *out, size_t out_sz)
{
    if (!out || out_sz == 0)
        return;
    snprintf(out, out_sz, "%u.%u.%u.%u",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

static void request_rst_both(app_ctx_t *app, const flow_key_t *flow)
{
    if (!app || !flow)
        return;
    httgw_sess_snapshot_t snap;
    if (httgw_get_session_snapshot(app->gw, flow, &snap) != 0)
        return;
    if (!snap.seen_ab || !snap.seen_ba)
    {
        if (app->shared->debug_log_enabled)
            fprintf(stderr, "[TCP] skip waiting_bidir seen_ab=%u seen_ba=%u\n",
                    snap.seen_ab, snap.seen_ba);
        app_log_write(app->shared,
                      "INFO",
                      "event=rst_skip reason=waiting_bidir seen_ab=%u seen_ba=%u",
                      snap.seen_ab,
                      snap.seen_ba);
        return;
    }

    uint32_t win_ab = (snap.win_scale_ab > 14 ? snap.win_ab << 14 : snap.win_ab << snap.win_scale_ab);
    uint32_t win_ba = (snap.win_scale_ba > 14 ? snap.win_ba << 14 : snap.win_ba << snap.win_scale_ba);
    if (app->shared->debug_log_enabled)
    {
        fprintf(stderr, "[TCP] Client->Server rel_ack=%u rel_seq=%u WIN=%u\n",
                snap.next_seq_ba - snap.base_seq_ba, snap.next_seq_ab - snap.base_seq_ab, win_ba);
        fprintf(stderr, "[TCP] Server->Client rel_ack=%u rel_seq=%u WIN=%u\n",
                snap.next_seq_ab - snap.base_seq_ab, snap.next_seq_ba - snap.base_seq_ba, win_ab);
    }

    rst_log_cache_put(app, flow, &snap, 0);

    int rc_ab = httgw_request_rst_with_snapshot(app->gw, flow, DIR_AB, &snap);
    int rc_ba = httgw_request_rst_with_snapshot(app->gw, flow, DIR_BA, &snap);
    if (app->shared->debug_log_enabled)
    {
        fprintf(stderr, "[TCP] RST Client->Server rc=%d\n", rc_ab);
        fprintf(stderr, "[TCP] RST Server->Client rc=%d\n", rc_ba);
    }
    app_log_write(app->shared,
                  (rc_ab == 0 && rc_ba == 0) ? "WARN" : "ERROR",
                  "event=rst_request src_ip=%u.%u.%u.%u src_port=%u dst_ip=%u.%u.%u.%u dst_port=%u rc_ab=%d rc_ba=%d",
                  (flow->src_ip >> 24) & 0xFF, (flow->src_ip >> 16) & 0xFF, (flow->src_ip >> 8) & 0xFF, flow->src_ip & 0xFF,
                  flow->src_port,
                  (flow->dst_ip >> 24) & 0xFF, (flow->dst_ip >> 16) & 0xFF, (flow->dst_ip >> 8) & 0xFF, flow->dst_ip & 0xFF,
                  flow->dst_port,
                  rc_ab,
                  rc_ba);
}

static int hex_val(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int url_decode(const char *in, size_t in_len, uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t oi = 0;
    for (size_t i = 0; i < in_len; i++)
    {
        unsigned char c = (unsigned char)in[i];
        if (c == '%' && i + 2 < in_len)
        {
            int hi = hex_val((unsigned char)in[i + 1]);
            int lo = hex_val((unsigned char)in[i + 2]);
            if (hi < 0 || lo < 0)
                return -1;
            if (oi >= out_cap)
                return -1;
            out[oi++] = (uint8_t)((hi << 4) | lo);
            i += 2;
            continue;
        }
        if (c == '+')
            c = ' ';
        if (oi >= out_cap)
            return -1;
        out[oi++] = (uint8_t)c;
    }
    *out_len = oi;
    return 0;
}

static int detect_match_decoded(
    detect_engine_t *det,
    const uint8_t *data,
    size_t len,
    ips_context_t ctx,
    detect_match_list_t *matches,
    uint64_t *elapsed_us
)
{
    uint64_t start_us;
    uint64_t end_us;
    int rc;

    start_us = monotonic_us();
    rc = detect_engine_collect_matches_ctx(det, data, len, ctx, matches);
    end_us = monotonic_us();
    if (elapsed_us)
        *elapsed_us += (end_us - start_us);
    if (rc != 0 || len == 0)
        return rc;

    int need_decode = 0;
    for (size_t i = 0; i < len; i++)
    {
        if (data[i] == '%' || data[i] == '+')
        {
            need_decode = 1;
            break;
        }
    }
    if (!need_decode)
        return 0;

    uint8_t *buf = (uint8_t *)malloc(len);
    if (!buf)
        return 0;

    size_t out_len = 0;
    if (url_decode((const char *)data, len, buf, len, &out_len) == 0 && out_len > 0)
    {
        start_us = monotonic_us();
        rc = detect_engine_collect_matches_ctx(det, buf, out_len, ctx, matches);
        end_us = monotonic_us();
        if (elapsed_us)
            *elapsed_us += (end_us - start_us);
    }

    free(buf);
    return rc;
}

static int run_detect(
    detect_engine_t *det,
    const http_message_t *msg,
    int *out_score,
    const IPS_Signature **matched_rule,
    detect_match_list_t *matches,
    uint64_t *detect_elapsed_us
)
{
    int rc;
    int score = 0;
    size_t prev_count = 0;
    size_t i;

    if (detect_elapsed_us)
        *detect_elapsed_us = 0;

    if (matched_rule)
        *matched_rule = NULL;
    if (!det || !msg)
        return 0;
    if (matches)
        detect_match_list_init(matches);

    /* REQUEST_URI */
    if (msg->uri[0] != '\0')
    {
        prev_count = matches ? matches->count : 0;
        rc = detect_match_decoded(det, (const uint8_t *)msg->uri, strlen(msg->uri),
                                  IPS_CTX_REQUEST_URI, matches, detect_elapsed_us);
        if (rc < 0)
            return rc;
        if (matches)
            for (i = prev_count; i < matches->count; i++)
                score += matches->items[i].rule ? matches->items[i].rule->is_high_priority : 0;
    }

    /* ARGS / ARGS_NAMES from query string */
    if (msg->uri[0] != '\0')
    {
        const char *qm = strchr(msg->uri, '?');
        if (qm && *(qm + 1) != '\0')
        {
            const char *hash = strchr(qm + 1, '#');
            size_t qlen = hash ? (size_t)(hash - (qm + 1)) : strlen(qm + 1);

            const char *p = qm + 1;
            const char *qend = p + qlen;
            while (p < qend)
            {
                const char *amp = memchr(p, '&', (size_t)(qend - p));
                const char *seg_end = amp ? amp : qend;
                const char *eq = memchr(p, '=', (size_t)(seg_end - p));

                if (eq)
                {
                    size_t name_len = (size_t)(eq - p);
                    size_t val_len = (size_t)(seg_end - (eq + 1));
                    if (name_len > 0)
                    {
                        prev_count = matches ? matches->count : 0;
                        rc = detect_match_decoded(det, (const uint8_t *)p, name_len,
                                                  IPS_CTX_ARGS_NAMES, matches, detect_elapsed_us);
                        if (rc < 0)
                            return rc;
                        if (matches)
                            for (i = prev_count; i < matches->count; i++)
                                score += matches->items[i].rule ? matches->items[i].rule->is_high_priority : 0;
                    }
                    if (val_len > 0)
                    {
                        prev_count = matches ? matches->count : 0;
                        rc = detect_match_decoded(det, (const uint8_t *)(eq + 1), val_len,
                                                  IPS_CTX_ARGS, matches, detect_elapsed_us);
                        if (rc < 0)
                            return rc;
                        if (matches)
                            for (i = prev_count; i < matches->count; i++)
                                score += matches->items[i].rule ? matches->items[i].rule->is_high_priority : 0;
                    }
                }
                else if (seg_end > p)
                {
                    prev_count = matches ? matches->count : 0;
                    rc = detect_match_decoded(det, (const uint8_t *)p, (size_t)(seg_end - p),
                                              IPS_CTX_ARGS_NAMES, matches, detect_elapsed_us);
                    if (rc < 0)
                        return rc;
                    if (matches)
                        for (i = prev_count; i < matches->count; i++)
                            score += matches->items[i].rule ? matches->items[i].rule->is_high_priority : 0;
                }

                if (!amp)
                    break;
                p = amp + 1;
            }
        }
    }

    /* ARGS / ARGS_NAMES from body when form-encoded */
    if (msg->body && msg->body_len > 0 && msg->content_type[0] != '\0')
    {
        const char *ct = msg->content_type;
        if (strstr(ct, "application/x-www-form-urlencoded") != NULL)
        {
            const char *p = (const char *)msg->body;
            const char *end = p + msg->body_len;
            while (p < end)
            {
                const char *amp = memchr(p, '&', (size_t)(end - p));
                const char *seg_end = amp ? amp : end;
                const char *eq = memchr(p, '=', (size_t)(seg_end - p));

                if (eq)
                {
                    size_t name_len = (size_t)(eq - p);
                    size_t val_len = (size_t)(seg_end - (eq + 1));
                    if (name_len > 0)
                    {
                        prev_count = matches ? matches->count : 0;
                        rc = detect_match_decoded(det, (const uint8_t *)p, name_len,
                                                  IPS_CTX_ARGS_NAMES, matches, detect_elapsed_us);
                        if (rc < 0)
                            return rc;
                        if (matches)
                            for (i = prev_count; i < matches->count; i++)
                                score += matches->items[i].rule ? matches->items[i].rule->is_high_priority : 0;
                    }
                    if (val_len > 0)
                    {
                        prev_count = matches ? matches->count : 0;
                        rc = detect_match_decoded(det, (const uint8_t *)(eq + 1), val_len,
                                                  IPS_CTX_ARGS, matches, detect_elapsed_us);
                        if (rc < 0)
                            return rc;
                        if (matches)
                            for (i = prev_count; i < matches->count; i++)
                                score += matches->items[i].rule ? matches->items[i].rule->is_high_priority : 0;
                    }
                }
                else if (seg_end > p)
                {
                    prev_count = matches ? matches->count : 0;
                    rc = detect_match_decoded(det, (const uint8_t *)p, (size_t)(seg_end - p),
                                              IPS_CTX_ARGS_NAMES, matches, detect_elapsed_us);
                    if (rc < 0)
                        return rc;
                    if (matches)
                        for (i = prev_count; i < matches->count; i++)
                            score += matches->items[i].rule ? matches->items[i].rule->is_high_priority : 0;
                }

                if (!amp)
                    break;
                p = amp + 1;
            }
        }
    }

    if (msg->headers_raw && msg->headers_raw_len > 0)
    {
        uint64_t start_us = monotonic_us();
        prev_count = matches ? matches->count : 0;
        rc = detect_engine_collect_matches_ctx(det, msg->headers_raw, msg->headers_raw_len,
                                               IPS_CTX_REQUEST_HEADERS, matches);
        uint64_t end_us = monotonic_us();
        if (detect_elapsed_us)
            *detect_elapsed_us += (end_us - start_us);
        if (rc < 0)
            return rc;
        if (matches)
            for (i = prev_count; i < matches->count; i++)
                score += matches->items[i].rule ? matches->items[i].rule->is_high_priority : 0;
    }

    if (msg->body && msg->body_len > 0)
    {
        uint64_t start_us = monotonic_us();
        prev_count = matches ? matches->count : 0;
        rc = detect_engine_collect_matches_ctx(det, msg->body, msg->body_len,
                                               IPS_CTX_REQUEST_BODY, matches);
        uint64_t end_us = monotonic_us();
        if (detect_elapsed_us)
            *detect_elapsed_us += (end_us - start_us);
        if (rc < 0)
            return rc;
        if (matches)
            for (i = prev_count; i < matches->count; i++)
                score += matches->items[i].rule ? matches->items[i].rule->is_high_priority : 0;
    }

    if (matched_rule)
        *matched_rule = (matches && matches->count > 0 && matches->items[0].rule) ? matches->items[0].rule : NULL;
    if (out_score)
        *out_score = score;
    return (score >= THREADHOLD) ? 1 : 0;
}


static void on_request(
    const flow_key_t *flow,
    tcp_dir_t dir,
    const http_message_t *msg,
    const char *query,
    size_t query_len,
    void *user
)
{
    app_ctx_t *app = (app_ctx_t *)user;
    const IPS_Signature *rule = NULL;
    detect_match_list_t matches;
    int score = 0;
    int rc;
    uint64_t detect_us = 0;
    long detect_ms;
    strbuf_t matched_rules = {0};
    strbuf_t matched_texts = {0};

    if (!app || !app->shared || !app->det)
        return;

    (void)query;
    (void)query_len;
    rc = run_detect(app->det, msg, &score, &rule, &matches, &detect_us);
    detect_ms = (long)((detect_us + 999ULL) / 1000ULL);
    if (rc > 0)
    {
        char ip[32];
        char from[256];

        ip4_to_str(flow->src_ip, ip, sizeof(ip));
        snprintf(from, sizeof(from), "%.31s %.200s",
                 msg->method[0] ? msg->method : "UNKNOWN",
                 msg->uri[0] ? msg->uri : "/");
        append_match_strings(&matches, &matched_rules, &matched_texts);
        fprintf(stderr, "[HTTP] Detect attack=%s IP=%s Port=%u score=%d threshold=%d\n",
                rule ? rule->policy_name : "unknown", ip, flow->src_port, score, THREADHOLD);
        app_log_attack(app->shared,
                       rule ? rule->policy_name : "unknown",
                       "REQUEST",
                       from,
                       rule ? rule->pattern : "unknown",
                       matched_rules.buf,
                       matched_texts.buf,
                       ip,
                       flow->src_port,
                       score,
                       THREADHOLD,
                       matches.count,
                       detect_us,
                       detect_ms);
        atomic_fetch_add(&app->shared->http_msgs, 1);
        atomic_fetch_add(&app->shared->reqs, 1);
        request_rst_both(app, flow);
    }
    else if (rc == 0)
    {
        char ip[32];
        ip4_to_str(flow->src_ip, ip, sizeof(ip));
        if (app->shared->pass_log_enabled)
        {
            fprintf(stderr, "[HTTP] Pass method=%s uri=%s IP=%s Port=%u\n",
                    msg->method[0] ? msg->method : "unknown",
                    msg->uri[0] ? msg->uri : "/",
                    ip, flow->src_port);
            app_log_write(app->shared,
                          "INFO",
                          "event=http_pass where=request method=%s uri=\"%s\" src_ip=%s src_port=%u detect_ms=%ld",
                          msg->method[0] ? msg->method : "unknown",
                          msg->uri[0] ? msg->uri : "/",
                          ip,
                          flow->src_port,
                          detect_ms);
        }
        atomic_fetch_add(&app->shared->http_msgs, 1);
        atomic_fetch_add(&app->shared->reqs, 1);
    }
    else if (rc < 0)
    {
        fprintf(stderr, "detect error: %s\n", detect_engine_last_error(app->det));
        app_log_write(app->shared,
                      "ERROR",
                      "event=detect_error detail=\"%s\"",
                      detect_engine_last_error(app->det));
    }
    detect_match_list_free(&matches);
    strbuf_free(&matched_rules);
    strbuf_free(&matched_texts);
    (void)dir;
}

static void on_response(
    const flow_key_t *flow,
    tcp_dir_t dir,
    const http_message_t *msg,
    void *user
)
{
    app_ctx_t *app = (app_ctx_t *)user;
    const IPS_Signature *rule = NULL;
    detect_match_list_t matches;
    int score = 0;
    int rc;
    uint64_t detect_us = 0;
    long detect_ms;
    strbuf_t matched_rules = {0};
    strbuf_t matched_texts = {0};

    if (!app || !app->shared || !app->det)
        return;

    if (app->mode == HTTGW_MODE_SNIFF)
        return;

    rc = run_detect(app->det, msg, &score, &rule, &matches, &detect_us);
    detect_ms = (long)((detect_us + 999ULL) / 1000ULL);
    if (rc > 0)
    {
        char ip[32];
        char from[64];

        ip4_to_str(flow->src_ip, ip, sizeof(ip));
        snprintf(from, sizeof(from), "status=%d", msg->status_code);
        append_match_strings(&matches, &matched_rules, &matched_texts);
        fprintf(stderr, "[HTTP] Detect attack=%s IP=%s Port=%u score=%d threshold=%d\n",
                rule ? rule->policy_name : "unknown", ip, flow->src_port, score, THREADHOLD);
        app_log_attack(app->shared,
                       rule ? rule->policy_name : "unknown",
                       "RESPONSE",
                       from,
                       rule ? rule->pattern : "unknown",
                       matched_rules.buf,
                       matched_texts.buf,
                       ip,
                       flow->src_port,
                       score,
                       THREADHOLD,
                       matches.count,
                       detect_us,
                       detect_ms);
        atomic_fetch_add(&app->shared->http_msgs, 1);
        atomic_fetch_add(&app->shared->resps, 1);
        request_rst_both(app, flow);
    }
    else if (rc == 0)
    {
        char ip[32];
        ip4_to_str(flow->src_ip, ip, sizeof(ip));
        if (app->shared->pass_log_enabled)
        {
            fprintf(stderr, "[HTTP] Pass status=%d IP=%s Port=%u\n",
                    msg->status_code, ip, flow->src_port);
            app_log_write(app->shared,
                          "INFO",
                          "event=http_pass where=response status=%d src_ip=%s src_port=%u detect_ms=%ld",
                          msg->status_code,
                          ip,
                          flow->src_port,
                          detect_ms);
        }
        atomic_fetch_add(&app->shared->http_msgs, 1);
        atomic_fetch_add(&app->shared->resps, 1);
    }
    else if (rc < 0)
    {
        fprintf(stderr, "detect error: %s\n", detect_engine_last_error(app->det));
        app_log_write(app->shared,
                      "ERROR",
                      "event=detect_error detail=\"%s\"",
                      detect_engine_last_error(app->det));
    }
    detect_match_list_free(&matches);
    strbuf_free(&matched_rules);
    strbuf_free(&matched_texts);
    (void)dir;
}

static void on_error(const char *stage, const char *detail, void *user)
{
    app_ctx_t *app = (app_ctx_t *)user;
    if (!app || !app->shared)
        return;
    fprintf(stderr, "[ERR] %s: %s\n", stage ? stage : "unknown", detail ? detail : "unknown");
    app_log_write(app->shared,
                  "ERROR",
                  "event=stream_error stage=%s detail=\"%s\"",
                  stage ? stage : "unknown",
                  detail ? detail : "unknown");
    if (stage)
    {
        if (strcmp(stage, "reasm_ingest") == 0)
            atomic_fetch_add(&app->shared->reasm_errs, 1);
        if (strcmp(stage, "http_stream_feed") == 0)
            atomic_fetch_add(&app->shared->parse_errs, 1);
    }
}

static void on_packet(
    const uint8_t *data,
    uint32_t len,
    uint64_t ts_ns,
    void *user
)
{
    app_ctx_t *app = (app_ctx_t *)user;
    uint64_t ts_ms = ts_ns / 1000000ULL;
    flow_key_t flow;
    tcp_dir_t dir;
    uint8_t flags = 0;
    httgw_sess_snapshot_t pre_snap;
    const httgw_sess_snapshot_t *fallback_snap = NULL;

    if (app && app->gw &&
        parse_flow_dir_and_flags(data, len, &flow, &dir, &flags) &&
        (flags & TCP_RST))
    {
        if (httgw_get_session_snapshot(app->gw, &flow, &pre_snap) == 0)
        {
            rst_log_cache_put(app, &flow, &pre_snap, ts_ms);
            fallback_snap = &pre_snap;
        }
        else
        {
            fallback_snap = rst_log_cache_get(app, &flow, ts_ms);
        }
    }

    switch (app->mode)
    {
        case HTTGW_MODE_SNIFF:
            (void)httgw_ingest_packet(app->gw, data, len, ts_ms);
            log_tcp_packet_line(app, data, len, fallback_snap);
            break;
        case HTTGW_MODE_TP_SYN:
            /* TODO: TP/SYN proxy mode */
            break;
        case HTTGW_MODE_REVERSE:
            /* TODO: reverse proxy mode */
            break;
        default:
            break;
    }
}

static void destroy_workers(app_ctx_t *workers, int count)
{
    if (!workers || count <= 0)
        return;
    for (int i = 0; i < count; i++)
    {
        app_ctx_t *w = &workers[i];
        if (w->det)
        {
            detect_engine_destroy(w->det);
            w->det = NULL;
        }
        if (w->gw)
        {
            httgw_destroy(w->gw);
            w->gw = NULL;
        }
        tx_ctx_destroy(&w->rst_tx);
    }
}

static int parse_mode_arg(const char *arg, httgw_mode_t *out)
{
    if (!arg || !out)
        return -1;
    if (strcmp(arg, "sniffing") == 0 || strcmp(arg, "sniff") == 0)
    {
        *out = HTTGW_MODE_SNIFF;
        return 0;
    }
    if (strcmp(arg, "tp/syn") == 0 || strcmp(arg, "tp_syn") == 0 || strcmp(arg, "tpsyn") == 0)
    {
        *out = HTTGW_MODE_TP_SYN;
        return 0;
    }
    if (strcmp(arg, "reverse") == 0)
    {
        *out = HTTGW_MODE_REVERSE;
        return 0;
    }
    return -1;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s -iface=<iface> -bpf=<filter> [-mode=sniffing|tp/syn|reverse]\n",
            prog ? prog : "main");
}

int main(int argc, char **argv)
{
    const char *iface = NULL;
    const char *bpf = NULL;
    const char *policy = "ALL";
    httgw_mode_t mode = HTTGW_MODE_SNIFF;
    driver_runtime_t rt;
    app_shared_t shared;
    app_ctx_t *workers = NULL;
    void **worker_users = NULL;
    int worker_count = 1;
    httgw_cfg_t hcfg;
    httgw_callbacks_t cbs;
    pcap_ctx_t pcfg;
    int rc;
    int argi = 0;

    for (int i = 1; i < argc; i++)
    {
        if (strncmp(argv[i], "-mode=", 6) == 0)
        {
            if (parse_mode_arg(argv[i] + 6, &mode) != 0)
            {
                fprintf(stderr, "invalid mode: %s\n", argv[i] + 6);
                return 1;
            }
            continue;
        }
        if (strncmp(argv[i], "-iface=", 7) == 0)
        {
            iface = argv[i] + 7;
            continue;
        }
        if (strncmp(argv[i], "-bpf=", 5) == 0)
        {
            bpf = argv[i] + 5;
            continue;
        }
        if (argv[i][0] == '-')
            continue;
        argi++;
        if (argi == 1)
            iface = argv[i];
        else if (argi == 2)
            bpf = argv[i];
    }

    if (!iface || !bpf)
    {
        usage(argv[0]);
        return 1;
    }

    signal(SIGINT, on_sigint);

    memset(&rt, 0, sizeof(rt));
    memset(&shared, 0, sizeof(shared));

    if (app_log_open(&shared) != 0)
    {
        fprintf(stderr, "log init failed\n");
        return 1;
    }
    atomic_init(&shared.http_msgs, 0);
    atomic_init(&shared.reqs, 0);
    atomic_init(&shared.resps, 0);
    atomic_init(&shared.reasm_errs, 0);
    atomic_init(&shared.parse_errs, 0);
    shared.pass_log_enabled = env_flag_enabled("IPS_LOG_PASS", 0);
    shared.debug_log_enabled = env_flag_enabled("IPS_LOG_DEBUG", 0);

    long cpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpu > 0)
        worker_count = (int)cpu;
    if (worker_count < 1)
        worker_count = 1;
    if (worker_count > MAX_QUEUE_COUNT)
        worker_count = MAX_QUEUE_COUNT;

    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.dev = iface;
    pcfg.snaplen = 65535;
    pcfg.promisc = 1;
    pcfg.timeout_ms = 1000;
    pcfg.nonblocking = 0;

    if (driver_init(&rt, worker_count) != 0)
    {
        fprintf(stderr, "driver_init failed\n");
        app_log_write(&shared, "ERROR", "driver_init failed");
        app_log_close(&shared);
        return 1;
    }

    rc = capture_create(&rt.cc, &pcfg);
    if (rc != 0)
    {
        fprintf(stderr, "capture_create failed rc=%d\n", rc);
        app_log_write(&shared, "ERROR", "capture_create failed rc=%d", rc);
        driver_destroy(&rt);
        app_log_close(&shared);
        return 1;
    }
    rc = capture_activate(&rt.cc, &pcfg);   
    if (rc != 0)
    {
        fprintf(stderr, "capture_activate failed rc=%d\n", rc);
        app_log_write(&shared, "ERROR", "capture_activate failed rc=%d", rc);
        driver_destroy(&rt);
        app_log_close(&shared);
        return 1;
    }

    if (bpf && bpf[0])
    {
        struct bpf_program fp;
        if (pcap_compile(rt.cc.handle, &fp, bpf, 1, PCAP_NETMASK_UNKNOWN) < 0)
        {
            fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(rt.cc.handle));
            app_log_write(&shared, "ERROR", "pcap_compile failed: %s", pcap_geterr(rt.cc.handle));
            driver_destroy(&rt);
            app_log_close(&shared);
            return 1;
        }
        if (pcap_setfilter(rt.cc.handle, &fp) < 0)
        {
            fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(rt.cc.handle));
            app_log_write(&shared, "ERROR", "pcap_setfilter failed: %s", pcap_geterr(rt.cc.handle));
            pcap_freecode(&fp);
            driver_destroy(&rt);
            app_log_close(&shared);
            return 1;
        }
        pcap_freecode(&fp);
    }

    memset(&hcfg, 0, sizeof(hcfg));
    hcfg.max_buffer_bytes = 2U * 1024U * 1024U;
    hcfg.max_body_bytes = 2U * 1024U * 1024U;
    hcfg.reasm_mode = REASM_MODE_LATE_START;
    hcfg.verbose = 0;
    hcfg.mode = mode;

    memset(&cbs, 0, sizeof(cbs));
    cbs.on_request = on_request;
    cbs.on_response = on_response;
    cbs.on_error = on_error;

    workers = calloc(worker_count, sizeof(*workers));
    worker_users = calloc(worker_count, sizeof(*worker_users));
    if (!workers || !worker_users)
    {
        fprintf(stderr, "worker alloc failed\n");
        app_log_write(&shared, "ERROR", "worker alloc failed");
        free(workers);
        free(worker_users);
        driver_destroy(&rt);
        app_log_close(&shared);
        return 1;
    }

    for (int i = 0; i < worker_count; i++)
    {
        app_ctx_t *w = &workers[i];
        memset(w, 0, sizeof(*w));
        w->shared = &shared;
        w->mode = hcfg.mode;
        w->det = detect_engine_create(policy, DETECT_JIT_AUTO);
        if (!w->det)
        {
            fprintf(stderr, "detect_engine_create failed\n");
            app_log_write(&shared, "ERROR", "detect_engine_create failed");
            destroy_workers(workers, worker_count);
            free(worker_users);
            free(workers);
            driver_destroy(&rt);
            app_log_close(&shared);
            return 1;
        }
        w->gw = httgw_create(&hcfg, &cbs, w);
        if (!w->gw)
        {
            fprintf(stderr, "httgw_create failed\n");
            app_log_write(&shared, "ERROR", "httgw_create failed");
            destroy_workers(workers, worker_count);
            free(worker_users);
            free(workers);
            driver_destroy(&rt);
            app_log_close(&shared);
            return 1;
        }
        if (tx_ctx_init(&w->rst_tx) != 0)
        {
            fprintf(stderr, "tx_ctx_init failed (need root?)\n");
            app_log_write(&shared, "ERROR", "tx_ctx_init failed");
            destroy_workers(workers, worker_count);
            free(worker_users);
            free(workers);
            driver_destroy(&rt);
            app_log_close(&shared);
            return 1;
        }
        if (httgw_set_tx(w->gw, &w->rst_tx) != 0)
        {
            fprintf(stderr, "httgw_set_tx failed\n");
            app_log_write(&shared, "ERROR", "httgw_set_tx failed");
            destroy_workers(workers, worker_count);
            free(worker_users);
            free(workers);
            driver_destroy(&rt);
            app_log_close(&shared);
            return 1;
        }
        worker_users[i] = w;
    }

    driver_set_packet_handler_multi(&rt, on_packet, worker_users, (size_t)worker_count);

    if (driver_start(&rt) != 0)
    {
        fprintf(stderr, "driver_start failed\n");
        app_log_write(&shared, "ERROR", "driver_start failed");
        destroy_workers(workers, worker_count);
        free(worker_users);
        free(workers);
        driver_destroy(&rt);
        app_log_close(&shared);
        return 1;
    }

    printf("capture start: iface=%s filter=\"%s\" policy=%s mode=%d\n",
           iface, bpf, policy, mode);
    app_log_write(&shared,
                  "INFO",
                  "event=capture_start iface=%s filter=\"%s\" policy=%s mode=%d pass_log=%d debug_log=%d",
                  iface,
                  bpf,
                  policy,
                  mode,
                  shared.pass_log_enabled,
                  shared.debug_log_enabled);
    while (!g_stop)
    {
        usleep(200 * 1000);
    }

    driver_stop(&rt);
    driver_destroy(&rt);
    destroy_workers(workers, worker_count);
    free(worker_users);
    free(workers);
    app_log_write(&shared, "INFO", "event=capture_stop");
    app_log_close(&shared);
    return 0;
}

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
#include "net_compat.h"
#include "detect.h"
#include "driver.h"
#include "httgw.h"

#define THREADHOLD 5

typedef struct app_ctx
{
    httgw_t *gw;
    detect_engine_t *det;
    httgw_mode_t mode;
    tx_ctx_t rst_tx;
    FILE *log_fp;
    char log_path[256];
} app_ctx_t;

typedef struct rst_log_cache
{
    flow_key_t flow;
    httgw_sess_snapshot_t snap;
    uint64_t expires_ms;
    int valid;
} rst_log_cache_t;

static volatile sig_atomic_t g_stop = 0;
static void ip4_to_str(uint32_t ip, char *out, size_t out_sz);
static rst_log_cache_t g_rst_log_cache;

/**
 * @brief 현재 시각을 로그 출력용 문자열로 변환한다.
 * @param out 결과 문자열 버퍼
 * @param out_sz 버퍼 크기
 */
static void make_log_timestamp(char *out, size_t out_sz)
{
    time_t now;
    struct tm tm_now;

    if (!out || out_sz == 0)
        return;

    now = time(NULL);
    localtime_r(&now, &tm_now);
    strftime(out, out_sz, "%y-%m-%d %H:%M:%S", &tm_now);
}

/**
 * @brief 로그 디렉터리와 파일을 준비한다.
 * @param app 애플리케이션 컨텍스트
 * @return 성공 시 0, 실패 시 -1
 */
static int app_log_open(app_ctx_t *app)
{
    if (!app)
        return -1;

    if (mkdir("logs", 0755) != 0 && errno != EEXIST)
        return -1;

    snprintf(app->log_path, sizeof(app->log_path), "logs/ips.log");
    app->log_fp = fopen(app->log_path, "a");
    if (!app->log_fp)
        return -1;

    return 0;
}

/**
 * @brief 열린 로그 파일을 정리한다.
 * @param app 애플리케이션 컨텍스트
 */
static void app_log_close(app_ctx_t *app)
{
    if (!app || !app->log_fp)
        return;
    fclose(app->log_fp);
    app->log_fp = NULL;
}

/**
 * @brief 공통 런타임 로그를 파일에 기록한다.
 * @param app 애플리케이션 컨텍스트
 * @param category 로그 분류
 * @param fmt 본문 포맷 문자열
 */
static void app_log_write(app_ctx_t *app, const char *category, const char *fmt, ...)
{
    va_list ap;
    char ts[32];

    if (!app || !app->log_fp || !fmt)
        return;

    make_log_timestamp(ts, sizeof(ts));
    fprintf(app->log_fp, "[%s] %s: ", ts, category ? category : "INFO");

    va_start(ap, fmt);
    vfprintf(app->log_fp, fmt, ap);
    va_end(ap);

    fputc('\n', app->log_fp);
    fflush(app->log_fp);
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
static void app_log_attack(app_ctx_t *app,
                           const char *attack,
                           const char *where,
                           const char *from,
                           const char *detected,
                           const char *ip,
                           uint16_t port,
                           long detect_ms)
{
    char ts[32];

    if (!app || !app->log_fp)
        return;

    make_log_timestamp(ts, sizeof(ts));
    fprintf(app->log_fp,
            "[%s] ATTACK: [%s] , WHERE: [%s] FROM: [%s] DETECTED: [%s], IP: [%s], PORT: [%u], PCRE DETECT TIME: [%ld ms]\n",
            ts,
            attack ? attack : "unknown",
            where ? where : "unknown",
            from ? from : "unknown",
            detected ? detected : "unknown",
            ip ? ip : "unknown",
            (unsigned int)port,
            detect_ms);
    fflush(app->log_fp);
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

static void rst_log_cache_put(const flow_key_t *flow, const httgw_sess_snapshot_t *snap, uint64_t now_ms)
{
    if (!flow || !snap)
        return;
    g_rst_log_cache.flow = *flow;
    g_rst_log_cache.snap = *snap;
    g_rst_log_cache.expires_ms = (now_ms == 0) ? UINT64_MAX : (now_ms + 3000ULL);
    g_rst_log_cache.valid = 1;
}

static const httgw_sess_snapshot_t *rst_log_cache_get(const flow_key_t *flow, uint64_t now_ms)
{
    if (!g_rst_log_cache.valid)
        return NULL;
    if (g_rst_log_cache.expires_ms <= now_ms)
    {
        g_rst_log_cache.valid = 0;
        return NULL;
    }
    if (!flow_eq(&g_rst_log_cache.flow, flow))
        return NULL;
    return &g_rst_log_cache.snap;
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
    if (app && app->gw && httgw_get_session_snapshot(&flow, &snap) == 0)
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

static void request_rst_both(const app_ctx_t *app, const flow_key_t *flow)
{
    if (!app || !flow)
        return;
    httgw_sess_snapshot_t snap;
    if (httgw_get_session_snapshot(flow, &snap) != 0)
        return;
    if (!snap.seen_ab || !snap.seen_ba)
    {
        fprintf(stderr, "[TCP] skip waiting_bidir seen_ab=%u seen_ba=%u\n",
                snap.seen_ab, snap.seen_ba);
        return;
    }

    uint32_t win_ab = (snap.win_scale_ab > 14 ? snap.win_ab << 14 : snap.win_ab << snap.win_scale_ab);
    uint32_t win_ba = (snap.win_scale_ba > 14 ? snap.win_ba << 14 : snap.win_ba << snap.win_scale_ba);
    fprintf(stderr, "[TCP] Client->Server rel_ack=%u rel_seq=%u WIN=%u\n",
            snap.next_seq_ba - snap.base_seq_ba, snap.next_seq_ab - snap.base_seq_ab, win_ba);
    fprintf(stderr, "[TCP] Server->Client rel_ack=%u rel_seq=%u WIN=%u\n",
            snap.next_seq_ab - snap.base_seq_ab, snap.next_seq_ba - snap.base_seq_ba, win_ab);

    rst_log_cache_put(flow, &snap, 0);

    int rc_ab = httgw_request_rst_with_snapshot(app->gw, flow, DIR_AB, &snap);
    fprintf(stderr, "[TCP] RST Client->Server rc=%d\n", rc_ab);
    int rc_ba = httgw_request_rst_with_snapshot(app->gw, flow, DIR_BA, &snap);
    fprintf(stderr, "[TCP] RST Server->Client rc=%d\n", rc_ba);
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
    const IPS_Signature **matched_rule,
    uint64_t *elapsed_us
)
{
    uint64_t start_us;
    uint64_t end_us;
    int rc;

    start_us = monotonic_us();
    rc = detect_engine_match_ctx(det, data, len, ctx, matched_rule);
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
        rc = detect_engine_match_ctx(det, buf, out_len, ctx, matched_rule);
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
    uint64_t *detect_elapsed_us
)
{
    int rc;
    int score = 0;

    if (detect_elapsed_us)
        *detect_elapsed_us = 0;

    if (matched_rule)
        *matched_rule = NULL;
    if (!det || !msg)
        return 0;

    /* REQUEST_URI */
    if (msg->uri[0] != '\0')
    {
        rc = detect_match_decoded(det, (const uint8_t *)msg->uri, strlen(msg->uri),
                                  IPS_CTX_REQUEST_URI, matched_rule, detect_elapsed_us);
        if (rc < 0)
            return rc;
        if (rc > 0)
        {
            score += (*matched_rule)->is_high_priority;
            if (score >= THREADHOLD)
                goto out;
        }
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
                        rc = detect_match_decoded(det, (const uint8_t *)p, name_len,
                                                  IPS_CTX_ARGS_NAMES, matched_rule, detect_elapsed_us);
                        if (rc < 0)
                            return rc;
                        if (rc > 0)
                        {
                            score += (*matched_rule)->is_high_priority;
                            if (score >= THREADHOLD)
                                goto out;
                        }
                    }
                    if (val_len > 0)
                    {
                        rc = detect_match_decoded(det, (const uint8_t *)(eq + 1), val_len,
                                                  IPS_CTX_ARGS, matched_rule, detect_elapsed_us);
                        if (rc < 0)
                            return rc;
                        if (rc > 0)
                        {
                            score += (*matched_rule)->is_high_priority;
                            if (score >= THREADHOLD)
                                goto out;
                        }
                    }
                }
                else if (seg_end > p)
                {
                    /* name only */
                    rc = detect_match_decoded(det, (const uint8_t *)p, (size_t)(seg_end - p),
                                              IPS_CTX_ARGS_NAMES, matched_rule, detect_elapsed_us);
                    if (rc < 0)
                        return rc;
                    if (rc > 0)
                    {
                        score += (*matched_rule)->is_high_priority;
                        if (score >= THREADHOLD)
                            goto out;
                    }
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
                        rc = detect_match_decoded(det, (const uint8_t *)p, name_len,
                                                  IPS_CTX_ARGS_NAMES, matched_rule, detect_elapsed_us);
                        if (rc < 0)
                            return rc;
                        if (rc > 0)
                        {
                            score += (*matched_rule)->is_high_priority;
                            if (score >= THREADHOLD)
                                goto out;
                        }
                    }
                    if (val_len > 0)
                    {
                        rc = detect_match_decoded(det, (const uint8_t *)(eq + 1), val_len,
                                                  IPS_CTX_ARGS, matched_rule, detect_elapsed_us);
                        if (rc < 0)
                            return rc;
                        if (rc > 0)
                        {
                            score += (*matched_rule)->is_high_priority;
                            if (score >= THREADHOLD)
                                goto out;
                        }
                    }
                }
                else if (seg_end > p)
                {
                    rc = detect_match_decoded(det, (const uint8_t *)p, (size_t)(seg_end - p),
                                              IPS_CTX_ARGS_NAMES, matched_rule, detect_elapsed_us);
                    if (rc < 0)
                        return rc;
                    if (rc > 0)
                    {
                        score += (*matched_rule)->is_high_priority;
                        if (score >= THREADHOLD)
                            goto out;
                    }
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
        rc = detect_engine_match_ctx(det, msg->headers_raw, msg->headers_raw_len,
                                     IPS_CTX_REQUEST_HEADERS, matched_rule);
        uint64_t end_us = monotonic_us();
        if (detect_elapsed_us)
            *detect_elapsed_us += (end_us - start_us);
        if (rc < 0)
            return rc;
        if (rc > 0)
        {
            score += (*matched_rule)->is_high_priority;
            if (score >= THREADHOLD)
                goto out;
        }
    }

    if (msg->body && msg->body_len > 0)
    {
        uint64_t start_us = monotonic_us();
        rc = detect_engine_match_ctx(det, msg->body, msg->body_len,
                                     IPS_CTX_REQUEST_BODY, matched_rule);
        uint64_t end_us = monotonic_us();
        if (detect_elapsed_us)
            *detect_elapsed_us += (end_us - start_us);
        if (rc < 0)
            return rc;
        if (rc > 0)
        {
            score += (*matched_rule)->is_high_priority;
            if (score >= THREADHOLD)
                goto out;
        }
    }

out:
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
    int score = 0;
    int rc;
    uint64_t detect_us = 0;
    long detect_ms;

    (void)query;
    (void)query_len;
    rc = run_detect(app->det, msg, &score, &rule, &detect_us);
    detect_ms = (long)((detect_us + 999ULL) / 1000ULL);
    if (rc > 0)
    {
        char ip[32];
        char from[256];

        ip4_to_str(flow->src_ip, ip, sizeof(ip));
        snprintf(from, sizeof(from), "%.31s %.200s",
                 msg->method[0] ? msg->method : "UNKNOWN",
                 msg->uri[0] ? msg->uri : "/");
        fprintf(stderr, "[HTTP] Detect attack=%s IP=%s Port=%u score=%d threshold=%d\n",
                rule ? rule->policy_name : "unknown", ip, flow->src_port, score, THREADHOLD);
        app_log_attack(app,
                       rule ? rule->policy_name : "unknown",
                       "REQUEST",
                       from,
                       rule ? rule->pattern : "unknown",
                       ip,
                       flow->src_port,
                       detect_ms);
        request_rst_both(app, flow);
    }
    else if (rc == 0)
    {
        char ip[32];
        ip4_to_str(flow->src_ip, ip, sizeof(ip));
        fprintf(stderr, "[HTTP] Pass method=%s uri=%s IP=%s Port=%u\n",
                msg->method[0] ? msg->method : "unknown",
                msg->uri[0] ? msg->uri : "/",
                ip, flow->src_port);
        app_log_write(app,
                      "HTTP",
                      "PASS method=%s uri=%s ip=%s port=%u detect_ms=%ld",
                      msg->method[0] ? msg->method : "unknown",
                      msg->uri[0] ? msg->uri : "/",
                      ip,
                      flow->src_port,
                      detect_ms);
    }
    else if (rc < 0)
    {
        fprintf(stderr, "detect error: %s\n", detect_engine_last_error(app->det));
        app_log_write(app,
                      "ERROR",
                      "detect error: %s",
                      detect_engine_last_error(app->det));
    }
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
    int score = 0;
    int rc;
    uint64_t detect_us = 0;
    long detect_ms;

    if (app->mode == HTTGW_MODE_SNIFF)
        return;

    rc = run_detect(app->det, msg, &score, &rule, &detect_us);
    detect_ms = (long)((detect_us + 999ULL) / 1000ULL);
    if (rc > 0)
    {
        char ip[32];
        char from[64];

        ip4_to_str(flow->src_ip, ip, sizeof(ip));
        snprintf(from, sizeof(from), "status=%d", msg->status_code);
        fprintf(stderr, "[HTTP] Detect attack=%s IP=%s Port=%u score=%d threshold=%d\n",
                rule ? rule->policy_name : "unknown", ip, flow->src_port, score, THREADHOLD);
        app_log_attack(app,
                       rule ? rule->policy_name : "unknown",
                       "RESPONSE",
                       from,
                       rule ? rule->pattern : "unknown",
                       ip,
                       flow->src_port,
                       detect_ms);
        request_rst_both(app, flow);
    }
    else if (rc == 0)
    {
        char ip[32];
        ip4_to_str(flow->src_ip, ip, sizeof(ip));
        fprintf(stderr, "[HTTP] Pass status=%d IP=%s Port=%u\n",
                msg->status_code, ip, flow->src_port);
        app_log_write(app,
                      "HTTP",
                      "PASS status=%d ip=%s port=%u detect_ms=%ld",
                      msg->status_code,
                      ip,
                      flow->src_port,
                      detect_ms);
    }
    else if (rc < 0)
    {
        fprintf(stderr, "detect error: %s\n", detect_engine_last_error(app->det));
        app_log_write(app,
                      "ERROR",
                      "detect error: %s",
                      detect_engine_last_error(app->det));
    }
    (void)dir;
}

static void on_error(const char *stage, const char *detail, void *user)
{
    app_ctx_t *app = (app_ctx_t *)user;
    fprintf(stderr, "[ERR] %s: %s\n", stage ? stage : "unknown", detail ? detail : "unknown");
    app_log_write(app,
                  "ERROR",
                  "%s: %s",
                  stage ? stage : "unknown",
                  detail ? detail : "unknown");
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
        if (httgw_get_session_snapshot(&flow, &pre_snap) == 0)
        {
            rst_log_cache_put(&flow, &pre_snap, ts_ms);
            fallback_snap = &pre_snap;
        }
        else
        {
            fallback_snap = rst_log_cache_get(&flow, ts_ms);
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
    packet_ring_t ring;
    httgw_t *gw = NULL;
    detect_engine_t *det = NULL;
    httgw_cfg_t hcfg;
    httgw_callbacks_t cbs;
    pcap_ctx_t pcfg;
    app_ctx_t app;
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
    memset(&ring, 0, sizeof(ring));
    memset(&app, 0, sizeof(app));

    if (app_log_open(&app) != 0)
    {
        fprintf(stderr, "log init failed\n");
        return 1;
    }

    if (packet_ring_init(&ring, DEFAULT_SLOT_COUNT, 1) != 0)
    {
        fprintf(stderr, "packet_ring_init failed\n");
        app_log_write(&app, "ERROR", "packet_ring_init failed");
        app_log_close(&app);
        return 1;
    }

    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.dev = iface;
    pcfg.snaplen = 65535;
    pcfg.promisc = 1;
    pcfg.timeout_ms = 1000;
    pcfg.nonblocking = 0;

    rt.cc.ring = &ring;
    rc = capture_create(&rt.cc, &pcfg);
    if (rc != 0)
    {
        fprintf(stderr, "capture_create failed rc=%d\n", rc);
        app_log_write(&app, "ERROR", "capture_create failed rc=%d", rc);
        app_log_close(&app);
        return 1;
    }
    rc = capture_activate(&rt.cc, &pcfg);   
    if (rc != 0)
    {
        fprintf(stderr, "capture_activate failed rc=%d\n", rc);
        app_log_write(&app, "ERROR", "capture_activate failed rc=%d", rc);
        app_log_close(&app);
        return 1;
    }

    if (bpf && bpf[0])
    {
        struct bpf_program fp;
        if (pcap_compile(rt.cc.handle, &fp, bpf, 1, PCAP_NETMASK_UNKNOWN) < 0)
        {
            fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(rt.cc.handle));
            app_log_write(&app, "ERROR", "pcap_compile failed: %s", pcap_geterr(rt.cc.handle));
            app_log_close(&app);
            return 1;
        }
        if (pcap_setfilter(rt.cc.handle, &fp) < 0)
        {
            fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(rt.cc.handle));
            app_log_write(&app, "ERROR", "pcap_setfilter failed: %s", pcap_geterr(rt.cc.handle));
            pcap_freecode(&fp);
            app_log_close(&app);
            return 1;
        }
        pcap_freecode(&fp);
    }

    det = detect_engine_create(policy, DETECT_JIT_AUTO);
    if (!det)
    {
        fprintf(stderr, "detect_engine_create failed\n");
        app_log_write(&app, "ERROR", "detect_engine_create failed");
        app_log_close(&app);
        return 1;
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

    gw = httgw_create(&hcfg, &cbs, &app);
    if (!gw)
    {
        fprintf(stderr, "httgw_create failed\n");
        app_log_write(&app, "ERROR", "httgw_create failed");
        app_log_close(&app);
        return 1;
    }

    if (tx_ctx_init(&app.rst_tx) != 0)
    {
        fprintf(stderr, "tx_ctx_init failed (need root?)\n");
        app_log_write(&app, "ERROR", "tx_ctx_init failed");
        app_log_close(&app);
        return 1;
    }
    if (httgw_set_tx(gw, &app.rst_tx) != 0)
    {
        fprintf(stderr, "httgw_set_tx failed\n");
        app_log_write(&app, "ERROR", "httgw_set_tx failed");
        app_log_close(&app);
        return 1;
    }

    app.gw = gw;
    app.det = det;
    app.mode = hcfg.mode;

    if (driver_init(&rt, 1) != 0)
    {
        fprintf(stderr, "driver_init failed\n");
        app_log_write(&app, "ERROR", "driver_init failed");
        app_log_close(&app);
        return 1;
    }
    driver_set_packet_handler(&rt, on_packet, &app);

    if (driver_start(&rt) != 0)
    {
        fprintf(stderr, "driver_start failed\n");
        app_log_write(&app, "ERROR", "driver_start failed");
        app_log_close(&app);
        return 1;
    }

    printf("capture start: iface=%s filter=\"%s\" policy=%s mode=%d\n",
           iface, bpf, policy, mode);
    app_log_write(&app,
                  "INFO",
                  "capture start iface=%s filter=\"%s\" policy=%s mode=%d",
                  iface,
                  bpf,
                  policy,
                  mode);
    while (!g_stop)
    {
        usleep(200 * 1000);
    }

    driver_stop(&rt);
    driver_destroy(&rt);
    detect_engine_destroy(det);
    httgw_destroy(gw);
    tx_ctx_destroy(&app.rst_tx);
    packet_ring_destroy(&ring);
    app_log_write(&app, "INFO", "capture stop");
    app_log_close(&app);
    return 0;
}

/**
* @file runtime.c
* @brief IPS 런타임 핵심 로직 구현

IPS 런타임은 네트워크 패킷을 캡처하여 HTTP 메시지를 재조립하고,
탐지 엔진을 실행하여 공격 여부를 판단하는 핵심 로직을 구현합니다.
*/
#define _DEFAULT_SOURCE

#include "html.h"
#include "logging.h"

#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint16_t be16(const uint8_t *p);
static uint32_t be32(const uint8_t *p);
static int endpoint_cmp(uint32_t a_ip,
                        uint16_t a_port,
                        uint32_t b_ip,
                        uint16_t b_port);
static void normalize_flow(uint32_t sip,
                           uint16_t sport,
                           uint32_t dip,
                           uint16_t dport,
                           flow_key_t *key,
                           tcp_dir_t *dir);
static int flow_eq(const flow_key_t *a, const flow_key_t *b);
static int parse_ts_option(const uint8_t *opts,
                           uint32_t opt_len,
                           uint32_t *tsval,
                           uint32_t *tsecr);
static int hex_val(int c);
static int url_decode(const char *in,
                      size_t in_len,
                      uint8_t *out,
                      size_t out_cap,
                      size_t *out_len);
static int detect_match_decoded(detect_engine_t *det,
                                const uint8_t *data,
                                size_t len,
                                ips_context_t ctx,
                                detect_match_list_t *matches,
                                uint64_t *elapsed_us);
static int add_new_match_score(detect_match_list_t *matches,
                               size_t prev_count,
                               int *score);
static int collect_matches_for_slice(detect_engine_t *det,
                                     const uint8_t *data,
                                     size_t len,
                                     ips_context_t ctx,
                                     detect_match_list_t *matches,
                                     uint64_t *detect_elapsed_us,
                                     int decode_before_match,
                                     int *score);
static int collect_query_pairs(detect_engine_t *det,
                               const char *data,
                               size_t len,
                               detect_match_list_t *matches,
                               uint64_t *detect_elapsed_us,
                               int *score);
static const IPS_Signature *select_representative_rule(
    const detect_match_list_t *matches);

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
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

static void normalize_flow(uint32_t sip, uint16_t sport,
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

/**
 * @brief TCP 패킷 파싱, flow 키, 방향 추출하는 함수
 *
 * @param data 패킷 데이터
 * @param len 길이
 * @param flow 플로우 세션
 * @param dir 플로우 방향
 * @param flags TCP 플래그
 * @return int
 */
int parse_flow_dir_and_flags(const uint8_t *data,
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

void rst_log_cache_put(app_ctx_t *app,
                       const flow_key_t *flow,
                       const httgw_sess_snapshot_t *snap,
                       uint64_t now_ms)
{
    if (!app || !flow || !snap)
        return;
    app->rst_cache.flow = *flow;
    app->rst_cache.snap = *snap;
    app->rst_cache.expires_ms = (now_ms == 0) ? UINT64_MAX : (now_ms + 3000ULL);
    app->rst_cache.valid = 1;
}

const httgw_sess_snapshot_t *rst_log_cache_get(app_ctx_t *app,
                                               const flow_key_t *flow,
                                               uint64_t now_ms)
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

static int parse_ts_option(const uint8_t *opts,
                           uint32_t opt_len,
                           uint32_t *tsval,
                           uint32_t *tsecr)
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

void log_tcp_packet_line(const app_ctx_t *app,
                         const uint8_t *data,
                         uint32_t len,
                         const httgw_sess_snapshot_t *fallback_snap)
{
    const uint8_t *p;
    uint16_t eth_type;
    uint32_t n;
    uint32_t ihl;
    uint16_t total_len;
    uint32_t sip;
    uint32_t dip;
    const uint8_t *tcp;
    uint32_t ip_payload_len;
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint32_t thl;
    uint16_t win;
    uint32_t payload_len;
    uint32_t tsval = 0;
    uint32_t tsecr = 0;
    int has_ts = 0;
    uint32_t rel_seq = 0;
    uint32_t rel_ack = 0;
    uint32_t rel_end = 0;
    flow_key_t flow;
    tcp_dir_t dir = DIR_AB;
    httgw_sess_snapshot_t snap;
    int have_snap = 0;
    char src_ip[32];
    char dst_ip[32];
    char opts[96];

    if (!app || !app->shared || !app->shared->debug_log_enabled)
        return;
    if (!data || len < 14 + 20 + 20)
        return;

    p = data;
    eth_type = be16(p + 12);
    p += 14;
    n = len - 14;

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

    ihl = (uint32_t)(p[0] & 0x0F) * 4U;
    if (ihl < 20 || n < ihl)
        return;
    total_len = be16(p + 2);
    if (total_len < ihl || n < total_len)
        return;
    if (p[9] != IPPROTO_TCP)
        return;

    sip = be32(p + 12);
    dip = be32(p + 16);
    tcp = p + ihl;
    ip_payload_len = (uint32_t)total_len - ihl;
    if (ip_payload_len < 20)
        return;

    sport = be16(tcp + 0);
    dport = be16(tcp + 2);
    seq = be32(tcp + 4);
    ack = be32(tcp + 8);
    thl = (uint32_t)((tcp[12] >> 4) & 0x0F) * 4U;
    if (thl < 20 || ip_payload_len < thl)
        return;
    win = be16(tcp + 14);
    payload_len = ip_payload_len - thl;
    rel_seq = seq;
    rel_ack = ack;
    rel_end = seq + payload_len;

    if (thl > 20)
        has_ts = parse_ts_option(tcp + 20, thl - 20, &tsval, &tsecr);

    ip4_to_str(sip, src_ip, sizeof(src_ip));
    ip4_to_str(dip, dst_ip, sizeof(dst_ip));

    normalize_flow(sip, sport, dip, dport, &flow, &dir);
    if (app->gw && httgw_get_session_snapshot(app->gw, &flow, &snap) == 0)
    {
        have_snap = 1;
    }
    else if (fallback_snap)
    {
        snap = *fallback_snap;
        have_snap = 1;
    }

    if (have_snap)
    {
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
    {
        snprintf(opts, sizeof(opts), "options [TS val %u ecr %u]", tsval, tsecr);
    }
    else
    {
        snprintf(opts, sizeof(opts), "options []");
    }

    fprintf(stderr,
            have_snap ? "[TCP] IP %s.%u > %s.%u, rel_seq %u:%u, "
                        "rel_ack %u, win %u, %s, length %u\n"
                      : "[TCP] IP %s.%u > %s.%u, seq %u:%u, "
                        "ack %u, win %u, %s, length %u\n",
            src_ip, sport, dst_ip, dport,
            have_snap ? rel_seq : seq,
            have_snap ? rel_end : seq + payload_len,
            have_snap ? rel_ack : ack,
            win, opts, payload_len);
}

void request_rst_both(app_ctx_t *app, const flow_key_t *flow, const char *event_id)
{
    httgw_sess_snapshot_t snap;
    int rc_ab;
    int rc_ba;

    if (!app || !flow)
    {
        return;
    }

    if (httgw_get_session_snapshot(app->gw, flow, &snap) != 0)
    {
        return;


    }
    if (!snap.seen_ab || !snap.seen_ba)
    {
        app_log_write(app->shared,
                      "INFO",
                      "event=rst_skip event_id=%s reason=waiting_bidir seen_ab=%u seen_ba=%u",
                      (event_id && event_id[0] != '\0') ? event_id : "-",
                      snap.seen_ab,
                      snap.seen_ba);
        return;
    }

    rst_log_cache_put(app, flow, &snap, 0);

    rc_ab = httgw_request_rst_with_snapshot(app->gw, flow, DIR_AB, &snap);
    rc_ba = httgw_request_rst_with_snapshot(app->gw, flow, DIR_BA, &snap);

    app_log_write(app->shared,
                  (rc_ab == 0 && rc_ba == 0) ? "WARN" : "BLOCK",
                  "event=rst_request event_id=%s src_ip=%u.%u.%u.%u src_port=%u "
                  "dst_ip=%u.%u.%u.%u dst_port=%u rc_ab=%d rc_ba=%d",
                  (event_id && event_id[0] != '\0') ? event_id : "-",
                  (flow->src_ip >> 24) & 0xFF,
                  (flow->src_ip >> 16) & 0xFF,
                  (flow->src_ip >> 8) & 0xFF,
                  flow->src_ip & 0xFF,
                  flow->src_port,
                  (flow->dst_ip >> 24) & 0xFF,
                  (flow->dst_ip >> 16) & 0xFF,
                  (flow->dst_ip >> 8) & 0xFF,
                  flow->dst_ip & 0xFF,
                  flow->dst_port,
                  rc_ab,
                  rc_ba);
}

void request_block_action_v2(app_ctx_t *app, const flow_key_t *flow, const char *event_id)
{
    httgw_sess_snapshot_t snap;
    char *response = NULL;
    size_t response_len = 0;
    int rc_ab;
    int rc_ba;

    if (!app || !flow)
        return;
    if (httgw_get_session_snapshot(app->gw, flow, &snap) != 0)
        return;
    if (!snap.seen_ab || !snap.seen_ba)
    {
        app_log_write(app->shared,
                      "INFO",
                      "event=block_inject_skip event_id=%s reason=waiting_bidir seen_ab=%u seen_ba=%u",
                      (event_id && event_id[0] != '\0') ? event_id : "-",
                      snap.seen_ab,
                      snap.seen_ba);
        return;
    }

    if (!app->last_block_page_html)
    {
        request_rst_both(app, flow, event_id);
        return;
    }

    response = app_build_block_http_response(app->last_block_page_html, &response_len);
    if (!response)
    {
        app_log_write(app->shared,
                      "ERROR",
                      "event=block_inject_build_failed event_id=%s",
                      (event_id && event_id[0] != '\0') ? event_id : "-");
        request_rst_both(app, flow, event_id);
        return;
    }

    rst_log_cache_put(app, flow, &snap, 0);

    rc_ab = httgw_request_rst_with_snapshot(app->gw, flow, DIR_AB, &snap);
    rc_ba = httgw_inject_block_response_with_snapshot(app->gw,
                                                      flow,
                                                      &snap,
                                                      (const uint8_t *)response,
                                                      response_len);

    app_log_write(app->shared,
                  (rc_ab == 0 && rc_ba == 0) ? "WARN" : "BLOCK",
                  "event=block_inject event_id=%s src_ip=%u.%u.%u.%u src_port=%u "
                  "dst_ip=%u.%u.%u.%u dst_port=%u bytes=%zu rc_ab=%d rc_ba=%d",
                  (event_id && event_id[0] != '\0') ? event_id : "-",
                  (flow->src_ip >> 24) & 0xFF,
                  (flow->src_ip >> 16) & 0xFF,
                  (flow->src_ip >> 8) & 0xFF,
                  flow->src_ip & 0xFF,
                  flow->src_port,
                  (flow->dst_ip >> 24) & 0xFF,
                  (flow->dst_ip >> 16) & 0xFF,
                  (flow->dst_ip >> 8) & 0xFF,
                  flow->dst_ip & 0xFF,
                  flow->dst_port,
                  response_len,
                  rc_ab,
                  rc_ba);

    free(response);
}

static int hex_val(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F')
        return 10 + (c - 'A');
    return -1;
}

static int url_decode(const char *in, size_t in_len, uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t oi = 0;
    size_t i;

    for (i = 0; i < in_len; i++)
    {
        unsigned char c = (unsigned char)in[i];
        if (c == '%' && i + 2 < in_len)
        {
            int hi = hex_val((unsigned char)in[i + 1]);
            int lo = hex_val((unsigned char)in[i + 2]);
            if (hi < 0 || lo < 0 || oi >= out_cap)
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

static int detect_match_decoded(detect_engine_t *det,
                                const uint8_t *data,
                                size_t len,
                                ips_context_t ctx,
                                detect_match_list_t *matches,
                                uint64_t *elapsed_us)
{
    uint64_t regex_elapsed_us = 0;
    int need_decode = 0;
    int rc;
    size_t i;
    uint8_t *buf;
    size_t out_len = 0;

    rc = detect_engine_collect_matches_ctx_timed(det,
                                                 data,
                                                 len,
                                                 ctx,
                                                 matches,
                                                 &regex_elapsed_us);
    if (elapsed_us)
        *elapsed_us += regex_elapsed_us;
    if (rc != 0 || len == 0)
        return rc;

    for (i = 0; i < len; i++)
    {
        if (data[i] == '%' || data[i] == '+')
        {
            need_decode = 1;
            break;
        }
    }
    if (!need_decode)
        return 0;

    buf = (uint8_t *)malloc(len);
    if (!buf)
        return 0;

    if (url_decode((const char *)data, len, buf, len, &out_len) == 0 &&
        out_len > 0)
    {
        regex_elapsed_us = 0;
        rc = detect_engine_collect_matches_ctx_timed(det,
                                                     buf,
                                                     out_len,
                                                     ctx,
                                                     matches,
                                                     &regex_elapsed_us);
        if (elapsed_us)
            *elapsed_us += regex_elapsed_us;
    }

    free(buf);
    return rc;
}

static int add_new_match_score(detect_match_list_t *matches, size_t prev_count, int *score)
{
    size_t i;

    if (!matches || !score)
        return 0;
    for (i = prev_count; i < matches->count; i++)
        *score += matches->items[i].rule ? matches->items[i].rule->is_high_priority : 0;
    return 0;
}

static int collect_matches_for_slice(detect_engine_t *det,
                                     const uint8_t *data,
                                     size_t len,
                                     ips_context_t ctx,
                                     detect_match_list_t *matches,
                                     uint64_t *detect_elapsed_us,
                                     int decode_before_match,
                                     int *score)
{
    int rc;
    uint64_t regex_elapsed_us = 0;
    size_t prev_count = matches ? matches->count : 0;

    if (!data || len == 0)
        return 0;

    if (decode_before_match)
    {
        rc = detect_match_decoded(det, data, len, ctx, matches, detect_elapsed_us);
    }
    else
    {
        rc = detect_engine_collect_matches_ctx_timed(det,
                                                     data,
                                                     len,
                                                     ctx,
                                                     matches,
                                                     &regex_elapsed_us);
        if (detect_elapsed_us)
            *detect_elapsed_us += regex_elapsed_us;
    }
    if (rc < 0)
        return rc;
    return add_new_match_score(matches, prev_count, score);
}

static int collect_query_pairs(detect_engine_t *det,
                               const char *data,
                               size_t len,
                               detect_match_list_t *matches,
                               uint64_t *detect_elapsed_us,
                               int *score)
{
    const char *p = data;
    const char *end = data + len;

    while (p < end)
    {
        const char *amp = memchr(p, '&', (size_t)(end - p));
        const char *seg_end = amp ? amp : end;
        const char *eq = memchr(p, '=', (size_t)(seg_end - p));
        int rc;

        if (eq)
        {
            size_t name_len = (size_t)(eq - p);
            size_t val_len = (size_t)(seg_end - (eq + 1));

            rc = collect_matches_for_slice(det,
                                           (const uint8_t *)p,
                                           name_len,
                                           IPS_CTX_ARGS_NAMES,
                                           matches,
                                           detect_elapsed_us,
                                           1,
                                           score);
            if (rc < 0)
                return rc;
            rc = collect_matches_for_slice(det,
                                           (const uint8_t *)(eq + 1),
                                           val_len,
                                           IPS_CTX_ARGS,
                                           matches,
                                           detect_elapsed_us,
                                           1,
                                           score);
            if (rc < 0)
                return rc;
        }
        else if (seg_end > p)
        {
            rc = collect_matches_for_slice(det,
                                           (const uint8_t *)p,
                                           (size_t)(seg_end - p),
                                           IPS_CTX_ARGS_NAMES,
                                           matches,
                                           detect_elapsed_us,
                                           1,
                                           score);
            if (rc < 0)
                return rc;
        }

        if (!amp)
            break;
        p = amp + 1;
    }
    return 0;
}

static const IPS_Signature *select_representative_rule(
    const detect_match_list_t *matches)
{
    typedef struct
    {
        POLICY policy_id;
        int best_prio;
        int total_prio;
        size_t count;
        const IPS_Signature *best_rule;
    } policy_bucket_t;

    policy_bucket_t buckets[POLICY_MAX];
    size_t i;
    int best_idx = -1;

    if (!matches || matches->count == 0)
        return NULL;

    memset(buckets, 0, sizeof(buckets));
    for (i = 0; i < matches->count; i++)
    {
        const IPS_Signature *rule = matches->items[i].rule;
        int idx;

        if (!rule)
            continue;

        idx = (rule->policy_id >= POLICY_START && rule->policy_id < POLICY_MAX)
                  ? (int)rule->policy_id
                  : POLICY_START;

        buckets[idx].policy_id = (POLICY)idx;
        buckets[idx].total_prio += rule->is_high_priority;
        buckets[idx].count++;

        if (!buckets[idx].best_rule ||
            rule->is_high_priority > buckets[idx].best_prio)
        {
            buckets[idx].best_prio = rule->is_high_priority;
            buckets[idx].best_rule = rule;
        }
    }

    for (i = 0; i < POLICY_MAX; i++)
    {
        if (!buckets[i].best_rule)
            continue;

        if (best_idx < 0 ||
            buckets[i].best_prio > buckets[best_idx].best_prio ||
            (buckets[i].best_prio == buckets[best_idx].best_prio &&
             buckets[i].total_prio > buckets[best_idx].total_prio) ||
            (buckets[i].best_prio == buckets[best_idx].best_prio &&
             buckets[i].total_prio == buckets[best_idx].total_prio &&
             buckets[i].count > buckets[best_idx].count))
        {
            best_idx = (int)i;
        }
    }

    if (best_idx >= 0)
        return buckets[best_idx].best_rule;

    return matches->items[0].rule;
}

/**
 * @brief 탐지 엔진 실행 함수
 *
 * @param det 탐지 엔진
 * @param msg HTTP 메시지
 * @param out_score 탐지 점수 출력
 * @param matched_rule 탐지된 룰 출력
 * @param matches 탐지된 매치 리스트 출력
 * @param detect_elapsed_us 탐지에 걸린 시간 출력 (마이크로초)
 * @return int
 */
int run_detect(detect_engine_t *det,
               const http_message_t *msg,
               int *out_score,
               const IPS_Signature **matched_rule,
               detect_match_list_t *matches,
               uint64_t *detect_elapsed_us)
{
    int rc;
    int score = 0;

    if (detect_elapsed_us)
        *detect_elapsed_us = 0;
    if (matched_rule)
        *matched_rule = NULL;
    if (!det || !msg)
        return 0;
    if (matches)
        detect_match_list_init(matches);
    /* URL 전체 검사*/
    rc = collect_matches_for_slice(det, /* det = PCRE/HS */
                                   (const uint8_t *)msg->uri,
                                   strlen(msg->uri),
                                   IPS_CTX_REQUEST_URI,
                                   matches,
                                   detect_elapsed_us,
                                   1,
                                   &score);
    if (rc < 0)
        return rc;
    /* URL 안의 쿼리 스트링을 꺼내서 쪼개고 검사하는 부분 */
    if (msg->uri[0] != '\0')
    {
        const char *qm = strchr(msg->uri, '?');
        if (qm && *(qm + 1) != '\0')
        {
            const char *hash = strchr(qm + 1, '#');
            size_t qlen = hash ? (size_t)(hash - (qm + 1)) : strlen(qm + 1);

            rc = collect_query_pairs(det,
                                     qm + 1,
                                     qlen,
                                     matches,
                                     detect_elapsed_us,
                                     &score);
            if (rc < 0)
                return rc;
        }
    }
    /* body를 query string처럼 쪼개서 검사해도 되는 형식인지 확인하는 조건문*/
    if (msg->body && msg->body_len > 0 &&
        msg->content_type[0] != '\0' &&
        strstr(msg->content_type, "application/x-www-form-urlencoded") != NULL)
    { /* 조건이 다 맞으면 user, mode, payload ->ARGS_NAMES, admin, normal %27+union.. -> ARGS*/
        rc = collect_query_pairs(det,
                                 (const char *)msg->body,
                                 msg->body_len,
                                 matches,
                                 detect_elapsed_us,
                                 &score);
        if (rc < 0)
            return rc;
    }

    /* HTTP 헤더 전체 검사 */
    rc = collect_matches_for_slice(det,
                                   msg->headers_raw,
                                   msg->headers_raw_len,
                                   IPS_CTX_REQUEST_HEADERS,
                                   matches,
                                   detect_elapsed_us,
                                   0,
                                   &score);
    if (rc < 0)
        return rc;

    /* BODY 전체 검사 */
    rc = collect_matches_for_slice(det,
                                   msg->body,
                                   msg->body_len,
                                   IPS_CTX_REQUEST_BODY,
                                   matches,
                                   detect_elapsed_us,
                                   0,
                                   &score);
    if (rc < 0)
        return rc;
    /* 첫 매치 하나만 쓰면 범용 SQLi 룰이 대표 정책을 덮는 경우가 많다.
     * 대표 정책은 matches 전체에서 가장 강한(policy별 우선순위/누적점수) 룰로 고른다.
     */
    if (matched_rule)
        *matched_rule = select_representative_rule(matches);
    if (out_score)
        *out_score = score;
    return score >= APP_DETECT_THRESHOLD ? 1 : 0;
}

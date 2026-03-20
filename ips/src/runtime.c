/**
 * @file runtime.c
 * @brief IPS 런타임 패킷/탐지 보조 로직 구현
 *
 * 본 파일은 패킷 한 건에서 flow 키를 추출하고, TCP 로그 출력을 보조하며,
 * HTTP 요청 단위 탐지와 차단 후속 동작을 연결하는 런타임 helper를 담는다.
 */
#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "html.h"
#include "logging.h"

static uint16_t be16(const uint8_t *p);
static uint32_t be32(const uint8_t *p);
static int      endpoint_cmp(uint32_t a_ip, uint16_t a_port, uint32_t b_ip,
                             uint16_t b_port);
static void     normalize_flow(uint32_t sip, uint16_t sport, uint32_t dip,
                               uint16_t dport, flow_key_t *key, tcp_dir_t *dir);
static int      flow_eq(const flow_key_t *a, const flow_key_t *b);
static int      parse_ts_option(const uint8_t *opts, uint32_t opt_len,
                                uint32_t *tsval, uint32_t *tsecr);
static int      hex_val(int c);
static int      url_decode(const char *in, size_t in_len, uint8_t *out,
                           size_t out_cap, size_t *out_len);
static int      detect_match_decoded(detect_engine_t *det, const uint8_t *data,
                                     size_t len, ips_context_t ctx,
                                     detect_match_list_t *matches,
                                     uint64_t            *elapsed_us);
static int add_new_match_score(detect_match_list_t *matches, size_t prev_count,
                               int *score);
static int collect_matches_for_slice(detect_engine_t *det, const uint8_t *data,
                                     size_t len, ips_context_t ctx,
                                     detect_match_list_t *matches,
                                     uint64_t            *detect_elapsed_us,
                                     int decode_before_match, int *score);
static int collect_query_pairs(detect_engine_t *det, const char *data,
                               size_t len, detect_match_list_t *matches,
                               uint64_t *detect_elapsed_us, int *score);
static const IPS_Signature *select_representative_rule(
    const detect_match_list_t *matches);

/**
 * @brief 네트워크 바이트 순서 16비트 값을 host order로 읽는다.
 *
 * @param p 16비트 값이 놓인 바이트 포인터
 * @return uint16_t host order로 변환된 값
 */
static uint16_t be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

/**
 * @brief 네트워크 바이트 순서 32비트 값을 host order로 읽는다.
 *
 * @param p 32비트 값이 놓인 바이트 포인터
 * @return uint32_t host order로 변환된 값
 */
static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/**
 * @brief `(ip, port)` 엔드포인트 두 개를 사전식으로 비교한다.
 *
 * @param a_ip 첫 번째 IP
 * @param a_port 첫 번째 port
 * @param b_ip 두 번째 IP
 * @param b_port 두 번째 port
 * @return int a < b 이면 -1, 같으면 0, a > b 이면 1
 */
static int endpoint_cmp(uint32_t a_ip, uint16_t a_port, uint32_t b_ip,
                        uint16_t b_port) {
    if (a_ip < b_ip) {
        return -1;
    }
    if (a_ip > b_ip) {
        return 1;
    }
    if (a_port < b_port) {
        return -1;
    }
    if (a_port > b_port) {
        return 1;
    }
    return 0;
}

/**
 * @brief 5-tuple을 정규화된 flow 키와 방향으로 변환한다.
 *
 * 정규화된 flow 키는 항상 endpoint 사전식 순서를 기준으로 저장한다.
 * 실제 패킷이 정규화 순서와 같으면 `DIR_AB`, 반대면 `DIR_BA`를 반환한다.
 *
 * @param sip source IP
 * @param sport source port
 * @param dip destination IP
 * @param dport destination port
 * @param key 정규화된 flow 키 출력
 * @param dir 원래 패킷 방향 출력
 */
static void normalize_flow(uint32_t sip, uint16_t sport, uint32_t dip,
                           uint16_t dport, flow_key_t *key, tcp_dir_t *dir) {
    int c = endpoint_cmp(sip, sport, dip, dport);
    memset(key, 0, sizeof(*key));
    key->proto = 6;
    if (0 >= c) {
        key->src_ip   = sip;
        key->src_port = sport;
        key->dst_ip   = dip;
        key->dst_port = dport;
        *dir          = DIR_AB;
    } else {
        key->src_ip   = dip;
        key->src_port = dport;
        key->dst_ip   = sip;
        key->dst_port = sport;
        *dir          = DIR_BA;
    }
}

/**
 * @brief TCP 패킷에서 flow 키, 방향, TCP 플래그를 추출한다.
 *
 * Ethernet/VLAN/IPv4/TCP 헤더를 최소한으로 해석해 worker 공통 로그와
 * 세션 lookup에 필요한 정보를 만든다.
 *
 * @param data raw packet bytes
 * @param len packet length
 * @param flow 정규화된 flow 키 출력
 * @param dir 패킷 방향 출력
 * @param flags TCP 플래그 출력
 * @return int 파싱 성공 시 1, 실패 시 0
 */
int parse_flow_dir_and_flags(const uint8_t *data, uint32_t len,
                             flow_key_t *flow, tcp_dir_t *dir, uint8_t *flags) {
    const uint8_t *p = data;
    uint32_t       n;
    uint16_t       eth_type;
    uint32_t       ihl;
    uint16_t       total_len;
    uint32_t       sip;
    uint32_t       dip;
    uint16_t       sport;
    uint16_t       dport;

    if (NULL == data || (14 + 20 + 20) > len) {
        return 0;
    }

    /* Ethernet type을 읽고 VLAN tag가 있으면 안쪽 ethertype로 진입한다. */
    eth_type = be16(p + 12);
    p += 14;
    n = len - 14;

    if (0x8100 == eth_type || 0x88A8 == eth_type) {
        if (4 > n) {
            return 0;
        }
        eth_type = be16(p + 2);
        p += 4;
        n -= 4;
    }
    if (0x0800 != eth_type || 20 > n) {
        return 0;
    }
    if (4 != (p[0] >> 4)) {
        return 0;
    }

    ihl = (uint32_t)(p[0] & 0x0F) * 4U;
    if (20 > ihl || ihl > n) {
        return 0;
    }
    total_len = be16(p + 2);
    if (total_len < ihl || n < total_len) {
        return 0;
    }
    if (p[9] != IPPROTO_TCP) {
        return 0;
    }

    /* IPv4 source/destination과 TCP 4-tuple을 꺼내 flow 키로 정규화한다. */
    sip = be32(p + 12);
    dip = be32(p + 16);
    p += ihl;
    if (20 > (uint32_t)(total_len - ihl)) {
        return 0;
    }

    sport = be16(p + 0);
    dport = be16(p + 2);
    if (flags) {
        *flags = p[13];
    }
    normalize_flow(sip, sport, dip, dport, flow, dir);
    return 1;
}

/**
 * @brief 두 정규화 flow 키가 동일한지 비교한다.
 *
 * @param a 첫 번째 flow 키
 * @param b 두 번째 flow 키
 * @return int 동일하면 1, 아니면 0
 */
static int flow_eq(const flow_key_t *a, const flow_key_t *b) {
    return a && b && a->src_ip == b->src_ip && a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port && a->dst_port == b->dst_port &&
           a->proto == b->proto;
}

/**
 * @brief 최근 RST 대상 세션 snapshot을 캐시에 저장한다.
 *
 * RST 패킷이 실제 wire에서 관측될 때 live session이 이미 사라졌더라도
 * 직전 snapshot으로 로그 상대 seq/ack를 계산할 수 있도록 짧게 보존한다.
 *
 * @param app worker app context
 * @param flow flow 키
 * @param snap 저장할 세션 snapshot
 * @param now_ms 현재 시각(ms)
 */
void rst_log_cache_put(app_ctx_t *app, const flow_key_t *flow,
                       const httgw_sess_snapshot_t *snap, uint64_t now_ms) {
    if (!app || !flow || !snap) {
        return;
    }
    app->rst_cache.flow       = *flow;
    app->rst_cache.snap       = *snap;
    app->rst_cache.expires_ms = (now_ms == 0) ? UINT64_MAX : (now_ms + 3000ULL);
    app->rst_cache.valid      = 1;
}

/**
 * @brief flow에 대응하는 RST 로그용 snapshot 캐시를 조회한다.
 *
 * @param app worker app context
 * @param flow flow 키
 * @param now_ms 현재 시각(ms)
 * @return const httgw_sess_snapshot_t* 유효한 snapshot 또는 NULL
 */
const httgw_sess_snapshot_t *rst_log_cache_get(app_ctx_t        *app,
                                               const flow_key_t *flow,
                                               uint64_t          now_ms) {
    int eq;

    if (NULL == app || 0 == app->rst_cache.valid) {
        return NULL;
    }
    if (app->rst_cache.expires_ms <= now_ms) {
        app->rst_cache.valid = 0;
        return NULL;
    }
    eq = flow_eq(&app->rst_cache.flow, flow);
    if (0 == eq) {
        return NULL;
    }
    return &app->rst_cache.snap;
}

/**
 * @brief TCP option 영역에서 timestamp option을 찾아 파싱한다.
 *
 * @param opts TCP option 시작 포인터
 * @param opt_len option 길이
 * @param tsval TSval 출력
 * @param tsecr TSecr 출력
 * @return int timestamp option을 찾으면 1, 아니면 0
 */
static int parse_ts_option(const uint8_t *opts, uint32_t opt_len,
                           uint32_t *tsval, uint32_t *tsecr) {
    uint32_t i = 0;
    while (i < opt_len) {
        uint8_t kind = opts[i];
        if (0 == kind) {
            break;
        }
        if (1 == kind) {
            i++;
            continue;
        }
        if (i + 1 >= opt_len) {
            break;
        }
        uint8_t len = opts[i + 1];
        if (2 > len || i + len > opt_len) {
            break;
        }
        if (8 == kind && 10 == len) {
            *tsval = be32(opts + i + 2);
            *tsecr = be32(opts + i + 6);
            return 1;
        }
        i += len;
    }
    return 0;
}

/**
 * @brief 디버그용 TCP 패킷 한 줄 로그에 필요한 정보를 계산한다.
 *
 * 실제 로그 출력은 현재 비활성화되어 있지만, flow 정규화와 snapshot 기준
 * 상대 seq/ack 계산 규칙을 한 곳에 모아 두어 디버그 로그 포맷을 유지한다.
 *
 * @param app worker app context
 * @param data raw packet bytes
 * @param len packet length
 * @param fallback_snap live session이 없을 때 사용할 보조 snapshot
 */
void log_tcp_packet_line(const app_ctx_t *app, const uint8_t *data,
                         uint32_t                     len,
                         const httgw_sess_snapshot_t *fallback_snap) {
    const uint8_t        *p;
    uint16_t              eth_type;
    uint32_t              n;
    uint32_t              ihl;
    uint16_t              total_len;
    uint32_t              sip;
    uint32_t              dip;
    const uint8_t        *tcp;
    uint32_t              ip_payload_len;
    uint16_t              sport;
    uint16_t              dport;
    uint32_t              seq;
    uint32_t              ack;
    uint32_t              thl;
    uint32_t              payload_len;
    uint32_t              tsval   = 0;
    uint32_t              tsecr   = 0;
    int                   has_ts  = 0;
    uint32_t              rel_seq = 0;
    uint32_t              rel_ack = 0;
    uint32_t              rel_end = 0;
    flow_key_t            flow;
    tcp_dir_t             dir = DIR_AB;
    httgw_sess_snapshot_t snap;
    int                   have_snap = 0;
    char                  src_ip[32];
    char                  dst_ip[32];
    char                  opts[96];
    int                   ret;

    if (NULL == app || NULL == app->shared ||
        0 == app->shared->debug_log_enabled) {
        return;
    }
    if (NULL == data || (14 + 20 + 20) > len) {
        return;
    }

    /* 디버그 로그가 꺼져 있으면 불필요한 파싱 비용 없이 바로 종료한다. */
    p        = data;
    eth_type = be16(p + 12);
    p += 14;
    n = len - 14;

    if (0x8100 == eth_type || 0x88A8 == eth_type) {
        if (4 > n) {
            return;
        }
        eth_type = be16(p + 2);
        p += 4;
        n -= 4;
    }
    if (0x0800 != eth_type || 20 > n) {
        return;
    }
    if (4 != (p[0] >> 4)) {
        return;
    }

    ihl = (uint32_t)(p[0] & 0x0F) * 4U;
    if (20 > ihl || ihl > n) {
        return;
    }
    total_len = be16(p + 2);
    if (total_len < ihl || n < total_len) {
        return;
    }
    if (p[9] != IPPROTO_TCP) {
        return;
    }

    sip            = be32(p + 12);
    dip            = be32(p + 16);
    tcp            = p + ihl;
    ip_payload_len = (uint32_t)total_len - ihl;
    if (20 > ip_payload_len) {
        return;
    }

    sport = be16(tcp + 0);
    dport = be16(tcp + 2);
    seq   = be32(tcp + 4);
    ack   = be32(tcp + 8);
    thl   = (uint32_t)((tcp[12] >> 4) & 0x0F) * 4U;
    if (20 > thl || thl > ip_payload_len) {
        return;
    }
    payload_len = ip_payload_len - thl;
    rel_seq     = seq;
    rel_ack     = ack;
    rel_end     = seq + payload_len;

    if (20 < thl) {
        has_ts = parse_ts_option(tcp + 20, thl - 20, &tsval, &tsecr);
    }

    ip4_to_str(sip, src_ip, sizeof(src_ip));
    ip4_to_str(dip, dst_ip, sizeof(dst_ip));

    /* live session 또는 fallback snapshot을 기준으로 상대 seq/ack를 계산한다. */
    normalize_flow(sip, sport, dip, dport, &flow, &dir);
    ret = -1;
    if (NULL != app->gw) {
        ret = httgw_get_session_snapshot(app->gw, &flow, &snap);
    }
    if (0 == ret) {
        have_snap = 1;
    } else if (NULL != fallback_snap) {
        snap      = *fallback_snap;
        have_snap = 1;
    }

    if (have_snap) {
        if (dir == DIR_AB) {
            rel_seq = seq - snap.base_seq_ab;
            rel_end = rel_seq + payload_len;
            if (0 != ack && 0 != snap.seen_ba) {
                rel_ack = ack - snap.base_seq_ba;
            }
        } else {
            rel_seq = seq - snap.base_seq_ba;
            rel_end = rel_seq + payload_len;
            if (0 != ack && 0 != snap.seen_ab) {
                rel_ack = ack - snap.base_seq_ab;
            }
        }
    }

    if (has_ts) {
        snprintf(opts, sizeof(opts), "options [TS val %u ecr %u]", tsval,
                 tsecr);
    } else {
        snprintf(opts, sizeof(opts), "options []");
    }

    (void)rel_seq;
    (void)rel_ack;
    (void)rel_end;
    (void)src_ip;
    (void)dst_ip;
    (void)opts;
}

/**
 * @brief 양방향 RST burst를 요청한다.
 *
 * 차단용 HTML 응답을 주입하지 못하는 상황에서 연결을 빠르게 끊기 위한
 * fallback 경로다. 세션 snapshot을 먼저 고정해 두고 AB/BA 양방향에 대해
 * burst RST를 보낸다.
 *
 * @param app worker app context
 * @param flow 대상 flow
 * @param event_id 현재 차단 이벤트 ID
 */
void request_rst_both(app_ctx_t *app, const flow_key_t *flow,
                      const char *event_id) {
    httgw_sess_snapshot_t snap;
    int                   rc_ab;
    int                   rc_ba;
    int                   ret;

    if (NULL == app || NULL == flow) {
        return;
    }

    ret = httgw_get_session_snapshot(app->gw, flow, &snap);
    if (0 != ret) {
        return;
    }

    /* 실제 RST가 관측될 때 relative seq 로그를 복원할 수 있도록 보관한다. */
    rst_log_cache_put(app, flow, &snap, 0);

    rc_ab = httgw_request_rst_with_snapshot(app->gw, flow, DIR_AB, &snap);
    rc_ba = httgw_request_rst_with_snapshot(app->gw, flow, DIR_BA, &snap);

    app_log_write(
        app->shared, (rc_ab == 0 && rc_ba == 0) ? "WARN" : "BLOCK",
        "event=rst_request event_id=%s src_ip=%u.%u.%u.%u src_port=%u "
        "dst_ip=%u.%u.%u.%u dst_port=%u rc_ab=%d rc_ba=%d",
        (event_id && event_id[0] != '\0') ? event_id : "-",
        (flow->src_ip >> 24) & 0xFF, (flow->src_ip >> 16) & 0xFF,
        (flow->src_ip >> 8) & 0xFF, flow->src_ip & 0xFF, flow->src_port,
        (flow->dst_ip >> 24) & 0xFF, (flow->dst_ip >> 16) & 0xFF,
        (flow->dst_ip >> 8) & 0xFF, flow->dst_ip & 0xFF, flow->dst_port, rc_ab,
        rc_ba);
}

/**
 * @brief 차단 페이지 주입 또는 RST fallback을 수행한다.
 *
 * 양방향 세션이 모두 관측된 경우에만 block HTML 응답을 구성한다. 주입용
 * HTML을 만들지 못하면 즉시 RST-only 경로로 fallback 한다.
 *
 * @param app worker app context
 * @param flow 대상 flow
 * @param event_id 현재 차단 이벤트 ID
 */
void request_block_action_v2(app_ctx_t *app, const flow_key_t *flow,
                             const char *event_id) {
    httgw_sess_snapshot_t snap;
    char                 *response     = NULL;
    size_t                response_len = 0;
    int                   rc_ab;
    int                   rc_ba;
    int                   ret;

    if (NULL == app || NULL == flow) {
        return;
    }
    ret = httgw_get_session_snapshot(app->gw, flow, &snap);
    if (0 != ret) {
        return;
    }
    if (0 == snap.seen_ab || 0 == snap.seen_ba) {
        app_log_write(app->shared, "INFO",
                      "event=block_inject_fallback event_id=%s "
                      "reason=waiting_bidir seen_ab=%u seen_ba=%u",
                      (event_id && event_id[0] != '\0') ? event_id : "-",
                      snap.seen_ab, snap.seen_ba);
        request_rst_both(app, flow, event_id);
        return;
    }

    /* 차단 페이지 템플릿이 없으면 응답 주입 없이 RST 차단만 수행한다. */
    if (!app->last_block_page_html) {
        request_rst_both(app, flow, event_id);
        return;
    }

    response =
        app_build_block_http_response(app->last_block_page_html, &response_len);
    if (!response) {
        app_log_write(app->shared, "ERROR",
                      "event=block_inject_build_failed event_id=%s",
                      (event_id && event_id[0] != '\0') ? event_id : "-");
        request_rst_both(app, flow, event_id);
        return;
    }

    /* 차단 응답 후 wire에서 보이는 RST 로그 계산을 위해 snapshot을 캐시한다. */
    rst_log_cache_put(app, flow, &snap, 0);

    rc_ab = httgw_request_rst_with_snapshot(app->gw, flow, DIR_AB, &snap);
    rc_ba = httgw_inject_block_response_with_snapshot(
        app->gw, flow, &snap, (const uint8_t *)response, response_len);

    app_log_write(
        app->shared, (rc_ab == 0 && rc_ba == 0) ? "WARN" : "BLOCK",
        "event=block_inject event_id=%s src_ip=%u.%u.%u.%u src_port=%u "
        "dst_ip=%u.%u.%u.%u dst_port=%u bytes=%zu rc_ab=%d rc_ba=%d",
        (event_id && event_id[0] != '\0') ? event_id : "-",
        (flow->src_ip >> 24) & 0xFF, (flow->src_ip >> 16) & 0xFF,
        (flow->src_ip >> 8) & 0xFF, flow->src_ip & 0xFF, flow->src_port,
        (flow->dst_ip >> 24) & 0xFF, (flow->dst_ip >> 16) & 0xFF,
        (flow->dst_ip >> 8) & 0xFF, flow->dst_ip & 0xFF, flow->dst_port,
        response_len, rc_ab, rc_ba);
    app_log_write(
        app->shared, (0 == rc_ba) ? "WARN" : "ERROR",
        "event=block_page_send event_id=%s status=%s http_status=403 "
        "src_ip=%u.%u.%u.%u src_port=%u dst_ip=%u.%u.%u.%u dst_port=%u "
        "bytes=%zu rc=%d",
        (event_id && event_id[0] != '\0') ? event_id : "-",
        (0 == rc_ba) ? "sent" : "failed", (flow->src_ip >> 24) & 0xFF,
        (flow->src_ip >> 16) & 0xFF, (flow->src_ip >> 8) & 0xFF,
        flow->src_ip & 0xFF, flow->src_port, (flow->dst_ip >> 24) & 0xFF,
        (flow->dst_ip >> 16) & 0xFF, (flow->dst_ip >> 8) & 0xFF,
        flow->dst_ip & 0xFF, flow->dst_port, response_len, rc_ba);

    free(response);
}

/**
 * @brief hex 문자 하나를 0~15 값으로 변환한다.
 *
 * @param c 입력 문자
 * @return int 유효한 hex면 0~15, 아니면 -1
 */
static int hex_val(int c) {
    if ('0' <= c && '9' >= c) {
        return c - '0';
    }
    if ('a' <= c && 'f' >= c) {
        return 10 + (c - 'a');
    }
    if ('A' <= c && 'F' >= c) {
        return 10 + (c - 'A');
    }
    return -1;
}

/**
 * @brief URL-encoded 문자열을 byte sequence로 복원한다.
 *
 * `%xx`와 `+` 치환만 처리하는 단순 decoder다. 탐지 전 정규화가 필요한
 * request URI/query string 검사에서 사용한다.
 *
 * @param in 입력 문자열
 * @param in_len 입력 길이
 * @param out 출력 버퍼
 * @param out_cap 출력 버퍼 크기
 * @param out_len 실제 출력 길이
 * @return int 성공 시 0, 잘못된 escape 또는 버퍼 부족 시 -1
 */
static int url_decode(const char *in, size_t in_len, uint8_t *out,
                      size_t out_cap, size_t *out_len) {
    size_t oi = 0;
    size_t i;

    for (i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)in[i];
        if ('%' == c && in_len > i + 2) {
            int hi = hex_val((unsigned char)in[i + 1]);
            int lo = hex_val((unsigned char)in[i + 2]);
            if (0 > hi || 0 > lo || oi >= out_cap) {
                return -1;
            }
            out[oi++] = (uint8_t)((hi << 4) | lo);
            i += 2;
            continue;
        }
        if ('+' == c) {
            c = ' ';
        }
        if (oi >= out_cap) {
            return -1;
        }
        out[oi++] = (uint8_t)c;
    }
    *out_len = oi;
    return 0;
}

/**
 * @brief 원문과 URL-decoded 변형을 모두 검사해 매치를 수집한다.
 *
 * 먼저 원문에 대해 탐지를 수행하고, `%` 또는 `+`가 포함된 경우에만
 * decoded 버전을 추가 검사한다. URL 정규화가 필요 없는 입력에는 추가
 * 할당/복호화를 하지 않도록 설계되어 있다.
 *
 * @param det 탐지 엔진
 * @param data 검사할 바이트열
 * @param len 바이트열 길이
 * @param ctx 탐지 컨텍스트
 * @param matches 탐지 결과 누적 리스트
 * @param elapsed_us 탐지 시간 누적값
 * @return int 탐지 엔진 반환값
 */
static int detect_match_decoded(detect_engine_t *det, const uint8_t *data,
                                size_t len, ips_context_t ctx,
                                detect_match_list_t *matches,
                                uint64_t            *elapsed_us) {
    uint64_t regex_elapsed_us = 0;
    int      need_decode      = 0;
    int      rc;
    size_t   i;
    uint8_t *buf;
    size_t   out_len = 0;

    /* 항상 원문을 먼저 검사하고, 필요할 때만 decode된 변형을 추가로 본다. */
    rc = detect_engine_collect_matches_ctx_timed(det, data, len, ctx, matches,
                                                 &regex_elapsed_us);
    if (NULL != elapsed_us) {
        *elapsed_us += regex_elapsed_us;
    }
    if (0 != rc || 0 == len) {
        return rc;
    }

    for (i = 0; i < len; i++) {
        if ('%' == data[i] || '+' == data[i]) {
            need_decode = 1;
            break;
        }
    }
    if (!need_decode) {
        return 0;
    }

    buf = (uint8_t *)malloc(len);
    if (NULL == buf) {
        return 0;
    }

    rc = url_decode((const char *)data, len, buf, len, &out_len);
    if (0 == rc && 0U < out_len) {
        regex_elapsed_us = 0;
        rc               = detect_engine_collect_matches_ctx_timed(
            det, buf, out_len, ctx, matches, &regex_elapsed_us);
        if (NULL != elapsed_us) {
            *elapsed_us += regex_elapsed_us;
        }
    }

    free(buf);
    return rc;
}

/**
 * @brief 새로 추가된 매치들의 우선순위를 점수에 반영한다.
 *
 * @param matches 누적 매치 리스트
 * @param prev_count 이전 매치 개수
 * @param score 누적 점수 출력
 * @return int 항상 0
 */
static int add_new_match_score(detect_match_list_t *matches, size_t prev_count,
                               int *score) {
    size_t i;

    if (NULL == matches || NULL == score) {
        return 0;
    }
    for (i = prev_count; i < matches->count; i++) {
        *score += matches->items[i].rule
                      ? matches->items[i].rule->is_high_priority
                      : 0;
    }
    return 0;
}

/**
 * @brief 입력 slice 하나를 주어진 컨텍스트로 검사한다.
 *
 * decode가 필요한 컨텍스트는 `detect_match_decoded()`를 통해 원문/복호문을
 * 모두 보고, 그 외 컨텍스트는 바로 엔진 timed 매치를 수행한다.
 *
 * @param det 탐지 엔진
 * @param data 검사 데이터
 * @param len 검사 길이
 * @param ctx 탐지 컨텍스트
 * @param matches 누적 매치 리스트
 * @param detect_elapsed_us 탐지 시간 누적값
 * @param decode_before_match URL decode 후 재검사 여부
 * @param score 누적 점수
 * @return int 0이면 성공, -1이면 탐지 엔진 오류
 */
static int collect_matches_for_slice(detect_engine_t *det, const uint8_t *data,
                                     size_t len, ips_context_t ctx,
                                     detect_match_list_t *matches,
                                     uint64_t            *detect_elapsed_us,
                                     int decode_before_match, int *score) {
    int      rc;
    uint64_t regex_elapsed_us = 0;
    size_t   prev_count       = matches ? matches->count : 0;

    if (NULL == data || 0 == len) {
        return 0;
    }

    if (decode_before_match) {
        rc = detect_match_decoded(det, data, len, ctx, matches,
                                  detect_elapsed_us);
    } else {
        rc = detect_engine_collect_matches_ctx_timed(
            det, data, len, ctx, matches, &regex_elapsed_us);
        if (detect_elapsed_us) {
            *detect_elapsed_us += regex_elapsed_us;
        }
    }
    if (0 > rc) {
        return rc;
    }
    return add_new_match_score(matches, prev_count, score);
}

/**
 * @brief query string/body를 `key=value` 단위로 분해해 검사한다.
 *
 * parameter 이름은 `ARGS_NAMES`, 값은 `ARGS` 컨텍스트로 매핑해 검사한다.
 *
 * @param det 탐지 엔진
 * @param data query string 시작 포인터
 * @param len query string 길이
 * @param matches 누적 매치 리스트
 * @param detect_elapsed_us 탐지 시간 누적값
 * @param score 누적 점수
 * @return int 0이면 성공, -1이면 탐지 엔진 오류
 */
static int collect_query_pairs(detect_engine_t *det, const char *data,
                               size_t len, detect_match_list_t *matches,
                               uint64_t *detect_elapsed_us, int *score) {
    const char *p   = data;
    const char *end = data + len;

    while (p < end) {
        const char *amp     = memchr(p, '&', (size_t)(end - p));
        const char *seg_end = amp ? amp : end;
        const char *eq      = memchr(p, '=', (size_t)(seg_end - p));
        int         rc;

        if (eq) {
            size_t name_len = (size_t)(eq - p);
            size_t val_len  = (size_t)(seg_end - (eq + 1));

            rc = collect_matches_for_slice(det, (const uint8_t *)p, name_len,
                                           IPS_CTX_ARGS_NAMES, matches,
                                           detect_elapsed_us, 1, score);
            if (0 > rc) {
                return rc;
            }
            rc = collect_matches_for_slice(det, (const uint8_t *)(eq + 1),
                                           val_len, IPS_CTX_ARGS, matches,
                                           detect_elapsed_us, 1, score);
            if (0 > rc) {
                return rc;
            }
        } else if (seg_end > p) {
            rc = collect_matches_for_slice(
                det, (const uint8_t *)p, (size_t)(seg_end - p),
                IPS_CTX_ARGS_NAMES, matches, detect_elapsed_us, 1, score);
            if (0 > rc) {
                return rc;
            }
        }

        if (!amp) {
            break;
        }
        p = amp + 1;
    }
    return 0;
}

/**
 * @brief 누적 매치에서 대표 정책 룰 하나를 고른다.
 *
 * 첫 매치 하나만 쓰면 범용 룰이 정책 대표값을 덮는 경우가 있어, 정책별
 * 최고 우선순위/누적 우선순위/매치 수를 함께 비교해 대표 룰을 선택한다.
 *
 * @param matches 누적 매치 리스트
 * @return const IPS_Signature* 대표 룰 또는 NULL
 */
static const IPS_Signature *select_representative_rule(
    const detect_match_list_t *matches) {
    typedef struct {
        POLICY               policy_id;
        int                  best_prio;
        int                  total_prio;
        size_t               count;
        const IPS_Signature *best_rule;
    } policy_bucket_t;

    policy_bucket_t buckets[POLICY_MAX];
    size_t          i;
    int             best_idx = -1;

    if (NULL == matches || 0 == matches->count) {
        return NULL;
    }

    memset(buckets, 0, sizeof(buckets));
    for (i = 0; i < matches->count; i++) {
        const IPS_Signature *rule = matches->items[i].rule;
        int                  idx;

        if (!rule) {
            continue;
        }

        idx = (rule->policy_id >= POLICY_START && rule->policy_id < POLICY_MAX)
                  ? (int)rule->policy_id
                  : POLICY_START;

        buckets[idx].policy_id = (POLICY)idx;
        buckets[idx].total_prio += rule->is_high_priority;
        buckets[idx].count++;

        if (!buckets[idx].best_rule ||
            rule->is_high_priority > buckets[idx].best_prio) {
            buckets[idx].best_prio = rule->is_high_priority;
            buckets[idx].best_rule = rule;
        }
    }

    for (i = 0; i < POLICY_MAX; i++) {
        if (!buckets[i].best_rule) {
            continue;
        }

        if (0 > best_idx ||
            buckets[i].best_prio > buckets[best_idx].best_prio ||
            (buckets[i].best_prio == buckets[best_idx].best_prio &&
             buckets[i].total_prio > buckets[best_idx].total_prio) ||
            (buckets[i].best_prio == buckets[best_idx].best_prio &&
             buckets[i].total_prio == buckets[best_idx].total_prio &&
             buckets[i].count > buckets[best_idx].count)) {
            best_idx = (int)i;
        }
    }

    if (0 <= best_idx) {
        return buckets[best_idx].best_rule;
    }

    return matches->items[0].rule;
}

/**
 * @brief HTTP 요청 하나에 대해 모든 탐지 컨텍스트를 실행한다.
 *
 * 검사 순서는 URI -> query string -> form body -> raw headers -> raw body다.
 * 최종 점수는 새로 추가된 룰의 우선순위를 누적해 계산하며, threshold 이상이면
 * 차단 대상으로 간주한다.
 *
 * @param det 탐지 엔진
 * @param msg HTTP 메시지
 * @param out_score 누적 탐지 점수 출력
 * @param matched_rule 대표 룰 출력
 * @param matches 세부 매치 리스트 출력
 * @param detect_elapsed_us 탐지에 걸린 시간(us) 누적 출력
 * @return int 0이면 정상 완료, -1이면 탐지 엔진 오류
 */
int run_detect(detect_engine_t *det, const http_message_t *msg, int *out_score,
               const IPS_Signature **matched_rule, detect_match_list_t *matches,
               uint64_t *detect_elapsed_us) {
    int rc;
    int score = 0;

    if (detect_elapsed_us) {
        *detect_elapsed_us = 0;
    }
    if (matched_rule) {
        *matched_rule = NULL;
    }
    if (!det || !msg) {
        return 0;
    }
    if (matches) {
        detect_match_list_init(matches);
    }
    /* URI 전체 문자열을 먼저 검사한다. */
    rc = collect_matches_for_slice(det, /* det = PCRE/HS */
                                   (const uint8_t *)msg->uri, strlen(msg->uri),
                                   IPS_CTX_REQUEST_URI, matches,
                                   detect_elapsed_us, 1, &score);
    if (0 > rc) {
        return rc;
    }
    /* URI에 query string이 있으면 `key=value` 단위로 분해해 별도 검사한다. */
    if ('\0' != msg->uri[0]) {
        const char *qm = strchr(msg->uri, '?');
        if (NULL != qm && '\0' != *(qm + 1)) {
            const char *hash = strchr(qm + 1, '#');
            size_t qlen = hash ? (size_t)(hash - (qm + 1)) : strlen(qm + 1);

            rc = collect_query_pairs(det, qm + 1, qlen, matches,
                                     detect_elapsed_us, &score);
            if (0 > rc) {
                return rc;
            }
        }
    }
    /* form-urlencoded body는 query string과 동일한 규칙으로 재검사한다. */
    if (NULL != msg->body && 0 < msg->body_len && '\0' != msg->content_type[0] &&
        strstr(msg->content_type, "application/x-www-form-urlencoded") !=
            NULL) {
        rc = collect_query_pairs(det, (const char *)msg->body, msg->body_len,
                                 matches, detect_elapsed_us, &score);
        if (0 > rc) {
            return rc;
        }
    }

    /* raw header block 전체를 한 번 더 검사한다. */
    rc = collect_matches_for_slice(det, msg->headers_raw, msg->headers_raw_len,
                                   IPS_CTX_REQUEST_HEADERS, matches,
                                   detect_elapsed_us, 0, &score);
    if (0 > rc) {
        return rc;
    }

    /* raw body 전체도 별도 컨텍스트로 검사한다. */
    rc = collect_matches_for_slice(det, msg->body, msg->body_len,
                                   IPS_CTX_REQUEST_BODY, matches,
                                   detect_elapsed_us, 0, &score);
    if (0 > rc) {
        return rc;
    }
    /* 첫 매치 하나만 쓰면 범용 SQLi 룰이 대표 정책을 덮는 경우가 많다.
     * 대표 정책은 matches 전체에서 가장 강한(policy별 우선순위/누적점수) 룰로
     * 고른다.
     */
    if (matched_rule) {
        *matched_rule = select_representative_rule(matches);
    }
    if (out_score) {
        *out_score = score;
    }
    return 0;
}

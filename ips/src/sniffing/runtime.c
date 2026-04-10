/**
 * @file runtime.c
 * @brief IPS 런타임 패킷/탐지 보조 로직 구현
 *
 * 본 파일은 패킷 한 건에서 flow 키를 추출하고, TCP 로그 출력을 보조하며,
 * HTTP 요청 단위 탐지와 차단 후속 동작을 연결하는 런타임 helper를 담는다.
 * 즉 `main.c`와 `detect.c/html.c/logging.c` 사이를 이어 주는 glue code
 * 성격이다.
 */
#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common/html.h"
#include "logging.h"

static run_detect_metrics_t g_run_detect_metrics;

static int build_block_http_response(uint8_t *out, size_t out_cap,
                                     size_t *out_len,
                                     const char *event_id,
                                     const char *timestamp,
                                     const char *client_ip) {
    static const char fallback_body[] = "blocked by mini-ips\n";
    char             *html_body;
    char             *http_resp;
    size_t            http_resp_len;
    int               n;

    if (NULL == out || NULL == out_len || 0U == out_cap) {
        return -1;
    }

    html_body = app_render_block_page(NULL, event_id, timestamp, client_ip);
    if (NULL != html_body) {
        http_resp = app_build_block_http_response(html_body, &http_resp_len);
        free(html_body);
        if (NULL != http_resp) {
            if (http_resp_len < out_cap) {
                memcpy(out, http_resp, http_resp_len);
                out[http_resp_len] = '\0';
                *out_len = http_resp_len;
                free(http_resp);
                return 0;
            }
            free(http_resp);
        }
    }

    n = snprintf((char *)out, out_cap,
                 "HTTP/1.1 403 Forbidden\r\n"
                 "Content-Type: text/plain\r\n"
                 "Content-Length: %zu\r\n"
                 "Connection: close\r\n"
                 "X-Mini-IPS-Block: 1\r\n"
                 "\r\n"
                 "%s",
                 sizeof(fallback_body) - 1U, fallback_body);
    if (0 > n || (size_t)n >= out_cap) {
        return -1;
    }

    *out_len = (size_t)n;
    return 0;
}

/* --------------------------- packet / flow parsing helpers
 * --------------------------- */

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
    /* endpoint 정렬 결과 */
    int c = endpoint_cmp(sip, sport, dip, dport);
    /* 출력 flow key 초기화 */
    memset(key, 0, sizeof(*key));
    /* 현재 helper는 TCP flow만 생성 */
    key->proto = 6;
    /* 오름차순 endpoint를 정규화 기준으로 사용 */
    if (0 >= c) {
        key->src_ip   = sip;
        key->src_port = sport;
        key->dst_ip   = dip;
        key->dst_port = dport;
        *dir          = DIR_AB;
    } else {
        /* 반대 방향 패킷이면 endpoint를 뒤집고 BA로 표시 */
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
    /* 현재 파싱 위치 */
    const uint8_t *p = data;
    /* Ethernet 이후 남은 바이트 수 */
    uint32_t n;
    /* Ethernet type */
    uint16_t eth_type;
    /* IPv4 header length */
    uint32_t ihl;
    /* IPv4 total length */
    uint16_t total_len;
    /* src/dst IPv4 */
    uint32_t sip;
    uint32_t dip;
    /* src/dst TCP port */
    uint16_t sport;
    uint16_t dport;

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
    /* NULL flow 방지 */
    if (NULL == a || NULL == b) {
        return 0;
    }

    /* source IP 비교 */
    if (a->src_ip != b->src_ip) {
        return 0;
    }

    /* destination IP 비교 */
    if (a->dst_ip != b->dst_ip) {
        return 0;
    }

    /* source port 비교 */
    if (a->src_port != b->src_port) {
        return 0;
    }

    /* destination port 비교 */
    if (a->dst_port != b->dst_port) {
        return 0;
    }

    /* protocol 비교 */
    if (a->proto != b->proto) {
        return 0;
    }

    return 1;
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
    /* flow 비교 결과 */
    int eq;

    /* app 또는 cache 유효성 검사 */
    if (NULL == app || 0 == app->rst_cache.valid) {
        return NULL;
    }

    /* flow 포인터 검사 */
    if (NULL == flow) {
        return NULL;
    }

    /* 만료 캐시 제거 */
    if (app->rst_cache.expires_ms <= now_ms) {
        app->rst_cache.valid = 0;
        return NULL;
    }

    /* flow 일치 여부 확인 */
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
    /* TCP option 순회 인덱스 */
    uint32_t i = 0;
    while (i < opt_len) {
        /* 현재 option kind */
        uint8_t kind = opts[i];
        if (0 == kind) {
            break;
        }
        /* NOP은 1바이트만 소비 */
        if (1 == kind) {
            i++;
            continue;
        }
        /* option length 바이트 접근 가능 여부 */
        if (i + 1 >= opt_len) {
            break;
        }
        /* 현재 option 길이 */
        uint8_t len = opts[i + 1];
        /* 잘못된 길이면 option 파싱 중단 */
        if (2 > len || i + len > opt_len) {
            break;
        }
        /* kind 8, len 10이면 TCP timestamp option */
        if (8 == kind && 10 == len) {
            *tsval = be32(opts + i + 2);
            *tsecr = be32(opts + i + 6);
            return 1;
        }
        /* 다음 option으로 이동 */
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
    /* 현재 Ethernet/IP 파싱 위치 */
    const uint8_t *p;
    /* Ethernet type */
    uint16_t eth_type;
    /* Ethernet 이후 남은 바이트 수 */
    uint32_t n;
    /* IPv4 header length */
    uint32_t ihl;
    /* IPv4 total length */
    uint16_t total_len;
    /* src/dst IPv4 */
    uint32_t sip;
    uint32_t dip;
    /* TCP 헤더 시작 포인터 */
    const uint8_t *tcp;
    /* IPv4 payload 길이 */
    uint32_t ip_payload_len;
    /* src/dst TCP port */
    uint16_t sport;
    uint16_t dport;
    /* raw seq/ack */
    uint32_t seq;
    uint32_t ack;
    /* TCP header length */
    uint32_t thl;
    /* TCP payload 길이 */
    uint32_t payload_len;
    /* TCP timestamp option 값 */
    uint32_t tsval = 0;
    uint32_t tsecr = 0;
    /* timestamp option 존재 여부 */
    int has_ts = 0;
    /* snapshot 기준 상대 seq/ack/end */
    uint32_t rel_seq = 0;
    uint32_t rel_ack = 0;
    uint32_t rel_end = 0;
    /* 정규화 flow와 방향 */
    flow_key_t flow;
    tcp_dir_t  dir = DIR_AB;
    /* live session snapshot */
    httgw_sess_snapshot_t snap;
    /* snapshot 확보 여부 */
    int have_snap = 0;
    /* 로그용 IP 문자열 */
    char src_ip[32];
    char dst_ip[32];
    /* 로그용 TCP options 문자열 */
    char opts[96];
    /* helper 반환값 */
    int ret;

    /* 디버그 로그가 꺼져 있으면 파싱 자체를 생략한다 */
    if (NULL == app || NULL == app->shared ||
        0 == app->shared->debug_log_enabled) {
        return;
    }
    /* 최소 Ethernet + IPv4 + TCP 헤더 길이 검사 */
    if (NULL == data || (14 + 20 + 20) > len) {
        return;
    }

    /* Ethernet 헤더부터 파싱을 시작한다 */
    p        = data;
    eth_type = be16(p + 12);
    p += 14;
    n = len - 14;

    /* 단일 VLAN 태그가 있으면 inner EtherType로 진입한다 */
    if (0x8100 == eth_type || 0x88A8 == eth_type) {
        if (4 > n) {
            return;
        }
        eth_type = be16(p + 2);
        p += 4;
        n -= 4;
    }
    /* IPv4/TCP 패킷만 디버그 로그 대상으로 본다 */
    if (0x0800 != eth_type || 20 > n) {
        return;
    }
    if (4 != (p[0] >> 4)) {
        return;
    }

    /* IPv4 기본 필드 추출 */
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

    /* TCP 기본 필드 추출 */
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

    /* TCP option이 있으면 timestamp option을 확인한다 */
    if (20 < thl) {
        has_ts = parse_ts_option(tcp + 20, thl - 20, &tsval, &tsecr);
    }

    /* 사람이 읽을 수 있는 점표기 IP 문자열로 변환 */
    ip4_to_str(sip, src_ip, sizeof(src_ip));
    ip4_to_str(dip, dst_ip, sizeof(dst_ip));

    /* live session 또는 fallback snapshot을 기준으로 상대 seq/ack를 계산한다.
     */
    normalize_flow(sip, sport, dip, dport, &flow, &dir);
    ret = -1;
    /* live session snapshot을 우선 사용한다 */
    if (NULL != app->gw) {
        ret = httgw_get_session_snapshot(app->gw, &flow, &snap);
    }
    /* live session이 없으면 fallback snapshot을 사용한다 */
    if (0 == ret) {
        have_snap = 1;
    } else if (NULL != fallback_snap) {
        snap      = *fallback_snap;
        have_snap = 1;
    }

    /* snapshot이 있으면 raw seq/ack를 상대값으로 변환한다 */
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

    /* timestamp option 유무에 따라 로그용 options 문자열 구성 */
    if (has_ts) {
        snprintf(opts, sizeof(opts), "options [TS val %u ecr %u]", tsval,
                 tsecr);
    } else {
        memcpy(opts, "options []", sizeof("options []"));
    }

    /* 현재는 실제 로그 출력 없이 계산 결과만 검증한다 */
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
    /* 현재 세션 snapshot */
    httgw_sess_snapshot_t snap;
    /* 양방향 RST 요청 결과 */
    int rc_ab;
    int rc_ba;
    /* helper 반환값 */
    int ret;

    /* app/flow가 없으면 차단 동작 자체를 수행할 수 없다 */
    if (NULL == app || NULL == flow) {
        return;
    }

    /* 양방향 RST 계산 기준이 될 현재 세션 snapshot 확보 */
    ret = httgw_get_session_snapshot(app->gw, flow, &snap);
    if (0 != ret) {
        return;
    }

    /* 실제 RST가 관측될 때 relative seq 로그를 복원할 수 있도록 보관한다. */
    rst_log_cache_put(app, flow, &snap, 0);

    /* 클라이언트 방향 RST 요청 */
    rc_ab = httgw_request_rst_with_snapshot(app->gw, flow, DIR_AB, &snap);
    /* 서버 방향 RST 요청 */
    rc_ba = httgw_request_rst_with_snapshot(app->gw, flow, DIR_BA, &snap);

    /* 양방향 RST 요청 결과를 구조화 로그 한 줄로 남긴다 */
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
 * @brief 차단 대상 flow에 대해 항상 양방향 RST만 요청한다.
 *
 * 과거에는 조건에 따라 차단 페이지(HTTP 403) 주입을 시도했지만,
 * 현재 정책은 차단 경로를 단순화해 서버/클라이언트 양방향 RST만 보낸다.
 *
 * @param app worker app context
 * @param flow 대상 flow
 * @param request_dir 현재 요청이 관측된 방향
 * @param event_id 현재 차단 이벤트 ID
 */
void request_block_action_v2(app_ctx_t *app, const flow_key_t *flow,
                             tcp_dir_t request_dir, const char *event_id) {
    httgw_sess_snapshot_t snap;
    tcp_dir_t             response_dir;
    uint8_t               response[16384];
    size_t                response_len;
    char                  event_ts[64];
    char                  client_ip[32];
    uint32_t              client_ip_raw;
    int                   rc;

    if (NULL == app || NULL == flow) {
        return;
    }

    rc = httgw_get_session_snapshot(app->gw, flow, &snap);
    if (0 != rc) {
        return;
    }

    if (0 != app_make_timestamp(event_ts, sizeof(event_ts))) {
        snprintf(event_ts, sizeof(event_ts), "-");
    }

    client_ip_raw = (DIR_AB == request_dir) ? flow->src_ip : flow->dst_ip;
    ip4_to_str(client_ip_raw, client_ip, sizeof(client_ip));

    rc = build_block_http_response(response, sizeof(response), &response_len,
                                   event_id, event_ts, client_ip);
    if (0 != rc) {
        return;
    }

    response_dir = (DIR_AB == request_dir) ? DIR_BA : DIR_AB;
    rc = httgw_inject_block_response_with_snapshot(app->gw, flow, response_dir,
                                                   &snap, response,
                                                   response_len);

    app_log_write(
        app->shared, (0 == rc) ? "WARN" : "ERROR",
        "event=block_inject event_id=%s response_dir=%s rc=%d",
        (event_id && event_id[0] != '\0') ? event_id : "-",
        (DIR_AB == response_dir) ? "AB" : "BA", rc);
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
    /* 새 매치 순회 인덱스 */
    size_t i;

    /* 출력 포인터 없으면 아무 점수도 더하지 않는다 */
    if (NULL == matches || NULL == score) {
        return 0;
    }
    /* 이번 slice에서 새로 추가된 매치만 점수에 반영한다 */
    for (i = prev_count; i < matches->count; i++) {
        *score += matches->items[i].rule
                      ? matches->items[i].rule->is_high_priority
                      : 0;
    }
    return 0;
}

static void count_collect_call(ips_context_t ctx) {
    /* 총 collect 호출 수 증가 */
    g_run_detect_metrics.total_collect_calls++;

    switch (ctx) {
    case IPS_CTX_REQUEST_URI:
        g_run_detect_metrics.uri_calls++;
        break;
    case IPS_CTX_ARGS:
        g_run_detect_metrics.args_calls++;
        break;
    case IPS_CTX_ARGS_NAMES:
        g_run_detect_metrics.args_names_calls++;
        break;
    case IPS_CTX_REQUEST_HEADERS:
        g_run_detect_metrics.headers_calls++;
        break;
    case IPS_CTX_REQUEST_BODY:
        g_run_detect_metrics.body_calls++;
        break;
    default:
        break;
    }
}

/**
 * @brief 입력 slice 하나를 주어진 컨텍스트로 검사한다.
 *
 * 현재는 입력 slice 원문만 timed match로 검사한다.
 *
 * @param det 탐지 엔진
 * @param data 검사 데이터
 * @param len 검사 길이
 * @param ctx 탐지 컨텍스트
 * @param matches 누적 매치 리스트
 * @param detect_elapsed_us 탐지 시간 누적값
 * @param decode_before_match 미사용 인자
 * @param score 누적 점수
 * @return int 0이면 성공, -1이면 탐지 엔진 오류
 */
static int collect_matches_for_slice(detect_engine_t *det, const uint8_t *data,
                                     size_t len, ips_context_t ctx,
                                     detect_match_list_t *matches,
                                     uint64_t            *detect_elapsed_us,
                                     int decode_before_match, int *score) {
    /* 하위 탐지 함수 반환값 */
    int rc;
    /* 이번 slice의 regex 시간 */
    uint64_t regex_elapsed_us = 0;
    /* 탐지 전 매치 개수 */
    size_t prev_count = matches ? matches->count : 0;

    /* 빈 slice 건너뜀 */
    if (NULL == data || 0 == len) {
        return 0;
    }

    /* 컨텍스트별 collect 호출 수 집계 */
    count_collect_call(ctx);

    /* 현재는 decode 없이 원문 그대로 timed 매치 수행 */
    (void)decode_before_match;
    rc = detect_engine_collect_matches_ctx_timed(det, data, len, ctx, matches,
                                                 &regex_elapsed_us);
    if (detect_elapsed_us) {
        *detect_elapsed_us += regex_elapsed_us;
    }

    /* 엔진 오류 전파 */
    if (0 > rc) {
        return rc;
    }

    /* 새 매치 점수 반영 */
    return add_new_match_score(matches, prev_count, score);
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
    /* 정책별 대표성 계산 버킷 */
    typedef struct {
        POLICY               policy_id;
        int                  best_prio;
        int                  total_prio;
        size_t               count;
        const IPS_Signature *best_rule;
    } policy_bucket_t;

    /* 정책별 누적 버킷 */
    policy_bucket_t buckets[POLICY_MAX];
    /* 매치 순회 인덱스 */
    size_t i;
    /* 현재까지 선택된 대표 정책 인덱스 */
    int best_idx = -1;

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
               const char *query, size_t query_len,
               const IPS_Signature **matched_rule, detect_match_list_t *matches,
               uint64_t *detect_elapsed_us) {
    int rc;
    int score = 0;

    /* 탐지 시간 초기화 */
    if (detect_elapsed_us) {
        *detect_elapsed_us = 0;
    }

    /* 대표 룰 초기화 */
    if (matched_rule) {
        *matched_rule = NULL;
    }

    /* 입력 유효성 검사 */
    if (!det || !msg) {
        return 0;
    }

    /* 현재는 파라미터 단위 재분해 탐지를 비활성화한다 */
    (void)query;
    (void)query_len;

    /* 매치 리스트 초기화 */
    if (matches) {
        detect_match_list_init(matches);
    }

    /* URI 컨텍스트 검사 */
    rc = collect_matches_for_slice(det, (const uint8_t *)msg->uri,
                                   strlen(msg->uri), IPS_CTX_REQUEST_URI,
                                   matches, detect_elapsed_us, 1, &score);
    if (0 > rc) {
        return rc;
    }

    /* query/form 파라미터를 ARGS/ARGS_NAMES로 재분해하는 추가 탐지는 생략한다
     */

    /* raw header block 검사 */
    rc = collect_matches_for_slice(det, msg->headers_raw, msg->headers_raw_len,
                                   IPS_CTX_REQUEST_HEADERS, matches,
                                   detect_elapsed_us, 0, &score);
    if (0 > rc) {
        return rc;
    }

    /* raw body 컨텍스트 검사 */
    rc = collect_matches_for_slice(det, msg->body, msg->body_len,
                                   IPS_CTX_REQUEST_BODY, matches,
                                   detect_elapsed_us, 0, &score);
    if (0 > rc) {
        return rc;
    }

    /* 대표 정책 룰 선택 */
    if (matched_rule) {
        *matched_rule = select_representative_rule(matches);
    }

    /* 최종 점수 반환 */
    if (out_score) {
        *out_score = score;
    }
    return 0;
}

void run_detect_metrics_reset(void) {
    /* collect 호출 카운터 초기화 */
    memset(&g_run_detect_metrics, 0, sizeof(g_run_detect_metrics));
}

void run_detect_metrics_get(run_detect_metrics_t *out) {
    /* 출력 포인터 검사 */
    if (NULL == out) {
        return;
    }

    /* 현재 metrics 스냅샷 반환 */
    *out = g_run_detect_metrics;
}

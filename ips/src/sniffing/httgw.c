/**
 * @file httgw.c
 * @brief HTTP 게이트웨이, TCP 재조립, RST 처리 구현
 *
 * raw packet을 받아 flow 정규화, 세션 관리, TCP 상태 추적, reasm 연계,
 * http_stream 연계, 차단 응답/RST 송신까지 연결하는 중심 계층이다.
 */
#include "httgw.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "net_compat.h"
#include "reasm.h"

/* ---------- seq 비교(랩어라운드 고려) ---------- */
static inline int32_t seq_diff(uint32_t a, uint32_t b) {
    return (int32_t)(a - b);
}

#define SEQ_LT(a, b) (seq_diff((a), (b)) < 0)
#define SEQ_LEQ(a, b) (seq_diff((a), (b)) <= 0)
#define SEQ_GT(a, b) (seq_diff((a), (b)) > 0)
#define SEQ_GEQ(a, b) (seq_diff((a), (b)) >= 0)

/* */
#define HTTGW_INJECT_SEGMENT_BYTES 1200U

/**
 * @brief HTTP gateway 최상위 상태.
 *
 * `httgw`는 단순 HTTP 파서가 아니라,
 * 1. raw packet 파싱
 * 2. flow 정규화 및 세션 관리
 * 3. TCP 재조립 엔진 연계
 * 4. 방향별 HTTP 스트림 파서 연계
 * 5. 차단 응답/RST 송신
 * 을 모두 묶는 coordinator 역할을 한다.
 */
struct httgw {
    reasm_ctx_t *reasm;           /* TCP 재조립 엔진 */
    http_stream_cfg_t stream_cfg; /* 세션 생성 시 사용할 HTTP 파서 설정 */
    httgw_callbacks_t cbs;        /* 상위 요청/오류 콜백 */

    void         *user;    /* 상위 계층이 넘긴 사용자 컨텍스트 */
    httgw_stats_t stats;   /* 누적 HTTP/오류 통계 */
    int           verbose; /* 디버그 출력 여부 */

    /* 송신 경로 핸들 + RST 송신함수*/
    void             *tx_ctx;      /* raw L3 송신 컨텍스트 */
    httgw_send_rst_fn tx_send_rst; /* 실제 RST 송신 함수 포인터 */

    httgw_session_t **sess_buckets; /* flow 기반 세션 해시 테이블 */
    uint32_t          sess_bucket_count; /* 해시 버킷 수 */
    uint32_t          sess_count;        /* 현재 live 세션 수 */
};

struct ip_hash {
    ip_node_t **buckets;
    size_t      nbuckets;
};

#if defined(__GNUC__)
#define HTTGW_UNUSED __attribute__((unused))
#endif

/**
 * @brief flow 하나에 대한 런타임 세션 상태.
 *
 * 핵심은 방향별(`DIR_AB`, `DIR_BA`) HTTP 스트림 파서 2개와
 * RST/차단 응답 계산에 필요한 TCP 상태 snapshot을 함께 유지한다는 점이다.
 */
struct httgw_session {
    flow_key_t     flow;       /* 정규화된 5-tuple key */
    http_stream_t *streams[2]; /* 방향별 HTTP 스트림 파서 */

    uint32_t base_seq_ab;  /* AB 방향에서 처음 본 seq */
    uint32_t base_seq_ba;  /* BA 방향에서 처음 본 seq */
    uint32_t last_seq_ab;  /* 최근 AB 세그먼트의 시작 seq */
    uint32_t next_seq_ab;  /* 최근 AB 세그먼트 기준 다음 seq */
    uint32_t last_ack_ab;  /* 최근 AB 방향 ack */
    uint32_t last_seq_ba;  /* 최근 BA 세그먼트의 시작 seq */
    uint32_t next_seq_ba;  /* 최근 BA 세그먼트 기준 다음 seq */
    uint32_t last_ack_ba;  /* 최근 BA 방향 ack */
    uint16_t win_ab;       /* 최근 AB advertised window */
    uint16_t win_ba;       /* 최근 BA advertised window */
    uint8_t  win_scale_ab; /* AB SYN에서 관측한 window scale */
    uint8_t  win_scale_ba; /* BA SYN에서 관측한 window scale */

    uint8_t seen_ab;
    uint8_t seen_ba;  // 해당 방향 패킷을 봤는지?

    uint64_t last_ts_ms;  // 세션 타임아웃/GC용

    uint8_t fin_seen_ab;
    uint8_t fin_seen_ba;  // 종료 상태 추적
    uint8_t rst_sent_ab;
    uint8_t rst_sent_ba;

    struct httgw_session *next;
};

/* --------------------------- session table --------------------------- */
#define HTTGW_SESS_BUCKETS 4096
#define HTTGW_SESS_TIMEOUT_MS (60ULL * 1000ULL)
#define HTTGW_RST_BURST_COUNT 5U

static void sess_destroy(httgw_session_t *s) {
    /* 세션 포인터 없으면 종료 */
    if (!s) {
        return;
    }
    /* AB 방향 HTTP 스트림 정리 */
    if (s->streams[DIR_AB]) {
        http_stream_destroy(s->streams[DIR_AB]);
    }
    /* BA 방향 HTTP 스트림 정리 */
    if (s->streams[DIR_BA]) {
        http_stream_destroy(s->streams[DIR_BA]);
    }
    /* 세션 본체 해제 */
    free(s);
}

/* --------------------------- flow/session helpers ---------------------------
 */

/**
 * @brief flow key를 세션 해시 테이블 인덱스로 매핑한다.
 *
 * 여기서의 flow는 이미 정규화된 키이므로, 방향이 달라도 같은 TCP 연결이면
 * 동일한 해시 결과를 갖는다.
 */
static uint32_t sess_flow_hash(const flow_key_t *k) {
    /* FNV 계열 해시 상수 */
    const uint32_t prime = 16777619u;
    /* FNV offset basis */
    uint32_t h = 2166136261u;
    /* 포트 쌍을 32비트로 묶은 값 */
    uint32_t ports;

    /* src/dst 포트를 한 번에 결합 */
    ports = ((uint32_t)k->src_port << 16) | k->dst_port;

    /* src_ip 반영 */
    h ^= (uint32_t)k->src_ip;
    h *= prime;

    /* dst_ip 반영 */
    h ^= (uint32_t)k->dst_ip;
    h *= prime;

    /* 포트 쌍 반영 */
    h ^= ports;
    h *= prime;

    /* 프로토콜 반영 */
    h ^= (uint32_t)k->proto;
    h *= prime;

    /* 최종 해시 반환 */
    return h;
}

static int sess_flow_eq(const flow_key_t *a, const flow_key_t *b) {
    /* src_ip 다르면 다른 flow */
    if (a->src_ip != b->src_ip) {
        return 0;
    }
    /* dst_ip 다르면 다른 flow */
    if (a->dst_ip != b->dst_ip) {
        return 0;
    }
    /* src_port 다르면 다른 flow */
    if (a->src_port != b->src_port) {
        return 0;
    }
    /* dst_port 다르면 다른 flow */
    if (a->dst_port != b->dst_port) {
        return 0;
    }
    /* proto 다르면 다른 flow */
    if (a->proto != b->proto) {
        return 0;
    }

    /* 5-tuple 모두 같으면 같은 flow */
    return 1;
}

/* --------------------------- ip hash table (unused for now)
 * --------------------------- */
static uint32_t HTTGW_UNUSED ip_hash_fn(uint32_t ip) {
    ip ^= ip >> 16;
    ip *= 0x7feb352d;
    ip ^= ip >> 15;
    ip *= 0x846ca68b;
    ip ^= ip >> 16;
    return ip;
}

static httgw_session_t *sess_find(const httgw_t *gw, const flow_key_t *flow) {
    /* flow 해시로 버킷 선택 */
    uint32_t idx = sess_flow_hash(flow) % gw->sess_bucket_count;
    /* 같은 버킷 체인 순회 */
    for (httgw_session_t *s = gw->sess_buckets[idx]; s; s = s->next) {
        /* 현재 노드의 flow 일치 여부 */
        int eq;

        eq = sess_flow_eq(&s->flow, flow);
        if (0 != eq) {
            /* 일치 세션 반환 */
            return s;
        }
    }
    /* 일치 세션 없음 */
    return NULL;
}

/**
 * @brief 세션을 해시 테이블에서 제거하되, 메모리 해제는 호출자에게 맡긴다.
 *
 * 재조립 오류나 RST 관측 시에는 먼저 테이블에서 unlink 한 뒤,
 * 이후 정리/로그 순서를 호출자가 결정할 수 있게 분리해 둔다.
 */
static httgw_session_t *sess_remove_internal(httgw_t          *gw,
                                             const flow_key_t *flow) {
    /* 제거 대상이 속한 버킷 인덱스 */
    uint32_t idx;
    /* unlink를 위한 이전 next 포인터 주소 */
    httgw_session_t **pp;
    /* flow 비교 결과 */
    int eq;

    /* 기본 인자 검증 */
    if (NULL == gw || NULL == flow) {
        return NULL;
    }

    /* flow 해시로 버킷 선택 */
    idx = sess_flow_hash(flow) % gw->sess_bucket_count;
    /* 단일 연결 리스트 unlink 시작점 */
    pp = &gw->sess_buckets[idx];
    while (*pp) {
        /* 현재 세션이 제거 대상인지 비교 */
        eq = sess_flow_eq(&(*pp)->flow, flow);
        if (0 != eq) {
            /* 현재 노드 분리 */
            httgw_session_t *s = *pp;
            *pp                = s->next;
            /* live 세션 수 감소 */
            if (0 < gw->sess_count) {
                gw->sess_count--;
            }
            /* 반환 전 next 링크 제거 */
            s->next = NULL;
            return s;
        }
        /* 다음 링크로 이동 */
        pp = &(*pp)->next;
    }
    /* 제거 대상 없음 */
    return NULL;
}

/**
 * @brief flow에 해당하는 세션을 가져오거나, 없으면 새로 만든다.
 *
 * 세션 생성 시 방향별 HTTP 파서를 동시에 만들어 두므로, 이후 ingest 경로는
 * packet 방향만 보고 `streams[dir]`를 바로 참조할 수 있다.
 */
static httgw_session_t *sess_get_or_create_internal(httgw_t          *gw,
                                                    const flow_key_t *flow,
                                                    uint64_t          ts_ms) {
    /* flow 해시로 버킷 선택 */
    uint32_t idx = sess_flow_hash(flow) % gw->sess_bucket_count;
    /* flow 비교 결과 */
    int eq;

    /* 기존 세션 탐색 */
    for (httgw_session_t *s = gw->sess_buckets[idx]; s; s = s->next) {
        eq = sess_flow_eq(&s->flow, flow);
        if (0 != eq) {
            /* 재관측 시 마지막 시각 갱신 */
            s->last_ts_ms = ts_ms;
            return s;
        }
    }

    /* 세션 본체 할당 */
    httgw_session_t *s = (httgw_session_t *)malloc(sizeof(*s));
    if (NULL == s) {
        return NULL;
    }
    /* 세션 상태 zero-init */
    memset(s, 0, sizeof(*s));

    /* 방향별 HTTP 스트림 파서 생성 */
    s->streams[DIR_AB] = http_stream_create(&gw->stream_cfg);
    s->streams[DIR_BA] = http_stream_create(&gw->stream_cfg);
    if (NULL == s->streams[DIR_AB] || NULL == s->streams[DIR_BA]) {
        /* 부분 생성 시 공통 destroy 경로 사용 */
        sess_destroy(s);
        return NULL;
    }

    /* flow key와 관측 시각 저장 */
    s->flow       = *flow;
    s->last_ts_ms = ts_ms;
    /* 버킷 체인 앞에 연결 */
    s->next               = gw->sess_buckets[idx];
    gw->sess_buckets[idx] = s;
    /* live 세션 수 증가 */
    gw->sess_count++;
    return s;
}

static int endpoint_cmp(uint32_t a_ip, uint16_t a_port, uint32_t b_ip,
                        uint16_t b_port) {
    /* 먼저 IP 오름차순 비교 */
    if (a_ip < b_ip) {
        return -1;
    }
    if (a_ip > b_ip) {
        return 1;
    }
    /* IP가 같으면 포트 오름차순 비교 */
    if (a_port < b_port) {
        return -1;
    }
    if (a_port > b_port) {
        return 1;
    }
    /* IP와 포트 모두 같음 */
    return 0;
}

static void normalize_flow(uint32_t sip, uint16_t sport, uint32_t dip,
                           uint16_t dport, flow_key_t *key, tcp_dir_t *dir) {
    /* endpoint 정렬 결과 */
    int c = endpoint_cmp(sip, sport, dip, dport);
    /* 결과 key zero-init */
    memset(key, 0, sizeof(*key));
    /* 현재 httgw는 TCP만 처리 */
    key->proto = 6;
    /* 오름차순 endpoint를 AB 기준으로 사용 */
    if (0 >= c) {
        key->src_ip   = sip;
        key->src_port = sport;
        key->dst_ip   = dip;
        key->dst_port = dport;
        *dir          = DIR_AB;
    } else {
        /* 반대 방향이면 endpoint를 뒤집고 BA로 표시 */
        key->src_ip   = dip;
        key->src_port = dport;
        key->dst_ip   = sip;
        key->dst_port = sport;
        *dir          = DIR_BA;
    }
}

/**
 * @brief Ethernet/IPv4/TCP 프레임에서 HTTP 처리에 필요한 최소 정보를 추출한다.
 *
 * 이 함수는 일반-purpose TCP 파서가 아니라 `httgw_ingest_packet()`가
 * 바로 필요한 값만 꺼내는 fast path helper다. 성공하면
 * - 정규화 flow key
 * - 원래 패킷 방향
 * - seq/ack/flags/window
 * - TCP payload 포인터와 길이
 * 를 한 번에 돌려준다.
 */
static int parse_ipv4_tcp_payload(const uint8_t *pkt, uint32_t caplen,
                                  flow_key_t *flow, tcp_dir_t *dir,
                                  uint32_t *seq, uint32_t *ack, uint8_t *flags,
                                  const uint8_t **payload,
                                  uint32_t *payload_len, uint16_t *window,
                                  uint8_t *win_scale) {
    /* 현재 파싱 위치 */
    const uint8_t *p = pkt;
    /* 현재 남은 바이트 수 */
    uint32_t n = caplen;
    /* Ethernet type */
    uint16_t eth_type;
    /* IPv4 header length */
    uint32_t ip_hl;
    /* IPv4 total length */
    uint32_t ip_len;
    /* TCP header length */
    uint32_t tcp_hl;
    /* IPv4 total_len 필드 */
    uint16_t total_len;
    /* IP protocol */
    uint8_t proto;
    /* src/dst IPv4 */
    uint32_t sip;
    uint32_t dip;
    /* src/dst TCP port */
    uint16_t sport;
    uint16_t dport;

    /* 최소 Ethernet 헤더 길이 검사 */
    if (14 > n) {
        return 0;
    }
    /* EtherType 추출 */
    eth_type = (uint16_t)((p[12] << 8) | p[13]);
    /* Ethernet 헤더 소비 */
    p += 14;
    n -= 14;

    /* 단일 VLAN 태그가 있으면 건너뛴다 */
    if (0x8100 == eth_type || 0x88A8 == eth_type) {
        if (4 > n) {
            return 0;
        }
        /* inner EtherType로 갱신 */
        eth_type = (uint16_t)((p[2] << 8) | p[3]);
        p += 4;
        n -= 4;
    }

    /* IPv4 패킷만 처리 */
    if (0x0800 != eth_type) {
        return 0;
    }
    /* 최소 IPv4 헤더 길이 검사 */
    if (20 > n) {
        return 0;
    }
    /* IPv4 version 확인 */
    if (4 != (p[0] >> 4)) {
        return 0;
    }

    /* IHL을 바이트 단위로 환산 */
    ip_hl = (uint32_t)(p[0] & 0x0F) * 4U;
    /* IHL 유효성 검사 */
    if (20 > ip_hl || ip_hl > n) {
        return 0;
    }

    /* IPv4 total_len 추출 */
    total_len = (uint16_t)((p[2] << 8) | p[3]);
    /* 캡처 버퍼 안에 전체 IPv4 패킷이 들어왔는지 확인 */
    if (total_len < ip_hl || n < total_len) {
        return 0;
    }

    /* TCP만 처리 */
    proto = p[9];
    if (6 != proto) {
        return 0;
    }

    /* src/dst IPv4 추출 */
    sip = (uint32_t)((p[12] << 24) | (p[13] << 16) | (p[14] << 8) | p[15]);
    dip = (uint32_t)((p[16] << 24) | (p[17] << 16) | (p[18] << 8) | p[19]);

    /* TCP 헤더 시작 위치로 이동 */
    p += ip_hl;
    /* IPv4 payload 길이로 갱신 */
    n = total_len - ip_hl;
    /* 최소 TCP 헤더 길이 검사 */
    if (20 > n) {
        return 0;
    }

    /* TCP 포트 추출 */
    sport = (uint16_t)((p[0] << 8) | p[1]);
    dport = (uint16_t)((p[2] << 8) | p[3]);
    /* TCP seq/ack 추출 */
    *seq = (uint32_t)((p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7]);
    *ack = (uint32_t)((p[8] << 24) | (p[9] << 16) | (p[10] << 8) | p[11]);
    /* TCP data offset를 바이트 단위로 환산 */
    tcp_hl = (uint32_t)((p[12] >> 4) & 0x0F) * 4U;
    /* TCP header 길이 유효성 검사 */
    if (20 > tcp_hl || tcp_hl > n) {
        return 0;
    }
    /* TCP flags 추출 */
    *flags = p[13];
    /* advertised window가 필요하면 반환 */
    if (window) {
        *window = (uint16_t)((p[14] << 8) | p[15]);
    }
    /* window scale 기본값은 0 */
    if (win_scale) {
        *win_scale = 0;
    }

    /* 전체 IP 패킷 길이 기록 */
    ip_len = total_len;
    /* 헤더 길이 합이 total_len보다 크면 비정상 */
    if (ip_len < ip_hl + tcp_hl) {
        return 0;
    }

    /* TCP payload 길이 계산 */
    *payload_len = ip_len - ip_hl - tcp_hl;
    /* payload 시작 포인터 반환 */
    *payload = p + tcp_hl;

    /* SYN 패킷이면 window scale option을 추가로 스캔한다 */
    if (NULL != win_scale && 0 != (p[13] & TCP_SYN) && 20 < tcp_hl) {
        /* TCP option 전체 길이 */
        uint32_t opt_len = tcp_hl - 20;
        /* option 시작 포인터 */
        const uint8_t *opt = p + 20;
        /* option 순회 인덱스 */
        uint32_t i = 0;
        while (i < opt_len) {
            /* 현재 option kind */
            uint8_t kind = opt[i];
            /* EOL이면 option 파싱 종료 */
            if (0 == kind) {
                break;
            }
            /* NOP은 1바이트만 소비 */
            if (1 == kind) {
                i++;
                continue;
            }
            /* length 바이트를 읽을 수 있어야 함 */
            if (i + 1 >= opt_len) {
                break;
            }
            /* 현재 option 길이 */
            uint8_t len = opt[i + 1];
            /* 길이 이상하면 option 파싱 중단 */
            if (2 > len || i + len > opt_len) {
                break;
            }
            /* Window Scale option이면 scale 값 기록 */
            if (3 == kind && 3 == len) {
                *win_scale = opt[i + 2];
                break;
            }
            /* 다음 option으로 이동 */
            i += len;
        }
    }

    /* 정규화 flow key와 방향 계산 */
    normalize_flow(sip, sport, dip, dport, flow, dir);
    /* 파싱 성공 */
    return 1;
}

static uint32_t tcp_next_seq(uint32_t seq, uint32_t payload_len,
                             uint8_t flags) {
    uint32_t next = seq + payload_len;

    if (flags & TCP_SYN) {
        next++;
    }
    if (flags & TCP_FIN) {
        next++;
    }
    return next;
}

/**
 * @brief HTTP 메시지 파싱 및 콜백 호출함수
 *
 * on_stream_data에서 flow/dir 전달받도록 수정하여 해당 방향 스트림에서 메시지
 * 파싱하도록 변경
 * @param gw http 게이트웨이 컨텍스트
 * @param flow HTTP 메시지가 속한 플로우 정보
 * @param dir HTTP 메시지가 속한 방향 (DIR_AB 또는 DIR_BA)
 */
static void drain_http(httgw_t *gw, const flow_key_t *flow, tcp_dir_t dir) {
    /* 현재 flow의 live session 조회 */
    httgw_session_t *sess = sess_find(gw, flow);
    /* 방향별 HTTP 스트림 핸들 */
    http_stream_t *s;
    /* poll로 꺼낼 HTTP 메시지 */
    http_message_t msg;
    /* stream poll 반환값 */
    http_stream_rc_t rc;

    /* 세션 없으면 drain 불가 */
    if (NULL == sess) {
        return;
    }
    /* 현재 방향 스트림 선택 */
    s = sess->streams[dir];
    /* 스트림 없으면 종료 */
    if (NULL == s) {
        return;
    }

    /*
     * http_stream은 feed 시점에 메시지를 즉시 콜백하지 않고 내부 큐에 적재한다.
     * 따라서 여기서는 큐를 비울 때까지 poll 하면서 요청 메시지를 상위에
     * 순서대로 전달한다.
     */
    /* 첫 번째 완성 메시지를 poll */
    rc = http_stream_poll_message(s, &msg);
    while (HTTP_STREAM_OK == rc) {
        /* 파싱 완료 HTTP 메시지 수 증가 */
        gw->stats.http_msgs++;
        if (msg.is_request) {
            /* 요청 메시지 수 증가 */
            gw->stats.reqs++;
            if (gw->cbs.on_request) {
                /* query string 시작 포인터와 길이 */
                const char *q     = NULL;
                size_t      q_len = 0;
                /* URI에서 query 부분 추출 */
                (void)httgw_extract_query(&msg, &q, &q_len);
                /* 상위 요청 콜백 호출 */
                gw->cbs.on_request(flow, dir, &msg, q, q_len, gw->user);
            }
        }
        /* 메시지 동적 필드 해제 */
        http_message_free(&msg);
        /* 다음 완성 메시지 poll */
        rc = http_stream_poll_message(s, &msg);
    }
}

static char *httgw_build_stream_error_detail(http_stream_t *stream) {
    /* http_stream 마지막 오류 문자열 */
    const char *err;
    /* 현재 파서 버퍼 포인터 */
    const uint8_t *buf;
    /* 현재 파서 버퍼 길이 */
    size_t len;
    /* 오류 prefix 길이 */
    size_t prefix_len;
    /* 버퍼 순회 인덱스 */
    size_t i;
    /* 최종 detail 문자열 */
    char *detail;

    /* stream 없으면 detail 생성 불가 */
    if (NULL == stream) {
        return NULL;
    }

    /* 최근 파서 오류 문자열 조회 */
    err = http_stream_last_error(stream);
    /* 파서 내부 버퍼 미리보기 */
    if (0 != http_stream_peek_buffer(stream, &buf, &len)) {
        return NULL;
    }

    /* "오류문구: " prefix 길이 계산 */
    prefix_len = strlen(NULL != err ? err : "unknown error");
    /* 오류 prefix + 버퍼 스냅샷 공간 할당 */
    detail = (char *)malloc(prefix_len + 2U + len + 1U);
    if (NULL == detail) {
        return NULL;
    }

    /* 오류 prefix 복사 */
    memcpy(detail, NULL != err ? err : "unknown error", prefix_len);
    detail[prefix_len]     = ':';
    detail[prefix_len + 1] = ' ';
    for (i = 0; i < len; i++) {
        /* 현재 버퍼 바이트 */
        unsigned char c = buf[i];

        /* 가시 문자는 그대로, 제어 문자는 '.'로 치환 */
        if (('\r' == c) || ('\n' == c) || ('\t' == c) || 0 != isprint(c)) {
            detail[prefix_len + 2U + i] = (char)c;
        } else {
            detail[prefix_len + 2U + i] = '.';
        }
    }
    /* 최종 NUL 종료 */
    detail[prefix_len + 2U + len] = '\0';
    return detail;
}

/**
 * @brief 재조립된 TCP payload를 HTTP 스트림에 밀어 넣고, 완성된 메시지를 상위로
 * 전달한다.
 *
 * 재조립 계층에서 순서가 맞는 데이터 조각이 준비되면 호출된다.
 * 지정한 flow와 방향(dir)에 해당하는 HTTP 스트림을 찾아 데이터를 공급하고,
 * 파싱이 성공하면 누적된 HTTP 메시지를 꺼내 `drain_http()`로 상위 콜백에
 * 넘긴다.
 *
 * @param flow 현재 데이터가 속한 TCP flow key
 * @param dir 데이터가 들어온 방향 (DIR_AB 또는 DIR_BA)
 * @param data 재조립된 TCP payload 시작 주소
 * @param len payload 길이
 * @param seq_start 재조립된 payload의 시작 TCP sequence 번호
 * @param user httgw_create()에서 등록된 사용자 컨텍스트. 내부적으로 httgw_t*로
 * 사용된다.
 */
static void on_stream_data(const flow_key_t *flow, tcp_dir_t dir,
                           const uint8_t *data, uint32_t len,
                           uint32_t seq_start, void *user) {
    httgw_t         *gw = (httgw_t *)user;
    httgw_session_t *sess;
    http_stream_t   *stream;
    http_stream_rc_t rc;

    /*
     * reasm 계층의 책임은 "연속 바이트 스트림을 만든다"까지다.
     * 여기서부터는 해당 바이트를 방향별 HTTP 파서에 넣고, 파싱 완료 메시지를
     * drain 하는 것이 httgw 책임이다.
     *
     * 현재 HTTP 계층은 seq 자체를 직접 쓰지 않으므로 seq_start는 unused다.
     */
    (void)seq_start;

    /*
     * user는 httgw_create()에서 넘긴 gw 컨텍스트여야 한다.
     * 여기서 NULL이면 이후 sess_find(), stats 갱신, on_error 호출 모두
     * 불가능하므로 더 진행하지 않고 즉시 중단한다.
     */
    if (NULL == gw) {
        return;
    }

    /*
     * flow는 어떤 TCP 세션의 재조립 결과인지 식별하는 키다.
     * flow가 없으면 세션 lookup 자체가 성립하지 않으므로 상위에 오류를 알리고
     * 반환한다.
     */
    if (NULL == flow) {
        if (NULL != gw->cbs.on_error) {
            gw->cbs.on_error("on_stream_data", "missing flow", gw->user);
        }
        return;
    }

    /*
     * dir은 반드시 DIR_AB 또는 DIR_BA여야 한다.
     * 범위를 벗어난 값은 sess->streams[dir] 접근 시 잘못된 인덱스로 이어질 수
     * 있으므로 방어적으로 차단한다.
     */
    if (dir != DIR_AB && dir != DIR_BA) {
        if (NULL != gw->cbs.on_error) {
            gw->cbs.on_error("on_stream_data", "invalid direction", gw->user);
        }
        return;
    }

    /*
     * data는 reasm 계층이 넘긴 연속된 TCP payload 시작 주소다.
     * len > 0 인데 data가 NULL이면 파서에 넘길 수 없으므로 오류로 본다.
     */
    if (NULL == data) {
        if (NULL != gw->cbs.on_error) {
            gw->cbs.on_error("on_stream_data", "missing stream data", gw->user);
        }
        return;
    }

    /*
     * 길이가 0인 payload는 현재 HTTP 스트림 파서에 공급할 실데이터가 없다는
     * 뜻이다. 오류로 보지는 않고, 조용히 무시한다.
     */
    if (0 == len) {
        return;
    }

    /*
     * 재조립 결과가 들어온 flow에 대응하는 live session을 찾는다.
     * 세션이 없다는 것은 reasm 계층과 session table의 lifecycle이 어긋났거나
     * 이미 세션이 정리된 뒤 callback이 들어왔다는 뜻일 수 있으므로 오류로
     * 남긴다.
     */
    sess = sess_find(gw, flow);
    if (NULL == sess) {
        if (NULL != gw->cbs.on_error) {
            gw->cbs.on_error("on_stream_data", "missing httgw session",
                             gw->user);
        }
        return;
    }

    /*
     * 한 세션은 방향별로 HTTP 스트림 파서를 하나씩 가진다.
     * 현재 payload가 속한 방향의 스트림 핸들을 가져와 그쪽에만 데이터를
     * 공급한다.
     */
    stream = sess->streams[dir];
    if (NULL == stream) {
        if (NULL != gw->cbs.on_error) {
            gw->cbs.on_error("on_stream_data", "missing http stream", gw->user);
        }
        return;
    }

    /*
     * 재조립 계층이 순서를 맞춰 넘긴 payload를 HTTP 스트림 파서에 공급한다.
     * 여기서 헤더/바디 누적, 메시지 경계 판정, 파서 상태 전이가 진행된다.
     */
    rc = http_stream_feed(stream, data, len);
    if (rc != HTTP_STREAM_OK) {
        char *detail = NULL;

        gw->stats.parse_errs++;

        /*
         * 파서가 프로토콜 오류나 버퍼 상태 이상을 보고한 경우다.
         * 오류 내용을 상위에 전달한 뒤, 현재 방향 스트림 상태를 reset 해서
         * 이후 데이터가 새 메시지처럼 다시 파싱될 수 있게 한다.
         */
        if (NULL != gw->cbs.on_error) {
            detail = httgw_build_stream_error_detail(stream);
            gw->cbs.on_error(
                "http_stream_feed",
                NULL != detail ? detail : http_stream_last_error(stream),
                gw->user);
        }
        free(detail);
        http_stream_reset(stream);
        return;
    }

    /*
     * feed 결과로 완성된 HTTP 메시지가 내부 큐에 쌓였을 수 있으므로,
     * drain_http()를 호출해 요청/응답 메시지를 상위 콜백으로 배출한다.
     */
    drain_http(gw, flow, dir);  // MODIFY
}

/**
 * @brief HTTP 게이트웨이 인스턴스를 생성하고 내부 상태를 초기화한다.
 *
 * 재조립 엔진, HTTP 스트림 설정, 세션 해시 테이블, 콜백 정보를 묶은
 * httgw_t 객체를 생성한다. 생성이 성공하면 패킷을 `httgw_ingest_packet()`
 * 으로 투입할 수 있는 초기 상태가 된다.
 *
 * @param cfg 게이트웨이 설정값. NULL이면 기본값을 사용한다.
 * @param cbs 요청/오류 처리 콜백 묶음. NULL이면 모든 콜백을 비활성화한다.
 * @param user 콜백 호출 시 함께 전달할 사용자 컨텍스트 포인터
 * @return httgw_t* 생성된 게이트웨이 인스턴스 포인터, 실패 시 NULL
 */
httgw_t *httgw_create(const httgw_cfg_t *cfg, const httgw_callbacks_t *cbs,
                      void *user) {
    /* 생성할 게이트웨이 본체 */
    httgw_t *gw = NULL;

    /* 게이트웨이 본체를 zero-init 상태로 생성한다. */
    gw = (httgw_t *)malloc(sizeof(*gw));
    if (!gw) {
        return NULL;
    }
    memset(gw, 0, sizeof(*gw));

    /* 콜백과 사용자 컨텍스트를 먼저 고정한다. */
    gw->user = user;
    if (cbs) {
        gw->cbs = *cbs;
    } else {
        memset(&gw->cbs, 0, sizeof(gw->cbs));
    }

    /* verbose는 명시적으로 켜진 경우에만 활성화한다. */
    gw->verbose = 0;
    if (cfg && cfg->verbose) {
        gw->verbose = 1;
    }

    /*
     * HTTP 스트림 메모리 상한을 설정한다.
     * 설정값이 없으면 buffer/body 모두 기본 12MB를 사용한다.
     */
    memset(&gw->stream_cfg, 0, sizeof(gw->stream_cfg));
    gw->stream_cfg.max_buffer_bytes = 12U * 1024U * 1024U;
    if (cfg && cfg->max_buffer_bytes) {
        gw->stream_cfg.max_buffer_bytes = cfg->max_buffer_bytes;
    }

    gw->stream_cfg.max_body_bytes = 12U * 1024U * 1024U;
    if (cfg && cfg->max_body_bytes) {
        gw->stream_cfg.max_body_bytes = cfg->max_body_bytes;
    }

    /* TCP 재조립 엔진을 만들고, 재조립 완료 데이터는 on_stream_data()로 넘긴다.
     */
    gw->reasm = reasm_create(8192, on_stream_data, gw);
    if (!gw->reasm) {
        httgw_destroy(gw);
        return NULL;
    }

    /* flow 기반 세션 조회를 위한 해시 버킷 배열을 준비한다. */
    gw->sess_bucket_count = HTTGW_SESS_BUCKETS;
    gw->sess_buckets      = (httgw_session_t **)malloc(
        (size_t)gw->sess_bucket_count * sizeof(*gw->sess_buckets));
    if (!gw->sess_buckets) {
        httgw_destroy(gw);
        return NULL;
    }
    memset(gw->sess_buckets, 0,
           (size_t)gw->sess_bucket_count * sizeof(*gw->sess_buckets));

    /* 재조립 시작 정책은 설정값을 우선하고, 없으면 late-start를 기본으로 쓴다.
     */
    if (cfg) {
        reasm_set_mode(gw->reasm, cfg->reasm_mode);
    } else {
        reasm_set_mode(gw->reasm, REASM_MODE_LATE_START);
    }

    return gw;
}

/**
 * @brief 게이트웨이 인스턴스와 내부 자원을 모두 해제한다.
 *
 * 세션 해시 버킷, 각 세션의 HTTP 스트림 상태, TCP 재조립 엔진을 순서대로
 * 정리한 뒤 `httgw_t` 본체를 해제한다.
 *
 * @param gw 해제할 httgw 인스턴스. NULL이면 아무 작업도 하지 않는다.
 */
void httgw_destroy(httgw_t *gw) {
    /* 버킷 순회 인덱스 */
    uint32_t i = 0;

    if (NULL == gw) {
        return;
    }

    /* 세션 버킷 배열과 각 세션 객체를 모두 정리한다. */
    if (NULL != gw->sess_buckets) {
        for (i = 0; i < gw->sess_bucket_count; i++) {
            httgw_session_t *next = NULL;
            /* 현재 버킷 체인 순회 포인터 */
            httgw_session_t *sess = NULL;

            sess = gw->sess_buckets[i];
            while (NULL != sess) {
                next = sess->next;
                sess_destroy(sess);
                sess = next;
            }

            gw->sess_buckets[i] = NULL;
        }

        free(gw->sess_buckets);
        gw->sess_buckets = NULL;
    }

    /* 남은 세션 수와 재조립 엔진 상태를 정리한다. */
    gw->sess_count = 0;
    if (NULL != gw->reasm) {
        reasm_destroy(gw->reasm);
        gw->reasm = NULL;
    }

    free(gw);
}

/**
 * @brief 패킷을 입력으로 받아 세션 테이블 업데이트 및 TCP 스트림 재조립 수행
 *
 * @param gw httgw 인스턴스
 * @param pkt 입력패킷 이더넷 프레임 시작 주소
 * @param caplen 길이
 * @param ts_ms 타임스탬프 ms 단위
 * @return int 0이면 정상 완료, -1이면 오류
 */
int httgw_ingest_packet(httgw_t *gw, const uint8_t *pkt, uint32_t caplen,
                        uint64_t ts_ms) {
    /* 정규화된 TCP flow key */
    flow_key_t flow;
    /* 패킷이 속한 정규화 방향 */
    tcp_dir_t dir;
    /* TCP sequence 번호 */
    uint32_t seq = 0;
    /* TCP ack 번호 */
    uint32_t ack = 0;
    /* TCP flags */
    uint8_t flags = 0;
    /* TCP payload 시작 포인터 */
    const uint8_t *payload = NULL;
    /* TCP payload 길이 */
    uint32_t payload_len = 0;
    /* SYN/FIN까지 반영한 다음 seq */
    uint32_t next_seq = 0;
    /* advertised window */
    uint16_t window = 0;
    /* SYN option에서 추출한 window scale */
    uint8_t win_scale = 0;
    /* 내부 함수 반환값 */
    int rc;
    /* 현재 flow의 live session */
    httgw_session_t *sess;

    /* 기본 인자와 캡처 버퍼 상태가 유효한지 먼저 확인한다. */
    if (NULL == gw || (NULL == pkt && 0 != caplen)) {
        return -1;
    }

    /*
     * 1. raw packet을 파싱해 TCP 의미 단위(flow/dir/seq/ack/payload)로 바꾼다.
     * 2. 세션 테이블을 갱신한다.
     * 3. 재조립 엔진에 payload를 투입한다.
     * 4. 재조립이 완료되면 reasm callback -> on_stream_data -> http_stream으로
     *    이어진다.
     *
     * 즉 httgw_ingest_packet은 raw packet 계층과 HTTP 메시지 계층을 잇는
     * ingress coordinator다.
     */
    rc = parse_ipv4_tcp_payload(pkt, caplen, &flow, &dir, &seq, &ack, &flags,
                                &payload, &payload_len, &window, &win_scale);
    if (0 == rc) {
        return 0;
    }

    /* 현재 세그먼트 기준으로 다음에 기대되는 TCP seq를 계산한다. */
    next_seq = tcp_next_seq(seq, payload_len, flags);

    /*
     * RST는 연결 종료를 강하게 의미하므로 live session을 먼저 제거한다.
     * 다만 reasm 계층도 RST를 알아야 대기 중 세그먼트와 expected seq 상태를
     * 즉시 버릴 수 있으므로, 세션 제거 후에도 reasm_ingest는 호출한다.
     */
    if (0 != (flags & TCP_RST)) {
        sess = sess_remove_internal(gw, &flow);
        if (NULL != sess) {
            sess_destroy(sess);
        }

        rc = reasm_ingest(gw->reasm, &flow, dir, seq, flags, payload,
                          payload_len, ts_ms);
        if (0 != rc) {
            gw->stats.reasm_errs++;
            if (NULL != gw->cbs.on_error) {
                /* reasm 오류 코드를 문자열로 기록 */
                char buf[64];

                snprintf(buf, sizeof(buf), "rc=%d", rc);
                gw->cbs.on_error("reasm_ingest", buf, gw->user);
            }
            return -1;
        }
        return 0;
    }

    /* 일반 패킷이면 세션을 찾거나 새로 생성한다. */
    sess = sess_get_or_create_internal(gw, &flow, ts_ms);
    if (NULL == sess) {
        return -1;
    }

    /*
     * 세션에는 재조립 자체와 별개로 "최근 TCP 상태 snapshot"을 유지한다.
     * 이 값은 나중에 차단 응답/RST 주입 시 seq/ack/window를 계산하는 데 쓴다.
     */
    if (DIR_AB == dir) {
        /* ack 증가 여부 검사 결과 */
        int ack_ok;

        if (0 == sess->seen_ab) {
            sess->base_seq_ab = seq;
        }

        sess->last_seq_ab = seq;
        sess->next_seq_ab = next_seq;

        ack_ok = SEQ_GEQ(ack, sess->last_ack_ab);
        if (0 == sess->seen_ab || 0 != ack_ok) {
            sess->last_ack_ab = ack;
            sess->win_ab      = window;
        }

        if (0 != (flags & TCP_SYN)) {
            sess->win_scale_ab = win_scale;
        }

        sess->seen_ab = 1;
        if (0 != (flags & TCP_FIN)) {
            sess->fin_seen_ab = 1;
        }
    } else {
        /* ack 증가 여부 검사 결과 */
        int ack_ok;

        if (0 == sess->seen_ba) {
            sess->base_seq_ba = seq;
        }

        sess->last_seq_ba = seq;
        sess->next_seq_ba = next_seq;

        ack_ok = SEQ_GEQ(ack, sess->last_ack_ba);
        if (0 == sess->seen_ba || 0 != ack_ok) {
            sess->last_ack_ba = ack;
            sess->win_ba      = window;
        }

        if (0 != (flags & TCP_SYN)) {
            sess->win_scale_ba = win_scale;
        }

        sess->seen_ba = 1;
        if (0 != (flags & TCP_FIN)) {
            sess->fin_seen_ba = 1;
        }
    }

    /* 세션의 마지막 관측 시각을 갱신한다. */
    sess->last_ts_ms = ts_ms;

    /*
     * 여기서부터 실제 TCP 재조립 계층으로 진입한다.
     * in-order면 바로 상위에 flush 되고, out-of-order면 reasm 내부 리스트에
     * 대기한다.
     */
    rc = reasm_ingest(gw->reasm, &flow, dir, seq, flags, payload, payload_len,
                      ts_ms);
    if (0 != rc) {
        httgw_session_t *stale = sess_remove_internal(gw, &flow);

        gw->stats.reasm_errs++;
        if (NULL != stale) {
            sess_destroy(stale);
        }
        if (NULL != gw->cbs.on_error) {
            /* reasm 오류 코드를 문자열로 기록 */
            char buf[64];

            snprintf(buf, sizeof(buf), "rc=%d", rc);
            gw->cbs.on_error("reasm_ingest", buf, gw->user);
        }
        return -1;
    }

    return 0;
}

/**
 * @brief httgw 의 가비지컬렉터
 * 만료된 HTTP/TCP 세션과 재조립 상태를 정리한다.
 * 현재 시각(ms). 세션 timeout 판정 기준으로 사용
 * @param gw 컨텍스트
 * @param now_ms 지금 시간
 */
void httgw_gc(httgw_t *gw, uint64_t now_ms) {
    if (!gw || !gw->reasm) {
        return;
    }

    reasm_gc(gw->reasm, now_ms);
    for (uint32_t i = 0; i < gw->sess_bucket_count; i++) {
        httgw_session_t **pp = &gw->sess_buckets[i];
        while (*pp) {
            /* 현재 노드를 가리키는 포인터의 주소 */
            httgw_session_t *s = *pp;
            if (now_ms - s->last_ts_ms > HTTGW_SESS_TIMEOUT_MS) /* 삭제 조건*/
            {
                *pp = s->next;
                sess_destroy(s);
                if (0 < gw->sess_count) {
                    gw->sess_count--;
                }
                /* 삭제 후 *pp는 이미 다음 노드를 가르키고 있다.*/
                /* 삭제 전 A-> B-> C*/
                /* 삭제 후 A-> C*/
                /* 하지만 *pp는 여전히 A를 가르킨다. */
                continue;
            }
            pp = &(*pp)->next;
        }
    }
}

/**
 * @brief 게이트웨이 누적 통계 구조체를 읽기 전용으로 반환한다.
 *
 * 현재 메인 런타임에서 적극 사용되기보다는 테스트나 상태 확인 용도로
 * 활용되는 getter이다.
 *
 * @param gw httgw 컨텍스트
 * @return const httgw_stats_t* 통계 구조체 포인터, 입력이 NULL이면 NULL
 */
const httgw_stats_t *httgw_stats(const httgw_t *gw) {
    if (!gw) {
        return NULL;
    }
    return &gw->stats;
}

/**
 * @brief 게이트웨이 내부 재조립 순서 통계를 복사한다.
 *
 * @param gw httgw 컨텍스트
 * @param out 출력 통계
 * @return int 성공 시 0, 실패 시 -1
 */
int httgw_get_reasm_stats(const httgw_t *gw, reasm_stats_t *out) {
    if (!gw || !out) {
        return -1;
    }

    reasm_get_stats(gw->reasm, out);
    return 0;
}

/**
 * @brief httgw 내부 세션 상태 외부에 복사하는 함수
 * RST/차단페이지 주입하기 위해 현재 seq/ack/window를 알아야함
 * 그래서 이를 복사해주는 getter
 * @param gw httgw 컨텍스트
 * @param flow 찾고싶은 tcp 세션 키
 * @param out
 * @return int
 */
int httgw_get_session_snapshot(const httgw_t *gw, const flow_key_t *flow,
                               httgw_sess_snapshot_t *out) {
    /* 기본 인자 검증 */
    if (!gw || !flow || !out) {
        return -1;
    }

    /* 현재 flow의 live session 조회 */
    httgw_session_t *sess = sess_find(gw, flow);
    if (!sess) {
        return -1;
    }
    /* 출력 snapshot zero-init */
    memset(out, 0, sizeof(*out));
    /* RST/주입 계산에 필요한 seq/ack/window 상태 복사 */
    out->base_seq_ab  = sess->base_seq_ab;
    out->base_seq_ba  = sess->base_seq_ba;
    out->last_ack_ab  = sess->last_ack_ab;
    out->next_seq_ab  = sess->next_seq_ab;
    out->last_ack_ba  = sess->last_ack_ba;
    out->next_seq_ba  = sess->next_seq_ba;
    out->win_ab       = sess->win_ab;
    out->win_ba       = sess->win_ba;
    out->win_scale_ab = sess->win_scale_ab;
    out->win_scale_ba = sess->win_scale_ba;
    out->seen_ab      = sess->seen_ab;
    out->seen_ba      = sess->seen_ba;
    return 0;
}

/**
 * @brief 광고된 TCP window 값에 window scale을 적용한다.
 *
 * @param win 16비트 TCP window 값
 * @param win_scale SYN 옵션으로 학습한 window scale
 * @return uint32_t scale이 적용된 window 크기
 */
static uint32_t scaled_window_value(uint16_t win, uint8_t win_scale) {
    /* window scale은 과도한 shift를 막기 위해 14로 clamp */
    return ((uint32_t)win) << (win_scale > 14 ? 14 : win_scale);
}
/**
 * @brief 헤더 이름 대소문자 무시 비교함
 * a[0..an-1],
 * @param a 비교할 첫 번째 문자열 시작 주소
 * @param an a의 길이
 * @param b 비교 기준이 되는 두 번째 문자열
 * @return int
 */
static int ci_eq(const uint8_t *a, size_t an, const char *b) {
    /* 순회 인덱스 */
    size_t i;
    /* 비교 기준 문자열 길이 */
    size_t bn = strlen(b);
    /* 길이가 다르면 불일치 */
    if (an != bn) {
        return 0;
    }

    for (i = 0; i < an; i++) {
        /* 입력 slice 문자 */
        unsigned char ca = (unsigned char)a[i];
        /* 비교 기준 문자 */
        unsigned char cb = (unsigned char)b[i];
        /* 소문자 정규화 결과 */
        int fa;
        int fb;

        fa = tolower(ca);
        fb = tolower(cb);
        if (fa != fb) {
            return 0;
        }
    }

    return 1;
}

/**
 * @brief HTTP 메시지의 raw header 블록에서 지정한 헤더 값을 조회한다.
 *
 * 요청/응답 start-line 다음에 이어지는 header 영역을 순회하면서
 * `name`과 일치하는 헤더를 대소문자 구분 없이 찾는다.
 * 값을 찾으면 leading/trailing 공백을 제외한 slice를 `value`와 `value_len`
 * 으로 반환한다.
 *
 * @param msg 조회 대상 HTTP 메시지
 * @param name 찾을 헤더 이름. 예: "Host", "User-Agent"
 * @param value 조회된 헤더 값 시작 주소를 돌려받을 출력 포인터
 * @param value_len 조회된 헤더 값 길이를 돌려받을 출력 포인터
 * @return int 성공 시 0, 실패 시 -1
 */
int httgw_header_get(const http_message_t *msg, const char *name,
                     const uint8_t **value, size_t *value_len) {
    const uint8_t *p;
    size_t         len;
    size_t         pos = 0;
    size_t         line_end;

    /* 입력 포인터와 출력 버퍼가 유효한지 먼저 확인한다. */
    if (NULL != value) {
        *value = NULL;
    }
    if (NULL != value_len) {
        *value_len = 0;
    }
    if (NULL == msg || NULL == name || NULL == value || NULL == value_len) {
        return -1;
    }

    /* raw header 블록이 없으면 조회할 대상이 없다. */
    if (NULL == msg->headers_raw || 0 == msg->headers_raw_len) {
        return -1;
    }

    p   = msg->headers_raw;
    len = msg->headers_raw_len;

    /* start-line을 건너뛰고 첫 번째 header line 시작 위치를 찾는다. */
    while (pos + 1 < len) {
        if ('\r' == p[pos] && '\n' == p[pos + 1]) {
            pos += 2;
            break;
        }
        pos++;
    }

    /* header line을 한 줄씩 순회하며 이름이 일치하는 항목을 찾는다. */
    while (pos < len) {
        size_t         i;
        const uint8_t *line     = p + pos;
        size_t         line_len = 0;
        const uint8_t *colon;
        const uint8_t *val;
        const uint8_t *val_end;

        /* 현재 header line의 끝(CRLF)을 찾는다. */
        for (i = pos; i + 1 < len; i++) {
            if ('\r' == p[i] && '\n' == p[i + 1]) {
                line_end = i;
                line_len = line_end - pos;
                break;
            }
        }
        if (0 == line_len) {
            break;
        }

        /* "name: value" 형태인지 확인하고 헤더 이름을 비교한다. */
        colon = (const uint8_t *)memchr(line, ':', line_len);
        if (NULL != colon) {
            size_t name_len = (size_t)(colon - line);
            int    eq;

            eq = ci_eq(line, name_len, name);
            if (0 != eq) {
                /* ':' 뒤 공백을 건너뛰고 값 시작 위치를 맞춘다. */
                val = colon + 1;
                while (val < line + line_len && (*val == ' ' || *val == '\t')) {
                    val++;
                }

                /* 값 끝의 trailing space/tab을 제거한다. */
                val_end = line + line_len;
                while (val_end > val &&
                       ((*(val_end - 1) == ' ') || (*(val_end - 1) == '\t'))) {
                    val_end--;
                }

                /* 값 slice를 그대로 반환한다. 복사본은 만들지 않는다. */
                *value     = val;
                *value_len = (size_t)(val_end - val);
                return 0;
            }
        }

        /* 다음 header line으로 이동한다. */
        pos = line_end + 2;
    }

    return -1;
}

/**
 * @brief slice extractor 함수
 * 상위 콜백에 쿼리 구간만 넘겨주기 위한 헬퍼임
 * @param msg 입력 http메시지
 * @param q 출력용 포인터
 * @param q_len 출력용 길이 값
 * @return int 성공 시 0, 실패 시 -1
 */
int httgw_extract_query(const http_message_t *msg, const char **q,
                        size_t *q_len) {
    /* URI 시작 포인터 */
    const char *uri;
    /* '?' 위치 */
    const char *qm;
    /* '#' 위치 */
    const char *hash;
    /* query 길이 */
    size_t len;

    /* 출력 포인터 초기화 */
    if (NULL != q) {
        *q = NULL;
    }
    if (NULL != q_len) {
        *q_len = 0;
    }
    if (NULL == msg || NULL == q || NULL == q_len) {
        return -1;
    }
    /* 요청 메시지만 query를 가질 수 있다 */
    if (0 == msg->is_request) {
        return -1;
    }

    /* URI가 비어 있으면 query 추출 불가 */
    uri = msg->uri;
    if (NULL == uri || '\0' == uri[0]) {
        return -1;
    }

    /* query 시작 구분자 탐색 */
    qm = strchr(uri, '?');
    if (NULL == qm || '\0' == *(qm + 1)) {
        return -1;
    }

    /* fragment가 있으면 그 앞까지만 query로 본다 */
    hash = strchr(qm + 1, '#');
    if (NULL != hash) {
        len = (size_t)(hash - (qm + 1));
    } else {
        len = strlen(qm + 1);
    }

    /* 빈 query는 실패 처리 */
    if (0 == len) {
        return -1;
    }
    /* query slice 반환 */
    *q     = qm + 1;
    *q_len = len;
    return 0;
}

/* 헬퍼 체크섬*/
static uint16_t checksum16(const void *data, size_t len) {
    /* 입력 바이트 순회 포인터 */
    const uint8_t *p = (const uint8_t *)data;

    /* 16비트 누적 합 */
    uint32_t sum = 0;

    /* 16비트 단위로 합산 */
    while (len > 1) {
        sum += (uint16_t)((p[0] << 8) | p[1]);
        p   = p + 2;
        len = len - 2;
    }
    /* 홀수 바이트가 남으면 상위 바이트로 더한다 */
    if (len) {
        sum += (uint16_t)(p[0] << 8);
    }
    /* carry를 16비트 안으로 접는다 */
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    /* 1의 보수 체크섬 반환 */
    return (uint16_t)(~sum);
}

static uint16_t tcp_checksum(uint32_t src_be, uint32_t dst_be,
                             const uint8_t *tcp, size_t tcp_len) {
    /* pseudo header + TCP 누적 합 */
    uint32_t sum = 0;
    /* 현재 순회 포인터 */
    const uint8_t *p;
    /* 남은 길이 */
    size_t len;

    /* source IP 반영 */
    p = (const uint8_t *)&src_be;
    sum += (uint16_t)((p[0] << 8) | p[1]);
    sum += (uint16_t)((p[2] << 8) | p[3]);

    /* destination IP 반영 */
    p = (const uint8_t *)&dst_be;
    sum += (uint16_t)((p[0] << 8) | p[1]);
    sum += (uint16_t)((p[2] << 8) | p[3]);

    /* protocol과 TCP 길이 반영 */
    sum += IPPROTO_TCP;
    sum += (uint16_t)tcp_len;

    /* TCP 헤더/바디 16비트 합산 */
    p   = tcp;
    len = tcp_len;
    while (len > 1) {
        sum += (uint16_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }
    /* 홀수 바이트 처리 */
    if (len) {
        sum += (uint16_t)(p[0] << 8);
    }

    /* carry를 16비트 안으로 접는다 */
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    /* 1의 보수 체크섬 반환 */
    return (uint16_t)(~sum);
}

// Layer 3 전송 함수, 레이어 3 = IP 계층, IP 헤더부터 시작하는 패킷을 raw
// socket으로 보내라는 함수이다.
int tx_send_l3(void *ctx, const uint8_t *buf, size_t len) {
    tx_ctx_t          *tx = (tx_ctx_t *)ctx;
    struct sockaddr_in dst;
    const IPHDR       *ip;
    ssize_t n;  // signed size type, 부호있는 크기타입 음수 가능
    // 유효성 검사 -> 송신 컨텍스트/버퍼/최소 IP 헤더 길이 확인
    if (NULL == tx || 0 > tx->fd || NULL == buf || IP_HDR_SIZE > len) {
        return -1;
    }
    // Raw L3 버퍼의 시작은 IPv4 헤더
    ip = (const IPHDR *)buf;

    // sendto() 목적지 주소 구조체 초기화
    memset(&dst, 0, sizeof(dst));
    dst.sin_family      = AF_INET;
    dst.sin_addr.s_addr = IP_DADDR(ip);

    // Raw 소켓으로 미리 구성된 IP/TCP 패킷을 그대로 전송
    n = sendto(tx->fd, buf, len, 0, (struct sockaddr *)&dst, sizeof(dst));
    // sendto는 소켓으로 데이터를 보내는 시스템 호출
    if (0 > n)  // sendto 실패
    {
        return -1;
    }
    return (size_t)n == len ? 0 : -1;
}

int tx_ctx_init(tx_ctx_t *tx) {
    /* raw socket fd */
    int fd;
    /* IP_HDRINCL 옵션 값 */
    int on = 1;
    /* setsockopt 반환값 */
    int ret;

    /* 출력 컨텍스트 검증 */
    if (NULL == tx) {
        return -1;
    }
    /* 컨텍스트 zero-init */
    memset(tx, 0, sizeof(*tx));

    /* raw IPv4 송신 소켓 생성 */
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (0 > fd) {
        return -1;
    }
    /* 사용자 정의 IP 헤더 사용 설정 */
    ret = setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    if (0 != ret) {
        close(fd);
        return -1;
    }

    /* 초기화된 전송 컨텍스트 공개 */
    tx->fd      = fd;
    tx->send_l3 = tx_send_l3;
    tx->ctx     = tx;
    return 0;
}

void tx_ctx_destroy(tx_ctx_t *tx) {
    /* 컨텍스트 없으면 종료 */
    if (!tx) {
        return;
    }
    /* 열린 raw socket 정리 */
    if (0 <= tx->fd) {
        close(tx->fd);
    }
    /* 재사용 방지를 위해 필드 초기화 */
    tx->fd      = -1;
    tx->send_l3 = NULL;
    tx->ctx     = NULL;
}

int httgw_set_tx(httgw_t *gw, tx_ctx_t *tx) {
    /* 게이트웨이 없으면 실패 */
    if (!gw) {
        return -1;
    }
    /* 송신 컨텍스트와 RST 전송 함수 연결 */
    gw->tx_ctx      = tx;
    gw->tx_send_rst = tx_send_rst;
    return 0;
}

/**
 * @brief
 *
 * @param tx_ctx
 * @param flow
 * @param dir
 * @param seq
 * @param ack
 * @param flags
 * @param window
 * @param payload
 * @param payload_len
 * @return int
 */
static int tx_send_tcp_segment(void *tx_ctx, const flow_key_t *flow,
                               tcp_dir_t dir, uint32_t seq, uint32_t ack,
                               uint8_t flags, uint16_t window,
                               const uint8_t *payload, size_t payload_len) {
    /* raw 송신 컨텍스트 */
    tx_ctx_t *tx = (tx_ctx_t *)tx_ctx;
    /* 실제 송신/수신 IPv4 */
    uint32_t sip, dip;
    /* 실제 송신/수신 TCP port */
    uint16_t sport, dport;
    /* 전체 패킷 길이 */
    size_t total_len;
    /* raw 패킷 버퍼 */
    uint8_t *buf;
    /* 버퍼 위 IPv4/TCP 헤더 뷰 */
    IPHDR  *ip;
    TCPHDR *tcp;
    /* 하위 송신 반환값 */
    int rc;
    /* 송신 컨텍스트, 하위 L3 송신 함수, flow 입력이 유효한지 확인한다. */
    if (!tx || !tx->send_l3 || !flow) {
        return -1;
    }

    /* payload 길이가 있는데 payload 포인터가 없으면 잘못된 입력이다. */
    if (0 < payload_len && NULL == payload) {
        return -1;
    }

    /* IP + TCP + payload를 합친 전체 패킷 길이를 계산한다. */
    total_len = IP_HDR_SIZE + TCP_HDR_SIZE + payload_len;
    if (0xFFFFu < total_len) {
        return -1;
    }

    /*
     * flow와 방향(dir)에 따라 실제 송신/수신 endpoint를 결정한다.
     * DIR_AB는 flow의 원래 방향, DIR_BA는 src/dst를 뒤집은 방향이다.
     */
    if (dir == DIR_AB) {
        sip   = flow->src_ip;
        sport = flow->src_port;

        dip   = flow->dst_ip;
        dport = flow->dst_port;
    } else {
        sip   = flow->dst_ip;
        sport = flow->dst_port;

        dip   = flow->src_ip;
        dport = flow->src_port;
    }
    /* 전송할 raw IPv4/TCP 패킷 버퍼를 확보한다. */
    buf = (uint8_t *)malloc(total_len);
    if (!buf) {
        return -1;
    }
    memset(buf, 0, total_len);

    /* 버퍼 앞부분을 IPv4 헤더와 TCP 헤더로 해석한다. */
    ip  = (IPHDR *)buf;
    tcp = (TCPHDR *)(buf + sizeof(*ip));

    /* IPv4 헤더 필드를 채운다. */
    IP_VER(ip)       = 4;
    IP_IHL(ip)       = 5;
    IP_TTL_FIELD(ip) = 64;
    IP_PROTO(ip)     = IPPROTO_TCP;
    IP_TOTLEN(ip)    = htons((uint16_t)total_len);
    IP_SADDR(ip)     = htonl(sip);
    IP_DADDR(ip)     = htonl(dip);
    IP_CHECK(ip)     = 0;
    IP_CHECK(ip)     = checksum16(ip, sizeof(*ip));

    /* TCP 헤더 필드를 채운다. */
    TCP_SPORT(tcp) = htons(sport);
    TCP_DPORT(tcp) = htons(dport);
    TCP_SEQ(tcp)   = htonl(seq);
    TCP_ACK(tcp)   = htonl(ack);
    TCP_DOFF(tcp)  = 5;
    TCP_SET_FLAGS(tcp, flags);
    TCP_WIN(tcp)   = htons(window);
    TCP_CHECK(tcp) = 0;
    /* payload가 있으면 TCP 헤더 뒤에 그대로 복사한다. */
    if (0 < payload_len) {
        memcpy((uint8_t *)tcp + TCP_HDR_SIZE, payload, payload_len);
    }
    /* pseudo-header를 포함한 TCP 체크섬을 계산해 기록한다. */
    TCP_CHECK(tcp) =
        htons(tcp_checksum(IP_SADDR(ip), IP_DADDR(ip), (const uint8_t *)tcp,
                           TCP_HDR_SIZE + payload_len));

    /* 완성된 raw 패킷을 하위 L3 송신 함수로 넘긴다. */
    rc = tx->send_l3(tx->ctx, buf, total_len);
    free(buf);
    /* 임시 버퍼를 해제하고 송신 결과를 반환한다. */
    return rc;
}

/**
 * @brief TCP RST 세그먼트를 생성해 지정한 방향으로 전송한다.
 *
 * ack값이 0이 아니면 RST|ACK 형태로 보내고,
 * 0이면 순수 RST 세그먼트로 보낸다. 실제 패킷 생성과 송신은
 * tx_send_tcp_segment에 위임한다.
 *
 * @param tx_ctx raw L3 송신에 사용할 전송 컨텍스트
 * @param flow 송신 대상 TCP flow key
 * @param dir RST를 보낼 방향 (DIR_AB 또는 DIR_BA)
 * @param seq TCP sequence 번호
 * @param ack TCP acknowledgement 번호. 0이 아니면 ACK 플래그도 함께 설정된다.
 * @return int 0=전송 성공, 음수=송신 실패
 */
int tx_send_rst(void *tx_ctx, const flow_key_t *flow, tcp_dir_t dir,
                uint32_t seq, uint32_t ack) {
    /* 기본은 순수 RST */
    uint8_t flags = TCP_RST;

    /* ACK 번호가 있으면 RST|ACK 형태로 보낸다. */
    if (0 != ack) {
        flags |= TCP_ACK;
    }

    /* payload 없는 TCP RST 세그먼트를 생성해 전송한다. */
    return tx_send_tcp_segment(tx_ctx, flow, dir, seq, ack, flags, 0, NULL, 0);
}

/**
 * @brief snapshot에서 RST burst용 seq/ack/window 기준값을 계산한다.
 *
 * 양방향 세션을 모두 본 경우에는 기존 계산식을 유지한다. 아직 반대 방향
 * 패킷을 보지 못한 초기 단계에서는, 관측한 방향의 마지막 ACK 값을 반대 방향
 * seq의 근사치로 사용해 best-effort unilateral RST를 허용한다.
 *
 * @param snap 현재 세션 상태 snapshot
 * @param dir RST를 보낼 방향
 * @param seq_base 계산된 seq 기준값
 * @param ack 계산된 ack 값
 * @param win 계산된 수신 window
 * @return int 계산 성공 시 0, 상태 부족 시 -1
 */
static int calc_rst_params_from_snapshot(const httgw_sess_snapshot_t *snap,
                                         tcp_dir_t dir, uint32_t *seq_base,
                                         uint32_t *ack, uint32_t *win) {
    /* 기본 인자 검증 */
    if (NULL == snap || NULL == seq_base || NULL == ack || NULL == win) {
        return -1;
    }

    /* AB 방향 RST 기준값 계산 */
    if (DIR_AB == dir) {
        if (0 != snap->seen_ab && 0 != snap->seen_ba) {
            if (0 == snap->next_seq_ab || 0 == snap->next_seq_ba) {
                return -1;
            }

            *seq_base = snap->next_seq_ab;
            *ack      = snap->next_seq_ba + HTTGW_SERVER_NEXT_BIAS;
            *win      = scaled_window_value(snap->win_ba, snap->win_scale_ba);
            return (0 == *win) ? -1 : 0;
        }

        if (0 == snap->seen_ba || 0 == snap->next_seq_ba ||
            0 == snap->last_ack_ba) {
            return -1;
        }

        *seq_base = snap->last_ack_ba;
        *ack      = snap->next_seq_ba + HTTGW_SERVER_NEXT_BIAS;
        *win      = scaled_window_value(snap->win_ba, snap->win_scale_ba);
        return (0 == *win) ? -1 : 0;
    }

    /* BA 방향 RST 기준값 계산 */
    if (0 != snap->seen_ab && 0 != snap->seen_ba) {
        if (0 == snap->next_seq_ab || 0 == snap->next_seq_ba) {
            return -1;
        }

        *seq_base = snap->next_seq_ba + HTTGW_SERVER_NEXT_BIAS;
        *ack      = snap->next_seq_ab;
        *win      = scaled_window_value(snap->win_ab, snap->win_scale_ab);
        return (0 == *win) ? -1 : 0;
    }

    if (0 == snap->seen_ab || 0 == snap->next_seq_ab ||
        0 == snap->last_ack_ab) {
        return -1;
    }

    *seq_base = snap->last_ack_ab + HTTGW_SERVER_NEXT_BIAS;
    *ack      = snap->next_seq_ab;
    *win      = scaled_window_value(snap->win_ab, snap->win_scale_ab);
    return (0 == *win) ? -1 : 0;
}

/**
 * @brief 세션 상태 또는 snapshot을 기준으로 RST 패킷 버스트를 전송한다.
 *
 * 지정한 flow와 방향(dir)에 대해 현재 TCP 상태를 계산하고,
 * 수신 윈도우 범위 안에 여러 개의 RST를 분산 전송한다.
 * snap이 주어지면 snapshot 값을 우선 사용하고, 없으면 live session 상태를
 * 사용한다.
 *
 * @param gw RST 송신에 사용할 httgw 인스턴스
 * @param flow RST를 보낼 대상 TCP flow key
 * @param dir RST를 보낼 방향 (DIR_AB 또는 DIR_BA)
 * @param snap 선택적 세션 snapshot. NULL이면 현재 세션 상태를 직접 사용한다.
 * @return int 성공 시 0, 실패 시 -1
 */
int httgw_request_rst_with_snapshot(httgw_t *gw, const flow_key_t *flow,
                                    tcp_dir_t                    dir,
                                    const httgw_sess_snapshot_t *snap) {
    /* 현재 flow의 live session */
    httgw_session_t *sess;
    /* snapshot이 없을 때 사용할 임시 복사본 */
    httgw_sess_snapshot_t live_snap;
    /* 실제 계산에 사용할 snapshot 포인터 */
    const httgw_sess_snapshot_t *rst_snap;
    /* burst 기준 seq/ack/window */
    uint32_t seq_base = 0;
    uint32_t ack      = 0;
    uint32_t win      = 0;
    /* 성공 송신 개수와 마지막 오류 */
    int sent_ok  = 0;
    int last_err = -1;

    /* 기본 인자와 방향값이 정상인지 먼저 확인한다. */
    if (NULL == gw || NULL == flow) {
        return -1;
    }
    if (dir != DIR_AB && dir != DIR_BA) {
        return -1;
    }

    /* 실제 송신 함수가 연결되지 않았으면 RST를 만들 수 없다. */
    if (NULL == gw->tx_send_rst) {
        return -1;
    }
    /*
     * flow에 대응하는 live session을 찾는다.
     * 현재 구현은 중복 RST 전송 여부를 세션 플래그로 관리하므로
     * snapshot이 있어도 session lookup 자체는 필요하다.
     */
    sess = sess_find(gw, flow);
    if (NULL == sess) {
        return -1;
    }

    /* 같은 방향으로 이미 RST를 보낸 세션이면 재전송하지 않는다. */
    if (dir == DIR_AB && sess->rst_sent_ab) {
        return 0;
    }
    if (dir == DIR_BA && sess->rst_sent_ba) {
        return 0;
    }

    /*
     * snapshot이 없으면 live session을 동일한 snapshot 형태로 복사해 같은 계산
     * 경로를 사용한다. 이렇게 하면 양방향 세션이 아직 완성되지 않아도, 마지막
     * ACK를 기반으로 best-effort unilateral RST를 계산할 수 있다.
     */
    if (NULL != snap) {
        rst_snap = snap;
    } else {
        memset(&live_snap, 0, sizeof(live_snap));
        live_snap.base_seq_ab  = sess->base_seq_ab;
        live_snap.base_seq_ba  = sess->base_seq_ba;
        live_snap.last_ack_ab  = sess->last_ack_ab;
        live_snap.next_seq_ab  = sess->next_seq_ab;
        live_snap.last_ack_ba  = sess->last_ack_ba;
        live_snap.next_seq_ba  = sess->next_seq_ba;
        live_snap.win_ab       = sess->win_ab;
        live_snap.win_ba       = sess->win_ba;
        live_snap.win_scale_ab = sess->win_scale_ab;
        live_snap.win_scale_ba = sess->win_scale_ba;
        live_snap.seen_ab      = sess->seen_ab;
        live_snap.seen_ba      = sess->seen_ba;
        rst_snap               = &live_snap;
    }

    last_err =
        calc_rst_params_from_snapshot(rst_snap, dir, &seq_base, &ack, &win);
    if (0 != last_err) {
        return -1;
    }

    /* 수신 윈도우가 0이면 유효한 burst 분산 범위를 만들 수 없다. */
    if (0 == win) {
        return -1;
    }

    /*
     * 수신 윈도우 범위 안에 RST를 여러 개 분산 전송한다.
     * 수신측이 현재 어느 seq를 받아들일지 애매한 경우를 대비한 burst다.
     */
    for (uint32_t i = 0; i < HTTGW_RST_BURST_COUNT; i++) {
        uint32_t seq_off;

        /* burst 개수가 1이거나 window가 1이면 기준 seq 하나만 사용한다. */
        if (1 == HTTGW_RST_BURST_COUNT || 1 == win) {
            seq_off = 0;
        } else {
            /* seq_off는 seq_base에 더할 오프셋이다. */
            seq_off = (uint32_t)(((uint64_t)(win - 1) * i) /
                                 (HTTGW_RST_BURST_COUNT - 1));
        }

        uint32_t seq_try = seq_base + seq_off;

        /* 계산된 seq/ack 조합으로 RST 1회를 전송한다. */
        int rc = gw->tx_send_rst(gw->tx_ctx, flow, dir, seq_try, ack);
        if (0 == rc) {
            sent_ok++;
        } else {
            last_err = rc;
        }
    }

    /* 모든 burst 전송이 성공했을 때만 해당 방향 RST 송신 완료로 기록한다. */
    if ((int)HTTGW_RST_BURST_COUNT == sent_ok) {
        if (dir == DIR_AB) {
            sess->rst_sent_ab = 1;
        } else {
            sess->rst_sent_ba = 1;
        }
        return 0;
    }

    /* 하나라도 실패했으면 마지막 송신 오류를 상위로 전달한다. */
    (void)last_err;
    return -1;
}

/**
 * @brief 세션 snapshot을 기준으로 클라이언트 방향 HTTP 차단 응답을 주입한다.
 *
 * 서버에서 클라이언트로 가는 방향(DIR_BA)으로 위조 TCP 세그먼트를 생성해
 * HTTP 차단 페이지 payload를 분할 전송하고, 마지막에 FIN|ACK를 보내 연결을
 * 정리한다. seq/ack 기준값은 전달받은 snapshot에서 계산한다.
 *
 * @param gw 주입 송신에 사용할 httgw 인스턴스
 * @param flow 차단 응답을 주입할 대상 TCP flow key
 * @param snap 현재 세션의 seq/ack/window 정보를 담은 snapshot
 * @param payload 클라이언트에게 보낼 HTTP 응답 바디/헤더 데이터
 * @param payload_len payload 전체 길이
 * @return int 성공 시 0, 실패 시 -1
 */
int httgw_inject_block_response_with_snapshot(httgw_t                     *gw,
                                              const flow_key_t            *flow,
                                              const httgw_sess_snapshot_t *snap,
                                              const uint8_t *payload,
                                              size_t         payload_len) {
    /* 현재 flow의 live session */
    httgw_session_t *sess;
    /* 응답 주입 기준 seq/ack */
    uint32_t seq_base;
    uint32_t ack;
    /* 누적 전송 바이트와 마지막 오류 */
    size_t sent     = 0;
    int    last_err = -1;

    /* 기본 인자와 payload 길이가 정상인지 먼저 확인한다. */
    if (NULL == gw || NULL == flow || NULL == snap || NULL == payload ||
        0 == payload_len) {
        return -1;
    }

    /* 실제 L3/TCP 송신 컨텍스트가 연결되지 않았으면 주입할 수 없다. */
    if (NULL == gw->tx_ctx) {
        return -1;
    }

    /*
     * 현재 구현은 live session 존재를 전제로 주입한다.
     * snapshot은 seq/ack 계산에 쓰고, session lookup은 flow 유효성 확인 용도로
     * 쓴다.
     */
    sess = sess_find(gw, flow);
    if (NULL == sess) {
        return -1;
    }

    /* 양방향 상태를 모두 본 세션이 아니면 정상적인 응답 주입 기준을 만들 수
     * 없다. */
    if (0 == snap->seen_ab || 0 == snap->seen_ba) {
        return -1;
    }
    if (0 == snap->next_seq_ab || 0 == snap->next_seq_ba) {
        return -1;
    }

    /* 서버 -> 클라이언트 방향(DIR_BA)으로 보낼 seq/ack 기준값을 snapshot에서
     * 잡는다. */
    seq_base = snap->next_seq_ba;
    ack      = snap->next_seq_ab;

    /*
     * 차단 응답 payload를 여러 TCP 세그먼트로 분할 전송한다.
     * 마지막 payload 세그먼트에는 PSH를 넣어 클라이언트가 바로 처리하게 한다.
     */
    while (sent < payload_len) {
        size_t  chunk = payload_len - sent;
        uint8_t flags = TCP_ACK;
        int     rc;

        /* 한 세그먼트가 너무 커지지 않도록 주입용 상한으로 자른다. */
        if (chunk > HTTGW_INJECT_SEGMENT_BYTES) {
            chunk = HTTGW_INJECT_SEGMENT_BYTES;
        }

        /* 마지막 payload 조각이면 PSH를 같이 넣는다. */
        if (sent + chunk == payload_len) {
            flags |= TCP_PSH;
        }

        /* DIR_BA 방향으로 위조 응답 데이터를 실제 전송한다. */
        rc = tx_send_tcp_segment(gw->tx_ctx, flow, DIR_BA,
                                 seq_base + (uint32_t)sent, ack, flags,
                                 snap->win_ba, payload + sent, chunk);
        if (0 != rc) {
            return -1;
        }
        sent += chunk;
    }

    /* payload 전송이 끝나면 FIN|ACK로 응답 방향 연결을 정리한다. */
    last_err = tx_send_tcp_segment(
        gw->tx_ctx, flow, DIR_BA, seq_base + (uint32_t)payload_len, ack,
        (uint8_t)(TCP_FIN | TCP_ACK), snap->win_ba, NULL, 0);

    /* 마지막 FIN 전송 결과를 상위로 반환한다. */
    return (0 == last_err) ? 0 : -1;
}

/**************************** httgw를 바깥에서 쓰기 쉽게 감싼 wrapper AIP
 * *************************** */
int httgw_request_rst(httgw_t *gw, const flow_key_t *flow, tcp_dir_t dir) {
    /* live session 기준 RST helper 호출 */
    return httgw_request_rst_with_snapshot(gw, flow, dir, NULL);
}

int sess_get_or_create(httgw_t *gw, const flow_key_t flow, uint64_t ts_ms) {
    /* 게이트웨이 없으면 실패 */
    if (NULL == gw) {
        return -1;
    }
    /* 내부 세션 생성 helper를 외부용 int API로 감싼다 */
    return sess_get_or_create_internal(gw, &flow, ts_ms) ? 0 : -1;
}

int sess_lookup(const httgw_t *gw, const flow_key_t flow) {
    /* 게이트웨이 없으면 실패 */
    if (NULL == gw) {
        return -1;
    }
    /* 내부 세션 조회 helper를 외부용 int API로 감싼다 */
    return sess_find(gw, &flow) ? 0 : -1;
}

void sess_gc(httgw_t *gw, uint64_t ts_ms) {
    /* 외부용 wrapper에서 내부 GC 호출 */
    httgw_gc(gw, ts_ms);
}

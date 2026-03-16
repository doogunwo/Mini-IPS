/**
 * @file httgw.h
 * @brief HTTP 게이트웨이 공개 인터페이스
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "http_stream.h"

#ifndef REASM_SESSION_TIMEOUT_MS
#define REASM_SESSION_TIMEOUT_MS (60ULL * 1000ULL)
#endif

#ifndef REASM_MAX_SESSIONS
#define REASM_MAX_SESSIONS 4096
#endif

#ifndef REASM_MAX_SEGMENTS_PER_DIR
#define REASM_MAX_SEGMENTS_PER_DIR 1024
#endif

#ifndef REASM_MAX_BYTES_PER_DIR
#define REASM_MAX_BYTES_PER_DIR (12U * 1024U * 1024U)
#endif

#ifndef HTTGW_SERVER_NEXT_BIAS
#define HTTGW_SERVER_NEXT_BIAS 64U
#endif

/* TCP flags */
enum {
    TCP_FIN = 0x01,
    TCP_SYN = 0x02,
    TCP_RST = 0x04,
    TCP_PSH = 0x08,
    TCP_ACK = 0x10,
    TCP_URG = 0x20,
    TCP_ECE = 0x40,
    TCP_CWR = 0x80
};

/** TCP 흐름 내부의 패킷 방향을 나타낸다. */
typedef enum { DIR_AB = 0, DIR_BA = 1 } tcp_dir_t;

/* 5-tuple key (host order) */
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto; /* 6 for TCP */
} flow_key_t;

/** 중간부터 관측된 흐름에 대한 재조립 동작 모드이다. */
typedef enum {
    REASM_MODE_STRICT_SYN = 0,
    REASM_MODE_LATE_START = 1
} reasm_mode_t;

/** 게이트웨이 실행 통계이다. */
typedef struct {
    size_t http_msgs;
    size_t reqs;
    size_t reasm_errs;
    size_t parse_errs;
} httgw_stats_t;

/** 파싱된 클라이언트 요청을 전달하는 콜백이다. */
typedef void (*httgw_on_request_cb)(const flow_key_t *flow, tcp_dir_t dir,

                                    const http_message_t *msg,
                                    const char *query, size_t query_len,
                                    void *user);

/** IP 보조 테이블에서 사용하는 연결 리스트 노드이다. */
typedef struct ip_node {
    uint32_t        ip;
    struct ip_node *next;
} ip_node_t;

/** 파서 및 재조립 단계에서 사용하는 오류 콜백이다. */
typedef void (*httgw_on_error_cb)(const char *stage, const char *detail,
                                  void *user);

/** 게이트웨이 생성 시 등록하는 콜백 묶음이다. */
typedef struct {
    httgw_on_request_cb on_request;
    httgw_on_error_cb   on_error;
} httgw_callbacks_t;

/** 파서와 재조립 계층이 공유하는 게이트웨이 설정이다. */
typedef struct {
    size_t       max_buffer_bytes;
    size_t       max_body_bytes;
    reasm_mode_t reasm_mode;
    int          verbose;
} httgw_cfg_t;

/** 게이트웨이 내부 구조를 숨기는 핸들 타입이다. */
typedef struct httgw httgw_t;

/** RST 주입에 사용하는 L3 송신 컨텍스트이다. */
typedef struct tx_ctx {
    int fd;
    int (*send_l3)(void *ctx, const uint8_t *buf, size_t len);
    void *ctx;
} tx_ctx_t;

typedef struct httgw_session httgw_session_t;

/** 로그 출력과 RST 계산에 사용하는 TCP 상태 스냅샷이다. */
typedef struct {
    uint32_t base_seq_ab;
    uint32_t base_seq_ba;
    uint32_t last_ack_ab;
    uint32_t next_seq_ab;
    uint32_t last_ack_ba;
    uint32_t next_seq_ba;
    uint16_t win_ab;
    uint16_t win_ba;
    uint8_t  win_scale_ab;
    uint8_t  win_scale_ba;
    uint8_t  seen_ab;
    uint8_t  seen_ba;
} httgw_sess_snapshot_t;

/** 게이트웨이 인스턴스를 생성한다. */
httgw_t *httgw_create(const httgw_cfg_t *cfg, const httgw_callbacks_t *cbs,
                      void *user);
/** 게이트웨이 인스턴스와 모든 세션을 해제한다. */
void httgw_destroy(httgw_t *gw);

/** 캡처된 패킷 한 개를 TCP/HTTP 처리 파이프라인에 투입한다. */
int httgw_ingest_packet(httgw_t *gw, const uint8_t *pkt, uint32_t caplen,
                        uint64_t ts_ms);
/** 만료된 세션을 정리한다. */
void httgw_gc(httgw_t *gw, uint64_t now_ms);
/** 읽기 전용 실행 통계를 돌려준다. */
const httgw_stats_t *httgw_stats(const httgw_t *gw);
/** 지정한 흐름의 현재 TCP 상태 스냅샷을 복사한다. */
int httgw_get_session_snapshot(const httgw_t *gw, const flow_key_t *flow,
                               httgw_sess_snapshot_t *out);

/** 파싱된 요청 URI에서 query 부분을 추출한다. */
int httgw_extract_query(const http_message_t *msg, const char **q,
                        size_t *q_len);

/** 파싱된 HTTP 메시지에서 헤더 값을 조회한다. */
int httgw_header_get(const http_message_t *msg, const char *name,
                     const uint8_t **value, size_t *value_len);

typedef struct ip_hash ip_hash_t;

/* --------------------------- RST 패킷 관련 ---------------------------*/
/** 게이트웨이가 사용하는 원시 RST 송신 콜백이다. */
typedef int (*httgw_send_rst_fn)(void *tx_ctx, const flow_key_t *flow,
                                 tcp_dir_t dir, uint32_t seq, uint32_t ack);

/** 원시 송신 컨텍스트를 초기화한다. */
int tx_ctx_init(tx_ctx_t *tx);
/** 원시 송신 컨텍스트를 정리한다. */
void tx_ctx_destroy(tx_ctx_t *tx);
/** 이미 구성된 L3 패킷을 송신한다. */
int tx_send_l3(void *ctx, const uint8_t *buf, size_t len);
/** TCP RST 패킷 한 개를 생성하고 송신한다. */
int tx_send_rst(void *tx_ctx, const flow_key_t *flow, tcp_dir_t dir,
                uint32_t seq, uint32_t ack);
/** RST 주입에 사용할 원시 송신 컨텍스트를 등록한다. */
int httgw_set_tx(httgw_t *gw, tx_ctx_t *tx);

/** 지정한 흐름 방향으로 RST 주입을 요청한다. */
int httgw_request_rst(httgw_t *gw, const flow_key_t *flow, tcp_dir_t dir);
/** 미리 확보한 TCP 상태 스냅샷으로 RST 주입을 요청한다. */
int httgw_request_rst_with_snapshot(httgw_t *gw, const flow_key_t *flow,
                                    tcp_dir_t                    dir,
                                    const httgw_sess_snapshot_t *snap);
int httgw_inject_block_response_with_snapshot(httgw_t                     *gw,
                                              const flow_key_t            *flow,
                                              const httgw_sess_snapshot_t *snap,
                                              const uint8_t *payload,
                                              size_t         payload_len);

/** 필요 시 세션 엔트리를 생성하는 테스트용 헬퍼이다. */
int sess_get_or_create(httgw_t *gw, const flow_key_t flow, uint64_t ts_ms);
/** 세션 존재 여부를 확인하는 테스트용 헬퍼이다. */
int sess_lookup(const httgw_t *gw, const flow_key_t flow);
/** 세션 가비지 컬렉션을 수행하는 테스트용 헬퍼이다. */
void sess_gc(httgw_t *gw, uint64_t ts_ms);

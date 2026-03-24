/**
 * @file reasm.h
 * @brief HTTP 게이트웨이 내부 TCP 재조립 인터페이스
 *
 * reasm 계층은 TCP sequence 기준으로 payload를 정렬하고 trim하며,
 * 연속 구간만 상위 HTTP 파서에 전달한다.
 */
#pragma once

#include "httgw.h"

/** 재조립 결과를 상위 계층으로 전달하는 콜백 타입이다. */
typedef void (*reasm_on_data_cb)(const flow_key_t *flow, tcp_dir_t dir,
                                 const uint8_t *data, uint32_t len,
                                 uint32_t seq_start, void *user);

/** 재조립 엔진 내부 구조를 숨기는 핸들 타입이다. */
typedef struct reasm_ctx reasm_ctx_t;

/** 재조립 컨텍스트를 생성한다. */
reasm_ctx_t *reasm_create(uint32_t nbuckets, reasm_on_data_cb cb, void *user);
/** 재조립 모드를 갱신한다. */
void reasm_set_mode(reasm_ctx_t *c, reasm_mode_t mode);
/** 재조립 컨텍스트와 모든 세션을 해제한다. */
void reasm_destroy(reasm_ctx_t *c);
/** 만료된 재조립 세션을 정리한다. */
void reasm_gc(reasm_ctx_t *c, uint64_t now_ms);
/** 재조립 순서 관련 누적 통계를 복사한다. */
void reasm_get_stats(const reasm_ctx_t *c, reasm_stats_t *out);
/** TCP 패킷 한 개를 재조립 엔진에 투입한다. */
int reasm_ingest(reasm_ctx_t *c, const flow_key_t *flow, tcp_dir_t dir,
                 uint32_t seq, uint8_t tcp_flags, const uint8_t *payload,
                 uint32_t len, uint64_t ts_ms);

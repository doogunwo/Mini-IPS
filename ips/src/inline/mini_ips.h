#pragma once

#include "engine.h"
#include "detect.h"
#include "blocking.h"
#include "decoding.h"
#include "normalization.h"
#include "regex.h"
#include "ring.h"
#include "tproxy.h"
#include "http_parser.h"

#define MINI_IPS_RULESET_ENV     "MINI_IPS_RULESET_DIR"
#define MINI_IPS_RING_SLOT_COUNT 256
#define MINI_IPS_MAX_SESSIONS    256

typedef struct mini_ips_reasm {
    int      in_use;
    uint32_t session_id;
    size_t   cap;
    size_t   len;
    uint8_t *buf;
} mini_ips_reasm_t;

typedef struct mini_ips_ctx {
    tproxy_t *tp;
    regex_db_t db;
    detect_engine_t *engine;

    req_ring_t req_ring;
    res_ring_t res_ring;

    mini_ips_session_t sessions[MINI_IPS_MAX_SESSIONS];
    mini_ips_reasm_t   reasm[MINI_IPS_MAX_SESSIONS];
    uint32_t           next_session_id;

    const char *ruleset_path;
    int initialized;
    int stop;
    int ring_enabled;
} mini_ips_ctx_t;
/**
 * @brief ctx 초기화 함수
 * 공용 런타임 자원 초기화함
 * @param ctx 
 * @return int 
 */
int mini_ips_set(mini_ips_ctx_t *ctx);

/**
 * @brief TP 레이어 실행
 * 리스너 기반 억셉/이폴 루프 수행
 * req ring 적재와 res ring 소비를 포함한 저수준 I/O 처리담당
 */

int mini_ips_run_tp(mini_ips_ctx_t *ctx);

int mini_ips_run_worker(mini_ips_ctx_t *ctx);

void mini_ips_destroy(mini_ips_ctx_t *ctx);

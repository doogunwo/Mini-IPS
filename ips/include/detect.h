/**
 * @file detect.h
 * @brief 탐지 엔진 공개 인터페이스
 */
#ifndef DETECT_H
#define DETECT_H

#include <stddef.h>
#include <stdint.h>

#include "regex.h"
#define APP_DETECT_THRESHOLD 80


typedef enum {
    DETECT_JIT_AUTO = -1,
    DETECT_JIT_OFF  = 0,
    DETECT_JIT_ON   = 1
} detect_jit_mode_t;

typedef struct detect_engine detect_engine_t;

typedef struct {
    const IPS_Signature *rule;
    ips_context_t        context;
    char                *matched_text;
    uint64_t             elapsed_us;
} detect_match_t;

typedef struct {
    detect_match_t *items;
    size_t          count;
    size_t          capacity;
} detect_match_list_t;


detect_engine_t *detect_engine_create(const char       *policy_name,
                                      detect_jit_mode_t jit_mode);

void detect_engine_destroy(detect_engine_t *e);

int detect_engine_collect_matches_ctx_timed(detect_engine_t *e,
                                            const uint8_t *data, size_t len,
                                            ips_context_t        ctx,
                                            detect_match_list_t *matches,
                                            uint64_t *elapsed_us_sum);

void detect_match_list_init(detect_match_list_t *matches);
void detect_match_list_free(detect_match_list_t *matches);

/**
 * @brief 디버깅과 로그 출력을 위해 마지막 내부 오류 문자열을 돌려준다.
 * @param e 탐지 엔진 핸들.
 * @return 내부 오류 문자열 포인터.
 */
const char *detect_engine_last_error(const detect_engine_t *e);
const char *detect_engine_backend_name(const detect_engine_t *e);
int         detect_engine_jit_enabled(const detect_engine_t *e);

#endif

/**
 * @file detect.h
 * @brief 탐지 엔진 공개 인터페이스
 */
#ifndef DETECT_H
#define DETECT_H

#include <stddef.h>
#include <stdint.h>

#include "regex.h"

typedef enum {
    DETECT_JIT_AUTO = -1,
    DETECT_JIT_OFF = 0,
    DETECT_JIT_ON = 1
} detect_jit_mode_t;

typedef struct detect_engine detect_engine_t;

typedef struct {
    const IPS_Signature *rule;
    ips_context_t context;
    char *matched_text;
    uint64_t elapsed_us;
} detect_match_t;

typedef struct {
    detect_match_t *items;
    size_t count;
    size_t capacity;
} detect_match_list_t;

/**
 * @brief 탐지 엔진 인스턴스 생성
 * @details 입력받은 정책 이름을 바탕으로 탐지 엔진을 초기화하고 메모리를 할당한다. 
 * JIT 모드 설정에 따라 룰 컴파일 방식을 결정한다.
 * @param policy_name 탐지에 사용할 정책 파일 경로 또는 이름 문자열
 * @param jit_mode JIT(Just-In-Time) 컴파일러 활성화 및 모드 설정값
 * @return 생성된 detect_engine_t 객체의 포인터, 생성 실패 시 NULL 반환
 */
detect_engine_t *detect_engine_create(const char *policy_name, detect_jit_mode_t jit_mode);

/**
 * @brief 생성된 탐지 엔진을 해제한다.
 * @param e 탐지 엔진 핸들.
 */
void detect_engine_destroy(detect_engine_t *e);

/**
 * @brief 기본 컨텍스트로 입력 버퍼를 탐지한다.
 * @param e 탐지 엔진 핸들.
 * @param data 입력 버퍼.
 * @param len 입력 길이.
 * @param matched_rule 최초 매칭된 룰을 돌려줄 출력 포인터.
 * @return 매칭이면 1, 미매칭이면 0, 오류이면 음수.
 */
int detect_engine_match(
    detect_engine_t *e,
    const uint8_t *data,
    size_t len,
    const IPS_Signature **matched_rule
);

/**
 * @brief 지정한 IPS 컨텍스트로 입력 버퍼를 탐지한다.
 * @param e 탐지 엔진 핸들.
 * @param data 입력 버퍼.
 * @param len 입력 길이.
 * @param ctx IPS 파싱 컨텍스트.
 * @param matched_rule 최초 매칭된 룰을 돌려줄 출력 포인터.
 * @return 매칭이면 1, 미매칭이면 0, 오류이면 음수.
 */
int detect_engine_match_ctx(
    detect_engine_t *e,
    const uint8_t *data,
    size_t len,
    ips_context_t ctx,
    const IPS_Signature **matched_rule
);

int detect_engine_collect_matches_ctx(
    detect_engine_t *e,
    const uint8_t *data,
    size_t len,
    ips_context_t ctx,
    detect_match_list_t *matches
);

void detect_match_list_init(detect_match_list_t *matches);
void detect_match_list_free(detect_match_list_t *matches);

/**
 * @brief 디버깅과 로그 출력을 위해 마지막 내부 오류 문자열을 돌려준다.
 * @param e 탐지 엔진 핸들.
 * @return 내부 오류 문자열 포인터.
 */
const char *detect_engine_last_error(const detect_engine_t *e);
const char *detect_engine_backend_name(const detect_engine_t *e);
int detect_engine_jit_enabled(const detect_engine_t *e);

#endif

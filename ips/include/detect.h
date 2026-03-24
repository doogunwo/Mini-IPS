/**
 * @file detect.h
 * @brief 탐지 엔진 공개 인터페이스
 *
 * `detect` 계층은 상위 런타임이 넘긴 HTTP 컨텍스트별 바이트열을 받아
 * 실제 regex backend(PCRE2/Hyperscan)를 호출하고, 매치 결과를
 * `detect_match_list_t`로 수집하는 얇은 파사드 역할을 담당한다.
 */
#ifndef DETECT_H
#define DETECT_H

#include <stddef.h>
#include <stdint.h>

#include "regex.h"
#define APP_DETECT_THRESHOLD 80

/** detect backend가 JIT을 어떻게 사용할지 지정하는 정책이다. */
typedef enum {
    DETECT_JIT_AUTO = -1,
    DETECT_JIT_OFF  = 0,
    DETECT_JIT_ON   = 1
} detect_jit_mode_t;

typedef struct detect_engine detect_engine_t;

/** 한 번의 탐지에서 얻은 단일 매치 결과이다. */
typedef struct {
    const IPS_Signature *rule;         /**< 매치된 시그니처 */
    ips_context_t        context;      /**< 어느 HTTP 컨텍스트에서 매치됐는지 */
    char                *matched_text; /**< 로그 출력을 위해 복사한 매치 문자열 */
    uint64_t             elapsed_us;   /**< 이 매치 평가에 사용된 누적 시간 */
} detect_match_t;

/** 매치 결과를 동적 배열로 모으는 컨테이너이다. */
typedef struct {
    detect_match_t *items;    /**< 결과 배열 */
    size_t          count;    /**< 현재 채워진 엔트리 수 */
    size_t          capacity; /**< 현재 할당된 배열 크기 */
} detect_match_list_t;

/** 정책 이름에 맞는 탐지 엔진 인스턴스를 생성한다. */
detect_engine_t *detect_engine_create(const char       *policy_name,
                                      detect_jit_mode_t jit_mode);

/** 탐지 엔진 인스턴스를 해제한다. */
void detect_engine_destroy(detect_engine_t *e);

/**
 * @brief 지정한 HTTP 컨텍스트에 대해 매치를 수집한다.
 *
 * 상위 런타임은 URI, 헤더, 바디, args 같은 컨텍스트별 slice를 이 함수에
 * 넘기고, 함수는 backend를 호출해 매치 결과를 `matches` 뒤에 누적한다.
 */
int detect_engine_collect_matches_ctx_timed(detect_engine_t *e,
                                            const uint8_t *data, size_t len,
                                            ips_context_t        ctx,
                                            detect_match_list_t *matches,
                                            uint64_t *elapsed_us_sum);

/** 빈 매치 리스트를 초기화한다. */
void detect_match_list_init(detect_match_list_t *matches);
/** 매치 리스트 내부 동적 메모리를 모두 해제한다. */
void detect_match_list_free(detect_match_list_t *matches);

/**
 * @brief 디버깅과 로그 출력을 위해 마지막 내부 오류 문자열을 돌려준다.
 * @param e 탐지 엔진 핸들.
 * @return 내부 오류 문자열 포인터.
 */
const char *detect_engine_last_error(const detect_engine_t *e);
/** 현재 detect 엔진이 사용 중인 backend 이름을 반환한다. */
const char *detect_engine_backend_name(const detect_engine_t *e);
/** 현재 detect 엔진에서 JIT이 활성화됐는지 반환한다. */
int         detect_engine_jit_enabled(const detect_engine_t *e);

#endif

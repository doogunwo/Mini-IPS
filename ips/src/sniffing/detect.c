/**
 * @file detect.c
 * @brief 탐지 엔진 구현
 *
 * 이 파일은 "정책 이름 -> 룰 집합 -> backend runtime" 연결을 담당한다.
 * 실제 regex 실행은 engine.c가 수행하고, detect.c는 상위 런타임이 쓰기 쉬운
 * 형태로 룰 선택과 match list 관리만 담당한다.
 */
#include "detect.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "engine.h"

typedef struct policy_pattern_set {
    /* 선택된 룰 포인터 배열 */
    const IPS_Signature **rules;
    /* 선택된 룰 개수 */
    unsigned int count;
} policy_pattern_set_t;

/** detect 엔진 최상위 핸들. 선택한 룰 집합과 backend runtime을 함께 가진다. */
struct detect_engine {
    engine_runtime_t     *runtime;
    const IPS_Signature **rules;
    unsigned int          rule_count;
    char                  last_err[128];
};

static void set_err(detect_engine_t *e, const char *msg) {
    /* 엔진 포인터 검사 */
    if (NULL == e) {
        return;
    }
    /* NULL 메시지 보정 */
    if (NULL == msg) {
        msg = "unknown error";
    }
    /* 마지막 오류 문자열 갱신 */
    snprintf(e->last_err, sizeof(e->last_err), "%s", msg);
}
/* --------------------------- match collection --------------------------- */

/**
 * @brief 탐지 엔진의 핵심 탐지 함수
 * 입력 데이터에 대해 탐지 엔진을 실행하여 매치되는 룰과 매치된 텍스트를 matches
 * 리스트에 추가한다.
 * @param e 탐지 엔진 객체
 * @param data 검사할 바이트 데이터
 * @param len 데이터 길이
 * @param ctx 어떤 HTTP 영역을 볼지? 헤더, URL, ARGS, ARGS_NAMES, 바디 등등
 * @param matches 매치 결과 저장할 리스트
 * @param elapsed_us_sum 탐지 수행 시간 누적값을 저장할 포인터
 * @return int
 */
static int collect_matches_ctx_timed(detect_engine_t *e, const uint8_t *data,
                                     size_t len, ips_context_t ctx,
                                     detect_match_list_t *matches,
                                     uint64_t            *elapsed_us_sum) {
    /* 탐지 시간 출력 초기화 */
    if (NULL != elapsed_us_sum) {
        *elapsed_us_sum = 0;
    }
    /* 매치 리스트 포인터 검사 */
    if (NULL == matches) {
        if (NULL != e) {
            /* 오류 문자열 기록 */
            set_err(e, "null matches");
        }
        return -1;
    }
    /* 엔진/입력 데이터/길이 검사 */
    if (NULL == e || NULL == data || 0U == len) {
        return 0;
    }
    /* engine backend가 처리 가능한 길이 상한 검사 */
    if ((size_t)INT_MAX < len) {
        set_err(e, "payload too large");
        return -1;
    }

    /* 지원하는 detect context인지 검증 */
    switch (ctx) {
    case IPS_CTX_REQUEST_URI:
    case IPS_CTX_ARGS:
    case IPS_CTX_ARGS_NAMES:
    case IPS_CTX_REQUEST_HEADERS:
    case IPS_CTX_REQUEST_BODY:
    case IPS_CTX_RESPONSE_BODY:
    case IPS_CTX_ALL:
        break;
    default:
        /* 잘못된 context 오류 기록 */
        set_err(e, "invalid context");

        return -1;
    }
    /* engine backend에 실제 매치 수집 위임 */
    int rc = engine_runtime_collect_matches_timed(
        e->runtime, data, len, ctx, matches, elapsed_us_sum, e->last_err,
        sizeof(e->last_err));
    /* backend 반환값 전달 */
    return rc;
}

/**
 * @brief detect_match_list를 빈 상태로 초기화한다.
 *
 * @param matches 매치 결과 리스트
 */
void detect_match_list_init(detect_match_list_t *matches) {
    /* 출력 포인터 검사 */
    if (NULL == matches) {
        return;
    }
    /* 리스트 전체 초기화 */
    memset(matches, 0, sizeof(*matches));
}

/**
 * @brief detect_match_list 내부 항목과 배열 메모리를 해제한다.
 *
 * @param matches 매치 결과 리스트
 */
void detect_match_list_free(detect_match_list_t *matches) {
    /* 순회 인덱스 */
    size_t i;

    /* 입력 포인터 검사 */
    if (NULL == matches) {
        return;
    }
    for (i = 0; i < matches->count; i++) {
        /* 항목별 matched_text 해제 */
        free(matches->items[i].matched_text);
    }
    /* items 배열 해제 */
    free(matches->items);
    /* 구조체 초기화 */
    memset(matches, 0, sizeof(*matches));
}

/**
 * @brief 특정 정책 이름에 해당하는 룰 집합만 추려낸다.
 *
 * @param policy_name 찾을 정책 이름
 * @param out 결과 룰 집합
 * @return int 0이면 성공, -1이면 실패
 */
static int collect_policy_patterns(const char           *policy_name,
                                   policy_pattern_set_t *out) {
    /* 시그니처 순회 인덱스 */
    int i;
    /* 문자열 비교 결과 */
    int ret;
    /* 선택된 룰 개수 */
    unsigned int n = 0;

    /* 입력 포인터 검사 */
    if (NULL == policy_name || NULL == out) {
        return -1;
    }

    /* 선택 개수 초기화 */
    n = 0;
    /* 출력 구조체 초기화 */
    memset(out, 0, sizeof(*out));

    /* 선택 정책과 일치하는 룰 개수 1차 집계 */
    for (i = 0; i < g_signature_count; i++) {
        ret = strcmp(g_ips_signatures[i].policy_name, policy_name);
        if (0 == ret) {
            n++;
        }
    }

    /* 선택된 룰이 없으면 실패 */
    if (0 == n) {
        return -1;
    }

    /* 선택된 룰 포인터 배열 할당 */
    out->rules = (const IPS_Signature **)malloc(n * sizeof(*out->rules));
    if (NULL == out->rules) {
        /* 실패 시 출력 구조체 재초기화 */
        memset(out, 0, sizeof(*out));
        return -1;
    }

    /* 최종 룰 개수 저장 */
    out->count = n;
    /* 실제 채우기 인덱스 초기화 */
    n = 0;

    /* 선택 정책과 일치하는 룰 포인터 수집 */
    for (i = 0; i < g_signature_count; i++) {
        ret = strcmp(g_ips_signatures[i].policy_name, policy_name);
        if (0 == ret) {
            /* 선택 룰 배열에 포인터 저장 */
            out->rules[n] = &g_ips_signatures[i];
            n++;
        }
    }

    /* 정책별 룰 집합 수집 성공 */
    return 0;
}

/**
 * @brief 로드된 모든 룰을 하나의 집합으로 수집한다.
 *
 * @param out 결과 룰 집합
 * @return int 0이면 성공, -1이면 실패
 */
static int collect_all_patterns(policy_pattern_set_t *out) {
    /* 전체 룰 개수 */
    unsigned int n = (unsigned int)g_signature_count;
    /* 복사용 인덱스 */
    unsigned int i;

    /* 출력 구조체 초기화 */
    memset(out, 0, sizeof(*out));
    /* 로드된 룰이 없으면 실패 */
    if (0U == n) {
        return -1;
    }

    /* 전체 룰 포인터 배열 할당 */
    out->rules = (const IPS_Signature **)malloc(n * sizeof(*out->rules));
    if (NULL == out->rules) {
        /* 실패 시 출력 구조체 재초기화 */
        memset(out, 0, sizeof(*out));
        return -1;
    }
    /* 전체 룰 개수 저장 */
    out->count = n;

    for (i = 0; i < n; i++) {
        /* 전역 시그니처 포인터 복사 */
        out->rules[i] = &g_ips_signatures[i];
    }
    /* 전체 룰 수집 성공 */
    return 0;
}

/**
 * @brief collect_* 함수가 만든 임시 룰 집합을 해제한다.
 *
 * @param set 해제할 룰 집합
 */
static void free_policy_patterns(policy_pattern_set_t *set) {
    /* 룰 포인터 배열 해제 */
    free(set->rules);
    /* 구조체 초기화 */
    memset(set, 0, sizeof(*set));
}

/**
 * @brief 정책 이름에 맞는 탐지 엔진 인스턴스를 생성한다.
 *
 * JSONL 시그니처를 적재하고, 선택한 정책에 맞는 룰 집합만 모아 내부
 * regex backend 런타임을 초기화한다.
 *
 * @param policy_name 사용할 정책 이름, NULL/ALL이면 전체 룰 사용
 * @param jit_mode JIT 사용 정책
 * @return detect_engine_t* 생성된 탐지 엔진, 실패 시 NULL
 */
detect_engine_t *detect_engine_create(const char       *policy_name,
                                      detect_jit_mode_t jit_mode) {
    /* detect 엔진 객체 */
    detect_engine_t *e;
    /* 선택된 정책 룰 집합 */
    policy_pattern_set_t set;
    /* helper 반환값 */
    int ret;

    /* 임시 룰 집합 초기화 */
    memset(&set, 0, sizeof(set));

    /* JSONL 시그니처 로드 */
    ret = regex_signatures_load(NULL);
    if (0 != ret) {
        return NULL;
    }

    /* detect 엔진 객체 할당 */
    e = (detect_engine_t *)malloc(sizeof(*e));
    if (NULL == e) {
        return NULL;
    }
    /* 엔진 객체 0 초기화 */
    memset(e, 0, sizeof(*e));
    /* 마지막 오류 문자열 초기화 */
    e->last_err[0] = '\0';

    /* policy가 NULL, ALL, all, * 중 하나면 전체 룰 사용 */
    if (NULL == policy_name || '\0' == policy_name[0] ||
        0 == strcmp(policy_name, "ALL") || 0 == strcmp(policy_name, "all") ||
        0 == strcmp(policy_name, "*")) {
        /* 전체 룰 집합 수집 */
        ret = collect_all_patterns(&set);
        if (0 != ret) {
            /* 오류 문자열 기록 */
            set_err(e, "no patterns");
            /* 엔진 객체 정리 */
            detect_engine_destroy(e);
            return NULL;
        }
    } else {
        /* 지정 정책 룰 집합 수집 */
        ret = collect_policy_patterns(policy_name, &set);
        if (0 != ret) {
            /* 오류 문자열 기록 */
            set_err(e, "unknown policy");
            /* 엔진 객체 정리 */
            detect_engine_destroy(e);
            return NULL;
        }
    }

    /* 선택된 룰 집합으로 backend runtime 생성 */
    e->runtime = engine_runtime_create(set.rules, set.count, jit_mode,
                                       e->last_err, sizeof(e->last_err));
    if (NULL == e->runtime) {
        /* 임시 룰 집합 해제 */
        free_policy_patterns(&set);
        /* 엔진 객체 정리 */
        detect_engine_destroy(e);
        return NULL;
    }

    /* 선택된 룰 집합 포인터 저장 */
    e->rules = set.rules;
    /* 선택된 룰 개수 저장 */
    e->rule_count = set.count;
    /* detect 엔진 생성 성공 */
    return e;
}

/**
 * @brief 탐지 엔진과 내부 regex runtime을 해제한다.
 *
 * @param e 해제할 탐지 엔진
 */
void detect_engine_destroy(detect_engine_t *e) {
    /* 엔진 포인터 검사 */
    if (NULL == e) {
        return;
    }
    /* backend runtime 해제 */
    engine_runtime_destroy(e->runtime);
    /* 선택된 룰 포인터 배열 해제 */
    free(e->rules);
    /* detect 엔진 객체 해제 */
    free(e);
}

/**
 * @brief 지정한 context에서 첫 번째 매칭 룰 하나를 찾는다.
 *
 * @param e 탐지 엔진
 * @param data 검사할 데이터
 * @param len 데이터 길이
 * @param ctx 검사 context
 * @param matched_rule 첫 매칭 룰을 받을 포인터
 * @return int 0이면 정상 완료, -1이면 오류
 */
int detect_engine_match_ctx(detect_engine_t *e, const uint8_t *data, size_t len,
                            ips_context_t         ctx,
                            const IPS_Signature **matched_rule) {
    /* 지원하는 detect context인지 검증 */
    switch (ctx) {
    case IPS_CTX_REQUEST_URI:
    case IPS_CTX_ARGS:
    case IPS_CTX_ARGS_NAMES:
    case IPS_CTX_REQUEST_HEADERS:
    case IPS_CTX_REQUEST_BODY:
    case IPS_CTX_RESPONSE_BODY:
    case IPS_CTX_ALL:
        break;
    default:
        /* 출력 포인터가 있으면 NULL 반환 */
        if (NULL != matched_rule) {
            *matched_rule = NULL;
        }
        if (NULL != e) {
            /* 오류 문자열 기록 */
            set_err(e, "invalid context");
        }
        return -1;
    }

    /* NULL 엔진은 no-op 처리 */
    if (NULL == e) {
        return 0;
    }

    /* backend에 first match 탐지 위임 */
    int ret =
        engine_runtime_match_first(e->runtime, data, len, ctx, matched_rule,
                                   e->last_err, sizeof(e->last_err));
    /* backend 반환값 전달 */
    return ret;
}

/**
 * @brief 지정한 context에서 매칭된 모든 룰을 수집한다.
 *
 * @param e 탐지 엔진
 * @param data 검사할 데이터
 * @param len 데이터 길이
 * @param ctx 검사 context
 * @param matches 매치 결과 리스트
 * @return int 0이면 정상 완료, -1이면 오류
 */
int detect_engine_collect_matches_ctx(detect_engine_t *e, const uint8_t *data,
                                      size_t len, ips_context_t ctx,
                                      detect_match_list_t *matches) {
    /* timed helper를 time 출력 없이 호출 */
    return collect_matches_ctx_timed(e, data, len, ctx, matches, NULL);
}

/**
 * @brief 탐지 엔진 매치 함수
 * 특정된 컨텍스트에서 매칭된 룰들을 전부 수집하고, 그 탐지 시간까지 돌려주는
 * 함수
 * @param e
 * @param data
 * @param len
 * @param ctx
 * @param matches
 * @param elapsed_us_sum
 * @return int
 */
int detect_engine_collect_matches_ctx_timed(detect_engine_t *e,
                                            const uint8_t *data, size_t len,
                                            ips_context_t        ctx,
                                            detect_match_list_t *matches,
                                            uint64_t *elapsed_us_sum) {
    /* timed helper로 실제 매치 수집 수행 */
    return collect_matches_ctx_timed(e, data, len, ctx, matches,
                                     elapsed_us_sum);
}

int detect_engine_match(detect_engine_t *e, const uint8_t *data, size_t len,
                        const IPS_Signature **matched_rule) {
    /* 전체 컨텍스트 대상으로 first match 수행 */
    int ret = detect_engine_match_ctx(e, data, len, IPS_CTX_ALL, matched_rule);
    /* helper 반환값 전달 */
    return ret;
}

/**
 * @brief 현재 탐지 엔진이 사용하는 regex backend 이름을 반환한다.
 *
 * @param e 탐지 엔진
 * @return const char* backend 이름
 */
const char *detect_engine_backend_name(const detect_engine_t *e) {
    /* 엔진 포인터 검사 */
    if (NULL == e) {
        return "-";
    }
    /* backend 이름 반환 */
    return engine_runtime_backend_name(e->runtime);
}

/**
 * @brief 탐지 엔진의 JIT 활성화 여부를 반환한다.
 *
 * @param e 탐지 엔진
 * @return int 활성화면 1, 아니면 0
 */
int detect_engine_jit_enabled(const detect_engine_t *e) {
    /* 엔진 포인터 검사 */
    if (NULL == e) {
        return 0;
    }
    /* backend의 JIT 활성화 여부 반환 */
    return engine_runtime_jit_enabled(e->runtime);
}

/**
 * @brief 마지막 탐지 오류 문자열을 반환한다.
 *
 * @param e 탐지 엔진
 * @return const char* 마지막 오류 문자열
 */
const char *detect_engine_last_error(const detect_engine_t *e) {
    /* NULL 엔진 메시지 반환 */
    if (NULL == e) {
        return "null engine";
    }
    /* 오류가 없으면 ok 반환 */
    if ('\0' == e->last_err[0]) {
        return "ok";
    }
    /* 마지막 오류 문자열 반환 */
    return e->last_err;
}

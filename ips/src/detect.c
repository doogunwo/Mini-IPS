/**
 * @file detect.c
 * @brief 탐지 엔진 구현
 */
#include "detect.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "engine.h"

typedef struct policy_pattern_set {
    const IPS_Signature **rules;
    unsigned int          count;
} policy_pattern_set_t;

struct detect_engine {
    engine_runtime_t     *runtime;
    const IPS_Signature **rules;
    unsigned int          rule_count;
    char                  last_err[128];
};

static void set_err(detect_engine_t *e, const char *msg);

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
    if (NULL != elapsed_us_sum) {
        *elapsed_us_sum = 0;
    }
    if (NULL == matches) {
        if (NULL != e) {
            set_err(e, "null matches");
        }
        return -1;
    }
    if (NULL == e || NULL == data || 0U == len) {
        return 0;
    }
    if ((size_t)INT_MAX < len) {
        set_err(e, "payload too large");
        return -1;
    }

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
        set_err(e, "invalid context");

        return -1;
    }
    int rc = engine_runtime_collect_matches_timed(
        e->runtime, data, len, ctx, matches, elapsed_us_sum, e->last_err,
        sizeof(e->last_err));
    return rc;
}

static void set_err(detect_engine_t *e, const char *msg) {
    if (NULL == e) {
        return;
    }
    if (NULL == msg) {
        msg = "unknown error";
    }
    snprintf(e->last_err, sizeof(e->last_err), "%s", msg);
}

/**
 * @brief detect_match_list를 빈 상태로 초기화한다.
 *
 * @param matches 매치 결과 리스트
 */
void detect_match_list_init(detect_match_list_t *matches) {
    if (NULL == matches) {
        return;
    }
    memset(matches, 0, sizeof(*matches));
}

/**
 * @brief detect_match_list 내부 항목과 배열 메모리를 해제한다.
 *
 * @param matches 매치 결과 리스트
 */
void detect_match_list_free(detect_match_list_t *matches) {
    size_t i;

    if (NULL == matches) {
        return;
    }
    for (i = 0; i < matches->count; i++) {
        free(matches->items[i].matched_text);
    }
    free(matches->items);
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
    int          i;
    int          ret;
    unsigned int n = 0;

    if (NULL == policy_name || NULL == out) {
        return -1;
    }

    n = 0;
    memset(out, 0, sizeof(*out));

    /* 지금 당장 교체 불가능 */
    for (i = 0; i < g_signature_count; i++) {
        ret = strcmp(g_ips_signatures[i].policy_name, policy_name);
        if (0 == ret) {
            n++;
        }
    }

    if (0 == n) {
        return -1;
    }

    out->rules = (const IPS_Signature **)malloc(n * sizeof(*out->rules));
    if (NULL == out->rules) {
        memset(out, 0, sizeof(*out));
        return -1;
    }

    out->count = n;
    n          = 0;

    for (i = 0; i < g_signature_count; i++) {
        ret = strcmp(g_ips_signatures[i].policy_name, policy_name);
        if (0 == ret) {
            out->rules[n] = &g_ips_signatures[i];
            n++;
        }
    }

    return 0;
}

/**
 * @brief 로드된 모든 룰을 하나의 집합으로 수집한다.
 *
 * @param out 결과 룰 집합
 * @return int 0이면 성공, -1이면 실패
 */
static int collect_all_patterns(policy_pattern_set_t *out) {
    unsigned int n = (unsigned int)g_signature_count;
    unsigned int i;

    memset(out, 0, sizeof(*out));
    if (0U == n) {
        return -1;
    }

    out->rules = (const IPS_Signature **)malloc(n * sizeof(*out->rules));
    if (NULL == out->rules) {
        memset(out, 0, sizeof(*out));
        return -1;
    }
    out->count = n;

    for (i = 0; i < n; i++) {
        out->rules[i] = &g_ips_signatures[i];
    }
    return 0;
}

/**
 * @brief collect_* 함수가 만든 임시 룰 집합을 해제한다.
 *
 * @param set 해제할 룰 집합
 */
static void free_policy_patterns(policy_pattern_set_t *set) {
    free(set->rules);
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
    detect_engine_t     *e;
    policy_pattern_set_t set;
    int                  ret;

    memset(&set, 0, sizeof(set));

    ret = regex_signatures_load(NULL);
    if (0 != ret) {
        return NULL;
    }

    e = (detect_engine_t *)malloc(sizeof(*e));
    if (NULL == e) {
        return NULL;
    }
    memset(e, 0, sizeof(*e));
    e->last_err[0] = '\0';

    if (NULL == policy_name || '\0' == policy_name[0] ||
        0 == strcmp(policy_name, "ALL") || 0 == strcmp(policy_name, "all") ||
        0 == strcmp(policy_name, "*")) {
        ret = collect_all_patterns(&set);
        if (0 != ret) {
            set_err(e, "no patterns");
            detect_engine_destroy(e);
            return NULL;
        }
    } else {
        ret = collect_policy_patterns(policy_name, &set);
        if (0 != ret) {
            set_err(e, "unknown policy");
            detect_engine_destroy(e);
            return NULL;
        }
    }

    e->runtime = engine_runtime_create(set.rules, set.count, jit_mode,
                                       e->last_err, sizeof(e->last_err));
    if (NULL == e->runtime) {
        free_policy_patterns(&set);
        detect_engine_destroy(e);
        return NULL;
    }

    e->rules      = set.rules;
    e->rule_count = set.count;
    return e;
}

/**
 * @brief 탐지 엔진과 내부 regex runtime을 해제한다.
 *
 * @param e 해제할 탐지 엔진
 */
void detect_engine_destroy(detect_engine_t *e) {
    if (NULL == e) {
        return;
    }
    engine_runtime_destroy(e->runtime);
    free(e->rules);
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
        if (NULL != matched_rule) {
            *matched_rule = NULL;
        }
        if (NULL != e) {
            set_err(e, "invalid context");
        }
        return -1;
    }

    if (NULL == e) {
        return 0;
    }

    int ret =
        engine_runtime_match_first(e->runtime, data, len, ctx, matched_rule,
                                   e->last_err, sizeof(e->last_err));
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
    return collect_matches_ctx_timed(e, data, len, ctx, matches,
                                     elapsed_us_sum);
}

int detect_engine_match(detect_engine_t *e, const uint8_t *data, size_t len,
                        const IPS_Signature **matched_rule) {
    int ret = detect_engine_match_ctx(e, data, len, IPS_CTX_ALL, matched_rule);
    return ret;
}

/**
 * @brief 현재 탐지 엔진이 사용하는 regex backend 이름을 반환한다.
 *
 * @param e 탐지 엔진
 * @return const char* backend 이름
 */
const char *detect_engine_backend_name(const detect_engine_t *e) {
    if (NULL == e) {
        return "-";
    }
    return engine_runtime_backend_name(e->runtime);
}

/**
 * @brief 탐지 엔진의 JIT 활성화 여부를 반환한다.
 *
 * @param e 탐지 엔진
 * @return int 활성화면 1, 아니면 0
 */
int detect_engine_jit_enabled(const detect_engine_t *e) {
    if (NULL == e) {
        return 0;
    }
    return engine_runtime_jit_enabled(e->runtime);
}

/**
 * @brief 마지막 탐지 오류 문자열을 반환한다.
 *
 * @param e 탐지 엔진
 * @return const char* 마지막 오류 문자열
 */
const char *detect_engine_last_error(const detect_engine_t *e) {
    if (NULL == e) {
        return "null engine";
    }
    if ('\0' == e->last_err[0]) {
        return "ok";
    }
    return e->last_err;
}

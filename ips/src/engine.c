/**
 * @file engine.c
 * @brief PCRE2/HS 정규식 백엔드 래퍼 구현
 */
#include "engine.h"

#define PCRE2_CODE_UNIT_WIDTH 8
#include <hs/hs.h>
#include <limits.h>
#include <pcre2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef enum { REGEX_BACKEND_PCRE2 = 0, REGEX_BACKEND_HS } regex_backend_t;

typedef struct {
    const IPS_Signature *rule;
    pcre2_code          *re;
    pcre2_match_data    *match_data;
} compiled_rule_t;

typedef struct {
    hs_database_t *db;
    unsigned int  *rule_indexes;
    unsigned int   rule_count;
} hs_group_t;

typedef struct {
    const engine_runtime_t *runtime;
    detect_match_list_t    *matches;
    ips_context_t           ctx;
    const uint8_t          *data;
    size_t                  data_len;
    int                     matched_any;
    int                     stop_after_first;
    const IPS_Signature   **first_rule;
    uint8_t                *seen;
} hs_scan_ctx_t;

struct engine_runtime {
    compiled_rule_t     *compiled_rules;
    unsigned int         compiled_count;
    regex_backend_t      backend;
    int                  jit_enabled;
    pcre2_jit_stack     *jit_stack;
    pcre2_match_context *match_ctx;
    hs_scratch_t        *hs_scratch;
    hs_group_t           hs_groups[IPS_CTX_RESPONSE_BODY + 1];
};

static regex_backend_t g_selected_backend = REGEX_BACKEND_PCRE2;

/**
 * @brief backend/runtime 계층에서 사용할 오류 문자열을 기록한다.
 *
 * @param errbuf 오류 버퍼
 * @param errbuf_size 오류 버퍼 크기
 * @param msg 기록할 오류 메시지
 */
static void set_err(char *errbuf, size_t errbuf_size, const char *msg) {
    if (NULL == errbuf || 0U == errbuf_size) {
        return;
    }
    snprintf(errbuf, errbuf_size, "%s", msg != NULL ? msg : "unknown error");
}

/**
 * @brief detect_match_list에 로컬 match 항목 하나를 추가한다.
 *
 * @param matches 매치 결과 리스트
 * @param rule 매칭된 룰
 * @param ctx 매칭된 context
 * @param matched_text 매칭된 텍스트
 * @param matched_len 매칭 길이
 * @param elapsed_us 해당 매칭 탐지 시간
 * @return int 0이면 성공, -1이면 실패
 */
static int detect_match_list_append_local(
    detect_match_list_t *matches, const IPS_Signature *rule, ips_context_t ctx,
    const char *matched_text, size_t matched_len, uint64_t elapsed_us) {
    detect_match_t *next_items;
    char           *copy;
    size_t          next_cap;

    if (NULL == matches) {
        return -1;
    }

    if (matches->count == matches->capacity) {
        next_cap   = matches->capacity != 0 ? matches->capacity * 2U : 8U;
        next_items = (detect_match_t *)realloc(matches->items,
                                               next_cap * sizeof(*next_items));
        if (NULL == next_items) {
            return -1;
        }
        matches->items    = next_items;
        matches->capacity = next_cap;
    }

    copy = (char *)malloc(matched_len + 1U);
    if (NULL == copy) {
        return -1;
    }
    if (0U < matched_len) {
        memcpy(copy, matched_text, matched_len);
    }
    copy[matched_len] = '\0';

    matches->items[matches->count].rule         = rule;
    matches->items[matches->count].context      = ctx;
    matches->items[matches->count].matched_text = copy;
    matches->items[matches->count].elapsed_us   = elapsed_us;
    matches->count++;
    return 0;
}

/**
 * @brief 현재 검사 context와 룰 context가 호환되는지 검사한다.
 *
 * @param rule 검사할 룰
 * @param ctx 현재 검사 context
 * @return int 호환되면 1, 아니면 0
 */
static int rule_context_matches(const IPS_Signature *rule, ips_context_t ctx) {
    if (NULL == rule) {
        return 0;
    }
    if (IPS_CTX_ALL == ctx || IPS_CTX_ALL == rule->context) {
        return 1;
    }
    return rule->context == ctx;
}

/**
 * @brief 전역 regex backend 선택값을 변경한다.
 *
 * @param name backend 이름 문자열
 * @param errbuf 오류 버퍼
 * @param errbuf_size 오류 버퍼 크기
 * @return int 0이면 성공, -1이면 실패
 */
int engine_set_backend_name(const char *name, char *errbuf,
                            size_t errbuf_size) {
    int ret;

    ret = strcmp(name, "pcre2");
    if (0 == ret) {
        g_selected_backend = REGEX_BACKEND_PCRE2;
        return 0;
    }
    ret = strcmp(name, "hs");
    if (0 == ret) {
        g_selected_backend = REGEX_BACKEND_HS;
        return 0;
    }
    set_err(errbuf, errbuf_size, "invalid regex backend");
    return -1;
}

/**
 * @brief PCRE2 backend가 확보한 코드와 JIT 자원을 해제한다.
 *
 * @param runtime engine runtime
 */
static void pcre2_release(engine_runtime_t *runtime) {
    unsigned int i;

    if (NULL == runtime || NULL == runtime->compiled_rules) {
        return;
    }

    if (NULL != runtime->jit_stack) {
        pcre2_jit_stack_free(runtime->jit_stack);
        runtime->jit_stack = NULL;
    }
    if (NULL != runtime->match_ctx) {
        pcre2_match_context_free(runtime->match_ctx);
        runtime->match_ctx = NULL;
    }

    for (i = 0; i < runtime->compiled_count; i++) {
        if (NULL != runtime->compiled_rules[i].match_data) {
            pcre2_match_data_free(runtime->compiled_rules[i].match_data);
            runtime->compiled_rules[i].match_data = NULL;
        }
        if (NULL != runtime->compiled_rules[i].re) {
            pcre2_code_free(runtime->compiled_rules[i].re);
            runtime->compiled_rules[i].re = NULL;
        }
    }
}

/**
 * @brief Hyperscan backend가 확보한 DB/scratch 자원을 해제한다.
 *
 * @param runtime engine runtime
 */
static void hs_release(engine_runtime_t *runtime) {
    unsigned int i;
    unsigned int ctx;

    if (NULL == runtime) {
        return;
    }

    if (NULL != runtime->hs_scratch) {
        hs_free_scratch(runtime->hs_scratch);
        runtime->hs_scratch = NULL;
    }

    for (ctx = 0; ctx <= (unsigned int)IPS_CTX_RESPONSE_BODY; ctx++) {
        if (NULL != runtime->hs_groups[ctx].db) {
            hs_free_database(runtime->hs_groups[ctx].db);
            runtime->hs_groups[ctx].db = NULL;
        }
        free(runtime->hs_groups[ctx].rule_indexes);
        runtime->hs_groups[ctx].rule_indexes = NULL;
        runtime->hs_groups[ctx].rule_count   = 0;
    }

    for (i = 0; i < runtime->compiled_count; i++) {
        if (NULL != runtime->compiled_rules[i].re) {
            runtime->compiled_rules[i].re = NULL;
        }
        if (NULL != runtime->compiled_rules[i].match_data) {
            runtime->compiled_rules[i].match_data = NULL;
        }
    }
}

/**
 * @brief Hyperscan match callback으로 매칭 결과를 수집한다.
 *
 * @param id 매칭된 pattern id
 * @param from 매칭 시작 offset
 * @param to 매칭 끝 offset
 * @param flags Hyperscan flags
 * @param ctx hs scan context
 * @return int 계속 스캔이면 0, 조기 종료면 1
 */
static int hs_on_match(unsigned int id, unsigned long long from,
                       unsigned long long to, unsigned int flags, void *ctx) {
    hs_scan_ctx_t         *scan_ctx = (hs_scan_ctx_t *)ctx;
    const IPS_Signature   *rule;
    const compiled_rule_t *compiled_rule;
    unsigned int           rule_index;
    size_t                 match_off;
    size_t                 match_len;
    int                    ret;

    (void)flags;

    if (NULL == scan_ctx || NULL == scan_ctx->runtime) {
        return 1;
    }

    if (id >= scan_ctx->runtime->compiled_count) {
        return 1;
    }

    rule_index = id;
    if (NULL != scan_ctx->seen && 0 != scan_ctx->seen[rule_index]) {
        return 0;
    }

    compiled_rule = &scan_ctx->runtime->compiled_rules[rule_index];
    rule          = compiled_rule->rule;
    if (NULL == rule) {
        return 0;
    }

    scan_ctx->matched_any = 1;
    if (NULL != scan_ctx->seen) {
        scan_ctx->seen[rule_index] = 1;
    }

    if (NULL != scan_ctx->first_rule && NULL == *scan_ctx->first_rule) {
        *scan_ctx->first_rule = rule;
    }

    if (NULL != scan_ctx->matches) {
        match_off = (size_t)from;
        match_len = (size_t)(to >= from ? (to - from) : 0);
        if (scan_ctx->data_len < match_off) {
            match_off = scan_ctx->data_len;
            match_len = 0;
        }
        if (scan_ctx->data_len < match_off + match_len) {
            match_len = scan_ctx->data_len - match_off;
        }
        ret = detect_match_list_append_local(
            scan_ctx->matches, rule, scan_ctx->ctx,
            (const char *)scan_ctx->data + match_off, match_len, 0);
        if (0 != ret) {
            return 1;
        }
    }

    return scan_ctx->stop_after_first ? 1 : 0;
}

/**
 * @brief PCRE2 룰 1개를 컴파일하고 필요 시 JIT까지 준비한다.
 *
 * @param runtime engine runtime
 * @param slot 컴파일 결과를 저장할 슬롯
 * @param rule 컴파일할 룰
 * @param jit_mode JIT 사용 정책
 * @param errbuf 오류 버퍼
 * @param errbuf_size 오류 버퍼 크기
 * @return int 0이면 성공, -1이면 실패
 */
static int compile_pcre2_rule(engine_runtime_t *runtime, compiled_rule_t *slot,
                              const IPS_Signature *rule,
                              detect_jit_mode_t jit_mode, char *errbuf,
                              size_t errbuf_size) {
    int         errcode   = 0;
    PCRE2_SIZE  erroffset = 0;
    uint32_t    jit_cfg   = 0;
    int         rc_cfg;
    int         jit_rc;
    int         jit_info_rc;
    size_t      jit_size = 0;
    PCRE2_UCHAR errstr[256];

    rc_cfg = pcre2_config(PCRE2_CONFIG_JIT, &jit_cfg);
    if (DETECT_JIT_OFF == jit_mode) {
        runtime->jit_enabled = 0;
    } else if (DETECT_JIT_ON == jit_mode) {
        if (!(0 == rc_cfg && 1U == jit_cfg)) {
            set_err(errbuf, errbuf_size,
                    "requested -jit=on but PCRE2 JIT is unavailable");
            return -1;
        }
        runtime->jit_enabled = 1;
    } else {
        runtime->jit_enabled = (0 == rc_cfg && 1U == jit_cfg) ? 1 : 0;
    }

    slot->re = pcre2_compile((PCRE2_SPTR)rule->pattern, PCRE2_ZERO_TERMINATED,
                             PCRE2_CASELESS, &errcode, &erroffset, NULL);
    if (NULL == slot->re) {
        char msg[256];
        pcre2_get_error_message(errcode, errstr, sizeof(errstr));
        snprintf(msg, sizeof(msg),
                 "pcre2_compile failed: rid=%d offset=%zu err=%.160s",
                 rule->rule_id, (size_t)erroffset, (char *)errstr);
        set_err(errbuf, errbuf_size, msg);
        return -1;
    }

    slot->match_data = pcre2_match_data_create_from_pattern(slot->re, NULL);
    if (NULL == slot->match_data) {
        set_err(errbuf, errbuf_size,
                "pcre2_match_data_create_from_pattern failed");
        return -1;
    }

    if (0 == runtime->jit_enabled) {
        return 0;
    }

    jit_rc = pcre2_jit_compile(slot->re, PCRE2_JIT_COMPLETE);
    if (0 != jit_rc) {
        if (DETECT_JIT_ON == jit_mode) {
            char msg[256];
            pcre2_get_error_message(jit_rc, errstr, sizeof(errstr));
            snprintf(msg, sizeof(msg),
                     "pcre2_jit_compile failed: rid=%d err=%.180s",
                     rule->rule_id, (char *)errstr);
            set_err(errbuf, errbuf_size, msg);
            return -1;
        }
        runtime->jit_enabled = 0;
        return 0;
    }

    jit_info_rc = pcre2_pattern_info(slot->re, PCRE2_INFO_JITSIZE, &jit_size);
    if (0 != jit_info_rc || 0U == jit_size) {
        if (DETECT_JIT_ON == jit_mode) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                     "pcre2 JIT compile unavailable for rid=%d", rule->rule_id);
            set_err(errbuf, errbuf_size, msg);
            return -1;
        }
        runtime->jit_enabled = 0;
    }

    return 0;
}

/**
 * @brief context별 Hyperscan database를 구성한다.
 *
 * RX operator를 가진 룰만 골라 multi-pattern database를 만든다.
 *
 * @param runtime engine runtime
 * @param group context별 hs 그룹
 * @param ctx 대상 context
 * @param errbuf 오류 버퍼
 * @param errbuf_size 오류 버퍼 크기
 * @return int 0이면 성공, -1이면 실패
 */
static int compile_hs_group(engine_runtime_t *runtime, hs_group_t *group,
                            unsigned int ctx, char *errbuf,
                            size_t errbuf_size) {
    const char        **patterns    = NULL;
    unsigned int       *flags       = NULL;
    unsigned int       *ids         = NULL;
    hs_compile_error_t *compile_err = NULL;
    hs_error_t          rc;
    unsigned int        count = 0;
    unsigned int        i;
    int                 rule_matches;

    for (i = 0; i < runtime->compiled_count; i++) {
        rule_matches = rule_context_matches(runtime->compiled_rules[i].rule,
                                            (ips_context_t)ctx);
        if (0 == rule_matches) {
            continue;
        }
        if (NULL == runtime->compiled_rules[i].rule ||
            IPS_OP_RX != runtime->compiled_rules[i].rule->op) {
            continue;
        }
        count++;
    }

    if (0U == count) {
        return 0;
    }

    patterns = (const char **)malloc(count * sizeof(*patterns));
    flags    = (unsigned int *)malloc(count * sizeof(*flags));
    ids      = (unsigned int *)malloc(count * sizeof(*ids));
    group->rule_indexes =
        (unsigned int *)malloc(count * sizeof(*group->rule_indexes));
    if (NULL == patterns || NULL == flags || NULL == ids ||
        NULL == group->rule_indexes) {
        free(patterns);
        free(flags);
        free(ids);
        free(group->rule_indexes);
        group->rule_indexes = NULL;
        set_err(errbuf, errbuf_size, "hs group alloc failed");
        return -1;
    }

    count = 0;
    for (i = 0; i < runtime->compiled_count; i++) {
        rule_matches = rule_context_matches(runtime->compiled_rules[i].rule,
                                            (ips_context_t)ctx);
        if (0 == rule_matches) {
            continue;
        }
        if (NULL == runtime->compiled_rules[i].rule ||
            IPS_OP_RX != runtime->compiled_rules[i].rule->op) {
            continue;
        }
        patterns[count]            = runtime->compiled_rules[i].rule->pattern;
        flags[count]               = 0;
        ids[count]                 = i;
        group->rule_indexes[count] = i;
        count++;
    }

    group->rule_count = count;

    rc = hs_compile_multi(patterns, flags, ids, count, HS_MODE_BLOCK, NULL,
                          &group->db, &compile_err);
    free(patterns);
    free(flags);
    free(ids);

    if (HS_SUCCESS != rc) {
        char msg[256];
        snprintf(msg, sizeof(msg), "hs_compile_multi failed: ctx=%u err=%s",
                 ctx,
                 (NULL != compile_err && NULL != compile_err->message)
                     ? compile_err->message
                     : "unknown");
        set_err(errbuf, errbuf_size, msg);
        if (NULL != compile_err) {
            hs_free_compile_error(compile_err);
        }
        return -1;
    }

    if (NULL != compile_err) {
        hs_free_compile_error(compile_err);
    }

    rc = hs_alloc_scratch(group->db, &runtime->hs_scratch);
    if (HS_SUCCESS != rc) {
        set_err(errbuf, errbuf_size, "hs_alloc_scratch failed");
        return -1;
    }

    return 0;
}

/**
 * @brief 룰 집합을 기준으로 regex runtime을 생성한다.
 *
 * 선택된 backend에 따라 PCRE2 code 또는 Hyperscan database를 준비한다.
 *
 * @param rules 컴파일할 룰 배열
 * @param rule_count 룰 개수
 * @param jit_mode JIT 사용 정책
 * @param errbuf 오류 버퍼
 * @param errbuf_size 오류 버퍼 크기
 * @return engine_runtime_t* 생성된 runtime, 실패 시 NULL
 */
engine_runtime_t *engine_runtime_create(const IPS_Signature *const *rules,
                                        unsigned int                rule_count,
                                        detect_jit_mode_t           jit_mode,
                                        char *errbuf, size_t errbuf_size) {
    engine_runtime_t *runtime;
    unsigned int      i;
    int               ret;

    runtime = (engine_runtime_t *)malloc(sizeof(*runtime));
    if (NULL == runtime) {
        set_err(errbuf, errbuf_size, "engine alloc failed");
        return NULL;
    }
    memset(runtime, 0, sizeof(*runtime));

    runtime->backend = g_selected_backend;
    if (0U != rule_count) {
        runtime->compiled_rules = (compiled_rule_t *)malloc(
            rule_count * sizeof(*runtime->compiled_rules));
        if (NULL == runtime->compiled_rules) {
            set_err(errbuf, errbuf_size, "engine compile alloc failed");
            engine_runtime_destroy(runtime);
            return NULL;
        }
        memset(runtime->compiled_rules, 0,
               rule_count * sizeof(*runtime->compiled_rules));
    }
    runtime->compiled_count = rule_count;

    for (i = 0; i < rule_count; i++) {
        runtime->compiled_rules[i].rule = rules[i];
        if (NULL == rules[i] || IPS_OP_RX != rules[i]->op) {
            continue;
        }

        if (REGEX_BACKEND_HS != runtime->backend) {
            ret = compile_pcre2_rule(runtime, &runtime->compiled_rules[i],
                                     rules[i], jit_mode, errbuf, errbuf_size);
            if (0 != ret) {
                engine_runtime_destroy(runtime);
                return NULL;
            }
        }
    }

    if (REGEX_BACKEND_HS == runtime->backend) {
        for (i = 0; i <= (unsigned int)IPS_CTX_RESPONSE_BODY; i++) {
            ret = compile_hs_group(runtime, &runtime->hs_groups[i], i, errbuf,
                                   errbuf_size);
            if (0 != ret) {
                engine_runtime_destroy(runtime);
                return NULL;
            }
        }
    }

    if (REGEX_BACKEND_PCRE2 == runtime->backend && 0 != runtime->jit_enabled) {
        runtime->match_ctx = pcre2_match_context_create(NULL);
        if (NULL == runtime->match_ctx) {
            set_err(errbuf, errbuf_size, "pcre2_match_context_create failed");
            engine_runtime_destroy(runtime);
            return NULL;
        }

        runtime->jit_stack =
            pcre2_jit_stack_create(32 * 1024, 512 * 1024, NULL);
        if (NULL == runtime->jit_stack) {
            if (DETECT_JIT_ON == jit_mode) {
                set_err(errbuf, errbuf_size, "pcre2_jit_stack_create failed");
                engine_runtime_destroy(runtime);
                return NULL;
            }
            runtime->jit_enabled = 0;
        } else {
            pcre2_jit_stack_assign(runtime->match_ctx, NULL,
                                   runtime->jit_stack);
        }
    }

    return runtime;
}

/**
 * @brief regex runtime이 보유한 backend 자원과 메모리를 해제한다.
 *
 * @param runtime 해제할 runtime
 */
void engine_runtime_destroy(engine_runtime_t *runtime) {
    if (NULL == runtime) {
        return;
    }

    if (REGEX_BACKEND_HS == runtime->backend) {
        hs_release(runtime);
    } else {
        pcre2_release(runtime);
    }

    free(runtime->compiled_rules);
    free(runtime);
}

/**
 * @brief regex profiling 기능 활성화 여부를 환경 변수에서 읽는다.
 *
 * @return int 활성화면 1, 아니면 0
 */
static int regex_profile_enabled(void) {
    const char *v = getenv("IPS_PROFILE_REGEX");
    int         ret;

    if (NULL == v) {
        return 0;
    }

    ret = strcmp(v, "0");
    if (0 == ret) {
        return 0;
    }

    ret = strcmp(v, "false");
    if (0 == ret) {
        return 0;
    }

    return 1;
}

/**
 * @brief regex profiling 로그 기준 임계시간(us)을 읽는다.
 *
 * @return long 임계시간 마이크로초
 */
static long regex_profile_threshold_us(void) {
    const char *v   = getenv("IPS_PROFILE_THRESHOLD_US");
    char       *end = NULL;
    long        n;

    if (NULL == v || '\0' == *v) {
        return 50000;
    }
    n = strtol(v, &end, 10);
    if (end == v || 0 > n) {
        return 50000;
    }
    return n;
}

/**
 * @brief monotonic clock 기준 현재 시각을 us 단위로 구한다.
 *
 * @return unsigned long long 현재 시각(us)
 */
static unsigned long long mono_us_now(void) {
    struct timespec ts;
    int             rc;

    rc = clock_gettime(CLOCK_MONOTONIC, &ts);
    if (0 != rc) {
        return 0;
    }
    return (unsigned long long)ts.tv_sec * 1000000ULL +
           (unsigned long long)(ts.tv_nsec / 1000ULL);
}

/**
 * @brief regex profiling 로그 조건을 만족하면 룰 실행 시간을 기록한다.
 *
 * 현재는 fprintf가 주석 처리되어 있어 실제 출력은 하지 않지만, profiling
 * 포인트는 유지해 두었다.
 *
 * @param compiled_rule 컴파일된 룰
 * @param ctx 검사 context
 * @param len 입력 길이
 * @param elapsed_us 수행 시간
 * @param rc 실행 결과 코드
 */
static void maybe_log_rule_profile(const compiled_rule_t *compiled_rule,
                                   ips_context_t ctx, size_t len,
                                   unsigned long long elapsed_us, int rc) {
    int  enabled;
    long threshold_us;

    enabled = regex_profile_enabled();
    if (0 == enabled) {
        return;
    }

    threshold_us = regex_profile_threshold_us();
    if (threshold_us > (long)elapsed_us) {
        return;
    }

    (void)compiled_rule;
    (void)ctx;
    (void)len;
    (void)rc;
    /*
    fprintf(stderr,
        "[REGEX][PROFILE] rid=%d policy=%s ctx=%d len=%zu elapsed_us=%llu rc=%d
    pat=\"%s\"\n", rule != NULL ? rule->rule_id : -1, rule != NULL &&
    rule->policy_name != NULL ? rule->policy_name : "-", (int)ctx, len,
        elapsed_us,
        rc,
        rule != NULL && rule->pattern != NULL ? rule->pattern : "");
    */
}

/**
 * @brief PCRE2 backend로 룰 1개를 실행한다.
 *
 * @param runtime engine runtime
 * @param compiled_rule 실행할 컴파일 룰
 * @param data 입력 데이터
 * @param len 입력 길이
 * @param match_off 첫 매칭 시작 offset
 * @param match_len 첫 매칭 길이
 * @param errbuf 오류 버퍼
 * @param errbuf_size 오류 버퍼 크기
 * @return int 0이면 정상 완료, -1이면 오류
 */
static int engine_match_pcre2(engine_runtime_t      *runtime,
                              const compiled_rule_t *compiled_rule,
                              const uint8_t *data, size_t len,
                              size_t *match_off, size_t *match_len,
                              char *errbuf, size_t errbuf_size) {
    int         rc;
    PCRE2_SIZE *ovector;

    rc = pcre2_match(compiled_rule->re, (PCRE2_SPTR)data, len, 0, 0,
                     compiled_rule->match_data,
                     NULL != runtime ? runtime->match_ctx : NULL);

    if (0 <= rc) {
        ovector    = pcre2_get_ovector_pointer(compiled_rule->match_data);
        *match_off = (size_t)ovector[0];
        *match_len = (size_t)(ovector[1] - ovector[0]);
        return 1;
    }
    if (PCRE2_ERROR_NOMATCH == rc) {
        return 0;
    }

    set_err(errbuf, errbuf_size, "pcre2_match error");
    return -1;
}

/**
 * @brief Hyperscan backend로 지정 context에 대한 첫 매칭을 찾는다.
 *
 * @param runtime engine runtime
 * @param ctx 검사 context
 * @param data 입력 데이터
 * @param len 입력 길이
 * @param match_off 첫 매칭 시작 offset
 * @param match_len 첫 매칭 길이
 * @param matched_rule 첫 매칭 룰 포인터
 * @param errbuf 오류 버퍼
 * @param errbuf_size 오류 버퍼 크기
 * @return int 1이면 매칭, 0이면 미매칭, -1이면 오류
 */
static int engine_match_hs(engine_runtime_t *runtime, ips_context_t ctx,
                           const uint8_t *data, size_t len, size_t *match_off,
                           size_t               *match_len,
                           const IPS_Signature **matched_rule, char *errbuf,
                           size_t errbuf_size) {
    hs_scan_ctx_t scan_ctx;
    hs_group_t   *group;
    hs_error_t    rc;

    if (IPS_CTX_ALL > ctx || IPS_CTX_RESPONSE_BODY < ctx) {
        set_err(errbuf, errbuf_size, "invalid hs ctx");
        return -1;
    }

    group = &runtime->hs_groups[ctx];
    if (NULL == group->db) {
        return 0;
    }

    memset(&scan_ctx, 0, sizeof(scan_ctx));
    scan_ctx.runtime          = runtime;
    scan_ctx.ctx              = ctx;
    scan_ctx.data             = data;
    scan_ctx.data_len         = len;
    scan_ctx.stop_after_first = 1;
    scan_ctx.first_rule       = matched_rule;

    rc = hs_scan(group->db, (const char *)data, (unsigned int)len, 0,
                 runtime->hs_scratch, hs_on_match, &scan_ctx);
    if (HS_SUCCESS != rc && HS_SCAN_TERMINATED != rc) {
        set_err(errbuf, errbuf_size, "hs_scan error");
        return -1;
    }
    if (0 == scan_ctx.matched_any) {
        return 0;
    }

    *match_off = 0;
    *match_len = 0;
    return 1;
}

/**
 * @brief runtime backend 종류에 따라 적절한 단일 룰 매칭 함수를 호출한다.
 *
 * @param runtime engine runtime
 * @param compiled_rule 컴파일된 룰
 * @param data 입력 데이터
 * @param len 입력 길이
 * @param match_off 매칭 시작 offset
 * @param match_len 매칭 길이
 * @param matched_rule 첫 매칭 룰 포인터
 * @param errbuf 오류 버퍼
 * @param errbuf_size 오류 버퍼 크기
 * @return int 1이면 매칭, 0이면 미매칭, -1이면 오류
 */
static int engine_match_one(engine_runtime_t      *runtime,
                            const compiled_rule_t *compiled_rule,
                            const uint8_t *data, size_t len, size_t *match_off,
                            size_t               *match_len,
                            const IPS_Signature **matched_rule, char *errbuf,
                            size_t errbuf_size) {
    if (REGEX_BACKEND_HS == runtime->backend) {
        return engine_match_hs(
            runtime,
            NULL != compiled_rule->rule ? compiled_rule->rule->context
                                        : IPS_CTX_ALL,
            data, len, match_off, match_len, matched_rule, errbuf, errbuf_size);
    }
    return engine_match_pcre2(runtime, compiled_rule, data, len, match_off,
                              match_len, errbuf, errbuf_size);
}

/**
 * @brief 지정 context에서 첫 번째 매칭 룰 하나를 찾는다.
 *
 * @param runtime engine runtime
 * @param data 입력 데이터
 * @param len 입력 길이
 * @param ctx 검사 context
 * @param matched_rule 첫 매칭 룰을 받을 포인터
 * @param errbuf 오류 버퍼
 * @param errbuf_size 오류 버퍼 크기
 * @return int 1이면 매칭, 0이면 미매칭, -1이면 오류
 */
int engine_runtime_match_first(engine_runtime_t *runtime, const uint8_t *data,
                               size_t len, ips_context_t ctx,
                               const IPS_Signature **matched_rule, char *errbuf,
                               size_t errbuf_size) {
    unsigned int i;
    int          rule_matches;

    if (NULL != matched_rule) {
        *matched_rule = NULL;
    }
    if (NULL == runtime || NULL == data || 0U == len) {
        return 0;
    }
    if ((size_t)INT_MAX < len) {
        set_err(errbuf, errbuf_size, "payload too large");
        return -1;
    }

    if (REGEX_BACKEND_HS == runtime->backend) {
        size_t             match_off = 0;
        size_t             match_len = 0;
        unsigned long long t0        = mono_us_now();
        int rc = engine_match_hs(runtime, ctx, data, len, &match_off,
                                 &match_len, matched_rule, errbuf, errbuf_size);

        maybe_log_rule_profile(NULL, ctx, len, mono_us_now() - t0, rc);
        return (rc < 0) ? -1 : 0;
    }

    for (i = 0; i < runtime->compiled_count; i++) {
        size_t match_off = 0;
        size_t match_len = 0;
        int    rc;

        rule_matches =
            rule_context_matches(runtime->compiled_rules[i].rule, ctx);
        if (0 == rule_matches) {
            continue;
        }
        if (NULL == runtime->compiled_rules[i].rule ||
            IPS_OP_RX != runtime->compiled_rules[i].rule->op) {
            continue;
        }

        {
            unsigned long long t0 = mono_us_now();
            rc = engine_match_one(runtime, &runtime->compiled_rules[i], data,
                                  len, &match_off, &match_len, matched_rule,
                                  errbuf, errbuf_size);
            maybe_log_rule_profile(&runtime->compiled_rules[i], ctx, len,
                                   mono_us_now() - t0, rc);
        }
        if (0 > rc) {
            return -1;
        }
        if (0 < rc) {
            if (NULL != matched_rule) {
                *matched_rule = runtime->compiled_rules[i].rule;
            }
            return 0;
        }
    }

    return 0;
}

/**
 * @brief 지정 context에서 매칭된 모든 룰을 수집한다.
 *
 * @param runtime engine runtime
 * @param data 입력 데이터
 * @param len 입력 길이
 * @param ctx 검사 context
 * @param matches 매치 결과 리스트
 * @param errbuf 오류 버퍼
 * @param errbuf_size 오류 버퍼 크기
 * @return int 0이면 정상 완료, -1이면 오류
 */
int engine_runtime_collect_matches(engine_runtime_t *runtime,
                                   const uint8_t *data, size_t len,
                                   ips_context_t        ctx,
                                   detect_match_list_t *matches, char *errbuf,
                                   size_t errbuf_size) {
    return engine_runtime_collect_matches_timed(
        runtime, data, len, ctx, matches, NULL, errbuf, errbuf_size);
}

/**
 * @brief 엔진 함수
 * pcre/hs 백엔드를 실제로 돌려서 매치 목록과 탐지 시간을 만들어내는 엔진 핵심
 * 함수이다.
 * @param runtime 런타임
 * @param data HTTP 데이터, 입력데이터
 * @param len 길이
 * @param ctx  컨텍스트에 대해서
 * @param matches 매칭된 룰을 MATCHES에 담고
 * @param elapsed_us_sum  걸린 시간을 누적하여
 * @param errbuf 에러가 나면 errbuf에 메시지를 채우는 함수이다.
 * @param errbuf_size 에러 버퍼 크기
 * @return int 0이면 정상 완료, -1이면 오류
 */
int engine_runtime_collect_matches_timed(engine_runtime_t *runtime,
                                         const uint8_t *data, size_t len,
                                         ips_context_t        ctx,
                                         detect_match_list_t *matches,
                                         uint64_t *elapsed_us_sum, char *errbuf,
                                         size_t errbuf_size) {
    unsigned int i;
    int          rule_matches;
    if (NULL != elapsed_us_sum) {
        *elapsed_us_sum = 0;
    }

    if (NULL == matches) {
        set_err(errbuf, errbuf_size, "null matches");
        return -1;
    }
    if (NULL == runtime || NULL == data || 0U == len) {
        return 0;
    }
    if ((size_t)INT_MAX < len) {
        set_err(errbuf, errbuf_size, "payload too large");
        return -1;
    }
    /* hs가 백엔드 인 경우 */
    if (REGEX_BACKEND_HS == runtime->backend) {
        hs_group_t        *group;
        hs_scan_ctx_t      scan_ctx;
        uint64_t           elapsed_us = 0;
        unsigned long long t0;
        uint8_t           *seen;
        hs_error_t         rc_hs;

        if (IPS_CTX_ALL > ctx || IPS_CTX_RESPONSE_BODY < ctx) {
            set_err(errbuf, errbuf_size, "invalid hs ctx");
            return -1;
        }
        group = &runtime->hs_groups[ctx];
        if (NULL == group->db) {
            return 0;
        }

        seen = (uint8_t *)malloc(runtime->compiled_count * sizeof(*seen));
        if (NULL == seen) {
            set_err(errbuf, errbuf_size, "hs seen alloc failed");
            return -1;
        }
        memset(seen, 0, runtime->compiled_count * sizeof(*seen));

        memset(&scan_ctx, 0, sizeof(scan_ctx));
        scan_ctx.runtime  = runtime;
        scan_ctx.matches  = matches;
        scan_ctx.ctx      = ctx;
        scan_ctx.data     = data;
        scan_ctx.data_len = len;
        scan_ctx.seen     = seen;

        t0    = mono_us_now();
        rc_hs = hs_scan(group->db, (const char *)data, (unsigned int)len, 0,
                        runtime->hs_scratch, hs_on_match, &scan_ctx);
        elapsed_us = (uint64_t)(mono_us_now() - t0);
        free(seen);

        if (NULL != elapsed_us_sum) {
            *elapsed_us_sum += elapsed_us;
        }

        if (HS_SUCCESS != rc_hs && HS_SCAN_TERMINATED != rc_hs) {
            set_err(errbuf, errbuf_size, "hs_scan error");
            return -1;
        }
        /* PCRE2는 이 룰 검사하는데 몇초 걸렸음 을 알 수 있지만 */
        /* HS는 여러 룰을 한번에 검사하기 때문에 어떤 룰이 몇초 걸렸는지 정확히
         * 알기 어렵다. */
        if (0 != scan_ctx.matched_any) {
            /* 그래서 스캔된 항목들 중 0이면서 컨텍스트인 것*/
            /* 해당 컨텍스트의 전체 스캔 시간을 구한 뒤 */
            for (i = 0; i < matches->count; i++) {
                if (0 == matches->items[i].elapsed_us &&
                    ctx == matches->items[i].context) {
                    /* 방금 생성된 매치 항목들에 일괄 기록(Post-processing)하는
                     * 방식 */
                    matches->items[i].elapsed_us = elapsed_us;
                }
            }
        }
        return 0;  // 끝
    }
    /* 백엔드가 pcre인 경우 */
    for (i = 0; i < runtime->compiled_count; i++) {
        size_t   match_off  = 0;
        size_t   match_len  = 0;
        uint64_t elapsed_us = 0;
        int      rc;
        int      append_rc;

        rule_matches =
            rule_context_matches(runtime->compiled_rules[i].rule, ctx);
        if (0 == rule_matches) {
            continue;
        }
        if (NULL == runtime->compiled_rules[i].rule ||
            IPS_OP_RX != runtime->compiled_rules[i].rule->op) {
            continue;
        }

        {
            unsigned long long t0 = mono_us_now();
            rc = engine_match_one(runtime, &runtime->compiled_rules[i], data,
                                  len, &match_off, &match_len, NULL, errbuf,
                                  errbuf_size);
            elapsed_us = (uint64_t)(mono_us_now() - t0);
            maybe_log_rule_profile(&runtime->compiled_rules[i], ctx, len,
                                   elapsed_us, rc);
            if (NULL != elapsed_us_sum) {
                *elapsed_us_sum += elapsed_us;
            }
        }
        if (0 > rc) {
            return -1;
        }
        if (0 == rc) {
            continue;
        }

        append_rc = detect_match_list_append_local(
            matches, runtime->compiled_rules[i].rule, ctx,
            0U != match_len ? (const char *)data + match_off : "", match_len,
            elapsed_us);
        if (0 != append_rc) {
            set_err(errbuf, errbuf_size, "append match failed");
            return -1;
        }
    }

    return 0;
}

/**
 * @brief runtime이 사용하는 backend 이름을 반환한다.
 *
 * @param runtime engine runtime
 * @return const char* backend 이름
 */
const char *engine_runtime_backend_name(const engine_runtime_t *runtime) {
    if (NULL == runtime) {
        return "-";
    }
    return REGEX_BACKEND_HS == runtime->backend ? "hs" : "pcre2";
}

/**
 * @brief runtime의 JIT 활성화 여부를 반환한다.
 *
 * @param runtime engine runtime
 * @return int 활성화면 1, 아니면 0
 */
int engine_runtime_jit_enabled(const engine_runtime_t *runtime) {
    if (NULL == runtime) {
        return 0;
    }
    return runtime->jit_enabled;
}

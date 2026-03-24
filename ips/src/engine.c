/**
 * @file engine.c
 * @brief PCRE2/HS 정규식 백엔드 래퍼 구현
 *
 * backend별 차이는 이 파일 안으로 숨기고, 상위 계층에는
 * "주어진 컨텍스트에서 매치를 수집한다"는 동일한 API만 노출한다.
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

/** PCRE2 backend에서 룰별로 유지하는 컴파일 결과이다. */
typedef struct {
    const IPS_Signature *rule;       /* 원본 시그니처 메타데이터 */
    pcre2_code          *re;         /* PCRE2 컴파일 결과 */
    pcre2_match_data    *match_data; /* 룰별 재사용 match data */
} compiled_rule_t;

/** Hyperscan은 컨텍스트별 database를 따로 갖기 때문에 그 묶음을 저장한다. */
typedef struct {
    hs_database_t *db;           /* context 전용 Hyperscan DB */
    unsigned int  *rule_indexes; /* DB id -> compiled_rules 인덱스 매핑 */
    unsigned int   rule_count;   /* 이 DB에 포함된 룰 수 */
} hs_group_t;

/** Hyperscan scan callback이 공유하는 런타임 상태이다. */
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
    compiled_rule_t     *compiled_rules; /* rule_count 길이의 컴파일 결과 배열 */
    unsigned int         compiled_count; /* 전체 룰 수 */
    regex_backend_t      backend;        /* 선택된 backend */
    int                  jit_enabled;    /* PCRE2 JIT 활성화 여부 */
    pcre2_jit_stack     *jit_stack;      /* PCRE2 JIT용 stack */
    pcre2_match_context *match_ctx;      /* PCRE2 match context */
    hs_scratch_t        *hs_scratch;     /* Hyperscan scan scratch */
    hs_group_t           hs_groups[IPS_CTX_RESPONSE_BODY + 1]; /**< ctx별 HS DB */
};

static regex_backend_t g_selected_backend = REGEX_BACKEND_PCRE2;

/* --------------------------- common helpers --------------------------- */

/**
 * @brief backend/runtime 계층에서 사용할 오류 문자열을 기록한다.
 *
 * @param errbuf 오류 버퍼
 * @param errbuf_size 오류 버퍼 크기
 * @param msg 기록할 오류 메시지
 */
static void set_err(char *errbuf, size_t errbuf_size, const char *msg) {
    /* 오류 버퍼가 없으면 기록 자체를 생략한다. */
    if (NULL == errbuf || 0U == errbuf_size) {
        return;
    }
    /* NULL 메시지도 기본 문자열로 치환해 로그 가독성을 유지한다. */
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

    /* 결과 배열이 가득 찼으면 capacity를 2배씩 확장한다. */
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

    /* 매치 텍스트는 원본 입력 버퍼 수명과 분리하기 위해 별도 복사한다. */
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
    /* rule 자체가 없으면 현재 컨텍스트와 매칭될 수 없다. */
    if (NULL == rule) {
        return 0;
    }
    /* 어느 한쪽이 ALL이면 컨텍스트 제한 없이 허용한다. */
    if (IPS_CTX_ALL == ctx || IPS_CTX_ALL == rule->context) {
        return 1;
    }
    /* 그 외에는 정확히 같은 컨텍스트에서만 평가한다. */
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

    /* 문자열 "pcre2"는 PCRE2 backend 선택을 의미한다. */
    ret = strcmp(name, "pcre2");
    if (0 == ret) {
        g_selected_backend = REGEX_BACKEND_PCRE2;
        return 0;
    }
    /* 문자열 "hs"는 Hyperscan backend 선택을 의미한다. */
    ret = strcmp(name, "hs");
    if (0 == ret) {
        g_selected_backend = REGEX_BACKEND_HS;
        return 0;
    }
    /* 둘 다 아니면 호출자가 잘못된 backend 이름을 넘긴 것이다. */
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

    /* runtime이나 룰 배열이 없으면 해제할 PCRE2 자원도 없다. */
    if (NULL == runtime || NULL == runtime->compiled_rules) {
        return;
    }

    /* JIT stack과 match context를 먼저 정리한다. */
    if (NULL != runtime->jit_stack) {
        pcre2_jit_stack_free(runtime->jit_stack);
        runtime->jit_stack = NULL;
    }
    if (NULL != runtime->match_ctx) {
        pcre2_match_context_free(runtime->match_ctx);
        runtime->match_ctx = NULL;
    }

    for (i = 0; i < runtime->compiled_count; i++) {
        /* 룰별 match data는 PCRE2가 별도 할당한 객체다. */
        if (NULL != runtime->compiled_rules[i].match_data) {
            pcre2_match_data_free(runtime->compiled_rules[i].match_data);
            runtime->compiled_rules[i].match_data = NULL;
        }
        /* 마지막으로 컴파일된 regex code를 해제한다. */
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

    /* runtime 자체가 없으면 Hyperscan 자원도 해제할 것이 없다. */
    if (NULL == runtime) {
        return;
    }

    /* 모든 scan이 공유하는 scratch 영역을 먼저 반환한다. */
    if (NULL != runtime->hs_scratch) {
        hs_free_scratch(runtime->hs_scratch);
        runtime->hs_scratch = NULL;
    }

    for (ctx = 0; ctx <= (unsigned int)IPS_CTX_RESPONSE_BODY; ctx++) {
        /* 컨텍스트별 database와 인덱스 매핑 배열을 함께 정리한다. */
        if (NULL != runtime->hs_groups[ctx].db) {
            hs_free_database(runtime->hs_groups[ctx].db);
            runtime->hs_groups[ctx].db = NULL;
        }
        free(runtime->hs_groups[ctx].rule_indexes);
        runtime->hs_groups[ctx].rule_indexes = NULL;
        runtime->hs_groups[ctx].rule_count   = 0;
    }

    for (i = 0; i < runtime->compiled_count; i++) {
        /* HS backend에서는 개별 룰 객체를 소유하지 않으므로 포인터만 정리한다. */
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

    /* scan context가 없으면 이후 처리 자체가 불가능하므로 중단한다. */
    if (NULL == scan_ctx || NULL == scan_ctx->runtime) {
        return 1;
    }

    /*
     * Hyperscan callback의 id는 compile 시 넘긴 pattern id다.
     * 이 구현에서는 compiled_rules 배열 인덱스를 그대로 id로 쓰므로
     * 범위 검사를 먼저 한다.
     */
    if (id >= scan_ctx->runtime->compiled_count) {
        return 1;
    }

    rule_index = id;
    /*
     * Hyperscan은 같은 룰이 입력 내 여러 위치에서 매치될 수 있다.
     * 현재 런타임은 "룰이 매치됐는지"가 더 중요하므로 seen 비트로 중복 기록을
     * 막는다.
     */
    if (NULL != scan_ctx->seen && 0 != scan_ctx->seen[rule_index]) {
        return 0;
    }

    compiled_rule = &scan_ctx->runtime->compiled_rules[rule_index];
    rule          = compiled_rule->rule;
    /* 룰 메타데이터가 없으면 결과를 추가하지 않고 다음 매치로 넘어간다. */
    if (NULL == rule) {
        return 0;
    }

    /* 최소 한 번 이상 매치가 있었음을 표시한다. */
    scan_ctx->matched_any = 1;
    if (NULL != scan_ctx->seen) {
        scan_ctx->seen[rule_index] = 1;
    }

    /* 첫 매치만 필요한 호출자는 여기서 대표 룰 포인터를 받는다. */
    if (NULL != scan_ctx->first_rule && NULL == *scan_ctx->first_rule) {
        *scan_ctx->first_rule = rule;
    }

    if (NULL != scan_ctx->matches) {
        /*
         * Hyperscan은 from/to offset만 알려주므로, 그 범위를 원본 data에 다시
         * 매핑해 detect_match_list 형식으로 저장한다.
         */
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

    /* 첫 매치만 필요하면 callback에서 scan 조기 종료를 요청한다. */
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

    /*
     * JIT 정책은
     * - OFF: 절대 사용 안 함
     * - ON: 시스템 지원이 없으면 생성 실패
     * - AUTO: 가능하면 사용, 아니면 일반 compile로 fallback
     * 으로 동작한다.
     */
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

    /* 룰의 정규식을 PCRE2 code로 컴파일한다. */
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

    /* match data는 이 룰 패턴 구조에 맞춰 한 번 생성해 재사용한다. */
    slot->match_data = pcre2_match_data_create_from_pattern(slot->re, NULL);
    if (NULL == slot->match_data) {
        set_err(errbuf, errbuf_size,
                "pcre2_match_data_create_from_pattern failed");
        return -1;
    }

    /* JIT이 비활성화된 경우 여기서 준비를 마친다. */
    if (0 == runtime->jit_enabled) {
        return 0;
    }

    /* JIT compile이 실패해도 AUTO 모드면 일반 PCRE2 경로로 fallback 가능하다. */
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

    /* JIT size가 0이면 실질적으로 JIT code가 준비되지 않은 것으로 본다. */
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

    /*
     * Hyperscan DB는 "컨텍스트별 RX 룰 집합"만 담는다.
     * 따라서
     * - 현재 ctx와 맞지 않는 룰
     * - RX가 아닌 operator 룰
     * 은 HS DB에 넣지 않는다.
     */
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

    /* 이 컨텍스트에 RX 룰이 하나도 없으면 DB 생성 없이 빈 그룹으로 둔다. */
    if (0U == count) {
        return 0;
    }

    /* Hyperscan compile 입력 배열과 id->rule 인덱스 매핑 배열을 확보한다. */
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
        /* Hyperscan DB에 넣을 패턴 문자열과 rule 인덱스를 같은 순서로 채운다. */
        patterns[count]            = runtime->compiled_rules[i].rule->pattern;
        flags[count]               = 0;
        ids[count]                 = i;
        group->rule_indexes[count] = i;
        count++;
    }

    /* 이후 callback이 같은 ID를 받아 원본 룰을 되찾을 수 있게 한다. */
    group->rule_count = count;

    /*
     * 이 단계가 Hyperscan의 핵심.
     * 여러 정규식을 하나의 database로 컴파일해 이후 scan 한 번으로
     * 다수의 패턴을 동시에 검사할 수 있게 만든다.
     */
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

    /* scan scratch는 실제 매칭 시 반복 재사용되는 작업 공간이다. */
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

    /* runtime 본체를 먼저 확보해 backend 공용 상태를 담는다. */
    runtime = (engine_runtime_t *)malloc(sizeof(*runtime));
    if (NULL == runtime) {
        set_err(errbuf, errbuf_size, "engine alloc failed");
        return NULL;
    }
    memset(runtime, 0, sizeof(*runtime));

    /*
     * 생성 시점에 선택된 backend를 고정한다.
     * 이후 이 runtime 인스턴스는 lifetime 동안 한 backend만 사용한다.
     */
    runtime->backend = g_selected_backend;
    if (0U != rule_count) {
        /* 룰 수만큼 compile 결과 배열을 확보한다. */
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

    /*
     * PCRE2 backend는 룰 단위 compile 결과를 전부 미리 만든다.
     * HS backend는 개별 compile 대신 아래에서 context별 database를 만든다.
     */
    for (i = 0; i < rule_count; i++) {
        runtime->compiled_rules[i].rule = rules[i];
        /* RX가 아닌 룰은 regex compile 대상이 아니다. */
        if (NULL == rules[i] || IPS_OP_RX != rules[i]->op) {
            continue;
        }

        if (REGEX_BACKEND_HS != runtime->backend) {
            /* PCRE2 backend는 룰 단위로 개별 compile을 수행한다. */
            ret = compile_pcre2_rule(runtime, &runtime->compiled_rules[i],
                                     rules[i], jit_mode, errbuf, errbuf_size);
            if (0 != ret) {
                engine_runtime_destroy(runtime);
                return NULL;
            }
        }
    }

    if (REGEX_BACKEND_HS == runtime->backend) {
        /* 각 HTTP 컨텍스트마다 독립적인 HS DB를 준비한다. */
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
        /* JIT이 켜진 PCRE2 backend는 match context와 JIT stack도 준비한다. */
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
    /* NULL destroy는 no-op로 둬 상위 정리 코드를 단순화한다. */
    if (NULL == runtime) {
        return;
    }

    /* backend 종류에 맞는 자원 해제 루틴을 먼저 호출한다. */
    if (REGEX_BACKEND_HS == runtime->backend) {
        hs_release(runtime);
    } else {
        pcre2_release(runtime);
    }

    /* 공통 compile 결과 배열과 runtime 본체를 마지막에 반환한다. */
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

    /* 환경변수가 없으면 profiling 기능은 기본 비활성이다. */
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

    /* 임계값이 없거나 비정상이면 기본값 50ms를 사용한다. */
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

    /* monotonic clock 조회 실패 시 elapsed 계산은 0으로 둔다. */
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

    /* profiling이 꺼져 있으면 호출 비용만 최소화하고 즉시 반환한다. */
    enabled = regex_profile_enabled();
    if (0 == enabled) {
        return;
    }

    /* threshold보다 짧은 실행은 노이즈로 보고 기록하지 않는다. */
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

    /* PCRE2 경로는 "룰 하나를 입력 하나에 적용"하는 전통적 방식이다. */
    rc = pcre2_match(compiled_rule->re, (PCRE2_SPTR)data, len, 0, 0,
                     compiled_rule->match_data,
                     NULL != runtime ? runtime->match_ctx : NULL);

    if (0 <= rc) {
        /* 첫 매치 범위를 ovector에서 읽어 호출자에게 반환한다. */
        ovector    = pcre2_get_ovector_pointer(compiled_rule->match_data);
        *match_off = (size_t)ovector[0];
        *match_len = (size_t)(ovector[1] - ovector[0]);
        return 1;
    }
    /* 매치가 없으면 오류가 아니라 정상적인 미탐지다. */
    if (PCRE2_ERROR_NOMATCH == rc) {
        return 0;
    }

    /* 그 외 PCRE2 에러는 상위에 일반화된 오류 문자열로 올린다. */
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

    /* HS는 미리 정의된 컨텍스트 범위 안에서만 database를 찾을 수 있다. */
    if (IPS_CTX_ALL > ctx || IPS_CTX_RESPONSE_BODY < ctx) {
        set_err(errbuf, errbuf_size, "invalid hs ctx");
        return -1;
    }

    /* HS 경로는 현재 컨텍스트 전용 database 하나를 선택해 scan 한다. */
    group = &runtime->hs_groups[ctx];
    /* 해당 컨텍스트용 DB가 없으면 이 입력에서 평가할 HS 룰이 없다. */
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

    /* scan 한 번으로 같은 ctx의 다수 룰을 동시에 검사한다. */
    rc = hs_scan(group->db, (const char *)data, (unsigned int)len, 0,
                 runtime->hs_scratch, hs_on_match, &scan_ctx);
    if (HS_SUCCESS != rc && HS_SCAN_TERMINATED != rc) {
        set_err(errbuf, errbuf_size, "hs_scan error");
        return -1;
    }
    /* callback에서 단 한 번도 매치를 받지 못했으면 미탐지다. */
    if (0 == scan_ctx.matched_any) {
        return 0;
    }

    /* first-match API에서는 룰 존재 여부만 중요하므로 offset은 사용하지 않는다. */
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
    /*
     * 상위는 backend를 몰라도 되게 하려는 helper다.
     * 다만 HS는 사실상 "룰 하나"가 아니라 "컨텍스트 그룹" 단위로 스캔한다는
     * 점이 PCRE2와 가장 큰 차이다.
     */
    /* backend 차이는 여기서 감춘다. 상위는 공통 API만 본다. */
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

    /* 호출자는 대표 룰 포인터를 기대하므로 먼저 NULL로 초기화한다. */
    if (NULL != matched_rule) {
        *matched_rule = NULL;
    }
    /* runtime, data, len 중 하나라도 비면 검사할 입력이 없다. */
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

        /*
         * HS는 개별 룰 실행 시간이 아니라 "컨텍스트 전체 scan 시간"만
         * 자연스럽게 잴 수 있으므로, 여기서도 그 단위로만 profiling 한다.
         */
        maybe_log_rule_profile(NULL, ctx, len, mono_us_now() - t0, rc);
        return (rc < 0) ? -1 : 0;
    }

    /* PCRE2는 컨텍스트에 맞는 룰을 하나씩 순회하며 첫 매치를 찾는다. */
    for (i = 0; i < runtime->compiled_count; i++) {
        size_t match_off = 0;
        size_t match_len = 0;
        int    rc;

        /* 현재 컨텍스트와 맞지 않는 룰은 첫 매치 탐색 대상에서 제외한다. */
        rule_matches =
            rule_context_matches(runtime->compiled_rules[i].rule, ctx);
        if (0 == rule_matches) {
            continue;
        }
        /* RX 룰만 실제 정규식 평가를 수행한다. */
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
        /* 첫 매치가 나오면 그 룰을 대표 룰로 확정하고 즉시 반환한다. */
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
    /* 시간 누적이 필요 없는 호출자는 timed 버전을 그대로 재사용한다. */
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

    /* 결과 컨테이너가 없으면 수집 API 의미 자체가 성립하지 않는다. */
    if (NULL == matches) {
        set_err(errbuf, errbuf_size, "null matches");
        return -1;
    }
    /* 입력이 비어 있으면 검사 없이 정상 종료한다. */
    if (NULL == runtime || NULL == data || 0U == len) {
        return 0;
    }
    if ((size_t)INT_MAX < len) {
        set_err(errbuf, errbuf_size, "payload too large");
        return -1;
    }
    /*
     * HS와 PCRE2의 수집 전략은 다르다.
     * - HS: context별 DB 하나를 scan하고 callback에서 매치를 누적
     * - PCRE2: context에 맞는 룰을 순회하며 룰별로 match 수행
     */
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

        /*
         * HS는 같은 룰이 입력 안에서 여러 번 매치될 수 있으므로,
         * 이번 scan에서 이미 기록한 rule인지 체크하는 seen 배열을 둔다.
         */
        /* 이번 scan에서 이미 기록한 rule인지 추적하기 위한 배열이다. */
        seen = (uint8_t *)malloc(runtime->compiled_count * sizeof(*seen));
        if (NULL == seen) {
            set_err(errbuf, errbuf_size, "hs seen alloc failed");
            return -1;
        }
        memset(seen, 0, runtime->compiled_count * sizeof(*seen));

        /* callback이 matches에 직접 결과를 append 하도록 scan context를 채운다. */
        memset(&scan_ctx, 0, sizeof(scan_ctx));
        scan_ctx.runtime  = runtime;
        scan_ctx.matches  = matches;
        scan_ctx.ctx      = ctx;
        scan_ctx.data     = data;
        scan_ctx.data_len = len;
        scan_ctx.seen     = seen;

        /* 이번 컨텍스트 전체 HS scan 시간을 한 번에 측정한다. */
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
        /*
         * HS는 "다수 룰 동시 스캔" 구조라서 룰별 elapsed_us를 자연스럽게
         * 쪼갤 수 없다. 따라서 이번 컨텍스트 scan 전체 시간을 새로 생성된
         * match 항목들에 일괄 기록한다.
         */
        /* HS는 룰별 시간이 아니라 컨텍스트 scan 전체 시간을 새 매치에 일괄 부여한다. */
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
    /*
     * PCRE2는 룰 단위 실행 모델이므로,
     * 각 룰의 실행 시간과 매치 문자열을 개별적으로 기록할 수 있다.
     */
    /* 백엔드가 pcre인 경우 */
    for (i = 0; i < runtime->compiled_count; i++) {
        size_t   match_off  = 0;
        size_t   match_len  = 0;
        uint64_t elapsed_us = 0;
        int      rc;
        int      append_rc;

        /* 컨텍스트가 다르면 이 룰은 현재 입력에서 건너뛴다. */
        rule_matches =
            rule_context_matches(runtime->compiled_rules[i].rule, ctx);
        if (0 == rule_matches) {
            continue;
        }
        /* PCRE2 경로도 RX 룰만 실제 regex 평가 대상이다. */
        if (NULL == runtime->compiled_rules[i].rule ||
            IPS_OP_RX != runtime->compiled_rules[i].rule->op) {
            continue;
        }

        {
            /* 룰 단위 elapsed_us를 측정해 매치 결과와 함께 보관한다. */
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
        /* 미매치면 결과를 추가하지 않고 다음 룰로 넘어간다. */
        if (0 == rc) {
            continue;
        }

        /* 실제 매치가 난 룰만 detect_match_list에 새 항목으로 append 한다. */
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

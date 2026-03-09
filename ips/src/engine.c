/**
 * @file engine.c
 * @brief PCRE/HS 정규식 백엔드 래퍼 구현
 */
#define _DEFAULT_SOURCE
#include "engine.h"

#include <hs/hs.h>
#include <limits.h>
#include <pcre.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef enum {
    REGEX_BACKEND_PCRE = 0,
    REGEX_BACKEND_HS
} regex_backend_t;

typedef struct {
    const IPS_Signature *rule;
    pcre *re;
    pcre_extra *extra;
    hs_database_t *hs_db;
} compiled_rule_t;

typedef struct {
    int matched;
    unsigned long long from;
    unsigned long long to;
} hs_match_ctx_t;

struct engine_runtime {
    compiled_rule_t *compiled_rules;
    unsigned int compiled_count;
    regex_backend_t backend;
    int jit_enabled;
    pcre_jit_stack *jit_stack;
    hs_scratch_t *hs_scratch;
};

static regex_backend_t g_selected_backend = REGEX_BACKEND_PCRE;

static void set_err(char *errbuf, size_t errbuf_size, const char *msg)
{
    if (errbuf == NULL || errbuf_size == 0) {
        return;
    }
    snprintf(errbuf, errbuf_size, "%s", msg != NULL ? msg : "unknown error");
}

static int detect_match_list_append_local(
    detect_match_list_t *matches,
    const IPS_Signature *rule,
    ips_context_t ctx,
    const char *matched_text,
    size_t matched_len,
    uint64_t elapsed_us)
{
    detect_match_t *next_items;
    char *copy;
    size_t next_cap;

    if (matches == NULL) {
        return -1;
    }

    if (matches->count == matches->capacity) {
        next_cap = matches->capacity != 0 ? matches->capacity * 2U : 8U;
        next_items = (detect_match_t *)realloc(matches->items, next_cap * sizeof(*next_items));
        if (next_items == NULL) {
            return -1;
        }
        matches->items = next_items;
        matches->capacity = next_cap;
    }

    copy = (char *)malloc(matched_len + 1U);
    if (copy == NULL) {
        return -1;
    }
    if (matched_len > 0) {
        memcpy(copy, matched_text, matched_len);
    }
    copy[matched_len] = '\0';

    matches->items[matches->count].rule = rule;
    matches->items[matches->count].context = ctx;
    matches->items[matches->count].matched_text = copy;
    matches->items[matches->count].elapsed_us = elapsed_us;
    matches->count++;
    return 0;
}

static int rule_context_matches(const IPS_Signature *rule, ips_context_t ctx)
{
    if (rule == NULL) {
        return 0;
    }
    if (ctx == IPS_CTX_ALL || rule->context == IPS_CTX_ALL) {
        return 1;
    }
    return rule->context == ctx;
}

int engine_set_backend_name(const char *name, char *errbuf, size_t errbuf_size)
{
    if (name == NULL || strcmp(name, "pcre") == 0) {
        g_selected_backend = REGEX_BACKEND_PCRE;
        return 0;
    }
    if (strcmp(name, "hs") == 0) {
        g_selected_backend = REGEX_BACKEND_HS;
        return 0;
    }
    set_err(errbuf, errbuf_size, "invalid regex backend");
    return -1;
}

static void pcre_release(engine_runtime_t *runtime)
{
    unsigned int i;

    if (runtime == NULL || runtime->compiled_rules == NULL) {
        return;
    }

    if (runtime->jit_stack != NULL) {
        pcre_jit_stack_free(runtime->jit_stack);
        runtime->jit_stack = NULL;
    }

    for (i = 0; i < runtime->compiled_count; i++) {
        if (runtime->compiled_rules[i].extra != NULL) {
            pcre_free_study(runtime->compiled_rules[i].extra);
            runtime->compiled_rules[i].extra = NULL;
        }
        if (runtime->compiled_rules[i].re != NULL) {
            pcre_free(runtime->compiled_rules[i].re);
            runtime->compiled_rules[i].re = NULL;
        }
    }
}

static void hs_release(engine_runtime_t *runtime)
{
    unsigned int i;

    if (runtime == NULL || runtime->compiled_rules == NULL) {
        return;
    }

    if (runtime->hs_scratch != NULL) {
        hs_free_scratch(runtime->hs_scratch);
        runtime->hs_scratch = NULL;
    }

    for (i = 0; i < runtime->compiled_count; i++) {
        if (runtime->compiled_rules[i].hs_db != NULL) {
            hs_free_database(runtime->compiled_rules[i].hs_db);
            runtime->compiled_rules[i].hs_db = NULL;
        }
    }
}

static int hs_on_match(
    unsigned int id,
    unsigned long long from,
    unsigned long long to,
    unsigned int flags,
    void *ctx)
{
    hs_match_ctx_t *match_ctx = (hs_match_ctx_t *)ctx;

    (void)id;
    (void)flags;

    if (match_ctx == NULL) {
        return 1;
    }

    match_ctx->matched = 1;
    match_ctx->from = from;
    match_ctx->to = to;
    return 1;
}

static int compile_pcre_rule(
    engine_runtime_t *runtime,
    compiled_rule_t *slot,
    const IPS_Signature *rule,
    detect_jit_mode_t jit_mode,
    char *errbuf,
    size_t errbuf_size)
{
    const char *err = NULL;
    const char *study_err = NULL;
    int erroffset = 0;
    int jit_cfg = 0;
    int rc_cfg;
    int jit_info = 0;

    rc_cfg = pcre_config(PCRE_CONFIG_JIT, &jit_cfg);
    if (jit_mode == DETECT_JIT_OFF) {
        runtime->jit_enabled = 0;
    } else if (jit_mode == DETECT_JIT_ON) {
        if (!(rc_cfg == 0 && jit_cfg == 1)) {
            set_err(errbuf, errbuf_size, "requested -jit=on but PCRE JIT is unavailable");
            return -1;
        }
        runtime->jit_enabled = 1;
    } else {
        runtime->jit_enabled = (rc_cfg == 0 && jit_cfg == 1) ? 1 : 0;
    }

    slot->re = pcre_compile(rule->pattern, PCRE_CASELESS, &err, &erroffset, NULL);
    if (slot->re == NULL) {
        char msg[256];
        snprintf(msg, sizeof(msg), "pcre_compile failed: rid=%d offset=%d err=%s",
            rule->rule_id, erroffset, err != NULL ? err : "unknown");
        set_err(errbuf, errbuf_size, msg);
        return -1;
    }

    if (!runtime->jit_enabled) {
        return 0;
    }

    slot->extra = pcre_study(slot->re, PCRE_STUDY_JIT_COMPILE, &study_err);
    if (study_err != NULL) {
        if (jit_mode == DETECT_JIT_ON) {
            char msg[256];
            snprintf(msg, sizeof(msg), "pcre_study(JIT) failed: rid=%d err=%s",
                rule->rule_id, study_err);
            set_err(errbuf, errbuf_size, msg);
            return -1;
        }
        runtime->jit_enabled = 0;
        return 0;
    }

    if (slot->extra == NULL ||
        pcre_fullinfo(slot->re, slot->extra, PCRE_INFO_JIT, &jit_info) != 0 ||
        jit_info != 1) {
        if (jit_mode == DETECT_JIT_ON) {
            char msg[256];
            snprintf(msg, sizeof(msg), "pcre JIT compile unavailable for rid=%d", rule->rule_id);
            set_err(errbuf, errbuf_size, msg);
            return -1;
        }
        runtime->jit_enabled = 0;
    }

    return 0;
}

static int compile_hs_rule(
    compiled_rule_t *slot,
    const IPS_Signature *rule,
    hs_scratch_t **scratch,
    char *errbuf,
    size_t errbuf_size)
{
    hs_compile_error_t *compile_err = NULL;
    hs_error_t rc;

    rc = hs_compile(rule->pattern,
        0,
        HS_MODE_BLOCK,
        NULL,
        &slot->hs_db,
        &compile_err);
    if (rc != HS_SUCCESS) {
        char msg[256];
        snprintf(msg, sizeof(msg), "hs_compile failed: rid=%d err=%s",
            rule->rule_id,
            (compile_err != NULL && compile_err->message != NULL) ? compile_err->message : "unknown");
        set_err(errbuf, errbuf_size, msg);
        if (compile_err != NULL) {
            hs_free_compile_error(compile_err);
        }
        return -1;
    }

    if (compile_err != NULL) {
        hs_free_compile_error(compile_err);
    }

    rc = hs_alloc_scratch(slot->hs_db, scratch);
    if (rc != HS_SUCCESS) {
        set_err(errbuf, errbuf_size, "hs_alloc_scratch failed");
        return -1;
    }

    return 0;
}

engine_runtime_t *engine_runtime_create(
    const IPS_Signature *const *rules,
    unsigned int rule_count,
    detect_jit_mode_t jit_mode,
    char *errbuf,
    size_t errbuf_size)
{
    engine_runtime_t *runtime;
    unsigned int i;

    runtime = (engine_runtime_t *)calloc(1, sizeof(*runtime));
    if (runtime == NULL) {
        set_err(errbuf, errbuf_size, "engine alloc failed");
        return NULL;
    }

    runtime->backend = g_selected_backend;
    runtime->compiled_rules = (compiled_rule_t *)calloc(rule_count, sizeof(*runtime->compiled_rules));
    if (runtime->compiled_rules == NULL) {
        set_err(errbuf, errbuf_size, "engine compile alloc failed");
        engine_runtime_destroy(runtime);
        return NULL;
    }
    runtime->compiled_count = rule_count;

    for (i = 0; i < rule_count; i++) {
        runtime->compiled_rules[i].rule = rules[i];
        if (rules[i] == NULL || rules[i]->op != IPS_OP_RX) {
            continue;
        }

        if (runtime->backend == REGEX_BACKEND_HS) {
            if (compile_hs_rule(&runtime->compiled_rules[i], rules[i], &runtime->hs_scratch, errbuf, errbuf_size) != 0) {
                engine_runtime_destroy(runtime);
                return NULL;
            }
        } else {
            if (compile_pcre_rule(runtime, &runtime->compiled_rules[i], rules[i], jit_mode, errbuf, errbuf_size) != 0) {
                engine_runtime_destroy(runtime);
                return NULL;
            }
        }
    }

    if (runtime->backend == REGEX_BACKEND_PCRE && runtime->jit_enabled) {
        runtime->jit_stack = pcre_jit_stack_alloc(32 * 1024, 512 * 1024);
        if (runtime->jit_stack == NULL) {
            if (jit_mode == DETECT_JIT_ON) {
                set_err(errbuf, errbuf_size, "pcre_jit_stack_alloc failed");
                engine_runtime_destroy(runtime);
                return NULL;
            }
            runtime->jit_enabled = 0;
        } else {
            for (i = 0; i < runtime->compiled_count; i++) {
                if (runtime->compiled_rules[i].extra != NULL) {
                    pcre_assign_jit_stack(runtime->compiled_rules[i].extra, NULL, runtime->jit_stack);
                }
            }
        }
    }

    return runtime;
}

void engine_runtime_destroy(engine_runtime_t *runtime)
{
    if (runtime == NULL) {
        return;
    }

    if (runtime->backend == REGEX_BACKEND_HS) {
        hs_release(runtime);
    } else {
        pcre_release(runtime);
    }

    free(runtime->compiled_rules);
    free(runtime);
}


static int regex_profile_enabled(void)
{
    const char *v = getenv("IPS_PROFILE_REGEX");
    return v != NULL && strcmp(v, "0") != 0 && strcmp(v, "false") != 0;
}

static long regex_profile_threshold_us(void)
{
    const char *v = getenv("IPS_PROFILE_THRESHOLD_US");
    char *end = NULL;
    long n;

    if (v == NULL || *v == '\0') {
        return 50000;
    }
    n = strtol(v, &end, 10);
    if (end == v || n < 0) {
        return 50000;
    }
    return n;
}

static unsigned long long mono_us_now(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (unsigned long long)ts.tv_sec * 1000000ULL + (unsigned long long)(ts.tv_nsec / 1000ULL);
}

static void maybe_log_rule_profile(
    const compiled_rule_t *compiled_rule,
    ips_context_t ctx,
    size_t len,
    unsigned long long elapsed_us,
    int rc)
{
    const IPS_Signature *rule;

    if (!regex_profile_enabled()) {
        return;
    }
    if ((long)elapsed_us < regex_profile_threshold_us()) {
        return;
    }

    rule = compiled_rule != NULL ? compiled_rule->rule : NULL;
    fprintf(stderr,
        "[REGEX][PROFILE] rid=%d policy=%s ctx=%d len=%zu elapsed_us=%llu rc=%d pat=\"%s\"\n",
        rule != NULL ? rule->rule_id : -1,
        rule != NULL && rule->policy_name != NULL ? rule->policy_name : "-",
        (int)ctx,
        len,
        elapsed_us,
        rc,
        rule != NULL && rule->pattern != NULL ? rule->pattern : "");
}

static int engine_match_pcre(
    const compiled_rule_t *compiled_rule,
    const uint8_t *data,
    size_t len,
    size_t *match_off,
    size_t *match_len,
    char *errbuf,
    size_t errbuf_size)
{
    int ovector[30];
    int rc;

    rc = pcre_exec(
        compiled_rule->re,
        compiled_rule->extra,
        (const char *)data,
        (int)len,
        0,
        0,
        ovector,
        (int)(sizeof(ovector) / sizeof(ovector[0])));

    if (rc >= 0) {
        *match_off = (size_t)ovector[0];
        *match_len = (size_t)(ovector[1] - ovector[0]);
        return 1;
    }
    if (rc == PCRE_ERROR_NOMATCH) {
        return 0;
    }

    set_err(errbuf, errbuf_size, "pcre_exec error");
    return -1;
}

static int engine_match_hs(
    engine_runtime_t *runtime,
    const compiled_rule_t *compiled_rule,
    const uint8_t *data,
    size_t len,
    size_t *match_off,
    size_t *match_len,
    char *errbuf,
    size_t errbuf_size)
{
    hs_match_ctx_t ctx;
    hs_error_t rc;

    memset(&ctx, 0, sizeof(ctx));
    rc = hs_scan(compiled_rule->hs_db,
        (const char *)data,
        (unsigned int)len,
        0,
        runtime->hs_scratch,
        hs_on_match,
        &ctx);
    if (rc != HS_SUCCESS && rc != HS_SCAN_TERMINATED) {
        set_err(errbuf, errbuf_size, "hs_scan error");
        return -1;
    }
    if (!ctx.matched) {
        return 0;
    }

    *match_off = 0;
    *match_len = (size_t)ctx.to;
    if (*match_off > len) {
        *match_off = 0;
    }
    if (*match_off + *match_len > len) {
        *match_len = 0;
    }
    return 1;
}

static int engine_match_one(
    engine_runtime_t *runtime,
    const compiled_rule_t *compiled_rule,
    const uint8_t *data,
    size_t len,
    size_t *match_off,
    size_t *match_len,
    char *errbuf,
    size_t errbuf_size)
{
    if (runtime->backend == REGEX_BACKEND_HS) {
        return engine_match_hs(runtime, compiled_rule, data, len, match_off, match_len, errbuf, errbuf_size);
    }
    return engine_match_pcre(compiled_rule, data, len, match_off, match_len, errbuf, errbuf_size);
}

int engine_runtime_match_first(
    engine_runtime_t *runtime,
    const uint8_t *data,
    size_t len,
    ips_context_t ctx,
    const IPS_Signature **matched_rule,
    char *errbuf,
    size_t errbuf_size)
{
    unsigned int i;

    if (matched_rule != NULL) {
        *matched_rule = NULL;
    }
    if (runtime == NULL || data == NULL || len == 0) {
        return 0;
    }
    if (len > (size_t)INT_MAX) {
        set_err(errbuf, errbuf_size, "payload too large");
        return -1;
    }

    for (i = 0; i < runtime->compiled_count; i++) {
        size_t match_off = 0;
        size_t match_len = 0;
        int rc;

        if (!rule_context_matches(runtime->compiled_rules[i].rule, ctx)) {
            continue;
        }
        if (runtime->compiled_rules[i].rule == NULL || runtime->compiled_rules[i].rule->op != IPS_OP_RX) {
            continue;
        }

        {
            unsigned long long t0 = mono_us_now();
            rc = engine_match_one(runtime, &runtime->compiled_rules[i], data, len, &match_off, &match_len, errbuf, errbuf_size);
            maybe_log_rule_profile(&runtime->compiled_rules[i], ctx, len, mono_us_now() - t0, rc);
        }
        if (rc < 0) {
            return -1;
        }
        if (rc > 0) {
            if (matched_rule != NULL) {
                *matched_rule = runtime->compiled_rules[i].rule;
            }
            return 1;
        }
    }

    return 0;
}

int engine_runtime_collect_matches(
    engine_runtime_t *runtime,
    const uint8_t *data,
    size_t len,
    ips_context_t ctx,
    detect_match_list_t *matches,
    char *errbuf,
    size_t errbuf_size)
{
    return engine_runtime_collect_matches_timed(
        runtime,
        data,
        len,
        ctx,
        matches,
        NULL,
        errbuf,
        errbuf_size);
}

int engine_runtime_collect_matches_timed(
    engine_runtime_t *runtime,
    const uint8_t *data,
    size_t len,
    ips_context_t ctx,
    detect_match_list_t *matches,
    uint64_t *elapsed_us_sum,
    char *errbuf,
    size_t errbuf_size)
{
    unsigned int i;
    int matched_any = 0;

    if (elapsed_us_sum != NULL) {
        *elapsed_us_sum = 0;
    }

    if (matches == NULL) {
        set_err(errbuf, errbuf_size, "null matches");
        return -1;
    }
    if (runtime == NULL || data == NULL || len == 0) {
        return 0;
    }
    if (len > (size_t)INT_MAX) {
        set_err(errbuf, errbuf_size, "payload too large");
        return -1;
    }

    for (i = 0; i < runtime->compiled_count; i++) {
        size_t match_off = 0;
        size_t match_len = 0;
        uint64_t elapsed_us = 0;
        int rc;

        if (!rule_context_matches(runtime->compiled_rules[i].rule, ctx)) {
            continue;
        }
        if (runtime->compiled_rules[i].rule == NULL || runtime->compiled_rules[i].rule->op != IPS_OP_RX) {
            continue;
        }

        {
            unsigned long long t0 = mono_us_now();
            rc = engine_match_one(runtime, &runtime->compiled_rules[i], data, len, &match_off, &match_len, errbuf, errbuf_size);
            elapsed_us = (uint64_t)(mono_us_now() - t0);
            maybe_log_rule_profile(&runtime->compiled_rules[i], ctx, len, elapsed_us, rc);
            if (elapsed_us_sum != NULL) {
                *elapsed_us_sum += elapsed_us;
            }
        }
        if (rc < 0) {
            return -1;
        }
        if (rc == 0) {
            continue;
        }

        if (detect_match_list_append_local(
                matches,
                runtime->compiled_rules[i].rule,
                ctx,
                match_len != 0 ? (const char *)data + match_off : "",
                match_len,
                elapsed_us) != 0) {
            set_err(errbuf, errbuf_size, "append match failed");
            return -1;
        }
        matched_any = 1;
    }

    return matched_any ? 1 : 0;
}

const char *engine_runtime_backend_name(const engine_runtime_t *runtime)
{
    if (runtime == NULL) return "-";
    return runtime->backend == REGEX_BACKEND_HS ? "hs" : "pcre";
}

int engine_runtime_jit_enabled(const engine_runtime_t *runtime)
{
    if (runtime == NULL) return 0;
    return runtime->jit_enabled;
}

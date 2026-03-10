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
} compiled_rule_t;

typedef struct {
    hs_database_t *db;
    unsigned int *rule_indexes;
    unsigned int rule_count;
} hs_group_t;

typedef struct {
    const engine_runtime_t *runtime;
    detect_match_list_t *matches;
    ips_context_t ctx;
    int matched_any;
    int stop_after_first;
    const IPS_Signature **first_rule;
    uint8_t *seen;
} hs_scan_ctx_t;

struct engine_runtime {
    compiled_rule_t *compiled_rules;
    unsigned int compiled_count;
    regex_backend_t backend;
    int jit_enabled;
    pcre_jit_stack *jit_stack;
    hs_scratch_t *hs_scratch;
    hs_group_t hs_groups[IPS_CTX_RESPONSE_BODY + 1];
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
    unsigned int ctx;

    if (runtime == NULL) {
        return;
    }

    if (runtime->hs_scratch != NULL) {
        hs_free_scratch(runtime->hs_scratch);
        runtime->hs_scratch = NULL;
    }

    for (ctx = 0; ctx <= (unsigned int)IPS_CTX_RESPONSE_BODY; ctx++) {
        if (runtime->hs_groups[ctx].db != NULL) {
            hs_free_database(runtime->hs_groups[ctx].db);
            runtime->hs_groups[ctx].db = NULL;
        }
        free(runtime->hs_groups[ctx].rule_indexes);
        runtime->hs_groups[ctx].rule_indexes = NULL;
        runtime->hs_groups[ctx].rule_count = 0;
    }

    for (i = 0; i < runtime->compiled_count; i++) {
        if (runtime->compiled_rules[i].re != NULL) {
            runtime->compiled_rules[i].re = NULL;
        }
        if (runtime->compiled_rules[i].extra != NULL) {
            runtime->compiled_rules[i].extra = NULL;
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
    hs_scan_ctx_t *scan_ctx = (hs_scan_ctx_t *)ctx;
    const IPS_Signature *rule;
    const compiled_rule_t *compiled_rule;
    unsigned int rule_index;

    (void)flags;
    (void)from;

    if (scan_ctx == NULL || scan_ctx->runtime == NULL) {
        return 1;
    }

    if (id >= scan_ctx->runtime->compiled_count) {
        return 1;
    }

    rule_index = id;
    if (scan_ctx->seen != NULL && scan_ctx->seen[rule_index]) {
        return 0;
    }

    compiled_rule = &scan_ctx->runtime->compiled_rules[rule_index];
    rule = compiled_rule->rule;
    if (rule == NULL) {
        return 0;
    }

    scan_ctx->matched_any = 1;
    if (scan_ctx->seen != NULL) {
        scan_ctx->seen[rule_index] = 1;
    }

    if (scan_ctx->first_rule != NULL && *scan_ctx->first_rule == NULL) {
        *scan_ctx->first_rule = rule;
    }

    if (scan_ctx->matches != NULL) {
        size_t match_len = (size_t)to;
        if (match_len > 0 && detect_match_list_append_local(
                scan_ctx->matches,
                rule,
                scan_ctx->ctx,
                "",
                0,
                0) != 0) {
            return 1;
        }
    }

    return scan_ctx->stop_after_first ? 1 : 0;
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

static int compile_hs_group(
    engine_runtime_t *runtime,
    hs_group_t *group,
    unsigned int ctx,
    char *errbuf,
    size_t errbuf_size)
{
    const char **patterns = NULL;
    unsigned int *flags = NULL;
    unsigned int *ids = NULL;
    hs_compile_error_t *compile_err = NULL;
    hs_error_t rc;
    unsigned int count = 0;
    unsigned int i;

    for (i = 0; i < runtime->compiled_count; i++) {
        if (!rule_context_matches(runtime->compiled_rules[i].rule, (ips_context_t)ctx)) {
            continue;
        }
        if (runtime->compiled_rules[i].rule == NULL || runtime->compiled_rules[i].rule->op != IPS_OP_RX) {
            continue;
        }
        count++;
    }

    if (count == 0) {
        return 0;
    }

    patterns = (const char **)calloc(count, sizeof(*patterns));
    flags = (unsigned int *)calloc(count, sizeof(*flags));
    ids = (unsigned int *)calloc(count, sizeof(*ids));
    group->rule_indexes = (unsigned int *)calloc(count, sizeof(*group->rule_indexes));
    if (patterns == NULL || flags == NULL || ids == NULL || group->rule_indexes == NULL) {
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
        if (!rule_context_matches(runtime->compiled_rules[i].rule, (ips_context_t)ctx)) {
            continue;
        }
        if (runtime->compiled_rules[i].rule == NULL || runtime->compiled_rules[i].rule->op != IPS_OP_RX) {
            continue;
        }
        patterns[count] = runtime->compiled_rules[i].rule->pattern;
        flags[count] = 0;
        ids[count] = i;
        group->rule_indexes[count] = i;
        count++;
    }

    group->rule_count = count;

    rc = hs_compile_multi(patterns,
        flags,
        ids,
        count,
        HS_MODE_BLOCK,
        NULL,
        &group->db,
        &compile_err);
    free(patterns);
    free(flags);
    free(ids);

    if (rc != HS_SUCCESS) {
        char msg[256];
        snprintf(msg, sizeof(msg), "hs_compile_multi failed: ctx=%u err=%s",
            ctx,
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

    rc = hs_alloc_scratch(group->db, &runtime->hs_scratch);
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

        if (runtime->backend != REGEX_BACKEND_HS) {
            if (compile_pcre_rule(runtime, &runtime->compiled_rules[i], rules[i], jit_mode, errbuf, errbuf_size) != 0) {
                engine_runtime_destroy(runtime);
                return NULL;
            }
        }
    }

    if (runtime->backend == REGEX_BACKEND_HS) {
        for (i = 0; i <= (unsigned int)IPS_CTX_RESPONSE_BODY; i++) {
            if (compile_hs_group(runtime, &runtime->hs_groups[i], i, errbuf, errbuf_size) != 0) {
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
    ips_context_t ctx,
    const uint8_t *data,
    size_t len,
    size_t *match_off,
    size_t *match_len,
    const IPS_Signature **matched_rule,
    char *errbuf,
    size_t errbuf_size)
{
    hs_scan_ctx_t scan_ctx;
    hs_group_t *group;
    hs_error_t rc;

    if (ctx < IPS_CTX_ALL || ctx > IPS_CTX_RESPONSE_BODY) {
        set_err(errbuf, errbuf_size, "invalid hs ctx");
        return -1;
    }

    group = &runtime->hs_groups[ctx];
    if (group->db == NULL) {
        return 0;
    }

    memset(&scan_ctx, 0, sizeof(scan_ctx));
    scan_ctx.runtime = runtime;
    scan_ctx.ctx = ctx;
    scan_ctx.stop_after_first = 1;
    scan_ctx.first_rule = matched_rule;

    rc = hs_scan(group->db,
        (const char *)data,
        (unsigned int)len,
        0,
        runtime->hs_scratch,
        hs_on_match,
        &scan_ctx);
    if (rc != HS_SUCCESS && rc != HS_SCAN_TERMINATED) {
        set_err(errbuf, errbuf_size, "hs_scan error");
        return -1;
    }
    if (!scan_ctx.matched_any) {
        return 0;
    }

    *match_off = 0;
    *match_len = 0;
    return 1;
}

static int engine_match_one(
    engine_runtime_t *runtime,
    const compiled_rule_t *compiled_rule,
    const uint8_t *data,
    size_t len,
    size_t *match_off,
    size_t *match_len,
    const IPS_Signature **matched_rule,
    char *errbuf,
    size_t errbuf_size)
{
    if (runtime->backend == REGEX_BACKEND_HS) {
        return engine_match_hs(runtime, compiled_rule->rule != NULL ? compiled_rule->rule->context : IPS_CTX_ALL, data, len, match_off, match_len, matched_rule, errbuf, errbuf_size);
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

    if (runtime->backend == REGEX_BACKEND_HS) {
        size_t match_off = 0;
        size_t match_len = 0;
        unsigned long long t0 = mono_us_now();
        int rc = engine_match_hs(runtime, ctx, data, len, &match_off, &match_len, matched_rule, errbuf, errbuf_size);

        maybe_log_rule_profile(NULL, ctx, len, mono_us_now() - t0, rc);
        return rc;
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
            rc = engine_match_one(runtime, &runtime->compiled_rules[i], data, len, &match_off, &match_len, matched_rule, errbuf, errbuf_size);
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

    if (runtime->backend == REGEX_BACKEND_HS) {
        hs_group_t *group;
        hs_scan_ctx_t scan_ctx;
        uint64_t elapsed_us = 0;
        unsigned long long t0;
        uint8_t *seen;
        hs_error_t rc_hs;

        if (ctx < IPS_CTX_ALL || ctx > IPS_CTX_RESPONSE_BODY) {
            set_err(errbuf, errbuf_size, "invalid hs ctx");
            return -1;
        }
        group = &runtime->hs_groups[ctx];
        if (group->db == NULL) {
            return 0;
        }

        seen = (uint8_t *)calloc(runtime->compiled_count, 1);
        if (seen == NULL) {
            set_err(errbuf, errbuf_size, "hs seen alloc failed");
            return -1;
        }

        memset(&scan_ctx, 0, sizeof(scan_ctx));
        scan_ctx.runtime = runtime;
        scan_ctx.matches = matches;
        scan_ctx.ctx = ctx;
        scan_ctx.seen = seen;

        t0 = mono_us_now();
        rc_hs = hs_scan(group->db,
            (const char *)data,
            (unsigned int)len,
            0,
            runtime->hs_scratch,
            hs_on_match,
            &scan_ctx);
        elapsed_us = (uint64_t)(mono_us_now() - t0);
        free(seen);

        if (elapsed_us_sum != NULL) {
            *elapsed_us_sum += elapsed_us;
        }
        if (rc_hs != HS_SUCCESS && rc_hs != HS_SCAN_TERMINATED) {
            set_err(errbuf, errbuf_size, "hs_scan error");
            return -1;
        }
        if (!scan_ctx.matched_any) {
            return 0;
        }
        for (i = 0; i < matches->count; i++) {
            if (matches->items[i].elapsed_us == 0 && matches->items[i].context == ctx) {
                matches->items[i].elapsed_us = elapsed_us;
            }
        }
        return 1;
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
            rc = engine_match_one(runtime, &runtime->compiled_rules[i], data, len, &match_off, &match_len, NULL, errbuf, errbuf_size);
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

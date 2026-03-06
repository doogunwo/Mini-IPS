/**
 * @file detect.c
 * @brief 탐지 엔진 구현
 */
#include "detect.h"

#include <pcre.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
typedef struct policy_pattern_set
{
    const IPS_Signature **rules;
    const char **patterns;
    unsigned int count;
} policy_pattern_set_t;

typedef struct pcre_ctx
{
    pcre **compiled;
    pcre_extra **extra;
    unsigned int count;
    int jit_enabled;
    pcre_jit_stack *jit_stack;
} pcre_ctx_t;

struct detect_engine
{
    pcre_ctx_t pcre;
    const IPS_Signature **rules;
    unsigned int rule_count;
    char last_err[128];
};
static void set_err(detect_engine_t *e, const char *msg)
{
    if (!e)
        return;
    if (!msg)
        msg = "unknown error";
    snprintf(e->last_err, sizeof(e->last_err), "%s", msg);
}

const char *detect_engine_last_error(const detect_engine_t *e)
{
    if (!e)
        return "null engine";
    if (e->last_err[0] == '\0')
        return "ok";
    return e->last_err;
}

static int collect_policy_patterns(const char *policy_name, policy_pattern_set_t *out)
{
    int i;
    unsigned int n = 0;

    memset(out, 0, sizeof(*out));
    for (i = 0; i < g_signature_count; i++) {
        if (strcmp(g_ips_signatures[i].policy_name, policy_name) == 0) n++;
    }
    if (n == 0) return -1;

    out->rules = (const IPS_Signature **)calloc(n, sizeof(*out->rules));
    out->patterns = (const char **)calloc(n, sizeof(*out->patterns));
    if (!out->rules || !out->patterns) {
        free(out->rules);
        free(out->patterns);
        memset(out, 0, sizeof(*out));
        return -1;
    }
    out->count = n;

    n = 0;
    for (i = 0; i < g_signature_count; i++) {
        if (strcmp(g_ips_signatures[i].policy_name, policy_name) == 0) {
            out->rules[n] = &g_ips_signatures[i];
            out->patterns[n] = g_ips_signatures[i].pattern;
            n++;
        }
    }
    return 0;
}

static int collect_all_patterns(policy_pattern_set_t *out)
{
    unsigned int n = (unsigned int)g_signature_count;
    unsigned int i;

    memset(out, 0, sizeof(*out));
    if (n == 0)
        return -1;

    out->rules = (const IPS_Signature **)calloc(n, sizeof(*out->rules));
    out->patterns = (const char **)calloc(n, sizeof(*out->patterns));
    if (!out->rules || !out->patterns)
    {
        free(out->rules);
        free(out->patterns);
        memset(out, 0, sizeof(*out));
        return -1;
    }
    out->count = n;

    for (i = 0; i < n; i++)
    {
        out->rules[i] = &g_ips_signatures[i];
        out->patterns[i] = g_ips_signatures[i].pattern;
    }
    return 0;
}

static void free_policy_patterns(policy_pattern_set_t *set)
{
    free(set->rules);
    free(set->patterns);
    memset(set, 0, sizeof(*set));
}

static void pcre_release(pcre_ctx_t *ctx)
{
    if(ctx->jit_stack)
    {
        pcre_jit_stack_free(ctx->jit_stack);
        ctx->jit_stack = NULL;
    }
    if(ctx->extra)
    {
        for(unsigned int i=0; i<ctx->count; i++)
        {
            if(ctx->extra[i]) pcre_free_study(ctx->extra[i]);
        }
        free(ctx->extra);
        ctx->extra = NULL;
    }
    if(ctx->compiled)
    {
        for(unsigned int i=0; i<ctx->count; i++)
        {
            if(ctx->compiled[i]) pcre_free(ctx->compiled[i]);
        }
        free(ctx->compiled);
        ctx->compiled = NULL;
    }
    memset(ctx, 0, sizeof(*ctx));
}

static int pcre_prepare(pcre_ctx_t *ctx, const policy_pattern_set_t *set, detect_jit_mode_t jit_mode)
{
    unsigned int i;
    const char *err = NULL;
    const char *study_err = NULL;
    int erroffset = 0;
    int jit_cfg = 0;
    int rc_cfg = pcre_config(PCRE_CONFIG_JIT, &jit_cfg);
    int jit_runtime_available = (rc_cfg == 0 && jit_cfg == 1) ? 1 : 0;

    memset(ctx, 0, sizeof(*ctx));
    ctx->compiled = (pcre **)calloc(set->count, sizeof(*ctx->compiled));
    ctx->extra = (pcre_extra **)calloc(set->count, sizeof(*ctx->extra));
    if (!ctx->compiled || !ctx->extra) {
        pcre_release(ctx);
        return -1;
    }
    ctx->count = set->count;
    if (jit_mode == DETECT_JIT_OFF) {
        ctx->jit_enabled = 0;
    } else if (jit_mode == DETECT_JIT_ON) {
        if (!jit_runtime_available) {
            fprintf(stderr, "requested -jit=on but PCRE JIT is unavailable\n");
            pcre_release(ctx);
            return -1;
        }
        ctx->jit_enabled = 1;
    } else {
        ctx->jit_enabled = jit_runtime_available;
    }

    for (i = 0; i < ctx->count; i++) {
        int jit_info = 0;
        ctx->compiled[i] = pcre_compile(set->patterns[i], PCRE_CASELESS, &err, &erroffset, NULL);
        if (!ctx->compiled[i]) {
            fprintf(stderr, "pcre_compile failed: idx=%u offset=%d err=%s\n", i, erroffset, err ? err : "unknown");
            pcre_release(ctx);
            return -1;
        }
        if (ctx->jit_enabled) {
            ctx->extra[i] = pcre_study(ctx->compiled[i], PCRE_STUDY_JIT_COMPILE, &study_err);
            if (study_err) {
                if (jit_mode == DETECT_JIT_ON) {
                    fprintf(stderr, "pcre_study(JIT) failed: idx=%u err=%s\n", i, study_err);
                    pcre_release(ctx);
                    return -1;
                }
                ctx->jit_enabled = 0;
            }
            if (ctx->jit_enabled &&
                (!ctx->extra[i] || pcre_fullinfo(ctx->compiled[i], ctx->extra[i], PCRE_INFO_JIT, &jit_info) != 0 || jit_info != 1)) {
                if (jit_mode == DETECT_JIT_ON) {
                    fprintf(stderr, "pcre JIT compile unavailable for pattern idx=%u\n", i);
                    pcre_release(ctx);
                    return -1;
                }
                ctx->jit_enabled = 0;
            }
        }
    }
    if (ctx->jit_enabled) {
        ctx->jit_stack = pcre_jit_stack_alloc(32 * 1024, 512 * 1024);
        if (!ctx->jit_stack) {
            if (jit_mode == DETECT_JIT_ON) {
                fprintf(stderr, "pcre_jit_stack_alloc failed\n");
                pcre_release(ctx);
                return -1;
            }
            ctx->jit_enabled = 0;
        } else {
            for (i = 0; i < ctx->count; i++) {
                if (ctx->extra[i]) {
                    pcre_assign_jit_stack(ctx->extra[i], NULL, ctx->jit_stack);
                }
            }
        }
    }
    return 0;
}

detect_engine_t *detect_engine_create(const char *policy_name, detect_jit_mode_t jit_mode)
{
    detect_engine_t *e;
    policy_pattern_set_t set;

    e = (detect_engine_t *)calloc(1, sizeof(*e));
    if (!e) return NULL;
    e->last_err[0] = '\0';

    if (!policy_name || !policy_name[0] ||
        strcmp(policy_name, "ALL") == 0 || strcmp(policy_name, "all") == 0 || strcmp(policy_name, "*") == 0)
    {
        if (collect_all_patterns(&set) != 0)
        {
            set_err(e, "no patterns");
            detect_engine_destroy(e);
            return NULL;
        }
    }
    else
    {
        if (collect_policy_patterns(policy_name, &set) != 0)
        {
            set_err(e, "unknown policy");
            detect_engine_destroy(e);
            return NULL;
        }
    }

    if (pcre_prepare(&e->pcre, &set, jit_mode) != 0) {
        set_err(e, "pcre prepare failed");
        free_policy_patterns(&set);
        detect_engine_destroy(e);
        return NULL;
    }

    e->rules = set.rules;
    e->rule_count = set.count;
    free(set.patterns);
    return e;
}

void detect_engine_destroy(detect_engine_t *e)
{
    if (!e) return;
    pcre_release(&e->pcre);
    free(e->rules);
    free(e);
}

static int detect_engine_match_internal(
    detect_engine_t *e,
    const uint8_t *data,
    size_t len,
    ips_context_t ctx,
    const IPS_Signature **matched_rule
)
{
    int ovector[30];
    unsigned int i;

    if (matched_rule) *matched_rule = NULL;
    if (!e || !data || len == 0) return 0;
    if (len > (size_t)INT_MAX) {
        set_err(e, "payload too large");
        return -1;
    }

    for (i = 0; i < e->pcre.count; i++) {
        if (i < e->rule_count && e->rules[i]) {
            ips_context_t rule_ctx = e->rules[i]->context;
            if (ctx != IPS_CTX_ALL && rule_ctx != IPS_CTX_ALL && rule_ctx != ctx)
                continue;
        }
        int rc = pcre_exec(
            e->pcre.compiled[i],
            e->pcre.extra ? e->pcre.extra[i] : NULL,
            (const char *)data,
            (int)len,
            0,
            0,
            ovector,
            (int)(sizeof(ovector) / sizeof(ovector[0]))
        );
        if (rc >= 0) {
            if (matched_rule && i < e->rule_count) *matched_rule = e->rules[i];
            return 1;
        }
        if (rc != PCRE_ERROR_NOMATCH) {
            set_err(e, "pcre_exec error");
            return -1;
        }
    }
    return 0;
}

int detect_engine_match_ctx(
    detect_engine_t *e,
    const uint8_t *data,
    size_t len,
    ips_context_t ctx,
    const IPS_Signature **matched_rule
)
{
    switch (ctx) {
        case IPS_CTX_REQUEST_URI:
        case IPS_CTX_ARGS:
        case IPS_CTX_ARGS_NAMES:
        case IPS_CTX_REQUEST_HEADERS:
        case IPS_CTX_REQUEST_BODY:
        case IPS_CTX_ALL:
            break;
        default:
            if (matched_rule) *matched_rule = NULL;
            if (e) set_err(e, "invalid context");
            return -1;
    }
    return detect_engine_match_internal(e, data, len, ctx, matched_rule);
}

int detect_engine_match(
    detect_engine_t *e,
    const uint8_t *data,
    size_t len,
    const IPS_Signature **matched_rule
)
{
    return detect_engine_match_internal(e, data, len, IPS_CTX_ALL, matched_rule);
}

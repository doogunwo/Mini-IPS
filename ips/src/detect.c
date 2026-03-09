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

typedef struct policy_pattern_set
{
    const IPS_Signature **rules;
    unsigned int count;
} policy_pattern_set_t;

struct detect_engine
{
    engine_runtime_t *runtime;
    const IPS_Signature **rules;
    unsigned int rule_count;
    char last_err[128];
};

static void set_err(detect_engine_t *e, const char *msg);

static int collect_matches_ctx_timed(
    detect_engine_t *e,
    const uint8_t *data,
    size_t len,
    ips_context_t ctx,
    detect_match_list_t *matches,
    uint64_t *elapsed_us_sum)
{
    if (elapsed_us_sum != NULL) {
        *elapsed_us_sum = 0;
    }
    if (!matches)
    {
        if (e)
            set_err(e, "null matches");
        return -1;
    }
    if (!e || !data || len == 0)
        return 0;
    if (len > (size_t)INT_MAX)
    {
        set_err(e, "payload too large");
        return -1;
    }

    switch (ctx)
    {
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

    return engine_runtime_collect_matches_timed(
        e->runtime,
        data,
        len,
        ctx,
        matches,
        elapsed_us_sum,
        e->last_err,
        sizeof(e->last_err));
}

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

void detect_match_list_init(detect_match_list_t *matches)
{
    if (!matches)
        return;
    memset(matches, 0, sizeof(*matches));
}

void detect_match_list_free(detect_match_list_t *matches)
{
    size_t i;

    if (!matches)
        return;
    for (i = 0; i < matches->count; i++)
        free(matches->items[i].matched_text);
    free(matches->items);
    memset(matches, 0, sizeof(*matches));
}

static int collect_policy_patterns(const char *policy_name, policy_pattern_set_t *out)
{
    int i;
    unsigned int n = 0;

    memset(out, 0, sizeof(*out));
    for (i = 0; i < g_signature_count; i++)
    {
        if (strcmp(g_ips_signatures[i].policy_name, policy_name) == 0)
            n++;
    }
    if (n == 0)
        return -1;

    out->rules = (const IPS_Signature **)calloc(n, sizeof(*out->rules));
    if (!out->rules)
    {
        memset(out, 0, sizeof(*out));
        return -1;
    }
    out->count = n;

    n = 0;
    for (i = 0; i < g_signature_count; i++)
    {
        if (strcmp(g_ips_signatures[i].policy_name, policy_name) == 0)
            out->rules[n++] = &g_ips_signatures[i];
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
    if (!out->rules)
    {
        memset(out, 0, sizeof(*out));
        return -1;
    }
    out->count = n;

    for (i = 0; i < n; i++)
        out->rules[i] = &g_ips_signatures[i];
    return 0;
}

static void free_policy_patterns(policy_pattern_set_t *set)
{
    free(set->rules);
    memset(set, 0, sizeof(*set));
}

detect_engine_t *detect_engine_create(const char *policy_name, detect_jit_mode_t jit_mode)
{
    detect_engine_t *e;
    policy_pattern_set_t set;

    if (regex_load_signatures(NULL) != 0)
        return NULL;

    e = (detect_engine_t *)calloc(1, sizeof(*e));
    if (!e)
        return NULL;
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

    e->runtime = engine_runtime_create(set.rules, set.count, jit_mode, e->last_err, sizeof(e->last_err));
    if (!e->runtime)
    {
        free_policy_patterns(&set);
        detect_engine_destroy(e);
        return NULL;
    }

    e->rules = set.rules;
    e->rule_count = set.count;
    return e;
}

void detect_engine_destroy(detect_engine_t *e)
{
    if (!e)
        return;
    engine_runtime_destroy(e->runtime);
    free(e->rules);
    free(e);
}

int detect_engine_match_ctx(
    detect_engine_t *e,
    const uint8_t *data,
    size_t len,
    ips_context_t ctx,
    const IPS_Signature **matched_rule
)
{
    switch (ctx)
    {
        case IPS_CTX_REQUEST_URI:
        case IPS_CTX_ARGS:
        case IPS_CTX_ARGS_NAMES:
        case IPS_CTX_REQUEST_HEADERS:
        case IPS_CTX_REQUEST_BODY:
        case IPS_CTX_RESPONSE_BODY:
        case IPS_CTX_ALL:
            break;
        default:
            if (matched_rule)
                *matched_rule = NULL;
            if (e)
                set_err(e, "invalid context");
            return -1;
    }

    if (!e)
        return 0;

    return engine_runtime_match_first(e->runtime, data, len, ctx, matched_rule, e->last_err, sizeof(e->last_err));
}

int detect_engine_collect_matches_ctx(
    detect_engine_t *e,
    const uint8_t *data,
    size_t len,
    ips_context_t ctx,
    detect_match_list_t *matches
)
{
    return collect_matches_ctx_timed(e, data, len, ctx, matches, NULL);
}

int detect_engine_collect_matches_ctx_timed(
    detect_engine_t *e,
    const uint8_t *data,
    size_t len,
    ips_context_t ctx,
    detect_match_list_t *matches,
    uint64_t *elapsed_us_sum)
{
    return collect_matches_ctx_timed(e, data, len, ctx, matches, elapsed_us_sum);
}

int detect_engine_match(
    detect_engine_t *e,
    const uint8_t *data,
    size_t len,
    const IPS_Signature **matched_rule
)
{
    return detect_engine_match_ctx(e, data, len, IPS_CTX_ALL, matched_rule);
}

const char *detect_engine_backend_name(const detect_engine_t *e)
{
    if (!e) return "-";
    return engine_runtime_backend_name(e->runtime);
}

int detect_engine_jit_enabled(const detect_engine_t *e)
{
    if (!e) return 0;
    return engine_runtime_jit_enabled(e->runtime);
}

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <hs/hs.h>
#include <hs/hs_runtime.h>
#include <hs/hs_common.h>
#include <hs/hs_compile.h>

#include "engine.h"
#include "http_parser.h"
#include "regex.h"

typedef struct detect_runtime {
    const regex_table_t *table;
    hs_database_t *db;
    hs_scratch_t *scratch;
    int compile_errors;
} detect_runtime_t;

typedef struct hs_scan_ctx {
    const detect_runtime_t *runtime;
    const uint8_t          *subject;
    size_t                  subject_len;
    int                     context;
    size_t                 *out_matches;
    int                    *out_score;
    detect_match_info_t    *out_first_match;
    uint8_t                *seen;
} hs_scan_ctx_t;

static void set_last_error(detect_engine_t *engine, const char *msg,
                           const char *pattern) {
    if (NULL == engine) {
        return;
    }

    if (NULL == msg && NULL == pattern) {
        engine->last_err[0] = '\0';
        return;
    }

    if (NULL == pattern) {
        (void)snprintf(engine->last_err, sizeof(engine->last_err), "%s", msg);
        return;
    }

    (void)snprintf(engine->last_err, sizeof(engine->last_err), "%s: %s", msg,
                   pattern);
}

static int select_subject(const regex_signature_t *sig, const http_message_t *msg,
                          const uint8_t **out_subject,
                          size_t *out_subject_len) {
    if (NULL == sig || NULL == msg || NULL == out_subject ||
        NULL == out_subject_len) {
        return -1;
    }

    *out_subject = NULL;
    *out_subject_len = 0U;

    if (1 == sig->context) {
        if (NULL == msg->uri) {
            return 0;
        }
        *out_subject = (const uint8_t *)msg->uri;
        *out_subject_len = strlen(msg->uri);
        return 0;
    }

    if (2 == sig->context) {
        if (NULL == msg->headers) {
            return 0;
        }
        *out_subject = (const uint8_t *)msg->headers;
        *out_subject_len = strlen(msg->headers);
        return 0;
    }

    if (3 == sig->context) {
        if (1 != msg->type || NULL == msg->body) {
            return 0;
        }
        *out_subject = msg->body;
        *out_subject_len = msg->body_len;
        return 0;
    }

    if (4 == sig->context) {
        if (0 != msg->type || NULL == msg->body) {
            return 0;
        }
        *out_subject = msg->body;
        *out_subject_len = msg->body_len;
        return 0;
    }

    return 0;
}

static void detect_match_info_reset(detect_match_info_t *info) {
    if (NULL == info) {
        return;
    }

    memset(info, 0, sizeof(*info));
}

static void detect_copy_printable_snippet(char *dst, size_t dst_sz,
                                          const uint8_t *src, size_t len) {
    size_t i;
    size_t copy_len;

    if (NULL == dst || 0U == dst_sz) {
        return;
    }

    dst[0] = '\0';
    if (NULL == src || 0U == len) {
        return;
    }

    copy_len = len;
    if (copy_len >= dst_sz) {
        copy_len = dst_sz - 1U;
    }

    for (i = 0; i < copy_len; i++) {
        unsigned char ch;

        ch = src[i];
        if ('\r' == ch || '\n' == ch || '\t' == ch) {
            dst[i] = ' ';
        } else if (0 == isprint(ch)) {
            dst[i] = '.';
        } else {
            dst[i] = (char)ch;
        }
    }
    dst[copy_len] = '\0';
}

static int hs_on_match(unsigned int id,
                       unsigned long long from,
                       unsigned long long to,
                       unsigned int flags,
                       void *ctx) {
    hs_scan_ctx_t          *scan_ctx;
    const regex_signature_t *sig;
    size_t                  match_off;
    size_t                  match_end;

    (void)flags;

    if (NULL == ctx) {
        return 1;
    }

    scan_ctx = (hs_scan_ctx_t *)ctx;
    if (NULL == scan_ctx->runtime || NULL == scan_ctx->runtime->table) {
        return 1;
    }

    if ((size_t)id >= scan_ctx->runtime->table->count) {
        return 1;
    }

    sig = &scan_ctx->runtime->table->items[id];
    if (sig->context != scan_ctx->context) {
        return 0;
    }

    if (NULL != scan_ctx->seen && 0 != scan_ctx->seen[id]) {
        return 0;
    }

    if (NULL != scan_ctx->seen) {
        scan_ctx->seen[id] = 1U;
    }

    if (NULL != scan_ctx->out_matches) {
        (*scan_ctx->out_matches)++;
    }
    if (NULL != scan_ctx->out_score) {
        *scan_ctx->out_score += sig->priority;
    }

    if (NULL != scan_ctx->out_first_match &&
        0 == scan_ctx->out_first_match->matched) {
        scan_ctx->out_first_match->matched = 1;
        scan_ctx->out_first_match->context = sig->context;
        (void)snprintf(scan_ctx->out_first_match->pattern,
                       sizeof(scan_ctx->out_first_match->pattern), "%s",
                       NULL != sig->pattern ? sig->pattern : "(null)");

        match_off = (size_t)from;
        match_end = (size_t)to;
        if (match_end >= match_off && match_end <= scan_ctx->subject_len) {
            detect_copy_printable_snippet(scan_ctx->out_first_match->text,
                                          sizeof(scan_ctx->out_first_match->text),
                                          scan_ctx->subject + match_off,
                                          match_end - match_off);
        }
    }

    return 0;
}

static void detect_runtime_report_compile_failure(detect_engine_t *engine,
                                                  const regex_table_t *table,
                                                  const char *label,
                                                  const char *fallback_msg) {
    hs_compile_error_t *compile_err;
    hs_database_t      *tmp_db;
    hs_error_t          rc;
    size_t              i;

    if (NULL == engine || NULL == table) {
        return;
    }

    for (i = 0; i < table->count; i++) {
        const char *pattern;

        pattern = table->items[i].pattern;
        if (NULL == pattern) {
            continue;
        }

        compile_err = NULL;
        tmp_db = NULL;
        rc = hs_compile(pattern, 0U, HS_MODE_BLOCK, NULL, &tmp_db,
                        &compile_err);
        if (HS_SUCCESS == rc) {
            if (NULL != tmp_db) {
                hs_free_database(tmp_db);
            }
            if (NULL != compile_err) {
                hs_free_compile_error(compile_err);
            }
            continue;
        }

        if (NULL != compile_err && NULL != compile_err->message) {
            set_last_error(engine, compile_err->message, pattern);
        } else {
            set_last_error(engine, fallback_msg, pattern);
        }

        if (NULL != tmp_db) {
            hs_free_database(tmp_db);
        }
        if (NULL != compile_err) {
            hs_free_compile_error(compile_err);
        }
        return;
    }

    set_last_error(engine, fallback_msg, label);
}

static void *detect_runtime_compile(detect_engine_t *engine,
    const regex_table_t *table,
    const char *label) {
    detect_runtime_t *runtime;
    const char **patterns;
    unsigned int *ids;
    unsigned int *flags;
    hs_compile_error_t *compile_err;
    hs_error_t rc;
    size_t i;
    size_t valid_count;

    if (NULL == table) {
        return NULL;
    }

    runtime = (detect_runtime_t *)malloc(sizeof(*runtime));
    if (NULL == runtime) {
        return NULL;
    }

    memset(runtime, 0, sizeof(*runtime));
    runtime->table = table;

    if (0U == table->count) {
        return runtime;
    }

    patterns = (const char **)malloc(table->count * sizeof(*patterns));
    ids = (unsigned int *)malloc(table->count * sizeof(*ids));
    flags = (unsigned int *)malloc(table->count * sizeof(*flags));
    if (NULL == patterns || NULL == ids || NULL == flags) {
        free(patterns);
        free(ids);
        free(flags);
        free(runtime);
        return NULL;
    }

    valid_count = 0U;
    for (i = 0; i < table->count; i++) {
        if (NULL == table->items[i].pattern) {
            runtime->compile_errors++;
            continue;
        }

        patterns[valid_count] = table->items[i].pattern;
        ids[valid_count] = (unsigned int)i;
        flags[valid_count] = 0U;
        valid_count++;
    }

    if (0U == valid_count) {
        free(patterns);
        free(ids);
        free(flags);
        return runtime;
    }

    compile_err = NULL;
    rc = hs_compile_multi((const char * const *)patterns,
                          flags,
                          ids,
                          (unsigned int)valid_count,
                          HS_MODE_BLOCK,
                          NULL,
                          &runtime->db,
                          &compile_err);

    free(patterns);
    free(ids);
    free(flags);

    if (HS_SUCCESS != rc) {
        runtime->compile_errors++;

        if (NULL != engine) {
            detect_runtime_report_compile_failure(engine, table, label,
                                                  "hs_compile_multi failed");
        }

        if (NULL != compile_err) {
            hs_free_compile_error(compile_err);
        }

        free(runtime);
        return NULL;
    }

    if (NULL != compile_err) {
        hs_free_compile_error(compile_err);
    }

    rc = hs_alloc_scratch(runtime->db, &runtime->scratch);
    if (HS_SUCCESS != rc) {
        if (NULL != engine) {
            set_last_error(engine, "hs_alloc_scratch failed", label);
        }

        hs_free_database(runtime->db);
        free(runtime);
        return NULL;
    }

    return runtime;
}                                      

detect_engine_t *engine_regex_create(const regex_db_t *db) {
    detect_engine_t *engine;

    if (NULL == db) {
        return NULL;
    }

    engine = (detect_engine_t *)malloc(sizeof(*engine));
    if (NULL == engine) {
        return NULL;
    }

    memset(engine, 0, sizeof(*engine));
    engine->db = db;

    engine->sqli_runtime = detect_runtime_compile(engine, &db->sqli, "sqli");
    if (NULL == engine->sqli_runtime) {
        if ('\0' != engine->last_err[0]) {
            fprintf(stderr, "[ENGINE_HS] %s\n", engine->last_err);
        }
        engine_regex_destroy(engine);
        return NULL;
    }
    engine->compile_errors +=
        ((detect_runtime_t *)engine->sqli_runtime)->compile_errors;

    engine->xss_runtime = detect_runtime_compile(engine, &db->xss, "xss");
    if (NULL == engine->xss_runtime) {
        if ('\0' != engine->last_err[0]) {
            fprintf(stderr, "[ENGINE_HS] %s\n", engine->last_err);
        }
        engine_regex_destroy(engine);
        return NULL;
    }
    engine->compile_errors +=
        ((detect_runtime_t *)engine->xss_runtime)->compile_errors;

    engine->rce_runtime = detect_runtime_compile(engine, &db->rce, "rce");
    if (NULL == engine->rce_runtime) {
        if ('\0' != engine->last_err[0]) {
            fprintf(stderr, "[ENGINE_HS] %s\n", engine->last_err);
        }
        engine_regex_destroy(engine);
        return NULL;
    }
    engine->compile_errors +=
        ((detect_runtime_t *)engine->rce_runtime)->compile_errors;

    engine->dir_traversal_runtime =
        detect_runtime_compile(engine, &db->directory_traversal,
                               "directory_traversal");
    if (NULL == engine->dir_traversal_runtime) {
        if ('\0' != engine->last_err[0]) {
            fprintf(stderr, "[ENGINE_HS] %s\n", engine->last_err);
        }
        engine_regex_destroy(engine);
        return NULL;
    }
    engine->compile_errors +=
        ((detect_runtime_t *)engine->dir_traversal_runtime)->compile_errors;

    return engine;
}

static void detect_runtime_destroy(void *runtime_ptr) {
    detect_runtime_t *runtime;
    if (NULL == runtime_ptr) {
        return;
    }

    runtime = (detect_runtime_t *)runtime_ptr;
    
    if (NULL != runtime->scratch) hs_free_scratch(runtime->scratch);
    if (NULL != runtime->db) hs_free_database(runtime->db);

    free(runtime);
}

int engine_match_runtime(const void          *runtime_ptr,
                         const http_message_t *msg,
                         size_t              *out_matches,
                         int                 *out_score,
                         int                 *out_errors,
                         detect_match_info_t *out_first_match) {
    const detect_runtime_t *runtime;
    hs_scan_ctx_t           scan_ctx;
    const uint8_t          *subject;
    size_t                  subject_len;
    uint8_t                *seen;
    hs_error_t              rc;
    size_t                  matches;
    int                     score;
    int                     errors;
    int                     context;
    regex_signature_t       sig;

    if (NULL == msg || NULL == out_matches || NULL == out_score ||
        NULL == out_errors) {
        return -1;
    }

    *out_matches = 0U;
    *out_score = 0;
    *out_errors = 0;
    detect_match_info_reset(out_first_match);

    if (NULL == runtime_ptr) {
        *out_errors = 1;
        return 0;
    }

    runtime = (const detect_runtime_t *)runtime_ptr;
    if (NULL == runtime->table) {
        *out_errors = runtime->compile_errors;
        return 0;
    }

    seen = (uint8_t *)calloc(runtime->table->count, sizeof(*seen));
    if (NULL == seen) {
        *out_errors = runtime->compile_errors + 1;
        return -1;
    }

    matches = 0U;
    score = 0;
    errors = runtime->compile_errors;

    memset(&scan_ctx, 0, sizeof(scan_ctx));
    scan_ctx.runtime = runtime;
    scan_ctx.out_matches = &matches;
    scan_ctx.out_score = &score;
    scan_ctx.out_first_match = out_first_match;
    scan_ctx.seen = seen;

    memset(&sig, 0, sizeof(sig));
    for (context = 1; context <= 4; context++) {
        sig.context = context;
        subject = NULL;
        subject_len = 0U;

        if (0 != select_subject(&sig, msg, &subject, &subject_len)) {
            errors++;
            continue;
        }
        if (NULL == subject || 0U == subject_len) {
            continue;
        }

        scan_ctx.subject = subject;
        scan_ctx.subject_len = subject_len;
        scan_ctx.context = context;

        rc = hs_scan(runtime->db,
                     (const char *)subject,
                     (unsigned int)subject_len,
                     0,
                     runtime->scratch,
                     hs_on_match,
                     &scan_ctx);
        if (HS_SUCCESS != rc && HS_SCAN_TERMINATED != rc) {
            errors++;
        }
    }

    free(seen);

    *out_matches = matches;
    *out_score = score;
    *out_errors = errors;
    return 0;
}

void engine_regex_destroy(detect_engine_t *engine) {
    if (NULL == engine) {
        return;
    }

    detect_runtime_destroy(engine->sqli_runtime);
    detect_runtime_destroy(engine->xss_runtime);
    detect_runtime_destroy(engine->rce_runtime);
    detect_runtime_destroy(engine->dir_traversal_runtime);

    free(engine);
}

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define PCRE2_CODE_UNIT_WIDTH 8

#include <pcre2.h>

#include "engine.h"
#include "http_parser.h"
#include "regex.h"

typedef struct detect_runtime_entry {
    const regex_signature_t *sig;
    pcre2_code              *code;
} detect_runtime_entry_t;

typedef struct detect_runtime {
    detect_runtime_entry_t *entries;
    size_t                  count;
    int                     compile_errors;
} detect_runtime_t;

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

static void detect_runtime_destroy(void *runtime_ptr) {
    detect_runtime_t *runtime;
    size_t            i;

    if (NULL == runtime_ptr) {
        return;
    }

    runtime = (detect_runtime_t *)runtime_ptr;

    if (NULL != runtime->entries) {
        for (i = 0; i < runtime->count; i++) {
            if (NULL != runtime->entries[i].code) {
                pcre2_code_free(runtime->entries[i].code);
            }
        }
        free(runtime->entries);
    }
    free(runtime);
}

static void *detect_runtime_compile(detect_engine_t *engine,
                                    const regex_table_t *table,
                                    const char          *label) {
    detect_runtime_t *runtime;
    size_t            i;

    if (NULL == table) {
        return NULL;
    }

    runtime = (detect_runtime_t *)malloc(sizeof(*runtime));
    if (NULL == runtime) {
        return NULL;
    }

    memset(runtime, 0, sizeof(*runtime));
    if (0U == table->count) {
        return runtime;
    }

    runtime->entries =
        (detect_runtime_entry_t *)malloc(table->count * sizeof(*runtime->entries));
    if (NULL == runtime->entries) {
        free(runtime);
        return NULL;
    }
    memset(runtime->entries, 0, table->count * sizeof(*runtime->entries));
    runtime->count = table->count;

    for (i = 0; i < table->count; i++) {
        int         errcode;
        PCRE2_SIZE  erroffset;
        PCRE2_UCHAR errbuf[256];
        const char *pattern;

        pattern = table->items[i].pattern;
        runtime->entries[i].sig = &table->items[i];
        if (NULL == pattern) {
            runtime->compile_errors++;
            continue;
        }

        runtime->entries[i].code =
            pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED, 0,
                          &errcode, &erroffset, NULL);
        if (NULL == runtime->entries[i].code) {
            runtime->compile_errors++;
            if (NULL != engine) {
                if (0 <= pcre2_get_error_message(errcode, errbuf,
                                                 sizeof(errbuf))) {
                    set_last_error(engine, (const char *)errbuf, pattern);
                } else {
                    set_last_error(engine, label, pattern);
                }
            }
        }
    }

    return runtime;
}

static int select_subject(const regex_signature_t *sig, const http_message_t *msg,
                          PCRE2_SPTR *out_subject,
                          PCRE2_SIZE *out_subject_len) {
    if (NULL == sig || NULL == msg || NULL == out_subject ||
        NULL == out_subject_len) {
        return -1;
    }

    *out_subject = NULL;
    *out_subject_len = 0;

    if (1 == sig->context) {
        if (NULL == msg->uri) {
            return 0;
        }
        *out_subject = (PCRE2_SPTR)msg->uri;
        *out_subject_len = (PCRE2_SIZE)strlen(msg->uri);
        return 0;
    }

    if (2 == sig->context) {
        if (NULL == msg->headers) {
            return 0;
        }
        *out_subject = (PCRE2_SPTR)msg->headers;
        *out_subject_len = (PCRE2_SIZE)strlen(msg->headers);
        return 0;
    }

    if (3 == sig->context) {
        if (1 != msg->type || NULL == msg->body) {
            return 0;
        }
        *out_subject = (PCRE2_SPTR)msg->body;
        *out_subject_len = (PCRE2_SIZE)msg->body_len;
        return 0;
    }

    if (4 == sig->context) {
        if (0 != msg->type || NULL == msg->body) {
            return 0;
        }
        *out_subject = (PCRE2_SPTR)msg->body;
        *out_subject_len = (PCRE2_SIZE)msg->body_len;
        return 0;
    }

    return 0;
}

int engine_match_runtime(const void          *runtime_ptr,
                         const http_message_t *msg,
                         size_t              *out_matches,
                         int                 *out_score,
                         int                 *out_errors) {
    const detect_runtime_t *runtime;
    size_t                  i;
    size_t                  matches;
    int                     score;
    int                     errors;

    if (NULL == msg || NULL == out_matches || NULL == out_score ||
        NULL == out_errors) {
        return -1;
    }

    *out_matches = 0U;
    *out_score = 0;
    *out_errors = 0;

    if (NULL == runtime_ptr) {
        *out_errors = 1;
        return 0;
    }

    runtime = (const detect_runtime_t *)runtime_ptr;

    matches = 0U;
    score = 0;
    errors = runtime->compile_errors;

    for (i = 0; i < runtime->count; i++) {
        const regex_signature_t *sig;
        pcre2_code              *code;
        pcre2_match_data        *match_data;
        PCRE2_SPTR               subject;
        PCRE2_SIZE               subject_len;
        int                      rc;

        sig = runtime->entries[i].sig;
        code = runtime->entries[i].code;
        subject = NULL;
        subject_len = 0;

        if (NULL == sig) {
            errors++;
            continue;
        }
        if (NULL == code) {
            continue;
        }
        if (0 != select_subject(sig, msg, &subject, &subject_len)) {
            errors++;
            continue;
        }
        if (NULL == subject || 0U == subject_len) {
            continue;
        }

        match_data = pcre2_match_data_create_from_pattern(code, NULL);
        if (NULL == match_data) {
            errors++;
            continue;
        }

        rc = pcre2_match(code, subject, subject_len, 0, 0, match_data, NULL);
        pcre2_match_data_free(match_data);

        if (rc >= 0) {
            matches++;
            score += sig->priority;
        } else if (PCRE2_ERROR_NOMATCH != rc) {
            errors++;
        }
    }

    *out_matches = matches;
    *out_score = score;
    *out_errors = errors;
    return 0;
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
        engine_regex_destroy(engine);
        return NULL;
    }

    engine->compile_errors +=
        ((detect_runtime_t *)engine->sqli_runtime)->compile_errors;

    engine->xss_runtime = detect_runtime_compile(engine, &db->xss, "xss");
    if (NULL == engine->xss_runtime) {
        engine_regex_destroy(engine);
        return NULL;
    }
    engine->compile_errors +=
        ((detect_runtime_t *)engine->xss_runtime)->compile_errors;

    engine->rce_runtime = detect_runtime_compile(engine, &db->rce, "rce");
    if (NULL == engine->rce_runtime) {
        engine_regex_destroy(engine);
        return NULL;
    }
    engine->compile_errors +=
        ((detect_runtime_t *)engine->rce_runtime)->compile_errors;

    engine->dir_traversal_runtime =
        detect_runtime_compile(engine, &db->directory_traversal,
                               "directory_traversal");
    if (NULL == engine->dir_traversal_runtime) {
        engine_regex_destroy(engine);
        return NULL;
    }
    engine->compile_errors +=
        ((detect_runtime_t *)engine->dir_traversal_runtime)->compile_errors;

    return engine;
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

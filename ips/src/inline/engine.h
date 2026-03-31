#pragma once

#include <stddef.h>

typedef struct regex_db regex_db_t;
typedef struct http_message http_message_t;

#define DETECT_MATCH_PATTERN_MAX 192
#define DETECT_MATCH_TEXT_MAX    160

typedef struct detect_match_info {
    int  matched;
    int  context;
    char pattern[DETECT_MATCH_PATTERN_MAX];
    char text[DETECT_MATCH_TEXT_MAX];
} detect_match_info_t;

typedef struct detect_engine {
    const regex_db_t *db; 

    void *sqli_runtime;
    void *xss_runtime;
    void *rce_runtime;
    void *dir_traversal_runtime;

    int   compile_errors;
    char  last_err[128];

} detect_engine_t;

detect_engine_t *engine_regex_create(const regex_db_t *db);
void             engine_regex_destroy(detect_engine_t *engine);
int              engine_match_runtime(const void         *runtime,
                                      const http_message_t *msg,
                                      size_t             *out_matches,
                                      int                *out_score,
                                      int                *out_errors,
                                      detect_match_info_t *out_first_match);

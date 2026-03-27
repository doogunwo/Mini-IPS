#pragma once

#include <stddef.h>


typedef struct regex_db regex_db_t;
typedef struct http_message http_message_t;
typedef struct detect_engine detect_engine_t;



typedef struct detect_result {
    int    matched;
    int    matched_sqli;
    int    matched_directory_traversal;
    int    matched_rce;
    int    matched_xss;
    int    sqli_score;
    int    directory_traversal_score;
    int    rce_score;
    int    xss_score;
    int    total_score;
    int    total_errors;
    size_t total_matches;
} detect_result_t;

int detect_run(detect_engine_t *engine, const http_message_t *msg, detect_result_t *out_result);

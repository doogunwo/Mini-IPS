#pragma once

/* JSONL 로더 */

#include <stddef.h>

typedef struct regex_signature {
    char *pattern;
    int priority;
    int context;
} regex_signature_t;

typedef struct regex_table {
    regex_signature_t *items;
    size_t count;
} regex_table_t;

typedef struct regex_db {
    regex_table_t sqli;
    regex_table_t directory_traversal;
    regex_table_t rce;
    regex_table_t xss;
} regex_db_t;

int     regex_signatures_load(regex_db_t *db, const char *jsonl_path);
void    regex_signatures_free(regex_db_t *db);


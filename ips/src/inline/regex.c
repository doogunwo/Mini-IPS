#include "regex.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
} strbuf_t;

static int strbuf_append_char(strbuf_t *sb, char ch) {
    char  *next;
    size_t next_cap;

    if (NULL == sb) {
        return -1;
    }

    if (sb->len + 1U >= sb->cap) {
        next_cap = (0U == sb->cap) ? 64U : (sb->cap * 2U);
        next = (char *)realloc(sb->buf, next_cap);
        if (NULL == next) {
            return -1;
        }
        sb->buf = next;
        sb->cap = next_cap;
    }

    sb->buf[sb->len++] = ch;
    sb->buf[sb->len] = '\0';
    return 0;
}

static void strbuf_free(strbuf_t *sb) {
    if (NULL == sb) {
        return;
    }

    free(sb->buf);
    sb->buf = NULL;
    sb->len = 0;
    sb->cap = 0;
}

static char *xstrdup(const char *s) {
    size_t len;
    char  *copy;

    if (NULL == s) {
        return NULL;
    }

    len = strlen(s);
    copy = (char *)malloc(len + 1U);
    if (NULL == copy) {
        return NULL;
    }

    memcpy(copy, s, len + 1U);
    return copy;
}

static const char *skip_ws(const char *p) {
    while (NULL != p && '\0' != *p && 0 != isspace((unsigned char)*p)) {
        p++;
    }
    return p;
}

static int is_json_value_delim(char ch) {
    if ('\0' == ch || ',' == ch || '}' == ch || ']' == ch) {
        return 1;
    }

    return (0 != isspace((unsigned char)ch));
}

static int parse_json_string_at(const char **cursor, char **out) {
    const char *p;
    strbuf_t    sb;
    int         ret;
    int         is_hex;

    if (NULL == cursor || NULL == out) {
        return -1;
    }

    p = *cursor;
    *out = NULL;
    if (NULL == p || '"' != *p) {
        return -1;
    }
    p++;

    memset(&sb, 0, sizeof(sb));
    while ('\0' != *p) {
        if ('\\' == *p) {
            p++;
            if ('\0' == *p) {
                break;
            }

            switch (*p) {
            case '"':
                ret = strbuf_append_char(&sb, '"');
                if (0 != ret) {
                    goto fail;
                }
                break;
            case '\\':
                ret = strbuf_append_char(&sb, '\\');
                if (0 != ret) {
                    goto fail;
                }
                break;
            case '/':
                ret = strbuf_append_char(&sb, '/');
                if (0 != ret) {
                    goto fail;
                }
                break;
            case 'b':
                ret = strbuf_append_char(&sb, '\b');
                if (0 != ret) {
                    goto fail;
                }
                break;
            case 'f':
                ret = strbuf_append_char(&sb, '\f');
                if (0 != ret) {
                    goto fail;
                }
                break;
            case 'n':
                ret = strbuf_append_char(&sb, '\n');
                if (0 != ret) {
                    goto fail;
                }
                break;
            case 'r':
                ret = strbuf_append_char(&sb, '\r');
                if (0 != ret) {
                    goto fail;
                }
                break;
            case 't':
                ret = strbuf_append_char(&sb, '\t');
                if (0 != ret) {
                    goto fail;
                }
                break;
            case 'u': {
                unsigned int cp;
                unsigned int v;
                int          i;

                cp = 0U;
                for (i = 1; i <= 4; i++) {
                    is_hex = 0;
                    if ('\0' != p[i]) {
                        is_hex = isxdigit((unsigned char)p[i]);
                    }
                    if ('\0' == p[i] || 0 == is_hex) {
                        goto fail;
                    }

                    if ('0' <= p[i] && '9' >= p[i]) {
                        v = (unsigned int)(p[i] - '0');
                    } else if ('a' <= p[i] && 'f' >= p[i]) {
                        v = (unsigned int)(p[i] - 'a' + 10);
                    } else if ('A' <= p[i] && 'F' >= p[i]) {
                        v = (unsigned int)(p[i] - 'A' + 10);
                    } else {
                        goto fail;
                    }

                    cp = (cp << 4) | v;
                }

                if (0xD800U <= cp && 0xDBFFU >= cp) {
                    unsigned int low;

                    if ('\\' != p[5] || 'u' != p[6]) {
                        goto fail;
                    }

                    low = 0U;
                    for (i = 7; i <= 10; i++) {
                        is_hex = 0;
                        if ('\0' != p[i]) {
                            is_hex = isxdigit((unsigned char)p[i]);
                        }
                        if ('\0' == p[i] || 0 == is_hex) {
                            goto fail;
                        }

                        if ('0' <= p[i] && '9' >= p[i]) {
                            v = (unsigned int)(p[i] - '0');
                        } else if ('a' <= p[i] && 'f' >= p[i]) {
                            v = (unsigned int)(p[i] - 'a' + 10);
                        } else if ('A' <= p[i] && 'F' >= p[i]) {
                            v = (unsigned int)(p[i] - 'A' + 10);
                        } else {
                            goto fail;
                        }

                        low = (low << 4) | v;
                    }

                    if (0xDC00U > low || 0xDFFFU < low) {
                        goto fail;
                    }

                    cp = 0x10000U +
                         (((cp - 0xD800U) << 10U) | (low - 0xDC00U));
                    p += 10;
                } else {
                    if (0xDC00U <= cp && 0xDFFFU >= cp) {
                        goto fail;
                    }
                    p += 4;
                }

                if (0x7FU >= cp) {
                    ret = strbuf_append_char(&sb, (char)cp);
                    if (0 != ret) {
                        goto fail;
                    }
                } else if (0x7FFU >= cp) {
                    ret = strbuf_append_char(
                        &sb, (char)(0xC0U | ((cp >> 6U) & 0x1FU)));
                    if (0 != ret) {
                        goto fail;
                    }
                    ret = strbuf_append_char(
                        &sb, (char)(0x80U | (cp & 0x3FU)));
                    if (0 != ret) {
                        goto fail;
                    }
                } else if (0xFFFFU >= cp) {
                    ret = strbuf_append_char(
                        &sb, (char)(0xE0U | ((cp >> 12U) & 0x0FU)));
                    if (0 != ret) {
                        goto fail;
                    }
                    ret = strbuf_append_char(
                        &sb, (char)(0x80U | ((cp >> 6U) & 0x3FU)));
                    if (0 != ret) {
                        goto fail;
                    }
                    ret = strbuf_append_char(
                        &sb, (char)(0x80U | (cp & 0x3FU)));
                    if (0 != ret) {
                        goto fail;
                    }
                } else if (0x10FFFFU >= cp) {
                    ret = strbuf_append_char(
                        &sb, (char)(0xF0U | ((cp >> 18U) & 0x07U)));
                    if (0 != ret) {
                        goto fail;
                    }
                    ret = strbuf_append_char(
                        &sb, (char)(0x80U | ((cp >> 12U) & 0x3FU)));
                    if (0 != ret) {
                        goto fail;
                    }
                    ret = strbuf_append_char(
                        &sb, (char)(0x80U | ((cp >> 6U) & 0x3FU)));
                    if (0 != ret) {
                        goto fail;
                    }
                    ret = strbuf_append_char(
                        &sb, (char)(0x80U | (cp & 0x3FU)));
                    if (0 != ret) {
                        goto fail;
                    }
                } else {
                    goto fail;
                }
            } break;
            default:
                goto fail;
            }

            p++;
            continue;
        }

        if ('"' == *p) {
            *out = (NULL != sb.buf) ? sb.buf : xstrdup("");
            *cursor = p + 1;
            return (NULL != *out) ? 1 : -1;
        }

        ret = strbuf_append_char(&sb, *p);
        if (0 != ret) {
            goto fail;
        }
        p++;
    }

fail:
    strbuf_free(&sb);
    return -1;
}

static int parse_json_int_at(const char **cursor, int *out) {
    const char *p;
    char       *endptr;
    long        value;

    if (NULL == cursor || NULL == out) {
        return -1;
    }

    p = skip_ws(*cursor);
    if (NULL == p) {
        return -1;
    }

    if (0 == strncmp(p, "null", 4) && 0 != is_json_value_delim(p[4])) {
        *cursor = p + 4;
        return 0;
    }

    value = strtol(p, &endptr, 10);
    if (endptr == p || 0 == is_json_value_delim(*endptr)) {
        return -1;
    }

    *out = (int)value;
    *cursor = endptr;
    return 1;
}

static int skip_json_nested(const char **cursor, char open_ch, char close_ch) {
    const char *p;
    int         depth;
    int         in_string;
    int         escaped;

    if (NULL == cursor || NULL == *cursor || open_ch != **cursor) {
        return -1;
    }

    p = *cursor;
    depth = 0;
    in_string = 0;
    escaped = 0;

    while ('\0' != *p) {
        if (0 != in_string) {
            if (0 != escaped) {
                escaped = 0;
            } else if ('\\' == *p) {
                escaped = 1;
            } else if ('"' == *p) {
                in_string = 0;
            }
        } else {
            if ('"' == *p) {
                in_string = 1;
            } else if (open_ch == *p) {
                depth++;
            } else if (close_ch == *p) {
                depth--;
                if (0 == depth) {
                    *cursor = p + 1;
                    return 0;
                }
            }
        }
        p++;
    }

    return -1;
}

static int skip_json_value(const char **cursor) {
    const char *p;
    char       *endptr;
    char       *tmp;

    if (NULL == cursor) {
        return -1;
    }

    p = skip_ws(*cursor);
    if (NULL == p || '\0' == *p) {
        return -1;
    }

    if ('"' == *p) {
        tmp = NULL;
        if (0 > parse_json_string_at(&p, &tmp)) {
            return -1;
        }
        free(tmp);
        *cursor = p;
        return 0;
    }

    if ('[' == *p) {
        if (0 != skip_json_nested(&p, '[', ']')) {
            return -1;
        }
        *cursor = p;
        return 0;
    }

    if ('{' == *p) {
        if (0 != skip_json_nested(&p, '{', '}')) {
            return -1;
        }
        *cursor = p;
        return 0;
    }

    if (0 == strncmp(p, "true", 4) && 0 != is_json_value_delim(p[4])) {
        *cursor = p + 4;
        return 0;
    }
    if (0 == strncmp(p, "false", 5) && 0 != is_json_value_delim(p[5])) {
        *cursor = p + 5;
        return 0;
    }
    if (0 == strncmp(p, "null", 4) && 0 != is_json_value_delim(p[4])) {
        *cursor = p + 4;
        return 0;
    }

    (void)strtod(p, &endptr);
    if (endptr == p || 0 == is_json_value_delim(*endptr)) {
        return -1;
    }

    *cursor = endptr;
    return 0;
}

static int parse_context(const char *name) {
    if (NULL == name) {
        return 0;
    }
    if (0 == strcmp(name, "URI") || 0 == strcmp(name, "REQUEST_URI")) {
        return 1;
    }
    if (0 == strcmp(name, "HEADERS") ||
        0 == strcmp(name, "REQUEST_HEADERS")) {
        return 2;
    }
    if (0 == strcmp(name, "BODY") || 0 == strcmp(name, "REQUEST_BODY")) {
        return 3;
    }
    if (0 == strcmp(name, "RESPONSE_BODY")) {
        return 4;
    }
    return 0;
}

static int parse_jsonl_line(const char *line, regex_signature_t *sig) {
    const char *cursor;
    char       *key;
    char       *pattern;
    char       *ctx;
    int         score;
    int         parse_ret;

    if (NULL == line || NULL == sig) {
        return -1;
    }

    memset(sig, 0, sizeof(*sig));
    key = NULL;
    pattern = NULL;
    ctx = NULL;
    score = 0;

    cursor = skip_ws(line);
    if (NULL == cursor || '{' != *cursor) {
        goto fail;
    }
    cursor++;

    while (1) {
        cursor = skip_ws(cursor);
        if (NULL == cursor || '\0' == *cursor) {
            goto fail;
        }
        if ('}' == *cursor) {
            cursor++;
            break;
        }
        if ('"' != *cursor) {
            goto fail;
        }

        parse_ret = parse_json_string_at(&cursor, &key);
        if (0 > parse_ret) {
            goto fail;
        }

        cursor = skip_ws(cursor);
        if (':' != *cursor) {
            goto fail;
        }
        cursor++;
        cursor = skip_ws(cursor);

        if (0 == strcmp(key, "pat")) {
            free(pattern);
            pattern = NULL;
            parse_ret = parse_json_string_at(&cursor, &pattern);
            if (0 > parse_ret) {
                goto fail;
            }
        } else if (0 == strcmp(key, "ctx")) {
            free(ctx);
            ctx = NULL;
            parse_ret = parse_json_string_at(&cursor, &ctx);
            if (0 > parse_ret) {
                goto fail;
            }
        } else if (0 == strcmp(key, "score") || 0 == strcmp(key, "prio")) {
            parse_ret = parse_json_int_at(&cursor, &score);
            if (0 > parse_ret) {
                goto fail;
            }
        } else {
            if (0 != skip_json_value(&cursor)) {
                goto fail;
            }
        }

        free(key);
        key = NULL;

        cursor = skip_ws(cursor);
        if (',' == *cursor) {
            cursor++;
            continue;
        }
        if ('}' == *cursor) {
            cursor++;
            break;
        }
        goto fail;
    }

    cursor = skip_ws(cursor);
    if ('\0' != *cursor) {
        goto fail;
    }
    if (NULL == pattern || NULL == ctx) {
        goto fail;
    }

    sig->pattern = pattern;
    sig->priority = score;
    sig->context = parse_context(ctx);
    free(ctx);
    return 0;

fail:
    free(key);
    free(pattern);
    free(ctx);
    memset(sig, 0, sizeof(*sig));
    return -1;
}

static int try_load_jsonl_file(regex_table_t *table, const char *path) {
    FILE              *fp;
    char               line[65536];
    regex_signature_t *items;
    size_t             count;
    size_t             capacity;
    int                loaded_any;

    if (NULL == table || NULL == path) {
        return -1;
    }

    fp = fopen(path, "r");
    if (NULL == fp) {
        return -1;
    }

    items      = NULL;
    count      = 0;
    capacity   = 0;
    loaded_any = 0;

    while (NULL != fgets(line, sizeof(line), fp)) {
        regex_signature_t  sig;
        regex_signature_t *next;
        size_t             new_capacity;
        int                ret;

        memset(&sig, 0, sizeof(sig));

        if ('\0' == line[0] || '\n' == line[0]) {
            continue;
        }

        ret = parse_jsonl_line(line, &sig);
        if (0 != ret) {
            continue;
        }

        if (count == capacity) {
            if (0U == capacity) {
                new_capacity = 64U;
            } else {
                new_capacity = capacity * 2U;
            }

            next = (regex_signature_t *)malloc(new_capacity * sizeof(*next));
            if (NULL == next) {
                free(sig.pattern);

                while (0U < count) {
                    count--;
                    free(items[count].pattern);
                }
                free(items);
                fclose(fp);
                return -1;
            }

            if (NULL != items) {
                memcpy(next, items, count * sizeof(*next));
                free(items);
            }

            items    = next;
            capacity = new_capacity;
        }

        items[count] = sig;
        count++;
        loaded_any = 1;
    }

    fclose(fp);

    if (!loaded_any) {
        free(items);
        return -1;
    }

    table->items = items;
    table->count = count;
    return 0;
}

static int try_load_file(regex_db_t *db, const char *ruleset_dir) {
    char path[512];
    int  ret;

    if (NULL == db || NULL == ruleset_dir) {
        return -1;
    }

    ret = snprintf(path, sizeof(path), "%s/sqli.jsonl", ruleset_dir);
    if (ret < 0 || (size_t)ret >= sizeof(path)) {
        return -1;
    }
    if (0 != try_load_jsonl_file(&db->sqli, path)) {
        return -1;
    }

    ret = snprintf(path, sizeof(path), "%s/xss.jsonl", ruleset_dir);
    if (ret < 0 || (size_t)ret >= sizeof(path)) {
        regex_signatures_free(db);
        return -1;
    }
    if (0 != try_load_jsonl_file(&db->xss, path)) {
        regex_signatures_free(db);
        return -1;
    }

    ret = snprintf(path, sizeof(path), "%s/rce.jsonl", ruleset_dir);
    if (ret < 0 || (size_t)ret >= sizeof(path)) {
        regex_signatures_free(db);
        return -1;
    }
    if (0 != try_load_jsonl_file(&db->rce, path)) {
        regex_signatures_free(db);
        return -1;
    }

    ret = snprintf(path, sizeof(path), "%s/directory_traversal.jsonl",
                   ruleset_dir);
    if (ret < 0 || (size_t)ret >= sizeof(path)) {
        regex_signatures_free(db);
        return -1;
    }
    if (0 != try_load_jsonl_file(&db->directory_traversal, path)) {
        regex_signatures_free(db);
        return -1;
    }

    return 0;
}

int regex_signatures_load(regex_db_t *db, const char *jsonl_path) {
    if (NULL == db || NULL == jsonl_path) {
        return -1;
    }

    memset(db, 0, sizeof(*db));
    return try_load_file(db, jsonl_path);
}

void regex_signatures_free(regex_db_t *db) {
    regex_table_t *tables[4];
    size_t         i;
    size_t         j;

    if (NULL == db) {
        return;
    }

    tables[0] = &db->sqli;
    tables[1] = &db->directory_traversal;
    tables[2] = &db->rce;
    tables[3] = &db->xss;

    for (i = 0; i < 4U; i++) {
        for (j = 0; j < tables[i]->count; j++) {
            free(tables[i]->items[j].pattern);
        }
        free(tables[i]->items);
        tables[i]->items = NULL;
        tables[i]->count = 0;
    }
}

/**
 * @file regex.c
 * @brief JSONL 기반 IPS 시그니처 로더
 */
#include "regex.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RULES_FILE_ENV "IPS_RULES_FILE"

const IPS_Signature *g_ips_signatures  = NULL;
int                  g_signature_count = 0;

static IPS_Signature *g_loaded_signatures = NULL;

static POLICY        policy_from_string(const char *name);
static ips_context_t ctx_from_string(const char *name);

typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
} strbuf_t;

/**
 * @brief 동적 문자열 버퍼 뒤에 문자를 1개 추가한다.
 *
 * JSON 문자열 unescape 과정에서 임시 버퍼를 키우며 사용한다.
 *
 * @param sb 동적 문자열 버퍼
 * @param ch 추가할 문자
 * @return int 0이면 성공, -1이면 실패
 */
static int strbuf_append_char(strbuf_t *sb, char ch) {
    char  *next;
    size_t next_cap;

    if (sb->len + 1 >= sb->cap) {
        next_cap = sb->cap ? sb->cap * 2U : 64U;
        next     = (char *)realloc(sb->buf, next_cap);
        if (!next) {
            return -1;
        }
        sb->buf = next;
        sb->cap = next_cap;
    }
    sb->buf[sb->len++] = ch;
    sb->buf[sb->len]   = '\0';
    return 0;
}

/**
 * @brief 동적 문자열 버퍼 메모리를 해제한다.
 *
 * @param sb 해제할 버퍼
 */
static void strbuf_free(strbuf_t *sb) {
    free(sb->buf);
    sb->buf = NULL;
    sb->len = 0;
    sb->cap = 0;
}

/**
 * @brief 문자열 복사본을 새로 만든다.
 *
 * @param s 복사할 원본 문자열
 * @return char* 복사본, 실패 시 NULL
 */
static char *xstrdup(const char *s) {
    size_t len;
    char  *copy;

    if (!s) {
        return NULL;
    }
    len  = strlen(s);
    copy = (char *)malloc(len + 1U);
    if (!copy) {
        return NULL;
    }
    memcpy(copy, s, len + 1U);
    return copy;
}

/**
 * @brief 문자열 앞쪽의 공백 문자를 건너뛴다.
 *
 * @param p 현재 위치
 * @return const char* 공백을 건너뛴 새 위치
 */
static const char *skip_ws(const char *p) {
    int is_ws;

    while (NULL != p && '\0' != *p) {
        is_ws = isspace((unsigned char)*p);
        if (0 == is_ws) {
            break;
        }
        p++;
    }
    return p;
}

/**
 * @brief 현재 cursor가 가리키는 JSON 문자열 하나를 파싱한다.
 *
 * array 요소처럼 line 전체가 아니라 특정 위치부터 문자열 하나만 읽을 때 쓴다.
 *
 * @param cursor 현재 읽기 위치 포인터
 * @param out 파싱된 문자열을 받을 포인터
 * @return int 1이면 성공, -1이면 실패
 */
static int parse_json_string_at(const char **cursor, char **out) {
    const char *p;
    strbuf_t    sb;
    int         ret;
    int         is_hex;

    p    = *cursor;
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
                    goto oom;
                }
                break;
            case '\\':
                ret = strbuf_append_char(&sb, '\\');
                if (0 != ret) {
                    goto oom;
                }
                break;
            case '/':
                ret = strbuf_append_char(&sb, '/');
                if (0 != ret) {
                    goto oom;
                }
                break;
            case 'b':
                ret = strbuf_append_char(&sb, '\b');
                if (0 != ret) {
                    goto oom;
                }
                break;
            case 'f':
                ret = strbuf_append_char(&sb, '\f');
                if (0 != ret) {
                    goto oom;
                }
                break;
            case 'n':
                ret = strbuf_append_char(&sb, '\n');
                if (0 != ret) {
                    goto oom;
                }
                break;
            case 'r':
                ret = strbuf_append_char(&sb, '\r');
                if (0 != ret) {
                    goto oom;
                }
                break;
            case 't':
                ret = strbuf_append_char(&sb, '\t');
                if (0 != ret) {
                    goto oom;
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
                        goto oom;
                    }

                    if ('0' <= p[i] && '9' >= p[i]) {
                        v = (unsigned int)(p[i] - '0');
                    } else if ('a' <= p[i] && 'f' >= p[i]) {
                        v = (unsigned int)(p[i] - 'a' + 10);
                    } else if ('A' <= p[i] && 'F' >= p[i]) {
                        v = (unsigned int)(p[i] - 'A' + 10);
                    } else {
                        goto oom;
                    }

                    cp = (cp << 4) | v;
                }

                if (0xD800U <= cp && 0xDBFFU >= cp) {
                    unsigned int low;

                    if ('\\' != p[5] || 'u' != p[6]) {
                        goto oom;
                    }

                    low = 0U;
                    for (i = 7; i <= 10; i++) {
                        is_hex = 0;
                        if ('\0' != p[i]) {
                            is_hex = isxdigit((unsigned char)p[i]);
                        }
                        if ('\0' == p[i] || 0 == is_hex) {
                            goto oom;
                        }

                        if ('0' <= p[i] && '9' >= p[i]) {
                            v = (unsigned int)(p[i] - '0');
                        } else if ('a' <= p[i] && 'f' >= p[i]) {
                            v = (unsigned int)(p[i] - 'a' + 10);
                        } else if ('A' <= p[i] && 'F' >= p[i]) {
                            v = (unsigned int)(p[i] - 'A' + 10);
                        } else {
                            goto oom;
                        }

                        low = (low << 4) | v;
                    }

                    if (0xDC00U > low || 0xDFFFU < low) {
                        goto oom;
                    }

                    cp = 0x10000U + (((cp - 0xD800U) << 10) | (low - 0xDC00U));
                    p += 10;
                } else {
                    if (0xDC00U <= cp && 0xDFFFU >= cp) {
                        goto oom;
                    }
                    p += 4;
                }

                if (0x7FU >= cp) {
                    ret = strbuf_append_char(&sb, (char)cp);
                    if (0 != ret) {
                        goto oom;
                    }
                } else if (0x7FFU >= cp) {
                    ret = strbuf_append_char(
                        &sb, (char)(0xC0U | ((cp >> 6) & 0x1FU)));
                    if (0 != ret) {
                        goto oom;
                    }
                    ret = strbuf_append_char(&sb, (char)(0x80U | (cp & 0x3FU)));
                    if (0 != ret) {
                        goto oom;
                    }
                } else if (0xFFFFU >= cp) {
                    ret = strbuf_append_char(
                        &sb, (char)(0xE0U | ((cp >> 12) & 0x0FU)));
                    if (0 != ret) {
                        goto oom;
                    }
                    ret = strbuf_append_char(
                        &sb, (char)(0x80U | ((cp >> 6) & 0x3FU)));
                    if (0 != ret) {
                        goto oom;
                    }
                    ret = strbuf_append_char(&sb, (char)(0x80U | (cp & 0x3FU)));
                    if (0 != ret) {
                        goto oom;
                    }
                } else if (0x10FFFFU >= cp) {
                    ret = strbuf_append_char(
                        &sb, (char)(0xF0U | ((cp >> 18) & 0x07U)));
                    if (0 != ret) {
                        goto oom;
                    }
                    ret = strbuf_append_char(
                        &sb, (char)(0x80U | ((cp >> 12) & 0x3FU)));
                    if (0 != ret) {
                        goto oom;
                    }
                    ret = strbuf_append_char(
                        &sb, (char)(0x80U | ((cp >> 6) & 0x3FU)));
                    if (0 != ret) {
                        goto oom;
                    }
                    ret = strbuf_append_char(&sb, (char)(0x80U | (cp & 0x3FU)));
                    if (0 != ret) {
                        goto oom;
                    }
                } else {
                    goto oom;
                }
            } break;
            default:
                goto oom;
            }
            p++;
            continue;
        }
        if ('"' == *p) {
            *out    = sb.buf ? sb.buf : xstrdup("");
            *cursor = p + 1;
            return *out ? 1 : -1;
        }
        ret = strbuf_append_char(&sb, *p);
        if (0 != ret) {
            goto oom;
        }
        p++;
    }
oom:
    strbuf_free(&sb);
    return -1;
}

/**
 * @brief 문자열 배열 원소들을 전부 해제한다.
 *
 * @param values 해제할 문자열 포인터 배열
 * @param count 배열 원소 수
 */
static void free_string_values(const char **values, size_t count) {
    size_t i;

    for (i = 0; i < count; i++) {
        free((char *)values[i]);
    }
    free((char **)values);
}

/**
 * @brief 현재 위치가 JSON 값 경계인지 검사한다.
 *
 * 숫자/리터럴 뒤에 다른 식별자 문자가 이어지면 malformed input으로 본다.
 *
 * @param ch 검사할 문자
 * @return int 경계 문자면 1, 아니면 0
 */
static int is_json_value_delim(char ch) {
    if ('\0' == ch || ',' == ch || '}' == ch || ']' == ch) {
        return 1;
    }
    return 0 != isspace((unsigned char)ch);
}

/**
 * @brief cursor가 가리키는 정수 또는 null 값을 읽는다.
 *
 * @param cursor 현재 읽기 위치
 * @param out 파싱된 정수 값을 받을 포인터
 * @return int 1이면 정수 성공, 0이면 null, -1이면 실패
 */
static int parse_json_int_at(const char **cursor, int *out) {
    const char *p;
    char       *endptr;
    long        value;
    int         ret;

    p = skip_ws(*cursor);
    if (NULL == p) {
        return -1;
    }

    ret = strncmp(p, "null", 4);
    if (0 == ret && 0 != is_json_value_delim(p[4])) {
        *cursor = p + 4;
        return 0;
    }

    value = strtol(p, &endptr, 10);
    ret   = is_json_value_delim(*endptr);
    if (endptr == p || 0 == ret) {
        return -1;
    }

    *out    = (int)value;
    *cursor = endptr;
    return 1;
}

/**
 * @brief cursor가 가리키는 boolean 값을 읽는다.
 *
 * @param cursor 현재 읽기 위치
 * @param out 파싱된 bool 값을 받을 포인터
 * @return int 1이면 성공, -1이면 실패
 */
static int parse_json_bool_at(const char **cursor, int *out) {
    const char *p;
    int         ret;

    p = skip_ws(*cursor);
    if (NULL == p) {
        return -1;
    }

    ret = strncmp(p, "true", 4);
    if (0 == ret && 0 != is_json_value_delim(p[4])) {
        *out    = 1;
        *cursor = p + 4;
        return 1;
    }

    ret = strncmp(p, "false", 5);
    if (0 == ret && 0 != is_json_value_delim(p[5])) {
        *out    = 0;
        *cursor = p + 5;
        return 1;
    }

    return -1;
}

/**
 * @brief cursor가 가리키는 문자열 배열 값을 읽는다.
 *
 * @param cursor 현재 읽기 위치
 * @param out_values 파싱된 문자열 배열
 * @param out_count 배열 원소 수
 * @return int 1이면 성공, -1이면 실패
 */
static int parse_json_string_array_at(const char  **cursor,
                                      const char ***out_values,
                                      size_t       *out_count) {
    const char  *p;
    const char **values;
    const char **next_values;
    size_t       count;
    size_t       capacity;
    int          ret;

    *out_values = NULL;
    *out_count  = 0;

    values   = NULL;
    count    = 0;
    capacity = 0;

    p = skip_ws(*cursor);
    if (NULL == p || '[' != *p) {
        return -1;
    }
    p++;

    while ('\0' != *p) {
        char *item;

        p = skip_ws(p);
        if (']' == *p) {
            *cursor     = p + 1;
            *out_values = values;
            *out_count  = count;
            return 1;
        }

        if ('"' != *p) {
            free_string_values(values, count);
            return -1;
        }

        item = NULL;
        ret  = parse_json_string_at(&p, &item);
        if (0 > ret) {
            free_string_values(values, count);
            return -1;
        }

        if (count == capacity) {
            size_t next_capacity;

            next_capacity = (0U == capacity) ? 4U : (capacity * 2U);
            next_values   = (const char **)realloc(
                (void *)values, next_capacity * sizeof(*next_values));
            if (NULL == next_values) {
                free(item);
                free_string_values(values, count);
                return -1;
            }

            values   = next_values;
            capacity = next_capacity;
        }

        values[count] = item;
        count++;

        p = skip_ws(p);
        if (',' == *p) {
            p++;
            continue;
        }
        if (']' == *p) {
            *cursor     = p + 1;
            *out_values = values;
            *out_count  = count;
            return 1;
        }

        free_string_values(values, count);
        return -1;
    }

    free_string_values(values, count);
    return -1;
}

/**
 * @brief 현재 cursor가 가리키는 중첩 JSON 값 전체를 건너뛴다.
 *
 * @param cursor 현재 읽기 위치
 * @param open_ch 시작 문자
 * @param close_ch 종료 문자
 * @return int 0이면 성공, -1이면 실패
 */
static int skip_json_nested(const char **cursor, char open_ch, char close_ch) {
    const char *p;
    int         depth;
    int         in_string;
    int         escaped;

    p = *cursor;
    if (NULL == p || open_ch != *p) {
        return -1;
    }

    depth     = 0;
    in_string = 0;
    escaped   = 0;

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

/**
 * @brief 현재 cursor가 가리키는 값을 파싱 없이 건너뛴다.
 *
 * 알려지지 않은 key를 무시하기 위해 문자열/숫자/리터럴/배열/객체를
 * 한 값 단위로 소비한다.
 *
 * @param cursor 현재 읽기 위치
 * @return int 0이면 성공, -1이면 실패
 */
static int skip_json_value(const char **cursor) {
    const char *p;
    char       *endptr;
    char       *tmp;
    int         ret;

    p = skip_ws(*cursor);
    if (NULL == p || '\0' == *p) {
        return -1;
    }

    if ('"' == *p) {
        tmp = NULL;
        ret = parse_json_string_at(&p, &tmp);
        if (0 > ret) {
            return -1;
        }
        free(tmp);
        *cursor = p;
        return 0;
    }

    if ('[' == *p) {
        ret = skip_json_nested(&p, '[', ']');
        if (0 != ret) {
            return -1;
        }
        *cursor = p;
        return 0;
    }

    if ('{' == *p) {
        ret = skip_json_nested(&p, '{', '}');
        if (0 != ret) {
            return -1;
        }
        *cursor = p;
        return 0;
    }

    ret = strncmp(p, "true", 4);
    if (0 == ret && 0 != is_json_value_delim(p[4])) {
        *cursor = p + 4;
        return 0;
    }
    ret = strncmp(p, "false", 5);
    if (0 == ret && 0 != is_json_value_delim(p[5])) {
        *cursor = p + 5;
        return 0;
    }
    ret = strncmp(p, "null", 4);
    if (0 == ret && 0 != is_json_value_delim(p[4])) {
        *cursor = p + 4;
        return 0;
    }

    (void)strtod(p, &endptr);
    ret = is_json_value_delim(*endptr);
    if (endptr == p || 0 == ret) {
        return -1;
    }

    *cursor = endptr;
    return 0;
}

/**
 * @brief rules.jsonl 한 줄을 top-level object 기준으로 한 번만 훑어 파싱한다.
 *
 * key 탐색을 위해 line을 여러 번 다시 스캔하지 않고, cursor를 앞에서 뒤로
 * 한 번만 이동시키며 필요한 필드를 채운다.
 *
 * @param line JSONL 한 줄
 * @param sig 파싱 결과 시그니처
 * @return int 0이면 성공, -1이면 실패
 */
static int regex_signature_parse(const char *line, IPS_Signature *sig) {
    const char  *cursor;
    char        *key;
    char        *pid;
    char        *pname;
    char        *pat;
    char        *ctx;
    char        *op;
    char        *source;
    int          prio;
    int          rid;
    int          negated;
    int          cmp;
    int          parse_ret;
    const char **data_values;
    size_t       data_value_count;

    memset(sig, 0, sizeof(*sig));

    key              = NULL;
    pid              = NULL;
    pname            = NULL;
    pat              = NULL;
    ctx              = NULL;
    op               = NULL;
    source           = NULL;
    prio             = 0;
    rid              = 0;
    negated          = 0;
    data_values      = NULL;
    data_value_count = 0;

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

        cmp = strcmp(key, "pid");
        if (0 == cmp) {
            free(pid);
            pid       = NULL;
            parse_ret = parse_json_string_at(&cursor, &pid);
            if (0 > parse_ret) {
                goto fail;
            }
        } else {
            cmp = strcmp(key, "pname");
            if (0 == cmp) {
                free(pname);
                pname     = NULL;
                parse_ret = parse_json_string_at(&cursor, &pname);
                if (0 > parse_ret) {
                    goto fail;
                }
            } else {
                cmp = strcmp(key, "pat");
                if (0 == cmp) {
                    free(pat);
                    pat       = NULL;
                    parse_ret = parse_json_string_at(&cursor, &pat);
                    if (0 > parse_ret) {
                        goto fail;
                    }
                } else {
                    cmp = strcmp(key, "ctx");
                    if (0 == cmp) {
                        free(ctx);
                        ctx       = NULL;
                        parse_ret = parse_json_string_at(&cursor, &ctx);
                        if (0 > parse_ret) {
                            goto fail;
                        }
                    } else {
                        cmp = strcmp(key, "op");
                        if (0 == cmp) {
                            free(op);
                            op        = NULL;
                            parse_ret = parse_json_string_at(&cursor, &op);
                            if (0 > parse_ret) {
                                goto fail;
                            }
                        } else {
                            cmp = strcmp(key, "source");
                            if (0 == cmp) {
                                free(source);
                                source = NULL;
                                parse_ret =
                                    parse_json_string_at(&cursor, &source);
                                if (0 > parse_ret) {
                                    goto fail;
                                }
                            } else {
                                cmp = strcmp(key, "prio");
                                if (0 == cmp) {
                                    parse_ret =
                                        parse_json_int_at(&cursor, &prio);
                                    if (0 > parse_ret) {
                                        goto fail;
                                    }
                                } else {
                                    cmp = strcmp(key, "rid");
                                    if (0 == cmp) {
                                        parse_ret =
                                            parse_json_int_at(&cursor, &rid);
                                        if (0 > parse_ret) {
                                            goto fail;
                                        }
                                    } else {
                                        cmp = strcmp(key, "op_negated");
                                        if (0 == cmp) {
                                            parse_ret = parse_json_bool_at(
                                                &cursor, &negated);
                                            if (0 > parse_ret) {
                                                goto fail;
                                            }
                                        } else {
                                            cmp = strcmp(key, "data_values");
                                            if (0 == cmp) {
                                                free_string_values(
                                                    data_values,
                                                    data_value_count);
                                                data_values      = NULL;
                                                data_value_count = 0;
                                                parse_ret =
                                                    parse_json_string_array_at(
                                                        &cursor, &data_values,
                                                        &data_value_count);
                                                if (0 > parse_ret) {
                                                    goto fail;
                                                }
                                            } else {
                                                parse_ret =
                                                    skip_json_value(&cursor);
                                                if (0 != parse_ret) {
                                                    goto fail;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
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

    if (NULL == pid || NULL == pname || NULL == ctx || NULL == op) {
        goto fail;
    }

    if (NULL == pat) {
        pat = xstrdup("");
        if (NULL == pat) {
            goto fail;
        }
    }
    if (NULL == source) {
        source = xstrdup("");
        if (NULL == source) {
            goto fail;
        }
    }

    sig->policy_id        = policy_from_string(pname);
    sig->policy_name      = pname;
    sig->pattern          = pat;
    sig->is_high_priority = prio;
    sig->context          = ctx_from_string(ctx);
    sig->op               = ips_operator_from_string(op);
    sig->op_negated       = negated;
    sig->rule_id          = rid;
    sig->source           = source;
    sig->data_values      = data_values;
    sig->data_value_count = data_value_count;

    free(pid);
    free(ctx);
    free(op);
    return 0;

fail:
    free(key);
    free(pid);
    free(pname);
    free(pat);
    free(ctx);
    free(op);
    free(source);
    free_string_values(data_values, data_value_count);
    memset(sig, 0, sizeof(*sig));
    return -1;
}

/**
 * @brief 정책 이름 문자열을 POLICY enum으로 변환한다.
 *
 * @param name 정책 이름 문자열
 * @return POLICY 매핑된 정책 enum
 */
static POLICY policy_from_string(const char *name) {
    size_t i;
    int    cmp;
    static const struct {
        POLICY      policy;
        const char *name;
    } policies[] = {
#define X(ename, sname) {ename, sname},
        POLICY_LIST
#undef X
    };

    if (NULL == name) {
        return POLICY_COMMAND_INJECTION;
    }

    for (i = 0; i < (sizeof(policies) / sizeof(policies[0])); i++) {
        cmp = strcmp(name, policies[i].name);
        if (0 == cmp) {
            return policies[i].policy;
        }
    }

    return POLICY_COMMAND_INJECTION;
}

/**
 * @brief 룰 context 문자열을 내부 context enum으로 변환한다.
 *
 * @param name context 이름 문자열
 * @return ips_context_t 매핑된 context enum
 */
static ips_context_t ctx_from_string(const char *name) {
    size_t i;
    size_t len;
    int    cmp;
    static const struct {
        ips_context_t context;
        const char   *name;
        size_t        len;
    } aliases[] = {
        {IPS_CTX_REQUEST_URI, "URI", 3U},
        {IPS_CTX_REQUEST_URI, "REQUEST_URI", 11U},
        {IPS_CTX_ARGS, "ARGS", 4U},
        {IPS_CTX_ARGS_NAMES, "ARGS_NAMES", 10U},
        {IPS_CTX_REQUEST_HEADERS, "HEADERS", 7U},
        {IPS_CTX_REQUEST_HEADERS, "REQUEST_HEADERS", 15U},
        {IPS_CTX_REQUEST_BODY, "BODY", 4U},
        {IPS_CTX_REQUEST_BODY, "REQUEST_BODY", 12U},
        {IPS_CTX_RESPONSE_BODY, "RESPONSE_BODY", 13U},
    };

    if (NULL == name) {
        return IPS_CTX_ALL;
    }

    len = strlen(name);

    for (i = 0; i < (sizeof(aliases) / sizeof(aliases[0])); i++) {
        if (aliases[i].len != len) {
            continue;
        }
        cmp = strncmp(name, aliases[i].name, aliases[i].len);
        if (0 == cmp) {
            return aliases[i].context;
        }
    }

    return IPS_CTX_ALL;
}

/**
 * @brief 룰 operator 문자열을 내부 operator enum으로 변환한다.
 *
 * @param name operator 이름 문자열
 * @return ips_operator_t 매핑된 operator enum
 */
ips_operator_t ips_operator_from_string(const char *name) {
    size_t i;
    int    cmp;
    static const struct {
        ips_operator_t op;
        const char    *name;
    } operators[] = {
        {IPS_OP_RX, "rx"},
        {IPS_OP_PM, "pm"},
        {IPS_OP_PM_FROM_FILE, "pmFromFile"},
        {IPS_OP_CONTAINS, "contains"},
        {IPS_OP_BEGINS_WITH, "beginsWith"},
        {IPS_OP_ENDS_WITH, "endsWith"},
        {IPS_OP_STREQ, "streq"},
        {IPS_OP_WITHIN, "within"},
        {IPS_OP_DETECT_SQLI, "detectSQLi"},
        {IPS_OP_DETECT_XSS, "detectXSS"},
        {IPS_OP_EQ, "eq"},
        {IPS_OP_GE, "ge"},
        {IPS_OP_GT, "gt"},
        {IPS_OP_LT, "lt"},
        {IPS_OP_VALIDATE_BYTE_RANGE, "validateByteRange"},
        {IPS_OP_IP_MATCH, "ipMatch"},
    };

    if (NULL == name) {
        return IPS_OP_UNKNOWN;
    }

    for (i = 0; i < (sizeof(operators) / sizeof(operators[0])); i++) {
        cmp = strcmp(name, operators[i].name);
        if (0 == cmp) {
            return operators[i].op;
        }
    }

    return IPS_OP_UNKNOWN;
}

/**
 * @brief operator enum을 사람이 읽을 문자열로 변환한다.
 *
 * @param op operator enum
 * @return const char* operator 이름
 */
const char *ips_operator_name(ips_operator_t op) {
    switch (op) {
    case IPS_OP_RX:
        return "rx";
    case IPS_OP_PM:
        return "pm";
    case IPS_OP_PM_FROM_FILE:
        return "pmFromFile";
    case IPS_OP_CONTAINS:
        return "contains";
    case IPS_OP_BEGINS_WITH:
        return "beginsWith";
    case IPS_OP_ENDS_WITH:
        return "endsWith";
    case IPS_OP_STREQ:
        return "streq";
    case IPS_OP_WITHIN:
        return "within";
    case IPS_OP_DETECT_SQLI:
        return "detectSQLi";
    case IPS_OP_DETECT_XSS:
        return "detectXSS";
    case IPS_OP_EQ:
        return "eq";
    case IPS_OP_GE:
        return "ge";
    case IPS_OP_GT:
        return "gt";
    case IPS_OP_LT:
        return "lt";
    case IPS_OP_VALIDATE_BYTE_RANGE:
        return "validateByteRange";
    case IPS_OP_IP_MATCH:
        return "ipMatch";
    default:
        return "unknown";
    }
}

/**
 * @brief 시그니처 1개가 보유한 동적 문자열/배열을 해제한다.
 *
 * @param sig 정리할 시그니처
 */
static void regex_signature_free(IPS_Signature *sig) {
    size_t i;

    free((char *)sig->policy_name);
    free((char *)sig->pattern);
    free((char *)sig->source);
    for (i = 0; i < sig->data_value_count; i++) {
        free((char *)sig->data_values[i]);
    }
    free((char **)sig->data_values);
    memset(sig, 0, sizeof(*sig));
}

/**
 * @brief 현재 적재된 모든 시그니처를 메모리에서 내린다.
 *
 * @return 없음
 */
void regex_signatures_unload(void) {
    int i;

    if (NULL == g_loaded_signatures) {
        return;
    }
    for (i = 0; i < g_signature_count; i++) {
        regex_signature_free(&g_loaded_signatures[i]);
    }
    free(g_loaded_signatures);
    g_loaded_signatures = NULL;
    g_ips_signatures    = NULL;
    g_signature_count   = 0;
}

/**
 * @brief 시그니처 배열 뒤에 새 시그니처를 추가한다.
 *
 * @param items 시그니처 동적 배열
 * @param count 현재 원소 수
 * @param capacity 현재 배열 용량
 * @param sig 추가할 시그니처
 * @return int 0이면 성공, -1이면 실패
 */
static int regex_signature_append(IPS_Signature **items, int *count,
                                  int *capacity, const IPS_Signature *sig) {
    IPS_Signature *next;
    int            next_cap;

    if (*count == *capacity) {
        next_cap = *capacity ? (*capacity * 2) : 64;
        next =
            (IPS_Signature *)realloc(*items, (size_t)next_cap * sizeof(*next));
        if (!next) {
            return -1;
        }
        *items    = next;
        *capacity = next_cap;
    }
    (*items)[*count] = *sig;
    (*count)++;
    return 0;
}

/**
 * @brief JSON line 1개를 IPS_Signature 구조체로 변환한다.
 *
 * 필수/선택 필드를 읽어 시그니처 구조체를 채우고, 문자열 필드는
 * 새 메모리에 복사해 소유권을 넘긴다.
 *
 * @param line JSONL 한 줄
 * @param sig 파싱 결과 시그니처
 * @return int 0이면 성공, -1이면 실패
 */
static int regex_signature_load(const char *line, IPS_Signature *sig) {
    return regex_signature_parse(line, sig);
}

/**
 * @brief 지정한 JSONL 파일에서 시그니처를 전부 적재한다.
 *
 * @param path 읽을 JSONL 파일 경로
 * @return int 0이면 성공, -1이면 실패
 */
static int try_load_file(const char *path) {
    FILE          *fp;
    char           line[65536];
    IPS_Signature *items    = NULL;
    int            count    = 0;
    int            capacity = 0;
    int            ret;

    fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    /* 줄 단위로 읽어 정상 파싱된 룰만 배열에 누적한다. */
    while (fgets(line, sizeof(line), fp)) {
        IPS_Signature sig;
        if ('\0' == line[0] || '\n' == line[0]) {
            continue;
        }
        ret = regex_signature_load(line, &sig);
        if (-1 == ret) {
            continue;
        }
        ret = regex_signature_append(&items, &count, &capacity, &sig);
        if (-1 == ret) {
            regex_signature_free(&sig);
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);

    if (0 == count) {
        free(items);
        return -1;
    }

    regex_signatures_unload();
    g_loaded_signatures = items;
    g_ips_signatures    = items;
    g_signature_count   = count;
    return 0;
}

/**
 * @brief IPS 시그니처 JSONL 파일을 적재한다.
 *
 * 명시적 경로를 먼저 시도하고, 실패하면 환경 변수 `IPS_RULES_FILE`을
 * fallback으로 사용한다.
 *
 * @param jsonl_path 우선 시도할 JSONL 파일 경로
 * @return int 0이면 성공, -1이면 실패
 */
int regex_signatures_load(const char *jsonl_path) {
    const char *env_path;
    int         ret;

    if (NULL != g_loaded_signatures) {
        return 0;
    }

    /* 경로로 받던지 */
    ret = -1;
    if (NULL != jsonl_path) {
        ret = try_load_file(jsonl_path);
    }
    if (0 == ret) {
        return 0;
    }

    /* 환경변수로 받던지 */
    env_path = getenv(RULES_FILE_ENV);
    ret      = -1;
    if (NULL != env_path && '\0' != env_path[0]) {
        ret = try_load_file(env_path);
    }
    if (0 == ret) {
        return 0;
    }

    return -1;
}

/**
 * @brief POLICY enum을 사람이 읽을 문자열로 변환한다.
 *
 * @param p 정책 enum
 * @return const char* 정책 이름
 */
const char *get_policy_name(POLICY p) {
    static const char *policy_names[] = {
#define X(ename, sname) [ename] = sname,
        POLICY_LIST
#undef X
    };

    if (0 > (int)p || POLICY_MAX <= p) {
        return "UNKNOWN_POLICY";
    }
    return policy_names[p] ? policy_names[p] : "UNDEFINED_NAME";
}

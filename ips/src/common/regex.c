/**
 * @file regex.c
 * @brief JSONL 기반 IPS 시그니처 로더
 *
 * rules JSONL에서 정책/컨텍스트/operator 메타데이터를 읽어
 * 전역 시그니처 테이블 형태로 적재한다. detect 계층은 이 전역 테이블을
 * 기준으로 엔진을 초기화한다.
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

typedef struct {
    /* 동적 문자열 버퍼 시작 주소 */
    char *buf;
    /* 현재 사용 길이 */
    size_t len;
    /* 현재 할당 용량 */
    size_t cap;
} strbuf_t;

/**
 * @brief 정책 이름 문자열을 POLICY enum으로 변환한다.
 *
 * @param name 정책 이름 문자열
 * @return POLICY 매핑된 정책 enum
 */
static POLICY policy_from_string(const char *name) {
    /* 정책 테이블 순회 인덱스 */
    size_t i;
    /* 문자열 비교 결과 */
    int cmp;
    static const struct {
        POLICY      policy;
        const char *name;
    } policies[] = {
#define X(ename, sname) {ename, sname},
        POLICY_LIST
#undef X
    };

    /* 이름이 없으면 보수적 기본 정책 사용 */
    if (NULL == name) {
        return POLICY_RCE;
    }

    /* 등록된 정책 이름 테이블을 순회한다 */
    for (i = 0; i < (sizeof(policies) / sizeof(policies[0])); i++) {
        cmp = strcmp(name, policies[i].name);
        if (0 == cmp) {
            return policies[i].policy;
        }
    }

    /* 알 수 없는 이름이면 기본 정책 사용 */
    return POLICY_RCE;
}

/**
 * @brief 룰 context 문자열을 내부 context enum으로 변환한다.
 *
 * @param name context 이름 문자열
 * @return ips_context_t 매핑된 context enum
 */
static ips_context_t ctx_from_string(const char *name) {
    /* alias 테이블 순회 인덱스 */
    size_t i;
    /* 입력 문자열 길이 */
    size_t len;
    /* 문자열 비교 결과 */
    int cmp;
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

    /* context가 없으면 전체 컨텍스트로 본다 */
    if (NULL == name) {
        return IPS_CTX_ALL;
    }

    /* 입력 문자열 길이 계산 */
    len = strlen(name);

    /* 허용 alias 테이블을 순회한다 */
    for (i = 0; i < (sizeof(aliases) / sizeof(aliases[0])); i++) {
        /* 길이가 다르면 비교 생략 */
        if (aliases[i].len != len) {
            continue;
        }
        cmp = strncmp(name, aliases[i].name, aliases[i].len);
        if (0 == cmp) {
            return aliases[i].context;
        }
    }

    /* 알 수 없는 context는 전체 컨텍스트 처리 */
    return IPS_CTX_ALL;
}

/* --------------------------- JSON parsing helpers ---------------------------
 */

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
    /* realloc 결과 포인터 */
    char *next;
    /* 다음 확장 용량 */
    size_t next_cap;

    /* NUL 포함 1바이트를 더 넣을 공간이 없으면 확장한다 */
    if (sb->len + 1 >= sb->cap) {
        next_cap = sb->cap ? sb->cap * 2U : 64U;
        next     = (char *)realloc(sb->buf, next_cap);
        if (!next) {
            return -1;
        }
        sb->buf = next;
        sb->cap = next_cap;
    }
    /* 문자 1개 추가 */
    sb->buf[sb->len++] = ch;
    /* 항상 NUL 종료 유지 */
    sb->buf[sb->len] = '\0';
    return 0;
}

/**
 * @brief 동적 문자열 버퍼 메모리를 해제한다.
 *
 * @param sb 해제할 버퍼
 */
static void strbuf_free(strbuf_t *sb) {
    /* 동적 문자열 버퍼 본체 해제 */
    free(sb->buf);
    /* 해제 후 dangling pointer 방지 */
    sb->buf = NULL;
    /* 사용 길이 초기화 */
    sb->len = 0;
    /* 할당 용량 초기화 */
    sb->cap = 0;
}

/**
 * @brief 문자열 복사본을 새로 만든다.
 *
 * @param s 복사할 원본 문자열
 * @return char* 복사본, 실패 시 NULL
 */
static char *xstrdup(const char *s) {
    /* 원본 문자열 길이 */
    size_t len;
    /* 복사본 버퍼 */
    char *copy;

    /* NULL 입력은 NULL 유지 */
    if (!s) {
        return NULL;
    }
    /* 길이 측정 */
    len = strlen(s);
    /* NUL 포함 공간 확보 */
    copy = (char *)malloc(len + 1U);
    if (!copy) {
        return NULL;
    }
    /* NUL 포함 전체 복사 */
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
    /* 현재 문자가 공백인지 여부 */
    int is_ws;

    /* 공백이 아닌 첫 위치까지 전진 */
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
    /* 현재 cursor 위치 */
    const char *p;
    /* 문자열 누적 버퍼 */
    strbuf_t sb;
    /* helper 반환값 */
    int ret;
    /* hex digit 검사 결과 */
    int is_hex;

    /* 현재 위치와 출력 포인터 초기화 */
    p    = *cursor;
    *out = NULL;
    /* 시작 문자는 반드시 큰따옴표여야 한다 */
    if (NULL == p || '"' != *p) {
        return -1;
    }
    p++;

    /* 누적 버퍼 초기화 */
    memset(&sb, 0, sizeof(sb));
    while ('\0' != *p) {
        /* escape 시퀀스 시작 처리 */
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
                /* unicode code point 누적값 */
                unsigned int cp;
                /* hex digit 1개 값 */
                unsigned int v;
                /* unicode escape 순회 인덱스 */
                int i;

                /* \uXXXX 상위 code point 초기화 */
                cp = 0U;
                for (i = 1; i <= 4; i++) {
                    /* 각 자리의 hex 유효성 검사 */
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

                /* high surrogate면 뒤따르는 low surrogate까지 결합한다 */
                if (0xD800U <= cp && 0xDBFFU >= cp) {
                    /* low surrogate 임시 누적값 */
                    unsigned int low;

                    if ('\\' != p[5] || 'u' != p[6]) {
                        goto oom;
                    }

                    /* 두 번째 \uXXXX 초기화 */
                    low = 0U;
                    for (i = 7; i <= 10; i++) {
                        /* low surrogate hex 자리 검증 */
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

                    /* surrogate pair를 실제 code point로 결합 */
                    cp = 0x10000U + (((cp - 0xD800U) << 10) | (low - 0xDC00U));
                    /* 두 번째 escape까지 cursor를 건너뛴다 */
                    p += 10;
                } else {
                    /* low surrogate 단독 출현은 malformed input 처리 */
                    if (0xDC00U <= cp && 0xDFFFU >= cp) {
                        goto oom;
                    }
                    /* 현재 \uXXXX 4자리를 소비한다 */
                    p += 4;
                }

                /* code point 크기에 따라 UTF-8 바이트열로 변환한다 */
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
        /* 닫는 큰따옴표면 문자열 파싱 완료 */
        if ('"' == *p) {
            *out    = sb.buf ? sb.buf : xstrdup("");
            *cursor = p + 1;
            return *out ? 1 : -1;
        }
        /* 일반 문자를 누적한다 */
        ret = strbuf_append_char(&sb, *p);
        if (0 != ret) {
            goto oom;
        }
        p++;
    }
oom:
    /* 실패 시 누적 버퍼 해제 */
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
    /* 배열 순회 인덱스 */
    size_t i;

    /* 문자열 원소별 해제 */
    for (i = 0; i < count; i++) {
        free((char *)values[i]);
    }
    /* 배열 본체 해제 */
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
    /* 현재 읽기 위치 */
    const char *p;
    /* strtol 종료 위치 */
    char *endptr;
    /* 파싱된 long 값 */
    long value;
    /* helper 반환값 */
    int ret;

    /* 공백 건너뛴 시작 위치 */
    p = skip_ws(*cursor);
    if (NULL == p) {
        return -1;
    }

    /* null literal 처리 */
    ret = strncmp(p, "null", 4);
    if (0 == ret && 0 != is_json_value_delim(p[4])) {
        *cursor = p + 4;
        return 0;
    }

    /* 일반 정수 파싱 */
    value = strtol(p, &endptr, 10);
    ret   = is_json_value_delim(*endptr);
    if (endptr == p || 0 == ret) {
        return -1;
    }

    /* 결과 저장 */
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
static __attribute__((unused)) int parse_json_bool_at(const char **cursor,
                                                      int         *out) {
    /* 현재 읽기 위치 */
    const char *p;
    /* 문자열 비교 결과 */
    int ret;

    p = skip_ws(*cursor);
    if (NULL == p) {
        return -1;
    }

    /* true literal 처리 */
    ret = strncmp(p, "true", 4);
    if (0 == ret && 0 != is_json_value_delim(p[4])) {
        *out    = 1;
        *cursor = p + 4;
        return 1;
    }

    /* false literal 처리 */
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
static __attribute__((unused)) int parse_json_string_array_at(
    const char **cursor, const char ***out_values, size_t *out_count) {
    /* 현재 읽기 위치 */
    const char *p;
    /* 문자열 포인터 배열 */
    const char **values;
    /* realloc 결과 배열 */
    const char **next_values;
    /* 현재 원소 수 */
    size_t count;
    /* 현재 배열 용량 */
    size_t capacity;
    /* helper 반환값 */
    int ret;

    /* 출력 포인터 초기화 */
    *out_values = NULL;
    *out_count  = 0;

    /* 내부 누적 배열 초기화 */
    values   = NULL;
    count    = 0;
    capacity = 0;

    /* 배열 시작 '[' 확인 */
    p = skip_ws(*cursor);
    if (NULL == p || '[' != *p) {
        return -1;
    }
    p++;

    while ('\0' != *p) {
        /* 현재 문자열 원소 */
        char *item;

        p = skip_ws(p);
        /* 빈 배열 또는 마지막 원소 뒤 ']' 처리 */
        if (']' == *p) {
            *cursor     = p + 1;
            *out_values = values;
            *out_count  = count;
            return 1;
        }

        /* 배열 원소는 문자열만 허용 */
        if ('"' != *p) {
            free_string_values(values, count);
            return -1;
        }

        /* 문자열 원소 하나 파싱 */
        item = NULL;
        ret  = parse_json_string_at(&p, &item);
        if (0 > ret) {
            free_string_values(values, count);
            return -1;
        }

        /* 배열 용량이 꽉 차면 확장 */
        if (count == capacity) {
            /* 다음 용량 */
            size_t next_capacity;

            /* 작은 배열에서 시작해 2배씩 확장 */
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

        /* 새 원소 저장 */
        values[count] = item;
        count++;

        p = skip_ws(p);
        /* 다음 원소 계속 */
        if (',' == *p) {
            p++;
            continue;
        }
        /* 배열 종료 */
        if (']' == *p) {
            *cursor     = p + 1;
            *out_values = values;
            *out_count  = count;
            return 1;
        }

        /* 배열 구문 오류 */
        free_string_values(values, count);
        return -1;
    }

    /* 문자열 끝까지 갔는데 닫는 ']'를 못 찾음 */
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
    /* 현재 읽기 위치 */
    const char *p;
    /* 중첩 깊이 */
    int depth;
    /* 문자열 내부 여부 */
    int in_string;
    /* 직전 문자가 escape인지 여부 */
    int escaped;

    /* 시작 문자가 기대한 중첩 시작 문자인지 확인 */
    p = *cursor;
    if (NULL == p || open_ch != *p) {
        return -1;
    }

    /* 중첩 상태 초기화 */
    depth     = 0;
    in_string = 0;
    escaped   = 0;

    /* 문자열/중첩 상태를 추적하며 닫는 문자까지 이동 */
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
    /* 현재 읽기 위치 */
    const char *p;
    /* 숫자 파싱 종료 위치 */
    char *endptr;
    /* 임시 문자열 버퍼 */
    char *tmp;
    /* helper 반환값 */
    int ret;

    /* 시작 위치 정렬 */
    p = skip_ws(*cursor);
    if (NULL == p || '\0' == *p) {
        return -1;
    }

    /* 문자열 값 skip */
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

    /* 배열 값 skip */
    if ('[' == *p) {
        ret = skip_json_nested(&p, '[', ']');
        if (0 != ret) {
            return -1;
        }
        *cursor = p;
        return 0;
    }

    /* 객체 값 skip */
    if ('{' == *p) {
        ret = skip_json_nested(&p, '{', '}');
        if (0 != ret) {
            return -1;
        }
        *cursor = p;
        return 0;
    }

    /* true/false/null literal skip */
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

    /* 숫자 값 skip */
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
    /* top-level object cursor */
    const char *cursor;
    /* 현재 key 이름 */
    char *key;
    /* 개별 필드 문자열 */
    char *pname;
    char *pat;
    char *ctx;
    char *source;
    /* 점수/식별자 필드 */
    int score;
    int rid;
    /* helper 비교/파싱 반환값 */
    int cmp;
    int parse_ret;

    /* 출력 시그니처 zero-init */
    memset(sig, 0, sizeof(*sig));

    /* 필드별 임시 포인터 초기화 */
    key    = NULL;
    pname  = NULL;
    pat    = NULL;
    ctx    = NULL;
    source = NULL;
    score  = 0;
    rid    = 0;

    /* top-level object 시작 확인 */
    cursor = skip_ws(line);
    if (NULL == cursor || '{' != *cursor) {
        goto fail;
    }
    cursor++;

    /* object를 key:value 단위로 순회 */
    while (1) {
        cursor = skip_ws(cursor);
        if (NULL == cursor || '\0' == *cursor) {
            goto fail;
        }
        if ('}' == *cursor) {
            cursor++;
            break;
        }
        /* key는 문자열이어야 한다 */
        if ('"' != *cursor) {
            goto fail;
        }

        /* key 하나 파싱 */
        parse_ret = parse_json_string_at(&cursor, &key);
        if (0 > parse_ret) {
            goto fail;
        }

        /* ':' 구분자 확인 */
        cursor = skip_ws(cursor);
        if (':' != *cursor) {
            goto fail;
        }
        cursor++;
        cursor = skip_ws(cursor);

        /* key 이름에 따라 대상 필드를 파싱한다 */
        cmp = strcmp(key, "name");
        if (0 == cmp) {
            free(pname);
            pname     = NULL;
            parse_ret = parse_json_string_at(&cursor, &pname);
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
                        cmp = strcmp(key, "score");
                        if (0 == cmp) {
                            parse_ret = parse_json_int_at(&cursor, &score);
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
                                        parse_json_int_at(&cursor, &score);
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
                                        parse_ret = skip_json_value(&cursor);
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

        /* 이번 key 문자열은 더 이상 필요 없다 */
        free(key);
        key = NULL;

        /* 다음 key 또는 object 종료로 이동 */
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

    /* object 뒤에 쓰레기 문자가 남으면 실패 */
    cursor = skip_ws(cursor);
    if ('\0' != *cursor) {
        goto fail;
    }

    /* 필수 필드 검증 */
    if (NULL == pname || NULL == pat || NULL == ctx) {
        goto fail;
    }

    /* source가 없으면 빈 문자열로 채운다 */
    if (NULL == source) {
        source = xstrdup("");
        if (NULL == source) {
            goto fail;
        }
    }

    /* 문자열 메타를 내부 enum/구조 필드로 변환한다 */
    sig->policy_id        = policy_from_string(pname);
    sig->policy_name      = pname;
    sig->pattern          = pat;
    sig->is_high_priority = score;
    sig->context          = ctx_from_string(ctx);
    sig->op               = IPS_OP_RX;
    sig->op_negated       = 0;
    sig->rule_id          = rid;
    sig->source           = source;
    sig->data_values      = NULL;
    sig->data_value_count = 0;

    /* 임시 필드 중 구조체에 저장하지 않는 것만 정리한다 */
    free(ctx);
    return 0;

fail:
    /* 파싱 실패 시 확보한 임시 메모리를 모두 정리한다 */
    free(key);
    free(pname);
    free(pat);
    free(ctx);
    free(source);
    memset(sig, 0, sizeof(*sig));
    return -1;
}

/**
 * @brief 룰 operator 문자열을 내부 operator enum으로 변환한다.
 *
 * @param name operator 이름 문자열
 * @return ips_operator_t 매핑된 operator enum
 */
ips_operator_t ips_operator_from_string(const char *name) {
    /* operator 테이블 순회 인덱스 */
    size_t i;
    /* 문자열 비교 결과 */
    int cmp;
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

    /* 입력이 없으면 unknown 반환 */
    if (NULL == name) {
        return IPS_OP_UNKNOWN;
    }

    /* 등록된 operator 이름 테이블을 순회한다 */
    for (i = 0; i < (sizeof(operators) / sizeof(operators[0])); i++) {
        cmp = strcmp(name, operators[i].name);
        if (0 == cmp) {
            return operators[i].op;
        }
    }

    /* 알 수 없는 이름이면 unknown */
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
    /* data_values 순회 인덱스 */
    size_t i;

    /* NULL 입력 방어 */
    if (NULL == sig) {
        return;
    }

    /* 문자열 필드 해제 */
    free((char *)sig->policy_name);
    free((char *)sig->pattern);
    free((char *)sig->source);
    /* data_values 원소별 해제 */
    for (i = 0; i < sig->data_value_count; i++) {
        free((char *)sig->data_values[i]);
    }
    /* 배열 본체 해제 */
    free((char **)sig->data_values);
    /* 구조체 재초기화 */
    memset(sig, 0, sizeof(*sig));
}

/**
 * @brief 현재 적재된 모든 시그니처를 메모리에서 내린다.
 *
 * @return 없음
 */
void regex_signatures_unload(void) {
    /* 시그니처 순회 인덱스 */
    int i;

    /* 적재된 시그니처가 없으면 종료 */
    if (NULL == g_loaded_signatures) {
        return;
    }
    /* 각 시그니처 내부 메모리 정리 */
    for (i = 0; i < g_signature_count; i++) {
        regex_signature_free(&g_loaded_signatures[i]);
    }
    /* 전역 배열과 공개 포인터 초기화 */
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
    /* realloc 결과 배열 */
    IPS_Signature *next;
    /* 다음 배열 용량 */
    int next_cap;

    /* 배열이 꽉 차면 용량을 늘린다 */
    if (*count == *capacity) {
        /* 빈 배열이면 64개부터 시작하고 이후 2배 확장 */
        next_cap = *capacity ? (*capacity * 2) : 64;
        next =
            (IPS_Signature *)realloc(*items, (size_t)next_cap * sizeof(*next));
        if (!next) {
            return -1;
        }
        *items    = next;
        *capacity = next_cap;
    }
    /* 시그니처 구조체를 값 복사로 append */
    (*items)[*count] = *sig;
    (*count)++;
    return 0;
}

static int try_load_file_append(const char *path, IPS_Signature **items,
                                int *count, int *capacity) {
    FILE *fp;
    char  line[65536];
    int   ret;
    int   line_no = 0;

    fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        IPS_Signature sig;

        line_no++;
        memset(&sig, 0, sizeof(sig));
        if ('\0' == line[0] || '\n' == line[0]) {
            continue;
        }
        ret = regex_signature_parse(line, &sig);
        if (-1 == ret) {
            continue;
        }
        if (0 == sig.rule_id) {
            sig.rule_id = line_no;
        }
        ret = regex_signature_append(items, count, capacity, &sig);
        if (-1 == ret) {
            regex_signature_free(&sig);
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return 0;
}

/**
 * @brief 지정한 JSONL 파일에서 시그니처를 전부 적재한다.
 *
 * @param path 읽을 JSONL 파일 경로
 * @return int 0이면 성공, -1이면 실패
 */
static int try_load_file(const char *path) {
    /* 동적 시그니처 배열 */
    IPS_Signature *items = NULL;
    /* 현재 원소 수와 용량 */
    int count    = 0;
    int capacity = 0;
    /* helper 반환값 */
    int ret;

    ret = try_load_file_append(path, &items, &count, &capacity);
    if (-1 == ret) {
        return -1;
    }

    /* 유효한 룰이 하나도 없으면 실패 처리 */
    if (0 == count) {
        free(items);
        return -1;
    }

    /* 기존 전역 시그니처를 내리고 새 배열로 교체한다 */
    regex_signatures_unload();
    g_loaded_signatures = items;
    g_ips_signatures    = items;
    g_signature_count   = count;
    return 0;
}

static int try_load_split_rule_set(const char *base_dir) {
    static const char *const names[] = {
        "sqli.jsonl",
        "xss.jsonl",
        "rce.jsonl",
        "directory_traversal.jsonl",
    };
    IPS_Signature *items    = NULL;
    int            count    = 0;
    int            capacity = 0;
    int            ret;
    size_t         i;

    for (i = 0; i < (sizeof(names) / sizeof(names[0])); i++) {
        char path[512];

        ret = snprintf(path, sizeof(path), "%s/%s", base_dir, names[i]);
        if (0 > ret || (size_t)ret >= sizeof(path)) {
            goto fail;
        }

        ret = try_load_file_append(path, &items, &count, &capacity);
        if (-1 == ret) {
            goto fail;
        }
    }

    if (0 == count) {
        goto fail;
    }

    regex_signatures_unload();
    g_loaded_signatures = items;
    g_ips_signatures    = items;
    g_signature_count   = count;
    return 0;

fail:
    if (NULL != items) {
        int j;

        for (j = 0; j < count; j++) {
            regex_signature_free(&items[j]);
        }
        free(items);
    }
    return -1;
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
    /* 환경변수 fallback 경로 */
    const char *env_path;
    /* helper 반환값 */
    int ret;
    /* 기본 split rules 경로 후보 */
    static const char *const default_dirs[] = {
        "rules",
        "./rules",
        "../rules",
        "../../rules",
    };
    size_t i;

    /* 이미 적재된 상태면 재로딩 없이 성공 처리 */
    if (NULL != g_loaded_signatures) {
        return 0;
    }

    /* 직접 받은 경로를 먼저 시도 */
    ret = -1;
    if (NULL != jsonl_path) {
        ret = try_load_file(jsonl_path);
        if (0 != ret) {
            ret = try_load_split_rule_set(jsonl_path);
        }
    }
    if (0 == ret) {
        return 0;
    }

    /* 실패하면 환경변수 fallback 경로 시도 */
    env_path = getenv(RULES_FILE_ENV);
    ret      = -1;
    if (NULL != env_path && '\0' != env_path[0]) {
        ret = try_load_file(env_path);
        if (0 != ret) {
            ret = try_load_split_rule_set(env_path);
        }
    }
    if (0 == ret) {
        return 0;
    }

    for (i = 0; i < (sizeof(default_dirs) / sizeof(default_dirs[0])); i++) {
        ret = try_load_split_rule_set(default_dirs[i]);
        if (0 == ret) {
            return 0;
        }
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
    /* enum 값별 사람이 읽는 정책 이름 테이블 */
    static const char *policy_names[] = {
#define X(ename, sname) [ename] = sname,
        POLICY_LIST
#undef X
    };

    /* 범위를 벗어난 enum이면 fallback 이름 반환 */
    if (0 > (int)p || POLICY_MAX <= p) {
        return "UNKNOWN_POLICY";
    }
    /* 이름이 등록되지 않은 슬롯도 fallback 처리 */
    return policy_names[p] ? policy_names[p] : "UNDEFINED_NAME";
}

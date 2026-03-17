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
    while (p && *p && isspace((unsigned char)*p)) {
        p++;
    }
    return p;
}

/**
 * @brief JSON line 안에서 특정 key 토큰의 시작 위치를 찾는다.
 *
 * 간단한 JSONL 입력을 전제로 `"key"` 문자열을 그대로 검색한다.
 *
 * @param line JSON 한 줄
 * @param key 찾을 key 이름
 * @return const char* key가 있으면 그 위치, 없으면 NULL
 */
static const char *find_json_key(const char *line, const char *key) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    return strstr(line, needle);
}

/**
 * @brief JSON line에서 문자열 필드 하나를 unescape 하며 읽는다.
 *
 * @param line JSON 한 줄
 * @param key 찾을 key 이름
 * @param out 파싱한 문자열을 받을 포인터
 * @return int 1이면 성공, 0이면 key 없음, -1이면 파싱 실패
 */
static int parse_json_string_field(const char *line, const char *key,
                                   char **out) {
    const char *p;
    strbuf_t    sb;

    *out = NULL;
    p    = find_json_key(line, key);
    if (!p) {
        return 0;
    }

    /* key 뒤의 ':'를 찾고, 문자열 값 시작 따옴표까지 이동한다. */
    p = strchr(p, ':');
    if (!p) {
        return -1;
    }
    p = skip_ws(p + 1);
    if (!p || *p != '"') {
        return -1;
    }
    p++;

    memset(&sb, 0, sizeof(sb));
    /* escape 시퀀스를 해석하며 문자열 종료 따옴표까지 복원한다. */
    while (*p) {
        if (*p == '\\') {
            p++;
            if (!*p) {
                break;
            }
            switch (*p) {
            case '"':
                if (strbuf_append_char(&sb, '"') != 0) {
                    goto oom;
                }
                break;
            case '\\':
                if (strbuf_append_char(&sb, '\\') != 0) {
                    goto oom;
                }
                break;
            case '/':
                if (strbuf_append_char(&sb, '/') != 0) {
                    goto oom;
                }
                break;
            case 'b':
                if (strbuf_append_char(&sb, '\b') != 0) {
                    goto oom;
                }
                break;
            case 'f':
                if (strbuf_append_char(&sb, '\f') != 0) {
                    goto oom;
                }
                break;
            case 'n':
                if (strbuf_append_char(&sb, '\n') != 0) {
                    goto oom;
                }
                break;
            case 'r':
                if (strbuf_append_char(&sb, '\r') != 0) {
                    goto oom;
                }
                break;
            case 't':
                if (strbuf_append_char(&sb, '\t') != 0) {
                    goto oom;
                }
                break;
            case 'u':
                if (strbuf_append_char(&sb, '?') != 0) {
                    goto oom;
                }
                while (p[1] && isxdigit((unsigned char)p[1])) {
                    p++;
                }
                break;
            default:
                if (strbuf_append_char(&sb, *p) != 0) {
                    goto oom;
                }
                break;
            }
            p++;
            continue;
        }
        if (*p == '"') {
            *out = sb.buf ? sb.buf : xstrdup("");
            return *out ? 1 : -1;
        }
        if (strbuf_append_char(&sb, *p) != 0) {
            goto oom;
        }
        p++;
    }

oom:
    strbuf_free(&sb);
    return -1;
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
    const char *p = *cursor;
    strbuf_t    sb;

    *out = NULL;
    if (!p || *p != '"') {
        return -1;
    }
    p++;

    memset(&sb, 0, sizeof(sb));
    while (*p) {
        if (*p == '\\') {
            p++;
            if (!*p) {
                break;
            }
            switch (*p) {
            case '"':
                if (strbuf_append_char(&sb, '"') != 0) {
                    goto oom;
                }
                break;
            case '\\':
                if (strbuf_append_char(&sb, '\\') != 0) {
                    goto oom;
                }
                break;
            case '/':
                if (strbuf_append_char(&sb, '/') != 0) {
                    goto oom;
                }
                break;
            case 'b':
                if (strbuf_append_char(&sb, '\b') != 0) {
                    goto oom;
                }
                break;
            case 'f':
                if (strbuf_append_char(&sb, '\f') != 0) {
                    goto oom;
                }
                break;
            case 'n':
                if (strbuf_append_char(&sb, '\n') != 0) {
                    goto oom;
                }
                break;
            case 'r':
                if (strbuf_append_char(&sb, '\r') != 0) {
                    goto oom;
                }
                break;
            case 't':
                if (strbuf_append_char(&sb, '\t') != 0) {
                    goto oom;
                }
                break;
            default:
                if (strbuf_append_char(&sb, *p) != 0) {
                    goto oom;
                }
                break;
            }
            p++;
            continue;
        }
        if (*p == '"') {
            *out    = sb.buf ? sb.buf : xstrdup("");
            *cursor = p + 1;
            return *out ? 1 : -1;
        }
        if (strbuf_append_char(&sb, *p) != 0) {
            goto oom;
        }
        p++;
    }
oom:
    strbuf_free(&sb);
    return -1;
}

/**
 * @brief JSON line에서 정수 필드를 읽는다.
 *
 * @param line JSON 한 줄
 * @param key 찾을 key 이름
 * @param out 파싱된 정수 값을 받을 포인터
 * @return int 1이면 성공, 0이면 key 없음/null, -1이면 파싱 실패
 */
static int parse_json_int_field(const char *line, const char *key, int *out) {
    const char *p;
    char       *endptr;
    long        value;

    p = find_json_key(line, key);
    if (!p) {
        return 0;
    }
    p = strchr(p, ':');
    if (!p) {
        return -1;
    }
    p = skip_ws(p + 1);
    if (!strncmp(p, "null", 4)) {
        return 0;
    }

    value = strtol(p, &endptr, 10);
    if (endptr == p) {
        return -1;
    }
    *out = (int)value;
    return 1;
}

/**
 * @brief JSON line에서 boolean 필드를 읽는다.
 *
 * @param line JSON 한 줄
 * @param key 찾을 key 이름
 * @param out 파싱된 bool 값을 받을 포인터
 * @return int 1이면 성공, 0이면 key 없음, -1이면 파싱 실패
 */
static int parse_json_bool_field(const char *line, const char *key, int *out) {
    const char *p;

    p = find_json_key(line, key);
    if (!p) {
        return 0;
    }
    p = strchr(p, ':');
    if (!p) {
        return -1;
    }
    p = skip_ws(p + 1);
    if (!strncmp(p, "true", 4)) {
        *out = 1;
        return 1;
    }
    if (!strncmp(p, "false", 5)) {
        *out = 0;
        return 1;
    }
    return -1;
}

/**
 * @brief JSON line에서 문자열 배열 필드를 읽는다.
 *
 * `["a", "b"]` 형태의 단순 문자열 배열만 지원한다.
 *
 * @param line JSON 한 줄
 * @param key 찾을 key 이름
 * @param out_values 파싱된 문자열 배열
 * @param out_count 배열 원소 수
 * @return int 1이면 성공, 0이면 key 없음, -1이면 실패
 */
static int parse_json_string_array_field(const char *line, const char *key,
                                         const char ***out_values,
                                         size_t       *out_count) {
    const char  *p;
    const char  *cursor;
    const char **values = NULL;
    size_t       count  = 0;

    *out_values = NULL;
    *out_count  = 0;

    p = find_json_key(line, key);
    if (!p) {
        return 0;
    }
    p = strchr(p, ':');
    if (!p) {
        return -1;
    }
    p = skip_ws(p + 1);
    if (*p != '[') {
        return -1;
    }
    cursor = p + 1;

    /* 닫는 대괄호를 만날 때까지 문자열 원소를 하나씩 읽어 배열에 붙인다. */
    while (*cursor) {
        char        *item = NULL;
        const char **next_values;

        cursor = skip_ws(cursor);
        if (*cursor == ']') {
            break;
        }
        if (*cursor != '"') {
            return -1;
        }

        if (parse_json_string_at(&cursor, &item) < 0) {
            return -1;
        }
        next_values =
            (const char **)realloc(values, (count + 1U) * sizeof(*next_values));
        if (!next_values) {
            free(item);
            return -1;
        }
        values          = next_values;
        values[count++] = item;

        cursor = skip_ws(cursor);
        if (*cursor == ',') {
            cursor++;
            continue;
        }
        if (*cursor == ']') {
            break;
        }
    }

    *out_values = values;
    *out_count  = count;
    return 1;
}

/**
 * @brief 정책 이름 문자열을 POLICY enum으로 변환한다.
 *
 * @param name 정책 이름 문자열
 * @return POLICY 매핑된 정책 enum
 */
static POLICY policy_from_string(const char *name) {
#define X(ename, sname)                   \
    if (name && strcmp(name, sname) == 0) \
        return ename;
    POLICY_LIST
#undef X
    return POLICY_COMMAND_INJECTION;
}

/**
 * @brief 룰 context 문자열을 내부 context enum으로 변환한다.
 *
 * @param name context 이름 문자열
 * @return ips_context_t 매핑된 context enum
 */
static ips_context_t ctx_from_string(const char *name) {
    if (!name) {
        return IPS_CTX_ALL;
    }
    if (strcmp(name, "URI") == 0 || strcmp(name, "REQUEST_URI") == 0) {
        return IPS_CTX_REQUEST_URI;
    }
    if (strcmp(name, "ARGS") == 0) {
        return IPS_CTX_ARGS;
    }
    if (strcmp(name, "ARGS_NAMES") == 0) {
        return IPS_CTX_ARGS_NAMES;
    }
    if (strcmp(name, "HEADERS") == 0 || strcmp(name, "REQUEST_HEADERS") == 0) {
        return IPS_CTX_REQUEST_HEADERS;
    }
    if (strcmp(name, "BODY") == 0 || strcmp(name, "REQUEST_BODY") == 0) {
        return IPS_CTX_REQUEST_BODY;
    }
    if (strcmp(name, "RESPONSE_BODY") == 0) {
        return IPS_CTX_RESPONSE_BODY;
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
    if (!name) {
        return IPS_OP_UNKNOWN;
    }
    if (strcmp(name, "rx") == 0) {
        return IPS_OP_RX;
    }
    if (strcmp(name, "pm") == 0) {
        return IPS_OP_PM;
    }
    if (strcmp(name, "pmFromFile") == 0) {
        return IPS_OP_PM_FROM_FILE;
    }
    if (strcmp(name, "contains") == 0) {
        return IPS_OP_CONTAINS;
    }
    if (strcmp(name, "beginsWith") == 0) {
        return IPS_OP_BEGINS_WITH;
    }
    if (strcmp(name, "endsWith") == 0) {
        return IPS_OP_ENDS_WITH;
    }
    if (strcmp(name, "streq") == 0) {
        return IPS_OP_STREQ;
    }
    if (strcmp(name, "within") == 0) {
        return IPS_OP_WITHIN;
    }
    if (strcmp(name, "detectSQLi") == 0) {
        return IPS_OP_DETECT_SQLI;
    }
    if (strcmp(name, "detectXSS") == 0) {
        return IPS_OP_DETECT_XSS;
    }
    if (strcmp(name, "eq") == 0) {
        return IPS_OP_EQ;
    }
    if (strcmp(name, "ge") == 0) {
        return IPS_OP_GE;
    }
    if (strcmp(name, "gt") == 0) {
        return IPS_OP_GT;
    }
    if (strcmp(name, "lt") == 0) {
        return IPS_OP_LT;
    }
    if (strcmp(name, "validateByteRange") == 0) {
        return IPS_OP_VALIDATE_BYTE_RANGE;
    }
    if (strcmp(name, "ipMatch") == 0) {
        return IPS_OP_IP_MATCH;
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
static void free_signature_entry(IPS_Signature *sig) {
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
void regex_unload_signatures(void) {
    int i;

    if (!g_loaded_signatures) {
        return;
    }
    for (i = 0; i < g_signature_count; i++) {
        free_signature_entry(&g_loaded_signatures[i]);
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
static int append_signature(IPS_Signature **items, int *count, int *capacity,
                            const IPS_Signature *sig) {
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
static int load_one_signature(const char *line, IPS_Signature *sig) {
    char        *pid              = NULL;
    char        *pname            = NULL;
    char        *pat              = NULL;
    char        *ctx              = NULL;
    char        *op               = NULL;
    char        *source           = NULL;
    int          prio             = 0;
    int          rid              = 0;
    int          negated          = 0;
    const char **data_values      = NULL;
    size_t       data_value_count = 0;

    memset(sig, 0, sizeof(*sig));

    /* 룰 해석에 필요한 핵심 필드는 먼저 읽고, 하나라도 실패하면 해당 줄을 버린다. */
    if (parse_json_string_field(line, "pid", &pid) <= 0 ||
        parse_json_string_field(line, "pname", &pname) <= 0 ||
        parse_json_string_field(line, "pat", &pat) < 0 ||
        parse_json_string_field(line, "ctx", &ctx) <= 0 ||
        parse_json_string_field(line, "op", &op) <= 0) {
        goto fail;
    }

    if (parse_json_int_field(line, "prio", &prio) < 0) {
        goto fail;
    }
    if (parse_json_int_field(line, "rid", &rid) < 0) {
        goto fail;
    }
    if (parse_json_bool_field(line, "op_negated", &negated) < 0) {
        goto fail;
    }
    if (parse_json_string_field(line, "source", &source) < 0) {
        goto fail;
    }
    if (parse_json_string_array_field(line, "data_values", &data_values,
                                      &data_value_count) < 0) {
        goto fail;
    }

    sig->policy_id   = policy_from_string(pname);
    sig->policy_name = pname ? pname : xstrdup(get_policy_name(sig->policy_id));
    sig->pattern     = pat ? pat : xstrdup("");
    sig->is_high_priority = prio;
    sig->context          = ctx_from_string(ctx);
    sig->op               = ips_operator_from_string(op);
    sig->op_negated       = negated;
    sig->rule_id          = rid;
    sig->source           = source ? source : xstrdup("");
    sig->data_values      = data_values;
    sig->data_value_count = data_value_count;

    free(pid);
    free(ctx);
    free(op);
    return 0;

fail:
    /* 부분적으로 확보된 문자열과 배열을 모두 정리하고 실패를 돌려준다. */
    free(pid);
    free(pname);
    free(pat);
    free(ctx);
    free(op);
    free(source);
    if (data_values) {
        size_t i;
        for (i = 0; i < data_value_count; i++) {
            free((char *)data_values[i]);
        }
        free((char **)data_values);
    }
    return -1;
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

    fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    /* 줄 단위로 읽어 정상 파싱된 룰만 배열에 누적한다. */
    while (fgets(line, sizeof(line), fp)) {
        IPS_Signature sig;
        if (line[0] == '\0' || line[0] == '\n') {
            continue;
        }
        if (load_one_signature(line, &sig) != 0) {
            continue;
        }
        if (append_signature(&items, &count, &capacity, &sig) != 0) {
            free_signature_entry(&sig);
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);

    regex_unload_signatures();
    g_loaded_signatures = items;
    g_ips_signatures    = items;
    g_signature_count   = count;
    return 0;
}

/**
 * @brief IPS 시그니처 JSONL 파일을 적재한다.
 *
 * 명시적 경로를 먼저 시도하고, 실패하면 환경 변수 `IPS_RULES_FILE`을 fallback으로
 * 사용한다.
 *
 * @param jsonl_path 우선 시도할 JSONL 파일 경로
 * @return int 0이면 성공, -1이면 실패
 */
int regex_load_signatures(const char *jsonl_path) {
    const char *env_path;

    if (g_loaded_signatures) {
        return 0;
    }

    if (jsonl_path && try_load_file(jsonl_path) == 0) {
        return 0;
    }

    env_path = getenv(RULES_FILE_ENV);
    if (env_path && env_path[0] != '\0' && try_load_file(env_path) == 0) {
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

    if ((int)p < 0 || p >= POLICY_MAX) {
        return "UNKNOWN_POLICY";
    }
    return policy_names[p] ? policy_names[p] : "UNDEFINED_NAME";
}

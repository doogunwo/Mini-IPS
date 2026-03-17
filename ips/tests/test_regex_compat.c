/**
 * @file test_regex_compat.c
 * @brief PCRE2와 Hyperscan 정규식 호환성 비교 유틸리티
 */
#include <ctype.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <hs/hs.h>
#include <pcre2.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_BUF_SIZE 262144

/**
 * @brief 문자열 일부 구간을 새 버퍼로 복사한다.
 *
 * @param start 시작 주소
 * @param end 끝 주소
 * @return char* 복사 결과, 실패 시 NULL
 */
static char *dup_range(const char *start, const char *end) {
    size_t len;
    char  *out;

    if (start == NULL || end == NULL || end < start) {
        return NULL;
    }

    len = (size_t)(end - start);
    out = (char *)malloc(len + 1);
    if (out == NULL) {
        return NULL;
    }

    memcpy(out, start, len);
    out[len] = '\0';
    return out;
}

/**
 * @brief 단일 hex 문자를 정수값으로 변환한다.
 *
 * @param c hex 문자
 * @return int 0~15, 실패 시 -1
 */
static int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

/**
 * @brief JSON 문자열 escape를 해제해 일반 문자열로 변환한다.
 *
 * @param src JSON 문자열 본문
 * @return char* 변환 결과, 실패 시 NULL
 */
static char *json_unescape(const char *src) {
    size_t src_len;
    char  *out;
    size_t i;
    size_t j = 0;

    if (src == NULL) {
        return NULL;
    }

    src_len = strlen(src);
    out     = (char *)malloc(src_len + 1);
    if (out == NULL) {
        return NULL;
    }

    for (i = 0; i < src_len; i++) {
        if (src[i] != '\\') {
            out[j++] = src[i];
            continue;
        }

        i++;
        if (i >= src_len) {
            break;
        }

        switch (src[i]) {
        case '\\':
            out[j++] = '\\';
            break;
        case '"':
            out[j++] = '"';
            break;
        case '/':
            out[j++] = '/';
            break;
        case 'b':
            out[j++] = '\b';
            break;
        case 'f':
            out[j++] = '\f';
            break;
        case 'n':
            out[j++] = '\n';
            break;
        case 'r':
            out[j++] = '\r';
            break;
        case 't':
            out[j++] = '\t';
            break;
        case 'u':
            if (i + 4 < src_len) {
                int h1 = hex_value(src[i + 1]);
                int h2 = hex_value(src[i + 2]);
                int h3 = hex_value(src[i + 3]);
                int h4 = hex_value(src[i + 4]);
                if (h1 >= 0 && h2 >= 0 && h3 >= 0 && h4 >= 0) {
                    int code = (h1 << 12) | (h2 << 8) | (h3 << 4) | h4;
                    out[j++] = (code >= 0 && code <= 0x7f) ? (char)code : '?';
                    i += 4;
                    break;
                }
            }
            out[j++] = 'u';
            break;
        default:
            out[j++] = src[i];
            break;
        }
    }

    out[j] = '\0';
    return out;
}

static char *json_extract_string(const char *line, const char *key) {
    char        pattern[64];
    const char *p;
    const char *start;
    const char *cur;
    char       *raw;
    char       *decoded;

    snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    p = strstr(line, pattern);
    if (p == NULL) {
        return NULL;
    }

    p += strlen(pattern);
    while (*p != '\0' && isspace((unsigned char)*p)) {
        p++;
    }
    if (*p != '"') {
        return NULL;
    }

    start = ++p;
    for (cur = start; *cur != '\0'; cur++) {
        if (*cur == '"' && cur > start && cur[-1] != '\\') {
            raw = dup_range(start, cur);
            if (raw == NULL) {
                return NULL;
            }
            decoded = json_unescape(raw);
            free(raw);
            return decoded;
        }
    }

    return NULL;
}

static bool pcre_pattern_ok(const char *pattern) {
    int         errcode = 0;
    PCRE2_SIZE  erroff  = 0;
    pcre2_code *re;

    re = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED, 0, &errcode,
                       &erroff, NULL);
    if (re == NULL) {
        (void)errcode;
        (void)erroff;
        return false;
    }

    pcre2_code_free(re);
    return true;
}

static bool hs_pattern_ok(const char *pattern) {
    hs_database_t      *db  = NULL;
    hs_compile_error_t *err = NULL;
    hs_error_t          rc;

    rc = hs_compile(pattern, 0, HS_MODE_BLOCK, NULL, &db, &err);
    if (rc != HS_SUCCESS) {
        if (err != NULL) {
            hs_free_compile_error(err);
        }
        if (db != NULL) {
            hs_free_database(db);
        }
        return false;
    }

    hs_free_database(db);
    return true;
}

static int filter_file(const char *input_path, const char *common_path,
                       const char *hs_fail_path) {
    FILE        *in;
    FILE        *common_out;
    FILE        *hs_fail_out;
    char         line[LINE_BUF_SIZE];
    unsigned int total_rx      = 0;
    unsigned int common_count  = 0;
    unsigned int hs_fail_count = 0;

    in = fopen(input_path, "r");
    if (in == NULL) {
        perror("fopen input");
        return 1;
    }

    common_out = fopen(common_path, "w");
    if (common_out == NULL) {
        perror("fopen common");
        fclose(in);
        return 1;
    }

    hs_fail_out = fopen(hs_fail_path, "w");
    if (hs_fail_out == NULL) {
        perror("fopen hs_fail");
        fclose(common_out);
        fclose(in);
        return 1;
    }

    while (fgets(line, sizeof(line), in) != NULL) {
        char *op  = json_extract_string(line, "op");
        char *pat = NULL;
        bool  pcre_ok;
        bool  hs_ok;

        if (op == NULL) {
            continue;
        }
        if (strcmp(op, "rx") != 0) {
            free(op);
            continue;
        }

        total_rx++;
        pat = json_extract_string(line, "pat");
        if (pat == NULL) {
            free(op);
            continue;
        }

        pcre_ok = pcre_pattern_ok(pat);
        hs_ok   = hs_pattern_ok(pat);

        if (pcre_ok && hs_ok) {
            fputs(line, common_out);
            common_count++;
        } else if (pcre_ok && !hs_ok) {
            fputs(line, hs_fail_out);
            hs_fail_count++;
        }

        free(pat);
        free(op);
    }

    fclose(hs_fail_out);
    fclose(common_out);
    fclose(in);

    printf("total_rx=%u\n", total_rx);
    printf("common=%u\n", common_count);
    printf("hs_incompatible=%u\n", hs_fail_count);
    return 0;
}

int main(int argc, char **argv) {
    const char *input_path   = "rules/generated/rules.jsonl";
    const char *common_path  = "rules/generated/rules_common.jsonl";
    const char *hs_fail_path = "rules/generated/rules_hs_incompatible.jsonl";

    if (argc > 1) {
        input_path = argv[1];
    }
    if (argc > 2) {
        common_path = argv[2];
    }
    if (argc > 3) {
        hs_fail_path = argv[3];
    }

    return filter_file(input_path, common_path, hs_fail_path);
}

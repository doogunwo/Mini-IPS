#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "regex.h"

#ifndef REGEX_LOAD_FN
#define REGEX_LOAD_FN regex_signatures_load
#endif

#ifndef REGEX_UNLOAD_FN
#define REGEX_UNLOAD_FN regex_signatures_unload
#endif

static int write_test_rules(const char *path) {
    FILE *fp;

    fp = fopen(path, "w");
    if (NULL == fp) {
        return -1;
    }

    /*
     * 100: \uXXXX가 UTF-8로 정확히 복원되어야 하는 정상 문자열 패턴
     * 101: data_values 배열 안의 \uXXXX도 동일하게 복원되어야 함
     * 102: ctx="U" 같은 prefix는 URI로 오인되면 안 되고 ALL로 남아야 함
     * 103: 닫는 ] 없는 배열은 malformed line으로 skip되어야 함
     * 104: \q 같은 잘못된 escape는 malformed line으로 skip되어야 함
     * 105: 알 수 없는 중첩 객체/배열 key가 있어도 known field는 정상 적재
     */
    if (0 >
        fprintf(
            fp,
            "{\"pid\":\"p100\",\"pname\":\"SQL_INJECTION\","
            "\"pat\":\"\\uAC00\",\"ctx\":\"URI\",\"op\":\"rx\","
            "\"rid\":100,\"source\":\"unicode-pattern\"}\n"
            "{\"pid\":\"p101\",\"pname\":\"XSS\","
            "\"pat\":\"plain\",\"ctx\":\"URI\",\"op\":\"pmFromFile\","
            "\"rid\":101,\"data_values\":[\"\\uAC00\",\"plain\"],"
            "\"source\":\"unicode-array\"}\n"
            "{\"pid\":\"p102\",\"pname\":\"XSS\","
            "\"pat\":\"ctx-check\",\"ctx\":\"U\",\"op\":\"rx\","
            "\"rid\":102}\n"
            "{\"pid\":\"p103\",\"pname\":\"XSS\","
            "\"pat\":\"broken-array\",\"ctx\":\"URI\",\"op\":\"pmFromFile\","
            "\"rid\":103,\"data_values\":[\"a\",\"b\"\n"
            "{\"pid\":\"p104\",\"pname\":\"XSS\","
            "\"pat\":\"\\q\",\"ctx\":\"URI\",\"op\":\"rx\","
            "\"rid\":104}\n"
            "{\"pid\":\"p105\",\"pname\":\"SCANNER\","
            "\"pat\":\"kept\",\"ctx\":\"REQUEST_BODY\","
            "\"op\":\"contains\",\"rid\":105,"
            "\"unknown\":{\"nested\":[1,2,{\"x\":true}]},"
            "\"source\":\"with-unknown\"}\n")) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

static const IPS_Signature *find_signature_by_rid(int rid) {
    int i;

    for (i = 0; i < g_signature_count; i++) {
        if (g_ips_signatures[i].rule_id == rid) {
            return &g_ips_signatures[i];
        }
    }
    return NULL;
}

static int expect_signature_count(int expected) {
    if (g_signature_count != expected) {
        fprintf(stderr, "expected signature_count=%d got=%d\n", expected,
                g_signature_count);
        return -1;
    }
    return 0;
}

static int expect_pattern_utf8(int rid, const unsigned char *expected) {
    const IPS_Signature *sig;

    sig = find_signature_by_rid(rid);
    if (NULL == sig) {
        fprintf(stderr, "missing rid=%d\n", rid);
        return -1;
    }

    if (0 != strcmp(sig->pattern, (const char *)expected)) {
        fprintf(stderr, "rid=%d pattern mismatch: got=\"%s\"\n", rid,
                sig->pattern);
        return -1;
    }
    return 0;
}

static int expect_array_utf8(int rid, size_t index,
                             const unsigned char *expected) {
    const IPS_Signature *sig;

    sig = find_signature_by_rid(rid);
    if (NULL == sig) {
        fprintf(stderr, "missing rid=%d\n", rid);
        return -1;
    }
    if (index >= sig->data_value_count) {
        fprintf(stderr, "rid=%d missing data_values[%zu]\n", rid, index);
        return -1;
    }
    if (0 != strcmp(sig->data_values[index], (const char *)expected)) {
        fprintf(stderr, "rid=%d data_values[%zu] mismatch: got=\"%s\"\n", rid,
                index, sig->data_values[index]);
        return -1;
    }
    return 0;
}

static int expect_context(int rid, ips_context_t ctx) {
    const IPS_Signature *sig;

    sig = find_signature_by_rid(rid);
    if (NULL == sig) {
        fprintf(stderr, "missing rid=%d\n", rid);
        return -1;
    }
    if (sig->context != ctx) {
        fprintf(stderr, "rid=%d context mismatch: got=%d expected=%d\n", rid,
                (int)sig->context, (int)ctx);
        return -1;
    }
    return 0;
}

static int expect_missing(int rid) {
    if (NULL != find_signature_by_rid(rid)) {
        fprintf(stderr, "rid=%d should have been skipped\n", rid);
        return -1;
    }
    return 0;
}

static int expect_loaded(int rid) {
    if (NULL == find_signature_by_rid(rid)) {
        fprintf(stderr, "rid=%d should be loaded\n", rid);
        return -1;
    }
    return 0;
}

int main(void) {
    char          path_template[] = "/tmp/regex_rules_XXXXXX.jsonl";
    int           fd;
    unsigned char utf8_ga[] = {0xEA, 0xB0, 0x80, 0x00};

    fd = mkstemps(path_template, 6);
    if (fd < 0) {
        perror("mkstemps");
        return 1;
    }
    close(fd);

    if (0 != write_test_rules(path_template)) {
        fprintf(stderr, "failed to write test rules\n");
        unlink(path_template);
        return 1;
    }

    if (0 != REGEX_LOAD_FN(path_template)) {
        fprintf(stderr, "load failed: %s\n", path_template);
        unlink(path_template);
        return 1;
    }

    if (0 != expect_signature_count(4) ||
        0 != expect_pattern_utf8(100, utf8_ga) ||
        0 != expect_array_utf8(101, 0, utf8_ga) ||
        0 != expect_context(102, IPS_CTX_ALL) || 0 != expect_missing(103) ||
        0 != expect_missing(104) || 0 != expect_loaded(105)) {
        REGEX_UNLOAD_FN();
        unlink(path_template);
        return 1;
    }

    REGEX_UNLOAD_FN();

    if (0 != g_signature_count || NULL != g_ips_signatures) {
        fprintf(stderr, "unload did not reset globals\n");
        unlink(path_template);
        return 1;
    }

    unlink(path_template);
    printf("regex parser correctness: ok\n");
    return 0;
}

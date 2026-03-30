#include "../../src/inline/mini_ips.h"

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../common/unit_test.h"

static int resolve_ruleset_dir(char *out, size_t out_sz) {
    if (NULL == out || out_sz == 0U) {
        return -1;
    }

    if (NULL != realpath("rules", out)) {
        return 0;
    }

    if (NULL != realpath("ips/rules", out)) {
        return 0;
    }

    return -1;
}

static void *worker_main(void *arg) {
    mini_ips_ctx_t *ctx;
    int             rc;

    ctx = (mini_ips_ctx_t *)arg;
    rc = mini_ips_run_worker(ctx);
    return (void *)(intptr_t)rc;
}

static int run_pipeline_case(const char *req_payload, const char *res_payload) {
    mini_ips_ctx_t ctx;
    pthread_t      worker;
    void          *worker_ret;
    uint32_t       out_len;
    uint32_t       session_id;
    uint8_t        scratch[PACKET_MAX_BYTES];
    int            rc;

    rc = mini_ips_set(&ctx);
    if (0 != rc) {
        return 1;
    }

    rc = packet_ring_enq(&ctx.req_ring, (const uint8_t *)req_payload,
                         (uint32_t)strlen(req_payload), -1);
    EXPECT_INT_EQ("packet_ring_enq.req", 0, rc);

    rc = packet_ring_enq(&ctx.res_ring, (const uint8_t *)res_payload,
                         (uint32_t)strlen(res_payload), -1);
    EXPECT_INT_EQ("packet_ring_enq.res", 0, rc);

    rc = pthread_create(&worker, NULL, worker_main, &ctx);
    EXPECT_INT_EQ("pthread_create", 0, rc);

    usleep(100000);
    ctx.stop = 1;

    rc = pthread_join(worker, &worker_ret);
    EXPECT_INT_EQ("pthread_join", 0, rc);
    EXPECT_INT_EQ("mini_ips_run_worker", 0, (int)(intptr_t)worker_ret);

    rc = packet_ring_deq(&ctx.req_ring, scratch, sizeof(scratch), &out_len,
                         &session_id);
    EXPECT_INT_EQ("packet_ring_deq.req_empty", -1, rc);

    rc = packet_ring_deq(&ctx.res_ring, scratch, sizeof(scratch), &out_len,
                         &session_id);
    EXPECT_INT_EQ("packet_ring_deq.res_empty", -1, rc);

    mini_ips_destroy(&ctx);
    return 0;
}

int main(void) {
    char       rules_dir[PATH_MAX];
    const char *normal_req;
    const char *attack_req;
    const char *normal_res;
    const char *attack_res;

    EXPECT_INT_EQ("resolve_ruleset_dir", 0,
                  resolve_ruleset_dir(rules_dir, sizeof(rules_dir)));
    EXPECT_INT_EQ("setenv", 0, setenv(MINI_IPS_RULESET_ENV, rules_dir, 1));

    normal_req =
        "GET /index HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n";
    normal_res =
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    if (run_pipeline_case(normal_req, normal_res)) {
        unsetenv(MINI_IPS_RULESET_ENV);
        return 1;
    }

    attack_req =
        "POST /../../admin?x=select HTTP/1.1\r\nHost: a\r\n"
        "Content-Length: 8\r\n\r\n<script>";
    attack_res =
        "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n<script>";
    if (run_pipeline_case(attack_req, attack_res)) {
        unsetenv(MINI_IPS_RULESET_ENV);
        return 1;
    }

    unsetenv(MINI_IPS_RULESET_ENV);
    return 0;
}

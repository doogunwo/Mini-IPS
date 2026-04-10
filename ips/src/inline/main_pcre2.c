#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mini_ips_pcre2.h"

static volatile sig_atomic_t g_stop = 0;
static mini_ips_ctx_t       *g_ctx = NULL;

static void handle_signal(int sig) {
    (void)sig;
    g_stop = 1;
    if (NULL != g_ctx) {
        mini_ips_stop(g_ctx);
    }
}

static void *worker_main(void *arg) {
    mini_ips_ctx_t *ctx;
    int             rc;

    ctx = (mini_ips_ctx_t *)arg;
    rc = mini_ips_run_worker(ctx);
    return (void *)(intptr_t)rc;
}

int main(void) {
    mini_ips_ctx_t ctx;
    pthread_t      worker;
    void          *worker_ret;
    int            worker_started;
    int            tp_rc;
    int            worker_rc;
    int            exit_code;
    int            ret;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    worker_started = 0;
    worker_ret = NULL;
    worker_rc = 0;
    exit_code = 0;

    ret = mini_ips_set(&ctx);
    if (-1 == ret) {
        fprintf(stderr, "[MAIN] failed to initialize mini_ips (ret=%d)\n", ret);
        return 1;
    }
    g_ctx = &ctx;

    ret = pthread_create(&worker, NULL, worker_main, &ctx);
    if (0 != ret) {
        fprintf(stderr,
                "[MAIN] failed to start worker thread (ret=%d: %s)\n",
                ret, strerror(ret));
        mini_ips_destroy(&ctx);
        g_ctx = NULL;
        return 1;
    }
    worker_started = 1;

    tp_rc = mini_ips_run_tp(&ctx);
    mini_ips_stop(&ctx);
    g_stop = 1;

    if (worker_started) {
        if (0 != pthread_join(worker, &worker_ret)) {
            fprintf(stderr, "[MAIN] failed to join worker thread\n");
            exit_code = 1;
        } else {
            worker_rc = (int)(intptr_t)worker_ret;
        }
    }

    if (0 != tp_rc) {
        fprintf(stderr, "[MAIN] mini_ips_run_tp failed (rc=%d)\n", tp_rc);
        exit_code = 1;
    }
    if (0 != worker_rc) {
        fprintf(stderr, "[MAIN] mini_ips_run_worker failed (rc=%d)\n",
                worker_rc);
        exit_code = 1;
    }

    mini_ips_destroy(&ctx);
    g_ctx = NULL;

    return exit_code;
}

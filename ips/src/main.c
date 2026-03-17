/**
 * @file main.c
 * @brief Mini-IPS 프로세스 초기화와 메인 콜백 연결
 */

/**
 * @mainpage 첫페이지
 * @section 소개
 * 이 프로젝트는 모니터랩 수습 과제를 포함하고 있습니다.
 * @section 개발자 도건우 (gunwoo.do@monitorapp.com)
 * @section history 이 프로젝트는 2026년 2월 24일 시작되었다.
 */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "detect.h"
#include "driver.h"
#include "engine.h"
#include "html.h"
#include "httgw.h"
#include "logging.h"
#include "net_compat.h"

static volatile sig_atomic_t g_stop = 0; /**< stop signal flag */
static const char           *g_block_page_template_path = "DB/index.html";

static void on_sigint(int signo);
static void on_request(const flow_key_t *flow, tcp_dir_t dir,
                       const http_message_t *msg, const char *query,
                       size_t query_len, void *user);
static void on_error(const char *stage, const char *detail, void *user);
static void on_packet(const uint8_t *data, uint32_t len, uint64_t ts_ns,
                      void *user);
static void maybe_emit_monitor_stats(app_ctx_t *app, uint64_t ts_ms);
static void destroy_workers(app_ctx_t *workers, int count);
static void usage(const char *prog);

/**
 * @brief 캡처/탐지/게이트웨이 런타임을 구성하고 패킷 처리를 시작한다.
 *
 * 명령행 인자를 해석한 뒤 driver, pcap capture, worker별 detect engine,
 * worker별 httgw를 차례로 초기화한다. 종료 신호 또는 capture thread 실패가
 * 감지되면 전체 runtime을 역순으로 정리한다.
 *
 * @param argc 인자 개수
 * @param argv 인자 문자열 배열
 * @return int 성공 시 0, 초기화 실패 시 1
 */
int main(int argc, char **argv) {
    const char       *iface       = NULL;
    const char       *bpf         = NULL;
    const char       *policy      = "ALL";
    const char       *engine_name = NULL;
    driver_runtime_t  rt;
    app_shared_t      shared;
    app_ctx_t        *workers      = NULL;
    void            **worker_users = NULL;
    int               worker_count = 1;
    httgw_cfg_t       hcfg;
    httgw_callbacks_t cbs;
    pcap_ctx_t        pcfg;
    int               rc;
    int               exit_code = 0;
    int               argi      = 0;
    int               i;

    (void)argc;

    /* 위치 인자와 `-key=value` 형태를 모두 허용해 최소 설정만 읽는다. */
    for (i = 1; argv[i] != NULL; i++) {
        if (strncmp(argv[i], "-iface=", 7) == 0) {
            iface = argv[i] + 7;
            continue;
        }

        if (strncmp(argv[i], "-bpf=", 5) == 0) {
            bpf = argv[i] + 5;
            continue;
        }

        if (strncmp(argv[i], "-engine=", 8) == 0) {
            engine_name = argv[i] + 8;
            continue;
        }

        if ('-' == argv[i][0]) {
            continue;
        }

        argi++;
        if (1 == argi) {
            iface = argv[i];
        } else if (2 == argi) {
            bpf = argv[i];
        }
    }

    if (!iface || !bpf) {
        usage(argv[0]);
        return 1;
    }

    if (engine_name != NULL) {
        char errbuf[64];

        if (engine_set_backend_name(engine_name, errbuf, sizeof(errbuf)) != 0) {
            fprintf(stderr, "invalid engine: %s\n", engine_name);
            usage(argv[0]);
            return 1;
        }
    }

    signal(SIGINT, on_sigint);

    memset(&rt, 0, sizeof(rt));
    memset(&shared, 0, sizeof(shared));

    if (app_log_open(&shared) != 0) {
        fprintf(stderr, "log init failed\n");
        return 1;
    }

    atomic_init(&shared.http_msgs, 0);
    atomic_init(&shared.reqs, 0);
    atomic_init(&shared.packet_count, 0);
    atomic_init(&shared.detect_count, 0);
    atomic_init(&shared.reasm_errs, 0);
    atomic_init(&shared.parse_errs, 0);
    atomic_init(&shared.event_seq, 0);
    atomic_init(&shared.monitor_last_emit_ms, 0);
    shared.pass_log_enabled  = env_flag_enabled("IPS_LOG_PASS", 0);
    shared.debug_log_enabled = env_flag_enabled("IPS_LOG_DEBUG", 0);
    shared.driver_rt         = &rt;
    shared.workers           = NULL;
    shared.worker_count      = 0;

    worker_count = 1;
    if (worker_count < 1) {
        worker_count = 1;
    }
    if (worker_count > MAX_QUEUE_COUNT) {
        worker_count = MAX_QUEUE_COUNT;
    }

    /* pcap capture는 full snaplen/sniffing 모드 기준으로 초기화한다. */
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.dev         = iface;
    pcfg.snaplen     = 65535;
    pcfg.promisc     = 1;
    pcfg.timeout_ms  = 1000;
    pcfg.nonblocking = 0;

    if (driver_init(&rt, worker_count) != 0) {
        fprintf(stderr, "driver_init failed\n");
        app_log_write(&shared, "ERROR", "driver_init failed");
        app_log_close(&shared);
        return 1;
    }

    rc = capture_create(&rt.cc, &pcfg);
    if (rc != 0) {
        fprintf(stderr, "capture_create failed rc=%d\n", rc);
        app_log_write(&shared, "ERROR", "capture_create failed rc=%d", rc);
        driver_destroy(&rt);
        app_log_close(&shared);
        return 1;
    }

    rc = capture_activate(&rt.cc, &pcfg);
    if (rc != 0) {
        fprintf(stderr, "capture_activate failed rc=%d\n", rc);
        app_log_write(&shared, "ERROR", "capture_activate failed rc=%d", rc);
        driver_destroy(&rt);
        app_log_close(&shared);
        return 1;
    }

    if (bpf && bpf[0] != '\0') {
        struct bpf_program fp;

        if (pcap_compile(rt.cc.handle, &fp, bpf, 1, PCAP_NETMASK_UNKNOWN) < 0) {
            fprintf(stderr, "pcap_compile failed: %s\n",
                    pcap_geterr(rt.cc.handle));
            app_log_write(&shared, "ERROR", "pcap_compile failed: %s",
                          pcap_geterr(rt.cc.handle));
            driver_destroy(&rt);
            app_log_close(&shared);
            return 1;
        }

        if (pcap_setfilter(rt.cc.handle, &fp) < 0) {
            fprintf(stderr, "pcap_setfilter failed: %s\n",
                    pcap_geterr(rt.cc.handle));
            app_log_write(&shared, "ERROR", "pcap_setfilter failed: %s",
                          pcap_geterr(rt.cc.handle));
            pcap_freecode(&fp);
            driver_destroy(&rt);
            app_log_close(&shared);
            return 1;
        }

        pcap_freecode(&fp);
    }

    memset(&hcfg, 0, sizeof(hcfg));
    hcfg.max_buffer_bytes = 12U * 1024U * 1024U;
    hcfg.max_body_bytes   = 12U * 1024U * 1024U;
    hcfg.reasm_mode       = REASM_MODE_LATE_START;
    hcfg.verbose          = 0;

    memset(&cbs, 0, sizeof(cbs));
    cbs.on_request = on_request;
    cbs.on_error   = on_error;

    workers      = calloc((size_t)worker_count, sizeof(*workers));
    worker_users = calloc((size_t)worker_count, sizeof(*worker_users));
    if (!workers || !worker_users) {
        fprintf(stderr, "worker alloc failed\n");
        app_log_write(&shared, "ERROR", "worker alloc failed");
        free(workers);
        free(worker_users);
        driver_destroy(&rt);
        app_log_close(&shared);
        return 1;
    }

    shared.workers      = workers;
    shared.worker_count = worker_count;

    /* worker마다 detect engine, httgw, raw RST 송신 컨텍스트를 따로 둔다. */
    for (i = 0; i < worker_count; i++) {
        app_ctx_t *w = &workers[i];

        memset(w, 0, sizeof(*w));
        w->shared = &shared;
        w->det    = detect_engine_create(policy, DETECT_JIT_AUTO);
        if (!w->det) {
            fprintf(stderr, "detect_engine_create failed\n");
            app_log_write(&shared, "ERROR", "detect_engine_create failed");
            destroy_workers(workers, worker_count);
            free(worker_users);
            free(workers);
            driver_destroy(&rt);
            app_log_close(&shared);
            return 1;
        }

        fprintf(stderr, "[DETECT] backend=%s jit=%s\n",
                detect_engine_backend_name(w->det),
                detect_engine_jit_enabled(w->det) ? "on" : "off");
        app_log_write(&shared, "INFO", "event=detect_engine backend=%s jit=%s",
                      detect_engine_backend_name(w->det),
                      detect_engine_jit_enabled(w->det) ? "on" : "off");

        w->gw = httgw_create(&hcfg, &cbs, w);
        if (!w->gw) {
            fprintf(stderr, "httgw_create failed\n");
            app_log_write(&shared, "ERROR", "httgw_create failed");
            destroy_workers(workers, worker_count);
            free(worker_users);
            free(workers);
            driver_destroy(&rt);
            app_log_close(&shared);
            return 1;
        }

        if (tx_ctx_init(&w->rst_tx) != 0) {
            fprintf(stderr, "tx_ctx_init failed (need root?)\n");
            app_log_write(&shared, "ERROR", "tx_ctx_init failed");
            destroy_workers(workers, worker_count);
            free(worker_users);
            free(workers);
            driver_destroy(&rt);
            app_log_close(&shared);
            return 1;
        }

        if (httgw_set_tx(w->gw, &w->rst_tx) != 0) {
            fprintf(stderr, "httgw_set_tx failed\n");
            app_log_write(&shared, "ERROR", "httgw_set_tx failed");
            destroy_workers(workers, worker_count);
            free(worker_users);
            free(workers);
            driver_destroy(&rt);
            app_log_close(&shared);
            return 1;
        }

        worker_users[i] = w;
    }

    driver_set_packet_handler_multi(&rt, on_packet, worker_users,
                                    (size_t)worker_count);

    if (driver_start(&rt) != 0) {
        fprintf(stderr, "driver_start failed\n");
        app_log_write(&shared, "ERROR", "driver_start failed");
        destroy_workers(workers, worker_count);
        free(worker_users);
        free(workers);
        driver_destroy(&rt);
        app_log_close(&shared);
        return 1;
    }

    printf("capture start: iface=%s filter=\"%s\" policy=%s mode=sniffing\n",
           iface, bpf, policy);
    app_log_write(&shared, "INFO",
                  "event=capture_start iface=%s filter=\"%s\" "
                  "policy=%s mode=sniffing pass_log=%d debug_log=%d",
                  iface, bpf, policy, shared.pass_log_enabled,
                  shared.debug_log_enabled);

    /* 메인 스레드는 stop 신호 또는 capture thread 실패만 감시한다. */
    while (!g_stop) {
        if (driver_has_failed(&rt)) {
            rc = driver_last_error(&rt);
            fprintf(stderr, "capture thread failed rc=%d\n", rc);
            app_log_write(&shared, "ERROR", "event=capture_thread_failed rc=%d",
                          rc);
            exit_code = 1;
            break;
        }
        usleep(200U * 1000U);
    }

    driver_stop(&rt);
    driver_destroy(&rt);
    destroy_workers(workers, worker_count);
    free(worker_users);
    free(workers);
    app_log_write(&shared, "INFO", "event=capture_stop");
    app_log_close(&shared);
    return exit_code;
}

/**
 * @brief SIGINT를 수신하면 메인 루프 종료 플래그를 세운다.
 *
 * @param signo 수신한 signal 번호
 */
static void on_sigint(int signo) {
    (void)signo;
    g_stop = 1;
}

/**
 * @brief 완성된 HTTP 요청에 대해 탐지와 차단 후속 동작을 수행한다.
 *
 * `httgw`가 요청 하나를 완성하면 본 콜백이 실행된다. 탐지 결과를 로그로 남기고,
 * threshold를 넘기면 차단 페이지 렌더링과 RST/응답 주입까지 이어서 수행한다.
 *
 * @param flow 정규화된 flow 키
 * @param dir 요청 방향
 * @param msg 완성된 HTTP 메시지
 * @param query query string 포인터
 * @param query_len query string 길이
 * @param user worker app context
 */
static void on_request(const flow_key_t *flow, tcp_dir_t dir,
                       const http_message_t *msg, const char *query,
                       size_t query_len, void *user) {

    app_ctx_t           *app  = (app_ctx_t *)user;
    const IPS_Signature *rule = NULL;
    detect_match_list_t  matches;
    int                  score = 0;
    int                  rc;
    uint64_t             detect_us = 0;
    long                 detect_ms;
    strbuf_t             matched_rules = {0};
    strbuf_t             matched_texts = {0};
    char                 ip[32];
    char                 event_id[48];
    char                 event_ts[40];
    char                *block_page_html = NULL;

    if (!app || !app->shared || !app->det) {
        return;
    }

    (void)query;
    (void)query_len;

    /* HTTP 요청 전체 컨텍스트를 돌며 탐지 엔진을 실행한다. */
    rc        = run_detect(app->det, msg, &score, &rule, &matches, &detect_us);
    detect_ms = (long)((detect_us + 999ULL) / 1000ULL);
    ip4_to_str(flow->src_ip, ip, sizeof(ip));

    if (rc > 0) {
        char from[256];

        if (app_make_event_id(app->shared, event_id, sizeof(event_id)) != 0) {
            snprintf(event_id, sizeof(event_id), "evt-unavailable");
        }
        if (app_make_timestamp(event_ts, sizeof(event_ts)) != 0) {
            snprintf(event_ts, sizeof(event_ts), "1970-01-01T00:00:00.000");
        }

        /* 차단 이벤트를 고유 ID로 기록하고, 같은 이벤트 ID로 차단 페이지를 생성한다. */
        block_page_html = app_render_block_page(g_block_page_template_path,
                                                event_id, event_ts, ip);
        free(app->last_block_page_html);
        app->last_block_page_html = block_page_html;
        snprintf(app->last_event_id, sizeof(app->last_event_id), "%s",
                 event_id);
        snprintf(app->last_event_ts, sizeof(app->last_event_ts), "%s",
                 event_ts);
        snprintf(app->last_client_ip, sizeof(app->last_client_ip), "%s", ip);
        if (block_page_html == NULL) {
            app_log_write(
                app->shared, "ERROR",
                "event=block_page_render_failed event_id=%s template=%s",
                event_id, g_block_page_template_path);
        }

        snprintf(from, sizeof(from), "%.31s %.200s",
                 msg->method[0] ? msg->method : "UNKNOWN",
                 msg->uri[0] ? msg->uri : "/");
        append_match_strings(&matches, &matched_rules, &matched_texts);
        app_log_attack(app->shared, event_id, event_ts,
                       rule ? rule->policy_name : "unknown", "REQUEST", from,
                       rule ? rule->pattern : "unknown", matched_rules.buf,
                       matched_texts.buf, ip, flow->src_port, score,
                       APP_DETECT_THRESHOLD, matches.count, detect_us,
                       detect_ms);
        atomic_fetch_add(&app->shared->detect_count, 1);
        atomic_fetch_add(&app->shared->http_msgs, 1);
        atomic_fetch_add(&app->shared->reqs, 1);
        /* 탐지 로그 기록 후 실제 차단 동작을 수행한다. */
        request_block_action_v2(app, flow, event_id);
    } else if (0 == rc) {
        if (app->shared->pass_log_enabled) {
            char *uri_esc = log_escape_dup(msg->uri[0] ? msg->uri : "/");

            if (uri_esc != NULL) {
                app_log_write(app->shared, "INFO",
                              "event=http_pass where=request "
                              "method=%s uri=\"%s\" src_ip=%s "
                              "src_port=%u detect_ms=%ld",
                              msg->method[0] ? msg->method : "unknown", uri_esc,
                              ip, flow->src_port, detect_ms);
                free(uri_esc);
            }
        }
        atomic_fetch_add(&app->shared->http_msgs, 1);
        atomic_fetch_add(&app->shared->reqs, 1);
    } else {
        char *detail_esc;

        detail_esc = log_escape_dup(detect_engine_last_error(app->det));

        if (detail_esc != NULL) {
            app_log_write(app->shared, "ERROR",
                          "event=detect_error detail=\"%s\"", detail_esc);
            free(detail_esc);
        }
    }

    detect_match_list_free(&matches);
    strbuf_free(&matched_rules);
    strbuf_free(&matched_texts);
    (void)dir;
}

/**
 * @brief `httgw`/`http_stream` 오류를 공통 로그와 통계에 반영한다.
 *
 * @param stage 오류가 발생한 단계
 * @param detail 오류 상세 정보
 * @param user worker app context
 */
static void on_error(const char *stage, const char *detail, void *user) {
    app_ctx_t *app = (app_ctx_t *)user;
    char      *detail_esc;

    if (!app || !app->shared) {
        return;
    }

    detail_esc = log_escape_dup(detail ? detail : "unknown");

    if (detail_esc != NULL) {
        app_log_write(app->shared, "ERROR",
                      "event=stream_error stage=%s detail=\"%s\"",
                      stage ? stage : "unknown", detail_esc);
        free(detail_esc);
    }

    if (stage) {
        if (strcmp(stage, "reasm_ingest") == 0) {
            atomic_fetch_add(&app->shared->reasm_errs, 1);
        }
        if (strcmp(stage, "http_stream_feed") == 0) {
            atomic_fetch_add(&app->shared->parse_errs, 1);
        }
    }
}

/**
 * @brief worker가 dequeue한 raw packet을 `httgw`와 로그 계층에 전달한다.
 *
 * RST 패킷은 세션이 사라지기 전에 snapshot을 미리 보관하고, 이후 패킷을
 * `httgw_ingest_packet()`에 넣어 재조립/HTTP 파싱/탐지로 넘긴다. timeout
 * 기반 stale session 정리를 위해 주기적으로 `httgw_gc()`도 호출한다.
 *
 * @param data 패킷 데이터
 * @param len 패킷 길이
 * @param ts_ns 패킷 캡처 시각(ns)
 * @param user worker app context
 */
static void on_packet(const uint8_t *data, uint32_t len, uint64_t ts_ns,
                      void *user) {
    app_ctx_t                   *app   = (app_ctx_t *)user;
    uint64_t                     ts_ms = ts_ns / 1000000ULL;
    flow_key_t                   flow;
    tcp_dir_t                    dir;
    uint8_t                      flags = 0;
    httgw_sess_snapshot_t        pre_snap;
    const httgw_sess_snapshot_t *fallback_snap = NULL;

    /* wire에서 RST가 관측될 때 사용할 fallback snapshot을 미리 잡아 둔다. */
    if (app && app->gw &&
        parse_flow_dir_and_flags(data, len, &flow, &dir, &flags) &&
        (flags & TCP_RST)) {
        if (httgw_get_session_snapshot(app->gw, &flow, &pre_snap) == 0) {
            rst_log_cache_put(app, &flow, &pre_snap, ts_ms);
            fallback_snap = &pre_snap;
        } else {
            fallback_snap = rst_log_cache_get(app, &flow, ts_ms);
        }
    }

    if (app && app->gw) {
        atomic_fetch_add(&app->shared->packet_count, 1);

        int rc = httgw_ingest_packet(app->gw, data, len, ts_ms);

        /* idle session/reassembly state가 무한히 쌓이지 않도록 주기 GC를 돈다. */
        if (0 == app->last_gc_ms || ts_ms - app->last_gc_ms >= 1000ULL) {
            httgw_gc(app->gw, ts_ms);
            app->last_gc_ms = ts_ms;
        }

        /* ingest 결과는 무시/입력 오류만 로깅하고, 정상 경로는 후속 콜백에서 처리한다. */
        if (rc == 0) {
            app_log_write(app->shared, "DEBUG",
                          "event=packet_ignored len=%u ts_ms=%llu", len,
                          (unsigned long long)ts_ms);
        } else if (rc == -1) {
            app_log_write(app->shared, "ERROR",
                          "event=httgw_ingest_invalid_arg len=%u ts_ms=%llu",
                          len, (unsigned long long)ts_ms);
        }

        /* 디버그 로그가 켜진 경우 TCP 라인 로그용 파싱을 별도로 수행한다. */
        log_tcp_packet_line(app, data, len, fallback_snap);
        maybe_emit_monitor_stats(app, ts_ms);
    }

    (void)dir;
}

/**
 * @brief 주기적으로 monitor.log에 성능/상태 통계를 기록한다.
 *
 * event 단위 로그가 아니라 pps, req/s, detect/s, queue depth, 재조립 순서 통계의
 * 누적/초당 변화를 1초 주기로 한 줄에 기록한다.
 *
 * @param app worker app context
 * @param ts_ms 현재 패킷 시각(ms)
 */
static void maybe_emit_monitor_stats(app_ctx_t *app, uint64_t ts_ms) {
    app_shared_t     *shared;
    uint_fast64_t     last_emit_ms;
    uint_fast64_t     expected;
    uint64_t          interval_ms;
    uint64_t          packets;
    uint64_t          reqs;
    uint64_t          detects;
    uint64_t          pps;
    uint64_t          req_ps;
    uint64_t          detect_ps;
    uint64_t          queue_depth = 0;
    reasm_stats_t     total_reasm = {0};
    uint64_t          reasm_in_order_ps;
    uint64_t          reasm_out_of_order_ps;
    uint64_t          reasm_trimmed_ps;

    if (NULL == app || NULL == app->shared) {
        return;
    }

    shared = app->shared;
    if (NULL == shared->monitor_log_fp || NULL == shared->driver_rt ||
        NULL == shared->workers || shared->worker_count <= 0) {
        return;
    }

    last_emit_ms = atomic_load_explicit(&shared->monitor_last_emit_ms,
                                        memory_order_relaxed);
    if (0 != last_emit_ms && ts_ms - (uint64_t)last_emit_ms < 1000ULL) {
        return;
    }

    expected = last_emit_ms;
    if (0 == atomic_compare_exchange_strong_explicit(
                 &shared->monitor_last_emit_ms, &expected, ts_ms,
                 memory_order_relaxed, memory_order_relaxed)) {
        return;
    }

    interval_ms = (0 != last_emit_ms && ts_ms > (uint64_t)last_emit_ms)
                      ? (ts_ms - (uint64_t)last_emit_ms)
                      : 1000ULL;

    packets =
        atomic_load_explicit(&shared->packet_count, memory_order_relaxed);
    reqs = atomic_load_explicit(&shared->reqs, memory_order_relaxed);
    detects =
        atomic_load_explicit(&shared->detect_count, memory_order_relaxed);

    for (int i = 0; i < shared->worker_count; i++) {
        reasm_stats_t rs = {0};

        if (NULL != shared->workers[i].gw &&
            0 == httgw_get_reasm_stats(shared->workers[i].gw, &rs)) {
            total_reasm.in_order_pkts += rs.in_order_pkts;
            total_reasm.out_of_order_pkts += rs.out_of_order_pkts;
            total_reasm.trimmed_pkts += rs.trimmed_pkts;
        }
    }

    for (uint32_t i = 0; i < shared->driver_rt->queues.qcount; i++) {
        packet_ring_t *ring = &shared->driver_rt->queues.q[i];
        uint32_t       head;
        uint32_t       tail;

        head = atomic_load_explicit(&ring->head, memory_order_relaxed);
        tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
        queue_depth += (uint64_t)(tail - head);
    }

    pps =
        ((packets - shared->monitor_prev_packets) * 1000ULL) / interval_ms;
    req_ps = ((reqs - shared->monitor_prev_reqs) * 1000ULL) / interval_ms;
    detect_ps =
        ((detects - shared->monitor_prev_detects) * 1000ULL) / interval_ms;
    reasm_in_order_ps =
        ((total_reasm.in_order_pkts - shared->monitor_prev_reasm_in_order) *
         1000ULL) /
        interval_ms;
    reasm_out_of_order_ps =
        ((total_reasm.out_of_order_pkts -
          shared->monitor_prev_reasm_out_of_order) *
         1000ULL) /
        interval_ms;
    reasm_trimmed_ps =
        ((total_reasm.trimmed_pkts - shared->monitor_prev_reasm_trimmed) *
         1000ULL) /
        interval_ms;

    app_monitor_write(
        shared,
        "event=stats interval_ms=%llu worker_count=%d "
        "pps=%llu req_ps=%llu detect_ps=%llu queue_depth=%llu "
        "reasm_in_order_ps=%llu reasm_out_of_order_ps=%llu "
        "reasm_trimmed_ps=%llu total_packets=%llu total_reqs=%llu "
        "total_detect=%llu total_reasm_in_order=%llu "
        "total_reasm_out_of_order=%llu total_reasm_trimmed=%llu",
        (unsigned long long)interval_ms, shared->worker_count,
        (unsigned long long)pps, (unsigned long long)req_ps,
        (unsigned long long)detect_ps, (unsigned long long)queue_depth,
        (unsigned long long)reasm_in_order_ps,
        (unsigned long long)reasm_out_of_order_ps,
        (unsigned long long)reasm_trimmed_ps, (unsigned long long)packets,
        (unsigned long long)reqs, (unsigned long long)detects,
        (unsigned long long)total_reasm.in_order_pkts,
        (unsigned long long)total_reasm.out_of_order_pkts,
        (unsigned long long)total_reasm.trimmed_pkts);

    shared->monitor_prev_packets           = packets;
    shared->monitor_prev_reqs              = reqs;
    shared->monitor_prev_detects           = detects;
    shared->monitor_prev_reasm_in_order    = total_reasm.in_order_pkts;
    shared->monitor_prev_reasm_out_of_order =
        total_reasm.out_of_order_pkts;
    shared->monitor_prev_reasm_trimmed = total_reasm.trimmed_pkts;
}

/**
 * @brief worker별 런타임 자원을 정리한다.
 *
 * detect engine, httgw, 차단 페이지 캐시, raw RST 송신 컨텍스트를 worker 단위로
 * 해제한다.
 *
 * @param workers worker 배열
 * @param count worker 개수
 */
static void destroy_workers(app_ctx_t *workers, int count) {
    int i;

    if (!workers || count <= 0) {
        return;
    }

    for (i = 0; i < count; i++) {
        app_ctx_t *w = &workers[i];

        if (w->det) {
            detect_engine_destroy(w->det);
            w->det = NULL;
        }

        if (w->gw) {
            httgw_destroy(w->gw);
            w->gw = NULL;
        }

        free(w->last_block_page_html);
        w->last_block_page_html = NULL;

        tx_ctx_destroy(&w->rst_tx);
    }
}

/**
 * @brief 명령행 사용법을 출력한다.
 *
 * @param prog 실행 파일 이름
 */
static void usage(const char *prog) {
    fprintf(stderr,
            "usage: %s -iface=<iface> -bpf=<filter> "
            "[-engine=pcre2|hs]\n",
            prog ? prog : "main");
}

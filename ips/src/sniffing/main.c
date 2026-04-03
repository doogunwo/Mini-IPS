/**
 * @file main.c
 * @brief Mini-IPS 프로세스 초기화와 메인 콜백 연결
 *
 * 애플리케이션 진입점으로서 capture, driver, worker별 detect/httgw,
 * 로그, 차단 페이지 경로를 조립한 뒤 패킷 처리 콜백 체인을 연결한다.
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
#include "httgw.h"
#include "logging.h"
#include "net_compat.h"

static volatile sig_atomic_t g_stop = 0; /**< stop signal flag */

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
 * @brief 환경변수 두개 중에서 먼저 비어있지 않은 값 반환하는 함수
 * 환경변수 alias를 지원하려는 헬퍼함수
 * @param first 환경변수 첫번째
 * @param second 환경변수 두번째
 * @return const char*
 */
static const char *first_nonempty_env(const char *first, const char *second) {
    const char *value;

    if (NULL != first) {
        value = getenv(first);
        if (NULL != value && '\0' != value[0]) {
            return value;
        }
    }
    if (NULL != second) {
        value = getenv(second);
        if (NULL != value && '\0' != value[0]) {
            return value;
        }
    }
    return NULL;
}

/* 26-04-03 추가 내용: detect 시점 요청 길이를 로그에 남기기 위한 계산 헬퍼 */
static size_t request_len_for_detect_log(const http_message_t *msg) {
    size_t request_line_len = 0U;

    if (NULL == msg) {
        return 0U;
    }

    if (msg->is_request) {
        request_line_len = strlen(msg->method) + 1U + strlen(msg->uri) + 1U +
                           strlen(msg->version) + 2U;
    }

    return request_line_len + msg->headers_raw_len + 2U + msg->body_len;
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
    int                  ret;
    uint64_t             detect_us = 0;
    long                 detect_ms;
    strbuf_t             matched_rules = {0};
    strbuf_t             matched_texts = {0};
    char                 ip[32];
    char                 event_id[48];
    char                 event_ts[40];

    /*
     * on_request는 이미 "HTTP 메시지 하나가 완성된 뒤" 호출되는 상위 정책
     * 콜백이다. 여기서는 더 이상 패킷 단위 처리를 하지 않고,
     * 완성된 요청을 탐지/로그/차단 관점에서만 다룬다.
     */

    /* 널 체크 */
    if (!app || !app->shared || !app->det) {
        return;
    }

    /*
     * run_detect는 내부에서
     * - URI
     * - ARGS_NAMES
     * - ARGS
     * - REQUEST_HEADERS
     * - REQUEST_BODY
     * 를 순회하며 컨텍스트별 매치를 수집하고 score를 계산한다.
     */
    rc = run_detect(app->det, msg, &score, query, query_len, &rule, &matches,
                    &detect_us);
    detect_ms = (long)((detect_us + 999ULL) / 1000ULL);
    /* flow->src_ip에 들어있는 ipv4 주소를 사람이 읽을 수 있는 문자열로 바꾸는
     * 함수이다. */
    ip4_to_str(flow->src_ip, ip, sizeof(ip));
    app_log_detect_time(app->shared, NULL, ip, flow->src_port, detect_us,
                        detect_ms, request_len_for_detect_log(msg));

    if (0 > rc) {
        char *detail_esc;
        /* detect 엔진이 보관한 오류 문자열을 로그 문자열로 복사 */
        detail_esc = log_escape_dup(detect_engine_last_error(app->det));
        if (NULL != detail_esc) {
            app_log_write(app->shared, "ERROR",
                          "event=detect_error detail=\"%s\"", detail_esc);
            free(detail_esc);
        }
    } else if (score >= APP_DETECT_THRESHOLD) {
        char from[256];
        /* 이번 차단 이벤트를 식별할 고유 event_id를 생성한다. */
        ret = app_make_event_id(app->shared, event_id, sizeof(event_id));
        /* 이벤트 아이디 생성 실패해도 후속 로직 깨지지않게 fallback 문자열을
         * 넣는다. */
        if (0 != ret) {
            memcpy(event_id, "evt-unavailable", sizeof("evt-unavailable"));
        }
        /* 차단 이벤트 문자열 생성하고 실패시 고정 fallback을 넣는다. */
        ret = app_make_timestamp(event_ts, sizeof(event_ts));
        if (0 != ret) {
            memcpy(event_ts, "1970-01-01T00:00:00.000",
                   sizeof("1970-01-01T00:00:00.000"));
        }

        /* 로그용 요청 출처 문자열을 "METHOD URI" 형태로 길이 제한해 조합한다.
         */
        snprintf(from, sizeof(from), "%.31s %.200s",
                 msg->method[0] ? msg->method : "UNKNOWN",
                 msg->uri[0] ? msg->uri : "/");
        /* 매치된 룰 이름들과 매치 텍스트를 로그 기록용 문자열로 직렬화한다. */
        append_match_strings(&matches, &matched_rules, &matched_texts);
        /* 탐지 이벤트를 구조화 로그 한 줄로 기록한다. */
        app_log_attack(app->shared, event_id, event_ts,
                       rule ? rule->policy_name : "unknown", "REQUEST", from,
                       rule ? rule->pattern : "unknown", matched_rules.buf,
                       matched_texts.buf, ip, flow->src_port, score,
                       APP_DETECT_THRESHOLD, matches.count, detect_us,
                       detect_ms);
        /* 차단 임계치를 넘긴 탐지 이벤트 수를 증가시킨다. */
        atomic_fetch_add(&app->shared->detect_count, 1);
        /* 처리 완료된 HTTP 메시지 수를 증가시킨다. */
        atomic_fetch_add(&app->shared->http_msgs, 1);
        /* 처리 완료된 HTTP 요청 수를 증가시킨다. */
        atomic_fetch_add(&app->shared->reqs, 1);
        /* 현재 차단 경로는 양방향 RST 요청만 수행한다. */
        request_block_action_v2(app, flow, dir, event_id);
    } else {
        /*
         * threshold 미만이면 허용 경로다.
         * 필요 시 pass 로그만 남기고, 탐지 수치는 올리지 않는다.
         */
        if (app->shared->pass_log_enabled) {
            /* URI를 구조화 로그에 안전하게 넣기 위해 escape 복사본을 만든다. */
            char *uri_esc = log_escape_dup(msg->uri[0] ? msg->uri : "/");

            /* escape에 성공한 경우에만 허용 요청 로그를 기록한다. */
            if (NULL != uri_esc) {
                /* 탐지 임계치 미만으로 통과한 HTTP 요청 한 건을 INFO 로그로
                 * 남긴다. */
                app_log_write(app->shared, "INFO",
                              "event=http_pass where=request "
                              "method=%s uri=\"%s\" src_ip=%s "
                              "src_port=%u detect_ms=%ld",
                              msg->method[0] ? msg->method : "unknown", uri_esc,
                              ip, flow->src_port, detect_ms);

                /* 로그 기록 후 URI escape 임시 버퍼를 해제한다. */
                free(uri_esc);
            }
        }

        /* 처리 완료된 HTTP 메시지 수를 증가시킨다. */
        atomic_fetch_add(&app->shared->http_msgs, 1);

        /* 처리 완료된 HTTP 요청 수를 증가시킨다. */
        atomic_fetch_add(&app->shared->reqs, 1);
    }

    /* run_detect가 쌓은 동적 match 리스트와 로그 조합 버퍼를 정리한다. */
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
    /* worker app context 포인터 */
    app_ctx_t *app = (app_ctx_t *)user;
    /* 로그용 detail escape 복사본 */
    char *detail_esc;
    /* stage 비교 결과 */
    int ret;

    /* 공유 상태 유효성 검사 */
    if (!app || !app->shared) {
        return;
    }

    /* detail escape */
    detail_esc = log_escape_dup(detail ? detail : "unknown");

    /* stream_error 로그 기록 */
    if (NULL != detail_esc) {
        app_log_write(app->shared, "ERROR",
                      "event=stream_error stage=%s detail=\"%s\"",
                      stage ? stage : "unknown", detail_esc);
        /* 임시 escape 버퍼 해제 */
        free(detail_esc);
    }

    /* stage별 오류 카운터 갱신 */
    if (stage) {
        ret = strcmp(stage, "reasm_ingest");
        if (0 == ret) {
            atomic_fetch_add(&app->shared->reasm_errs, 1);
        }
        ret = strcmp(stage, "http_stream_feed");
        if (0 == ret) {
            atomic_fetch_add(&app->shared->parse_errs, 1);
        }
    }
}

/* --------------------------- packet callback / monitor
 * --------------------------- */

/**
 * @brief 주기적으로 monitor.log에 성능/상태 통계를 기록한다.
 *
 * event 단위 로그가 아니라 pps, req/s, detect/s, queue depth, 재조립 순서
 * 통계의 누적/초당 변화를 1초 주기로 한 줄에 기록한다.
 *
 * @param app worker app context
 * @param ts_ms 현재 패킷 시각(ms)
 */
static void maybe_emit_monitor_stats(app_ctx_t *app, uint64_t ts_ms) {
    app_shared_t *shared;
    uint_fast64_t last_emit_ms;
    uint_fast64_t expected;
    uint64_t      interval_ms;
    uint64_t      packets;
    uint64_t      reqs;
    uint64_t      detects;
    uint64_t      pps;
    uint64_t      req_ps;
    uint64_t      detect_ps;
    uint64_t      queue_depth = 0;
    reasm_stats_t total_reasm = {0};
    uint64_t      reasm_in_order_ps;
    uint64_t      reasm_out_of_order_ps;
    uint64_t      reasm_trimmed_ps;
    int           exchanged;
    int           ret;

    /*
     * monitor 출력은 패킷마다 찍지 않고 1초 단위로 rate를 계산해 기록한다.
     * compare_exchange를 써서 여러 worker가 있더라도 한 주기에는 한 번만
     * 찍히게 한다.
     */
    if (NULL == app || NULL == app->shared) {
        return;
    }

    shared = app->shared;
    /* monitor 출력에 필요한 공유 상태나 파일 핸들이 없으면 기록하지 않는다. */
    if (NULL == shared->monitor_log_fp || NULL == shared->driver_rt ||
        NULL == shared->workers || shared->worker_count <= 0) {
        return;
    }

    /* 마지막 출력 시각을 읽고, 아직 1초가 지나지 않았으면 이번 호출은 건너뛴다.
     */
    last_emit_ms = atomic_load_explicit(&shared->monitor_last_emit_ms,
                                        memory_order_relaxed);
    if (0 != last_emit_ms && 1000ULL > (ts_ms - (uint64_t)last_emit_ms)) {
        return;
    }

    /* 이번 시각으로 출력 권한을 선점한 worker만 실제 monitor 로그를 작성한다.
     */
    expected  = last_emit_ms;
    exchanged = atomic_compare_exchange_strong_explicit(
        &shared->monitor_last_emit_ms, &expected, ts_ms, memory_order_relaxed,
        memory_order_relaxed);
    if (0 == exchanged) {
        return;
    }

    /* 직전 출력 시점과의 간격을 구해 초당 rate 환산의 기준 구간으로 사용한다.
     */
    interval_ms = (0 != last_emit_ms && ts_ms > (uint64_t)last_emit_ms)
                      ? (ts_ms - (uint64_t)last_emit_ms)
                      : 1000ULL;

    /* 패킷/요청/탐지 누적 카운터의 현재 스냅샷을 읽는다. */
    packets = atomic_load_explicit(&shared->packet_count, memory_order_relaxed);
    reqs    = atomic_load_explicit(&shared->reqs, memory_order_relaxed);
    detects = atomic_load_explicit(&shared->detect_count, memory_order_relaxed);

    /*
     * 재조립 통계는 worker별 httgw가 따로 들고 있으므로,
     * 모니터 로그에서는 전 worker 값을 합산한 뒤 초당 rate로 환산한다.
     */
    for (int i = 0; i < shared->worker_count; i++) {
        reasm_stats_t rs = {0};

        ret = -1;
        if (NULL != shared->workers[i].gw) {
            ret = httgw_get_reasm_stats(shared->workers[i].gw, &rs);
        }
        if (0 == ret) {
            /* worker별 재조립 누적치를 전체 합계에 더한다. */
            total_reasm.in_order_pkts += rs.in_order_pkts;
            total_reasm.out_of_order_pkts += rs.out_of_order_pkts;
            total_reasm.trimmed_pkts += rs.trimmed_pkts;
        }
    }

    /* queue depth는 각 worker queue의 tail-head 차이를 더해 계산한다. */
    for (uint32_t i = 0; i < shared->driver_rt->queues.qcount; i++) {
        packet_ring_t *ring = &shared->driver_rt->queues.q[i];
        uint32_t       head;
        uint32_t       tail;

        head = atomic_load_explicit(&ring->head, memory_order_relaxed);
        tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
        /* tail-head 차이를 현재 queue 적체량으로 보고 전체 depth에 합산한다. */
        queue_depth += (uint64_t)(tail - head);
    }

    /* 직전 누적치와 현재 누적치의 차이를 interval_ms 기준 초당 처리량으로
     * 환산한다. */
    pps    = ((packets - shared->monitor_prev_packets) * 1000ULL) / interval_ms;
    req_ps = ((reqs - shared->monitor_prev_reqs) * 1000ULL) / interval_ms;
    detect_ps =
        ((detects - shared->monitor_prev_detects) * 1000ULL) / interval_ms;
    reasm_in_order_ps =
        ((total_reasm.in_order_pkts - shared->monitor_prev_reasm_in_order) *
         1000ULL) /
        interval_ms;
    reasm_out_of_order_ps = ((total_reasm.out_of_order_pkts -
                              shared->monitor_prev_reasm_out_of_order) *
                             1000ULL) /
                            interval_ms;
    reasm_trimmed_ps =
        ((total_reasm.trimmed_pkts - shared->monitor_prev_reasm_trimmed) *
         1000ULL) /
        interval_ms;

    /* 계산한 rate와 누적치를 monitor.log 한 줄로 기록한다. */
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

    /* 다음 주기 rate 계산을 위해 이번 누적치를 직전값으로 저장한다. */
    shared->monitor_prev_packets            = packets;
    shared->monitor_prev_reqs               = reqs;
    shared->monitor_prev_detects            = detects;
    shared->monitor_prev_reasm_in_order     = total_reasm.in_order_pkts;
    shared->monitor_prev_reasm_out_of_order = total_reasm.out_of_order_pkts;
    shared->monitor_prev_reasm_trimmed      = total_reasm.trimmed_pkts;
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
    int                          ret;

    /*
     * 차단 이후 wire에서 관측되는 RST는 세션이 이미 사라진 뒤일 수 있다.
     * 그래서 ingest 전에 snapshot을 미리 저장해 두면, 나중에 로그에서
     * seq/ack를 더 잘 해석할 수 있다.
     */
    ret = 0;
    if (NULL != app && NULL != app->gw) {
        ret = parse_flow_dir_and_flags(data, len, &flow, &dir, &flags);
    }
    if (NULL != app && NULL != app->gw && 0 != ret && 0 != (flags & TCP_RST)) {
        ret = httgw_get_session_snapshot(app->gw, &flow, &pre_snap);
        if (0 == ret) {
            rst_log_cache_put(app, &flow, &pre_snap, ts_ms);
            fallback_snap = &pre_snap;
        } else {
            fallback_snap = rst_log_cache_get(app, &flow, ts_ms);
        }
    }

    if (app && app->gw) {
        atomic_fetch_add(&app->shared->packet_count, 1);

        /*
         * raw packet은 여기서 HTTP 처리 파이프라인으로 들어간다.
         * 이후 흐름은
         *   httgw_ingest_packet()
         *     -> reasm
         *     -> http_stream
         *     -> on_request()#request callback 함수
         * 다.
         */
        int rc = httgw_ingest_packet(app->gw, data, len, ts_ms);

        /* idle session, reassembly state가 무한히 쌓이지 않도록 주기 GC를 돈다.
         */
        if (0 == app->last_gc_ms || 1000ULL <= (ts_ms - app->last_gc_ms)) {
            httgw_gc(app->gw, ts_ms);
            app->last_gc_ms = ts_ms;
        }

        /* ingest 실패만 오류로 기록하고, 정상 경로는 후속 콜백에서 처리한다. */
        if (0 > rc) {
            app_log_write(app->shared, "ERROR",
                          "event=httgw_ingest_failed len=%u ts_ms=%llu", len,
                          (unsigned long long)ts_ms);
        }

        /*
         * 기능 경로와 별개로, 운영 관찰을 위해 패킷 단위 TCP 로그와 모니터
         * 통계를 병행 기록한다.
         */
        log_tcp_packet_line(app, data, len, fallback_snap);
        maybe_emit_monitor_stats(app, ts_ms);
    }

    (void)dir;
}

/**
 * @brief worker별 런타임 자원을 정리한다.
 *
 * detect engine, httgw, raw RST 송신 컨텍스트를 worker 단위로
 * 해제한다.
 *
 * @param workers worker 배열
 * @param count worker 개수
 */
static void destroy_workers(app_ctx_t *workers, int count) {
    int i;

    if (NULL == workers || 0 >= count) {
        return;
    }

    /*
     * worker가 가진 자원은 서로 독립적이므로 worker 단위로 깨끗이 회수한다.
     * detect -> httgw -> tx context 순으로 정리한다.
     */
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
            "[-engine=pcre2|hs]\n"
            "env: IFACE|IPS_IFACE, BPF|IPS_BPF, ENGINE|IPS_ENGINE\n",
            prog ? prog : "main");
}

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

/*
 * main.c에서 중요한 호출 흐름은 아래와 같다.
 *
 * main()
 *   -> driver/libpcap 초기화
 *   -> worker별 detect + httgw 초기화
 *   -> driver_start()
 *   -> capture thread가 raw packet을 worker queue로 분배
 *   -> worker thread가 on_packet() 호출
 *   -> on_packet() -> httgw_ingest_packet()
 *   -> reasm -> http_stream -> on_request()
 *   -> on_request() -> run_detect() -> 차단/로그
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
    int               ret;

    /* argc는 현재 구현에서 별도 검증에 쓰지 않으므로 명시적으로 무시한다. */
    (void)argc;

    /*
     * 기본 설정은 환경변수에서 먼저 읽고,
     * 이후 명령행 인자로 덮어쓰는 순서로 처리한다.
     * 이렇게 하면 시스템 서비스/스크립트 환경과 수동 실행 환경을 모두 지원할 수
     * 있다.
     */
    iface       = first_nonempty_env("IFACE", "IPS_IFACE");
    bpf         = first_nonempty_env("BPF", "IPS_BPF");
    engine_name = first_nonempty_env("ENGINE", "IPS_ENGINE");

    /* 위치 인자와 `-key=value` 형태를 모두 허용해 최소 설정만 읽는다. */
    for (i = 1; argv[i] != NULL; i++) {
        ret = strncmp(argv[i], "-iface=", 7);
        if (0 == ret) {
            iface = argv[i] + 7;
            continue;
        }

        ret = strncmp(argv[i], "-bpf=", 5);
        if (0 == ret) {
            bpf = argv[i] + 5;
            continue;
        }

        ret = strncmp(argv[i], "-engine=", 8);
        if (0 == ret) {
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

    if (NULL != engine_name) {
        char errbuf[64];

        /* detect/engine 계층이 쓸 backend를 프로세스 시작 시점에 확정한다. */
        ret = engine_set_backend_name(engine_name, errbuf, sizeof(errbuf));
        if (0 != ret) {
            fprintf(stderr, "invalid engine: %s\n", engine_name);
            usage(argv[0]);
            return 1;
        }
    }

    /*
     * signal() 대신 sigaction()을 사용해 시그널 핸들러 동작을 명시적으로
     * 설정한다. 장기 실행 프로세스에서 더 예측 가능한 선택이다.
     */
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = on_sigint;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        /* sigaction은 어떤 핸들러, 시그널, 플래그를 쓸지 명시적으로 설정
         * 가능하다. */
        sigaction(SIGINT, &sa, NULL);
    }

    memset(&rt, 0, sizeof(rt));
    memset(&shared, 0, sizeof(shared));

    /* 로그 파일과 monitor 로그 파일을 연다. 이후 오류도 모두 이 채널로 남긴다.
     */
    ret = app_log_open(&shared);
    if (0 != ret) {
        fprintf(stderr, "log init failed\n");
        return 1;
    }

    /*
     * shared는 worker 간 공용 통계/로그 상태다.
     * 여기서부터는 worker가 실시간으로 올리는 누적값들을 모두 0에서 시작한다.
     */
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

    /*
     * 현재 구현은 worker_count=1로 고정하지만,
     * queue/driver 계층은 다중 worker까지 확장 가능한 형태라 범위 보정 로직은
     * 남겨둔다.
     */
    worker_count = 1;
    if (1 > worker_count) {
        worker_count = 1;
    }
    if (worker_count > MAX_QUEUE_COUNT) {
        worker_count = MAX_QUEUE_COUNT;
    }

    /*
     * capture 설정은 "패킷을 원본 그대로 충분히 확보해 재조립/HTTP 파싱에
     * 넘긴다"는 목적에 맞춘다.
     * snaplen은 링버퍼 슬롯 크기와 맞춰 두고, promiscuous mode를 켠다.
     */
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.dev         = iface;
    pcfg.snaplen     = 2032;
    pcfg.promisc     = 1;
    pcfg.timeout_ms  = 100;
    pcfg.nonblocking = 0;

    /*
     * driver는 capture thread + worker thread + queue set을 관리하는 최상위
     * 실행기다. 이후 capture_create/activate는 rt.cc 내부 libpcap 핸들을
     * 실제로 준비하는 단계다.
     */
    ret = driver_init(&rt, worker_count);
    if (0 != ret) {
        fprintf(stderr, "driver_init failed\n");
        app_log_write(&shared, "ERROR", "driver_init failed");
        app_log_close(&shared);
        return 1;
    }

    rc = capture_create(&rt.cc, &pcfg);
    if (0 != rc) {
        fprintf(stderr, "capture_create failed rc=%d\n", rc);
        app_log_write(&shared, "ERROR", "capture_create failed rc=%d", rc);
        driver_destroy(&rt);
        app_log_close(&shared);
        return 1;
    }

    rc = capture_activate(&rt.cc, &pcfg);
    if (0 != rc) {
        fprintf(stderr, "capture_activate failed rc=%d\n", rc);
        app_log_write(&shared, "ERROR", "capture_activate failed rc=%d", rc);
        driver_destroy(&rt);
        app_log_close(&shared);
        return 1;
    }

    /*
     * BPF 필터는 가능한 한 커널/libpcap 단계에서 불필요한 패킷을 줄이기 위한
     * 첫 번째 필터다. 실패하면 트래픽 범위가 달라지므로 즉시 종료한다.
     */
    if (NULL != bpf && '\0' != bpf[0]) {
        struct bpf_program fp;

        ret = pcap_compile(rt.cc.handle, &fp, bpf, 1, PCAP_NETMASK_UNKNOWN);
        if (0 > ret) {
            fprintf(stderr, "pcap_compile failed: %s\n",
                    pcap_geterr(rt.cc.handle));
            app_log_write(&shared, "ERROR", "pcap_compile failed: %s",
                          pcap_geterr(rt.cc.handle));
            driver_destroy(&rt);
            app_log_close(&shared);
            return 1;
        }

        ret = pcap_setfilter(rt.cc.handle, &fp);
        if (0 > ret) {
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

    /*
     * httgw/http_stream 계층의 메모리 한도와 재조립 정책을 설정한다.
     * 여기서 정한 값이 worker별 HTTP 처리 파이프라인 기본 정책이 된다.
     */
    memset(&hcfg, 0, sizeof(hcfg));
    hcfg.max_buffer_bytes = 12U * 1024U * 1024U;
    hcfg.max_body_bytes   = 12U * 1024U * 1024U;
    hcfg.reasm_mode       = REASM_MODE_LATE_START;
    hcfg.verbose          = 0;

    /*
     * httgw는 요청이 완성되면 on_request, 재조립/파싱 오류가 나면 on_error를
     * 호출한다. 즉 main.c는 여기서 상위 정책 콜백을 연결한다.
     */
    memset(&cbs, 0, sizeof(cbs));
    /*
     * on_request: 정상적으로 완성된 HTTP 요청을 받아 탐지와 차단을 수행함
     * on_error: 재조립/파싱 과정의 오류를 받아 로그와 통계에 반영
     */
    cbs.on_request = on_request;
    cbs.on_error   = on_error;

    /* 현재 구조상으로는 worker_count = 1 고정이라서 단일 포인터 방식으로
     * 충분하다. */
    /* worker별 독립 context를 따로 두어 detect/gateway 상태를 분리한다. */
    /* workers: 실제 worker 상태 구조체 배열 */
    workers = (app_ctx_t *)malloc((size_t)worker_count * sizeof(*workers));
    /* worker_users는 그 worker 들을 가르키는 user 포인터 배열이다. */
    worker_users =
        (void **)malloc((size_t)worker_count * sizeof(*worker_users));
    if (NULL == workers || NULL == worker_users) {
        fprintf(stderr, "worker alloc failed\n");
        app_log_write(&shared, "ERROR", "worker alloc failed");
        free(workers);
        free(worker_users);
        driver_destroy(&rt);
        app_log_close(&shared);
        return 1;
    }
    memset(workers, 0, (size_t)worker_count * sizeof(*workers));
    memset(worker_users, 0, (size_t)worker_count * sizeof(*worker_users));

    shared.workers      = workers;
    shared.worker_count = worker_count;

    /*
     * worker는 각자
     * - detect engine
     * - httgw(= reasm + http_stream + 세션 상태)
     * - raw RST 송신 컨텍스트
     * 를 독립적으로 가진다.
     * 이렇게 해야 패킷 처리 경로가 서로 상태를 덜 공유하고, 이후 N-worker
     * 확장도 가능해진다.
     */
    for (i = 0; i < worker_count; i++) {
        app_ctx_t *w = &workers[i];

        memset(w, 0, sizeof(*w));
        w->shared = &shared;
        /* 정책별 룰 집합과 backend runtime을 가지는 탐지 엔진 생성 */
        w->det = detect_engine_create(policy, DETECT_JIT_AUTO);
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

        /*
         * gw는 raw packet에서 HTTP 메시지까지 올려주는 중간 계층이며,
         * user 포인터로 worker 자신을 넘겨 이후 on_request/on_error에서 다시
         * app_ctx를 바로 참조할 수 있게 한다.
         */
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

        /*
         * 차단 시 RST/403 주입을 위해 raw L3 송신 소켓을 worker마다 준비한다.
         * 이 단계가 실패하면 탐지는 가능해도 차단이 불완전해지므로 시작을
         * 중단한다.
         */
        ret = tx_ctx_init(&w->rst_tx);
        if (0 != ret) {
            fprintf(stderr, "tx_ctx_init failed (need root?)\n");
            app_log_write(&shared, "ERROR", "tx_ctx_init failed");
            destroy_workers(workers, worker_count);
            free(worker_users);
            free(workers);
            driver_destroy(&rt);
            app_log_close(&shared);
            return 1;
        }

        ret = httgw_set_tx(w->gw, &w->rst_tx);
        if (0 != ret) {
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

    /*
     * capture->worker->on_packet 체인의 마지막 목적지를 등록한다.
     * 이후 worker thread는 dequeue한 패킷을 on_packet()으로 넘긴다.
     */
    driver_set_packet_handler_multi(&rt, on_packet, worker_users,
                                    (size_t)worker_count);

    /* capture thread와 worker thread를 실제로 올리는 시점 */
    ret = driver_start(&rt);
    if (0 != ret) {
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

    /*
     * 메인 스레드는 data path에 직접 참여하지 않는다.
     * 여기서는
     * - SIGINT에 의한 정상 종료 요청
     * - capture/worker 계층의 치명적 실패
     * 만 감시한다.
     */
    while (!g_stop) {
        ret = driver_has_failed(&rt);
        if (0 != ret) {
            rc = driver_last_error(&rt);
            fprintf(stderr, "capture thread failed rc=%d\n", rc);
            app_log_write(&shared, "ERROR", "event=capture_thread_failed rc=%d",
                          rc);
            exit_code = 1;
            break;
        }
        usleep(200U * 1000U);
    }

    /*
     * 종료는 시작의 역순으로 정리한다.
     * thread 정지 -> driver 자원 해제 -> worker별 gateway/detect 해제
     * -> 로그 종료 순서로 내려간다.
     */
    driver_stop(&rt);
    driver_destroy(&rt);
    destroy_workers(workers, worker_count);
    free(worker_users);
    free(workers);
    app_log_write(&shared, "INFO", "event=capture_stop");
    app_log_close(&shared);
    return exit_code;
}

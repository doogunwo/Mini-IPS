/**
 * @file logging.h
 * @brief 로그/모니터링/런타임 helper 공개 인터페이스
 *
 * 이름은 logging이지만 실제로는 구조화 로그 기록 외에도
 * main/runtime 계층이 공유하는 app context, RST 보조 상태,
 * run_detect 계측 API까지 함께 담는 운영 보조 헤더 역할을 한다.
 */

#ifndef LOGGING_H
#define LOGGING_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>

#include "detect.h"
#include "httgw.h"

struct app_ctx;
struct driver_runtime;

typedef struct rst_log_cache {
    flow_key_t            flow;       /**< snapshot이 대응하는 flow */
    httgw_sess_snapshot_t snap;       /**< 로그 계산용 TCP 상태 snapshot */
    uint64_t              expires_ms; /**< 캐시 만료 시각 */
    int                   valid;      /**< 캐시 유효 여부 */
} rst_log_cache_t;

/** worker 간 공유되는 전역 상태와 로그 핸들 묶음이다. */
typedef struct app_shared {
    FILE                *log_fp;              /**< 메인 IPS 로그 파일 */
    char                 log_path[256];       /**< 로그 파일 경로 */
    FILE                *monitor_log_fp;      /**< 모니터링 로그 파일 */
    char                 monitor_log_path[256]; /**< 모니터 로그 경로 */
    pthread_mutex_t      log_mu;              /**< 로그 파일 동시 기록 보호 */
    int                  pass_log_enabled;    /**< 정상 요청 로그 출력 여부 */
    int                  debug_log_enabled;   /**< 디버그 로그 출력 여부 */
    atomic_uint_fast64_t event_seq;           /**< 이벤트 ID용 시퀀스 */
    atomic_uint_fast64_t packet_count;        /**< 관측 패킷 수 */
    atomic_uint_fast64_t http_msgs;           /**< 파싱 완료 HTTP 메시지 수 */
    atomic_uint_fast64_t reqs;                /**< 처리한 요청 수 */
    atomic_uint_fast64_t detect_count;        /**< 탐지 발생 수 */
    atomic_uint_fast64_t reasm_errs;          /**< 재조립 오류 수 */
    atomic_uint_fast64_t parse_errs;          /**< HTTP 파싱 오류 수 */
    atomic_uint_fast64_t monitor_last_emit_ms; /**< 마지막 모니터 출력 시각 */
    struct driver_runtime *driver_rt;
    struct app_ctx        *workers;
    int                    worker_count;
    uint64_t               monitor_prev_packets;
    uint64_t               monitor_prev_reqs;
    uint64_t               monitor_prev_detects;
    uint64_t               monitor_prev_reasm_in_order;
    uint64_t               monitor_prev_reasm_out_of_order;
    uint64_t               monitor_prev_reasm_trimmed;
} app_shared_t;

/** worker thread 하나가 독립적으로 가지는 실행 컨텍스트이다. */
typedef struct app_ctx {
    httgw_t         *gw;                  /**< worker 전용 HTTP gateway */
    detect_engine_t *det;                 /**< worker 전용 탐지 엔진 */
    tx_ctx_t         rst_tx;              /**< RST/차단 응답 송신 컨텍스트 */
    app_shared_t    *shared;              /**< 공유 상태 */
    rst_log_cache_t  rst_cache;           /**< 세션 종료 직후 로그 보조 캐시 */
    char             last_event_id[48];   /**< 최근 이벤트 ID */
    char             last_event_ts[40];   /**< 최근 이벤트 시각 */
    char             last_client_ip[32];  /**< 최근 차단 대상 IP */
    char            *last_block_page_html; /**< 최근 렌더링한 차단 페이지 */
    uint64_t         last_gc_ms;          /**< 마지막 GC 수행 시각 */
} app_ctx_t;

/** 로그 문자열 조합에 쓰는 간단한 동적 버퍼이다. */
typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
} strbuf_t;

/** run_detect 호출 횟수를 컨텍스트별로 관측하는 테스트/디버그용 계측 구조체이다. */
typedef struct {
    uint64_t total_collect_calls;
    uint64_t uri_calls;
    uint64_t args_calls;
    uint64_t args_names_calls;
    uint64_t headers_calls;
    uint64_t body_calls;
} run_detect_metrics_t;

int   env_flag_enabled(const char *name, int default_value);
void  strbuf_free(strbuf_t *sb);
char *log_escape_dup(const char *s);
int   app_make_timestamp(char *out, size_t out_sz);
int   app_make_event_id(app_shared_t *shared, char *out, size_t out_sz);
int   append_match_strings(const detect_match_list_t *matches, strbuf_t *rules,
                           strbuf_t *texts);
int   app_log_open(app_shared_t *shared);
void  app_log_close(app_shared_t *shared);
void  app_log_write(app_shared_t *shared, const char *category, const char *fmt,
                    ...);
void  app_monitor_write(app_shared_t *shared, const char *fmt, ...);
void  app_log_attack(app_shared_t *shared, const char *event_id,
                     const char *event_ts, const char *attack, const char *where,
                     const char *from, const char *detected,
                     const char *matched_rules, const char *matched_texts,
                     const char *ip, uint16_t port, int score, int threshold,
                     size_t match_count, uint64_t detect_us, long detect_ms);
void  ip4_to_str(uint32_t ip, char *out, size_t out_sz);
int   parse_flow_dir_and_flags(const uint8_t *data, uint32_t len,
                               flow_key_t *flow, tcp_dir_t *dir, uint8_t *flags);
void  rst_log_cache_put(app_ctx_t *app, const flow_key_t *flow,
                        const httgw_sess_snapshot_t *snap, uint64_t now_ms);
const httgw_sess_snapshot_t *rst_log_cache_get(app_ctx_t        *app,
                                               const flow_key_t *flow,
                                               uint64_t          now_ms);
void log_tcp_packet_line(const app_ctx_t *app, const uint8_t *data,
                         uint32_t                     len,
                         const httgw_sess_snapshot_t *fallback_snap);
void request_rst_both(app_ctx_t *app, const flow_key_t *flow,
                      const char *event_id);
void request_block_action_v2(app_ctx_t *app, const flow_key_t *flow,
                             const char *event_id);
int  run_detect(detect_engine_t *det, const http_message_t *msg, int *out_score,
                const char *query, size_t query_len,
                const IPS_Signature **matched_rule,
                detect_match_list_t *matches, uint64_t *detect_elapsed_us);
void run_detect_metrics_reset(void);
void run_detect_metrics_get(run_detect_metrics_t *out);

#endif

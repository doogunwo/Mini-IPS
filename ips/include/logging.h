/**
 * @file core.h
 * @brief
 */

#ifndef CORE_H
#define CORE_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>

#include "detect.h"
#include "httgw.h"

typedef struct rst_log_cache {
    flow_key_t            flow;
    httgw_sess_snapshot_t snap;
    uint64_t              expires_ms;
    int                   valid;
} rst_log_cache_t;

typedef struct app_shared {
    FILE                *log_fp;
    char                 log_path[256];
    pthread_mutex_t      log_mu;
    int                  pass_log_enabled;
    int                  debug_log_enabled;
    atomic_uint_fast64_t event_seq;
    atomic_uint_fast64_t http_msgs;
    atomic_uint_fast64_t reqs;
    atomic_uint_fast64_t reasm_errs;
    atomic_uint_fast64_t parse_errs;
} app_shared_t;

typedef struct app_ctx {
    httgw_t         *gw;
    detect_engine_t *det;
    tx_ctx_t         rst_tx;
    app_shared_t    *shared;
    rst_log_cache_t  rst_cache;
    char             last_event_id[48];
    char             last_event_ts[40];
    char             last_client_ip[32];
    char            *last_block_page_html;
} app_ctx_t;

typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
} strbuf_t;

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
                const IPS_Signature **matched_rule, detect_match_list_t *matches,
                uint64_t *detect_elapsed_us);

#endif

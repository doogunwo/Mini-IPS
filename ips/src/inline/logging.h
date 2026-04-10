#pragma once

#include <stddef.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdint.h>

typedef struct detect_result detect_result_t;
typedef struct http_message http_message_t;

int  mini_ips_log_open(void);
void mini_ips_log_close(void);
void mini_ips_log_errno(const char *scope, const char *detail, int errnum);
void mini_ips_log_message(const char *scope, const char *detail);
void mini_ips_log_parser_incomplete(uint32_t session_id, size_t raw_len,
                                    size_t reasm_len);
void mini_ips_log_detect_result(uint32_t session_id,
                                const detect_result_t *result,
                                const struct sockaddr_in *peer, int blocked,
                                const char *reason, uint64_t detect_us,
                                long detect_ms);
void mini_ips_log_detect_time(uint32_t session_id, uint64_t detect_us,
                              long detect_ms, size_t request_len);
void mini_ips_log_allow_message(uint32_t session_id,
                                const http_message_t *msg);
void mini_ips_log_response_to_client(uint32_t session_id,
                                     const struct sockaddr_in *peer,
                                     const char *kind, size_t len,
                                     const char *detail);
void mini_ips_log_note_packet(void);
void mini_ips_log_note_request(void);
void mini_ips_log_emit_monitor(size_t queue_depth);
int mini_ips_debug_flow_enabled(void);
void mini_ips_log_debug_flow(uint32_t session_id, int step,
                             const char *detail);
void mini_ips_log_debug_flowf(uint32_t session_id, int step,
                              const char *fmt, ...);

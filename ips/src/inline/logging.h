#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct detect_result detect_result_t;
typedef struct http_message http_message_t;

void mini_ips_log_errno(const char *scope, const char *detail, int errnum);
void mini_ips_log_message(const char *scope, const char *detail);
void mini_ips_log_parser_incomplete(uint32_t session_id, size_t raw_len,
                                    size_t reasm_len);
void mini_ips_log_detect_result(uint32_t session_id,
                                const detect_result_t *result, int blocked,
                                const char *reason);
void mini_ips_log_allow_message(uint32_t session_id,
                                const http_message_t *msg);

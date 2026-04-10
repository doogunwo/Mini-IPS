#pragma once

// TRUE_DETECT_NEED_BLOCK = 1;
// FALSE_DETECT = 0;

#include <stddef.h>

typedef struct detect_result detect_result_t;

typedef struct block_decision {
    int is_blocked;
    int status_code;
    const char *reason; 
} block_decision_t;

typedef struct blocking_ctx {
    const detect_result_t   *rs;
    block_decision_t        *dc;
    char                    *res_buf;
    char                    **res_owned;
    size_t                  res_buf_sz;
    size_t                  *rs_len;
    const char              *template_path;
    const char              *event_id;
    const char              *timestamp;
    const char              *client_ip;
} blocking_ctx_t;

/*
 * return:
 * -1 : error
 *  0 : allow
 *  1 : blocked, response built
 */
int blocking_request(blocking_ctx_t *ctx);

/*
 * return:
 * -1 : error
 *  0 : response sent
 */
int blocking_send(int client_fd, const char *res_buf, size_t res_len);

/*
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

int blocking_reqeust(const detect_result_t *results, block_decision_t *out);

*/

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "blocking.h"
#include "detect.h"


static int blocking_build_response(blocking_ctx_t *ctx) {
    if (NULL == ctx || NULL == ctx->dc) {
        return -1;
    }

    if (NULL == ctx->rs || NULL == ctx->res_buf || NULL ==ctx->rs_len || 0U == ctx->res_buf_sz) {
        return -1;
    }

    if (0 == ctx->dc->is_blocked) {
        ctx->res_buf[0] = '\0';
        *ctx->rs_len = 0;
        return 0;
    }

    const char *body;
    int written;

    if (NULL != ctx->dc->reason) {
        body = ctx->dc->reason;
    } else {
        body = "request blocked";
    }

    written = snprintf(ctx->res_buf, ctx->res_buf_sz,
                       "HTTP/1.1 403 Forbidden\r\n"
                       "Content-Type: text/plain\r\n"
                       "Content-Length: %zu\r\n"
                       "Connection: close\r\n"
                       "\r\n"
                       "%s",
                       strlen(body), body);
    if (written < 0 || (size_t)written >= ctx->res_buf_sz) {
        return -1;
    }

    *ctx->rs_len = (size_t)written;
    return 1;
}


int blocking_request(blocking_ctx_t *ctx) {

    if (NULL == ctx || NULL == ctx->rs || NULL == ctx->dc) {
        return -1;
    }

    memset(ctx->dc, 0, sizeof(*ctx->dc));

    if (NULL != ctx->res_buf && 0U < ctx->res_buf_sz) {
        ctx->res_buf[0] = '\0';
    }
    if (NULL != ctx->rs_len) {
        *ctx->rs_len = 0;
    }

    if (ctx->rs->matched_rce) {
        ctx->dc->is_blocked = 1;
        ctx->dc->status_code = 403;
        ctx->dc->reason = "request blocked : rce";
        return blocking_build_response(ctx);
    }

    if (ctx->rs->matched_sqli) {
        ctx->dc->is_blocked = 1;
        ctx->dc->status_code = 403;
        ctx->dc->reason = "request blocked : sqli";
        return blocking_build_response(ctx);
    }

    if (ctx->rs->matched_xss) {
        ctx->dc->is_blocked = 1;
        ctx->dc->status_code = 403;
        ctx->dc->reason = "request blocked : xss";
        return blocking_build_response(ctx);
    }

    if (ctx->rs->matched_directory_traversal) {
        ctx->dc->is_blocked = 1;
        ctx->dc->status_code = 403;
        ctx->dc->reason = "request blocked : directory traversal";
        return blocking_build_response(ctx);
    }

    return 0;
}

int blocking_send(int client_fd, const char *res_buf, size_t res_len) {
    size_t sent_len;

    if (client_fd < 0 || NULL == res_buf || 0U == res_len) {
        return -1;
    }

    sent_len = 0U;
    while (sent_len < res_len) {
        ssize_t n;

        n = send(client_fd, res_buf + sent_len, res_len - sent_len, 0);
        if (n < 0) {
            if (EINTR == errno) {
                continue;
            }
            return -1;
        }

        if (0 == n) {
            return -1;
        }

        sent_len += (size_t)n;
    }

    return 0;
}

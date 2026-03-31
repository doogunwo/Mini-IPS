#include "logging.h"

#include "detect.h"
#include "http_parser.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

void mini_ips_log_errno(const char *scope, const char *detail, int errnum) {
    fprintf(stderr, "[MINI_IPS][%s] %s failed (errno=%d: %s)\n",
            NULL != scope ? scope : "unknown",
            NULL != detail ? detail : "operation", errnum,
            strerror(errnum));
}

void mini_ips_log_message(const char *scope, const char *detail) {
    fprintf(stderr, "[MINI_IPS][%s] %s\n",
            NULL != scope ? scope : "unknown",
            NULL != detail ? detail : "message");
}

void mini_ips_log_parser_incomplete(uint32_t session_id, size_t raw_len,
                                    size_t reasm_len) {
    (void)session_id;
    (void)raw_len;
    (void)reasm_len;
}

void mini_ips_log_detect_result(uint32_t session_id,
                                const detect_result_t *result, int blocked,
                                const char *reason) {
    (void)session_id;
    (void)result;
    (void)blocked;
    (void)reason;
}

void mini_ips_log_allow_message(uint32_t session_id,
                                const http_message_t *msg) {
    if (NULL == msg) {
        return;
    }

    fprintf(stderr, "[ALLOW] session_id=%u\n", session_id);

    if (NULL != msg->uri) {
        fprintf(stderr, "[ALLOW_URI] session_id=%u uri=\"%s\"\n", session_id,
                msg->uri);
    }

    fprintf(stderr, "[ALLOW_HEADERS] session_id=%u\n", session_id);
    if (NULL != msg->headers && '\0' != msg->headers[0]) {
        fputs(msg->headers, stderr);
        if ('\n' != msg->headers[strlen(msg->headers) - 1U]) {
            fputc('\n', stderr);
        }
    }
    fprintf(stderr, "[ALLOW_HEADERS_END] session_id=%u\n", session_id);

    fprintf(stderr, "[ALLOW_BODY] session_id=%u body_len=%zu\n", session_id,
            NULL != msg->body ? msg->body_len : 0U);
    if (NULL != msg->body && 0U < msg->body_len) {
        fwrite(msg->body, 1U, msg->body_len, stderr);
        if ('\n' != msg->body[msg->body_len - 1U]) {
            fputc('\n', stderr);
        }
    }
    fprintf(stderr, "[ALLOW_BODY_END] session_id=%u\n", session_id);

    if (NULL == msg->body || 0U == msg->body_len) {
        fputc('\n', stderr);
    }
    fprintf(stderr, "[ALLOW_END] session_id=%u\n", session_id);
}

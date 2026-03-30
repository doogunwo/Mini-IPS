#include "mini_ips.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>

#define MINI_IPS_BIND_IP      "0.0.0.0"
#define MINI_IPS_BIND_PORT    50080
#define MINI_IPS_BIND_BACKLOG 128

static void mini_ips_log_errno(const char *scope, const char *detail,
                               int errnum) {
    fprintf(stderr, "[MINI_IPS][%s] %s failed (errno=%d: %s)\n",
            NULL != scope ? scope : "unknown",
            NULL != detail ? detail : "operation",
            errnum, strerror(errnum));
}

static void mini_ips_log_message(const char *scope, const char *detail) {
    fprintf(stderr, "[MINI_IPS][%s] %s\n",
            NULL != scope ? scope : "unknown",
            NULL != detail ? detail : "message");
}

static void mini_ips_log_payload_preview(const char *tag, uint32_t session_id,
                                         const uint8_t *data, size_t len) {
    size_t preview_len;

    if (NULL == tag || NULL == data || 0U == len) {
        return;
    }

    preview_len = len;
    if (preview_len > 256U) {
        preview_len = 256U;
    }

    fprintf(stderr,
            "[HTTP_RAW] tag=%s session_id=%u len=%zu preview=%.*s\n",
            tag, session_id, len, (int)preview_len, (const char *)data);
}

static void mini_ips_log_http_message(uint32_t session_id,
                                      const http_message_t *msg) {
    size_t header_len;
    size_t body_preview_len;

    if (NULL == msg) {
        return;
    }

    fprintf(stderr,
            "[HTTP] session_id=%u method=%s uri=%s body_len=%zu\n",
            session_id,
            NULL != msg->method ? msg->method : "(null)",
            NULL != msg->uri ? msg->uri : "(null)",
            msg->body_len);

    if (NULL != msg->headers) {
        header_len = strlen(msg->headers);
        if (header_len > 256U) {
            header_len = 256U;
        }
        fprintf(stderr, "[HTTP_HEADERS] session_id=%u preview=%.*s\n",
                session_id, (int)header_len, msg->headers);
    }

    if (NULL != msg->body && 0U < msg->body_len) {
        body_preview_len = msg->body_len;
        if (body_preview_len > 256U) {
            body_preview_len = 256U;
        }
        fprintf(stderr, "[HTTP_BODY] session_id=%u preview=%.*s\n",
                session_id, (int)body_preview_len, (const char *)msg->body);
    }
}

static int mini_ips_upstream_connect(const struct sockaddr_in *orig_dst,
                                     int *upstream_fd) {
    int fd;
    int rc;

    if (NULL == orig_dst || NULL == upstream_fd) {
        errno = EINVAL;
        mini_ips_log_errno("tp", "mini_ips_upstream_connect.invalid_argument",
                           errno);
        return -1;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        mini_ips_log_errno("tp", "mini_ips_upstream_connect.socket", errno);
        return -1;
    }

    rc = connect(fd, (const struct sockaddr *)orig_dst, sizeof(*orig_dst));
    if (rc < 0) {
        mini_ips_log_errno("tp", "mini_ips_upstream_connect.connect", errno);
        close(fd);
        return -1;
    }

    *upstream_fd = fd;
    return 0;
}

static int mini_ips_epoll_add(int epoll_fd, int fd, uint32_t events) {
    struct epoll_event ev;

    if (epoll_fd < 0 || fd < 0) {
        errno = EINVAL;
        mini_ips_log_errno("tp", "mini_ips_epoll_add.invalid_argument", errno);
        return -1;
    }

    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.fd = fd;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        mini_ips_log_errno("tp", "mini_ips_epoll_add.epoll_ctl_add", errno);
        return -1;
    }

    return 0;
}

static int mini_ips_epoll_del(int epoll_fd, int fd) {
    if (epoll_fd < 0 || fd < 0) {
        errno = EINVAL;
        mini_ips_log_errno("tp", "mini_ips_epoll_del.invalid_argument", errno);
        return -1;
    }

    if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL) < 0) {
        if (ENOENT == errno) {
            return 0;
        }
        mini_ips_log_errno("tp", "mini_ips_epoll_del.epoll_ctl_del", errno);
        return -1;
    }

    return 0;
}

static int mini_ips_write_all(int fd, const uint8_t *buf, size_t len) {
    size_t written;

    if (fd < 0 || (NULL == buf && 0U != len)) {
        errno = EINVAL;
        mini_ips_log_errno("tp", "mini_ips_write_all.invalid_argument", errno);
        return -1;
    }

    written = 0U;
    while (written < len) {
        ssize_t n;

        n = send(fd, buf + written, len - written, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            mini_ips_log_errno("tp", "mini_ips_write_all.send", errno);
            return -1;
        }

        written += (size_t)n;
    }

    return 0;
}

static int mini_ips_ensure_tproxy(mini_ips_ctx_t *ctx) {
    tproxy_cfg_t cfg;

    if (NULL == ctx) {
        mini_ips_log_message("set", "mini_ips_ensure_tproxy.ctx_is_null");
        return -1;
    }

    if (NULL != ctx->tp) {
        return 0;
    }

    cfg.bind_ip = MINI_IPS_BIND_IP;
    cfg.bind_port = MINI_IPS_BIND_PORT;
    cfg.backlog = MINI_IPS_BIND_BACKLOG;

    ctx->tp = tproxy_create(&cfg);
    if (NULL == ctx->tp) {
        mini_ips_log_message("set", "tproxy_create returned NULL");
    }
    return NULL != ctx->tp ? 0 : -1;
}

static int mini_ips_transform_uri(http_message_t *msg) {
    char  *buf_a;
    char  *buf_b;
    size_t cap;

    if (NULL == msg || NULL == msg->uri) {
        return 0;
    }

    cap = strlen(msg->uri) + 1U;
    buf_a = (char *)malloc(cap);
    buf_b = (char *)malloc(cap);
    if (NULL == buf_a || NULL == buf_b) {
        free(buf_a);
        free(buf_b);
        return -1;
    }

    memcpy(buf_a, msg->uri, cap);
    if (0 > http_decode_percent_recursive(buf_b, cap, buf_a, 2)) {
        free(buf_a);
        free(buf_b);
        return -1;
    }
    memcpy(buf_a, buf_b, strlen(buf_b) + 1U);

    if (0 > http_decode_plus_as_space(buf_b, cap, buf_a)) {
        free(buf_a);
        free(buf_b);
        return -1;
    }
    memcpy(buf_a, buf_b, strlen(buf_b) + 1U);

    if (0 > http_normalize_uri(buf_b, cap, buf_a)) {
        free(buf_a);
        free(buf_b);
        return -1;
    }

    free(msg->uri);
    msg->uri = buf_b;
    free(buf_a);
    return 0;
}

static int mini_ips_transform_headers(http_message_t *msg) {
    char  *buf_a;
    char  *buf_b;
    size_t cap;

    if (NULL == msg || NULL == msg->headers) {
        return 0;
    }

    cap = strlen(msg->headers) + 1U;
    buf_a = (char *)malloc(cap);
    buf_b = (char *)malloc(cap);
    if (NULL == buf_a || NULL == buf_b) {
        free(buf_a);
        free(buf_b);
        return -1;
    }

    memcpy(buf_a, msg->headers, cap);
    if (0 > http_normalize_line_endings(buf_b, cap, buf_a)) {
        free(buf_a);
        free(buf_b);
        return -1;
    }
    memcpy(buf_a, buf_b, strlen(buf_b) + 1U);

    if (0 > http_normalize_spaces(buf_b, cap, buf_a)) {
        free(buf_a);
        free(buf_b);
        return -1;
    }

    free(msg->headers);
    msg->headers = buf_b;
    free(buf_a);
    return 0;
}

static int mini_ips_transform_body(http_message_t *msg) {
    uint8_t *buf_a;
    uint8_t *buf_b;
    size_t   next_len;
    size_t   cap;

    if (NULL == msg || NULL == msg->body || 0U == msg->body_len) {
        return 0;
    }

    cap = msg->body_len;
    buf_a = (uint8_t *)malloc(cap);
    buf_b = (uint8_t *)malloc(cap);
    if (NULL == buf_a || NULL == buf_b) {
        free(buf_a);
        free(buf_b);
        return -1;
    }

    memcpy(buf_a, msg->body, cap);
    next_len = cap;

    if (0 > http_body_decode_percent_recursive(buf_b, cap, buf_a, next_len, 2,
                                               &next_len)) {
        free(buf_a);
        free(buf_b);
        return -1;
    }
    memcpy(buf_a, buf_b, next_len);

    if (0 > http_body_normalize_lowercase(buf_b, cap, buf_a, next_len,
                                          &next_len)) {
        free(buf_a);
        free(buf_b);
        return -1;
    }

    free(msg->body);
    msg->body = buf_b;
    msg->body_len = next_len;
    free(buf_a);
    return 0;
}

static int mini_ips_prepare_message(http_message_t *msg) {
    if (NULL == msg) {
        mini_ips_log_message("worker", "mini_ips_prepare_message.msg_is_null");
        return -1;
    }

    if (0 != mini_ips_transform_uri(msg)) {
        mini_ips_log_message("worker",
                             "mini_ips_transform_uri failed, keep original");
    }
    if (0 != mini_ips_transform_headers(msg)) {
        mini_ips_log_message("worker",
                             "mini_ips_transform_headers failed, keep original");
    }
    if (0 != mini_ips_transform_body(msg)) {
        mini_ips_log_message("worker",
                             "mini_ips_transform_body failed, keep original");
    }

    return 0;
}

static mini_ips_session_t *mini_ips_session_alloc(mini_ips_ctx_t *ctx,
                                                  int client_fd,
                                                  const struct sockaddr_in *orig_dst) {
    size_t i;

    if (NULL == ctx || client_fd < 0 || NULL == orig_dst) {
        return NULL;
    }

    for (i = 0; i < MINI_IPS_MAX_SESSIONS; i++) {
        mini_ips_session_t *session;

        session = &ctx->sessions[i];
        if (session->in_use) {
            continue;
        }

        memset(session, 0, sizeof(*session));
        session->in_use = 1;
        session->client_fd = client_fd;
        session->upstream_fd = -1;
        session->blocked = 0;
        session->decision_queued = 0;
        session->request_forwarded = 0;
        session->orig_dst = *orig_dst;

        ctx->next_session_id++;
        if (0U == ctx->next_session_id) {
            ctx->next_session_id++;
        }
        session->session_id = ctx->next_session_id;
        return session;
    }

    return NULL;
}

static mini_ips_session_t *mini_ips_session_find(mini_ips_ctx_t *ctx,
                                                 uint32_t session_id) {
    size_t i;

    if (NULL == ctx || 0U == session_id) {
        return NULL;
    }

    for (i = 0; i < MINI_IPS_MAX_SESSIONS; i++) {
        mini_ips_session_t *session;

        session = &ctx->sessions[i];
        if (!session->in_use) {
            continue;
        }
        if (session->session_id == session_id) {
            return session;
        }
    }

    return NULL;
}

static void mini_ips_session_release(mini_ips_session_t *session) {
    if (NULL == session) {
        return;
    }

    free(session->pending_request);
    memset(session, 0, sizeof(*session));
}

static mini_ips_reasm_t *mini_ips_reasm_get(mini_ips_ctx_t *ctx,
                                            uint32_t session_id) {
    size_t i;

    if (NULL == ctx || 0U == session_id) {
        return NULL;
    }

    for (i = 0; i < MINI_IPS_MAX_SESSIONS; i++) {
        if (ctx->reasm[i].in_use && ctx->reasm[i].session_id == session_id) {
            return &ctx->reasm[i];
        }
    }

    for (i = 0; i < MINI_IPS_MAX_SESSIONS; i++) {
        if (ctx->reasm[i].in_use) {
            continue;
        }

        memset(&ctx->reasm[i], 0, sizeof(ctx->reasm[i]));
        ctx->reasm[i].in_use = 1;
        ctx->reasm[i].session_id = session_id;
        return &ctx->reasm[i];
    }

    return NULL;
}

static void mini_ips_reasm_release(mini_ips_ctx_t *ctx, uint32_t session_id) {
    size_t i;

    if (NULL == ctx || 0U == session_id) {
        return;
    }

    for (i = 0; i < MINI_IPS_MAX_SESSIONS; i++) {
        if (!ctx->reasm[i].in_use) {
            continue;
        }
        if (ctx->reasm[i].session_id != session_id) {
            continue;
        }

        free(ctx->reasm[i].buf);
        memset(&ctx->reasm[i], 0, sizeof(ctx->reasm[i]));
        return;
    }
}

static int mini_ips_reserve_buffer(uint8_t **buf, size_t *cap, size_t need) {
    uint8_t *new_buf;
    size_t   new_cap;

    if (NULL == buf || NULL == cap || 0U == need) {
        return -1;
    }

    if (*cap >= need) {
        return 0;
    }

    new_cap = *cap;
    if (0U == new_cap) {
        new_cap = PACKET_MAX_BYTES;
    }
    while (new_cap < need) {
        new_cap += PACKET_MAX_BYTES;
    }

    new_buf = (uint8_t *)realloc(*buf, new_cap);
    if (NULL == new_buf) {
        return -1;
    }

    *buf = new_buf;
    *cap = new_cap;
    return 0;
}

static int mini_ips_reasm_append(mini_ips_reasm_t *reasm,
                                 const uint8_t *data, size_t len) {
    if (NULL == reasm || NULL == data || 0U == len) {
        return -1;
    }

    if (0 != mini_ips_reserve_buffer(&reasm->buf, &reasm->cap,
                                     reasm->len + len)) {
        return -1;
    }

    memcpy(reasm->buf + reasm->len, data, len);
    reasm->len += len;
    return 0;
}

static int mini_ips_handle_res_ring(mini_ips_ctx_t *ctx,
                                    mini_ips_session_t *current_session,
                                    int *client_open, int *upstream_open,
                                    int *waiting_decision) {
    uint32_t session_id;
    uint32_t payload_len;
    uint32_t action;
    uint8_t  payload_buf[PACKET_MAX_BYTES];

    if (NULL == ctx || NULL == current_session || NULL == client_open ||
        NULL == upstream_open || NULL == waiting_decision) {
        return -1;
    }

    while (0 == res_ring_deq(&ctx->res_ring, payload_buf,
                             sizeof(payload_buf), &payload_len,
                             &session_id, &action)) {
        mini_ips_session_t *session;

        session = mini_ips_session_find(ctx, session_id);
        if (NULL == session || !session->in_use || session->client_fd < 0) {
            continue;
        }

        session->decision_queued = 0;

        if (MINI_IPS_RING_ACTION_BLOCK == action) {
            session->blocked = 1;

            if (0 != blocking_send(session->client_fd,
                                   (const char *)payload_buf, payload_len)) {
                if (EPIPE != errno && ECONNRESET != errno &&
                    ENOTSOCK != errno && EBADF != errno) {
                    mini_ips_log_errno("tp", "blocking_send", errno);
                    return -1;
                }
            }

            if (session->upstream_fd >= 0) {
                shutdown(session->upstream_fd, SHUT_RDWR);
            }
            shutdown(session->client_fd, SHUT_RDWR);

            if (session == current_session) {
                *waiting_decision = 0;
                *client_open = 0;
                *upstream_open = 0;
                mini_ips_epoll_del(ctx->tp->epoll_fd, session->client_fd);
                if (session->upstream_fd >= 0) {
                    mini_ips_epoll_del(ctx->tp->epoll_fd, session->upstream_fd);
                }
                return 1;
            }
            continue;
        }

        if (MINI_IPS_RING_ACTION_ALLOW == action) {
            if (session->request_forwarded) {
                continue;
            }

            if (session->upstream_fd < 0) {
                if (0 != mini_ips_upstream_connect(&session->orig_dst,
                                                   &session->upstream_fd)) {
                    mini_ips_log_message("tp",
                                         "mini_ips_upstream_connect failed");
                    return -1;
                }

                if (0 != mini_ips_epoll_add(ctx->tp->epoll_fd,
                                            session->upstream_fd,
                                            EPOLLIN | EPOLLRDHUP |
                                                EPOLLHUP | EPOLLERR)) {
                    mini_ips_log_message("tp",
                                         "mini_ips_epoll_add upstream_fd failed");
                    close(session->upstream_fd);
                    session->upstream_fd = -1;
                    return -1;
                }
            }

            if (0 != mini_ips_write_all(session->upstream_fd,
                                        session->pending_request,
                                        session->pending_request_len)) {
                mini_ips_log_message("tp",
                                     "mini_ips_write_all(upstream_fd) failed");
                return -1;
            }

            session->request_forwarded = 1;
            session->pending_request_len = 0U;

            if (session == current_session) {
                *waiting_decision = 0;
                *upstream_open = 1;
                if (!*client_open) {
                    shutdown(session->upstream_fd, SHUT_WR);
                }
            }
        }
    }

    return 0;
}

static int mini_ips_process_payload(mini_ips_ctx_t *ctx, const uint8_t *data,
                                    size_t len, uint32_t session_id) {
    http_message_t  msg;
    detect_result_t result;
    block_decision_t decision;
    blocking_ctx_t  block_ctx;
    mini_ips_session_t *session;
    mini_ips_reasm_t *reasm;
    char            response_buf[512];
    char            logbuf[256];
    size_t          response_len;
    int             rc;

    if (NULL == ctx || NULL == data || 0U == len || NULL == ctx->engine) {
        mini_ips_log_message("worker",
                             "mini_ips_process_payload invalid input or engine");
        return -1;
    }

    session = mini_ips_session_find(ctx, session_id);
    if (NULL == session || !session->in_use || session->client_fd < 0) {
        return 0;
    }
    if (session->blocked || session->decision_queued) {
        return 0;
    }

    reasm = mini_ips_reasm_get(ctx, session_id);
    if (NULL == reasm) {
        mini_ips_log_message("worker", "mini_ips_reasm_get failed");
        return -1;
    }

    memset(&msg, 0, sizeof(msg));
    memset(&result, 0, sizeof(result));
    memset(&decision, 0, sizeof(decision));
    memset(&block_ctx, 0, sizeof(block_ctx));

    mini_ips_log_payload_preview("req_ring.deq", session_id, data, len);

    if (0 != mini_ips_reasm_append(reasm, data, len)) {
        mini_ips_log_message("worker", "mini_ips_reasm_append failed");
        mini_ips_reasm_release(ctx, session_id);
        return -1;
    }

    rc = http_parser_try(reasm->buf, reasm->len, &msg);
    if (0 == rc) {
        fprintf(stderr,
                "[HTTP] session_id=%u parser=incomplete raw_len=%zu reasm_len=%zu\n",
                session_id, len, reasm->len);
        return 0;
    }
    if (0 > rc) {
        mini_ips_log_message("worker", "http_parser_try failed");
        mini_ips_reasm_release(ctx, session_id);
        return -1;
    }

    mini_ips_log_http_message(session_id, &msg);

    if (0 != mini_ips_prepare_message(&msg)) {
        http_parser_free(&msg);
        mini_ips_log_message("worker", "mini_ips_prepare_message failed");
        mini_ips_reasm_release(ctx, session_id);
        return -1;
    }

    mini_ips_log_http_message(session_id, &msg);

    rc = detect_run(ctx->engine, &msg, &result);
    if (0 != rc) {
        http_parser_free(&msg);
        mini_ips_log_message("worker", "detect_run failed");
        mini_ips_reasm_release(ctx, session_id);
        return -1;
    }

    response_buf[0] = '\0';
    response_len = 0U;
    block_ctx.rs = &result;
    block_ctx.dc = &decision;
    block_ctx.res_buf = response_buf;
    block_ctx.res_buf_sz = sizeof(response_buf);
    block_ctx.rs_len = &response_len;

    rc = blocking_request(&block_ctx);
    http_parser_free(&msg);
    if (0 > rc) {
        mini_ips_log_message("worker", "blocking_request failed");
        mini_ips_reasm_release(ctx, session_id);
        return -1;
    }

    if (result.matched) {
        snprintf(logbuf, sizeof(logbuf),
                 "[BLOCK] session_id=%u blocked=%s reason=%s",
                 session_id, 1 == rc ? "yes" : "no",
                 NULL != decision.reason ? decision.reason : "none");
        fprintf(stderr, "%s\n", logbuf);
    }

    if (1 == rc && NULL != session && session->client_fd >= 0) {
        if (0 != res_ring_enq(&ctx->res_ring, MINI_IPS_RING_ACTION_BLOCK,
                              session_id,
                              (const uint8_t *)response_buf,
                              (uint32_t)response_len)) {
            mini_ips_log_message("worker", "res_ring_enq(block) failed");
            return -1;
        }
        session->decision_queued = 1;
    } else if (0 == rc && NULL != session && session->client_fd >= 0) {
        if (0 != mini_ips_reserve_buffer(&session->pending_request,
                                         &session->pending_request_cap,
                                         reasm->len)) {
            mini_ips_log_message("worker", "pending_request reserve failed");
            mini_ips_reasm_release(ctx, session_id);
            return -1;
        }

        memcpy(session->pending_request, reasm->buf, reasm->len);
        session->pending_request_len = reasm->len;

        if (0 != res_ring_enq(&ctx->res_ring, MINI_IPS_RING_ACTION_ALLOW,
                              session_id, NULL, 0U)) {
            mini_ips_log_message("worker", "res_ring_enq(allow) failed");
            mini_ips_reasm_release(ctx, session_id);
            return -1;
        }
        session->decision_queued = 1;
    }

    mini_ips_reasm_release(ctx, session_id);

    return 0;
}

int mini_ips_set(mini_ips_ctx_t *ctx) {
    const char *ruleset_path;

    if (NULL == ctx) {
        mini_ips_log_message("set", "mini_ips_set.ctx_is_null");
        return -1;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->tp = NULL;
    ctx->engine = NULL;
    ctx->ruleset_path = NULL;
    ctx->initialized = 0;
    ctx->stop = 0;
    ctx->ring_enabled = 0;

    ruleset_path = getenv(MINI_IPS_RULESET_ENV);
    if (NULL == ruleset_path || '\0' == ruleset_path[0]) {
        mini_ips_log_message("set",
                             "MINI_IPS_RULESET_DIR is missing or empty");
        return -1;
    }

    ctx->ruleset_path = ruleset_path;

    if (0 != regex_signatures_load(&ctx->db, ctx->ruleset_path)) {
        mini_ips_log_message("set", "regex_signatures_load failed");
        return -1;
    }

    ctx->engine = engine_regex_create(&ctx->db);
    if (NULL == ctx->engine) {
        mini_ips_log_message("set", "engine_regex_create returned NULL");
        regex_signatures_free(&ctx->db);
        return -1;
    }

    if (0 != req_ring_init(&ctx->req_ring, MINI_IPS_RING_SLOT_COUNT)) {
        mini_ips_log_message("set", "req_ring_init failed");
        engine_regex_destroy(ctx->engine);
        ctx->engine = NULL;
        regex_signatures_free(&ctx->db);
        return -1;
    }

    if (0 != res_ring_init(&ctx->res_ring, MINI_IPS_RING_SLOT_COUNT)) {
        mini_ips_log_message("set", "res_ring_init failed");
        req_ring_free(&ctx->req_ring);
        engine_regex_destroy(ctx->engine);
        ctx->engine = NULL;
        regex_signatures_free(&ctx->db);
        return -1;
    }

    ctx->ring_enabled = 1;
    ctx->initialized = 1;
    return 0;
}

int mini_ips_run_tp(mini_ips_ctx_t *ctx) {
    struct sockaddr_in peer_addr;
    struct sockaddr_in orig_dst;
    int                client_fd;
    int                upstream_fd;
    int                client_open;
    int                upstream_open;
    int                waiting_decision;
    mini_ips_session_t *session;
    uint8_t            req_buf[PACKET_MAX_BYTES];
    uint8_t            res_buf[PACKET_MAX_BYTES];
    struct epoll_event events[8];

    if (NULL == ctx || 0 == ctx->initialized) {
        mini_ips_log_message("tp", "ctx is null or not initialized");
        return -1;
    }

    if (0 != mini_ips_ensure_tproxy(ctx)) {
        mini_ips_log_message("tp", "mini_ips_ensure_tproxy failed");
        return -1;
    }

    while (!ctx->stop) {
        int rc;

        memset(&peer_addr, 0, sizeof(peer_addr));
        memset(&orig_dst, 0, sizeof(orig_dst));
        client_fd = -1;
        upstream_fd = -1;
        session = NULL;

        rc = tproxy_accept_client(ctx->tp, &peer_addr, &orig_dst, &client_fd);
        if (-2 == rc) {
            continue;
        }
        if (0 > rc) {
            mini_ips_log_errno("tp", "tproxy_accept_client", errno);
            return -1;
        }

        session = mini_ips_session_alloc(ctx, client_fd, &orig_dst);
        if (NULL == session) {
            close(client_fd);
            mini_ips_log_message("tp", "mini_ips_session_alloc returned NULL");
            return -1;
        }

        if (0 != mini_ips_epoll_add(ctx->tp->epoll_fd, client_fd,
                                    EPOLLIN | EPOLLRDHUP | EPOLLHUP |
                                        EPOLLERR)) {
            mini_ips_session_release(session);
            close(client_fd);
            mini_ips_log_message("tp", "mini_ips_epoll_add client_fd failed");
            return -1;
        }

        client_open = 1;
        upstream_open = 0;
        waiting_decision = 0;

        while (!ctx->stop && (client_open || upstream_open || waiting_decision)) {
            int nready;
            int i;
            int res_rc;

            res_rc = mini_ips_handle_res_ring(ctx, session, &client_open,
                                              &upstream_open,
                                              &waiting_decision);
            if (res_rc < 0) {
                if (NULL != session) {
                    upstream_fd = session->upstream_fd;
                }
                if (upstream_fd >= 0) {
                    close(upstream_fd);
                }
                close(client_fd);
                return -1;
            }
            if (res_rc > 0) {
                break;
            }

            if (NULL != session) {
                upstream_fd = session->upstream_fd;
            }

            nready = epoll_wait(ctx->tp->epoll_fd, events, 8, 100);
            if (nready < 0) {
                if (errno == EINTR) {
                    continue;
                }
                mini_ips_log_errno("tp", "epoll_wait", errno);
                mini_ips_epoll_del(ctx->tp->epoll_fd, client_fd);
                if (upstream_fd >= 0) {
                    mini_ips_epoll_del(ctx->tp->epoll_fd, upstream_fd);
                    close(upstream_fd);
                }
                close(client_fd);
                return -1;
            }

            for (i = 0; i < nready; i++) {
                int fd;
                uint32_t ev;
                ssize_t n;

                fd = events[i].data.fd;
                ev = events[i].events;

                if (fd == ctx->tp->listen_fd) {
                    continue;
                }

                if (NULL != session && session->blocked) {
                    client_open = 0;
                    upstream_open = 0;
                    mini_ips_epoll_del(ctx->tp->epoll_fd, client_fd);
                    mini_ips_epoll_del(ctx->tp->epoll_fd, upstream_fd);
                    break;
                }

                if (fd == client_fd && client_open &&
                    ((ev & EPOLLERR) || (ev & EPOLLHUP) ||
                     (ev & EPOLLRDHUP) || (ev & EPOLLIN))) {
                    /* client 소켓에서 요청 바이트를 읽는다. */
                    n = recv(client_fd, req_buf, sizeof(req_buf), 0); 
                    if (n < 0) {
                        if (errno == EINTR || errno == EAGAIN ||
                            errno == EWOULDBLOCK) {
                            continue;
                        }
                        mini_ips_log_errno("tp", "recv(client_fd)", errno);
                        mini_ips_epoll_del(ctx->tp->epoll_fd, client_fd);
                        if (upstream_fd >= 0) {
                            mini_ips_epoll_del(ctx->tp->epoll_fd, upstream_fd);
                            close(upstream_fd);
                        }
                        close(client_fd);
                        return -1;
                    }

                    if (0 == n) {
                        if (upstream_fd >= 0) {
                            shutdown(upstream_fd, SHUT_WR);
                        }
                        client_open = 0;
                        mini_ips_epoll_del(ctx->tp->epoll_fd, client_fd);
                        continue;
                    }

                    if (ctx->ring_enabled &&
                        0 != req_ring_enq(&ctx->req_ring,
                                          NULL != session ? session->session_id : 0U,
                                          req_buf, (uint32_t)n)) {
                        mini_ips_log_message("tp", "req_ring_enq failed");
                        mini_ips_epoll_del(ctx->tp->epoll_fd, client_fd);
                        if (upstream_fd >= 0) {
                            mini_ips_epoll_del(ctx->tp->epoll_fd, upstream_fd);
                            close(upstream_fd);
                        }
                        close(client_fd);
                        return -1;
                    }

                    waiting_decision = 1;
                } else if (fd == upstream_fd && upstream_open &&
                           ((ev & EPOLLERR) || (ev & EPOLLHUP) ||
                            (ev & EPOLLRDHUP) || (ev & EPOLLIN))) {
                    n = recv(upstream_fd, res_buf, sizeof(res_buf), 0);
                    if (n < 0) {
                        if (errno == EINTR || errno == EAGAIN ||
                            errno == EWOULDBLOCK) {
                            continue;
                        }
                        mini_ips_log_errno("tp", "recv(upstream_fd)", errno);
                        mini_ips_epoll_del(ctx->tp->epoll_fd, client_fd);
                        if (upstream_fd >= 0) {
                            mini_ips_epoll_del(ctx->tp->epoll_fd, upstream_fd);
                            close(upstream_fd);
                        }
                        close(client_fd);
                        return -1;
                    }

                    if (0 == n) {
                        shutdown(client_fd, SHUT_WR);
                        upstream_open = 0;
                        mini_ips_epoll_del(ctx->tp->epoll_fd, upstream_fd);
                        continue;
                    }

                    if (0 != mini_ips_write_all(client_fd, res_buf,
                                                (size_t)n)) {
                        mini_ips_log_message("tp", "mini_ips_write_all(client_fd) failed");
                        mini_ips_epoll_del(ctx->tp->epoll_fd, client_fd);
                        if (upstream_fd >= 0) {
                            mini_ips_epoll_del(ctx->tp->epoll_fd, upstream_fd);
                            close(upstream_fd);
                        }
                        close(client_fd);
                        return -1;
                    }
                }
            }
        }

        mini_ips_epoll_del(ctx->tp->epoll_fd, client_fd);
        if (upstream_fd >= 0) {
            mini_ips_epoll_del(ctx->tp->epoll_fd, upstream_fd);
            close(upstream_fd);
        }
        close(client_fd);
        if (NULL != session) {
            mini_ips_reasm_release(ctx, session->session_id);
        }
        mini_ips_session_release(session);
    }

    return 0;
}

int mini_ips_run_worker(mini_ips_ctx_t *ctx) {
    uint8_t buf[PACKET_MAX_BYTES];
    uint32_t out_len;
    uint32_t session_id;
    int worked;

    if (NULL == ctx || 0 == ctx->initialized || 0 == ctx->ring_enabled) {
        mini_ips_log_message("worker",
                             "ctx is null, not initialized, or ring disabled");
        return -1;
    }

    while (!ctx->stop) {
        worked = 0;
        out_len = 0U;
        session_id = 0U;

        if (0 == req_ring_deq(&ctx->req_ring, buf, sizeof(buf), &out_len,
                              &session_id)) {
            worked = 1;
            if (0 != mini_ips_process_payload(ctx, buf, out_len, session_id)) {
                mini_ips_log_message("worker",
                                     "mini_ips_process_payload(req_ring) failed");
                continue;
            }
        }

        if (!worked) {
            usleep(1000);
        }
    }

    return 0;
}

void mini_ips_destroy(mini_ips_ctx_t *ctx) {
    if (NULL == ctx) {
        return;
    }

    if (ctx->ring_enabled) {
        res_ring_free(&ctx->res_ring);
        req_ring_free(&ctx->req_ring);
        ctx->ring_enabled = 0;
    }

    if (NULL != ctx->engine) {
        engine_regex_destroy(ctx->engine);
        ctx->engine = NULL;
    }

    regex_signatures_free(&ctx->db);

    if (NULL != ctx->tp) {
        tproxy_destroy(ctx->tp);
        ctx->tp = NULL;
    }

    ctx->ruleset_path = NULL;
    ctx->initialized = 0;
    ctx->stop = 0;
}

#include "mini_ips.h"
#include "logging.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/eventfd.h>
#include <stdint.h>

#define MINI_IPS_BIND_IP      "0.0.0.0"
#define MINI_IPS_BIND_PORT    50080
#define MINI_IPS_BIND_BACKLOG 128
/* eventfd wakeup 전 100ms polling 병목을 줄이기 위해 timeout을 낮췄다.
 * eventfd가 놓치더라도 res_ring을 짧은 주기로 다시 확인하는 fallback이다. */
#define MINI_IPS_RES_RING_POLL_MS 1

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

static void mini_ips_signal_res_event(mini_ips_ctx_t *ctx) {
    uint64_t one;
    ssize_t  nwrite;

    if (NULL == ctx || ctx->res_event_fd < 0) {
        return;
    }

    one = 1;
    nwrite = write(ctx->res_event_fd, &one, sizeof(one));
    if (nwrite == (ssize_t)sizeof(one)) {
        return;
    }
    if (nwrite < 0 && (EAGAIN == errno || EINTR == errno)) {
        return;
    }

    mini_ips_log_errno("worker", "write(res_event_fd)", errno);
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
    int ret = 0;
    if (NULL == msg || NULL == msg->uri) {
        return 0;
    }

    cap = (strlen(msg->uri) * 2U) + 64U;
    buf_a = (char *)malloc(cap);
    buf_b = (char *)malloc(cap);
    if (NULL == buf_a || NULL == buf_b) {
        free(buf_a);
        free(buf_b);
        return -1;
    }

    memcpy(buf_a, msg->uri, strlen(msg->uri) + 1U);
    ret = http_uri_canonicalize(buf_b, cap, buf_a, 3);
    if (0 > ret) {
        free(buf_a);
        free(buf_b);
        return -1;
    }

    memcpy(buf_a, buf_b, strlen(buf_b) + 1U);
    ret = http_decode_plus_as_space(buf_b, cap, buf_a);
    if (0 > ret) {
        free(buf_a);
        free(buf_b);
        return -1;
    }
    
    memcpy(buf_a, buf_b, strlen(buf_b) + 1U);
    ret = http_normalize_uri(buf_b, cap, buf_a);
    if (0 > ret) {
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

    cap = (strlen(msg->headers) * 2U) + 64U;
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

    if (0 > http_text_canonicalize(buf_b, cap, buf_a, 3)) {
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

    cap = (msg->body_len * 2U) + 64U;
    buf_a = (uint8_t *)malloc(cap);
    buf_b = (uint8_t *)malloc(cap);
    if (NULL == buf_a || NULL == buf_b) {
        free(buf_a);
        free(buf_b);
        return -1;
    }

    memcpy(buf_a, msg->body, msg->body_len);
    next_len = msg->body_len;
    if (0 > http_body_decode_percent_recursive(buf_b, cap, buf_a, next_len, 2,
                                               &next_len)) {
        free(buf_a);
        free(buf_b);
        return -1;
    }
    memcpy(buf_a, buf_b, next_len);
    if (0 > http_body_canonicalize(buf_b, cap, buf_a, next_len, 3, &next_len)) {
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

/* 26-04-03 추가 내용: 클라이언트가 write side를 닫은 뒤에도 HTTP 메시지가
 * 끝까지 완성되지 않은 세션은 더 이상 진전이 없으므로 408로 정리한다. */
static int mini_ips_reasm_is_incomplete_locked(mini_ips_ctx_t *ctx,
                                               uint32_t session_id) {
    http_message_t msg;
    int            i;
    int            rc;

    if (NULL == ctx || 0U == session_id) {
        return 0;
    }

    for (i = 0; i < MINI_IPS_MAX_SESSIONS; i++) {
        mini_ips_reasm_t *reasm;

        reasm = &ctx->reasm[i];
        if (!reasm->in_use || reasm->session_id != session_id ||
            NULL == reasm->buf || 0U == reasm->len) {
            continue;
        }

        memset(&msg, 0, sizeof(msg));
        rc = http_parser_try(reasm->buf, reasm->len, &msg);
        if (rc > 0) {
            http_parser_free(&msg);
        }

        return (0 == rc);
    }

    return 0;
}

/* 26-04-03 추가 내용: 더 이상 바이트가 오지 않는 incomplete 요청은
 * gotestwaf가 미판정으로 남기지 않도록 명시적으로 408 응답을 보낸다. */
static int mini_ips_send_timeout_response(int client_fd) {
    static const char response[] =
        "HTTP/1.1 408 Request Timeout\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 15\r\n"
        "Connection: close\r\n"
        "\r\n"
        "request timeout";

    return blocking_send(client_fd, response, sizeof(response) - 1U);
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

        pthread_mutex_lock(&ctx->state_lock);
        session = mini_ips_session_find(ctx, session_id);
        if (NULL == session || !session->in_use || session->client_fd < 0) {
            pthread_mutex_unlock(&ctx->state_lock);
            continue;
        }

        session->decision_queued = 0;

        if (MINI_IPS_RING_ACTION_BLOCK == action) {
            session->blocked = 1;

            if (0 != blocking_send(session->client_fd,
                                   (const char *)payload_buf, payload_len)) {
                if (EPIPE != errno && ECONNRESET != errno &&
                    ENOTSOCK != errno && EBADF != errno) {
                    pthread_mutex_unlock(&ctx->state_lock);
                    mini_ips_log_errno("tp", "blocking_send", errno);
                    return -1;
                }
            } else {
                /* 26-04-03 추가 내용: 응답 로그는 IPS가 클라이언트로 실제 보낸
                 * 차단 응답만 남긴다. */
                mini_ips_log_response_to_client(session_id, "block_403",
                                                payload_len,
                                                "blocked response sent");
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
                pthread_mutex_unlock(&ctx->state_lock);
                return 1;
            }
            pthread_mutex_unlock(&ctx->state_lock);
            continue;
        }

        if (MINI_IPS_RING_ACTION_ALLOW == action) {
            if (session->request_forwarded) {
                pthread_mutex_unlock(&ctx->state_lock);
                continue;
            }

            mini_ips_log_debug_flow(session_id, 11,
                                    "tp consumed allow decision");

            if (session->upstream_fd < 0) {
                if (0 != mini_ips_upstream_connect(&session->orig_dst,
                                                   &session->upstream_fd)) {
                    pthread_mutex_unlock(&ctx->state_lock);
                    mini_ips_log_message("tp",
                                         "mini_ips_upstream_connect failed");
                    return -1;
                }

                mini_ips_log_debug_flowf(session_id, 12,
                                         "upstream connected fd=%d",
                                         session->upstream_fd);

                if (0 != mini_ips_epoll_add(ctx->tp->epoll_fd,
                                            session->upstream_fd,
                                            EPOLLIN | EPOLLRDHUP |
                                                EPOLLHUP | EPOLLERR)) {
                    mini_ips_log_message("tp",
                                         "mini_ips_epoll_add upstream_fd failed");
                    close(session->upstream_fd);
                    session->upstream_fd = -1;
                    pthread_mutex_unlock(&ctx->state_lock);
                    return -1;
                }
            }

            if (0 != mini_ips_write_all(session->upstream_fd,
                                        session->pending_request,
                                        session->pending_request_len)) {
                pthread_mutex_unlock(&ctx->state_lock);
                mini_ips_log_message("tp",
                                     "mini_ips_write_all(upstream_fd) failed");
                return -1;
            }

            mini_ips_log_debug_flowf(session_id, 13,
                                     "request forwarded upstream len=%zu",
                                     session->pending_request_len);

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

        pthread_mutex_unlock(&ctx->state_lock);
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
    size_t          response_len;
    int             rc;

    if (NULL == ctx || NULL == data || 0U == len || NULL == ctx->engine) {
        mini_ips_log_message("worker",
                             "mini_ips_process_payload invalid input or engine");
        return -1;
    }

    pthread_mutex_lock(&ctx->state_lock);
    session = mini_ips_session_find(ctx, session_id);
    if (NULL == session || !session->in_use || session->client_fd < 0) {
        pthread_mutex_unlock(&ctx->state_lock);
        return 0;
    }
    if (session->blocked || session->decision_queued) {
        pthread_mutex_unlock(&ctx->state_lock);
        return 0;
    }

    reasm = mini_ips_reasm_get(ctx, session_id);
    if (NULL == reasm) {
        pthread_mutex_unlock(&ctx->state_lock);
        mini_ips_log_message("worker", "mini_ips_reasm_get failed");
        return -1;
    }

    memset(&msg, 0, sizeof(msg));
    memset(&result, 0, sizeof(result));
    memset(&decision, 0, sizeof(decision));
    memset(&block_ctx, 0, sizeof(block_ctx));

    if (0 != mini_ips_reasm_append(reasm, data, len)) {
        mini_ips_log_message("worker", "mini_ips_reasm_append failed");
        mini_ips_reasm_release(ctx, session_id);
        pthread_mutex_unlock(&ctx->state_lock);
        return -1;
    }

    mini_ips_log_debug_flowf(session_id, 5,
                             "worker appended payload chunk=%zu reasm_len=%zu",
                             len, reasm->len);

    rc = http_parser_try(reasm->buf, reasm->len, &msg);
    if (0 == rc) {
        pthread_mutex_unlock(&ctx->state_lock);
        mini_ips_log_parser_incomplete(session_id, len, reasm->len);
        return 0;
    }
    if (0 > rc) {
        mini_ips_log_message("worker", "http_parser_try failed");
        mini_ips_reasm_release(ctx, session_id);
        pthread_mutex_unlock(&ctx->state_lock);
        return -1;
    }

    mini_ips_log_debug_flowf(session_id, 6,
                             "http parsed method=%s uri_len=%zu body_len=%zu",
                             NULL != msg.method ? msg.method : "(null)",
                             NULL != msg.uri ? strlen(msg.uri) : 0U,
                             msg.body_len);

    if (0 != mini_ips_prepare_message(&msg)) {
        http_parser_free(&msg);
        mini_ips_log_message("worker", "mini_ips_prepare_message failed");
        mini_ips_reasm_release(ctx, session_id);
        pthread_mutex_unlock(&ctx->state_lock);
        return -1;
    }

    mini_ips_log_debug_flowf(session_id, 7,
                             "message prepared uri_len=%zu headers_len=%zu body_len=%zu",
                             NULL != msg.uri ? strlen(msg.uri) : 0U,
                             NULL != msg.headers ? strlen(msg.headers) : 0U,
                             msg.body_len);

    {
        uint64_t detect_us;
        long     detect_ms;

        detect_us = 0U;
        rc = detect_run(ctx->engine, &msg, &result, &detect_us);
        if (0 != rc) {
            http_parser_free(&msg);
            mini_ips_log_message("worker", "detect_run failed");
            mini_ips_reasm_release(ctx, session_id);
            pthread_mutex_unlock(&ctx->state_lock);
            return -1;
        }

        detect_ms = (long)((detect_us + 999ULL) / 1000ULL);
        mini_ips_log_detect_time(session_id, detect_us, detect_ms,
                                 reasm->len);
    }

    mini_ips_log_debug_flowf(session_id, 8,
                             "detect finished matched=%zu blocked=%d score=%d",
                             result.total_matches, result.matched,
                             result.total_score);

    response_buf[0] = '\0';
    response_len = 0U;
    block_ctx.rs = &result;
    block_ctx.dc = &decision;
    block_ctx.res_buf = response_buf;
    block_ctx.res_buf_sz = sizeof(response_buf);
    block_ctx.rs_len = &response_len;

    rc = blocking_request(&block_ctx);
    if (0 > rc) {
        http_parser_free(&msg);
        mini_ips_log_message("worker", "blocking_request failed");
        mini_ips_reasm_release(ctx, session_id);
        pthread_mutex_unlock(&ctx->state_lock);
        return -1;
    }

    mini_ips_log_detect_result(session_id, &result, (1 == rc), decision.reason);

    if (1 == rc && NULL != session && session->client_fd >= 0) {
        if (0 != res_ring_enq(&ctx->res_ring, MINI_IPS_RING_ACTION_BLOCK,
                              session_id,
                              (const uint8_t *)response_buf,
                              (uint32_t)response_len)) {
            pthread_mutex_unlock(&ctx->state_lock);
            mini_ips_log_message("worker", "res_ring_enq(block) failed");
            return -1;
        }
        mini_ips_log_debug_flowf(session_id, 9,
                                 "block queued response_len=%zu reason=%s",
                                 response_len,
                                 NULL != decision.reason ? decision.reason :
                                                           "n/a");
        mini_ips_signal_res_event(ctx);
        session->decision_queued = 1;
    } else if (0 == rc && NULL != session && session->client_fd >= 0) {
        mini_ips_log_allow_message(session_id, &msg);

        if (0 != mini_ips_reserve_buffer(&session->pending_request,
                                         &session->pending_request_cap,
                                         reasm->len)) {
            http_parser_free(&msg);
            mini_ips_log_message("worker", "pending_request reserve failed");
            mini_ips_reasm_release(ctx, session_id);
            pthread_mutex_unlock(&ctx->state_lock);
            return -1;
        }

        memcpy(session->pending_request, reasm->buf, reasm->len);
        session->pending_request_len = reasm->len;

        if (0 != res_ring_enq(&ctx->res_ring, MINI_IPS_RING_ACTION_ALLOW,
                              session_id, NULL, 0U)) {
            http_parser_free(&msg);
            mini_ips_log_message("worker", "res_ring_enq(allow) failed");
            mini_ips_reasm_release(ctx, session_id);
            pthread_mutex_unlock(&ctx->state_lock);
            return -1;
        }
        mini_ips_log_debug_flowf(session_id, 9,
                                 "allow queued pending_request_len=%zu",
                                 reasm->len);
        mini_ips_signal_res_event(ctx);
        session->decision_queued = 1;
    }

    http_parser_free(&msg);

    mini_ips_reasm_release(ctx, session_id);
    pthread_mutex_unlock(&ctx->state_lock);

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
    ctx->res_event_fd = -1;
    ctx->res_event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (-1 == ctx->res_event_fd) {
        ctx->res_event_fd = -1;
        return -1;
    }

    if (0 != pthread_mutex_init(&ctx->state_lock, NULL)) {
        mini_ips_log_message("set", "pthread_mutex_init(state_lock) failed");
        close(ctx->res_event_fd);
        ctx->res_event_fd = -1;
        return -1;
    }

    ruleset_path = getenv(MINI_IPS_RULESET_ENV);
    if (NULL == ruleset_path || '\0' == ruleset_path[0]) {
        mini_ips_log_message("set",
                             "MINI_IPS_RULESET_DIR is missing or empty");
        pthread_mutex_destroy(&ctx->state_lock);
        close(ctx->res_event_fd);
        ctx->res_event_fd = -1;
        return -1;
    }

    ctx->ruleset_path = ruleset_path;

    if (0 != regex_signatures_load(&ctx->db, ctx->ruleset_path)) {
        mini_ips_log_message("set", "regex_signatures_load failed");
        pthread_mutex_destroy(&ctx->state_lock);
        close(ctx->res_event_fd);
        ctx->res_event_fd = -1;
        return -1;
    }

    ctx->engine = engine_regex_create(&ctx->db);
    if (NULL == ctx->engine) {
        mini_ips_log_message("set", "engine_regex_create returned NULL");
        regex_signatures_free(&ctx->db);
        pthread_mutex_destroy(&ctx->state_lock);
        close(ctx->res_event_fd);
        ctx->res_event_fd = -1;
        return -1;
    }

    if (0 != req_ring_init(&ctx->req_ring, MINI_IPS_RING_SLOT_COUNT)) {
        mini_ips_log_message("set", "req_ring_init failed");
        engine_regex_destroy(ctx->engine);
        ctx->engine = NULL;
        regex_signatures_free(&ctx->db);
        pthread_mutex_destroy(&ctx->state_lock);
        close(ctx->res_event_fd);
        ctx->res_event_fd = -1;
        return -1;
    }

    if (0 != res_ring_init(&ctx->res_ring, MINI_IPS_RING_SLOT_COUNT)) {
        mini_ips_log_message("set", "res_ring_init failed");
        req_ring_free(&ctx->req_ring);
        engine_regex_destroy(ctx->engine);
        ctx->engine = NULL;
        regex_signatures_free(&ctx->db);
        pthread_mutex_destroy(&ctx->state_lock);
        close(ctx->res_event_fd);
        ctx->res_event_fd = -1;
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
    
    if (0 != mini_ips_epoll_add(ctx->tp->epoll_fd, ctx->res_event_fd,
                                EPOLLIN | EPOLLERR | EPOLLHUP)) {
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

        pthread_mutex_lock(&ctx->state_lock);
        session = mini_ips_session_alloc(ctx, client_fd, &orig_dst);
        if (NULL == session) {
            pthread_mutex_unlock(&ctx->state_lock);
            close(client_fd);
            mini_ips_log_message("tp", "mini_ips_session_alloc returned NULL");
            return -1;
        }
        mini_ips_log_debug_flowf(session->session_id, 1,
                                 "accepted client_fd=%d orig_dst=%s:%u",
                                 client_fd, inet_ntoa(orig_dst.sin_addr),
                                 (unsigned)ntohs(orig_dst.sin_port));
        pthread_mutex_unlock(&ctx->state_lock);

        if (0 != mini_ips_epoll_add(ctx->tp->epoll_fd, client_fd,
                                    EPOLLIN | EPOLLRDHUP | EPOLLHUP |
                                        EPOLLERR)) {
            pthread_mutex_lock(&ctx->state_lock);
            mini_ips_session_release(session);
            pthread_mutex_unlock(&ctx->state_lock);
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
                mini_ips_epoll_del(ctx->tp->epoll_fd, ctx->res_event_fd);
                return -1;
            }
            if (res_rc > 0) {
                break;
            }

            if (NULL != session) {
                upstream_fd = session->upstream_fd;
            }

            nready = epoll_wait(ctx->tp->epoll_fd, events, 8,
                                MINI_IPS_RES_RING_POLL_MS);
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
                mini_ips_epoll_del(ctx->tp->epoll_fd, ctx->res_event_fd);
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

                if (fd == ctx->res_event_fd) {
                    uint64_t counter;

                    for (;;) {
                        ssize_t nread;

                        nread = read(ctx->res_event_fd, &counter,
                                     sizeof(counter));
                        if (nread == (ssize_t)sizeof(counter)) {
                            continue;
                        }
                        if (nread < 0 &&
                            (errno == EAGAIN || errno == EWOULDBLOCK)) {
                            break;
                        }
                        if (nread < 0 && errno == EINTR) {
                            continue;
                        }
                        break;
                    }

                    res_rc = mini_ips_handle_res_ring(ctx, session,
                                                      &client_open,
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
                        mini_ips_epoll_del(ctx->tp->epoll_fd,
                                           ctx->res_event_fd);
                        return -1;
                    }
                    if (res_rc > 0) {
                        break;
                    }
                    continue;
                }

                if (NULL != session) {
                    pthread_mutex_lock(&ctx->state_lock);
                    if (session->blocked) {
                        client_open = 0;
                        upstream_open = 0;
                        mini_ips_epoll_del(ctx->tp->epoll_fd, client_fd);
                        mini_ips_epoll_del(ctx->tp->epoll_fd, upstream_fd);
                        pthread_mutex_unlock(&ctx->state_lock);
                        break;
                    }
                    pthread_mutex_unlock(&ctx->state_lock);
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
                        mini_ips_epoll_del(ctx->tp->epoll_fd, ctx->res_event_fd);
                        return -1;
                    }

                    if (0 == n) {
                        int should_timeout;

                        should_timeout = 0;
                        if (NULL != session) {
                            pthread_mutex_lock(&ctx->state_lock);
                            should_timeout =
                                waiting_decision && !session->decision_queued &&
                                !session->request_forwarded && !session->blocked &&
                                mini_ips_reasm_is_incomplete_locked(
                                    ctx, session->session_id);
                            pthread_mutex_unlock(&ctx->state_lock);
                        }

                        /* 26-04-03 추가 내용: EOF 이후에도 HTTP 파싱이 incomplete면
                         * 더 기다리지 않고 408 응답으로 세션을 종료한다. */
                        if (should_timeout) {
                            if (0 != mini_ips_send_timeout_response(client_fd) &&
                                EPIPE != errno && ECONNRESET != errno &&
                                ENOTSOCK != errno && EBADF != errno) {
                                mini_ips_log_errno("tp",
                                                   "mini_ips_send_timeout_response",
                                                   errno);
                            } else if (NULL != session) {
                                /* 26-04-03 추가 내용: EOF 이후 incomplete 요청에
                                 * 대해 클라이언트로 보낸 408 응답만 기록한다. */
                                mini_ips_log_response_to_client(
                                    session->session_id, "timeout_408", 112U,
                                    "incomplete request on client close");
                            }

                            if (upstream_fd >= 0) {
                                shutdown(upstream_fd, SHUT_RDWR);
                                mini_ips_epoll_del(ctx->tp->epoll_fd,
                                                   upstream_fd);
                            }
                            shutdown(client_fd, SHUT_RDWR);
                            client_open = 0;
                            upstream_open = 0;
                            waiting_decision = 0;
                            mini_ips_epoll_del(ctx->tp->epoll_fd, client_fd);
                            continue;
                        }

                        if (upstream_fd >= 0) {
                            shutdown(upstream_fd, SHUT_WR);
                        }
                        if (NULL != session) {
                            mini_ips_log_debug_flow(session->session_id, 14,
                                                    "client closed write side");
                        }
                        client_open = 0;
                        mini_ips_epoll_del(ctx->tp->epoll_fd, client_fd);
                        continue;
                    }

                    if (NULL != session) {
                        mini_ips_log_debug_flowf(session->session_id, 2,
                                                 "client recv len=%zd", n);
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
                        mini_ips_epoll_del(ctx->tp->epoll_fd, ctx->res_event_fd);
                        return -1;
                    }

                    if (NULL != session) {
                        mini_ips_log_debug_flowf(session->session_id, 3,
                                                 "request queued to worker len=%zd",
                                                 n);
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
                        mini_ips_epoll_del(ctx->tp->epoll_fd, ctx->res_event_fd);
                        return -1;
                    }

                    if (0 == n) {
                        shutdown(client_fd, SHUT_WR);
                        if (NULL != session) {
                            mini_ips_log_debug_flow(session->session_id, 15,
                                                    "upstream closed write side");
                        }
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
                        mini_ips_epoll_del(ctx->tp->epoll_fd, ctx->res_event_fd);
                        return -1;
                    }

                    if (NULL != session) {
                        /* 26-04-03 추가 내용: 응답 로그는 upstream에서 받아
                         * 클라이언트로 릴레이한 바이트만 남긴다. */
                        mini_ips_log_response_to_client(
                            session->session_id, "relay_upstream",
                            (size_t)n, "upstream response relayed");
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
            mini_ips_log_debug_flow(session->session_id, 18,
                                    "session cleanup");
            pthread_mutex_lock(&ctx->state_lock);
            mini_ips_reasm_release(ctx, session->session_id);
            mini_ips_session_release(session);
            pthread_mutex_unlock(&ctx->state_lock);
        }
    }

    mini_ips_epoll_del(ctx->tp->epoll_fd, ctx->res_event_fd);
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
            mini_ips_log_debug_flowf(session_id, 4,
                                     "worker dequeued request len=%u",
                                     out_len);
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

    if (ctx->res_event_fd >= 0) {
        close(ctx->res_event_fd);
    }

    regex_signatures_free(&ctx->db);

    if (NULL != ctx->tp) {
        tproxy_destroy(ctx->tp);
        ctx->tp = NULL;
    }

    ctx->ruleset_path = NULL;
    ctx->initialized = 0;
    ctx->stop = 0;
    
    pthread_mutex_destroy(&ctx->state_lock);
}

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/tproxy.h"

typedef struct {
    int socket_fd;
    int socket_calls;
    int setsockopt_calls;
    int bind_calls;
    int listen_calls;
    int close_calls;
    int last_close_fd;
    int last_listen_backlog;
    struct sockaddr_in last_bind_addr;
    int transparent_rc;
    int reuseaddr_rc;
    int bind_rc;
    int listen_rc;
} mock_state_t;

static mock_state_t mock;

static void mock_reset(void) {
    memset(&mock, 0, sizeof(mock));
    mock.socket_fd = 100;
}

int mock_socket(int domain, int type, int protocol);
int mock_setsockopt(int sockfd, int level, int optname,
                    const void *optval, socklen_t optlen);
int mock_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int mock_listen(int sockfd, int backlog);
int mock_close(int fd);

#define socket mock_socket
#define setsockopt mock_setsockopt
#define bind mock_bind
#define listen mock_listen
#define close mock_close
#include "../src/inline/tproxy.c"
#undef close
#undef listen
#undef bind
#undef setsockopt
#undef socket

int mock_socket(int domain, int type, int protocol) {
    (void)domain;
    (void)type;
    (void)protocol;
    mock.socket_calls++;
    return mock.socket_fd;
}

int mock_setsockopt(int sockfd, int level, int optname,
                    const void *optval, socklen_t optlen) {
    (void)sockfd;
    (void)level;
    (void)optval;
    (void)optlen;
    mock.setsockopt_calls++;
    if (optname == IP_TRANSPARENT) {
        return mock.transparent_rc;
    }
    if (optname == SO_REUSEADDR) {
        return mock.reuseaddr_rc;
    }
    return 0;
}

int mock_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    (void)sockfd;
    (void)addrlen;
    mock.bind_calls++;
    memcpy(&mock.last_bind_addr, addr, sizeof(mock.last_bind_addr));
    return mock.bind_rc;
}

int mock_listen(int sockfd, int backlog) {
    (void)sockfd;
    mock.listen_calls++;
    mock.last_listen_backlog = backlog;
    return mock.listen_rc;
}

int mock_close(int fd) {
    mock.close_calls++;
    mock.last_close_fd = fd;
    return 0;
}

static int check_true(int condition, const char *expr, int line) {
    if (!condition) {
        fprintf(stderr, "check failed at line %d: %s\n", line, expr);
        return 1;
    }
    return 0;
}

#define CHECK(expr)                                                           \
    do {                                                                      \
        if (check_true((expr), #expr, __LINE__) != 0) {                       \
            return 1;                                                         \
        }                                                                     \
    } while (0)

static int test_create_rejects_null_cfg(void) {
    mock_reset();

    CHECK(tproxy_create(NULL) == NULL);
    CHECK(mock.socket_calls == 0);

    return 0;
}

static int test_create_uses_defaults_for_null_ip_and_non_positive_backlog(void) {
    tproxy_cfg_t cfg = {.bind_ip = NULL, .bind_port = 18080, .backlog = 0};
    tproxy_t    *tp  = NULL;

    mock_reset();

    tp = tproxy_create(&cfg);
    CHECK(tp != NULL);
    CHECK(tp->listen_fd == mock.socket_fd);
    CHECK(tp->bind_port == cfg.bind_port);
    CHECK(tp->backlog == 128);
    CHECK(strcmp(tp->bind_ip, "0.0.0.0") == 0);
    CHECK(mock.socket_calls == 1);
    CHECK(mock.setsockopt_calls == 2);
    CHECK(mock.bind_calls == 1);
    CHECK(mock.listen_calls == 1);
    CHECK(mock.last_listen_backlog == 128);
    CHECK(mock.last_bind_addr.sin_family == AF_INET);
    CHECK(mock.last_bind_addr.sin_port == htons(cfg.bind_port));
    CHECK(mock.last_bind_addr.sin_addr.s_addr == htonl(INADDR_ANY));

    tproxy_destroy(tp);
    CHECK(mock.close_calls == 1);
    CHECK(mock.last_close_fd == mock.socket_fd);

    return 0;
}

static int test_create_keeps_explicit_bind_ip_and_backlog(void) {
    tproxy_cfg_t cfg = {.bind_ip = "127.0.0.1", .bind_port = 8080, .backlog = 7};
    tproxy_t    *tp  = NULL;
    struct in_addr expected_addr;

    mock_reset();
    CHECK(inet_pton(AF_INET, cfg.bind_ip, &expected_addr) == 1);

    tp = tproxy_create(&cfg);
    CHECK(tp != NULL);
    CHECK(strcmp(tp->bind_ip, cfg.bind_ip) == 0);
    CHECK(tp->backlog == cfg.backlog);
    CHECK(mock.last_listen_backlog == cfg.backlog);
    CHECK(mock.last_bind_addr.sin_addr.s_addr == expected_addr.s_addr);

    tproxy_destroy(tp);
    CHECK(mock.close_calls == 1);

    return 0;
}

static int test_create_closes_socket_when_bind_ip_is_invalid(void) {
    tproxy_cfg_t cfg = {.bind_ip = "bad-ip", .bind_port = 50080, .backlog = 3};

    mock_reset();
    mock.socket_fd = 55;

    CHECK(tproxy_create(&cfg) == NULL);
    CHECK(mock.socket_calls == 1);
    CHECK(mock.setsockopt_calls == 2);
    CHECK(mock.bind_calls == 0);
    CHECK(mock.listen_calls == 0);
    CHECK(mock.close_calls == 1);
    CHECK(mock.last_close_fd == 55);

    return 0;
}

int main(void) {
    if (test_create_rejects_null_cfg() != 0) {
        return 1;
    }
    if (test_create_uses_defaults_for_null_ip_and_non_positive_backlog() != 0) {
        return 1;
    }
    if (test_create_keeps_explicit_bind_ip_and_backlog() != 0) {
        return 1;
    }
    if (test_create_closes_socket_when_bind_ip_is_invalid() != 0) {
        return 1;
    }

    puts("ok: units_tproxy_create");
    return 0;
}

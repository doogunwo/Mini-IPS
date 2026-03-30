#include "tproxy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

/* -----------------epoll API (internal static) ----------------------------*/

static int tproxy_epoll_add(int event_fd, int fd, uint32_t events) {
    struct epoll_event ev;

    if (event_fd < 0 || fd < 0) {
        errno = EINVAL;
        return -1;
    }

    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.fd = fd;

    if (epoll_ctl(event_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        return -1;
    }

    return 0;
}

static int tproxy_epoll_del(int event_fd, int fd) {
    if (event_fd < 0 || fd < 0) {
        errno = EINVAL;
        return -1;
    }

    if (epoll_ctl(event_fd, EPOLL_CTL_DEL, fd, NULL) < 0) {
        return -1;
    }

    return 0;
}

static int tproxy_epoll_init(tproxy_t *tp) {
    if (tp == NULL || tp->listen_fd < 0) {
        errno = EINVAL;
        return -1;
    }

    tp->epoll_fd = epoll_create1(0);
    if (tp->epoll_fd < 0) {
        return -1;
    }

    if (tproxy_epoll_add(tp->epoll_fd, tp->listen_fd,
                         EPOLLIN | EPOLLERR | EPOLLHUP) < 0) {
        close(tp->epoll_fd);
        tp->epoll_fd = -1;
        return -1;
    }

    return 0;
}

static int write_all(int fd, const uint8_t *buf, size_t len) {
    size_t written = 0;

    while (written < len) {
        ssize_t n = send(fd, buf + written, len - written, 0);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        written += (size_t)n;
    }

    return 0;
}

static void format_endpoint(const struct sockaddr_in *addr, char *buf,
                            size_t buf_len) {
    char ip[INET_ADDRSTRLEN];

    if (addr == NULL || buf == NULL || buf_len == 0) {
        return;
    }

    if (inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip)) == NULL) {
        strncpy(ip, "?", sizeof(ip) - 1);
        ip[sizeof(ip) - 1] = '\0';
    }

    snprintf(buf, buf_len, "%s:%u", ip, (unsigned)ntohs(addr->sin_port));
}

tproxy_t *tproxy_create(const tproxy_cfg_t *cfg) {
    tproxy_t *tproxy = NULL;
    struct sockaddr_in addr;
    int fd = -1;
    int opt = 1;
    const char *bind_ip = NULL;
    int backlog = 0;
    int saved_errno = 0;

    if (cfg == NULL) {
        fprintf(stderr, "tproxy_create: cfg is NULL\n");
        return NULL;
    }

    bind_ip = (cfg->bind_ip != NULL) ? cfg->bind_ip : "0.0.0.0";
    backlog = (cfg->backlog > 0) ? cfg->backlog : 128;

    tproxy = (tproxy_t *)malloc(sizeof(*tproxy));
    if (tproxy == NULL) {
        perror("malloc");
        return NULL;
    }

    memset(tproxy, 0, sizeof(*tproxy));
    tproxy->listen_fd = -1;
    tproxy->epoll_fd = -1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        saved_errno = errno;
        perror("socket");
        goto fail;
    }

    if (setsockopt(fd, IPPROTO_IP, IP_TRANSPARENT, &opt, sizeof(opt)) < 0) {
        saved_errno = errno;
        perror("setsockopt(IP_TRANSPARENT)");
        goto fail;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        saved_errno = errno;
        perror("setsockopt(SO_REUSEADDR)");
        goto fail;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(cfg->bind_port);

    if (strcmp(bind_ip, "0.0.0.0") == 0) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (inet_pton(AF_INET, bind_ip, &addr.sin_addr) != 1) {
        saved_errno = EINVAL;
        fprintf(stderr, "invalid bind_ip: %s\n", bind_ip);
        goto fail;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        saved_errno = errno;
        perror("bind");
        goto fail;
    }

    if (listen(fd, backlog) < 0) {
        saved_errno = errno;
        perror("listen");
        goto fail;
    }

    tproxy->listen_fd = fd;
    tproxy->bind_port = cfg->bind_port;
    tproxy->backlog = backlog;
    strncpy(tproxy->bind_ip, bind_ip, sizeof(tproxy->bind_ip) - 1);
    tproxy->bind_ip[sizeof(tproxy->bind_ip) - 1] = '\0';

    if (tproxy_epoll_init(tproxy) < 0) {
        saved_errno = errno;
        perror("tproxy_epoll_init");
        goto fail;
    }

    return tproxy;

fail:
    if (fd >= 0) {
        close(fd);
    }
    tproxy_destroy(tproxy);
    if (saved_errno != 0) {
        errno = saved_errno;
    }
    return NULL;
}

int tproxy_accept_client(tproxy_t *tp,
                         struct sockaddr_in *peer,
                         struct sockaddr_in *orig_dst,
                         int *client_fd) {
    socklen_t peer_len;
    socklen_t dst_len;
    int fd;

    if (tp == NULL || peer == NULL || orig_dst == NULL || client_fd == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (tp->listen_fd < 0) {
        errno = EBADF;
        return -1;
    }

    peer_len = sizeof(*peer);
    dst_len = sizeof(*orig_dst);

    fd = accept(tp->listen_fd, (struct sockaddr *)peer, &peer_len);
    if (fd < 0) {
        if (errno == EINTR) {
            return -2;
        }
        return -1;
    }

    if (getsockname(fd, (struct sockaddr *)orig_dst, &dst_len) < 0) {
        close(fd);
        return -1;
    }

    *client_fd = fd;
    return 0;
}

int upstream_connect(const struct sockaddr_in *orig_dst, int *upstream_fd) {
    int fd;
    int rc;

    if (orig_dst == NULL || upstream_fd == NULL) {
        errno = EINVAL;
        return -1;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    rc = connect(fd, (const struct sockaddr *)orig_dst, sizeof(*orig_dst));
    if (rc < 0) {
        close(fd);
        return -1;
    }

    *upstream_fd = fd;
    return 0;
}

int tproxy_relay_loop(tproxy_t *tp, int client_fd, int upstream_fd) {
    struct epoll_event events[8];
    uint8_t client_buf[8192];
    uint8_t upstream_buf[8192];
    struct sockaddr_in client_peer;
    struct sockaddr_in orig_dst;
    socklen_t client_peer_len = sizeof(client_peer);
    socklen_t orig_dst_len = sizeof(orig_dst);
    char client_ep[64];
    char server_ep[64];
    int client_open = 1;
    int upstream_open = 1;

    if (tp == NULL || tp->epoll_fd < 0 || client_fd < 0 || upstream_fd < 0) {
        errno = EINVAL;
        return -1;
    }

    memset(&client_peer, 0, sizeof(client_peer));
    memset(&orig_dst, 0, sizeof(orig_dst));
    if (getpeername(client_fd, (struct sockaddr *)&client_peer, &client_peer_len) < 0) {
        strncpy(client_ep, "unknown", sizeof(client_ep) - 1);
        client_ep[sizeof(client_ep) - 1] = '\0';
    } else {
        format_endpoint(&client_peer, client_ep, sizeof(client_ep));
    }
    if (getsockname(client_fd, (struct sockaddr *)&orig_dst, &orig_dst_len) < 0) {
        strncpy(server_ep, "unknown", sizeof(server_ep) - 1);
        server_ep[sizeof(server_ep) - 1] = '\0';
    } else {
        format_endpoint(&orig_dst, server_ep, sizeof(server_ep));
    }

    if (tproxy_epoll_add(tp->epoll_fd, client_fd,
                         EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR) < 0) {
        return -1;
    }

    if (tproxy_epoll_add(tp->epoll_fd, upstream_fd,
                         EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR) < 0) {
        tproxy_epoll_del(tp->epoll_fd, client_fd);
        return -1;
    }

    while (client_open || upstream_open) {
        int i;
        int nready = epoll_wait(tp->epoll_fd, events, 8, -1);

        if (nready < 0) {
            if (errno == EINTR) {
                continue;
            }
            goto fail;
        }

        for (i = 0; i < nready; ++i) {
            int fd = events[i].data.fd;
            uint32_t ev = events[i].events;
            ssize_t n;

            if (fd == tp->listen_fd) {
                continue;
            }

            if (fd == client_fd && client_open) {
                if ((ev & EPOLLERR) || (ev & EPOLLHUP) || (ev & EPOLLRDHUP) ||
                    (ev & EPOLLIN)) {
                    n = recv(client_fd, client_buf, sizeof(client_buf), 0);
                    if (n < 0) {
                        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                            continue;
                        }
                        goto fail;
                    }
                    if (n == 0) {
                        shutdown(upstream_fd, SHUT_WR);
                        client_open = 0;
                        tproxy_epoll_del(tp->epoll_fd, client_fd);
                    } else if (write_all(upstream_fd, client_buf, (size_t)n) < 0) {
                        goto fail;
                    } else {
                        printf("[TPROXY][request] %s -> %s bytes=%zd\n", client_ep, server_ep, n);
                    }
                }
            } else if (fd == upstream_fd && upstream_open) {
                if ((ev & EPOLLERR) || (ev & EPOLLHUP) || (ev & EPOLLRDHUP) ||
                    (ev & EPOLLIN)) {
                    n = recv(upstream_fd, upstream_buf, sizeof(upstream_buf), 0);
                    if (n < 0) {
                        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                            continue;
                        }
                        goto fail;
                    }
                    if (n == 0) {
                        shutdown(client_fd, SHUT_WR);
                        upstream_open = 0;
                        tproxy_epoll_del(tp->epoll_fd, upstream_fd);
                    } else if (write_all(client_fd, upstream_buf, (size_t)n) < 0) {
                        goto fail;
                    } else {
                        printf("[TPROXY][response] %s -> %s bytes=%zd\n", server_ep, client_ep, n);
                    }
                }
            }
        }
    }

    tproxy_epoll_del(tp->epoll_fd, client_fd);
    tproxy_epoll_del(tp->epoll_fd, upstream_fd);
    return 0;

fail:
    tproxy_epoll_del(tp->epoll_fd, client_fd);
    tproxy_epoll_del(tp->epoll_fd, upstream_fd);
    return -1;
}

void tproxy_destroy(tproxy_t *tp) {
    if (tp == NULL) {
        return;
    }

    if (tp->epoll_fd >= 0) {
        close(tp->epoll_fd);
        tp->epoll_fd = -1;
    }

    if (tp->listen_fd >= 0) {
        close(tp->listen_fd);
        tp->listen_fd = -1;
    }

    free(tp);
}

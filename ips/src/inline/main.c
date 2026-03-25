#include "tproxy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;

static void handle_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static void print_endpoint(const char *label, const struct sockaddr_in *addr) {
    char ip[INET_ADDRSTRLEN];

    if (inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip)) == NULL) {
        strncpy(ip, "?", sizeof(ip) - 1);
        ip[sizeof(ip) - 1] = '\0';
    }

    printf("%s=%s:%u", label, ip, (unsigned)ntohs(addr->sin_port));
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

static int connect_upstream(const struct sockaddr_in *dst_addr) {
    int upstream_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (upstream_fd < 0) {
        perror("socket(upstream)");
        return -1;
    }

    if (connect(upstream_fd, (const struct sockaddr *)dst_addr, sizeof(*dst_addr)) < 0) {
        perror("connect(upstream)");
        close(upstream_fd);
        return -1;
    }

    return upstream_fd;
}

static int relay_loop(int client_fd, int upstream_fd) {
    uint8_t client_buf[8192];
    uint8_t upstream_buf[8192];
    int client_open = 1;
    int upstream_open = 1;

    while (client_open || upstream_open) {
        struct pollfd pfds[2];
        int rc;

        memset(pfds, 0, sizeof(pfds));
        pfds[0].fd = client_fd;
        pfds[0].events = client_open ? (short)(POLLIN | POLLHUP | POLLERR) : 0;
        pfds[1].fd = upstream_fd;
        pfds[1].events = upstream_open ? (short)(POLLIN | POLLHUP | POLLERR) : 0;

        rc = poll(pfds, 2, -1);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("poll");
            return -1;
        }

        if (client_open && (pfds[0].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n = recv(client_fd, client_buf, sizeof(client_buf), 0);

            if (n < 0) {
                if (errno != EINTR) {
                    perror("recv(client)");
                    return -1;
                }
            } else if (n == 0) {
                shutdown(upstream_fd, SHUT_WR);
                client_open = 0;
            } else if (write_all(upstream_fd, client_buf, (size_t)n) < 0) {
                perror("send(upstream)");
                return -1;
            }
        }

        if (upstream_open && (pfds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n = recv(upstream_fd, upstream_buf, sizeof(upstream_buf), 0);

            if (n < 0) {
                if (errno != EINTR) {
                    perror("recv(upstream)");
                    return -1;
                }
            } else if (n == 0) {
                shutdown(client_fd, SHUT_WR);
                upstream_open = 0;
            } else if (write_all(client_fd, upstream_buf, (size_t)n) < 0) {
                perror("send(client)");
                return -1;
            }
        }
    }

    return 0;
}

int main(void) {
    tproxy_cfg_t cfg = {
        .bind_ip = "0.0.0.0",
        .bind_port = 50080,
        .backlog = 128,
    };
    tproxy_t *tp;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGPIPE, SIG_IGN);

    tp = tproxy_create(&cfg);
    if (tp == NULL) {
        fprintf(stderr, "failed to create tproxy listener\n");
        return 1;
    }

    printf("TPROXY listener started: %s:%u backlog=%d fd=%d\n",
           tp->bind_ip, tp->bind_port, tp->backlog, tp->listen_fd);
    fflush(stdout);

    while (!g_stop) {
        struct sockaddr_in peer_addr;
        struct sockaddr_in local_addr;
        socklen_t peer_len = sizeof(peer_addr);
        socklen_t local_len = sizeof(local_addr);
        int client_fd;
        int upstream_fd;

        memset(&peer_addr, 0, sizeof(peer_addr));
        memset(&local_addr, 0, sizeof(local_addr));

        client_fd = accept(tp->listen_fd, (struct sockaddr *)&peer_addr, &peer_len);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            break;
        }

        if (getsockname(client_fd, (struct sockaddr *)&local_addr, &local_len) < 0) {
            perror("getsockname");
            close(client_fd);
            continue;
        }

        printf("[TPROXY] accepted ");
        print_endpoint("client", &peer_addr);
        printf(" ");
        print_endpoint("original_dst", &local_addr);
        printf("\n");
        fflush(stdout);

        upstream_fd = connect_upstream(&local_addr);
        if (upstream_fd < 0) {
            close(client_fd);
            continue;
        }

        if (relay_loop(client_fd, upstream_fd) < 0) {
            fprintf(stderr, "[TPROXY] relay error\n");
        }

        close(upstream_fd);
        close(client_fd);
    }

    tproxy_destroy(tp);
    return 0;
}

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

#include "tproxy.h"

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

int main(void) {
    tproxy_cfg_t cfg = {
        .bind_ip   = "0.0.0.0",
        .bind_port = 50080,
        .backlog   = 128,
    };
    tproxy_t *tp;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    tp = tproxy_create(&cfg);
    if (NULL == tp) {
        fprintf(stderr, "failed to create tproxy listener\n");
        return 1;
    }

    printf("TPROXY listener started: %s:%u backlog=%d fd=%d\n", tp->bind_ip,
           tp->bind_port, tp->backlog, tp->listen_fd);
    fflush(stdout);

    while (!g_stop) {
        printf("------------------------------------------------------------------\n");
        struct sockaddr_in peer_addr;
        struct sockaddr_in local_addr;

        int client_fd   = -1;
        int upstream_fd = -1;
        int rc;

        memset(&peer_addr, 0, sizeof(peer_addr));
        memset(&local_addr, 0, sizeof(local_addr));
        
        rc = tproxy_accept_client(tp, &peer_addr, &local_addr, &client_fd);
        if (-2 == rc) {
            continue;
        }

        if (rc < 0) {
            perror("tproxy accept client");
            continue;;
        }
        printf("[TPROXY] accepted ");
        print_endpoint("client", &peer_addr);
        printf(" ");
        print_endpoint("original_dst", &local_addr);
        printf("\n------------------------------------------------------------------\n");

        rc = tproxy_connect_upstream(&local_addr, &upstream_fd); //현재 여기 에러 발생함
        if (rc < 0) {
            perror("tproxy_connect_upstream");
            close(client_fd);
            continue;
        }

        rc = tproxy_relay_loop(tp, client_fd, upstream_fd);
        if (rc < 0 ){
            fprintf(stderr, "[TPORXY] relay error\n");
        }

        close(upstream_fd);
        close(client_fd);
    }

    tproxy_destroy(tp);
    return 0;
}

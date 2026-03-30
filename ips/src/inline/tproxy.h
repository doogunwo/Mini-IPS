#pragma once
#include <netinet/in.h>
#include <stdint.h>

#define IP_TRANSPARENT 19

/** TPROXY listener 생성 설정 */
typedef struct {
    const char *bind_ip;
    uint16_t    bind_port;
    int         backlog;
} tproxy_cfg_t;

/** TPROXY listener 객체 */
typedef struct {
    int      listen_fd;
    int      epoll_fd;
    char     bind_ip[INET_ADDRSTRLEN];
    uint16_t bind_port;
    int      backlog;
} tproxy_t;

/** TPROXY listener 생성 */
tproxy_t *tproxy_create(const tproxy_cfg_t *cfg);

int tproxy_accept_client(tproxy_t *tp, struct sockaddr_in *peer,
                         struct sockaddr_in *orig_dst, int *client_fd);
int upstream_connect(const struct sockaddr_in *orig_dst, int *upstream_fd);
int tproxy_relay_loop(tproxy_t *tp, int client_fd, int upstream_fd);
/** TPROXY listener 해제 */
void tproxy_destroy(tproxy_t *tp);

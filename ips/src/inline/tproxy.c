#include "tproxy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

tproxy_t *tproxy_create(const tproxy_cfg_t *cfg) {
    tproxy_t *tproxy = NULL;
    struct sockaddr_in addr;
    int fd = -1;
    int opt = 1;
    const char *bind_ip = NULL;
    int backlog = 0;
    int saved_errno = 0;

    if (NULL == cfg) {
        fprintf(stderr, "tproxy_create: cfg is NULL\n");
        return NULL;
    }

    bind_ip = (cfg->bind_ip != NULL) ? cfg->bind_ip : "0.0.0.0";
    backlog = (cfg->backlog > 0) ? cfg->backlog : 128;

    tproxy = (tproxy_t *)malloc(sizeof(*tproxy));
    if (NULL == tproxy) {
        perror("malloc");
        return NULL;
    }
    
    memset(tproxy, 0, sizeof(*tproxy));
    tproxy->listen_fd = -1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        saved_errno = errno;
        perror("socket");
        goto fail;
    }

    if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &opt, sizeof(opt)) < 0) {
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
    } else {
        if (inet_pton(AF_INET, bind_ip, &addr.sin_addr) != 1) {
            saved_errno = EINVAL;
            fprintf(stderr, "invalid bind_ip: %s\n", bind_ip);
            goto fail;
        }
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

    return tproxy;

fail:
    {
        if (fd >= 0) {
            close(fd);
        }
        tproxy_destroy(tproxy);
        if (saved_errno != 0) {
            errno = saved_errno;
        }
    }
    return NULL;
}

void tproxy_destroy(tproxy_t *tp) {
    if (tp == NULL) {
        return;
    }

    if (tp->listen_fd >= 0) {
        close(tp->listen_fd);
        tp->listen_fd = -1;
    }

    free(tp);
}

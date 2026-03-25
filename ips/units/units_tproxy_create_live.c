#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../include/tproxy.h"

static int read_proc_flag(const char *path, int *value) {
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }

    if (fscanf(fp, "%d", value) != 1) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

static void print_proc_flag(const char *name, const char *path) {
    int value = -1;

    if (read_proc_flag(path, &value) == 0) {
        printf("%s=%d\n", name, value);
        return;
    }

    printf("%s=unavailable\n", name);
}

int main(void) {
    tproxy_cfg_t cfg = {
        .bind_ip = "198.51.100.10",
        .bind_port = 50080,
        .backlog = 16,
    };
    tproxy_t *tp = NULL;
    int saved_errno = 0;

    printf("uid=%ld euid=%ld\n", (long)getuid(), (long)geteuid());
    print_proc_flag("net.ipv4.ip_nonlocal_bind", "/proc/sys/net/ipv4/ip_nonlocal_bind");
    print_proc_flag("net.ipv4.conf.all.route_localnet",
                    "/proc/sys/net/ipv4/conf/all/route_localnet");
    fflush(stdout);

    errno = 0;
    tp = tproxy_create(&cfg);
    saved_errno = errno;
    if (tp == NULL) {
        fprintf(stderr,
                "live check failed: tproxy_create(%s:%u) errno=%d (%s)\n",
                cfg.bind_ip, cfg.bind_port, saved_errno, strerror(saved_errno));
        return 1;
    }

    printf("ok: units_tproxy_create_live listen_fd=%d bind_ip=%s bind_port=%u backlog=%d\n",
           tp->listen_fd, tp->bind_ip, tp->bind_port, tp->backlog);
    tproxy_destroy(tp);
    return 0;
}

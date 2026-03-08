#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#if defined(__APPLE__)
#include <netinet/tcp.h>
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#else
#include <linux/tcp.h>
#endif
#include <unistd.h>
/* ----------------------*/
#include "tests/sqli_attack.h"
#include "tests/xss_attack.h"
#include "tests/RCE_attack.h"
#include "tests/LFI_attack.h"
#include "tests/RFI_attack.h"
#include "tests/php_attack.h"
#include "tests/java_attack.h"
#include "tests/generic_attack.h"
#include "tests/protocol_attack.h"
#include "tests/session_fixation_attack.h"
#include "tests/response_data.h"
#include "tests/multipart_attack.h"

typedef struct options {
    const char *ip;
    int port;
    const char *attack;
    unsigned int seed;
    int verbose;

} bot_options_t;

static void print_usage(const char *prog) {
    fprintf(stderr,
        "usage: %s <ip> <port> -attack <name> [options]\n"
        "options:\n"
        "  -seed <N>          random seed (default 0 = time)\n"
        "  -verbose           verbose output\n",
        prog
    );
}

static int parse_int(const char *s, int *out) 
{
    char *end = NULL;
    long v;
    errno = 0;
    v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') return 0;
    *out = (int)v;
    return 1;
}

typedef struct attack_group {
    const char *name;
    int (*get_count)(void);
    const test_case_t *(*get_case)(int);
} attack_group_t;

static int str_eq_ignore_case(const char *a, const char *b)
{
    while (*a && *b) {
        char ca = *a;
        char cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static const attack_group_t g_attack_groups[] = {
    { "SQLI", sqli_get_count, sqli_get_case },
    { "XSS", xss_get_count, xss_get_case },
    { "RCE", RCE_get_count, RCE_get_case },
    { "LFI", LFI_get_count, LFI_get_case },
    { "RFI", RFI_get_count, RFI_get_case },
    { "PHP", php_get_count, php_get_case },
    { "JAVA", java_get_count, java_get_case },
    { "GENERIC", generic_get_count, generic_get_case },
    { "PROTOCOL", protocol_get_count, protocol_get_case },
    { "SESSION_FIXATION", session_fixation_get_count, session_fixation_get_case },
    { "RESPONSE", response_data_get_count, response_data_get_case },
    { "RESPONSE_DATA", response_data_get_count, response_data_get_case },
    { "MULTIPART", multipart_get_count, multipart_get_case }
};

static const size_t g_attack_group_count =
    sizeof(g_attack_groups) / sizeof(g_attack_groups[0]);

static void print_available_attacks(void)
{
    size_t i;
    fprintf(stderr, "available attacks:");
    for (i = 0; i < g_attack_group_count; i++) {
        fprintf(stderr, " %s", g_attack_groups[i].name);
    }
    fputc('\n', stderr);
}

static const attack_group_t *find_attack_group(const char *name)
{
    size_t i;
    if (!name) return NULL;
    for (i = 0; i < g_attack_group_count; i++) {
        if (str_eq_ignore_case(name, g_attack_groups[i].name)) {
            return &g_attack_groups[i];
        }
    }
    return NULL;
}

static int connect_tcp(const char *ip, int port)
{
    int fd;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
#if defined(__APPLE__)
    {
        int on = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
    }
#endif

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static int send_all(int fd, const char *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n > 0) {
            sent += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        return -1;
    }
    return 0;
}

static void log_tcp_state(int fd, size_t app_tx_bytes, size_t app_rx_bytes)
{
#if defined(__APPLE__)
    struct tcp_connection_info ti;
    socklen_t ti_len = (socklen_t)sizeof(ti);
    memset(&ti, 0, sizeof(ti));
    if (getsockopt(fd, IPPROTO_TCP, TCP_CONNECTION_INFO, &ti, &ti_len) != 0)
        return;

    fprintf(stderr,
            "[BOT][TCP] rel_seq=%zu rel_ack=%zu snd_cwnd=%u rcv_wnd=%u rtt_ms=%u total_retrans=%llu\n",
            app_tx_bytes + 1U,
            app_rx_bytes + 1U,
            (unsigned int)ti.tcpi_snd_cwnd,
            (unsigned int)ti.tcpi_rcv_wnd,
            (unsigned int)ti.tcpi_rttcur,
            (unsigned long long)ti.tcpi_txretransmitpackets);
#else
    struct tcp_info ti;
    socklen_t ti_len = (socklen_t)sizeof(ti);
    memset(&ti, 0, sizeof(ti));
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &ti_len) != 0)
        return;

    fprintf(stderr,
            "[BOT][TCP] rel_seq=%zu rel_ack=%zu unacked=%u rcv_space=%u snd_cwnd=%u rtt_us=%u total_retrans=%u\n",
            app_tx_bytes + 1U,
            app_rx_bytes + 1U,
            (unsigned int)ti.tcpi_unacked,
            (unsigned int)ti.tcpi_rcv_space,
            (unsigned int)ti.tcpi_snd_cwnd,
            (unsigned int)ti.tcpi_rtt,
            (unsigned int)ti.tcpi_total_retrans);
#endif
}

static const test_case_t *pick_case(const attack_group_t *group, expect_t want)
{
    int count;
    int i;
    const test_case_t *tc;

    if (!group) return NULL;
    count = group->get_count();
    if (count <= 0) return NULL;

    if (want != EXPECT_MATCH && want != EXPECT_NO_MATCH) {
        return group->get_case(rand() % count);
    }

    for (i = 0; i < count * 2; i++) {
        tc = group->get_case(rand() % count);
        if (tc && tc->expect == want) return tc;
    }

    for (i = 0; i < count; i++) {
        tc = group->get_case(i);
        if (tc && tc->expect == want) return tc;
    }

    return group->get_case(rand() % count);
}

int main(int argc, char **argv)
{
    bot_options_t opt;
    int i = 1; 
    memset(&opt, 0, sizeof(opt));
    opt.seed = 0 ;
    opt.verbose = 0;

    if(argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    opt.ip = argv[i++];
    if(!parse_int(argv[i++], &opt.port)){
        fprintf(stderr, "invalid port\n");
        return 1;
    }

    while (i < argc) {
        if (strcmp(argv[i], "-attack") == 0 && i + 1 < argc) {
            opt.attack = argv[++i];
        } else if (strcmp(argv[i], "-seed") == 0 && i + 1 < argc) {
            int tmp;
            if (!parse_int(argv[++i], &tmp)) return 1;
            opt.seed = (unsigned int)tmp;
        } else if (strcmp(argv[i], "-verbose") == 0) {
            opt.verbose = 1;
        } else {
            print_usage(argv[0]);
            return 1;
        }
        i++;
    }

    if (!opt.attack) {
        fprintf(stderr, "missing -attack\n");
        print_usage(argv[0]);
        print_available_attacks();
        return 1;
    }

    {
        const attack_group_t *attack_group = find_attack_group(opt.attack);
        int sock = -1;
        const test_case_t *tc = NULL;
        int sent = 0;
        size_t app_tx_bytes = 0;
        size_t app_rx_bytes = 0;

        if (!attack_group) {
            fprintf(stderr, "unknown attack: %s\n", opt.attack);
            print_available_attacks();
            return 1;
        }

        if (opt.seed == 0) opt.seed = (unsigned int)time(NULL);
        srand(opt.seed);

        signal(SIGPIPE, SIG_IGN);

        sock = connect_tcp(opt.ip, opt.port);
        if (sock < 0) {
            fprintf(stderr, "connect failed\n");
            return 1;
        }

        while (1) {
            tc = pick_case(attack_group, EXPECT_MATCH);
            if (!tc || !tc->req) {
                fprintf(stderr, "no attack test case available\n");
                close(sock);
                return 1;
            }

            if (send_all(sock, tc->req, strlen(tc->req)) < 0) {
                if (opt.verbose) {
                    fprintf(stderr, "disconnected after %d attack requests\n", sent);
                    log_tcp_state(sock, app_tx_bytes, app_rx_bytes);
                } else {
                    fprintf(stderr, "send failed\n");
                }
                break;
            }

            app_tx_bytes += strlen(tc->req);
            sent++;
            if (opt.verbose) {
                fprintf(stderr, "sent %d: attack (rule %d)\n", sent, tc->rule_id);
                log_tcp_state(sock, app_tx_bytes, app_rx_bytes);
            }
            sleep(1);
            //usleep(700000);
        }

        if (sock >= 0) close(sock);
    }

    return 0;
    
}

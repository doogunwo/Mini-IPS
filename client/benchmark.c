#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#ifdef __linux__
#include <linux/tcp.h>
#endif
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>

typedef enum
{
    MODE_URL = 0,
    MODE_BODY,
    MODE_HEADER
} bot_mode_t;

typedef enum
{
    PAYLOAD_SQLI = 0,
    PAYLOAD_XSS,
    PAYLOAD_REDOS,
    PAYLOAD_RCE
} payload_kind_t;

typedef struct
{
    const char *ip;
    int port;
    bot_mode_t mode;
    payload_kind_t payload;
    bool mode_set;
    bool payload_set;
    size_t uri_size;
    size_t body_size;
    size_t header_size;
    const char *prefix;
    const char *suffix;
    bool prefix_set;
    bool suffix_set;
    int verbose;
    unsigned int seed;
    int count;
    unsigned int interval_ms;
} bot_cfg_t;

typedef struct
{
    const char *prefix;
    const char *suffix;
} payload_variant_t;

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s <ip> <port> -mode <url|body|header> -payload <sqli|xss|redos|rce> [options]\n"
            "scenario:\n"
            "  keep-alive TCP session 1개를 열고 공격 요청만 반복 전송\n"
            "options:\n"
            "  -uri-size <N>      generated URI payload size\n"
            "  -body-size <N>     generated BODY payload size\n"
            "  -header-size <N>   generated HEADER payload size\n"
            "  -prefix <TEXT>     prefix text added before generated padding\n"
            "  -suffix <TEXT>     suffix text added after generated padding\n"
            "  -count <N>         number of attack requests on same session\n"
            "  -interval-ms <N>   delay between attack requests in milliseconds\n"
            "  -seed <N>          random seed (default 0 = time)\n"
            "  -verbose           verbose output\n",
            prog);
}

static const payload_variant_t *payload_variants(payload_kind_t kind, size_t *out_count)
{
    static const payload_variant_t sqli_variants[] = {
        {"", "' OR 1=1 --"},
        {"", "' UNION SELECT 1,2,3 --"},
        {"", "' AND SLEEP(5) --"},
        {"", "' OR 'a'='a' --"}};
    static const payload_variant_t xss_variants[] = {
        {"", "\"><script>alert(1)</script>"},
        {"", "\"><img src=x onerror=alert(1)>"},
        {"", "\"><svg/onload=alert(1)>"},
        {"", "'\"><body onload=alert(1)>"}};
    static const payload_variant_t redos_variants[] = {
        {"^(", "a+)+$"},
        {"^(([a-z])+)+$", ""},
        {"^((a|aa)+)+$", ""},
        {"^([A-Za-z]+)*$", ""}};
    static const payload_variant_t rce_variants[] = {
        {"", ";id;uname -a"},
        {"", "$(id)"},
        {"", "`id`"},
        {"", "| id"}};

    switch (kind)
    {
    case PAYLOAD_SQLI:
        *out_count = sizeof(sqli_variants) / sizeof(sqli_variants[0]);
        return sqli_variants;
    case PAYLOAD_XSS:
        *out_count = sizeof(xss_variants) / sizeof(xss_variants[0]);
        return xss_variants;
    case PAYLOAD_REDOS:
        *out_count = sizeof(redos_variants) / sizeof(redos_variants[0]);
        return redos_variants;
    case PAYLOAD_RCE:
        *out_count = sizeof(rce_variants) / sizeof(rce_variants[0]);
        return rce_variants;
    default:
        *out_count = 0;
        return NULL;
    }
}

static const char *mode_name(bot_mode_t mode)
{
    switch (mode)
    {
    case MODE_URL:
        return "url";
    case MODE_BODY:
        return "body";
    case MODE_HEADER:
        return "header";
    default:
        return "unknown";
    }
}

static const char *payload_name(payload_kind_t kind)
{
    switch (kind)
    {
    case PAYLOAD_SQLI:
        return "sqli";
    case PAYLOAD_XSS:
        return "xss";
    case PAYLOAD_REDOS:
        return "redos";
    case PAYLOAD_RCE:
        return "rce";
    default:
        return "unknown";
    }
}

static int parse_mode(const char *s, bot_mode_t *out)
{
    if (strcmp(s, "url") == 0)
    {
        *out = MODE_URL;
        return 0;
    }
    if (strcmp(s, "body") == 0)
    {
        *out = MODE_BODY;
        return 0;
    }
    if (strcmp(s, "header") == 0)
    {
        *out = MODE_HEADER;
        return 0;
    }
    return -1;
}

static int parse_payload(const char *s, payload_kind_t *out)
{
    if (strcmp(s, "sqli") == 0)
    {
        *out = PAYLOAD_SQLI;
        return 0;
    }
    if (strcmp(s, "xss") == 0)
    {
        *out = PAYLOAD_XSS;
        return 0;
    }
    if (strcmp(s, "redos") == 0)
    {
        *out = PAYLOAD_REDOS;
        return 0;
    }
    if (strcmp(s, "rce") == 0)
    {
        *out = PAYLOAD_RCE;
        return 0;
    }
    return -1;
}

static size_t parse_size_or_die(const char *arg, const char *name)
{
    char *end = NULL;
    unsigned long long v = strtoull(arg, &end, 10);
    if (arg[0] == '\0' || end == NULL || *end != '\0')
    {
        fprintf(stderr, "invalid %s: %s\n", name, arg);
        exit(1);
    }
    return (size_t)v;
}

static int connect_target(const char *ip, int port)
{
    struct sockaddr_in addr;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        perror("socket");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1)
    {
        fprintf(stderr, "invalid ip: %s\n", ip);
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("connect");
        close(fd);
        return -1;
    }

    return fd;
}

static int send_all(int fd, const char *buf, size_t len)
{
    size_t off = 0;
    while (off < len)
    {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        if (n == 0)
        {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static void sleep_ms(unsigned int interval_ms)
{
    struct timespec req;
    struct timespec rem;

    if (interval_ms == 0U)
    {
        return;
    }

    req.tv_sec = (time_t)(interval_ms / 1000U);
    req.tv_nsec = (long)(interval_ms % 1000U) * 1000000L;

    while (nanosleep(&req, &rem) != 0)
    {
        if (errno != EINTR)
        {
            break;
        }
        req = rem;
    }
}

static void print_tcp_info(int fd)
{
    struct tcp_info info;
    socklen_t len = sizeof(info);
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &len) == 0)
    {
        printf("[BOT][TCP] unacked=%u rcv_space=%u snd_cwnd=%u rtt_us=%u total_retrans=%u\n",
               info.tcpi_unacked,
               info.tcpi_rcv_space,
               info.tcpi_snd_cwnd,
               info.tcpi_rtt,
               info.tcpi_total_retrans);
    }
}

static char filler_char(payload_kind_t kind)
{
    return kind == PAYLOAD_REDOS ? 'a' : 'A';
}

static payload_variant_t choose_variant(payload_kind_t kind, unsigned int *variant_index)
{
    size_t count = 0;
    const payload_variant_t *variants = payload_variants(kind, &count);
    size_t idx = 0;
    payload_variant_t empty = {"", ""};

    if (variants == NULL || count == 0) {
        if (variant_index != NULL)
        {
            *variant_index = 0;
        }
        return empty;
    }

    idx = (size_t)(rand() % (int)count);
    if (variant_index != NULL)
    {
        *variant_index = (unsigned int)idx;
    }
    return variants[idx];
}

static char *build_value(payload_kind_t kind, size_t target_size, const char *prefix, const char *suffix)
{
    size_t prefix_len = prefix ? strlen(prefix) : 0;
    size_t suffix_len = suffix ? strlen(suffix) : 0;
    size_t fill_len = 0;
    char *buf;

    if (target_size > prefix_len + suffix_len)
    {
        fill_len = target_size - prefix_len - suffix_len;
    }

    buf = (char *)malloc(prefix_len + fill_len + suffix_len + 1);
    if (buf == NULL)
    {
        return NULL;
    }

    if (prefix_len > 0)
    {
        memcpy(buf, prefix, prefix_len);
    }
    memset(buf + prefix_len, filler_char(kind), fill_len);
    if (suffix_len > 0)
    {
        memcpy(buf + prefix_len + fill_len, suffix, suffix_len);
    }
    buf[prefix_len + fill_len + suffix_len] = '\0';
    return buf;
}

static int is_unreserved_uri_char(unsigned char c)
{
    return isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~';
}

static char *url_encode_component(const char *src)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t i;
    size_t len;
    size_t out_len = 0;
    char *out;
    char *p;

    if (src == NULL)
    {
        return NULL;
    }

    len = strlen(src);
    for (i = 0; i < len; i++)
    {
        unsigned char c = (unsigned char)src[i];
        out_len += is_unreserved_uri_char(c) ? 1 : 3;
    }

    out = (char *)malloc(out_len + 1);
    if (out == NULL)
    {
        return NULL;
    }

    p = out;
    for (i = 0; i < len; i++)
    {
        unsigned char c = (unsigned char)src[i];
        if (is_unreserved_uri_char(c))
        {
            *p++ = (char)c;
        }
        else
        {
            *p++ = '%';
            *p++ = hex[(c >> 4) & 0x0F];
            *p++ = hex[c & 0x0F];
        }
    }
    *p = '\0';
    return out;
}

static char *build_url_request(const bot_cfg_t *cfg)
{
    char *value = build_value(cfg->payload, cfg->uri_size, cfg->prefix, cfg->suffix);
    char *encoded = NULL;
    char *req;
    size_t needed;

    if (value == NULL)
    {
        return NULL;
    }

    encoded = url_encode_component(value);
    free(value);
    if (encoded == NULL)
    {
        return NULL;
    }

    needed = snprintf(NULL, 0,
                      "GET /bench?x=%s HTTP/1.1\r\n"
                      "Host: localhost\r\n"
                      "User-Agent: Mini-IPS bench agent\r\n"
                      "Connection: keep-alive\r\n"
                      "\r\n",
                      encoded);
    req = (char *)malloc(needed + 1);
    if (req != NULL)
    {
        snprintf(req, needed + 1,
                 "GET /bench?x=%s HTTP/1.1\r\n"
                 "Host: localhost\r\n"
                 "User-Agent: Mini-IPS bench agent\r\n"
                 "Connection: keep-alive\r\n"
                 "\r\n",
                 encoded);
    }

    free(encoded);
    return req;
}

static char *build_body_request(const bot_cfg_t *cfg)
{
    char *value = build_value(cfg->payload, cfg->body_size, cfg->prefix, cfg->suffix);
    char *req;
    size_t body_len;
    size_t needed;

    if (value == NULL)
    {
        return NULL;
    }

    body_len = strlen("x=") + strlen(value);
    needed = snprintf(NULL, 0,
                      "POST /bench HTTP/1.1\r\n"
                      "Host: localhost\r\n"
                      "User-Agent: Mini-IPS bench agent\r\n"
                      "Content-Type: application/x-www-form-urlencoded\r\n"
                      "Content-Length: %zu\r\n"
                      "Connection: keep-alive\r\n"
                      "\r\n"
                      "x=%s",
                      body_len,
                      value);
    req = (char *)malloc(needed + 1);
    if (req != NULL)
    {
        snprintf(req, needed + 1,
                 "POST /bench HTTP/1.1\r\n"
                 "Host: localhost\r\n"
                 "User-Agent: Mini-IPS bench agent\r\n"
                 "Content-Type: application/x-www-form-urlencoded\r\n"
                 "Content-Length: %zu\r\n"
                 "Connection: keep-alive\r\n"
                 "\r\n"
                 "x=%s",
                 body_len,
                 value);
    }

    free(value);
    return req;
}

static char *build_header_request(const bot_cfg_t *cfg)
{
    char *value = build_value(cfg->payload, cfg->header_size, cfg->prefix, cfg->suffix);
    char *req;
    size_t needed;

    if (value == NULL)
    {
        return NULL;
    }

    needed = snprintf(NULL, 0,
                      "GET /bench HTTP/1.1\r\n"
                      "Host: localhost\r\n"
                      "User-Agent: Mini-IPS bench agent\r\n"
                      "X-Attack: %s\r\n"
                      "Connection: keep-alive\r\n"
                      "\r\n",
                      value);
    req = (char *)malloc(needed + 1);
    if (req != NULL)
    {
        snprintf(req, needed + 1,
                 "GET /bench HTTP/1.1\r\n"
                 "Host: localhost\r\n"
                 "User-Agent: Mini-IPS bench agent\r\n"
                 "X-Attack: %s\r\n"
                 "Connection: keep-alive\r\n"
                 "\r\n",
                 value);
    }

    free(value);
    return req;
}

static char *build_attack_request(const bot_cfg_t *cfg)
{
    switch (cfg->mode)
    {
    case MODE_URL:
        return build_url_request(cfg);
    case MODE_BODY:
        return build_body_request(cfg);
    case MODE_HEADER:
        return build_header_request(cfg);
    default:
        return NULL;
    }
}

static void set_default_sizes(bot_cfg_t *cfg)
{
    if (cfg->uri_size == 0)
    {
        cfg->uri_size = 8192;
    }
    if (cfg->body_size == 0)
    {
        cfg->body_size = 1024 * 1024;
    }
    if (cfg->header_size == 0)
    {
        cfg->header_size = 4096;
    }
    if (cfg->count <= 0)
    {
        cfg->count = 20;
    }
    if (cfg->interval_ms == 0U)
    {
        cfg->interval_ms = 1000U;
    }
}

int main(int argc, char **argv)
{
    bot_cfg_t cfg;
    int fd;

    memset(&cfg, 0, sizeof(cfg));
    cfg.prefix = "";
    cfg.suffix = NULL;

    signal(SIGPIPE, SIG_IGN);

    if (argc < 5)
    {
        usage(argv[0]);
        return 1;
    }

    cfg.ip = argv[1];
    cfg.port = atoi(argv[2]);

    for (int i = 3; i < argc; i++)
    {
        if (strcmp(argv[i], "-mode") == 0 && i + 1 < argc)
        {
            if (parse_mode(argv[++i], &cfg.mode) != 0)
            {
                fprintf(stderr, "invalid mode\n");
                return 1;
            }
            cfg.mode_set = true;
        }
        else if (strcmp(argv[i], "-payload") == 0 && i + 1 < argc)
        {
            if (parse_payload(argv[++i], &cfg.payload) != 0)
            {
                fprintf(stderr, "invalid payload\n");
                return 1;
            }
            cfg.payload_set = true;
        }
        else if (strcmp(argv[i], "-uri-size") == 0 && i + 1 < argc)
        {
            cfg.uri_size = parse_size_or_die(argv[++i], "uri-size");
        }
        else if (strcmp(argv[i], "-body-size") == 0 && i + 1 < argc)
        {
            cfg.body_size = parse_size_or_die(argv[++i], "body-size");
        }
        else if (strcmp(argv[i], "-header-size") == 0 && i + 1 < argc)
        {
            cfg.header_size = parse_size_or_die(argv[++i], "header-size");
        }
        else if (strcmp(argv[i], "-prefix") == 0 && i + 1 < argc)
        {
            cfg.prefix = argv[++i];
            cfg.prefix_set = true;
        }
        else if (strcmp(argv[i], "-suffix") == 0 && i + 1 < argc)
        {
            cfg.suffix = argv[++i];
            cfg.suffix_set = true;
        }
        else if (strcmp(argv[i], "-count") == 0 && i + 1 < argc)
        {
            cfg.count = (int)parse_size_or_die(argv[++i], "count");
        }
        else if (strcmp(argv[i], "-interval-ms") == 0 && i + 1 < argc)
        {
            cfg.interval_ms = (unsigned int)parse_size_or_die(argv[++i], "interval-ms");
        }
        else if (strcmp(argv[i], "-seed") == 0 && i + 1 < argc)
        {
            cfg.seed = (unsigned int)strtoul(argv[++i], NULL, 10);
        }
        else if (strcmp(argv[i], "-verbose") == 0)
        {
            cfg.verbose = 1;
        }
        else
        {
            usage(argv[0]);
            return 1;
        }
    }

    if (cfg.port <= 0 || cfg.port > 65535)
    {
        fprintf(stderr, "invalid port\n");
        return 1;
    }

    if (!cfg.mode_set || !cfg.payload_set)
    {
        usage(argv[0]);
        return 1;
    }

    if (cfg.seed == 0)
    {
        cfg.seed = (unsigned int)time(NULL);
    }
    srand(cfg.seed);
    set_default_sizes(&cfg);

    fd = connect_target(cfg.ip, cfg.port);
    if (fd < 0)
    {
        return 1;
    }

    for (int i = 0; i < cfg.count; i++)
    {
        bot_cfg_t req_cfg = cfg;
        payload_variant_t variant = {"", ""};
        char *attack_req;
        const char *size_name = "uri_size";
        size_t size_value = cfg.uri_size;
        unsigned int variant_index = 0;

        if (!cfg.prefix_set || !cfg.suffix_set)
        {
            variant = choose_variant(cfg.payload, &variant_index);
        }
        if (!cfg.prefix_set)
        {
            req_cfg.prefix = variant.prefix;
        }
        if (!cfg.suffix_set)
        {
            req_cfg.suffix = variant.suffix;
        }

        attack_req = build_attack_request(&req_cfg);
        if (attack_req == NULL)
        {
            fprintf(stderr, "failed to build attack request\n");
            close(fd);
            return 1;
        }

        if (send_all(fd, attack_req, strlen(attack_req)) != 0)
        {
            perror("send");
            printf("disconnected after %d attack requests\n", i);
            close(fd);
            free(attack_req);
            return 1;
        }

        if (cfg.mode == MODE_BODY)
        {
            size_name = "body_size";
            size_value = cfg.body_size;
        }
        else if (cfg.mode == MODE_HEADER)
        {
            size_name = "header_size";
            size_value = cfg.header_size;
        }

        printf("sent %d: attack mode=%s payload=%s %s=%zu\n",
               i + 1,
               mode_name(cfg.mode),
               payload_name(cfg.payload),
               size_name,
               size_value);
        if (cfg.verbose && !cfg.suffix_set)
        {
            printf("[BOT] variant=%u prefix=\"%s\" suffix=\"%s\"\n",
                   variant_index + 1,
                   req_cfg.prefix ? req_cfg.prefix : "",
                   req_cfg.suffix ? req_cfg.suffix : "");
        }

        if (cfg.verbose)
        {
            print_tcp_info(fd);
        }
        free(attack_req);
        if (i + 1 < cfg.count)
        {
            sleep_ms(cfg.interval_ms);
        }
    }

    close(fd);
    return 0;
}

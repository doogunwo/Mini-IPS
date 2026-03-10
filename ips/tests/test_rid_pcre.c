#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "detect.h"
#include "engine.h"
#include "regex.h"

#define ERRBUF_SIZE 256

typedef enum {
    MODE_URL = 0,
    MODE_BODY,
    MODE_HEADER
} attack_mode_t;

typedef enum {
    PAYLOAD_SQLI = 0,
    PAYLOAD_XSS,
    PAYLOAD_REDOS,
    PAYLOAD_RCE
} payload_kind_t;

typedef struct {
    attack_mode_t mode;
    payload_kind_t payload;
    size_t uri_size;
    size_t body_size;
    size_t header_size;
    const char *prefix;
    const char *suffix;
    const char *policy;
    ips_context_t ctx;
} test_cfg_t;

static const char *default_suffix(payload_kind_t p)
{
    switch (p) {
    case PAYLOAD_SQLI:
        return "' union select 1,2,3 from dual--";
    case PAYLOAD_XSS:
        return "\"><script>alert(1)</script>";
    case PAYLOAD_REDOS:
        return "X";
    case PAYLOAD_RCE:
        return ";id";
    default:
        return "X";
    }
}

static attack_mode_t parse_mode(const char *s)
{
    if (strcmp(s, "url") == 0) return MODE_URL;
    if (strcmp(s, "body") == 0) return MODE_BODY;
    if (strcmp(s, "header") == 0) return MODE_HEADER;
    return MODE_URL;
}

static payload_kind_t parse_payload(const char *s)
{
    if (strcmp(s, "sqli") == 0) return PAYLOAD_SQLI;
    if (strcmp(s, "xss") == 0) return PAYLOAD_XSS;
    if (strcmp(s, "redos") == 0) return PAYLOAD_REDOS;
    if (strcmp(s, "rce") == 0) return PAYLOAD_RCE;
    return PAYLOAD_SQLI;
}

static ips_context_t parse_ctx(const char *s)
{
    if (strcmp(s, "ALL") == 0 || strcmp(s, "all") == 0) return IPS_CTX_ALL;
    if (strcmp(s, "URI") == 0 || strcmp(s, "url") == 0) return IPS_CTX_REQUEST_URI;
    if (strcmp(s, "ARGS") == 0 || strcmp(s, "args") == 0) return IPS_CTX_ARGS;
    if (strcmp(s, "ARGS_NAMES") == 0 || strcmp(s, "args_names") == 0) return IPS_CTX_ARGS_NAMES;
    if (strcmp(s, "HEADERS") == 0 || strcmp(s, "headers") == 0) return IPS_CTX_REQUEST_HEADERS;
    if (strcmp(s, "BODY") == 0 || strcmp(s, "body") == 0) return IPS_CTX_REQUEST_BODY;
    if (strcmp(s, "RESPONSE_BODY") == 0 || strcmp(s, "response_body") == 0) return IPS_CTX_RESPONSE_BODY;
    return IPS_CTX_ALL;
}

static const char *ctx_name(ips_context_t ctx)
{
    switch (ctx) {
    case IPS_CTX_ALL: return "ALL";
    case IPS_CTX_REQUEST_URI: return "URI";
    case IPS_CTX_ARGS: return "ARGS";
    case IPS_CTX_ARGS_NAMES: return "ARGS_NAMES";
    case IPS_CTX_REQUEST_HEADERS: return "HEADERS";
    case IPS_CTX_REQUEST_BODY: return "BODY";
    case IPS_CTX_RESPONSE_BODY: return "RESPONSE_BODY";
    default: return "UNKNOWN";
    }
}

static char *make_repeat(size_t len, char ch)
{
    char *out = (char *)malloc(len + 1);
    if (out == NULL) return NULL;
    memset(out, ch, len);
    out[len] = '\0';
    return out;
}

static int is_unreserved(unsigned char c)
{
    return isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~';
}

static char *url_encode_dup(const char *src)
{
    size_t i;
    size_t len = 0;
    char *out;
    char *p;

    for (i = 0; src[i] != '\0'; i++) {
        len += is_unreserved((unsigned char)src[i]) ? 1 : 3;
    }

    out = (char *)malloc(len + 1);
    if (out == NULL) return NULL;

    p = out;
    for (i = 0; src[i] != '\0'; i++) {
        unsigned char c = (unsigned char)src[i];
        if (is_unreserved(c)) {
            *p++ = (char)c;
        } else {
            sprintf(p, "%%%02X", c);
            p += 3;
        }
    }
    *p = '\0';
    return out;
}

static char *build_attack_request(const test_cfg_t *cfg, size_t *out_len)
{
    char *pad = NULL;
    char *encoded = NULL;
    char *combined = NULL;
    char *req = NULL;
    size_t pad_len;
    size_t need;
    const char *prefix = cfg->prefix ? cfg->prefix : "";
    const char *suffix = cfg->suffix ? cfg->suffix : default_suffix(cfg->payload);

    if (out_len == NULL) return NULL;

    if (cfg->mode == MODE_URL) {
        pad_len = cfg->uri_size;
    } else if (cfg->mode == MODE_BODY) {
        pad_len = cfg->body_size;
    } else {
        pad_len = cfg->header_size;
    }

    pad = make_repeat(pad_len, 'A');
    if (pad == NULL) return NULL;

    need = strlen(prefix) + strlen(pad) + strlen(suffix) + 1;
    combined = (char *)malloc(need);
    if (combined == NULL) {
        free(pad);
        return NULL;
    }
    snprintf(combined, need, "%s%s%s", prefix, pad, suffix);
    free(pad);

    if (cfg->mode == MODE_URL) {
        encoded = url_encode_dup(combined);
        free(combined);
        if (encoded == NULL) return NULL;

        need = strlen("GET /bench?x= HTTP/1.1\r\n"
                      "Host: localhost\r\n"
                      "User-Agent: Mini-IPS bench agent\r\n"
                      "Connection: keep-alive\r\n"
                      "\r\n")
             + strlen(encoded) + 1;
        req = (char *)malloc(need);
        if (req == NULL) {
            free(encoded);
            return NULL;
        }

        snprintf(req, need,
            "GET /bench?x=%s HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "User-Agent: Mini-IPS bench agent\r\n"
            "Connection: keep-alive\r\n"
            "\r\n",
            encoded);
        free(encoded);
    } else if (cfg->mode == MODE_BODY) {
        size_t body_len = strlen("x=") + strlen(combined);
        need = strlen("POST /bench HTTP/1.1\r\n"
                      "Host: localhost\r\n"
                      "User-Agent: Mini-IPS bench agent\r\n"
                      "Connection: keep-alive\r\n"
                      "Content-Type: application/x-www-form-urlencoded\r\n"
                      "Content-Length: \r\n"
                      "\r\n"
                      "x=")
             + 32 + strlen(combined) + 1;
        req = (char *)malloc(need);
        if (req == NULL) {
            free(combined);
            return NULL;
        }

        snprintf(req, need,
            "POST /bench HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "User-Agent: Mini-IPS bench agent\r\n"
            "Connection: keep-alive\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: %zu\r\n"
            "\r\n"
            "x=%s",
            body_len, combined);
        free(combined);
    } else {
        need = strlen("GET /bench HTTP/1.1\r\n"
                      "Host: localhost\r\n"
                      "User-Agent: Mini-IPS bench agent\r\n"
                      "Connection: keep-alive\r\n"
                      "X-Attack: \r\n"
                      "\r\n")
             + strlen(combined) + 1;
        req = (char *)malloc(need);
        if (req == NULL) {
            free(combined);
            return NULL;
        }

        snprintf(req, need,
            "GET /bench HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "User-Agent: Mini-IPS bench agent\r\n"
            "Connection: keep-alive\r\n"
            "X-Attack: %s\r\n"
            "\r\n",
            combined);
        free(combined);
    }

    *out_len = strlen(req);
    return req;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s <policy|ALL> <ctx> <mode:url|body|header> <payload:sqli|xss|redos|rce> "
        "<size> [suffix]\n",
        prog);
}

int main(int argc, char **argv)
{
    const char *policy;
    ips_context_t ctx;
    test_cfg_t cfg;
    char errbuf[ERRBUF_SIZE];
    detect_engine_t *det = NULL;
    detect_match_list_t matches;
    char *input = NULL;
    size_t input_len = 0;
    uint64_t total_regex_us = 0;
    int rc;
    size_t i;

    if (argc < 6 || argc > 7) {
        usage(argv[0]);
        return 1;
    }

    memset(&cfg, 0, sizeof(cfg));
    policy = argv[1];
    ctx = parse_ctx(argv[2]);
    cfg.mode = parse_mode(argv[3]);
    cfg.payload = parse_payload(argv[4]);
    cfg.policy = policy;
    cfg.ctx = ctx;
    cfg.prefix = "";
    cfg.suffix = (argc == 7) ? argv[6] : default_suffix(cfg.payload);

    if (cfg.mode == MODE_URL) {
        cfg.uri_size = (size_t)strtoull(argv[5], NULL, 10);
    } else if (cfg.mode == MODE_BODY) {
        cfg.body_size = (size_t)strtoull(argv[5], NULL, 10);
    } else {
        cfg.header_size = (size_t)strtoull(argv[5], NULL, 10);
    }

    memset(errbuf, 0, sizeof(errbuf));
    if (engine_set_backend_name("pcre", errbuf, sizeof(errbuf)) != 0) {
        fprintf(stderr, "engine_set_backend_name failed: %s\n", errbuf);
        return 1;
    }

    input = build_attack_request(&cfg, &input_len);
    if (input == NULL) {
        fprintf(stderr, "build_attack_request failed\n");
        return 1;
    }

    det = detect_engine_create(policy, DETECT_JIT_AUTO);
    if (det == NULL) {
        fprintf(stderr, "detect_engine_create failed\n");
        free(input);
        return 1;
    }

    detect_match_list_init(&matches);
    rc = detect_engine_collect_matches_ctx_timed(
        det,
        (const uint8_t *)input,
        input_len,
        ctx,
        &matches,
        &total_regex_us);

    if (rc < 0) {
        fprintf(stderr, "detect_engine_collect_matches_ctx_timed failed: %s\n",
            detect_engine_last_error(det));
        detect_match_list_free(&matches);
        detect_engine_destroy(det);
        free(input);
        return 1;
    }

    printf("backend=%s jit=%s policy=%s ctx=%s input_len=%zu total_matches=%zu total_regex_us=%" PRIu64 "\n",
        detect_engine_backend_name(det),
        detect_engine_jit_enabled(det) ? "on" : "off",
        policy,
        ctx_name(ctx),
        input_len,
        matches.count,
        total_regex_us);

    for (i = 0; i < matches.count; i++) {
        const detect_match_t *m = &matches.items[i];
        const IPS_Signature *r = m->rule;

        printf("rid=%d pname=%s ctx=%s elapsed_us=%" PRIu64,
            r ? r->rule_id : -1,
            (r && r->policy_name) ? r->policy_name : "-",
            ctx_name(m->context),
            m->elapsed_us);

        if (r && r->source) {
            printf(" source=%s", r->source);
        }

        if (m->matched_text && m->matched_text[0] != '\0') {
            printf(" match=\"%s\"", m->matched_text);
        }

        putchar('\n');
    }

    detect_match_list_free(&matches);
    detect_engine_destroy(det);
    free(input);
    return 0;
}

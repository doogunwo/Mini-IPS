/**
 * @file httgw.c
 * @brief HTTP 게이트웨이, TCP 재조립, RST 처리 구현
 */
#define _DEFAULT_SOURCE
#include "httgw.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <errno.h>
#include "net_compat.h"
#include <sys/socket.h>
#include <unistd.h>

#ifndef REASM_SESSION_TIMEOUT_MS
#define REASM_SESSION_TIMEOUT_MS (60ULL * 1000ULL)
#endif

#ifndef REASM_MAX_SESSIONS
#define REASM_MAX_SESSIONS 4096
#endif

#ifndef REASM_MAX_SEGMENTS_PER_DIR
#define REASM_MAX_SEGMENTS_PER_DIR 1024
#endif

#ifndef REASM_MAX_BYTES_PER_DIR
#define REASM_MAX_BYTES_PER_DIR (2U * 1024U * 1024U)
#endif

#ifndef HTTGW_SERVER_NEXT_BIAS
#define HTTGW_SERVER_NEXT_BIAS 64U
#endif

typedef void (*reasm_on_data_cb)(
    const flow_key_t *flow, tcp_dir_t dir,
    const uint8_t *data, uint32_t len, uint32_t seq_start,
    void *user
);

/* ---------- seq 비교(랩어라운드 고려) ---------- */
static inline int32_t seq_diff(uint32_t a, uint32_t b) { return (int32_t)(a - b); }
#define SEQ_LT(a,b)  (seq_diff((a),(b)) < 0)
#define SEQ_LEQ(a,b) (seq_diff((a),(b)) <= 0)
#define SEQ_GT(a,b)  (seq_diff((a),(b)) > 0)
#define SEQ_GEQ(a,b) (seq_diff((a),(b)) >= 0)

typedef struct reasm_seg_node {
    uint32_t seq;
    uint32_t len;
    uint8_t *data;
    struct reasm_seg_node *next;
} reasm_seg_node_t;

typedef struct {
    uint8_t has_next;
    uint32_t next_seq;
    uint8_t fin_seen;
    uint8_t rst_seen;

    reasm_seg_node_t *head;
    uint32_t seg_count;
    uint32_t bytes_queued;
} reasm_dir_t;

typedef struct reasm_session {
    flow_key_t key;
    uint64_t last_seen_ms;

    reasm_dir_t dir[2];
    struct reasm_session *next;
} reasm_session_t;

typedef struct reasm_ctx {
    reasm_session_t **buckets;
    uint32_t nbuckets;
    uint32_t nsessions;

    reasm_mode_t mode;
    reasm_on_data_cb on_data;
    void *user;
} reasm_ctx_t;

static uint32_t reasm_flow_hash(const flow_key_t *k)
{
    uint32_t h = 2166136261u;
#define H1(x) do { h ^= (uint32_t)(x); h *= 16777619u; } while (0)
    H1(k->src_ip);
    H1(k->dst_ip);
    H1(((uint32_t)k->src_port << 16) | k->dst_port);
    H1(k->proto);
#undef H1
    return h;
}

static int reasm_flow_eq(const flow_key_t *a, const flow_key_t *b)
{
    return a->src_ip == b->src_ip && a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port && a->dst_port == b->dst_port &&
           a->proto == b->proto;
}

static void reasm_seg_free(reasm_seg_node_t *s)
{
    if (!s)
        return;
    free(s->data);
    free(s);
}

static void reasm_dir_clear(reasm_dir_t *d)
{
    reasm_seg_node_t *p = d->head;
    while (p)
    {
        reasm_seg_node_t *n = p->next;
        reasm_seg_free(p);
        p = n;
    }
    memset(d, 0, sizeof(*d));
}

static void reasm_session_free(reasm_session_t *s)
{
    if (!s)
        return;
    reasm_dir_clear(&s->dir[0]);
    reasm_dir_clear(&s->dir[1]);
    free(s);
}

static reasm_ctx_t *reasm_create(uint32_t nbuckets, reasm_on_data_cb cb, void *user)
{
    reasm_ctx_t *c = (reasm_ctx_t *)calloc(1, sizeof(*c));
    if (!c)
        return NULL;

    if (nbuckets == 0)
        nbuckets = 8192;

    c->buckets = (reasm_session_t **)calloc(nbuckets, sizeof(reasm_session_t *));
    if (!c->buckets)
    {
        free(c);
        return NULL;
    }

    c->nbuckets = nbuckets;
    c->mode = REASM_MODE_LATE_START;
    c->on_data = cb;
    c->user = user;
    return c;
}

static void reasm_set_mode(reasm_ctx_t *c, reasm_mode_t mode)
{
    if (!c)
        return;
    c->mode = mode;
}

static void reasm_destroy(reasm_ctx_t *c)
{
    if (!c)
        return;

    for (uint32_t i = 0; i < c->nbuckets; i++)
    {
        reasm_session_t *p = c->buckets[i];
        while (p)
        {
            reasm_session_t *n = p->next;
            reasm_session_free(p);
            p = n;
        }
    }
    free(c->buckets);
    free(c);
}

static void reasm_gc(reasm_ctx_t *c, uint64_t now_ms)
{
    if (!c)
        return;

    for (uint32_t i = 0; i < c->nbuckets; i++)
    {
        reasm_session_t **pp = &c->buckets[i];
        while (*pp)
        {
            reasm_session_t *s = *pp;
            if (now_ms - s->last_seen_ms > REASM_SESSION_TIMEOUT_MS)
            {
                *pp = s->next;
                c->nsessions--;
                reasm_session_free(s);
                continue;
            }
            pp = &s->next;
        }
    }
}

static reasm_session_t *reasm_lookup(reasm_ctx_t *c, const flow_key_t *k, uint64_t ts_ms)
{
    uint32_t idx = reasm_flow_hash(k) % c->nbuckets;
    for (reasm_session_t *p = c->buckets[idx]; p; p = p->next)
    {
        if (reasm_flow_eq(&p->key, k))
        {
            p->last_seen_ms = ts_ms;
            return p;
        }
    }
    return NULL;
}

static reasm_session_t *reasm_get_or_create(reasm_ctx_t *c, const flow_key_t *k, uint64_t ts_ms)
{
    reasm_session_t *s = reasm_lookup(c, k, ts_ms);
    if (s)
        return s;

    if (c->nsessions >= REASM_MAX_SESSIONS)
        return NULL;

    uint32_t idx = reasm_flow_hash(k) % c->nbuckets;
    s = (reasm_session_t *)calloc(1, sizeof(*s));
    if (!s)
        return NULL;

    s->key = *k;
    s->last_seen_ms = ts_ms;
    s->next = c->buckets[idx];
    c->buckets[idx] = s;
    c->nsessions++;
    return s;
}

static void reasm_trim_to_next(reasm_dir_t *d, uint32_t *seq, const uint8_t **payload, uint32_t *len)
{
    if (*len == 0 || !d->has_next)
        return;

    uint32_t start = *seq;
    uint32_t end = start + *len;

    if (SEQ_LEQ(end, d->next_seq))
    {
        *len = 0;
        return;
    }

    if (SEQ_LT(start, d->next_seq))
    {
        uint32_t delta = (uint32_t)(d->next_seq - start);
        *seq = d->next_seq;
        *payload += delta;
        *len -= delta;
    }
}

static int reasm_insert_segment(reasm_dir_t *d, uint32_t seq, const uint8_t *payload, uint32_t len)
{
    reasm_seg_node_t **pp;
    reasm_seg_node_t *prev = NULL;
    uint32_t new_start = seq;
    uint32_t new_end = seq + len;

    if (len == 0)
        return 0;
    if (d->seg_count >= REASM_MAX_SEGMENTS_PER_DIR)
        return -1;
    if (d->bytes_queued + len > REASM_MAX_BYTES_PER_DIR)
        return -2;

    pp = &d->head;
    while (*pp && SEQ_LT((*pp)->seq, seq))
        pp = &(*pp)->next;

    if (pp != &d->head)
    {
        reasm_seg_node_t *p = d->head;
        while (p && p->next != *pp)
            p = p->next;
        prev = p;
    }

    if (prev)
    {
        uint32_t prev_end = prev->seq + prev->len;
        if (SEQ_GEQ(prev_end, new_start))
        {
            if (SEQ_GEQ(prev_end, new_end))
                return 0;
            uint32_t delta = (uint32_t)(prev_end - new_start);
            new_start = prev_end;
            payload += delta;
            len -= delta;
            new_end = new_start + len;
        }
    }

    while (*pp)
    {
        reasm_seg_node_t *cur = *pp;
        uint32_t cur_start = cur->seq;
        uint32_t cur_end = cur->seq + cur->len;

        if (SEQ_LEQ(new_end, cur_start))
            break;

        if (SEQ_LT(new_start, cur_start))
        {
            uint32_t keep = (uint32_t)(cur_start - new_start);
            len = keep;
            new_end = new_start + len;
            break;
        }
        if (SEQ_LT(new_start, cur_end))
        {
            if (SEQ_GEQ(cur_end, new_end))
                return 0;
            uint32_t delta = (uint32_t)(cur_end - new_start);
            new_start = cur_end;
            payload += delta;
            len -= delta;
            new_end = new_start + len;
            pp = &cur->next;
            continue;
        }
        pp = &(*pp)->next;
    }

    if (len == 0)
        return 0;
    if (d->seg_count >= REASM_MAX_SEGMENTS_PER_DIR)
        return -1;
    if (d->bytes_queued + len > REASM_MAX_BYTES_PER_DIR)
        return -2;

    reasm_seg_node_t *n = (reasm_seg_node_t *)calloc(1, sizeof(*n));
    if (!n)
        return -3;

    n->data = (uint8_t *)malloc(len);
    if (!n->data)
    {
        free(n);
        return -3;
    }
    memcpy(n->data, payload, len);
    n->seq = new_start;
    n->len = len;

    pp = &d->head;
    while (*pp && SEQ_LT((*pp)->seq, n->seq))
        pp = &(*pp)->next;
    n->next = *pp;
    *pp = n;
    d->seg_count++;
    d->bytes_queued += len;

    while (n->next)
    {
        reasm_seg_node_t *nx = n->next;
        uint32_t n_end = n->seq + n->len;
        if (n_end != nx->seq)
            break;

        uint32_t merged_len = n->len + nx->len;
        uint8_t *buf = (uint8_t *)realloc(n->data, merged_len);
        if (!buf)
            break;
        n->data = buf;
        memcpy(n->data + n->len, nx->data, nx->len);
        n->len = merged_len;

        n->next = nx->next;
        d->seg_count--;
        reasm_seg_free(nx);
    }

    return 0;
}

static int reasm_looks_like_http_start(const uint8_t *payload, uint32_t len)
{
    static const char *const methods[] = {
        "GET ", "POST ", "PUT ", "HEAD ", "DELETE ",
        "OPTIONS ", "PATCH ", "TRACE ", "CONNECT ",
        "HTTP/"
    };
    size_t i;

    if (!payload || len == 0)
        return 0;

    for (i = 0; i < sizeof(methods) / sizeof(methods[0]); i++)
    {
        size_t n = strlen(methods[i]);
        if (len >= n && memcmp(payload, methods[i], n) == 0)
            return 1;
    }
    return 0;
}

static void reasm_flush(reasm_ctx_t *c, reasm_session_t *s, tcp_dir_t dir)
{
    reasm_dir_t *d = &s->dir[dir];
    if (!d->has_next)
        return;

    while (d->head && d->head->seq == d->next_seq)
    {
        reasm_seg_node_t *h = d->head;
        if (c->on_data)
        {
            c->on_data(&s->key, dir, h->data, h->len, h->seq, c->user);
        }

        d->next_seq += h->len;
        d->bytes_queued -= h->len;
        d->seg_count--;
        d->head = h->next;
        reasm_seg_free(h);
    }
}

static int reasm_ingest(
    reasm_ctx_t *c,
    const flow_key_t *flow,
    tcp_dir_t dir,
    uint32_t seq,
    uint8_t tcp_flags,
    const uint8_t *payload,
    uint32_t len,
    uint64_t ts_ms)
{
    if (!c || !flow)
        return -1;
    if (dir != DIR_AB && dir != DIR_BA)
        return -1;

    reasm_session_t *s = reasm_lookup(c, flow, ts_ms);
    if (tcp_flags & TCP_RST)
    {
        if (!s)
            return 0;
        uint32_t idx = reasm_flow_hash(flow) % c->nbuckets;
        reasm_session_t **pp = &c->buckets[idx];
        while (*pp)
        {
            if (*pp == s)
            {
                *pp = s->next;
                c->nsessions--;
                reasm_session_free(s);
                break;
            }
            pp = &(*pp)->next;
        }
        return 0;
    }

    if (!s)
    {
        if (len == 0 && c->mode == REASM_MODE_LATE_START)
            return 0;
        if (c->mode == REASM_MODE_STRICT_SYN && !(tcp_flags & TCP_SYN))
            return 0;
        s = reasm_get_or_create(c, flow, ts_ms);
        if (!s)
            return -2;
    }

    reasm_dir_t *d = &s->dir[dir];
    if (tcp_flags & TCP_FIN)
        d->fin_seen = 1;

    if (!d->has_next)
    {
        if (c->mode == REASM_MODE_STRICT_SYN)
        {
            d->has_next = 1;
            d->next_seq = seq + 1;
        }
        else
        {
            if (len == 0)
                return 0;
            if (!reasm_looks_like_http_start(payload, len))
                return reasm_insert_segment(d, seq, payload, len);
            d->has_next = 1;
            d->next_seq = seq;
        }
    }

    uint32_t adj_seq = seq;
    const uint8_t *adj_pl = payload;
    uint32_t adj_len = len;

    reasm_trim_to_next(d, &adj_seq, &adj_pl, &adj_len);
    if (adj_len == 0)
        return 0;

    int rc = reasm_insert_segment(d, adj_seq, adj_pl, adj_len);
    if (rc != 0)
    {
        uint32_t idx = reasm_flow_hash(flow) % c->nbuckets;
        reasm_session_t **pp = &c->buckets[idx];
        while (*pp)
        {
            if (*pp == s)
            {
                *pp = s->next;
                c->nsessions--;
                reasm_session_free(s);
                break;
            }
            pp = &(*pp)->next;
        }
        return rc;
    }

    reasm_flush(c, s, dir);

    if (s->dir[0].fin_seen && s->dir[1].fin_seen &&
        s->dir[0].head == NULL && s->dir[1].head == NULL)
    {
        uint32_t idx = reasm_flow_hash(flow) % c->nbuckets;
        reasm_session_t **pp = &c->buckets[idx];
        while (*pp)
        {
            if (*pp == s)
            {
                *pp = s->next;
                c->nsessions--;
                reasm_session_free(s);
                break;
            }
            pp = &(*pp)->next;
        }
    }

    return 0;
}

struct httgw
{
    reasm_ctx_t *reasm;
    http_stream_cfg_t stream_cfg;
    httgw_callbacks_t cbs;

    void *user;
    httgw_stats_t stats;
    int verbose;
    httgw_mode_t mode;

    /* 송신 경로 핸들 + RST 송신함수*/
    void *tx_ctx;
    httgw_send_rst_fn tx_send_rst;

    httgw_session_t **sess_buckets;
    uint32_t sess_bucket_count;
    uint32_t sess_count;
};

struct ip_hash
{
    ip_node_t **buckets;
    size_t nbuckets;
};

#if defined(__GNUC__)
#define HTTGW_UNUSED __attribute__((unused))
#endif

struct httgw_session
{
    flow_key_t flow;
    http_stream_t *streams[2];

    uint32_t base_seq_ab;
    uint32_t base_seq_ba;
    uint32_t last_seq_ab;
    uint32_t next_seq_ab;
    uint32_t last_ack_ab;
    uint32_t last_seq_ba;
    uint32_t next_seq_ba;
    uint32_t last_ack_ba;
    uint16_t win_ab;
    uint16_t win_ba;
    uint8_t win_scale_ab;
    uint8_t win_scale_ba;

    uint8_t seen_ab;
    uint8_t seen_ba; // 해당 방향 패킷을 봤는지?

    uint64_t last_ts_ms; // 세션 타임아웃/GC용

    uint8_t fin_seen_ab;
    uint8_t fin_seen_ba; // 종료 상태 추적
    uint8_t rst_sent_ab;
    uint8_t rst_sent_ba;

    struct httgw_session *next;
};

/* --------------------------- session table --------------------------- */
#define HTTGW_SESS_BUCKETS 4096
#define HTTGW_SESS_TIMEOUT_MS (60ULL * 1000ULL)
#define HTTGW_RST_BURST_COUNT 5U

static void sess_destroy(httgw_session_t *s)
{
    if (!s)
        return;
    if (s->streams[DIR_AB])
        http_stream_destroy(s->streams[DIR_AB]);
    if (s->streams[DIR_BA])
        http_stream_destroy(s->streams[DIR_BA]);
    free(s);
}

static uint32_t sess_flow_hash(const flow_key_t *k)
{
    uint32_t h = 2166136261u;
#define H1(x)               \
    do                      \
    {                       \
        h ^= (uint32_t)(x); \
        h *= 16777619u;     \
    } while (0)
    H1(k->src_ip);
    H1(k->dst_ip);
    H1(((uint32_t)k->src_port << 16) | k->dst_port);
    H1(k->proto);
#undef H1
    return h;
}

static int sess_flow_eq(const flow_key_t *a, const flow_key_t *b)
{
    return a->src_ip == b->src_ip && a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port && a->dst_port == b->dst_port &&
           a->proto == b->proto;
}

/* --------------------------- ip hash table (unused for now) --------------------------- */
static uint32_t HTTGW_UNUSED ip_hash_fn(uint32_t ip)
{
    ip ^= ip >> 16;
    ip *= 0x7feb352d;
    ip ^= ip >> 15;
    ip *= 0x846ca68b;
    ip ^= ip >> 16;
    return ip;
}

static httgw_session_t *sess_find(const httgw_t *gw, const flow_key_t *flow)
{
    uint32_t idx = sess_flow_hash(flow) % gw->sess_bucket_count;
    for (httgw_session_t *s = gw->sess_buckets[idx]; s; s = s->next)
    {
        if (sess_flow_eq(&s->flow, flow))
            return s;
    }
    return NULL;
}

static httgw_session_t *sess_remove_internal(httgw_t *gw, const flow_key_t *flow)
{
    uint32_t idx;
    httgw_session_t **pp;

    if (!gw || !flow)
        return NULL;

    idx = sess_flow_hash(flow) % gw->sess_bucket_count;
    pp = &gw->sess_buckets[idx];
    while (*pp)
    {
        if (sess_flow_eq(&(*pp)->flow, flow))
        {
            httgw_session_t *s = *pp;
            *pp = s->next;
            if (gw->sess_count > 0)
                gw->sess_count--;
            s->next = NULL;
            return s;
        }
        pp = &(*pp)->next;
    }
    return NULL;
}

static httgw_session_t *sess_get_or_create_internal(httgw_t *gw, const flow_key_t *flow, uint64_t ts_ms)
{
    uint32_t idx = sess_flow_hash(flow) % gw->sess_bucket_count;
    for (httgw_session_t *s = gw->sess_buckets[idx]; s; s = s->next)
    {
        if (sess_flow_eq(&s->flow, flow))
        {
            s->last_ts_ms = ts_ms;
            return s;
        }
    }

    httgw_session_t *s = (httgw_session_t *)calloc(1, sizeof(*s));
    if (!s)
        return NULL;

    s->streams[DIR_AB] = http_stream_create(&gw->stream_cfg);
    s->streams[DIR_BA] = http_stream_create(&gw->stream_cfg);
    if (!s->streams[DIR_AB] || !s->streams[DIR_BA])
    {
        sess_destroy(s);
        return NULL;
    }

    s->flow = *flow;
    s->last_ts_ms = ts_ms;
    s->next = gw->sess_buckets[idx];
    gw->sess_buckets[idx] = s;
    gw->sess_count++;
    return s;
}

static void print_preview(const uint8_t *data, uint32_t len)
{
    uint32_t i;
    uint32_t n = len < 48 ? len : 48;
    putchar('"');
    for (i = 0; i < n; i++)
    {
        uint8_t c = data[i];
        if (c >= 32 && c <= 126)
        {
            putchar((int)c);
        }
        else
        {
            putchar('.');
        }
    }
    if (len > n)
        printf("...");
    putchar('"');
}

static int endpoint_cmp(uint32_t a_ip, uint16_t a_port, uint32_t b_ip, uint16_t b_port)
{
    if (a_ip < b_ip)
        return -1;
    if (a_ip > b_ip)
        return 1;
    if (a_port < b_port)
        return -1;
    if (a_port > b_port)
        return 1;
    return 0;
}

static void normalize_flow(
    uint32_t sip, uint16_t sport,
    uint32_t dip, uint16_t dport,
    flow_key_t *key, tcp_dir_t *dir)
{
    int c = endpoint_cmp(sip, sport, dip, dport);
    memset(key, 0, sizeof(*key));
    key->proto = 6;
    if (c <= 0)
    {
        key->src_ip = sip;
        key->src_port = sport;
        key->dst_ip = dip;
        key->dst_port = dport;
        *dir = DIR_AB;
    }
    else
    {
        key->src_ip = dip;
        key->src_port = dport;
        key->dst_ip = sip;
        key->dst_port = sport;
        *dir = DIR_BA;
    }
}

static int parse_ipv4_tcp_payload(
    const uint8_t *pkt, uint32_t caplen,
    flow_key_t *flow, tcp_dir_t *dir,
    uint32_t *seq, uint32_t *ack, uint8_t *flags,
    const uint8_t **payload, uint32_t *payload_len,
    uint16_t *window, uint8_t *win_scale)
{
    const uint8_t *p = pkt;
    uint32_t n = caplen;
    uint16_t eth_type;
    uint32_t ip_hl;
    uint32_t ip_len;
    uint32_t tcp_hl;
    uint16_t total_len;
    uint8_t proto;
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;

    if (n < 14)
        return 0;
    eth_type = (uint16_t)((p[12] << 8) | p[13]);
    p += 14;
    n -= 14;

    if (eth_type == 0x8100 || eth_type == 0x88A8)
    {
        if (n < 4)
            return 0;
        eth_type = (uint16_t)((p[2] << 8) | p[3]);
        p += 4;
        n -= 4;
    }

    if (eth_type != 0x0800)
        return 0;
    if (n < 20)
        return 0;
    if ((p[0] >> 4) != 4)
        return 0;

    ip_hl = (uint32_t)(p[0] & 0x0F) * 4U;
    if (ip_hl < 20 || n < ip_hl)
        return 0;

    total_len = (uint16_t)((p[2] << 8) | p[3]);
    if (total_len < ip_hl || n < total_len)
        return 0;

    proto = p[9];
    if (proto != 6)
        return 0;

    sip = (uint32_t)((p[12] << 24) | (p[13] << 16) | (p[14] << 8) | p[15]);
    dip = (uint32_t)((p[16] << 24) | (p[17] << 16) | (p[18] << 8) | p[19]);

    p += ip_hl;
    n = total_len - ip_hl;
    if (n < 20)
        return 0;

    sport = (uint16_t)((p[0] << 8) | p[1]);
    dport = (uint16_t)((p[2] << 8) | p[3]);
    *seq = (uint32_t)((p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7]);
    *ack = (uint32_t)((p[8] << 24) | (p[9] << 16) | (p[10] << 8) | p[11]);
    tcp_hl = (uint32_t)((p[12] >> 4) & 0x0F) * 4U;
    if (tcp_hl < 20 || n < tcp_hl)
        return 0;
    *flags = p[13];
    if (window)
        *window = (uint16_t)((p[14] << 8) | p[15]);
    if (win_scale)
        *win_scale = 0;

    ip_len = total_len;
    if (ip_len < ip_hl + tcp_hl)
        return 0;

    *payload_len = ip_len - ip_hl - tcp_hl;
    *payload = p + tcp_hl;

    if (win_scale && (p[13] & TCP_SYN) && tcp_hl > 20)
    {
        uint32_t opt_len = tcp_hl - 20;
        const uint8_t *opt = p + 20;
        uint32_t i = 0;
        while (i < opt_len)
        {
            uint8_t kind = opt[i];
            if (kind == 0)
                break;
            if (kind == 1)
            {
                i++;
                continue;
            }
            if (i + 1 >= opt_len)
                break;
            uint8_t len = opt[i + 1];
            if (len < 2 || i + len > opt_len)
                break;
            if (kind == 3 && len == 3)
            {
                *win_scale = opt[i + 2];
                break;
            }
            i += len;
        }
    }

    normalize_flow(sip, sport, dip, dport, flow, dir);
    return 1;
}

static uint32_t tcp_next_seq(uint32_t seq, uint32_t payload_len, uint8_t flags)
{
    uint32_t next = seq + payload_len;

    if (flags & TCP_SYN)
        next++;
    if (flags & TCP_FIN)
        next++;
    return next;
}

static void drain_http(httgw_t *gw, const flow_key_t *flow, tcp_dir_t dir)
{
    httgw_session_t *sess = sess_find(gw, flow);
    http_stream_t *s;
    http_message_t msg;

    if (!sess)
        return;
    s = sess->streams[dir];
    if (!s)
        return;

    while (http_stream_poll_message(s, &msg) == HTTP_STREAM_OK)
    {
        gw->stats.http_msgs++;
        if (msg.is_request)
        {
            gw->stats.reqs++;
            if (gw->cbs.on_request)
            {
                const char *q = NULL;
                size_t q_len = 0;
                (void)httgw_extract_query(&msg, &q, &q_len);
                gw->cbs.on_request(flow, dir, &msg, q, q_len, gw->user);
            }
        }
        else
        {
            gw->stats.resps++;
            if (gw->cbs.on_response)
            {
                gw->cbs.on_response(flow, dir, &msg, gw->user);
            }
        }
        http_message_free(&msg);
    }
}
// MODIFY: on_stream_data에서 drain_http 호출 시 flow/dir 전달함
static void on_stream_data(
    const flow_key_t *flow,
    tcp_dir_t dir,
    const uint8_t *data,
    uint32_t len,
    uint32_t seq_start,
    void *user)
{
    httgw_t *gw = (httgw_t *)user;
    httgw_session_t *sess;
    http_stream_t *stream;
    http_stream_rc_t rc;

    sess = sess_find(gw, flow);
    if (!sess)
    {
        if (gw->cbs.on_error)
            gw->cbs.on_error("on_stream_data", "missing httgw session", gw->user);
        return;
    }
    stream = sess->streams[dir];
    if (!stream)
    {
        if (gw->cbs.on_error)
            gw->cbs.on_error("on_stream_data", "missing http stream", gw->user);
        return;
    }

    if (gw->verbose)
    {
        char sip[32], dip[32];
        snprintf(sip, sizeof(sip), "%u.%u.%u.%u",
                 (flow->src_ip >> 24) & 0xFF, (flow->src_ip >> 16) & 0xFF,
                 (flow->src_ip >> 8) & 0xFF, flow->src_ip & 0xFF);
        snprintf(dip, sizeof(dip), "%u.%u.%u.%u",
                 (flow->dst_ip >> 24) & 0xFF, (flow->dst_ip >> 16) & 0xFF,
                 (flow->dst_ip >> 8) & 0xFF, flow->dst_ip & 0xFF);
        printf("[REASM] dir=%s flow=%s:%u -> %s:%u seq_start=%u len=%u preview=",
               (dir == DIR_AB ? "Client->Server" : "Server->Client"),
               sip, flow->src_port, dip, flow->dst_port, seq_start, len);
        print_preview(data, len);
        putchar('\n');
    }

    rc = http_stream_feed(stream, data, len);
    if (rc != HTTP_STREAM_OK)
    {
        gw->stats.parse_errs++;
        if (gw->cbs.on_error)
        {
            gw->cbs.on_error("http_stream_feed", http_stream_last_error(stream), gw->user);
        }
        http_stream_reset(stream);
        return;
    }
    drain_http(gw, flow, dir); // MODIFY
}

httgw_t *httgw_create(const httgw_cfg_t *cfg, const httgw_callbacks_t *cbs, void *user)
{
    httgw_t *gw = NULL;

    gw = (httgw_t *)calloc(1, sizeof(*gw));
    if (!gw)
        return NULL;

    gw->user = user;
    if (cbs)
    {
        gw->cbs = *cbs;
    }
    else
    {
        memset(&gw->cbs, 0, sizeof(gw->cbs));
    }
    gw->verbose = cfg ? (cfg->verbose ? 1 : 0) : 0;

    memset(&gw->stream_cfg, 0, sizeof(gw->stream_cfg));
    gw->stream_cfg.max_buffer_bytes = cfg && cfg->max_buffer_bytes ? cfg->max_buffer_bytes : (2U * 1024U * 1024U);
    gw->stream_cfg.max_body_bytes = cfg && cfg->max_body_bytes ? cfg->max_body_bytes : (2U * 1024U * 1024U);

    gw->reasm = reasm_create(8192, on_stream_data, gw);
    if (!gw->reasm)
    {
        httgw_destroy(gw);
        return NULL;
    }
    gw->sess_bucket_count = HTTGW_SESS_BUCKETS;
    gw->sess_buckets = (httgw_session_t **)calloc(gw->sess_bucket_count, sizeof(*gw->sess_buckets));
    if (!gw->sess_buckets)
    {
        httgw_destroy(gw);
        return NULL;
    }

    if (cfg)
    {
        reasm_set_mode(gw->reasm, cfg->reasm_mode);
    }
    else
    {
        reasm_set_mode(gw->reasm, REASM_MODE_LATE_START);
    }
    gw->mode = cfg ? cfg->mode : HTTGW_MODE_SNIFF;

    return gw;
}

void httgw_destroy(httgw_t *gw)
{
    if (!gw)
        return;
    if (gw->sess_buckets)
    {
        for (uint32_t i = 0; i < gw->sess_bucket_count; i++)
        {
            httgw_session_t *s = gw->sess_buckets[i];
            while (s)
            {
                httgw_session_t *n = s->next;
                sess_destroy(s);
                s = n;
            }
            gw->sess_buckets[i] = NULL;
        }
        free(gw->sess_buckets);
        gw->sess_buckets = NULL;
    }
    gw->sess_count = 0;
    if (gw->reasm)
        reasm_destroy(gw->reasm);
    free(gw);
}

int httgw_set_mode(httgw_t *gw, httgw_mode_t mode)
{
    if (!gw)
        return -1;
    gw->mode = mode;
    return 0;
}

int httgw_ingest_packet(httgw_t *gw, const uint8_t *pkt, uint32_t caplen, uint64_t ts_ms)
{
    flow_key_t flow;
    tcp_dir_t dir;
    uint32_t seq = 0;
    uint32_t ack = 0;
    uint8_t flags = 0;
    const uint8_t *payload = NULL;
    uint32_t payload_len = 0;
    uint32_t next_seq = 0;
    uint16_t window = 0;
    uint8_t win_scale = 0;
    int rc;
    httgw_session_t *sess;

    if (!gw || (!pkt && caplen))
        return -1;

    if (!parse_ipv4_tcp_payload(pkt, caplen, &flow, &dir, &seq, &ack, &flags, &payload, &payload_len, &window, &win_scale))
    {
        return 0;
    }

    next_seq = tcp_next_seq(seq, payload_len, flags);

    if (flags & TCP_RST)
    {
        sess = sess_remove_internal(gw, &flow);
        if (sess)
            sess_destroy(sess);

        rc = reasm_ingest(gw->reasm, &flow, dir, seq, flags, payload, payload_len, ts_ms);
        if (rc != 0)
        {
            gw->stats.reasm_errs++;
            if (gw->cbs.on_error)
            {
                char buf[64];
                snprintf(buf, sizeof(buf), "rc=%d", rc);
                gw->cbs.on_error("reasm_ingest", buf, gw->user);
            }
            return -2;
        }
        return 1;
    }

    sess = sess_get_or_create_internal(gw, &flow, ts_ms);
    if (!sess)
        return -3;
    if (dir == DIR_AB)
    {
        if (!sess->seen_ab)
            sess->base_seq_ab = seq;
        sess->last_seq_ab = seq;
        sess->next_seq_ab = next_seq;
        if (!sess->seen_ab || SEQ_GEQ(ack, sess->last_ack_ab))
        {
            sess->last_ack_ab = ack;
            sess->win_ab = window;
        }
        if (flags & TCP_SYN)
            sess->win_scale_ab = win_scale;
        sess->seen_ab = 1;
        if (flags & TCP_FIN)
            sess->fin_seen_ab = 1;
    }
    else
    {
        if (!sess->seen_ba)
            sess->base_seq_ba = seq;
        sess->last_seq_ba = seq;
        sess->next_seq_ba = next_seq;
        if (!sess->seen_ba || SEQ_GEQ(ack, sess->last_ack_ba))
        {
            sess->last_ack_ba = ack;
            sess->win_ba = window;
        }
        if (flags & TCP_SYN)
            sess->win_scale_ba = win_scale;
        sess->seen_ba = 1;
        if (flags & TCP_FIN)
            sess->fin_seen_ba = 1;
    }
    sess->last_ts_ms = ts_ms;

    rc = reasm_ingest(gw->reasm, &flow, dir, seq, flags, payload, payload_len, ts_ms);
    if (rc != 0)
    {
        httgw_session_t *stale = sess_remove_internal(gw, &flow);
        gw->stats.reasm_errs++;
        if (stale)
            sess_destroy(stale);
        if (gw->cbs.on_error)
        {
            char buf[64];
            snprintf(buf, sizeof(buf), "rc=%d", rc);
            gw->cbs.on_error("reasm_ingest", buf, gw->user);
        }
        return -2;
    }
    return 1;
}

void httgw_gc(httgw_t *gw, uint64_t now_ms)
{
    if (!gw || !gw->reasm)
        return;
    reasm_gc(gw->reasm, now_ms);
    for (uint32_t i = 0; i < gw->sess_bucket_count; i++)
    {
        httgw_session_t **pp = &gw->sess_buckets[i];
        while (*pp)
        {
            httgw_session_t *s = *pp;
            if (now_ms - s->last_ts_ms > HTTGW_SESS_TIMEOUT_MS)
            {
                *pp = s->next;
                sess_destroy(s);
                if (gw->sess_count > 0)
                    gw->sess_count--;
                continue;
            }
            pp = &(*pp)->next;
        }
    }
}

const httgw_stats_t *httgw_stats(const httgw_t *gw)
{
    if (!gw)
        return NULL;
    return &gw->stats;
}

int httgw_get_session_snapshot(const httgw_t *gw, const flow_key_t *flow, httgw_sess_snapshot_t *out)
{
    if (!gw || !flow || !out)
        return -1;
    httgw_session_t *sess = sess_find(gw, flow);
    if (!sess)
        return -2;
    memset(out, 0, sizeof(*out));
    out->base_seq_ab = sess->base_seq_ab;
    out->base_seq_ba = sess->base_seq_ba;
    out->last_ack_ab = sess->last_ack_ab;
    out->next_seq_ab = sess->next_seq_ab;
    out->last_ack_ba = sess->last_ack_ba;
    out->next_seq_ba = sess->next_seq_ba;
    out->win_ab = sess->win_ab;
    out->win_ba = sess->win_ba;
    out->win_scale_ab = sess->win_scale_ab;
    out->win_scale_ba = sess->win_scale_ba;
    out->seen_ab = sess->seen_ab;
    out->seen_ba = sess->seen_ba;
    return 0;
}

static int ci_eq(const uint8_t *a, size_t an, const char *b)
{
    size_t i;
    size_t bn = strlen(b);
    if (an != bn)
        return 0;
    for (i = 0; i < an; i++)
    {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i]))
            return 0;
    }
    return 1;
}

int httgw_header_get(
    const http_message_t *msg,
    const char *name,
    const uint8_t **value,
    size_t *value_len)
{
    const uint8_t *p;
    size_t len;
    size_t pos = 0;
    size_t line_end;

    if (!msg || !name || !value || !value_len)
        return 0;
    if (!msg->headers_raw || msg->headers_raw_len == 0)
        return 0;

    p = msg->headers_raw;
    len = msg->headers_raw_len;

    while (pos + 1 < len)
    {
        if (p[pos] == '\r' && p[pos + 1] == '\n')
        {
            pos += 2;
            break;
        }
        pos++;
    }

    while (pos < len)
    {
        size_t i;
        const uint8_t *line = p + pos;
        size_t line_len = 0;
        const uint8_t *colon;
        const uint8_t *val;
        const uint8_t *val_end;

        for (i = pos; i + 1 < len; i++)
        {
            if (p[i] == '\r' && p[i + 1] == '\n')
            {
                line_end = i;
                line_len = line_end - pos;
                break;
            }
        }
        if (line_len == 0)
            break;

        colon = (const uint8_t *)memchr(line, ':', line_len);
        if (colon)
        {
            size_t name_len = (size_t)(colon - line);
            if (ci_eq(line, name_len, name))
            {
                val = colon + 1;
                while (val < line + line_len && (*val == ' ' || *val == '\t'))
                    val++;
                val_end = line + line_len;
                while (val_end > val && ((*(val_end - 1) == ' ') || (*(val_end - 1) == '\t')))
                    val_end--;
                *value = val;
                *value_len = (size_t)(val_end - val);
                return 1;
            }
        }

        pos = line_end + 2;
    }

    return 0;
}

int httgw_extract_query(const http_message_t *msg, const char **q, size_t *q_len)
{
    const char *uri;
    const char *qm;
    const char *hash;
    size_t len;

    if (!msg || !q || !q_len)
        return 0;
    if (!msg->is_request)
        return 0;

    uri = msg->uri;
    if (!uri || uri[0] == '\0')
        return 0;

    qm = strchr(uri, '?');
    if (!qm || *(qm + 1) == '\0')
        return 0;

    hash = strchr(qm + 1, '#');
    if (hash)
    {
        len = (size_t)(hash - (qm + 1));
    }
    else
    {
        len = strlen(qm + 1);
    }

    if (len == 0)
        return 0;
    *q = qm + 1;
    *q_len = len;
    return 1;
}

static int HTTGW_UNUSED iphash_init(ip_hash_t *h, size_t nbuckets)
{
    if (!h || nbuckets == 0)
        return -1; // h=0, 버킷이 0
    h->buckets = (ip_node_t **)calloc(nbuckets, sizeof(ip_node_t *));
    if (!h->buckets)
        return -1;
    return 0;
}

static void HTTGW_UNUSED iphash_destroy(ip_hash_t *h)
{
    if (!h || !h->buckets)
        return;
    for (size_t i = 0; i < h->nbuckets; i++)
    {
        ip_node_t *p = h->buckets[i];
        while (p)
        {
            ip_node_t *n = p->next;
            free(p);
            p = n;
        }
    }
    free(h->buckets);
    h->buckets = NULL;
    h->nbuckets = 0;
}

static int HTTGW_UNUSED iphash_insert(ip_hash_t *h, uint32_t ip)
{
    if (!h || !h->buckets)
        return -1;
    size_t idx = ip_hash_fn(ip) % h->nbuckets;
    // 중복체크
    for (ip_node_t *p = h->buckets[idx]; p; p = p->next)
    {
        if (p->ip == ip)
            return 0;
    }
    // 메모리에 할당하고 1반환함
    ip_node_t *n = (ip_node_t *)calloc(1, sizeof(*n));
    if (!n)
        return -1;
    n->ip = ip;
    n->next = h->buckets[idx];
    h->buckets[idx] = n;
    return 1;
}

static int HTTGW_UNUSED iphash_delete(ip_hash_t *h, uint32_t ip)
{
    if (!h || !h->buckets)
        return -1;
    size_t idx = ip_hash_fn(ip) % h->nbuckets;

    ip_node_t **pp = &h->buckets[idx];
    while (*pp)
    {
        if ((*pp)->ip == ip)
        {
            ip_node_t *del = *pp;
            *pp = del->next;
            free(del);
            return 1;
        }
        pp = &(*pp)->next;
    }
    return 0;
}
/* 헬퍼 체크섬*/
static uint16_t checksum16(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;

    uint32_t sum = 0;

    while (len > 1)
    {
        sum += (uint16_t)((p[0] << 8) | p[1]);
        p = p + 2;
        len = len - 2;
    }
    if (len)
        sum += (uint16_t)(p[0] << 8);
    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum);
}

static uint16_t tcp_checksum(uint32_t src_be, uint32_t dst_be, const uint8_t *tcp, size_t tcp_len)
{
    uint32_t sum = 0;
    const uint8_t *p;
    size_t len;

    p = (const uint8_t *)&src_be;
    sum += (uint16_t)((p[0] << 8) | p[1]);
    sum += (uint16_t)((p[2] << 8) | p[3]);

    p = (const uint8_t *)&dst_be;
    sum += (uint16_t)((p[0] << 8) | p[1]);
    sum += (uint16_t)((p[2] << 8) | p[3]);

    sum += IPPROTO_TCP;
    sum += (uint16_t)tcp_len;

    p = tcp;
    len = tcp_len;
    while (len > 1) {
        sum += (uint16_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }
    if (len) {
        sum += (uint16_t)(p[0] << 8);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

// Layer 3 전송 함수, 레이어 3 = IP 계층, IP 헤더부터 시작하는 패킷을 raw socket으로 보내라는 함수이다.
int tx_send_l3(void *ctx, const uint8_t *buf, size_t len)
{
    tx_ctx_t *tx = (tx_ctx_t *)ctx;
    struct sockaddr_in dst;
    const IPHDR *ip;
    ssize_t n; //signed size type, 부호있는 크기타입 음수 가능
    // 유효성 검사 -> 송신 컨텍스트/버퍼/최소 IP 헤더 길이 확인
    if (!tx || tx->fd < 0 || !buf || len < IP_HDR_SIZE)
        return -1;
    // Raw L3 버퍼의 시작은 IPv4 헤더
    ip = (const IPHDR *)buf;

    // sendto() 목적지 주소 구조체 초기화
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = IP_DADDR(ip);

    // Raw 소켓으로 미리 구성된 IP/TCP 패킷을 그대로 전송
    n = sendto(tx->fd, buf, len, 0, (struct sockaddr *)&dst, sizeof(dst));
    // sendto는 소켓으로 데이터를 보내는 시스템 호출
    if (n < 0)// sendto 실패
        return -1;
    return (size_t)n == len ? 0 : -1;
}

int tx_ctx_init(tx_ctx_t *tx)
{
    int fd;
    int on = 1;

    if (!tx)
        return -1;
    memset(tx, 0, sizeof(*tx));

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0)
        return -1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) != 0)
    {
        close(fd);
        return -1;
    }

    tx->fd = fd;
    tx->send_l3 = tx_send_l3;
    tx->ctx = tx;
    return 0;
}

void tx_ctx_destroy(tx_ctx_t *tx)
{
    if (!tx)
        return;
    if (tx->fd >= 0)
        close(tx->fd);
    tx->fd = -1;
    tx->send_l3 = NULL;
    tx->ctx = NULL;
}

int httgw_set_tx(httgw_t *gw, tx_ctx_t *tx)
{
    if (!gw)
        return -1;
    gw->tx_ctx = tx;
    gw->tx_send_rst = tx_send_rst;
    return 0;
}

int tx_send_rst(void *tx_ctx, const flow_key_t *flow, tcp_dir_t dir, uint32_t seq, uint32_t ack)
{
    tx_ctx_t *tx = (tx_ctx_t *)tx_ctx;
    uint32_t sip, dip; //RSt 패킷의 source IP, RST 패킷의 destination IP
    uint16_t sport, dport;// Source PORT, Destination IP

    if (!tx || !tx->send_l3 || !flow)
        return -1;

    if (dir == DIR_AB)// 
    {
        sip = flow->src_ip;
        sport = flow->src_port;

        dip = flow->dst_ip;
        dport = flow->dst_port;
    }
    else
    {
        sip = flow->dst_ip;
        sport = flow->dst_port;

        dip = flow->src_ip;
        dport = flow->src_port;
    }
    uint8_t buf[IP_HDR_SIZE + TCP_HDR_SIZE];
    memset(buf, 0, sizeof(buf));

    IPHDR *ip = (IPHDR *)buf;
    TCPHDR *tcp = (TCPHDR *)(buf + sizeof(*ip));

    IP_VER(ip) = 4;
    IP_IHL(ip) = 5;
    IP_TTL_FIELD(ip) = 64;
    IP_PROTO(ip) = IPPROTO_TCP;
    IP_TOTLEN(ip) = htons((uint16_t)sizeof(buf));
    IP_SADDR(ip) = htonl(sip);
    IP_DADDR(ip) = htonl(dip);
    IP_CHECK(ip) = 0;
    IP_CHECK(ip) = checksum16(ip, sizeof(*ip));

    TCP_SPORT(tcp) = htons(sport);
    TCP_DPORT(tcp) = htons(dport);
    TCP_SEQ(tcp) = htonl(seq);
    TCP_ACK(tcp) = htonl(ack);
    TCP_DOFF(tcp) = 5;
    TCP_SET_RST(tcp);
    TCP_SET_ACK(tcp, ack != 0);
    TCP_WIN(tcp) = htons(0);
    TCP_CHECK(tcp) = 0;
    //TCP_CHECK(tcp) = tcp_checksum(IP_SADDR(ip), IP_DADDR(ip), (const uint8_t *)tcp, sizeof(*tcp));
    TCP_CHECK(tcp) = htons(tcp_checksum(IP_SADDR(ip), IP_DADDR(ip), (const uint8_t *)tcp, sizeof(*tcp)));

    return tx->send_l3(tx->ctx, buf, sizeof(buf));
}

int httgw_request_rst_with_snapshot(
    httgw_t *gw,
    const flow_key_t *flow,
    tcp_dir_t dir,
    const httgw_sess_snapshot_t *snap
)
{
    httgw_session_t *sess;
    uint32_t seq_base = 0;
    uint32_t ack = 0;
    uint32_t win = 0;
    int sent_ok = 0;
    int last_err = -1;

    if (!gw || !flow)
        return -1;
    if (!gw->tx_send_rst)
        return -4;

    sess = sess_find(gw, flow);
    if (!sess)
        return -2;
    if (dir == DIR_AB && sess->rst_sent_ab)
        return 1;
    if (dir == DIR_BA && sess->rst_sent_ba)
        return 1;

    if (snap)
    {
        if (!snap->seen_ab || !snap->seen_ba)
            return -3;
        if (dir == DIR_AB)
        {
            if (snap->next_seq_ab == 0 || snap->next_seq_ba == 0)
                return -3;
            seq_base = snap->next_seq_ab;
            ack = snap->next_seq_ba + HTTGW_SERVER_NEXT_BIAS;
            win = ((uint32_t)snap->win_ba) << (snap->win_scale_ba > 14 ? 14 : snap->win_scale_ba);
        }
        else
        {
            if (snap->next_seq_ab == 0 || snap->next_seq_ba == 0)
                return -3;
            seq_base = snap->next_seq_ba + HTTGW_SERVER_NEXT_BIAS;
            ack = snap->next_seq_ab;
            win = ((uint32_t)snap->win_ab) << (snap->win_scale_ab > 14 ? 14 : snap->win_scale_ab);
        }
    }
    else
    {
        if (!sess->seen_ab || !sess->seen_ba)
            return -3;
        if (dir == DIR_AB)//Client -> Server
        {
            if (sess->next_seq_ab == 0 || sess->next_seq_ba == 0)
                return -3;
            seq_base = sess->next_seq_ab;
            ack = sess->next_seq_ba + HTTGW_SERVER_NEXT_BIAS;
            win = ((uint32_t)sess->win_ba) << (sess->win_scale_ba > 14 ? 14 : sess->win_scale_ba);
        }
        else// Server -> Client
        {
            if (sess->next_seq_ab == 0 || sess->next_seq_ba == 0)
                return -3;
            seq_base = sess->next_seq_ba + HTTGW_SERVER_NEXT_BIAS;
            ack = sess->next_seq_ab;
            win = ((uint32_t)sess->win_ab) << (sess->win_scale_ab > 14 ? 14 : sess->win_scale_ab);
        }
    }
    if (win == 0)
        return -3;
    //RST 버스트 날리기, 5번 반복, HTTGW_RST_BUSRT_COUNT = 5 
    for (uint32_t i = 0; i < HTTGW_RST_BURST_COUNT; i++)
    {
        uint32_t seq_off;
        //버스트 1회이거나 윈도우가 1바이트면 분산못하므로 Base만 날리기?
        if (HTTGW_RST_BURST_COUNT == 1 || win == 1) // 둘다 seq_off=0으로 보내는 예외처리
            seq_off = 0;
        else//seq_off는 seq_base에 더할 오프셋이다.
            seq_off = (uint32_t)(((uint64_t)(win - 1) * i) / (HTTGW_RST_BURST_COUNT - 1));
        uint32_t seq_try = seq_base + seq_off;
        if (snap)
        {
            uint32_t rel_seq = seq_try;
            uint32_t rel_ack = ack;
            if (dir == DIR_AB)
            {
                rel_seq -= snap->base_seq_ab;
                rel_ack -= snap->base_seq_ba;
            }
            else
            {
                rel_seq -= snap->base_seq_ba;
                rel_ack -= snap->base_seq_ab;
            }
            fprintf(stderr, "[TCP] RST try dir=%s i=%u rel_seq=%u rel_ack=%u win=%u\n",
                    dir == DIR_AB ? "AB" : "BA", i, rel_seq, rel_ack, win);
        }
        else
        {
            fprintf(stderr, "[TCP] RST try dir=%s i=%u seq=%u ack=%u win=%u\n",
                    dir == DIR_AB ? "AB" : "BA", i, seq_try, ack, win);
        }
        // 계산된 seq/ack로 RST 1회 전송
        int rc = gw->tx_send_rst(gw->tx_ctx, flow, dir, seq_try, ack);
        if (rc == 0)
            sent_ok++;
        else
            last_err = rc;
    }

    if (sent_ok == 5)
    {
        if (dir == DIR_AB)
            sess->rst_sent_ab = 1;
        else
            sess->rst_sent_ba = 1;
        return 0;
    }
    return last_err;
}

int httgw_request_rst(httgw_t *gw, const flow_key_t *flow, tcp_dir_t dir)
{
    return httgw_request_rst_with_snapshot(gw, flow, dir, NULL);
}

int sess_get_or_create(httgw_t *gw, const flow_key_t flow, uint64_t ts_ms)
{
    if (!gw)
        return -1;
    return sess_get_or_create_internal(gw, &flow, ts_ms) ? 1 : 0;
}

int sess_lookup(const httgw_t *gw, const flow_key_t flow)
{
    if (!gw)
        return 0;
    return sess_find(gw, &flow) ? 1 : 0;
}

void sess_gc(httgw_t *gw, uint64_t ts_ms)
{
    httgw_gc(gw, ts_ms);
}

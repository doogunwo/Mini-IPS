/**
 * @file http_stream.c
 * @brief HTTP 세션 관리
 * 

*/
#include "http_stream.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct msg_node {
    http_message_t msg;
    struct msg_node *next;
} msg_node_t;

struct http_stream {
    uint8_t *buf;
    size_t len;
    size_t cap;

    size_t max_buffer_bytes;
    size_t max_body_bytes;

    msg_node_t *q_head;
    msg_node_t *q_tail;

    char last_err[128];
};

static void set_err(http_stream_t *s, const char *msg)
{
    if (!s) return;
    if (!msg) msg = "unknown error";
    snprintf(s->last_err, sizeof(s->last_err), "%s", msg);
}

const char *http_stream_last_error(const http_stream_t *s)
{
    if (!s) return "null stream";
    if (s->last_err[0] == '\0') return "ok";
    return s->last_err;
}

static int ensure_cap(http_stream_t *s, size_t need)
{
    if (need <= s->cap) return 0;
    size_t ncap = s->cap ? s->cap : 1024;
    while (ncap < need) ncap *= 2;
    if (ncap > s->max_buffer_bytes) return -1;
    uint8_t *nb = (uint8_t *)realloc(s->buf, ncap);
    if (!nb) return -1;
    s->buf = nb;
    s->cap = ncap;
    return 0;
}

static int memmem_crlf(const uint8_t *p, size_t len, size_t *idx)
{
    size_t i;
    for (i = 0; i + 1 < len; i++) {
        if (p[i] == '\r' && p[i + 1] == '\n') {
            *idx = i;
            return 1;
        }
    }
    return 0;
}

static int memmem_crlfcrlf(const uint8_t *p, size_t len, size_t *idx)
{
    size_t i;
    for (i = 0; i + 3 < len; i++) {
        if (p[i] == '\r' && p[i + 1] == '\n' && p[i + 2] == '\r' && p[i + 3] == '\n') {
            *idx = i;
            return 1;
        }
    }
    return 0;
}

static int copy_token(char *dst, size_t dst_cap, const uint8_t *src, size_t n)
{
    if (n + 1 > dst_cap) return -1;
    memcpy(dst, src, n);
    dst[n] = '\0';
    return 0;
}

static const uint8_t *skip_lws(const uint8_t *p, const uint8_t *end)
{
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    return p;
}

static void trim_rws(const uint8_t **p, const uint8_t **end)
{
    while (*end > *p && ((*(*end - 1) == ' ') || (*(*end - 1) == '\t'))) {
        (*end)--;
    }
}

static int ci_eq_token(const uint8_t *a, size_t an, const char *b)
{
    size_t i;
    size_t bn = strlen(b);
    if (an != bn) return 0;
    for (i = 0; i < an; i++) {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) return 0;
    }
    return 1;
}

static int ci_contains(const uint8_t *a, size_t an, const char *needle)
{
    size_t i;
    size_t nn = strlen(needle);
    if (nn == 0 || an < nn) return 0;
    for (i = 0; i + nn <= an; i++) {
        size_t j;
        int ok = 1;
        for (j = 0; j < nn; j++) {
            if (tolower((unsigned char)a[i + j]) != tolower((unsigned char)needle[j])) {
                ok = 0;
                break;
            }
        }
        if (ok) return 1;
    }
    return 0;
}

static http_stream_rc_t parse_start_line(http_message_t *m, const uint8_t *line, size_t n)
{
    const uint8_t *sp1;
    const uint8_t *sp2;
    const uint8_t *end = line + n;
    const uint8_t *p;

    if (n >= 5 && memcmp(line, "HTTP/", 5) == 0) {
        m->is_request = 0;

        sp1 = (const uint8_t *)memchr(line, ' ', n);
        if (!sp1) return HTTP_STREAM_EPROTO;
        if (copy_token(m->version, sizeof(m->version), line, (size_t)(sp1 - line)) != 0) {
            return HTTP_STREAM_EOVERFLOW;
        }

        p = sp1 + 1;
        sp2 = (const uint8_t *)memchr(p, ' ', (size_t)(end - p));
        if (!sp2) return HTTP_STREAM_EPROTO;

        {
            char code_buf[8];
            size_t cn = (size_t)(sp2 - p);
            if (cn == 0 || cn >= sizeof(code_buf)) return HTTP_STREAM_EPROTO;
            memcpy(code_buf, p, cn);
            code_buf[cn] = '\0';
            m->status_code = atoi(code_buf);
        }

        p = sp2 + 1;
        if (copy_token(m->reason, sizeof(m->reason), p, (size_t)(end - p)) != 0) {
            return HTTP_STREAM_EOVERFLOW;
        }
    } else {
        m->is_request = 1;

        sp1 = (const uint8_t *)memchr(line, ' ', n);
        if (!sp1) return HTTP_STREAM_EPROTO;
        sp2 = (const uint8_t *)memchr(sp1 + 1, ' ', (size_t)(end - (sp1 + 1)));
        if (!sp2) return HTTP_STREAM_EPROTO;

        if (copy_token(m->method, sizeof(m->method), line, (size_t)(sp1 - line)) != 0) {
            return HTTP_STREAM_EOVERFLOW;
        }
        if (copy_token(m->uri, sizeof(m->uri), sp1 + 1, (size_t)(sp2 - (sp1 + 1))) != 0) {
            return HTTP_STREAM_EOVERFLOW;
        }
        if (copy_token(m->version, sizeof(m->version), sp2 + 1, (size_t)(end - (sp2 + 1))) != 0) {
            return HTTP_STREAM_EOVERFLOW;
        }
    }

    return HTTP_STREAM_OK;
}

static http_stream_rc_t parse_headers_meta(
    http_message_t *m,
    const uint8_t *headers,
    size_t headers_len,
    size_t max_body_bytes
)
{
    size_t pos = 0;
    int first_line_done = 0;

    m->content_length = -1;
    m->chunked = 0;
    m->content_type[0] = '\0';

    while (pos < headers_len) {
        size_t line_end;
        const uint8_t *line;
        size_t line_len;

        if (!memmem_crlf(headers + pos, headers_len - pos, &line_end)) {
            return HTTP_STREAM_EPROTO;
        }

        line = headers + pos;
        line_len = line_end;
        pos += line_end + 2;

        if (line_len == 0) break;

        if (!first_line_done) {
            http_stream_rc_t rc = parse_start_line(m, line, line_len);
            if (rc != HTTP_STREAM_OK) return rc;
            first_line_done = 1;
            continue;
        }

        {
            const uint8_t *colon = (const uint8_t *)memchr(line, ':', line_len);
            const uint8_t *name_end;
            const uint8_t *val;
            const uint8_t *val_end;

            if (!colon) return HTTP_STREAM_EPROTO;
            name_end = colon;
            val = skip_lws(colon + 1, line + line_len);
            val_end = line + line_len;
            trim_rws(&val, &val_end);

            if (ci_eq_token(line, (size_t)(name_end - line), "content-length")) {
                char tmp[32];
                size_t vn = (size_t)(val_end - val);
                long long v;
                if (vn == 0 || vn >= sizeof(tmp)) return HTTP_STREAM_EPROTO;
                memcpy(tmp, val, vn);
                tmp[vn] = '\0';
                v = atoll(tmp);
                if (v < 0 || (size_t)v > max_body_bytes) return HTTP_STREAM_EOVERFLOW;
                m->content_length = v;
            } else if (ci_eq_token(line, (size_t)(name_end - line), "transfer-encoding")) {
                if (ci_contains(val, (size_t)(val_end - val), "chunked")) {
                    m->chunked = 1;
                }
            } else if (ci_eq_token(line, (size_t)(name_end - line), "content-type")) {
                size_t vn = (size_t)(val_end - val);
                if (copy_token(m->content_type, sizeof(m->content_type), val, vn) != 0) {
                    return HTTP_STREAM_EOVERFLOW;
                }
            }
        }
    }

    if (!first_line_done) return HTTP_STREAM_EPROTO;
    return HTTP_STREAM_OK;
}

static http_stream_rc_t append_body(
    uint8_t **buf,
    size_t *len,
    const uint8_t *data,
    size_t n,
    size_t max_body_bytes
)
{
    uint8_t *nb;
    if (*len + n > max_body_bytes) return HTTP_STREAM_EOVERFLOW;
    nb = (uint8_t *)realloc(*buf, *len + n);
    if (!nb) return HTTP_STREAM_ENOMEM;
    memcpy(nb + *len, data, n);
    *buf = nb;
    *len += n;
    return HTTP_STREAM_OK;
}

static http_stream_rc_t parse_chunked_body(
    const uint8_t *p,
    size_t n,
    size_t max_body_bytes,
    size_t *consumed,
    uint8_t **body,
    size_t *body_len
)
{
    size_t pos = 0;
    *body = NULL;
    *body_len = 0;

    while (1) {
        size_t le;
        char tmp[64];
        char *semi;
        unsigned long sz;

        if (!memmem_crlf(p + pos, n - pos, &le)) return HTTP_STREAM_NEED_MORE;
        if (le == 0 || le >= sizeof(tmp)) return HTTP_STREAM_EPROTO;

        memcpy(tmp, p + pos, le);
        tmp[le] = '\0';
        semi = strchr(tmp, ';');
        if (semi) *semi = '\0';

        sz = strtoul(tmp, NULL, 16);
        pos += le + 2;

        if (sz == 0) {
            if (n - pos >= 2 && p[pos] == '\r' && p[pos + 1] == '\n') {
                pos += 2;
                *consumed = pos;
                return HTTP_STREAM_OK;
            }
            {
                size_t tr_end;
                if (!memmem_crlfcrlf(p + pos, n - pos, &tr_end)) return HTTP_STREAM_NEED_MORE;
                pos += tr_end + 4;
                *consumed = pos;
                return HTTP_STREAM_OK;
            }
        }

        if (n - pos < sz + 2) return HTTP_STREAM_NEED_MORE;
        if (p[pos + sz] != '\r' || p[pos + sz + 1] != '\n') return HTTP_STREAM_EPROTO;

        {
            http_stream_rc_t rc = append_body(body, body_len, p + pos, sz, max_body_bytes);
            if (rc != HTTP_STREAM_OK) return rc;
        }

        pos += sz + 2;
    }
}

static http_stream_rc_t queue_message(http_stream_t *s, http_message_t *msg)
{
    msg_node_t *n = (msg_node_t *)calloc(1, sizeof(*n));
    if (!n) return HTTP_STREAM_ENOMEM;
    n->msg = *msg;
    if (!s->q_head) {
        s->q_head = s->q_tail = n;
    } else {
        s->q_tail->next = n;
        s->q_tail = n;
    }
    return HTTP_STREAM_OK;
}

static void consume_front(http_stream_t *s, size_t n)
{
    if (n >= s->len) {
        s->len = 0;
        return;
    }
    memmove(s->buf, s->buf + n, s->len - n);
    s->len -= n;
}

static http_stream_rc_t parse_one(http_stream_t *s, int *produced)
{
    size_t hdr_end_pos;
    size_t msg_hdr_len;
    http_message_t m;
    size_t body_off;
    size_t consumed = 0;

    *produced = 0;
    if (!memmem_crlfcrlf(s->buf, s->len, &hdr_end_pos)) {
        return HTTP_STREAM_NEED_MORE;
    }

    msg_hdr_len = hdr_end_pos + 4;
    if (msg_hdr_len > s->max_buffer_bytes) return HTTP_STREAM_EOVERFLOW;

    memset(&m, 0, sizeof(m));
    m.content_length = -1;

    m.headers_raw = (uint8_t *)malloc(msg_hdr_len);
    if (!m.headers_raw) return HTTP_STREAM_ENOMEM;
    memcpy(m.headers_raw, s->buf, msg_hdr_len);
    m.headers_raw_len = msg_hdr_len;

    {
        http_stream_rc_t rc = parse_headers_meta(&m, s->buf, msg_hdr_len, s->max_body_bytes);
        if (rc != HTTP_STREAM_OK) {
            http_message_free(&m);
            return rc;
        }
    }

    if(m.chunked && m.content_length >=0 ) {
        http_message_free(&m);
        return HTTP_STREAM_EPROTO;
    }

    body_off = msg_hdr_len;
    if (m.chunked) {
        http_stream_rc_t rc = parse_chunked_body(
            s->buf + body_off,
            s->len - body_off,
            s->max_body_bytes,
            &consumed,
            &m.body,
            &m.body_len
        );
        if (rc != HTTP_STREAM_OK) {
            http_message_free(&m);
            return rc;
        }
        consumed += body_off;
    } else if (m.content_length > 0) {
        if ((size_t)m.content_length > s->len - body_off) {
            http_message_free(&m);
            return HTTP_STREAM_NEED_MORE;
        }
        m.body_len = (size_t)m.content_length;
        if (m.body_len > 0) {
            m.body = (uint8_t *)malloc(m.body_len);
            if (!m.body) {
                http_message_free(&m);
                return HTTP_STREAM_ENOMEM;
            }
            memcpy(m.body, s->buf + body_off, m.body_len);
        }
        consumed = body_off + m.body_len;
    } else {
        m.body = NULL;
        m.body_len = 0;
        consumed = body_off;
    }

    {
        http_stream_rc_t rc = queue_message(s, &m);
        if (rc != HTTP_STREAM_OK) {
            http_message_free(&m);
            return rc;
        }
    }

    consume_front(s, consumed);
    *produced = 1;
    return HTTP_STREAM_OK;
}

http_stream_t *http_stream_create(const http_stream_cfg_t *cfg)
{
    http_stream_t *s;
    size_t max_buf = 12 * 1024 * 1024;
    size_t max_body = 12 * 1024 * 1024;

    if (cfg) {
        if (cfg->max_buffer_bytes > 0) max_buf = cfg->max_buffer_bytes;
        if (cfg->max_body_bytes > 0) max_body = cfg->max_body_bytes;
    }

    s = (http_stream_t *)calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->max_buffer_bytes = max_buf;
    s->max_body_bytes = max_body;
    s->last_err[0] = '\0';
    return s;
}

void http_message_free(http_message_t *m)
{
    if (!m) return;
    free(m->headers_raw);
    free(m->body);
    memset(m, 0, sizeof(*m));
}

void http_stream_reset(http_stream_t *s)
{
    msg_node_t *p;
    if (!s) return;
    s->len = 0;
    while (s->q_head) {
        p = s->q_head;
        s->q_head = p->next;
        http_message_free(&p->msg);
        free(p);
    }
    s->q_tail = NULL;
    s->last_err[0] = '\0';
}

void http_stream_destroy(http_stream_t *s)
{
    if (!s) return;
    http_stream_reset(s);
    free(s->buf);
    free(s);
}

http_stream_rc_t http_stream_feed(http_stream_t *s, const uint8_t *data, size_t len)
{
    int produced;
    http_stream_rc_t rc;

    if (!s || (!data && len > 0)) return HTTP_STREAM_EINVAL;
    if (len == 0) return HTTP_STREAM_OK;

    if (s->len + len > s->max_buffer_bytes) {
        set_err(s, "buffer overflow");
        return HTTP_STREAM_EOVERFLOW;
    }
    if (ensure_cap(s, s->len + len) != 0) {
        set_err(s, "memory allocation failed");
        return HTTP_STREAM_ENOMEM;
    }

    memcpy(s->buf + s->len, data, len);
    s->len += len;

    while (1) {
        rc = parse_one(s, &produced);
        if (rc == HTTP_STREAM_NEED_MORE) return HTTP_STREAM_OK;
        if (rc != HTTP_STREAM_OK) {
            set_err(s, "HTTP parse error");
            return rc;
        }
        if (!produced) break;
    }

    return HTTP_STREAM_OK;
}

http_stream_rc_t http_stream_poll_message(http_stream_t *s, http_message_t *out)
{
    msg_node_t *n;
    if (!s || !out) return HTTP_STREAM_EINVAL;
    if (!s->q_head) return HTTP_STREAM_NO_MESSAGE;

    n = s->q_head;
    s->q_head = n->next;
    if (!s->q_head) s->q_tail = NULL;

    *out = n->msg;
    free(n);
    return HTTP_STREAM_OK;
}

#include "html.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct html_buf {
    char  *buf;
    size_t len;
    size_t cap;
} html_buf_t;

static int   html_buf_reserve(html_buf_t *sb, size_t need);
static int   html_buf_append_char(html_buf_t *sb, char c);
static int   html_buf_append_str(html_buf_t *sb, const char *s);
static int   html_buf_append_html_escaped(html_buf_t *sb, const char *s);
static char *read_text_file(const char *path);

char *app_render_block_page(const char *template_path, const char *event_id,
                            const char *timestamp, const char *client_ip) {
    const char *p;
    char       *template_text;
    html_buf_t  out = {0};

    if (!template_path) {
        return NULL;
    }

    template_text = read_text_file(template_path);
    if (!template_text) {
        return NULL;
    }

    p = template_text;
    while (*p != '\0') {
        if (strncmp(p, "{{EVENT_ID}}", 12) == 0) {
            if (html_buf_append_html_escaped(&out, event_id ? event_id : "-") !=
                0) {
                free(template_text);
                free(out.buf);
                return NULL;
            }
            p += 12;
            continue;
        }
        if (strncmp(p, "{{TIMESTAMP}}", 13) == 0) {
            if (html_buf_append_html_escaped(
                    &out, timestamp ? timestamp : "-") != 0) {
                free(template_text);
                free(out.buf);
                return NULL;
            }
            p += 13;
            continue;
        }
        if (strncmp(p, "{{CLIENT_IP}}", 13) == 0) {
            if (html_buf_append_html_escaped(
                    &out, client_ip ? client_ip : "-") != 0) {
                free(template_text);
                free(out.buf);
                return NULL;
            }
            p += 13;
            continue;
        }

        if (html_buf_append_char(&out, *p) != 0) {
            free(template_text);
            free(out.buf);
            return NULL;
        }
        p++;
    }

    free(template_text);
    if (!out.buf) {
        char *empty = (char *)malloc(1U);
        if (!empty) {
            return NULL;
        }
        empty[0] = '\0';
        return empty;
    }
    return out.buf;
}

char *app_build_block_http_response(const char *html_body, size_t *out_len) {
    static const char response_fmt[] =
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n"
        "Content-Length: %zu\r\n"
        "X-Mini-IPS-Block: 1\r\n"
        "\r\n"
        "%s";
    char  *resp;
    int    n;
    size_t body_len;
    size_t total_len;

    if (!html_body) {
        return NULL;
    }

    body_len = strlen(html_body);
    n        = snprintf(NULL, 0, response_fmt, body_len, html_body);
    if (n < 0) {
        return NULL;
    }

    total_len = (size_t)n;
    resp      = (char *)malloc(total_len + 1U);
    if (!resp) {
        return NULL;
    }

    snprintf(resp, total_len + 1U, response_fmt, body_len, html_body);
    if (out_len) {
        *out_len = total_len;
    }
    return resp;
}

static int html_buf_reserve(html_buf_t *sb, size_t need) {
    char  *next;
    size_t next_cap;

    if (!sb) {
        return -1;
    }

    if (need <= sb->cap) {
        return 0;
    }

    next_cap = sb->cap ? sb->cap : 256U;
    while (next_cap < need) {
        next_cap *= 2U;
    }

    next = (char *)realloc(sb->buf, next_cap);
    if (!next) {
        return -1;
    }

    sb->buf = next;
    sb->cap = next_cap;
    return 0;
}

static int html_buf_append_char(html_buf_t *sb, char c) {
    if (html_buf_reserve(sb, sb->len + 2U) != 0) {
        return -1;
    }

    sb->buf[sb->len++] = c;
    sb->buf[sb->len]   = '\0';
    return 0;
}

static int html_buf_append_str(html_buf_t *sb, const char *s) {
    size_t n;

    if (!s) {
        s = "";
    }

    n = strlen(s);
    if (html_buf_reserve(sb, sb->len + n + 1U) != 0) {
        return -1;
    }

    memcpy(sb->buf + sb->len, s, n);
    sb->len += n;
    sb->buf[sb->len] = '\0';
    return 0;
}

static int html_buf_append_html_escaped(html_buf_t *sb, const char *s) {
    size_t i;

    if (!s) {
        return html_buf_append_str(sb, "");
    }

    for (i = 0; s[i] != '\0'; i++) {
        switch (s[i]) {
        case '&':
            if (html_buf_append_str(sb, "&amp;") != 0) {
                return -1;
            }
            break;
        case '<':
            if (html_buf_append_str(sb, "&lt;") != 0) {
                return -1;
            }
            break;
        case '>':
            if (html_buf_append_str(sb, "&gt;") != 0) {
                return -1;
            }
            break;
        case '"':
            if (html_buf_append_str(sb, "&quot;") != 0) {
                return -1;
            }
            break;
        case '\'':
            if (html_buf_append_str(sb, "&#39;") != 0) {
                return -1;
            }
            break;
        default:
            if (html_buf_append_char(sb, s[i]) != 0) {
                return -1;
            }
            break;
        }
    }

    return 0;
}

static char *read_text_file(const char *path) {
    FILE  *fp;
    long   sz;
    size_t nread;
    char  *buf;

    if (!path) {
        return NULL;
    }

    fp = fopen(path, "rb");
    if (!fp) {
        return NULL;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }

    sz = ftell(fp);
    if (sz < 0) {
        fclose(fp);
        return NULL;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }

    buf = (char *)malloc((size_t)sz + 1U);
    if (!buf) {
        fclose(fp);
        return NULL;
    }

    nread = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    if (nread != (size_t)sz) {
        free(buf);
        return NULL;
    }

    buf[nread] = '\0';
    return buf;
}

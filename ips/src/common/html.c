#include "html.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

typedef struct html_buf {
    char  *buf;
    size_t len;
    size_t cap;
} html_buf_t;

static int         html_buf_reserve(html_buf_t *sb, size_t need);
static int         html_buf_append_char(html_buf_t *sb, char c);
static int         html_buf_append_str(html_buf_t *sb, const char *s);
static int         html_buf_append_html_escaped(html_buf_t *sb, const char *s);
static char       *read_text_file(const char *path);
static uint8_t    *read_binary_file(const char *path, size_t *out_len);
static const char *resolve_block_template_path(const char *template_path);
static const char *resolve_logo_image_path(void);
static char       *base64_encode_alloc(const uint8_t *src, size_t len);
static char       *build_logo_image_html(void);
static const char *get_logo_image_html(void);

char *app_render_block_page(const char *template_path, const char *event_id,
                            const char *timestamp, const char *client_ip) {
    const char *p;
    const char *resolved_template_path;
    char       *template_text;
    html_buf_t  out = {0};

    resolved_template_path = resolve_block_template_path(template_path);
    if (NULL == resolved_template_path) {
        return NULL;
    }

    template_text = read_text_file(resolved_template_path);
    if (NULL == template_text) {
        return NULL;
    }

    p = template_text;
    while (*p != '\0') {
        if (strncmp(p, "{{EVENT_ID}}", 12) == 0) {
            if (0 != html_buf_append_html_escaped(&out,
                                                  NULL != event_id ? event_id :
                                                                     "-")) {
                free(template_text);
                free(out.buf);
                return NULL;
            }
            p += 12;
            continue;
        }
        if (strncmp(p, "{{TIMESTAMP}}", 13) == 0) {
            if (0 != html_buf_append_html_escaped(
                         &out, NULL != timestamp ? timestamp : "-")) {
                free(template_text);
                free(out.buf);
                return NULL;
            }
            p += 13;
            continue;
        }
        if (strncmp(p, "{{CLIENT_IP}}", 13) == 0) {
            if (0 != html_buf_append_html_escaped(
                         &out, NULL != client_ip ? client_ip : "-")) {
                free(template_text);
                free(out.buf);
                return NULL;
            }
            p += 13;
            continue;
        }
        if (strncmp(p, "{{LOGO_IMAGE}}", 14) == 0) {
            if (0 != html_buf_append_str(&out, get_logo_image_html())) {
                free(template_text);
                free(out.buf);
                return NULL;
            }
            p += 14;
            continue;
        }
        if (0 != html_buf_append_char(&out, *p)) {
            free(template_text);
            free(out.buf);
            return NULL;
        }
        p++;
    }

    free(template_text);
    if (NULL == out.buf) {
        out.buf = (char *)malloc(1U);
        if (NULL == out.buf) {
            return NULL;
        }
        out.buf[0] = '\0';
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
    size_t body_len;
    size_t total_len;
    int    n;
    char  *resp;

    if (NULL == html_body) {
        return NULL;
    }

    body_len = strlen(html_body);
    n = snprintf(NULL, 0, response_fmt, body_len, html_body);
    if (0 > n) {
        return NULL;
    }

    total_len = (size_t)n;
    resp = (char *)malloc(total_len + 1U);
    if (NULL == resp) {
        return NULL;
    }

    snprintf(resp, total_len + 1U, response_fmt, body_len, html_body);
    if (NULL != out_len) {
        *out_len = total_len;
    }
    return resp;
}

static int html_buf_reserve(html_buf_t *sb, size_t need) {
    char  *next;
    size_t next_cap;

    if (NULL == sb) {
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
    if (NULL == next) {
        return -1;
    }

    sb->buf = next;
    sb->cap = next_cap;
    return 0;
}

static int html_buf_append_char(html_buf_t *sb, char c) {
    if (0 != html_buf_reserve(sb, sb->len + 2U)) {
        return -1;
    }

    sb->buf[sb->len++] = c;
    sb->buf[sb->len] = '\0';
    return 0;
}

static int html_buf_append_str(html_buf_t *sb, const char *s) {
    size_t n;

    if (NULL == s) {
        s = "";
    }

    n = strlen(s);
    if (0 != html_buf_reserve(sb, sb->len + n + 1U)) {
        return -1;
    }

    memcpy(sb->buf + sb->len, s, n);
    sb->len += n;
    sb->buf[sb->len] = '\0';
    return 0;
}

static int html_buf_append_html_escaped(html_buf_t *sb, const char *s) {
    size_t i;

    if (NULL == s) {
        return html_buf_append_str(sb, "");
    }

    for (i = 0U; s[i] != '\0'; i++) {
        switch (s[i]) {
        case '&':
            if (0 != html_buf_append_str(sb, "&amp;")) {
                return -1;
            }
            break;
        case '<':
            if (0 != html_buf_append_str(sb, "&lt;")) {
                return -1;
            }
            break;
        case '>':
            if (0 != html_buf_append_str(sb, "&gt;")) {
                return -1;
            }
            break;
        case '"':
            if (0 != html_buf_append_str(sb, "&quot;")) {
                return -1;
            }
            break;
        case '\'':
            if (0 != html_buf_append_str(sb, "&#39;")) {
                return -1;
            }
            break;
        default:
            if (0 != html_buf_append_char(sb, s[i])) {
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

    if (NULL == path) {
        return NULL;
    }

    fp = fopen(path, "rb");
    if (NULL == fp) {
        return NULL;
    }
    if (0 != fseek(fp, 0, SEEK_END)) {
        fclose(fp);
        return NULL;
    }
    sz = ftell(fp);
    if (0 > sz) {
        fclose(fp);
        return NULL;
    }
    if (0 != fseek(fp, 0, SEEK_SET)) {
        fclose(fp);
        return NULL;
    }

    buf = (char *)malloc((size_t)sz + 1U);
    if (NULL == buf) {
        fclose(fp);
        return NULL;
    }

    nread = fread(buf, 1U, (size_t)sz, fp);
    fclose(fp);
    if (nread != (size_t)sz) {
        free(buf);
        return NULL;
    }

    buf[nread] = '\0';
    return buf;
}

static uint8_t *read_binary_file(const char *path, size_t *out_len) {
    FILE    *fp;
    long     sz;
    size_t   nread;
    uint8_t *buf;

    if (NULL == path) {
        return NULL;
    }

    fp = fopen(path, "rb");
    if (NULL == fp) {
        return NULL;
    }
    if (0 != fseek(fp, 0, SEEK_END)) {
        fclose(fp);
        return NULL;
    }
    sz = ftell(fp);
    if (0 > sz) {
        fclose(fp);
        return NULL;
    }
    if (0 != fseek(fp, 0, SEEK_SET)) {
        fclose(fp);
        return NULL;
    }

    buf = (uint8_t *)malloc((size_t)sz);
    if (NULL == buf) {
        fclose(fp);
        return NULL;
    }

    nread = fread(buf, 1U, (size_t)sz, fp);
    fclose(fp);
    if (nread != (size_t)sz) {
        free(buf);
        return NULL;
    }

    if (NULL != out_len) {
        *out_len = nread;
    }
    return buf;
}

static const char *resolve_block_template_path(const char *template_path) {
    static const char *candidates[] = {
        "image/block.html",
        "DB/block.html",
        "../image/block.html",
        "../DB/block.html",
        "../../image/block.html",
        "../../DB/block.html",
    };
    size_t i;

    if (NULL != template_path && 0 == access(template_path, R_OK)) {
        return template_path;
    }

    for (i = 0U; i < (sizeof(candidates) / sizeof(candidates[0])); i++) {
        if (0 == access(candidates[i], R_OK)) {
            return candidates[i];
        }
    }

    return NULL;
}

static const char *resolve_logo_image_path(void) {
    static const char *candidates[] = {
        "image/image.png",
        "image.png",
        "../image/image.png",
        "../../image/image.png",
    };
    size_t i;

    for (i = 0U; i < (sizeof(candidates) / sizeof(candidates[0])); i++) {
        if (0 == access(candidates[i], R_OK)) {
            return candidates[i];
        }
    }

    return NULL;
}

static char *base64_encode_alloc(const uint8_t *src, size_t len) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char   *out;
    size_t  i;
    size_t  j;
    size_t  out_len;

    if (NULL == src || 0U == len) {
        return NULL;
    }

    out_len = ((len + 2U) / 3U) * 4U;
    out = (char *)malloc(out_len + 1U);
    if (NULL == out) {
        return NULL;
    }

    i = 0U;
    j = 0U;
    while (i < len) {
        size_t   remain;
        uint32_t octet_a;
        uint32_t octet_b;
        uint32_t octet_c;
        uint32_t triple;

        remain = len - i;
        octet_a = src[i++];
        octet_b = (remain > 1U) ? src[i++] : 0U;
        octet_c = (remain > 2U) ? src[i++] : 0U;
        triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        out[j++] = table[(triple >> 18) & 0x3FU];
        out[j++] = table[(triple >> 12) & 0x3FU];
        out[j++] = (remain > 1U) ? table[(triple >> 6) & 0x3FU] : '=';
        out[j++] = (remain > 2U) ? table[triple & 0x3FU] : '=';
    }

    out[out_len] = '\0';
    return out;
}

static char *build_logo_image_html(void) {
    static const char prefix[] =
        "<div class=\"logo-wrap\">"
        "<img class=\"brand-logo\" src=\"data:image/png;base64,";
    static const char suffix[] = "\" alt=\"Mini-IPS logo\"></div>";
    const char *image_path;
    uint8_t    *image_data;
    char       *image_b64;
    char       *html;
    size_t      image_len;
    size_t      total_len;

    image_path = resolve_logo_image_path();
    if (NULL == image_path) {
        return NULL;
    }

    image_data = read_binary_file(image_path, &image_len);
    if (NULL == image_data) {
        return NULL;
    }

    image_b64 = base64_encode_alloc(image_data, image_len);
    free(image_data);
    if (NULL == image_b64) {
        return NULL;
    }

    total_len = strlen(prefix) + strlen(image_b64) + strlen(suffix);
    html = (char *)malloc(total_len + 1U);
    if (NULL == html) {
        free(image_b64);
        return NULL;
    }

    snprintf(html, total_len + 1U, "%s%s%s", prefix, image_b64, suffix);
    free(image_b64);
    return html;
}

static const char *get_logo_image_html(void) {
    static char *cached_html;
    static int   cache_ready;

    if (!cache_ready) {
        cached_html = build_logo_image_html();
        cache_ready = 1;
    }

    if (NULL == cached_html) {
        return "";
    }

    return cached_html;
}

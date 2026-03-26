/**
 * @file html.c
 * @brief 차단 페이지 HTML 렌더링 및 HTTP 응답 조립 구현
 *
 * 탐지 이후 사용자에게 보여줄 차단 페이지를 템플릿 기반으로 렌더링하고,
 * 이를 실제 403 HTTP 응답으로 감싸는 presentation 계층이다.
 */
#include "html.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct html_buf {
    char  *buf;
    size_t len;
    size_t cap;
} html_buf_t;

static pthread_once_t g_logo_image_once = PTHREAD_ONCE_INIT;
static char          *g_logo_image_html = NULL;

/**
 * @brief html_buf_t가 지정한 길이 이상을 담을 수 있게 버퍼를 확장한다.
 *
 * @param sb 동적 문자열 버퍼
 * @param need 필요한 최소 바이트 수
 * @return int 0이면 성공, -1이면 실패
 */
static int html_buf_reserve(html_buf_t *sb, size_t need) {
    char  *next;
    size_t next_cap;

    if (!sb) {
        return -1;
    }

    /* 이미 충분한 용량이 있으면 재할당 없이 그대로 사용한다. */
    if (need <= sb->cap) {
        return 0;
    }

    /* 작은 문자열부터 시작해 2배씩 키우는 방식으로 재할당 횟수를 줄인다. */
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

/**
 * @brief 버퍼 뒤에 단일 문자를 추가한다.
 *
 * @param sb 동적 문자열 버퍼
 * @param c 추가할 문자
 * @return int 0이면 성공, -1이면 실패
 */
static int html_buf_append_char(html_buf_t *sb, char c) {
    int ret;

    ret = html_buf_reserve(sb, sb->len + 2U);
    if (0 != ret) {
        return -1;
    }

    /* 새 문자 뒤에는 항상 NUL 종료를 유지해 C 문자열로 쓸 수 있게 한다. */
    sb->buf[sb->len++] = c;
    sb->buf[sb->len]   = '\0';
    return 0;
}

/**
 * @brief 버퍼 뒤에 문자열 전체를 추가한다.
 *
 * @param sb 동적 문자열 버퍼
 * @param s 추가할 문자열
 * @return int 0이면 성공, -1이면 실패
 */
static int html_buf_append_str(html_buf_t *sb, const char *s) {
    size_t n;
    int    ret;

    /* NULL 입력은 빈 문자열로 취급해 호출자 분기를 줄인다. */
    if (!s) {
        s = "";
    }

    n   = strlen(s);
    ret = html_buf_reserve(sb, sb->len + n + 1U);
    if (0 != ret) {
        return -1;
    }

    memcpy(sb->buf + sb->len, s, n);
    sb->len += n;
    sb->buf[sb->len] = '\0';
    return 0;
}

/**
 * @brief 문자열을 HTML escape 하며 버퍼에 추가한다.
 *
 * `&`, `<`, `>`, `"`, `'` 문자를 엔티티로 변환해 템플릿 삽입값이
 * 브라우저에서 마크업으로 해석되지 않도록 한다.
 *
 * @param sb 동적 문자열 버퍼
 * @param s escape 후 추가할 문자열
 * @return int 0이면 성공, -1이면 실패
 */
static int html_buf_append_html_escaped(html_buf_t *sb, const char *s) {
    size_t i;
    int    ret;

    if (!s) {
        return html_buf_append_str(sb, "");
    }

    /* 사용자 입력 문자열을 한 글자씩 훑으며 치환 대상 문자를 escape 한다. */
    for (i = 0; s[i] != '\0'; i++) {
        switch (s[i]) {
        case '&':
            ret = html_buf_append_str(sb, "&amp;");
            if (0 != ret) {
                return -1;
            }
            break;
        case '<':
            ret = html_buf_append_str(sb, "&lt;");
            if (0 != ret) {
                return -1;
            }
            break;
        case '>':
            ret = html_buf_append_str(sb, "&gt;");
            if (0 != ret) {
                return -1;
            }
            break;
        case '"':
            ret = html_buf_append_str(sb, "&quot;");
            if (0 != ret) {
                return -1;
            }
            break;
        case '\'':
            ret = html_buf_append_str(sb, "&#39;");
            if (0 != ret) {
                return -1;
            }
            break;
        default:
            ret = html_buf_append_char(sb, s[i]);
            if (0 != ret) {
                return -1;
            }
            break;
        }
    }

    return 0;
}

/**
 * @brief 텍스트 파일 전체를 메모리 버퍼로 읽는다.
 *
 * 템플릿 파일처럼 크기가 크지 않은 파일을 한 번에 읽어 NUL 종료 문자열로
 * 반환한다.
 *
 * @param path 읽을 파일 경로
 * @return char* 읽은 파일 내용, 실패 시 NULL
 */
static char *read_text_file(const char *path) {
    FILE  *fp;
    long   sz;
    size_t nread;
    char  *buf;
    int    ret;

    /* 파일 경로가 없으면 열 수 없으므로 바로 실패한다. */
    if (!path) {
        return NULL;
    }

    /* 바이너리 모드로 열어 플랫폼별 줄바꿈 변환 없이 원문 그대로 읽는다. */
    fp = fopen(path, "rb");
    if (!fp) {
        return NULL;
    }

    /* 파일 끝으로 이동해 전체 길이를 먼저 구한다. */
    ret = fseek(fp, 0, SEEK_END);
    if (0 != ret) {
        fclose(fp);
        return NULL;
    }

    sz = ftell(fp);
    if (0 > sz) {
        fclose(fp);
        return NULL;
    }

    ret = fseek(fp, 0, SEEK_SET);
    if (0 != ret) {
        fclose(fp);
        return NULL;
    }

    /* 전체 길이 + NUL 종료 문자를 담을 버퍼를 한 번에 확보한다. */
    buf = (char *)malloc((size_t)sz + 1U);
    if (!buf) {
        fclose(fp);
        return NULL;
    }

    /* 파일을 전부 읽고, 기대한 길이와 다르면 실패로 처리한다. */
    nread = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    if (nread != (size_t)sz) {
        free(buf);
        return NULL;
    }

    buf[nread] = '\0';
    return buf;
}

/**
 * @brief 바이너리 파일 전체를 메모리 버퍼로 읽는다.
 *
 * PNG 로고처럼 NUL 문자를 포함할 수 있는 리소스를 읽기 위해 길이를 함께
 * 돌려준다.
 *
 * @param path 읽을 파일 경로
 * @param out_len 읽은 바이트 수를 돌려받을 포인터
 * @return char* 읽은 파일 내용, 실패 시 NULL
 */
static char *read_binary_file(const char *path, size_t *out_len) {
    FILE  *fp;
    long   sz;
    size_t nread;
    char  *buf;
    int    ret;

    if (!path || !out_len) {
        return NULL;
    }

    fp = fopen(path, "rb");
    if (!fp) {
        return NULL;
    }

    ret = fseek(fp, 0, SEEK_END);
    if (0 != ret) {
        fclose(fp);
        return NULL;
    }

    sz = ftell(fp);
    if (0 > sz) {
        fclose(fp);
        return NULL;
    }

    ret = fseek(fp, 0, SEEK_SET);
    if (0 != ret) {
        fclose(fp);
        return NULL;
    }

    buf = (char *)malloc((size_t)sz);
    if (!buf) {
        fclose(fp);
        return NULL;
    }

    nread = fread(buf, 1U, (size_t)sz, fp);
    fclose(fp);
    if (nread != (size_t)sz) {
        free(buf);
        return NULL;
    }

    *out_len = (size_t)sz;
    return buf;
}

/**
 * @brief 바이트 버퍼를 Base64 문자열로 인코딩한다.
 *
 * 차단 페이지 안에 PNG를 data URI로 내장하기 위해 사용한다.
 *
 * @param data 인코딩할 바이너리 버퍼
 * @param len 버퍼 길이
 * @return char* Base64 인코딩 결과, 실패 시 NULL
 */
static char *base64_encode(const unsigned char *data, size_t len) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char  *out;
    size_t out_len;
    size_t i;
    size_t j;

    if (!data && 0U != len) {
        return NULL;
    }

    out_len = 4U * ((len + 2U) / 3U);
    out     = (char *)malloc(out_len + 1U);
    if (!out) {
        return NULL;
    }

    i = 0U;
    j = 0U;
    while (i < len) {
        unsigned int octet_a = data[i++];
        unsigned int octet_b = (i < len) ? data[i++] : 0U;
        unsigned int octet_c = (i < len) ? data[i++] : 0U;
        unsigned int triple  = (octet_a << 16) | (octet_b << 8) | octet_c;

        out[j++] = table[(triple >> 18) & 0x3FU];
        out[j++] = table[(triple >> 12) & 0x3FU];
        out[j++] = table[(triple >> 6) & 0x3FU];
        out[j++] = table[triple & 0x3FU];
    }

    if (0U != (len % 3U)) {
        out[out_len - 1U] = '=';
        if (1U == (len % 3U)) {
            out[out_len - 2U] = '=';
        }
    }

    out[out_len] = '\0';
    return out;
}

/**
 * @brief 차단 페이지 로고 파일 경로를 현재 작업 디렉터리 기준으로 찾는다.
 *
 * 실행 위치가 repo root 또는 build 디렉터리일 수 있으므로 흔히 쓰는 경로를
 * 차례로 검사한다.
 *
 * @return const char* 접근 가능한 로고 경로, 찾지 못하면 NULL
 */
static const char *resolve_block_logo_path(void) {
    static const char *candidates[] = {
        "image/image.png",
        "../image/image.png",
        "../../image/image.png",
    };
    size_t i;
    int    ret;

    for (i = 0U; i < (sizeof(candidates) / sizeof(candidates[0])); i++) {
        ret = access(candidates[i], R_OK);
        if (0 == ret) {
            return candidates[i];
        }
    }

    return NULL;
}

/**
 * @brief 차단 페이지용 로고 <img> 마크업을 1회 생성해 캐시한다.
 *
 * 이미지 파일이 없으면 빈 문자열을 캐시해 이후 렌더링 비용과 오류 로그를
 * 줄인다.
 */
static void init_logo_image_html_once(void) {
    static const char img_fmt[] =
        "<div class=\"logo-wrap\">"
        "<img class=\"brand-logo\" src=\"data:image/png;base64,%s\" "
        "alt=\"Mini-IPS logo\">"
        "</div>";
    const char *logo_path;
    char       *logo_raw;
    char       *logo_b64;
    int         n;
    size_t      logo_len;

    logo_path = resolve_block_logo_path();
    if (!logo_path) {
        g_logo_image_html = (char *)malloc(1U);
        if (NULL != g_logo_image_html) {
            g_logo_image_html[0] = '\0';
        }
        return;
    }

    logo_raw = read_binary_file(logo_path, &logo_len);
    if (!logo_raw) {
        g_logo_image_html = (char *)malloc(1U);
        if (NULL != g_logo_image_html) {
            g_logo_image_html[0] = '\0';
        }
        return;
    }

    logo_b64 = base64_encode((const unsigned char *)logo_raw, logo_len);
    free(logo_raw);
    if (!logo_b64) {
        g_logo_image_html = (char *)malloc(1U);
        if (NULL != g_logo_image_html) {
            g_logo_image_html[0] = '\0';
        }
        return;
    }

    n = snprintf(NULL, 0, img_fmt, logo_b64);
    if (0 > n) {
        free(logo_b64);
        g_logo_image_html = (char *)malloc(1U);
        if (NULL != g_logo_image_html) {
            g_logo_image_html[0] = '\0';
        }
        return;
    }

    g_logo_image_html = (char *)malloc((size_t)n + 1U);
    if (!g_logo_image_html) {
        free(logo_b64);
        return;
    }

    snprintf(g_logo_image_html, (size_t)n + 1U, img_fmt, logo_b64);
    free(logo_b64);
}

/**
 * @brief 차단 페이지용 로고 <img> 마크업을 반환한다.
 *
 * @return const char* data URI를 포함한 <img> 마크업, 실패 시 빈 문자열
 */
static const char *get_logo_image_html(void) {
    (void)pthread_once(&g_logo_image_once, init_logo_image_html_once);

    if (!g_logo_image_html) {
        return "";
    }
    return g_logo_image_html;
}

/* --------------------------- public rendering entrypoints
 * --------------------------- */

/**
 * @brief 차단 페이지 템플릿에 이벤트 값을 치환해 최종 HTML을 만든다.
 *
 * 템플릿 파일을 읽어 `{{EVENT_ID}}`, `{{TIMESTAMP}}`, `{{CLIENT_IP}}`
 * 토큰을 찾아 HTML escaping 된 값으로 치환한다.
 *
 * @param template_path HTML 템플릿 파일 경로
 * @param event_id 차단 이벤트 식별자
 * @param timestamp 차단 시각 문자열
 * @param client_ip 클라이언트 IP 문자열
 * @return char* 렌더링된 HTML 문자열, 실패 시 NULL
 */
char *app_render_block_page(const char *template_path, const char *event_id,
                            const char *timestamp, const char *client_ip) {
    const char *p;
    char       *template_text;
    html_buf_t  out = {0};
    int         ret;

    /* 템플릿 경로가 없으면 렌더링 자체를 진행할 수 없다. */
    if (!template_path) {
        return NULL;
    }

    /* 템플릿 파일 전체를 메모리로 읽어 토큰 치환 대상으로 사용한다. */
    template_text = read_text_file(template_path);
    if (!template_text) {
        return NULL;
    }

    /* 템플릿을 한 글자씩 훑으면서 알려진 토큰만 치환한다. */
    p = template_text;
    while (*p != '\0') {
        /* 이벤트 ID는 HTML escape 후 삽입해 XSS 가능성을 줄인다. */
        ret = strncmp(p, "{{EVENT_ID}}", 12);
        if (0 == ret) {
            ret = html_buf_append_html_escaped(&out, event_id ? event_id : "-");
            if (0 != ret) {
                free(template_text);
                free(out.buf);
                return NULL;
            }
            p += 12;
            continue;
        }

        /* 차단 시각도 템플릿 토큰과 매칭되면 escape 후 삽입한다. */
        ret = strncmp(p, "{{TIMESTAMP}}", 13);
        if (0 == ret) {
            ret =
                html_buf_append_html_escaped(&out, timestamp ? timestamp : "-");
            if (0 != ret) {
                free(template_text);
                free(out.buf);
                return NULL;
            }
            p += 13;
            continue;
        }

        /* 클라이언트 IP 역시 그대로 출력하지 않고 escape 후 삽입한다. */
        ret = strncmp(p, "{{CLIENT_IP}}", 13);
        if (0 == ret) {
            ret =
                html_buf_append_html_escaped(&out, client_ip ? client_ip : "-");
            if (0 != ret) {
                free(template_text);
                free(out.buf);
                return NULL;
            }
            p += 13;
            continue;
        }

        /*
         * 로고 이미지는 data URI가 들어간 <img> 마크업 전체를 삽입한다.
         * 이미지 파일을 찾지 못한 경우엔 빈 문자열로 대체해 깨진 아이콘을
         * 노출하지 않는다.
         */
        ret = strncmp(p, "{{LOGO_IMAGE}}", 14);
        if (0 == ret) {
            ret = html_buf_append_str(&out, get_logo_image_html());
            if (0 != ret) {
                free(template_text);
                free(out.buf);
                return NULL;
            }
            p += 14;
            continue;
        }

        /* 치환 대상이 아닌 일반 텍스트는 그대로 출력 버퍼에 복사한다. */
        ret = html_buf_append_char(&out, *p);
        if (0 != ret) {
            free(template_text);
            free(out.buf);
            return NULL;
        }
        p++;
    }

    free(template_text);

    /* 빈 템플릿이어도 호출자는 NUL 종료 문자열을 기대하므로 빈 문자열을 만든다.
     */
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

/**
 * @brief 렌더링된 HTML을 403 HTTP 응답 문자열로 감싼다.
 *
 * Content-Length를 계산한 뒤 차단 페이지 HTML을 포함하는 완전한
 * HTTP/1.1 403 응답을 생성한다.
 *
 * @param html_body 응답 body로 사용할 HTML 문자열
 * @param out_len 생성된 응답 길이를 받을 포인터
 * @return char* 완성된 HTTP 응답 문자열, 실패 시 NULL
 */
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

    /* body가 없으면 Content-Length 계산과 응답 조립을 할 수 없다. */
    if (!html_body) {
        return NULL;
    }

    /* 응답 본문의 길이를 기준으로 최종 HTTP 응답 길이를 먼저 계산한다. */
    body_len = strlen(html_body);
    n        = snprintf(NULL, 0, response_fmt, body_len, html_body);
    if (0 > n) {
        return NULL;
    }

    total_len = (size_t)n;
    resp      = (char *)malloc(total_len + 1U);
    if (!resp) {
        return NULL;
    }

    /* 계산한 길이만큼 실제 응답 문자열을 조립한다. */
    snprintf(resp, total_len + 1U, response_fmt, body_len, html_body);
    if (out_len) {
        *out_len = total_len;
    }
    return resp;
}

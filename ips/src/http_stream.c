/**
 * @file http_stream.c
 * @brief HTTP 스트림 버퍼링, 메시지 파싱, 큐잉 구현
 */
#include "http_stream.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct msg_node {
    http_message_t   msg;
    struct msg_node *next;
    uint8_t          data[];
} msg_node_t;

struct http_stream {
    uint8_t *buf;
    size_t   len;
    size_t   cap;
    size_t   start;

    size_t max_buffer_bytes;
    size_t max_body_bytes;

    msg_node_t *q_head;
    msg_node_t *q_tail;

    char last_err[128];
};

/**
 * @brief 마지막 파서 오류 메시지를 스트림에 기록한다.
 *
 * @param s HTTP 스트림 컨텍스트
 * @param msg 기록할 오류 문자열
 */
static void http_stream_error_log(http_stream_t *s, const char *msg) {
    if (!s) {
        return;
    }
    if (!msg) {
        msg = "unknown error";
    }
    snprintf(s->last_err, sizeof(s->last_err), "%s", msg);
}

static void http_stream_buffer_compact(http_stream_t *s) {
    if (0 == s->len) {
        s->start = 0;
        return;
    }

    if (0 == s->start) {
        return;
    }

    memmove(s->buf, s->buf + s->start, s->len);
    s->start = 0;
}

static int http_stream_buffer_reserve_append(http_stream_t *s,
                                             size_t         append_len) {
    size_t   need;
    size_t   ncap;
    uint8_t *nb;

    if (append_len > s->max_buffer_bytes - s->len) {
        return -1;
    }

    need = s->len + append_len;

    if (s->start + need <= s->cap) {
        return 0;
    }

    if (need <= s->cap) {
        http_stream_buffer_compact(s);
        return 0;
    }

    http_stream_buffer_compact(s);

    if (need <= s->cap) {
        return 0;
    }

    ncap = s->cap;
    if (0 == ncap) {
        ncap = 1024;
    }

    while (ncap < need) {
        if (ncap > (SIZE_MAX / 2)) {
            return -1;
        }
        ncap *= 2;
    }

    if (ncap > s->max_buffer_bytes) {
        return -1;
    }

    nb = (uint8_t *)realloc(s->buf, ncap);
    if (NULL == nb) {
        return -1;
    }

    s->buf = nb;
    s->cap = ncap;
    return 0;
}

/**
 * @brief 스트림에 기록된 마지막 오류 문자열을 반환한다.
 *
 * @param s HTTP 스트림 컨텍스트
 * @return const char* 마지막 오류 문자열
 */
const char *http_stream_last_error(const http_stream_t *s) {
    if (!s) {
        return "null stream";
    }
    if ('\0' == s->last_err[0]) {
        return "ok";
    }
    return s->last_err;
}

int http_stream_peek_buffer(const http_stream_t *s, const uint8_t **out_data,
                            size_t *out_len) {
    if (NULL == s || NULL == out_data || NULL == out_len) {
        return -1;
    }

    *out_data = s->buf + s->start;
    *out_len  = s->len;
    return 0;
}

/**
 * @brief 바이트 배열에서 첫 번째 CRLF 위치를 찾는다.
 *
 * @param p 검색 대상 버퍼
 * @param len 검색 길이
 * @param idx 찾은 위치를 받을 포인터
 * @return int 찾으면 1, 못 찾으면 0
 */
static int http_stream_buffer_find_crlf(const uint8_t *p, size_t len,
                                        size_t *idx) {
    const uint8_t *cur;
    const uint8_t *hit;
    size_t         remain;

    cur    = p;
    remain = len;

    while (1) {
        if (2U > remain) {
            return 0;
        }

        hit = (const uint8_t *)memchr(cur, '\r', remain - 1U);
        if (NULL == hit) {
            return 0;
        }

        if ('\n' == hit[1]) {
            *idx = (size_t)(hit - p);
            return 1;
        }

        remain -= (size_t)((hit - cur) + 1U);
        cur = hit + 1;
    }
}
/**
 * @brief 바이트 배열에서 첫 번째 CRLFCRLF 위치를 찾는다.
 *
 * HTTP 헤더 종료 지점 검출에 사용한다.
 *
 * @param p 검색 대상 버퍼
 * @param len 검색 길이
 * @param idx 찾은 위치를 받을 포인터
 * @return int 찾으면 1, 못 찾으면 0
 */
static int http_stream_buffer_find_header_end(const uint8_t *p, size_t len,
                                              size_t *idx) {
    const uint8_t *cur;
    const uint8_t *hit;
    size_t         remain;

    cur    = p;
    remain = len;

    while (1) {
        if (4U > remain) {
            return 0;
        }

        hit = (const uint8_t *)memchr(cur, '\r', remain - 3U);
        if (NULL == hit) {
            return 0;
        }

        if ('\n' == hit[1] && '\r' == hit[2] && '\n' == hit[3]) {
            *idx = (size_t)(hit - p);
            return 1;
        }

        remain -= (size_t)((hit - cur) + 1U);
        cur = hit + 1;
    }
}

/**
 * @brief 길이가 명시된 토큰을 C 문자열 버퍼로 복사한다.
 *
 * @param dst 목적지 문자열 버퍼
 * @param dst_cap 목적지 버퍼 크기
 * @param src 원본 토큰 시작 주소
 * @param n 원본 길이
 * @return int 0이면 성공, -1이면 overflow
 */
static int http_stream_token_copy(char *dst, size_t dst_cap, const uint8_t *src,
                                  size_t n) {
    if (n + 1 > dst_cap) {
        return -1;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
    return 0;
}

/**
 * @brief HTTP header value 앞의 공백/탭을 건너뛴다.
 *
 * @param p 현재 위치
 * @param end 버퍼 끝
 * @return const uint8_t* leading whitespace를 건너뛴 새 위치
 */
static const uint8_t *http_stream_value_skip_lws(const uint8_t *p,
                                                 const uint8_t *end) {
    while (p < end && (*p == ' ' || *p == '\t')) {
        p++;
    }
    return p;
}

/**
 * @brief HTTP header value 뒤의 공백/탭을 제거한다.
 *
 * @param p 값 시작 위치
 * @param end 값 끝 위치
 */
static void http_stream_value_trim_rws(const uint8_t **p, const uint8_t **end) {
    while (*end > *p && ((*(*end - 1) == ' ') || (*(*end - 1) == '\t'))) {
        (*end)--;
    }
}

/**
 * @brief 길이가 명시된 토큰과 C 문자열을 대소문자 무시 비교한다.
 *
 * @param a 길이 명시 토큰
 * @param an 토큰 길이
 * @param b 비교할 C 문자열
 * @return int 같으면 1, 다르면 0
 */
static int http_stream_token_equals_ci(const uint8_t *a, size_t an,
                                       const char *b) {
    size_t i;
    size_t bn = strlen(b);
    int    ca;
    int    cb;

    if (an != bn) {
        return 0;
    }
    for (i = 0; i < an; i++) {
        ca = tolower((unsigned char)a[i]);
        cb = tolower((unsigned char)b[i]);
        if (ca != cb) {
            return 0;
        }
    }
    return 1;
}

/**
 * @brief 길이가 명시된 토큰에 부분 문자열이 포함되는지 대소문자 무시 검사한다.
 *
 * @param a 검색 대상 토큰
 * @param an 토큰 길이
 * @param needle 찾을 문자열
 * @return int 포함하면 1, 아니면 0
 */
static int http_stream_token_contains_ci(const uint8_t *a, size_t an,
                                         const char *needle) {
    size_t i;
    size_t nn = strlen(needle);
    int    ca;
    int    cb;
    if (0 == nn || nn > an) {
        return 0;
    }
    for (i = 0; i + nn <= an; i++) {
        size_t j;
        int    ok = 1;
        for (j = 0; j < nn; j++) {
            ca = tolower((unsigned char)a[i + j]);
            cb = tolower((unsigned char)needle[j]);
            if (ca != cb) {
                ok = 0;
                break;
            }
        }
        if (ok) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief HTTP start-line 한 줄을 request/response 형식으로 해석한다.
 *
 * @param m 파싱 결과를 채울 메시지 구조체
 * @param line start-line 시작 주소
 * @param n 줄 길이
 * @return http_stream_rc_t 파싱 결과 코드
 */
static http_stream_rc_t http_stream_start_line_parse(http_message_t *m,
                                                     const uint8_t  *line,
                                                     size_t          n) {
    const uint8_t *sp1;
    const uint8_t *sp2;
    const uint8_t *end;
    const uint8_t *p;
    int            ret;
    int            is_digit;

    end = line + n;

    /* "HTTP/"로 시작하면 response status-line으로 해석한다. */
    ret = 0;
    if (5U <= n) {
        ret = memcmp(line, "HTTP/", 5);
    }
    if (5U <= n && 0 == ret) {
        m->is_request = 0;

        sp1 = (const uint8_t *)memchr(line, ' ', n);
        if (NULL == sp1) {
            return HTTP_STREAM_EPROTO;
        }

        ret = http_stream_token_copy(m->version, sizeof(m->version), line,
                                     (size_t)(sp1 - line));
        if (-1 == ret) {
            return HTTP_STREAM_EOVERFLOW;
        }

        p   = sp1 + 1;
        sp2 = (const uint8_t *)memchr(p, ' ', (size_t)(end - p));
        if (NULL == sp2) {
            return HTTP_STREAM_EPROTO;
        }

        is_digit = isdigit((unsigned char)p[0]);
        if (3U != (size_t)(sp2 - p) || 0 == is_digit) {
            return HTTP_STREAM_EPROTO;
        }
        is_digit = isdigit((unsigned char)p[1]);
        if (0 == is_digit) {
            return HTTP_STREAM_EPROTO;
        }
        is_digit = isdigit((unsigned char)p[2]);
        if (0 == is_digit) {
            return HTTP_STREAM_EPROTO;
        }

        m->status_code =
            (int)((p[0] - '0') * 100 + (p[1] - '0') * 10 + (p[2] - '0'));

        p   = sp2 + 1;
        ret = http_stream_token_copy(m->reason, sizeof(m->reason), p,
                                     (size_t)(end - p));
        if (-1 == ret) {
            return HTTP_STREAM_EOVERFLOW;
        }
    } else {
        /* 그 외 형식은 request line으로 보고 method/uri/version을 추출한다. */
        m->is_request = 1;

        sp1 = (const uint8_t *)memchr(line, ' ', n);
        if (NULL == sp1) {
            return HTTP_STREAM_EPROTO;
        }

        sp2 = (const uint8_t *)memchr(sp1 + 1, ' ', (size_t)(end - (sp1 + 1)));
        if (NULL == sp2) {
            return HTTP_STREAM_EPROTO;
        }

        ret = http_stream_token_copy(m->method, sizeof(m->method), line,
                                     (size_t)(sp1 - line));
        if (-1 == ret) {
            return HTTP_STREAM_EOVERFLOW;
        }

        ret = http_stream_token_copy(m->uri, sizeof(m->uri), sp1 + 1,
                                     (size_t)(sp2 - (sp1 + 1)));
        if (-1 == ret) {
            return HTTP_STREAM_EOVERFLOW;
        }

        ret = http_stream_token_copy(m->version, sizeof(m->version), sp2 + 1,
                                     (size_t)(end - (sp2 + 1)));
        if (-1 == ret) {
            return HTTP_STREAM_EOVERFLOW;
        }
    }

    return HTTP_STREAM_OK;
}

/**
 * @brief 헤더 블록 전체를 파싱해 메시지 메타데이터를 추출한다.
 *
 * start-line, content-length, transfer-encoding, content-type를 해석한다.
 *
 * @param m 결과 메시지 구조체
 * @param headers CRLFCRLF를 포함한 헤더 블록
 * @param headers_len 헤더 블록 길이
 * @param max_body_bytes 허용 최대 body 길이
 * @return http_stream_rc_t 파싱 결과 코드
 */
static http_stream_rc_t http_stream_headers_parse_meta(http_message_t *m,
                                                       const uint8_t  *headers,
                                                       size_t headers_len,
                                                       size_t max_body_bytes) {
    size_t pos;
    int    first_line_done;
    int    ret;

    /* pos는 아직 해석하지 않은 현재 줄의 시작 위치를 가리킨다. */
    pos             = 0;
    first_line_done = 0;
    ret             = 0;

    /*
     * body 관련 메타데이터는 헤더 파싱 전에 기본값으로 초기화한다.
     * content-length는 "없음"을 나타내기 위해 -1로 시작한다.
     */
    m->content_length  = -1;
    m->chunked         = 0;
    m->content_type[0] = '\0';

    /*
     * 헤더 블록을 CRLF 단위로 순차 파싱한다.
     * 첫 줄은 start-line, 그 이후는 header field로 해석한다.
     */
    while (pos < headers_len) {
        size_t         line_end;
        const uint8_t *line;
        size_t         line_len;
        const uint8_t *colon;
        const uint8_t *name_end;
        const uint8_t *val;
        const uint8_t *val_end;

        /*
         * 현재 위치부터 다음 CRLF를 찾는다.
         * CRLF를 못 찾으면 헤더 형식이 깨진 것으로 본다.
         */
        ret = http_stream_buffer_find_crlf(headers + pos, headers_len - pos,
                                           &line_end);
        if (0 == ret) {
            return HTTP_STREAM_EPROTO;
        }

        /*
         * 현재 줄의 시작 주소와 길이를 계산한 뒤,
         * 다음 줄로 넘어가기 위해 pos를 line_end + CRLF만큼 전진한다.
         */
        line     = headers + pos;
        line_len = line_end;
        pos += line_end + 2;

        /*
         * 빈 줄은 header block 종료를 뜻한다.
         * start-line 뒤의 CRLFCRLF에서 마지막 CRLF를 만난 경우 여기로 온다.
         */
        if (0 == line_len) {
            break;
        }

        /*
         * 첫 번째 줄은 request-line 또는 status-line이다.
         * start-line 파싱이 끝나면 이후 줄부터는 일반 header field로 처리한다.
         */
        if (0 == first_line_done) {
            http_stream_rc_t rc;

            rc = http_stream_start_line_parse(m, line, line_len);
            if (HTTP_STREAM_OK != rc) {
                return rc;
            }

            first_line_done = 1;
            continue;
        }

        /*
         * 일반 header field는 "name: value" 형식이어야 한다.
         * ':'가 없으면 비정상 헤더로 본다.
         */
        colon = (const uint8_t *)memchr(line, ':', line_len);
        if (NULL == colon) {
            return HTTP_STREAM_EPROTO;
        }

        /*
         * name은 line 시작부터 ':' 직전까지이고,
         * value는 ':' 뒤의 leading whitespace를 건너뛴 뒤 끝의 trailing
         * whitespace를 제거한 구간으로 본다.
         */
        name_end = colon;
        val      = http_stream_value_skip_lws(colon + 1, line + line_len);
        val_end  = line + line_len;
        http_stream_value_trim_rws(&val, &val_end);

        /*
         * Content-Length는 body 길이를 결정하는 핵심 메타데이터다.
         * 값은 비어 있으면 안 되고, 모든 문자가 숫자여야 하며,
         * 누적 결과가 max_body_bytes를 넘으면 overflow로 처리한다.
         */
        ret = http_stream_token_equals_ci(line, (size_t)(name_end - line),
                                          "content-length");
        if (1 == ret) {
            size_t    vn;
            size_t    i;
            long long v;

            vn = (size_t)(val_end - val);
            if (0 == vn) {
                return HTTP_STREAM_EPROTO;
            }

            v = 0;
            for (i = 0; i < vn; i++) {
                ret = isdigit((unsigned char)val[i]);
                if (0 == ret) {
                    return HTTP_STREAM_EPROTO;
                }

                v = (v * 10) + (long long)(val[i] - '0');
                if ((size_t)v > max_body_bytes) {
                    return HTTP_STREAM_EOVERFLOW;
                }
            }

            m->content_length = v;
        } else {
            /*
             * Transfer-Encoding은 현재 구현상 "chunked" 포함 여부만 본다.
             * 여러 토큰이 들어와도 value 안에 chunked가 포함되면 활성화한다.
             */
            ret = http_stream_token_equals_ci(line, (size_t)(name_end - line),
                                              "transfer-encoding");
            if (1 == ret) {
                ret = http_stream_token_contains_ci(
                    val, (size_t)(val_end - val), "chunked");
                if (0 != ret) {
                    m->chunked = 1;
                }
            } else {
                /*
                 * Content-Type은 원문 값을 그대로 content_type 버퍼에 보관한다.
                 * 버퍼 크기를 넘으면 overflow로 처리한다.
                 */
                ret = http_stream_token_equals_ci(
                    line, (size_t)(name_end - line), "content-type");
                if (1 == ret) {
                    size_t vn;

                    vn  = (size_t)(val_end - val);
                    ret = http_stream_token_copy(
                        m->content_type, sizeof(m->content_type), val, vn);
                    if (0 != ret) {
                        return HTTP_STREAM_EOVERFLOW;
                    }
                }
            }
        }
    }

    /*
     * start-line을 하나도 못 읽고 끝났다면 정상적인 HTTP 메시지가 아니다.
     */
    if (0 == first_line_done) {
        return HTTP_STREAM_EPROTO;
    }

    return HTTP_STREAM_OK;
}

/**
 * @brief body 버퍼 뒤에 새 바이트 구간을 이어 붙인다.
 *
 * @param buf body 버퍼 포인터
 * @param len 현재 body 길이
 * @param cap 현재 body 버퍼 용량
 * @param data 추가할 데이터
 * @param n 추가 길이
 * @param max_body_bytes 허용 최대 body 길이
 * @return http_stream_rc_t append 결과 코드
 */
static http_stream_rc_t http_stream_body_append(uint8_t **buf, size_t *len,
                                                size_t        *cap,
                                                const uint8_t *data, size_t n,
                                                size_t max_body_bytes) {
    size_t   need;
    size_t   new_cap;
    uint8_t *nb;

    if (n > max_body_bytes - *len) {
        return HTTP_STREAM_EOVERFLOW;
    }

    need = *len + n;
    if (need > *cap) {
        new_cap = *cap;
        if (0 == new_cap) {
            new_cap = 1024;
        }

        while (new_cap < need) {
            if (new_cap > (SIZE_MAX / 2)) {
                return HTTP_STREAM_ENOMEM;
            }
            new_cap *= 2;
        }

        if (new_cap > max_body_bytes) {
            new_cap = max_body_bytes;
        }

        if (new_cap < need) {
            return HTTP_STREAM_EOVERFLOW;
        }
        /*
         * chunked body는 조각 수를 미리 알 수 없으므로, cap을 점진적으로 늘려
         * heap 확장 횟수와 기존 누적 body 재복사 횟수를 줄인다.
         */
        nb = (uint8_t *)realloc(*buf, new_cap);
        if (NULL == nb) {
            return HTTP_STREAM_ENOMEM;
        }

        *buf = nb;
        *cap = new_cap;
    }

    memcpy(*buf + *len, data, n);
    *len += n;
    return HTTP_STREAM_OK;
}

/**
 * @brief chunked transfer-encoding body를 완전한 body로 풀어낸다.
 *
 * 각 chunk size line, chunk data, trailing CRLF를 해석해 body 버퍼로
 * 이어 붙인다.
 *
 * @param p chunked body 시작 주소
 * @param n 남은 입력 길이
 * @param max_body_bytes 허용 최대 body 길이
 * @param consumed 소비한 총 길이
 * @param body 완성된 body 버퍼
 * @param body_len 완성된 body 길이
 * @return http_stream_rc_t 파싱 결과 코드
 */
static http_stream_rc_t http_stream_body_parse_chunked(
    const uint8_t *p, size_t n, size_t max_body_bytes, size_t *consumed,
    uint8_t **body, size_t *body_len) {
    size_t           pos;
    int              ret;
    http_stream_rc_t rc;
    size_t           body_cap;

    pos       = 0;
    *body     = NULL;
    *body_len = 0;
    body_cap  = 0;

    /* 0-size chunk를 만날 때까지 chunk line과 data를 순차적으로 해석한다. */
    while (1) {
        size_t        le;
        char          tmp[64];
        char         *semi;
        char         *endptr;
        unsigned long sz;
        size_t        tr_end;

        ret = http_stream_buffer_find_crlf(p + pos, n - pos, &le);
        if (0 == ret) {
            return HTTP_STREAM_NEED_MORE;
        }

        ret = (int)(le >= sizeof(tmp));
        if (0 == le || 0 != ret) {
            return HTTP_STREAM_EPROTO;
        }

        memcpy(tmp, p + pos, le);
        tmp[le] = '\0';

        semi = strchr(tmp, ';');
        if (NULL != semi) {
            *semi = '\0';
        }

        endptr = NULL;
        sz     = strtoul(tmp, &endptr, 16);
        if (endptr == tmp || '\0' != *endptr) {
            return HTTP_STREAM_EPROTO;
        }

        pos += le + 2;

        if (0UL == sz) {
            /* 마지막 chunk 뒤에는 빈 줄 또는 trailer header block이 올 수 있다.
             */
            if (2 <= (n - pos) && '\r' == p[pos] && '\n' == p[pos + 1]) {
                pos += 2;
                *consumed = pos;
                return HTTP_STREAM_OK;
            }

            ret = http_stream_buffer_find_header_end(p + pos, n - pos, &tr_end);
            if (0 == ret) {
                return HTTP_STREAM_NEED_MORE;
            }

            pos += tr_end + 4;
            *consumed = pos;
            return HTTP_STREAM_OK;
        }

        if (n - pos < (size_t)sz + 2U) {
            return HTTP_STREAM_NEED_MORE;
        }

        if ('\r' != p[pos + sz] || '\n' != p[pos + sz + 1]) {
            return HTTP_STREAM_EPROTO;
        }

        rc = http_stream_body_append(body, body_len, &body_cap, p + pos,
                                     (size_t)sz, max_body_bytes);
        if (HTTP_STREAM_OK != rc) {
            return rc;
        }

        pos += (size_t)sz + 2U;
    }
}

/**
 * @brief 완성된 HTTP 메시지를 스트림 내부 큐에 적재한다.
 *
 * @param s HTTP 스트림 컨텍스트
 * @param n 큐에 넣을 메시지 노드
 */
static void http_stream_queue_push(http_stream_t *s, msg_node_t *n) {
    if (NULL == s->q_head) {
        s->q_head = n;
        s->q_tail = n;
    } else {
        s->q_tail->next = n;
        s->q_tail       = n;
    }
}

/**
 * @brief 입력 버퍼 앞쪽 n바이트를 소비한다.
 *
 * @param s HTTP 스트림 컨텍스트
 * @param n 제거할 길이
 */
static void http_stream_buffer_consume_front(http_stream_t *s, size_t n) {
    if (n >= s->len) {
        s->start = 0;
        s->len   = 0;
        return;
    }

    s->start += n;
    s->len -= n;
}

/**
 * @brief 현재 버퍼 앞부분에서 HTTP 메시지 1개를 파싱한다.
 *
 * header block을 찾고, 메타데이터를 해석한 뒤 body를 확보해 메시지 큐에 넣는다.
 *
 * @param s HTTP 스트림 컨텍스트
 * @param produced 메시지를 하나 만들었는지 여부
 * @return http_stream_rc_t 파싱 결과 코드
 */
static http_stream_rc_t http_stream_message_parse_one(http_stream_t *s,
                                                      int           *produced) {
    size_t           hdr_end_pos;
    size_t           msg_hdr_len;
    size_t           start_line_end;
    size_t           headers_only_off;
    size_t           headers_only_len;
    http_message_t   m;
    size_t           body_off;
    size_t           consumed;
    const uint8_t   *base;
    http_stream_rc_t rc;
    int              ret;
    size_t           total_size;
    msg_node_t      *node;
    uint8_t         *cursor;

    *produced = 0;
    base      = s->buf + s->start;
    consumed  = 0;
    node      = NULL;

    /* 헤더 끝(CRLFCRLF)을 아직 못 찾으면 메시지가 덜 들어온 상태다. */
    ret = http_stream_buffer_find_header_end(base, s->len, &hdr_end_pos);
    if (0 == ret) {
        return HTTP_STREAM_NEED_MORE;
    }
    /* http_message_t m 구조체를 0으로 초기화한다. */
    msg_hdr_len = hdr_end_pos + 4;
    memset(&m, 0, sizeof(m));
    /* Content-Length 미존재 상태를 구분하기 위해 -1로 둔다. */
    m.content_length = -1;

    /* start-line과 주요 헤더를 먼저 파싱해 body 처리 방식을 결정한다. */
    rc = http_stream_headers_parse_meta(&m, base, msg_hdr_len,
                                        s->max_body_bytes);
    if (HTTP_STREAM_OK != rc) {
        http_message_free(&m);
        return rc;
    }
    /* 버퍼에서 crlf 찾기 */
    ret = http_stream_buffer_find_crlf(base, msg_hdr_len, &start_line_end);
    if (0 == ret) {
        http_message_free(&m);
        return HTTP_STREAM_EPROTO;
    }

    headers_only_off = start_line_end + 2;
    if (headers_only_off > hdr_end_pos) {
        headers_only_len = 0;
    } else {
        headers_only_len = hdr_end_pos - headers_only_off;
    }

    /* queue에 저장할 수 있도록 헤더 원문을 start-line 제외 구간만 따로
     * 복사한다. */
    if (0 != m.chunked && 0 <= m.content_length) {
        http_message_free(&m);
        return HTTP_STREAM_EPROTO;
    }

    body_off = msg_hdr_len;
    if (0 != m.chunked) {
        rc = http_stream_body_parse_chunked(base + body_off, s->len - body_off,
                                            s->max_body_bytes, &consumed,
                                            &m.body, &m.body_len);
        if (HTTP_STREAM_OK != rc) {
            http_message_free(&m);
            return rc;
        }

        consumed += body_off;
    } else if (0 < m.content_length) {
        if ((size_t)m.content_length > s->len - body_off) {
            http_message_free(&m);
            return HTTP_STREAM_NEED_MORE;
        }
        m.body_len = (size_t)m.content_length;
        consumed   = body_off + m.body_len;
    } else {
        m.body_len = 0;
        consumed   = body_off;
    }

    total_size = sizeof(*node) + headers_only_len + 1 + m.body_len;
    node       = (msg_node_t *)malloc(total_size);
    if (NULL == node) {
        http_message_free(&m);
        return HTTP_STREAM_ENOMEM;
    }

    memset(node, 0, sizeof(*node));
    node->msg               = m;
    node->msg.owned_storage = (uint8_t *)node;
    node->next              = NULL;

    cursor = node->data;

    node->msg.headers_raw = cursor;
    if (0U != headers_only_len) {
        memcpy(node->msg.headers_raw, base + headers_only_off,
               headers_only_len);
    }

    node->msg.headers_raw[headers_only_len] = '\0';
    node->msg.headers_raw_len               = headers_only_len;

    cursor += headers_only_len + 1;

    if (0U != m.body_len) {
        if (0 != m.chunked) {
            memcpy(cursor, m.body, m.body_len);
            free(m.body);
            m.body = NULL;
        } else {
            memcpy(cursor, base + body_off, m.body_len);
        }

        node->msg.body = cursor;
    } else {
        node->msg.body = NULL;
    }

    node->msg.body_len = m.body_len;
    http_stream_queue_push(s, node);

    http_stream_buffer_consume_front(s, consumed);
    *produced = 1;
    return HTTP_STREAM_OK;
}

/**
 * @brief HTTP 스트림 컨텍스트를 생성한다.
 *
 * @param cfg 버퍼/바디 제한 설정
 * @return http_stream_t* 생성된 스트림 컨텍스트
 */
http_stream_t *http_stream_create(const http_stream_cfg_t *cfg) {
    http_stream_t *s;
    size_t         max_buf  = 12 * 1024 * 1024;
    size_t         max_body = 12 * 1024 * 1024;

    /* 설정이 없으면 보수적인 기본 최대치로 생성한다. */
    if (NULL != cfg) {
        if (0 < cfg->max_buffer_bytes) {
            max_buf = cfg->max_buffer_bytes;
        }
        if (0 < cfg->max_body_bytes) {
            max_body = cfg->max_body_bytes;
        }
    }

    s = (http_stream_t *)malloc(sizeof(*s));
    if (NULL == s) {
        return NULL;
    }

    memset(s, 0, sizeof(*s));
    s->max_buffer_bytes = max_buf;
    s->max_body_bytes   = max_body;
    s->last_err[0]      = '\0';

    return s;
}

/**
 * @brief HTTP 메시지 내부 동적 메모리를 해제한다.
 *
 * @param m 해제할 메시지
 */
void http_message_free(http_message_t *m) {
    if (!m) {
        return;
    }

    if (NULL != m->owned_storage) {
        free(m->owned_storage);
    } else {
        free(m->headers_raw);
        free(m->body);
    }

    memset(m, 0, sizeof(*m));
}

/**
 * @brief 스트림 버퍼와 메시지 큐를 초기 상태로 되돌린다.
 *
 * @param s HTTP 스트림 컨텍스트
 */
void http_stream_reset(http_stream_t *s) {
    msg_node_t *p;
    if (NULL == s) {
        return;
    }

    s->start = 0;
    s->len   = 0;

    while (s->q_head) {
        p         = s->q_head;
        s->q_head = p->next;

        if ((uint8_t *)p == p->msg.owned_storage) {
            free(p);
        } else {
            http_message_free(&p->msg);
            free(p);
        }
    }

    s->q_tail      = NULL;
    s->last_err[0] = '\0';
}

/**
 * @brief HTTP 스트림 컨텍스트를 완전히 해제한다.
 *
 * @param s HTTP 스트림 컨텍스트
 */
void http_stream_destroy(http_stream_t *s) {
    if (!s) {
        return;
    }
    http_stream_reset(s);
    free(s->buf);
    free(s);
}

/**
 * @brief 새 TCP payload를 스트림 버퍼에 추가하고 가능한 메시지를 파싱한다.
 *
 * @param s HTTP 스트림 컨텍스트
 * @param data 추가할 payload
 * @param len payload 길이
 * @return http_stream_rc_t 처리 결과 코드
 */
http_stream_rc_t http_stream_feed(http_stream_t *s, const uint8_t *data,
                                  size_t len) {
    int              produced;
    int              ret;
    http_stream_rc_t rc;

    if (NULL == s || (NULL == data && 0 < len)) {
        return HTTP_STREAM_EINVAL;
    }

    if (0 == len) {
        return HTTP_STREAM_OK;
    }

    /*
     * append 대상은 buf[0]이 아니라 unread window의 끝인
     * buf[start + len]이다. 따라서 단순 grow(len + append)로는 부족하고,
     * 뒤 공간이 모자라면 compact 후 다시 확인하는 reserve_append 경로를
     * 통해 실제 쓰기 위치까지 안전하게 확보해야 한다.
     */
    ret = http_stream_buffer_reserve_append(s, len);
    if (0 != ret) {
        http_stream_error_log(s, "memory allocation failed");
        return HTTP_STREAM_ENOMEM;
    }

    /* unread window 뒤에 새 payload를 이어 붙인다. */
    memcpy(s->buf + s->start + s->len, data, len);
    s->len += len;

    while (1) {
        rc = http_stream_message_parse_one(s, &produced);
        if (HTTP_STREAM_NEED_MORE == rc) {
            return HTTP_STREAM_OK;
        }
        if (HTTP_STREAM_OK != rc) {
            http_stream_error_log(s, "HTTP parse error");
            return rc;
        }
        if (0 == produced) {
            break;
        }
    }

    return HTTP_STREAM_OK;
}

/**
 * @brief 파싱 완료된 메시지 큐에서 메시지 하나를 꺼낸다.
 *
 * @param s HTTP 스트림 컨텍스트
 * @param out 꺼낸 메시지를 받을 구조체
 * @return http_stream_rc_t 메시지 존재 여부 및 처리 결과
 */
http_stream_rc_t http_stream_poll_message(http_stream_t  *s,
                                          http_message_t *out) {
    msg_node_t *n;
    if (!s || !out) {
        return HTTP_STREAM_EINVAL;
    }
    if (!s->q_head) {
        return HTTP_STREAM_NO_MESSAGE;
    }

    n         = s->q_head;
    s->q_head = n->next;
    if (!s->q_head) {
        s->q_tail = NULL;
    }

    *out = n->msg;
    return HTTP_STREAM_OK;
}

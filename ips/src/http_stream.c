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
} msg_node_t;

struct http_stream {
    uint8_t *buf;
    size_t   len;
    size_t   cap;

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
static void set_err(http_stream_t *s, const char *msg) {
    if (!s) {
        return;
    }
    if (!msg) {
        msg = "unknown error";
    }
    snprintf(s->last_err, sizeof(s->last_err), "%s", msg);
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
    if (s->last_err[0] == '\0') {
        return "ok";
    }
    return s->last_err;
}

/**
 * @brief 내부 수신 버퍼가 지정 크기 이상을 담을 수 있도록 확장한다.
 *
 * @param s HTTP 스트림 컨텍스트
 * @param need 필요한 최소 버퍼 크기
 * @return int 0이면 성공, -1이면 실패
 */
static int ensure_cap(http_stream_t *s, size_t need) {
    /* 현재 용량이 충분하면 재할당하지 않는다. */
    if (need <= s->cap) {
        return 0;
    }

    /* 작은 버퍼에서 시작해 2배씩 키워 realloc 횟수를 줄인다. */
    size_t ncap = s->cap ? s->cap : 1024;
    while (ncap < need) {
        ncap *= 2;
    }

    /* 설정한 최대 버퍼 크기를 넘으면 더 이상 입력을 받지 않는다. */
    if (ncap > s->max_buffer_bytes) {
        return -1;
    }
    uint8_t *nb = (uint8_t *)realloc(s->buf, ncap);
    if (!nb) {
        return -1;
    }
    s->buf = nb;
    s->cap = ncap;
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
static int memmem_crlf(const uint8_t *p, size_t len, size_t *idx) {
    size_t i;
    for (i = 0; i + 1 < len; i++) {
        if (p[i] == '\r' && p[i + 1] == '\n') {
            *idx = i;
            return 1;
        }
    }
    return 0;
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
static int memmem_crlfcrlf(const uint8_t *p, size_t len, size_t *idx) {
    size_t i;
    for (i = 0; i + 3 < len; i++) {
        if (p[i] == '\r' && p[i + 1] == '\n' && p[i + 2] == '\r' &&
            p[i + 3] == '\n') {
            *idx = i;
            return 1;
        }
    }
    return 0;
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
static int copy_token(char *dst, size_t dst_cap, const uint8_t *src, size_t n) {
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
static const uint8_t *skip_lws(const uint8_t *p, const uint8_t *end) {
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
static void trim_rws(const uint8_t **p, const uint8_t **end) {
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
static int ci_eq_token(const uint8_t *a, size_t an, const char *b) {
    size_t i;
    size_t bn = strlen(b);
    if (an != bn) {
        return 0;
    }
    for (i = 0; i < an; i++) {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) {
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
static int ci_contains(const uint8_t *a, size_t an, const char *needle) {
    size_t i;
    size_t nn = strlen(needle);
    if (nn == 0 || an < nn) {
        return 0;
    }
    for (i = 0; i + nn <= an; i++) {
        size_t j;
        int    ok = 1;
        for (j = 0; j < nn; j++) {
            if (tolower((unsigned char)a[i + j]) !=
                tolower((unsigned char)needle[j])) {
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
static http_stream_rc_t parse_start_line(http_message_t *m, const uint8_t *line,
                                         size_t n) {
    const uint8_t *sp1;
    const uint8_t *sp2;
    const uint8_t *end = line + n;
    const uint8_t *p;

    /* "HTTP/"로 시작하면 response status-line으로 해석한다. */
    if (n >= 5 && memcmp(line, "HTTP/", 5) == 0) {
        m->is_request = 0;

        sp1 = (const uint8_t *)memchr(line, ' ', n);
        if (!sp1) {
            return HTTP_STREAM_EPROTO;
        }
        if (copy_token(m->version, sizeof(m->version), line,
                       (size_t)(sp1 - line)) != 0) {
            return HTTP_STREAM_EOVERFLOW;
        }

        p   = sp1 + 1;
        sp2 = (const uint8_t *)memchr(p, ' ', (size_t)(end - p));
        if (!sp2) {
            return HTTP_STREAM_EPROTO;
        }

        {
            char   code_buf[8];
            size_t cn = (size_t)(sp2 - p);
            if (cn == 0 || cn >= sizeof(code_buf)) {
                return HTTP_STREAM_EPROTO;
            }
            memcpy(code_buf, p, cn);
            code_buf[cn]   = '\0';
            m->status_code = atoi(code_buf);
        }

        p = sp2 + 1;
        if (copy_token(m->reason, sizeof(m->reason), p, (size_t)(end - p)) !=
            0) {
            return HTTP_STREAM_EOVERFLOW;
        }
    } else {
        /* 그 외 형식은 request line으로 보고 method/uri/version을 추출한다. */
        m->is_request = 1;

        sp1 = (const uint8_t *)memchr(line, ' ', n);
        if (!sp1) {
            return HTTP_STREAM_EPROTO;
        }
        sp2 = (const uint8_t *)memchr(sp1 + 1, ' ', (size_t)(end - (sp1 + 1)));
        if (!sp2) {
            return HTTP_STREAM_EPROTO;
        }

        if (copy_token(m->method, sizeof(m->method), line,
                       (size_t)(sp1 - line)) != 0) {
            return HTTP_STREAM_EOVERFLOW;
        }
        if (copy_token(m->uri, sizeof(m->uri), sp1 + 1,
                       (size_t)(sp2 - (sp1 + 1))) != 0) {
            return HTTP_STREAM_EOVERFLOW;
        }
        if (copy_token(m->version, sizeof(m->version), sp2 + 1,
                       (size_t)(end - (sp2 + 1))) != 0) {
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
static http_stream_rc_t parse_headers_meta(http_message_t *m,
                                           const uint8_t  *headers,
                                           size_t          headers_len,
                                           size_t          max_body_bytes) {
    size_t pos             = 0;
    int    first_line_done = 0;

    /* 바디 관련 메타데이터는 헤더 파싱 전에 기본값으로 초기화한다. */
    m->content_length  = -1;
    m->chunked         = 0;
    m->content_type[0] = '\0';

    /* CRLF 단위로 헤더를 끊어 start-line과 각 header field를 순차 해석한다. */
    while (pos < headers_len) {
        size_t         line_end;
        const uint8_t *line;
        size_t         line_len;

        if (!memmem_crlf(headers + pos, headers_len - pos, &line_end)) {
            return HTTP_STREAM_EPROTO;
        }

        line     = headers + pos;
        line_len = line_end;
        pos += line_end + 2;

        if (line_len == 0) {
            break;
        }

        if (!first_line_done) {
            http_stream_rc_t rc = parse_start_line(m, line, line_len);
            if (rc != HTTP_STREAM_OK) {
                return rc;
            }
            first_line_done = 1;
            continue;
        }

        {
            const uint8_t *colon = (const uint8_t *)memchr(line, ':', line_len);
            const uint8_t *name_end;
            const uint8_t *val;
            const uint8_t *val_end;

            if (!colon) {
                return HTTP_STREAM_EPROTO;
            }
            name_end = colon;
            val      = skip_lws(colon + 1, line + line_len);
            val_end  = line + line_len;
            trim_rws(&val, &val_end);

            /* 알려진 헤더만 별도 메타데이터 필드로 정규화한다. */
            if (ci_eq_token(line, (size_t)(name_end - line),
                            "content-length")) {
                char      tmp[32];
                size_t    vn = (size_t)(val_end - val);
                long long v;
                if (vn == 0 || vn >= sizeof(tmp)) {
                    return HTTP_STREAM_EPROTO;
                }
                memcpy(tmp, val, vn);
                tmp[vn] = '\0';
                v       = atoll(tmp);
                if (v < 0 || (size_t)v > max_body_bytes) {
                    return HTTP_STREAM_EOVERFLOW;
                }
                m->content_length = v;
            } else if (ci_eq_token(line, (size_t)(name_end - line),
                                   "transfer-encoding")) {
                if (ci_contains(val, (size_t)(val_end - val), "chunked")) {
                    m->chunked = 1;
                }
            } else if (ci_eq_token(line, (size_t)(name_end - line),
                                   "content-type")) {
                size_t vn = (size_t)(val_end - val);
                if (copy_token(m->content_type, sizeof(m->content_type), val,
                               vn) != 0) {
                    return HTTP_STREAM_EOVERFLOW;
                }
            }
        }
    }

    if (!first_line_done) {
        return HTTP_STREAM_EPROTO;
    }
    return HTTP_STREAM_OK;
}

/**
 * @brief body 버퍼 뒤에 새 바이트 구간을 이어 붙인다.
 *
 * @param buf body 버퍼 포인터
 * @param len 현재 body 길이
 * @param data 추가할 데이터
 * @param n 추가 길이
 * @param max_body_bytes 허용 최대 body 길이
 * @return http_stream_rc_t append 결과 코드
 */
static http_stream_rc_t append_body(uint8_t **buf, size_t *len,
                                    const uint8_t *data, size_t n,
                                    size_t max_body_bytes) {
    uint8_t *nb;

    /* chunked body도 최종 누적 길이는 max_body_bytes를 넘지 않게 제한한다. */
    if (*len + n > max_body_bytes) {
        return HTTP_STREAM_EOVERFLOW;
    }
    nb = (uint8_t *)realloc(*buf, *len + n);
    if (!nb) {
        return HTTP_STREAM_ENOMEM;
    }
    memcpy(nb + *len, data, n);
    *buf = nb;
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
static http_stream_rc_t parse_chunked_body(const uint8_t *p, size_t n,
                                           size_t  max_body_bytes,
                                           size_t *consumed, uint8_t **body,
                                           size_t *body_len) {
    size_t pos = 0;
    *body      = NULL;
    *body_len  = 0;

    /* 0-size chunk를 만날 때까지 chunk line과 data를 순차적으로 해석한다. */
    while (1) {
        size_t        le;
        char          tmp[64];
        char         *semi;
        unsigned long sz;

        if (!memmem_crlf(p + pos, n - pos, &le)) {
            return HTTP_STREAM_NEED_MORE;
        }
        if (le == 0 || le >= sizeof(tmp)) {
            return HTTP_STREAM_EPROTO;
        }

        memcpy(tmp, p + pos, le);
        tmp[le] = '\0';
        semi    = strchr(tmp, ';');
        if (semi) {
            *semi = '\0';
        }

        sz = strtoul(tmp, NULL, 16);
        pos += le + 2;

        if (sz == 0) {
            /* 마지막 chunk 뒤에는 빈 줄 또는 trailer header block이 올 수 있다. */
            if (n - pos >= 2 && p[pos] == '\r' && p[pos + 1] == '\n') {
                pos += 2;
                *consumed = pos;
                return HTTP_STREAM_OK;
            }
            {
                size_t tr_end;
                if (!memmem_crlfcrlf(p + pos, n - pos, &tr_end)) {
                    return HTTP_STREAM_NEED_MORE;
                }
                pos += tr_end + 4;
                *consumed = pos;
                return HTTP_STREAM_OK;
            }
        }

        if (n - pos < sz + 2) {
            return HTTP_STREAM_NEED_MORE;
        }
        if (p[pos + sz] != '\r' || p[pos + sz + 1] != '\n') {
            return HTTP_STREAM_EPROTO;
        }

        /* chunk payload만 body 버퍼에 누적하고, 뒤 CRLF는 소비만 한다. */
        {
            http_stream_rc_t rc =
                append_body(body, body_len, p + pos, sz, max_body_bytes);
            if (rc != HTTP_STREAM_OK) {
                return rc;
            }
        }

        pos += sz + 2;
    }
}

/**
 * @brief 완성된 HTTP 메시지를 스트림 내부 큐에 적재한다.
 *
 * @param s HTTP 스트림 컨텍스트
 * @param msg 큐에 넣을 메시지
 * @return http_stream_rc_t 0이면 성공, 메모리 부족이면 오류
 */
static http_stream_rc_t queue_message(http_stream_t *s, http_message_t *msg) {
    msg_node_t *n = (msg_node_t *)calloc(1, sizeof(*n));
    if (!n) {
        return HTTP_STREAM_ENOMEM;
    }
    n->msg = *msg;
    if (!s->q_head) {
        s->q_head = s->q_tail = n;
    } else {
        s->q_tail->next = n;
        s->q_tail       = n;
    }
    return HTTP_STREAM_OK;
}

/**
 * @brief 입력 버퍼 앞쪽 n바이트를 소비한다.
 *
 * @param s HTTP 스트림 컨텍스트
 * @param n 제거할 길이
 */
static void consume_front(http_stream_t *s, size_t n) {
    if (n >= s->len) {
        s->len = 0;
        return;
    }

    /* 아직 해석하지 않은 나머지 바이트를 버퍼 앞으로 당겨 재사용한다. */
    memmove(s->buf, s->buf + n, s->len - n);
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
static http_stream_rc_t parse_one(http_stream_t *s, int *produced) {
    size_t         hdr_end_pos;
    size_t         msg_hdr_len;
    size_t         start_line_end;
    size_t         headers_only_off;
    size_t         headers_only_len;
    http_message_t m;
    size_t         body_off;
    size_t         consumed = 0;

    /* 헤더 끝(CRLFCRLF)을 아직 못 찾으면 메시지가 덜 들어온 상태다. */
    *produced = 0;
    if (!memmem_crlfcrlf(s->buf, s->len, &hdr_end_pos)) {
        return HTTP_STREAM_NEED_MORE;
    }

    /* 헤더 블록이 max buffer를 넘으면 비정상 입력으로 본다. */
    msg_hdr_len = hdr_end_pos + 4;
    if (msg_hdr_len > s->max_buffer_bytes) {
        return HTTP_STREAM_EOVERFLOW;
    }

    memset(&m, 0, sizeof(m));
    m.content_length = -1;

    /* start-line과 주요 헤더를 먼저 파싱해 body 처리 방식을 결정한다. */
    {
        http_stream_rc_t rc =
            parse_headers_meta(&m, s->buf, msg_hdr_len, s->max_body_bytes);
        if (rc != HTTP_STREAM_OK) {
            http_message_free(&m);
            return rc;
        }
    }

    if (!memmem_crlf(s->buf, msg_hdr_len, &start_line_end)) {
        http_message_free(&m);
        return HTTP_STREAM_EPROTO;
    }

    headers_only_off = start_line_end + 2;
    if (headers_only_off > hdr_end_pos) {
        headers_only_len = 0;
    } else {
        headers_only_len = hdr_end_pos - headers_only_off;
    }

    /* queue에 저장할 수 있도록 헤더 원문을 start-line 제외 구간만 따로 복사한다. */
    m.headers_raw = (uint8_t *)malloc(headers_only_len + 1);
    if (!m.headers_raw) {
        http_message_free(&m);
        return HTTP_STREAM_ENOMEM;
    }
    if (headers_only_len > 0) {
        memcpy(m.headers_raw, s->buf + headers_only_off, headers_only_len);
    }
    m.headers_raw[headers_only_len] = '\0';
    m.headers_raw_len               = headers_only_len;

    /* chunked와 content-length를 동시에 허용하지 않는다. */
    if (m.chunked && m.content_length >= 0) {
        http_message_free(&m);
        return HTTP_STREAM_EPROTO;
    }

    body_off = msg_hdr_len;
    if (m.chunked) {
        /* chunked 메시지는 body를 완전히 풀어서 단일 body 버퍼로 만든다. */
        http_stream_rc_t rc = parse_chunked_body(
            s->buf + body_off, s->len - body_off, s->max_body_bytes, &consumed,
            &m.body, &m.body_len);
        if (rc != HTTP_STREAM_OK) {
            http_message_free(&m);
            return rc;
        }
        consumed += body_off;
    } else if (m.content_length > 0) {
        /* content-length가 있으면 그 길이만큼 body가 쌓일 때까지 기다린다. */
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
        /* body 없는 메시지는 헤더까지만 소비하고 바로 완료 처리한다. */
        m.body     = NULL;
        m.body_len = 0;
        consumed   = body_off;
    }

    /* 완성된 메시지는 내부 큐로 넘기고, 입력 버퍼 앞부분은 소비한다. */
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
    if (cfg) {
        if (cfg->max_buffer_bytes > 0) {
            max_buf = cfg->max_buffer_bytes;
        }
        if (cfg->max_body_bytes > 0) {
            max_body = cfg->max_body_bytes;
        }
    }

    s = (http_stream_t *)calloc(1, sizeof(*s));
    if (!s) {
        return NULL;
    }
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
    free(m->headers_raw);
    free(m->body);
    memset(m, 0, sizeof(*m));
}

/**
 * @brief 스트림 버퍼와 메시지 큐를 초기 상태로 되돌린다.
 *
 * @param s HTTP 스트림 컨텍스트
 */
void http_stream_reset(http_stream_t *s) {
    msg_node_t *p;
    if (!s) {
        return;
    }

    /* 누적 버퍼는 비우고, 대기 중인 메시지 큐도 전부 해제한다. */
    s->len = 0;
    while (s->q_head) {
        p         = s->q_head;
        s->q_head = p->next;
        http_message_free(&p->msg);
        free(p);
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
    http_stream_rc_t rc;

    /* 입력 검증과 빈 payload 처리부터 빠르게 끝낸다. */
    if (!s || (!data && len > 0)) {
        return HTTP_STREAM_EINVAL;
    }
    if (len == 0) {
        return HTTP_STREAM_OK;
    }

    /* 내부 버퍼 상한을 넘는 입력은 parse 전에 바로 막는다. */
    if (s->len + len > s->max_buffer_bytes) {
        set_err(s, "buffer overflow");
        return HTTP_STREAM_EOVERFLOW;
    }
    if (ensure_cap(s, s->len + len) != 0) {
        set_err(s, "memory allocation failed");
        return HTTP_STREAM_ENOMEM;
    }

    /* 새 payload를 이어 붙인 뒤, 더 이상 완전한 메시지가 안 나올 때까지 파싱한다. */
    memcpy(s->buf + s->len, data, len);
    s->len += len;

    while (1) {
        rc = parse_one(s, &produced);
        if (rc == HTTP_STREAM_NEED_MORE) {
            return HTTP_STREAM_OK;
        }
        if (rc != HTTP_STREAM_OK) {
            set_err(s, "HTTP parse error");
            return rc;
        }
        if (!produced) {
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
    free(n);
    return HTTP_STREAM_OK;
}

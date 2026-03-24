/**
 * @file http_stream.c
 * @brief HTTP 스트림 버퍼링, 메시지 파싱, 큐잉 구현
 *
 * reasm 계층이 넘긴 연속 TCP 바이트를 내부 버퍼에 누적하고,
 * 완전한 HTTP 메시지가 준비되면 `http_message_t`로 만들어 큐에 적재한다.
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

/**
 * @brief HTTP 파서 한 방향의 상태.
 *
 * `buf[start .. start+len)` 구간이 아직 소비되지 않은 연속 TCP 스트림이다.
 * 파싱이 완료된 메시지는 별도 큐에 넣어 상위가 poll하도록 한다.
 */
struct http_stream {
    uint8_t *buf;   /**< 누적 스트림 버퍼 */
    size_t   len;   /**< 현재 유효 데이터 길이 */
    size_t   cap;   /**< 전체 버퍼 용량 */
    size_t   start; /**< 유효 데이터 시작 오프셋 */

    size_t max_buffer_bytes;
    size_t max_body_bytes;

    msg_node_t *q_head;
    msg_node_t *q_tail;

    char last_err[128];
};

/* --------------------------- buffer management --------------------------- */

/**
 * @brief 마지막 파서 오류 메시지를 스트림에 기록한다.
 *
 * @param s HTTP 스트림 컨텍스트
 * @param msg 기록할 오류 문자열
 */
static void http_stream_error_log(http_stream_t *s, const char *msg) {
    /* 스트림 포인터 검증 */
    if (!s) {
        return;
    }
    /* NULL 오류 문자열은 기본 메시지 사용 */
    if (!msg) {
        msg = "unknown error";
    }
    /* 마지막 오류 문자열 갱신 */
    snprintf(s->last_err, sizeof(s->last_err), "%s", msg);
}

static void http_stream_buffer_compact(http_stream_t *s) {
    /* unread 데이터가 없으면 시작 오프셋만 초기화 */
    if (0 == s->len) {
        s->start = 0;
        return;
    }

    /* 이미 버퍼 앞에 붙어 있으면 이동 불필요 */
    if (0 == s->start) {
        return;
    }

    /* unread window를 버퍼 앞쪽으로 당긴다 */
    memmove(s->buf, s->buf + s->start, s->len);
    /* 새로운 unread window 시작 위치는 0 */
    s->start = 0;
}

static int http_stream_buffer_reserve_append(http_stream_t *s,
                                             size_t         append_len) {
    /* append 후 필요한 총 unread 길이 */
    size_t   need;
    /* 다음 버퍼 용량 */
    size_t   ncap;
    /* realloc 결과 버퍼 */
    uint8_t *nb;

    /* buffer 총량 제한 초과 방지 */
    if (append_len > s->max_buffer_bytes - s->len) {
        return -1;
    }

    /* append 후 unread window 총 길이 */
    need = s->len + append_len;

    /* 현재 뒤쪽 공간만으로 append 가능 */
    if (s->start + need <= s->cap) {
        return 0;
    }

    /* compact만으로 공간이 나면 그 경로 사용 */
    if (need <= s->cap) {
        http_stream_buffer_compact(s);
        return 0;
    }

    /* 앞 공간을 회수한 뒤 다시 확인 */
    http_stream_buffer_compact(s);

    if (need <= s->cap) {
        return 0;
    }

    /* 아직 부족하면 실제 버퍼를 늘린다 */
    ncap = s->cap;
    if (0 == ncap) {
        ncap = 1024;
    }

    /* overflow를 피하며 2배씩 확장 */
    while (ncap < need) {
        if (ncap > (SIZE_MAX / 2)) {
            return -1;
        }
        ncap *= 2;
    }

    /* 설정된 최대 버퍼 한도 초과 방지 */
    if (ncap > s->max_buffer_bytes) {
        return -1;
    }

    /* 실제 힙 확장 */
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
    /* 출력 포인터 검증 */
    if (NULL == s || NULL == out_data || NULL == out_len) {
        return -1;
    }

    /* 현재 unread window 시작 주소 반환 */
    *out_data = s->buf + s->start;
    /* 현재 unread 길이 반환 */
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
    /* 현재 탐색 위치 */
    const uint8_t *cur;
    /* memchr hit 위치 */
    const uint8_t *hit;
    /* 남은 탐색 길이 */
    size_t         remain;

    cur    = p;
    remain = len;

    /* CR 문자를 점프 탐색하며 CRLF를 찾는다 */
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
    /* 현재 탐색 위치 */
    const uint8_t *cur;
    /* memchr hit 위치 */
    const uint8_t *hit;
    /* 남은 탐색 길이 */
    size_t         remain;

    cur    = p;
    remain = len;

    /* CR 문자를 점프 탐색하며 CRLFCRLF를 찾는다 */
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
    /* NUL 종료 포함 목적 버퍼 길이 확인 */
    if (n + 1 > dst_cap) {
        return -1;
    }
    /* 토큰 본문 복사 */
    memcpy(dst, src, n);
    /* C 문자열 종료 */
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
    /* leading SP/HTAB 제거 */
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
    /* trailing SP/HTAB 제거 */
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
    /* 순회 인덱스 */
    size_t i;
    /* 비교 문자열 길이 */
    size_t bn = strlen(b);
    /* 현재 비교 문자 */
    int    ca;
    int    cb;

    /* 길이가 다르면 바로 불일치 */
    if (an != bn) {
        return 0;
    }
    /* 각 문자를 소문자로 정규화해 비교 */
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
    /* 시작 위치 인덱스 */
    size_t i;
    /* needle 길이 */
    size_t nn = strlen(needle);
    /* 현재 비교 문자 */
    int    ca;
    int    cb;
    /* 빈 needle 또는 더 긴 needle은 불일치 */
    if (0 == nn || nn > an) {
        return 0;
    }
    /* 모든 시작 위치를 sliding window로 검사 */
    for (i = 0; i + nn <= an; i++) {
        /* needle 내부 순회 인덱스 */
        size_t j;
        /* 현재 시작 위치가 일치하는지 여부 */
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
    /* 첫 번째 공백 위치 */
    const uint8_t *sp1;
    /* 두 번째 공백 위치 */
    const uint8_t *sp2;
    /* 줄 끝 주소 */
    const uint8_t *end;
    /* 임시 cursor */
    const uint8_t *p;
    /* helper 반환값 */
    int            ret;
    /* 숫자 여부 검사 결과 */
    int            is_digit;

    /* 현재 줄 끝 주소 계산 */
    end = line + n;

    /* "HTTP/"로 시작하면 response status-line으로 해석한다. */
    ret = 0;
    if (5U <= n) {
        /* 접두어가 HTTP/ 인지 확인 */
        ret = memcmp(line, "HTTP/", 5);
    }
    if (5U <= n && 0 == ret) {
        /* 응답 메시지 경로 */
        m->is_request = 0;

        /* version 뒤 첫 공백을 찾는다 */
        sp1 = (const uint8_t *)memchr(line, ' ', n);
        if (NULL == sp1) {
            return HTTP_STREAM_EPROTO;
        }

        /* HTTP version 문자열 저장 */
        ret = http_stream_token_copy(m->version, sizeof(m->version), line,
                                     (size_t)(sp1 - line));
        if (-1 == ret) {
            return HTTP_STREAM_EOVERFLOW;
        }

        /* status code 시작 위치 */
        p   = sp1 + 1;
        /* reason phrase 앞 공백 위치 */
        sp2 = (const uint8_t *)memchr(p, ' ', (size_t)(end - p));
        if (NULL == sp2) {
            return HTTP_STREAM_EPROTO;
        }

        /* status code 첫 자리가 숫자인지 확인 */
        is_digit = isdigit((unsigned char)p[0]);
        if (3U != (size_t)(sp2 - p) || 0 == is_digit) {
            return HTTP_STREAM_EPROTO;
        }
        /* status code 두 번째 자리 확인 */
        is_digit = isdigit((unsigned char)p[1]);
        if (0 == is_digit) {
            return HTTP_STREAM_EPROTO;
        }
        /* status code 세 번째 자리 확인 */
        is_digit = isdigit((unsigned char)p[2]);
        if (0 == is_digit) {
            return HTTP_STREAM_EPROTO;
        }

        /* 3자리 숫자를 정수 status code로 변환 */
        m->status_code =
            (int)((p[0] - '0') * 100 + (p[1] - '0') * 10 + (p[2] - '0'));

        /* reason phrase 시작 위치 */
        p   = sp2 + 1;
        /* reason phrase 원문 복사 */
        ret = http_stream_token_copy(m->reason, sizeof(m->reason), p,
                                     (size_t)(end - p));
        if (-1 == ret) {
            return HTTP_STREAM_EOVERFLOW;
        }
    } else {
        /* 그 외 형식은 request line으로 보고 method/uri/version을 추출한다. */
        m->is_request = 1;

        /* method 뒤 첫 공백 위치 */
        sp1 = (const uint8_t *)memchr(line, ' ', n);
        if (NULL == sp1) {
            return HTTP_STREAM_EPROTO;
        }

        /* uri 뒤 두 번째 공백 위치 */
        sp2 = (const uint8_t *)memchr(sp1 + 1, ' ', (size_t)(end - (sp1 + 1)));
        if (NULL == sp2) {
            return HTTP_STREAM_EPROTO;
        }

        /* method 문자열 복사 */
        ret = http_stream_token_copy(m->method, sizeof(m->method), line,
                                     (size_t)(sp1 - line));
        if (-1 == ret) {
            return HTTP_STREAM_EOVERFLOW;
        }

        /* request uri 문자열 복사 */
        ret = http_stream_token_copy(m->uri, sizeof(m->uri), sp1 + 1,
                                     (size_t)(sp2 - (sp1 + 1)));
        if (-1 == ret) {
            return HTTP_STREAM_EOVERFLOW;
        }

        /* HTTP version 문자열 복사 */
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
    /* 현재 파싱 위치 */
    size_t pos;
    /* start-line 파싱 여부 */
    int    first_line_done;
    /* helper 반환값 */
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
        /* 현재 줄 시작 주소 */
        const uint8_t *line;
        /* 현재 줄 길이 */
        size_t         line_len;
        /* ':' 위치 */
        const uint8_t *colon;
        /* header name 끝 위치 */
        const uint8_t *name_end;
        /* header value 시작 위치 */
        const uint8_t *val;
        /* header value 끝 위치 */
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
            /* start-line parse 결과 */
            http_stream_rc_t rc;

            /* 첫 줄을 request-line/status-line으로 해석 */
            rc = http_stream_start_line_parse(m, line, line_len);
            if (HTTP_STREAM_OK != rc) {
                return rc;
            }

            /* 이후 줄부터는 일반 헤더로 처리 */
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
            /* content-length 값 길이 */
            size_t    vn;
            /* 숫자 순회 인덱스 */
            size_t    i;
            /* 누적 body 길이 */
            long long v;

            /* value 길이 계산 */
            vn = (size_t)(val_end - val);
            if (0 == vn) {
                return HTTP_STREAM_EPROTO;
            }

            /* 누적값 초기화 */
            v = 0;
            /* 10진 숫자 문자열을 정수로 누적 변환 */
            for (i = 0; i < vn; i++) {
                ret = isdigit((unsigned char)val[i]);
                if (0 == ret) {
                    return HTTP_STREAM_EPROTO;
                }

                v = (v * 10) + (long long)(val[i] - '0');
                /* 설정된 최대 body 한도를 넘으면 overflow 처리 */
                if ((size_t)v > max_body_bytes) {
                    return HTTP_STREAM_EOVERFLOW;
                }
            }

            /* 최종 content-length 저장 */
            m->content_length = v;
        } else {
            /*
             * Transfer-Encoding은 현재 구현상 "chunked" 포함 여부만 본다.
             * 여러 토큰이 들어와도 value 안에 chunked가 포함되면 활성화한다.
             */
            ret = http_stream_token_equals_ci(line, (size_t)(name_end - line),
                                              "transfer-encoding");
            if (1 == ret) {
                /* value 안에 chunked 토큰이 있으면 chunked body로 본다 */
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
                    /* content-type 원문 길이 */
                    size_t vn;

                    /* value 길이 계산 */
                    vn  = (size_t)(val_end - val);
                    /* content_type 버퍼로 원문 복사 */
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
    /* append 후 필요한 총 길이 */
    size_t   need;
    /* 확장 후 새 용량 */
    size_t   new_cap;
    /* realloc 결과 버퍼 */
    uint8_t *nb;

    /* body 총량 제한 초과 방지 */
    if (n > max_body_bytes - *len) {
        return HTTP_STREAM_EOVERFLOW;
    }

    /* append 후 body 총 길이 */
    need = *len + n;
    if (need > *cap) {
        /* 현재 버퍼 용량 */
        new_cap = *cap;
        if (0 == new_cap) {
            new_cap = 1024;
        }

        /* overflow를 피하며 2배 확장 */
        while (new_cap < need) {
            if (new_cap > (SIZE_MAX / 2)) {
                return HTTP_STREAM_ENOMEM;
            }
            new_cap *= 2;
        }

        /* body 최대 한도를 넘지 않게 조정 */
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
        /* 실제 버퍼 확장 */
        nb = (uint8_t *)realloc(*buf, new_cap);
        if (NULL == nb) {
            return HTTP_STREAM_ENOMEM;
        }

        *buf = nb;
        *cap = new_cap;
    }

    /* 새 body 조각을 뒤에 이어 붙인다 */
    memcpy(*buf + *len, data, n);
    /* body 길이 갱신 */
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
    /* 현재 chunk 파싱 위치 */
    size_t           pos;
    /* helper 반환값 */
    int              ret;
    /* body append 결과 */
    http_stream_rc_t rc;
    /* body 버퍼 용량 */
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
    /* 첫 노드면 head/tail 동시 초기화 */
    if (NULL == s->q_head) {
        s->q_head = n;
        s->q_tail = n;
    } else {
        /* 기존 tail 뒤에 연결 */
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
    /* 전체 unread를 다 소비하면 초기 상태로 리셋 */
    if (n >= s->len) {
        s->start = 0;
        s->len   = 0;
        return;
    }

    /* 앞쪽 n바이트만 window에서 제거 */
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
    /* CRLFCRLF 위치 */
    size_t           hdr_end_pos;
    /* 헤더 포함 총 길이 */
    size_t           msg_hdr_len;
    /* start-line 종료 위치 */
    size_t           start_line_end;
    /* start-line 제외 헤더 시작 오프셋 */
    size_t           headers_only_off;
    /* start-line 제외 헤더 길이 */
    size_t           headers_only_len;
    /* 임시 메시지 구조체 */
    http_message_t   m;
    /* body 시작 오프셋 */
    size_t           body_off;
    /* 현재 메시지가 소비한 총 길이 */
    size_t           consumed;
    /* unread window 시작 주소 */
    const uint8_t   *base;
    /* helper 결과 */
    http_stream_rc_t rc;
    int              ret;
    /* queue 노드 전체 할당 크기 */
    size_t           total_size;
    /* queue 노드 */
    msg_node_t      *node;
    /* owned storage 내부 쓰기 cursor */
    uint8_t         *cursor;

    /* produced 기본값은 아직 메시지 없음 */
    *produced = 0;
    /* 현재 unread window 시작 주소 */
    base      = s->buf + s->start;
    /* 소비 길이 초기화 */
    consumed  = 0;
    /* queue 노드 포인터 초기화 */
    node      = NULL;

    /* 헤더 끝(CRLFCRLF)을 아직 못 찾으면 메시지가 덜 들어온 상태다. */
    ret = http_stream_buffer_find_header_end(base, s->len, &hdr_end_pos);
    if (0 == ret) {
        return HTTP_STREAM_NEED_MORE;
    }
    /* 헤더 포함 길이 계산 */
    msg_hdr_len = hdr_end_pos + 4;
    /* 임시 메시지 구조체 zero-init */
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
    /* 첫 줄 끝 위치를 다시 찾아 start-line과 header block을 분리한다 */
    ret = http_stream_buffer_find_crlf(base, msg_hdr_len, &start_line_end);
    if (0 == ret) {
        http_message_free(&m);
        return HTTP_STREAM_EPROTO;
    }

    /* start-line 뒤부터 header raw 복사 구간을 계산한다 */
    headers_only_off = start_line_end + 2;
    if (headers_only_off > hdr_end_pos) {
        headers_only_len = 0;
    } else {
        headers_only_len = hdr_end_pos - headers_only_off;
    }

    /* chunked와 content-length 동시 사용은 비정상 메시지로 본다 */
    if (0 != m.chunked && 0 <= m.content_length) {
        http_message_free(&m);
        return HTTP_STREAM_EPROTO;
    }

    /* body는 헤더 바로 뒤에서 시작한다 */
    body_off = msg_hdr_len;
    if (0 != m.chunked) {
        /* chunked body는 조각을 풀어 연속 body로 만든다 */
        rc = http_stream_body_parse_chunked(base + body_off, s->len - body_off,
                                            s->max_body_bytes, &consumed,
                                            &m.body, &m.body_len);
        if (HTTP_STREAM_OK != rc) {
            http_message_free(&m);
            return rc;
        }

        /* chunked parser가 반환한 consumed 길이에 헤더 길이를 더한다 */
        consumed += body_off;
    } else if (0 < m.content_length) {
        /* content-length body는 전체 길이가 들어왔는지 확인한다 */
        if ((size_t)m.content_length > s->len - body_off) {
            http_message_free(&m);
            return HTTP_STREAM_NEED_MORE;
        }
        /* body 길이와 총 소비 길이를 확정한다 */
        m.body_len = (size_t)m.content_length;
        consumed   = body_off + m.body_len;
    } else {
        /* body가 없는 메시지 */
        m.body_len = 0;
        consumed   = body_off;
    }

    /* queue 노드 + 헤더 원문 + body 저장소를 한 블록으로 할당한다 */
    total_size = sizeof(*node) + headers_only_len + 1 + m.body_len;
    node       = (msg_node_t *)malloc(total_size);
    if (NULL == node) {
        http_message_free(&m);
        return HTTP_STREAM_ENOMEM;
    }

    /* queue 노드 메타데이터 초기화 */
    memset(node, 0, sizeof(*node));
    node->msg               = m;
    node->msg.owned_storage = (uint8_t *)node;
    node->next              = NULL;

    /* owned storage 내부 직렬화 시작 위치 */
    cursor = node->data;

    /* start-line 제외 헤더 원문 저장 위치 */
    node->msg.headers_raw = cursor;
    if (0U != headers_only_len) {
        memcpy(node->msg.headers_raw, base + headers_only_off,
               headers_only_len);
    }

    /* 헤더 문자열 NUL 종료 */
    node->msg.headers_raw[headers_only_len] = '\0';
    node->msg.headers_raw_len               = headers_only_len;

    /* body 저장 위치로 cursor 이동 */
    cursor += headers_only_len + 1;

    if (0U != m.body_len) {
        /* chunked body는 임시 body 버퍼에서 owned storage로 복사 */
        if (0 != m.chunked) {
            memcpy(cursor, m.body, m.body_len);
            free(m.body);
            m.body = NULL;
        /* non-chunked body는 현재 입력 버퍼에서 직접 복사 */
        } else {
            memcpy(cursor, base + body_off, m.body_len);
        }

        /* body 포인터를 owned storage 내부 주소로 갱신 */
        node->msg.body = cursor;
    } else {
        /* body가 없으면 NULL 유지 */
        node->msg.body = NULL;
    }

    /* 최종 body 길이 저장 */
    node->msg.body_len = m.body_len;
    /* 완성된 메시지를 내부 큐에 적재 */
    http_stream_queue_push(s, node);

    /* 입력 버퍼에서 방금 소비한 메시지 길이를 제거 */
    http_stream_buffer_consume_front(s, consumed);
    /* 메시지 1개 생산 완료 */
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
    /* 생성될 스트림 객체 */
    http_stream_t *s;
    /* 기본 최대 버퍼 크기 */
    size_t         max_buf  = 12 * 1024 * 1024;
    /* 기본 최대 body 크기 */
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

    /* 스트림 객체 본체 할당 */
    s = (http_stream_t *)malloc(sizeof(*s));
    if (NULL == s) {
        return NULL;
    }

    /* 구조체 zero-init */
    memset(s, 0, sizeof(*s));
    /* 설정값 반영 */
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
    /* NULL 입력 방어 */
    if (!m) {
        return;
    }

    /* owned storage가 있으면 한 블록만 해제하면 된다 */
    if (NULL != m->owned_storage) {
        free(m->owned_storage);
    } else {
        /* 개별 할당 경로는 헤더/바디를 각각 해제 */
        free(m->headers_raw);
        free(m->body);
    }

    /* 호출자 재사용을 막기 위해 구조체 초기화 */
    memset(m, 0, sizeof(*m));
}

/**
 * @brief 스트림 버퍼와 메시지 큐를 초기 상태로 되돌린다.
 *
 * @param s HTTP 스트림 컨텍스트
 */
void http_stream_reset(http_stream_t *s) {
    /* queue 순회용 노드 */
    msg_node_t *p;
    /* NULL 입력 방어 */
    if (NULL == s) {
        return;
    }

    /* unread window 초기화 */
    s->start = 0;
    s->len   = 0;

    /* 큐에 쌓인 메시지를 전부 정리한다 */
    while (s->q_head) {
        p         = s->q_head;
        s->q_head = p->next;

        /* node 자체가 owned storage면 free(p)만으로 충분하다 */
        if ((uint8_t *)p == p->msg.owned_storage) {
            free(p);
        } else {
            /* 아닌 경우 메시지 내부 메모리를 먼저 정리한다 */
            http_message_free(&p->msg);
            free(p);
        }
    }

    /* queue tail과 마지막 오류 초기화 */
    s->q_tail      = NULL;
    s->last_err[0] = '\0';
}

/**
 * @brief HTTP 스트림 컨텍스트를 완전히 해제한다.
 *
 * @param s HTTP 스트림 컨텍스트
 */
void http_stream_destroy(http_stream_t *s) {
    /* NULL 입력 방어 */
    if (!s) {
        return;
    }
    /* queue와 상태부터 초기화 */
    http_stream_reset(s);
    /* 입력 버퍼 해제 */
    free(s->buf);
    /* 스트림 객체 본체 해제 */
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
    /* message_parse_one produced 플래그 */
    int              produced;
    /* helper 반환값 */
    int              ret;
    /* 파싱 결과 코드 */
    http_stream_rc_t rc;

    /* 입력 포인터/길이 조합 검증 */
    if (NULL == s || (NULL == data && 0 < len)) {
        return HTTP_STREAM_EINVAL;
    }

    /* 빈 입력은 그대로 성공 처리 */
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
        /* 파싱 오류는 last_err 갱신 후 상위로 전파 */
        if (HTTP_STREAM_OK != rc) {
            http_stream_error_log(s, "HTTP parse error");
            return rc;
        }
        /* 더 이상 새 메시지가 안 만들어지면 종료 */
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
    /* 큐에서 꺼낼 노드 */
    msg_node_t *n;
    /* 출력 포인터 검증 */
    if (!s || !out) {
        return HTTP_STREAM_EINVAL;
    }
    /* 큐가 비어 있으면 더 꺼낼 메시지가 없다 */
    if (!s->q_head) {
        return HTTP_STREAM_NO_MESSAGE;
    }

    /* head 노드를 pop */
    n         = s->q_head;
    s->q_head = n->next;
    /* 마지막 노드였으면 tail도 비운다 */
    if (!s->q_head) {
        s->q_tail = NULL;
    }

    /* 메시지 소유권을 호출자에게 넘긴다 */
    *out = n->msg;
    return HTTP_STREAM_OK;
}

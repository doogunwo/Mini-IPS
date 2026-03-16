/**
 * @file http_stream.h
 * @brief HTTP 스트림 파서 공개 인터페이스
 */
#ifndef HTTP_STREAM_H
#define HTTP_STREAM_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    HTTP_STREAM_OK         = 0,
    HTTP_STREAM_NEED_MORE  = 1,
    HTTP_STREAM_NO_MESSAGE = 2,
    HTTP_STREAM_EINVAL     = -1,
    HTTP_STREAM_ENOMEM     = -2,
    HTTP_STREAM_EPROTO     = -3,
    HTTP_STREAM_EOVERFLOW  = -4
} http_stream_rc_t;

/** 한 HTTP 방향에서 공유하는 스트림 파서 제한값이다. */
typedef struct {
    size_t max_buffer_bytes;
    size_t max_body_bytes;
} http_stream_cfg_t;

/** 스트림 파서가 생성한 HTTP 메시지 결과 구조체이다. */
typedef struct {
    int  is_request;
    char method[16];
    char uri[1048576];
    char version[16];
    int  status_code;
    char reason[64];

    int       chunked;
    long long content_length;
    char      content_type[64];

    uint8_t *headers_raw;
    size_t   headers_raw_len;
    uint8_t *body;
    size_t   body_len;
} http_message_t;

/** HTTP 스트림 파서 내부 구조를 숨기는 핸들 타입이다. */
typedef struct http_stream http_stream_t;

/** 새 HTTP 스트림 파서를 생성한다. */
http_stream_t *http_stream_create(const http_stream_cfg_t *cfg);
/** 스트림 파서를 해제하고 큐에 남은 메시지를 정리한다. */
void http_stream_destroy(http_stream_t *s);
/** 파싱 오류나 연결 초기화 이후 파서 상태를 재설정한다. */
void http_stream_reset(http_stream_t *s);

/** 재조립된 바이트 스트림을 파서에 입력한다. */
http_stream_rc_t http_stream_feed(http_stream_t *s, const uint8_t *data,
                                  size_t len);
/** 내부 큐에서 파싱된 HTTP 메시지 한 개를 꺼낸다. */
http_stream_rc_t http_stream_poll_message(http_stream_t  *s,
                                          http_message_t *out);
/** 파싱된 메시지가 소유한 동적 메모리를 해제한다. */
void http_message_free(http_message_t *m);

/** 마지막 파서 오류 문자열을 돌려준다. */
const char *http_stream_last_error(const http_stream_t *s);

#endif

/**
 * @file http_stream.h
 * @brief HTTP 스트림 파서 공개 인터페이스
 *
 * 이 계층은 TCP 재조립 결과로 얻은 연속 바이트 스트림을 버퍼에 누적한 뒤,
 * 완전한 HTTP 메시지 단위로 파싱해 큐에 적재한다.
 */
#ifndef HTTP_STREAM_H
#define HTTP_STREAM_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief HTTP stream parser 반환하는 상태 코드 집합
 */
typedef enum {
    HTTP_STREAM_OK        = 0, /* dequeue 성공 또는 요청 파싱 */
    HTTP_STREAM_NEED_MORE = 1, /* HTTP 메시지 완성이 불가능 아직 */
    HTTP_STREAM_NO_MESSAGE = 2, /* poll시 꺼낼 파싱 완료 메시지가 없음 */
    HTTP_STREAM_EINVAL = -1, /* 잘못된 인자 또는 호출 */
    HTTP_STREAM_ENOMEM = -2, /* 동적 메모리 할당 실패 */
    HTTP_STREAM_EPROTO = -3, /* HTTP 문법 오류 또는 비정상 메시지 */
    HTTP_STREAM_EOVERFLOW = -4 /* 내부 버퍼 길이 제한 초과 */
} http_stream_rc_t;

/** 한 HTTP 방향에서 공유하는 스트림 파서 제한값이다. */
typedef struct {
    size_t max_buffer_bytes;
    size_t max_body_bytes;
} http_stream_cfg_t;

/** 스트림 파서가 생성한 HTTP 메시지 결과 구조체이다. */
typedef struct {
    int  is_request;   /**< 요청 메시지면 1, 응답 메시지면 0 */
    char method[16];   /**< 요청 메서드 */
    char uri[1048576]; /**< 요청 URI */
    char version[16];  /**< HTTP 버전 문자열 */
    int  status_code;  /**< 응답 상태 코드 */
    char reason[64];   /**< 응답 reason phrase */

    int       chunked;           /**< Transfer-Encoding: chunked 여부 */
    long long content_length;    /**< Content-Length 값, 없으면 -1 계열 */
    char      content_type[200]; /**< Content-Type 헤더 값 */

    uint8_t *headers_raw;     /**< 헤더 블록 원문 */
    size_t   headers_raw_len; /**< 헤더 블록 길이 */
    uint8_t *body;            /**< body 포인터 */
    size_t   body_len;        /**< body 길이 */
    uint8_t *owned_storage; /**< headers/body를 함께 보관하는 소유 메모리 */
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
/** 현재 파서 버퍼의 시작 포인터와 길이를 읽기 전용으로 돌려준다. */
int http_stream_peek_buffer(const http_stream_t *s, const uint8_t **out_data,
                            size_t *out_len);

#endif

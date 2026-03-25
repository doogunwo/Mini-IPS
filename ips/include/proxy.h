/**
 * @file proxy.h
 * @brief 인라인 프록시 중계/차단 공개 인터페이스
 */
#ifndef PROXY_H
#define PROXY_H

#include <stddef.h>
#include <stdint.h>

struct conn;

/** 프록시 동작 결과 코드 */
typedef enum {
    PROXY_OK = 0,
    PROXY_BLOCKED = 1,
    PROXY_ERROR = -1
} proxy_rc_t;

/** 클라이언트에서 읽은 바이트를 upstream 또는 탐지 경로로 전달 */
proxy_rc_t proxy_handle_client_data(struct conn *c, const uint8_t *buf,
                                    size_t len);

/** upstream에서 읽은 바이트를 클라이언트로 전달 */
proxy_rc_t proxy_handle_upstream_data(struct conn *c, const uint8_t *buf,
                                      size_t len);

/** 차단 응답을 생성해 클라이언트로 보낸다 */
proxy_rc_t proxy_send_block_response(struct conn *c, const char *html,
                                     size_t html_len);

#endif

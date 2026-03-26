#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct tcp_node {
    uint8_t         *data;
    size_t           len;
    size_t           offset;
    struct tcp_node *next;
} tcp_node_t;

typedef struct http_request {
    char *method;  // 중요(메서드 정책, 비정상 메서드)
    char *uri;     // 최중요(공격 패턴 핵심)

    char *headers;             // 최중요(Host, Cookie, CL, TE, UA 등)
    long long content_length;  // 중요(정합성, 크기 제한, 우회 탐지)

    uint8_t *body;      // 최중요(POST payload, 업로드, injection)
    size_t   body_len;  // 중요(정합성, 크기 제한)
} http_request_t;

typedef struct http_response {
    int status_code;  // 중요(공격 성공/스캔 판단)

    char     *headers;  // 중요(서버정보, 쿠키, 타입, 리다이렉트)
    long long content_length;  // 중요

    uint8_t *body;      // 중요~최중요(유출, 악성응답, 다운로드)
    size_t   body_len;  // 중요
} http_response_t;

typedef struct node_list {
    tcp_node_t     *head;
    tcp_node_t     *tail;
    int             has_parsed_http;
    int             parsed_is_request;
    http_request_t  parsed_request;
    http_response_t parsed_response;
} node_list_t;

int node_list_init(node_list_t *list);
int node_list_try_parser(node_list_t *list);  // http가 되는지 파싱하는거임
int node_list_append(node_list_t *list, const uint8_t *data, size_t len);
int node_list_free(node_list_t *list);

#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * 반환 규약
 *  1  : 성공
 *  0  : 변화 없음 또는 입력 부족
 * -1  : 실패
 */

/* ---------------- text ---------------- */

int http_decode_percent(char *dst, size_t dst_sz, const char *src);

int http_decode_percent_recursive(char *dst, size_t dst_sz, const char *src,
                                  int max_depth);

int http_decode_plus_as_space(char *dst, size_t dst_sz, const char *src);

int http_decode_html_entity(char *dst, size_t dst_sz, const char *src);

int http_decode_escape_sequence(char *dst, size_t dst_sz, const char *src);

int http_has_invalid_percent_encoding(const char *src);

/* ---------------- body / bytes ---------------- */

int http_body_decode_percent(uint8_t *dst, size_t dst_sz, const uint8_t *src,
                             size_t src_len, size_t *out_len);

int http_body_decode_percent_recursive(uint8_t *dst, size_t dst_sz,
                                       const uint8_t *src, size_t src_len,
                                       int max_depth, size_t *out_len);

int http_body_decode_html_entity(uint8_t *dst, size_t dst_sz,
                                 const uint8_t *src, size_t src_len,
                                 size_t *out_len);

int http_body_decode_escape_sequence(uint8_t *dst, size_t dst_sz,
                                     const uint8_t *src, size_t src_len,
                                     size_t *out_len);

int http_body_has_invalid_percent_encoding(const uint8_t *src, size_t src_len);
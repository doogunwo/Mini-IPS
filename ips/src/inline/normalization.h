#pragma once

#include <stddef.h>
#include <stdint.h>

/**
 * 반환 규약
 * 1 성공
 * 0 변화없음
 * -1 실패
 */

/* ---------------- text ----------------*/

/* URI 전체 정규화 */
int http_normalize_uri(char *dst, size_t dst_sz, const char *src);

/* path 정규화 */
int http_normalize_path(char *dst, size_t dst_sz, const char *src);

/* query 정규화 */
int http_normalize_query(char *dst, size_t dst_sz, const char *src);

/* 헤더명 정규화: 소문자화 등 */
int http_normalize_header_name(char *dst, size_t dst_sz, const char *src);

/* Host 값 정규화 */
int http_normalize_host(char *dst, size_t dst_sz, const char *src);

/* 연속 슬래시 정리 */
int http_normalize_slashes(char *dst, size_t dst_sz, const char *src);

/* . / .. segment 제거 */
int http_remove_dot_segments(char *dst, size_t dst_sz, const char *src);

/* 앞뒤 공백 제거 및 내부 공백 정책 정리 */
int http_normalize_spaces(char *dst, size_t dst_sz, const char *src);

/* 개행 정규화 */
int http_normalize_line_endings(char *dst, size_t dst_sz, const char *src);

/* 영문 소문자화 */
int http_normalize_lowercase(char *dst, size_t dst_sz, const char *src);

/* ---------------- body / bytes ---------------- */

/* body 공백 정규화 */
int http_body_normalize_spaces(uint8_t *dst, size_t dst_sz, const uint8_t *src,
                               size_t src_len, size_t *out_len);

/* body 줄바꿈 정규화 */
int http_body_normalize_line_endings(uint8_t *dst, size_t dst_sz,
                                     const uint8_t *src, size_t src_len,
                                     size_t *out_len);

/* body 소문자화: 텍스트 body에만 사용 */
int http_body_normalize_lowercase(uint8_t *dst, size_t dst_sz,
                                  const uint8_t *src, size_t src_len,
                                  size_t *out_len);
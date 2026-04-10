#include "http_parser.h"

#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define HTTP_REQ 1
#define HTTP_RES 0

#define BODY_MODE_NONE 0
#define BODY_MODE_FIXED 1
#define BODY_MODE_CHUNKED 2

/**
 * @brief http message t 구조체를 파싱 전에 초기 상태로 세팅함
 * 
 * @param msg 
 * @return int 
 */
static int http_message_init(http_message_t *msg) {
    if (NULL == msg) {
        return -1;
    }

    memset(msg, 0, sizeof(*msg));
    msg->content_length = -1;
    return 1;
}

static int http_message_reset(http_message_t *msg) {
    if (NULL == msg) {
        return -1;
    }

    free(msg->method);
    free(msg->uri);
    free(msg->headers);
    free(msg->body);
    return http_message_init(msg);
}

static int find_crlf(const uint8_t *data, size_t len, size_t *out_pos) {
    size_t i;

    if (NULL == data || NULL == out_pos) {
        return -1;
    }

    for (i = 0; i + 1 < len; i++) {
        if ('\r' == data[i] && '\n' == data[i + 1]) {
            *out_pos = i;
            return 1;
        }
    }

    return 0;
}

/**
 * @brief HTTP 메시지에서 헤더가 끝나는 위치를 찾는다.
 * 
 * @param data 검사할 http 바이트버퍼
 * @param len 버퍼 길이
 * @param out_pos 헤더 끝 위치를 담을 출력 포인터
 * @return int 
 */
static int find_header_end(const uint8_t *data, size_t len, size_t *out_pos) {
    size_t i;

    if (NULL == data || NULL == out_pos) {
        return -1;
    }
    //\r\n\r\n는 4바이트라서 i+3까지 볼수있는 범위 탐색함
    for (i = 0; i + 3 < len; i++) {
        if ('\r' == data[i] && '\n' == data[i + 1] && '\r' == data[i + 2] &&
            '\n' == data[i + 3]) {
            *out_pos = i;
            return 1;
        }
    }

    return 0;
}

static char *dup_slice(const uint8_t *data, size_t len) {
    char *copy;

    if (NULL == data && 0 != len) {
        return NULL;
    }

    copy = (char *)malloc(len + 1);
    if (NULL == copy) {
        return NULL;
    }

    if (0 < len) {
        memcpy(copy, data, len);
    }
    copy[len] = '\0';
    return copy;
}

static int bytes_equal_ci(const uint8_t *data, size_t len, const char *text) {
    size_t i;

    if (NULL == data || NULL == text) {
        return 0;
    }

    for (i = 0; i < len; i++) {
        if ('\0' == text[i]) {
            return 0;
        }
        if (tolower((unsigned char)data[i]) !=
            tolower((unsigned char)text[i])) {
            return 0;
        }
    }

    return '\0' == text[len];
}

static int parse_request_line(const uint8_t *data, size_t line_len,
                              http_message_t *msg) {
    const uint8_t *sp1;
    const uint8_t *sp2;

    if (NULL == data || NULL == msg) {
        return -1;
    }
    if (0 == line_len) {
        return -1;
    }

    sp1 = memchr(data, ' ', line_len);
    if (NULL == sp1) {
        return -1;
    }

    sp2 = memchr(sp1 + 1, ' ', (size_t)(data + line_len - (sp1 + 1)));
    if (NULL == sp2) {
        return -1;
    }
    if (sp1 == data || sp2 == sp1 + 1) {
        return -1;
    }
    if ((size_t)(data + line_len - (sp2 + 1)) < 5) {
        return -1;
    }
    if (0 != memcmp(sp2 + 1, "HTTP/", 5)) {
        return -1;
    }

    msg->type   = HTTP_REQ;
    msg->method = dup_slice(data, (size_t)(sp1 - data));
    msg->uri    = dup_slice(sp1 + 1, (size_t)(sp2 - (sp1 + 1)));
    if (NULL == msg->method || NULL == msg->uri) {
        return -1;
    }

    return 1;
}

static int parse_status_line(const uint8_t *data, size_t line_len,
                             http_message_t *msg) {
    const uint8_t *sp1;
    const uint8_t *status;

    if (NULL == data || NULL == msg) {
        return -1;
    }
    if (line_len < 8) {
        return -1;
    }
    if (0 != memcmp(data, "HTTP/", 5)) {
        return -1;
    }

    sp1 = memchr(data, ' ', line_len);
    if (NULL == sp1) {
        return -1;
    }

    status = sp1 + 1;
    if ((size_t)(data + line_len - status) < 3) {
        return -1;
    }
    if (!isdigit((unsigned char)status[0]) ||
        !isdigit((unsigned char)status[1]) ||
        !isdigit((unsigned char)status[2])) {
        return -1;
    }
    if ((size_t)(data + line_len - status) > 3 && ' ' != status[3]) {
        return -1;
    }

    msg->type = HTTP_RES;
    msg->status_code =
        (status[0] - '0') * 100 + (status[1] - '0') * 10 + (status[2] - '0');
    return 1;
}

static int parse_content_length_value(const uint8_t *data, size_t len,
                                      long long *out_value) {
    size_t    i;
    long long value;

    if (NULL == data || NULL == out_value) {
        return -1;
    }

    while (0 < len && (' ' == *data || '\t' == *data)) {
        data++;
        len--;
    }
    while (0 < len && (' ' == data[len - 1] || '\t' == data[len - 1])) {
        len--;
    }
    if (0 == len) {
        return -1;
    }

    value = 0;
    for (i = 0; i < len; i++) {
        if (!isdigit((unsigned char)data[i])) {
            return -1;
        }
        if (value > (LLONG_MAX - (long long)(data[i] - '0')) / 10LL) {
            return -1;
        }
        value = value * 10LL + (long long)(data[i] - '0');
    }

    *out_value = value;
    return 1;
}

static int header_value_has_chunked(const uint8_t *data, size_t len) {
    size_t i;

    if (NULL == data) {
        return 0;
    }

    i = 0;
    while (i < len) {
        size_t token_start;
        size_t token_end;

        while (i < len &&
               (',' == data[i] || ' ' == data[i] || '\t' == data[i])) {
            i++;
        }
        token_start = i;
        while (i < len && ',' != data[i]) {
            i++;
        }
        token_end = i;
        while (token_start < token_end &&
               (' ' == data[token_start] || '\t' == data[token_start])) {
            token_start++;
        }
        while (token_start < token_end &&
               (' ' == data[token_end - 1] || '\t' == data[token_end - 1])) {
            token_end--;
        }
        if (token_start < token_end &&
            bytes_equal_ci(data + token_start, token_end - token_start,
                           "chunked")) {
            return 1;
        }
    }

    return 1;
}

static int parse_headers(const uint8_t *data, size_t len, http_message_t *msg,
                         int *is_chunked) {
    size_t    pos;
    long long content_length;
    int       have_content_length;
    int       chunked;

    if (NULL == data || NULL == msg || NULL == is_chunked) {
        return -1;
    }

    msg->headers = dup_slice(data, len);
    if (NULL == msg->headers) {
        return -1;
    }

    pos                 = 0;
    content_length      = -1;
    have_content_length = 0;
    chunked             = 0;
    while (pos < len) {
        size_t line_len;
        size_t line_end;
        size_t line_pos;
        size_t colon_pos;

        line_end  = 0;
        line_pos  = 0;
        colon_pos = 0;

        {
            int ret;

            ret = find_crlf(data + pos, len - pos, &line_end);
            if (ret < 0) {
                return -1;
            }
            if (0 == ret) {
                line_len = len - pos;
                line_pos = len;
            } else {
                line_len = line_end;
                line_pos = pos + line_end + 2;
            }
        }
        if (0 == line_len) {
            return -1;
        }

        colon_pos = 0;
        while (colon_pos < line_len && ':' != data[pos + colon_pos]) {
            colon_pos++;
        }
        if (0 == colon_pos || colon_pos == line_len) {
            return -1;
        }

        if (bytes_equal_ci(data + pos, colon_pos, "Content-Length")) {
            long long parsed_length;

            if (parse_content_length_value(data + pos + colon_pos + 1,
                                           line_len - colon_pos - 1,
                                           &parsed_length) < 1) {
                return -1;
            }
            if (have_content_length && content_length != parsed_length) {
                return -1;
            }
            content_length      = parsed_length;
            have_content_length = 1;
        } else if (bytes_equal_ci(data + pos, colon_pos, "Transfer-Encoding")) {
            if (header_value_has_chunked(data + pos + colon_pos + 1,
                                         line_len - colon_pos - 1)) {
                chunked = 1;
            }
        }

        pos = line_pos;
    }

    msg->content_length = content_length;
    *is_chunked         = chunked;
    return 1;
}

static int decide_body_mode(const http_message_t *msg, int is_chunked) {
    if (NULL == msg) {
        return -1;
    }
    if (0 != is_chunked && 0 <= msg->content_length) {
        return -1;
    }
    if (0 != is_chunked) {
        return BODY_MODE_CHUNKED;
    }
    if (0 < msg->content_length) {
        return BODY_MODE_FIXED;
    }
    return BODY_MODE_NONE;
}

static int parse_fixed_body(const uint8_t *data, size_t len,
                            http_message_t *msg) {
    size_t body_len;

    if (NULL == data || NULL == msg) {
        return -1;
    }
    if (msg->content_length < 0) {
        msg->body     = NULL;
        msg->body_len = 0;
        return 1;
    }

    body_len = (size_t)msg->content_length;
    if (body_len > len) {
        return 0;
    }

    if (0 == body_len) {
        msg->body     = NULL;
        msg->body_len = 0;
        return 1;
    }

    msg->body = (uint8_t *)malloc(body_len);
    if (NULL == msg->body) {
        return -1;
    }

    memcpy(msg->body, data, body_len);
    msg->body_len = body_len;
    return 1;
}

static int parse_chunk_size(const uint8_t *data, size_t len, size_t *out_size) {
    size_t size_value;
    size_t i;
    int    saw_digit;

    if (NULL == data || NULL == out_size) {
        return -1;
    }

    size_value = 0;
    saw_digit  = 0;
    for (i = 0; i < len && ';' != data[i]; i++) {
        int digit;

        if (' ' == data[i] || '\t' == data[i]) {
            continue;
        }
        if (!isxdigit((unsigned char)data[i])) {
            return -1;
        }
        saw_digit = 1;
        if (isdigit((unsigned char)data[i])) {
            digit = data[i] - '0';
        } else {
            digit = 10 + tolower((unsigned char)data[i]) - 'a';
        }
        if (size_value > (SIZE_MAX - (size_t)digit) / 16U) {
            return -1;
        }
        size_value = size_value * 16U + (size_t)digit;
    }
    if (0 == saw_digit) {
        return -1;
    }

    *out_size = size_value;
    return 1;
}

static int chunked_body_append(uint8_t **body, size_t *body_len,
                               const uint8_t *chunk, size_t chunk_len) {
    uint8_t *new_body;

    if (NULL == body || NULL == body_len || (NULL == chunk && 0 < chunk_len)) {
        return -1;
    }
    if (0 == chunk_len) {
        return 1;
    }
    if (*body_len > SIZE_MAX - chunk_len) {
        return -1;
    }

    new_body = (uint8_t *)realloc(*body, *body_len + chunk_len);
    if (NULL == new_body) {
        return -1;
    }

    memcpy(new_body + *body_len, chunk, chunk_len);
    *body = new_body;
    *body_len += chunk_len;
    return 1;
}

static int parse_chunked_body(const uint8_t *data, size_t len,
                              http_message_t *msg) {
    size_t   pos;
    uint8_t *body;
    size_t   body_len;

    if (NULL == data || NULL == msg) {
        return -1;
    }

    pos      = 0;
    body     = NULL;
    body_len = 0;
    while (1) {
        size_t line_len;
        size_t chunk_size;

        {
            int ret;

            ret = find_crlf(data + pos, len - pos, &line_len);
            if (ret < 0) {
                free(body);
                return -1;
            }
            if (0 == ret) {
                free(body);
                return 0;
            }
        }
        if (parse_chunk_size(data + pos, line_len, &chunk_size) < 1) {
            free(body);
            return -1;
        }
        pos += line_len + 2;

        if (0 == chunk_size) {
            if (len - pos >= 2 && '\r' == data[pos] && '\n' == data[pos + 1]) {
                pos += 2;
                break;
            }
            {
                int ret;

                ret = find_header_end(data + pos, len - pos, &line_len);
                if (ret < 0) {
                    free(body);
                    return -1;
                }
                if (0 == ret) {
                    free(body);
                    return 0;
                }
            }
            pos += line_len + 4;
            break;
        }

        if (len - pos < chunk_size + 2) {
            free(body);
            return 0;
        }
        if ('\r' != data[pos + chunk_size] ||
            '\n' != data[pos + chunk_size + 1]) {
            free(body);
            return -1;
        }
        if (chunked_body_append(&body, &body_len, data + pos, chunk_size) < 1) {
            free(body);
            return -1;
        }

        pos += chunk_size + 2;
    }

    msg->body     = body;
    msg->body_len = body_len;
    return 1;
}

int http_parser_try(const uint8_t *data, size_t len, http_message_t *out) {
    size_t         start_line_len;
    size_t         header_end_pos;
    size_t         headers_off;
    size_t         headers_len;
    size_t         body_off;
    http_message_t tmp;
    int            is_chunked;
    int            body_mode;
    int            rc;
    int            ret;

    if (NULL == data || NULL == out) {
        return -1;
    }
    
    rc = http_message_init(&tmp);
    if (rc < 1) {
        return -1;
    }


    ret = find_header_end(data, len, &header_end_pos);
    if (ret == 0) {
        return 0;
    }
    if (ret < 0) {
        return -1;
    }

    ret = find_crlf(data, header_end_pos, &start_line_len);
    if (ret == 0) {
        return 0;
    }
    if (ret < 0) {
        return -1;
    }

    if (5 <= start_line_len && 0 == memcmp(data, "HTTP/", 5)) {
        rc = parse_status_line(data, start_line_len, &tmp);
    } else {
        rc = parse_request_line(data, start_line_len, &tmp);
    }
    if (rc < 1) {
        http_message_reset(&tmp);
        return -1;
    }

    headers_off = start_line_len + 2;
    headers_len = header_end_pos - headers_off;
    is_chunked  = 0;
    rc = parse_headers(data + headers_off, headers_len, &tmp, &is_chunked);
    if (rc < 1) {
        http_message_reset(&tmp);
        return -1;
    }

    body_mode = decide_body_mode(&tmp, is_chunked);
    if (body_mode < 0) {
        http_message_reset(&tmp);
        return -1;
    }

    body_off = header_end_pos + 4;
    if (BODY_MODE_NONE == body_mode) {
        tmp.body     = NULL;
        tmp.body_len = 0;
        *out         = tmp;
        return 1;
    }
    
    if (BODY_MODE_FIXED == body_mode) {
        rc = parse_fixed_body(data + body_off, len - body_off, &tmp);
    } else {
        rc = parse_chunked_body(data + body_off, len - body_off, &tmp);
    }

    if (rc < 0) {
        http_message_reset(&tmp);
        return -1;
    }
    if (0 == rc) {
        http_message_reset(&tmp);
        return 0;
    }

    *out = tmp;
    return 1;
}

int http_parser_free(http_message_t *msg) {
    return http_message_reset(msg);
}

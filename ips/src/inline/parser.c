#include "parser.h"

#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

enum { HTTP_PARSE_ERROR = -1, HTTP_PARSE_NEED_MORE = 0, HTTP_PARSE_OK = 1 };

static void http_request_init(http_request_t *req) {
    if (NULL == req) {
        return;
    }

    memset(req, 0, sizeof(*req));
    req->content_length = -1;
}

static void http_response_init(http_response_t *resp) {
    if (NULL == resp) {
        return;
    }

    memset(resp, 0, sizeof(*resp));
    resp->content_length = -1;
}

static void http_request_free(http_request_t *req) {
    if (NULL == req) {
        return;
    }

    free(req->method);
    free(req->uri);
    free(req->headers);
    free(req->body);
    http_request_init(req);
}

static void http_response_free(http_response_t *resp) {
    if (NULL == resp) {
        return;
    }

    free(resp->headers);
    free(resp->body);
    http_response_init(resp);
}

static void node_list_clear_parsed(node_list_t *list) {
    if (NULL == list) {
        return;
    }

    http_request_free(&list->parsed_request);
    http_response_free(&list->parsed_response);
    list->has_parsed_http   = 0;
    list->parsed_is_request = 0;
}

static int bytes_find_crlf(const uint8_t *data, size_t len, size_t *out_pos) {
    size_t i;

    if (NULL == data || NULL == out_pos) {
        return 0;
    }

    for (i = 0; i + 1 < len; i++) {
        if ('\r' == data[i] && '\n' == data[i + 1]) {
            *out_pos = i;
            return 1;
        }
    }

    return 0;
}

static int bytes_find_header_end(const uint8_t *data, size_t len,
                                 size_t *out_pos) {
    size_t i;

    if (NULL == data || NULL == out_pos) {
        return 0;
    }

    for (i = 0; i + 3 < len; i++) {
        if ('\r' == data[i] && '\n' == data[i + 1] && '\r' == data[i + 2] &&
            '\n' == data[i + 3]) {
            *out_pos = i;
            return 1;
        }
    }

    return 0;
}

static char *dup_cstring(const uint8_t *data, size_t len) {
    char *copy;

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

static int ascii_equal_ci_char(uint8_t a, char b) {
    return tolower((unsigned char)a) == tolower((unsigned char)b);
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
        if (!ascii_equal_ci_char(data[i], text[i])) {
            return 0;
        }
    }

    return '\0' == text[len];
}

static int parse_content_length_value(const uint8_t *data, size_t len,
                                      long long *out_value) {
    size_t    i;
    long long value;

    if (NULL == data || NULL == out_value) {
        return HTTP_PARSE_ERROR;
    }

    while (0 < len && (' ' == *data || '\t' == *data)) {
        data++;
        len--;
    }
    while (0 < len && (' ' == data[len - 1] || '\t' == data[len - 1])) {
        len--;
    }
    if (0 == len) {
        return HTTP_PARSE_ERROR;
    }

    value = 0;
    for (i = 0; i < len; i++) {
        if (!isdigit((unsigned char)data[i])) {
            return HTTP_PARSE_ERROR;
        }
        if (value > (LLONG_MAX - (long long)(data[i] - '0')) / 10LL) {
            return HTTP_PARSE_ERROR;
        }
        value = value * 10LL + (long long)(data[i] - '0');
    }

    *out_value = value;
    return HTTP_PARSE_OK;
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

    return 0;
}

static int parse_headers_meta(const uint8_t *data, size_t len,
                              char **out_headers, long long *out_content_length,
                              int *out_chunked) {
    size_t    pos;
    char     *headers_copy;
    long long content_length;
    int       have_content_length;
    int       chunked;

    if (NULL == out_headers || NULL == out_content_length ||
        NULL == out_chunked) {
        return HTTP_PARSE_ERROR;
    }

    headers_copy = dup_cstring(data, len);
    if (NULL == headers_copy) {
        return HTTP_PARSE_ERROR;
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

        if (bytes_find_crlf(data + pos, len - pos, &line_end)) {
            line_len = line_end;
            line_pos = pos + line_end + 2;
        } else {
            line_len = len - pos;
            line_pos = len;
        }
        if (0 == line_len) {
            free(headers_copy);
            return HTTP_PARSE_ERROR;
        }

        colon_pos = 0;
        while (colon_pos < line_len && ':' != data[pos + colon_pos]) {
            colon_pos++;
        }
        if (0 == colon_pos || colon_pos == line_len) {
            free(headers_copy);
            return HTTP_PARSE_ERROR;
        }

        if (bytes_equal_ci(data + pos, colon_pos, "Content-Length")) {
            long long parsed_length;
            int       rc;

            rc = parse_content_length_value(data + pos + colon_pos + 1,
                                            line_len - colon_pos - 1,
                                            &parsed_length);
            if (HTTP_PARSE_OK != rc) {
                free(headers_copy);
                return HTTP_PARSE_ERROR;
            }
            if (have_content_length && content_length != parsed_length) {
                free(headers_copy);
                return HTTP_PARSE_ERROR;
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

    *out_headers        = headers_copy;
    *out_content_length = content_length;
    *out_chunked        = chunked;
    return HTTP_PARSE_OK;
}

static int body_copy(const uint8_t *data, size_t len, uint8_t **out_body) {
    uint8_t *copy;

    if (NULL == out_body) {
        return HTTP_PARSE_ERROR;
    }

    if (0 == len) {
        *out_body = NULL;
        return HTTP_PARSE_OK;
    }

    copy = (uint8_t *)malloc(len);
    if (NULL == copy) {
        return HTTP_PARSE_ERROR;
    }

    memcpy(copy, data, len);
    *out_body = copy;
    return HTTP_PARSE_OK;
}

static int chunked_body_append(uint8_t **body, size_t *body_len,
                               const uint8_t *chunk, size_t chunk_len) {
    uint8_t *new_body;

    if (NULL == body || NULL == body_len || (NULL == chunk && 0 < chunk_len)) {
        return HTTP_PARSE_ERROR;
    }
    if (0 == chunk_len) {
        return HTTP_PARSE_OK;
    }
    if (*body_len > SIZE_MAX - chunk_len) {
        return HTTP_PARSE_ERROR;
    }

    new_body = (uint8_t *)realloc(*body, *body_len + chunk_len);
    if (NULL == new_body) {
        return HTTP_PARSE_ERROR;
    }

    memcpy(new_body + *body_len, chunk, chunk_len);
    *body = new_body;
    *body_len += chunk_len;
    return HTTP_PARSE_OK;
}

static int parse_chunk_size_line(const uint8_t *data, size_t len,
                                 size_t *out_size) {
    size_t size_value;
    size_t i;
    int    saw_digit;

    if (NULL == data || NULL == out_size) {
        return HTTP_PARSE_ERROR;
    }

    size_value = 0;
    saw_digit  = 0;
    i          = 0;
    while (i < len && ';' != data[i]) {
        int digit;

        if (' ' == data[i] || '\t' == data[i]) {
            i++;
            continue;
        }
        digit = isxdigit((unsigned char)data[i]);
        if (0 == digit) {
            return HTTP_PARSE_ERROR;
        }
        saw_digit = 1;
        if (isdigit((unsigned char)data[i])) {
            digit = data[i] - '0';
        } else {
            digit = 10 + tolower((unsigned char)data[i]) - 'a';
        }
        if (size_value > (SIZE_MAX - (size_t)digit) / 16U) {
            return HTTP_PARSE_ERROR;
        }
        size_value = size_value * 16U + (size_t)digit;
        i++;
    }
    if (0 == saw_digit) {
        return HTTP_PARSE_ERROR;
    }

    *out_size = size_value;
    return HTTP_PARSE_OK;
}

static int parse_chunked_body(const uint8_t *data, size_t len,
                              uint8_t **out_body, size_t *out_body_len) {
    size_t   pos;
    uint8_t *body;
    size_t   body_len;

    if (NULL == out_body || NULL == out_body_len) {
        return HTTP_PARSE_ERROR;
    }

    pos      = 0;
    body     = NULL;
    body_len = 0;
    while (1) {
        size_t line_len;
        size_t chunk_size;
        int    rc;

        if (!bytes_find_crlf(data + pos, len - pos, &line_len)) {
            free(body);
            return HTTP_PARSE_NEED_MORE;
        }

        rc = parse_chunk_size_line(data + pos, line_len, &chunk_size);
        if (HTTP_PARSE_OK != rc) {
            free(body);
            return HTTP_PARSE_ERROR;
        }
        pos += line_len + 2;

        if (0 == chunk_size) {
            if (len - pos >= 2 && '\r' == data[pos] && '\n' == data[pos + 1]) {
                pos += 2;
                break;
            }

            if (!bytes_find_header_end(data + pos, len - pos, &line_len)) {
                free(body);
                return HTTP_PARSE_NEED_MORE;
            }

            pos += line_len + 4;
            break;
        }

        if (len - pos < chunk_size + 2) {
            free(body);
            return HTTP_PARSE_NEED_MORE;
        }
        if ('\r' != data[pos + chunk_size] ||
            '\n' != data[pos + chunk_size + 1]) {
            free(body);
            return HTTP_PARSE_ERROR;
        }

        rc = chunked_body_append(&body, &body_len, data + pos, chunk_size);
        if (HTTP_PARSE_OK != rc) {
            free(body);
            return HTTP_PARSE_ERROR;
        }
        pos += chunk_size + 2;
    }

    *out_body     = body;
    *out_body_len = body_len;
    return HTTP_PARSE_OK;
}

static int http_parse_request(const uint8_t *data, size_t len,
                              http_request_t *out_req) {
    size_t         header_end_pos;
    size_t         start_line_len;
    size_t         body_off;
    size_t         headers_off;
    size_t         headers_len;
    const uint8_t *sp1;
    const uint8_t *sp2;
    http_request_t req;
    int            chunked;
    int            rc;

    if (NULL == data || NULL == out_req) {
        return HTTP_PARSE_ERROR;
    }
    if (!bytes_find_header_end(data, len, &header_end_pos)) {
        return HTTP_PARSE_NEED_MORE;
    }
    if (!bytes_find_crlf(data, header_end_pos, &start_line_len)) {
        return HTTP_PARSE_ERROR;
    }
    if (0 == start_line_len ||
        (5 <= start_line_len && 0 == memcmp(data, "HTTP/", 5))) {
        return HTTP_PARSE_ERROR;
    }

    sp1 = memchr(data, ' ', start_line_len);
    if (NULL == sp1) {
        return HTTP_PARSE_ERROR;
    }
    sp2 = memchr(sp1 + 1, ' ', (size_t)(data + start_line_len - (sp1 + 1)));
    if (NULL == sp2 || sp1 == data || sp2 == sp1 + 1) {
        return HTTP_PARSE_ERROR;
    }
    if ((size_t)(data + start_line_len - (sp2 + 1)) < 5 ||
        0 != memcmp(sp2 + 1, "HTTP/", 5)) {
        return HTTP_PARSE_ERROR;
    }

    http_request_init(&req);
    req.method = dup_cstring(data, (size_t)(sp1 - data));
    req.uri    = dup_cstring(sp1 + 1, (size_t)(sp2 - (sp1 + 1)));
    if (NULL == req.method || NULL == req.uri) {
        http_request_free(&req);
        return HTTP_PARSE_ERROR;
    }

    headers_off = start_line_len + 2;
    headers_len = header_end_pos - headers_off;
    rc = parse_headers_meta(data + headers_off, headers_len, &req.headers,
                            &req.content_length, &chunked);
    if (HTTP_PARSE_OK != rc) {
        http_request_free(&req);
        return HTTP_PARSE_ERROR;
    }
    if (0 != chunked && 0 <= req.content_length) {
        http_request_free(&req);
        return HTTP_PARSE_ERROR;
    }

    body_off = header_end_pos + 4;
    if (0 <= req.content_length) {
        size_t body_len;

        body_len = (size_t)req.content_length;
        if (body_len > len - body_off) {
            http_request_free(&req);
            return HTTP_PARSE_NEED_MORE;
        }
        rc = body_copy(data + body_off, body_len, &req.body);
        if (HTTP_PARSE_OK != rc) {
            http_request_free(&req);
            return HTTP_PARSE_ERROR;
        }
        req.body_len = body_len;
    } else if (chunked) {
        rc = parse_chunked_body(data + body_off, len - body_off, &req.body,
                                &req.body_len);
        if (HTTP_PARSE_OK != rc) {
            http_request_free(&req);
            return rc;
        }
    }

    *out_req = req;
    return HTTP_PARSE_OK;
}

static int http_parse_response(const uint8_t *data, size_t len,
                               http_response_t *out_resp) {
    size_t          header_end_pos;
    size_t          start_line_len;
    size_t          body_off;
    size_t          headers_off;
    size_t          headers_len;
    const uint8_t  *sp1;
    const uint8_t  *status_ptr;
    http_response_t resp;
    long long       content_length;
    int             chunked;
    int             rc;

    if (NULL == data || NULL == out_resp) {
        return HTTP_PARSE_ERROR;
    }
    if (!bytes_find_header_end(data, len, &header_end_pos)) {
        return HTTP_PARSE_NEED_MORE;
    }
    if (!bytes_find_crlf(data, header_end_pos, &start_line_len)) {
        return HTTP_PARSE_ERROR;
    }
    if (start_line_len < 8 || 0 != memcmp(data, "HTTP/", 5)) {
        return HTTP_PARSE_ERROR;
    }

    sp1 = memchr(data, ' ', start_line_len);
    if (NULL == sp1) {
        return HTTP_PARSE_ERROR;
    }
    status_ptr = sp1 + 1;
    if ((size_t)(data + start_line_len - status_ptr) < 3) {
        return HTTP_PARSE_ERROR;
    }
    if (!isdigit((unsigned char)status_ptr[0]) ||
        !isdigit((unsigned char)status_ptr[1]) ||
        !isdigit((unsigned char)status_ptr[2])) {
        return HTTP_PARSE_ERROR;
    }
    if ((size_t)(data + start_line_len - status_ptr) > 3 &&
        ' ' != status_ptr[3]) {
        return HTTP_PARSE_ERROR;
    }

    http_response_init(&resp);
    resp.status_code = (status_ptr[0] - '0') * 100 +
                       (status_ptr[1] - '0') * 10 + (status_ptr[2] - '0');

    headers_off = start_line_len + 2;
    headers_len = header_end_pos - headers_off;
    rc = parse_headers_meta(data + headers_off, headers_len, &resp.headers,
                            &content_length, &chunked);
    if (HTTP_PARSE_OK != rc) {
        http_response_free(&resp);
        return HTTP_PARSE_ERROR;
    }
    resp.content_length = content_length;
    if (0 != chunked && 0 <= resp.content_length) {
        http_response_free(&resp);
        return HTTP_PARSE_ERROR;
    }

    body_off = header_end_pos + 4;
    if (0 <= resp.content_length) {
        size_t body_len;

        body_len = (size_t)resp.content_length;
        if (body_len > len - body_off) {
            http_response_free(&resp);
            return HTTP_PARSE_NEED_MORE;
        }
        rc = body_copy(data + body_off, body_len, &resp.body);
        if (HTTP_PARSE_OK != rc) {
            http_response_free(&resp);
            return HTTP_PARSE_ERROR;
        }
        resp.body_len = body_len;
    } else if (chunked) {
        rc = parse_chunked_body(data + body_off, len - body_off, &resp.body,
                                &resp.body_len);
        if (HTTP_PARSE_OK != rc) {
            http_response_free(&resp);
            return rc;
        }
    }

    *out_resp = resp;
    return HTTP_PARSE_OK;
}

static int http_parse_buffer(const uint8_t *data, size_t len, int *is_request,
                             http_request_t  *out_req,
                             http_response_t *out_resp) {
    if (NULL == data || NULL == is_request || NULL == out_req ||
        NULL == out_resp) {
        return HTTP_PARSE_ERROR;
    }

    if (5 <= len && 0 == memcmp(data, "HTTP/", 5)) {
        *is_request = 0;
        return http_parse_response(data, len, out_resp);
    }

    *is_request = 1;
    return http_parse_request(data, len, out_req);
}

int node_list_init(node_list_t *list) {
    if (NULL == list) {
        return -1;
    }

    memset(list, 0, sizeof(*list));
    http_request_init(&list->parsed_request);
    http_response_init(&list->parsed_response);
    return 0;
}

int node_list_append(node_list_t *list, const uint8_t *data, size_t len) {
    tcp_node_t *node;

    if (NULL == list || NULL == data || 0 == len) {
        return -1;
    }

    node = (tcp_node_t *)malloc(sizeof(*node));
    if (NULL == node) {
        return -1;
    }
    node->data = (uint8_t *)malloc(len);
    if (NULL == node->data) {
        free(node);
        return -1;
    }

    memcpy(node->data, data, len);
    node->len    = len;
    node->offset = 0;
    node->next   = NULL;

    if (NULL != list->tail) {
        list->tail->next = node;
    } else {
        list->head = node;
    }
    list->tail = node;
    return 0;
}

int node_list_try_parser(node_list_t *list) {
    tcp_node_t *node;
    uint8_t    *assembled;
    size_t      assembled_len;

    if (NULL == list) {
        return -1;
    }
    if (0 != list->has_parsed_http) {
        return 1;
    }

    assembled     = NULL;
    assembled_len = 0;
    for (node = list->head; NULL != node; node = node->next) {
        size_t          node_len;
        uint8_t        *new_buf;
        http_request_t  req;
        http_response_t resp;
        int             is_request;
        int             rc;

        if (node->offset > node->len) {
            free(assembled);
            return -1;
        }

        node_len = node->len - node->offset;
        if (0 == node_len) {
            continue;
        }
        if (assembled_len > SIZE_MAX - node_len) {
            free(assembled);
            return -1;
        }

        new_buf = (uint8_t *)realloc(assembled, assembled_len + node_len);
        if (NULL == new_buf) {
            free(assembled);
            return -1;
        }
        assembled = new_buf;
        memcpy(assembled + assembled_len, node->data + node->offset, node_len);
        assembled_len += node_len;

        http_request_init(&req);
        http_response_init(&resp);
        is_request = 0;
        rc = http_parse_buffer(assembled, assembled_len, &is_request, &req,
                               &resp);
        if (HTTP_PARSE_OK == rc) {
            node_list_clear_parsed(list);
            list->has_parsed_http   = 1;
            list->parsed_is_request = is_request;
            list->parsed_request    = req;
            list->parsed_response   = resp;
            free(assembled);
            return 1;
        }
        if (HTTP_PARSE_ERROR == rc) {
            http_request_free(&req);
            http_response_free(&resp);
            free(assembled);
            return -1;
        }

        http_request_free(&req);
        http_response_free(&resp);
    }

    free(assembled);
    return 0;
}

int node_list_free(node_list_t *list) {
    tcp_node_t *cur;

    if (NULL == list) {
        return 0;
    }

    cur = list->head;
    while (NULL != cur) {
        tcp_node_t *next;

        next = cur->next;
        free(cur->data);
        free(cur);
        cur = next;
    }

    node_list_clear_parsed(list);
    list->head = NULL;
    list->tail = NULL;
    return 0;
}

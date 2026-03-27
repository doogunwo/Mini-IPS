#include "normalization.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

static int copy_text(char *dst, size_t dst_sz, const char *src) {
    size_t len;

    if (NULL == dst || NULL == src || 0U == dst_sz) {
        return -1;
    }

    len = strlen(src);
    if (len + 1U > dst_sz) {
        return -1;
    }

    memcpy(dst, src, len + 1U);
    return 1;
}

static int finalize_text_result(char *dst, const char *src) {
    if (NULL == dst || NULL == src) {
        return -1;
    }
    return 0 == strcmp(dst, src) ? 0 : 1;
}

static int normalize_lowercase_core(char *dst, size_t dst_sz, const char *src) {
    size_t i;
    size_t len;

    if (copy_text(dst, dst_sz, src) < 0) {
        return -1;
    }

    len = strlen(dst);
    for (i = 0; i < len; i++) {
        dst[i] = (char)tolower((unsigned char)dst[i]);
    }

    return finalize_text_result(dst, src);
}

static int normalize_spaces_core(char *dst, size_t dst_sz, const char *src) {
    size_t i;
    size_t j;
    int    in_space;

    if (NULL == dst || NULL == src || 0U == dst_sz) {
        return -1;
    }

    i = 0;
    while ('\0' != src[i] && isspace((unsigned char)src[i])) {
        i++;
    }

    j        = 0;
    in_space = 0;
    while ('\0' != src[i]) {
        if (isspace((unsigned char)src[i])) {
            in_space = 1;
        } else {
            if (in_space && 0U < j) {
                if (j + 1U >= dst_sz) {
                    return -1;
                }
                dst[j++] = ' ';
            }
            if (j + 1U >= dst_sz) {
                return -1;
            }
            dst[j++] = src[i];
            in_space = 0;
        }
        i++;
    }

    if (j >= dst_sz) {
        return -1;
    }
    dst[j] = '\0';
    return finalize_text_result(dst, src);
}

static int normalize_line_endings_core(char *dst, size_t dst_sz,
                                       const char *src) {
    size_t i;
    size_t j;

    if (NULL == dst || NULL == src || 0U == dst_sz) {
        return -1;
    }

    i = 0;
    j = 0;
    while ('\0' != src[i]) {
        if ('\r' == src[i]) {
            if (j + 1U >= dst_sz) {
                return -1;
            }
            dst[j++] = '\n';
            if ('\n' == src[i + 1]) {
                i++;
            }
        } else {
            if (j + 1U >= dst_sz) {
                return -1;
            }
            dst[j++] = src[i];
        }
        i++;
    }

    dst[j] = '\0';
    return finalize_text_result(dst, src);
}

static int normalize_slashes_core(char *dst, size_t dst_sz, const char *src) {
    size_t i;
    size_t j;
    int    prev_slash;

    if (NULL == dst || NULL == src || 0U == dst_sz) {
        return -1;
    }

    i          = 0;
    j          = 0;
    prev_slash = 0;
    while ('\0' != src[i]) {
        char c;

        c = src[i];
        if ('\\' == c) {
            c = '/';
        }
        if ('/' == c) {
            if (prev_slash) {
                i++;
                continue;
            }
            prev_slash = 1;
        } else {
            prev_slash = 0;
        }

        if (j + 1U >= dst_sz) {
            return -1;
        }
        dst[j++] = c;
        i++;
    }

    dst[j] = '\0';
    return finalize_text_result(dst, src);
}

static int remove_dot_segments_core(char *dst, size_t dst_sz, const char *src) {
    char  *tmp;
    char **segments;
    size_t seg_count;
    size_t i;
    size_t src_len;
    size_t out_len;
    int    absolute;
    int    trailing_slash;

    if (NULL == dst || NULL == src || 0U == dst_sz) {
        return -1;
    }

    src_len  = strlen(src);
    tmp      = (char *)malloc(src_len + 1U);
    segments = (char **)malloc((src_len + 1U) * sizeof(*segments));
    if (NULL == tmp || NULL == segments) {
        free(tmp);
        free(segments);
        return -1;
    }

    memcpy(tmp, src, src_len + 1U);
    absolute       = ('/' == src[0]);
    trailing_slash = (0U < src_len && '/' == src[src_len - 1U]);
    seg_count      = 0;

    {
        char *p;

        p = tmp;
        while (1) {
            char *start;
            char *slash;

            while ('/' == *p) {
                p++;
            }
            if ('\0' == *p) {
                break;
            }
            start = p;
            slash = strchr(p, '/');
            if (NULL != slash) {
                *slash = '\0';
                p      = slash + 1;
            } else {
                p = start + strlen(start);
            }

            if (0 == strcmp(start, ".")) {
                continue;
            }
            if (0 == strcmp(start, "..")) {
                if (0U < seg_count) {
                    seg_count--;
                }
                continue;
            }

            segments[seg_count++] = start;
            if ('\0' == *p) {
                break;
            }
        }
    }

    out_len = 0;
    if (absolute) {
        if (out_len + 1U >= dst_sz) {
            free(tmp);
            free(segments);
            return -1;
        }
        dst[out_len++] = '/';
    }

    for (i = 0; i < seg_count; i++) {
        size_t seg_len;

        seg_len = strlen(segments[i]);
        if (0U < i || (absolute && 1U < out_len)) {
            if (out_len + 1U >= dst_sz) {
                free(tmp);
                free(segments);
                return -1;
            }
            dst[out_len++] = '/';
        }
        if (!absolute && 0U < i) {
            dst[out_len - 1U] = '/';
        }
        if (out_len + seg_len >= dst_sz) {
            free(tmp);
            free(segments);
            return -1;
        }
        memcpy(dst + out_len, segments[i], seg_len);
        out_len += seg_len;
    }

    if (!absolute && 0U == seg_count) {
        if (dst_sz < 2U) {
            free(tmp);
            free(segments);
            return -1;
        }
        dst[0] = '\0';
        free(tmp);
        free(segments);
        return finalize_text_result(dst, src);
    }

    if (trailing_slash && 0U < out_len && '/' != dst[out_len - 1U]) {
        if (out_len + 1U >= dst_sz) {
            free(tmp);
            free(segments);
            return -1;
        }
        dst[out_len++] = '/';
    }

    dst[out_len] = '\0';
    free(tmp);
    free(segments);
    return finalize_text_result(dst, src);
}

static int body_copy(const uint8_t *src, size_t src_len, uint8_t *dst,
                     size_t dst_sz, size_t *out_len) {
    if (NULL == src || NULL == dst || NULL == out_len) {
        return -1;
    }
    if (dst_sz < src_len) {
        return -1;
    }

    memcpy(dst, src, src_len);
    *out_len = src_len;
    return 1;
}

int http_normalize_uri(char *dst, size_t dst_sz, const char *src) {
    char  *path_buf;
    char  *query_buf;
    size_t src_len;
    size_t prefix_len;
    size_t path_len;
    size_t query_len;
    size_t slash_off;
    size_t query_off;
    char  *query_ptr;
    int    absolute_uri;
    int    rc;

    if (NULL == dst || NULL == src || 0U == dst_sz) {
        return -1;
    }

    src_len   = strlen(src);
    path_buf  = (char *)malloc(dst_sz);
    query_buf = (char *)malloc(dst_sz);
    if (NULL == path_buf || NULL == query_buf) {
        free(path_buf);
        free(query_buf);
        return -1;
    }

    absolute_uri = 0;
    prefix_len   = 0;
    slash_off    = 0;
    query_off    = src_len;
    if (NULL != strstr(src, "://")) {
        const char *scheme_end;
        const char *path_start;
        const char *query_start;

        absolute_uri = 1;
        scheme_end   = strstr(src, "://") + 3;
        path_start   = strchr(scheme_end, '/');
        query_start  = strchr(scheme_end, '?');
        if (NULL != query_start &&
            (NULL == path_start || query_start < path_start)) {
            path_start = query_start;
        }
        if (NULL == path_start) {
            path_start = src + src_len;
        }
        prefix_len = (size_t)(path_start - src);
        slash_off  = prefix_len;
    }
    if (0U == prefix_len) {
        slash_off = 0;
    }

    query_ptr = strchr(src + slash_off, '?');
    if (NULL != query_ptr) {
        query_off = (size_t)(query_ptr - src);
    }
    path_len  = query_off - slash_off;
    query_len = src_len - query_off;

    if (path_len + 1U > dst_sz) {
        free(path_buf);
        free(query_buf);
        return -1;
    }
    memcpy(path_buf, src + slash_off, path_len);
    path_buf[path_len] = '\0';

    rc = http_normalize_path(path_buf, dst_sz, path_buf);
    if (rc < 0) {
        free(path_buf);
        free(query_buf);
        return -1;
    }

    if (0U < query_len) {
        rc = http_normalize_query(query_buf, dst_sz, src + query_off);
        if (rc < 0) {
            free(path_buf);
            free(query_buf);
            return -1;
        }
    } else {
        query_buf[0] = '\0';
    }

    if (absolute_uri) {
        if (prefix_len + strlen(path_buf) + strlen(query_buf) + 1U > dst_sz) {
            free(path_buf);
            free(query_buf);
            return -1;
        }
        memcpy(dst, src, prefix_len);
        dst[prefix_len] = '\0';
        strcat(dst, path_buf);
        strcat(dst, query_buf);
    } else {
        if (strlen(path_buf) + strlen(query_buf) + 1U > dst_sz) {
            free(path_buf);
            free(query_buf);
            return -1;
        }
        strcpy(dst, path_buf);
        strcat(dst, query_buf);
    }

    free(path_buf);
    free(query_buf);
    return finalize_text_result(dst, src);
}

int http_normalize_path(char *dst, size_t dst_sz, const char *src) {
    char *tmp;
    int   rc;

    if (NULL == dst || NULL == src || 0U == dst_sz) {
        return -1;
    }

    tmp = (char *)malloc(dst_sz);
    if (NULL == tmp) {
        return -1;
    }

    rc = http_normalize_slashes(tmp, dst_sz, src);
    if (rc < 0) {
        free(tmp);
        return -1;
    }

    rc = http_remove_dot_segments(dst, dst_sz, tmp);
    free(tmp);
    return rc;
}

int http_normalize_query(char *dst, size_t dst_sz, const char *src) {
    return http_normalize_spaces(dst, dst_sz, src);
}

int http_normalize_header_name(char *dst, size_t dst_sz, const char *src) {
    char *tmp;
    int   rc;

    if (NULL == dst || NULL == src || 0U == dst_sz) {
        return -1;
    }

    tmp = (char *)malloc(dst_sz);
    if (NULL == tmp) {
        return -1;
    }

    rc = http_normalize_spaces(tmp, dst_sz, src);
    if (rc < 0) {
        free(tmp);
        return -1;
    }

    rc = http_normalize_lowercase(dst, dst_sz, tmp);
    free(tmp);
    return rc;
}

int http_normalize_host(char *dst, size_t dst_sz, const char *src) {
    char  *tmp;
    size_t len;
    int    rc;

    if (NULL == dst || NULL == src || 0U == dst_sz) {
        return -1;
    }

    tmp = (char *)malloc(dst_sz);
    if (NULL == tmp) {
        return -1;
    }

    rc = http_normalize_spaces(tmp, dst_sz, src);
    if (rc < 0) {
        free(tmp);
        return -1;
    }

    len = strlen(tmp);
    if (0U < len && '.' == tmp[len - 1U]) {
        tmp[len - 1U] = '\0';
    }

    rc = http_normalize_lowercase(dst, dst_sz, tmp);
    free(tmp);
    return rc;
}

int http_normalize_slashes(char *dst, size_t dst_sz, const char *src) {
    return normalize_slashes_core(dst, dst_sz, src);
}

int http_remove_dot_segments(char *dst, size_t dst_sz, const char *src) {
    return remove_dot_segments_core(dst, dst_sz, src);
}

int http_normalize_spaces(char *dst, size_t dst_sz, const char *src) {
    return normalize_spaces_core(dst, dst_sz, src);
}

int http_normalize_line_endings(char *dst, size_t dst_sz, const char *src) {
    return normalize_line_endings_core(dst, dst_sz, src);
}

int http_normalize_lowercase(char *dst, size_t dst_sz, const char *src) {
    return normalize_lowercase_core(dst, dst_sz, src);
}

int http_body_normalize_spaces(uint8_t *dst, size_t dst_sz, const uint8_t *src,
                               size_t src_len, size_t *out_len) {
    size_t i;
    size_t j;
    int    in_space;
    int    changed;

    if (NULL == dst || NULL == src || NULL == out_len) {
        return -1;
    }

    i = 0;
    while (i < src_len && isspace((unsigned char)src[i])) {
        i++;
    }

    j        = 0;
    in_space = 0;
    changed  = 0;
    while (i < src_len) {
        if (isspace((unsigned char)src[i])) {
            in_space = 1;
            changed  = 1;
        } else {
            if (in_space && 0U < j) {
                if (j >= dst_sz) {
                    return -1;
                }
                dst[j++] = ' ';
            }
            if (j >= dst_sz) {
                return -1;
            }
            dst[j++] = src[i];
            in_space = 0;
        }
        i++;
    }

    *out_len = j;
    if (!changed && j == src_len && 0 == memcmp(dst, src, src_len)) {
        return 0;
    }
    return 1;
}

int http_body_normalize_line_endings(uint8_t *dst, size_t dst_sz,
                                     const uint8_t *src, size_t src_len,
                                     size_t *out_len) {
    size_t i;
    size_t j;
    int    changed;

    if (NULL == dst || NULL == src || NULL == out_len) {
        return -1;
    }

    i       = 0;
    j       = 0;
    changed = 0;
    while (i < src_len) {
        if ('\r' == src[i]) {
            if (j >= dst_sz) {
                return -1;
            }
            dst[j++] = '\n';
            changed  = 1;
            if (i + 1U < src_len && '\n' == src[i + 1U]) {
                i++;
            }
        } else {
            if (j >= dst_sz) {
                return -1;
            }
            dst[j++] = src[i];
        }
        i++;
    }

    *out_len = j;
    if (!changed && j == src_len && 0 == memcmp(dst, src, src_len)) {
        return 0;
    }
    return 1;
}

int http_body_normalize_lowercase(uint8_t *dst, size_t dst_sz,
                                  const uint8_t *src, size_t src_len,
                                  size_t *out_len) {
    size_t i;
    int    changed;

    if (body_copy(src, src_len, dst, dst_sz, out_len) < 0) {
        return -1;
    }

    changed = 0;
    for (i = 0; i < src_len; i++) {
        uint8_t lower;

        lower = (uint8_t)tolower((unsigned char)dst[i]);
        if (lower != dst[i]) {
            dst[i]  = lower;
            changed = 1;
        }
    }

    return changed ? 1 : 0;
}

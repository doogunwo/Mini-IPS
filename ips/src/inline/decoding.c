#include "decoding.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

static int hex_value(unsigned char c) {
    if ('0' <= c && c <= '9') {
        return c - '0';
    }
    if ('a' <= c && c <= 'f') {
        return 10 + (c - 'a');
    }
    if ('A' <= c && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

static int utf8_encode(uint32_t cp, uint8_t *dst, size_t dst_sz,
                       size_t *out_len) {
    if (NULL == dst || NULL == out_len) {
        return -1;
    }

    if (cp <= 0x7FU) {
        if (dst_sz < 1U) {
            return -1;
        }
        dst[0]   = (uint8_t)cp;
        *out_len = 1U;
        return 1;
    }
    if (cp <= 0x7FFU) {
        if (dst_sz < 2U) {
            return -1;
        }
        dst[0]   = (uint8_t)(0xC0U | (cp >> 6));
        dst[1]   = (uint8_t)(0x80U | (cp & 0x3FU));
        *out_len = 2U;
        return 1;
    }
    if (cp <= 0xFFFFU) {
        if (dst_sz < 3U) {
            return -1;
        }
        dst[0]   = (uint8_t)(0xE0U | (cp >> 12));
        dst[1]   = (uint8_t)(0x80U | ((cp >> 6) & 0x3FU));
        dst[2]   = (uint8_t)(0x80U | (cp & 0x3FU));
        *out_len = 3U;
        return 1;
    }
    if (cp <= 0x10FFFFU) {
        if (dst_sz < 4U) {
            return -1;
        }
        dst[0]   = (uint8_t)(0xF0U | (cp >> 18));
        dst[1]   = (uint8_t)(0x80U | ((cp >> 12) & 0x3FU));
        dst[2]   = (uint8_t)(0x80U | ((cp >> 6) & 0x3FU));
        dst[3]   = (uint8_t)(0x80U | (cp & 0x3FU));
        *out_len = 4U;
        return 1;
    }

    return -1;
}

static int decode_percent_core(uint8_t *dst, size_t dst_sz, const uint8_t *src,
                               size_t src_len, size_t *out_len) {
    size_t i;
    size_t j;
    int    changed;

    if (NULL == dst || NULL == src || NULL == out_len) {
        return -1;
    }

    j       = 0;
    changed = 0;
    for (i = 0; i < src_len; i++) {
        if ('%' == src[i]) {
            int hi;
            int lo;

            if (i + 2 >= src_len) {
                return -1;
            }
            hi = hex_value(src[i + 1]);
            lo = hex_value(src[i + 2]);
            if (hi < 0 || lo < 0) {
                return -1;
            }
            if (j >= dst_sz) {
                return -1;
            }
            dst[j++] = (uint8_t)((hi << 4) | lo);
            i += 2;
            changed = 1;
            continue;
        }

        if (j >= dst_sz) {
            return -1;
        }
        dst[j++] = src[i];
    }

    *out_len = j;
    return changed ? 1 : 0;
}

static int decode_plus_core(uint8_t *dst, size_t dst_sz, const uint8_t *src,
                            size_t src_len, size_t *out_len) {
    size_t i;
    int    changed;

    if (NULL == dst || NULL == src || NULL == out_len) {
        return -1;
    }
    if (dst_sz < src_len) {
        return -1;
    }

    changed = 0;
    for (i = 0; i < src_len; i++) {
        if ('+' == src[i]) {
            dst[i]  = ' ';
            changed = 1;
        } else {
            dst[i] = src[i];
        }
    }

    *out_len = src_len;
    return changed ? 1 : 0;
}

static int decode_html_entity_core(uint8_t *dst, size_t dst_sz,
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
        if ('&' == src[i]) {
            size_t k;

            k = i + 1U;
            while (k < src_len && ';' != src[k] && k - i <= 10U) {
                k++;
            }
            if (k < src_len && ';' == src[k]) {
                const uint8_t *ent;
                size_t         ent_len;
                uint8_t        decoded[4];
                size_t         dec_len;
                uint32_t       cp;

                ent     = src + i + 1U;
                ent_len = k - (i + 1U);
                dec_len = 0;
                cp      = 0;
                if (3U == ent_len && 0 == memcmp(ent, "amp", 3)) {
                    decoded[0] = '&';
                    dec_len    = 1U;
                } else if (2U == ent_len && 0 == memcmp(ent, "lt", 2)) {
                    decoded[0] = '<';
                    dec_len    = 1U;
                } else if (2U == ent_len && 0 == memcmp(ent, "gt", 2)) {
                    decoded[0] = '>';
                    dec_len    = 1U;
                } else if (4U == ent_len && 0 == memcmp(ent, "quot", 4)) {
                    decoded[0] = '"';
                    dec_len    = 1U;
                } else if (4U == ent_len && 0 == memcmp(ent, "apos", 4)) {
                    decoded[0] = '\'';
                    dec_len    = 1U;
                } else if (1U < ent_len && '#' == ent[0]) {
                    size_t m;
                    int    base;

                    base = 10;
                    m    = 1U;
                    if (2U < ent_len && ('x' == ent[1] || 'X' == ent[1])) {
                        base = 16;
                        m    = 2U;
                    }
                    for (; m < ent_len; m++) {
                        int digit;

                        if (16 == base) {
                            digit = hex_value(ent[m]);
                        } else if (isdigit((unsigned char)ent[m])) {
                            digit = ent[m] - '0';
                        } else {
                            digit = -1;
                        }
                        if (digit < 0) {
                            cp = 0;
                            break;
                        }
                        cp = cp * (uint32_t)base + (uint32_t)digit;
                    }
                    if (0U != cp && utf8_encode(cp, decoded, sizeof(decoded),
                                                &dec_len) < 0) {
                        return -1;
                    }
                }

                if (0U < dec_len) {
                    if (j + dec_len > dst_sz) {
                        return -1;
                    }
                    memcpy(dst + j, decoded, dec_len);
                    j += dec_len;
                    i       = k + 1U;
                    changed = 1;
                    continue;
                }
            }
        }

        if (j >= dst_sz) {
            return -1;
        }
        dst[j++] = src[i++];
    }

    *out_len = j;
    return changed ? 1 : 0;
}

static int decode_escape_core(uint8_t *dst, size_t dst_sz, const uint8_t *src,
                              size_t src_len, size_t *out_len) {
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
        if ('\\' == src[i] && i + 1U < src_len) {
            uint8_t decoded[4];
            size_t  dec_len;
            int     handled;

            dec_len = 0;
            handled = 1;
            switch (src[i + 1]) {
            case 'n':
                decoded[0] = '\n';
                dec_len    = 1U;
                i += 2U;
                break;
            case 'r':
                decoded[0] = '\r';
                dec_len    = 1U;
                i += 2U;
                break;
            case 't':
                decoded[0] = '\t';
                dec_len    = 1U;
                i += 2U;
                break;
            case '\\':
                decoded[0] = '\\';
                dec_len    = 1U;
                i += 2U;
                break;
            case '"':
                decoded[0] = '"';
                dec_len    = 1U;
                i += 2U;
                break;
            case '\'':
                decoded[0] = '\'';
                dec_len    = 1U;
                i += 2U;
                break;
            case 'x':
                if (i + 3U >= src_len || hex_value(src[i + 2]) < 0 ||
                    hex_value(src[i + 3]) < 0) {
                    return -1;
                }
                decoded[0] = (uint8_t)((hex_value(src[i + 2]) << 4) |
                                       hex_value(src[i + 3]));
                dec_len    = 1U;
                i += 4U;
                break;
            case 'u':
                if (i + 5U >= src_len) {
                    return -1;
                }
                {
                    uint32_t cp;
                    size_t   m;

                    cp = 0;
                    for (m = 0; m < 4U; m++) {
                        int digit;

                        digit = hex_value(src[i + 2U + m]);
                        if (digit < 0) {
                            return -1;
                        }
                        cp = (cp << 4) | (uint32_t)digit;
                    }
                    if (utf8_encode(cp, decoded, sizeof(decoded), &dec_len) <
                        0) {
                        return -1;
                    }
                    i += 6U;
                }
                break;
            default:
                handled = 0;
                break;
            }

            if (handled) {
                if (j + dec_len > dst_sz) {
                    return -1;
                }
                memcpy(dst + j, decoded, dec_len);
                j += dec_len;
                changed = 1;
                continue;
            }
        }

        if (j >= dst_sz) {
            return -1;
        }
        dst[j++] = src[i++];
    }

    *out_len = j;
    return changed ? 1 : 0;
}

static int invalid_percent_core(const uint8_t *src, size_t src_len) {
    size_t i;

    if (NULL == src) {
        return -1;
    }

    for (i = 0; i < src_len; i++) {
        if ('%' == src[i]) {
            if (i + 2U >= src_len) {
                return 1;
            }
            if (hex_value(src[i + 1]) < 0 || hex_value(src[i + 2]) < 0) {
                return 1;
            }
            i += 2U;
        }
    }

    return 0;
}

int http_decode_percent(char *dst, size_t dst_sz, const char *src) {
    size_t out_len;
    int    rc;

    if (NULL == dst || NULL == src || 0U == dst_sz) {
        return -1;
    }

    rc = decode_percent_core((uint8_t *)dst, dst_sz - 1U, (const uint8_t *)src,
                             strlen(src), &out_len);
    if (rc < 0) {
        return -1;
    }
    dst[out_len] = '\0';
    return rc;
}

int http_decode_percent_recursive(char *dst, size_t dst_sz, const char *src,
                                  int max_depth) {
    char  *buf_a;
    char  *buf_b;
    char  *in_buf;
    char  *out_buf;
    size_t len;
    int    depth;
    int    changed_any;

    if (NULL == dst || NULL == src || 0U == dst_sz || max_depth < 1) {
        return -1;
    }
    if (dst_sz < strlen(src) + 1U) {
        return -1;
    }

    buf_a = (char *)malloc(dst_sz);
    buf_b = (char *)malloc(dst_sz);
    if (NULL == buf_a || NULL == buf_b) {
        free(buf_a);
        free(buf_b);
        return -1;
    }

    memcpy(buf_a, src, strlen(src) + 1U);
    in_buf      = buf_a;
    out_buf     = buf_b;
    changed_any = 0;
    for (depth = 0; depth < max_depth; depth++) {
        int rc;

        rc = http_decode_percent(out_buf, dst_sz, in_buf);
        if (rc < 0) {
            free(buf_a);
            free(buf_b);
            return -1;
        }
        if (0 == rc) {
            break;
        }
        changed_any = 1;
        len         = strlen(out_buf) + 1U;
        memcpy(in_buf, out_buf, len);
    }

    memcpy(dst, in_buf, strlen(in_buf) + 1U);
    free(buf_a);
    free(buf_b);
    return changed_any ? 1 : 0;
}

int http_decode_plus_as_space(char *dst, size_t dst_sz, const char *src) {
    size_t out_len;
    int    rc;

    if (NULL == dst || NULL == src || 0U == dst_sz) {
        return -1;
    }

    rc = decode_plus_core((uint8_t *)dst, dst_sz - 1U, (const uint8_t *)src,
                          strlen(src), &out_len);
    if (rc < 0) {
        return -1;
    }
    dst[out_len] = '\0';
    return rc;
}

int http_decode_html_entity(char *dst, size_t dst_sz, const char *src) {
    size_t out_len;
    int    rc;

    if (NULL == dst || NULL == src || 0U == dst_sz) {
        return -1;
    }

    rc = decode_html_entity_core((uint8_t *)dst, dst_sz - 1U,
                                 (const uint8_t *)src, strlen(src), &out_len);
    if (rc < 0) {
        return -1;
    }
    dst[out_len] = '\0';
    return rc;
}

int http_decode_escape_sequence(char *dst, size_t dst_sz, const char *src) {
    size_t out_len;
    int    rc;

    if (NULL == dst || NULL == src || 0U == dst_sz) {
        return -1;
    }

    rc = decode_escape_core((uint8_t *)dst, dst_sz - 1U, (const uint8_t *)src,
                            strlen(src), &out_len);
    if (rc < 0) {
        return -1;
    }
    dst[out_len] = '\0';
    return rc;
}

int http_has_invalid_percent_encoding(const char *src) {
    if (NULL == src) {
        return -1;
    }
    return invalid_percent_core((const uint8_t *)src, strlen(src));
}

int http_body_decode_percent(uint8_t *dst, size_t dst_sz, const uint8_t *src,
                             size_t src_len, size_t *out_len) {
    return decode_percent_core(dst, dst_sz, src, src_len, out_len);
}

int http_body_decode_percent_recursive(uint8_t *dst, size_t dst_sz,
                                       const uint8_t *src, size_t src_len,
                                       int max_depth, size_t *out_len) {
    uint8_t *buf_a;
    uint8_t *buf_b;
    uint8_t *in_buf;
    uint8_t *out_buf;
    size_t   in_len;
    int      depth;
    int      changed_any;

    if (NULL == dst || NULL == src || NULL == out_len || max_depth < 1) {
        return -1;
    }
    if (dst_sz < src_len) {
        return -1;
    }

    buf_a = (uint8_t *)malloc(dst_sz);
    buf_b = (uint8_t *)malloc(dst_sz);
    if (NULL == buf_a || NULL == buf_b) {
        free(buf_a);
        free(buf_b);
        return -1;
    }

    memcpy(buf_a, src, src_len);
    in_buf      = buf_a;
    out_buf     = buf_b;
    in_len      = src_len;
    changed_any = 0;
    for (depth = 0; depth < max_depth; depth++) {
        size_t next_len;
        int    rc;

        rc = decode_percent_core(out_buf, dst_sz, in_buf, in_len, &next_len);
        if (rc < 0) {
            free(buf_a);
            free(buf_b);
            return -1;
        }
        if (0 == rc) {
            break;
        }
        changed_any = 1;
        memcpy(in_buf, out_buf, next_len);
        in_len = next_len;
    }

    memcpy(dst, in_buf, in_len);
    *out_len = in_len;
    free(buf_a);
    free(buf_b);
    return changed_any ? 1 : 0;
}

int http_body_decode_html_entity(uint8_t *dst, size_t dst_sz,
                                 const uint8_t *src, size_t src_len,
                                 size_t *out_len) {
    return decode_html_entity_core(dst, dst_sz, src, src_len, out_len);
}

int http_body_decode_escape_sequence(uint8_t *dst, size_t dst_sz,
                                     const uint8_t *src, size_t src_len,
                                     size_t *out_len) {
    return decode_escape_core(dst, dst_sz, src, src_len, out_len);
}

int http_body_has_invalid_percent_encoding(const uint8_t *src, size_t src_len) {
    return invalid_percent_core(src, src_len);
}

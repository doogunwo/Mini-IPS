#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t monotonic_ns(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void table_line(void) {
    puts("+----------------------+----------------------+");
}

static void table_row_str(const char *metric, const char *value) {
    printf("| %-20s | %20s |\n", metric, value);
}

static void table_row_u64(const char *metric, uint64_t value) {
    printf("| %-20s | %20llu |\n", metric, (unsigned long long)value);
}

static void table_row_f64(const char *metric, double value, const char *unit) {
    printf("| %-20s | %14.3f %-5s |\n", metric, value, unit);
}

static int linear_find_crlf(const uint8_t *p, size_t len, size_t *idx) {
    size_t i;

    for (i = 0; i + 1 < len; i++) {
        if (p[i] == '\r' && p[i + 1] == '\n') {
            *idx = i;
            return 1;
        }
    }

    return 0;
}

static int memchr_find_crlf(const uint8_t *p, size_t len, size_t *idx) {
    const uint8_t *cur;
    const uint8_t *hit;
    size_t         remain;

    cur    = p;
    remain = len;

    while (1) {
        if (remain < 2U) {
            return 0;
        }

        hit = (const uint8_t *)memchr(cur, '\r', remain - 1U);
        if (NULL == hit) {
            return 0;
        }

        if ('\n' == hit[1]) {
            *idx = (size_t)(hit - p);
            return 1;
        }

        remain -= (size_t)((hit - cur) + 1U);
        cur = hit + 1;
    }
}

static int linear_find_header_end(const uint8_t *p, size_t len, size_t *idx) {
    size_t i;

    for (i = 0; i + 3 < len; i++) {
        if (p[i] == '\r' && p[i + 1] == '\n' && p[i + 2] == '\r' &&
            p[i + 3] == '\n') {
            *idx = i;
            return 1;
        }
    }

    return 0;
}

static int memchr_find_header_end(const uint8_t *p, size_t len, size_t *idx) {
    const uint8_t *cur;
    const uint8_t *hit;
    size_t         remain;

    cur    = p;
    remain = len;

    while (1) {
        if (remain < 4U) {
            return 0;
        }

        hit = (const uint8_t *)memchr(cur, '\r', remain - 3U);
        if (NULL == hit) {
            return 0;
        }

        if ('\n' == hit[1] && '\r' == hit[2] && '\n' == hit[3]) {
            *idx = (size_t)(hit - p);
            return 1;
        }

        remain -= (size_t)((hit - cur) + 1U);
        cur = hit + 1;
    }
}

static void fill_pattern(uint8_t *buf, size_t len) {
    size_t i;

    for (i = 0; i < len; i++) {
        buf[i] = (uint8_t)('a' + (i % 23U));
    }
}

static void bench_pair(const char *name,
                       int (*baseline)(const uint8_t *, size_t, size_t *),
                       int (*candidate)(const uint8_t *, size_t, size_t *),
                       const uint8_t *buf, size_t len, uint64_t iterations) {
    uint64_t        t0;
    uint64_t        t1;
    size_t          idx;
    uint64_t        i;
    volatile size_t sink;
    double          baseline_ns;
    double          candidate_ns;

    sink = 0;

    t0 = monotonic_ns();
    for (i = 0; i < iterations; i++) {
        if (0 == baseline(buf, len, &idx)) {
            idx = (size_t)-1;
        }
        sink ^= idx;
    }
    t1          = monotonic_ns();
    baseline_ns = (double)(t1 - t0);

    t0 = monotonic_ns();
    for (i = 0; i < iterations; i++) {
        if (0 == candidate(buf, len, &idx)) {
            idx = (size_t)-1;
        }
        sink ^= idx;
    }
    t1           = monotonic_ns();
    candidate_ns = (double)(t1 - t0);

    printf("[%s]\n", name);
    table_line();
    table_row_str("metric", "value");
    table_line();
    table_row_u64("buffer_len", (uint64_t)len);
    table_row_u64("iterations", iterations);
    table_row_f64("baseline_ms", baseline_ns / 1000000.0, "ms");
    table_row_f64("candidate_ms", candidate_ns / 1000000.0, "ms");
    table_row_f64("baseline_ns_op", baseline_ns / (double)iterations, "ns");
    table_row_f64("candidate_ns_op", candidate_ns / (double)iterations, "ns");
    table_row_f64("speedup",
                  (0.0 == candidate_ns) ? 0.0 : baseline_ns / candidate_ns,
                  "x");
    table_row_u64("sink", (uint64_t)sink);
    table_line();
    putchar('\n');
}

int main(int argc, char **argv) {
    uint64_t iterations;
    size_t   crlf_len;
    size_t   header_len;
    uint8_t *crlf_buf;
    uint8_t *header_buf;

    iterations = 5000000ULL;
    crlf_len   = 4096U;
    header_len = 8192U;

    if (argc >= 2) {
        iterations = strtoull(argv[1], NULL, 10);
    }
    if (argc >= 3) {
        crlf_len = (size_t)strtoull(argv[2], NULL, 10);
    }
    if (argc >= 4) {
        header_len = (size_t)strtoull(argv[3], NULL, 10);
    }

    if (crlf_len < 2U) {
        crlf_len = 2U;
    }
    if (header_len < 4U) {
        header_len = 4U;
    }

    crlf_buf   = (uint8_t *)malloc(crlf_len);
    header_buf = (uint8_t *)malloc(header_len);
    if (NULL == crlf_buf || NULL == header_buf) {
        fprintf(stderr, "allocation failed\n");
        free(crlf_buf);
        free(header_buf);
        return 1;
    }

    fill_pattern(crlf_buf, crlf_len);
    fill_pattern(header_buf, header_len);

    crlf_buf[crlf_len - 2U] = '\r';
    crlf_buf[crlf_len - 1U] = '\n';

    header_buf[header_len - 4U] = '\r';
    header_buf[header_len - 3U] = '\n';
    header_buf[header_len - 2U] = '\r';
    header_buf[header_len - 1U] = '\n';

    bench_pair("benchmark_find_crlf", linear_find_crlf, memchr_find_crlf,
               crlf_buf, crlf_len, iterations);
    bench_pair("benchmark_find_header_end", linear_find_header_end,
               memchr_find_header_end, header_buf, header_len, iterations);

    free(crlf_buf);
    free(header_buf);
    return 0;
}

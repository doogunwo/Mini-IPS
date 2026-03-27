#pragma once

#include <stdio.h>
#include <string.h>

static inline int unit_test_log_result(const char *file, const char *target,
                                       const char *expected,
                                       const char *actual, int passed) {
    FILE *stream;

    stream = passed ? stdout : stderr;
    fprintf(stream, "%s | %s | %s | %s | %s\n", file, target, expected, actual,
            passed ? "pass" : "fail");
    return passed ? 0 : 1;
}

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        int _passed = !!(cond);                                                \
        if (unit_test_log_result(__FILE__, (msg), "condition true",            \
                                 _passed ? "condition true" : "condition false",\
                                 _passed)) {                                   \
            return 1;                                                          \
        }                                                                      \
    } while (0)

#define EXPECT_INT_EQ(target, expected, actual)                                \
    do {                                                                       \
        long long _expected = (long long)(expected);                           \
        long long _actual   = (long long)(actual);                             \
        char      _exp_buf[64];                                                \
        char      _act_buf[64];                                                \
        snprintf(_exp_buf, sizeof(_exp_buf), "%lld", _expected);               \
        snprintf(_act_buf, sizeof(_act_buf), "%lld", _actual);                 \
        if (unit_test_log_result(__FILE__, (target), _exp_buf, _act_buf,       \
                                 _expected == _actual)) {                      \
            return 1;                                                          \
        }                                                                      \
    } while (0)

#define EXPECT_SIZE_EQ(target, expected, actual)                               \
    do {                                                                       \
        size_t _expected = (size_t)(expected);                                 \
        size_t _actual   = (size_t)(actual);                                   \
        char   _exp_buf[64];                                                   \
        char   _act_buf[64];                                                   \
        snprintf(_exp_buf, sizeof(_exp_buf), "%zu", _expected);                \
        snprintf(_act_buf, sizeof(_act_buf), "%zu", _actual);                  \
        if (unit_test_log_result(__FILE__, (target), _exp_buf, _act_buf,       \
                                 _expected == _actual)) {                      \
            return 1;                                                          \
        }                                                                      \
    } while (0)

#define EXPECT_STR_EQ(target, expected, actual)                                \
    do {                                                                       \
        const char *_expected = (expected);                                    \
        const char *_actual   = (actual);                                      \
        int         _passed;                                                   \
        _passed = (NULL != _expected && NULL != _actual &&                     \
                   0 == strcmp(_expected, _actual));                           \
        if (unit_test_log_result(__FILE__, (target),                           \
                                 NULL != _expected ? _expected : "(null)",     \
                                 NULL != _actual ? _actual : "(null)",         \
                                 _passed)) {                                   \
            return 1;                                                          \
        }                                                                      \
    } while (0)

#define EXPECT_PTR_NOT_NULL(target, actual)                                    \
    do {                                                                       \
        const void *_actual = (const void *)(actual);                          \
        if (unit_test_log_result(__FILE__, (target), "non-null",               \
                                 NULL != _actual ? "non-null" : "null",        \
                                 NULL != _actual)) {                           \
            return 1;                                                          \
        }                                                                      \
    } while (0)

#define EXPECT_MEM_EQ(target, expected, actual, len)                           \
    do {                                                                       \
        const void *_expected = (const void *)(expected);                      \
        const void *_actual   = (const void *)(actual);                        \
        size_t      _len      = (size_t)(len);                                 \
        int         _passed;                                                   \
        _passed = (NULL != _expected && NULL != _actual &&                     \
                   0 == memcmp(_expected, _actual, _len));                     \
        if (unit_test_log_result(__FILE__, (target), "equal buffer",           \
                                 _passed ? "equal buffer" : "different buffer",\
                                 _passed)) {                                   \
            return 1;                                                          \
        }                                                                      \
    } while (0)

#define EXPECT_TRUE(target, expected_desc, cond)                               \
    do {                                                                       \
        int _passed = !!(cond);                                                \
        if (unit_test_log_result(__FILE__, (target), (expected_desc),          \
                                 _passed ? (expected_desc) : "condition false",\
                                 _passed)) {                                   \
            return 1;                                                          \
        }                                                                      \
    } while (0)

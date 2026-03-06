#pragma once
#ifndef TEST_BASIC_H
#define TEST_BASIC_H

typedef enum {
    EXPECT_MATCH,
    EXPECT_NO_MATCH
} expect_t;

typedef struct {
    const char *req;
    expect_t expect;
    int rule_id;
} test_case_t;


#endif

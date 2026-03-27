#include "detect.h"

#include "engine.h"
#include "http_parser.h"

#include <stddef.h>
#include <string.h>

int detect_run(detect_engine_t *engine, const http_message_t *msg,
               detect_result_t *out_result) {
    size_t matches;
    int    score;
    int    errors;
    int    rc;

    if (NULL == engine || NULL == engine->db || NULL == msg ||
        NULL == out_result) {
        return -1;
    }

    /* 탐지 결과 누적 구조체를 0으로 초기화한다. */ 
    memset(out_result, 0, sizeof(*out_result));

    /* SQLi 룰셋을 끝까지 순회하며 매치 수와 점수를 누적한다. */ 
    matches = 0;
    /* SQLi 룰셋을 끝까지 순회하며 매치 수와 점수를 누적한다. */ 
    score = 0;
    /* SQLi 룰셋을 끝까지 순회하며 매치 수와 점수를 누적한다. */ 
    errors = 0;
    /* SQLi 룰셋은 engine runtime만 호출하고 detect는 결과만 집계한다. */ 
    rc = engine_match_runtime(engine->sqli_runtime, msg, &matches, &score, &errors);
    out_result->matched_sqli = (matches > 0U);
    out_result->sqli_score = score;
    out_result->total_matches += matches;
    out_result->total_score += score;
    out_result->total_errors += errors;
    if (0 != rc) {
        out_result->total_errors++;
    }

    /* Directory Traversal 룰셋을 끝까지 순회하며 매치 수와 점수를 누적한다. */ 
    matches = 0;
    /* Directory Traversal 룰셋을 끝까지 순회하며 매치 수와 점수를 누적한다. */ 
    score = 0;
    /* Directory Traversal 룰셋을 끝까지 순회하며 매치 수와 점수를 누적한다. */ 
    errors = 0;
    /* Directory Traversal 룰셋은 engine runtime만 호출하고 detect는 결과만 집계한다. */ 
    rc = engine_match_runtime(engine->dir_traversal_runtime, msg, &matches, &score, &errors);
    out_result->matched_directory_traversal = (matches > 0U);
    out_result->directory_traversal_score = score;
    out_result->total_matches += matches;
    out_result->total_score += score;
    out_result->total_errors += errors;
    if (0 != rc) {
        out_result->total_errors++;
    }

    /* RCE 룰셋을 끝까지 순회하며 매치 수와 점수를 누적한다. */ 
    matches = 0;
    /* RCE 룰셋을 끝까지 순회하며 매치 수와 점수를 누적한다. */ 
    score = 0;
    /* RCE 룰셋을 끝까지 순회하며 매치 수와 점수를 누적한다. */ 
    errors = 0;
    /* RCE 룰셋은 engine runtime만 호출하고 detect는 결과만 집계한다. */ 
    rc = engine_match_runtime(engine->rce_runtime, msg, &matches, &score, &errors);
    out_result->matched_rce = (matches > 0U);
    out_result->rce_score = score;
    out_result->total_matches += matches;
    out_result->total_score += score;
    out_result->total_errors += errors;
    if (0 != rc) {
        out_result->total_errors++;
    }

    /* XSS 룰셋을 끝까지 순회하며 매치 수와 점수를 누적한다. */ 
    matches = 0;
    /* XSS 룰셋을 끝까지 순회하며 매치 수와 점수를 누적한다. */ 
    score = 0;
    /* XSS 룰셋을 끝까지 순회하며 매치 수와 점수를 누적한다. */ 
    errors = 0;
    /* XSS 룰셋은 engine runtime만 호출하고 detect는 결과만 집계한다. */ 
    rc = engine_match_runtime(engine->xss_runtime, msg, &matches, &score, &errors);
    out_result->matched_xss = (matches > 0U);
    out_result->xss_score = score;
    out_result->total_matches += matches;
    out_result->total_score += score;
    out_result->total_errors += errors;
    if (0 != rc) {
        out_result->total_errors++;
    }

    /* 전체 매치 수가 1건 이상이면 최종 matched 플래그를 올린다. */ 
    out_result->matched = (out_result->total_matches > 0U);
    return 0;
}

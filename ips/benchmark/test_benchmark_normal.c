/**
 * @file test_benchmark_normal.c
 * @brief benign 요청만 사용하는 탐지 파이프라인 벤치마크 진입점
 */
#include "configurable_detect_benchmark.h"

int main(int argc, char **argv) {
    return benchmark_detect_pipeline_main(argc, argv, BENCHMARK_MODE_NORMAL);
}

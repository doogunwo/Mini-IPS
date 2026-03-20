/**
 * @file test_benchmark_attack.c
 * @brief 11개 공격 분류를 포함한 탐지 파이프라인 벤치마크 진입점
 */
#include "configurable_detect_benchmark.h"

int main(int argc, char **argv) {
    return benchmark_detect_pipeline_main(argc, argv, BENCHMARK_MODE_ATTACK);
}

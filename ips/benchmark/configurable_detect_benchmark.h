/**
 * @file configurable_detect_benchmark.h
 * @brief normal/attack 탐지 파이프라인 벤치 공용 진입점 선언
 */
#ifndef CONFIGURABLE_DETECT_BENCHMARK_H
#define CONFIGURABLE_DETECT_BENCHMARK_H

typedef enum benchmark_mode {
    BENCHMARK_MODE_NORMAL = 0,
    BENCHMARK_MODE_ATTACK = 1
} benchmark_mode_t;

int benchmark_detect_pipeline_main(int argc, char **argv,
                                   benchmark_mode_t mode);

#endif

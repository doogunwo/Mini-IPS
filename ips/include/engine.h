/**
 * @file engine.h
 * @brief IPS 룰 실행 엔진 내부 인터페이스
 */
#ifndef ENGINE_H
#define ENGINE_H

#include <stddef.h>
#include <stdint.h>

#include "detect.h"

typedef struct engine_runtime engine_runtime_t;

int engine_set_backend_name(const char *name, char *errbuf, size_t errbuf_size);

engine_runtime_t *engine_runtime_create(const IPS_Signature *const *rules,
                                        unsigned int                rule_count,
                                        detect_jit_mode_t           jit_mode,
                                        char *errbuf, size_t errbuf_size);

void engine_runtime_destroy(engine_runtime_t *runtime);

int engine_runtime_match_first(engine_runtime_t *runtime, const uint8_t *data,
                               size_t len, ips_context_t ctx,
                               const IPS_Signature **matched_rule, char *errbuf,
                               size_t errbuf_size);

int engine_runtime_collect_matches(engine_runtime_t *runtime,
                                   const uint8_t *data, size_t len,
                                   ips_context_t        ctx,
                                   detect_match_list_t *matches, char *errbuf,
                                   size_t errbuf_size);

int engine_runtime_collect_matches_timed(engine_runtime_t *runtime,
                                         const uint8_t *data, size_t len,
                                         ips_context_t        ctx,
                                         detect_match_list_t *matches,
                                         uint64_t *elapsed_us_sum, char *errbuf,
                                         size_t errbuf_size);

const char *engine_runtime_backend_name(const engine_runtime_t *runtime);
int         engine_runtime_jit_enabled(const engine_runtime_t *runtime);

#endif

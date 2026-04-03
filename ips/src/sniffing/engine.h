/**
 * @file engine.h
 * @brief IPS 룰 실행 엔진 내부 인터페이스
 *
 * detect 계층 바로 아래에서 PCRE2/Hyperscan 차이를 흡수하는 내부 추상화다.
 * 상위 계층은 backend 종류를 몰라도 동일한 collect/match API를 사용한다.
 */
#ifndef ENGINE_H
#define ENGINE_H

#include <stddef.h>
#include <stdint.h>

#include "detect.h"

typedef struct engine_runtime engine_runtime_t;

/** 사용할 정규식 backend를 이름으로 선택한다. */
int engine_set_backend_name(const char *name, char *errbuf, size_t errbuf_size);

/** 선택된 룰 집합으로 backend runtime을 생성한다. */
engine_runtime_t *engine_runtime_create(const IPS_Signature *const *rules,
                                        unsigned int                rule_count,
                                        detect_jit_mode_t           jit_mode,
                                        char *errbuf, size_t errbuf_size);

/** backend runtime을 정리한다. */
void engine_runtime_destroy(engine_runtime_t *runtime);

/** 첫 매치 하나만 필요한 경로에서 사용하는 helper이다. */
int engine_runtime_match_first(engine_runtime_t *runtime, const uint8_t *data,
                               size_t len, ips_context_t ctx,
                               const IPS_Signature **matched_rule, char *errbuf,
                               size_t errbuf_size);

/** 모든 매치를 수집한다. */
int engine_runtime_collect_matches(engine_runtime_t *runtime,
                                   const uint8_t *data, size_t len,
                                   ips_context_t        ctx,
                                   detect_match_list_t *matches, char *errbuf,
                                   size_t errbuf_size);

/** 모든 매치를 수집하면서 backend 실행 시간을 누적한다. */
int engine_runtime_collect_matches_timed(engine_runtime_t *runtime,
                                         const uint8_t *data, size_t len,
                                         ips_context_t        ctx,
                                         detect_match_list_t *matches,
                                         uint64_t *elapsed_us_sum, char *errbuf,
                                         size_t errbuf_size);

/** runtime이 실제로 사용하는 backend 이름을 반환한다. */
const char *engine_runtime_backend_name(const engine_runtime_t *runtime);
/** runtime에 대해 JIT이 활성화됐는지 반환한다. */
int engine_runtime_jit_enabled(const engine_runtime_t *runtime);

#endif

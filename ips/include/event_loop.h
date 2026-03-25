/**
 * @file event_loop.h
 * @brief worker thread별 epoll 이벤트 루프 공개 인터페이스
 */
#ifndef EVENT_LOOP_H
#define EVENT_LOOP_H

#include <stdint.h>

/** worker별 epoll 루프 핸들 */
typedef struct event_loop event_loop_t;

/** 이벤트 루프 생성 시 필요한 기본 설정 */
typedef struct {
    int worker_id;      /**< worker 식별자 */
    int epoll_timeout;  /**< epoll_wait timeout(ms) */
} event_loop_cfg_t;

/** 이벤트 루프 생성 */
event_loop_t *event_loop_create(const event_loop_cfg_t *cfg);

/** 이벤트 루프 종료 및 자원 해제 */
void event_loop_destroy(event_loop_t *loop);

/** 이벤트 루프 1회 또는 메인 루프 실행 */
int event_loop_run(event_loop_t *loop);

#endif

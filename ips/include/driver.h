/**
 * @file driver.h
 * @brief 패킷 캡처 및 큐 공개 정의
 *
 * driver 계층은 libpcap capture thread와 worker thread 사이의
 * 데이터 이동을 담당한다. 한쪽 끝에서는 패킷을 수집하고, 다른 쪽 끝에서는
 * worker별 SPSC 링 버퍼에 패킷을 분배하는 역할을 한다.
 */
#pragma once
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

// 드라이버 모듈 주요 기능은
//  1. 패킷 큐 생성 및 초기화
//  2. 시스템콜 함수 생성
//  3. 패킷 처리
//   - 프록시 모드에 따른 예외 처리
//   - 정책에 의한 예외 처리
//   - 필터링이 필요한 패킷을 응용에 전달
/*default*/
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/*pcap*/
#include <pcap.h>

/* Per-Thread TCP */
#include <arpa/inet.h>
#include <stdatomic.h>
#include <unistd.h>
#define SERVER_PORT 8080
#define BACKLOG 128
#define BUF_SIZE 4096

/* Packet Filter Header*/
#include <stdbool.h>
#include <stddef.h>
#include "packet_ring.h"

typedef void (*driver_packet_cb)(const uint8_t *data, uint32_t len,
                                 uint64_t ts_ns, void *user);

/*------------------------ libpcap --------------*/
/** libpcap 핸들과 worker 분배 상태를 묶은 capture 컨텍스트이다. */
typedef struct capture_ctx {
    pcap_t             *handle; /**< 활성화된 libpcap capture handle */
    packet_queue_set_t *queues; /**< worker별 ring queue 집합 */
    uint32_t            rr;     /**< 비정상 패킷 fallback용 round-robin 인덱스 */
} capture_ctx_t;

/** libpcap 활성화에 필요한 설정 묶음이다. */
typedef struct pcap_ctx {
    const char *dev;         /**< capture 대상 인터페이스 이름 */
    int         snaplen;     /**< 캡처할 최대 바이트 수 */
    int         promisc;     /**< promiscuous mode 여부 */
    int         timeout_ms;  /**< pcap read timeout */
    int         nonblocking; /**< 0=blocking, 1=non-blocking */
} pcap_ctx_t;

// open_live보다 세밀한 설정을 하도록
int capture_create(capture_ctx_t *cpature_ctx, pcap_ctx_t *pcap_ctx);
int capture_activate(capture_ctx_t *cpature_ctx, pcap_ctx_t *pcap_ctx);

// pcap 닫기
void capture_close(capture_ctx_t *capture_ctx);

// 패킷 1개 수집 후 ring enqueue
int capture_poll_once(capture_ctx_t *capture_ctx);

/*------------------------ Per-Thread --------------*/
/**
 * @brief driver 전체 실행 상태를 담는 최상위 런타임 구조체.
 *
 * capture thread 1개와 worker thread N개, 그리고 둘 사이의 queue set을
 * 함께 보관한다. main.c는 이 구조체 하나를 통해 캡처 시작/정지/정리를
 * 수행한다.
 */
typedef struct driver_runtime {
    capture_ctx_t cc; /**< libpcap capture 상태 */

    pthread_t  capture_tid;  /**< capture thread 핸들 */
    pthread_t *worker_tids;  /**< worker thread 배열 */
    void      *worker_args;  /**< worker 시작 인자 배열 */
    int        worker_count; /**< 생성한 worker 수 */

    int capture_started; /**< capture thread 시작 여부 */
    int workers_started; /**< worker thread 시작 여부 */

    atomic_bool stop;       /**< 전체 종료 요청 플래그 */
    atomic_bool failed;     /**< capture/worker 중 하나라도 실패했는지 */
    atomic_int  last_error; /**< 최근 오류 코드 */

    pthread_mutex_t  handler_mu;       /**< 핸들러 교체 시점 보호용 mutex */
    driver_packet_cb on_packet;        /**< worker가 호출할 최종 패킷 콜백 */
    void            *on_packet_user;   /**< 단일 user 포인터 모드 */
    void           **worker_users;     /**< worker별 user 포인터 배열 */
    size_t           worker_user_count; /**< worker_users 길이 */

    packet_queue_set_t queues; /**< capture->worker SPSC 큐 집합 */
} driver_runtime_t;

/** queue set과 runtime 기본 상태를 초기화한다. */
int  driver_init(driver_runtime_t *rt, int worker_count);
/** capture thread와 worker thread를 실제로 시작한다. */
int  driver_start(driver_runtime_t *rt);
/** 모든 스레드에 정지를 요청하고 join한다. */
int  driver_stop(driver_runtime_t *rt);
/** runtime이 보유한 자원을 역순으로 해제한다. */
void driver_destroy(driver_runtime_t *rt);
/** worker/capture 실패 여부를 반환한다. */
int  driver_has_failed(driver_runtime_t *rt);
/** 최근 오류 코드를 반환한다. */
int  driver_last_error(driver_runtime_t *rt);
/** 모든 worker가 같은 user 포인터를 쓰는 단일 핸들러를 등록한다. */
void driver_set_packet_handler(driver_runtime_t *rt, driver_packet_cb cb,
                               void *user);
/** worker별 user 포인터를 가지는 멀티 핸들러를 등록한다. */
void driver_set_packet_handler_multi(driver_runtime_t *rt, driver_packet_cb cb,
                                     void **users, size_t user_count);

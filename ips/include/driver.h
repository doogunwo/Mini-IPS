/**
 * @file driver.h
 * @brief 패킷 캡처 및 큐 공개 정의
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
typedef struct capture_ctx {
    pcap_t             *handle;
    packet_queue_set_t *queues;
    uint32_t            rr;
} capture_ctx_t;

typedef struct pcap_ctx {
    const char *dev;
    int         snaplen;
    int         promisc;
    int         timeout_ms;
    int         nonblocking;  // 0=blocking, 1=non-blocking
} pcap_ctx_t;

// open_live보다 세밀한 설정을 하도록
int capture_create(capture_ctx_t *cpature_ctx, pcap_ctx_t *pcap_ctx);
int capture_activate(capture_ctx_t *cpature_ctx, pcap_ctx_t *pcap_ctx);

// pcap 닫기
void capture_close(capture_ctx_t *capture_ctx);

// 패킷 1개 수집 후 ring enqueue
int capture_poll_once(capture_ctx_t *capture_ctx);

/*------------------------ Per-Thread --------------*/
typedef struct driver_runtime {
    capture_ctx_t cc;

    pthread_t  capture_tid;
    pthread_t *worker_tids;
    void      *worker_args;
    int        worker_count;

    int capture_started;
    int workers_started;

    atomic_bool stop;
    atomic_bool failed;
    atomic_int  last_error;

    pthread_mutex_t  handler_mu;
    driver_packet_cb on_packet;
    void            *on_packet_user;
    void           **worker_users;
    size_t           worker_user_count;

    packet_queue_set_t queues;
} driver_runtime_t;

int  driver_init(driver_runtime_t *rt, int worker_count);
int  driver_start(driver_runtime_t *rt);
int  driver_stop(driver_runtime_t *rt);
void driver_destroy(driver_runtime_t *rt);
int  driver_has_failed(driver_runtime_t *rt);
int  driver_last_error(driver_runtime_t *rt);
void driver_set_packet_handler(driver_runtime_t *rt, driver_packet_cb cb,
                               void *user);
void driver_set_packet_handler_multi(driver_runtime_t *rt, driver_packet_cb cb,
                                     void **users, size_t user_count);

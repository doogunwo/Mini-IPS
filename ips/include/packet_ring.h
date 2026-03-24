/**
 * @file packet_ring.h
 * @brief 패킷 링 큐 공개 정의
 *
 * capture thread와 worker thread 사이의 hot path를 담당하는 SPSC 링 버퍼다.
 * slot 배열 자체는 hugepage mmap을 우선 시도하고, 실패 시 일반 heap으로
 * fallback 한다.
 */
#pragma once

#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdalign.h>
#include <stdatomic.h>

#define DEFAULT_SLOT_COUNT 4096
#define MIN_QUEUE_COUNT 1
#define MAX_QUEUE_COUNT 64
#define PACKET_MAX_BYTES 2032 // 16(헤더 바이트) + 2032(패킷 크기) -> 2048임

/* */
/** 링 버퍼의 한 칸(slot)에 저장되는 실제 패킷 데이터이다. */
typedef struct packet_slot {
    uint32_t len;                   /**< 저장된 패킷 길이 */
    uint64_t ts_ns;                 /**< 캡처 타임스탬프(ns) */
    uint8_t  data[PACKET_MAX_BYTES]; /**< 패킷 바이트 원문 */
} packet_slot_t;

/** 링 버퍼 운영 중 관측하는 간단한 통계이다. */
typedef struct {
    uint64_t enq_ok;
    uint64_t deq_ok;
    uint64_t drop_full;
    uint64_t wait_full;
} packet_ring_stats_t;

typedef struct {
    _Alignas(64) _Atomic uint32_t head;
    uint8_t head_pad[64 - sizeof(_Atomic uint32_t)];

    _Alignas(64) _Atomic uint32_t tail;
    uint8_t tail_pad[64 - sizeof(_Atomic uint32_t)];

    packet_slot_t *slots;          /**< slot 배열 시작 주소 */
    size_t slots_alloc_len;        /**< slot backing memory 길이 */
    int slots_use_mmap;            /**< hugepage mmap 사용 여부 */
    uint32_t slot_count;           /**< slot 개수(2의 거듭제곱) */
    uint32_t mask;                 /**< modulo 대신 쓰는 인덱스 마스크 */
    _Atomic int use_blocking;      /**< full/empty 시 대기 여부 */

    packet_ring_stats_t stats;
} packet_ring_t;

/** 여러 worker queue를 하나로 묶어 capture가 분배할 수 있게 한 구조체이다. */
typedef struct packet_queue_set {
    uint32_t       qcount;
    packet_ring_t *q;
    uint32_t       rr;
} packet_queue_set_t;



int packet_ring_init(packet_ring_t *r, uint32_t slot_count, int use_blocking);
void packet_ring_destroy(packet_ring_t *r);
int packet_ring_enq(packet_ring_t *r, const uint8_t *data, uint32_t len,
                    uint64_t ts_ns);
int packet_ring_deq(packet_ring_t *r, uint8_t *out, uint32_t out_cap,
                    uint32_t *out_len, uint64_t *out_ts_ns);

int packet_queue_set_init(packet_queue_set_t *set, uint32_t packet_queue_count,
                          uint32_t slot_count, int user_blocking);
void packet_queue_set_destroy(packet_queue_set_t *set);

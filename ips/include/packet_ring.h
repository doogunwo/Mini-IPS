/**
 * @file packet_ring.h
 * @brief 패킷 링 큐 공개 정의
 */
#pragma once

#include <stdio.h>
#include <errno.h>
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
typedef struct packet_slot {
    uint32_t len;
    uint64_t ts_ns;
    uint8_t  data[PACKET_MAX_BYTES];
} packet_slot_t;

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

    packet_slot_t *slots;
    size_t slots_alloc_len;
    int slots_use_mmap;
    uint32_t slot_count;
    uint32_t mask;
    _Atomic int use_blocking;

    packet_ring_stats_t stats;
} packet_ring_t;

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

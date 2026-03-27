/* ring_buffer.h */

#pragma once

#include <stdatomic.h>
#include <stdint.h>

#define PACKET_MAX_BYTES 2032

/* 링버퍼 슬롯 */
typedef struct ring_slot {
    uint32_t len;
    uint8_t  data[PACKET_MAX_BYTES];
} packet_slot_t;

/* 단순 SPSC 링버퍼 */
typedef struct ring_buffer {
    _Atomic uint32_t head;
    _Atomic uint32_t tail;
    packet_slot_t   *slots;
    uint32_t         slot_count;
} packet_ring_t;

int  packet_ring_init(packet_ring_t *r, uint32_t slot_count);
void packet_ring_free(packet_ring_t *r);

int packet_ring_enq(packet_ring_t *r, const uint8_t *data, uint32_t len);
int packet_ring_deq(packet_ring_t *r, uint8_t *out, uint32_t out_cap,
                    uint32_t *out_len);

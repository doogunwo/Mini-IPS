/* ring_buffer.c */

#include "ring.h"

#include <stdlib.h>
#include <string.h>

int packet_ring_init(packet_ring_t *r, uint32_t slot_count) {
    if (NULL == r) {
        return -1;
    }
    if (0 == slot_count) {
        return -1;
    }

    memset(r, 0, sizeof(*r));

    r->slots = (packet_slot_t *)malloc(sizeof(*r->slots) * slot_count);
    if (NULL == r->slots) {
        return -1;
    }

    memset(r->slots, 0, sizeof(*r->slots) * slot_count);
    r->slot_count = slot_count;
    atomic_store(&r->head, 0);
    atomic_store(&r->tail, 0);
    return 0;
}

void packet_ring_free(packet_ring_t *r) {
    if (NULL == r) {
        return;
    }

    free(r->slots);
    r->slots      = NULL;
    r->slot_count = 0;
    atomic_store(&r->head, 0);
    atomic_store(&r->tail, 0);
}

int packet_ring_enq(packet_ring_t *r, const uint8_t *data, uint32_t len) {
    uint32_t       head;
    uint32_t       tail;
    packet_slot_t *slot;

    if (NULL == r || NULL == data) {
        return -1;
    }
    if (NULL == r->slots || 0 == r->slot_count) {
        return -1;
    }
    if (0 == len || len > PACKET_MAX_BYTES) {
        return -1;
    }

    head = atomic_load(&r->head);
    tail = atomic_load(&r->tail);

    if ((tail - head) >= r->slot_count) {
        return -1;
    }

    slot = &r->slots[tail % r->slot_count];
    memcpy(slot->data, data, len);
    slot->len = len;

    atomic_store(&r->tail, tail + 1);
    return 0;
}

int packet_ring_deq(packet_ring_t *r, uint8_t *out, uint32_t out_cap,
                    uint32_t *out_len) {
    uint32_t       head;
    uint32_t       tail;
    packet_slot_t *slot;

    if (NULL == r || NULL == out || NULL == out_len) {
        return -1;
    }
    if (NULL == r->slots || 0 == r->slot_count) {
        return -1;
    }
    if (0 == out_cap) {
        return -1;
    }

    head = atomic_load(&r->head);
    tail = atomic_load(&r->tail);

    if (head == tail) {
        return -1;
    }

    slot = &r->slots[head % r->slot_count];
    if (out_cap < slot->len) {
        return -1;
    }

    memcpy(out, slot->data, slot->len);
    *out_len = slot->len;

    atomic_store(&r->head, head + 1);
    return 0;
}

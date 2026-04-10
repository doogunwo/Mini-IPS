/* ring_buffer.c */

#include "ring.h"

#include <stdlib.h>
#include <string.h>

int req_ring_init(req_ring_t *r, uint32_t slot_count) {
    if (NULL == r) {
        return -1;
    }
    if (0 == slot_count) {
        return -1;
    }

    memset(r, 0, sizeof(*r));

    r->slots = (req_slot_t *)malloc(sizeof(*r->slots) * slot_count);
    if (NULL == r->slots) {
        return -1;
    }

    memset(r->slots, 0, sizeof(*r->slots) * slot_count);
    r->slot_count = slot_count;
    atomic_store(&r->head, 0);
    atomic_store(&r->tail, 0);
    return 0;
}

void req_ring_free(req_ring_t *r) {
    if (NULL == r) {
        return;
    }

    free(r->slots);
    r->slots = NULL;
    r->slot_count = 0;
    atomic_store(&r->head, 0);
    atomic_store(&r->tail, 0);
}

int req_ring_enq(req_ring_t *r, uint32_t session_id,
                 const uint8_t *data, uint32_t len) {
    uint32_t   head;
    uint32_t   tail;
    req_slot_t *slot;

    if (NULL == r || NULL == data) {
        return -1;
    }
    if (NULL == r->slots || 0 == r->slot_count) {
        return -1;
    }
    if (0U == len || len > PACKET_MAX_BYTES) {
        return -1;
    }

    head = atomic_load(&r->head);
    tail = atomic_load(&r->tail);

    if ((tail - head) >= r->slot_count) {
        return -1;
    }

    slot = &r->slots[tail % r->slot_count];
    slot->session_id = session_id;
    memcpy(slot->data, data, len);
    slot->len = len;

    atomic_store(&r->tail, tail + 1);
    return 0;
}

/**
 * @brief req_ring에서 deq하는 함수임
 * 
 * @param r 
 * @param out 
 * @param out_cap 
 * @param out_len 
 * @param session_id 
 * @return int 정상 리턴: 0, 실패 리턴: -1(head==tail | out_cap < slot->len)
 */
int req_ring_deq(req_ring_t *r, uint8_t *out, uint32_t out_cap,
                 uint32_t *out_len, uint32_t *session_id) {
    uint32_t   head;
    uint32_t   tail;
    req_slot_t *slot;

    if (NULL == r || NULL == out || NULL == out_len || NULL == session_id) {
        return -1;
    }
    if (NULL == r->slots || 0 == r->slot_count) {
        return -1;
    }
    if (0U == out_cap) {
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
    *session_id = slot->session_id;

    atomic_store(&r->head, head + 1);
    return 0;
}

int res_ring_init(res_ring_t *r, uint32_t slot_count) {
    if (NULL == r) {
        return -1;
    }
    if (0 == slot_count) {
        return -1;
    }

    memset(r, 0, sizeof(*r));

    r->slots = (res_slot_t *)malloc(sizeof(*r->slots) * slot_count);
    if (NULL == r->slots) {
        return -1;
    }

    memset(r->slots, 0, sizeof(*r->slots) * slot_count);
    r->slot_count = slot_count;
    atomic_store(&r->head, 0);
    atomic_store(&r->tail, 0);
    return 0;
}

void res_ring_free(res_ring_t *r) {
    if (NULL == r) {
        return;
    }

    free(r->slots);
    r->slots = NULL;
    r->slot_count = 0;
    atomic_store(&r->head, 0);
    atomic_store(&r->tail, 0);
}

int res_ring_enq(res_ring_t *r, uint32_t action, uint32_t session_id,
                 const uint8_t *data, uint32_t len) {
    uint32_t   head;
    uint32_t   tail;
    res_slot_t *slot;

    if (NULL == r) {
        return -1;
    }
    if (NULL == r->slots || 0 == r->slot_count) {
        return -1;
    }
    if (len > PACKET_MAX_BYTES) {
        return -1;
    }
    if (0U < len && NULL == data) {
        return -1;
    }

    head = atomic_load(&r->head);
    tail = atomic_load(&r->tail);

    if ((tail - head) >= r->slot_count) {
        return -1;
    }

    slot = &r->slots[tail % r->slot_count];
    slot->action = action;
    slot->session_id = session_id;
    if (0U < len) {
        memcpy(slot->data, data, len);
    }
    slot->len = len;

    atomic_store(&r->tail, tail + 1);
    return 0;
}

int res_ring_deq(res_ring_t *r, uint8_t *out, uint32_t out_cap,
                 uint32_t *out_len, uint32_t *session_id,
                 uint32_t *action) {
    uint32_t   head;
    uint32_t   tail;
    res_slot_t *slot;

    if (NULL == r || NULL == out || NULL == out_len ||
        NULL == session_id || NULL == action) {
        return -1;
    }
    if (NULL == r->slots || 0 == r->slot_count) {
        return -1;
    }
    if (0U == out_cap) {
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

    if (0U < slot->len) {
        memcpy(out, slot->data, slot->len);
    }
    *out_len = slot->len;
    *session_id = slot->session_id;
    *action = slot->action;

    atomic_store(&r->head, head + 1);
    return 0;
}

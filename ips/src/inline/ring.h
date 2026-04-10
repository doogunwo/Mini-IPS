/* ring_buffer.h */

#pragma once

#include <netinet/in.h>
#include <stdatomic.h>
#include <stdint.h>

#define PACKET_MAX_BYTES 8192
#define MINI_IPS_RING_ACTION_REQUEST 1U
#define MINI_IPS_RING_ACTION_ALLOW   2U
#define MINI_IPS_RING_ACTION_BLOCK   3U

typedef struct  mini_ips_session {
    int in_use;
    uint32_t session_id;
    int client_fd;
    int upstream_fd;
    int blocked;
    int decision_queued;
    int request_forwarded;
    size_t pending_request_cap;
    size_t pending_request_len;
    uint8_t *pending_request;
    size_t pending_block_len;
    uint8_t *pending_block_response;
    struct sockaddr_in peer_addr;
    struct sockaddr_in orig_dst;
} mini_ips_session_t; 

typedef struct req_ring_slot {
    uint32_t session_id;
    uint32_t len;
    uint8_t  data[PACKET_MAX_BYTES];
} req_slot_t;

typedef struct req_ring_buffer {
    _Atomic uint32_t head;
    _Atomic uint32_t tail;
    req_slot_t      *slots;
    uint32_t         slot_count;
} req_ring_t;

typedef struct res_ring_slot {
    uint32_t action;
    uint32_t session_id;
    uint32_t len;
    uint8_t  data[PACKET_MAX_BYTES];
} res_slot_t;

typedef struct res_ring_buffer {
    _Atomic uint32_t head;
    _Atomic uint32_t tail;
    res_slot_t      *slots;
    uint32_t         slot_count;
} res_ring_t;

int  req_ring_init(req_ring_t *r, uint32_t slot_count);
void req_ring_free(req_ring_t *r);
int  req_ring_enq(req_ring_t *r, uint32_t session_id,
                  const uint8_t *data, uint32_t len);
int  req_ring_deq(req_ring_t *r, uint8_t *out, uint32_t out_cap,
                  uint32_t *out_len, uint32_t *session_id);

int  res_ring_init(res_ring_t *r, uint32_t slot_count);
void res_ring_free(res_ring_t *r);
int  res_ring_enq(res_ring_t *r, uint32_t action, uint32_t session_id,
                  const uint8_t *data, uint32_t len);
int  res_ring_deq(res_ring_t *r, uint8_t *out, uint32_t out_cap,
                  uint32_t *out_len, uint32_t *session_id,
                  uint32_t *action);

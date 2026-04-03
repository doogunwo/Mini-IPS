#include "../../src/inline/ring.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    req_ring_t req;
    res_ring_t res;
    uint8_t out[PACKET_MAX_BYTES];
    uint32_t out_len;
    uint32_t session_id;
    uint32_t action;

    memset(&req, 0, sizeof(req));
    memset(&res, 0, sizeof(res));

    EXPECT_INT_EQ("req_ring_init", 0, req_ring_init(&req, 4U));
    EXPECT_INT_EQ("req_ring_enq", 0,
                  req_ring_enq(&req, 101U, (const uint8_t *)"A", 1U));
    EXPECT_INT_EQ("req_ring_deq", 0,
                  req_ring_deq(&req, out, sizeof(out), &out_len, &session_id));
    EXPECT_SIZE_EQ("req_ring_deq.len", 1U, out_len);
    EXPECT_INT_EQ("req_ring_deq.session_id", 101, session_id);
    EXPECT_MEM_EQ("req_ring_deq.payload", "A", out, 1U);
    req_ring_free(&req);

    EXPECT_INT_EQ("res_ring_init", 0, res_ring_init(&res, 4U));
    EXPECT_INT_EQ("res_ring_enq", 0,
                  res_ring_enq(&res, MINI_IPS_RING_ACTION_BLOCK, 202U,
                               (const uint8_t *)"B", 1U));
    EXPECT_INT_EQ("res_ring_deq", 0,
                  res_ring_deq(&res, out, sizeof(out), &out_len,
                               &session_id, &action));
    EXPECT_SIZE_EQ("res_ring_deq.len", 1U, out_len);
    EXPECT_INT_EQ("res_ring_deq.session_id", 202, session_id);
    EXPECT_INT_EQ("res_ring_deq.action", MINI_IPS_RING_ACTION_BLOCK, action);
    EXPECT_MEM_EQ("res_ring_deq.payload", "B", out, 1U);
    res_ring_free(&res);

    return 0;
}

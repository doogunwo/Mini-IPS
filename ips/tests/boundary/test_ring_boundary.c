#include "../../src/inline/ring.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    req_ring_t req;
    res_ring_t res;
    uint8_t out[4];
    uint32_t out_len;
    uint32_t session_id;
    uint32_t action;

    memset(&req, 0, sizeof(req));
    memset(&res, 0, sizeof(res));

    EXPECT_INT_EQ("req_ring_init.null", -1, req_ring_init(NULL, 1U));
    EXPECT_INT_EQ("req_ring_init.zero_slots", -1, req_ring_init(&req, 0U));
    EXPECT_INT_EQ("req_ring_enq.uninitialized", -1,
                  req_ring_enq(&req, 1U, (const uint8_t *)"A", 1U));

    EXPECT_INT_EQ("req_ring_init.valid", 0, req_ring_init(&req, 1U));
    EXPECT_INT_EQ("req_ring_deq.empty", -1,
                  req_ring_deq(&req, out, sizeof(out), &out_len, &session_id));
    EXPECT_INT_EQ("req_ring_enq.oversize", -1,
                  req_ring_enq(&req, 1U, (const uint8_t *)"A",
                               PACKET_MAX_BYTES + 1U));
    EXPECT_INT_EQ("req_ring_enq.valid", 0,
                  req_ring_enq(&req, 9U, (const uint8_t *)"ABCD", 4U));
    EXPECT_INT_EQ("req_ring_deq.small_out_cap", -1,
                  req_ring_deq(&req, out, 2U, &out_len, &session_id));
    req_ring_free(&req);

    EXPECT_INT_EQ("res_ring_init.zero_slots", -1, res_ring_init(&res, 0U));
    EXPECT_INT_EQ("res_ring_init.valid", 0, res_ring_init(&res, 1U));
    EXPECT_INT_EQ("res_ring_enq.null_data_with_len", -1,
                  res_ring_enq(&res, MINI_IPS_RING_ACTION_BLOCK, 1U, NULL, 1U));
    EXPECT_INT_EQ("res_ring_enq.valid_zero_len", 0,
                  res_ring_enq(&res, MINI_IPS_RING_ACTION_ALLOW, 5U, NULL, 0U));
    EXPECT_INT_EQ("res_ring_deq.zero_cap", -1,
                  res_ring_deq(&res, out, 0U, &out_len, &session_id, &action));
    EXPECT_INT_EQ("res_ring_deq.valid", 0,
                  res_ring_deq(&res, out, sizeof(out), &out_len, &session_id,
                               &action));
    EXPECT_INT_EQ("res_ring_deq.action", MINI_IPS_RING_ACTION_ALLOW, action);
    EXPECT_SIZE_EQ("res_ring_deq.out_len", 0U, out_len);
    res_ring_free(&res);

    return 0;
}

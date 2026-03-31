#include "ring.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    req_ring_t req_ring;
    res_ring_t res_ring;
    uint8_t    out[PACKET_MAX_BYTES];
    uint32_t   out_len;
    uint32_t   session_id;
    uint32_t   action;
    int        rc;

    rc = req_ring_init(NULL, 4);
    EXPECT_INT_EQ("req_ring_init", -1, rc);

    rc = req_ring_init(&req_ring, 0);
    EXPECT_INT_EQ("req_ring_init", -1, rc);

    rc = req_ring_init(&req_ring, 2);
    EXPECT_INT_EQ("req_ring_init", 0, rc);

    rc = req_ring_enq(&req_ring, 101, (const uint8_t *)"A", 1);
    EXPECT_INT_EQ("req_ring_enq", 0, rc);
    rc = req_ring_enq(&req_ring, 202, (const uint8_t *)"B", 1);
    EXPECT_INT_EQ("req_ring_enq", 0, rc);
    rc = req_ring_enq(&req_ring, 303, (const uint8_t *)"C", 1);
    EXPECT_INT_EQ("req_ring_enq", -1, rc);

    rc = req_ring_deq(&req_ring, out, sizeof(out), &out_len, &session_id);
    EXPECT_INT_EQ("req_ring_deq", 0, rc);
    EXPECT_TRUE("req_ring_deq", "out_len=1 and first byte=A",
                1 == out_len && 'A' == out[0]);
    EXPECT_INT_EQ("req_ring_deq.session_id", 101, session_id);

    rc = req_ring_deq(&req_ring, out, 0, &out_len, &session_id);
    EXPECT_INT_EQ("req_ring_deq", -1, rc);

    rc = req_ring_deq(&req_ring, out, sizeof(out), &out_len, &session_id);
    EXPECT_INT_EQ("req_ring_deq", 0, rc);
    EXPECT_TRUE("req_ring_deq", "out_len=1 and first byte=B",
                1 == out_len && 'B' == out[0]);
    EXPECT_INT_EQ("req_ring_deq.session_id", 202, session_id);

    rc = req_ring_deq(&req_ring, out, sizeof(out), &out_len, &session_id);
    EXPECT_INT_EQ("req_ring_deq", -1, rc);

    rc = res_ring_init(NULL, 4);
    EXPECT_INT_EQ("res_ring_init", -1, rc);

    rc = res_ring_init(&res_ring, 0);
    EXPECT_INT_EQ("res_ring_init", -1, rc);

    rc = res_ring_init(&res_ring, 2);
    EXPECT_INT_EQ("res_ring_init", 0, rc);

    rc = res_ring_enq(&res_ring, MINI_IPS_RING_ACTION_ALLOW, 111, NULL, 0);
    EXPECT_INT_EQ("res_ring_enq", 0, rc);
    rc = res_ring_enq(&res_ring, MINI_IPS_RING_ACTION_BLOCK, 222,
                      (const uint8_t *)"403", 3);
    EXPECT_INT_EQ("res_ring_enq", 0, rc);
    rc = res_ring_enq(&res_ring, MINI_IPS_RING_ACTION_REQUEST, 333,
                      (const uint8_t *)"x", 1);
    EXPECT_INT_EQ("res_ring_enq", -1, rc);

    memset(out, 0, sizeof(out));
    rc = res_ring_deq(&res_ring, out, sizeof(out), &out_len, &session_id,
                      &action);
    EXPECT_INT_EQ("res_ring_deq", 0, rc);
    EXPECT_INT_EQ("res_ring_deq.action", MINI_IPS_RING_ACTION_ALLOW, action);
    EXPECT_INT_EQ("res_ring_deq.session_id", 111, session_id);
    EXPECT_INT_EQ("res_ring_deq.out_len", 0, out_len);

    memset(out, 0, sizeof(out));
    rc = res_ring_deq(&res_ring, out, sizeof(out), &out_len, &session_id,
                      &action);
    EXPECT_INT_EQ("res_ring_deq", 0, rc);
    EXPECT_INT_EQ("res_ring_deq.action", MINI_IPS_RING_ACTION_BLOCK, action);
    EXPECT_INT_EQ("res_ring_deq.session_id", 222, session_id);
    EXPECT_SIZE_EQ("res_ring_deq.out_len", 3, out_len);
    EXPECT_MEM_EQ("res_ring_deq.payload", "403", out, 3);

    rc = res_ring_deq(&res_ring, out, sizeof(out), &out_len, &session_id,
                      &action);
    EXPECT_INT_EQ("res_ring_deq", -1, rc);

    req_ring_free(&req_ring);
    res_ring_free(&res_ring);
    return 0;
}

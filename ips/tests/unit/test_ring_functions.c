#include "ring.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    packet_ring_t ring;
    uint8_t       out[PACKET_MAX_BYTES];
    uint32_t      out_len;
    int           rc;

    rc = packet_ring_init(NULL, 4);
    EXPECT_INT_EQ("packet_ring_init", -1, rc);

    rc = packet_ring_init(&ring, 0);
    EXPECT_INT_EQ("packet_ring_init", -1, rc);

    rc = packet_ring_init(&ring, 2);
    EXPECT_INT_EQ("packet_ring_init", 0, rc);

    rc = packet_ring_enq(&ring, (const uint8_t *)"A", 1);
    EXPECT_INT_EQ("packet_ring_enq", 0, rc);
    rc = packet_ring_enq(&ring, (const uint8_t *)"B", 1);
    EXPECT_INT_EQ("packet_ring_enq", 0, rc);
    rc = packet_ring_enq(&ring, (const uint8_t *)"C", 1);
    EXPECT_INT_EQ("packet_ring_enq", -1, rc);

    rc = packet_ring_deq(&ring, out, sizeof(out), &out_len);
    EXPECT_INT_EQ("packet_ring_deq", 0, rc);
    EXPECT_TRUE("packet_ring_deq", "out_len=1 and first byte=A",
                1 == out_len && 'A' == out[0]);

    rc = packet_ring_deq(&ring, out, 0, &out_len);
    EXPECT_INT_EQ("packet_ring_deq", -1, rc);

    rc = packet_ring_deq(&ring, out, sizeof(out), &out_len);
    EXPECT_INT_EQ("packet_ring_deq", 0, rc);
    EXPECT_TRUE("packet_ring_deq", "out_len=1 and first byte=B",
                1 == out_len && 'B' == out[0]);

    rc = packet_ring_deq(&ring, out, sizeof(out), &out_len);
    EXPECT_INT_EQ("packet_ring_deq", -1, rc);

    packet_ring_free(&ring);
    return 0;
}

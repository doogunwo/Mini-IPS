#include "ring.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    packet_ring_t ring;
    uint8_t       payload[PACKET_MAX_BYTES];
    uint8_t       out[PACKET_MAX_BYTES];
    uint32_t      out_len;
    int           rc;

    memset(payload, 'Z', sizeof(payload));

    rc = packet_ring_init(&ring, 1);
    CHECK(0 == rc, "ring boundary init one slot");

    rc = packet_ring_enq(&ring, payload, PACKET_MAX_BYTES);
    CHECK(0 == rc, "ring boundary max payload enqueue");

    rc = packet_ring_deq(&ring, out, PACKET_MAX_BYTES - 1U, &out_len);
    CHECK(-1 == rc, "ring boundary dequeue small buffer reject");

    rc = packet_ring_enq(&ring, payload, 1);
    CHECK(-1 == rc, "ring boundary full reject");

    rc = packet_ring_deq(&ring, out, PACKET_MAX_BYTES, &out_len);
    CHECK(0 == rc, "ring boundary dequeue max payload");
    CHECK(PACKET_MAX_BYTES == out_len, "ring boundary dequeue len");
    CHECK(0 == memcmp(out, payload, sizeof(payload)),
          "ring boundary dequeue payload");

    rc = packet_ring_enq(&ring, payload, PACKET_MAX_BYTES + 1U);
    CHECK(-1 == rc, "ring boundary oversize reject");

    packet_ring_free(&ring);
    return 0;
}

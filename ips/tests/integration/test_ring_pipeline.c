#include "ring.h"

#include <string.h>

#include "../common/unit_test.h"

int main(void) {
    packet_ring_t ring;
    uint8_t       out[PACKET_MAX_BYTES];
    uint32_t      out_len;
    int           rc;

    rc = packet_ring_init(&ring, 3);
    CHECK(0 == rc, "ring init integration");

    CHECK(0 == packet_ring_enq(&ring, (const uint8_t *)"one", 3),
          "ring enq one");
    CHECK(0 == packet_ring_enq(&ring, (const uint8_t *)"two", 3),
          "ring enq two");
    CHECK(0 == packet_ring_deq(&ring, out, sizeof(out), &out_len),
          "ring deq one");
    CHECK(3 == out_len && 0 == memcmp(out, "one", 3), "ring deq one result");

    CHECK(0 == packet_ring_enq(&ring, (const uint8_t *)"tri", 3),
          "ring enq tri");
    CHECK(0 == packet_ring_enq(&ring, (const uint8_t *)"for", 3),
          "ring enq for");

    CHECK(0 == packet_ring_deq(&ring, out, sizeof(out), &out_len),
          "ring deq two");
    CHECK(3 == out_len && 0 == memcmp(out, "two", 3), "ring deq two result");
    CHECK(0 == packet_ring_deq(&ring, out, sizeof(out), &out_len),
          "ring deq tri");
    CHECK(3 == out_len && 0 == memcmp(out, "tri", 3), "ring deq tri result");
    CHECK(0 == packet_ring_deq(&ring, out, sizeof(out), &out_len),
          "ring deq for");
    CHECK(3 == out_len && 0 == memcmp(out, "for", 3), "ring deq for result");

    packet_ring_free(&ring);
    return 0;
}

/**
 * @file test_packet_ring_full.c
 * @brief 컨슈머를 의도적으로 늦춰서 큐를 자주 가득 채워보기,  busy-wait가 과도한 CPU 사용을 만드는지
 * 
 * @copyright Copyright (c) 2026
 * 
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "packet_ring.h"

#define CHECK(cond, msg)                          \
    do {                                          \
        if (!(cond)) {                            \
            fprintf(stderr, "FAIL: %s\n", (msg)); \
            return 1;                             \
        }                                         \
    } while (0)

int main(void) {
    packet_ring_t ring;
    uint8_t pkt0[] = {0x10};
    uint8_t pkt1[] = {0x11};
    uint8_t pkt2[] = {0x12};
    uint8_t pkt3[] = {0x13};
    uint8_t pkt4[] = {0x14};
    uint8_t out[4];
    uint32_t out_len = 0;
    uint64_t out_ts_ns = 0;

    CHECK(0 == packet_ring_init(&ring, 4, 0), "packet_ring_init failed");

    CHECK(0 == packet_ring_enq(&ring, pkt0, sizeof(pkt0), 100),
          "enqueue pkt0 failed");
    CHECK(0 == packet_ring_enq(&ring, pkt1, sizeof(pkt1), 101),
          "enqueue pkt1 failed");
    CHECK(0 == packet_ring_enq(&ring, pkt2, sizeof(pkt2), 102),
          "enqueue pkt2 failed");
    CHECK(0 == packet_ring_enq(&ring, pkt3, sizeof(pkt3), 103),
          "enqueue pkt3 failed");

    CHECK(-1 == packet_ring_enq(&ring, pkt4, sizeof(pkt4), 104),
          "full ring should return -1");
    CHECK(1 == ring.stats.drop_full, "drop_full should be incremented once");
    CHECK(0 == ring.stats.wait_full, "wait_full should stay zero");
    CHECK(4 == ring.stats.enq_ok, "enq_ok mismatch");

    CHECK(0 == packet_ring_deq(&ring, out, sizeof(out), &out_len, &out_ts_ns),
          "dequeue pkt0 failed");
    CHECK(1U == out_len, "out_len mismatch");
    CHECK(pkt0[0] == out[0], "pkt0 payload mismatch");
    CHECK(100U == out_ts_ns, "pkt0 ts mismatch");

    CHECK(0 == packet_ring_deq(&ring, out, sizeof(out), &out_len, &out_ts_ns),
          "dequeue pkt1 failed");
    CHECK(pkt1[0] == out[0], "pkt1 payload mismatch");
    CHECK(101U == out_ts_ns, "pkt1 ts mismatch");

    CHECK(0 == packet_ring_deq(&ring, out, sizeof(out), &out_len, &out_ts_ns),
          "dequeue pkt2 failed");
    CHECK(pkt2[0] == out[0], "pkt2 payload mismatch");
    CHECK(102U == out_ts_ns, "pkt2 ts mismatch");

    CHECK(0 == packet_ring_deq(&ring, out, sizeof(out), &out_len, &out_ts_ns),
          "dequeue pkt3 failed");
    CHECK(pkt3[0] == out[0], "pkt3 payload mismatch");
    CHECK(103U == out_ts_ns, "pkt3 ts mismatch");

    CHECK(4 == ring.stats.deq_ok, "deq_ok mismatch");

    fprintf(stderr,
            "[test_packet_ring_full] fill_count=4 drop_full=%llu wait_full=%llu "
            "enq_ok=%llu deq_ok=%llu last_out=0x%02x last_ts_ns=%llu\n",
            (unsigned long long)ring.stats.drop_full,
            (unsigned long long)ring.stats.wait_full,
            (unsigned long long)ring.stats.enq_ok,
            (unsigned long long)ring.stats.deq_ok,
            out[0], (unsigned long long)out_ts_ns);

    packet_ring_destroy(&ring);
    printf("ok: test_packet_ring_full\n");
    return 0;
}

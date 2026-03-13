/**
 * @file test_driver_fragments.c
 * @brief driver fragment worker selection unit test
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <sys/types.h>
#include <stdio.h>
#include <string.h>

/* Static helpers are exercised by including the implementation. */
#include "../src/driver.c"

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", (msg)); \
        return 1; \
    } \
} while (0)

static void write_eth_ipv4_header(uint8_t *pkt,
                                  uint16_t total_len,
                                  uint16_t ip_id,
                                  uint16_t frag_field,
                                  uint8_t proto)
{
    memset(pkt, 0, 14 + 20);

    pkt[12] = 0x08;
    pkt[13] = 0x00;

    pkt[14] = 0x45;
    pkt[15] = 0x00;
    pkt[16] = (uint8_t)(total_len >> 8);
    pkt[17] = (uint8_t)(total_len & 0xff);
    pkt[18] = (uint8_t)(ip_id >> 8);
    pkt[19] = (uint8_t)(ip_id & 0xff);
    pkt[20] = (uint8_t)(frag_field >> 8);
    pkt[21] = (uint8_t)(frag_field & 0xff);
    pkt[22] = 64;
    pkt[23] = proto;

    pkt[26] = 10;
    pkt[27] = 0;
    pkt[28] = 0;
    pkt[29] = 1;
    pkt[30] = 10;
    pkt[31] = 0;
    pkt[32] = 0;
    pkt[33] = 2;
}

static int test_fragmented_packets_do_not_parse_as_5tuple(void)
{
    uint8_t first_frag[14 + 20 + 16];
    uint8_t later_frag[14 + 20 + 8];
    uint32_t sip = 0;
    uint32_t dip = 0;
    uint16_t sport = 0;
    uint16_t dport = 0;
    uint8_t proto = 0;

    write_eth_ipv4_header(first_frag, 20 + 16, 0x1234, 0x2000, IPPROTO_UDP);
    first_frag[34] = 0x30;
    first_frag[35] = 0x39;
    first_frag[36] = 0x00;
    first_frag[37] = 0x50;
    first_frag[38] = 0x00;
    first_frag[39] = 0x10;
    first_frag[40] = 0x00;
    first_frag[41] = 0x00;

    write_eth_ipv4_header(later_frag, 20 + 8, 0x1234, 0x0001, IPPROTO_UDP);
    later_frag[34] = 0xaa;
    later_frag[35] = 0xbb;
    later_frag[36] = 0xcc;
    later_frag[37] = 0xdd;

    CHECK(parse_ipv4_5tuple(first_frag, sizeof(first_frag), &sip, &dip, &sport, &dport, &proto) == 0,
          "first fragment should not be treated as a complete 5-tuple packet");
    CHECK(parse_ipv4_5tuple(later_frag, sizeof(later_frag), &sip, &dip, &sport, &dport, &proto) == 0,
          "non-initial fragment should not be treated as a 5-tuple packet");
    return 0;
}

static int test_fragments_stick_to_same_worker(void)
{
    uint8_t first_frag[14 + 20 + 16];
    uint8_t later_frag[14 + 20 + 8];
    capture_ctx_t cc;
    uint32_t first_idx;
    uint32_t later_idx;

    memset(&cc, 0, sizeof(cc));

    write_eth_ipv4_header(first_frag, 20 + 16, 0x1234, 0x2000, IPPROTO_UDP);
    first_frag[34] = 0x30;
    first_frag[35] = 0x39;
    first_frag[36] = 0x00;
    first_frag[37] = 0x50;
    first_frag[38] = 0x00;
    first_frag[39] = 0x10;
    first_frag[40] = 0x00;
    first_frag[41] = 0x00;

    write_eth_ipv4_header(later_frag, 20 + 8, 0x1234, 0x0001, IPPROTO_UDP);
    later_frag[34] = 0xaa;
    later_frag[35] = 0xbb;
    later_frag[36] = 0xcc;
    later_frag[37] = 0xdd;
    later_frag[38] = 0xee;
    later_frag[39] = 0xff;
    later_frag[40] = 0x12;
    later_frag[41] = 0x34;

    first_idx = pick_worker_idx(&cc, first_frag, sizeof(first_frag), 8);
    later_idx = pick_worker_idx(&cc, later_frag, sizeof(later_frag), 8);
    CHECK(first_idx == later_idx,
          "all fragments of the same IPv4 datagram should map to the same worker");
    return 0;
}

int main(void)
{
    if (test_fragmented_packets_do_not_parse_as_5tuple() != 0)
        return 1;
    if (test_fragments_stick_to_same_worker() != 0)
        return 1;

    printf("ok: test_driver_fragments\n");
    return 0;
}

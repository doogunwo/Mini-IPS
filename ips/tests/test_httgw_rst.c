/**
 * @file test_httgw_rst.c
 * @brief RST 생성 단위 테스트
 */
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "httgw.h"
#include "net_compat.h"

#define CHECK(cond, msg)                          \
    do {                                          \
        if (!(cond)) {                            \
            fprintf(stderr, "FAIL: %s\n", (msg)); \
            return 1;                             \
        }                                         \
    } while (0)

typedef struct {
    uint8_t pkt[128];
    size_t  len;
    int     calls;
} rst_capture_t;

static uint16_t checksum16_test(const void *data, size_t len) {
    const uint8_t *p   = (const uint8_t *)data;
    uint32_t       sum = 0;

    while (len > 1) {
        sum += (uint16_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }
    if (len) {
        sum += (uint16_t)(p[0] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

static uint16_t tcp_checksum_test(uint32_t src_be, uint32_t dst_be,
                                  const uint8_t *tcp, size_t tcp_len) {
    uint32_t       sum = 0;
    const uint8_t *p;
    size_t         len;

    p = (const uint8_t *)&src_be;
    sum += (uint16_t)((p[0] << 8) | p[1]);
    sum += (uint16_t)((p[2] << 8) | p[3]);

    p = (const uint8_t *)&dst_be;
    sum += (uint16_t)((p[0] << 8) | p[1]);
    sum += (uint16_t)((p[2] << 8) | p[3]);

    sum += IPPROTO_TCP;
    sum += (uint16_t)tcp_len;

    p   = tcp;
    len = tcp_len;
    while (len > 1) {
        sum += (uint16_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }
    if (len) {
        sum += (uint16_t)(p[0] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

static int fake_send_l3(void *ctx, const uint8_t *buf, size_t len) {
    rst_capture_t *cap = (rst_capture_t *)ctx;
    if (!cap || !buf || len > sizeof(cap->pkt)) {
        return -1;
    }
    memcpy(cap->pkt, buf, len);
    cap->len = len;
    cap->calls++;
    return 0;
}

static int build_tcp_packet(uint8_t *out, size_t out_cap, uint32_t sip,
                            uint16_t sport, uint32_t dip, uint16_t dport,
                            uint32_t seq, uint32_t ack, uint8_t flags,
                            const uint8_t *payload, uint32_t payload_len,
                            uint32_t *out_len) {
    struct ether_header *eth;
    IPHDR               *ip;
    TCPHDR              *tcp;
    size_t               total =
        sizeof(struct ether_header) + IP_HDR_SIZE + TCP_HDR_SIZE + payload_len;

    if (out_cap < total) {
        return -1;
    }

    memset(out, 0, total);
    eth             = (struct ether_header *)out;
    eth->ether_type = htons(ETHERTYPE_IP);

    ip               = (IPHDR *)(out + sizeof(struct ether_header));
    IP_VER(ip)       = 4;
    IP_IHL(ip)       = 5;
    IP_TTL_FIELD(ip) = 64;
    IP_PROTO(ip)     = IPPROTO_TCP;
    IP_TOTLEN(ip) = htons((uint16_t)(IP_HDR_SIZE + TCP_HDR_SIZE + payload_len));
    IP_SADDR(ip)  = htonl(sip);
    IP_DADDR(ip)  = htonl(dip);

    tcp            = (TCPHDR *)((uint8_t *)ip + IP_HDR_SIZE);
    TCP_SPORT(tcp) = htons(sport);
    TCP_DPORT(tcp) = htons(dport);
    TCP_SEQ(tcp)   = htonl(seq);
    TCP_ACK(tcp)   = htonl(ack);
    TCP_DOFF(tcp)  = 5;
    TCP_WIN(tcp)   = htons(4096);
    TCP_SET_FLAGS(tcp, flags);

    if (payload_len > 0 && payload) {
        memcpy((uint8_t *)tcp + TCP_HDR_SIZE, payload, payload_len);
    }

    *out_len = (uint32_t)total;
    return 0;
}

static int assert_rst_pkt(const rst_capture_t *cap, uint32_t exp_sip,
                          uint16_t exp_sport, uint32_t exp_dip,
                          uint16_t exp_dport, uint32_t exp_seq,
                          uint32_t exp_ack) {
    const IPHDR  *ip;
    const TCPHDR *tcp;
    IPHDR         ip_copy;
    TCPHDR        tcp_copy;

    CHECK(cap->calls == 5, "expected 5 RST packets");
    CHECK(cap->len == IP_HDR_SIZE + TCP_HDR_SIZE,
          "captured RST length mismatch");

    ip  = (const IPHDR *)cap->pkt;
    tcp = (const TCPHDR *)(cap->pkt + IP_HDR_SIZE);

    CHECK(IP_PROTO(ip) == IPPROTO_TCP, "RST packet protocol is not TCP");
    CHECK(ntohl(IP_SADDR(ip)) == exp_sip, "RST src IP mismatch");
    CHECK(ntohl(IP_DADDR(ip)) == exp_dip, "RST dst IP mismatch");

    CHECK(ntohs(TCP_SPORT(tcp)) == exp_sport, "RST src port mismatch");
    CHECK(ntohs(TCP_DPORT(tcp)) == exp_dport, "RST dst port mismatch");
    CHECK(ntohl(TCP_SEQ(tcp)) == exp_seq, "RST seq mismatch");
    CHECK(ntohl(TCP_ACK(tcp)) == exp_ack, "RST ack mismatch");
    CHECK(TCP_HAS_FLAG(tcp, TCP_RST), "RST flag is not set");
    CHECK(TCP_HAS_FLAG(tcp, TCP_ACK), "ACK flag is not set");

    memcpy(&ip_copy, ip, sizeof(ip_copy));
    IP_CHECK(&ip_copy) = 0;
    CHECK(checksum16_test(&ip_copy, sizeof(ip_copy)) == IP_CHECK(ip),
          "IP checksum mismatch");

    memcpy(&tcp_copy, tcp, sizeof(tcp_copy));
    TCP_CHECK(&tcp_copy) = 0;
    CHECK(htons(tcp_checksum_test(IP_SADDR(ip), IP_DADDR(ip),
                                  (const uint8_t *)&tcp_copy,
                                  sizeof(tcp_copy))) == TCP_CHECK(tcp),
          "TCP checksum mismatch");
    return 0;
}

static int test_rst_seq_ack_bidir(void) {
    httgw_t      *gw;
    httgw_cfg_t   cfg;
    tx_ctx_t      tx;
    rst_capture_t cap;
    flow_key_t    flow;
    uint8_t       pkt[512];
    uint32_t      pkt_len;
    const uint8_t p1[] = "ABCDEFGHIJ"; /* len=10 */
    const uint8_t p2[] = "XYZ";        /* len=3 */

    memset(&cfg, 0, sizeof(cfg));
    cfg.max_buffer_bytes = 4096;
    cfg.max_body_bytes   = 1024;
    cfg.reasm_mode       = REASM_MODE_LATE_START;

    gw = httgw_create(&cfg, NULL, NULL);
    CHECK(gw != NULL, "httgw_create failed");

    memset(&cap, 0, sizeof(cap));
    memset(&tx, 0, sizeof(tx));
    tx.send_l3 = fake_send_l3;
    tx.ctx     = &cap;
    CHECK(httgw_set_tx(gw, &tx) == 0, "httgw_set_tx failed");

    CHECK(build_tcp_packet(pkt, sizeof(pkt), 0x0A000001, 1111, 0x0A000002, 80,
                           100, 700, TCP_ACK | TCP_PSH, p1, sizeof(p1) - 1,
                           &pkt_len) == 0,
          "build AB packet failed");
    CHECK(httgw_ingest_packet(gw, pkt, pkt_len, 1) == 1,
          "ingest AB packet failed");

    CHECK(build_tcp_packet(pkt, sizeof(pkt), 0x0A000002, 80, 0x0A000001, 1111,
                           700, 110, TCP_ACK | TCP_PSH, p2, sizeof(p2) - 1,
                           &pkt_len) == 0,
          "build BA packet failed");
    CHECK(httgw_ingest_packet(gw, pkt, pkt_len, 2) == 1,
          "ingest BA packet failed");

    memset(&flow, 0, sizeof(flow));
    flow.src_ip   = 0x0A000001;
    flow.src_port = 1111;
    flow.dst_ip   = 0x0A000002;
    flow.dst_port = 80;
    flow.proto    = 6;

    cap.calls = 0;
    CHECK(httgw_request_rst(gw, &flow, DIR_AB) == 0,
          "httgw_request_rst AB failed");
    CHECK(assert_rst_pkt(&cap, 0x0A000001, 1111, 0x0A000002, 80, 110 + 4095,
                         767) == 0,
          "AB RST packet assert failed");
    fprintf(stderr,
            "[test_httgw_rst] case=bidir_ab calls=%d len=%zu seq=%u ack=%u\n",
            cap.calls, cap.len, 110U + 4095U, 767U);

    cap.calls = 0;
    CHECK(httgw_request_rst(gw, &flow, DIR_BA) == 0,
          "httgw_request_rst BA failed");
    CHECK(assert_rst_pkt(&cap, 0x0A000002, 80, 0x0A000001, 1111, 767 + 4095,
                         110) == 0,
          "BA RST packet assert failed");
    fprintf(stderr,
            "[test_httgw_rst] case=bidir_ba calls=%d len=%zu seq=%u ack=%u\n",
            cap.calls, cap.len, 767U + 4095U, 110U);

    httgw_destroy(gw);
    return 0;
}

static int test_rst_best_effort_when_single_direction_seen(void) {
    httgw_t      *gw;
    httgw_cfg_t   cfg;
    tx_ctx_t      tx;
    rst_capture_t cap;
    flow_key_t    flow;
    uint8_t       pkt[512];
    uint32_t      pkt_len;
    const uint8_t payload[] = "DATA"; /* len=4 */

    memset(&cfg, 0, sizeof(cfg));
    cfg.max_buffer_bytes = 4096;
    cfg.max_body_bytes   = 1024;
    cfg.reasm_mode       = REASM_MODE_LATE_START;
    gw                   = httgw_create(&cfg, NULL, NULL);
    CHECK(gw != NULL, "httgw_create failed");

    memset(&cap, 0, sizeof(cap));
    memset(&tx, 0, sizeof(tx));
    tx.send_l3 = fake_send_l3;
    tx.ctx     = &cap;
    CHECK(httgw_set_tx(gw, &tx) == 0, "httgw_set_tx failed");

    CHECK(build_tcp_packet(pkt, sizeof(pkt), 0x0A000001, 3333, 0x0A000002, 8080,
                           100, 50, TCP_ACK | TCP_PSH, payload,
                           sizeof(payload) - 1, &pkt_len) == 0,
          "build AB packet failed");
    CHECK(httgw_ingest_packet(gw, pkt, pkt_len, 5) == 1,
          "ingest AB packet failed");

    memset(&flow, 0, sizeof(flow));
    flow.src_ip   = 0x0A000001;
    flow.src_port = 3333;
    flow.dst_ip   = 0x0A000002;
    flow.dst_port = 8080;
    flow.proto    = 6;

    cap.calls = 0;
    CHECK(httgw_request_rst(gw, &flow, DIR_BA) == 0,
          "httgw_request_rst BA best-effort fallback failed");
    CHECK(assert_rst_pkt(&cap, 0x0A000002, 8080, 0x0A000001, 3333,
                         50U + HTTGW_SERVER_NEXT_BIAS + 4095U, 104U) == 0,
          "BA best-effort RST packet assert failed");

    fprintf(stderr,
            "[test_httgw_rst] case=single_direction_ba calls=%d len=%zu seq=%u "
            "ack=%u\n",
            cap.calls, cap.len, 50U + HTTGW_SERVER_NEXT_BIAS + 4095U, 104U);

    httgw_destroy(gw);
    return 0;
}

int main(void) {
    if (test_rst_seq_ack_bidir() != 0) {
        return 1;
    }
    if (test_rst_best_effort_when_single_direction_seen() != 0) {
        return 1;
    }
    printf("ok: test_httgw_rst\n");
    return 0;
}

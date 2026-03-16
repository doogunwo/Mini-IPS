#ifndef NET_COMPAT_H
#define NET_COMPAT_H

#include <netinet/ip.h>
#include <netinet/tcp.h>

#if defined(__APPLE__)
#define IPHDR struct ip
#define TCPHDR struct tcphdr
#define IP_HDR_SIZE (sizeof(IPHDR))
#define TCP_HDR_SIZE (sizeof(TCPHDR))
#define IP_VER(ip) ((ip)->ip_v)
#define IP_IHL(ip) ((ip)->ip_hl)
#define IP_TTL_FIELD(ip) ((ip)->ip_ttl)
#define IP_PROTO(ip) ((ip)->ip_p)
#define IP_TOTLEN(ip) ((ip)->ip_len)
#define IP_SADDR(ip) ((ip)->ip_src.s_addr)
#define IP_DADDR(ip) ((ip)->ip_dst.s_addr)
#define IP_CHECK(ip) ((ip)->ip_sum)
#define TCP_SPORT(tcp) ((tcp)->th_sport)
#define TCP_DPORT(tcp) ((tcp)->th_dport)
#define TCP_SEQ(tcp) ((tcp)->th_seq)
#define TCP_ACK(tcp) ((tcp)->th_ack)
#define TCP_DOFF(tcp) ((tcp)->th_off)
#define TCP_SET_RST(tcp) ((tcp)->th_flags |= TH_RST)
#define TCP_SET_ACK(tcp, on)           \
    do {                               \
        if (on) {                      \
            (tcp)->th_flags |= TH_ACK; \
        }                              \
    } while (0)
#define TCP_SET_FLAGS(tcp, flags) ((tcp)->th_flags |= (flags))
#define TCP_HAS_FLAG(tcp, flag) (((tcp)->th_flags & (flag)) != 0)
#define TCP_WIN(tcp) ((tcp)->th_win)
#define TCP_CHECK(tcp) ((tcp)->th_sum)
#else
#define IPHDR struct iphdr
#define TCPHDR struct tcphdr
#define IP_HDR_SIZE (sizeof(IPHDR))
#define TCP_HDR_SIZE (sizeof(TCPHDR))
#define IP_VER(ip) ((ip)->version)
#define IP_IHL(ip) ((ip)->ihl)
#define IP_TTL_FIELD(ip) ((ip)->ttl)
#define IP_PROTO(ip) ((ip)->protocol)
#define IP_TOTLEN(ip) ((ip)->tot_len)
#define IP_SADDR(ip) ((ip)->saddr)
#define IP_DADDR(ip) ((ip)->daddr)
#define IP_CHECK(ip) ((ip)->check)
#define TCP_SPORT(tcp) ((tcp)->source)
#define TCP_DPORT(tcp) ((tcp)->dest)
#define TCP_SEQ(tcp) ((tcp)->seq)
#define TCP_ACK(tcp) ((tcp)->ack_seq)
#define TCP_DOFF(tcp) ((tcp)->doff)
#define TCP_SET_RST(tcp) ((tcp)->rst = 1)
#define TCP_SET_ACK(tcp, on) ((tcp)->ack = ((on) ? 1 : 0))
#define TCP_SET_FLAGS(tcp, flags) \
    do {                          \
        if ((flags) & TCP_FIN)    \
            (tcp)->fin = 1;       \
        if ((flags) & TCP_SYN)    \
            (tcp)->syn = 1;       \
        if ((flags) & TCP_RST)    \
            (tcp)->rst = 1;       \
        if ((flags) & TCP_PSH)    \
            (tcp)->psh = 1;       \
        if ((flags) & TCP_ACK)    \
            (tcp)->ack = 1;       \
        if ((flags) & TCP_URG)    \
            (tcp)->urg = 1;       \
    } while (0)
#define TCP_HAS_FLAG(tcp, flag)            \
    ((((flag) & TCP_FIN) && (tcp)->fin) || \
     (((flag) & TCP_SYN) && (tcp)->syn) || \
     (((flag) & TCP_RST) && (tcp)->rst) || \
     (((flag) & TCP_PSH) && (tcp)->psh) || \
     (((flag) & TCP_ACK) && (tcp)->ack) || (((flag) & TCP_URG) && (tcp)->urg))
#define TCP_WIN(tcp) ((tcp)->window)
#define TCP_CHECK(tcp) ((tcp)->check)
#endif

#endif

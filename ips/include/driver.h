/**
 * @file driver.h
 * @brief 패킷 캡처 및 큐 공개 정의
 */
#pragma once
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

// 드라이버 모듈 주요 기능은
//  1. 패킷 큐 생성 및 초기화
//  2. 시스템콜 함수 생성
//  3. 패킷 처리
//   - 프록시 모드에 따른 예외 처리
//   - 정책에 의한 예외 처리
//   - 필터링이 필요한 패킷을 응용에 전달
/*default*/
#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>

/*pcap*/
#include <pcap.h>


/* Per-Thread TCP */
#include <stdatomic.h>
#include <arpa/inet.h>
#include <unistd.h>
#define SERVER_PORT 8080
#define BACKLOG 128
#define BUF_SIZE 4096

/* Packet Filter Header*/
#include <stddef.h>
#include <stdbool.h>

/*------패킷 큐 구현 -------------*/
//  패킷 큐 (8~64), 패킷 슬롯 카운트 (기본 4096)
#define DEFAULT_SLOT_COUNT 4096
#define MIN_QUEUE_COUNT 1
#define MAX_QUEUE_COUNT 64
#define PACKET_MAX_BYTES 2048

typedef struct packet_slot
{
    uint32_t len;
    uint64_t ts_ns;
    uint8_t data[PACKET_MAX_BYTES];
} packet_slot_t;

typedef struct packet_ring
{
    packet_slot_t *slots;
    uint32_t slot_count;

    uint32_t mask;
    uint32_t head;
    uint32_t tail;
    uint32_t count;

    /*-----아직 드랍 구현x / 상태*/
    uint64_t enq_ok;
    uint64_t deq_ok;
    uint64_t drop_full;

    /* 쓰레드 안전*/
    pthread_mutex_t mu;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
    int use_blocking;
} packet_ring_t;

typedef struct packet_queue_set
{
    uint32_t qcount;  /* 8..64 */
    packet_ring_t *q; /*array[qcount]*/
    uint32_t rr;      /* round-robin selector */
} packet_queue_set_t;

typedef void (*driver_packet_cb)(
    const uint8_t *data,
    uint32_t len,
    uint64_t ts_ns,
    void *user
);

static inline int is_power_of_two_u32(uint32_t x)
{
    return x && ((x & (x - 1)) == 0);
}

/*------------------------ ring init/dest--------------*/

static inline int packet_ring_init(packet_ring_t *r, uint32_t slot_count, int use_blocking)
{
    if (!r)
        return EINVAL;
    if (!is_power_of_two_u32(slot_count))
        return EINVAL;

    memset(r, 0, sizeof(*r));
    r->slots = (packet_slot_t *)calloc(slot_count, sizeof(packet_slot_t));
    if (!r->slots)
        return ENOMEM;

    r->slot_count = slot_count;
    r->mask = slot_count - 1;
    r->use_blocking = use_blocking ? 1 : 0;

    pthread_mutex_init(&r->mu, NULL);
    pthread_cond_init(&r->not_empty, NULL);
    pthread_cond_init(&r->not_full, NULL);
    return 0;
}

static inline void packet_ring_destroy(packet_ring_t *r)
{
    if (!r)
        return;
    pthread_mutex_destroy(&r->mu);
    pthread_cond_destroy(&r->not_empty);
    pthread_cond_destroy(&r->not_full);
    free(r->slots);
    memset(r, 0, sizeof(*r));
}

/*------------------------ enqueue / dequeue (copy-in/cout-out) --------------*/
static inline int packet_ring_enq(packet_ring_t *r,
                                  const uint8_t *data,
                                  uint32_t len,
                                  uint64_t ts_ns)
{
    if (!r || (!data && len))
        return EINVAL;
    if (len > PACKET_MAX_BYTES)
        return EMSGSIZE;

    pthread_mutex_lock(&r->mu);

    while (r->count == r->slot_count)
    {
        r->drop_full++;
        if (!r->use_blocking)
        {
            pthread_mutex_unlock(&r->mu);
            return EAGAIN; // full
        }
        pthread_cond_wait(&r->not_full, &r->mu);
    }
    packet_slot_t *s = &r->slots[r->tail & r->mask];
    s->len = len;
    s->ts_ns = ts_ns;
    if (len)
        memcpy(s->data, data, len);

    r->tail++;
    r->count++;
    r->enq_ok++;

    pthread_cond_signal(&r->not_empty);
    pthread_mutex_unlock(&r->mu);
    return 0;
}

static inline int packet_ring_deq(packet_ring_t *r,
                                  uint8_t *out,
                                  uint32_t out_cap,
                                  uint32_t *out_len,
                                  uint64_t *out_ts_ns)
{
    if (!r || !out_len)
        return EINVAL;
    pthread_mutex_lock(&r->mu);

    while (r->count == 0)
    {
        if (!r->use_blocking)
        {
            pthread_mutex_unlock(&r->mu);
            return EAGAIN;
        }
        pthread_cond_wait(&r->not_empty, &r->mu);
    }

    packet_slot_t *s = &r->slots[r->head & r->mask];
    uint32_t len = s->len;

    if (out)
    {
        if (out_cap < len)
        {
            pthread_mutex_unlock(&r->mu);
            return EMSGSIZE;
        }
        if (len)
            memcpy(out, s->data, len);
    }
    *out_len = len;
    if (out_ts_ns)
        *out_ts_ns = s->ts_ns;

    r->head++;
    r->count--;
    r->deq_ok++;

    pthread_cond_signal(&r->not_full);
    pthread_mutex_unlock(&r->mu);
    return 0;
}

/*------------------------ queue-set (8~64 rings) --------------*/

static inline int packet_queue_set_init(packet_queue_set_t *set,
                                        uint32_t packet_queue_count,
                                        uint32_t slot_count, // 기본 4096,
                                        int user_blocking)
{
    if (!set)
        return EINVAL;
    if (packet_queue_count < MIN_QUEUE_COUNT || packet_queue_count > MAX_QUEUE_COUNT)
        return EINVAL;
    if (slot_count == 0)
        slot_count = DEFAULT_SLOT_COUNT;
    if (!is_power_of_two_u32(slot_count))
        return EINVAL;

    memset(set, 0, sizeof(*set));
    set->q = (packet_ring_t *)calloc(packet_queue_count, sizeof(packet_ring_t));
    if (!set->q)
        return ENOMEM;

    set->qcount = packet_queue_count;
    for (uint32_t i = 0; i < packet_queue_count; i++)
    {
        int rc = packet_ring_init(&set->q[i], slot_count, user_blocking);
        if (rc != 0)
        {
            for (uint32_t j = 0; j < i; j++)
                packet_ring_destroy(&set->q[j]);
            free(set->q);
            memset(set, 0, sizeof(*set));
            return rc;
        }
    }

    return 0;
}

static inline void packet_queue_set_destroy(packet_queue_set_t *set)
{
    if (!set || !set->q)
        return;
    for (uint32_t i = 0; i < set->qcount; i++)
        packet_ring_destroy(&set->q[i]);
    free(set->q);
    memset(set, 0, sizeof(*set));
}

/*------------------------ libpcap --------------*/
typedef struct capture_ctx
{
    pcap_t *handle;
    packet_queue_set_t *queues;
    uint32_t rr;
} capture_ctx_t;

typedef struct pcap_ctx
{
    const char *dev;
    int snaplen;
    int promisc;
    int timeout_ms;
    int nonblocking; // 0=blocking, 1=non-blocking
} pcap_ctx_t;

// open_live보다 세밀한 설정을 하도록 
int capture_create(capture_ctx_t *cpature_ctx, pcap_ctx_t *pcap_ctx);
int capture_activate(capture_ctx_t *cpature_ctx, pcap_ctx_t *pcap_ctx);

// pcap 닫기
void capture_close(capture_ctx_t *capture_ctx);

// 패킷 1개 수집 후 ring enqueue
int capture_poll_once(capture_ctx_t *capture_ctx);

// 루프 기반 수집
int capture_loop(capture_ctx_t *capture_ctx);

/*------------------------ Per-Thread --------------*/
typedef struct {
    capture_ctx_t cc;

    pthread_t capture_tid;
    pthread_t *worker_tids;
    void *worker_args;
    int worker_count;

    atomic_bool stop;

    driver_packet_cb on_packet;
    void *on_packet_user;
    void **worker_users;
    size_t worker_user_count;

    packet_queue_set_t queues;
} driver_runtime_t;

int driver_init(driver_runtime_t *rt, int worker_count);
int driver_start(driver_runtime_t *rt);
int driver_stop(driver_runtime_t *rt);
void driver_destroy(driver_runtime_t *rt);
void driver_set_packet_handler(driver_runtime_t *rt, driver_packet_cb cb, void *user);
void driver_set_packet_handler_multi(driver_runtime_t *rt, driver_packet_cb cb, void **users, size_t user_count);


/*------------------------ Packet filter --------------*/
// 패킷 방향 확인(in/out) 확인
// 정책과 매칭(mac/ip/port)
// 결과를 BYPASS/PASS/DROP 중 하나로 결정

// 필터 패킷 결과
typedef enum plugin_handler_result {
    PLUGIN_HANDLER_PASS     = 0,
    PLUGIN_HANDLER_BYPASS   = 1,
    PLUGIN_HANDLER_DROP     = 2,
    PLUGIN_HANDLER_CONSUMED = 3
} plugin_handler_result_t;

// Direction
typedef enum driver_direction {
    DRIVER_DIR_UNKNOWN  = 0,
    DRIVER_DIR_INBOUND  = 1, /* outside -> inside */
    DRIVER_DIR_OUTBOUND = 2  /* inside -> outside */
} driver_direction_t;

// 프로토콜 enum
typedef enum driver_l3_proto {
    DRIVER_L3_UNKNOWN = 0,
    DRIVER_L3_IPV4 = 4,
    DRIVER_L3_IPV6 = 6
} driver_l3_proto_t;

typedef enum driver_l4_proto {
    DRIVER_L4_UNKNOWN = 0,
    DRIVER_L4_TCP = 6,
    DRIVER_L4_UDP = 17
} driver_l4_proto_t;

// 주소타입
typedef struct driver_mac {
    uint8_t b[6];
} driver_mac_t;

// IPv4 in network byte order
typedef struct driver_ipv4 {
    uint32_t addr_be;
} driver_ipv4_t;
// IPv4 CIDR net/mask 
typedef struct driver_ipv4_cidr {
    uint32_t net_be;
    uint32_t mask_be;
} driver_ipv4_cidr_t;

// packet meta passed into filter
typedef struct driver_pkt_meta {
    uint64_t ts_ns;

    driver_mac_t src_mac;
    driver_mac_t dst_mac;

    driver_l3_proto_t l3;
    driver_l4_proto_t l4;

    driver_ipv4_t src_v4;
    driver_ipv4_t dst_v4;

    uint16_t src_port;
    uint16_t dst_port;

    driver_direction_t dir;

    bool is_tunnel;
    bool is_tls;
    bool is_http;
} driver_pkt_meta_t;

/* ---------------Config ---------------*/
#define DRIVER_FILTER_MAX_MACS 256
#define DRIVER_FILTER_MAX_CIDRS 64
#define DRIVER_FILTER_MAX_PORTS 256

typedef struct driver_filter_policy {
    bool bypass_tunnel; // L2/L3 터널링 등 BYPASS 조건 흉내, is_tunnel=true -> bypass

    driver_mac_t mac_bypass[DRIVER_FILTER_MAX_MACS];
    uint32_t mac_bypass_cnt;

    /*DROP/CONSUMED 흉내 조건: MIRRORING 등에서 특정 MAC drop */
    driver_mac_t mac_drop[DRIVER_FILTER_MAX_MACS];
    uint32_t     mac_drop_cnt;
    
    /* port bypass/drop */
    uint16_t port_bypass[DRIVER_FILTER_MAX_PORTS];
    uint32_t port_bypass_cnt;

    uint16_t port_drop[DRIVER_FILTER_MAX_PORTS];
    uint32_t port_drop_cnt;

    bool use_consumed;
} driver_filter_policy_t;
//init
void driver_filter_policy_init(driver_filter_policy_t *p);
// main filter
plugin_handler_result_t driver_filter_eval(
    const driver_pkt_meta_t *m,
    const driver_filter_policy_t *p
);

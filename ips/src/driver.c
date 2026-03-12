/**
 * @file driver.c
 * @brief 패킷 캡처 드라이버 구현
 */
#include "driver.h"
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <netinet/in.h>

typedef struct worker_arg
{
    driver_runtime_t *rt;
    uint32_t index;
} worker_arg_t;

static int endpoint_cmp(uint32_t a_ip, uint16_t a_port, uint32_t b_ip, uint16_t b_port)
{
    if (a_ip < b_ip)
        return -1;
    if (a_ip > b_ip)
        return 1;
    if (a_port < b_port)
        return -1;
    if (a_port > b_port)
        return 1;
    return 0;
}

static uint32_t flow_hash_5tuple(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, uint8_t proto)
{
    if (endpoint_cmp(sip, sport, dip, dport) > 0)
    {
        uint32_t tmp_ip = sip;
        uint16_t tmp_port = sport;
        sip = dip;
        sport = dport;
        dip = tmp_ip;
        dport = tmp_port;
    }

    uint32_t h = 2166136261u;
    h ^= sip;
    h *= 16777619u;
    h ^= dip;
    h *= 16777619u;
    h ^= ((uint32_t)sport << 16) | dport;
    h *= 16777619u;
    h ^= proto;
    h *= 16777619u;
    return h;
}

static int parse_ipv4_5tuple(const uint8_t *pkt, uint32_t len,
                             uint32_t *sip, uint32_t *dip,
                             uint16_t *sport, uint16_t *dport,
                             uint8_t *proto)
{
    const uint8_t *p = pkt;
    uint32_t n;
    uint16_t eth_type;
    uint32_t ihl;
    uint16_t total_len;

    if (!pkt || len < 14 + 20)
        return 0;

    eth_type = (uint16_t)((p[12] << 8) | p[13]);
    p += 14;
    n = len - 14;

    if (eth_type == 0x8100 || eth_type == 0x88A8)
    {
        if (n < 4)
            return 0;
        eth_type = (uint16_t)((p[2] << 8) | p[3]);
        p += 4;
        n -= 4;
    }

    if (eth_type != 0x0800 || n < 20)
        return 0;
    if ((p[0] >> 4) != 4)
        return 0;

    ihl = (uint32_t)(p[0] & 0x0F) * 4U;
    if (ihl < 20 || n < ihl)
        return 0;
    total_len = (uint16_t)((p[2] << 8) | p[3]);
    if (total_len < ihl || n < total_len)
        return 0;

    *proto = p[9];
    if (*proto != IPPROTO_TCP && *proto != IPPROTO_UDP)
        return 0;

    *sip = (uint32_t)((p[12] << 24) | (p[13] << 16) | (p[14] << 8) | p[15]);
    *dip = (uint32_t)((p[16] << 24) | (p[17] << 16) | (p[18] << 8) | p[19]);

    p += ihl;
    if ((uint32_t)(total_len - ihl) < 8)
        return 0;

    *sport = (uint16_t)((p[0] << 8) | p[1]);
    *dport = (uint16_t)((p[2] << 8) | p[3]);
    return 1;
}

static uint32_t pick_worker_idx(capture_ctx_t *cc, const uint8_t *pkt, uint32_t len, uint32_t worker_count)
{
    uint32_t sip = 0, dip = 0;
    uint16_t sport = 0, dport = 0;
    uint8_t proto = 0;

    if (worker_count == 0)
        return 0;
    if (!parse_ipv4_5tuple(pkt, len, &sip, &dip, &sport, &dport, &proto))
    {
        uint32_t idx = cc->rr % worker_count;
        cc->rr++;
        return idx;
    }

    return flow_hash_5tuple(sip, dip, sport, dport, proto) % worker_count;
}

static void wake_all_queues(driver_runtime_t *rt)
{
    if (!rt)
        return;
    for (uint32_t i = 0; i < rt->queues.qcount; i++)
    {
        packet_ring_t *r = &rt->queues.q[i];
        pthread_mutex_lock(&r->mu);
        r->use_blocking = 0;
        pthread_cond_broadcast(&r->not_empty);
        pthread_cond_broadcast(&r->not_full);
        pthread_mutex_unlock(&r->mu);
    }
}

/* 전체 사용 흐름
capture_create(&cc, &pc);
capture_activate(&cc, &pc);
*/
int capture_create(capture_ctx_t *cc, pcap_ctx_t *pc)
{
    if (!cc || !pc || !pc->dev)
        return EINVAL;
    cc->handle = NULL;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *h = pcap_create(pc->dev, errbuf);
    if (!h)
        return EIO;

    /* snaplen*/
    if (pcap_set_snaplen(h, pc->snaplen) != 0)
        goto fail;
    if (pcap_set_promisc(h, pc->promisc) != 0)
        goto fail;
    if (pcap_set_timeout(h, pc->timeout_ms) != 0)
        goto fail;

    cc->handle = h;
    return 0;

fail:
    pcap_close(h);
    return EIO;
}

int capture_activate(capture_ctx_t *cc, pcap_ctx_t *pc)
{
    if (!cc || !cc->handle)
        return EINVAL;
    int ret = pcap_activate(cc->handle);
    if (ret < 0)
    {
        fprintf(stderr, "pcap_activate failed ret=%d, err=%s\n", ret, pcap_geterr(cc->handle));
        return EIO;
    }

    if (pc && pc->nonblocking)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        if (pcap_setnonblock(cc->handle, 1, errbuf) != 0)
            return EIO;
    }
    return 0;
}

void capture_close(capture_ctx_t *cc)
{
    if (!cc)
        return;
    if (cc->handle)
    {
        pcap_close(cc->handle);
        cc->handle = NULL;
    }
}

/**
 * @brief 패킷 캡처 함수
 *
 * @param cc 캡처 컨텍스트
 * @return int
 */
int capture_poll_once(capture_ctx_t *cc)
{
    /* 인자 검증 */
    if (!cc || !cc->handle || !cc->queues || cc->queues->qcount == 0)
    {
        return EINVAL;
    }

    struct pcap_pkthdr *hdr;
    const u_char *pkt;

    /* libpcap에서 실제로 패킷을 읽는 지점 */
    int ret = pcap_next_ex(cc->handle, &hdr, &pkt);
    if (ret == 1)
    {
        uint64_t ts_ns = ((uint64_t)hdr->ts.tv_sec * 1000000000ULL) +
                         ((uint64_t)hdr->ts.tv_usec * 1000ULL);
        uint32_t idx = pick_worker_idx(cc, pkt, hdr->caplen, cc->queues->qcount);
        int rc = packet_ring_enq(&cc->queues->q[idx], pkt, hdr->caplen, ts_ns);

        fprintf(stderr,
                "[PCAP] ret=%d caplen=%u len=%u worker=%u enq_rc=%d\n",
                ret,
                hdr ? hdr->caplen : 0,
                hdr ? hdr->len : 0,
                idx,
                rc);
        if (rc != 0)
            return rc;
        return 1;
    }

    if (ret == 0)
    {
        return 0;
    }

    if (ret == -2)
    {
        return -2;
    }

    return EIO;
}

int capture_loop(capture_ctx_t *cc)
{
    if (!cc || !cc->handle || !cc->queues || cc->queues->qcount == 0)
        return EINVAL;
    while (1)
    {
        int rc = capture_poll_once(cc);
        if (rc == 1)
            continue;
        if (rc == 0)
        {
            usleep(200);
            continue;
        }
        if (rc == -2)
            return 0;
        if (rc == EAGAIN)
            continue;
        return rc;
    }
}

static void *capture_thread_func(void *arg)
{
    driver_runtime_t *rt = arg;
    while (!atomic_load(&rt->stop))
    {
        int rc = capture_poll_once(&rt->cc);
        if (rc == 0 || rc == EAGAIN)
        {
            usleep(200);
            continue;
        }
        if (rc < 0)
            break;
    }
    return NULL;
}

static void *worker_thread_func(void *arg)
{
    worker_arg_t *wa = arg;
    driver_runtime_t *rt = wa->rt;
    uint32_t idx = wa->index;
    packet_ring_t *ring = &rt->queues.q[idx];

    uint8_t buf[PACKET_MAX_BYTES];
    uint32_t len;
    uint64_t ts;

    while (!atomic_load(&rt->stop))
    {
        int rc = packet_ring_deq(ring, buf, sizeof(buf), &len, &ts);
        if (rc == 0)
        {
            if (rt->on_packet)
            {
                void *user = rt->on_packet_user;
                if (rt->worker_users && idx < rt->worker_user_count)
                    user = rt->worker_users[idx];
                rt->on_packet(buf, len, ts, user);
            }
            continue;
        }
        if (rc == EAGAIN)
            continue;
        break;
    }
    return NULL;
}

int driver_init(driver_runtime_t *rt, int worker_count)
{
    if (!rt || worker_count <= 0)
        return EINVAL;
    rt->worker_count = worker_count;
    rt->worker_tids = calloc(worker_count, sizeof(pthread_t));
    rt->worker_args = calloc(worker_count, sizeof(worker_arg_t));

    if (!rt->worker_tids || !rt->worker_args)
    {
        free(rt->worker_tids);
        free(rt->worker_args);
        rt->worker_tids = NULL;
        rt->worker_args = NULL;
        return ENOMEM;
    }
    int qrc = packet_queue_set_init(&rt->queues, (uint32_t)worker_count, DEFAULT_SLOT_COUNT, 1);
    if (qrc != 0)
    {
        free(rt->worker_tids);
        free(rt->worker_args);
        rt->worker_tids = NULL;
        rt->worker_args = NULL;
        return qrc;
    }
    rt->cc.queues = &rt->queues;
    rt->cc.rr = 0;
    atomic_init(&rt->stop, false);
    return 0;
}

int driver_start(driver_runtime_t *rt)
{
    if (!rt)
        return EINVAL;
    if (!rt->worker_tids)
        return EINVAL;

    for (int i = 0; i < rt->worker_count; i++)
    {
        worker_arg_t *wa = &((worker_arg_t *)rt->worker_args)[i];
        wa->rt = rt;
        wa->index = (uint32_t)i;
        if (pthread_create(&rt->worker_tids[i], NULL, worker_thread_func, wa) != 0)
        {
            atomic_store(&rt->stop, true);
            wake_all_queues(rt);
            for (int j = 0; j < i; j++)
                pthread_join(rt->worker_tids[j], NULL);
            return EIO;
        }
    }

    if (pthread_create(&rt->capture_tid, NULL, capture_thread_func, rt) != 0)
    {
        atomic_store(&rt->stop, true);
        wake_all_queues(rt);
        for (int i = 0; i < rt->worker_count; i++)
            pthread_join(rt->worker_tids[i], NULL);
        return EIO;
    }
    return 0;
}

int driver_stop(driver_runtime_t *rt)
{
    if (!rt)
        return EINVAL;
    atomic_store(&rt->stop, true);

    wake_all_queues(rt);

    pthread_join(rt->capture_tid, NULL);

    for (int i = 0; i < rt->worker_count; i++)
        pthread_join(rt->worker_tids[i], NULL);

    return 0;
}

void driver_destroy(driver_runtime_t *rt)
{
    if (!rt)
        return;
    capture_close(&rt->cc);
    packet_queue_set_destroy(&rt->queues);
    free(rt->worker_tids);
    rt->worker_tids = NULL;
    free(rt->worker_args);
    rt->worker_args = NULL;
    rt->worker_users = NULL;
    rt->worker_user_count = 0;
}

void driver_set_packet_handler(driver_runtime_t *rt, driver_packet_cb cb, void *user)
{
    if (!rt)
        return;
    rt->on_packet = cb;
    rt->on_packet_user = user;
}

void driver_set_packet_handler_multi(driver_runtime_t *rt, driver_packet_cb cb, void **users, size_t user_count)
{
    if (!rt)
        return;
    rt->on_packet = cb;
    rt->worker_users = users;
    rt->worker_user_count = user_count;
}

void driver_filter_policy_init(driver_filter_policy_t *p)
{
    if (!p)
        return;
    memset(p, 0, sizeof(*p));

    p->bypass_tunnel = false;
    p->use_consumed = false;
}

/*
    역할: 두 MAC 주소가 동일한지 비교
    동작: 6바이트 MAC 주소를 memcmp로 비교함 true, false
    주의 포인터 NULL 방어 포함
*/
bool mac_equal(const driver_mac_t *a, const driver_mac_t *b)
{
    if (!a || !b)
        return false;
    return memcmp(a->b, b->b, 6) == 0;
}

/*
    역할: 주어진 MAC 주소가 MAC 리스트에 포함되어 있는지 검사
    동작: 리스트를 선형탐색(O(n)), 하나라도 일치하면 true 반환
    사용 위치: MAC DROP 정책 검사함, MAC BYPASS 정책 검사
    주의: list는 배열 시작 주소, cnt는 실제 유효한 항목 개수
*/
bool mac_in_list(const driver_mac_t *mac, const driver_mac_t *list, uint32_t cnt)
{
    if (!mac || !list || cnt == 0)
        return false;
    for (uint32_t i = 0; i < cnt; i++)
    {
        if (mac_equal(mac, &list[i]))
            return true;
    }
    return false;
}

/**
 * @brief 주어진 포트가 포트 리스트에 포함되어 있는지 검사
 *
 * @param port 검사할 포트 번호
 * @param list 포트 번호 리스트 (배열 시작 주소)
 * @param cnt 리스트 내 유효한 포트 번호 개수
 * @return true / flase
 */
bool port_in_list(uint16_t port, const uint16_t *list, uint32_t cnt)
{
    if (!list || cnt == 0)
        return false;
    for (uint32_t i = 0; i < cnt; i++)
    {
        if (port == list[i])
            return true;
    }
    return false;
}

/**
 * @brief 해당 패킷이 소속 평가 함수
 * 패킷 메타데이터와 필터 정책을 입력받아
 * 해당 패킷이 DROP/BYPASS/CONSUMED/PASS 중 어디에 해당하는지 평가하는 함수
 * @param m 패킷 메타데이터
 * @param p 필터 정책
 * @return plugin_handler_result_t
 */
plugin_handler_result_t driver_filter_eval(const driver_pkt_meta_t *m, const driver_filter_policy_t *p)
{
    // 입력 유효성 검사
    if (!m || !p)
        return PLUGIN_HANDLER_PASS;

    // 터널링 BYPASS 조건
    // - 정책에서 bypass_tunnel == true 인지 확인
    // - m->is_tunnel == true이면 BYPASS 반환
    if (p->bypass_tunnel && m->is_tunnel)
        return PLUGIN_HANDLER_BYPASS;

    // MAC_DROP 검사
    // src_mac 또는 dst_mac이 mac_drop 리스트에 포함되는지 검사
    // 매칭 시 use_consumed == true -> CONSUMED  else DROP
    if (p->mac_drop_cnt > 0 &&
        (mac_in_list(&m->src_mac, p->mac_drop, p->mac_drop_cnt) ||
         mac_in_list(&m->dst_mac, p->mac_drop, p->mac_drop_cnt)))
    {
        // DROP/CONSUMED 선택
        return p->use_consumed ? PLUGIN_HANDLER_CONSUMED : PLUGIN_HANDLER_DROP;
    }

    // PORT 검사
    if (p->port_drop_cnt > 0 &&
        (port_in_list(m->src_port, p->port_drop, p->port_drop_cnt) ||
         port_in_list(m->dst_port, p->port_drop, p->port_drop_cnt)))
    {
        /* DROP/CONSUMED 선택*/
        return p->use_consumed ? PLUGIN_HANDLER_CONSUMED : PLUGIN_HANDLER_DROP;
    }

    // MAC BYPASS 검사
    if (p->mac_bypass_cnt > 0 &&
        (mac_in_list(&m->src_mac, p->mac_bypass, p->mac_bypass_cnt) ||
         mac_in_list(&m->dst_mac, p->mac_bypass, p->mac_bypass_cnt)))
    {
        return PLUGIN_HANDLER_BYPASS;
    }

    // PORT BYPASS 검사
    if (p->port_bypass_cnt > 0 &&
        (port_in_list(m->src_port, p->port_bypass, p->port_bypass_cnt) ||
         port_in_list(m->dst_port, p->port_bypass, p->port_bypass_cnt)))
    {
        return PLUGIN_HANDLER_BYPASS;
    }

    // 기본동작
    return PLUGIN_HANDLER_PASS;
    // 위 조건에 모두 해당하지 않으면 정상 검사 대상으로 간주하고
    // PASS 반환
}

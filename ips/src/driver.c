/**
 * @file driver.c
 * @brief 패킷 캡처 및 드라이버 구현
 */
#include "driver.h"
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>

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
        return EIO;

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

int capture_poll_once(capture_ctx_t *cc)
{
    // 1) 인자 검증
    if (!cc || !cc->handle || !cc->ring)
        return EINVAL;
    struct pcap_pkthdr *hdr;
    const u_char *pkt;

    int ret = pcap_next_ex(cc->handle, &hdr, &pkt);
    if (ret == 1)
    {
        uint64_t ts_ns = ((uint64_t)hdr->ts.tv_sec * 1000000000ULL) +
                         ((uint64_t)hdr->ts.tv_usec * 1000ULL);

        int rc = packet_ring_enq(cc->ring, pkt, hdr->caplen, ts_ns);
        if (rc != 0)
            return rc;
        return 1;
    }
    if (ret == 0)
        return 0;
    if (ret == -2)
        return -2;
    return EIO;
}

int capture_loop(capture_ctx_t *cc)
{
    if (!cc || !cc->handle || !cc->ring)
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
    driver_runtime_t *rt = arg;

    uint8_t buf[PACKET_MAX_BYTES];
    uint32_t len;
    uint64_t ts;

    while (!atomic_load(&rt->stop))
    {
        int rc = packet_ring_deq(rt->cc.ring, buf, sizeof(buf), &len, &ts);
        if (rc == 0)
        {
            if (rt->on_packet)
                rt->on_packet(buf, len, ts, rt->on_packet_user);
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

    if (!rt->worker_tids)
        return ENOMEM;
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
        if (pthread_create(&rt->worker_tids[i], NULL, worker_thread_func, rt) != 0)
        {
            atomic_store(&rt->stop, true);
            if (rt->cc.ring)
            {
                pthread_mutex_lock(&rt->cc.ring->mu);
                rt->cc.ring->use_blocking = 0;
                pthread_cond_broadcast(&rt->cc.ring->not_empty);
                pthread_cond_broadcast(&rt->cc.ring->not_full);
                pthread_mutex_unlock(&rt->cc.ring->mu);
            }
            for (int j = 0; j < i; j++)
                pthread_join(rt->worker_tids[j], NULL);
            return EIO;
        }
    }

    if (pthread_create(&rt->capture_tid, NULL, capture_thread_func, rt) != 0)
    {
        atomic_store(&rt->stop, true);
        if (rt->cc.ring)
        {
            pthread_mutex_lock(&rt->cc.ring->mu);
            rt->cc.ring->use_blocking = 0;
            pthread_cond_broadcast(&rt->cc.ring->not_empty);
            pthread_cond_broadcast(&rt->cc.ring->not_full);
            pthread_mutex_unlock(&rt->cc.ring->mu);
        }
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

    if (rt->cc.ring)
    {
        pthread_mutex_lock(&rt->cc.ring->mu);
        rt->cc.ring->use_blocking = 0;
        pthread_cond_broadcast(&rt->cc.ring->not_empty);
        pthread_cond_broadcast(&rt->cc.ring->not_full);
        pthread_mutex_unlock(&rt->cc.ring->mu);
    }

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
    free(rt->worker_tids);
    rt->worker_tids = NULL;
}

void driver_set_packet_handler(driver_runtime_t *rt, driver_packet_cb cb, void *user)
{
    if (!rt)
        return;
    rt->on_packet = cb;
    rt->on_packet_user = user;
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

/*
    역할: 특정 포트 번호가 리스트에 포함되어 있는지 검사
    동작: 리스트를 선형 탐색, 일치하면 true
    사용 위치: PORT DROP 정책, PORT BYPASS 정책
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
    if(p->mac_drop_cnt > 0 && 
        (mac_in_list(&m->src_mac, p->mac_drop, p->mac_drop_cnt) ||
        mac_in_list(&m->dst_mac, p->mac_drop, p->mac_drop_cnt)))
    {
        // DROP/CONSUMED 선택
        return p->use_consumed ? PLUGIN_HANDLER_CONSUMED : PLUGIN_HANDLER_DROP;
    }

    // PORT 검사
    if(p->port_drop_cnt > 0 &&
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

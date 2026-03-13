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

/**
 * @brief (ip, port) 두 엔드포인트를 사전식 비교함
 * 
 * @param a_ip 종단간 엔드포인트
 * @param a_port 
 * @param b_ip 
 * @param b_port 
 * @return int 
 */
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

/**
 * @brief 매개인자를 합쳐서 해시화하는 함수
 * 
 * @param sip 
 * @param dip 
 * @param sport 
 * @param dport 
 * @param proto 
 * @return uint32_t 
 */
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

static uint32_t flow_hash_fragment(uint32_t sip, uint32_t dip, uint16_t ip_id, uint8_t proto)
{
    uint32_t h = 2166136261u;
    h ^= sip;
    h *= 16777619u;
    h ^= dip;
    h *= 16777619u;
    h ^= ip_id;
    h *= 16777619u;
    h ^= proto;
    h *= 16777619u;
    return h;
}

static int parse_ipv4_dispatch_key(const uint8_t *pkt, uint32_t len,
                                   const uint8_t **l4,
                                   uint32_t *l4_len,
                                   uint32_t *sip, uint32_t *dip,
                                   uint16_t *ip_id, uint16_t *frag_field,
                                   uint8_t *proto)
{
    const uint8_t *p = pkt;
    uint32_t n;
    uint16_t eth_type;
    uint32_t ihl;
    uint16_t total_len;

    if (!pkt || !l4 || !l4_len || !sip || !dip || !ip_id || !frag_field || !proto)
        return 0;
    if (len < 14 + 20)
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

    *ip_id = (uint16_t)((p[4] << 8) | p[5]);
    *frag_field = (uint16_t)((p[6] << 8) | p[7]);
    *sip = (uint32_t)((p[12] << 24) | (p[13] << 16) | (p[14] << 8) | p[15]);
    *dip = (uint32_t)((p[16] << 24) | (p[17] << 16) | (p[18] << 8) | p[19]);
    *l4 = p + ihl;
    *l4_len = (uint32_t)(total_len - ihl);
    return 1;
}

/**
 * @brief 이더넷 프레임에서 ipv4, tcp/udp 5-tuple 추츨 함수
 * 
 * @param pkt 
 * @param len 
 * @param sip 
 * @param dip 
 * @param sport 
 * @param dport 
 * @param proto 
 * @return int 
 */
static int parse_ipv4_5tuple(const uint8_t *pkt, uint32_t len,
                             uint32_t *sip, uint32_t *dip,
                             uint16_t *sport, uint16_t *dport,
                             uint8_t *proto)
{
    const uint8_t *l4 = NULL;
    uint32_t l4_len = 0;
    uint16_t ip_id = 0;
    uint16_t frag_field = 0;
    uint16_t frag_offset;

    if (!sport || !dport)
        return 0;
    if (!parse_ipv4_dispatch_key(pkt, len, &l4, &l4_len, sip, dip, &ip_id, &frag_field, proto))
        return 0;

    (void)ip_id;
    frag_offset = (uint16_t)(frag_field & 0x1FFFu);
    if ((frag_field & 0x2000u) != 0 || frag_offset != 0)
        return 0;
    if (l4_len < 8)
        return 0;

    *sport = (uint16_t)((l4[0] << 8) | l4[1]);
    *dport = (uint16_t)((l4[2] << 8) | l4[3]);
    return 1;
}

/**
 * @brief 패킷을 누구에게 보낼건지 결정하는 함수
 * 정상 패킷은 flow hash , 외에는 round-robin fallback
 * capture -> queue 사이의 분배기 역할
 * @param cc 
 * @param pkt 
 * @param len 
 * @param worker_count 
 * @return uint32_t 
 */
static uint32_t pick_worker_idx(capture_ctx_t *cc, const uint8_t *pkt, uint32_t len, uint32_t worker_count)
{
    const uint8_t *l4 = NULL;
    uint32_t l4_len = 0;
    uint32_t sip = 0, dip = 0;
    uint16_t sport = 0, dport = 0;
    uint16_t ip_id = 0;
    uint16_t frag_field = 0;
    uint16_t frag_offset = 0;
    uint8_t proto = 0;

    if (worker_count == 0)
        return 0;
    if (parse_ipv4_5tuple(pkt, len, &sip, &dip, &sport, &dport, &proto))
        return flow_hash_5tuple(sip, dip, sport, dport, proto) % worker_count;
    if (parse_ipv4_dispatch_key(pkt, len, &l4, &l4_len, &sip, &dip, &ip_id, &frag_field, &proto))
    {
        (void)l4;
        (void)l4_len;
        frag_offset = (uint16_t)(frag_field & 0x1FFFu);
        if ((frag_field & 0x2000u) != 0 || frag_offset != 0)
            return flow_hash_fragment(sip, dip, ip_id, proto) % worker_count;
    }

    {
        uint32_t idx = cc->rr % worker_count;
        cc->rr++;
        return idx;
    }
}

/**
 * @brief 종료시 block중인 큐 대기 스레드들을 깨우는 함수
 * 
 * @param rt 
 */
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

static void wake_capture_handle(capture_ctx_t *cc)
{
    if (!cc || !cc->handle)
        return;
    pcap_breakloop(cc->handle);
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

    /* libpcap에d 실제로 패킷을 읽는 지점 */
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

static void *capture_thread_func(void *arg)
{
    driver_runtime_t *rt = arg;
    while (!atomic_load(&rt->stop))
    {
        int rc = capture_poll_once(&rt->cc);
        if (rc == 1)
            continue;
        if (rc == 0 || rc == EAGAIN)
        {
            usleep(200);
            continue;
        }
        if (rc == -2)
            break;

        atomic_store(&rt->last_error, rc);
        atomic_store(&rt->failed, true);
        atomic_store(&rt->stop, true);
        wake_all_queues(rt);
        fprintf(stderr, "[PCAP] capture thread stopping rc=%d\n", rc);
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
                void *user = NULL;
                pthread_mutex_lock(&rt->handler_mu);
                if(rt->worker_users)
                {
                    if(idx < rt->worker_user_count)
                    {
                        user = rt->worker_users[idx];
                    }
                }
                else
                {
                    user = rt->on_packet_user;
                }
                pthread_mutex_unlock(&rt->handler_mu);
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

/**
 * @brief 드라이버 초기화 함수
 * 런타임 구조체(rt)의 상태를 초기화하고
 * 워커 스레드 구동에 필요한 메모리와 큐를 할당
 * @param rt
 * @param worker_count
 * @return int
 */
int driver_init(driver_runtime_t *rt, int worker_count)
{
    if (!rt || worker_count <= 0)
        return EINVAL;

    rt->cc.handle = NULL;
    rt->cc.queues = NULL;
    rt->cc.rr = 0;
    rt->capture_tid = (pthread_t)0;
    rt->worker_tids = NULL;
    rt->worker_args = NULL;
    rt->worker_count = 0;
    rt->capture_started = 0;
    rt->workers_started = 0;
    atomic_init(&rt->stop, false);
    atomic_init(&rt->failed, false);
    atomic_init(&rt->last_error, 0);
    rt->on_packet = NULL;
    rt->on_packet_user = NULL;
    rt->worker_users = NULL;
    rt->worker_user_count = 0;
    memset(&rt->queues, 0, sizeof(rt->queues));

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
    if (pthread_mutex_init(&rt->handler_mu, NULL) != 0)
    {
        free(rt->worker_tids);
        free(rt->worker_args);
        rt->worker_tids = NULL;
        rt->worker_args = NULL;
        return EIO;
    }
    int qrc = packet_queue_set_init(&rt->queues, (uint32_t)worker_count, DEFAULT_SLOT_COUNT, 1);
    if (qrc != 0)
    {
        pthread_mutex_destroy(&rt->handler_mu);
        free(rt->worker_tids);
        free(rt->worker_args);
        rt->worker_tids = NULL;
        rt->worker_args = NULL;
        return qrc;
    }
    rt->cc.queues = &rt->queues;
    rt->cc.rr = 0;
    return 0;
}

/**
 * @brief 드라이버 실행 함수
 * 실제 워커 스레드들과 패킷 캡처 스레드를 생성하고 구동함
 * @param rt 드라이버 런타임 컨텍스트
 * @return int
 */
int driver_start(driver_runtime_t *rt)
{
    if (!rt)
        return EINVAL;
    if (!rt->worker_tids)
        return EINVAL;

    rt->workers_started = 0;
    rt->capture_started = 0;
    atomic_store(&rt->stop, false);

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
            {
                pthread_join(rt->worker_tids[j], NULL);
            }
            rt->workers_started = 0;
            return EIO;
        }
        rt->workers_started++;
    }

    if (pthread_create(&rt->capture_tid, NULL, capture_thread_func, rt) != 0)
    {
        atomic_store(&rt->stop, true);
        wake_all_queues(rt);
        for (int i = 0; i < rt->worker_count; i++)
        {
            pthread_join(rt->worker_tids[i], NULL);
        }
        rt->workers_started = 0;
        return EIO;
    }
    rt->capture_started = 1;
    return 0;
}

/**
 * @brief 정지 함수
 * 구동 중인 캡처 및 워커 스레드들을 안전하게 종료하기
 * @param rt
 * @return int
 */
int driver_stop(driver_runtime_t *rt)
{
    if(!rt)
    {
        return EINVAL;
    }
    if(!rt->capture_started && rt->workers_started == 0)
    {
        return 0;
    }

    atomic_store(&rt->stop, true);
    
    if(rt->capture_started)
    {
        wake_capture_handle(&rt->cc);
    }

    if(rt->workers_started > 0)
    {
        wake_all_queues(rt);
    }

    if(rt->capture_started)
    {
        pthread_join(rt->capture_tid, NULL);
        rt->capture_tid = (pthread_t)0;
        rt->capture_started = 0;
    }

    for(int i=0; i<rt->workers_started; i++)
    {
        pthread_join(rt->worker_tids[i], NULL);
    }

    rt->workers_started = 0;
    return 0;
}
/**
 * @brief 드라이버의 자원 해제 함수
 * 시스템 자원 반환
 * @param rt 런타임 객체
 */
void driver_destroy(driver_runtime_t *rt)
{
    if (!rt)
        return;

    (void)driver_stop(rt);

    capture_close(&rt->cc);
    packet_queue_set_destroy(&rt->queues);

    free(rt->worker_tids);
    rt->worker_tids = NULL;

    free(rt->worker_args);
    rt->worker_args = NULL;

    rt->worker_users = NULL;
    rt->worker_user_count = 0;
    rt->on_packet = NULL;
    rt->on_packet_user = NULL;
    rt->worker_count = 0;
    rt->cc.queues = NULL;
    pthread_mutex_destroy(&rt->handler_mu);

    atomic_store(&rt->failed, false);
    atomic_store(&rt->last_error, 0);
}
/**
 * @brief main.c에서 캡처 스레드 죽었는지 감시하는 함수
 *
 * @param rt 런타임
 * @return int
 */
int driver_has_failed(driver_runtime_t *rt)
{
    if (!rt)
        return 0;
    return atomic_load(&rt->failed) ? 1 : 0;
}

/**
 * @brief 실패가 있었다면 마지막 에러 꺼내기
 *
 * @param rt 런타임
 * @return int
 */
int driver_last_error(driver_runtime_t *rt)
{
    if (!rt)
        return EINVAL;
    return atomic_load(&rt->last_error);
}

/**
 * @brief wokrer가 쓸 패킷 콜백, user 포인터 등록
 * 워커는 dequeue 이후 이 콜백을 호출한다.
 * @param rt 런타임
 * @param cb 콜백
 * @param user 유저 포인터
 */
void driver_set_packet_handler(driver_runtime_t *rt, driver_packet_cb cb, void *user)
{
    if (!rt)
        return;

    pthread_mutex_lock(&rt->handler_mu);
    rt->on_packet = cb;
    rt->on_packet_user = user;

    rt->worker_users = NULL;
    rt->worker_user_count = 0;
    pthread_mutex_unlock(&rt->handler_mu);
}

/**
 * @brief 콜백은 하나지만, 워커마다 다른 user 포인터 배열 등록
 *
 * @param rt 런타임
 * @param cb 콜백
 * @param users 유저들 배열
 * @param user_count 유저들 수
 */
void driver_set_packet_handler_multi(driver_runtime_t *rt, driver_packet_cb cb, void **users, size_t user_count)
{
    if (!rt)
        return;
    pthread_mutex_lock(&rt->handler_mu);
    rt->on_packet = cb;
    rt->worker_users = users;
    rt->worker_user_count = user_count;

    rt->on_packet_user = NULL;
    pthread_mutex_unlock(&rt->handler_mu);
}

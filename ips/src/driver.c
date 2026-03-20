/**
 * @file driver.c
 * @brief 패킷 캡처 드라이버 구현
 */
#include "driver.h"

#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

typedef struct worker_arg {
    driver_runtime_t *rt;
    uint32_t          index;
} worker_arg_t;

/**
 * @brief (ip, port) 두 엔드포인트를 사전식 비교함
 *
 * @param a_ip 종단간 엔드포인트
 * @param a_port 종단간 엔드포인트
 * @param b_ip 종단간 엔드포인트
 * @param b_port 종단간 엔드포인트
 * @return int
 */
static int endpoint_cmp(uint32_t a_ip, uint16_t a_port, uint32_t b_ip,
                        uint16_t b_port) {
    if (a_ip < b_ip) {
        return -1;
    }
    if (a_ip > b_ip) {
        return 1;
    }
    if (a_port < b_port) {
        return -1;
    }
    if (a_port > b_port) {
        return 1;
    }
    return 0;
}

/**
 * @brief 4개의 정수 필드를 FNV 스타일로 섞어 32비트 해시를 만든다.
 *
 * @param a 첫 번째 필드
 * @param b 두 번째 필드
 * @param c 세 번째 필드
 * @param d 네 번째 필드
 * @return uint32_t 계산된 해시값
 */
static uint32_t flow_hash_mix4(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    uint32_t h = 2166136261u;

    h ^= a;
    h *= 16777619u;

    h ^= b;
    h *= 16777619u;

    h ^= c;
    h *= 16777619u;

    h ^= d;
    h *= 16777619u;

    return h;
}

/**
 * @brief TCP/UDP 5-tuple을 기반으로 worker 분산용 해시값을 계산한다.
 *
 * src/dst endpoint를 사전식으로 정렬한 뒤 해시하므로,
 * 같은 flow는 방향이 바뀌어도 동일한 해시값을 만든다.
 *
 * @param sip source IPv4 address
 * @param dip destination IPv4 address
 * @param sport source L4 port
 * @param dport destination L4 port
 * @param proto L4 protocol number
 * @return uint32_t 계산된 32비트 flow hash
 */
static uint32_t flow_hash_5tuple(uint32_t sip, uint32_t dip, uint16_t sport,
                                 uint16_t dport, uint8_t proto) {
    int cmp;

    cmp = endpoint_cmp(sip, sport, dip, dport);
    if (0 < cmp) {
        uint32_t tmp_ip   = sip;
        uint16_t tmp_port = sport;
        sip               = dip;
        sport             = dport;
        dip               = tmp_ip;
        dport             = tmp_port;
    }

    uint32_t h =
        flow_hash_mix4(sip, dip, ((uint32_t)sport << 16) | dport, proto);
    return h;
}

/**
 * @brief IPv4 fragment용 worker 분산 해시값을 계산한다.
 *
 * fragment에는 port 정보가 없으므로 src/dst IP와 IP ID, proto를 이용해
 * 해시를 계산한다. src/dst IP 순서를 정규화해 양방향 대칭성을 맞춘다.
 *
 * @param sip source IPv4 address
 * @param dip destination IPv4 address
 * @param ip_id IPv4 identification field
 * @param proto IP protocol number
 * @return uint32_t 계산된 32비트 fragment hash
 */
static uint32_t flow_hash_fragment(uint32_t sip, uint32_t dip, uint16_t ip_id,
                                   uint8_t proto) {
    int cmp;

    cmp = endpoint_cmp(sip, 0, dip, 0);
    if (0 < cmp) {
        uint32_t tmp_ip = sip;
        sip             = dip;
        dip             = tmp_ip;
    }

    uint32_t h = flow_hash_mix4(sip, dip, ip_id, proto);
    return h;
}

/**
 * @brief 이더넷 프레임에서 worker 분산에 필요한 IPv4 키를 추출한다.
 *
 * VLAN 태그가 있으면 이를 건너뛰고 IPv4 헤더를 파싱해 src/dst IP,
 * IP ID, fragment field, L4 시작 위치를 돌려준다.
 *
 * @param pkt 원본 패킷
 * @param len 패킷 길이
 * @param l4 L4 시작 주소
 * @param l4_len L4 길이
 * @param sip source IPv4
 * @param dip destination IPv4
 * @param ip_id IPv4 identification
 * @param frag_field IPv4 fragment field
 * @param proto IP protocol
 * @return int 성공이면 1, 아니면 0
 */
static int parse_ipv4_dispatch_key(const uint8_t *pkt, uint32_t len,
                                   const uint8_t **l4, uint32_t *l4_len,
                                   uint32_t *sip, uint32_t *dip,
                                   uint16_t *ip_id, uint16_t *frag_field,
                                   uint8_t *proto) {
    const uint8_t *p = pkt;
    uint32_t       n;
    uint16_t       eth_type;
    uint32_t       ihl;
    uint16_t       total_len;

    if (!pkt || !l4 || !l4_len || !sip || !dip || !ip_id || !frag_field ||
        !proto) {
        return 0;
    }
    if ((14 + 20) > len) {
        return 0;
    }

    eth_type = (uint16_t)((p[12] << 8) | p[13]);
    p += 14;
    n = len - 14;

    if (0x8100 == eth_type || 0x88A8 == eth_type) {
        if (4 > n) {
            return 0;
        }
        eth_type = (uint16_t)((p[2] << 8) | p[3]);
        p += 4;
        n -= 4;
    }

    if (0x0800 != eth_type || 20 > n) {
        return 0;
    }
    if (4 != (p[0] >> 4)) {
        return 0;
    }

    ihl = (uint32_t)(p[0] & 0x0F) * 4U;
    if (20 > ihl || ihl > n) {
        return 0;
    }
    total_len = (uint16_t)((p[2] << 8) | p[3]);
    if (total_len < ihl || n < total_len) {
        return 0;
    }

    *proto = p[9];
    if (*proto != IPPROTO_TCP && *proto != IPPROTO_UDP) {
        return 0;
    }

    *ip_id      = (uint16_t)((p[4] << 8) | p[5]);
    *frag_field = (uint16_t)((p[6] << 8) | p[7]);
    *sip    = (uint32_t)((p[12] << 24) | (p[13] << 16) | (p[14] << 8) | p[15]);
    *dip    = (uint32_t)((p[16] << 24) | (p[17] << 16) | (p[18] << 8) | p[19]);
    *l4     = p + ihl;
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
static int parse_ipv4_5tuple(const uint8_t *pkt, uint32_t len, uint32_t *sip,
                             uint32_t *dip, uint16_t *sport, uint16_t *dport,
                             uint8_t *proto) {
    const uint8_t *l4         = NULL;
    uint32_t       l4_len     = 0;
    uint16_t       ip_id      = 0;
    uint16_t       frag_field = 0;
    uint16_t       frag_offset;
    int            ret;

    if (NULL == sport || NULL == dport) {
        return 0;
    }
    ret = parse_ipv4_dispatch_key(pkt, len, &l4, &l4_len, sip, dip, &ip_id,
                                  &frag_field, proto);
    if (0 == ret) {
        return 0;
    }

    (void)ip_id;
    frag_offset = (uint16_t)(frag_field & 0x1FFFu);
    if (0 != (frag_field & 0x2000u) || 0 != frag_offset) {
        return 0;
    }
    if (8 > l4_len) {
        return 0;
    }

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
static uint32_t pick_worker_idx(capture_ctx_t *cc, const uint8_t *pkt,
                                uint32_t len, uint32_t worker_count) {
    const uint8_t *l4     = NULL;
    uint32_t       l4_len = 0;
    uint32_t       sip = 0, dip = 0;
    uint16_t       sport = 0, dport = 0;
    uint16_t       ip_id       = 0;
    uint16_t       frag_field  = 0;
    uint16_t       frag_offset = 0;
    uint8_t        proto       = 0;
    int            ret;

    if (0 == worker_count) {
        return 0;
    }
    ret = parse_ipv4_5tuple(pkt, len, &sip, &dip, &sport, &dport, &proto);
    if (0 != ret) {
        return flow_hash_5tuple(sip, dip, sport, dport, proto) % worker_count;
    }
    ret = parse_ipv4_dispatch_key(pkt, len, &l4, &l4_len, &sip, &dip, &ip_id,
                                  &frag_field, &proto);
    if (0 != ret) {
        (void)l4;
        (void)l4_len;
        frag_offset = (uint16_t)(frag_field & 0x1FFFu);
        if (0 != (frag_field & 0x2000u) || 0 != frag_offset) {
            return flow_hash_fragment(sip, dip, ip_id, proto) % worker_count;
        }
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
static void wake_all_queues(driver_runtime_t *rt) {
    if (NULL == rt) {
        return;
    }

    for (uint32_t i = 0; i < rt->queues.qcount; i++) {
        packet_ring_t *r = &rt->queues.q[i];
        atomic_store_explicit(&r->use_blocking, 0, memory_order_release);
    }
}

/**
 * @brief blocking libpcap 호출을 종료 방향으로 깨운다.
 *
 * @param cc 캡처 컨텍스트
 */
static void wake_capture_handle(capture_ctx_t *cc) {
    if (NULL == cc || NULL == cc->handle) {
        return;
    }
    pcap_breakloop(cc->handle);
}

/* 전체 사용 흐름
capture_create(&cc, &pc);
capture_activate(&cc, &pc);
*/
int capture_create(capture_ctx_t *cc, pcap_ctx_t *pc) {
    int ret;

    if (NULL == cc || NULL == pc || NULL == pc->dev) {
        return -1;
    }
    cc->handle = NULL;

    char    errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *h = pcap_create(pc->dev, errbuf);
    if (!h) {
        return -1;
    }

    /* snaplen/promisc/timeout 같은 capture 기본 속성을 먼저 설정한다. */
    ret = pcap_set_snaplen(h, pc->snaplen);
    if (0 != ret) {
        goto fail;
    }
    ret = pcap_set_promisc(h, pc->promisc);
    if (0 != ret) {
        goto fail;
    }
    ret = pcap_set_timeout(h, pc->timeout_ms);
    if (0 != ret) {
        goto fail;
    }

    cc->handle = h;
    return 0;

fail:
    pcap_close(h);
    return -1;
}

/**
 * @brief pcap handle을 실제 활성화하고 필요 시 non-blocking 모드를 건다.
 *
 * @param cc 캡처 컨텍스트
 * @param pc 사용자 pcap 설정
 * @return int 0이면 성공, 그 외 오류
 */
int capture_activate(capture_ctx_t *cc, pcap_ctx_t *pc) {
    int ret;

    if (NULL == cc || NULL == cc->handle) {
        return -1;
    }
    ret = pcap_activate(cc->handle);
    if (0 > ret) {
        /* fprintf(stderr, "pcap_activate failed ret=%d, err=%s\n", ret,
         * pcap_geterr(cc->handle)); */
        return -1;
    }

    if (pc && pc->nonblocking) {
        char errbuf[PCAP_ERRBUF_SIZE];
        ret = pcap_setnonblock(cc->handle, 1, errbuf);
        if (0 != ret) {
            return -1;
        }
    }
    return 0;
}

/**
 * @brief 열려 있는 pcap handle을 닫는다.
 *
 * @param cc 캡처 컨텍스트
 */
void capture_close(capture_ctx_t *cc) {
    if (!cc) {
        return;
    }
    if (cc->handle) {
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
int capture_poll_once(capture_ctx_t *cc) {
    /* 인자 검증 */
    if (NULL == cc || NULL == cc->handle || NULL == cc->queues ||
        0 == cc->queues->qcount) {
        return -1;
    }

    struct pcap_pkthdr *hdr;
    const u_char       *pkt;

    /* libpcap에서 실제 패킷 1건을 가져오는 지점이다. */
    int ret = pcap_next_ex(cc->handle, &hdr, &pkt);
    if (1 == ret) {
        uint64_t ts_ns = ((uint64_t)hdr->ts.tv_sec * 1000000000ULL) +
                         ((uint64_t)hdr->ts.tv_usec * 1000ULL);
        /* 5-tuple 또는 fragment hash로 worker queue를 골라 enqueue 한다. */
        uint32_t idx =
            pick_worker_idx(cc, pkt, hdr->caplen, cc->queues->qcount);
        int rc = packet_ring_enq(&cc->queues->q[idx], pkt, hdr->caplen, ts_ns);
        if (0 != rc) {
            return -1;
        }
        return 0;
    }

    if (0 == ret) {
        return 0;
    }

    if (ret == -2) {
        return -1;
    }

    return -1;
}

/**
 * @brief 캡처 스레드 메인 루프.
 *
 * 패킷을 읽어 worker queue로 넘기고, 오류 발생 시 stop 플래그와
 * 마지막 오류 코드를 기록한다.
 *
 * @param arg driver runtime
 * @return void* 항상 NULL
 */
static void *capture_thread_func(void *arg) {
    driver_runtime_t *rt = arg;
    int               stop;

    stop = atomic_load(&rt->stop);
    while (0 == stop) {
        int rc = capture_poll_once(&rt->cc);
        if (0 == rc) {
            stop = atomic_load(&rt->stop);
            continue;
        }

        stop = atomic_load(&rt->stop);
        if (0 != stop) {
            break;
        }

        atomic_store(&rt->last_error, rc);
        atomic_store(&rt->failed, true);
        atomic_store(&rt->stop, true);
        wake_all_queues(rt);
        /* fprintf(stderr, "[PCAP] capture thread stopping rc=%d\n", rc); */
        break;
    }
    return NULL;
}

/**
 * @brief worker 스레드 메인 루프.
 *
 * 자신의 ring queue에서 패킷을 dequeue 한 뒤 등록된 on_packet 콜백으로 넘긴다.
 *
 * @param arg worker 인자
 * @return void* 항상 NULL
 */
static void *worker_thread_func(void *arg) {
    worker_arg_t     *wa   = arg;
    driver_runtime_t *rt   = wa->rt;
    uint32_t          idx  = wa->index;
    packet_ring_t    *ring = &rt->queues.q[idx];
    uint8_t           buf[PACKET_MAX_BYTES];
    uint32_t          len;
    uint64_t          ts;
    int               stop;

    stop = atomic_load(&rt->stop);
    while (0 == stop) {
        int rc = packet_ring_deq(ring, buf, sizeof(buf), &len, &ts);
        if (0 == rc) {
            if (rt->on_packet) {
                void *user = NULL;
                pthread_mutex_lock(&rt->handler_mu);
                if (rt->worker_users) {
                    if (idx < rt->worker_user_count) {
                        user = rt->worker_users[idx];
                    }
                } else {
                    user = rt->on_packet_user;
                }
                pthread_mutex_unlock(&rt->handler_mu);
                rt->on_packet(buf, len, ts, user);
            }
            stop = atomic_load(&rt->stop);
            continue;
        }

        stop = atomic_load(&rt->stop);
        if (0 == stop) {
            continue;
        }
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
int driver_init(driver_runtime_t *rt, int worker_count) {
    int qrc;
    int ret;

    if (NULL == rt || 0 >= worker_count) {
        return -1;
    }

    rt->cc.handle       = NULL;
    rt->cc.queues       = NULL;
    rt->cc.rr           = 0;
    rt->capture_tid     = (pthread_t)0;
    rt->worker_tids     = NULL;
    rt->worker_args     = NULL;
    rt->worker_count    = 0;
    rt->capture_started = 0;
    rt->workers_started = 0;
    atomic_init(&rt->stop, false);
    atomic_init(&rt->failed, false);
    atomic_init(&rt->last_error, 0);
    rt->on_packet         = NULL;
    rt->on_packet_user    = NULL;
    rt->worker_users      = NULL;
    rt->worker_user_count = 0;
    memset(&rt->queues, 0, sizeof(rt->queues));

    rt->worker_count = worker_count;
    rt->worker_tids =
        (pthread_t *)malloc((size_t)worker_count * sizeof(pthread_t));
    rt->worker_args =
        (worker_arg_t *)malloc((size_t)worker_count * sizeof(worker_arg_t));

    if (NULL == rt->worker_tids || NULL == rt->worker_args) {
        free(rt->worker_tids);
        free(rt->worker_args);
        rt->worker_tids = NULL;
        rt->worker_args = NULL;
        return -1;
    }
    memset(rt->worker_tids, 0, (size_t)worker_count * sizeof(pthread_t));
    memset(rt->worker_args, 0, (size_t)worker_count * sizeof(worker_arg_t));

    ret = pthread_mutex_init(&rt->handler_mu, NULL);
    if (0 != ret) {
        free(rt->worker_tids);
        free(rt->worker_args);
        rt->worker_tids = NULL;
        rt->worker_args = NULL;
        return -1;
    }

    qrc = packet_queue_set_init(&rt->queues, (uint32_t)worker_count,
                                DEFAULT_SLOT_COUNT, 1);
    if (0 != qrc) {
        pthread_mutex_destroy(&rt->handler_mu);
        free(rt->worker_tids);
        free(rt->worker_args);
        rt->worker_tids = NULL;
        rt->worker_args = NULL;
        return qrc;
    }
    rt->cc.queues = &rt->queues;
    rt->cc.rr     = 0;
    return 0;
}

/**
 * @brief 드라이버 실행 함수
 * 실제 워커 스레드들과 패킷 캡처 스레드를 생성하고 구동함
 * @param rt 드라이버 런타임 컨텍스트
 * @return int
 */
int driver_start(driver_runtime_t *rt) {
    int ret;

    if (NULL == rt) {
        return -1;
    }
    if (NULL == rt->worker_tids) {
        return -1;
    }

    rt->workers_started = 0;
    rt->capture_started = 0;
    atomic_store(&rt->stop, false);

    for (int i = 0; i < rt->worker_count; i++) {
        worker_arg_t *wa = &((worker_arg_t *)rt->worker_args)[i];
        wa->rt           = rt;
        wa->index        = (uint32_t)i;

        ret = pthread_create(&rt->worker_tids[i], NULL, worker_thread_func, wa);
        if (0 != ret) {
            atomic_store(&rt->stop, true);
            wake_all_queues(rt);
            for (int j = 0; j < i; j++) {
                pthread_join(rt->worker_tids[j], NULL);
            }
            rt->workers_started = 0;
            return -1;
        }
        rt->workers_started++;
    }

    ret = pthread_create(&rt->capture_tid, NULL, capture_thread_func, rt);
    if (0 != ret) {
        atomic_store(&rt->stop, true);
        wake_all_queues(rt);
        for (int i = 0; i < rt->worker_count; i++) {
            pthread_join(rt->worker_tids[i], NULL);
        }
        rt->workers_started = 0;
        return -1;
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
int driver_stop(driver_runtime_t *rt) {
    if (NULL == rt) {
        return -1;
    }
    if (!rt->capture_started && 0 == rt->workers_started) {
        return 0;
    }

    atomic_store(&rt->stop, true);

    if (rt->capture_started) {
        wake_capture_handle(&rt->cc);
    }

    if (0 < rt->workers_started) {
        wake_all_queues(rt);
    }

    if (rt->capture_started) {
        pthread_join(rt->capture_tid, NULL);
        rt->capture_tid     = (pthread_t)0;
        rt->capture_started = 0;
    }

    for (int i = 0; i < rt->workers_started; i++) {
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
void driver_destroy(driver_runtime_t *rt) {
    if (!rt) {
        return;
    }

    (void)driver_stop(rt);

    capture_close(&rt->cc);
    packet_queue_set_destroy(&rt->queues);

    free(rt->worker_tids);
    rt->worker_tids = NULL;

    free(rt->worker_args);
    rt->worker_args = NULL;

    rt->worker_users      = NULL;
    rt->worker_user_count = 0;
    rt->on_packet         = NULL;
    rt->on_packet_user    = NULL;
    rt->worker_count      = 0;
    rt->cc.queues         = NULL;
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
int driver_has_failed(driver_runtime_t *rt) {
    if (!rt) {
        return 0;
    }
    return atomic_load(&rt->failed) ? 1 : 0;
}

/**
 * @brief 실패가 있었다면 마지막 에러 꺼내기
 *
 * @param rt 런타임
 * @return int
 */
int driver_last_error(driver_runtime_t *rt) {
    if (!rt) {
        return -1;
    }
    return atomic_load(&rt->last_error);
}

/**
 * @brief wokrer가 쓸 패킷 콜백, user 포인터 등록
 * 워커는 dequeue 이후 이 콜백을 호출한다.
 * @param rt 런타임
 * @param cb 콜백
 * @param user 유저 포인터
 */
void driver_set_packet_handler(driver_runtime_t *rt, driver_packet_cb cb,
                               void *user) {
    if (!rt) {
        return;
    }

    pthread_mutex_lock(&rt->handler_mu);
    rt->on_packet      = cb;
    rt->on_packet_user = user;

    rt->worker_users      = NULL;
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
void driver_set_packet_handler_multi(driver_runtime_t *rt, driver_packet_cb cb,
                                     void **users, size_t user_count) {
    if (!rt) {
        return;
    }
    pthread_mutex_lock(&rt->handler_mu);
    rt->on_packet         = cb;
    rt->worker_users      = users;
    rt->worker_user_count = user_count;

    rt->on_packet_user = NULL;
    pthread_mutex_unlock(&rt->handler_mu);
}

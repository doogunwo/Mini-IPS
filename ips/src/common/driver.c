/**
 * @file driver.c
 * @brief 패킷 캡처 드라이버 구현
 *
 * libpcap에서 패킷을 읽고, worker별 SPSC 링 버퍼로 분배하고,
 * worker thread가 최종 on_packet 콜백을 호출하도록 연결하는 모듈이다.
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
    /* 공유 driver runtime 포인터 */
    driver_runtime_t *rt;
    /* 담당 worker 인덱스 */
    uint32_t          index;
} worker_arg_t;

/* --------------------------- flow hashing / dispatch --------------------------- */

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
    /* 첫 번째 IP가 더 작음 */
    if (a_ip < b_ip) {
        return -1;
    }
    /* 첫 번째 IP가 더 큼 */
    if (a_ip > b_ip) {
        return 1;
    }
    /* IP가 같으면 port 비교 */
    if (a_port < b_port) {
        return -1;
    }
    /* 첫 번째 port가 더 큼 */
    if (a_port > b_port) {
        return 1;
    }
    /* endpoint 동일 */
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
    /* FNV 초기값 */
    uint32_t h = 2166136261u;

    /* 첫 번째 필드 반영 */
    h ^= a;
    /* FNV prime 곱 */
    h *= 16777619u;

    /* 두 번째 필드 반영 */
    h ^= b;
    /* FNV prime 곱 */
    h *= 16777619u;

    /* 세 번째 필드 반영 */
    h ^= c;
    /* FNV prime 곱 */
    h *= 16777619u;

    /* 네 번째 필드 반영 */
    h ^= d;
    /* FNV prime 곱 */
    h *= 16777619u;

    /* 최종 해시 반환 */
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
    /* endpoint 비교 결과 */
    int cmp;

    /* 양방향 대칭 해시를 위한 endpoint 정규화 */
    cmp = endpoint_cmp(sip, sport, dip, dport);
    if (0 < cmp) {
        /* IP swap 임시값 */
        uint32_t tmp_ip   = sip;
        /* port swap 임시값 */
        uint16_t tmp_port = sport;
        /* source/destination 교체 */
        sip               = dip;
        sport             = dport;
        dip               = tmp_ip;
        dport             = tmp_port;
    }

    /* 정규화된 5-tuple 해시 계산 */
    uint32_t h =
        flow_hash_mix4(sip, dip, ((uint32_t)sport << 16) | dport, proto);
    /* 최종 해시 반환 */
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
    /* endpoint 비교 결과 */
    int cmp;

    /* fragment도 src/dst를 정규화해 같은 flow를 같은 worker에 보낸다. */
    cmp = endpoint_cmp(sip, 0, dip, 0);
    if (0 < cmp) {
        /* IP swap 임시값 */
        uint32_t tmp_ip = sip;
        /* source/destination 교체 */
        sip             = dip;
        dip             = tmp_ip;
    }

    /* fragment 해시 계산 */
    uint32_t h = flow_hash_mix4(sip, dip, ip_id, proto);
    /* 최종 해시 반환 */
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
    /* 현재 파싱 위치 */
    const uint8_t *p = pkt;
    /* 남은 바이트 수 */
    uint32_t       n;
    /* Ethernet type */
    uint16_t       eth_type;
    /* IPv4 header length */
    uint32_t       ihl;
    /* IPv4 total length */
    uint16_t       total_len;

    /* 출력 포인터 유효성 검사 */
    if (!pkt || !l4 || !l4_len || !sip || !dip || !ip_id || !frag_field ||
        !proto) {
        return 0;
    }
    /* Ethernet + IPv4 최소 길이 검사 */
    if ((14 + 20) > len) {
        return 0;
    }

    /* Ethernet type 추출 */
    eth_type = (uint16_t)((p[12] << 8) | p[13]);
    /* Ethernet header 스킵 */
    p += 14;
    /* 남은 길이 갱신 */
    n = len - 14;

    /* VLAN tag 존재 시 안쪽 ethertype로 진입 */
    if (0x8100 == eth_type || 0x88A8 == eth_type) {
        if (4 > n) {
            return 0;
        }
        /* 내부 ethertype 읽기 */
        eth_type = (uint16_t)((p[2] << 8) | p[3]);
        /* VLAN header 스킵 */
        p += 4;
        /* 남은 길이 갱신 */
        n -= 4;
    }

    /* IPv4 frame 여부 및 최소 헤더 길이 검사 */
    if (0x0800 != eth_type || 20 > n) {
        return 0;
    }
    /* IPv4 version 검사 */
    if (4 != (p[0] >> 4)) {
        return 0;
    }

    /* IPv4 header length 계산 */
    ihl = (uint32_t)(p[0] & 0x0F) * 4U;
    /* IHL 유효성 검사 */
    if (20 > ihl || ihl > n) {
        return 0;
    }
    /* IPv4 total length 추출 */
    total_len = (uint16_t)((p[2] << 8) | p[3]);
    /* total length 유효성 검사 */
    if (total_len < ihl || n < total_len) {
        return 0;
    }

    /* IP protocol 저장 */
    *proto = p[9];
    /* TCP/UDP만 dispatch key로 사용 */
    if (*proto != IPPROTO_TCP && *proto != IPPROTO_UDP) {
        return 0;
    }

    /* IPv4 identification 저장 */
    *ip_id      = (uint16_t)((p[4] << 8) | p[5]);
    /* fragment field 저장 */
    *frag_field = (uint16_t)((p[6] << 8) | p[7]);
    /* source IPv4 추출 */
    *sip    = (uint32_t)((p[12] << 24) | (p[13] << 16) | (p[14] << 8) | p[15]);
    /* destination IPv4 추출 */
    *dip    = (uint32_t)((p[16] << 24) | (p[17] << 16) | (p[18] << 8) | p[19]);
    /* L4 시작 포인터 설정 */
    *l4     = p + ihl;
    /* L4 길이 계산 */
    *l4_len = (uint32_t)(total_len - ihl);
    /* 파싱 성공 */
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
    /* L4 시작 포인터 */
    const uint8_t *l4         = NULL;
    /* L4 길이 */
    uint32_t       l4_len     = 0;
    /* IPv4 identification */
    uint16_t       ip_id      = 0;
    /* fragment field */
    uint16_t       frag_field = 0;
    /* fragment offset */
    uint16_t       frag_offset;
    /* helper 반환값 */
    int            ret;

    /* port 출력 포인터 검사 */
    if (NULL == sport || NULL == dport) {
        return 0;
    }
    /* IPv4/L4 dispatch key 파싱 */
    ret = parse_ipv4_dispatch_key(pkt, len, &l4, &l4_len, sip, dip, &ip_id,
                                  &frag_field, proto);
    if (0 == ret) {
        return 0;
    }

    /* ip_id는 여기선 사용하지 않음 */
    (void)ip_id;
    /* fragment offset 추출 */
    frag_offset = (uint16_t)(frag_field & 0x1FFFu);
    /* fragmented packet이면 5-tuple 사용 불가 */
    if (0 != (frag_field & 0x2000u) || 0 != frag_offset) {
        return 0;
    }
    /* TCP/UDP 포트 읽기에 필요한 최소 길이 검사 */
    if (8 > l4_len) {
        return 0;
    }

    /* source port 추출 */
    *sport = (uint16_t)((l4[0] << 8) | l4[1]);
    /* destination port 추출 */
    *dport = (uint16_t)((l4[2] << 8) | l4[3]);
    /* 파싱 성공 */
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
    /* L4 시작 포인터 */
    const uint8_t *l4     = NULL;
    /* L4 길이 */
    uint32_t       l4_len = 0;
    /* IPv4 source/destination */
    uint32_t       sip = 0, dip = 0;
    /* L4 source/destination port */
    uint16_t       sport = 0, dport = 0;
    /* IPv4 identification */
    uint16_t       ip_id       = 0;
    /* fragment field */
    uint16_t       frag_field  = 0;
    /* fragment offset */
    uint16_t       frag_offset = 0;
    /* L4 protocol */
    uint8_t        proto       = 0;
    /* helper 반환값 */
    int            ret;

    /* worker가 없으면 0번 반환 */
    if (0 == worker_count) {
        return 0;
    }
    /* 5-tuple 파싱 가능하면 flow hash 사용 */
    ret = parse_ipv4_5tuple(pkt, len, &sip, &dip, &sport, &dport, &proto);
    if (0 != ret) {
        return flow_hash_5tuple(sip, dip, sport, dport, proto) % worker_count;
    }
    /* fragment는 fragment hash 사용 */
    ret = parse_ipv4_dispatch_key(pkt, len, &l4, &l4_len, &sip, &dip, &ip_id,
                                  &frag_field, &proto);
    if (0 != ret) {
        /* fragment fallback 경로에서 L4는 사용하지 않음 */
        (void)l4;
        /* fragment fallback 경로에서 L4 길이는 사용하지 않음 */
        (void)l4_len;
        /* fragment offset 추출 */
        frag_offset = (uint16_t)(frag_field & 0x1FFFu);
        if (0 != (frag_field & 0x2000u) || 0 != frag_offset) {
            return flow_hash_fragment(sip, dip, ip_id, proto) % worker_count;
        }
    }

    {
        /* round-robin 현재 인덱스 계산 */
        uint32_t idx = cc->rr % worker_count;
        /* 다음 round-robin 인덱스 증가 */
        cc->rr++;
        /* fallback worker 반환 */
        return idx;
    }
}

/**
 * @brief 종료시 block중인 큐 대기 스레드들을 깨우는 함수
 *
 * @param rt
 */
static void wake_all_queues(driver_runtime_t *rt) {
    /* runtime 포인터 검사 */
    if (NULL == rt) {
        return;
    }

    for (uint32_t i = 0; i < rt->queues.qcount; i++) {
        /* 대상 ring 포인터 */
        packet_ring_t *r = &rt->queues.q[i];
        /* blocking 해제로 대기 스레드 깨우기 */
        atomic_store_explicit(&r->use_blocking, 0, memory_order_release);
    }
}

/**
 * @brief blocking libpcap 호출을 종료 방향으로 깨운다.
 *
 * @param cc 캡처 컨텍스트
 */
static void wake_capture_handle(capture_ctx_t *cc) {
    /* capture context 및 handle 검사 */
    if (NULL == cc || NULL == cc->handle) {
        return;
    }
    /* blocking libpcap loop 중단 */
    pcap_breakloop(cc->handle);
}

/* 전체 사용 흐름
capture_create(&cc, &pc);
capture_activate(&cc, &pc);
*/
int capture_create(capture_ctx_t *cc, pcap_ctx_t *pc) {
    /* helper 반환값 */
    int ret;

    /* 입력 포인터 및 device 이름 검사 */
    if (NULL == cc || NULL == pc || NULL == pc->dev) {
        return -1;
    }
    /* handle 초기화 */
    cc->handle = NULL;

    /* libpcap 오류 버퍼 */
    char    errbuf[PCAP_ERRBUF_SIZE];
    /* pcap handle 생성 결과 */
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

    /* 초기화 완료된 handle 저장 */
    cc->handle = h;
    /* 생성 성공 */
    return 0;

fail:
    /* 중간 실패 시 handle 정리 */
    pcap_close(h);
    /* 생성 실패 */
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
    /* helper 반환값 */
    int ret;

    /* capture context 및 handle 검사 */
    if (NULL == cc || NULL == cc->handle) {
        return -1;
    }
    /* pcap handle 활성화 */
    ret = pcap_activate(cc->handle);
    if (0 > ret) {
        /* fprintf(stderr, "pcap_activate failed ret=%d, err=%s\n", ret,
         * pcap_geterr(cc->handle)); */
        return -1;
    }

    if (pc && pc->nonblocking) {
        /* libpcap 오류 버퍼 */
        char errbuf[PCAP_ERRBUF_SIZE];
        /* non-blocking 모드 설정 */
        ret = pcap_setnonblock(cc->handle, 1, errbuf);
        if (0 != ret) {
            return -1;
        }
    }
    /* 활성화 성공 */
    return 0;
}

/**
 * @brief 열려 있는 pcap handle을 닫는다.
 *
 * @param cc 캡처 컨텍스트
 */
void capture_close(capture_ctx_t *cc) {
    /* capture context 검사 */
    if (!cc) {
        return;
    }
    if (cc->handle) {
        /* pcap handle 종료 */
        pcap_close(cc->handle);
        /* handle 초기화 */
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

    /* libpcap packet header 포인터 */
    struct pcap_pkthdr *hdr;
    /* libpcap packet data 포인터 */
    const u_char       *pkt;

    /* libpcap에서 실제 패킷 1건을 가져오는 지점이다. */
    int ret = pcap_next_ex(cc->handle, &hdr, &pkt);
    if (1 == ret) {
        /* pcap timestamp를 ns 단위로 환산 */
        uint64_t ts_ns = ((uint64_t)hdr->ts.tv_sec * 1000000000ULL) +
                         ((uint64_t)hdr->ts.tv_usec * 1000ULL);
        /* 5-tuple 또는 fragment hash로 worker queue를 골라 enqueue 한다. */
        uint32_t idx =
            pick_worker_idx(cc, pkt, hdr->caplen, cc->queues->qcount);
        /* 선택된 worker queue에 패킷 enqueue */
        int rc = packet_ring_enq(&cc->queues->q[idx], pkt, hdr->caplen, ts_ns);
        if (0 != rc) {
            return -1;
        }
        /* 패킷 1건 처리 성공 */
        return 0;
    }

    /* timeout 또는 non-blocking empty */
    if (0 == ret) {
        return 0;
    }

    /* EOF 또는 breakloop */
    if (ret == -2) {
        return -1;
    }

    /* 그 외 pcap 오류 */
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
    /* 공유 runtime 포인터 */
    driver_runtime_t *rt = arg;
    /* stop 플래그 스냅샷 */
    int               stop;

    /* 초기 stop 상태 읽기 */
    stop = atomic_load(&rt->stop);
    while (0 == stop) {
        /* 패킷 1건 캡처 및 enqueue */
        int rc = capture_poll_once(&rt->cc);
        if (0 == rc) {
            /* 반복 전 stop 재확인 */
            stop = atomic_load(&rt->stop);
            continue;
        }

        /* 오류 후 stop 상태 재확인 */
        stop = atomic_load(&rt->stop);
        if (0 != stop) {
            break;
        }

        /* 마지막 오류 코드 저장 */
        atomic_store(&rt->last_error, rc);
        /* failure 상태 공개 */
        atomic_store(&rt->failed, true);
        /* 전체 정지 플래그 설정 */
        atomic_store(&rt->stop, true);
        /* 대기 중인 worker queue 깨우기 */
        wake_all_queues(rt);
        /* fprintf(stderr, "[PCAP] capture thread stopping rc=%d\n", rc); */
        break;
    }
    /* capture thread 종료 */
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
    /* worker 인자 포인터 */
    worker_arg_t     *wa   = arg;
    /* 공유 runtime 포인터 */
    driver_runtime_t *rt   = wa->rt;
    /* 담당 worker index */
    uint32_t          idx  = wa->index;
    /* 담당 ring 포인터 */
    packet_ring_t    *ring = &rt->queues.q[idx];
    /* dequeue payload 임시 버퍼 */
    uint8_t           buf[PACKET_MAX_BYTES];
    /* dequeue된 길이 */
    uint32_t          len;
    /* dequeue된 timestamp */
    uint64_t          ts;
    /* stop 플래그 스냅샷 */
    int               stop;

    /* 초기 stop 상태 읽기 */
    stop = atomic_load(&rt->stop);
    while (0 == stop) {
        /* 자기 ring에서 패킷 1건 dequeue */
        int rc = packet_ring_deq(ring, buf, sizeof(buf), &len, &ts);
        if (0 == rc) {
            /* on_packet 콜백 등록 여부 확인 */
            if (rt->on_packet) {
                /* 실제 콜백에 넘길 user 포인터 */
                void *user = NULL;
                /* handler 설정 보호 락 획득 */
                pthread_mutex_lock(&rt->handler_mu);
                if (rt->worker_users) {
                    /* worker별 user 배열 사용 여부 확인 */
                    if (idx < rt->worker_user_count) {
                        /* worker 전용 user 포인터 선택 */
                        user = rt->worker_users[idx];
                    }
                } else {
                    /* 공통 user 포인터 사용 */
                    user = rt->on_packet_user;
                }
                /* handler 설정 보호 락 해제 */
                pthread_mutex_unlock(&rt->handler_mu);
                /* 실제 on_packet 콜백 호출 */
                rt->on_packet(buf, len, ts, user);
            }
            /* 반복 전 stop 재확인 */
            stop = atomic_load(&rt->stop);
            continue;
        }

        /* dequeue 실패 후 stop 상태 확인 */
        stop = atomic_load(&rt->stop);
        if (0 == stop) {
            continue;
        }
        break;
    }
    /* worker thread 종료 */
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
    /* queue init 반환값 */
    int qrc;
    /* helper 반환값 */
    int ret;

    /* 입력 포인터 및 worker 수 검증 */
    if (NULL == rt || 0 >= worker_count) {
        return -1;
    }

    /* capture handle 초기화 */
    rt->cc.handle       = NULL;
    /* queue set 연결 포인터 초기화 */
    rt->cc.queues       = NULL;
    /* round-robin 인덱스 초기화 */
    rt->cc.rr           = 0;
    /* capture thread ID 초기화 */
    rt->capture_tid     = (pthread_t)0;
    /* worker thread ID 배열 초기화 */
    rt->worker_tids     = NULL;
    /* worker arg 배열 초기화 */
    rt->worker_args     = NULL;
    /* worker 수 초기화 */
    rt->worker_count    = 0;
    /* capture 시작 플래그 초기화 */
    rt->capture_started = 0;
    /* 시작된 worker 수 초기화 */
    rt->workers_started = 0;
    /* stop 플래그 초기화 */
    atomic_init(&rt->stop, false);
    /* failure 플래그 초기화 */
    atomic_init(&rt->failed, false);
    /* last_error 초기화 */
    atomic_init(&rt->last_error, 0);
    /* packet 콜백 초기화 */
    rt->on_packet         = NULL;
    /* 공통 user 포인터 초기화 */
    rt->on_packet_user    = NULL;
    /* worker별 user 배열 초기화 */
    rt->worker_users      = NULL;
    /* worker별 user 개수 초기화 */
    rt->worker_user_count = 0;
    /* queue set 구조체 초기화 */
    memset(&rt->queues, 0, sizeof(rt->queues));

    /* 실제 worker 수 저장 */
    rt->worker_count = worker_count;
    /* worker thread ID 배열 할당 */
    rt->worker_tids =
        (pthread_t *)malloc((size_t)worker_count * sizeof(pthread_t));
    /* worker arg 배열 할당 */
    rt->worker_args =
        (worker_arg_t *)malloc((size_t)worker_count * sizeof(worker_arg_t));

    /* 스레드 관련 배열 할당 실패 */
    if (NULL == rt->worker_tids || NULL == rt->worker_args) {
        /* 부분 할당 메모리 해제 */
        free(rt->worker_tids);
        /* 부분 할당 메모리 해제 */
        free(rt->worker_args);
        /* 포인터 초기화 */
        rt->worker_tids = NULL;
        /* 포인터 초기화 */
        rt->worker_args = NULL;
        return -1;
    }
    /* worker thread ID 배열 0 초기화 */
    memset(rt->worker_tids, 0, (size_t)worker_count * sizeof(pthread_t));
    /* worker arg 배열 0 초기화 */
    memset(rt->worker_args, 0, (size_t)worker_count * sizeof(worker_arg_t));

    /* handler mutex 초기화 */
    ret = pthread_mutex_init(&rt->handler_mu, NULL);
    if (0 != ret) {
        /* worker thread ID 배열 해제 */
        free(rt->worker_tids);
        /* worker arg 배열 해제 */
        free(rt->worker_args);
        /* 포인터 초기화 */
        rt->worker_tids = NULL;
        /* 포인터 초기화 */
        rt->worker_args = NULL;
        return -1;
    }

    /* worker 수만큼 queue set 생성 */
    qrc = packet_queue_set_init(&rt->queues, (uint32_t)worker_count,
                                DEFAULT_SLOT_COUNT, 1);
    if (0 != qrc) {
        /* mutex 정리 */
        pthread_mutex_destroy(&rt->handler_mu);
        /* worker thread ID 배열 해제 */
        free(rt->worker_tids);
        /* worker arg 배열 해제 */
        free(rt->worker_args);
        /* 포인터 초기화 */
        rt->worker_tids = NULL;
        /* 포인터 초기화 */
        rt->worker_args = NULL;
        return qrc;
    }
    /* capture context에 queue set 연결 */
    rt->cc.queues = &rt->queues;
    /* round-robin 인덱스 초기화 */
    rt->cc.rr     = 0;
    /* driver init 성공 */
    return 0;
}

/**
 * @brief 드라이버 실행 함수
 * 실제 워커 스레드들과 패킷 캡처 스레드를 생성하고 구동함
 * @param rt 드라이버 런타임 컨텍스트
 * @return int
 */
int driver_start(driver_runtime_t *rt) {
    /* helper 반환값 */
    int ret;

    /* runtime 포인터 검사 */
    if (NULL == rt) {
        return -1;
    }
    /* worker 배열 준비 여부 검사 */
    if (NULL == rt->worker_tids) {
        return -1;
    }

    /* 시작된 worker 수 초기화 */
    rt->workers_started = 0;
    /* capture 시작 플래그 초기화 */
    rt->capture_started = 0;
    /* stop 플래그 해제 */
    atomic_store(&rt->stop, false);

    for (int i = 0; i < rt->worker_count; i++) {
        /* i번째 worker arg 포인터 */
        worker_arg_t *wa = &((worker_arg_t *)rt->worker_args)[i];
        /* runtime 연결 */
        wa->rt           = rt;
        /* worker index 기록 */
        wa->index        = (uint32_t)i;

        /* worker thread 생성 */
        ret = pthread_create(&rt->worker_tids[i], NULL, worker_thread_func, wa);
        if (0 != ret) {
            /* 전체 정지 플래그 설정 */
            atomic_store(&rt->stop, true);
            /* block 중인 queue 깨우기 */
            wake_all_queues(rt);
            for (int j = 0; j < i; j++) {
                /* 이미 시작된 worker join */
                pthread_join(rt->worker_tids[j], NULL);
            }
            /* 시작된 worker 수 초기화 */
            rt->workers_started = 0;
            return -1;
        }
        /* 시작된 worker 수 증가 */
        rt->workers_started++;
    }

    /* capture thread 생성 */
    ret = pthread_create(&rt->capture_tid, NULL, capture_thread_func, rt);
    if (0 != ret) {
        /* 전체 정지 플래그 설정 */
        atomic_store(&rt->stop, true);
        /* block 중인 queue 깨우기 */
        wake_all_queues(rt);
        for (int i = 0; i < rt->worker_count; i++) {
            /* 시작된 worker join */
            pthread_join(rt->worker_tids[i], NULL);
        }
        /* 시작된 worker 수 초기화 */
        rt->workers_started = 0;
        return -1;
    }
    /* capture 시작 플래그 설정 */
    rt->capture_started = 1;
    /* driver start 성공 */
    return 0;
}

/**
 * @brief 정지 함수
 * 구동 중인 캡처 및 워커 스레드들을 안전하게 종료하기
 * @param rt
 * @return int
 */
int driver_stop(driver_runtime_t *rt) {
    /* runtime 포인터 검사 */
    if (NULL == rt) {
        return -1;
    }
    /* 이미 정지 상태면 바로 반환 */
    if (!rt->capture_started && 0 == rt->workers_started) {
        return 0;
    }

    /* 전체 정지 플래그 설정 */
    atomic_store(&rt->stop, true);

    if (rt->capture_started) {
        /* blocking capture 깨우기 */
        wake_capture_handle(&rt->cc);
    }

    if (0 < rt->workers_started) {
        /* block 중인 worker queue 깨우기 */
        wake_all_queues(rt);
    }

    if (rt->capture_started) {
        /* capture thread join */
        pthread_join(rt->capture_tid, NULL);
        /* thread ID 초기화 */
        rt->capture_tid     = (pthread_t)0;
        /* capture 시작 플래그 해제 */
        rt->capture_started = 0;
    }

    for (int i = 0; i < rt->workers_started; i++) {
        /* worker thread join */
        pthread_join(rt->worker_tids[i], NULL);
    }

    /* 시작된 worker 수 초기화 */
    rt->workers_started = 0;
    /* 정상 정지 완료 */
    return 0;
}
/**
 * @brief 드라이버의 자원 해제 함수
 * 시스템 자원 반환
 * @param rt 런타임 객체
 */
void driver_destroy(driver_runtime_t *rt) {
    /* runtime 포인터 검사 */
    if (!rt) {
        return;
    }

    /* 실행 중이면 먼저 정지 */
    (void)driver_stop(rt);

    /* capture handle 정리 */
    capture_close(&rt->cc);
    /* queue set 정리 */
    packet_queue_set_destroy(&rt->queues);

    /* worker thread ID 배열 해제 */
    free(rt->worker_tids);
    /* 포인터 초기화 */
    rt->worker_tids = NULL;

    /* worker arg 배열 해제 */
    free(rt->worker_args);
    /* 포인터 초기화 */
    rt->worker_args = NULL;

    /* worker별 user 배열 초기화 */
    rt->worker_users      = NULL;
    /* worker user 개수 초기화 */
    rt->worker_user_count = 0;
    /* 콜백 초기화 */
    rt->on_packet         = NULL;
    /* 공통 user 포인터 초기화 */
    rt->on_packet_user    = NULL;
    /* worker 수 초기화 */
    rt->worker_count      = 0;
    /* capture queue 연결 해제 */
    rt->cc.queues         = NULL;
    /* handler mutex 정리 */
    pthread_mutex_destroy(&rt->handler_mu);

    /* failure 플래그 초기화 */
    atomic_store(&rt->failed, false);
    /* 마지막 오류 초기화 */
    atomic_store(&rt->last_error, 0);
}
/**
 * @brief main.c에서 캡처 스레드 죽었는지 감시하는 함수
 *
 * @param rt 런타임
 * @return int
 */
int driver_has_failed(driver_runtime_t *rt) {
    /* runtime 포인터 검사 */
    if (!rt) {
        return 0;
    }
    /* failure 플래그 반환 */
    return atomic_load(&rt->failed) ? 1 : 0;
}

/**
 * @brief 실패가 있었다면 마지막 에러 꺼내기
 *
 * @param rt 런타임
 * @return int
 */
int driver_last_error(driver_runtime_t *rt) {
    /* runtime 포인터 검사 */
    if (!rt) {
        return -1;
    }
    /* 마지막 오류 코드 반환 */
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
    /* runtime 포인터 검사 */
    if (!rt) {
        return;
    }

    /* handler 설정 보호 락 획득 */
    pthread_mutex_lock(&rt->handler_mu);
    /* 공통 packet 콜백 저장 */
    rt->on_packet      = cb;
    /* 공통 user 포인터 저장 */
    rt->on_packet_user = user;

    /* worker별 user 배열 비활성화 */
    rt->worker_users      = NULL;
    /* worker별 user 개수 초기화 */
    rt->worker_user_count = 0;
    /* handler 설정 보호 락 해제 */
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
    /* runtime 포인터 검사 */
    if (!rt) {
        return;
    }
    /* handler 설정 보호 락 획득 */
    pthread_mutex_lock(&rt->handler_mu);
    /* 공통 packet 콜백 저장 */
    rt->on_packet         = cb;
    /* worker별 user 배열 저장 */
    rt->worker_users      = users;
    /* worker별 user 개수 저장 */
    rt->worker_user_count = user_count;

    /* 공통 user 포인터 비활성화 */
    rt->on_packet_user = NULL;
    /* handler 설정 보호 락 해제 */
    pthread_mutex_unlock(&rt->handler_mu);
}

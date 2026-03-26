/**
 * @file packet_ring.c
 * @brief 패킷 링 큐 구현
 *
 * capture thread(단일 producer)와 worker thread(단일 consumer) 사이의
 * hot path 데이터 전달부다. 동기화는 mutex 대신 atomic head/tail로 한다.
 */
#include "packet_ring.h"

#include <sched.h>
#include <sys/mman.h>

#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif

/* --------------------------- allocation helpers --------------------------- */

/**
 * @brief 비트 연산 함수
 * 링 버퍼는 인덱스가 끝에 도달하면 다시 0으로 롤백
 * 버퍼 크기가 2^N이면 *index & (size - 1)이라는 비트연산 처리가능
 * CPU 사이클을 절약하고 분기 예측 실패(Branch Misprediction) 가능성을 줄이기
 * 위함
 * @param x
 * @return int
 */
static int is_power_of_two_u32(uint32_t x) {
    /* 0은 2의 거듭제곱이 아니다. */
    if (0 == x) {
        return 0;
    }

    /* 2의 거듭제곱이면 하위 비트 제거 결과가 0이 된다. */
    uint32_t check = x & (x - 1U);

    /* 검증 성공 */
    if (0 == check) {
        return 1;
    }

    /* 검증 실패 */
    return 0;
}

/**
 * @brief 시스템 hugepage 크기를 조회한다.
 *
 * /proc/meminfo의 Hugepagesize 항목을 읽어 현재 시스템이 사용하는
 * explicit hugepage 크기를 얻는다. 조회에 실패하면 일반적인 x86_64
 * 기본값인 2MB를 보수적으로 사용한다.
 *
 * @return size_t hugepage 크기(바이트)
 */
static size_t packet_hugepage_size(void) {
    /* /proc/meminfo 파일 핸들 */
    FILE *fp;
    /* meminfo 한 줄 버퍼 */
    char line[128];
    /* hugepage 크기(kB) */
    size_t kb = 0;
    /* sscanf 반환값 */
    int ret;

    /* hugepage 크기는 커널이 /proc/meminfo에 kB 단위로 노출한다. */
    fp = fopen("/proc/meminfo", "r");
    if (NULL == fp) {
        return 2U * 1024U * 1024U;
    }

    /* Hugepagesize 행 탐색 */
    while (NULL != fgets(line, sizeof(line), fp)) {
        /* kB 단위 hugepage 크기 파싱 */
        ret = sscanf(line, "Hugepagesize: %zu kB", &kb);
        if (1 == ret) {
            /* 파일 닫기 */
            fclose(fp);
            /* 바이트 단위로 환산 후 반환 */
            return kb * 1024U;
        }
    }

    /* 파일 닫기 */
    fclose(fp);
    /* 조회 실패 시 기본 2MB 사용 */
    return 2U * 1024U * 1024U;
}

/**
 * @brief 값을 지정한 정렬 단위의 배수로 올림 정렬한다.
 *
 * hugepage mmap 길이는 hugepage 크기의 배수여야 하므로 slot 배열 총 크기를
 * 올림 정렬할 때 사용한다.
 *
 * @param value 원본 크기
 * @param align 정렬 단위
 * @return size_t align 배수로 올림된 크기
 */
static size_t align_up_size(size_t value, size_t align) {
    /* 나머지 값 */
    size_t rem;

    /* 정렬 단위가 없으면 원본 반환 */
    if (0U == align) {
        return value;
    }

    /* 정렬 단위 대비 나머지 계산 */
    rem = value % align;
    /* 이미 정렬된 값이면 그대로 반환 */
    if (0U == rem) {
        return value;
    }

    /* 다음 align 배수까지 올림 */
    return value + (align - rem);
}

/**
 * @brief slot 배열 backing memory를 할당한다.
 *
 * 먼저 MAP_HUGETLB 기반 hugepage mmap을 시도하고, 실패하면 일반 calloc으로
 * fallback 한다. 호출자는 alloc_len/used_mmap을 보고 해제 방식을 결정한다.
 *
 * @param bytes 필요한 slot 배열 크기
 * @param alloc_len 실제 할당 길이
 * @param used_mmap mmap 사용 여부
 * @return void* 할당된 메모리 주소, 실패 시 NULL
 */
static void *packet_slots_alloc(size_t bytes, size_t *alloc_len,
                                int *used_mmap) {
    /* 시스템 hugepage 크기 */
    size_t hugepage_size;
    /* mmap 할당 길이 */
    size_t map_len;
    /* 할당 결과 포인터 */
    void *p;

    /* 출력 포인터 유효성 검사 */
    if (NULL == alloc_len || NULL == used_mmap) {
        return NULL;
    }

    /* 실제 할당 길이 초기화 */
    *alloc_len = 0U;
    /* mmap 사용 여부 초기화 */
    *used_mmap = 0;

    /* 시스템 hugepage 크기 조회 */
    hugepage_size = packet_hugepage_size();
    /* hugepage 배수로 올림 정렬 */
    map_len = align_up_size(bytes, hugepage_size);

    /* hugepage pool이 준비되어 있으면 slot 배열 전체를 hugepage에 올린다. */
    p = mmap(NULL, map_len,
             PROT_READ |
                 PROT_WRITE, /* 시스템 헤더에 MAP_HUETLB가 정의되어있으면 안씀*/
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    if (MAP_FAILED != p) {
        /* 새 매핑 영역 0 초기화 */
        memset(p, 0, map_len);
        /* 실제 mmap 길이 기록 */
        *alloc_len = map_len;
        /* mmap 사용 표시 */
        *used_mmap = 1;
        /* hugepage 매핑 반환 */
        return p;
    }

    /* hugepage 확보에 실패한 환경에서는 일반 힙 할당으로 동작을 유지한다. */
    p = malloc(bytes);
    if (NULL != p) {
        /* 힙 메모리 0 초기화 */
        memset(p, 0, bytes);
        /* 실제 할당 길이 기록 */
        *alloc_len = bytes;
        /* fallback heap 표시 */
        *used_mmap = 0;
    }

    /* heap 또는 NULL 반환 */
    return p;
}

/**
 * @brief slot 배열 backing memory를 해제한다.
 *
 * alloc 시 mmap을 썼으면 munmap, fallback heap을 썼으면 free를 사용한다.
 *
 * @param ptr 해제할 메모리
 * @param alloc_len 할당 길이
 * @param used_mmap mmap 사용 여부
 */
static void packet_slots_free(void *ptr, size_t alloc_len, int used_mmap) {
    /* NULL 포인터 무시 */
    if (NULL == ptr) {
        return;
    }

    /* hugepage mmap으로 잡은 메모리는 길이를 함께 넘겨 munmap 해야 한다. */
    if (0 != used_mmap) {
        munmap(ptr, alloc_len);
        return;
    }

    /* heap 할당 메모리 해제 */
    free(ptr);
}

/**
 * @brief packet_ring_init 함수
 * 링버퍼 초기화 하는 역할
 * @param r 링버퍼 컨텍스트 구조체
 * @param slot_count 슬롯 개수
 * @param use_blocking 블로킹 여부 체크, use_blocking = 1, 큐가 full이면
 * 소비자가 공간만들때까지 기다림
 * @return int 성공 시 0, 실패 시 -1
 */
int packet_ring_init(packet_ring_t *r, uint32_t slot_count, int use_blocking) {
    /* slot 배열 총 바이트 수 */
    size_t slots_bytes;
    /* slot 배열 할당 결과 */
    void *slots_mem;
    /* helper 반환값 */
    int ret;

    /* 링 포인터 검사 */
    if (NULL == r) {
        return -1;
    }

    /* slot_count가 2의 거듭제곱인지 검증 */
    ret = is_power_of_two_u32(slot_count);
    if (0U == slot_count || 0 == ret) {
        return -1;
    }

    /* 구조체 전체 초기화 */
    memset(r, 0, sizeof(*r));

    /* slot 배열 총 크기 계산 */
    slots_bytes = (size_t)slot_count * sizeof(packet_slot_t);
    /* slot backing memory 할당 */
    slots_mem = packet_slots_alloc(slots_bytes, &r->slots_alloc_len,
                                   &r->slots_use_mmap);

    /* 할당 실패 */
    if (NULL == slots_mem) {
        return -1;
    }

    /* slot 배열 포인터 저장 */
    r->slots = (packet_slot_t *)slots_mem;
    /* slot 개수 저장 */
    r->slot_count = slot_count;
    /* 순환 인덱스용 mask 저장 */
    r->mask = slot_count - 1U;

    /* consumer head 초기화 */
    atomic_store_explicit(&r->head, 0U, memory_order_relaxed);
    /* producer tail 초기화 */
    atomic_store_explicit(&r->tail, 0U, memory_order_relaxed);
    /* blocking 정책 저장 */
    atomic_store_explicit(&r->use_blocking, use_blocking ? 1 : 0,
                          memory_order_relaxed);

    /* 초기화 성공 */
    return 0;
}

/**
 * @brief packet_ring이 보유한 자원을 해제한다.
 *
 * slot 배열 backing memory를 해제하고 구조체를 0으로 비워 재사용 가능한
 * 초기 상태로 되돌린다.
 *
 * @param r 링 버퍼 컨텍스트 구조체
 */
void packet_ring_destroy(packet_ring_t *r) {
    /* 링 포인터 검사 */
    if (NULL == r) {
        return;
    }

    /* slot backing memory 해제 */
    packet_slots_free(r->slots, r->slots_alloc_len, r->slots_use_mmap);
    /* 구조체 초기 상태로 재설정 */
    memset(r, 0, sizeof(*r));
}

int packet_ring_enq(packet_ring_t *r, const uint8_t *data, uint32_t len,
                    uint64_t ts_ns) {
    /* consumer가 공개한 head 스냅샷 */
    uint32_t head;
    /* producer가 소유한 tail 스냅샷 */
    uint32_t tail;
    /* blocking 정책 스냅샷 */
    int use_blocking;
    /* 이번 enqueue 대상 slot */
    packet_slot_t *s;

    /* 링 본체가 없거나, 길이가 있는 패킷인데 data가 없으면 잘못된 호출이다. */
    if (NULL == r || (NULL == data && 0U != len)) {
        return -1;
    }

    /*
     * slot 하나에는 최대 PACKET_MAX_BYTES까지만 저장할 수 있다.
     * 현재 운영 환경은 GRO/LRO를 끄고 MTU 수준 패킷을 전제로 하지만,
     * enqueue API 계약 자체는 여전히 slot 상한을 기준으로 검증한다.
     */
    if (len > PACKET_MAX_BYTES) {
        return -1;
    }

    /*
     * producer는 자신의 tail은 relaxed로 읽고, consumer가 publish한 head는
     * acquire로 읽는다. ring이 가득 찼으면 blocking/non-blocking 정책에 따라
     * 즉시 실패하거나 backoff 대기에 들어간다.
     */
    for (uint32_t spin = 0;; spin++) {
        /* producer 자신의 tail 읽기 */
        tail = atomic_load_explicit(&r->tail, memory_order_relaxed);
        /* consumer가 공개한 head 읽기 */
        head = atomic_load_explicit(&r->head, memory_order_acquire);

        /* head와 tail 차이가 slot_count 미만이면 빈 slot이 하나 이상 있다. */
        if ((tail - head) < r->slot_count) {
            break;
        }

        /* non-blocking 모드에서는 full을 만나면 즉시 실패를 돌려준다. */
        use_blocking =
            atomic_load_explicit(&r->use_blocking, memory_order_acquire);
        if (0 == use_blocking) {
            /* full drop 통계 증가 */
            r->stats.drop_full++;
            return -1;
        }

        /*
         * blocking 모드에서는 full 상태를 통계에 남기고, 짧은 spin 후
         * 필요할 때만 CPU를 양보한다. full 상태가 자주 발생하는 환경을
         * 고려해 dequeue와 같은 형태의 고정 backoff를 사용한다.
         */
        r->stats.wait_full++;
        if (256U > spin) {
#if defined(__x86_64__) || defined(__i386__)
            /* 짧은 spin 구간 CPU pause */
            __builtin_ia32_pause();
#endif
        } else {
            /* 장기 대기 시 CPU 양보 */
            sched_yield();
            /* spin 카운터 재시작 */
            spin = 0;
        }
    }

    /*
     * tail이 가리키는 slot이 이번 enqueue 대상이다. payload는 slot 내부의
     * 고정 버퍼에 복사되고, 길이와 타임스탬프도 함께 기록한다.
     */
    s = &r->slots[tail & r->mask];
    /* payload 길이 기록 */
    s->len = len;
    /* 캡처 시각 기록 */
    s->ts_ns = ts_ns;
    if (0U != len) {
        /* payload 바이트 복사 */
        memcpy(s->data, data, len);
    }

    /*
     * slot 내용을 모두 기록한 뒤 tail을 release store로 증가시켜
     * consumer가 이 slot을 안전하게 볼 수 있게 publish한다.
     */
    atomic_store_explicit(&r->tail, tail + 1U, memory_order_release);
    /* enqueue 성공 통계 증가 */
    r->stats.enq_ok++;
    /* enqueue 성공 */
    return 0;
}

int packet_ring_deq(packet_ring_t *r, uint8_t *out, uint32_t out_cap,
                    uint32_t *out_len, uint64_t *out_ts_ns) {
    /* consumer가 소유한 head 스냅샷 */
    uint32_t head;
    /* producer가 공개한 tail 스냅샷 */
    uint32_t tail;
    /* 현재 slot payload 길이 */
    uint32_t len;
    /* blocking 정책 스냅샷 */
    int use_blocking;
    /* 이번 dequeue 대상 slot */
    packet_slot_t *s;

    /* 결과 길이를 돌려줄 포인터는 필수다. */
    if (NULL == r || NULL == out_len) {
        return -1;
    }

    /*
     * consumer는 자신의 head는 relaxed로 읽고, producer가 publish한 tail은
     * acquire로 읽는다. ring이 비어 있으면 blocking/non-blocking 정책에 따라
     * 즉시 실패하거나 짧은 backoff 대기에 들어간다.
     */
    for (uint32_t spin = 0;; spin++) {
        /* consumer 자신의 head 읽기 */
        head = atomic_load_explicit(&r->head, memory_order_relaxed);
        /* producer가 공개한 tail 읽기 */
        tail = atomic_load_explicit(&r->tail, memory_order_acquire);

        /* head와 tail이 다르면 소비할 slot이 존재한다. */
        if (head != tail) {
            break;
        }

        /* non-blocking 모드에서는 empty를 만나면 즉시 실패를 돌려준다. */
        use_blocking =
            atomic_load_explicit(&r->use_blocking, memory_order_acquire);
        if (0 == use_blocking) {
            return -1;
        }

        /*
         * blocking 모드에서는 잠깐 busy-wait 하다가, 바로 데이터가 안 들어오면
         * 스케줄러에 CPU를 양보한다. SPSC 환경이라 짧은 spin이 보통 더
         * 유리하다.
         */
        if (256U > spin) {
#if defined(__x86_64__) || defined(__i386__)
            /* 짧은 spin 구간 CPU pause */
            __builtin_ia32_pause();
#endif
        } else {
            /* 장기 대기 시 CPU 양보 */
            sched_yield();
            /* spin 카운터 재시작 */
            spin = 0;
        }
    }

    /* head가 가리키는 slot이 이번 dequeue 대상이며, 현재 패킷 길이를 읽는다. */
    /* 읽기 대상 slot 선택 */
    s = &r->slots[head & r->mask];
    /* slot 길이 읽기 */
    len = s->len;

    /*
     * 호출자가 출력 버퍼를 제공한 경우에만 payload를 복사한다.
     * 현재 운영 환경은 GRO/LRO 비활성화로 MTU 수준 패킷을 기대하지만,
     * dequeue API 계약은 여전히 "out_cap >= 실제 slot 길이"를 요구한다.
     * 작은 버퍼를 넘기면 실패를 반환하며, 이 경우 head는 전진하지 않는다.
     */
    if (NULL != out) {
        /* 호출자 버퍼 크기 검증 */
        if (out_cap < len) {
            return -1;
        }
        if (0U != len) {
            /* payload 바이트 복사 */
            memcpy(out, s->data, len);
        }
    }

    /* payload 길이와 enqueue 시각을 호출자에게 함께 돌려준다. */
    /* 출력 길이 기록 */
    *out_len = len;
    if (NULL != out_ts_ns) {
        /* 출력 시각 기록 */
        *out_ts_ns = s->ts_ns;
    }

    /*
     * slot 데이터를 모두 읽은 뒤 head를 release store로 증가시켜
     * producer가 이 slot을 다시 재사용할 수 있게 소비 완료를 publish한다.
     */
    atomic_store_explicit(&r->head, head + 1U, memory_order_release);
    /* dequeue 성공 통계 증가 */
    r->stats.deq_ok++;
    /* dequeue 성공 */
    return 0;
}

/**
 * @brief 여러 worker queue를 묶은 queue set을 초기화한다.
 *
 * worker 수만큼 packet_ring을 생성하고 각 ring을 동일한 slot 수와
 * blocking 정책으로 맞춘다.
 *
 * @param set queue set 컨텍스트
 * @param packet_queue_count 생성할 queue 개수
 * @param slot_count queue 하나당 slot 개수
 * @param user_blocking blocking 동작 여부
 * @return int 성공 시 0, 실패 시 -1
 */
int packet_queue_set_init(packet_queue_set_t *set, uint32_t packet_queue_count,
                          uint32_t slot_count, int user_blocking) {
    /* helper 반환값 */
    int ret;

    /* queue set 포인터 검사 */
    if (NULL == set) {
        return -1;
    }
    /* queue 개수 범위 검증 */
    if (packet_queue_count < MIN_QUEUE_COUNT ||
        packet_queue_count > MAX_QUEUE_COUNT) {
        return -1;
    }
    if (0U == slot_count) {
        /* slot_count 미지정 시 기본값 사용 */
        slot_count = DEFAULT_SLOT_COUNT;
    }
    /* slot_count가 2의 거듭제곱인지 검증 */
    ret = is_power_of_two_u32(slot_count);
    if (0 == ret) {
        return -1;
    }

    /* queue set 자체를 먼저 초기화한 뒤 ring 배열을 동적으로 확보한다. */
    memset(set, 0, sizeof(*set));
    /* queue 배열 64바이트 정렬 할당 */
    ret = posix_memalign((void **)&set->q, 64,
                         packet_queue_count * sizeof(packet_ring_t));
    if (0 != ret) {
        /* 실패 시 포인터 정리 */
        set->q = NULL;
        return -1;
    }
    /* queue 배열 0 초기화 */
    memset(set->q, 0, packet_queue_count * sizeof(packet_ring_t));

    /*
     * 각 worker queue를 순서대로 생성한다. 중간 실패 시 이미 성공한 ring만
     * 역순으로 정리해 partial init 상태가 남지 않도록 rollback 한다.
     */
    set->qcount = packet_queue_count;
    for (uint32_t i = 0; i < packet_queue_count; i++) {
        /* worker별 ring 생성 */
        int rc = packet_ring_init(&set->q[i], slot_count, user_blocking);
        if (0 != rc) {
            for (uint32_t j = 0; j < i; j++) {
                /* 이미 만든 ring 역순 정리 */
                packet_ring_destroy(&set->q[j]);
            }
            /* queue 배열 해제 */
            free(set->q);
            /* 구조체 초기화 */
            memset(set, 0, sizeof(*set));
            /* 최초 실패 코드 반환 */
            return rc;
        }
    }

    /* queue set 초기화 성공 */
    return 0;
}

/**
 * @brief queue set이 보유한 모든 ring과 배열 메모리를 해제한다.
 *
 * @param set queue set 컨텍스트
 */
void packet_queue_set_destroy(packet_queue_set_t *set) {
    /* queue set 또는 queue 배열 검사 */
    if (NULL == set || NULL == set->q) {
        return;
    }

    /* 각 queue가 보유한 slot 배열을 먼저 해제한 뒤 queue 배열을 정리한다. */
    for (uint32_t i = 0; i < set->qcount; i++) {
        /* ring별 자원 해제 */
        packet_ring_destroy(&set->q[i]);
    }

    /* queue 배열 메모리 해제 */
    free(set->q);
    /* 구조체 초기화 */
    memset(set, 0, sizeof(*set));
}

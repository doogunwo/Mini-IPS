/**
 * @file packet_ring.c
 * @brief 패킷 링 큐 구현
 */
#include "packet_ring.h"

#include <sched.h>
#include <sys/mman.h>

#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif


/**
 * @brief 비트 연산 함수
 * 링 버퍼는 인덱스가 끝에 도달하면 다시 0으로 롤백
 * 버퍼 크기가 2^N이면 *index & (size - 1)이라는 비트연산 처리가능
 * CPU 사이클을 절약하고 분기 예측 실패(Branch Misprediction) 가능성을 줄이기 위함
 * @param x 
 * @return int 
 */
static int is_power_of_two_u32(uint32_t x) {
    if(0 == x) {
        return 0;
    }

    uint32_t check = x & (x-1U);

    if(0 == check) {
        return 1;
    }

    return 0;
}

static size_t packet_hugepage_size(void) {
    FILE    *fp;
    char    line[128];
    size_t  kb = 0;

    fp = fopen("/proc/meminfo", "r");
    if(NULL == fp) {
        return 2U * 1024U * 1024U;
    }

    while (NULL != fgets(line, sizeof(line), fp)) {
        if (1 == sscanf(line, "Hugepagesize: %zu kB", &kb)) {
            fclose(fp);
            return kb * 1024U;
        }
    }

    fclose(fp);
    return 2U * 1024U * 1024U;
}

static size_t align_up_size(size_t value, size_t align) {
    size_t rem;

    if (0U == align) {
        return value;
    }

    rem = value % align;
    if (0U == rem) {
        return value;
    }

    return value + (align - rem);
}

static void *packet_slots_alloc(size_t bytes, size_t *alloc_len,
                                int *used_mmap) {
    size_t hugepage_size;
    size_t map_len;
    void  *p;

    if (NULL == alloc_len || NULL == used_mmap) {
        return NULL;
    }

    *alloc_len = 0U;
    *used_mmap = 0;

    hugepage_size = packet_hugepage_size();
    map_len = align_up_size(bytes, hugepage_size);

    p = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    if (MAP_FAILED != p) {
        memset(p, 0, map_len);
        *alloc_len = map_len;
        *used_mmap = 1;
        return p;
    }

    p = calloc(1, bytes);
    if (NULL != p) {
        *alloc_len = bytes;
        *used_mmap = 0;
    }

    return p;
}

static void packet_slots_free(void *ptr, size_t alloc_len, int used_mmap) {
    if (NULL == ptr) {
        return;
    }

    if (0 != used_mmap) {
        munmap(ptr, alloc_len);
        return;
    }

    free(ptr);
}

/**
 * @brief packet_ring_init 함수
 * 링버퍼 초기화 하는 역할
 * @param r 링버퍼 컨텍스트 구조체
 * @param slot_count 슬롯 개수
 * @param use_blocking 블로킹 여부 체크, use_blocking = 1, 큐가 full이면 소비자가 공간만들때까지 기다림
 * @return int 
 */
int packet_ring_init(packet_ring_t *r, uint32_t slot_count, int use_blocking) {
    size_t slots_bytes;
    void *slots_mem;

    if (NULL == r) {
        return EINVAL;
    }

    if (0U == slot_count || 0 == is_power_of_two_u32(slot_count)) {
        return EINVAL;
    }

    memset(r, 0, sizeof(*r));

    slots_bytes = (size_t)slot_count * sizeof(packet_slot_t);
    slots_mem = packet_slots_alloc(slots_bytes, &r->slots_alloc_len,
                                   &r->slots_use_mmap);

    if (NULL == slots_mem) {
        return ENOMEM;
    }

    r->slots = (packet_slot_t *)slots_mem;
    r->slot_count = slot_count;
    r->mask = slot_count - 1U;

    atomic_store_explicit(&r->head, 0U, memory_order_relaxed);
    atomic_store_explicit(&r->tail, 0U, memory_order_relaxed);
    atomic_store_explicit(&r->use_blocking, use_blocking ? 1 : 0,
                          memory_order_relaxed);

    return 0;
}

void packet_ring_destroy(packet_ring_t *r) {
    if (NULL == r) {
        return;
    }

    packet_slots_free(r->slots, r->slots_alloc_len, r->slots_use_mmap);
    memset(r, 0, sizeof(*r));
}

int packet_ring_enq(packet_ring_t *r, const uint8_t *data, uint32_t len,
                    uint64_t ts_ns) {
    uint32_t head;
    uint32_t tail;
    packet_slot_t *s;

    if (NULL == r || (NULL == data && 0U != len)) {
        return EINVAL;
    }
    if (len > PACKET_MAX_BYTES) {
        return EMSGSIZE;
    }

    for (;;) {
        tail = atomic_load_explicit(&r->tail, memory_order_relaxed);
        head = atomic_load_explicit(&r->head, memory_order_acquire);
        /* 통계 변수들과 메인 인덱스 변수들 사이에 패딩(Padding)을 넣거나
        alignas(64)를 사용해 캐시 라인을 분리할 계획*/
        if ((tail - head) < r->slot_count) {
            break;
        }

        if (0 == atomic_load_explicit(&r->use_blocking, memory_order_acquire)) {
            r->stats.drop_full++;
            return EAGAIN;
        }

        r->stats.wait_full++;
        sched_yield();
    }

    s           = &r->slots[tail & r->mask];
    s->len      = len;
    s->ts_ns    = ts_ns;
    if (0U != len) {
        memcpy(s->data, data, len);
    }

    atomic_store_explicit(&r->tail, tail + 1U, memory_order_release);
    r->stats.enq_ok++;
    return 0;
}

int packet_ring_deq(packet_ring_t *r, uint8_t *out, uint32_t out_cap,
                    uint32_t *out_len, uint64_t *out_ts_ns) {
    uint32_t head;
    uint32_t tail;
    uint32_t len;
    packet_slot_t *s;

    if (NULL == r || NULL == out_len) {
        return EINVAL;
    }

    for (;;) {
        head = atomic_load_explicit(&r->head, memory_order_relaxed);
        tail = atomic_load_explicit(&r->tail, memory_order_acquire);

        if (head != tail) {
            break;
        }

        if (0 == atomic_load_explicit(&r->use_blocking, memory_order_acquire)) {
            return EAGAIN;
        }

        sched_yield();
    }

    s   = &r->slots[head & r->mask];
    len = s->len;

    if (NULL != out) {
        if (out_cap < len) {
            return EMSGSIZE;
        }
        if (0U != len) {
            memcpy(out, s->data, len);
        }
    }

    *out_len = len;
    if (NULL != out_ts_ns) {
        *out_ts_ns = s->ts_ns;
    }

    atomic_store_explicit(&r->head, head + 1U, memory_order_release);
    r->stats.deq_ok++;
    return 0;
}

int packet_queue_set_init(packet_queue_set_t *set, uint32_t packet_queue_count,
                          uint32_t slot_count, int user_blocking) {

    if (NULL == set) {
        return EINVAL;
    }
    if (packet_queue_count < MIN_QUEUE_COUNT ||
        packet_queue_count > MAX_QUEUE_COUNT) {
        return EINVAL;
    }
    if (0U == slot_count) {
        slot_count = DEFAULT_SLOT_COUNT;
    }
    if (0U == is_power_of_two_u32(slot_count)) {
        return EINVAL;
    }

    memset(set, 0, sizeof(*set));
    set->q = (packet_ring_t *)calloc(packet_queue_count, sizeof(packet_ring_t));
    if (NULL == set->q) {
        return ENOMEM;
    }

    set->qcount = packet_queue_count;
    for (uint32_t i = 0; i < packet_queue_count; i++) {
        int rc = packet_ring_init(&set->q[i], slot_count, user_blocking);
        if (0 != rc) {
            for (uint32_t j = 0; j < i; j++) {
                packet_ring_destroy(&set->q[j]);
            }
            free(set->q);
            memset(set, 0, sizeof(*set));
            return rc;
        }
    }

    return 0;
}

void packet_queue_set_destroy(packet_queue_set_t *set) {
    if (NULL == set || NULL == set->q) {
        return;
    }

    for (uint32_t i = 0; i < set->qcount; i++) {
        packet_ring_destroy(&set->q[i]);
    }

    free(set->q);
    memset(set, 0, sizeof(*set));
}

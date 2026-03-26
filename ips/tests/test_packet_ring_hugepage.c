/**
 * @file test_packet_ring_hugepage.c
 * @brief packet ring hugepage 사용 여부 진단 테스트
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "packet_ring.h"

#define CHECK(cond, msg)                          \
    do {                                          \
        if (!(cond)) {                            \
            fprintf(stderr, "FAIL: %s\n", (msg)); \
            return 1;                             \
        }                                         \
    } while (0)

static void read_huge_meminfo(unsigned long long *total,
                              unsigned long long *free_pages,
                              unsigned long long *size_kb) {
    FILE *fp;
    char  line[256];

    if (NULL != total) {
        *total = 0;
    }
    if (NULL != free_pages) {
        *free_pages = 0;
    }
    if (NULL != size_kb) {
        *size_kb = 0;
    }

    fp = fopen("/proc/meminfo", "r");
    if (NULL == fp) {
        return;
    }

    while (NULL != fgets(line, sizeof(line), fp)) {
        unsigned long long value;

        if (1 == sscanf(line, "HugePages_Total: %llu", &value)) {
            if (NULL != total) {
                *total = value;
            }
            continue;
        }
        if (1 == sscanf(line, "HugePages_Free: %llu", &value)) {
            if (NULL != free_pages) {
                *free_pages = value;
            }
            continue;
        }
        if (1 == sscanf(line, "Hugepagesize: %llu kB", &value)) {
            if (NULL != size_kb) {
                *size_kb = value;
            }
            continue;
        }
    }

    fclose(fp);
}

int main(void) {
    packet_ring_t      ring;
    unsigned long long huge_total;
    unsigned long long huge_free;
    unsigned long long huge_size_kb;
    size_t             slot_bytes;

    memset(&ring, 0, sizeof(ring));
    read_huge_meminfo(&huge_total, &huge_free, &huge_size_kb);

    CHECK(0 == packet_ring_init(&ring, 1024, 0), "packet_ring_init failed");

    slot_bytes = (size_t)ring.slot_count * sizeof(packet_slot_t);

    fprintf(stderr,
            "[test_packet_ring_hugepage] huge_total=%llu huge_free=%llu "
            "hugepagesize_kb=%llu slot_count=%u slot_bytes=%zu "
            "slots_alloc_len=%zu slots_use_mmap=%d\n",
            huge_total, huge_free, huge_size_kb, ring.slot_count, slot_bytes,
            ring.slots_alloc_len, ring.slots_use_mmap);

    packet_ring_destroy(&ring);

    printf("ok: test_packet_ring_hugepage\n");
    return 0;
}

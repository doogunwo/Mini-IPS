/**
 * @file reasm.c
 * @brief TCP 재조립 엔진 구현
 *
 * flow/방향별로 expected sequence와 out-of-order 세그먼트 리스트를 유지하며,
 * 연속 구간이 만들어질 때만 상위 HTTP 파서로 바이트를 전달한다.
 */
#include "reasm.h"

#include <stdlib.h>
#include <string.h>

/* ---------- seq 비교(랩어라운드 고려) ---------- */
static inline int32_t seq_diff(uint32_t a, uint32_t b) {
    /* 랩어라운드를 고려한 signed 차이 계산 */
    return (int32_t)(a - b);
}

#define SEQ_LT(a, b) (seq_diff((a), (b)) < 0)
#define SEQ_LEQ(a, b) (seq_diff((a), (b)) <= 0)
#define SEQ_GT(a, b) (seq_diff((a), (b)) > 0)
#define SEQ_GEQ(a, b) (seq_diff((a), (b)) >= 0)

/**
 * @brief HTTP 재조립, out-of-order 대비용 세그먼트 연결 리스트 노드
 */
typedef struct reasm_seg_node {
    uint32_t               seq;
    uint32_t               len;
    uint8_t               *data;
    struct reasm_seg_node *next;
} reasm_seg_node_t;

/**
 * @brief 방향별 재조립 상태
 */
typedef struct reasm_dir {
    uint8_t  has_next;  /**< next_seq가 유효한지 */
    uint32_t next_seq;  /**< 다음에 와야 하는 sequence */
    uint8_t  fin_seen;  /**< FIN 관측 여부 */
    uint8_t  rst_seen;  /**< RST 관측 여부 */

    reasm_seg_node_t *head;         /**< seq 정렬된 대기 세그먼트 리스트 */
    uint32_t          seg_count;    /**< 대기 세그먼트 개수 */
    uint32_t          bytes_queued; /**< 현재 대기 바이트 수 */
} reasm_dir_t;

/**
 * @brief TCP 연결 1개에 대한 재조립 상태
 */
typedef struct reasm_session {
    flow_key_t key;
    uint64_t   last_seen_ms;

    reasm_dir_t           dir[2];
    struct reasm_session *next;
} reasm_session_t;

/**
 * @brief 재조립 세션 저장소와 콜백을 묶은 컨텍스트
 */
struct reasm_ctx {
    reasm_session_t **buckets;
    uint32_t          nbuckets;
    uint32_t          nsessions;

    reasm_mode_t     mode;
    reasm_on_data_cb on_data;
    void            *user;
    reasm_stats_t    stats;
};

/* --------------------------- session / storage helpers --------------------------- */

/**
 * @brief flow key에 대한 FNV 기반 해시를 계산한다.
 *
 * @param k flow key
 * @return uint32_t 해시값
 */
static uint32_t reasm_flow_hash(const flow_key_t *k) {
    /* FNV hash seed */
    uint32_t       h     = 2166136261u;
    /* FNV prime */
    const uint32_t prime = 16777619u;

    /* src_ip 반영 */
    h ^= (uint32_t)k->src_ip;
    h *= prime;

    /* dst_ip 반영 */
    h ^= (uint32_t)k->dst_ip;
    h *= prime;

    /* 양쪽 포트를 묶어 반영 */
    h ^= ((uint32_t)k->src_port << 16) | k->dst_port;
    h *= prime;

    /* protocol 반영 */
    h ^= (uint32_t)k->proto;
    h *= prime;

    return h;
}

/**
 * @brief 두 flow key가 동일한 세션인지 비교한다.
 *
 * @param a 첫 번째 key
 * @param b 두 번째 key
 * @return int 동일하면 1, 아니면 0
 */
static int reasm_flow_eq(const flow_key_t *a, const flow_key_t *b) {
    if (a->src_ip != b->src_ip) {
        return 0;
    }
    if (a->dst_ip != b->dst_ip) {
        return 0;
    }
    if (a->src_port != b->src_port) {
        return 0;
    }
    if (a->dst_port != b->dst_port) {
        return 0;
    }
    if (a->proto != b->proto) {
        return 0;
    }

    return 1;
}

/**
 * @brief 세그먼트 노드 한 개를 해제한다.
 *
 * @param s 세그먼트 노드
 */
static void reasm_seg_free(reasm_seg_node_t *s) {
    /* NULL 입력 방어 */
    if (NULL == s) {
        return;
    }

    /* payload 버퍼 해제 */
    free(s->data);
    /* 노드 본체 해제 */
    free(s);
}

/**
 * @brief 방향별 대기열을 비우고 상태를 초기화한다.
 *
 * @param d 방향 상태
 */
static void reasm_dir_clear(reasm_dir_t *d) {
    /* 현재 순회 노드 */
    reasm_seg_node_t *p = d->head;

    /* 대기 세그먼트 리스트 전부 해제 */
    while (NULL != p) {
        /* 다음 노드 백업 */
        reasm_seg_node_t *n = p->next;

        reasm_seg_free(p);
        p = n;
    }

    /* 방향 상태 전체 초기화 */
    memset(d, 0, sizeof(*d));
}

/**
 * @brief 재조립 세션 하나를 해제한다.
 *
 * @param s 세션
 */
static void reasm_session_free(reasm_session_t *s) {
    /* NULL 입력 방어 */
    if (NULL == s) {
        return;
    }

    /* 양방향 대기열 정리 */
    reasm_dir_clear(&s->dir[0]);
    reasm_dir_clear(&s->dir[1]);
    /* 세션 본체 해제 */
    free(s);
}

/**
 * @brief 재조립 컨텍스트를 생성한다.
 *
 * @param nbuckets 해시 버킷 개수
 * @param cb 재조립 데이터 전달 콜백
 * @param user 상위 사용자 컨텍스트
 * @return reasm_ctx_t* 생성된 컨텍스트 또는 NULL
 */
reasm_ctx_t *reasm_create(uint32_t nbuckets, reasm_on_data_cb cb, void *user) {
    /* 생성될 재조립 컨텍스트 */
    reasm_ctx_t *c;

    /* 컨텍스트 본체 할당 */
    c = (reasm_ctx_t *)malloc(sizeof(*c));
    if (NULL == c) {
        return NULL;
    }
    /* zero-init */
    memset(c, 0, sizeof(*c));

    /* bucket 수 기본값 적용 */
    if (0 == nbuckets) {
        nbuckets = 8192;
    }

    /* bucket 배열 할당 */
    c->buckets = (reasm_session_t **)malloc((size_t)nbuckets *
                                            sizeof(reasm_session_t *));
    if (NULL == c->buckets) {
        free(c);
        return NULL;
    }
    /* bucket 배열 zero-init */
    memset(c->buckets, 0, (size_t)nbuckets * sizeof(reasm_session_t *));

    /* 생성 설정 저장 */
    c->nbuckets = nbuckets;
    c->mode     = REASM_MODE_LATE_START;
    c->on_data  = cb;
    c->user     = user;
    return c;
}

/**
 * @brief 기존 재조립 세션을 조회한다.
 *
 * @param c 재조립 컨텍스트
 * @param k flow key
 * @param ts_ms 현재 시각(ms)
 * @return reasm_session_t* 조회된 세션 또는 NULL
 */
static reasm_session_t *reasm_lookup(reasm_ctx_t *c, const flow_key_t *k,
                                     uint64_t ts_ms) {
    /* flow hash bucket index */
    uint32_t idx = reasm_flow_hash(k) % c->nbuckets;

    /* bucket 연결 리스트에서 동일 flow를 찾는다 */
    for (reasm_session_t *p = c->buckets[idx]; NULL != p; p = p->next) {
        /* flow 동등성 비교 결과 */
        int eq;

        eq = reasm_flow_eq(&p->key, k);
        if (0 != eq) {
            /* 찾은 세션은 마지막 관측 시각 갱신 */
            p->last_seen_ms = ts_ms;
            return p;
        }
    }

    return NULL;
}

/**
 * @brief 재조립 세션을 찾고, 없으면 새로 만든다.
 *
 * @param c 재조립 컨텍스트
 * @param k flow key
 * @param ts_ms 현재 시각(ms)
 * @return reasm_session_t* 조회 또는 생성된 세션
 */
static reasm_session_t *reasm_get_or_create(reasm_ctx_t *c, const flow_key_t *k,
                                            uint64_t ts_ms) {
    /* 조회 또는 생성 결과 세션 */
    reasm_session_t *s;
    /* bucket index */
    uint32_t         idx;

    /* 기존 세션이 있으면 그대로 재사용 */
    s = reasm_lookup(c, k, ts_ms);
    if (NULL != s) {
        return s;
    }

    /* 세션 상한을 넘기면 새 세션 생성 거부 */
    if (c->nsessions >= REASM_MAX_SESSIONS) {
        return NULL;
    }

    /* 새 세션이 들어갈 bucket index */
    idx = reasm_flow_hash(k) % c->nbuckets;
    /* 세션 본체 할당 */
    s   = (reasm_session_t *)malloc(sizeof(*s));
    if (NULL == s) {
        return NULL;
    }
    /* 세션 zero-init */
    memset(s, 0, sizeof(*s));

    /* flow key와 시간 저장 */
    s->key          = *k;
    s->last_seen_ms = ts_ms;
    /* bucket head에 삽입 */
    s->next         = c->buckets[idx];
    c->buckets[idx] = s;
    /* 전체 세션 수 증가 */
    c->nsessions++;
    return s;
}

/**
 * @brief 이미 처리된 앞부분을 잘라내고 아직 필요한 부분만 남긴다.
 *
 * @param d 방향별 재조립 상태
 * @param seq payload 시작 sequence
 * @param payload payload 시작 포인터
 * @param len payload 길이
 */
static void reasm_trim_to_next(reasm_dir_t *d, uint32_t *seq,
                               const uint8_t **payload, uint32_t *len) {
    /* 현재 세그먼트 시작 seq */
    uint32_t start;
    /* 현재 세그먼트 끝 seq */
    uint32_t end;
    /* helper 비교 결과 */
    int      ret;

    /* payload가 없거나 next_seq가 아직 없으면 trim 불필요 */
    if (0 == *len || 0 == d->has_next) {
        return;
    }

    /* 현재 세그먼트 구간 계산 */
    start = *seq;
    end   = start + *len;
    /* 세그먼트 전체가 이미 소비된 구간이면 버린다 */
    ret   = SEQ_LEQ(end, d->next_seq);
    if (0 != ret) {
        *len = 0;
        return;
    }

    /* 앞부분만 이미 소비됐다면 아직 필요한 뒤쪽만 남긴다 */
    ret = SEQ_LT(start, d->next_seq);
    if (0 != ret) {
        uint32_t delta = (uint32_t)(d->next_seq - start);

        *seq = d->next_seq;
        *payload += delta;
        *len -= delta;
    }
}

/**
 * @brief out-of-order TCP 조각을 재조립 대기열에 삽입한다.
 *
 * @param d 방향별 재조립 상태
 * @param seq payload 시작 sequence
 * @param payload payload 시작 주소
 * @param len payload 길이
 * @return int 0:정상, -1:세그먼트 수 초과, -2:바이트 한도 초과, -3:메모리 실패
 */
static int reasm_insert_segment(reasm_dir_t *d, uint32_t seq,
                                const uint8_t *payload, uint32_t len) {
    /* 삽입 위치를 가리키는 pointer-to-pointer */
    reasm_seg_node_t **pp;
    /* 삽입 직전 노드 */
    reasm_seg_node_t  *prev      = NULL;
    /* 새 세그먼트 시작/끝 */
    uint32_t           new_start = seq;
    uint32_t           new_end   = seq + len;
    /* helper 비교 결과 */
    int                ret;

    /* 빈 세그먼트는 무시 */
    if (0 == len) {
        return 0;
    }
    /* 세그먼트 개수 상한 검사 */
    if (d->seg_count >= REASM_MAX_SEGMENTS_PER_DIR) {
        return -1;
    }
    /* 큐 바이트 상한 검사 */
    if (d->bytes_queued + len > REASM_MAX_BYTES_PER_DIR) {
        return -2;
    }

    /* seq 순으로 들어갈 위치까지 이동 */
    pp  = &d->head;
    ret = (NULL != *pp) ? SEQ_LT((*pp)->seq, seq) : 0;
    while (NULL != *pp && 0 != ret) {
        pp  = &(*pp)->next;
        ret = (NULL != *pp) ? SEQ_LT((*pp)->seq, seq) : 0;
    }

    /* 삽입 지점의 직전 노드를 다시 찾는다 */
    if (pp != &d->head) {
        reasm_seg_node_t *p = d->head;

        while (NULL != p && p->next != *pp) {
            p = p->next;
        }
        prev = p;
    }

    /* 직전 노드와 겹치면 필요한 뒤쪽만 남긴다 */
    if (NULL != prev) {
        uint32_t prev_end = prev->seq + prev->len;
        int      seq_geq;

        seq_geq = SEQ_GEQ(prev_end, new_start);
        if (0 != seq_geq) {
            seq_geq = SEQ_GEQ(prev_end, new_end);
            if (0 != seq_geq) {
                return 0;
            }

            {
                uint32_t delta = (uint32_t)(prev_end - new_start);

                new_start = prev_end;
                payload += delta;
                len -= delta;
                new_end = new_start + len;
            }
        }
    }

    /* 뒤쪽 기존 세그먼트와의 겹침/포함 관계를 정리한다 */
    while (NULL != *pp) {
        /* 현재 비교 대상 노드 */
        reasm_seg_node_t *cur       = *pp;
        /* 현재 노드 구간 */
        uint32_t          cur_start = cur->seq;
        uint32_t          cur_end   = cur->seq + cur->len;
        /* helper 비교 결과 */
        int               seq_cmp;

        /* 더 이상 겹치지 않으면 삽입 준비 완료 */
        seq_cmp = SEQ_LEQ(new_end, cur_start);
        if (0 != seq_cmp) {
            break;
        }

        /* 새 세그먼트가 현재 노드를 완전히 덮으면 현재 노드 제거 */
        seq_cmp = SEQ_LT(new_start, cur_start);
        if (0 != seq_cmp) {
            seq_cmp = SEQ_GEQ(new_end, cur_end);
            if (0 != seq_cmp) {
                *pp = cur->next;
                d->seg_count--;
                d->bytes_queued -= cur->len;
                free(cur->data);
                free(cur);
                continue;
            } else {
                /* 새 세그먼트 뒤 일부만 유지 */
                uint32_t keep = (uint32_t)(cur_start - new_start);

                len     = keep;
                new_end = new_start + len;
                break;
            }
        }

        /* 현재 노드가 새 세그먼트 앞부분을 덮으면 시작점을 당긴다 */
        seq_cmp = SEQ_LT(new_start, cur_end);
        if (0 != seq_cmp) {
            seq_cmp = SEQ_GEQ(cur_end, new_end);
            if (0 != seq_cmp) {
                return 0;
            }

            {
                uint32_t delta = (uint32_t)(cur_end - new_start);

                new_start = cur_end;
                payload += delta;
                len -= delta;
                new_end = new_start + len;
                pp      = &cur->next;
                continue;
            }
        }

        pp = &(*pp)->next;
    }

    /* trim 결과 남는 데이터가 없으면 종료 */
    if (0 == len) {
        return 0;
    }
    /* trim 후에도 상한을 다시 검사 */
    if (d->seg_count >= REASM_MAX_SEGMENTS_PER_DIR) {
        return -1;
    }
    if (d->bytes_queued + len > REASM_MAX_BYTES_PER_DIR) {
        return -2;
    }

    {
        /* 새 세그먼트 노드 할당 */
        reasm_seg_node_t *n = (reasm_seg_node_t *)malloc(sizeof(*n));

        if (NULL == n) {
            return -3;
        }
        /* 노드 zero-init */
        memset(n, 0, sizeof(*n));
        /* payload 본문 버퍼 할당 */
        n->data = (uint8_t *)malloc(len);
        if (NULL == n->data) {
            free(n);
            return -3;
        }

        /* payload 본문 복사 */
        memcpy(n->data, payload, len);
        /* seq/len 메타 저장 */
        n->seq = new_start;
        n->len = len;

        /* 최종 삽입 위치를 다시 찾아 연결 */
        pp  = &d->head;
        ret = (NULL != *pp) ? SEQ_LT((*pp)->seq, n->seq) : 0;
        while (NULL != *pp && 0 != ret) {
            pp  = &(*pp)->next;
            ret = (NULL != *pp) ? SEQ_LT((*pp)->seq, n->seq) : 0;
        }
        /* 새 노드를 연결 리스트에 삽입 */
        n->next = *pp;
        *pp     = n;

        /* 방향별 대기열 통계 갱신 */
        d->seg_count++;
        d->bytes_queued += len;

        /* 바로 뒤에 연속한 노드는 하나로 병합한다 */
        while (NULL != n->next) {
            /* 다음 인접 노드 */
            reasm_seg_node_t *nx    = n->next;
            /* 현재 병합 노드 끝 seq */
            uint32_t          n_end = n->seq + n->len;

            /* gap이 있으면 병합 중단 */
            if (n_end != nx->seq) {
                break;
            }

            {
                /* 병합 후 총 길이 */
                uint32_t merged_len = n->len + nx->len;
                /* 재할당된 payload 버퍼 */
                uint8_t *buf        = (uint8_t *)realloc(n->data, merged_len);

                if (NULL == buf) {
                    break;
                }

                n->data = buf;
                /* 뒤 노드 payload를 현재 노드 뒤에 이어 붙인다 */
                memcpy(n->data + n->len, nx->data, nx->len);
                n->len = merged_len;
            }

            /* 병합 완료된 다음 노드는 제거 */
            n->next = nx->next;
            d->seg_count--;
            reasm_seg_free(nx);
        }
    }

    return 0;
}

/**
 * @brief payload 시작이 HTTP 요청/응답 시작줄처럼 보이는지 검사한다.
 *
 * late-start 모드에서는 첫 payload가 HTTP 메시지의 시작인지 알아야
 * out-of-order 적재 대신 즉시 next_seq 기준을 잡을 수 있다. 요청 메서드뿐만
 * 아니라 `HTTP/1.x` 응답 시작줄도 허용해야 서버/차단 응답 방향에서
 * 불필요한 out-of-order 누적을 피할 수 있다.
 *
 * @param payload payload 시작 주소
 * @param len payload 길이
 * @return int HTTP 시작으로 보이면 1, 아니면 0
 */
static int reasm_looks_like_http_start(const uint8_t *payload, uint32_t len) {
    static const char *const methods[] = {"GET ",   "POST ",   "PUT ",
                                          "HEAD ",  "DELETE ", "OPTIONS ",
                                          "PATCH ", "TRACE ",  "CONNECT "};
    size_t                   i;

    if (NULL == payload || 0 == len) {
        return 0;
    }

    for (i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
        size_t n = strlen(methods[i]);
        int    ret;

        ret = 1;
        if (len >= n) {
            ret = memcmp(payload, methods[i], n);
        }
        if (len >= n && 0 == ret) {
            return 1;
        }
    }

    if (len >= sizeof("HTTP/1.0") - 1U) {
        int ret;

        ret = memcmp(payload, "HTTP/1.0", sizeof("HTTP/1.0") - 1U);
        if (0 == ret) {
            return 1;
        }

        ret = memcmp(payload, "HTTP/1.1", sizeof("HTTP/1.1") - 1U);
        if (0 == ret) {
            return 1;
        }
    }

    return 0;
}

/**
 * @brief now in-order가 된 대기 세그먼트를 상위 계층으로 배출한다.
 *
 * @param c 재조립 컨텍스트
 * @param s 현재 세션
 * @param dir 방향
 */
static void reasm_flush(reasm_ctx_t *c, reasm_session_t *s, tcp_dir_t dir) {
    /* 현재 방향 상태 */
    reasm_dir_t *d = &s->dir[dir];

    /* next_seq가 아직 없으면 flush할 수 없다 */
    if (0 == d->has_next) {
        return;
    }

    /* head가 expected next_seq와 맞는 동안 연속 구간을 상위로 배출 */
    while (NULL != d->head && d->head->seq == d->next_seq) {
        /* 지금 배출할 head 세그먼트 */
        reasm_seg_node_t *h = d->head;

        /* 상위 on_data 콜백으로 연속 바이트 전달 */
        if (NULL != c->on_data) {
            c->on_data(&s->key, dir, h->data, h->len, h->seq, c->user);
        }

        /* next_seq를 현재 세그먼트 뒤로 전진 */
        d->next_seq += h->len;
        /* 대기열 통계 갱신 */
        d->bytes_queued -= h->len;
        d->seg_count--;
        /* head pop */
        d->head = h->next;
        reasm_seg_free(h);
    }
}

/**
 * @brief 재조립 모드를 설정한다.
 *
 * @param c 재조립 컨텍스트
 * @param mode 재조립 모드
 */
void reasm_set_mode(reasm_ctx_t *c, reasm_mode_t mode) {
    if (NULL == c) {
        return;
    }

    c->mode = mode;
}

/**
 * @brief 재조립 컨텍스트와 모든 세션을 해제한다.
 *
 * @param c 재조립 컨텍스트
 */
void reasm_destroy(reasm_ctx_t *c) {
    /* NULL 입력 방어 */
    if (NULL == c) {
        return;
    }

    /* 모든 bucket의 세션 리스트 정리 */
    for (uint32_t i = 0; i < c->nbuckets; i++) {
        reasm_session_t *p = c->buckets[i];

        while (NULL != p) {
            reasm_session_t *n = p->next;

            reasm_session_free(p);
            p = n;
        }
    }

    /* bucket 배열과 컨텍스트 본체 해제 */
    free(c->buckets);
    free(c);
}

/**
 * @brief 만료된 재조립 세션을 정리한다.
 *
 * @param c 재조립 컨텍스트
 * @param now_ms 현재 시각(ms)
 */
void reasm_gc(reasm_ctx_t *c, uint64_t now_ms) {
    /* NULL 입력 방어 */
    if (NULL == c) {
        return;
    }

    /* 모든 bucket을 순회하며 timeout 세션 제거 */
    for (uint32_t i = 0; i < c->nbuckets; i++) {
        reasm_session_t **pp = &c->buckets[i];

        while (NULL != *pp) {
            reasm_session_t *s = *pp;

            /* 마지막 관측 시각이 오래된 세션 제거 */
            if (now_ms - s->last_seen_ms > REASM_SESSION_TIMEOUT_MS) {
                *pp = s->next;
                c->nsessions--;
                reasm_session_free(s);
                continue;
            }

            /* 살아 있는 세션은 다음 링크로 진행 */
            pp = &s->next;
        }
    }
}

/**
 * @brief 재조립 순서 관련 누적 통계를 복사한다.
 *
 * @param c 재조립 컨텍스트
 * @param out 출력 통계
 */
void reasm_get_stats(const reasm_ctx_t *c, reasm_stats_t *out) {
    /* 출력 포인터 검증 */
    if (NULL == out) {
        return;
    }

    /* 기본값 zero-init */
    memset(out, 0, sizeof(*out));
    /* 컨텍스트가 없으면 0 통계 반환 */
    if (NULL == c) {
        return;
    }

    /* 누적 통계 구조체 복사 */
    *out = c->stats;
}

/**
 * @brief TCP 패킷 한 개를 재조립 엔진에 투입한다.
 *
 * @param c 재조립 컨텍스트
 * @param flow flow key
 * @param dir 방향
 * @param seq TCP sequence
 * @param tcp_flags TCP flags
 * @param payload payload 시작 주소
 * @param len payload 길이
 * @param ts_ms 현재 시각(ms)
 * @return int 0이면 정상, -1이면 실패
 */
int reasm_ingest(reasm_ctx_t *c, const flow_key_t *flow, tcp_dir_t dir,
                 uint32_t seq, uint8_t tcp_flags, const uint8_t *payload,
                 uint32_t len, uint64_t ts_ms) {
    /* 대상 재조립 세션 */
    reasm_session_t *s;
    /* 현재 방향 상태 */
    reasm_dir_t     *d;
    /* trim 이후 seq/payload/len */
    uint32_t         adj_seq;
    const uint8_t   *adj_pl;
    uint32_t         adj_len;
    /* helper 반환값 */
    int              rc;

    /* 필수 입력 검증 */
    if (NULL == c || NULL == flow) {
        return -1;
    }
    /* 허용된 방향 enum만 처리 */
    if (dir != DIR_AB && dir != DIR_BA) {
        return -1;
    }

    /* 기존 세션 조회 */
    s = reasm_lookup(c, flow, ts_ms);
    /* RST는 세션을 즉시 제거하는 종료 이벤트다 */
    if (tcp_flags & TCP_RST) {
        if (NULL == s) {
            return 0;
        }

        {
            uint32_t          idx = reasm_flow_hash(flow) % c->nbuckets;
            reasm_session_t **pp  = &c->buckets[idx];

            /* bucket 연결 리스트에서 해당 세션을 제거한다 */
            while (NULL != *pp) {
                if (*pp == s) {
                    *pp = s->next;
                    c->nsessions--;
                    reasm_session_free(s);
                    break;
                }
                pp = &(*pp)->next;
            }
        }

        /* RST 처리 후 추가 재조립은 하지 않는다 */
        return 0;
    }

    /* 세션이 없으면 현재 모드 정책에 따라 새 세션 생성 여부를 결정한다 */
    if (NULL == s) {
        /* late-start에서 pure ACK만 오면 세션 없이 무시한다 */
        if (0 == len && c->mode == REASM_MODE_LATE_START) {
            return 0;
        }
        /* strict-syn 모드에서는 SYN 없는 시작을 허용하지 않는다 */
        rc = (int)(tcp_flags & TCP_SYN);
        if (REASM_MODE_STRICT_SYN == c->mode && 0 == rc) {
            return 0;
        }

        /* 새 세션 생성 */
        s = reasm_get_or_create(c, flow, ts_ms);
        if (NULL == s) {
            return -1;
        }
    }

    /* 방향별 재조립 상태 참조 */
    d = &s->dir[dir];
    /* FIN은 나중에 양방향 종료 판단에 사용한다 */
    if (tcp_flags & TCP_FIN) {
        d->fin_seen = 1;
    }

    /* next_seq가 아직 없으면 첫 시작점 정책을 정한다 */
    if (0 == d->has_next) {
        if (c->mode == REASM_MODE_STRICT_SYN) {
            /* strict-syn은 SYN 이후 1바이트 뒤를 기대 seq로 잡는다 */
            d->has_next = 1;
            d->next_seq = seq + 1;
        } else {
            /* late-start는 payload 없는 패킷으로 시작하지 않는다 */
            if (0 == len) {
                return 0;
            }
            /* HTTP 시작처럼 보이지 않으면 일단 out-of-order로 적재한다 */
            rc = reasm_looks_like_http_start(payload, len);
            if (0 == rc) {
                c->stats.out_of_order_pkts++;
                return reasm_insert_segment(d, seq, payload, len);
            }

            /* HTTP 시작으로 보이면 현재 seq를 next_seq로 채택한다 */
            d->has_next = 1;
            d->next_seq = seq;
        }
    }

    /* 이미 소비된 앞부분을 제거한 조정 구간 */
    adj_seq = seq;
    adj_pl  = payload;
    adj_len = len;
    reasm_trim_to_next(d, &adj_seq, &adj_pl, &adj_len);
    /* trim 결과 남는 데이터가 없으면 중복 패킷으로 본다 */
    if (0 == adj_len) {
        c->stats.trimmed_pkts++;
        return 0;
    }

    /* expected seq와 맞으면 즉시 상위로 전달한다 */
    if (adj_seq == d->next_seq) {
        c->stats.in_order_pkts++;
        if (NULL != c->on_data) {
            c->on_data(&s->key, dir, adj_pl, adj_len, adj_seq, c->user);
        }

        /* 다음 expected seq를 전진시키고 대기열도 flush한다 */
        d->next_seq += adj_len;
        reasm_flush(c, s, dir);
        return 0;
    }

    /* 그 외는 out-of-order로 대기열에 적재한다 */
    c->stats.out_of_order_pkts++;
    rc = reasm_insert_segment(d, adj_seq, adj_pl, adj_len);
    if (0 != rc) {
        /* 대기열 삽입 실패 시 세션을 정리하고 에러 반환 */
        uint32_t          idx = reasm_flow_hash(flow) % c->nbuckets;
        reasm_session_t **pp  = &c->buckets[idx];

        while (NULL != *pp) {
            if (*pp == s) {
                *pp = s->next;
                c->nsessions--;
                reasm_session_free(s);
                break;
            }
            pp = &(*pp)->next;
        }

        return rc;
    }

    /* 새 세그먼트 추가 후 now in-order가 된 head를 배출한다 */
    reasm_flush(c, s, dir);

    /* 양방향 FIN을 모두 봤고 대기열도 비면 세션을 정리한다 */
    if (s->dir[0].fin_seen && s->dir[1].fin_seen && NULL == s->dir[0].head &&
        NULL == s->dir[1].head) {
        uint32_t          idx = reasm_flow_hash(flow) % c->nbuckets;
        reasm_session_t **pp  = &c->buckets[idx];

        while (NULL != *pp) {
            if (*pp == s) {
                *pp = s->next;
                c->nsessions--;
                reasm_session_free(s);
                break;
            }
            pp = &(*pp)->next;
        }
    }

    return 0;
}

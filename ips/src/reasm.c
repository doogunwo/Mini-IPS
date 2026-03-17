/**
 * @file reasm.c
 * @brief TCP 재조립 엔진 구현
 */
#include "reasm.h"

#include <stdlib.h>
#include <string.h>

/* ---------- seq 비교(랩어라운드 고려) ---------- */
static inline int32_t seq_diff(uint32_t a, uint32_t b) {
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
    uint8_t  has_next;
    uint32_t next_seq;
    uint8_t  fin_seen;
    uint8_t  rst_seen;

    reasm_seg_node_t *head;
    uint32_t          seg_count;
    uint32_t          bytes_queued;
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

static uint32_t reasm_flow_hash(const flow_key_t *k);
static int reasm_flow_eq(const flow_key_t *a, const flow_key_t *b);
static void reasm_seg_free(reasm_seg_node_t *s);
static void reasm_dir_clear(reasm_dir_t *d);
static void reasm_session_free(reasm_session_t *s);
static reasm_session_t *reasm_lookup(reasm_ctx_t *c, const flow_key_t *k,
                                     uint64_t ts_ms);
static reasm_session_t *reasm_get_or_create(reasm_ctx_t *c, const flow_key_t *k,
                                            uint64_t ts_ms);
static void reasm_trim_to_next(reasm_dir_t *d, uint32_t *seq,
                               const uint8_t **payload, uint32_t *len);
static int reasm_insert_segment(reasm_dir_t *d, uint32_t seq,
                                const uint8_t *payload, uint32_t len);
static int reasm_looks_like_http_start(const uint8_t *payload, uint32_t len);
static void reasm_flush(reasm_ctx_t *c, reasm_session_t *s, tcp_dir_t dir);

/**
 * @brief flow key에 대한 FNV 기반 해시를 계산한다.
 *
 * @param k flow key
 * @return uint32_t 해시값
 */
static uint32_t reasm_flow_hash(const flow_key_t *k) {
    uint32_t       h     = 2166136261u;
    const uint32_t prime = 16777619u;

    h ^= (uint32_t)k->src_ip;
    h *= prime;

    h ^= (uint32_t)k->dst_ip;
    h *= prime;

    h ^= ((uint32_t)k->src_port << 16) | k->dst_port;
    h *= prime;

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
    if (NULL == s) {
        return;
    }

    free(s->data);
    free(s);
}

/**
 * @brief 방향별 대기열을 비우고 상태를 초기화한다.
 *
 * @param d 방향 상태
 */
static void reasm_dir_clear(reasm_dir_t *d) {
    reasm_seg_node_t *p = d->head;

    while (NULL != p) {
        reasm_seg_node_t *n = p->next;

        reasm_seg_free(p);
        p = n;
    }

    memset(d, 0, sizeof(*d));
}

/**
 * @brief 재조립 세션 하나를 해제한다.
 *
 * @param s 세션
 */
static void reasm_session_free(reasm_session_t *s) {
    if (NULL == s) {
        return;
    }

    reasm_dir_clear(&s->dir[0]);
    reasm_dir_clear(&s->dir[1]);
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
    reasm_ctx_t *c;

    c = (reasm_ctx_t *)calloc(1, sizeof(*c));
    if (NULL == c) {
        return NULL;
    }

    if (0 == nbuckets) {
        nbuckets = 8192;
    }

    c->buckets = (reasm_session_t **)calloc(nbuckets, sizeof(reasm_session_t *));
    if (NULL == c->buckets) {
        free(c);
        return NULL;
    }

    c->nbuckets = nbuckets;
    c->mode     = REASM_MODE_LATE_START;
    c->on_data  = cb;
    c->user     = user;
    return c;
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
    if (NULL == c) {
        return;
    }

    for (uint32_t i = 0; i < c->nbuckets; i++) {
        reasm_session_t *p = c->buckets[i];

        while (NULL != p) {
            reasm_session_t *n = p->next;

            reasm_session_free(p);
            p = n;
        }
    }

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
    if (NULL == c) {
        return;
    }

    for (uint32_t i = 0; i < c->nbuckets; i++) {
        reasm_session_t **pp = &c->buckets[i];

        while (NULL != *pp) {
            reasm_session_t *s = *pp;

            if (now_ms - s->last_seen_ms > REASM_SESSION_TIMEOUT_MS) {
                *pp = s->next;
                c->nsessions--;
                reasm_session_free(s);
                continue;
            }

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
    if (NULL == out) {
        return;
    }

    memset(out, 0, sizeof(*out));
    if (NULL == c) {
        return;
    }

    *out = c->stats;
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
    uint32_t idx = reasm_flow_hash(k) % c->nbuckets;

    for (reasm_session_t *p = c->buckets[idx]; NULL != p; p = p->next) {
        if (reasm_flow_eq(&p->key, k)) {
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
    reasm_session_t *s;
    uint32_t         idx;

    s = reasm_lookup(c, k, ts_ms);
    if (NULL != s) {
        return s;
    }

    if (c->nsessions >= REASM_MAX_SESSIONS) {
        return NULL;
    }

    idx = reasm_flow_hash(k) % c->nbuckets;
    s   = (reasm_session_t *)calloc(1, sizeof(*s));
    if (NULL == s) {
        return NULL;
    }

    s->key          = *k;
    s->last_seen_ms = ts_ms;
    s->next         = c->buckets[idx];
    c->buckets[idx] = s;
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
    uint32_t start;
    uint32_t end;

    if (0 == *len || 0 == d->has_next) {
        return;
    }

    start = *seq;
    end   = start + *len;
    if (SEQ_LEQ(end, d->next_seq)) {
        *len = 0;
        return;
    }

    if (SEQ_LT(start, d->next_seq)) {
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
    reasm_seg_node_t **pp;
    reasm_seg_node_t  *prev      = NULL;
    uint32_t           new_start = seq;
    uint32_t           new_end   = seq + len;

    if (0 == len) {
        return 0;
    }
    if (d->seg_count >= REASM_MAX_SEGMENTS_PER_DIR) {
        return -1;
    }
    if (d->bytes_queued + len > REASM_MAX_BYTES_PER_DIR) {
        return -2;
    }

    pp = &d->head;
    while (NULL != *pp && SEQ_LT((*pp)->seq, seq)) {
        pp = &(*pp)->next;
    }

    if (pp != &d->head) {
        reasm_seg_node_t *p = d->head;

        while (NULL != p && p->next != *pp) {
            p = p->next;
        }
        prev = p;
    }

    if (NULL != prev) {
        uint32_t prev_end = prev->seq + prev->len;

        if (SEQ_GEQ(prev_end, new_start)) {
            if (SEQ_GEQ(prev_end, new_end)) {
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

    while (NULL != *pp) {
        reasm_seg_node_t *cur       = *pp;
        uint32_t          cur_start = cur->seq;
        uint32_t          cur_end   = cur->seq + cur->len;

        if (SEQ_LEQ(new_end, cur_start)) {
            break;
        }

        if (SEQ_LT(new_start, cur_start)) {
            if (SEQ_GEQ(new_end, cur_end)) {
                *pp = cur->next;
                d->seg_count--;
                d->bytes_queued -= cur->len;
                free(cur->data);
                free(cur);
                continue;
            } else {
                uint32_t keep = (uint32_t)(cur_start - new_start);

                len     = keep;
                new_end = new_start + len;
                break;
            }
        }

        if (SEQ_LT(new_start, cur_end)) {
            if (SEQ_GEQ(cur_end, new_end)) {
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

    if (0 == len) {
        return 0;
    }
    if (d->seg_count >= REASM_MAX_SEGMENTS_PER_DIR) {
        return -1;
    }
    if (d->bytes_queued + len > REASM_MAX_BYTES_PER_DIR) {
        return -2;
    }

    {
        reasm_seg_node_t *n = (reasm_seg_node_t *)calloc(1, sizeof(*n));

        if (NULL == n) {
            return -3;
        }
        /* ************* Malloc *****************/
        n->data = (uint8_t *)malloc(len);
        if (NULL == n->data) {
            free(n);
            return -3;
        }

        memcpy(n->data, payload, len);
        n->seq = new_start;
        n->len = len;

        pp = &d->head;
        while (NULL != *pp && SEQ_LT((*pp)->seq, n->seq)) {
            pp = &(*pp)->next;
        }
        n->next = *pp;
        *pp     = n;

        d->seg_count++;
        d->bytes_queued += len;

        while (NULL != n->next) {
            reasm_seg_node_t *nx    = n->next;
            uint32_t          n_end = n->seq + n->len;

            if (n_end != nx->seq) {
                break;
            }

            {
                uint32_t merged_len = n->len + nx->len;
                 /* ************* realloc *****************/
                uint8_t *buf = (uint8_t *)realloc(n->data, merged_len);

                if (NULL == buf) {
                    break;
                }

                n->data = buf;
                memcpy(n->data + n->len, nx->data, nx->len);
                n->len = merged_len;
            }

            n->next = nx->next;
            d->seg_count--;
            reasm_seg_free(nx);
        }
    }

    return 0;
}

/**
 * @brief payload 시작이 HTTP 요청처럼 보이는지 검사한다.
 *
 * @param payload payload 시작 주소
 * @param len payload 길이
 * @return int HTTP 시작으로 보이면 1, 아니면 0
 */
static int reasm_looks_like_http_start(const uint8_t *payload, uint32_t len) {
    static const char *const methods[] = {"GET ",   "POST ",   "PUT ",
                                          "HEAD ",  "DELETE ", "OPTIONS ",
                                          "PATCH ", "TRACE ",  "CONNECT "};
    size_t i;

    if (NULL == payload || 0 == len) {
        return 0;
    }

    for (i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
        size_t n = strlen(methods[i]);

        if (len >= n && memcmp(payload, methods[i], n) == 0) {
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
    reasm_dir_t *d = &s->dir[dir];

    if (0 == d->has_next) {
        return;
    }

    while (NULL != d->head && d->head->seq == d->next_seq) {
        reasm_seg_node_t *h = d->head;

        if (NULL != c->on_data) {
            c->on_data(&s->key, dir, h->data, h->len, h->seq, c->user);
        }

        d->next_seq += h->len;
        d->bytes_queued -= h->len;
        d->seg_count--;
        d->head = h->next;
        reasm_seg_free(h);
    }
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
 * @return int 0:정상, -1:입력 오류, -2:세션 생성 실패
 */
int reasm_ingest(reasm_ctx_t *c, const flow_key_t *flow, tcp_dir_t dir,
                 uint32_t seq, uint8_t tcp_flags, const uint8_t *payload,
                 uint32_t len, uint64_t ts_ms) {
    reasm_session_t *s;
    reasm_dir_t     *d;
    uint32_t         adj_seq;
    const uint8_t   *adj_pl;
    uint32_t         adj_len;
    int              rc;

    if (NULL == c || NULL == flow) {
        return -1;
    }
    if (dir != DIR_AB && dir != DIR_BA) {
        return -1;
    }

    s = reasm_lookup(c, flow, ts_ms);
    if (tcp_flags & TCP_RST) {
        if (NULL == s) {
            return 0;
        }

        {
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

    if (NULL == s) {
        if (0 == len && c->mode == REASM_MODE_LATE_START) {
            return 0;
        }
        if (c->mode == REASM_MODE_STRICT_SYN && !(tcp_flags & TCP_SYN)) {
            return 0;
        }

        s = reasm_get_or_create(c, flow, ts_ms);
        if (NULL == s) {
            return -2;
        }
    }

    d = &s->dir[dir];
    if (tcp_flags & TCP_FIN) {
        d->fin_seen = 1;
    }

    if (0 == d->has_next) {
        if (c->mode == REASM_MODE_STRICT_SYN) {
            d->has_next = 1;
            d->next_seq = seq + 1;
        } else {
            if (0 == len) {
                return 0;
            }
            if (0 == reasm_looks_like_http_start(payload, len)) {
                c->stats.out_of_order_pkts++;
                return reasm_insert_segment(d, seq, payload, len);
            }

            d->has_next = 1;
            d->next_seq = seq;
        }
    }

    adj_seq = seq;
    adj_pl  = payload;
    adj_len = len;
    reasm_trim_to_next(d, &adj_seq, &adj_pl, &adj_len);
    if (0 == adj_len) {
        c->stats.trimmed_pkts++;
        return 0;
    }

    if (adj_seq == d->next_seq) {
        c->stats.in_order_pkts++;
        if (NULL != c->on_data) {
            c->on_data(&s->key, dir, adj_pl, adj_len, adj_seq, c->user);
        }

        d->next_seq += adj_len;
        reasm_flush(c, s, dir);
        return 0;
    }

    c->stats.out_of_order_pkts++;
    rc = reasm_insert_segment(d, adj_seq, adj_pl, adj_len);
    if (0 != rc) {
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

    reasm_flush(c, s, dir);

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

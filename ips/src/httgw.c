/**
 * @file httgw.c
 * @brief HTTP 게이트웨이, TCP 재조립, RST 처리 구현
 */
#include "httgw.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "net_compat.h"

typedef void (*reasm_on_data_cb)(const flow_key_t *flow, tcp_dir_t dir,
                                 const uint8_t *data, uint32_t len,
                                 uint32_t seq_start, void *user);

/* ---------- seq 비교(랩어라운드 고려) ---------- */
static inline int32_t seq_diff(uint32_t a, uint32_t b) {
    return (int32_t)(a - b);
}

#define SEQ_LT(a, b) (seq_diff((a), (b)) < 0)
#define SEQ_LEQ(a, b) (seq_diff((a), (b)) <= 0)
#define SEQ_GT(a, b) (seq_diff((a), (b)) > 0)
#define SEQ_GEQ(a, b) (seq_diff((a), (b)) >= 0)

/* */
#define HTTGW_INJECT_SEGMENT_BYTES 1200U

/**
 * @brief HTTP 재조립, Out-of-order 대비용 연결리스트 구조체
 * 순서 맞추기 위한 임시 세그먼트 보관용 연결리스트
 */
typedef struct reasm_seg_node {
    uint32_t               seq;   // TCP 넘버
    uint32_t               len;   // 보관중인 길이
    uint8_t               *data;  // 실제 패킷 페이로드가 저장된 메모리 포인터
    struct reasm_seg_node *next;  // 더 큰 다음 조각을 가르키는 포인터
} reasm_seg_node_t;

/**
 * @brief 방향(dir)을 맞축디 위한 방향 상태 관리
 * 세션 구조체(reasm_session_t)에서 reasm_dir_t를 2개로 가짐 dir[2]
 * 요청/응답 양방향 추적은 유지하지만, 현재 상위 계층에는 요청만 전달한다.
 */
typedef struct reasm_dir {
    uint8_t  has_next;  // 다음 패킷이 있음? 0/1
    uint32_t next_seq;  // 이번에 와야할 패킷 번호
    uint8_t  fin_seen;  // 통신이 종료중인지?(FIN 봄?)
    uint8_t  rst_seen;  // RST 패킷 봄?

    reasm_seg_node_t *head;  // 첫번째를 가르키는 포인터, 이 포인터 뒤에
                             // next_seq보다 큰걸 붙여놓음
    uint32_t seg_count;      // 포인터 뒤에 붙어있는 세그먼트 개수
    uint32_t bytes_queued;   // 포인터 뒤에 붙어있는 세그먼트의 총 용량
} reasm_dir_t;

/**
 * @brief TCP 연결 1개에 대한 재조립 상태 묶음
 * 재조립 엔진(reasm_) 전체의 전역 컨텍스트
 */
typedef struct reasm_session {
    flow_key_t key;
    uint64_t   last_seen_ms;

    reasm_dir_t           dir[2];
    struct reasm_session *next;
} reasm_session_t;  // TCP연결 1개에 대한 상태

/**
 * @brief 재조립 세션 저장, 해시 테이블, 콜백함수 묶은 구조체
 *
 */
typedef struct reasm_ctx {
    reasm_session_t **buckets;    // 해시테이블
    uint32_t          nbuckets;   // 버킷 개수
    uint32_t          nsessions;  // 등록된 세션 개수

    reasm_mode_t     mode;     // 재조립 동작 모드 (strict/last-start)
    reasm_on_data_cb on_data;  // 붙일 콜백함수
    void            *user;     // 사용자 컨텍스트 포인터
} reasm_ctx_t;                 // 세션 전체를 관리함

/**
 * @brief 해시 계산 함수
 * 세션 삭제 시 버킷찾아야 하는데, 이 때 해시 계산용
 * @param k 해시 계산할 TCP FLOW 키
 * @return uint32_t
 */
static uint32_t reasm_flow_hash(const flow_key_t *k) {
    uint32_t       h     = 2166136261u;  // FNV offset basis (초기값)
    const uint32_t prime = 16777619u;    // FNV prime (곱하는 값)

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
 * @brief 두 키 비교하기 같은 세션인지?
 *
 * @param a  처음 키
 * @param b  두 번 째 키
 * @return int
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

static void reasm_seg_free(reasm_seg_node_t *s) {
    if (!s) {
        return;
    }
    free(s->data);
    free(s);
}

static void reasm_dir_clear(reasm_dir_t *d) {
    reasm_seg_node_t *p = d->head;
    while (p) {
        reasm_seg_node_t *n = p->next;
        reasm_seg_free(p);
        p = n;
    }
    memset(d, 0, sizeof(*d));
}

static void reasm_session_free(reasm_session_t *s) {
    if (!s) {
        return;
    }
    reasm_dir_clear(&s->dir[0]);
    reasm_dir_clear(&s->dir[1]);
    free(s);
}

/**
 * @brief reasm_ctx_t 생성하고 초기화하는 함수
 *
 * @param nbuckets 버킷 개수
 * @param cb 붙일 콜백함수
 * @param user 사용자 컨텍스트 포인터
 * @return reasm_ctx_t* 생성한 컨텍스트
 */
static reasm_ctx_t *reasm_create(uint32_t nbuckets, reasm_on_data_cb cb,
                                 void *user) {  // 0으로 초기화
    reasm_ctx_t *c = (reasm_ctx_t *)calloc(1, sizeof(*c));
    if (!c) {
        return NULL;
    }
    // 0 -> 기본 버킷 8192
    if (nbuckets == 0) {
        nbuckets = 8192;
    }

    // 각 버킷은 생성 및 NULL
    c->buckets =
        (reasm_session_t **)calloc(nbuckets, sizeof(reasm_session_t *));
    if (!c->buckets) {
        free(c);
        return NULL;
    }

    // 필드 초기화
    c->nbuckets = nbuckets;
    c->mode     = REASM_MODE_LATE_START;
    c->on_data  = cb;
    c->user     = user;
    return c;
}

/**
 * @brief 컨텍스트 동작 모드 설정
 * 널 체크 후 모드 값 설정하는 함수
 * @param c 재조립 컨텍스트
 * @param mode 재조립 모드
 * @return 없음
 */
static void reasm_set_mode(reasm_ctx_t *c, reasm_mode_t mode) {
    if (!c) {
        return;
    }
    c->mode = mode;
}

/**
 * @brief reasm_ctx_t 해제 소멸자
 *
 * @param c 없애버릴 컨텍스트
 * @return 없음
 */
static void reasm_destroy(reasm_ctx_t *c) {
    if (!c) {
        return;
    }
    // 모든 해시 버킷 순회
    for (uint32_t i = 0; i < c->nbuckets; i++) {
        reasm_session_t *p = c->buckets[i];
        while (p)  // 연결리스트 해제
        {
            reasm_session_t *n = p->next;
            reasm_session_free(p);
            p = n;
        }
    }
    free(c->buckets);  // 해시테이블 없애고
    free(c);           // 컨텍스트 없애기
}

/**
 * @brief 올드 세션 제거 함수
 * 세션을 해시테이블에서 제거하는 함수
 * @param c 해시테이블 봐야해서, 컨텍스트 전달
 * @param now_ms 지금 시간
 */
static void reasm_gc(reasm_ctx_t *c, uint64_t now_ms) {
    if (!c) {
        return;
    }
    // 버킷 순회
    for (uint32_t i = 0; i < c->nbuckets; i++) {
        reasm_session_t **pp = &c->buckets[i];  // 연결리스트 순회
        while (*pp)  // **pp로 인해 삭제 후 노드가 다음을 가르킨다.
        {
            reasm_session_t *s = *pp;
            if (now_ms - s->last_seen_ms >
                REASM_SESSION_TIMEOUT_MS)  // 타임아웃 점검
            {                              // 만료 세션 삭제
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
 * @brief flow_key에 해당하는 재조립 세션 찾기
 *
 * @param c 컨텍스트
 * @param k 키
 * @param ts_ms 지금 시간
 * @return reasm_session_t*, NULL
 */
static reasm_session_t *reasm_lookup(reasm_ctx_t *c, const flow_key_t *k,
                                     uint64_t ts_ms) {
    uint32_t idx = reasm_flow_hash(k) % c->nbuckets;  // k 해시 -> 버킷 찾기
    for (reasm_session_t *p = c->buckets[idx]; p;
         p = p->next) {  // 해시 충돌로 여러 세션이 있을 수 있으니 끝까지 검사
        if (reasm_flow_eq(&p->key, k)) {  // 같은지?
            p->last_seen_ms = ts_ms;      // 시간 갱신
            return p;                     // 반환
        }
    }
    return NULL;  // 없으면 널
}

/**
 * @brief 컨텍스트 찾거나 만드는 함수
 *  세션을 찾고 없으면 만듬
 * @param c 컨텍스트
 * @param k 키
 * @param ts_ms 시간
 * @return reasm_session_t*
 */
static reasm_session_t *reasm_get_or_create(
    reasm_ctx_t *c, const flow_key_t *k,
    uint64_t ts_ms) {  // 이미 있는 흐름이면 반환함
    reasm_session_t *s = reasm_lookup(c, k, ts_ms);
    if (s) {
        return s;
    }
    // 세션 너무 많으면 안만듬
    if (c->nsessions >= REASM_MAX_SESSIONS) {
        return NULL;
    }

    // 해시로 새로운 세션을 어느 버킷에 넣을지 결정
    uint32_t idx = reasm_flow_hash(k) % c->nbuckets;
    s            = (reasm_session_t *)calloc(1, sizeof(*s));  // 메모리 할당
    if (!s) {
        return NULL;
    }
    // 필드채우기
    s->key          = *k;
    s->last_seen_ms = ts_ms;
    s->next         = c->buckets[idx];
    c->buckets[idx] = s;
    c->nsessions++;
    return s;
}

/**
 * @brief 페이로드 트리밍 함수
 * 이미받은 데이터는 버리고 아직 안 받은 부분만 남기도록 seq, 페이로드, len 직접
 * 수정함 테스트 코드 필요함
 * @param d 방향
 * @param seq 다음에 받아야할 번호,
 * @param payload  현재 들어온 페이로드 시작 주소
 * @param len 길이
 */
static void reasm_trim_to_next(
    reasm_dir_t *d, uint32_t *seq, const uint8_t **payload,
    uint32_t *len) {  // 기존 정보 없으면 아무것도 안함
    if (*len == 0 || !d->has_next) {
        return;
    }
    // 현재 데이터는 어디쯤?
    uint32_t start = *seq;
    uint32_t end   = start + *len;
    // 이미 처리된거면 다 버리고
    if (SEQ_LEQ(end, d->next_seq)) {
        *len = 0;
        return;
    }
    // 앞부부남ㄴ 처리된 경우 그 부분만 잘라냄
    if (SEQ_LT(start, d->next_seq)) {
        uint32_t delta = (uint32_t)(d->next_seq - start);
        *seq           = d->next_seq;
        *payload += delta;
        *len -= delta;
    }
}

/**
 * @brief out-of order tcp조각 재조립 대기열에 넣는 함수
 *
 * @param d 방향의 재조립 상태
 * @param seq 연결 리스트
 * @param payload 대기 바이트 수
 * @param len 세그먼트 수
 * @return int 0:정상, -1: 개수 제한 초과, -2: 바이트큐 제한초과, -3: 메모리
 * 할당 실패
 */
static int reasm_insert_segment(reasm_dir_t *d, uint32_t seq,
                                const uint8_t *payload, uint32_t len) {
    reasm_seg_node_t **pp;
    reasm_seg_node_t  *prev      = NULL;
    uint32_t           new_start = seq;
    uint32_t           new_end   = seq + len;  // 세그먼트 범위
    // 입력 제한 점검
    if (len == 0)  // 할일없음
    {
        return 0;
    }
    if (d->seg_count >= REASM_MAX_SEGMENTS_PER_DIR)  // 세그먼트 수 제한 넘음
    {
        return -1;
    }
    if (d->bytes_queued + len >
        REASM_MAX_BYTES_PER_DIR)  // 누적 바이트 제한 넘음
    {
        return -2;
    }
    // 어디에 넣을까? 삽입 위치
    pp = &d->head;
    while (*pp && SEQ_LT((*pp)->seq, seq)) {
        pp = &(*pp)->next;
    }
    // 이전 노드는 어디인가?
    if (pp != &d->head) {
        reasm_seg_node_t *p = d->head;
        while (p && p->next != *pp) {
            p = p->next;
        }
        prev = p;
    }
    // 이전 세그먼트와 겹침 처리
    if (prev) {
        uint32_t prev_end = prev->seq + prev->len;
        if (SEQ_GEQ(prev_end, new_start)) {
            if (SEQ_GEQ(prev_end, new_end)) {
                return 0;
            }
            uint32_t delta = (uint32_t)(prev_end - new_start);
            new_start      = prev_end;
            payload += delta;
            len -= delta;
            new_end = new_start + len;
        }
    }
    // 뒤쪽 세그먼트들과 겹침 처리
    while (*pp) {
        reasm_seg_node_t *cur       = *pp;
        uint32_t          cur_start = cur->seq;
        uint32_t          cur_end   = cur->seq + cur->len;
        // 안겹치면 종료
        if (SEQ_LEQ(new_end, cur_start)) {
            break;
        }
        /*--------------------------------------------------------
        // 뒤는 잘라야 하는 경우
        if (SEQ_LT(new_start, cur_start))
        {
            uint32_t keep = (uint32_t)(cur_start - new_start);
            len = keep;
            new_end = new_start + len;
            break;
        }
        --------------------------------------------------------*/
        // 뒤는 잘라야 하는 경우
        if (SEQ_LT(new_start, cur_start)) {
            // 1. 새 조각이 기존 조각 을 완전히 덮는 경우
            if (SEQ_GEQ(new_end,
                        cur_end)) {  // 기존 조각은 완전히 포함되어 쓸모가
                                     // 없어졌으므로 리스트에서 제거하기
                *pp = cur->next;
                d->seg_count--;
                d->bytes_queued -= d->bytes_queued - cur->len;
                free(cur->data);
                free(cur);
                continue;
            } else  // 2. 새 조각이 기존 조각의 앞부분만 겹치고 끝나는 경우
            {
                uint32_t keep = (uint32_t)(cur_start - new_start);
                len           = keep;
                new_end       = new_start + len;
                break;  // 뒷 부분은 기존 조각이 갖고있어어서 여기서 자르기
            }
        }
        // 새 조각이 현재 노드 안에 들어간 경우
        if (SEQ_LT(new_start, cur_end)) {
            if (SEQ_GEQ(cur_end, new_end)) {
                return 0;
            }
            uint32_t delta = (uint32_t)(cur_end - new_start);
            new_start      = cur_end;
            payload += delta;
            len -= delta;
            new_end = new_start + len;
            pp      = &cur->next;
            continue;
        }
        pp = &(*pp)->next;
    }
    // 남은 데이터가 없음
    if (len == 0) {
        return 0;
    }
    if (d->seg_count >= REASM_MAX_SEGMENTS_PER_DIR) {
        return -1;
    }
    if (d->bytes_queued + len > REASM_MAX_BYTES_PER_DIR) {
        return -2;
    }
    // 새로운 노드 생성
    reasm_seg_node_t *n = (reasm_seg_node_t *)calloc(1, sizeof(*n));
    if (!n) {
        return -3;
    }

    n->data = (uint8_t *)malloc(len);
    if (!n->data) {
        free(n);
        return -3;
    }
    memcpy(n->data, payload, len);
    n->seq = new_start;
    n->len = len;
    // 정렬된 위치에 삽입
    pp = &d->head;
    while (*pp && SEQ_LT((*pp)->seq, n->seq)) {
        pp = &(*pp)->next;
    }
    n->next = *pp;
    *pp     = n;
    // 통계 갱신
    d->seg_count++;
    d->bytes_queued += len;
    // 바로 뒤 연속되면? 병합가능함
    while (n->next) {
        // 정확히 위치가 이어지면 merge
        reasm_seg_node_t *nx    = n->next;
        uint32_t          n_end = n->seq + n->len;
        if (n_end != nx->seq) {
            break;
        }
        // 데이터 버퍼를 늘리고 뒤 세그먼트를 붙임
        uint32_t merged_len = n->len + nx->len;
        uint8_t *buf        = (uint8_t *)realloc(n->data, merged_len);
        if (!buf) {
            break;
        }
        n->data = buf;
        memcpy(n->data + n->len, nx->data, nx->len);
        n->len = merged_len;
        // 병합된 다음 노드 제거
        n->next = nx->next;
        d->seg_count--;
        reasm_seg_free(nx);
    }

    return 0;
}

/**
 * @brief HTTP 맞는지? 판별 함수
 * 들어온 payload 시작 부분이 HTTP 메시지 시작처럼 보이는지
 * @param payload 검사할 데이터 주소
 * @param len 검사할 데이터 길이
 * @return int 1: http시작인듯, 0: 아닌듯
 */
static int reasm_looks_like_http_start(
    const uint8_t *payload,
    uint32_t       len) {  // 페이로드 맨앞에 HTTP 처럼 보이는 문자열이 있는지
    static const char *const methods[] = {"GET ",   "POST ",   "PUT ",
                                          "HEAD ",  "DELETE ", "OPTIONS ",
                                          "PATCH ", "TRACE ",  "CONNECT "};
    size_t                   i;
    // 데이터가 없으면 HTTP 시작 아님
    if (!payload || len == 0) {
        return 0;
    }
    // 배열에 있는 문자열 검사함
    for (i = 0; i < sizeof(methods) / sizeof(methods[0]);
         i++) {  // 길이, prefix 비교함
        size_t n = strlen(methods[i]);
        if (len >= n && memcmp(payload, methods[i], n) == 0) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief 순서 맞추는 함수
 * 재조립 대기열에 쌓여 있던 out-of-order 세그먼트 중에서,
 * 이제 순서가 맞는 것들을 앞에서부터 꺼내 전달하는 함수
 * @param c 재조립 컨텍스트
 * @param s 현재 세션
 * @param dir 방향
 */
static void reasm_flush(reasm_ctx_t *c, reasm_session_t *s,
                        tcp_dir_t dir) {  // 어느 방향인지
    reasm_dir_t *d = &s->dir[dir];
    // next seq 정해져있는지? 없으면 탈출
    if (!d->has_next) {
        return;
    }
    // 헤드 노드가 정확히 next_seq인가? 그러면 순서가 맞음
    while (d->head && d->head->seq == d->next_seq) {  // 헤드 꺼내고
        reasm_seg_node_t *h = d->head;
        if (c->on_data)  // 콜백 전달
        {
            c->on_data(&s->key, dir, h->data, h->len, h->seq, c->user);
        }
        // 다음에 와야할 시퀀스 갱신하기
        d->next_seq += h->len;
        // 큐 상태 갱신, 대기바이트 감소, 세그먼트 수 감소, 리스트 헤드
        // 다음노드로
        d->bytes_queued -= h->len;
        d->seg_count--;
        d->head = h->next;
        reasm_seg_free(h);
    }
}

/**
 * @brief  TCP 패킷 1개를 재조립 엔진에 넣는 메인 진입점
 *
 * @param c 재조립 컨텍스트, 세션테이블 모드 콜백을 가진다.
 * @param flow tcp 플로우 키
 * @param dir 방향
 * @param seq TCP 시작 시퀀스 번호
 * @param tcp_flags TCP 플래그
 * @param payload 시작 주소
 * @param len 길이
 * @param ts_ms 현재 패킷의 도착 시간
 * @return int 0: 정상, -1: 잘못, -2: 세션 생성못함
 */
static int reasm_ingest(reasm_ctx_t *c, const flow_key_t *flow, tcp_dir_t dir,
                        uint32_t seq, uint8_t tcp_flags, const uint8_t *payload,
                        uint32_t len, uint64_t ts_ms) {
    // 입력 검증
    if (!c || !flow) {
        return -1;
    }
    if (dir != DIR_AB && dir != DIR_BA) {
        return -1;
    }
    // 기존 세션 조회
    reasm_session_t *s = reasm_lookup(c, flow, ts_ms);
    if (tcp_flags & TCP_RST)  // RST이면 세션 제거함
    {
        if (!s) {
            return 0;  // 세션이 없네
        }
        uint32_t          idx = reasm_flow_hash(flow) % c->nbuckets;
        reasm_session_t **pp  = &c->buckets[idx];
        while (*pp) {
            if (*pp == s) {  // 세션이 있으면 해시 버킷에서 링크 풀고 프리
                *pp = s->next;
                c->nsessions--;
                reasm_session_free(s);
                break;
            }
            pp = &(*pp)->next;
        }
        return 0;
    }
    // 세션이 없으면 생성 여부 판단
    if (!s) {
        if (len == 0 &&
            c->mode == REASM_MODE_LATE_START)  // 페이로드없으면 세션안만듬
        {
            return 0;
        }
        if (c->mode == REASM_MODE_STRICT_SYN &&
            !(tcp_flags & TCP_SYN))  // SYN 없는 첫패킷이면 세션안만듬
        {
            return 0;
        }
        // 조건 통과하면 세션 생성함
        s = reasm_get_or_create(c, flow, ts_ms);
        if (!s) {
            return -2;
        }
    }
    // 방향과 FIN 기록 함, 현재 방향 재조립상태 가져오기
    reasm_dir_t *d = &s->dir[dir];
    if (tcp_flags & TCP_FIN) {
        d->fin_seen = 1;
    }
    // next_seq가 없으면 시작점 설정
    if (!d->has_next) {  // SYN은 시퀀스 번호 1소비하니까, 다음은 seq+1기대함
        if (c->mode == REASM_MODE_STRICT_SYN) {
            d->has_next = 1;
            d->next_seq = seq + 1;
        } else {  // 페이로드없으면 시작못함
            if (len == 0) {
                return 0;
            }
            // http 시작 맞으면 여기서부터 재조립시작
            if (!reasm_looks_like_http_start(payload, len)) {
                return reasm_insert_segment(d, seq, payload, len);
            }
            d->has_next = 1;
            d->next_seq = seq;
        }
    }
    // 이미 받은 앞부분 trimming
    uint32_t       adj_seq = seq;
    const uint8_t *adj_pl  = payload;
    uint32_t       adj_len = len;

    reasm_trim_to_next(d, &adj_seq, &adj_pl, &adj_len);
    if (adj_len == 0) {
        return 0;
    }
    // 세그먼트 삽입
    int rc = reasm_insert_segment(d, adj_seq, adj_pl, adj_len);
    // 실패하면 세션 제거
    if (rc != 0) {
        uint32_t          idx = reasm_flow_hash(flow) % c->nbuckets;
        reasm_session_t **pp  = &c->buckets[idx];
        while (*pp) {
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
    // 이어질 수 있는 데이터 flush, 연속된 세그먼트있으면 콜백으로 넘기고 큐에서
    // 제거 여기서 실제 상위 계층(HTTP 파서 등)으로 데이터가 전달
    reasm_flush(c, s, dir);

    if (s->dir[0].fin_seen && s->dir[1].fin_seen && s->dir[0].head == NULL &&
        s->dir[1].head == NULL) {
        uint32_t          idx = reasm_flow_hash(flow) % c->nbuckets;
        reasm_session_t **pp  = &c->buckets[idx];
        while (*pp) {  // 해시테이블 언링크, 프리
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

struct httgw {
    reasm_ctx_t      *reasm;
    http_stream_cfg_t stream_cfg;
    httgw_callbacks_t cbs;

    void         *user;
    httgw_stats_t stats;
    int           verbose;

    /* 송신 경로 핸들 + RST 송신함수*/
    void             *tx_ctx;
    httgw_send_rst_fn tx_send_rst;

    httgw_session_t **sess_buckets;
    uint32_t          sess_bucket_count;
    uint32_t          sess_count;
};

struct ip_hash {
    ip_node_t **buckets;
    size_t      nbuckets;
};

#if defined(__GNUC__)
#define HTTGW_UNUSED __attribute__((unused))
#endif

struct httgw_session {
    flow_key_t     flow;
    http_stream_t *streams[2];

    uint32_t base_seq_ab;
    uint32_t base_seq_ba;
    uint32_t last_seq_ab;
    uint32_t next_seq_ab;
    uint32_t last_ack_ab;
    uint32_t last_seq_ba;
    uint32_t next_seq_ba;
    uint32_t last_ack_ba;
    uint16_t win_ab;
    uint16_t win_ba;
    uint8_t  win_scale_ab;
    uint8_t  win_scale_ba;

    uint8_t seen_ab;
    uint8_t seen_ba;  // 해당 방향 패킷을 봤는지?

    uint64_t last_ts_ms;  // 세션 타임아웃/GC용

    uint8_t fin_seen_ab;
    uint8_t fin_seen_ba;  // 종료 상태 추적
    uint8_t rst_sent_ab;
    uint8_t rst_sent_ba;

    struct httgw_session *next;
};

/* --------------------------- session table --------------------------- */
#define HTTGW_SESS_BUCKETS 4096
#define HTTGW_SESS_TIMEOUT_MS (60ULL * 1000ULL)
#define HTTGW_RST_BURST_COUNT 5U

static void sess_destroy(httgw_session_t *s) {
    if (!s) {
        return;
    }
    if (s->streams[DIR_AB]) {
        http_stream_destroy(s->streams[DIR_AB]);
    }
    if (s->streams[DIR_BA]) {
        http_stream_destroy(s->streams[DIR_BA]);
    }
    free(s);
}

static uint32_t sess_flow_hash(const flow_key_t *k) {
    const uint32_t prime = 16777619u;
    uint32_t       h     = 2166136261u;
    uint32_t       ports;

    ports = ((uint32_t)k->src_port << 16) | k->dst_port;

    h ^= (uint32_t)k->src_ip;
    h *= prime;

    h ^= (uint32_t)k->dst_ip;
    h *= prime;

    h ^= ports;
    h *= prime;

    h ^= (uint32_t)k->proto;
    h *= prime;

    return h;
}

static int sess_flow_eq(const flow_key_t *a, const flow_key_t *b) {
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

/* --------------------------- ip hash table (unused for now)
 * --------------------------- */
static uint32_t HTTGW_UNUSED ip_hash_fn(uint32_t ip) {
    ip ^= ip >> 16;
    ip *= 0x7feb352d;
    ip ^= ip >> 15;
    ip *= 0x846ca68b;
    ip ^= ip >> 16;
    return ip;
}

static httgw_session_t *sess_find(const httgw_t *gw, const flow_key_t *flow) {
    uint32_t idx = sess_flow_hash(flow) % gw->sess_bucket_count;
    for (httgw_session_t *s = gw->sess_buckets[idx]; s; s = s->next) {
        if (sess_flow_eq(&s->flow, flow)) {
            return s;
        }
    }
    return NULL;
}

static httgw_session_t *sess_remove_internal(httgw_t          *gw,
                                             const flow_key_t *flow) {
    uint32_t          idx;
    httgw_session_t **pp;

    if (!gw || !flow) {
        return NULL;
    }

    idx = sess_flow_hash(flow) % gw->sess_bucket_count;
    pp  = &gw->sess_buckets[idx];
    while (*pp) {
        if (sess_flow_eq(&(*pp)->flow, flow)) {
            httgw_session_t *s = *pp;
            *pp                = s->next;
            if (gw->sess_count > 0) {
                gw->sess_count--;
            }
            s->next = NULL;
            return s;
        }
        pp = &(*pp)->next;
    }
    return NULL;
}

static httgw_session_t *sess_get_or_create_internal(httgw_t          *gw,
                                                    const flow_key_t *flow,
                                                    uint64_t          ts_ms) {
    uint32_t idx = sess_flow_hash(flow) % gw->sess_bucket_count;
    for (httgw_session_t *s = gw->sess_buckets[idx]; s; s = s->next) {
        if (sess_flow_eq(&s->flow, flow)) {
            s->last_ts_ms = ts_ms;
            return s;
        }
    }

    httgw_session_t *s = (httgw_session_t *)calloc(1, sizeof(*s));
    if (!s) {
        return NULL;
    }

    s->streams[DIR_AB] = http_stream_create(&gw->stream_cfg);
    s->streams[DIR_BA] = http_stream_create(&gw->stream_cfg);
    if (!s->streams[DIR_AB] || !s->streams[DIR_BA]) {
        sess_destroy(s);
        return NULL;
    }

    s->flow               = *flow;
    s->last_ts_ms         = ts_ms;
    s->next               = gw->sess_buckets[idx];
    gw->sess_buckets[idx] = s;
    gw->sess_count++;
    return s;
}

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

static void normalize_flow(uint32_t sip, uint16_t sport, uint32_t dip,
                           uint16_t dport, flow_key_t *key, tcp_dir_t *dir) {
    int c = endpoint_cmp(sip, sport, dip, dport);
    memset(key, 0, sizeof(*key));
    key->proto = 6;
    if (c <= 0) {
        key->src_ip   = sip;
        key->src_port = sport;
        key->dst_ip   = dip;
        key->dst_port = dport;
        *dir          = DIR_AB;
    } else {
        key->src_ip   = dip;
        key->src_port = dport;
        key->dst_ip   = sip;
        key->dst_port = sport;
        *dir          = DIR_BA;
    }
}

static int parse_ipv4_tcp_payload(const uint8_t *pkt, uint32_t caplen,
                                  flow_key_t *flow, tcp_dir_t *dir,
                                  uint32_t *seq, uint32_t *ack, uint8_t *flags,
                                  const uint8_t **payload,
                                  uint32_t *payload_len, uint16_t *window,
                                  uint8_t *win_scale) {
    const uint8_t *p = pkt;
    uint32_t       n = caplen;
    uint16_t       eth_type;
    uint32_t       ip_hl;
    uint32_t       ip_len;
    uint32_t       tcp_hl;
    uint16_t       total_len;
    uint8_t        proto;
    uint32_t       sip;
    uint32_t       dip;
    uint16_t       sport;
    uint16_t       dport;

    if (n < 14) {
        return 0;
    }
    eth_type = (uint16_t)((p[12] << 8) | p[13]);
    p += 14;
    n -= 14;

    if (eth_type == 0x8100 || eth_type == 0x88A8) {
        if (n < 4) {
            return 0;
        }
        eth_type = (uint16_t)((p[2] << 8) | p[3]);
        p += 4;
        n -= 4;
    }

    if (eth_type != 0x0800) {
        return 0;
    }
    if (n < 20) {
        return 0;
    }
    if ((p[0] >> 4) != 4) {
        return 0;
    }

    ip_hl = (uint32_t)(p[0] & 0x0F) * 4U;
    if (ip_hl < 20 || n < ip_hl) {
        return 0;
    }

    total_len = (uint16_t)((p[2] << 8) | p[3]);
    if (total_len < ip_hl || n < total_len) {
        return 0;
    }

    proto = p[9];
    if (proto != 6) {
        return 0;
    }

    sip = (uint32_t)((p[12] << 24) | (p[13] << 16) | (p[14] << 8) | p[15]);
    dip = (uint32_t)((p[16] << 24) | (p[17] << 16) | (p[18] << 8) | p[19]);

    p += ip_hl;
    n = total_len - ip_hl;
    if (n < 20) {
        return 0;
    }

    sport  = (uint16_t)((p[0] << 8) | p[1]);
    dport  = (uint16_t)((p[2] << 8) | p[3]);
    *seq   = (uint32_t)((p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7]);
    *ack   = (uint32_t)((p[8] << 24) | (p[9] << 16) | (p[10] << 8) | p[11]);
    tcp_hl = (uint32_t)((p[12] >> 4) & 0x0F) * 4U;
    if (tcp_hl < 20 || n < tcp_hl) {
        return 0;
    }
    *flags = p[13];
    if (window) {
        *window = (uint16_t)((p[14] << 8) | p[15]);
    }
    if (win_scale) {
        *win_scale = 0;
    }

    ip_len = total_len;
    if (ip_len < ip_hl + tcp_hl) {
        return 0;
    }

    *payload_len = ip_len - ip_hl - tcp_hl;
    *payload     = p + tcp_hl;

    if (win_scale && (p[13] & TCP_SYN) && tcp_hl > 20) {
        uint32_t       opt_len = tcp_hl - 20;
        const uint8_t *opt     = p + 20;
        uint32_t       i       = 0;
        while (i < opt_len) {
            uint8_t kind = opt[i];
            if (kind == 0) {
                break;
            }
            if (kind == 1) {
                i++;
                continue;
            }
            if (i + 1 >= opt_len) {
                break;
            }
            uint8_t len = opt[i + 1];
            if (len < 2 || i + len > opt_len) {
                break;
            }
            if (kind == 3 && len == 3) {
                *win_scale = opt[i + 2];
                break;
            }
            i += len;
        }
    }

    normalize_flow(sip, sport, dip, dport, flow, dir);
    return 1;
}

static uint32_t tcp_next_seq(uint32_t seq, uint32_t payload_len,
                             uint8_t flags) {
    uint32_t next = seq + payload_len;

    if (flags & TCP_SYN) {
        next++;
    }
    if (flags & TCP_FIN) {
        next++;
    }
    return next;
}

/**
 * @brief HTTP 메시지 파싱 및 콜백 호출함수
 *
 * on_stream_data에서 flow/dir 전달받도록 수정하여 해당 방향 스트림에서 메시지
 * 파싱하도록 변경
 * @param gw http 게이트웨이 컨텍스트
 * @param flow HTTP 메시지가 속한 플로우 정보
 * @param dir HTTP 메시지가 속한 방향 (DIR_AB 또는 DIR_BA)
 */
static void drain_http(httgw_t *gw, const flow_key_t *flow, tcp_dir_t dir) {
    httgw_session_t *sess = sess_find(gw, flow);
    http_stream_t   *s;
    http_message_t   msg;

    if (!sess) {
        return;
    }
    s = sess->streams[dir];
    if (!s) {
        return;
    }

    while (http_stream_poll_message(s, &msg) == HTTP_STREAM_OK) {
        gw->stats.http_msgs++;
        if (msg.is_request) {
            gw->stats.reqs++;
            if (gw->cbs.on_request) {
                const char *q     = NULL;
                size_t      q_len = 0;
                (void)httgw_extract_query(&msg, &q, &q_len);
                gw->cbs.on_request(flow, dir, &msg, q, q_len, gw->user);
            }
        }
        http_message_free(&msg);
    }
}

/**
 * @brief 재조립된 TCP payload를 HTTP 스트림에 밀어 넣고, 완성된 메시지를 상위로
 * 전달한다.
 *
 * 재조립 계층에서 순서가 맞는 데이터 조각이 준비되면 호출된다.
 * 지정한 flow와 방향(dir)에 해당하는 HTTP 스트림을 찾아 데이터를 공급하고,
 * 파싱이 성공하면 누적된 HTTP 메시지를 꺼내 `drain_http()`로 상위 콜백에
 * 넘긴다.
 *
 * @param flow 현재 데이터가 속한 TCP flow key
 * @param dir 데이터가 들어온 방향 (DIR_AB 또는 DIR_BA)
 * @param data 재조립된 TCP payload 시작 주소
 * @param len payload 길이
 * @param seq_start 재조립된 payload의 시작 TCP sequence 번호
 * @param user httgw_create()에서 등록된 사용자 컨텍스트. 내부적으로 httgw_t*로
 * 사용된다.
 */
static void on_stream_data(const flow_key_t *flow, tcp_dir_t dir,
                           const uint8_t *data, uint32_t len,
                           uint32_t seq_start, void *user) {
    httgw_t         *gw = (httgw_t *)user;
    httgw_session_t *sess;
    http_stream_t   *stream;
    http_stream_rc_t rc;

    /*
     * reasm callback 계약상 seq_start를 전달받지만,
     * 현재 HTTP 스트림 공급 경로에서는 시작 sequence 번호를 직접 참조하지 않는다.
     * 인터페이스는 유지하되, 현재 구현에서 의도적으로 미사용임을 명시한다.
     */
    (void)seq_start;

    /*
     * user는 httgw_create()에서 넘긴 gw 컨텍스트여야 한다.
     * 여기서 NULL이면 이후 sess_find(), stats 갱신, on_error 호출 모두 불가능하므로
     * 더 진행하지 않고 즉시 중단한다.
     */
    if (NULL == gw) {
        return;
    }

    /*
     * flow는 어떤 TCP 세션의 재조립 결과인지 식별하는 키다.
     * flow가 없으면 세션 lookup 자체가 성립하지 않으므로 상위에 오류를 알리고 반환한다.
     */
    if (NULL == flow) {
        if (NULL != gw->cbs.on_error) {
            gw->cbs.on_error("on_stream_data", "missing flow", gw->user);
        }
        return;
    }

    /*
     * dir은 반드시 DIR_AB 또는 DIR_BA여야 한다.
     * 범위를 벗어난 값은 sess->streams[dir] 접근 시 잘못된 인덱스로 이어질 수 있으므로
     * 방어적으로 차단한다.
     */
    if (dir != DIR_AB && dir != DIR_BA) {
        if (NULL != gw->cbs.on_error) {
            gw->cbs.on_error("on_stream_data", "invalid direction", gw->user);
        }
        return;
    }

    /*
     * data는 reasm 계층이 넘긴 연속된 TCP payload 시작 주소다.
     * len > 0 인데 data가 NULL이면 파서에 넘길 수 없으므로 오류로 본다.
     */
    if (NULL == data) {
        if (NULL != gw->cbs.on_error) {
            gw->cbs.on_error("on_stream_data", "missing stream data",
                             gw->user);
        }
        return;
    }

    /*
     * 길이가 0인 payload는 현재 HTTP 스트림 파서에 공급할 실데이터가 없다는 뜻이다.
     * 오류로 보지는 않고, 조용히 무시한다.
     */
    if (0 == len) {
        return;
    }

    /*
     * 재조립 결과가 들어온 flow에 대응하는 live session을 찾는다.
     * 세션이 없다는 것은 reasm 계층과 session table의 lifecycle이 어긋났거나
     * 이미 세션이 정리된 뒤 callback이 들어왔다는 뜻일 수 있으므로 오류로 남긴다.
     */
    sess = sess_find(gw, flow);
    if (NULL == sess) {
        if (NULL != gw->cbs.on_error) {
            gw->cbs.on_error("on_stream_data", "missing httgw session",
                             gw->user);
        }
        return;
    }

    /*
     * 한 세션은 방향별로 HTTP 스트림 파서를 하나씩 가진다.
     * 현재 payload가 속한 방향의 스트림 핸들을 가져와 그쪽에만 데이터를 공급한다.
     */
    stream = sess->streams[dir];
    if (NULL == stream) {
        if (NULL != gw->cbs.on_error) {
            gw->cbs.on_error("on_stream_data", "missing http stream", gw->user);
        }
        return;
    }

    /*
     * 재조립 계층이 순서를 맞춰 넘긴 payload를 HTTP 스트림 파서에 공급한다.
     * 여기서 헤더/바디 누적, 메시지 경계 판정, 파서 상태 전이가 진행된다.
     */
    rc = http_stream_feed(stream, data, len);
    if (rc != HTTP_STREAM_OK) {
        gw->stats.parse_errs++;

        /*
         * 파서가 프로토콜 오류나 버퍼 상태 이상을 보고한 경우다.
         * 오류 내용을 상위에 전달한 뒤, 현재 방향 스트림 상태를 reset 해서
         * 이후 데이터가 새 메시지처럼 다시 파싱될 수 있게 한다.
         */
        if (NULL != gw->cbs.on_error) {
            gw->cbs.on_error("http_stream_feed", http_stream_last_error(stream),
                             gw->user);
        }
        http_stream_reset(stream);
        return;
    }

    /*
     * feed 결과로 완성된 HTTP 메시지가 내부 큐에 쌓였을 수 있으므로,
     * drain_http()를 호출해 요청/응답 메시지를 상위 콜백으로 배출한다.
     */
    drain_http(gw, flow, dir);  // MODIFY
}

/**
 * @brief HTTP 게이트웨이 인스턴스를 생성하고 내부 상태를 초기화한다.
 *
 * 재조립 엔진, HTTP 스트림 설정, 세션 해시 테이블, 콜백 정보를 묶은
 * httgw_t 객체를 생성한다. 생성이 성공하면 패킷을 `httgw_ingest_packet()`
 * 으로 투입할 수 있는 초기 상태가 된다.
 *
 * @param cfg 게이트웨이 설정값. NULL이면 기본값을 사용한다.
 * @param cbs 요청/오류 처리 콜백 묶음. NULL이면 모든 콜백을 비활성화한다.
 * @param user 콜백 호출 시 함께 전달할 사용자 컨텍스트 포인터
 * @return httgw_t* 생성된 게이트웨이 인스턴스 포인터, 실패 시 NULL
 */
httgw_t *httgw_create(const httgw_cfg_t *cfg, const httgw_callbacks_t *cbs,
                      void *user) {
    httgw_t *gw = NULL;

    /* 게이트웨이 본체를 zero-init 상태로 생성한다. */
    gw = (httgw_t *)calloc(1, sizeof(*gw));
    if (!gw) {
        return NULL;
    }

    /* 콜백과 사용자 컨텍스트를 먼저 고정한다. */
    gw->user = user;
    if (cbs) {
        gw->cbs = *cbs;
    } else {
        memset(&gw->cbs, 0, sizeof(gw->cbs));
    }

    /* verbose는 명시적으로 켜진 경우에만 활성화한다. */
    gw->verbose = 0;
    if (cfg && cfg->verbose) {
        gw->verbose = 1;
    }

    /*
     * HTTP 스트림 메모리 상한을 설정한다.
     * 설정값이 없으면 buffer/body 모두 기본 12MB를 사용한다.
     */
    memset(&gw->stream_cfg, 0, sizeof(gw->stream_cfg));
    gw->stream_cfg.max_buffer_bytes = 12U * 1024U * 1024U;
    if (cfg && cfg->max_buffer_bytes) {
        gw->stream_cfg.max_buffer_bytes = cfg->max_buffer_bytes;
    }

    gw->stream_cfg.max_body_bytes = 12U * 1024U * 1024U;
    if (cfg && cfg->max_body_bytes) {
        gw->stream_cfg.max_body_bytes = cfg->max_body_bytes;
    }

    /* TCP 재조립 엔진을 만들고, 재조립 완료 데이터는 on_stream_data()로 넘긴다.
     */
    gw->reasm = reasm_create(8192, on_stream_data, gw);
    if (!gw->reasm) {
        httgw_destroy(gw);
        return NULL;
    }

    /* flow 기반 세션 조회를 위한 해시 버킷 배열을 준비한다. */
    gw->sess_bucket_count = HTTGW_SESS_BUCKETS;
    gw->sess_buckets      = (httgw_session_t **)calloc(gw->sess_bucket_count,
                                                       sizeof(*gw->sess_buckets));
    if (!gw->sess_buckets) {
        httgw_destroy(gw);
        return NULL;
    }

    /* 재조립 시작 정책은 설정값을 우선하고, 없으면 late-start를 기본으로 쓴다.
     */
    if (cfg) {
        reasm_set_mode(gw->reasm, cfg->reasm_mode);
    } else {
        reasm_set_mode(gw->reasm, REASM_MODE_LATE_START);
    }

    return gw;
}

/**
 * @brief 게이트웨이 인스턴스와 내부 자원을 모두 해제한다.
 *
 * 세션 해시 버킷, 각 세션의 HTTP 스트림 상태, TCP 재조립 엔진을 순서대로
 * 정리한 뒤 `httgw_t` 본체를 해제한다.
 *
 * @param gw 해제할 httgw 인스턴스. NULL이면 아무 작업도 하지 않는다.
 */
void httgw_destroy(httgw_t *gw) {
    uint32_t i = 0;

    if (NULL == gw) {
        return;
    }

    /* 세션 버킷 배열과 각 세션 객체를 모두 정리한다. */
    if (NULL != gw->sess_buckets) {
        for (i = 0; i < gw->sess_bucket_count; i++) {
            httgw_session_t *next = NULL;
            httgw_session_t *sess = NULL;

            sess = gw->sess_buckets[i];
            while (NULL != sess) {
                next = sess->next;
                sess_destroy(sess);
                sess = next;
            }

            gw->sess_buckets[i] = NULL;
        }

        free(gw->sess_buckets);
        gw->sess_buckets = NULL;
    }

    /* 남은 세션 수와 재조립 엔진 상태를 정리한다. */
    gw->sess_count = 0;
    if (NULL != gw->reasm) {
        reasm_destroy(gw->reasm);
        gw->reasm = NULL;
    }

    free(gw);
}

/**
 * @brief 패킷을 입력으로 받아 세션 테이블 업데이트 및 TCP 스트림 재조립 수행
 *
 * @param gw httgw 인스턴스
 * @param pkt 입력패킷 이더넷 프레임 시작 주소
 * @param caplen 길이
 * @param ts_ms 타임스탬프 ms 단위
 * @return int 1: 패킷이 정상적으로 처리됨, 0: 패킷이 무시됨, 음수: 오류 발생
 */
int httgw_ingest_packet(httgw_t *gw, const uint8_t *pkt, uint32_t caplen,
                        uint64_t ts_ms) {
    flow_key_t       flow;
    tcp_dir_t        dir;
    uint32_t         seq         = 0;
    uint32_t         ack         = 0;
    uint8_t          flags       = 0;
    const uint8_t   *payload     = NULL;
    uint32_t         payload_len = 0;
    uint32_t         next_seq    = 0;
    uint16_t         window      = 0;
    uint8_t          win_scale   = 0;
    int              rc;
    httgw_session_t *sess;

    /* 기본 인자와 캡처 버퍼 상태가 유효한지 먼저 확인한다. */
    if (NULL == gw || (NULL == pkt && 0 != caplen)) {
        return -1;
    }

    /*
     * Ethernet/IPv4/TCP 패킷에서 flow, 방향, seq/ack, payload를 추출한다.
     * HTTP 처리 대상이 아닌 패킷이면 조용히 무시한다.
     */
    if (0 == parse_ipv4_tcp_payload(pkt, caplen, &flow, &dir, &seq, &ack,
                                    &flags, &payload, &payload_len, &window,
                                    &win_scale)) {
        return 0;
    }

    /* 현재 세그먼트 기준으로 다음에 기대되는 TCP seq를 계산한다. */
    next_seq = tcp_next_seq(seq, payload_len, flags);

    /*
     * RST가 관측되면 세션 테이블에서 해당 flow를 먼저 제거한다.
     * 동시에 재조립 계층에도 RST를 전달해 하위 상태를 정리한다.
     */
    if (0 != (flags & TCP_RST)) {
        sess = sess_remove_internal(gw, &flow);
        if (NULL != sess) {
            sess_destroy(sess);
        }

        rc = reasm_ingest(gw->reasm, &flow, dir, seq, flags, payload,
                          payload_len, ts_ms);
        if (rc != 0) {
            gw->stats.reasm_errs++;
            if (NULL != gw->cbs.on_error) {
                char buf[64];

                snprintf(buf, sizeof(buf), "rc=%d", rc);
                gw->cbs.on_error("reasm_ingest", buf, gw->user);
            }
            return -2;
        }
        return 1;
    }

    /* 일반 패킷이면 세션을 찾거나 새로 생성한다. */
    sess = sess_get_or_create_internal(gw, &flow, ts_ms);
    if (NULL == sess) {
        return -3;
    }

    /*
     * 방향별로 마지막 seq/ack/window, 처음 본 base seq,
     * SYN/FIN 관측 여부를 세션에 기록한다.
     */
    if (DIR_AB == dir) {
        if (0 == sess->seen_ab) {
            sess->base_seq_ab = seq;
        }

        sess->last_seq_ab = seq;
        sess->next_seq_ab = next_seq;

        if (0 == sess->seen_ab || SEQ_GEQ(ack, sess->last_ack_ab)) {
            sess->last_ack_ab = ack;
            sess->win_ab      = window;
        }

        if (0 != (flags & TCP_SYN)) {
            sess->win_scale_ab = win_scale;
        }

        sess->seen_ab = 1;
        if (0 != (flags & TCP_FIN)) {
            sess->fin_seen_ab = 1;
        }
    } else {
        if (0 == sess->seen_ba) {
            sess->base_seq_ba = seq;
        }

        sess->last_seq_ba = seq;
        sess->next_seq_ba = next_seq;

        if (0 == sess->seen_ba || SEQ_GEQ(ack, sess->last_ack_ba)) {
            sess->last_ack_ba = ack;
            sess->win_ba      = window;
        }

        if (0 != (flags & TCP_SYN)) {
            sess->win_scale_ba = win_scale;
        }

        sess->seen_ba = 1;
        if (0 != (flags & TCP_FIN)) {
            sess->fin_seen_ba = 1;
        }
    }

    /* 세션의 마지막 관측 시각을 갱신한다. */
    sess->last_ts_ms = ts_ms;

    /* 갱신된 상태를 기준으로 TCP 재조립 엔진에 payload를 투입한다. */
    rc = reasm_ingest(gw->reasm, &flow, dir, seq, flags, payload, payload_len,
                      ts_ms);
    if (rc != 0) {
        httgw_session_t *stale = sess_remove_internal(gw, &flow);

        gw->stats.reasm_errs++;
        if (NULL != stale) {
            sess_destroy(stale);
        }
        if (NULL != gw->cbs.on_error) {
            char buf[64];

            snprintf(buf, sizeof(buf), "rc=%d", rc);
            gw->cbs.on_error("reasm_ingest", buf, gw->user);
        }
        return -2;
    }

    return 1;
}

/**
 * @brief httgw 의 가비지컬렉터
 * 만료된 HTTP/TCP 세션과 재조립 상태를 정리한다.
 * 현재 시각(ms). 세션 timeout 판정 기준으로 사용
 * @param gw 컨텍스트
 * @param now_ms 지금 시간
 */
void httgw_gc(httgw_t *gw, uint64_t now_ms) {
    if (!gw || !gw->reasm) {
        return;
    }

    reasm_gc(gw->reasm, now_ms);
    for (uint32_t i = 0; i < gw->sess_bucket_count; i++) {
        httgw_session_t **pp = &gw->sess_buckets[i];
        while (*pp) {
            /* 현재 노드를 가리키는 포인터의 주소 */
            httgw_session_t *s = *pp;
            if (now_ms - s->last_ts_ms > HTTGW_SESS_TIMEOUT_MS) /* 삭제 조건*/
            {
                *pp = s->next;
                sess_destroy(s);
                if (gw->sess_count > 0) {
                    gw->sess_count--;
                }
                /* 삭제 후 *pp는 이미 다음 노드를 가르키고 있다.*/
                /* 삭제 전 A-> B-> C*/
                /* 삭제 후 A-> C*/
                /* 하지만 *pp는 여전히 A를 가르킨다. */
                continue;
            }
            pp = &(*pp)->next;
        }
    }
}

/**
 * @brief 게이트웨이 누적 통계 구조체를 읽기 전용으로 반환한다.
 *
 * 현재 메인 런타임에서 적극 사용되기보다는 테스트나 상태 확인 용도로
 * 활용되는 getter이다.
 *
 * @param gw httgw 컨텍스트
 * @return const httgw_stats_t* 통계 구조체 포인터, 입력이 NULL이면 NULL
 */
const httgw_stats_t *httgw_stats(const httgw_t *gw) {
    if (!gw) {
        return NULL;
    }
    return &gw->stats;
}

/**
 * @brief httgw 내부 세션 상태 외부에 복사하는 함수
 * RST/차단페이지 주입하기 위해 현재 seq/ack/window를 알아야함
 * 그래서 이를 복사해주는 getter
 * @param gw httgw 컨텍스트
 * @param flow 찾고싶은 tcp 세션 키
 * @param out
 * @return int
 */
int httgw_get_session_snapshot(const httgw_t *gw, const flow_key_t *flow,
                               httgw_sess_snapshot_t *out) {
    if (!gw || !flow || !out) {
        return -1;
    }

    httgw_session_t *sess = sess_find(gw, flow);
    if (!sess) {
        return -2;
    }
    memset(out, 0, sizeof(*out));
    out->base_seq_ab  = sess->base_seq_ab;
    out->base_seq_ba  = sess->base_seq_ba;
    out->last_ack_ab  = sess->last_ack_ab;
    out->next_seq_ab  = sess->next_seq_ab;
    out->last_ack_ba  = sess->last_ack_ba;
    out->next_seq_ba  = sess->next_seq_ba;
    out->win_ab       = sess->win_ab;
    out->win_ba       = sess->win_ba;
    out->win_scale_ab = sess->win_scale_ab;
    out->win_scale_ba = sess->win_scale_ba;
    out->seen_ab      = sess->seen_ab;
    out->seen_ba      = sess->seen_ba;
    return 0;
}
/**
 * @brief 헤더 이름 대소문자 무시 비교함
 * a[0..an-1],
 * @param a 비교할 첫 번째 문자열 시작 주소
 * @param an a의 길이
 * @param b 비교 기준이 되는 두 번째 문자열
 * @return int
 */
static int ci_eq(const uint8_t *a, size_t an, const char *b) {
    size_t i;
    size_t bn = strlen(b);
    if (an != bn) {
        return 0;
    }

    for (i = 0; i < an; i++) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];

        if (tolower(ca) != tolower(cb)) {
            return 0;
        }
    }

    return 1;
}

/**
 * @brief HTTP 메시지의 raw header 블록에서 지정한 헤더 값을 조회한다.
 *
 * 요청/응답 start-line 다음에 이어지는 header 영역을 순회하면서
 * `name`과 일치하는 헤더를 대소문자 구분 없이 찾는다.
 * 값을 찾으면 leading/trailing 공백을 제외한 slice를 `value`와 `value_len`
 * 으로 반환한다.
 *
 * @param msg 조회 대상 HTTP 메시지
 * @param name 찾을 헤더 이름. 예: "Host", "User-Agent"
 * @param value 조회된 헤더 값 시작 주소를 돌려받을 출력 포인터
 * @param value_len 조회된 헤더 값 길이를 돌려받을 출력 포인터
 * @return int 1=헤더 찾음, 0=헤더 없음 또는 입력 오류
 */
int httgw_header_get(const http_message_t *msg, const char *name,
                     const uint8_t **value, size_t *value_len) {
    const uint8_t *p;
    size_t         len;
    size_t         pos = 0;
    size_t         line_end;

    /* 입력 포인터와 출력 버퍼가 유효한지 먼저 확인한다. */
    if (NULL == msg || NULL == name || NULL == value || NULL == value_len) {
        return 0;
    }

    /* raw header 블록이 없으면 조회할 대상이 없다. */
    if (NULL == msg->headers_raw || 0 == msg->headers_raw_len) {
        return 0;
    }

    p   = msg->headers_raw;
    len = msg->headers_raw_len;

    /* start-line을 건너뛰고 첫 번째 header line 시작 위치를 찾는다. */
    while (pos + 1 < len) {
        if (p[pos] == '\r' && p[pos + 1] == '\n') {
            pos += 2;
            break;
        }
        pos++;
    }

    /* header line을 한 줄씩 순회하며 이름이 일치하는 항목을 찾는다. */
    while (pos < len) {
        size_t         i;
        const uint8_t *line     = p + pos;
        size_t         line_len = 0;
        const uint8_t *colon;
        const uint8_t *val;
        const uint8_t *val_end;

        /* 현재 header line의 끝(CRLF)을 찾는다. */
        for (i = pos; i + 1 < len; i++) {
            if (p[i] == '\r' && p[i + 1] == '\n') {
                line_end = i;
                line_len = line_end - pos;
                break;
            }
        }
        if (line_len == 0) {
            break;
        }

        /* "name: value" 형태인지 확인하고 헤더 이름을 비교한다. */
        colon = (const uint8_t *)memchr(line, ':', line_len);
        if (NULL != colon) {
            size_t name_len = (size_t)(colon - line);

            if (ci_eq(line, name_len, name)) {
                /* ':' 뒤 공백을 건너뛰고 값 시작 위치를 맞춘다. */
                val = colon + 1;
                while (val < line + line_len && (*val == ' ' || *val == '\t')) {
                    val++;
                }

                /* 값 끝의 trailing space/tab을 제거한다. */
                val_end = line + line_len;
                while (val_end > val &&
                       ((*(val_end - 1) == ' ') || (*(val_end - 1) == '\t'))) {
                    val_end--;
                }

                /* 값 slice를 그대로 반환한다. 복사본은 만들지 않는다. */
                *value     = val;
                *value_len = (size_t)(val_end - val);
                return 1;
            }
        }

        /* 다음 header line으로 이동한다. */
        pos = line_end + 2;
    }

    return 0;
}

/**
 * @brief slice extractor 함수
 * 상위 콜백에 쿼리 구간만 넘겨주기 위한 헬퍼임
 * @param msg 입력 http메시지
 * @param q 출력용 포인터
 * @param q_len 출력용 길이 값
 * @return int
 */
int httgw_extract_query(const http_message_t *msg, const char **q,
                        size_t *q_len) {
    const char *uri;
    const char *qm;
    const char *hash;
    size_t      len;

    if (NULL == msg || NULL == q || NULL == q_len) {
        return 0;
    }
    if (0 == msg->is_request) {
        return 0;
    }

    uri = msg->uri;
    if (NULL == uri || '\0' == uri[0]) {
        return 0;
    }

    qm = strchr(uri, '?');
    if (NULL == qm || '\0' == *(qm + 1)) {
        return 0;
    }

    hash = strchr(qm + 1, '#');
    if (NULL != hash) {
        len = (size_t)(hash - (qm + 1));
    } else {
        len = strlen(qm + 1);
    }

    if (0 == len) {
        return 0;
    }
    *q     = qm + 1;
    *q_len = len;
    return 1;
}

/* 헬퍼 체크섬*/
static uint16_t checksum16(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;

    uint32_t sum = 0;

    while (len > 1) {
        sum += (uint16_t)((p[0] << 8) | p[1]);
        p   = p + 2;
        len = len - 2;
    }
    if (len) {
        sum += (uint16_t)(p[0] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

static uint16_t tcp_checksum(uint32_t src_be, uint32_t dst_be,
                             const uint8_t *tcp, size_t tcp_len) {
    uint32_t       sum = 0;
    const uint8_t *p;
    size_t         len;

    p = (const uint8_t *)&src_be;
    sum += (uint16_t)((p[0] << 8) | p[1]);
    sum += (uint16_t)((p[2] << 8) | p[3]);

    p = (const uint8_t *)&dst_be;
    sum += (uint16_t)((p[0] << 8) | p[1]);
    sum += (uint16_t)((p[2] << 8) | p[3]);

    sum += IPPROTO_TCP;
    sum += (uint16_t)tcp_len;

    p   = tcp;
    len = tcp_len;
    while (len > 1) {
        sum += (uint16_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }
    if (len) {
        sum += (uint16_t)(p[0] << 8);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

// Layer 3 전송 함수, 레이어 3 = IP 계층, IP 헤더부터 시작하는 패킷을 raw
// socket으로 보내라는 함수이다.
int tx_send_l3(void *ctx, const uint8_t *buf, size_t len) {
    tx_ctx_t          *tx = (tx_ctx_t *)ctx;
    struct sockaddr_in dst;
    const IPHDR       *ip;
    ssize_t            n;  // signed size type, 부호있는 크기타입 음수 가능
    // 유효성 검사 -> 송신 컨텍스트/버퍼/최소 IP 헤더 길이 확인
    if (!tx || tx->fd < 0 || !buf || len < IP_HDR_SIZE) {
        return -1;
    }
    // Raw L3 버퍼의 시작은 IPv4 헤더
    ip = (const IPHDR *)buf;

    // sendto() 목적지 주소 구조체 초기화
    memset(&dst, 0, sizeof(dst));
    dst.sin_family      = AF_INET;
    dst.sin_addr.s_addr = IP_DADDR(ip);

    // Raw 소켓으로 미리 구성된 IP/TCP 패킷을 그대로 전송
    n = sendto(tx->fd, buf, len, 0, (struct sockaddr *)&dst, sizeof(dst));
    // sendto는 소켓으로 데이터를 보내는 시스템 호출
    if (n < 0)  // sendto 실패
    {
        return -1;
    }
    return (size_t)n == len ? 0 : -1;
}

int tx_ctx_init(tx_ctx_t *tx) {
    int fd;
    int on = 1;

    if (!tx) {
        return -1;
    }
    memset(tx, 0, sizeof(*tx));

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) {
        return -1;
    }
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) != 0) {
        close(fd);
        return -1;
    }

    tx->fd      = fd;
    tx->send_l3 = tx_send_l3;
    tx->ctx     = tx;
    return 0;
}

void tx_ctx_destroy(tx_ctx_t *tx) {
    if (!tx) {
        return;
    }
    if (tx->fd >= 0) {
        close(tx->fd);
    }
    tx->fd      = -1;
    tx->send_l3 = NULL;
    tx->ctx     = NULL;
}

int httgw_set_tx(httgw_t *gw, tx_ctx_t *tx) {
    if (!gw) {
        return -1;
    }
    gw->tx_ctx      = tx;
    gw->tx_send_rst = tx_send_rst;
    return 0;
}

/**
 * @brief
 *
 * @param tx_ctx
 * @param flow
 * @param dir
 * @param seq
 * @param ack
 * @param flags
 * @param window
 * @param payload
 * @param payload_len
 * @return int
 */
static int tx_send_tcp_segment(void *tx_ctx, const flow_key_t *flow,
                               tcp_dir_t dir, uint32_t seq, uint32_t ack,
                               uint8_t flags, uint16_t window,
                               const uint8_t *payload, size_t payload_len) {
    tx_ctx_t *tx = (tx_ctx_t *)tx_ctx;
    uint32_t  sip, dip;
    uint16_t  sport, dport;
    size_t    total_len;
    uint8_t  *buf;
    IPHDR    *ip;
    TCPHDR   *tcp;
    int       rc;
    /* 송신 컨텍스트, 하위 L3 송신 함수, flow 입력이 유효한지 확인한다. */
    if (!tx || !tx->send_l3 || !flow) {
        return -1;
    }

    /* payload 길이가 있는데 payload 포인터가 없으면 잘못된 입력이다. */
    if (payload_len > 0 && !payload) {
        return -1;
    }

    /* IP + TCP + payload를 합친 전체 패킷 길이를 계산한다. */
    total_len = IP_HDR_SIZE + TCP_HDR_SIZE + payload_len;
    if (total_len > 0xFFFFu) {
        return -1;
    }

    /*
     * flow와 방향(dir)에 따라 실제 송신/수신 endpoint를 결정한다.
     * DIR_AB는 flow의 원래 방향, DIR_BA는 src/dst를 뒤집은 방향이다.
     */
    if (dir == DIR_AB) {
        sip   = flow->src_ip;
        sport = flow->src_port;

        dip   = flow->dst_ip;
        dport = flow->dst_port;
    } else {
        sip   = flow->dst_ip;
        sport = flow->dst_port;

        dip   = flow->src_ip;
        dport = flow->src_port;
    }
    /* 전송할 raw IPv4/TCP 패킷 버퍼를 확보한다. */
    buf = (uint8_t *)calloc(1, total_len);
    if (!buf) {
        return -1;
    }

    /* 버퍼 앞부분을 IPv4 헤더와 TCP 헤더로 해석한다. */
    ip  = (IPHDR *)buf;
    tcp = (TCPHDR *)(buf + sizeof(*ip));

    /* IPv4 헤더 필드를 채운다. */
    IP_VER(ip)       = 4;
    IP_IHL(ip)       = 5;
    IP_TTL_FIELD(ip) = 64;
    IP_PROTO(ip)     = IPPROTO_TCP;
    IP_TOTLEN(ip)    = htons((uint16_t)total_len);
    IP_SADDR(ip)     = htonl(sip);
    IP_DADDR(ip)     = htonl(dip);
    IP_CHECK(ip)     = 0;
    IP_CHECK(ip)     = checksum16(ip, sizeof(*ip));

    /* TCP 헤더 필드를 채운다. */
    TCP_SPORT(tcp) = htons(sport);
    TCP_DPORT(tcp) = htons(dport);
    TCP_SEQ(tcp)   = htonl(seq);
    TCP_ACK(tcp)   = htonl(ack);
    TCP_DOFF(tcp)  = 5;
    TCP_SET_FLAGS(tcp, flags);
    TCP_WIN(tcp)   = htons(window);
    TCP_CHECK(tcp) = 0;
    /* payload가 있으면 TCP 헤더 뒤에 그대로 복사한다. */
    if (payload_len > 0) {
        memcpy((uint8_t *)tcp + TCP_HDR_SIZE, payload, payload_len);
    }
    /* pseudo-header를 포함한 TCP 체크섬을 계산해 기록한다. */
    TCP_CHECK(tcp) =
        htons(tcp_checksum(IP_SADDR(ip), IP_DADDR(ip), (const uint8_t *)tcp,
                           TCP_HDR_SIZE + payload_len));

    /* 완성된 raw 패킷을 하위 L3 송신 함수로 넘긴다. */
    rc = tx->send_l3(tx->ctx, buf, total_len);
    free(buf);
    /* 임시 버퍼를 해제하고 송신 결과를 반환한다. */
    return rc;
}

/**
 * @brief TCP RST 세그먼트를 생성해 지정한 방향으로 전송한다.
 *
 * ack값이 0이 아니면 RST|ACK 형태로 보내고,
 * 0이면 순수 RST 세그먼트로 보낸다. 실제 패킷 생성과 송신은
 * tx_send_tcp_segment에 위임한다.
 *
 * @param tx_ctx raw L3 송신에 사용할 전송 컨텍스트
 * @param flow 송신 대상 TCP flow key
 * @param dir RST를 보낼 방향 (DIR_AB 또는 DIR_BA)
 * @param seq TCP sequence 번호
 * @param ack TCP acknowledgement 번호. 0이 아니면 ACK 플래그도 함께 설정된다.
 * @return int 0=전송 성공, 음수=송신 실패
 */
int tx_send_rst(void *tx_ctx, const flow_key_t *flow, tcp_dir_t dir,
                uint32_t seq, uint32_t ack) {
    uint8_t flags = TCP_RST;

    /* ACK 번호가 있으면 RST|ACK 형태로 보낸다. */
    if (ack != 0) {
        flags |= TCP_ACK;
    }

    /* payload 없는 TCP RST 세그먼트를 생성해 전송한다. */
    return tx_send_tcp_segment(tx_ctx, flow, dir, seq, ack, flags, 0, NULL, 0);
}

/**
 * @brief 세션 상태 또는 snapshot을 기준으로 RST 패킷 버스트를 전송한다.
 *
 * 지정한 flow와 방향(dir)에 대해 현재 TCP 상태를 계산하고,
 * 수신 윈도우 범위 안에 여러 개의 RST를 분산 전송한다.
 * snap이 주어지면 snapshot 값을 우선 사용하고, 없으면 live session 상태를
 * 사용한다.
 *
 * @param gw RST 송신에 사용할 httgw 인스턴스
 * @param flow RST를 보낼 대상 TCP flow key
 * @param dir RST를 보낼 방향 (DIR_AB 또는 DIR_BA)
 * @param snap 선택적 세션 snapshot. NULL이면 현재 세션 상태를 직접 사용한다.
 * @return int 0=전송 성공, 1=이미 해당 방향으로 RST 전송됨,
 *             -1=잘못된 인자, -2=세션 없음, -3=RST 계산에 필요한 상태 부족,
 *             -4=송신 함수 미설정, 그 외=하위 송신 함수 오류
 */
int httgw_request_rst_with_snapshot(httgw_t *gw, const flow_key_t *flow,
                                    tcp_dir_t                    dir,
                                    const httgw_sess_snapshot_t *snap) {
    httgw_session_t *sess;
    uint32_t         seq_base = 0;
    uint32_t         ack      = 0;
    uint32_t         win      = 0;
    int              sent_ok  = 0;
    int              last_err = -1;

    /* 기본 인자와 방향값이 정상인지 먼저 확인한다. */
    if (NULL == gw || NULL == flow) {
        return -1;
    }
    if (dir != DIR_AB && dir != DIR_BA) {
        return -1;
    }

    /* 실제 송신 함수가 연결되지 않았으면 RST를 만들 수 없다. */
    if (NULL == gw->tx_send_rst) {
        return -4;
    }

    /*
     * flow에 대응하는 live session을 찾는다.
     * 현재 구현은 중복 RST 전송 여부를 세션 플래그로 관리하므로
     * snapshot이 있어도 session lookup 자체는 필요하다.
     */
    sess = sess_find(gw, flow);
    if (NULL == sess) {
        return -2;
    }

    /* 같은 방향으로 이미 RST를 보낸 세션이면 재전송하지 않는다. */
    if (dir == DIR_AB && sess->rst_sent_ab) {
        return 1;
    }
    if (dir == DIR_BA && sess->rst_sent_ba) {
        return 1;
    }

    /*
     * snapshot이 주어지면 그 값을 우선 사용하고,
     * 없으면 현재 세션 상태에서 seq/ack/window 기준값을 계산한다.
     */
    if (NULL != snap) {
        if (0 == snap->seen_ab || 0 == snap->seen_ba) {
            return -3;
        }

        /* AB 방향 RST는 AB의 다음 seq와 BA가 광고한 window를 기준으로 잡는다.
         */
        if (dir == DIR_AB) {
            if (snap->next_seq_ab == 0 || snap->next_seq_ba == 0) {
                return -3;
            }
            seq_base = snap->next_seq_ab;
            ack      = snap->next_seq_ba + HTTGW_SERVER_NEXT_BIAS;
            win      = ((uint32_t)snap->win_ba)
                  << (snap->win_scale_ba > 14 ? 14 : snap->win_scale_ba);
        } else {
            /* BA 방향 RST는 BA의 다음 seq와 AB가 광고한 window를 기준으로
             * 잡는다. */
            if (snap->next_seq_ab == 0 || snap->next_seq_ba == 0) {
                return -3;
            }
            seq_base = snap->next_seq_ba + HTTGW_SERVER_NEXT_BIAS;
            ack      = snap->next_seq_ab;
            win      = ((uint32_t)snap->win_ab)
                  << (snap->win_scale_ab > 14 ? 14 : snap->win_scale_ab);
        }
    } else {
        if (0 == sess->seen_ab || 0 == sess->seen_ba) {
            return -3;
        }

        /* snapshot이 없으면 live session의 마지막 관측값으로 계산한다. */
        if (dir == DIR_AB)  // Client -> Server
        {
            if (sess->next_seq_ab == 0 || sess->next_seq_ba == 0) {
                return -3;
            }
            seq_base = sess->next_seq_ab;
            ack      = sess->next_seq_ba + HTTGW_SERVER_NEXT_BIAS;
            win      = ((uint32_t)sess->win_ba)
                  << (sess->win_scale_ba > 14 ? 14 : sess->win_scale_ba);
        } else  // Server -> Client
        {
            if (sess->next_seq_ab == 0 || sess->next_seq_ba == 0) {
                return -3;
            }
            seq_base = sess->next_seq_ba + HTTGW_SERVER_NEXT_BIAS;
            ack      = sess->next_seq_ab;
            win      = ((uint32_t)sess->win_ab)
                  << (sess->win_scale_ab > 14 ? 14 : sess->win_scale_ab);
        }
    }

    /* 수신 윈도우가 0이면 유효한 burst 분산 범위를 만들 수 없다. */
    if (win == 0) {
        return -3;
    }

    /*
     * 수신 윈도우 범위 안에 RST를 여러 개 분산 전송한다.
     * 수신측이 현재 어느 seq를 받아들일지 애매한 경우를 대비한 burst다.
     */
    for (uint32_t i = 0; i < HTTGW_RST_BURST_COUNT; i++) {
        uint32_t seq_off;

        /* burst 개수가 1이거나 window가 1이면 기준 seq 하나만 사용한다. */
        if (HTTGW_RST_BURST_COUNT == 1 || win == 1) {
            seq_off = 0;
        } else {
            /* seq_off는 seq_base에 더할 오프셋이다. */
            seq_off = (uint32_t)(((uint64_t)(win - 1) * i) /
                                 (HTTGW_RST_BURST_COUNT - 1));
        }

        uint32_t seq_try = seq_base + seq_off;

        /* 계산된 seq/ack 조합으로 RST 1회를 전송한다. */
        int rc = gw->tx_send_rst(gw->tx_ctx, flow, dir, seq_try, ack);
        if (rc == 0) {
            sent_ok++;
        } else {
            last_err = rc;
        }
    }

    /* 모든 burst 전송이 성공했을 때만 해당 방향 RST 송신 완료로 기록한다. */
    if (sent_ok == (int)HTTGW_RST_BURST_COUNT) {
        if (dir == DIR_AB) {
            sess->rst_sent_ab = 1;
        } else {
            sess->rst_sent_ba = 1;
        }
        return 0;
    }

    /* 하나라도 실패했으면 마지막 송신 오류를 상위로 전달한다. */
    return last_err;
}

/**
 * @brief 세션 snapshot을 기준으로 클라이언트 방향 HTTP 차단 응답을 주입한다.
 *
 * 서버에서 클라이언트로 가는 방향(DIR_BA)으로 위조 TCP 세그먼트를 생성해
 * HTTP 차단 페이지 payload를 분할 전송하고, 마지막에 FIN|ACK를 보내 연결을
 * 정리한다. seq/ack 기준값은 전달받은 snapshot에서 계산한다.
 *
 * @param gw 주입 송신에 사용할 httgw 인스턴스
 * @param flow 차단 응답을 주입할 대상 TCP flow key
 * @param snap 현재 세션의 seq/ack/window 정보를 담은 snapshot
 * @param payload 클라이언트에게 보낼 HTTP 응답 바디/헤더 데이터
 * @param payload_len payload 전체 길이
 * @return int 0=성공, -1=잘못된 인자, -2=세션 없음,
 *             -3=주입 계산에 필요한 상태 부족, -4=송신 컨텍스트 미설정,
 *             그 외=하위 송신 함수 오류
 */
int httgw_inject_block_response_with_snapshot(httgw_t                     *gw,
                                              const flow_key_t            *flow,
                                              const httgw_sess_snapshot_t *snap,
                                              const uint8_t *payload,
                                              size_t         payload_len) {
    httgw_session_t *sess;
    uint32_t         seq_base;
    uint32_t         ack;
    size_t           sent     = 0;
    int              last_err = -1;

    /* 기본 인자와 payload 길이가 정상인지 먼저 확인한다. */
    if (NULL == gw || NULL == flow || NULL == snap || NULL == payload ||
        0 == payload_len) {
        return -1;
    }

    /* 실제 L3/TCP 송신 컨텍스트가 연결되지 않았으면 주입할 수 없다. */
    if (NULL == gw->tx_ctx) {
        return -4;
    }

    /*
     * 현재 구현은 live session 존재를 전제로 주입한다.
     * snapshot은 seq/ack 계산에 쓰고, session lookup은 flow 유효성 확인 용도로
     * 쓴다.
     */
    sess = sess_find(gw, flow);
    if (NULL == sess) {
        return -2;
    }

    /* 양방향 상태를 모두 본 세션이 아니면 정상적인 응답 주입 기준을 만들 수
     * 없다. */
    if (0 == snap->seen_ab || 0 == snap->seen_ba) {
        return -3;
    }
    if (snap->next_seq_ab == 0 || snap->next_seq_ba == 0) {
        return -3;
    }

    /* 서버 -> 클라이언트 방향(DIR_BA)으로 보낼 seq/ack 기준값을 snapshot에서
     * 잡는다. */
    seq_base = snap->next_seq_ba;
    ack      = snap->next_seq_ab;

    /*
     * 차단 응답 payload를 여러 TCP 세그먼트로 분할 전송한다.
     * 마지막 payload 세그먼트에는 PSH를 넣어 클라이언트가 바로 처리하게 한다.
     */
    while (sent < payload_len) {
        size_t  chunk = payload_len - sent;
        uint8_t flags = TCP_ACK;
        int     rc;

        /* 한 세그먼트가 너무 커지지 않도록 주입용 상한으로 자른다. */
        if (chunk > HTTGW_INJECT_SEGMENT_BYTES) {
            chunk = HTTGW_INJECT_SEGMENT_BYTES;
        }

        /* 마지막 payload 조각이면 PSH를 같이 넣는다. */
        if (sent + chunk == payload_len) {
            flags |= TCP_PSH;
        }

        /* DIR_BA 방향으로 위조 응답 데이터를 실제 전송한다. */
        rc = tx_send_tcp_segment(gw->tx_ctx, flow, DIR_BA,
                                 seq_base + (uint32_t)sent, ack, flags,
                                 snap->win_ba, payload + sent, chunk);
        if (rc != 0) {
            return rc;
        }
        sent += chunk;
    }

    /* payload 전송이 끝나면 FIN|ACK로 응답 방향 연결을 정리한다. */
    last_err = tx_send_tcp_segment(
        gw->tx_ctx, flow, DIR_BA, seq_base + (uint32_t)payload_len, ack,
        (uint8_t)(TCP_FIN | TCP_ACK), snap->win_ba, NULL, 0);

    /* 마지막 FIN 전송 결과를 상위로 반환한다. */
    return last_err;
}

/**************************** httgw를 바깥에서 쓰기 쉽게 감싼 wrapper AIP
 * *************************** */
int httgw_request_rst(httgw_t *gw, const flow_key_t *flow, tcp_dir_t dir) {
    return httgw_request_rst_with_snapshot(gw, flow, dir, NULL);
}

int sess_get_or_create(httgw_t *gw, const flow_key_t flow, uint64_t ts_ms) {
    if (NULL == gw) {
        return -1;
    }
    return sess_get_or_create_internal(gw, &flow, ts_ms) ? 1 : 0;
}

int sess_lookup(const httgw_t *gw, const flow_key_t flow) {
    if (NULL == gw) {
        return 0;
    }
    return sess_find(gw, &flow) ? 1 : 0;
}

void sess_gc(httgw_t *gw, uint64_t ts_ms) {
    httgw_gc(gw, ts_ms);
}

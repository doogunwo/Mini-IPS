/**
 * @file httgw.c
 * @brief HTTP 게이트웨이, TCP 재조립, RST 처리 구현
 */
#define _DEFAULT_SOURCE
#include "httgw.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <errno.h>
#include "net_compat.h"
#include <sys/socket.h>
#include <unistd.h>

typedef void (*reasm_on_data_cb)(
    const flow_key_t *flow, tcp_dir_t dir,
    const uint8_t *data, uint32_t len, uint32_t seq_start,
    void *user);

/* ---------- seq 비교(랩어라운드 고려) ---------- */
static inline int32_t seq_diff(uint32_t a, uint32_t b) { return (int32_t)(a - b); }
#define SEQ_LT(a, b) (seq_diff((a), (b)) < 0)
#define SEQ_LEQ(a, b) (seq_diff((a), (b)) <= 0)
#define SEQ_GT(a, b) (seq_diff((a), (b)) > 0)
#define SEQ_GEQ(a, b) (seq_diff((a), (b)) >= 0)

/**
 * @brief HTTP 재조립, Out-of-order 대비용 연결리스트 구조체
 * 순서 맞추기 위한 임시 세그먼트 보관용 연결리스트
 */
typedef struct reasm_seg_node
{
    uint32_t seq; // TCP 넘버
    uint32_t len; // 보관중인 길이
    uint8_t *data; // 실제 패킷 페이로드가 저장된 메모리 포인터
    struct reasm_seg_node *next; // 더 큰 다음 조각을 가르키는 포인터
} reasm_seg_node_t;

/**
 * @brief 방향(dir)을 맞축디 위한 방향 상태 관리
 * 세션 구조체(reasm_session_t)에서 reasm_dir_t를 2개로 가짐 dir[2]
 * 요청/응답 양방향 추적은 유지하지만, 현재 상위 계층에는 요청만 전달한다.
 */
typedef struct reasm_dir
{
    uint8_t has_next; // 다음 패킷이 있음? 0/1
    uint32_t next_seq; // 이번에 와야할 패킷 번호
    uint8_t fin_seen; // 통신이 종료중인지?(FIN 봄?)
    uint8_t rst_seen; // RST 패킷 봄?

    reasm_seg_node_t *head; //첫번째를 가르키는 포인터, 이 포인터 뒤에 next_seq보다 큰걸 붙여놓음
    uint32_t seg_count;// 포인터 뒤에 붙어있는 세그먼트 개수
    uint32_t bytes_queued; // 포인터 뒤에 붙어있는 세그먼트의 총 용량
} reasm_dir_t;

/**
 * @brief TCP 연결 1개에 대한 재조립 상태 묶음
 * 재조립 엔진(reasm_) 전체의 전역 컨텍스트
 */
typedef struct reasm_session
{
    flow_key_t key; 
    uint64_t last_seen_ms;

    reasm_dir_t dir[2];
    struct reasm_session *next;
} reasm_session_t; // TCP연결 1개에 대한 상태

/**
 * @brief 재조립 세션 저장, 해시 테이블, 콜백함수 묶은 구조체
 * 
 */
typedef struct reasm_ctx
{
    reasm_session_t **buckets; // 해시테이블
    uint32_t nbuckets; // 버킷 개수
    uint32_t nsessions; // 등록된 세션 개수

    reasm_mode_t mode; // 재조립 동작 모드 (strict/last-start)
    reasm_on_data_cb on_data; //붙일 콜백함수
    void *user; // 사용자 컨텍스트 포인터
} reasm_ctx_t; //세션 전체를 관리함


static uint32_t reasm_flow_hash(const flow_key_t *k)
{
    uint32_t h = 2166136261u;         // FNV offset basis (초기값)
    const uint32_t prime = 16777619u; // FNV prime (곱하는 값)

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

static int reasm_flow_eq(const flow_key_t *a, const flow_key_t *b)
{
    return a->src_ip == b->src_ip && a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port && a->dst_port == b->dst_port &&
           a->proto == b->proto;
}

static void reasm_seg_free(reasm_seg_node_t *s)
{
    if (!s)
        return;
    free(s->data);
    free(s);
}

static void reasm_dir_clear(reasm_dir_t *d)
{
    reasm_seg_node_t *p = d->head;
    while (p)
    {
        reasm_seg_node_t *n = p->next;
        reasm_seg_free(p);
        p = n;
    }
    memset(d, 0, sizeof(*d));
}

static void reasm_session_free(reasm_session_t *s)
{
    if (!s)
        return;
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
static reasm_ctx_t *reasm_create(uint32_t nbuckets, reasm_on_data_cb cb, void *user)
{   // 0으로 초기화
    reasm_ctx_t *c = (reasm_ctx_t *)calloc(1, sizeof(*c));
    if (!c)
        return NULL;
    // 0 -> 기본 버킷 8192
    if (nbuckets == 0)
        nbuckets = 8192;

    // 각 버킷은 생성 및 NULL
    c->buckets = (reasm_session_t **)calloc(nbuckets, sizeof(reasm_session_t *));
    if (!c->buckets)
    {
        free(c);
        return NULL;
    }

    // 필드 초기화
    c->nbuckets = nbuckets;
    c->mode = REASM_MODE_LATE_START;
    c->on_data = cb;
    c->user = user;
    return c;
}

/**
 * @brief 컨텍스트 동작 모드 설정
 * 널 체크 후 모드 값 설정하는 함수
 * @param c 재조립 컨텍스트 
 * @param mode 재조립 모드
 * @return 없음
 */
static void reasm_set_mode(reasm_ctx_t *c, reasm_mode_t mode)
{
    if (!c)
        return;
    c->mode = mode;
}

/**
 * @brief reasm_ctx_t 해제 소멸자 
 * 
 * @param c 없애버릴 컨텍스트
 * @return 없음
 */
static void reasm_destroy(reasm_ctx_t *c)
{
    if (!c)
        return;
    // 모든 해시 버킷 순회 
    for (uint32_t i = 0; i < c->nbuckets; i++)
    {
        reasm_session_t *p = c->buckets[i];
        while (p) // 연결리스트 해제
        {
            reasm_session_t *n = p->next;
            reasm_session_free(p);
            p = n;
        }
    }
    free(c->buckets); //해시테이블 없애고
    free(c); // 컨텍스트 없애기
}

/**
 * @brief 올드 세션 제거 함수
 * 세션을 해시테이블에서 제거하는 함수
 * @param c 해시테이블 봐야해서, 컨텍스트 전달
 * @param now_ms 지금 시간
 */
static void reasm_gc(reasm_ctx_t *c, uint64_t now_ms)
{
    if (!c)
        return;
    // 버킷 순회
    for (uint32_t i = 0; i < c->nbuckets; i++)
    {
        reasm_session_t **pp = &c->buckets[i]; // 연결리스트 순회
        while (*pp) // **pp로 인해 삭제 후 노드가 다음을 가르킨다.
        {
            reasm_session_t *s = *pp;
            if (now_ms - s->last_seen_ms > REASM_SESSION_TIMEOUT_MS) //타임아웃 점검
            {   // 만료 세션 삭제
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
static reasm_session_t *reasm_lookup(reasm_ctx_t *c, const flow_key_t *k, uint64_t ts_ms)
{
    uint32_t idx = reasm_flow_hash(k) % c->nbuckets; // k 해시 -> 버킷 찾기
    for (reasm_session_t *p = c->buckets[idx]; p; p = p->next)
    { // 해시 충돌로 여러 세션이 있을 수 있으니 끝까지 검사
        if (reasm_flow_eq(&p->key, k))
        { // 같은지?
            p->last_seen_ms = ts_ms; //시간 갱신
            return p; //반환
        }
    }
    return NULL; // 없으면 널
}

/**
 * @brief 컨텍스트 찾거나 만드는 함수
 *  세션을 찾고 없으면 만듬
 * @param c 컨텍스트
 * @param k 키
 * @param ts_ms 시간
 * @return reasm_session_t* 
 */
static reasm_session_t *reasm_get_or_create(reasm_ctx_t *c, const flow_key_t *k, uint64_t ts_ms)
{   // 이미 있는 흐름이면 반환함
    reasm_session_t *s = reasm_lookup(c, k, ts_ms);
    if (s)
        return s;
    // 세션 너무 많으면 안만듬
    if (c->nsessions >= REASM_MAX_SESSIONS)
        return NULL;

    //해시로 새로운 세션을 어느 버킷에 넣을지 결정
    uint32_t idx = reasm_flow_hash(k) % c->nbuckets;
    s = (reasm_session_t *)calloc(1, sizeof(*s)); // 메모리 할당
    if (!s)
        return NULL;
    //필드채우기
    s->key = *k;
    s->last_seen_ms = ts_ms;
    s->next = c->buckets[idx];
    c->buckets[idx] = s;
    c->nsessions++;
    return s;
}

/**
 * @brief 페이로드 트리밍 함수
 * 이미받은 데이터는 버리고 아직 안 받은 부분만 남기도록 seq, 페이로드, len 직접 수정함
 * 테스트 코드 필요함
 * @param d 방향
 * @param seq 다음에 받아야할 번호,
 * @param payload  현재 들어온 페이로드 시작 주소
 * @param len 길이
 */
static void reasm_trim_to_next(reasm_dir_t *d, uint32_t *seq, const uint8_t **payload, uint32_t *len)
{   // 기존 정보 없으면 아무것도 안함
    if (*len == 0 || !d->has_next)
        return;
    // 현재 데이터는 어디쯤?
    uint32_t start = *seq;
    uint32_t end = start + *len;
    // 이미 처리된거면 다 버리고
    if (SEQ_LEQ(end, d->next_seq))
    {
        *len = 0;
        return;
    }
    // 앞부부남ㄴ 처리된 경우 그 부분만 잘라냄
    if (SEQ_LT(start, d->next_seq))
    {
        uint32_t delta = (uint32_t)(d->next_seq - start);
        *seq = d->next_seq;
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
 * @return int 0:정상, -1: 개수 제한 초과, -2: 바이트큐 제한초과, -3: 메모리 할당 실패
 */
static int reasm_insert_segment(reasm_dir_t *d, uint32_t seq, const uint8_t *payload, uint32_t len)
{
    reasm_seg_node_t **pp;
    reasm_seg_node_t *prev = NULL;
    uint32_t new_start = seq;
    uint32_t new_end = seq + len; //세그먼트 범위 
    // 입력 제한 점검
    if (len == 0) // 할일없음
        return 0;
    if (d->seg_count >= REASM_MAX_SEGMENTS_PER_DIR) // 세그먼트 수 제한 넘음
        return -1;
    if (d->bytes_queued + len > REASM_MAX_BYTES_PER_DIR) // 누적 바이트 제한 넘음
        return -2;
    // 어디에 넣을까? 삽입 위치 
    pp = &d->head;
    while (*pp && SEQ_LT((*pp)->seq, seq))
        pp = &(*pp)->next;
    // 이전 노드는 어디인가?
    if (pp != &d->head)
    {
        reasm_seg_node_t *p = d->head;
        while (p && p->next != *pp)
            p = p->next;
        prev = p;
    }
    // 이전 세그먼트와 겹침 처리
    if (prev)
    {
        uint32_t prev_end = prev->seq + prev->len;
        if (SEQ_GEQ(prev_end, new_start))
        {
            if (SEQ_GEQ(prev_end, new_end))
                return 0;
            uint32_t delta = (uint32_t)(prev_end - new_start);
            new_start = prev_end;
            payload += delta;
            len -= delta;
            new_end = new_start + len;
        }
    }
    // 뒤쪽 세그먼트들과 겹침 처리
    while (*pp)
    {
        reasm_seg_node_t *cur = *pp;
        uint32_t cur_start = cur->seq;
        uint32_t cur_end = cur->seq + cur->len;
        //안겹치면 종료
        if (SEQ_LEQ(new_end, cur_start))
            break;
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
        if(SEQ_LT(new_start, cur_start))
        {
            // 1. 새 조각이 기존 조각 을 완전히 덮는 경우
            if(SEQ_GEQ(new_end, cur_end))
            {   // 기존 조각은 완전히 포함되어 쓸모가 없어졌으므로 리스트에서 제거하기
                *pp = cur->next;
                d->seg_count--;
                d->bytes_queued -= d->bytes_queued - cur->len;
                free(cur->data);
                free(cur);
                continue;
            }
            else // 2. 새 조각이 기존 조각의 앞부분만 겹치고 끝나는 경우
            {
                uint32_t keep = (uint32_t)(cur_start - new_start);
                len = keep;
                new_end = new_start + len;
                break; // 뒷 부분은 기존 조각이 갖고있어어서 여기서 자르기
            }
        }
        // 새 조각이 현재 노드 안에 들어간 경우
        if (SEQ_LT(new_start, cur_end))
        {
            if (SEQ_GEQ(cur_end, new_end))
                return 0;
            uint32_t delta = (uint32_t)(cur_end - new_start);
            new_start = cur_end;
            payload += delta;
            len -= delta;
            new_end = new_start + len;
            pp = &cur->next;
            continue;
        }
        pp = &(*pp)->next;
    }
    // 남은 데이터가 없음
    if (len == 0)
        return 0;
    if (d->seg_count >= REASM_MAX_SEGMENTS_PER_DIR)
        return -1;
    if (d->bytes_queued + len > REASM_MAX_BYTES_PER_DIR)
        return -2;
    // 새로운 노드 생성
    reasm_seg_node_t *n = (reasm_seg_node_t *)calloc(1, sizeof(*n));
    if (!n)
        return -3;

    n->data = (uint8_t *)malloc(len);
    if (!n->data)
    {
        free(n);
        return -3;
    }
    memcpy(n->data, payload, len);
    n->seq = new_start;
    n->len = len;
    // 정렬된 위치에 삽입
    pp = &d->head;
    while (*pp && SEQ_LT((*pp)->seq, n->seq))
        pp = &(*pp)->next;
    n->next = *pp;
    *pp = n;
    // 통계 갱신
    d->seg_count++;
    d->bytes_queued += len;
    // 바로 뒤 연속되면? 병합가능함
    while (n->next)
    {
        // 정확히 위치가 이어지면 merge
        reasm_seg_node_t *nx = n->next;
        uint32_t n_end = n->seq + n->len;
        if (n_end != nx->seq)
            break;
        // 데이터 버퍼를 늘리고 뒤 세그먼트를 붙임
        uint32_t merged_len = n->len + nx->len;
        uint8_t *buf = (uint8_t *)realloc(n->data, merged_len);
        if (!buf)
            break;
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
static int reasm_looks_like_http_start(const uint8_t *payload, uint32_t len)
{   // 페이로드 맨앞에 HTTP 처럼 보이는 문자열이 있는지
    static const char *const methods[] = {
        "GET ", "POST ", "PUT ", "HEAD ", "DELETE ",
        "OPTIONS ", "PATCH ", "TRACE ", "CONNECT "};
    size_t i;
    // 데이터가 없으면 HTTP 시작 아님
    if (!payload || len == 0)
        return 0;
    // 배열에 있는 문자열 검사함
    for (i = 0; i < sizeof(methods) / sizeof(methods[0]); i++)
    {   // 길이, prefix 비교함
        size_t n = strlen(methods[i]);
        if (len >= n && memcmp(payload, methods[i], n) == 0)
            return 1;
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
static void reasm_flush(reasm_ctx_t *c, reasm_session_t *s, tcp_dir_t dir)
{   //어느 방향인지
    reasm_dir_t *d = &s->dir[dir];
    // next seq 정해져있는지? 없으면 탈출
    if (!d->has_next) 
        return;
    // 헤드 노드가 정확히 next_seq인가? 그러면 순서가 맞음
    while (d->head && d->head->seq == d->next_seq)
    {   // 헤드 꺼내고
        reasm_seg_node_t *h = d->head;
        if (c->on_data) // 콜백 전달
        {
            c->on_data(&s->key, dir, h->data, h->len, h->seq, c->user);
        }
        // 다음에 와야할 시퀀스 갱신하기
        d->next_seq += h->len;
        // 큐 상태 갱신, 대기바이트 감소, 세그먼트 수 감소, 리스트 헤드 다음노드로
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
static int reasm_ingest(
    reasm_ctx_t *c,
    const flow_key_t *flow,
    tcp_dir_t dir,
    uint32_t seq,
    uint8_t tcp_flags,
    const uint8_t *payload,
    uint32_t len,
    uint64_t ts_ms)
{
    // 입력 검증
    if (!c || !flow)
        return -1;
    if (dir != DIR_AB && dir != DIR_BA)
        return -1;
    // 기존 세션 조회
    reasm_session_t *s = reasm_lookup(c, flow, ts_ms);
    if (tcp_flags & TCP_RST) // RST이면 세션 제거함
    {
        if (!s) 
            return 0;// 세션이 없네
        uint32_t idx = reasm_flow_hash(flow) % c->nbuckets;
        reasm_session_t **pp = &c->buckets[idx]; 
        while (*pp)
        {
            if (*pp == s)
            {   // 세션이 있으면 해시 버킷에서 링크 풀고 프리
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
    if (!s)
    {
        if (len == 0 && c->mode == REASM_MODE_LATE_START) // 페이로드없으면 세션안만듬
            return 0;
        if (c->mode == REASM_MODE_STRICT_SYN && !(tcp_flags & TCP_SYN)) // SYN 없는 첫패킷이면 세션안만듬
            return 0;
        // 조건 통과하면 세션 생성함
        s = reasm_get_or_create(c, flow, ts_ms);
        if (!s)
            return -2;
    }
    // 방향과 FIN 기록 함, 현재 방향 재조립상태 가져오기
    reasm_dir_t *d = &s->dir[dir];
    if (tcp_flags & TCP_FIN)
        d->fin_seen = 1;
    // next_seq가 없으면 시작점 설정
    if (!d->has_next)
    {   // SYN은 시퀀스 번호 1소비하니까, 다음은 seq+1기대함
        if (c->mode == REASM_MODE_STRICT_SYN)
        {
            d->has_next = 1;
            d->next_seq = seq + 1;
        }
        else
        {   // 페이로드없으면 시작못함
            if (len == 0)
                return 0;
            // http 시작 맞으면 여기서부터 재조립시작
            if (!reasm_looks_like_http_start(payload, len))
                return reasm_insert_segment(d, seq, payload, len);
            d->has_next = 1;
            d->next_seq = seq;
        }
    }
    // 이미 받은 앞부분 trimming
    uint32_t adj_seq = seq;
    const uint8_t *adj_pl = payload;
    uint32_t adj_len = len;

    reasm_trim_to_next(d, &adj_seq, &adj_pl, &adj_len);
    if (adj_len == 0)
        return 0;
    // 세그먼트 삽입
    int rc = reasm_insert_segment(d, adj_seq, adj_pl, adj_len);
    // 실패하면 세션 제거
    if (rc != 0)
    {
        uint32_t idx = reasm_flow_hash(flow) % c->nbuckets;
        reasm_session_t **pp = &c->buckets[idx];
        while (*pp)
        {
            if (*pp == s)
            {
                *pp = s->next;
                c->nsessions--;
                reasm_session_free(s);
                break;
            }
            pp = &(*pp)->next;
        }
        return rc;
    }

    // 이어질 수 있는 데이터 flush, 연속된 세그먼트있으면 콜백으로 넘기고 큐에서 제거
    // 여기서 실제 상위 계층(HTTP 파서 등)으로 데이터가 전달
    reasm_flush(c, s, dir);

    if (s->dir[0].fin_seen && s->dir[1].fin_seen &&
        s->dir[0].head == NULL && s->dir[1].head == NULL)
    {
        uint32_t idx = reasm_flow_hash(flow) % c->nbuckets;
        reasm_session_t **pp = &c->buckets[idx];
        while (*pp)
        {   // 해시테이블 언링크, 프리
            if (*pp == s)
            {
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

struct httgw
{
    reasm_ctx_t *reasm;
    http_stream_cfg_t stream_cfg;
    httgw_callbacks_t cbs;

    void *user;
    httgw_stats_t stats;
    int verbose;
    httgw_mode_t mode;

    /* 송신 경로 핸들 + RST 송신함수*/
    void *tx_ctx;
    httgw_send_rst_fn tx_send_rst;

    httgw_session_t **sess_buckets;
    uint32_t sess_bucket_count;
    uint32_t sess_count;
};

struct ip_hash
{
    ip_node_t **buckets;
    size_t nbuckets;
};

#if defined(__GNUC__)
#define HTTGW_UNUSED __attribute__((unused))
#endif

struct httgw_session
{
    flow_key_t flow;
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
    uint8_t win_scale_ab;
    uint8_t win_scale_ba;

    uint8_t seen_ab;
    uint8_t seen_ba; // 해당 방향 패킷을 봤는지?

    uint64_t last_ts_ms; // 세션 타임아웃/GC용

    uint8_t fin_seen_ab;
    uint8_t fin_seen_ba; // 종료 상태 추적
    uint8_t rst_sent_ab;
    uint8_t rst_sent_ba;

    struct httgw_session *next;
};

/* --------------------------- session table --------------------------- */
#define HTTGW_SESS_BUCKETS 4096
#define HTTGW_SESS_TIMEOUT_MS (60ULL * 1000ULL)
#define HTTGW_RST_BURST_COUNT 5U

static void sess_destroy(httgw_session_t *s)
{
    if (!s)
        return;
    if (s->streams[DIR_AB])
        http_stream_destroy(s->streams[DIR_AB]);
    if (s->streams[DIR_BA])
        http_stream_destroy(s->streams[DIR_BA]);
    free(s);
}

static uint32_t sess_flow_hash(const flow_key_t *k)
{
    uint32_t h = 2166136261u;
#define H1(x)               \
    do                      \
    {                       \
        h ^= (uint32_t)(x); \
        h *= 16777619u;     \
    } while (0)
    H1(k->src_ip);
    H1(k->dst_ip);
    H1(((uint32_t)k->src_port << 16) | k->dst_port);
    H1(k->proto);
#undef H1
    return h;
}

static int sess_flow_eq(const flow_key_t *a, const flow_key_t *b)
{
    return a->src_ip == b->src_ip && a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port && a->dst_port == b->dst_port &&
           a->proto == b->proto;
}

/* --------------------------- ip hash table (unused for now) --------------------------- */
static uint32_t HTTGW_UNUSED ip_hash_fn(uint32_t ip)
{
    ip ^= ip >> 16;
    ip *= 0x7feb352d;
    ip ^= ip >> 15;
    ip *= 0x846ca68b;
    ip ^= ip >> 16;
    return ip;
}

static httgw_session_t *sess_find(const httgw_t *gw, const flow_key_t *flow)
{
    uint32_t idx = sess_flow_hash(flow) % gw->sess_bucket_count;
    for (httgw_session_t *s = gw->sess_buckets[idx]; s; s = s->next)
    {
        if (sess_flow_eq(&s->flow, flow))
            return s;
    }
    return NULL;
}

static httgw_session_t *sess_remove_internal(httgw_t *gw, const flow_key_t *flow)
{
    uint32_t idx;
    httgw_session_t **pp;

    if (!gw || !flow)
        return NULL;

    idx = sess_flow_hash(flow) % gw->sess_bucket_count;
    pp = &gw->sess_buckets[idx];
    while (*pp)
    {
        if (sess_flow_eq(&(*pp)->flow, flow))
        {
            httgw_session_t *s = *pp;
            *pp = s->next;
            if (gw->sess_count > 0)
                gw->sess_count--;
            s->next = NULL;
            return s;
        }
        pp = &(*pp)->next;
    }
    return NULL;
}

static httgw_session_t *sess_get_or_create_internal(httgw_t *gw, const flow_key_t *flow, uint64_t ts_ms)
{
    uint32_t idx = sess_flow_hash(flow) % gw->sess_bucket_count;
    for (httgw_session_t *s = gw->sess_buckets[idx]; s; s = s->next)
    {
        if (sess_flow_eq(&s->flow, flow))
        {
            s->last_ts_ms = ts_ms;
            return s;
        }
    }

    httgw_session_t *s = (httgw_session_t *)calloc(1, sizeof(*s));
    if (!s)
        return NULL;

    s->streams[DIR_AB] = http_stream_create(&gw->stream_cfg);
    s->streams[DIR_BA] = http_stream_create(&gw->stream_cfg);
    if (!s->streams[DIR_AB] || !s->streams[DIR_BA])
    {
        sess_destroy(s);
        return NULL;
    }

    s->flow = *flow;
    s->last_ts_ms = ts_ms;
    s->next = gw->sess_buckets[idx];
    gw->sess_buckets[idx] = s;
    gw->sess_count++;
    return s;
}

static void print_preview(const uint8_t *data, uint32_t len)
{
    uint32_t i;
    uint32_t n = len < 48 ? len : 48;
    putchar('"');
    for (i = 0; i < n; i++)
    {
        uint8_t c = data[i];
        if (c >= 32 && c <= 126)
        {
            putchar((int)c);
        }
        else
        {
            putchar('.');
        }
    }
    if (len > n)
        printf("...");
    putchar('"');
}

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

static void normalize_flow(
    uint32_t sip, uint16_t sport,
    uint32_t dip, uint16_t dport,
    flow_key_t *key, tcp_dir_t *dir)
{
    int c = endpoint_cmp(sip, sport, dip, dport);
    memset(key, 0, sizeof(*key));
    key->proto = 6;
    if (c <= 0)
    {
        key->src_ip = sip;
        key->src_port = sport;
        key->dst_ip = dip;
        key->dst_port = dport;
        *dir = DIR_AB;
    }
    else
    {
        key->src_ip = dip;
        key->src_port = dport;
        key->dst_ip = sip;
        key->dst_port = sport;
        *dir = DIR_BA;
    }
}

static int parse_ipv4_tcp_payload(
    const uint8_t *pkt, uint32_t caplen,
    flow_key_t *flow, tcp_dir_t *dir,
    uint32_t *seq, uint32_t *ack, uint8_t *flags,
    const uint8_t **payload, uint32_t *payload_len,
    uint16_t *window, uint8_t *win_scale)
{
    const uint8_t *p = pkt;
    uint32_t n = caplen;
    uint16_t eth_type;
    uint32_t ip_hl;
    uint32_t ip_len;
    uint32_t tcp_hl;
    uint16_t total_len;
    uint8_t proto;
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;

    if (n < 14)
        return 0;
    eth_type = (uint16_t)((p[12] << 8) | p[13]);
    p += 14;
    n -= 14;

    if (eth_type == 0x8100 || eth_type == 0x88A8)
    {
        if (n < 4)
            return 0;
        eth_type = (uint16_t)((p[2] << 8) | p[3]);
        p += 4;
        n -= 4;
    }

    if (eth_type != 0x0800)
        return 0;
    if (n < 20)
        return 0;
    if ((p[0] >> 4) != 4)
        return 0;

    ip_hl = (uint32_t)(p[0] & 0x0F) * 4U;
    if (ip_hl < 20 || n < ip_hl)
        return 0;

    total_len = (uint16_t)((p[2] << 8) | p[3]);
    if (total_len < ip_hl || n < total_len)
        return 0;

    proto = p[9];
    if (proto != 6)
        return 0;

    sip = (uint32_t)((p[12] << 24) | (p[13] << 16) | (p[14] << 8) | p[15]);
    dip = (uint32_t)((p[16] << 24) | (p[17] << 16) | (p[18] << 8) | p[19]);

    p += ip_hl;
    n = total_len - ip_hl;
    if (n < 20)
        return 0;

    sport = (uint16_t)((p[0] << 8) | p[1]);
    dport = (uint16_t)((p[2] << 8) | p[3]);
    *seq = (uint32_t)((p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7]);
    *ack = (uint32_t)((p[8] << 24) | (p[9] << 16) | (p[10] << 8) | p[11]);
    tcp_hl = (uint32_t)((p[12] >> 4) & 0x0F) * 4U;
    if (tcp_hl < 20 || n < tcp_hl)
        return 0;
    *flags = p[13];
    if (window)
        *window = (uint16_t)((p[14] << 8) | p[15]);
    if (win_scale)
        *win_scale = 0;

    ip_len = total_len;
    if (ip_len < ip_hl + tcp_hl)
        return 0;

    *payload_len = ip_len - ip_hl - tcp_hl;
    *payload = p + tcp_hl;

    if (win_scale && (p[13] & TCP_SYN) && tcp_hl > 20)
    {
        uint32_t opt_len = tcp_hl - 20;
        const uint8_t *opt = p + 20;
        uint32_t i = 0;
        while (i < opt_len)
        {
            uint8_t kind = opt[i];
            if (kind == 0)
                break;
            if (kind == 1)
            {
                i++;
                continue;
            }
            if (i + 1 >= opt_len)
                break;
            uint8_t len = opt[i + 1];
            if (len < 2 || i + len > opt_len)
                break;
            if (kind == 3 && len == 3)
            {
                *win_scale = opt[i + 2];
                break;
            }
            i += len;
        }
    }

    normalize_flow(sip, sport, dip, dport, flow, dir);
    return 1;
}

static uint32_t tcp_next_seq(uint32_t seq, uint32_t payload_len, uint8_t flags)
{
    uint32_t next = seq + payload_len;

    if (flags & TCP_SYN)
        next++;
    if (flags & TCP_FIN)
        next++;
    return next;
}

/**
 * @brief HTTP 메시지 파싱 및 콜백 호출함수
 *
 * on_stream_data에서 flow/dir 전달받도록 수정하여 해당 방향 스트림에서 메시지 파싱하도록 변경
 * @param gw http 게이트웨이 컨텍스트
 * @param flow HTTP 메시지가 속한 플로우 정보
 * @param dir HTTP 메시지가 속한 방향 (DIR_AB 또는 DIR_BA)
 */
static void drain_http(httgw_t *gw, const flow_key_t *flow, tcp_dir_t dir)
{
    httgw_session_t *sess = sess_find(gw, flow);
    http_stream_t *s;
    http_message_t msg;

    if (!sess)
        return;
    s = sess->streams[dir];
    if (!s)
        return;

    while (http_stream_poll_message(s, &msg) == HTTP_STREAM_OK)
    {
        fprintf(stderr,
                "[HTTP] polled is_request=%d uri=%s body_len=%zu\n",
                msg.is_request,
                msg.uri,
                msg.body_len);
            
        gw->stats.http_msgs++;
        if (msg.is_request)
        {
            gw->stats.reqs++;
            if (gw->cbs.on_request)
            {
                const char *q = NULL;
                size_t q_len = 0;
                (void)httgw_extract_query(&msg, &q, &q_len);
                gw->cbs.on_request(flow, dir, &msg, q, q_len, gw->user);
            }
        }
        http_message_free(&msg);
    }
}
// MODIFY: on_stream_data에서 drain_http 호출 시 flow/dir 전달함
static void on_stream_data(
    const flow_key_t *flow,
    tcp_dir_t dir,
    const uint8_t *data,
    uint32_t len,
    uint32_t seq_start,
    void *user)
{
    httgw_t *gw = (httgw_t *)user;
    httgw_session_t *sess;
    http_stream_t *stream;
    http_stream_rc_t rc;

    sess = sess_find(gw, flow);
    if (!sess)
    {
        if (gw->cbs.on_error)
            gw->cbs.on_error("on_stream_data", "missing httgw session", gw->user);
        return;
    }
    stream = sess->streams[dir];
    if (!stream)
    {
        if (gw->cbs.on_error)
            gw->cbs.on_error("on_stream_data", "missing http stream", gw->user);
        return;
    }

    if (gw->verbose)
    {
        char sip[32], dip[32];
        snprintf(sip, sizeof(sip), "%u.%u.%u.%u",
                 (flow->src_ip >> 24) & 0xFF, (flow->src_ip >> 16) & 0xFF,
                 (flow->src_ip >> 8) & 0xFF, flow->src_ip & 0xFF);
        snprintf(dip, sizeof(dip), "%u.%u.%u.%u",
                 (flow->dst_ip >> 24) & 0xFF, (flow->dst_ip >> 16) & 0xFF,
                 (flow->dst_ip >> 8) & 0xFF, flow->dst_ip & 0xFF);
        printf("[REASM] dir=%s flow=%s:%u -> %s:%u seq_start=%u len=%u preview=",
               (dir == DIR_AB ? "Client->Server" : "Server->Client"),
               sip, flow->src_port, dip, flow->dst_port, seq_start, len);
        print_preview(data, len);
        putchar('\n');
    }

    rc = http_stream_feed(stream, data, len);
    if (rc != HTTP_STREAM_OK)
    {
        gw->stats.parse_errs++;
        if (gw->cbs.on_error)
        {
            gw->cbs.on_error("http_stream_feed", http_stream_last_error(stream), gw->user);
        }
        http_stream_reset(stream);
        return;
    }
    drain_http(gw, flow, dir); // MODIFY
}

httgw_t *httgw_create(const httgw_cfg_t *cfg, const httgw_callbacks_t *cbs, void *user)
{
    httgw_t *gw = NULL;

    gw = (httgw_t *)calloc(1, sizeof(*gw));
    if (!gw)
        return NULL;

    gw->user = user;
    if (cbs)
    {
        gw->cbs = *cbs;
    }
    else
    {
        memset(&gw->cbs, 0, sizeof(gw->cbs));
    }
    gw->verbose = cfg ? (cfg->verbose ? 1 : 0) : 0;

    memset(&gw->stream_cfg, 0, sizeof(gw->stream_cfg));
    gw->stream_cfg.max_buffer_bytes = cfg && cfg->max_buffer_bytes ? cfg->max_buffer_bytes : (12U * 1024U * 1024U);
    gw->stream_cfg.max_body_bytes = cfg && cfg->max_body_bytes ? cfg->max_body_bytes : (12U * 1024U * 1024U);

    gw->reasm = reasm_create(8192, on_stream_data, gw);
    if (!gw->reasm)
    {
        httgw_destroy(gw);
        return NULL;
    }
    gw->sess_bucket_count = HTTGW_SESS_BUCKETS;
    gw->sess_buckets = (httgw_session_t **)calloc(gw->sess_bucket_count, sizeof(*gw->sess_buckets));
    if (!gw->sess_buckets)
    {
        httgw_destroy(gw);
        return NULL;
    }

    if (cfg)
    {
        reasm_set_mode(gw->reasm, cfg->reasm_mode);
    }
    else
    {
        reasm_set_mode(gw->reasm, REASM_MODE_LATE_START);
    }
    gw->mode = cfg ? cfg->mode : HTTGW_MODE_SNIFF;

    return gw;
}

void httgw_destroy(httgw_t *gw)
{
    if (!gw)
        return;
    if (gw->sess_buckets)
    {
        for (uint32_t i = 0; i < gw->sess_bucket_count; i++)
        {
            httgw_session_t *s = gw->sess_buckets[i];
            while (s)
            {
                httgw_session_t *n = s->next;
                sess_destroy(s);
                s = n;
            }
            gw->sess_buckets[i] = NULL;
        }
        free(gw->sess_buckets);
        gw->sess_buckets = NULL;
    }
    gw->sess_count = 0;
    if (gw->reasm)
        reasm_destroy(gw->reasm);
    free(gw);
}

int httgw_set_mode(httgw_t *gw, httgw_mode_t mode)
{
    if (!gw)
        return -1;
    gw->mode = mode;
    return 0;
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
int httgw_ingest_packet(httgw_t *gw, const uint8_t *pkt, uint32_t caplen, uint64_t ts_ms)
{
    flow_key_t flow;
    tcp_dir_t dir;
    uint32_t seq = 0;
    uint32_t ack = 0;
    uint8_t flags = 0;
    const uint8_t *payload = NULL;
    uint32_t payload_len = 0;
    uint32_t next_seq = 0;
    uint16_t window = 0;
    uint8_t win_scale = 0;
    int rc;
    httgw_session_t *sess;

    if (!gw || (!pkt && caplen))
        return -1;

    if (!parse_ipv4_tcp_payload(pkt, caplen, &flow, &dir, &seq, &ack, &flags, &payload, &payload_len, &window, &win_scale))
    {
        return 0;
    }

    next_seq = tcp_next_seq(seq, payload_len, flags);

    if (flags & TCP_RST)
    {
        sess = sess_remove_internal(gw, &flow);
        if (sess)
            sess_destroy(sess);

        rc = reasm_ingest(gw->reasm, &flow, dir, seq, flags, payload, payload_len, ts_ms);
        if (rc != 0)
        {
            gw->stats.reasm_errs++;
            if (gw->cbs.on_error)
            {
                char buf[64];
                snprintf(buf, sizeof(buf), "rc=%d", rc);
                gw->cbs.on_error("reasm_ingest", buf, gw->user);
            }
            return -2;
        }
        return 1;
    }

    sess = sess_get_or_create_internal(gw, &flow, ts_ms);
    if (!sess)
        return -3;
    if (dir == DIR_AB)
    {
        if (!sess->seen_ab)
            sess->base_seq_ab = seq;
        sess->last_seq_ab = seq;
        sess->next_seq_ab = next_seq;
        if (!sess->seen_ab || SEQ_GEQ(ack, sess->last_ack_ab))
        {
            sess->last_ack_ab = ack;
            sess->win_ab = window;
        }
        if (flags & TCP_SYN)
            sess->win_scale_ab = win_scale;
        sess->seen_ab = 1;
        if (flags & TCP_FIN)
            sess->fin_seen_ab = 1;
    }
    else
    {
        if (!sess->seen_ba)
            sess->base_seq_ba = seq;
        sess->last_seq_ba = seq;
        sess->next_seq_ba = next_seq;
        if (!sess->seen_ba || SEQ_GEQ(ack, sess->last_ack_ba))
        {
            sess->last_ack_ba = ack;
            sess->win_ba = window;
        }
        if (flags & TCP_SYN)
            sess->win_scale_ba = win_scale;
        sess->seen_ba = 1;
        if (flags & TCP_FIN)
            sess->fin_seen_ba = 1;
    }
    sess->last_ts_ms = ts_ms;

    rc = reasm_ingest(gw->reasm, &flow, dir, seq, flags, payload, payload_len, ts_ms);
    if (rc != 0)
    {
        httgw_session_t *stale = sess_remove_internal(gw, &flow);
        gw->stats.reasm_errs++;
        if (stale)
            sess_destroy(stale);
        if (gw->cbs.on_error)
        {
            char buf[64];
            snprintf(buf, sizeof(buf), "rc=%d", rc);
            gw->cbs.on_error("reasm_ingest", buf, gw->user);
        }
        return -2;
    }
    return 1;
}

void httgw_gc(httgw_t *gw, uint64_t now_ms)
{
    if (!gw || !gw->reasm)
        return;
    reasm_gc(gw->reasm, now_ms);
    for (uint32_t i = 0; i < gw->sess_bucket_count; i++)
    {
        httgw_session_t **pp = &gw->sess_buckets[i];
        while (*pp)
        {
            httgw_session_t *s = *pp;
            if (now_ms - s->last_ts_ms > HTTGW_SESS_TIMEOUT_MS)
            {
                *pp = s->next;
                sess_destroy(s);
                if (gw->sess_count > 0)
                    gw->sess_count--;
                continue;
            }
            pp = &(*pp)->next;
        }
    }
}

const httgw_stats_t *httgw_stats(const httgw_t *gw)
{
    if (!gw)
        return NULL;
    return &gw->stats;
}

int httgw_get_session_snapshot(const httgw_t *gw, const flow_key_t *flow, httgw_sess_snapshot_t *out)
{
    if (!gw || !flow || !out)
        return -1;
    httgw_session_t *sess = sess_find(gw, flow);
    if (!sess)
        return -2;
    memset(out, 0, sizeof(*out));
    out->base_seq_ab = sess->base_seq_ab;
    out->base_seq_ba = sess->base_seq_ba;
    out->last_ack_ab = sess->last_ack_ab;
    out->next_seq_ab = sess->next_seq_ab;
    out->last_ack_ba = sess->last_ack_ba;
    out->next_seq_ba = sess->next_seq_ba;
    out->win_ab = sess->win_ab;
    out->win_ba = sess->win_ba;
    out->win_scale_ab = sess->win_scale_ab;
    out->win_scale_ba = sess->win_scale_ba;
    out->seen_ab = sess->seen_ab;
    out->seen_ba = sess->seen_ba;
    return 0;
}

static int ci_eq(const uint8_t *a, size_t an, const char *b)
{
    size_t i;
    size_t bn = strlen(b);
    if (an != bn)
        return 0;
    for (i = 0; i < an; i++)
    {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i]))
            return 0;
    }
    return 1;
}

int httgw_header_get(
    const http_message_t *msg,
    const char *name,
    const uint8_t **value,
    size_t *value_len)
{
    const uint8_t *p;
    size_t len;
    size_t pos = 0;
    size_t line_end;

    if (!msg || !name || !value || !value_len)
        return 0;
    if (!msg->headers_raw || msg->headers_raw_len == 0)
        return 0;

    p = msg->headers_raw;
    len = msg->headers_raw_len;

    while (pos + 1 < len)
    {
        if (p[pos] == '\r' && p[pos + 1] == '\n')
        {
            pos += 2;
            break;
        }
        pos++;
    }

    while (pos < len)
    {
        size_t i;
        const uint8_t *line = p + pos;
        size_t line_len = 0;
        const uint8_t *colon;
        const uint8_t *val;
        const uint8_t *val_end;

        for (i = pos; i + 1 < len; i++)
        {
            if (p[i] == '\r' && p[i + 1] == '\n')
            {
                line_end = i;
                line_len = line_end - pos;
                break;
            }
        }
        if (line_len == 0)
            break;

        colon = (const uint8_t *)memchr(line, ':', line_len);
        if (colon)
        {
            size_t name_len = (size_t)(colon - line);
            if (ci_eq(line, name_len, name))
            {
                val = colon + 1;
                while (val < line + line_len && (*val == ' ' || *val == '\t'))
                    val++;
                val_end = line + line_len;
                while (val_end > val && ((*(val_end - 1) == ' ') || (*(val_end - 1) == '\t')))
                    val_end--;
                *value = val;
                *value_len = (size_t)(val_end - val);
                return 1;
            }
        }

        pos = line_end + 2;
    }

    return 0;
}

int httgw_extract_query(const http_message_t *msg, const char **q, size_t *q_len)
{
    const char *uri;
    const char *qm;
    const char *hash;
    size_t len;

    if (!msg || !q || !q_len)
        return 0;
    if (!msg->is_request)
        return 0;

    uri = msg->uri;
    if (!uri || uri[0] == '\0')
        return 0;

    qm = strchr(uri, '?');
    if (!qm || *(qm + 1) == '\0')
        return 0;

    hash = strchr(qm + 1, '#');
    if (hash)
    {
        len = (size_t)(hash - (qm + 1));
    }
    else
    {
        len = strlen(qm + 1);
    }

    if (len == 0)
        return 0;
    *q = qm + 1;
    *q_len = len;
    return 1;
}

static int HTTGW_UNUSED iphash_init(ip_hash_t *h, size_t nbuckets)
{
    if (!h || nbuckets == 0)
        return -1; // h=0, 버킷이 0
    h->buckets = (ip_node_t **)calloc(nbuckets, sizeof(ip_node_t *));
    if (!h->buckets)
        return -1;
    return 0;
}

static void HTTGW_UNUSED iphash_destroy(ip_hash_t *h)
{
    if (!h || !h->buckets)
        return;
    for (size_t i = 0; i < h->nbuckets; i++)
    {
        ip_node_t *p = h->buckets[i];
        while (p)
        {
            ip_node_t *n = p->next;
            free(p);
            p = n;
        }
    }
    free(h->buckets);
    h->buckets = NULL;
    h->nbuckets = 0;
}

static int HTTGW_UNUSED iphash_insert(ip_hash_t *h, uint32_t ip)
{
    if (!h || !h->buckets)
        return -1;
    size_t idx = ip_hash_fn(ip) % h->nbuckets;
    // 중복체크
    for (ip_node_t *p = h->buckets[idx]; p; p = p->next)
    {
        if (p->ip == ip)
            return 0;
    }
    // 메모리에 할당하고 1반환함
    ip_node_t *n = (ip_node_t *)calloc(1, sizeof(*n));
    if (!n)
        return -1;
    n->ip = ip;
    n->next = h->buckets[idx];
    h->buckets[idx] = n;
    return 1;
}

static int HTTGW_UNUSED iphash_delete(ip_hash_t *h, uint32_t ip)
{
    if (!h || !h->buckets)
        return -1;
    size_t idx = ip_hash_fn(ip) % h->nbuckets;

    ip_node_t **pp = &h->buckets[idx];
    while (*pp)
    {
        if ((*pp)->ip == ip)
        {
            ip_node_t *del = *pp;
            *pp = del->next;
            free(del);
            return 1;
        }
        pp = &(*pp)->next;
    }
    return 0;
}
/* 헬퍼 체크섬*/
static uint16_t checksum16(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;

    uint32_t sum = 0;

    while (len > 1)
    {
        sum += (uint16_t)((p[0] << 8) | p[1]);
        p = p + 2;
        len = len - 2;
    }
    if (len)
        sum += (uint16_t)(p[0] << 8);
    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum);
}

static uint16_t tcp_checksum(uint32_t src_be, uint32_t dst_be, const uint8_t *tcp, size_t tcp_len)
{
    uint32_t sum = 0;
    const uint8_t *p;
    size_t len;

    p = (const uint8_t *)&src_be;
    sum += (uint16_t)((p[0] << 8) | p[1]);
    sum += (uint16_t)((p[2] << 8) | p[3]);

    p = (const uint8_t *)&dst_be;
    sum += (uint16_t)((p[0] << 8) | p[1]);
    sum += (uint16_t)((p[2] << 8) | p[3]);

    sum += IPPROTO_TCP;
    sum += (uint16_t)tcp_len;

    p = tcp;
    len = tcp_len;
    while (len > 1)
    {
        sum += (uint16_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }
    if (len)
    {
        sum += (uint16_t)(p[0] << 8);
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

// Layer 3 전송 함수, 레이어 3 = IP 계층, IP 헤더부터 시작하는 패킷을 raw socket으로 보내라는 함수이다.
int tx_send_l3(void *ctx, const uint8_t *buf, size_t len)
{
    tx_ctx_t *tx = (tx_ctx_t *)ctx;
    struct sockaddr_in dst;
    const IPHDR *ip;
    ssize_t n; // signed size type, 부호있는 크기타입 음수 가능
    // 유효성 검사 -> 송신 컨텍스트/버퍼/최소 IP 헤더 길이 확인
    if (!tx || tx->fd < 0 || !buf || len < IP_HDR_SIZE)
        return -1;
    // Raw L3 버퍼의 시작은 IPv4 헤더
    ip = (const IPHDR *)buf;

    // sendto() 목적지 주소 구조체 초기화
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = IP_DADDR(ip);

    // Raw 소켓으로 미리 구성된 IP/TCP 패킷을 그대로 전송
    n = sendto(tx->fd, buf, len, 0, (struct sockaddr *)&dst, sizeof(dst));
    // sendto는 소켓으로 데이터를 보내는 시스템 호출
    if (n < 0) // sendto 실패
        return -1;
    return (size_t)n == len ? 0 : -1;
}

int tx_ctx_init(tx_ctx_t *tx)
{
    int fd;
    int on = 1;

    if (!tx)
        return -1;
    memset(tx, 0, sizeof(*tx));

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0)
        return -1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) != 0)
    {
        close(fd);
        return -1;
    }

    tx->fd = fd;
    tx->send_l3 = tx_send_l3;
    tx->ctx = tx;
    return 0;
}

void tx_ctx_destroy(tx_ctx_t *tx)
{
    if (!tx)
        return;
    if (tx->fd >= 0)
        close(tx->fd);
    tx->fd = -1;
    tx->send_l3 = NULL;
    tx->ctx = NULL;
}

int httgw_set_tx(httgw_t *gw, tx_ctx_t *tx)
{
    if (!gw)
        return -1;
    gw->tx_ctx = tx;
    gw->tx_send_rst = tx_send_rst;
    return 0;
}

int tx_send_rst(void *tx_ctx, const flow_key_t *flow, tcp_dir_t dir, uint32_t seq, uint32_t ack)
{
    tx_ctx_t *tx = (tx_ctx_t *)tx_ctx;
    uint32_t sip, dip;     // RSt 패킷의 source IP, RST 패킷의 destination IP
    uint16_t sport, dport; // Source PORT, Destination IP

    if (!tx || !tx->send_l3 || !flow)
        return -1;

    if (dir == DIR_AB) //
    {
        sip = flow->src_ip;
        sport = flow->src_port;

        dip = flow->dst_ip;
        dport = flow->dst_port;
    }
    else
    {
        sip = flow->dst_ip;
        sport = flow->dst_port;

        dip = flow->src_ip;
        dport = flow->src_port;
    }
    uint8_t buf[IP_HDR_SIZE + TCP_HDR_SIZE];
    memset(buf, 0, sizeof(buf));

    IPHDR *ip = (IPHDR *)buf;
    TCPHDR *tcp = (TCPHDR *)(buf + sizeof(*ip));

    IP_VER(ip) = 4;
    IP_IHL(ip) = 5;
    IP_TTL_FIELD(ip) = 64;
    IP_PROTO(ip) = IPPROTO_TCP;
    IP_TOTLEN(ip) = htons((uint16_t)sizeof(buf));
    IP_SADDR(ip) = htonl(sip);
    IP_DADDR(ip) = htonl(dip);
    IP_CHECK(ip) = 0;
    IP_CHECK(ip) = checksum16(ip, sizeof(*ip));

    TCP_SPORT(tcp) = htons(sport);
    TCP_DPORT(tcp) = htons(dport);
    TCP_SEQ(tcp) = htonl(seq);
    TCP_ACK(tcp) = htonl(ack);
    TCP_DOFF(tcp) = 5;
    TCP_SET_RST(tcp);
    TCP_SET_ACK(tcp, ack != 0);
    TCP_WIN(tcp) = htons(0);
    TCP_CHECK(tcp) = 0;
    // TCP_CHECK(tcp) = tcp_checksum(IP_SADDR(ip), IP_DADDR(ip), (const uint8_t *)tcp, sizeof(*tcp));
    TCP_CHECK(tcp) = htons(tcp_checksum(IP_SADDR(ip), IP_DADDR(ip), (const uint8_t *)tcp, sizeof(*tcp)));

    return tx->send_l3(tx->ctx, buf, sizeof(buf));
}

int httgw_request_rst_with_snapshot(
    httgw_t *gw,
    const flow_key_t *flow,
    tcp_dir_t dir,
    const httgw_sess_snapshot_t *snap)
{
    httgw_session_t *sess;
    uint32_t seq_base = 0;
    uint32_t ack = 0;
    uint32_t win = 0;
    int sent_ok = 0;
    int last_err = -1;

    if (!gw || !flow)
        return -1;
    if (!gw->tx_send_rst)
        return -4;

    sess = sess_find(gw, flow);
    if (!sess)
        return -2;
    if (dir == DIR_AB && sess->rst_sent_ab)
        return 1;
    if (dir == DIR_BA && sess->rst_sent_ba)
        return 1;

    if (snap)
    {
        if (!snap->seen_ab || !snap->seen_ba)
            return -3;
        if (dir == DIR_AB)
        {
            if (snap->next_seq_ab == 0 || snap->next_seq_ba == 0)
                return -3;
            seq_base = snap->next_seq_ab;
            ack = snap->next_seq_ba + HTTGW_SERVER_NEXT_BIAS;
            win = ((uint32_t)snap->win_ba) << (snap->win_scale_ba > 14 ? 14 : snap->win_scale_ba);
        }
        else
        {
            if (snap->next_seq_ab == 0 || snap->next_seq_ba == 0)
                return -3;
            seq_base = snap->next_seq_ba + HTTGW_SERVER_NEXT_BIAS;
            ack = snap->next_seq_ab;
            win = ((uint32_t)snap->win_ab) << (snap->win_scale_ab > 14 ? 14 : snap->win_scale_ab);
        }
    }
    else
    {
        if (!sess->seen_ab || !sess->seen_ba)
            return -3;
        if (dir == DIR_AB) // Client -> Server
        {
            if (sess->next_seq_ab == 0 || sess->next_seq_ba == 0)
                return -3;
            seq_base = sess->next_seq_ab;
            ack = sess->next_seq_ba + HTTGW_SERVER_NEXT_BIAS;
            win = ((uint32_t)sess->win_ba) << (sess->win_scale_ba > 14 ? 14 : sess->win_scale_ba);
        }
        else // Server -> Client
        {
            if (sess->next_seq_ab == 0 || sess->next_seq_ba == 0)
                return -3;
            seq_base = sess->next_seq_ba + HTTGW_SERVER_NEXT_BIAS;
            ack = sess->next_seq_ab;
            win = ((uint32_t)sess->win_ab) << (sess->win_scale_ab > 14 ? 14 : sess->win_scale_ab);
        }
    }
    if (win == 0)
        return -3;
    // RST 버스트 날리기, 5번 반복, HTTGW_RST_BUSRT_COUNT = 5
    for (uint32_t i = 0; i < HTTGW_RST_BURST_COUNT; i++)
    {
        uint32_t seq_off;
        // 버스트 1회이거나 윈도우가 1바이트면 분산못하므로 Base만 날리기?
        if (HTTGW_RST_BURST_COUNT == 1 || win == 1) // 둘다 seq_off=0으로 보내는 예외처리
            seq_off = 0;
        else // seq_off는 seq_base에 더할 오프셋이다.
            seq_off = (uint32_t)(((uint64_t)(win - 1) * i) / (HTTGW_RST_BURST_COUNT - 1));
        uint32_t seq_try = seq_base + seq_off;
        if (snap)
        {
            uint32_t rel_seq = seq_try;
            uint32_t rel_ack = ack;
            if (dir == DIR_AB)
            {
                rel_seq -= snap->base_seq_ab;
                rel_ack -= snap->base_seq_ba;
            }
            else
            {
                rel_seq -= snap->base_seq_ba;
                rel_ack -= snap->base_seq_ab;
            }
            fprintf(stderr, "[TCP] RST try dir=%s i=%u rel_seq=%u rel_ack=%u win=%u\n",
                    dir == DIR_AB ? "AB" : "BA", i, rel_seq, rel_ack, win);
        }
        else
        {
            fprintf(stderr, "[TCP] RST try dir=%s i=%u seq=%u ack=%u win=%u\n",
                    dir == DIR_AB ? "AB" : "BA", i, seq_try, ack, win);
        }
        // 계산된 seq/ack로 RST 1회 전송
        int rc = gw->tx_send_rst(gw->tx_ctx, flow, dir, seq_try, ack);
        if (rc == 0)
            sent_ok++;
        else
            last_err = rc;
    }

    if (sent_ok == 5)
    {
        if (dir == DIR_AB)
            sess->rst_sent_ab = 1;
        else
            sess->rst_sent_ba = 1;
        return 0;
    }
    return last_err;
}

int httgw_request_rst(httgw_t *gw, const flow_key_t *flow, tcp_dir_t dir)
{
    return httgw_request_rst_with_snapshot(gw, flow, dir, NULL);
}

int sess_get_or_create(httgw_t *gw, const flow_key_t flow, uint64_t ts_ms)
{
    if (!gw)
        return -1;
    return sess_get_or_create_internal(gw, &flow, ts_ms) ? 1 : 0;
}

int sess_lookup(const httgw_t *gw, const flow_key_t flow)
{
    if (!gw)
        return 0;
    return sess_find(gw, &flow) ? 1 : 0;
}

void sess_gc(httgw_t *gw, uint64_t ts_ms)
{
    httgw_gc(gw, ts_ms);
}

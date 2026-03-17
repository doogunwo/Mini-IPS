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
static char *build_pipeline_http_request(size_t uri_pad_len, size_t *out_len) {
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
                strlen(uri_suffix) + strlen(hdr_b) + (size_t)n +
                strlen(hdr_c) + strlen(body);
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
static int ingest_packet_via_ring(packet_ring_t *ring, httgw_t *gw,
                                  const uint8_t *pkt, uint32_t pkt_len,
                                  uint64_t ts_ms) {
    uint8_t  out[PACKET_MAX_BYTES];
    uint32_t out_len = 0;
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

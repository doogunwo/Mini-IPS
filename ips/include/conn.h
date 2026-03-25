/**
 * @file conn.h
 * @brief TPROXY 인라인 연결 상태 공개 인터페이스
 */
#ifndef CONN_H
#define CONN_H

#include <stddef.h>
#include <stdint.h>

/** worker가 소유하는 단일 인라인 연결 상태 핸들 */
typedef struct conn conn_t;

/** 연결 상태를 만들 때 쓰는 초기 설정 */
typedef struct {
    int      client_fd;      /**< 클라이언트 소켓 */
    int      upstream_fd;    /**< 원 서버 소켓 */
    uint32_t orig_dst_ip;    /**< 원래 목적지 IPv4 */
    uint16_t orig_dst_port;  /**< 원래 목적지 포트 */
    uint32_t client_ip;      /**< 클라이언트 IPv4 */
    uint16_t client_port;    /**< 클라이언트 포트 */
} conn_cfg_t;

/** 연결 상태 객체 생성 */
conn_t *conn_create(const conn_cfg_t *cfg);

/** 연결 상태 객체 해제 */
void conn_destroy(conn_t *c);

#endif

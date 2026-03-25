#ifndef TPROXY_H
#define TPROXY_H

#include <stdint.h>
#include <netinet/in.h>

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif

/** TPROXY listener 생성 설정 */
typedef struct {
    const char *bind_ip;   /**< bind할 로컬 주소 */
    uint16_t    bind_port; /**< bind할 포트 */
    int         backlog;   /**< listen backlog */
} tproxy_cfg_t;

/** TPROXY listener 객체 */
typedef struct {
    int listen_fd;
    char bind_ip[INET_ADDRSTRLEN];
    uint16_t bind_port;
    int backlog;
} tproxy_t;

/** TPROXY listener 생성 */
tproxy_t *tproxy_create(const tproxy_cfg_t *cfg);

/** TPROXY listener 해제 */
void tproxy_destroy(tproxy_t *tp);

#endif /* TPROXY_H */
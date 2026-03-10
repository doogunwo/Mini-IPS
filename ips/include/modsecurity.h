/**
 * @file modsecurity.h
 * @brief 모드시큐리티 C 래퍼
 */
#ifndef MODSECURITY_H
#define MODSECURITY_H

#ifdef __cplusplus
extern "C"{
#endif


typedef struct ms_engine ms_engine_t;
typedef struct {
    ms_engine_t *engine;
    const char *client_ip;
    int client_port;
    const char *server_ip;
    int server_port;
    const char *method;
    const char *uri;
    const char *http_version;
    const char *headers;
    const unsigned char *body;
    unsigned int body_len;
} ms_context_t;

ms_engine_t *ms_engine_create(const char *rules_path);



void ms_engine_destroy(ms_engine_t *engine);

int ms_engine_inspect_request(ms_context_t *http);
const char *ms_engine_last_error(ms_engine_t *engine);

#ifdef __cplusplus
}
#endif

#endif

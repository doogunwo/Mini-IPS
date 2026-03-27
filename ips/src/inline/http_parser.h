#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct http_message {
    int type;  // req = 1, res = 0

    char *method;
    char *uri; //탐지함
 
    int       status_code; 
    char     *headers; //탐지함
    long long content_length;

    uint8_t *body;//탐지함
    size_t   body_len;
} http_message_t;

int http_parser_try(const uint8_t *data, size_t len, http_message_t *out);

int http_parser_free(http_message_t *msg);

#pragma once

#include <stddef.h>

char *app_render_block_page(const char *template_path, const char *event_id,
                            const char *timestamp, const char *client_ip);
char *app_build_block_http_response(const char *html_body, size_t *out_len);

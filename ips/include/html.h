#ifndef HTML_H
#define HTML_H

#include <stddef.h>

/**
 * @brief 차단 페이지 템플릿을 렌더링한다.
 *
 * 템플릿 토큰을 이벤트 정보로 치환해 최종 HTML body를 생성한다.
 */
char *app_render_block_page(const char *template_path, const char *event_id,
                            const char *timestamp, const char *client_ip);
/** 렌더링된 HTML body를 403 응답으로 감싼다. */
char *app_build_block_http_response(const char *html_body, size_t *out_len);

#endif

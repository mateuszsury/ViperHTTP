#ifndef VHTTP_CORS_H
#define VHTTP_CORS_H

#include <stddef.h>
#include <stdint.h>

#include "vhttp_config.h"
#include "vhttp_parser.h"

typedef struct {
    uint8_t enabled;
    uint8_t allow_credentials;
    uint8_t allow_origin_any;
    uint8_t allow_methods_any;
    uint8_t allow_headers_any;
    uint32_t max_age;
    size_t origin_count;
    char origins[VHTTP_CORS_MAX_ORIGINS][VHTTP_CORS_MAX_ORIGIN_LEN];
    char allow_methods[VHTTP_CORS_MAX_METHODS_LEN];
    char allow_headers[VHTTP_CORS_MAX_HEADERS_LEN];
    char expose_headers[VHTTP_CORS_MAX_EXPOSE_LEN];
} vhttp_cors_config_t;

void vhttp_cors_reset(void);
void vhttp_cors_configure(const vhttp_cors_config_t *cfg);
int vhttp_cors_enabled(void);
int vhttp_cors_get_origin(const vhttp_parsed_request_t *req, const char **out, size_t *out_len);
int vhttp_cors_origin_allowed(const char *origin, size_t origin_len);
int vhttp_cors_is_preflight(uint8_t method, const vhttp_parsed_request_t *req);
size_t vhttp_cors_build_headers(
    char *dst,
    size_t dst_len,
    const vhttp_parsed_request_t *req,
    const char *origin,
    size_t origin_len,
    int preflight
);

#endif // VHTTP_CORS_H

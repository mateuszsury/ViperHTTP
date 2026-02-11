#ifndef VHTTP_PARSER_H
#define VHTTP_PARSER_H

#include <stddef.h>
#include <stdint.h>

#include "vhttp_config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *ptr;
    uint16_t len;
} vhttp_slice_t;

typedef struct {
    vhttp_slice_t key;
    vhttp_slice_t value;
    uint8_t has_value;
} vhttp_kv_t;

typedef struct {
    const char *name;
    uint8_t name_len;
    const char *value;
    uint16_t value_len;
} vhttp_header_t;

typedef struct {
    vhttp_slice_t method;
    vhttp_slice_t uri;
    vhttp_slice_t path;
    vhttp_slice_t query;

    vhttp_header_t headers[VHTTP_MAX_HEADERS];
    uint8_t num_headers;

    vhttp_kv_t query_params[VHTTP_MAX_QUERY_PARAMS];
    uint8_t num_query_params;

    const char *body;
    uint32_t body_len;
    uint32_t total_len;

    uint32_t content_length;
    uint8_t is_chunked;
    uint8_t is_websocket;
} vhttp_parsed_request_t;

typedef enum {
    VHTTP_PARSE_OK = 0,
    VHTTP_PARSE_INCOMPLETE,
    VHTTP_PARSE_INVALID,
    VHTTP_PARSE_TOO_LARGE,
    VHTTP_PARSE_UNSUPPORTED
} vhttp_parse_result_t;

vhttp_parse_result_t vhttp_parse_request(
    const char *buf,
    size_t len,
    vhttp_parsed_request_t *out
);

#ifdef __cplusplus
}
#endif

#endif // VHTTP_PARSER_H

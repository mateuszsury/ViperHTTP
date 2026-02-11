#ifndef VHTTP_ROUTER_H
#define VHTTP_ROUTER_H

#include <stddef.h>
#include <stdint.h>

#include "vhttp_config.h"
#include "vhttp_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VHTTP_NODE_NONE 0xFFFFu

typedef enum {
    VHTTP_PARAM_NONE = 0,
    VHTTP_PARAM_STR,
    VHTTP_PARAM_INT,
    VHTTP_PARAM_FLOAT,
    VHTTP_PARAM_PATH,
} vhttp_param_type_t;

typedef enum {
    VHTTP_METHOD_GET = 0,
    VHTTP_METHOD_POST,
    VHTTP_METHOD_PUT,
    VHTTP_METHOD_PATCH,
    VHTTP_METHOD_DELETE,
    VHTTP_METHOD_OPTIONS,
    VHTTP_METHOD_HEAD,
    VHTTP_METHOD_WS,
    VHTTP_METHOD_MAX
} vhttp_method_t;

typedef enum {
    VHTTP_ROUTER_OK = 0,
    VHTTP_ROUTER_NOT_FOUND,
    VHTTP_ROUTER_ERR_INVALID,
    VHTTP_ROUTER_ERR_CONFLICT,
    VHTTP_ROUTER_ERR_FULL,
    VHTTP_ROUTER_ERR_UNSUPPORTED,
    VHTTP_ROUTER_ERR_TOO_LARGE
} vhttp_router_result_t;

typedef struct {
    uint16_t handler_id;
    uint16_t dep_chain_id;
    uint16_t expected_status;
} vhttp_route_target_t;

typedef struct {
    vhttp_slice_t name;
    vhttp_slice_t value;
    vhttp_param_type_t type;
} vhttp_path_param_t;

typedef struct {
    vhttp_route_target_t target;
    vhttp_path_param_t params[VHTTP_MAX_PATH_PARAMS];
    uint8_t num_params;
} vhttp_match_t;

typedef struct {
    char segment[VHTTP_MAX_SEGMENT_LEN];
    uint8_t segment_len;

    vhttp_param_type_t param_type;
    char param_name[VHTTP_MAX_PARAM_NAME];
    uint8_t param_name_len;
    uint16_t first_static_child_edge;

    uint16_t param_child;
    uint16_t path_child;

    vhttp_route_target_t handlers[VHTTP_METHOD_MAX];
    uint8_t has_handler[VHTTP_METHOD_MAX];
} vhttp_trie_node_t;

typedef struct {
    uint16_t child_idx;
    uint16_t next_edge;
} vhttp_child_edge_t;

typedef struct {
    uint32_t magic;
    vhttp_trie_node_t *nodes;
    vhttp_child_edge_t *edges;
    uint16_t node_count;
    uint16_t edge_count;
    uint16_t route_count;
    uint16_t node_capacity;
    uint16_t edge_capacity;
    uint16_t route_capacity;
    uint8_t storage_in_psram;
} vhttp_router_t;

void vhttp_router_init(vhttp_router_t *router);
void vhttp_router_deinit(vhttp_router_t *router);
int vhttp_router_is_ready(const vhttp_router_t *router);

vhttp_router_result_t vhttp_router_add(
    vhttp_router_t *router,
    const char *method,
    size_t method_len,
    const char *pattern,
    size_t pattern_len,
    vhttp_route_target_t target
);

vhttp_router_result_t vhttp_router_match(
    const vhttp_router_t *router,
    const char *method,
    size_t method_len,
    vhttp_slice_t path,
    vhttp_match_t *out
);

#ifdef __cplusplus
}
#endif

#endif // VHTTP_ROUTER_H

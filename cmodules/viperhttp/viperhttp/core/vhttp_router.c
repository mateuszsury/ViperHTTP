#include "vhttp_router.h"

#include <stdlib.h>
#include <string.h>

#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
#include "esp_heap_caps.h"
#endif

typedef struct {
    uint8_t is_param;
    vhttp_param_type_t param_type;
    char param_name[VHTTP_MAX_PARAM_NAME];
    uint8_t param_name_len;
    char literal[VHTTP_MAX_SEGMENT_LEN];
    uint8_t literal_len;
} vhttp_pattern_segment_t;

#define VHTTP_ROUTER_MAGIC 0x56525452u

static void node_init(vhttp_trie_node_t *node) {
    memset(node, 0, sizeof(*node));
    node->param_type = VHTTP_PARAM_NONE;
    node->first_static_child_edge = VHTTP_NODE_NONE;
    node->param_child = VHTTP_NODE_NONE;
    node->path_child = VHTTP_NODE_NONE;
    for (size_t i = 0; i < VHTTP_METHOD_MAX; ++i) {
        node->has_handler[i] = 0;
    }
}

static void *vhttp_router_alloc(size_t size, uint8_t *out_psram) {
#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
    void *ptr = NULL;
#if defined(MALLOC_CAP_SPIRAM)
    ptr = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (ptr) {
        if (out_psram) {
            *out_psram = 1;
        }
        return ptr;
    }
#endif
    ptr = heap_caps_malloc(size, MALLOC_CAP_8BIT);
    if (out_psram) {
        *out_psram = 0;
    }
    return ptr;
#else
    if (out_psram) {
        *out_psram = 0;
    }
    return malloc(size);
#endif
}

static void vhttp_router_free(void *ptr) {
    if (!ptr) {
        return;
    }
#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
    heap_caps_free(ptr);
#else
    free(ptr);
#endif
}

static int method_from_str(const char *method, size_t len, vhttp_method_t *out) {
    if (len == 3 && memcmp(method, "GET", 3) == 0) {
        *out = VHTTP_METHOD_GET;
        return 0;
    }
    if (len == 4 && memcmp(method, "POST", 4) == 0) {
        *out = VHTTP_METHOD_POST;
        return 0;
    }
    if (len == 3 && memcmp(method, "PUT", 3) == 0) {
        *out = VHTTP_METHOD_PUT;
        return 0;
    }
    if (len == 5 && memcmp(method, "PATCH", 5) == 0) {
        *out = VHTTP_METHOD_PATCH;
        return 0;
    }
    if (len == 6 && memcmp(method, "DELETE", 6) == 0) {
        *out = VHTTP_METHOD_DELETE;
        return 0;
    }
    if (len == 7 && memcmp(method, "OPTIONS", 7) == 0) {
        *out = VHTTP_METHOD_OPTIONS;
        return 0;
    }
    if (len == 4 && memcmp(method, "HEAD", 4) == 0) {
        *out = VHTTP_METHOD_HEAD;
        return 0;
    }
    if (len == 2 && memcmp(method, "WS", 2) == 0) {
        *out = VHTTP_METHOD_WS;
        return 0;
    }
    return -1;
}

static int is_param_name_valid(const char *ptr, size_t len) {
    if (len == 0 || len > VHTTP_MAX_PARAM_NAME) {
        return 0;
    }
    for (size_t i = 0; i < len; ++i) {
        char c = ptr[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')) {
            return 0;
        }
    }
    return 1;
}

static int parse_param_type(const char *ptr, size_t len, vhttp_param_type_t *out) {
    if (len == 3 && memcmp(ptr, "int", 3) == 0) {
        *out = VHTTP_PARAM_INT;
        return 0;
    }
    if (len == 5 && memcmp(ptr, "float", 5) == 0) {
        *out = VHTTP_PARAM_FLOAT;
        return 0;
    }
    if (len == 3 && memcmp(ptr, "str", 3) == 0) {
        *out = VHTTP_PARAM_STR;
        return 0;
    }
    if (len == 4 && memcmp(ptr, "path", 4) == 0) {
        *out = VHTTP_PARAM_PATH;
        return 0;
    }
    return -1;
}

static int next_segment(const char *path, size_t len, size_t *offset, vhttp_slice_t *seg) {
    size_t i = *offset;

    if (i == 0) {
        if (len == 0) {
            return 0;
        }
        if (path[0] == '/') {
            i = 1;
        }
    }

    if (i >= len) {
        *offset = len;
        return 0;
    }

    if (path[i] == '/') {
        return -1;
    }

    size_t start = i;
    while (i < len && path[i] != '/') {
        i++;
    }

    seg->ptr = path + start;
    seg->len = (uint16_t)(i - start);

    if (i < len) {
        i++;
    }

    *offset = i;
    return 1;
}

static vhttp_router_result_t parse_pattern_segment(
    vhttp_slice_t seg,
    uint8_t is_last,
    vhttp_pattern_segment_t *out
) {
    if (seg.len == 0) {
        return VHTTP_ROUTER_ERR_INVALID;
    }

    if (seg.ptr[0] == '{' && seg.len >= 2 && seg.ptr[seg.len - 1] == '}') {
        size_t inner_len = seg.len - 2;
        if (inner_len == 0) {
            return VHTTP_ROUTER_ERR_INVALID;
        }

        const char *inner = seg.ptr + 1;
        const char *colon = memchr(inner, ':', inner_len);
        size_t name_len = colon ? (size_t)(colon - inner) : inner_len;
        size_t type_len = colon ? (size_t)(inner_len - name_len - 1) : 0;

        if (colon && type_len == 0) {
            return VHTTP_ROUTER_ERR_INVALID;
        }

        if (!is_param_name_valid(inner, name_len)) {
            return VHTTP_ROUTER_ERR_INVALID;
        }

        vhttp_param_type_t param_type = VHTTP_PARAM_STR;
        if (colon) {
            if (parse_param_type(colon + 1, type_len, &param_type) != 0) {
                return VHTTP_ROUTER_ERR_INVALID;
            }
        }

        if (param_type == VHTTP_PARAM_PATH && !is_last) {
            return VHTTP_ROUTER_ERR_UNSUPPORTED;
        }

        out->is_param = 1;
        out->param_type = param_type;
        out->param_name_len = (uint8_t)name_len;
        memcpy(out->param_name, inner, name_len);
        out->literal_len = 0;
        return VHTTP_ROUTER_OK;
    }

    for (size_t i = 0; i < seg.len; ++i) {
        if (seg.ptr[i] == '{' || seg.ptr[i] == '}') {
            return VHTTP_ROUTER_ERR_INVALID;
        }
    }

    if (seg.len > VHTTP_MAX_SEGMENT_LEN) {
        return VHTTP_ROUTER_ERR_TOO_LARGE;
    }

    out->is_param = 0;
    out->param_type = VHTTP_PARAM_NONE;
    out->param_name_len = 0;
    out->literal_len = (uint8_t)seg.len;
    memcpy(out->literal, seg.ptr, seg.len);
    return VHTTP_ROUTER_OK;
}

static uint16_t alloc_node(vhttp_router_t *router) {
    if (!router || !router->nodes || router->node_count >= router->node_capacity) {
        return VHTTP_NODE_NONE;
    }
    uint16_t idx = router->node_count++;
    node_init(&router->nodes[idx]);
    return idx;
}

static uint16_t alloc_edge(vhttp_router_t *router) {
    if (!router || !router->edges || router->edge_count >= router->edge_capacity) {
        return VHTTP_NODE_NONE;
    }
    uint16_t idx = router->edge_count++;
    router->edges[idx].child_idx = VHTTP_NODE_NONE;
    router->edges[idx].next_edge = VHTTP_NODE_NONE;
    return idx;
}

static uint16_t find_static_child(
    const vhttp_router_t *router,
    const vhttp_trie_node_t *node,
    const char *segment,
    size_t segment_len
) {
    uint16_t edge_idx = node->first_static_child_edge;
    while (edge_idx != VHTTP_NODE_NONE) {
        if (edge_idx >= router->edge_count) {
            break;
        }
        const vhttp_child_edge_t *edge = &router->edges[edge_idx];
        uint16_t idx = edge->child_idx;
        if (idx < router->node_count) {
            const vhttp_trie_node_t *child = &router->nodes[idx];
            if (child->param_type == VHTTP_PARAM_NONE &&
                child->segment_len == segment_len &&
                (segment_len == 0 || memcmp(child->segment, segment, segment_len) == 0)) {
                return idx;
            }
        }
        edge_idx = edge->next_edge;
    }
    return VHTTP_NODE_NONE;
}

static vhttp_router_result_t ensure_storage(vhttp_router_t *router) {
    if (!router) {
        return VHTTP_ROUTER_ERR_INVALID;
    }

    uint8_t nodes_psram = 0;
    uint8_t edges_psram = 0;

    if (router->nodes) {
        vhttp_router_free(router->nodes);
        router->nodes = NULL;
    }
    if (router->edges) {
        vhttp_router_free(router->edges);
        router->edges = NULL;
    }

    router->node_capacity = VHTTP_MAX_NODES;
    router->edge_capacity = VHTTP_MAX_ROUTER_EDGES;
    router->route_capacity = VHTTP_MAX_ROUTES;

    if (router->node_capacity == 0 || router->edge_capacity == 0 || router->route_capacity == 0) {
        memset(router, 0, sizeof(*router));
        return VHTTP_ROUTER_ERR_FULL;
    }

    size_t nodes_bytes = (size_t)router->node_capacity * sizeof(vhttp_trie_node_t);
    size_t edges_bytes = (size_t)router->edge_capacity * sizeof(vhttp_child_edge_t);

    router->nodes = (vhttp_trie_node_t *)vhttp_router_alloc(nodes_bytes, &nodes_psram);
    if (!router->nodes) {
        memset(router, 0, sizeof(*router));
        return VHTTP_ROUTER_ERR_FULL;
    }

    router->edges = (vhttp_child_edge_t *)vhttp_router_alloc(edges_bytes, &edges_psram);
    if (!router->edges) {
        vhttp_router_free(router->nodes);
        memset(router, 0, sizeof(*router));
        return VHTTP_ROUTER_ERR_FULL;
    }

    router->storage_in_psram = (nodes_psram || edges_psram) ? 1u : 0u;
    return VHTTP_ROUTER_OK;
}

void vhttp_router_init(vhttp_router_t *router) {
    if (!router) {
        return;
    }

    if (router->magic != VHTTP_ROUTER_MAGIC) {
        memset(router, 0, sizeof(*router));
        router->magic = VHTTP_ROUTER_MAGIC;
    }

    if (!router->nodes || !router->edges ||
        router->node_capacity != VHTTP_MAX_NODES ||
        router->edge_capacity != VHTTP_MAX_ROUTER_EDGES ||
        router->route_capacity != VHTTP_MAX_ROUTES) {
        if (ensure_storage(router) != VHTTP_ROUTER_OK) {
            return;
        }
    }

    memset(router->nodes, 0, (size_t)router->node_capacity * sizeof(vhttp_trie_node_t));
    memset(router->edges, 0, (size_t)router->edge_capacity * sizeof(vhttp_child_edge_t));
    router->node_count = 1;
    router->edge_count = 0;
    router->route_count = 0;
    node_init(&router->nodes[0]);
    router->magic = VHTTP_ROUTER_MAGIC;
}

void vhttp_router_deinit(vhttp_router_t *router) {
    if (!router) {
        return;
    }
    if (router->nodes) {
        vhttp_router_free(router->nodes);
    }
    if (router->edges) {
        vhttp_router_free(router->edges);
    }
    memset(router, 0, sizeof(*router));
}

int vhttp_router_is_ready(const vhttp_router_t *router) {
    return router &&
           router->magic == VHTTP_ROUTER_MAGIC &&
           router->nodes &&
           router->edges &&
           router->node_capacity > 0 &&
           router->edge_capacity > 0 &&
           router->node_count > 0;
}

vhttp_router_result_t vhttp_router_add(
    vhttp_router_t *router,
    const char *method,
    size_t method_len,
    const char *pattern,
    size_t pattern_len,
    vhttp_route_target_t target
) {
    if (!router || !method || !pattern) {
        return VHTTP_ROUTER_ERR_INVALID;
    }
    if (router->magic != VHTTP_ROUTER_MAGIC || !router->nodes || !router->edges || router->node_capacity == 0) {
        return VHTTP_ROUTER_ERR_FULL;
    }

    vhttp_method_t method_idx;
    if (method_from_str(method, method_len, &method_idx) != 0) {
        return VHTTP_ROUTER_ERR_INVALID;
    }

    if (router->route_count >= router->route_capacity) {
        return VHTTP_ROUTER_ERR_FULL;
    }

    size_t offset = 0;
    uint16_t node_idx = 0;
    int segment_count = 0;

    while (1) {
        vhttp_slice_t seg = {0};
        int rc = next_segment(pattern, pattern_len, &offset, &seg);
        if (rc == 0) {
            break;
        }
        if (rc < 0) {
            return VHTTP_ROUTER_ERR_INVALID;
        }

        segment_count++;
        uint8_t is_last = (offset >= pattern_len);

        vhttp_pattern_segment_t parsed;
        memset(&parsed, 0, sizeof(parsed));
        vhttp_router_result_t pres = parse_pattern_segment(seg, is_last, &parsed);
        if (pres != VHTTP_ROUTER_OK) {
            return pres;
        }

        vhttp_trie_node_t *node = &router->nodes[node_idx];

        if (parsed.is_param) {
            if (parsed.param_type == VHTTP_PARAM_PATH) {
                if (node->param_child != VHTTP_NODE_NONE && node->param_child != node->path_child) {
                    return VHTTP_ROUTER_ERR_CONFLICT;
                }
                if (node->path_child != VHTTP_NODE_NONE) {
                    if (node->path_child >= router->node_count) {
                        return VHTTP_ROUTER_ERR_INVALID;
                    }
                    vhttp_trie_node_t *child = &router->nodes[node->path_child];
                    if (child->param_type != VHTTP_PARAM_PATH || child->param_name_len != parsed.param_name_len ||
                        memcmp(child->param_name, parsed.param_name, parsed.param_name_len) != 0) {
                        return VHTTP_ROUTER_ERR_CONFLICT;
                    }
                    node_idx = node->path_child;
                } else {
                    uint16_t child_idx = alloc_node(router);
                    if (child_idx == VHTTP_NODE_NONE) {
                        return VHTTP_ROUTER_ERR_FULL;
                    }
                    vhttp_trie_node_t *child = &router->nodes[child_idx];
                    child->param_type = VHTTP_PARAM_PATH;
                    child->param_name_len = parsed.param_name_len;
                    memcpy(child->param_name, parsed.param_name, parsed.param_name_len);
                    node->path_child = child_idx;
                    node_idx = child_idx;
                }
            } else {
                if (node->path_child != VHTTP_NODE_NONE) {
                    return VHTTP_ROUTER_ERR_CONFLICT;
                }
                if (node->param_child != VHTTP_NODE_NONE) {
                    if (node->param_child >= router->node_count) {
                        return VHTTP_ROUTER_ERR_INVALID;
                    }
                    vhttp_trie_node_t *child = &router->nodes[node->param_child];
                    if (child->param_type != parsed.param_type || child->param_name_len != parsed.param_name_len ||
                        memcmp(child->param_name, parsed.param_name, parsed.param_name_len) != 0) {
                        return VHTTP_ROUTER_ERR_CONFLICT;
                    }
                    node_idx = node->param_child;
                } else {
                    uint16_t child_idx = alloc_node(router);
                    if (child_idx == VHTTP_NODE_NONE) {
                        return VHTTP_ROUTER_ERR_FULL;
                    }
                    vhttp_trie_node_t *child = &router->nodes[child_idx];
                    child->param_type = parsed.param_type;
                    child->param_name_len = parsed.param_name_len;
                    memcpy(child->param_name, parsed.param_name, parsed.param_name_len);
                    node->param_child = child_idx;
                    node_idx = child_idx;
                }
            }
        } else {
            uint16_t child_idx = find_static_child(router, node, parsed.literal, parsed.literal_len);
            if (child_idx == VHTTP_NODE_NONE) {
                child_idx = alloc_node(router);
                if (child_idx == VHTTP_NODE_NONE) {
                    return VHTTP_ROUTER_ERR_FULL;
                }

                uint16_t edge_idx = alloc_edge(router);
                if (edge_idx == VHTTP_NODE_NONE) {
                    router->node_count--;
                    return VHTTP_ROUTER_ERR_FULL;
                }

                vhttp_trie_node_t *child = &router->nodes[child_idx];
                child->segment_len = parsed.literal_len;
                memcpy(child->segment, parsed.literal, parsed.literal_len);

                vhttp_child_edge_t *edge = &router->edges[edge_idx];
                edge->child_idx = child_idx;
                edge->next_edge = node->first_static_child_edge;
                node->first_static_child_edge = edge_idx;
            }
            node_idx = child_idx;
        }
    }

    if (segment_count == 0 && !(pattern_len == 0 || (pattern_len == 1 && pattern[0] == '/'))) {
        return VHTTP_ROUTER_ERR_INVALID;
    }

    vhttp_trie_node_t *leaf = &router->nodes[node_idx];
    if (leaf->has_handler[method_idx]) {
        return VHTTP_ROUTER_ERR_CONFLICT;
    }

    leaf->handlers[method_idx] = target;
    leaf->has_handler[method_idx] = 1;
    router->route_count++;

    return VHTTP_ROUTER_OK;
}

static int match_int(vhttp_slice_t value) {
    if (value.len == 0) {
        return 0;
    }
    size_t i = 0;
    if (value.ptr[0] == '-') {
        i = 1;
        if (i >= value.len) {
            return 0;
        }
    }
    for (; i < value.len; ++i) {
        char c = value.ptr[i];
        if (c < '0' || c > '9') {
            return 0;
        }
    }
    return 1;
}

static int match_float(vhttp_slice_t value) {
    if (value.len == 0) {
        return 0;
    }
    size_t i = 0;
    if (value.ptr[0] == '-') {
        i = 1;
        if (i >= value.len) {
            return 0;
        }
    }

    int seen_digit = 0;
    int seen_dot = 0;
    int seen_digit_after_dot = 0;

    for (; i < value.len; ++i) {
        char c = value.ptr[i];
        if (c >= '0' && c <= '9') {
            seen_digit = 1;
            if (seen_dot) {
                seen_digit_after_dot = 1;
            }
            continue;
        }
        if (c == '.' && !seen_dot) {
            if (!seen_digit) {
                return 0;
            }
            seen_dot = 1;
            continue;
        }
        return 0;
    }

    if (!seen_digit) {
        return 0;
    }
    if (seen_dot && !seen_digit_after_dot) {
        return 0;
    }
    return 1;
}

static int match_param_value(vhttp_param_type_t type, vhttp_slice_t value) {
    switch (type) {
        case VHTTP_PARAM_STR:
            return value.len > 0;
        case VHTTP_PARAM_INT:
            return match_int(value);
        case VHTTP_PARAM_FLOAT:
            return match_float(value);
        case VHTTP_PARAM_PATH:
            return value.len > 0;
        default:
            return 0;
    }
}

vhttp_router_result_t vhttp_router_match(
    const vhttp_router_t *router,
    const char *method,
    size_t method_len,
    vhttp_slice_t path,
    vhttp_match_t *out
) {
    if (!router || !method || !out) {
        return VHTTP_ROUTER_ERR_INVALID;
    }
    if (router->magic != VHTTP_ROUTER_MAGIC || !router->nodes || !router->edges || router->node_count == 0) {
        return VHTTP_ROUTER_NOT_FOUND;
    }

    vhttp_method_t method_idx;
    if (method_from_str(method, method_len, &method_idx) != 0) {
        return VHTTP_ROUTER_ERR_INVALID;
    }

    memset(out, 0, sizeof(*out));

    size_t offset = 0;
    uint16_t node_idx = 0;

    while (1) {
        vhttp_slice_t seg = {0};
        int rc = next_segment(path.ptr, path.len, &offset, &seg);
        if (rc == 0) {
            break;
        }
        if (rc < 0) {
            return VHTTP_ROUTER_ERR_INVALID;
        }

        const vhttp_trie_node_t *node = &router->nodes[node_idx];
        uint16_t child_idx = find_static_child(router, node, seg.ptr, seg.len);
        if (child_idx != VHTTP_NODE_NONE) {
            node_idx = child_idx;
            continue;
        }

        if (node->param_child != VHTTP_NODE_NONE) {
            if (node->param_child >= router->node_count) {
                return VHTTP_ROUTER_NOT_FOUND;
            }
            const vhttp_trie_node_t *child = &router->nodes[node->param_child];
            if (!match_param_value(child->param_type, seg)) {
                return VHTTP_ROUTER_NOT_FOUND;
            }
            if (out->num_params >= VHTTP_MAX_PATH_PARAMS) {
                return VHTTP_ROUTER_ERR_TOO_LARGE;
            }
            vhttp_path_param_t *param = &out->params[out->num_params++];
            param->name.ptr = child->param_name;
            param->name.len = child->param_name_len;
            param->value = seg;
            param->type = child->param_type;
            node_idx = node->param_child;
            continue;
        }

        if (node->path_child != VHTTP_NODE_NONE) {
            if (node->path_child >= router->node_count) {
                return VHTTP_ROUTER_NOT_FOUND;
            }
            const vhttp_trie_node_t *child = &router->nodes[node->path_child];
            if (out->num_params >= VHTTP_MAX_PATH_PARAMS) {
                return VHTTP_ROUTER_ERR_TOO_LARGE;
            }
            vhttp_path_param_t *param = &out->params[out->num_params++];
            param->name.ptr = child->param_name;
            param->name.len = child->param_name_len;
            param->type = VHTTP_PARAM_PATH;
            param->value.ptr = seg.ptr;
            param->value.len = (uint16_t)((path.ptr + path.len) - seg.ptr);
            node_idx = node->path_child;
            offset = path.len;
            break;
        }

        return VHTTP_ROUTER_NOT_FOUND;
    }

    const vhttp_trie_node_t *leaf = &router->nodes[node_idx];
    if (!leaf->has_handler[method_idx]) {
        return VHTTP_ROUTER_NOT_FOUND;
    }

    out->target = leaf->handlers[method_idx];
    return VHTTP_ROUTER_OK;
}

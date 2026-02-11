#include "py/obj.h"
#include "py/binary.h"
#include "py/objexcept.h"
#include "py/objlist.h"
#include "py/objstr.h"
#include "py/misc.h"
#include "py/mperrno.h"
#include "py/runtime.h"
#include "py/qstr.h"
#include "py/stream.h"
#include "py/mphal.h"
#include "py/gc.h"

#include "extmod/vfs.h"

#include "vhttp_config.h"
#include "vhttp_ipc.h"
#include "vhttp_logger.h"
#include "vhttp_router.h"
#include "vhttp_server.h"
#include "vhttp_static.h"
#include "vhttp_static_etag.h"
#include "vhttp_static_gzip.h"
#include "vhttp_fs_lock.h"
#include "vhttp_cors.h"
#include "vhttp_ratelimit.h"
#include "vhttp_trusted_host.h"
#include "miniz.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <stdlib.h>

#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_heap_caps.h"
#endif

#ifndef VHTTP_MAX_KWARGS
#define VHTTP_MAX_KWARGS (VHTTP_MAX_PATH_PARAMS + VHTTP_MAX_QUERY_PARAMS)
#endif

#ifndef VHTTP_MAX_DEPENDENCIES
#define VHTTP_MAX_DEPENDENCIES 16
#endif

#ifndef VHTTP_MAX_DEP_CHAIN_DEPTH
#define VHTTP_MAX_DEP_CHAIN_DEPTH 8
#endif

static uint32_t g_mp_stream_backpressure_yield_hits = 0;
static uint32_t g_mp_stream_backpressure_queue_hits = 0;
static uint32_t g_mp_stream_backpressure_ring_hits = 0;
static uint32_t g_mp_stream_backpressure_delay_ms_total = 0;

static int vhttp_mp_static_gzip(
    const char *root,
    size_t root_len,
    size_t min_size,
    int level,
    vhttp_gzip_stats_t *stats
);
static int vhttp_mp_stat_path(const char *path, size_t path_len, size_t *size_out, uint32_t *mtime_out, int *is_dir_out);
static int vhttp_mp_open_file(const char *path, size_t path_len, const char *mode, mp_obj_t *out_obj);
static int vhttp_mp_listdir(const char *path, size_t path_len, mp_obj_t *out_list);
static int vhttp_mp_read_full(mp_obj_t file_obj, uint8_t *dst, size_t len);
static int vhttp_mp_static_send_simple(uint32_t request_id, uint16_t status_code, const char *body);
static int vhttp_ipc_send_stream_chunk(
    vhttp_ipc_state_t *ipc,
    uint32_t request_id,
    uint16_t status_code,
    const uint8_t *data,
    size_t len,
    vstr_t *headers_vstr,
    int send_headers,
    uint32_t total_len,
    int chunked,
    int final
);
static void vhttp_tpl_cache_clear_all(void);
static void vhttp_trim_ows(const char **ptr, size_t *len);
static int vhttp_path_has_suffix_ci(const char *path, size_t path_len, const char *suffix);
static int vhttp_map_level_to_probes(int level);

typedef enum {
    VHTTP_TPL_NODE_TEXT = 0,
    VHTTP_TPL_NODE_EXPR,
    VHTTP_TPL_NODE_IF,
    VHTTP_TPL_NODE_FOR,
    VHTTP_TPL_NODE_INCLUDE,
    VHTTP_TPL_NODE_SET,
} vhttp_tpl_node_type_t;

typedef struct vhttp_tpl_node_s vhttp_tpl_node_t;
typedef struct vhttp_tpl_if_branch_s vhttp_tpl_if_branch_t;

struct vhttp_tpl_if_branch_s {
    char *cond;
    size_t cond_len;
    vhttp_tpl_node_t *body;
    vhttp_tpl_if_branch_t *next;
};

struct vhttp_tpl_node_s {
    vhttp_tpl_node_type_t type;
    vhttp_tpl_node_t *next;
    union {
        struct {
            size_t off;
            size_t len;
        } text;
        struct {
            char *expr;
            size_t expr_len;
        } expr;
        struct {
            vhttp_tpl_if_branch_t *branches;
            vhttp_tpl_node_t *else_body;
        } if_stmt;
        struct {
            char *var_name;
            size_t var_len;
            char *var_name2;
            size_t var_len2;
            uint8_t unpack_two;
            char *iter_expr;
            size_t iter_len;
            vhttp_tpl_node_t *body;
            vhttp_tpl_node_t *else_body;
        } for_stmt;
        struct {
            char *path;
            size_t path_len;
        } include;
        struct {
            char *var_name;
            size_t var_len;
            char *expr;
            size_t expr_len;
        } set_stmt;
    } as;
};

typedef enum {
    VHTTP_TPL_STOP_NONE = 0,
    VHTTP_TPL_STOP_ENDIF,
    VHTTP_TPL_STOP_ELSE,
    VHTTP_TPL_STOP_ELIF,
    VHTTP_TPL_STOP_ENDFOR,
    VHTTP_TPL_STOP_FOR_ELSE,
} vhttp_tpl_stop_t;

typedef struct {
    const char *src;
    size_t len;
    size_t pos;
    size_t error_pos;
    uint32_t nodes;
    int error;
    char error_msg[96];
    vhttp_tpl_stop_t stop;
    char stop_expr[96];
    size_t stop_expr_len;
} vhttp_tpl_parser_t;

typedef struct {
    uint8_t used;
    char path[VHTTP_STATIC_MAX_PATH];
    size_t path_len;
    size_t source_len;
    size_t file_size;
    uint32_t mtime;
    uint32_t seq;
    uint32_t hits;
    uint32_t cache_bytes;
    char *source;
    vhttp_tpl_node_t *root;
} vhttp_tpl_cache_entry_t;

typedef struct {
    uint32_t renders;
    uint32_t compiles;
    uint32_t cache_hits;
    uint32_t cache_misses;
    uint32_t cache_evicts;
    uint32_t errors;
} vhttp_tpl_stats_t;

typedef struct {
    uint32_t dirs_seen;
    uint32_t files_seen;
    uint32_t candidates;
    uint32_t compiled;
    uint32_t cached;
    uint32_t errors;
} vhttp_tpl_warmup_stats_t;

static void vhttp_tpl_cache_entry_clear(vhttp_tpl_cache_entry_t *entry);

// Minimal version function for smoke testing the user C module.
static mp_obj_t viperhttp_version(void) {
    return mp_obj_new_str("0.1.0", 5);
}
static MP_DEFINE_CONST_FUN_OBJ_0(viperhttp_version_obj, viperhttp_version);

typedef struct {
    mp_obj_base_t base;
    mp_obj_t handlers;
    mp_obj_t handler_meta;
    mp_obj_t middlewares;
    mp_obj_t title;
    mp_obj_t version;
    mp_obj_t description;
    mp_obj_t docs_enabled;
    mp_obj_t openapi_url;
    mp_obj_t docs_url;
    mp_obj_t include_websocket_docs;
    mp_obj_t cache_schema;
    mp_obj_t servers;
} vhttp_app_t;

typedef struct {
    mp_obj_base_t base;
    vhttp_app_t *app;
    const char *method;
    size_t method_len;
    mp_obj_t path_obj;
    mp_obj_t query_spec;
    mp_obj_t deps_spec;
    mp_obj_t docs_spec;
    mp_obj_t protocols_spec;
} vhttp_route_decorator_t;

typedef struct {
    mp_obj_base_t base;
    mp_obj_t prefix;
    mp_obj_t tags;
    mp_obj_t deps;
    mp_obj_t routes;
} vhttp_router_obj_t;

typedef struct {
    mp_obj_base_t base;
    vhttp_router_obj_t *router;
    const char *method;
    size_t method_len;
    mp_obj_t path_obj;
    mp_obj_t query_spec;
    mp_obj_t deps_spec;
    mp_obj_t docs_spec;
    mp_obj_t protocols_spec;
} vhttp_router_decorator_t;

typedef struct {
    mp_obj_base_t base;
    vhttp_app_t *app;
    mp_int_t priority;
} vhttp_middleware_decorator_t;

typedef struct {
    mp_obj_base_t base;
    mp_obj_t method;
    mp_obj_t path;
    mp_obj_t query;
    mp_obj_t query_params;
    mp_obj_t headers;
    mp_obj_t body;
    mp_obj_t path_params;
    mp_obj_t state;
    mp_obj_t session;
    mp_obj_t user;
    mp_obj_t cookies_cache;
    mp_obj_t json_cache;
    mp_obj_t form_cache;
    uint8_t cookies_parsed;
    uint8_t json_parsed;
    uint8_t form_parsed;
} vhttp_request_t;

typedef struct {
    mp_obj_base_t base;
    mp_obj_t tasks;
} vhttp_background_tasks_t;

typedef struct {
    mp_obj_base_t base;
    mp_obj_t app;
} vhttp_base_middleware_t;

typedef struct {
    mp_obj_base_t base;
} vhttp_cors_middleware_t;

typedef struct {
    mp_obj_base_t base;
} vhttp_ratelimit_middleware_t;

typedef struct {
    mp_obj_base_t base;
} vhttp_trusted_host_middleware_t;
extern const mp_obj_type_t vhttp_app_type;
extern const mp_obj_type_t vhttp_request_type;
extern const mp_obj_type_t vhttp_background_tasks_type;

static vhttp_router_t g_router;
static uint8_t g_router_ready = 0;
static vhttp_tpl_cache_entry_t g_tpl_cache[VHTTP_TEMPLATE_CACHE_ENTRIES];
static uint32_t g_tpl_cache_seq = 1;
static uint32_t g_tpl_cache_bytes = 0;
static vhttp_tpl_stats_t g_tpl_stats;
static int g_tpl_debug_mode = 0;

MP_REGISTER_ROOT_POINTER(void *vhttp_tpl_cache_sources[VHTTP_TEMPLATE_CACHE_ENTRIES]);
MP_REGISTER_ROOT_POINTER(void *vhttp_tpl_cache_roots[VHTTP_TEMPLATE_CACHE_ENTRIES]);

#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
static StaticSemaphore_t g_tpl_lock_buf;
static SemaphoreHandle_t g_tpl_lock = NULL;

static void vhttp_tpl_lock_init(void) {
    if (g_tpl_lock) {
        return;
    }
    g_tpl_lock = xSemaphoreCreateRecursiveMutexStatic(&g_tpl_lock_buf);
}

static void vhttp_tpl_lock(void) {
    vhttp_tpl_lock_init();
    if (g_tpl_lock) {
        (void)xSemaphoreTakeRecursive(g_tpl_lock, portMAX_DELAY);
    }
}

static void vhttp_tpl_unlock(void) {
    if (g_tpl_lock) {
        (void)xSemaphoreGiveRecursive(g_tpl_lock);
    }
}
#else
static void vhttp_tpl_lock(void) {
}

static void vhttp_tpl_unlock(void) {
}
#endif

static inline void vhttp_tpl_keepalive_set(size_t slot, char *source, vhttp_tpl_node_t *root) {
    if (slot >= VHTTP_TEMPLATE_CACHE_ENTRIES) {
        return;
    }
    MP_STATE_VM(vhttp_tpl_cache_sources[slot]) = source;
    MP_STATE_VM(vhttp_tpl_cache_roots[slot]) = root;
}

MP_REGISTER_ROOT_POINTER(mp_obj_t viperhttp_active_app);
MP_REGISTER_ROOT_POINTER(mp_obj_t viperhttp_current_request);
MP_REGISTER_ROOT_POINTER(mp_obj_t viperhttp_dep_resolver);

static mp_obj_t vhttp_make_error_response(mp_int_t status_code, mp_obj_t detail);
static int vhttp_str_ci_equals(const char *a, size_t a_len, const char *b);
static int vhttp_str_ci_contains(const char *haystack, size_t hay_len, const char *needle);
static mp_obj_t vhttp_header_get_ci(mp_obj_t headers, const char *name, size_t *out_len);
static void vhttp_parse_query_params(mp_obj_t params_dict, const char *query, size_t query_len);
static void vhttp_raise_http(mp_int_t status_code, const char *message);
static void vhttp_parse_urlencoded_form(mp_obj_t dict, const char *body, size_t body_len);
static int vhttp_extract_boundary(const char *ct, size_t ct_len, const char **out, size_t *out_len);
static void vhttp_parse_multipart_form(
    mp_obj_t dict,
    const char *body,
    size_t body_len,
    const char *boundary,
    size_t boundary_len
);

static mp_obj_t vhttp_active_app_obj(void) {
    mp_obj_t obj = MP_STATE_VM(viperhttp_active_app);
    if (obj == MP_OBJ_NULL) {
        return MP_OBJ_NULL;
    }
    if (!mp_obj_is_type(obj, &vhttp_app_type)) {
        MP_STATE_VM(viperhttp_active_app) = MP_OBJ_NULL;
        return MP_OBJ_NULL;
    }
    return obj;
}

static vhttp_app_t *vhttp_active_app_ptr(void) {
    mp_obj_t obj = vhttp_active_app_obj();
    if (obj == MP_OBJ_NULL) {
        return NULL;
    }
    return MP_OBJ_TO_PTR(obj);
}

static vhttp_request_t *vhttp_request_ptr(mp_obj_t obj) {
    if (obj == MP_OBJ_NULL || obj == mp_const_none) {
        return NULL;
    }
    if (!mp_obj_is_obj(obj)) {
        return NULL;
    }
    if (!mp_obj_is_type(obj, &vhttp_request_type)) {
        return NULL;
    }
    return MP_OBJ_TO_PTR(obj);
}

MP_DEFINE_EXCEPTION(HTTPException, Exception);

static mp_obj_t viperhttp_active_app(void) {
    mp_obj_t obj = vhttp_active_app_obj();
    if (obj == MP_OBJ_NULL) {
        return mp_const_none;
    }
    return obj;
}
static MP_DEFINE_CONST_FUN_OBJ_0(viperhttp_active_app_obj, viperhttp_active_app);

static mp_obj_t viperhttp_current_request(void) {
    mp_obj_t obj = MP_STATE_VM(viperhttp_current_request);
    if (obj == MP_OBJ_NULL) {
        return mp_const_none;
    }
    return obj;
}
static MP_DEFINE_CONST_FUN_OBJ_0(viperhttp_current_request_obj, viperhttp_current_request);

static mp_obj_t viperhttp_set_current_request(mp_obj_t request_obj) {
    mp_obj_t prev = MP_STATE_VM(viperhttp_current_request);
    if (request_obj == mp_const_none) {
        MP_STATE_VM(viperhttp_current_request) = MP_OBJ_NULL;
    } else {
        MP_STATE_VM(viperhttp_current_request) = request_obj;
    }
    if (prev == MP_OBJ_NULL) {
        return mp_const_none;
    }
    return prev;
}
static MP_DEFINE_CONST_FUN_OBJ_1(viperhttp_set_current_request_obj, viperhttp_set_current_request);

static mp_obj_t viperhttp_set_dep_resolver(mp_obj_t cb_obj) {
    if (cb_obj == mp_const_none) {
        MP_STATE_VM(viperhttp_dep_resolver) = MP_OBJ_NULL;
        return mp_const_none;
    }
    if (!mp_obj_is_callable(cb_obj)) {
        mp_raise_TypeError(MP_ERROR_TEXT("callable or None required"));
    }
    MP_STATE_VM(viperhttp_dep_resolver) = cb_obj;
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_1(viperhttp_set_dep_resolver_obj, viperhttp_set_dep_resolver);

static mp_obj_t viperhttp_reset(void) {
    vhttp_router_init(&g_router);
    g_router_ready = 1;
    vhttp_tpl_lock();
    vhttp_tpl_cache_clear_all();
    memset(&g_tpl_stats, 0, sizeof(g_tpl_stats));
    vhttp_tpl_unlock();
    vhttp_static_reset();
    vhttp_cors_reset();
    vhttp_ratelimit_reset();
    vhttp_trusted_host_reset();
    vhttp_log_set_level(VHTTP_LOG_LEVEL_DEFAULT);
    MP_STATE_VM(viperhttp_active_app) = MP_OBJ_NULL;
    MP_STATE_VM(viperhttp_current_request) = MP_OBJ_NULL;
    MP_STATE_VM(viperhttp_dep_resolver) = MP_OBJ_NULL;
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_0(viperhttp_reset_obj, viperhttp_reset);

static qstr vhttp_qstr_cached(const char *str, size_t len, qstr *cache) {
    if (*cache == 0) {
        *cache = qstr_from_strn(str, len);
    }
    return *cache;
}

static int vhttp_qstr_equals_lit(qstr value, const char *lit, size_t lit_len) {
    size_t value_len = 0;
    const byte *value_str = qstr_data(value, &value_len);
    return value_len == lit_len && memcmp(value_str, lit, lit_len) == 0;
}

static void vhttp_request_attr(mp_obj_t self_in, qstr attr, mp_obj_t *dest) {
    vhttp_request_t *self = MP_OBJ_TO_PTR(self_in);
    static qstr qstr_method = 0;
    static qstr qstr_path = 0;
    static qstr qstr_query = 0;
    static qstr qstr_query_params = 0;
    static qstr qstr_headers = 0;
    static qstr qstr_body = 0;
    static qstr qstr_path_params = 0;
    static qstr qstr_cookies = 0;
    static qstr qstr_state = 0;
    static qstr qstr_session = 0;
    static qstr qstr_user = 0;

    if (dest[0] == MP_OBJ_NULL) {
        if (attr == vhttp_qstr_cached("method", 6, &qstr_method)) {
            dest[0] = self->method;
        } else if (attr == vhttp_qstr_cached("path", 4, &qstr_path)) {
            dest[0] = self->path;
        } else if (attr == vhttp_qstr_cached("query", 5, &qstr_query)) {
            dest[0] = self->query;
        } else if (attr == vhttp_qstr_cached("query_params", 12, &qstr_query_params)) {
            if (self->query_params == mp_const_none) {
                mp_obj_t parsed = mp_obj_new_dict(0);
                if (self->query != mp_const_none && mp_obj_is_str(self->query)) {
                    size_t query_len = 0;
                    const char *query_ptr = mp_obj_str_get_data(self->query, &query_len);
                    vhttp_parse_query_params(parsed, query_ptr, query_len);
                }
                self->query_params = parsed;
            }
            dest[0] = self->query_params;
        } else if (attr == vhttp_qstr_cached("headers", 7, &qstr_headers)) {
            dest[0] = self->headers;
        } else if (attr == vhttp_qstr_cached("body", 4, &qstr_body)) {
            dest[0] = self->body;
        } else if (attr == vhttp_qstr_cached("path_params", 11, &qstr_path_params)) {
            dest[0] = self->path_params;
        } else if (attr == vhttp_qstr_cached("state", 5, &qstr_state)) {
            if (self->state == mp_const_none) {
                self->state = mp_obj_new_dict(0);
            }
            dest[0] = self->state;
        } else if (attr == vhttp_qstr_cached("session", 7, &qstr_session)) {
            dest[0] = self->session;
        } else if (attr == vhttp_qstr_cached("user", 4, &qstr_user)) {
            dest[0] = self->user;
        } else if (attr == vhttp_qstr_cached("cookies", 7, &qstr_cookies)) {
            if (!self->cookies_parsed) {
                self->cookies_cache = mp_obj_new_dict(0);
                self->cookies_parsed = 1;
                size_t len = 0;
                mp_obj_t cookie_val = vhttp_header_get_ci(self->headers, "cookie", &len);
                if (cookie_val != MP_OBJ_NULL && len > 0) {
                    const char *data = NULL;
                    if (mp_obj_is_str(cookie_val)) {
                        data = mp_obj_str_get_data(cookie_val, &len);
                    } else if (mp_obj_is_type(cookie_val, &mp_type_bytes) || mp_obj_is_type(cookie_val, &mp_type_bytearray)) {
                        mp_buffer_info_t bufinfo;
                        mp_get_buffer_raise(cookie_val, &bufinfo, MP_BUFFER_READ);
                        data = (const char *)bufinfo.buf;
                        len = bufinfo.len;
                    }
                    if (data) {
                        const char *ptr = data;
                        size_t remaining = len;
                        while (remaining > 0) {
                            while (remaining > 0 && (*ptr == ';' || *ptr == ' ' || *ptr == '\t' || *ptr == '\r' || *ptr == '\n')) {
                                ptr++;
                                remaining--;
                            }
                            if (remaining == 0) {
                                break;
                            }
                            const char *pair_end = memchr(ptr, ';', remaining);
                            size_t pair_len = pair_end ? (size_t)(pair_end - ptr) : remaining;
                            const char *eq = memchr(ptr, '=', pair_len);
                            const char *name_ptr = ptr;
                            size_t name_len = eq ? (size_t)(eq - ptr) : pair_len;
                            const char *val_ptr = eq ? (eq + 1) : "";
                            size_t val_len = eq ? (size_t)((ptr + pair_len) - val_ptr) : 0;

                            while (name_len > 0 && (*name_ptr == ' ' || *name_ptr == '\t' || *name_ptr == '\r' || *name_ptr == '\n')) {
                                name_ptr++;
                                name_len--;
                            }
                            while (name_len > 0 && (name_ptr[name_len - 1] == ' ' || name_ptr[name_len - 1] == '\t' ||
                                                    name_ptr[name_len - 1] == '\r' || name_ptr[name_len - 1] == '\n')) {
                                name_len--;
                            }
                            while (val_len > 0 && (*val_ptr == ' ' || *val_ptr == '\t' || *val_ptr == '\r' || *val_ptr == '\n')) {
                                val_ptr++;
                                val_len--;
                            }
                            while (val_len > 0 && (val_ptr[val_len - 1] == ' ' || val_ptr[val_len - 1] == '\t' ||
                                                   val_ptr[val_len - 1] == '\r' || val_ptr[val_len - 1] == '\n')) {
                                val_len--;
                            }

                            if (name_len > 0) {
                                mp_obj_t key = mp_obj_new_str(name_ptr, name_len);
                                mp_obj_t val = mp_obj_new_str(val_ptr, val_len);
                                mp_obj_dict_store(self->cookies_cache, key, val);
                            }

                            if (!pair_end) {
                                break;
                            }
                            ptr += pair_len;
                            remaining -= pair_len;
                        }
                    }
                }
            }
            dest[0] = self->cookies_cache;
        }
        if (dest[0] == MP_OBJ_NULL) {
            // Allow attribute lookup to continue in locals_dict (methods like json()).
            dest[1] = MP_OBJ_SENTINEL;
        }
        return;
    }

    if (dest[1] != MP_OBJ_NULL) {
        if (attr == vhttp_qstr_cached("path_params", 11, &qstr_path_params)) {
            self->path_params = dest[1];
            dest[0] = MP_OBJ_NULL;
        } else if (attr == vhttp_qstr_cached("state", 5, &qstr_state)) {
            self->state = dest[1];
            dest[0] = MP_OBJ_NULL;
        } else if (attr == vhttp_qstr_cached("session", 7, &qstr_session)) {
            self->session = dest[1];
            dest[0] = MP_OBJ_NULL;
        } else if (attr == vhttp_qstr_cached("user", 4, &qstr_user)) {
            self->user = dest[1];
            dest[0] = MP_OBJ_NULL;
        }
    }
}

static mp_obj_t vhttp_request_json(mp_obj_t self_in) {
    vhttp_request_t *self = vhttp_request_ptr(self_in);
    if (!self) {
        return mp_const_none;
    }

    if (self->json_parsed) {
        return self->json_cache;
    }

    mp_obj_t body_obj = self->body;
    mp_obj_t json_input = body_obj;
    mp_buffer_info_t bufinfo;

    if (body_obj == mp_const_none) {
        mp_obj_t args[2] = {
            MP_OBJ_NEW_SMALL_INT(400),
            mp_obj_new_str("Invalid JSON", 12),
        };
        nlr_raise(mp_obj_new_exception_args(&mp_type_HTTPException, 2, args));
    }

    if (mp_obj_is_str(body_obj)) {
        // ok
    } else if (mp_obj_is_type(body_obj, &mp_type_bytes)) {
        // ok
    } else if (mp_obj_is_type(body_obj, &mp_type_bytearray)) {
        mp_get_buffer_raise(body_obj, &bufinfo, MP_BUFFER_READ);
        json_input = mp_obj_new_bytes(bufinfo.buf, bufinfo.len);
    } else {
        mp_obj_t args[2] = {
            MP_OBJ_NEW_SMALL_INT(400),
            mp_obj_new_str("Invalid JSON", 12),
        };
        nlr_raise(mp_obj_new_exception_args(&mp_type_HTTPException, 2, args));
    }

    nlr_buf_t nlr;
    if (nlr_push(&nlr) == 0) {
        qstr ujson_q = qstr_from_str("ujson");
        mp_obj_t mod = mp_import_name(ujson_q, mp_const_none, MP_OBJ_NEW_SMALL_INT(0));
        mp_obj_t loads = mp_load_attr(mod, MP_QSTR_loads);
        mp_obj_t result = mp_call_function_1(loads, json_input);
        self->json_cache = result;
        self->json_parsed = 1;
        nlr_pop();
        return result;
    }

    mp_obj_t args[2] = {
        MP_OBJ_NEW_SMALL_INT(400),
        mp_obj_new_str("Invalid JSON", 12),
    };
    nlr_raise(mp_obj_new_exception_args(&mp_type_HTTPException, 2, args));
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_1(vhttp_request_json_obj, vhttp_request_json);

static mp_obj_t vhttp_request_form(mp_obj_t self_in) {
    vhttp_request_t *self = vhttp_request_ptr(self_in);
    if (!self) {
        return mp_obj_new_dict(0);
    }
    if (self->form_parsed) {
        return self->form_cache;
    }
    self->form_cache = mp_obj_new_dict(0);
    self->form_parsed = 1;

    size_t ct_len = 0;
    mp_obj_t ct_obj = vhttp_header_get_ci(self->headers, "content-type", &ct_len);
    if (ct_obj == MP_OBJ_NULL || ct_len == 0) {
        return self->form_cache;
    }

    const char *ct = NULL;
    if (mp_obj_is_str(ct_obj)) {
        ct = mp_obj_str_get_data(ct_obj, &ct_len);
    } else if (mp_obj_is_type(ct_obj, &mp_type_bytes) || mp_obj_is_type(ct_obj, &mp_type_bytearray)) {
        mp_buffer_info_t ct_buf;
        mp_get_buffer_raise(ct_obj, &ct_buf, MP_BUFFER_READ);
        ct = (const char *)ct_buf.buf;
        ct_len = ct_buf.len;
    }
    if (!ct || ct_len == 0) {
        return self->form_cache;
    }

    mp_buffer_info_t body_buf;
    if (!mp_obj_is_type(self->body, &mp_type_bytes) && !mp_obj_is_type(self->body, &mp_type_bytearray)) {
        return self->form_cache;
    }
    mp_get_buffer_raise(self->body, &body_buf, MP_BUFFER_READ);
    if (body_buf.len == 0) {
        return self->form_cache;
    }
    const char *body = (const char *)body_buf.buf;

    if (vhttp_str_ci_contains(ct, ct_len, "application/x-www-form-urlencoded")) {
        vhttp_parse_urlencoded_form(self->form_cache, body, body_buf.len);
        return self->form_cache;
    }

    if (vhttp_str_ci_contains(ct, ct_len, "multipart/form-data")) {
        const char *boundary = NULL;
        size_t boundary_len = 0;
        if (vhttp_extract_boundary(ct, ct_len, &boundary, &boundary_len) != 0) {
            vhttp_raise_http(400, "Missing multipart boundary");
        }
        vhttp_parse_multipart_form(self->form_cache, body, body_buf.len, boundary, boundary_len);
        return self->form_cache;
    }

    return self->form_cache;
}
static MP_DEFINE_CONST_FUN_OBJ_1(vhttp_request_form_obj, vhttp_request_form);

static mp_obj_t vhttp_background_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    (void)n_args;
    (void)n_kw;
    (void)args;
    vhttp_background_tasks_t *self = mp_obj_malloc(vhttp_background_tasks_t, type);
    self->tasks = mp_obj_new_list(0, NULL);
    return MP_OBJ_FROM_PTR(self);
}

static mp_obj_t vhttp_background_add_task(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    if (n_args < 2) {
        mp_raise_TypeError(MP_ERROR_TEXT("add_task(callable, *args, **kwargs)"));
    }
    vhttp_background_tasks_t *self = MP_OBJ_TO_PTR(pos_args[0]);
    mp_obj_t callable = pos_args[1];
    if (!mp_obj_is_callable(callable)) {
        mp_raise_TypeError(MP_ERROR_TEXT("callable required"));
    }

    size_t extra_args = n_args > 2 ? (n_args - 2) : 0;
    mp_obj_t args_tuple = mp_obj_new_tuple(extra_args, extra_args ? (pos_args + 2) : NULL);
    mp_obj_t kwargs_dict = mp_obj_new_dict(0);
    if (kw_args && kw_args->used > 0) {
        mp_map_t *map = kw_args;
        for (size_t i = 0; i < map->alloc; ++i) {
            if (!mp_map_slot_is_filled(map, i)) {
                continue;
            }
            mp_obj_dict_store(kwargs_dict, map->table[i].key, map->table[i].value);
        }
    }

    mp_obj_t entry_items[3] = { callable, args_tuple, kwargs_dict };
    mp_obj_t entry = mp_obj_new_tuple(3, entry_items);
    mp_obj_list_append(self->tasks, entry);
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_background_add_task_obj, 1, vhttp_background_add_task);

static mp_obj_t vhttp_background_drain_tasks(mp_obj_t self_in) {
    vhttp_background_tasks_t *self = MP_OBJ_TO_PTR(self_in);
    mp_obj_t out = self->tasks;
    self->tasks = mp_obj_new_list(0, NULL);
    return out;
}
static MP_DEFINE_CONST_FUN_OBJ_1(vhttp_background_drain_tasks_obj, vhttp_background_drain_tasks);

static const mp_rom_map_elem_t vhttp_background_locals_table[] = {
    { MP_ROM_QSTR(MP_QSTR_add_task), MP_ROM_PTR(&vhttp_background_add_task_obj) },
    { MP_ROM_QSTR(MP_QSTR_drain_tasks), MP_ROM_PTR(&vhttp_background_drain_tasks_obj) },
};
static MP_DEFINE_CONST_DICT(vhttp_background_locals_dict, vhttp_background_locals_table);

MP_DEFINE_CONST_OBJ_TYPE(
    vhttp_background_tasks_type,
    MP_QSTR_BackgroundTasks,
    MP_TYPE_FLAG_NONE,
    make_new, vhttp_background_make_new,
    locals_dict, &vhttp_background_locals_dict
);

static mp_obj_t vhttp_base_middleware_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 1, false);
    vhttp_base_middleware_t *self = mp_obj_malloc(vhttp_base_middleware_t, type);
    self->app = (n_args >= 1) ? args[0] : mp_const_none;
    return MP_OBJ_FROM_PTR(self);
}

static mp_obj_t vhttp_base_middleware_dispatch(size_t n_args, const mp_obj_t *args) {
    (void)n_args;
    (void)args;
    mp_raise_NotImplementedError(MP_ERROR_TEXT("dispatch must be implemented"));
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(vhttp_base_middleware_dispatch_obj, 1, 3, vhttp_base_middleware_dispatch);

static const mp_rom_map_elem_t vhttp_base_middleware_locals_table[] = {
    { MP_ROM_QSTR(MP_QSTR_dispatch), MP_ROM_PTR(&vhttp_base_middleware_dispatch_obj) },
};
static MP_DEFINE_CONST_DICT(vhttp_base_middleware_locals_dict, vhttp_base_middleware_locals_table);

MP_DEFINE_CONST_OBJ_TYPE(
    vhttp_base_middleware_type,
    MP_QSTR_BaseHTTPMiddleware,
    MP_TYPE_FLAG_NONE,
    make_new, vhttp_base_middleware_make_new,
    locals_dict, &vhttp_base_middleware_locals_dict
);

static mp_obj_t vhttp_cors_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 0, false);
    vhttp_cors_middleware_t *self = mp_obj_malloc(vhttp_cors_middleware_t, type);
    return MP_OBJ_FROM_PTR(self);
}

MP_DEFINE_CONST_OBJ_TYPE(
    vhttp_cors_middleware_type,
    MP_QSTR_CORSMiddleware,
    MP_TYPE_FLAG_NONE,
    make_new, vhttp_cors_make_new
);

static mp_obj_t vhttp_ratelimit_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 0, false);
    vhttp_ratelimit_middleware_t *self = mp_obj_malloc(vhttp_ratelimit_middleware_t, type);
    return MP_OBJ_FROM_PTR(self);
}

MP_DEFINE_CONST_OBJ_TYPE(
    vhttp_ratelimit_middleware_type,
    MP_QSTR_RateLimitMiddleware,
    MP_TYPE_FLAG_NONE,
    make_new, vhttp_ratelimit_make_new
);

static mp_obj_t vhttp_trusted_host_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 0, false);
    vhttp_trusted_host_middleware_t *self = mp_obj_malloc(vhttp_trusted_host_middleware_t, type);
    return MP_OBJ_FROM_PTR(self);
}

MP_DEFINE_CONST_OBJ_TYPE(
    vhttp_trusted_host_middleware_type,
    MP_QSTR_TrustedHostMiddleware,
    MP_TYPE_FLAG_NONE,
    make_new, vhttp_trusted_host_make_new
);

static const mp_rom_map_elem_t vhttp_request_locals_table[] = {
    { MP_ROM_QSTR(MP_QSTR_json), MP_ROM_PTR(&vhttp_request_json_obj) },
    { MP_ROM_QSTR(MP_QSTR_form), MP_ROM_PTR(&vhttp_request_form_obj) },
};
static MP_DEFINE_CONST_DICT(vhttp_request_locals_dict, vhttp_request_locals_table);

MP_DEFINE_CONST_OBJ_TYPE(
    vhttp_request_type,
    MP_QSTR_Request,
    MP_TYPE_FLAG_NONE,
    attr, vhttp_request_attr,
    locals_dict, &vhttp_request_locals_dict
);

static void ensure_router_ready(void) {
    if (!g_router_ready) {
        vhttp_router_init(&g_router);
        g_router_ready = 1;
    }
}

static void vhttp_split_path_query(
    const char *path,
    size_t path_len,
    const char **path_out,
    size_t *path_len_out,
    const char **query_out,
    size_t *query_len_out
) {
    const char *qmark = memchr(path, '?', path_len);
    if (qmark) {
        size_t prefix_len = (size_t)(qmark - path);
        *path_out = path;
        *path_len_out = prefix_len;
        if (query_out) {
            *query_out = qmark + 1;
        }
        if (query_len_out) {
            *query_len_out = path_len - prefix_len - 1;
        }
    } else {
        *path_out = path;
        *path_len_out = path_len;
        if (query_out) {
            *query_out = NULL;
        }
        if (query_len_out) {
            *query_len_out = 0;
        }
    }
}

static int vhttp_hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static mp_obj_t vhttp_query_component_to_str(const char *ptr, size_t len) {
    if (!ptr || len == 0) {
        return mp_obj_new_str("", 0);
    }

    int needs_decode = 0;
    for (size_t i = 0; i < len; ++i) {
        if (ptr[i] == '%' || ptr[i] == '+') {
            needs_decode = 1;
            break;
        }
    }
    if (!needs_decode) {
        return mp_obj_new_str(ptr, len);
    }

    char *buf = m_new(char, len);
    size_t out_len = 0;
    size_t i = 0;
    while (i < len) {
        char c = ptr[i];
        if (c == '+') {
            buf[out_len++] = ' ';
            i++;
            continue;
        }
        if (c == '%' && i + 2 < len) {
            int hi = vhttp_hex_nibble(ptr[i + 1]);
            int lo = vhttp_hex_nibble(ptr[i + 2]);
            if (hi >= 0 && lo >= 0) {
                buf[out_len++] = (char)((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        buf[out_len++] = c;
        i++;
    }

    mp_obj_t out = mp_obj_new_str(buf, out_len);
    m_del(char, buf, len);
    return out;
}

static void vhttp_parse_query_params(mp_obj_t params_dict, const char *query, size_t query_len) {
    if (!query || query_len == 0) {
        return;
    }

    mp_map_t *map = mp_obj_dict_get_map(params_dict);
    const char *cur = query;
    const char *end = query + query_len;
    uint8_t count = 0;

    while (cur < end && count < VHTTP_MAX_QUERY_PARAMS) {
        const char *amp = memchr(cur, '&', (size_t)(end - cur));
        const char *segment_end = amp ? amp : end;
        if (segment_end > cur) {
            const char *eq = memchr(cur, '=', (size_t)(segment_end - cur));
            const char *key_ptr = cur;
            size_t key_len = eq ? (size_t)(eq - cur) : (size_t)(segment_end - cur);
            const char *val_ptr = eq ? (eq + 1) : "";
            size_t val_len = eq ? (size_t)(segment_end - (eq + 1)) : 0;

            if (key_len > 0) {
                mp_obj_t key = vhttp_query_component_to_str(key_ptr, key_len);
                if (mp_map_lookup(map, key, MP_MAP_LOOKUP) == NULL) {
                    mp_obj_t value = vhttp_query_component_to_str(val_ptr, val_len);
                    mp_obj_dict_store(params_dict, key, value);
                }
                count++;
            }
        }
        if (!amp) {
            break;
        }
        cur = amp + 1;
    }
}

static mp_obj_t vhttp_parse_headers_blob(const uint8_t *ptr, size_t len) {
    mp_obj_t headers = mp_obj_new_dict(0);
    if (!ptr || len == 0) {
        return headers;
    }

    size_t offset = 0;
    while (offset < len) {
        const uint8_t *name_ptr = ptr + offset;
        size_t remaining = len - offset;
        const uint8_t *name_end = memchr(name_ptr, 0, remaining);
        if (!name_end) {
            break;
        }
        size_t name_len = (size_t)(name_end - name_ptr);
        offset += name_len + 1;
        if (offset >= len) {
            break;
        }

        const uint8_t *value_ptr = ptr + offset;
        remaining = len - offset;
        const uint8_t *value_end = memchr(value_ptr, 0, remaining);
        if (!value_end) {
            break;
        }
        size_t value_len = (size_t)(value_end - value_ptr);
        offset += value_len + 1;

        if (name_len > 0) {
            mp_obj_t key = mp_obj_new_str((const char *)name_ptr, name_len);
            mp_obj_t val = mp_obj_new_str((const char *)value_ptr, value_len);
            mp_obj_dict_store(headers, key, val);
        }
    }

    return headers;
}

static mp_obj_t vhttp_request_make(
    mp_obj_t method,
    mp_obj_t path,
    mp_obj_t query,
    mp_obj_t query_params,
    mp_obj_t headers,
    mp_obj_t body
) {
    vhttp_request_t *req = mp_obj_malloc(vhttp_request_t, &vhttp_request_type);
    req->method = method;
    req->path = path;
    req->query = query;
    req->query_params = query_params;
    req->headers = headers;
    req->body = body;
    req->path_params = mp_obj_new_dict(0);
    req->state = mp_const_none;
    req->session = mp_const_none;
    req->user = mp_const_none;
    req->cookies_cache = mp_const_none;
    req->json_cache = mp_const_none;
    req->form_cache = mp_const_none;
    req->cookies_parsed = 0;
    req->json_parsed = 0;
    req->form_parsed = 0;
    return MP_OBJ_FROM_PTR(req);
}

static void vhttp_form_store(mp_obj_t dict, mp_obj_t key, mp_obj_t value) {
    mp_map_t *map = mp_obj_dict_get_map(dict);
    mp_map_elem_t *elem = mp_map_lookup(map, key, MP_MAP_LOOKUP);
    if (!elem) {
        mp_obj_dict_store(dict, key, value);
        return;
    }
    mp_obj_t existing = elem->value;
    if (mp_obj_is_type(existing, &mp_type_list)) {
        mp_obj_list_append(existing, value);
        return;
    }
    mp_obj_t items[2] = { existing, value };
    mp_obj_t list = mp_obj_new_list(2, items);
    mp_obj_dict_store(dict, key, list);
}

static void vhttp_parse_urlencoded_form(mp_obj_t dict, const char *body, size_t body_len) {
    if (!body || body_len == 0) {
        return;
    }
    const char *cur = body;
    const char *end = body + body_len;
    uint32_t count = 0;

    while (cur < end && count < VHTTP_MAX_FORM_PARTS) {
        const char *amp = memchr(cur, '&', (size_t)(end - cur));
        const char *segment_end = amp ? amp : end;
        if (segment_end > cur) {
            const char *eq = memchr(cur, '=', (size_t)(segment_end - cur));
            const char *key_ptr = cur;
            size_t key_len = eq ? (size_t)(eq - cur) : (size_t)(segment_end - cur);
            const char *val_ptr = eq ? (eq + 1) : "";
            size_t val_len = eq ? (size_t)(segment_end - (eq + 1)) : 0;

            if (key_len > 0) {
                if (key_len > VHTTP_MAX_FORM_FIELD_SIZE || val_len > VHTTP_MAX_FORM_FIELD_SIZE) {
                    vhttp_raise_http(413, "Form field too large");
                }
                mp_obj_t key = mp_obj_new_str(key_ptr, key_len);
                mp_obj_t val = mp_obj_new_str(val_ptr, val_len);
                vhttp_form_store(dict, key, val);
                count++;
            }
        }
        if (!amp) {
            break;
        }
        cur = amp + 1;
    }
    if (count >= VHTTP_MAX_FORM_PARTS) {
        vhttp_raise_http(413, "Too many form fields");
    }
}

static const char *vhttp_find_boundary(
    const char *buf,
    size_t len,
    const char *boundary,
    size_t boundary_len,
    int allow_start
) {
    size_t marker_len = boundary_len + 2;
    if (marker_len == 2 || len < marker_len) {
        return NULL;
    }
    for (size_t i = 0; i + marker_len <= len; ++i) {
        if (buf[i] != '-' || buf[i + 1] != '-') {
            continue;
        }
        if (!allow_start) {
            if (i < 2 || buf[i - 2] != '\r' || buf[i - 1] != '\n') {
                continue;
            }
        } else {
            if (i != 0 && !(i >= 2 && buf[i - 2] == '\r' && buf[i - 1] == '\n')) {
                continue;
            }
        }
        if (memcmp(buf + i + 2, boundary, boundary_len) == 0) {
            return buf + i;
        }
    }
    return NULL;
}

static int vhttp_extract_boundary(const char *ct, size_t ct_len, const char **out, size_t *out_len) {
    if (!ct || ct_len == 0) {
        return -1;
    }
    const char *needle = "boundary=";
    size_t needle_len = 9;
    for (size_t i = 0; i + needle_len <= ct_len; ++i) {
        size_t j = 0;
        for (; j < needle_len; ++j) {
            char ca = ct[i + j];
            char cb = needle[j];
            if (ca >= 'A' && ca <= 'Z') {
                ca = (char)(ca + ('a' - 'A'));
            }
            if (ca != cb) {
                break;
            }
        }
        if (j != needle_len) {
            continue;
        }
        const char *val = ct + i + needle_len;
        size_t remaining = ct_len - (i + needle_len);
        while (remaining > 0 && (*val == ' ' || *val == '\t')) {
            val++;
            remaining--;
        }
        if (remaining == 0) {
            return -1;
        }
        if (*val == '"') {
            val++;
            remaining--;
            const char *end = memchr(val, '"', remaining);
            if (!end) {
                return -1;
            }
            *out = val;
            *out_len = (size_t)(end - val);
            return (*out_len > 0) ? 0 : -1;
        }
        const char *end = val;
        while ((size_t)(end - val) < remaining) {
            char c = *end;
            if (c == ';' || c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                break;
            }
            end++;
        }
        *out = val;
        *out_len = (size_t)(end - val);
        return (*out_len > 0) ? 0 : -1;
    }
    return -1;
}

static int vhttp_parse_cd_param(
    const char *value,
    size_t value_len,
    const char *key,
    const char **out,
    size_t *out_len
) {
    size_t key_len = strlen(key);
    if (!value || value_len == 0 || key_len == 0) {
        return -1;
    }
    for (size_t i = 0; i + key_len + 1 <= value_len; ++i) {
        size_t j = 0;
        for (; j < key_len; ++j) {
            char ca = value[i + j];
            char cb = key[j];
            if (ca >= 'A' && ca <= 'Z') {
                ca = (char)(ca + ('a' - 'A'));
            }
            if (ca != cb) {
                break;
            }
        }
        if (j != key_len) {
            continue;
        }
        if (value[i + key_len] != '=') {
            continue;
        }
        const char *val = value + i + key_len + 1;
        size_t remaining = value_len - (i + key_len + 1);
        if (remaining == 0) {
            return -1;
        }
        if (*val == '"') {
            val++;
            remaining--;
            const char *end = memchr(val, '"', remaining);
            if (!end) {
                return -1;
            }
            *out = val;
            *out_len = (size_t)(end - val);
            return (*out_len > 0) ? 0 : -1;
        }
        const char *end = val;
        while ((size_t)(end - val) < remaining) {
            char c = *end;
            if (c == ';' || c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                break;
            }
            end++;
        }
        *out = val;
        *out_len = (size_t)(end - val);
        return (*out_len > 0) ? 0 : -1;
    }
    return -1;
}

static void vhttp_parse_multipart_form(
    mp_obj_t dict,
    const char *body,
    size_t body_len,
    const char *boundary,
    size_t boundary_len
) {
    if (!body || body_len == 0 || !boundary || boundary_len == 0) {
        return;
    }
    const char *cur = vhttp_find_boundary(body, body_len, boundary, boundary_len, 1);
    if (!cur) {
        vhttp_raise_http(400, "Invalid multipart data");
    }
    uint32_t parts = 0;
    const char *end = body + body_len;
    while (cur && cur < end) {
        const char *after = cur + 2 + boundary_len;
        if (after + 1 < end && after[0] == '-' && after[1] == '-') {
            break;
        }
        if (after < end && *after == '\r') {
            after++;
        }
        if (after < end && *after == '\n') {
            after++;
        }

        const char *headers_end = NULL;
        size_t sep_len = 0;
        const char *p = after;
        while (p + 1 < end) {
            if (p[0] == '\r' && p[1] == '\n') {
                if (p + 3 < end && p[2] == '\r' && p[3] == '\n') {
                    headers_end = p;
                    sep_len = 4;
                    break;
                }
            }
            if (p[0] == '\n' && p[1] == '\n') {
                headers_end = p;
                sep_len = 2;
                break;
            }
            p++;
        }
        if (!headers_end) {
            vhttp_raise_http(400, "Invalid multipart headers");
        }

        const char *part_start = headers_end + sep_len;
        const char *next_boundary = vhttp_find_boundary(part_start, (size_t)(end - part_start), boundary, boundary_len, 0);
        if (!next_boundary) {
            vhttp_raise_http(400, "Invalid multipart boundary");
        }
        const char *part_end = next_boundary;
        if (part_end > part_start && part_end[-1] == '\n') {
            part_end--;
            if (part_end > part_start && part_end[-1] == '\r') {
                part_end--;
            }
        }
        size_t part_len = (size_t)(part_end - part_start);

        const char *cd_val = NULL;
        size_t cd_len = 0;
        const char *ct_val = NULL;
        size_t ct_len = 0;
        const char *line = after;
        while (line < headers_end) {
            const char *line_end = memchr(line, '\n', (size_t)(headers_end - line));
            size_t line_len = line_end ? (size_t)(line_end - line) : (size_t)(headers_end - line);
            if (line_len > 0 && line[line_len - 1] == '\r') {
                line_len--;
            }
            if (line_len == 0) {
                break;
            }
            const char *colon = memchr(line, ':', line_len);
            if (colon) {
                const char *name_ptr = line;
                size_t name_len = (size_t)(colon - line);
                const char *val_ptr = colon + 1;
                size_t val_len = line_len - name_len - 1;
                while (val_len > 0 && (*val_ptr == ' ' || *val_ptr == '\t')) {
                    val_ptr++;
                    val_len--;
                }
                if (vhttp_str_ci_equals(name_ptr, name_len, "content-disposition")) {
                    cd_val = val_ptr;
                    cd_len = val_len;
                } else if (vhttp_str_ci_equals(name_ptr, name_len, "content-type")) {
                    ct_val = val_ptr;
                    ct_len = val_len;
                }
            }
            if (!line_end) {
                break;
            }
            line = line_end + 1;
        }

        if (cd_val && vhttp_str_ci_contains(cd_val, cd_len, "form-data")) {
            const char *name_val = NULL;
            size_t name_len = 0;
            const char *filename_val = NULL;
            size_t filename_len = 0;
            if (vhttp_parse_cd_param(cd_val, cd_len, "name", &name_val, &name_len) == 0) {
                (void)vhttp_parse_cd_param(cd_val, cd_len, "filename", &filename_val, &filename_len);
                if (name_len > 0) {
                    mp_obj_t key = mp_obj_new_str(name_val, name_len);
                    if (filename_val && filename_len > 0) {
                        if (part_len > VHTTP_MAX_FORM_FILE_SIZE) {
                            vhttp_raise_http(413, "Form file too large");
                        }
                        mp_obj_t file_dict = mp_obj_new_dict(3);
                        mp_obj_dict_store(file_dict, mp_obj_new_str("filename", 8), mp_obj_new_str(filename_val, filename_len));
                        if (ct_val && ct_len > 0) {
                            mp_obj_dict_store(file_dict, mp_obj_new_str("content_type", 12), mp_obj_new_str(ct_val, ct_len));
                        } else {
                            mp_obj_dict_store(file_dict, mp_obj_new_str("content_type", 12), mp_obj_new_str("", 0));
                        }
                        mp_obj_dict_store(file_dict, mp_obj_new_str("data", 4), mp_obj_new_bytes((const byte *)part_start, part_len));
                        vhttp_form_store(dict, key, file_dict);
                    } else {
                        if (part_len > VHTTP_MAX_FORM_FIELD_SIZE) {
                            vhttp_raise_http(413, "Form field too large");
                        }
                        mp_obj_t val = mp_obj_new_str(part_start, part_len);
                        vhttp_form_store(dict, key, val);
                    }
                    parts++;
                    if (parts >= VHTTP_MAX_FORM_PARTS) {
                        vhttp_raise_http(413, "Too many form parts");
                    }
                }
            }
        }

        cur = next_boundary;
    }
}

typedef enum {
    VHTTP_CAST_NONE = 0,
    VHTTP_CAST_STR,
    VHTTP_CAST_INT,
    VHTTP_CAST_FLOAT,
    VHTTP_CAST_BOOL,
} vhttp_cast_kind_t;

static int vhttp_is_query_spec(mp_obj_t obj) {
    if (!mp_obj_is_type(obj, &mp_type_dict)) {
        return 0;
    }
    mp_obj_t key = mp_obj_new_str("__vhttp_query__", 14);
    nlr_buf_t nlr;
    if (nlr_push(&nlr) == 0) {
        mp_obj_t val = mp_obj_dict_get(obj, key);
        nlr_pop();
        return mp_obj_is_true(val);
    }
    return 0;
}

static int vhttp_is_dep_spec(mp_obj_t obj) {
    if (!mp_obj_is_type(obj, &mp_type_dict)) {
        return 0;
    }
    mp_obj_t key = mp_obj_new_str("__vhttp_dep__", 13);
    nlr_buf_t nlr;
    if (nlr_push(&nlr) == 0) {
        mp_obj_t val = mp_obj_dict_get(obj, key);
        nlr_pop();
        return mp_obj_is_true(val);
    }
    return 0;
}

static vhttp_cast_kind_t vhttp_cast_kind_from_obj(mp_obj_t obj) {
    if (obj == MP_OBJ_FROM_PTR(&mp_type_str)) {
        return VHTTP_CAST_STR;
    }
    if (obj == MP_OBJ_FROM_PTR(&mp_type_int)) {
        return VHTTP_CAST_INT;
    }
    if (obj == MP_OBJ_FROM_PTR(&mp_type_float)) {
        return VHTTP_CAST_FLOAT;
    }
    if (obj == MP_OBJ_FROM_PTR(&mp_type_bool)) {
        return VHTTP_CAST_BOOL;
    }
    return VHTTP_CAST_NONE;
}

static int vhttp_cast_bool_from_str(const char *ptr, size_t len, mp_obj_t *out) {
    if (len == 1) {
        if (ptr[0] == '1') {
            *out = mp_const_true;
            return 0;
        }
        if (ptr[0] == '0') {
            *out = mp_const_false;
            return 0;
        }
    }
    if (vhttp_str_ci_equals(ptr, len, "true") ||
        vhttp_str_ci_equals(ptr, len, "yes") ||
        vhttp_str_ci_equals(ptr, len, "on")) {
        *out = mp_const_true;
        return 0;
    }
    if (vhttp_str_ci_equals(ptr, len, "false") ||
        vhttp_str_ci_equals(ptr, len, "no") ||
        vhttp_str_ci_equals(ptr, len, "off")) {
        *out = mp_const_false;
        return 0;
    }
    return -1;
}

static int vhttp_cast_from_str(const char *ptr, size_t len, vhttp_cast_kind_t kind, mp_obj_t *out) {
    if (kind == VHTTP_CAST_STR || kind == VHTTP_CAST_NONE) {
        *out = mp_obj_new_str(ptr, len);
        return 0;
    }
    if (kind == VHTTP_CAST_INT) {
        if (len == 0) {
            return -1;
        }
        long long num = 0;
        int sign = 1;
        size_t idx = 0;
        if (ptr[0] == '-') {
            sign = -1;
            idx = 1;
        }
        if (idx >= len) {
            return -1;
        }
        for (; idx < len; ++idx) {
            char c = ptr[idx];
            if (c < '0' || c > '9') {
                return -1;
            }
            num = num * 10 + (c - '0');
        }
        *out = mp_obj_new_int_from_ll((long long)(num * sign));
        return 0;
    }
    if (kind == VHTTP_CAST_FLOAT) {
        if (len == 0) {
            return -1;
        }
        double sign = 1.0;
        size_t idx = 0;
        if (ptr[0] == '-') {
            sign = -1.0;
            idx = 1;
        }
        if (idx >= len) {
            return -1;
        }
        double integer = 0.0;
        while (idx < len && ptr[idx] != '.') {
            char c = ptr[idx];
            if (c < '0' || c > '9') {
                return -1;
            }
            integer = integer * 10.0 + (double)(c - '0');
            idx++;
        }
        double frac = 0.0;
        double scale = 1.0;
        if (idx < len && ptr[idx] == '.') {
            idx++;
            if (idx >= len) {
                return -1;
            }
            while (idx < len) {
                char c = ptr[idx];
                if (c < '0' || c > '9') {
                    return -1;
                }
                scale *= 0.1;
                frac += scale * (double)(c - '0');
                idx++;
            }
        }
        *out = mp_obj_new_float((integer + frac) * sign);
        return 0;
    }
    if (kind == VHTTP_CAST_BOOL) {
        return vhttp_cast_bool_from_str(ptr, len, out);
    }
    return -1;
}

static void vhttp_validate_dep_value(mp_obj_t spec, size_t depth) {
    if (depth > VHTTP_MAX_DEP_CHAIN_DEPTH) {
        mp_raise_ValueError(MP_ERROR_TEXT("dependency chain too deep"));
    }
    if (!vhttp_is_dep_spec(spec)) {
        mp_raise_TypeError(MP_ERROR_TEXT("dependency must be Depends()"));
    }

    mp_obj_t key_callable = mp_obj_new_str("callable", 8);
    mp_obj_t key_deps = mp_obj_new_str("deps", 4);
    mp_obj_t callable = mp_const_none;
    mp_obj_t deps = mp_const_none;

    nlr_buf_t nlr;
    if (nlr_push(&nlr) == 0) {
        callable = mp_obj_dict_get(spec, key_callable);
        nlr_pop();
    } else {
        mp_raise_TypeError(MP_ERROR_TEXT("invalid Depends() spec"));
    }

    if (!mp_obj_is_callable(callable)) {
        mp_raise_TypeError(MP_ERROR_TEXT("dependency callable required"));
    }

    if (nlr_push(&nlr) == 0) {
        deps = mp_obj_dict_get(spec, key_deps);
        nlr_pop();
    } else {
        deps = mp_const_none;
    }

    if (deps == mp_const_none) {
        return;
    }
    if (!mp_obj_is_type(deps, &mp_type_dict)) {
        mp_raise_TypeError(MP_ERROR_TEXT("dependency deps must be dict"));
    }

    mp_map_t *deps_map = mp_obj_dict_get_map(deps);
    if (deps_map->used > VHTTP_MAX_DEPENDENCIES) {
        mp_raise_ValueError(MP_ERROR_TEXT("dependency list too large"));
    }

    for (size_t i = 0; i < deps_map->alloc; ++i) {
        if (!mp_map_slot_is_filled(deps_map, i)) {
            continue;
        }
        mp_obj_t key = deps_map->table[i].key;
        mp_obj_t val = deps_map->table[i].value;
        if (!mp_obj_is_str(key)) {
            mp_raise_TypeError(MP_ERROR_TEXT("dependency keys must be str"));
        }
        vhttp_validate_dep_value(val, depth + 1);
    }
}

static void vhttp_validate_deps_spec(mp_obj_t deps_spec) {
    if (deps_spec == mp_const_none) {
        return;
    }
    if (!mp_obj_is_type(deps_spec, &mp_type_dict)) {
        mp_raise_TypeError(MP_ERROR_TEXT("deps spec must be dict"));
    }

    mp_map_t *spec_map = mp_obj_dict_get_map(deps_spec);
    if (spec_map->used > VHTTP_MAX_DEPENDENCIES) {
        mp_raise_ValueError(MP_ERROR_TEXT("deps spec too large"));
    }

    for (size_t i = 0; i < spec_map->alloc; ++i) {
        if (!mp_map_slot_is_filled(spec_map, i)) {
            continue;
        }
        mp_obj_t key = spec_map->table[i].key;
        mp_obj_t val = spec_map->table[i].value;
        if (!mp_obj_is_str(key)) {
            mp_raise_TypeError(MP_ERROR_TEXT("deps spec keys must be str"));
        }
        vhttp_validate_dep_value(val, 1);
    }
}

static mp_obj_t vhttp_join_paths(mp_obj_t prefix_obj, mp_obj_t path_obj) {
    size_t prefix_len = 0;
    size_t path_len = 0;
    const char *prefix = mp_obj_str_get_data(prefix_obj, &prefix_len);
    const char *path = mp_obj_str_get_data(path_obj, &path_len);

    if (prefix_len == 0) {
        return mp_obj_new_str(path, path_len);
    }
    if (path_len == 0) {
        return mp_obj_new_str(prefix, prefix_len);
    }

    int drop_slash = 0;
    int add_slash = 0;
    if (prefix_len > 0 && path_len > 0) {
        char last = prefix[prefix_len - 1];
        char first = path[0];
        if (last == '/' && first == '/') {
            drop_slash = 1;
        } else if (last != '/' && first != '/') {
            add_slash = 1;
        }
    }

    size_t prefix_use = drop_slash ? (prefix_len - 1) : prefix_len;
    const char *path_ptr = drop_slash ? (path + 1) : path;
    size_t path_use = drop_slash ? (path_len - 1) : path_len;

    vstr_t v;
    vstr_init(&v, prefix_use + path_use + 2);
    vstr_add_strn(&v, prefix, prefix_use);
    if (add_slash) {
        vstr_add_char(&v, '/');
    }
    vstr_add_strn(&v, path_ptr, path_use);
    mp_obj_t out = mp_obj_new_str(v.buf, v.len);
    vstr_clear(&v);
    return out;
}

static int vhttp_default_compatible(mp_obj_t value, vhttp_cast_kind_t kind) {
    if (value == mp_const_none) {
        return 1;
    }
    if (kind == VHTTP_CAST_STR) {
        return mp_obj_is_str(value) ||
            mp_obj_is_type(value, &mp_type_bytes) ||
            mp_obj_is_type(value, &mp_type_bytearray);
    }
    if (kind == VHTTP_CAST_INT) {
        return mp_obj_is_int(value) ||
            mp_obj_is_str(value) ||
            mp_obj_is_type(value, &mp_type_bytes) ||
            mp_obj_is_type(value, &mp_type_bytearray);
    }
    if (kind == VHTTP_CAST_FLOAT) {
        return mp_obj_is_type(value, &mp_type_float) ||
            mp_obj_is_int(value) ||
            mp_obj_is_str(value) ||
            mp_obj_is_type(value, &mp_type_bytes) ||
            mp_obj_is_type(value, &mp_type_bytearray);
    }
    if (kind == VHTTP_CAST_BOOL) {
        return mp_obj_is_bool(value) ||
            mp_obj_is_int(value) ||
            mp_obj_is_str(value) ||
            mp_obj_is_type(value, &mp_type_bytes) ||
            mp_obj_is_type(value, &mp_type_bytearray);
    }
    return 1;
}

static mp_obj_t vhttp_resolve_dep_value(mp_obj_t dep_spec, size_t depth) {
    if (depth > VHTTP_MAX_DEP_CHAIN_DEPTH) {
        mp_raise_ValueError(MP_ERROR_TEXT("dependency chain too deep"));
    }
    if (!vhttp_is_dep_spec(dep_spec)) {
        mp_raise_TypeError(MP_ERROR_TEXT("dependency must be Depends()"));
    }

    mp_obj_t key_callable = mp_obj_new_str("callable", 8);
    mp_obj_t key_deps = mp_obj_new_str("deps", 4);
    mp_obj_t callable = mp_obj_dict_get(dep_spec, key_callable);
    mp_obj_t deps = mp_const_none;
    nlr_buf_t nlr;
    if (nlr_push(&nlr) == 0) {
        deps = mp_obj_dict_get(dep_spec, key_deps);
        nlr_pop();
    } else {
        deps = mp_const_none;
    }

    if (deps == mp_const_none || !mp_obj_is_type(deps, &mp_type_dict)) {
        return mp_call_function_0(callable);
    }

    mp_map_t *deps_map = mp_obj_dict_get_map(deps);
    if (deps_map->used > VHTTP_MAX_DEPENDENCIES) {
        mp_raise_ValueError(MP_ERROR_TEXT("dependency list too large"));
    }

    mp_obj_t kw_args[2 * VHTTP_MAX_DEPENDENCIES];
    size_t kw_idx = 0;
    for (size_t i = 0; i < deps_map->alloc; ++i) {
        if (!mp_map_slot_is_filled(deps_map, i)) {
            continue;
        }
        if (kw_idx >= VHTTP_MAX_DEPENDENCIES) {
            break;
        }
        mp_obj_t key = deps_map->table[i].key;
        mp_obj_t val = deps_map->table[i].value;
        if (!mp_obj_is_str(key)) {
            mp_raise_TypeError(MP_ERROR_TEXT("dependency keys must be str"));
        }
        mp_obj_t dep_val = vhttp_resolve_dep_value(val, depth + 1);
        qstr key_qstr = mp_obj_str_get_qstr(key);
        kw_args[kw_idx * 2] = MP_OBJ_NEW_QSTR(key_qstr);
        kw_args[kw_idx * 2 + 1] = dep_val;
        kw_idx++;
    }

    return mp_call_function_n_kw(callable, 0, kw_idx, kw_args);
}

static void vhttp_apply_deps(mp_obj_t params_dict, mp_obj_t deps_spec) {
    if (deps_spec == mp_const_none) {
        return;
    }
    if (!mp_obj_is_type(deps_spec, &mp_type_dict)) {
        mp_raise_TypeError(MP_ERROR_TEXT("deps spec must be dict"));
    }

    mp_map_t *spec_map = mp_obj_dict_get_map(deps_spec);
    if (spec_map->used > VHTTP_MAX_DEPENDENCIES) {
        mp_raise_ValueError(MP_ERROR_TEXT("deps spec too large"));
    }

    mp_map_t *params_map = mp_obj_dict_get_map(params_dict);
    for (size_t i = 0; i < spec_map->alloc; ++i) {
        if (!mp_map_slot_is_filled(spec_map, i)) {
            continue;
        }
        mp_obj_t key = spec_map->table[i].key;
        mp_obj_t spec = spec_map->table[i].value;
        if (!mp_obj_is_str(key)) {
            mp_raise_TypeError(MP_ERROR_TEXT("deps spec keys must be str"));
        }
        if (mp_map_lookup(params_map, key, MP_MAP_LOOKUP) != NULL) {
            mp_raise_ValueError(MP_ERROR_TEXT("dependency name conflicts with params"));
        }
        mp_obj_t value = vhttp_resolve_dep_value(spec, 1);
        if (mp_obj_is_type(value, &mp_type_gen_instance)) {
            mp_raise_TypeError(MP_ERROR_TEXT("async/yield dependencies not supported"));
        }
        mp_obj_dict_store(params_dict, key, value);
    }
}

static mp_obj_t vhttp_merge_deps(mp_obj_t base_deps, mp_obj_t extra_deps) {
    if (base_deps == mp_const_none) {
        return extra_deps;
    }
    if (extra_deps == mp_const_none) {
        return base_deps;
    }
    if (!mp_obj_is_type(base_deps, &mp_type_dict) || !mp_obj_is_type(extra_deps, &mp_type_dict)) {
        mp_raise_TypeError(MP_ERROR_TEXT("deps must be dict"));
    }

    mp_obj_t merged = mp_obj_new_dict(0);
    mp_map_t *map = mp_obj_dict_get_map(base_deps);
    for (size_t i = 0; i < map->alloc; ++i) {
        if (!mp_map_slot_is_filled(map, i)) {
            continue;
        }
        mp_obj_dict_store(merged, map->table[i].key, map->table[i].value);
    }

    mp_map_t *extra_map = mp_obj_dict_get_map(extra_deps);
    for (size_t i = 0; i < extra_map->alloc; ++i) {
        if (!mp_map_slot_is_filled(extra_map, i)) {
            continue;
        }
        mp_obj_t key = extra_map->table[i].key;
        if (mp_map_lookup(mp_obj_dict_get_map(merged), key, MP_MAP_LOOKUP) != NULL) {
            mp_raise_ValueError(MP_ERROR_TEXT("duplicate dependency key"));
        }
        mp_obj_dict_store(merged, key, extra_map->table[i].value);
    }

    return merged;
}

static mp_obj_t vhttp_query_error(const char *prefix, mp_obj_t key) {
    size_t key_len = 0;
    const char *key_str = mp_obj_str_get_data(key, &key_len);
    char buf[96];
    int len = snprintf(buf, sizeof(buf), "%s%.*s", prefix, (int)key_len, key_str);
    if (len < 0) {
        return vhttp_make_error_response(422, mp_obj_new_str("Invalid query param", 20));
    }
    if ((size_t)len >= sizeof(buf)) {
        len = (int)(sizeof(buf) - 1);
    }
    return vhttp_make_error_response(422, mp_obj_new_str(buf, (size_t)len));
}

static int vhttp_unpack_query_spec(
    mp_obj_t spec,
    vhttp_cast_kind_t *out_kind,
    mp_obj_t *out_default,
    int *out_required
) {
    *out_kind = VHTTP_CAST_NONE;
    *out_default = mp_const_none;
    *out_required = 1;

    if (vhttp_is_query_spec(spec)) {
        mp_obj_t key_default = mp_obj_new_str("default", 7);
        mp_obj_t key_cast = mp_obj_new_str("cast", 4);
        mp_obj_t key_required = mp_obj_new_str("required", 8);
        mp_obj_t default_val = mp_obj_dict_get(spec, key_default);
        mp_obj_t cast_val = mp_obj_dict_get(spec, key_cast);
        mp_obj_t required_val = mp_obj_dict_get(spec, key_required);
        *out_default = default_val;
        *out_required = mp_obj_is_true(required_val);
        if (cast_val != mp_const_none) {
            *out_kind = vhttp_cast_kind_from_obj(cast_val);
            if (*out_kind == VHTTP_CAST_NONE) {
                return -1;
            }
        }
        return 0;
    }

    vhttp_cast_kind_t kind = vhttp_cast_kind_from_obj(spec);
    if (kind != VHTTP_CAST_NONE) {
        *out_kind = kind;
        *out_required = 1;
        return 0;
    }
    return -1;
}

static mp_obj_t vhttp_apply_query_spec(mp_obj_t query_dict, mp_obj_t query_spec, mp_obj_t params_dict) {
    if (query_spec == mp_const_none) {
        return mp_const_none;
    }
    if (!mp_obj_is_type(query_spec, &mp_type_dict)) {
        mp_raise_TypeError(MP_ERROR_TEXT("query spec must be dict"));
    }

    mp_map_t *spec_map = mp_obj_dict_get_map(query_spec);
    mp_map_t *query_map = mp_obj_dict_get_map(query_dict);
    mp_map_t *params_map = mp_obj_dict_get_map(params_dict);

    for (size_t i = 0; i < spec_map->alloc; ++i) {
        if (!mp_map_slot_is_filled(spec_map, i)) {
            continue;
        }
        mp_obj_t key = spec_map->table[i].key;
        mp_obj_t spec = spec_map->table[i].value;

        if (mp_map_lookup(params_map, key, MP_MAP_LOOKUP) != NULL) {
            continue;
        }

        mp_map_elem_t *query_elem = mp_map_lookup(query_map, key, MP_MAP_LOOKUP);
        vhttp_cast_kind_t kind = VHTTP_CAST_NONE;
        mp_obj_t default_val = mp_const_none;
        int required = 1;
        if (vhttp_unpack_query_spec(spec, &kind, &default_val, &required) != 0) {
            mp_raise_TypeError(MP_ERROR_TEXT("invalid query spec"));
        }

        if (query_elem == NULL) {
            if (required) {
                return vhttp_query_error("Missing query param: ", key);
            }
            if (kind == VHTTP_CAST_NONE) {
                mp_obj_dict_store(query_dict, key, default_val);
            } else {
                if (!vhttp_default_compatible(default_val, kind)) {
                    mp_raise_TypeError(MP_ERROR_TEXT("query default incompatible with cast"));
                }
                if (default_val == mp_const_none) {
                    mp_obj_dict_store(query_dict, key, default_val);
                } else if (mp_obj_is_str(default_val) ||
                           mp_obj_is_type(default_val, &mp_type_bytes) ||
                           mp_obj_is_type(default_val, &mp_type_bytearray)) {
                    size_t val_len = 0;
                    const char *val_ptr = mp_obj_str_get_data(default_val, &val_len);
                    mp_obj_t casted = mp_const_none;
                    if (vhttp_cast_from_str(val_ptr, val_len, kind, &casted) != 0) {
                        return vhttp_query_error("Invalid query param: ", key);
                    }
                    mp_obj_dict_store(query_dict, key, casted);
                } else {
                    mp_obj_dict_store(query_dict, key, default_val);
                }
            }
            continue;
        }

        if (kind == VHTTP_CAST_NONE) {
            continue;
        }

        mp_obj_t value = query_elem->value;
        if (mp_obj_is_str(value) ||
            mp_obj_is_type(value, &mp_type_bytes) ||
            mp_obj_is_type(value, &mp_type_bytearray)) {
            size_t val_len = 0;
            const char *val_ptr = mp_obj_str_get_data(value, &val_len);
            mp_obj_t casted = mp_const_none;
            if (vhttp_cast_from_str(val_ptr, val_len, kind, &casted) != 0) {
                return vhttp_query_error("Invalid query param: ", key);
            }
            mp_obj_dict_store(query_dict, key, casted);
        } else if (vhttp_default_compatible(value, kind)) {
            mp_obj_dict_store(query_dict, key, value);
        } else {
            return vhttp_query_error("Invalid query param: ", key);
        }
    }

    return mp_const_none;
}

static void vhttp_merge_query_params(mp_obj_t params_dict, mp_obj_t query_dict) {
    mp_map_t *params_map = mp_obj_dict_get_map(params_dict);
    mp_map_t *query_map = mp_obj_dict_get_map(query_dict);
    for (size_t i = 0; i < query_map->alloc; ++i) {
        if (!mp_map_slot_is_filled(query_map, i)) {
            continue;
        }
        mp_obj_t key = query_map->table[i].key;
        if (mp_map_lookup(params_map, key, MP_MAP_LOOKUP) != NULL) {
            continue;
        }
        mp_obj_dict_store(params_dict, key, query_map->table[i].value);
    }
}

static void vhttp_validate_query_spec(mp_obj_t query_spec) {
    if (query_spec == mp_const_none) {
        return;
    }
    if (!mp_obj_is_type(query_spec, &mp_type_dict)) {
        mp_raise_TypeError(MP_ERROR_TEXT("query spec must be dict"));
    }
    mp_map_t *spec_map = mp_obj_dict_get_map(query_spec);
    for (size_t i = 0; i < spec_map->alloc; ++i) {
        if (!mp_map_slot_is_filled(spec_map, i)) {
            continue;
        }
        mp_obj_t key = spec_map->table[i].key;
        mp_obj_t spec = spec_map->table[i].value;
        if (!mp_obj_is_str(key)) {
            mp_raise_TypeError(MP_ERROR_TEXT("query spec keys must be str"));
        }
        if (vhttp_is_query_spec(spec)) {
            vhttp_cast_kind_t kind = VHTTP_CAST_NONE;
            mp_obj_t default_val = mp_const_none;
            int required = 1;
            if (vhttp_unpack_query_spec(spec, &kind, &default_val, &required) != 0) {
                mp_raise_TypeError(MP_ERROR_TEXT("invalid Query() spec"));
            }
            if (kind != VHTTP_CAST_NONE && !vhttp_default_compatible(default_val, kind)) {
                mp_raise_TypeError(MP_ERROR_TEXT("query default incompatible with cast"));
            }
            continue;
        }
        if (vhttp_cast_kind_from_obj(spec) != VHTTP_CAST_NONE) {
            continue;
        }
        mp_raise_TypeError(MP_ERROR_TEXT("query spec must use Query() or type"));
    }
}

static void vhttp_validate_tags_obj(mp_obj_t tags) {
    if (tags == mp_const_none) {
        return;
    }
    if (mp_obj_is_str(tags)) {
        return;
    }
    if (!(mp_obj_is_type(tags, &mp_type_list) || mp_obj_is_type(tags, &mp_type_tuple))) {
        mp_raise_TypeError(MP_ERROR_TEXT("tags must be str/list/tuple"));
    }
    size_t len = 0;
    mp_obj_t *items = NULL;
    mp_obj_get_array(tags, &len, &items);
    for (size_t i = 0; i < len; ++i) {
        if (!mp_obj_is_str(items[i])) {
            mp_raise_TypeError(MP_ERROR_TEXT("tags items must be str"));
        }
    }
}

static mp_obj_t vhttp_tags_to_list(mp_obj_t tags) {
    if (tags == mp_const_none) {
        return mp_obj_new_list(0, NULL);
    }
    if (mp_obj_is_str(tags)) {
        mp_obj_t out = mp_obj_new_list(0, NULL);
        mp_obj_list_append(out, tags);
        return out;
    }
    if (mp_obj_is_type(tags, &mp_type_list) || mp_obj_is_type(tags, &mp_type_tuple)) {
        size_t len = 0;
        mp_obj_t *items = NULL;
        mp_obj_get_array(tags, &len, &items);
        mp_obj_t out = mp_obj_new_list(0, NULL);
        for (size_t i = 0; i < len; ++i) {
            if (!mp_obj_is_str(items[i])) {
                mp_raise_TypeError(MP_ERROR_TEXT("tags items must be str"));
            }
            mp_obj_list_append(out, items[i]);
        }
        return out;
    }
    mp_raise_TypeError(MP_ERROR_TEXT("tags must be str/list/tuple"));
}

static int vhttp_tag_list_contains(mp_obj_t list_obj, mp_obj_t tag) {
    if (!mp_obj_is_type(list_obj, &mp_type_list)) {
        return 0;
    }
    size_t n = 0;
    mp_obj_t *items = NULL;
    mp_obj_get_array(list_obj, &n, &items);
    for (size_t i = 0; i < n; ++i) {
        if (!mp_obj_is_str(items[i])) {
            continue;
        }
        if (mp_obj_equal(items[i], tag)) {
            return 1;
        }
    }
    return 0;
}

static mp_obj_t vhttp_merge_tag_lists(mp_obj_t base_tags, mp_obj_t extra_tags) {
    mp_obj_t out = vhttp_tags_to_list(base_tags);
    mp_obj_t extra = vhttp_tags_to_list(extra_tags);
    size_t n = 0;
    mp_obj_t *items = NULL;
    mp_obj_get_array(extra, &n, &items);
    for (size_t i = 0; i < n; ++i) {
        if (!vhttp_tag_list_contains(out, items[i])) {
            mp_obj_list_append(out, items[i]);
        }
    }
    return out;
}

static mp_obj_t vhttp_copy_dict(mp_obj_t obj) {
    if (!mp_obj_is_type(obj, &mp_type_dict)) {
        mp_raise_TypeError(MP_ERROR_TEXT("dict required"));
    }
    mp_obj_t out = mp_obj_new_dict(0);
    mp_map_t *map = mp_obj_dict_get_map(obj);
    for (size_t i = 0; i < map->alloc; ++i) {
        if (!mp_map_slot_is_filled(map, i)) {
            continue;
        }
        mp_obj_dict_store(out, map->table[i].key, map->table[i].value);
    }
    return out;
}

static void vhttp_validate_docs_spec(mp_obj_t docs_spec) {
    if (docs_spec == mp_const_none) {
        return;
    }
    if (!mp_obj_is_type(docs_spec, &mp_type_dict)) {
        mp_raise_TypeError(MP_ERROR_TEXT("docs spec must be dict"));
    }
    mp_obj_t key_summary = mp_obj_new_str("summary", 7);
    mp_obj_t key_description = mp_obj_new_str("description", 11);
    mp_obj_t key_tags = mp_obj_new_str("tags", 4);
    mp_obj_t key_responses = mp_obj_new_str("responses", 9);
    mp_obj_t key_operation_id = mp_obj_new_str("operation_id", 12);
    mp_obj_t key_name = mp_obj_new_str("name", 4);
    mp_obj_t key_request_body = mp_obj_new_str("request_body", 12);
    mp_obj_t key_deprecated = mp_obj_new_str("deprecated", 10);
    mp_obj_t key_include = mp_obj_new_str("include_in_schema", 17);

    nlr_buf_t nlr;
    mp_obj_t val = mp_const_none;
    if (nlr_push(&nlr) == 0) {
        val = mp_obj_dict_get(docs_spec, key_summary);
        nlr_pop();
        if (val != mp_const_none && !mp_obj_is_str(val)) {
            mp_raise_TypeError(MP_ERROR_TEXT("summary must be str"));
        }
    }
    if (nlr_push(&nlr) == 0) {
        val = mp_obj_dict_get(docs_spec, key_description);
        nlr_pop();
        if (val != mp_const_none && !mp_obj_is_str(val)) {
            mp_raise_TypeError(MP_ERROR_TEXT("description must be str"));
        }
    }
    if (nlr_push(&nlr) == 0) {
        val = mp_obj_dict_get(docs_spec, key_tags);
        nlr_pop();
        if (val != mp_const_none) {
            vhttp_validate_tags_obj(val);
        }
    }
    if (nlr_push(&nlr) == 0) {
        val = mp_obj_dict_get(docs_spec, key_responses);
        nlr_pop();
        if (val != mp_const_none && !mp_obj_is_type(val, &mp_type_dict)) {
            mp_raise_TypeError(MP_ERROR_TEXT("responses must be dict"));
        }
    }
    if (nlr_push(&nlr) == 0) {
        val = mp_obj_dict_get(docs_spec, key_request_body);
        nlr_pop();
        if (val != mp_const_none && !mp_obj_is_type(val, &mp_type_dict)) {
            mp_raise_TypeError(MP_ERROR_TEXT("request_body must be dict"));
        }
    }
    if (nlr_push(&nlr) == 0) {
        val = mp_obj_dict_get(docs_spec, key_operation_id);
        nlr_pop();
        if (val != mp_const_none && !mp_obj_is_str(val)) {
            mp_raise_TypeError(MP_ERROR_TEXT("operation_id must be str"));
        }
    }
    if (nlr_push(&nlr) == 0) {
        val = mp_obj_dict_get(docs_spec, key_name);
        nlr_pop();
        if (val != mp_const_none && !mp_obj_is_str(val)) {
            mp_raise_TypeError(MP_ERROR_TEXT("name must be str"));
        }
    }
    if (nlr_push(&nlr) == 0) {
        val = mp_obj_dict_get(docs_spec, key_deprecated);
        nlr_pop();
        if (val != mp_const_none && !mp_obj_is_bool(val)) {
            mp_raise_TypeError(MP_ERROR_TEXT("deprecated must be bool"));
        }
    }
    if (nlr_push(&nlr) == 0) {
        val = mp_obj_dict_get(docs_spec, key_include);
        nlr_pop();
        if (val != mp_const_none && !mp_obj_is_bool(val)) {
            mp_raise_TypeError(MP_ERROR_TEXT("include_in_schema must be bool"));
        }
    }
}

static mp_obj_t vhttp_build_docs_spec(
    mp_obj_t summary,
    mp_obj_t description,
    mp_obj_t tags,
    mp_obj_t responses,
    mp_obj_t operation_id,
    mp_obj_t name,
    mp_obj_t request_body,
    int has_deprecated,
    mp_obj_t deprecated,
    int has_include_in_schema,
    mp_obj_t include_in_schema
) {
    mp_obj_t docs = mp_obj_new_dict(0);
    int used = 0;
    if (summary != mp_const_none) {
        if (!mp_obj_is_str(summary)) {
            mp_raise_TypeError(MP_ERROR_TEXT("summary must be str"));
        }
        mp_obj_dict_store(docs, mp_obj_new_str("summary", 7), summary);
        used = 1;
    }
    if (description != mp_const_none) {
        if (!mp_obj_is_str(description)) {
            mp_raise_TypeError(MP_ERROR_TEXT("description must be str"));
        }
        mp_obj_dict_store(docs, mp_obj_new_str("description", 11), description);
        used = 1;
    }
    if (tags != mp_const_none) {
        vhttp_validate_tags_obj(tags);
        mp_obj_dict_store(docs, mp_obj_new_str("tags", 4), vhttp_tags_to_list(tags));
        used = 1;
    }
    if (responses != mp_const_none) {
        if (!mp_obj_is_type(responses, &mp_type_dict)) {
            mp_raise_TypeError(MP_ERROR_TEXT("responses must be dict"));
        }
        mp_obj_dict_store(docs, mp_obj_new_str("responses", 9), responses);
        used = 1;
    }
    if (operation_id != mp_const_none) {
        if (!mp_obj_is_str(operation_id)) {
            mp_raise_TypeError(MP_ERROR_TEXT("operation_id must be str"));
        }
        mp_obj_dict_store(docs, mp_obj_new_str("operation_id", 12), operation_id);
        used = 1;
    }
    if (name != mp_const_none) {
        if (!mp_obj_is_str(name)) {
            mp_raise_TypeError(MP_ERROR_TEXT("name must be str"));
        }
        mp_obj_dict_store(docs, mp_obj_new_str("name", 4), name);
        used = 1;
    }
    if (request_body != mp_const_none) {
        if (!mp_obj_is_type(request_body, &mp_type_dict)) {
            mp_raise_TypeError(MP_ERROR_TEXT("request_body must be dict"));
        }
        mp_obj_dict_store(docs, mp_obj_new_str("request_body", 12), request_body);
        used = 1;
    }
    if (has_deprecated) {
        if (!mp_obj_is_bool(deprecated)) {
            mp_raise_TypeError(MP_ERROR_TEXT("deprecated must be bool"));
        }
        mp_obj_dict_store(docs, mp_obj_new_str("deprecated", 10), deprecated);
        used = 1;
    }
    if (has_include_in_schema) {
        if (!mp_obj_is_bool(include_in_schema)) {
            mp_raise_TypeError(MP_ERROR_TEXT("include_in_schema must be bool"));
        }
        mp_obj_dict_store(docs, mp_obj_new_str("include_in_schema", 17), include_in_schema);
        used = 1;
    }
    if (!used) {
        return mp_const_none;
    }
    return docs;
}

static mp_obj_t vhttp_merge_docs_with_router_tags(mp_obj_t docs_spec, mp_obj_t router_tags) {
    if (router_tags == mp_const_none) {
        return docs_spec;
    }
    vhttp_validate_tags_obj(router_tags);
    if (docs_spec == mp_const_none) {
        mp_obj_t docs = mp_obj_new_dict(0);
        mp_obj_dict_store(docs, mp_obj_new_str("tags", 4), vhttp_tags_to_list(router_tags));
        return docs;
    }
    vhttp_validate_docs_spec(docs_spec);
    mp_obj_t merged = vhttp_copy_dict(docs_spec);
    mp_obj_t key_tags = mp_obj_new_str("tags", 4);
    mp_obj_t current_tags = mp_const_none;
    nlr_buf_t nlr;
    if (nlr_push(&nlr) == 0) {
        current_tags = mp_obj_dict_get(merged, key_tags);
        nlr_pop();
    } else {
        current_tags = mp_const_none;
    }
    mp_obj_t final_tags = vhttp_merge_tag_lists(router_tags, current_tags);
    mp_obj_dict_store(merged, key_tags, final_tags);
    return merged;
}

static mp_obj_t vhttp_get_handler_meta(vhttp_app_t *app, mp_obj_t handler) {
    size_t handlers_len = 0;
    mp_obj_t *handlers_items = NULL;
    mp_obj_list_get(app->handlers, &handlers_len, &handlers_items);

    size_t meta_len = 0;
    mp_obj_t *meta_items = NULL;
    mp_obj_list_get(app->handler_meta, &meta_len, &meta_items);
    if (meta_len < handlers_len) {
        handlers_len = meta_len;
    }

    for (size_t i = 0; i < handlers_len; ++i) {
        if (handlers_items[i] == handler) {
            return meta_items[i];
        }
    }
    return mp_const_none;
}

static const char *router_err_to_str(vhttp_router_result_t res) {
    switch (res) {
        case VHTTP_ROUTER_OK:
            return "OK";
        case VHTTP_ROUTER_NOT_FOUND:
            return "NOT_FOUND";
        case VHTTP_ROUTER_ERR_INVALID:
            return "INVALID";
        case VHTTP_ROUTER_ERR_CONFLICT:
            return "CONFLICT";
        case VHTTP_ROUTER_ERR_FULL:
            return "FULL";
        case VHTTP_ROUTER_ERR_UNSUPPORTED:
            return "UNSUPPORTED";
        case VHTTP_ROUTER_ERR_TOO_LARGE:
            return "TOO_LARGE";
        default:
            return "UNKNOWN";
    }
}

static void vhttp_app_add_route(
    vhttp_app_t *app,
    const char *method,
    size_t method_len,
    mp_obj_t path_obj,
    mp_obj_t query_spec,
    mp_obj_t deps_spec,
    mp_obj_t docs_spec,
    mp_obj_t protocols_spec,
    mp_obj_t handler
) {
    if (app != vhttp_active_app_ptr()) {
        mp_raise_ValueError(MP_ERROR_TEXT("app not active"));
    }

    ensure_router_ready();
    vhttp_validate_query_spec(query_spec);
    vhttp_validate_deps_spec(deps_spec);
    vhttp_validate_docs_spec(docs_spec);
    if (protocols_spec != mp_const_none &&
        !(mp_obj_is_type(protocols_spec, &mp_type_list) || mp_obj_is_type(protocols_spec, &mp_type_tuple))) {
        mp_raise_TypeError(MP_ERROR_TEXT("protocols must be list/tuple"));
    }

    size_t path_len = 0;
    const char *path = mp_obj_str_get_data(path_obj, &path_len);

    size_t handlers_len = 0;
    mp_obj_t *handlers_items = NULL;
    mp_obj_list_get(app->handlers, &handlers_len, &handlers_items);
    size_t handler_id = handlers_len;

    vhttp_route_target_t target = {0};
    target.handler_id = (uint16_t)handler_id;

    vhttp_router_result_t res = vhttp_router_add(
        &g_router,
        method,
        method_len,
        path,
        path_len,
        target
    );

    if (res != VHTTP_ROUTER_OK) {
        mp_raise_msg_varg(
            &mp_type_ValueError,
            MP_ERROR_TEXT("route add failed: %s"),
            router_err_to_str(res)
        );
    }

    mp_obj_list_append(app->handlers, handler);
    mp_obj_t meta = mp_obj_new_dict(6);
    mp_obj_dict_store(meta, mp_obj_new_str("method", 6), mp_obj_new_str(method, method_len));
    mp_obj_dict_store(meta, mp_obj_new_str("path", 4), path_obj);
    if (query_spec != mp_const_none) {
        mp_obj_dict_store(meta, MP_OBJ_NEW_QSTR(MP_QSTR_query), query_spec);
    }
    if (deps_spec != mp_const_none) {
        mp_obj_dict_store(meta, mp_obj_new_str("deps", 4), deps_spec);
    }
    if (docs_spec != mp_const_none) {
        mp_obj_dict_store(meta, mp_obj_new_str("docs", 4), docs_spec);
    }
    if (protocols_spec != mp_const_none) {
        mp_obj_dict_store(meta, mp_obj_new_str("protocols", 9), protocols_spec);
    }
    mp_obj_list_append(app->handler_meta, meta);
}

static mp_obj_t vhttp_route_decorator_call(mp_obj_t self_in, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    if (n_kw != 0 || n_args != 1) {
        mp_raise_TypeError(MP_ERROR_TEXT("decorator expects handler"));
    }

    vhttp_route_decorator_t *dec = MP_OBJ_TO_PTR(self_in);
    vhttp_app_t *app = dec->app;
    mp_obj_t handler = args[0];
    vhttp_app_add_route(
        app,
        dec->method,
        dec->method_len,
        dec->path_obj,
        dec->query_spec,
        dec->deps_spec,
        dec->docs_spec,
        dec->protocols_spec,
        handler
    );

    return handler;
}

MP_DEFINE_CONST_OBJ_TYPE(
    vhttp_route_decorator_type,
    MP_QSTR__RouteDecorator,
    MP_TYPE_FLAG_NONE,
    call, vhttp_route_decorator_call
);

static mp_obj_t vhttp_middleware_decorator_call(mp_obj_t self_in, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    if (n_kw != 0 || n_args != 1) {
        mp_raise_TypeError(MP_ERROR_TEXT("decorator expects handler"));
    }

    vhttp_middleware_decorator_t *dec = MP_OBJ_TO_PTR(self_in);
    vhttp_app_t *app = dec->app;
    mp_obj_t handler = args[0];

    mp_obj_t entry_items[4] = {
        mp_obj_new_str("func", 4),
        handler,
        mp_const_none,
        mp_obj_new_int(dec->priority),
    };
    mp_obj_list_append(app->middlewares, mp_obj_new_tuple(4, entry_items));
    return handler;
}

MP_DEFINE_CONST_OBJ_TYPE(
    vhttp_middleware_decorator_type,
    MP_QSTR__MiddlewareDecorator,
    MP_TYPE_FLAG_NONE,
    call, vhttp_middleware_decorator_call
);

static mp_obj_t vhttp_router_decorator_call(mp_obj_t self_in, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    if (n_kw != 0 || n_args != 1) {
        mp_raise_TypeError(MP_ERROR_TEXT("decorator expects handler"));
    }

    vhttp_router_decorator_t *dec = MP_OBJ_TO_PTR(self_in);
    vhttp_router_obj_t *router = dec->router;
    mp_obj_t handler = args[0];

    vhttp_validate_query_spec(dec->query_spec);
    vhttp_validate_deps_spec(dec->deps_spec);
    vhttp_validate_docs_spec(dec->docs_spec);

    if (!mp_obj_is_str(dec->path_obj)) {
        mp_raise_TypeError(MP_ERROR_TEXT("path must be str"));
    }

    mp_obj_t route = mp_obj_new_dict(7);
    mp_obj_dict_store(route, mp_obj_new_str("method", 6), mp_obj_new_str(dec->method, dec->method_len));
    mp_obj_dict_store(route, mp_obj_new_str("path", 4), dec->path_obj);
    mp_obj_dict_store(route, mp_obj_new_str("handler", 7), handler);
    if (dec->query_spec != mp_const_none) {
        mp_obj_dict_store(route, mp_obj_new_str("query", 5), dec->query_spec);
    }
    if (dec->deps_spec != mp_const_none) {
        mp_obj_dict_store(route, mp_obj_new_str("deps", 4), dec->deps_spec);
    }
    if (dec->docs_spec != mp_const_none) {
        mp_obj_dict_store(route, mp_obj_new_str("docs", 4), dec->docs_spec);
    }
    if (dec->protocols_spec != mp_const_none) {
        mp_obj_dict_store(route, mp_obj_new_str("protocols", 9), dec->protocols_spec);
    }
    mp_obj_list_append(router->routes, route);

    return handler;
}

MP_DEFINE_CONST_OBJ_TYPE(
    vhttp_router_decorator_type,
    MP_QSTR__RouterDecorator,
    MP_TYPE_FLAG_NONE,
    call, vhttp_router_decorator_call
);

static mp_obj_t vhttp_make_response_dict(
    mp_int_t status_code,
    mp_obj_t body,
    mp_obj_t headers,
    mp_obj_t content_type
) {
    mp_obj_t dict = mp_obj_new_dict(5);
    mp_obj_dict_store(dict, mp_obj_new_str("__vhttp_response__", 18), mp_const_true);
    mp_obj_dict_store(dict, mp_obj_new_str("status_code", 11), mp_obj_new_int(status_code));
    mp_obj_dict_store(dict, mp_obj_new_str("body", 4), body);
    mp_obj_dict_store(dict, mp_obj_new_str("headers", 7), headers);
    mp_obj_dict_store(dict, mp_obj_new_str("content_type", 12), content_type);
    return dict;
}

static int vhttp_is_response_dict(mp_obj_t obj) {
    if (!mp_obj_is_type(obj, &mp_type_dict)) {
        return 0;
    }
    mp_obj_t key = mp_obj_new_str("__vhttp_response__", 18);
    nlr_buf_t nlr;
    if (nlr_push(&nlr) == 0) {
        mp_obj_t val = mp_obj_dict_get(obj, key);
        nlr_pop();
        return mp_obj_is_true(val);
    }
    return 0;
}

static int vhttp_str_ci_equals(const char *a, size_t a_len, const char *b) {
    size_t b_len = strlen(b);
    if (a_len != b_len) {
        return 0;
    }
    for (size_t i = 0; i < a_len; ++i) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z') {
            ca = (char)(ca + ('a' - 'A'));
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (char)(cb + ('a' - 'A'));
        }
        if (ca != cb) {
            return 0;
        }
    }
    return 1;
}

static int vhttp_str_ci_contains(const char *haystack, size_t hay_len, const char *needle) {
    size_t needle_len = strlen(needle);
    if (needle_len == 0 || hay_len < needle_len) {
        return 0;
    }
    for (size_t i = 0; i + needle_len <= hay_len; ++i) {
        size_t j = 0;
        for (; j < needle_len; ++j) {
            char ca = haystack[i + j];
            char cb = needle[j];
            if (ca >= 'A' && ca <= 'Z') {
                ca = (char)(ca + ('a' - 'A'));
            }
            if (cb >= 'A' && cb <= 'Z') {
                cb = (char)(cb + ('a' - 'A'));
            }
            if (ca != cb) {
                break;
            }
        }
        if (j == needle_len) {
            return 1;
        }
    }
    return 0;
}

static void vhttp_vstr_add_obj(vstr_t *v, mp_obj_t obj) {
    if (!v || obj == mp_const_none) {
        return;
    }
    if (mp_obj_is_str(obj)) {
        size_t len = 0;
        const char *data = mp_obj_str_get_data(obj, &len);
        vstr_add_strn(v, data, len);
        return;
    }
    if (mp_obj_is_type(obj, &mp_type_bytes) || mp_obj_is_type(obj, &mp_type_bytearray)) {
        mp_buffer_info_t bufinfo;
        mp_get_buffer_raise(obj, &bufinfo, MP_BUFFER_READ);
        vstr_add_strn(v, (const char *)bufinfo.buf, bufinfo.len);
        return;
    }
    mp_raise_ValueError(MP_ERROR_TEXT("header must be str/bytes/bytearray"));
}

static void vhttp_vstr_add_header(vstr_t *v, mp_obj_t key, mp_obj_t value) {
    if (!v || key == mp_const_none) {
        return;
    }
    vhttp_vstr_add_obj(v, key);
    vstr_add_str(v, ": ");
    vhttp_vstr_add_obj(v, value);
    vstr_add_str(v, "\r\n");
}

static int vhttp_headers_has_content_type(mp_obj_t headers) {
    if (headers == mp_const_none) {
        return 0;
    }
    if (mp_obj_is_type(headers, &mp_type_dict)) {
        mp_obj_dict_t *dict = MP_OBJ_TO_PTR(headers);
        mp_map_t *map = &dict->map;
        for (size_t i = 0; i < map->alloc; ++i) {
            if (MP_MAP_SLOT_IS_FILLED(map, i)) {
                mp_obj_t key = map->table[i].key;
                if (mp_obj_is_str(key)) {
                    size_t len = 0;
                    const char *data = mp_obj_str_get_data(key, &len);
                    if (vhttp_str_ci_equals(data, len, "content-type")) {
                        return 1;
                    }
                }
            }
        }
        return 0;
    }
    if (mp_obj_is_type(headers, &mp_type_list) || mp_obj_is_type(headers, &mp_type_tuple)) {
        size_t len = 0;
        mp_obj_t *items = NULL;
        mp_obj_get_array(headers, &len, &items);
        for (size_t i = 0; i < len; ++i) {
            mp_obj_t pair = items[i];
            if (mp_obj_is_type(pair, &mp_type_tuple) || mp_obj_is_type(pair, &mp_type_list)) {
                size_t pair_len = 0;
                mp_obj_t *pair_items = NULL;
                mp_obj_get_array(pair, &pair_len, &pair_items);
                if (pair_len >= 2 && mp_obj_is_str(pair_items[0])) {
                    size_t key_len = 0;
                    const char *key = mp_obj_str_get_data(pair_items[0], &key_len);
                    if (vhttp_str_ci_equals(key, key_len, "content-type")) {
                        return 1;
                    }
                }
            }
        }
        return 0;
    }
    if (mp_obj_is_str(headers) || mp_obj_is_type(headers, &mp_type_bytes) || mp_obj_is_type(headers, &mp_type_bytearray)) {
        size_t len = 0;
        const char *data = NULL;
        if (mp_obj_is_str(headers)) {
            data = mp_obj_str_get_data(headers, &len);
        } else {
            mp_buffer_info_t bufinfo;
            mp_get_buffer_raise(headers, &bufinfo, MP_BUFFER_READ);
            data = (const char *)bufinfo.buf;
            len = bufinfo.len;
        }
        return vhttp_str_ci_contains(data, len, "content-type");
    }
    return 0;
}

static void vhttp_append_headers(vstr_t *v, mp_obj_t headers) {
    if (!v || headers == mp_const_none) {
        return;
    }
    if (mp_obj_is_type(headers, &mp_type_dict)) {
        mp_obj_dict_t *dict = MP_OBJ_TO_PTR(headers);
        mp_map_t *map = &dict->map;
        for (size_t i = 0; i < map->alloc; ++i) {
            if (MP_MAP_SLOT_IS_FILLED(map, i)) {
                mp_obj_t key = map->table[i].key;
                mp_obj_t value = map->table[i].value;
                vhttp_vstr_add_header(v, key, value);
            }
        }
        return;
    }
    if (mp_obj_is_type(headers, &mp_type_list) || mp_obj_is_type(headers, &mp_type_tuple)) {
        size_t len = 0;
        mp_obj_t *items = NULL;
        mp_obj_get_array(headers, &len, &items);
        for (size_t i = 0; i < len; ++i) {
            mp_obj_t pair = items[i];
            if (mp_obj_is_type(pair, &mp_type_tuple) || mp_obj_is_type(pair, &mp_type_list)) {
                size_t pair_len = 0;
                mp_obj_t *pair_items = NULL;
                mp_obj_get_array(pair, &pair_len, &pair_items);
                if (pair_len >= 2) {
                    vhttp_vstr_add_header(v, pair_items[0], pair_items[1]);
                }
            }
        }
        return;
    }
    if (mp_obj_is_str(headers) || mp_obj_is_type(headers, &mp_type_bytes) || mp_obj_is_type(headers, &mp_type_bytearray)) {
        size_t before = v->len;
        vhttp_vstr_add_obj(v, headers);
        if (v->len >= before + 2) {
            if (!(v->buf[v->len - 2] == '\r' && v->buf[v->len - 1] == '\n')) {
                vstr_add_str(v, "\r\n");
            }
        } else if (v->len > before) {
            vstr_add_str(v, "\r\n");
        }
    }
}

static mp_obj_t vhttp_normalize_result(mp_obj_t result) {
    if (vhttp_is_response_dict(result)) {
        return result;
    }

    if (result == mp_const_none) {
        return vhttp_make_response_dict(204, mp_const_none, mp_const_none, mp_const_none);
    }

    if (mp_obj_is_type(result, &mp_type_dict) || mp_obj_is_type(result, &mp_type_list)) {
        mp_obj_t content_type = mp_obj_new_str("application/json", 16);
        return vhttp_make_response_dict(200, result, mp_const_none, content_type);
    }

    if (mp_obj_is_str(result)) {
        mp_obj_t content_type = mp_obj_new_str("text/plain; charset=utf-8", 25);
        return vhttp_make_response_dict(200, result, mp_const_none, content_type);
    }

    if (mp_obj_is_type(result, &mp_type_bytes) || mp_obj_is_type(result, &mp_type_bytearray)) {
        mp_obj_t content_type = mp_obj_new_str("application/octet-stream", 24);
        return vhttp_make_response_dict(200, result, mp_const_none, content_type);
    }

    return vhttp_make_response_dict(200, result, mp_const_none, mp_const_none);
}

static mp_obj_t vhttp_make_error_response(mp_int_t status_code, mp_obj_t detail) {
    if (detail == mp_const_none) {
        detail = mp_obj_new_str("Internal Server Error", 21);
    }
    mp_obj_t body = mp_obj_new_dict(1);
    mp_obj_dict_store(body, mp_obj_new_str("detail", 6), detail);
    mp_obj_t content_type = mp_obj_new_str("application/json", 16);
    return vhttp_make_response_dict(status_code, body, mp_const_none, content_type);
}

static void vhttp_raise_http(mp_int_t status_code, const char *message) {
    if (!message) {
        message = "Request error";
    }
    mp_obj_t args[2] = {
        MP_OBJ_NEW_SMALL_INT(status_code),
        mp_obj_new_str(message, strlen(message)),
    };
    nlr_raise(mp_obj_new_exception_args(&mp_type_HTTPException, 2, args));
}

static mp_obj_t vhttp_exception_to_response(mp_obj_t exc) {
    if (mp_obj_is_type(exc, &mp_type_HTTPException)) {
        mp_int_t status = 500;
        mp_obj_t detail = mp_const_none;
        mp_obj_t val = mp_obj_exception_get_value(exc);
        mp_obj_t args_obj = mp_const_none;
        nlr_buf_t nlr;
        if (nlr_push(&nlr) == 0) {
            args_obj = mp_load_attr(exc, MP_QSTR_args);
            nlr_pop();
        } else {
            args_obj = mp_const_none;
        }

        if (args_obj != mp_const_none &&
            (mp_obj_is_type(args_obj, &mp_type_tuple) || mp_obj_is_type(args_obj, &mp_type_list))) {
            size_t len = 0;
            mp_obj_t *vals = NULL;
            mp_obj_get_array(args_obj, &len, &vals);
            if (len >= 1 && mp_obj_is_int(vals[0])) {
                status = mp_obj_get_int(vals[0]);
            }
            if (len >= 2) {
                detail = vals[1];
            }
        } else if (mp_obj_is_type(val, &mp_type_tuple) || mp_obj_is_type(val, &mp_type_list)) {
            size_t len = 0;
            mp_obj_t *vals = NULL;
            mp_obj_get_array(val, &len, &vals);
            if (len >= 1 && mp_obj_is_int(vals[0])) {
                status = mp_obj_get_int(vals[0]);
            }
            if (len >= 2) {
                detail = vals[1];
            }
        } else if (mp_obj_is_int(val)) {
            status = mp_obj_get_int(val);
        } else if (val != MP_OBJ_NULL && val != mp_const_none) {
            detail = val;
        }
        return vhttp_make_error_response(status, detail);
    }
    return vhttp_make_error_response(500, mp_const_none);
}

static int vhttp_is_http_exception_obj(mp_obj_t exc) {
    if (exc == MP_OBJ_NULL || exc == mp_const_none) {
        return 0;
    }
    return mp_obj_is_type(exc, &mp_type_HTTPException);
}

static mp_obj_t vhttp_router_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    if (n_args > 1) {
        mp_raise_TypeError(MP_ERROR_TEXT("Router([prefix])"));
    }

    mp_obj_t prefix = mp_obj_new_str("", 0);
    if (n_args == 1) {
        prefix = args[0];
    }

    mp_obj_t tags = mp_const_none;
    mp_obj_t deps = mp_const_none;

    if (n_kw > 0) {
        mp_map_t kw_args;
        mp_map_init_fixed_table(&kw_args, n_kw, args + n_args);
        for (size_t i = 0; i < kw_args.alloc; ++i) {
            if (!mp_map_slot_is_filled(&kw_args, i)) {
                continue;
            }
            mp_obj_t key = kw_args.table[i].key;
            mp_obj_t val = kw_args.table[i].value;
            if (!mp_obj_is_str(key)) {
                mp_raise_TypeError(MP_ERROR_TEXT("keyword must be str"));
            }
            size_t len = 0;
            const char *name = mp_obj_str_get_data(key, &len);
            if (len == 6 && memcmp(name, "prefix", 6) == 0) {
                prefix = val;
            } else if (len == 4 && memcmp(name, "tags", 4) == 0) {
                tags = val;
            } else if (len == 4 && memcmp(name, "deps", 4) == 0) {
                deps = val;
            } else {
                mp_raise_TypeError(MP_ERROR_TEXT("unknown keyword"));
            }
        }
    }

    if (!mp_obj_is_str(prefix)) {
        mp_raise_TypeError(MP_ERROR_TEXT("prefix must be str"));
    }
    vhttp_validate_tags_obj(tags);
    if (deps != mp_const_none && !mp_obj_is_type(deps, &mp_type_dict)) {
        mp_raise_TypeError(MP_ERROR_TEXT("deps must be dict"));
    }

    vhttp_router_obj_t *router = mp_obj_malloc(vhttp_router_obj_t, type);
    router->prefix = prefix;
    router->tags = tags;
    router->deps = deps;
    router->routes = mp_obj_new_list(0, NULL);

    vhttp_validate_deps_spec(deps);
    return MP_OBJ_FROM_PTR(router);
}

static mp_obj_t vhttp_make_router_decorator(
    mp_obj_t self_in,
    mp_obj_t path_obj,
    mp_obj_t query_spec,
    mp_obj_t deps_spec,
    mp_obj_t docs_spec,
    mp_obj_t protocols_spec,
    const char *method
) {
    vhttp_router_decorator_t *dec = mp_obj_malloc(vhttp_router_decorator_t, &vhttp_router_decorator_type);
    dec->router = MP_OBJ_TO_PTR(self_in);
    dec->method = method;
    dec->method_len = strlen(method);
    dec->path_obj = path_obj;
    dec->query_spec = query_spec;
    dec->deps_spec = deps_spec;
    dec->docs_spec = docs_spec;
    dec->protocols_spec = protocols_spec;
    return MP_OBJ_FROM_PTR(dec);
}

static bool vhttp_is_unexpected_background_kw(mp_obj_t exc) {
    if (!mp_obj_is_type(exc, &mp_type_TypeError)) {
        return false;
    }
    mp_obj_t val = mp_obj_exception_get_value(exc);
    if (val == mp_const_none) {
        return false;
    }
    const char *msg = NULL;
    size_t msg_len = 0;
    if (mp_obj_is_str_or_bytes(val)) {
        msg = mp_obj_str_get_data(val, &msg_len);
    } else if (mp_obj_is_type(val, &mp_type_tuple) || mp_obj_is_type(val, &mp_type_list)) {
        size_t len = 0;
        mp_obj_t *items = NULL;
        mp_obj_get_array(val, &len, &items);
        if (len > 0 && mp_obj_is_str_or_bytes(items[0])) {
            msg = mp_obj_str_get_data(items[0], &msg_len);
        }
    }
    if (!msg || msg_len == 0) {
        return false;
    }
    if (strstr(msg, "unexpected keyword argument") == NULL) {
        return false;
    }
    if (strstr(msg, "background_tasks") == NULL) {
        return false;
    }
    return true;
}

static mp_obj_t vhttp_make_router_decorator_kw(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args, const char *method) {
    if (n_args > 2) {
        mp_raise_TypeError(MP_ERROR_TEXT("too many positional args"));
    }

    mp_obj_t path_obj = mp_const_none;
    if (n_args >= 2) {
        path_obj = pos_args[1];
    }

    mp_obj_t query_spec = mp_const_none;
    mp_obj_t deps_spec = mp_const_none;
    mp_obj_t summary = mp_const_none;
    mp_obj_t description = mp_const_none;
    mp_obj_t tags = mp_const_none;
    mp_obj_t responses = mp_const_none;
    mp_obj_t operation_id = mp_const_none;
    mp_obj_t name = mp_const_none;
    mp_obj_t request_body = mp_const_none;
    int has_deprecated = 0;
    mp_obj_t deprecated = mp_const_false;
    int has_include_in_schema = 0;
    mp_obj_t include_in_schema = mp_const_true;

    if (kw_args != NULL && kw_args->used > 0) {
        mp_map_t *map = kw_args;
        for (size_t i = 0; i < map->alloc; ++i) {
            if (!mp_map_slot_is_filled(map, i)) {
                continue;
            }
            mp_obj_t key = map->table[i].key;
            if (!mp_obj_is_str(key)) {
                mp_raise_TypeError(MP_ERROR_TEXT("keyword must be str"));
            }
            size_t len = 0;
            const char *data = mp_obj_str_get_data(key, &len);
            if (len == 4 && memcmp(data, "path", 4) == 0) {
                path_obj = map->table[i].value;
            } else if (len == 5 && memcmp(data, "query", 5) == 0) {
                query_spec = map->table[i].value;
            } else if (len == 4 && memcmp(data, "deps", 4) == 0) {
                deps_spec = map->table[i].value;
            } else if (len == 7 && memcmp(data, "summary", 7) == 0) {
                summary = map->table[i].value;
            } else if (len == 11 && memcmp(data, "description", 11) == 0) {
                description = map->table[i].value;
            } else if (len == 4 && memcmp(data, "tags", 4) == 0) {
                tags = map->table[i].value;
            } else if (len == 9 && memcmp(data, "responses", 9) == 0) {
                responses = map->table[i].value;
            } else if (len == 12 && memcmp(data, "operation_id", 12) == 0) {
                operation_id = map->table[i].value;
            } else if (len == 4 && memcmp(data, "name", 4) == 0) {
                name = map->table[i].value;
            } else if (len == 12 && memcmp(data, "request_body", 12) == 0) {
                request_body = map->table[i].value;
            } else if (len == 10 && memcmp(data, "deprecated", 10) == 0) {
                has_deprecated = 1;
                deprecated = map->table[i].value;
            } else if (len == 17 && memcmp(data, "include_in_schema", 17) == 0) {
                has_include_in_schema = 1;
                include_in_schema = map->table[i].value;
            } else {
                mp_raise_TypeError(MP_ERROR_TEXT("unknown keyword"));
            }
        }
    }

    if (path_obj == mp_const_none) {
        mp_raise_TypeError(MP_ERROR_TEXT("path required"));
    }
    if (!mp_obj_is_str(path_obj)) {
        mp_raise_TypeError(MP_ERROR_TEXT("path must be str"));
    }

    mp_obj_t docs_spec = vhttp_build_docs_spec(
        summary,
        description,
        tags,
        responses,
        operation_id,
        name,
        request_body,
        has_deprecated,
        deprecated,
        has_include_in_schema,
        include_in_schema
    );

    return vhttp_make_router_decorator(pos_args[0], path_obj, query_spec, deps_spec, docs_spec, mp_const_none, method);
}

static mp_obj_t vhttp_make_router_decorator_ws_kw(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    if (n_args > 2) {
        mp_raise_TypeError(MP_ERROR_TEXT("too many positional args"));
    }

    mp_obj_t path_obj = mp_const_none;
    if (n_args >= 2) {
        path_obj = pos_args[1];
    }

    mp_obj_t query_spec = mp_const_none;
    mp_obj_t deps_spec = mp_const_none;
    mp_obj_t protocols_spec = mp_const_none;
    mp_obj_t summary = mp_const_none;
    mp_obj_t description = mp_const_none;
    mp_obj_t tags = mp_const_none;
    mp_obj_t responses = mp_const_none;
    mp_obj_t operation_id = mp_const_none;
    mp_obj_t name = mp_const_none;
    mp_obj_t request_body = mp_const_none;
    int has_deprecated = 0;
    mp_obj_t deprecated = mp_const_false;
    int has_include_in_schema = 0;
    mp_obj_t include_in_schema = mp_const_true;

    if (kw_args != NULL && kw_args->used > 0) {
        mp_map_t *map = kw_args;
        for (size_t i = 0; i < map->alloc; ++i) {
            if (!mp_map_slot_is_filled(map, i)) {
                continue;
            }
            mp_obj_t key = map->table[i].key;
            if (!mp_obj_is_str(key)) {
                mp_raise_TypeError(MP_ERROR_TEXT("keyword must be str"));
            }
            size_t len = 0;
            const char *data = mp_obj_str_get_data(key, &len);
            if (len == 4 && memcmp(data, "path", 4) == 0) {
                path_obj = map->table[i].value;
            } else if (len == 5 && memcmp(data, "query", 5) == 0) {
                query_spec = map->table[i].value;
            } else if (len == 4 && memcmp(data, "deps", 4) == 0) {
                deps_spec = map->table[i].value;
            } else if (len == 9 && memcmp(data, "protocols", 9) == 0) {
                protocols_spec = map->table[i].value;
            } else if (len == 7 && memcmp(data, "summary", 7) == 0) {
                summary = map->table[i].value;
            } else if (len == 11 && memcmp(data, "description", 11) == 0) {
                description = map->table[i].value;
            } else if (len == 4 && memcmp(data, "tags", 4) == 0) {
                tags = map->table[i].value;
            } else if (len == 9 && memcmp(data, "responses", 9) == 0) {
                responses = map->table[i].value;
            } else if (len == 12 && memcmp(data, "operation_id", 12) == 0) {
                operation_id = map->table[i].value;
            } else if (len == 4 && memcmp(data, "name", 4) == 0) {
                name = map->table[i].value;
            } else if (len == 12 && memcmp(data, "request_body", 12) == 0) {
                request_body = map->table[i].value;
            } else if (len == 10 && memcmp(data, "deprecated", 10) == 0) {
                has_deprecated = 1;
                deprecated = map->table[i].value;
            } else if (len == 17 && memcmp(data, "include_in_schema", 17) == 0) {
                has_include_in_schema = 1;
                include_in_schema = map->table[i].value;
            } else {
                mp_raise_TypeError(MP_ERROR_TEXT("unknown keyword"));
            }
        }
    }

    if (path_obj == mp_const_none) {
        mp_raise_TypeError(MP_ERROR_TEXT("path required"));
    }
    if (!mp_obj_is_str(path_obj)) {
        mp_raise_TypeError(MP_ERROR_TEXT("path must be str"));
    }
    if (protocols_spec != mp_const_none &&
        !(mp_obj_is_type(protocols_spec, &mp_type_list) || mp_obj_is_type(protocols_spec, &mp_type_tuple))) {
        mp_raise_TypeError(MP_ERROR_TEXT("protocols must be list/tuple"));
    }

    mp_obj_t docs_spec = vhttp_build_docs_spec(
        summary,
        description,
        tags,
        responses,
        operation_id,
        name,
        request_body,
        has_deprecated,
        deprecated,
        has_include_in_schema,
        include_in_schema
    );

    return vhttp_make_router_decorator(pos_args[0], path_obj, query_spec, deps_spec, docs_spec, protocols_spec, "WS");
}

static mp_obj_t vhttp_router_get(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    return vhttp_make_router_decorator_kw(n_args, pos_args, kw_args, "GET");
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_router_get_obj, 2, vhttp_router_get);

static mp_obj_t vhttp_router_post(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    return vhttp_make_router_decorator_kw(n_args, pos_args, kw_args, "POST");
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_router_post_obj, 2, vhttp_router_post);

static mp_obj_t vhttp_router_put(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    return vhttp_make_router_decorator_kw(n_args, pos_args, kw_args, "PUT");
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_router_put_obj, 2, vhttp_router_put);

static mp_obj_t vhttp_router_patch(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    return vhttp_make_router_decorator_kw(n_args, pos_args, kw_args, "PATCH");
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_router_patch_obj, 2, vhttp_router_patch);

static mp_obj_t vhttp_router_delete(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    return vhttp_make_router_decorator_kw(n_args, pos_args, kw_args, "DELETE");
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_router_delete_obj, 2, vhttp_router_delete);

static mp_obj_t vhttp_router_options(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    return vhttp_make_router_decorator_kw(n_args, pos_args, kw_args, "OPTIONS");
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_router_options_obj, 2, vhttp_router_options);

static mp_obj_t vhttp_router_head(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    return vhttp_make_router_decorator_kw(n_args, pos_args, kw_args, "HEAD");
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_router_head_obj, 2, vhttp_router_head);

static mp_obj_t vhttp_router_websocket(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    return vhttp_make_router_decorator_ws_kw(n_args, pos_args, kw_args);
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_router_websocket_obj, 2, vhttp_router_websocket);

static void vhttp_router_attr(mp_obj_t self_in, qstr attr, mp_obj_t *dest) {
    if (dest[0] == MP_OBJ_NULL) {
        if (vhttp_qstr_equals_lit(attr, "head", 4)) {
            dest[0] = MP_OBJ_FROM_PTR(&vhttp_router_head_obj);
            dest[1] = self_in;
            return;
        }
        // Fallback to locals dict for all other attributes.
        dest[1] = MP_OBJ_SENTINEL;
    }
}

static const mp_rom_map_elem_t vhttp_router_locals_table[] = {
    { MP_ROM_QSTR(MP_QSTR_get), MP_ROM_PTR(&vhttp_router_get_obj) },
    { MP_ROM_QSTR(MP_QSTR_post), MP_ROM_PTR(&vhttp_router_post_obj) },
    { MP_ROM_QSTR(MP_QSTR_put), MP_ROM_PTR(&vhttp_router_put_obj) },
    { MP_ROM_QSTR(MP_QSTR_patch), MP_ROM_PTR(&vhttp_router_patch_obj) },
    { MP_ROM_QSTR(MP_QSTR_delete), MP_ROM_PTR(&vhttp_router_delete_obj) },
    { MP_ROM_QSTR(MP_QSTR_options), MP_ROM_PTR(&vhttp_router_options_obj) },
    { MP_ROM_QSTR(MP_QSTR_websocket), MP_ROM_PTR(&vhttp_router_websocket_obj) },
};
static MP_DEFINE_CONST_DICT(vhttp_router_locals_dict, vhttp_router_locals_table);

MP_DEFINE_CONST_OBJ_TYPE(
    vhttp_router_type,
    MP_QSTR_Router,
    MP_TYPE_FLAG_NONE,
    make_new, vhttp_router_make_new,
    attr, vhttp_router_attr,
    locals_dict, &vhttp_router_locals_dict
);

static mp_obj_t vhttp_make_decorator(mp_obj_t self_in, mp_obj_t path_in, mp_obj_t query_spec, mp_obj_t docs_spec, const char *method) {
    vhttp_route_decorator_t *dec = mp_obj_malloc(vhttp_route_decorator_t, &vhttp_route_decorator_type);
    dec->app = MP_OBJ_TO_PTR(self_in);
    dec->method = method;
    dec->method_len = strlen(method);
    dec->path_obj = path_in;
    dec->query_spec = query_spec;
    dec->deps_spec = mp_const_none;
    dec->docs_spec = docs_spec;
    dec->protocols_spec = mp_const_none;
    return MP_OBJ_FROM_PTR(dec);
}

static mp_obj_t vhttp_make_decorator_kw(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args, const char *method) {
    if (n_args > 2) {
        mp_raise_TypeError(MP_ERROR_TEXT("too many positional args"));
    }

    mp_obj_t path_obj = mp_const_none;
    if (n_args >= 2) {
        path_obj = pos_args[1];
    }
    mp_obj_t query_spec = mp_const_none;
    mp_obj_t deps_spec = mp_const_none;
    mp_obj_t summary = mp_const_none;
    mp_obj_t description = mp_const_none;
    mp_obj_t tags = mp_const_none;
    mp_obj_t responses = mp_const_none;
    mp_obj_t operation_id = mp_const_none;
    mp_obj_t name = mp_const_none;
    mp_obj_t request_body = mp_const_none;
    int has_deprecated = 0;
    mp_obj_t deprecated = mp_const_false;
    int has_include_in_schema = 0;
    mp_obj_t include_in_schema = mp_const_true;

    if (kw_args != NULL && kw_args->used > 0) {
        mp_map_t *map = kw_args;

        for (size_t i = 0; i < map->alloc; ++i) {
            if (!mp_map_slot_is_filled(map, i)) {
                continue;
            }
            mp_obj_t key = map->table[i].key;
            if (mp_obj_is_str(key)) {
                size_t len = 0;
                const char *data = mp_obj_str_get_data(key, &len);
                if (len == 4 && memcmp(data, "path", 4) == 0) {
                    path_obj = map->table[i].value;
                } else if (len == 5 && memcmp(data, "query", 5) == 0) {
                    query_spec = map->table[i].value;
                } else if (len == 4 && memcmp(data, "deps", 4) == 0) {
                    deps_spec = map->table[i].value;
                } else if (len == 7 && memcmp(data, "summary", 7) == 0) {
                    summary = map->table[i].value;
                } else if (len == 11 && memcmp(data, "description", 11) == 0) {
                    description = map->table[i].value;
                } else if (len == 4 && memcmp(data, "tags", 4) == 0) {
                    tags = map->table[i].value;
                } else if (len == 9 && memcmp(data, "responses", 9) == 0) {
                    responses = map->table[i].value;
                } else if (len == 12 && memcmp(data, "operation_id", 12) == 0) {
                    operation_id = map->table[i].value;
                } else if (len == 4 && memcmp(data, "name", 4) == 0) {
                    name = map->table[i].value;
                } else if (len == 12 && memcmp(data, "request_body", 12) == 0) {
                    request_body = map->table[i].value;
                } else if (len == 10 && memcmp(data, "deprecated", 10) == 0) {
                    has_deprecated = 1;
                    deprecated = map->table[i].value;
                } else if (len == 17 && memcmp(data, "include_in_schema", 17) == 0) {
                    has_include_in_schema = 1;
                    include_in_schema = map->table[i].value;
                } else {
                    mp_raise_TypeError(MP_ERROR_TEXT("unknown keyword"));
                }
            } else {
                mp_raise_TypeError(MP_ERROR_TEXT("keyword must be str"));
            }
        }
    }

    if (path_obj == mp_const_none) {
        mp_raise_TypeError(MP_ERROR_TEXT("path required"));
    }
    if (!mp_obj_is_str(path_obj)) {
        mp_raise_TypeError(MP_ERROR_TEXT("path must be str"));
    }

    mp_obj_t docs_spec = vhttp_build_docs_spec(
        summary,
        description,
        tags,
        responses,
        operation_id,
        name,
        request_body,
        has_deprecated,
        deprecated,
        has_include_in_schema,
        include_in_schema
    );

    mp_obj_t decorator = vhttp_make_decorator(pos_args[0], path_obj, query_spec, docs_spec, method);
    vhttp_route_decorator_t *dec = MP_OBJ_TO_PTR(decorator);
    dec->deps_spec = deps_spec;
    return decorator;
}

static mp_obj_t vhttp_make_decorator_ws_kw(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    if (n_args > 2) {
        mp_raise_TypeError(MP_ERROR_TEXT("too many positional args"));
    }

    mp_obj_t path_obj = mp_const_none;
    if (n_args >= 2) {
        path_obj = pos_args[1];
    }
    mp_obj_t query_spec = mp_const_none;
    mp_obj_t deps_spec = mp_const_none;
    mp_obj_t protocols_spec = mp_const_none;
    mp_obj_t summary = mp_const_none;
    mp_obj_t description = mp_const_none;
    mp_obj_t tags = mp_const_none;
    mp_obj_t responses = mp_const_none;
    mp_obj_t operation_id = mp_const_none;
    mp_obj_t name = mp_const_none;
    mp_obj_t request_body = mp_const_none;
    int has_deprecated = 0;
    mp_obj_t deprecated = mp_const_false;
    int has_include_in_schema = 0;
    mp_obj_t include_in_schema = mp_const_true;

    if (kw_args != NULL && kw_args->used > 0) {
        mp_map_t *map = kw_args;

        for (size_t i = 0; i < map->alloc; ++i) {
            if (!mp_map_slot_is_filled(map, i)) {
                continue;
            }
            mp_obj_t key = map->table[i].key;
            if (mp_obj_is_str(key)) {
                size_t len = 0;
                const char *data = mp_obj_str_get_data(key, &len);
                if (len == 4 && memcmp(data, "path", 4) == 0) {
                    path_obj = map->table[i].value;
                } else if (len == 5 && memcmp(data, "query", 5) == 0) {
                    query_spec = map->table[i].value;
                } else if (len == 4 && memcmp(data, "deps", 4) == 0) {
                    deps_spec = map->table[i].value;
                } else if (len == 9 && memcmp(data, "protocols", 9) == 0) {
                    protocols_spec = map->table[i].value;
                } else if (len == 7 && memcmp(data, "summary", 7) == 0) {
                    summary = map->table[i].value;
                } else if (len == 11 && memcmp(data, "description", 11) == 0) {
                    description = map->table[i].value;
                } else if (len == 4 && memcmp(data, "tags", 4) == 0) {
                    tags = map->table[i].value;
                } else if (len == 9 && memcmp(data, "responses", 9) == 0) {
                    responses = map->table[i].value;
                } else if (len == 12 && memcmp(data, "operation_id", 12) == 0) {
                    operation_id = map->table[i].value;
                } else if (len == 4 && memcmp(data, "name", 4) == 0) {
                    name = map->table[i].value;
                } else if (len == 12 && memcmp(data, "request_body", 12) == 0) {
                    request_body = map->table[i].value;
                } else if (len == 10 && memcmp(data, "deprecated", 10) == 0) {
                    has_deprecated = 1;
                    deprecated = map->table[i].value;
                } else if (len == 17 && memcmp(data, "include_in_schema", 17) == 0) {
                    has_include_in_schema = 1;
                    include_in_schema = map->table[i].value;
                } else {
                    mp_raise_TypeError(MP_ERROR_TEXT("unknown keyword"));
                }
            } else {
                mp_raise_TypeError(MP_ERROR_TEXT("keyword must be str"));
            }
        }
    }

    if (path_obj == mp_const_none) {
        mp_raise_TypeError(MP_ERROR_TEXT("path required"));
    }
    if (!mp_obj_is_str(path_obj)) {
        mp_raise_TypeError(MP_ERROR_TEXT("path must be str"));
    }
    if (protocols_spec != mp_const_none &&
        !(mp_obj_is_type(protocols_spec, &mp_type_list) || mp_obj_is_type(protocols_spec, &mp_type_tuple))) {
        mp_raise_TypeError(MP_ERROR_TEXT("protocols must be list/tuple"));
    }

    mp_obj_t docs_spec = vhttp_build_docs_spec(
        summary,
        description,
        tags,
        responses,
        operation_id,
        name,
        request_body,
        has_deprecated,
        deprecated,
        has_include_in_schema,
        include_in_schema
    );

    mp_obj_t decorator = vhttp_make_decorator(pos_args[0], path_obj, query_spec, docs_spec, "WS");
    vhttp_route_decorator_t *dec = MP_OBJ_TO_PTR(decorator);
    dec->deps_spec = deps_spec;
    dec->docs_spec = docs_spec;
    dec->protocols_spec = protocols_spec;
    return decorator;
}

static mp_obj_t vhttp_app_get(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    return vhttp_make_decorator_kw(n_args, pos_args, kw_args, "GET");
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_app_get_obj, 2, vhttp_app_get);

static mp_obj_t vhttp_app_post(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    return vhttp_make_decorator_kw(n_args, pos_args, kw_args, "POST");
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_app_post_obj, 2, vhttp_app_post);

static mp_obj_t vhttp_app_put(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    return vhttp_make_decorator_kw(n_args, pos_args, kw_args, "PUT");
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_app_put_obj, 2, vhttp_app_put);

static mp_obj_t vhttp_app_patch(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    return vhttp_make_decorator_kw(n_args, pos_args, kw_args, "PATCH");
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_app_patch_obj, 2, vhttp_app_patch);

static mp_obj_t vhttp_app_delete(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    return vhttp_make_decorator_kw(n_args, pos_args, kw_args, "DELETE");
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_app_delete_obj, 2, vhttp_app_delete);

static mp_obj_t vhttp_app_options(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    return vhttp_make_decorator_kw(n_args, pos_args, kw_args, "OPTIONS");
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_app_options_obj, 2, vhttp_app_options);

static mp_obj_t vhttp_app_head(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    return vhttp_make_decorator_kw(n_args, pos_args, kw_args, "HEAD");
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_app_head_obj, 2, vhttp_app_head);

static mp_obj_t vhttp_app_websocket(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    return vhttp_make_decorator_ws_kw(n_args, pos_args, kw_args);
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_app_websocket_obj, 2, vhttp_app_websocket);

static void vhttp_app_attr(mp_obj_t self_in, qstr attr, mp_obj_t *dest) {
    if (dest[0] == MP_OBJ_NULL) {
        if (vhttp_qstr_equals_lit(attr, "head", 4)) {
            dest[0] = MP_OBJ_FROM_PTR(&vhttp_app_head_obj);
            dest[1] = self_in;
            return;
        }
        // Fallback to locals dict for all other attributes.
        dest[1] = MP_OBJ_SENTINEL;
    }
}

static int vhttp_cors_get_str(mp_obj_t obj, const char **out, size_t *out_len) {
    if (mp_obj_is_str(obj)) {
        *out = mp_obj_str_get_data(obj, out_len);
        return 0;
    }
    if (mp_obj_is_type(obj, &mp_type_bytes) || mp_obj_is_type(obj, &mp_type_bytearray)) {
        mp_buffer_info_t bufinfo;
        mp_get_buffer_raise(obj, &bufinfo, MP_BUFFER_READ);
        *out = (const char *)bufinfo.buf;
        *out_len = bufinfo.len;
        return 0;
    }
    return -1;
}

static void vhttp_cors_copy_str(char *dst, size_t dst_len, const char *src, size_t src_len) {
    if (src_len == 0) {
        dst[0] = '\0';
        return;
    }
    if (src_len >= dst_len) {
        mp_raise_ValueError(MP_ERROR_TEXT("cors value too long"));
    }
    memcpy(dst, src, src_len);
    dst[src_len] = '\0';
}

static void vhttp_cors_defaults(vhttp_cors_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->allow_origin_any = 1;
    cfg->allow_methods_any = 1;
    cfg->allow_headers_any = 1;
    cfg->max_age = VHTTP_CORS_DEFAULT_MAX_AGE;
    vhttp_cors_copy_str(cfg->allow_methods, sizeof(cfg->allow_methods),
        VHTTP_CORS_DEFAULT_METHODS, strlen(VHTTP_CORS_DEFAULT_METHODS));
    vhttp_cors_copy_str(cfg->allow_headers, sizeof(cfg->allow_headers),
        VHTTP_CORS_DEFAULT_HEADERS, strlen(VHTTP_CORS_DEFAULT_HEADERS));
}

static void vhttp_cors_parse_origins(mp_obj_t obj, vhttp_cors_config_t *cfg) {
    if (obj == mp_const_none) {
        return;
    }
    cfg->allow_origin_any = 0;
    cfg->origin_count = 0;
    if (mp_obj_is_str(obj) || mp_obj_is_type(obj, &mp_type_bytes) || mp_obj_is_type(obj, &mp_type_bytearray)) {
        const char *val = NULL;
        size_t val_len = 0;
        if (vhttp_cors_get_str(obj, &val, &val_len) != 0) {
            mp_raise_TypeError(MP_ERROR_TEXT("allow_origins must be str or list"));
        }
        if (val_len == 1 && val[0] == '*') {
            cfg->allow_origin_any = 1;
            cfg->origin_count = 0;
            return;
        }
        vhttp_cors_copy_str(cfg->origins[0], sizeof(cfg->origins[0]), val, val_len);
        cfg->origin_count = 1;
        return;
    }
    if (mp_obj_is_type(obj, &mp_type_list) || mp_obj_is_type(obj, &mp_type_tuple)) {
        size_t len = 0;
        mp_obj_t *items = NULL;
        mp_obj_get_array(obj, &len, &items);
        for (size_t i = 0; i < len; ++i) {
            const char *val = NULL;
            size_t val_len = 0;
            if (vhttp_cors_get_str(items[i], &val, &val_len) != 0) {
                mp_raise_TypeError(MP_ERROR_TEXT("allow_origins must contain strings"));
            }
            if (val_len == 1 && val[0] == '*') {
                cfg->allow_origin_any = 1;
                cfg->origin_count = 0;
                return;
            }
            if (cfg->origin_count >= VHTTP_CORS_MAX_ORIGINS) {
                mp_raise_ValueError(MP_ERROR_TEXT("too many cors origins"));
            }
            vhttp_cors_copy_str(cfg->origins[cfg->origin_count], sizeof(cfg->origins[cfg->origin_count]), val, val_len);
            cfg->origin_count++;
        }
        return;
    }
    mp_raise_TypeError(MP_ERROR_TEXT("allow_origins must be str or list"));
}

static void vhttp_cors_parse_tokens(mp_obj_t obj, const char *fallback, char *out, size_t out_len, uint8_t *out_any) {
    if (obj == mp_const_none) {
        if (fallback) {
            vhttp_cors_copy_str(out, out_len, fallback, strlen(fallback));
        }
        return;
    }
    if (mp_obj_is_str(obj) || mp_obj_is_type(obj, &mp_type_bytes) || mp_obj_is_type(obj, &mp_type_bytearray)) {
        const char *val = NULL;
        size_t val_len = 0;
        if (vhttp_cors_get_str(obj, &val, &val_len) != 0) {
            mp_raise_TypeError(MP_ERROR_TEXT("cors value must be str or list"));
        }
        if (val_len == 1 && val[0] == '*') {
            if (out_any) {
                *out_any = 1;
            }
            if (fallback) {
                vhttp_cors_copy_str(out, out_len, fallback, strlen(fallback));
            } else {
                vhttp_cors_copy_str(out, out_len, val, val_len);
            }
            return;
        }
        vhttp_cors_copy_str(out, out_len, val, val_len);
        if (out_any) {
            *out_any = 0;
        }
        return;
    }
    if (mp_obj_is_type(obj, &mp_type_list) || mp_obj_is_type(obj, &mp_type_tuple)) {
        size_t len = 0;
        mp_obj_t *items = NULL;
        mp_obj_get_array(obj, &len, &items);
        size_t off = 0;
        if (out_any) {
            *out_any = 0;
        }
        for (size_t i = 0; i < len; ++i) {
            const char *val = NULL;
            size_t val_len = 0;
            if (vhttp_cors_get_str(items[i], &val, &val_len) != 0) {
                mp_raise_TypeError(MP_ERROR_TEXT("cors list must contain strings"));
            }
            if (val_len == 1 && val[0] == '*') {
                if (out_any) {
                    *out_any = 1;
                }
                if (fallback) {
                    vhttp_cors_copy_str(out, out_len, fallback, strlen(fallback));
                } else {
                    vhttp_cors_copy_str(out, out_len, val, val_len);
                }
                return;
            }
            if (val_len == 0) {
                continue;
            }
            if (off + val_len + 2 >= out_len) {
                mp_raise_ValueError(MP_ERROR_TEXT("cors value too long"));
            }
            if (off > 0) {
                out[off++] = ',';
                out[off++] = ' ';
            }
            memcpy(out + off, val, val_len);
            off += val_len;
        }
        out[off] = '\0';
        return;
    }
    mp_raise_TypeError(MP_ERROR_TEXT("cors value must be str or list"));
}

static void vhttp_trusted_hosts_parse(mp_obj_t obj, vhttp_trusted_host_config_t *cfg) {
    if (!cfg) {
        return;
    }
    cfg->host_count = 0;
    cfg->allow_any = 0;
    if (obj == mp_const_none) {
        return;
    }
    if (mp_obj_is_str(obj)) {
        size_t val_len = 0;
        const char *val = mp_obj_str_get_data(obj, &val_len);
        if (val_len == 1 && val[0] == '*') {
            cfg->allow_any = 1;
            return;
        }
        if (val_len == 0) {
            mp_raise_ValueError(MP_ERROR_TEXT("host value empty"));
        }
        if (val_len >= VHTTP_TRUSTED_HOST_MAX_LEN) {
            mp_raise_ValueError(MP_ERROR_TEXT("host value too long"));
        }
        memcpy(cfg->hosts[0], val, val_len);
        cfg->hosts[0][val_len] = '\0';
        cfg->host_count = 1;
        return;
    }
    if (mp_obj_is_type(obj, &mp_type_list) || mp_obj_is_type(obj, &mp_type_tuple)) {
        size_t len = 0;
        mp_obj_t *items = NULL;
        mp_obj_get_array(obj, &len, &items);
        for (size_t i = 0; i < len; ++i) {
            size_t val_len = 0;
            const char *val = NULL;
            if (!mp_obj_is_str(items[i])) {
                mp_raise_TypeError(MP_ERROR_TEXT("allowed_hosts must contain strings"));
            }
            val = mp_obj_str_get_data(items[i], &val_len);
            if (val_len == 1 && val[0] == '*') {
                cfg->allow_any = 1;
                continue;
            }
            if (val_len == 0) {
                mp_raise_ValueError(MP_ERROR_TEXT("host value empty"));
            }
            if (val_len >= VHTTP_TRUSTED_HOST_MAX_LEN) {
                mp_raise_ValueError(MP_ERROR_TEXT("host value too long"));
            }
            if (cfg->host_count >= VHTTP_TRUSTED_HOST_MAX) {
                mp_raise_ValueError(MP_ERROR_TEXT("too many trusted hosts"));
            }
            memcpy(cfg->hosts[cfg->host_count], val, val_len);
            cfg->hosts[cfg->host_count][val_len] = '\0';
            cfg->host_count++;
        }
        return;
    }
    mp_raise_TypeError(MP_ERROR_TEXT("allowed_hosts must be str or list"));
}

static mp_obj_t vhttp_app_add_middleware(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    if (n_args < 2) {
        mp_raise_TypeError(MP_ERROR_TEXT("add_middleware(middleware, **kwargs)"));
    }
    if (n_args > 2) {
        mp_raise_TypeError(MP_ERROR_TEXT("only middleware class positional arg supported"));
    }
    vhttp_app_t *app = MP_OBJ_TO_PTR(pos_args[0]);
    if (app != vhttp_active_app_ptr()) {
        mp_raise_ValueError(MP_ERROR_TEXT("app not active"));
    }
    mp_obj_t middleware_cls = pos_args[1];
    if (!mp_obj_is_callable(middleware_cls)) {
        mp_raise_TypeError(MP_ERROR_TEXT("middleware must be callable"));
    }

    mp_int_t priority = 0;

    if (middleware_cls == MP_OBJ_FROM_PTR(&vhttp_cors_middleware_type) ||
        mp_obj_is_type(middleware_cls, &vhttp_cors_middleware_type)) {
        vhttp_cors_config_t cfg;
        vhttp_cors_defaults(&cfg);
        if (kw_args && kw_args->used > 0) {
            mp_map_t *map = kw_args;
            for (size_t i = 0; i < map->alloc; ++i) {
                if (!mp_map_slot_is_filled(map, i)) {
                    continue;
                }
                mp_obj_t key = map->table[i].key;
                mp_obj_t val = map->table[i].value;
                if (!mp_obj_is_str(key)) {
                    mp_raise_TypeError(MP_ERROR_TEXT("cors keyword must be str"));
                }
                size_t key_len = 0;
                const char *key_str = mp_obj_str_get_data(key, &key_len);
                if (key_len == 8 && memcmp(key_str, "priority", 8) == 0) {
                    priority = mp_obj_get_int(val);
                } else if (key_len == 13 && memcmp(key_str, "allow_origins", 13) == 0) {
                    vhttp_cors_parse_origins(val, &cfg);
                } else if (key_len == 13 && memcmp(key_str, "allow_methods", 13) == 0) {
                    cfg.allow_methods_any = 0;
                    vhttp_cors_parse_tokens(val, VHTTP_CORS_DEFAULT_METHODS,
                        cfg.allow_methods, sizeof(cfg.allow_methods), &cfg.allow_methods_any);
                } else if (key_len == 13 && memcmp(key_str, "allow_headers", 13) == 0) {
                    cfg.allow_headers_any = 0;
                    vhttp_cors_parse_tokens(val, VHTTP_CORS_DEFAULT_HEADERS,
                        cfg.allow_headers, sizeof(cfg.allow_headers), &cfg.allow_headers_any);
                } else if (key_len == 17 && memcmp(key_str, "allow_credentials", 17) == 0) {
                    cfg.allow_credentials = mp_obj_is_true(val) ? 1 : 0;
                } else if (key_len == 13 && memcmp(key_str, "expose_headers", 13) == 0) {
                    vhttp_cors_parse_tokens(val, NULL, cfg.expose_headers, sizeof(cfg.expose_headers), NULL);
                } else if (key_len == 7 && memcmp(key_str, "max_age", 7) == 0) {
                    mp_int_t max_age = mp_obj_get_int(val);
                    if (max_age < 0) {
                        mp_raise_ValueError(MP_ERROR_TEXT("max_age must be >= 0"));
                    }
                    cfg.max_age = (uint32_t)max_age;
                } else {
                    mp_raise_TypeError(MP_ERROR_TEXT("unknown cors keyword"));
                }
            }
        }
        vhttp_cors_configure(&cfg);
        return mp_const_none;
    }

    if (middleware_cls == MP_OBJ_FROM_PTR(&vhttp_ratelimit_middleware_type) ||
        mp_obj_is_type(middleware_cls, &vhttp_ratelimit_middleware_type)) {
        vhttp_ratelimit_config_t cfg;
        cfg.enabled = 1;
        cfg.rate_per_sec = VHTTP_RL_DEFAULT_RATE_PER_SEC;
        cfg.burst = VHTTP_RL_DEFAULT_BURST;
        if (kw_args && kw_args->used > 0) {
            mp_map_t *map = kw_args;
            for (size_t i = 0; i < map->alloc; ++i) {
                if (!mp_map_slot_is_filled(map, i)) {
                    continue;
                }
                mp_obj_t key = map->table[i].key;
                mp_obj_t val = map->table[i].value;
                if (!mp_obj_is_str(key)) {
                    mp_raise_TypeError(MP_ERROR_TEXT("ratelimit keyword must be str"));
                }
                size_t key_len = 0;
                const char *key_str = mp_obj_str_get_data(key, &key_len);
                if (key_len == 4 && memcmp(key_str, "rate", 4) == 0) {
                    mp_int_t rate = mp_obj_get_int(val);
                    if (rate < 0) {
                        mp_raise_ValueError(MP_ERROR_TEXT("rate must be >= 0"));
                    }
                    cfg.rate_per_sec = (uint32_t)rate;
                } else if (key_len == 5 && memcmp(key_str, "burst", 5) == 0) {
                    mp_int_t burst = mp_obj_get_int(val);
                    if (burst < 0) {
                        mp_raise_ValueError(MP_ERROR_TEXT("burst must be >= 0"));
                    }
                    cfg.burst = (uint32_t)burst;
                } else if (key_len == 7 && memcmp(key_str, "enabled", 7) == 0) {
                    cfg.enabled = mp_obj_is_true(val) ? 1 : 0;
                } else if (key_len == 8 && memcmp(key_str, "priority", 8) == 0) {
                    // C-native middleware ignores priority; accept for API symmetry.
                } else {
                    mp_raise_TypeError(MP_ERROR_TEXT("unknown ratelimit keyword"));
                }
            }
        }
        vhttp_ratelimit_configure(&cfg);
        return mp_const_none;
    }

    if (middleware_cls == MP_OBJ_FROM_PTR(&vhttp_trusted_host_middleware_type) ||
        mp_obj_is_type(middleware_cls, &vhttp_trusted_host_middleware_type)) {
        vhttp_trusted_host_config_t cfg;
        vhttp_trusted_host_defaults(&cfg);
        if (kw_args && kw_args->used > 0) {
            mp_map_t *map = kw_args;
            for (size_t i = 0; i < map->alloc; ++i) {
                if (!mp_map_slot_is_filled(map, i)) {
                    continue;
                }
                mp_obj_t key = map->table[i].key;
                mp_obj_t val = map->table[i].value;
                if (!mp_obj_is_str(key)) {
                    mp_raise_TypeError(MP_ERROR_TEXT("trusted host keyword must be str"));
                }
                size_t key_len = 0;
                const char *key_str = mp_obj_str_get_data(key, &key_len);
                if (key_len == 13 && memcmp(key_str, "allowed_hosts", 13) == 0) {
                    vhttp_trusted_hosts_parse(val, &cfg);
                } else if (key_len == 7 && memcmp(key_str, "enabled", 7) == 0) {
                    cfg.enabled = mp_obj_is_true(val) ? 1 : 0;
                } else if (key_len == 8 && memcmp(key_str, "priority", 8) == 0) {
                    // C-native middleware ignores priority; accept for API symmetry.
                } else {
                    mp_raise_TypeError(MP_ERROR_TEXT("unknown trusted host keyword"));
                }
            }
        }
        vhttp_trusted_host_configure(&cfg);
        return mp_const_none;
    }

    mp_obj_t kwargs_dict = mp_obj_new_dict(0);
    if (kw_args && kw_args->used > 0) {
        mp_map_t *map = kw_args;
        for (size_t i = 0; i < map->alloc; ++i) {
            if (!mp_map_slot_is_filled(map, i)) {
                continue;
            }
            mp_obj_t key = map->table[i].key;
            if (mp_obj_is_str(key)) {
                size_t key_len = 0;
                const char *key_str = mp_obj_str_get_data(key, &key_len);
                if (key_len == 8 && memcmp(key_str, "priority", 8) == 0) {
                    priority = mp_obj_get_int(map->table[i].value);
                    continue;
                }
            }
            mp_obj_dict_store(kwargs_dict, key, map->table[i].value);
        }
    }

    mp_obj_t entry_items[4] = {
        mp_obj_new_str("class", 5),
        middleware_cls,
        kwargs_dict,
        mp_obj_new_int(priority),
    };
    mp_obj_list_append(app->middlewares, mp_obj_new_tuple(4, entry_items));
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_app_add_middleware_obj, 2, vhttp_app_add_middleware);

static mp_obj_t vhttp_app_middleware(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    if (n_args < 2) {
        mp_raise_TypeError(MP_ERROR_TEXT("middleware(kind, *, priority=0)"));
    }
    vhttp_app_t *app = MP_OBJ_TO_PTR(pos_args[0]);
    if (app != vhttp_active_app_ptr()) {
        mp_raise_ValueError(MP_ERROR_TEXT("app not active"));
    }
    mp_obj_t kind_in = pos_args[1];
    if (!mp_obj_is_str(kind_in)) {
        mp_raise_TypeError(MP_ERROR_TEXT("middleware kind must be str"));
    }
    size_t kind_len = 0;
    const char *kind = mp_obj_str_get_data(kind_in, &kind_len);
    if (!(kind_len == 4 && memcmp(kind, "http", 4) == 0)) {
        mp_raise_ValueError(MP_ERROR_TEXT("only http middleware supported"));
    }

    mp_arg_t allowed_args[] = {
        { MP_QSTR_priority, MP_ARG_INT, { .u_int = 0 } },
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args - 2, pos_args + 2, kw_args,
        MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    vhttp_middleware_decorator_t *dec = mp_obj_malloc(vhttp_middleware_decorator_t, &vhttp_middleware_decorator_type);
    dec->app = app;
    dec->priority = args[0].u_int;
    return MP_OBJ_FROM_PTR(dec);
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_app_middleware_obj, 2, vhttp_app_middleware);

static mp_obj_t vhttp_app_add_middleware_func(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    if (n_args < 2) {
        mp_raise_TypeError(MP_ERROR_TEXT("add_middleware_func(func, *, priority=0)"));
    }
    if (n_args > 3) {
        mp_raise_TypeError(MP_ERROR_TEXT("too many positional args"));
    }
    vhttp_app_t *app = MP_OBJ_TO_PTR(pos_args[0]);
    if (app != vhttp_active_app_ptr()) {
        mp_raise_ValueError(MP_ERROR_TEXT("app not active"));
    }
    mp_obj_t func = pos_args[1];
    if (!mp_obj_is_callable(func)) {
        mp_raise_TypeError(MP_ERROR_TEXT("middleware must be callable"));
    }

    mp_arg_t allowed_args[] = {
        { MP_QSTR_priority, MP_ARG_INT, { .u_int = 0 } },
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args - 2, pos_args + 2, kw_args,
        MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    mp_obj_t entry_items[4] = {
        mp_obj_new_str("func", 4),
        func,
        mp_const_none,
        mp_obj_new_int(args[0].u_int),
    };
    mp_obj_list_append(app->middlewares, mp_obj_new_tuple(4, entry_items));
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_app_add_middleware_func_obj, 2, vhttp_app_add_middleware_func);

static mp_obj_t vhttp_app_middleware_stack(mp_obj_t self_in) {
    vhttp_app_t *app = MP_OBJ_TO_PTR(self_in);
    return app->middlewares;
}
static MP_DEFINE_CONST_FUN_OBJ_1(vhttp_app_middleware_stack_obj, vhttp_app_middleware_stack);

static mp_obj_t vhttp_app_match(mp_obj_t self_in, mp_obj_t method_in, mp_obj_t path_in) {
    vhttp_app_t *app = MP_OBJ_TO_PTR(self_in);
    if (app != vhttp_active_app_ptr()) {
        mp_raise_ValueError(MP_ERROR_TEXT("app not active"));
    }

    ensure_router_ready();

    size_t method_len = 0;
    const char *method = mp_obj_str_get_data(method_in, &method_len);
    size_t path_len = 0;
    const char *path = mp_obj_str_get_data(path_in, &path_len);
    const char *path_only = NULL;
    size_t path_only_len = 0;
    vhttp_split_path_query(path, path_len, &path_only, &path_only_len, NULL, NULL);

    vhttp_match_t match;
    vhttp_slice_t path_slice = { path_only, (uint16_t)path_only_len };
    vhttp_router_result_t res = vhttp_router_match(
        &g_router,
        method,
        method_len,
        path_slice,
        &match
    );

    if (res != VHTTP_ROUTER_OK) {
        return mp_const_none;
    }

    size_t handlers_len = 0;
    mp_obj_t *handlers_items = NULL;
    mp_obj_list_get(app->handlers, &handlers_len, &handlers_items);
    if (match.target.handler_id >= handlers_len) {
        return mp_const_none;
    }

    mp_obj_t handler = handlers_items[match.target.handler_id];
    mp_obj_t params_dict = mp_obj_new_dict(match.num_params);

    for (uint8_t i = 0; i < match.num_params; ++i) {
        vhttp_path_param_t *param = &match.params[i];
        mp_obj_t key = mp_obj_new_str(param->name.ptr, param->name.len);
        mp_obj_t value = mp_const_none;

        if (param->type == VHTTP_PARAM_INT) {
            long long num = 0;
            int sign = 1;
            size_t idx = 0;
            if (param->value.len > 0 && param->value.ptr[0] == '-') {
                sign = -1;
                idx = 1;
            }
            for (; idx < param->value.len; ++idx) {
                num = num * 10 + (param->value.ptr[idx] - '0');
            }
            value = mp_obj_new_int_from_ll((long long)(num * sign));
        } else if (param->type == VHTTP_PARAM_FLOAT) {
            double sign = 1.0;
            size_t idx = 0;
            if (param->value.len > 0 && param->value.ptr[0] == '-') {
                sign = -1.0;
                idx = 1;
            }
            double integer = 0.0;
            while (idx < param->value.len && param->value.ptr[idx] != '.') {
                integer = integer * 10.0 + (double)(param->value.ptr[idx] - '0');
                idx++;
            }
            double frac = 0.0;
            double scale = 1.0;
            if (idx < param->value.len && param->value.ptr[idx] == '.') {
                idx++;
                while (idx < param->value.len) {
                    scale *= 0.1;
                    frac += scale * (double)(param->value.ptr[idx] - '0');
                    idx++;
                }
            }
            value = mp_obj_new_float((integer + frac) * sign);
        } else {
            value = mp_obj_new_str(param->value.ptr, param->value.len);
        }

        mp_obj_dict_store(params_dict, key, value);
    }

    mp_obj_t items[2] = { handler, params_dict };
    return mp_obj_new_tuple(2, items);
}
static MP_DEFINE_CONST_FUN_OBJ_3(vhttp_app_match_obj, vhttp_app_match);

static mp_obj_t vhttp_app_routes(mp_obj_t self_in) {
    vhttp_app_t *app = MP_OBJ_TO_PTR(self_in);
    size_t handlers_len = 0;
    mp_obj_t *handlers_items = NULL;
    mp_obj_list_get(app->handlers, &handlers_len, &handlers_items);

    size_t meta_len = 0;
    mp_obj_t *meta_items = NULL;
    mp_obj_list_get(app->handler_meta, &meta_len, &meta_items);
    size_t n = handlers_len;
    if (meta_len < n) {
        n = meta_len;
    }

    mp_obj_t out = mp_obj_new_list(0, NULL);
    for (size_t i = 0; i < n; ++i) {
        mp_obj_t meta = meta_items[i];
        if (!mp_obj_is_type(meta, &mp_type_dict)) {
            continue;
        }
        mp_obj_t row = vhttp_copy_dict(meta);
        mp_obj_dict_store(row, mp_obj_new_str("handler", 7), handlers_items[i]);
        mp_obj_list_append(out, row);
    }
    return out;
}
static MP_DEFINE_CONST_FUN_OBJ_1(vhttp_app_routes_obj, vhttp_app_routes);

static mp_obj_t vhttp_call_bridge_dep_http(
    mp_obj_t handler,
    mp_obj_t params,
    mp_obj_t deps_spec,
    mp_obj_t request_obj,
    mp_obj_t background_obj
) {
    mp_obj_t call = mp_obj_new_dict(0);
    mp_obj_dict_store(call, mp_obj_new_str("__vhttp_dep_call__", 18), mp_const_true);
    mp_obj_dict_store(call, mp_obj_new_str("handler", 7), handler);
    mp_obj_dict_store(call, mp_obj_new_str("params", 6), params);
    mp_obj_dict_store(call, mp_obj_new_str("deps", 4), deps_spec);
    mp_obj_dict_store(call, mp_obj_new_str("request", 7), request_obj);
    mp_obj_dict_store(call, mp_obj_new_str("background", 10), background_obj);
    return call;
}

static mp_obj_t vhttp_app_dispatch(size_t n_args, const mp_obj_t *args) {
    mp_obj_t self_in = args[0];
    mp_obj_t method_in = args[1];
    mp_obj_t path_in = args[2];
    mp_obj_t request_obj = mp_const_none;
    mp_obj_t background_obj = mp_const_none;
    if (n_args >= 4) {
        request_obj = args[3];
    }
    if (n_args >= 5) {
        background_obj = args[4];
    }

    mp_obj_t prev_request = MP_STATE_VM(viperhttp_current_request);
    if (request_obj == mp_const_none) {
        MP_STATE_VM(viperhttp_current_request) = MP_OBJ_NULL;
    } else {
        MP_STATE_VM(viperhttp_current_request) = request_obj;
    }

    vhttp_app_t *app = MP_OBJ_TO_PTR(self_in);
    mp_obj_t match_obj = vhttp_app_match(self_in, method_in, path_in);
    if (match_obj == mp_const_none) {
        MP_STATE_VM(viperhttp_current_request) = prev_request;
        return mp_const_none;
    }

    mp_obj_t *items = NULL;
    mp_obj_get_array_fixed_n(match_obj, 2, &items);
    mp_obj_t handler = items[0];
    mp_obj_t params = items[1];

    vhttp_request_t *request_ptr = vhttp_request_ptr(request_obj);
    if (request_ptr) {
        request_ptr->path_params = params;
    }

    mp_obj_t query_spec = mp_const_none;
    mp_obj_t deps_spec = mp_const_none;
    mp_obj_t meta = vhttp_get_handler_meta(app, handler);
    if (meta != mp_const_none && mp_obj_is_type(meta, &mp_type_dict)) {
        nlr_buf_t nlr;
        if (nlr_push(&nlr) == 0) {
            query_spec = mp_obj_dict_get(meta, MP_OBJ_NEW_QSTR(MP_QSTR_query));
            nlr_pop();
        }
        if (nlr_push(&nlr) == 0) {
            deps_spec = mp_obj_dict_get(meta, mp_obj_new_str("deps", 4));
            nlr_pop();
        }
    }

    size_t full_len = 0;
    const char *full_path = mp_obj_str_get_data(path_in, &full_len);
    const char *query_ptr = NULL;
    size_t query_len = 0;
    vhttp_split_path_query(full_path, full_len, &full_path, &full_len, &query_ptr, &query_len);
    if (query_len > 0 || query_spec != mp_const_none) {
        mp_obj_t query_dict = mp_obj_new_dict(0);
        vhttp_parse_query_params(query_dict, query_ptr, query_len);
        mp_obj_t err = vhttp_apply_query_spec(query_dict, query_spec, params);
        if (err != mp_const_none) {
            MP_STATE_VM(viperhttp_current_request) = prev_request;
            return err;
        }
        vhttp_merge_query_params(params, query_dict);
        if (request_ptr) {
            request_ptr->query_params = query_dict;
        }
    }

    if (deps_spec != mp_const_none) {
        MP_STATE_VM(viperhttp_current_request) = prev_request;
        return vhttp_call_bridge_dep_http(handler, params, deps_spec, request_obj, background_obj);
    }

    bool added_background = false;
    mp_obj_t background_key = MP_OBJ_NEW_QSTR(MP_QSTR_background_tasks);
    if (background_obj != mp_const_none) {
        if (mp_map_lookup(mp_obj_dict_get_map(params), background_key, MP_MAP_LOOKUP) == NULL) {
            mp_obj_dict_store(params, background_key, background_obj);
            added_background = true;
        }
    }

    for (int attempt = 0; attempt < 2; ++attempt) {
        mp_map_t *map = mp_obj_dict_get_map(params);
        size_t n_kw = map->used;
        if (n_kw == 0) {
            nlr_buf_t nlr;
            if (nlr_push(&nlr) == 0) {
                mp_obj_t result = mp_call_function_0(handler);
                nlr_pop();
                MP_STATE_VM(viperhttp_current_request) = prev_request;
                return result;
            } else {
                void *exc_ptr = nlr.ret_val;
                mp_obj_t exc = MP_OBJ_FROM_PTR(exc_ptr);
                if (!vhttp_is_http_exception_obj(exc)) {
                    MP_STATE_VM(viperhttp_current_request) = prev_request;
                    nlr_raise(exc_ptr);
                }
                MP_STATE_VM(viperhttp_current_request) = prev_request;
                return vhttp_exception_to_response(exc);
            }
        }

        mp_obj_t kw_args[2 * VHTTP_MAX_KWARGS];
        size_t kw_idx = 0;
        for (size_t i = 0; i < map->alloc; ++i) {
            if (!mp_map_slot_is_filled(map, i)) {
                continue;
            }
            if (kw_idx >= VHTTP_MAX_KWARGS) {
                break;
            }
            qstr key_qstr = mp_obj_str_get_qstr(map->table[i].key);
            kw_args[kw_idx * 2] = MP_OBJ_NEW_QSTR(key_qstr);
            kw_args[kw_idx * 2 + 1] = map->table[i].value;
            kw_idx++;
        }

        nlr_buf_t nlr;
        if (nlr_push(&nlr) == 0) {
            mp_obj_t result = mp_call_function_n_kw(handler, 0, kw_idx, kw_args);
            nlr_pop();
            MP_STATE_VM(viperhttp_current_request) = prev_request;
            return result;
        } else {
            void *exc_ptr = nlr.ret_val;
            mp_obj_t exc = MP_OBJ_FROM_PTR(exc_ptr);
            if (added_background && vhttp_is_unexpected_background_kw(exc)) {
                mp_obj_dict_delete(params, background_key);
                added_background = false;
                continue;
            }
            if (!vhttp_is_http_exception_obj(exc)) {
                MP_STATE_VM(viperhttp_current_request) = prev_request;
                nlr_raise(exc_ptr);
            }
            MP_STATE_VM(viperhttp_current_request) = prev_request;
            return vhttp_exception_to_response(exc);
        }
    }

    MP_STATE_VM(viperhttp_current_request) = prev_request;
    return vhttp_make_response_dict(500, mp_obj_new_str("Internal Server Error", 21), mp_const_none, mp_const_none);
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(vhttp_app_dispatch_obj, 3, 5, vhttp_app_dispatch);

static mp_obj_t vhttp_app_ws_dispatch(size_t n_args, const mp_obj_t *args) {
    if (n_args < 3 || n_args > 4) {
        mp_raise_TypeError(MP_ERROR_TEXT("ws_dispatch expects (path, ws[, request])"));
    }
    mp_obj_t self_in = args[0];
    mp_obj_t path_in = args[1];
    mp_obj_t ws_obj = args[2];
    mp_obj_t request_obj = mp_const_none;
    if (n_args == 4) {
        request_obj = args[3];
    }

    mp_obj_t prev_request = MP_STATE_VM(viperhttp_current_request);
    if (request_obj == mp_const_none) {
        MP_STATE_VM(viperhttp_current_request) = MP_OBJ_NULL;
    } else {
        MP_STATE_VM(viperhttp_current_request) = request_obj;
    }

    vhttp_app_t *app = MP_OBJ_TO_PTR(self_in);
    mp_obj_t match_obj = vhttp_app_match(self_in, mp_obj_new_str("WS", 2), path_in);
    if (match_obj == mp_const_none) {
        MP_STATE_VM(viperhttp_current_request) = prev_request;
        mp_obj_t out[2] = { mp_const_false, mp_const_none };
        return mp_obj_new_tuple(2, out);
    }

    mp_obj_t *items = NULL;
    mp_obj_get_array_fixed_n(match_obj, 2, &items);
    mp_obj_t handler = items[0];
    mp_obj_t params = items[1];

    vhttp_request_t *request_ptr = vhttp_request_ptr(request_obj);
    if (request_ptr) {
        request_ptr->path_params = params;
    }

    mp_obj_t query_spec = mp_const_none;
    mp_obj_t deps_spec = mp_const_none;
    mp_obj_t meta = vhttp_get_handler_meta(app, handler);
    if (meta != mp_const_none && mp_obj_is_type(meta, &mp_type_dict)) {
        nlr_buf_t nlr;
        if (nlr_push(&nlr) == 0) {
            query_spec = mp_obj_dict_get(meta, MP_OBJ_NEW_QSTR(MP_QSTR_query));
            nlr_pop();
        }
        if (nlr_push(&nlr) == 0) {
            deps_spec = mp_obj_dict_get(meta, mp_obj_new_str("deps", 4));
            nlr_pop();
        }
    }

    size_t full_len = 0;
    const char *full_path = mp_obj_str_get_data(path_in, &full_len);
    const char *query_ptr = NULL;
    size_t query_len = 0;
    vhttp_split_path_query(full_path, full_len, &full_path, &full_len, &query_ptr, &query_len);
    if (query_len > 0 || query_spec != mp_const_none) {
        mp_obj_t query_dict = mp_obj_new_dict(0);
        vhttp_parse_query_params(query_dict, query_ptr, query_len);
        mp_obj_t err = vhttp_apply_query_spec(query_dict, query_spec, params);
        if (err != mp_const_none) {
            MP_STATE_VM(viperhttp_current_request) = prev_request;
            mp_obj_t out[2] = { mp_const_true, err };
            return mp_obj_new_tuple(2, out);
        }
        vhttp_merge_query_params(params, query_dict);
        if (request_ptr) {
            request_ptr->query_params = query_dict;
        }
    }

    if (deps_spec != mp_const_none) {
        nlr_buf_t nlr;
        if (nlr_push(&nlr) == 0) {
            vhttp_apply_deps(params, deps_spec);
            nlr_pop();
        } else {
            mp_obj_t exc = MP_OBJ_FROM_PTR(nlr.ret_val);
            MP_STATE_VM(viperhttp_current_request) = prev_request;
            mp_obj_t out[2] = { mp_const_true, vhttp_exception_to_response(exc) };
            return mp_obj_new_tuple(2, out);
        }
    }

    mp_map_t *map = mp_obj_dict_get_map(params);
    size_t n_kw = map->used;
    if (n_kw == 0) {
        nlr_buf_t nlr;
        if (nlr_push(&nlr) == 0) {
            mp_obj_t result = mp_call_function_1(handler, ws_obj);
            nlr_pop();
            MP_STATE_VM(viperhttp_current_request) = prev_request;
            mp_obj_t out[2] = { mp_const_true, result };
            return mp_obj_new_tuple(2, out);
        } else {
            mp_obj_t exc = MP_OBJ_FROM_PTR(nlr.ret_val);
            MP_STATE_VM(viperhttp_current_request) = prev_request;
            mp_obj_t out[2] = { mp_const_true, vhttp_exception_to_response(exc) };
            return mp_obj_new_tuple(2, out);
        }
    }

    mp_obj_t kw_args[1 + 2 * VHTTP_MAX_KWARGS];
    size_t kw_idx = 0;
    kw_args[0] = ws_obj;
    for (size_t i = 0; i < map->alloc; ++i) {
        if (!mp_map_slot_is_filled(map, i)) {
            continue;
        }
        if (kw_idx >= VHTTP_MAX_KWARGS) {
            break;
        }
        qstr key_qstr = mp_obj_str_get_qstr(map->table[i].key);
        kw_args[1 + kw_idx * 2] = MP_OBJ_NEW_QSTR(key_qstr);
        kw_args[1 + kw_idx * 2 + 1] = map->table[i].value;
        kw_idx++;
    }

    nlr_buf_t nlr;
    if (nlr_push(&nlr) == 0) {
        mp_obj_t result = mp_call_function_n_kw(handler, 1, kw_idx, kw_args);
        nlr_pop();
        MP_STATE_VM(viperhttp_current_request) = prev_request;
        mp_obj_t out[2] = { mp_const_true, result };
        return mp_obj_new_tuple(2, out);
    } else {
        mp_obj_t exc = MP_OBJ_FROM_PTR(nlr.ret_val);
        MP_STATE_VM(viperhttp_current_request) = prev_request;
        mp_obj_t out[2] = { mp_const_true, vhttp_exception_to_response(exc) };
        return mp_obj_new_tuple(2, out);
    }
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(vhttp_app_ws_dispatch_obj, 3, 4, vhttp_app_ws_dispatch);

static mp_obj_t vhttp_app_include_router(mp_obj_t self_in, mp_obj_t router_in) {
    vhttp_app_t *app = MP_OBJ_TO_PTR(self_in);
    if (app != vhttp_active_app_ptr()) {
        mp_raise_ValueError(MP_ERROR_TEXT("app not active"));
    }

    if (!mp_obj_is_type(router_in, &vhttp_router_type)) {
        mp_raise_TypeError(MP_ERROR_TEXT("router required"));
    }

    vhttp_router_obj_t *router = MP_OBJ_TO_PTR(router_in);
    if (!mp_obj_is_str(router->prefix)) {
        mp_raise_TypeError(MP_ERROR_TEXT("router prefix must be str"));
    }
    vhttp_validate_tags_obj(router->tags);
    if (router->deps != mp_const_none && !mp_obj_is_type(router->deps, &mp_type_dict)) {
        mp_raise_TypeError(MP_ERROR_TEXT("router deps must be dict"));
    }

    vhttp_validate_deps_spec(router->deps);

    size_t routes_len = 0;
    mp_obj_t *routes_items = NULL;
    mp_obj_list_get(router->routes, &routes_len, &routes_items);

    mp_obj_t key_method = mp_obj_new_str("method", 6);
    mp_obj_t key_path = mp_obj_new_str("path", 4);
    mp_obj_t key_handler = mp_obj_new_str("handler", 7);
    mp_obj_t key_query = mp_obj_new_str("query", 5);
    mp_obj_t key_deps = mp_obj_new_str("deps", 4);
    mp_obj_t key_docs = mp_obj_new_str("docs", 4);
    mp_obj_t key_protocols = mp_obj_new_str("protocols", 9);

    for (size_t i = 0; i < routes_len; ++i) {
        mp_obj_t route = routes_items[i];
        if (!mp_obj_is_type(route, &mp_type_dict)) {
            mp_raise_TypeError(MP_ERROR_TEXT("route entry must be dict"));
        }

        mp_obj_t method_obj = mp_const_none;
        mp_obj_t path_obj = mp_const_none;
        mp_obj_t handler = mp_const_none;
        mp_obj_t query_spec = mp_const_none;
        mp_obj_t deps_spec = mp_const_none;
        mp_obj_t docs_spec = mp_const_none;
        mp_obj_t protocols_spec = mp_const_none;

        nlr_buf_t nlr;
        if (nlr_push(&nlr) == 0) {
            method_obj = mp_obj_dict_get(route, key_method);
            nlr_pop();
        } else {
            mp_raise_TypeError(MP_ERROR_TEXT("route missing method"));
        }
        if (nlr_push(&nlr) == 0) {
            path_obj = mp_obj_dict_get(route, key_path);
            nlr_pop();
        } else {
            mp_raise_TypeError(MP_ERROR_TEXT("route missing path"));
        }
        if (nlr_push(&nlr) == 0) {
            handler = mp_obj_dict_get(route, key_handler);
            nlr_pop();
        } else {
            mp_raise_TypeError(MP_ERROR_TEXT("route missing handler"));
        }
        if (nlr_push(&nlr) == 0) {
            query_spec = mp_obj_dict_get(route, key_query);
            nlr_pop();
        } else {
            query_spec = mp_const_none;
        }
        if (nlr_push(&nlr) == 0) {
            deps_spec = mp_obj_dict_get(route, key_deps);
            nlr_pop();
        } else {
            deps_spec = mp_const_none;
        }
        if (nlr_push(&nlr) == 0) {
            docs_spec = mp_obj_dict_get(route, key_docs);
            nlr_pop();
        } else {
            docs_spec = mp_const_none;
        }
        if (nlr_push(&nlr) == 0) {
            protocols_spec = mp_obj_dict_get(route, key_protocols);
            nlr_pop();
        } else {
            protocols_spec = mp_const_none;
        }

        if (!mp_obj_is_str(method_obj)) {
            mp_raise_TypeError(MP_ERROR_TEXT("route method must be str"));
        }
        if (!mp_obj_is_str(path_obj)) {
            mp_raise_TypeError(MP_ERROR_TEXT("route path must be str"));
        }

        mp_obj_t full_path = vhttp_join_paths(router->prefix, path_obj);
        mp_obj_t merged_deps = vhttp_merge_deps(router->deps, deps_spec);
        mp_obj_t merged_docs = vhttp_merge_docs_with_router_tags(docs_spec, router->tags);

        size_t method_len = 0;
        const char *method = mp_obj_str_get_data(method_obj, &method_len);
        vhttp_app_add_route(app, method, method_len, full_path, query_spec, merged_deps, merged_docs, protocols_spec, handler);
    }

    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_2(vhttp_app_include_router_obj, vhttp_app_include_router);

static mp_obj_t vhttp_app_mount(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    enum {
        ARG_prefix,
        ARG_root,
        ARG_html,
    };
    static const mp_arg_t allowed_args[] = {
        { MP_QSTR_prefix, MP_ARG_REQUIRED | MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_root, MP_ARG_REQUIRED | MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_html, MP_ARG_BOOL, { .u_bool = false } },
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args - 1, pos_args + 1, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    vhttp_app_t *app = MP_OBJ_TO_PTR(pos_args[0]);
    if (app != vhttp_active_app_ptr()) {
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("app not active"));
    }

    if (!mp_obj_is_str(args[ARG_prefix].u_obj) || !mp_obj_is_str(args[ARG_root].u_obj)) {
        mp_raise_TypeError(MP_ERROR_TEXT("mount paths must be str"));
    }

    size_t prefix_len = 0;
    size_t root_len = 0;
    const char *prefix = mp_obj_str_get_data(args[ARG_prefix].u_obj, &prefix_len);
    const char *root = mp_obj_str_get_data(args[ARG_root].u_obj, &root_len);

    int rc = vhttp_static_mount(prefix, prefix_len, root, root_len, args[ARG_html].u_bool);
    if (rc == -2) {
        mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("mount prefix already used"));
    }
    if (rc == -3) {
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("static filesystem mount failed"));
    }
    if (rc != 0) {
        mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("invalid mount"));
    }

    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_app_mount_obj, 3, vhttp_app_mount);

static mp_obj_t vhttp_app_mount_file(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    enum {
        ARG_path,
        ARG_file,
    };
    static const mp_arg_t allowed_args[] = {
        { MP_QSTR_path, MP_ARG_REQUIRED | MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_file, MP_ARG_REQUIRED | MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args - 1, pos_args + 1, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    vhttp_app_t *app = MP_OBJ_TO_PTR(pos_args[0]);
    if (app != vhttp_active_app_ptr()) {
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("app not active"));
    }

    if (!mp_obj_is_str(args[ARG_path].u_obj) || !mp_obj_is_str(args[ARG_file].u_obj)) {
        mp_raise_TypeError(MP_ERROR_TEXT("mount_file args must be str"));
    }

    size_t path_len = 0;
    size_t file_len = 0;
    const char *path = mp_obj_str_get_data(args[ARG_path].u_obj, &path_len);
    const char *file = mp_obj_str_get_data(args[ARG_file].u_obj, &file_len);

    int rc = vhttp_static_mount_file(path, path_len, file, file_len);
    if (rc == -2) {
        mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("mount_file path already used"));
    }
    if (rc == -3) {
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("static filesystem mount failed"));
    }
    if (rc != 0) {
        mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("invalid mount_file"));
    }

    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_app_mount_file_obj, 3, vhttp_app_mount_file);

static bool vhttp_kw_map_has(mp_map_t *kw_args, qstr key_qstr) {
    if (kw_args == NULL || kw_args->used == 0) {
        return false;
    }
    mp_map_elem_t *elem = mp_map_lookup(kw_args, MP_OBJ_NEW_QSTR(key_qstr), MP_MAP_LOOKUP);
    return elem != NULL;
}

static bool vhttp_kw_array_has(size_t n_args, size_t n_kw, const mp_obj_t *args, qstr key_qstr) {
    for (size_t i = 0; i < n_kw; ++i) {
        mp_obj_t key = args[n_args + i * 2];
        if (mp_obj_is_str(key) && mp_obj_str_equal(key, MP_OBJ_NEW_QSTR(key_qstr))) {
            return true;
        }
    }
    return false;
}

static mp_obj_t vhttp_app_docs_config(mp_obj_t self_in) {
    vhttp_app_t *app = MP_OBJ_TO_PTR(self_in);
    mp_obj_t out = mp_obj_new_dict(9);
    mp_obj_dict_store(out, mp_obj_new_str("title", 5), app->title);
    mp_obj_dict_store(out, mp_obj_new_str("version", 7), app->version);
    mp_obj_dict_store(out, mp_obj_new_str("description", 11), app->description);
    mp_obj_dict_store(out, mp_obj_new_str("docs", 4), app->docs_enabled);
    mp_obj_dict_store(out, mp_obj_new_str("openapi_url", 11), app->openapi_url);
    mp_obj_dict_store(out, mp_obj_new_str("docs_url", 8), app->docs_url);
    mp_obj_dict_store(out, mp_obj_new_str("include_websocket_docs", 22), app->include_websocket_docs);
    mp_obj_dict_store(out, mp_obj_new_str("cache_schema", 12), app->cache_schema);
    mp_obj_dict_store(out, mp_obj_new_str("servers", 7), app->servers);
    return out;
}
static MP_DEFINE_CONST_FUN_OBJ_1(vhttp_app_docs_config_obj, vhttp_app_docs_config);

static mp_obj_t vhttp_app_configure_docs(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    enum {
        ARG_title,
        ARG_version,
        ARG_description,
        ARG_docs,
        ARG_openapi_url,
        ARG_docs_url,
        ARG_include_websocket_docs,
        ARG_cache_schema,
        ARG_servers,
    };
    static const mp_arg_t allowed_args[] = {
        { MP_QSTR_title, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_version, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_description, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_docs, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_openapi_url, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_docs_url, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_include_websocket_docs, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_cache_schema, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_servers, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args - 1, pos_args + 1, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    vhttp_app_t *app = MP_OBJ_TO_PTR(pos_args[0]);

    if (args[ARG_title].u_obj != mp_const_none) {
        if (!mp_obj_is_str(args[ARG_title].u_obj)) {
            mp_raise_TypeError(MP_ERROR_TEXT("title must be str"));
        }
        app->title = args[ARG_title].u_obj;
    }
    if (args[ARG_version].u_obj != mp_const_none) {
        if (!mp_obj_is_str(args[ARG_version].u_obj)) {
            mp_raise_TypeError(MP_ERROR_TEXT("version must be str"));
        }
        app->version = args[ARG_version].u_obj;
    }
    if (args[ARG_description].u_obj != mp_const_none) {
        if (!mp_obj_is_str(args[ARG_description].u_obj)) {
            mp_raise_TypeError(MP_ERROR_TEXT("description must be str"));
        }
        app->description = args[ARG_description].u_obj;
    }
    if (args[ARG_docs].u_obj != mp_const_none) {
        app->docs_enabled = mp_obj_new_bool(mp_obj_is_true(args[ARG_docs].u_obj));
    }
    bool has_openapi_url = (n_args > (1 + ARG_openapi_url)) || vhttp_kw_map_has(kw_args, MP_QSTR_openapi_url);
    if (has_openapi_url) {
        if (args[ARG_openapi_url].u_obj != mp_const_none && !mp_obj_is_str(args[ARG_openapi_url].u_obj)) {
            mp_raise_TypeError(MP_ERROR_TEXT("openapi_url must be str or None"));
        }
        app->openapi_url = args[ARG_openapi_url].u_obj;
    }
    bool has_docs_url = (n_args > (1 + ARG_docs_url)) || vhttp_kw_map_has(kw_args, MP_QSTR_docs_url);
    if (has_docs_url) {
        if (args[ARG_docs_url].u_obj != mp_const_none && !mp_obj_is_str(args[ARG_docs_url].u_obj)) {
            mp_raise_TypeError(MP_ERROR_TEXT("docs_url must be str or None"));
        }
        app->docs_url = args[ARG_docs_url].u_obj;
    }
    if (args[ARG_include_websocket_docs].u_obj != mp_const_none) {
        app->include_websocket_docs = mp_obj_new_bool(mp_obj_is_true(args[ARG_include_websocket_docs].u_obj));
    }
    if (args[ARG_cache_schema].u_obj != mp_const_none) {
        app->cache_schema = mp_obj_new_bool(mp_obj_is_true(args[ARG_cache_schema].u_obj));
    }
    if (args[ARG_servers].u_obj != mp_const_none) {
        app->servers = args[ARG_servers].u_obj;
    }

    return pos_args[0];
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_app_configure_docs_obj, 1, vhttp_app_configure_docs);

static mp_obj_t vhttp_app_run(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    enum {
        ARG_port,
        ARG_loop,
        ARG_wifi,
        ARG_https,
        ARG_http2,
        ARG_http2_max_streams,
        ARG_tls_cert_pem,
        ARG_tls_key_pem,
        ARG_tls_cert_path,
        ARG_tls_key_path,
        ARG_ota,
        ARG_ota_prefix,
        ARG_ota_token,
        ARG_ota_token_header,
        ARG_ota_token_query,
        ARG_min_workers,
        ARG_max_workers,
        ARG_bridge_min_workers,
        ARG_bridge_max_workers,
        ARG_bridge_queue_size,
        ARG_bridge_poll_burst,
        ARG_bridge_idle_sleep_ms,
        ARG_bridge_autoscale,
        ARG_bridge_enqueue_wait_ms,
        ARG_bridge_worker_yield_every,
        ARG_bridge_scale_up_max_burst,
        ARG_auto_docs,
        ARG_title,
        ARG_version,
        ARG_description,
        ARG_openapi_url,
        ARG_docs_url,
        ARG_include_websocket_docs,
        ARG_cache_schema,
        ARG_servers,
    };
    static const mp_arg_t allowed_args[] = {
        { MP_QSTR_port, MP_ARG_INT, { .u_int = 8080 } },
        { MP_QSTR_loop, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_wifi, MP_ARG_BOOL, { .u_bool = true } },
        { MP_QSTR_https, MP_ARG_BOOL, { .u_bool = false } },
        { MP_QSTR_http2, MP_ARG_BOOL, { .u_bool = false } },
        { MP_QSTR_http2_max_streams, MP_ARG_INT, { .u_int = 8 } },
        { MP_QSTR_tls_cert_pem, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_tls_key_pem, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_tls_cert_path, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_tls_key_path, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_ota, MP_ARG_BOOL, { .u_bool = false } },
        { MP_QSTR_ota_prefix, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_ota_token, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_ota_token_header, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_ota_token_query, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_min_workers, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_max_workers, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_bridge_min_workers, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_bridge_max_workers, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_bridge_queue_size, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_bridge_poll_burst, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_bridge_idle_sleep_ms, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_bridge_autoscale, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_bridge_enqueue_wait_ms, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_bridge_worker_yield_every, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_bridge_scale_up_max_burst, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_auto_docs, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_title, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_version, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_description, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_openapi_url, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_docs_url, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_include_websocket_docs, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_cache_schema, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_servers, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args - 1, pos_args + 1, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    mp_obj_t bridge = mp_import_name(MP_QSTR_viperhttp_bridge, mp_const_none, MP_OBJ_NEW_SMALL_INT(0));
    mp_obj_t run_fun = mp_load_attr(bridge, MP_QSTR_run);

    mp_obj_t call_args[1 + 2 * 40];
    size_t n_kw = 0;
    call_args[0] = pos_args[0];

    call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_port);
    call_args[1 + 2 * n_kw + 1] = mp_obj_new_int(args[ARG_port].u_int);
    n_kw++;

    if (args[ARG_loop].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_loop);
        call_args[1 + 2 * n_kw + 1] = args[ARG_loop].u_obj;
        n_kw++;
    }

    call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_wifi);
    call_args[1 + 2 * n_kw + 1] = mp_obj_new_bool(args[ARG_wifi].u_bool);
    n_kw++;

    call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_https);
    call_args[1 + 2 * n_kw + 1] = mp_obj_new_bool(args[ARG_https].u_bool);
    n_kw++;

    call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_http2);
    call_args[1 + 2 * n_kw + 1] = mp_obj_new_bool(args[ARG_http2].u_bool);
    n_kw++;

    call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_http2_max_streams);
    call_args[1 + 2 * n_kw + 1] = mp_obj_new_int(args[ARG_http2_max_streams].u_int);
    n_kw++;

    if (args[ARG_tls_cert_pem].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_tls_cert_pem);
        call_args[1 + 2 * n_kw + 1] = args[ARG_tls_cert_pem].u_obj;
        n_kw++;
    }

    if (args[ARG_tls_key_pem].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_tls_key_pem);
        call_args[1 + 2 * n_kw + 1] = args[ARG_tls_key_pem].u_obj;
        n_kw++;
    }

    if (args[ARG_tls_cert_path].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_tls_cert_path);
        call_args[1 + 2 * n_kw + 1] = args[ARG_tls_cert_path].u_obj;
        n_kw++;
    }

    if (args[ARG_tls_key_path].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_tls_key_path);
        call_args[1 + 2 * n_kw + 1] = args[ARG_tls_key_path].u_obj;
        n_kw++;
    }

    call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_ota);
    call_args[1 + 2 * n_kw + 1] = mp_obj_new_bool(args[ARG_ota].u_bool);
    n_kw++;
    if (args[ARG_ota_prefix].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_ota_prefix);
        call_args[1 + 2 * n_kw + 1] = args[ARG_ota_prefix].u_obj;
        n_kw++;
    }
    if (args[ARG_ota_token].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_ota_token);
        call_args[1 + 2 * n_kw + 1] = args[ARG_ota_token].u_obj;
        n_kw++;
    }
    if (args[ARG_ota_token_header].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_ota_token_header);
        call_args[1 + 2 * n_kw + 1] = args[ARG_ota_token_header].u_obj;
        n_kw++;
    }
    if (args[ARG_ota_token_query].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_ota_token_query);
        call_args[1 + 2 * n_kw + 1] = args[ARG_ota_token_query].u_obj;
        n_kw++;
    }

    if (args[ARG_min_workers].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_min_workers);
        call_args[1 + 2 * n_kw + 1] = args[ARG_min_workers].u_obj;
        n_kw++;
    }
    if (args[ARG_max_workers].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_max_workers);
        call_args[1 + 2 * n_kw + 1] = args[ARG_max_workers].u_obj;
        n_kw++;
    }
    if (args[ARG_bridge_min_workers].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_bridge_min_workers);
        call_args[1 + 2 * n_kw + 1] = args[ARG_bridge_min_workers].u_obj;
        n_kw++;
    }
    if (args[ARG_bridge_max_workers].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_bridge_max_workers);
        call_args[1 + 2 * n_kw + 1] = args[ARG_bridge_max_workers].u_obj;
        n_kw++;
    }
    if (args[ARG_bridge_queue_size].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_bridge_queue_size);
        call_args[1 + 2 * n_kw + 1] = args[ARG_bridge_queue_size].u_obj;
        n_kw++;
    }
    if (args[ARG_bridge_poll_burst].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_bridge_poll_burst);
        call_args[1 + 2 * n_kw + 1] = args[ARG_bridge_poll_burst].u_obj;
        n_kw++;
    }
    if (args[ARG_bridge_idle_sleep_ms].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_bridge_idle_sleep_ms);
        call_args[1 + 2 * n_kw + 1] = args[ARG_bridge_idle_sleep_ms].u_obj;
        n_kw++;
    }
    if (args[ARG_bridge_autoscale].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_bridge_autoscale);
        call_args[1 + 2 * n_kw + 1] = args[ARG_bridge_autoscale].u_obj;
        n_kw++;
    }
    if (args[ARG_bridge_enqueue_wait_ms].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_bridge_enqueue_wait_ms);
        call_args[1 + 2 * n_kw + 1] = args[ARG_bridge_enqueue_wait_ms].u_obj;
        n_kw++;
    }
    if (args[ARG_bridge_worker_yield_every].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_bridge_worker_yield_every);
        call_args[1 + 2 * n_kw + 1] = args[ARG_bridge_worker_yield_every].u_obj;
        n_kw++;
    }
    if (args[ARG_bridge_scale_up_max_burst].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_bridge_scale_up_max_burst);
        call_args[1 + 2 * n_kw + 1] = args[ARG_bridge_scale_up_max_burst].u_obj;
        n_kw++;
    }
    if (args[ARG_auto_docs].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_auto_docs);
        call_args[1 + 2 * n_kw + 1] = args[ARG_auto_docs].u_obj;
        n_kw++;
    }
    if (args[ARG_title].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_title);
        call_args[1 + 2 * n_kw + 1] = args[ARG_title].u_obj;
        n_kw++;
    }
    if (args[ARG_version].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_version);
        call_args[1 + 2 * n_kw + 1] = args[ARG_version].u_obj;
        n_kw++;
    }
    if (args[ARG_description].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_description);
        call_args[1 + 2 * n_kw + 1] = args[ARG_description].u_obj;
        n_kw++;
    }
    bool has_openapi_url = (n_args > (1 + ARG_openapi_url)) || vhttp_kw_map_has(kw_args, MP_QSTR_openapi_url);
    if (has_openapi_url) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_openapi_url);
        call_args[1 + 2 * n_kw + 1] = args[ARG_openapi_url].u_obj;
        n_kw++;
    }
    bool has_docs_url = (n_args > (1 + ARG_docs_url)) || vhttp_kw_map_has(kw_args, MP_QSTR_docs_url);
    if (has_docs_url) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_docs_url);
        call_args[1 + 2 * n_kw + 1] = args[ARG_docs_url].u_obj;
        n_kw++;
    }
    if (args[ARG_include_websocket_docs].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_include_websocket_docs);
        call_args[1 + 2 * n_kw + 1] = args[ARG_include_websocket_docs].u_obj;
        n_kw++;
    }
    if (args[ARG_cache_schema].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_cache_schema);
        call_args[1 + 2 * n_kw + 1] = args[ARG_cache_schema].u_obj;
        n_kw++;
    }
    if (args[ARG_servers].u_obj != mp_const_none) {
        call_args[1 + 2 * n_kw] = MP_OBJ_NEW_QSTR(MP_QSTR_servers);
        call_args[1 + 2 * n_kw + 1] = args[ARG_servers].u_obj;
        n_kw++;
    }

    return mp_call_function_n_kw(run_fun, 1, n_kw, call_args);
}
static MP_DEFINE_CONST_FUN_OBJ_KW(vhttp_app_run_obj, 1, vhttp_app_run);

static mp_obj_t viperhttp_depends(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    if (n_args < 1 || n_args > 2) {
        mp_raise_TypeError(MP_ERROR_TEXT("Depends(callable, [deps])"));
    }

    mp_obj_t callable = pos_args[0];
    mp_obj_t deps = mp_const_none;
    mp_obj_t mode = mp_obj_new_str("value", 5);
    if (n_args >= 2) {
        deps = pos_args[1];
    }

    if (kw_args != NULL && kw_args->used > 0) {
        mp_map_elem_t *elem = mp_map_lookup(kw_args, mp_obj_new_str("deps", 4), MP_MAP_LOOKUP);
        if (elem) {
            deps = elem->value;
        }
        elem = mp_map_lookup(kw_args, mp_obj_new_str("mode", 4), MP_MAP_LOOKUP);
        if (elem) {
            mode = elem->value;
        }
    }

    if (!mp_obj_is_callable(callable)) {
        mp_raise_TypeError(MP_ERROR_TEXT("callable required"));
    }
    if (deps != mp_const_none && !mp_obj_is_type(deps, &mp_type_dict)) {
        mp_raise_TypeError(MP_ERROR_TEXT("deps must be dict"));
    }
    if (!mp_obj_is_str(mode)) {
        mp_raise_TypeError(MP_ERROR_TEXT("mode must be str"));
    }
    size_t mode_len = 0;
    const char *mode_ptr = mp_obj_str_get_data(mode, &mode_len);
    bool mode_ok = false;
    if ((mode_len == 5 && memcmp(mode_ptr, "value", 5) == 0) ||
        (mode_len == 5 && memcmp(mode_ptr, "yield", 5) == 0) ||
        (mode_len == 11 && memcmp(mode_ptr, "async_yield", 11) == 0) ||
        (mode_len == 4 && memcmp(mode_ptr, "auto", 4) == 0)) {
        mode_ok = true;
    }
    if (!mode_ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("mode must be value|yield|async_yield|auto"));
    }

    mp_obj_t dict = mp_obj_new_dict(5);
    mp_obj_dict_store(dict, mp_obj_new_str("__vhttp_dep__", 13), mp_const_true);
    mp_obj_dict_store(dict, mp_obj_new_str("callable", 8), callable);
    mp_obj_dict_store(dict, mp_obj_new_str("deps", 4), deps);
    mp_obj_dict_store(dict, mp_obj_new_str("mode", 4), mode);
    return dict;
}
static MP_DEFINE_CONST_FUN_OBJ_KW(viperhttp_depends_obj, 1, viperhttp_depends);

static mp_obj_t viperhttp_query(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    if (n_args > 2) {
        mp_raise_TypeError(MP_ERROR_TEXT("Query([default], [cast])"));
    }

    mp_obj_t default_val = mp_const_none;
    mp_obj_t cast_val = mp_const_none;
    int default_provided = 0;

    if (n_args >= 1) {
        default_val = pos_args[0];
        default_provided = 1;
    }
    if (n_args >= 2) {
        cast_val = pos_args[1];
    }

    if (kw_args != NULL && kw_args->used > 0) {
        mp_map_elem_t *elem = mp_map_lookup(kw_args, mp_obj_new_str("default", 7), MP_MAP_LOOKUP);
        if (elem) {
            default_val = elem->value;
            default_provided = 1;
        }
        elem = mp_map_lookup(kw_args, mp_obj_new_str("cast", 4), MP_MAP_LOOKUP);
        if (elem) {
            cast_val = elem->value;
        }
    }

    if (cast_val != mp_const_none && vhttp_cast_kind_from_obj(cast_val) == VHTTP_CAST_NONE) {
        mp_raise_TypeError(MP_ERROR_TEXT("cast must be type"));
    }
    if (cast_val != mp_const_none && default_provided &&
        !vhttp_default_compatible(default_val, vhttp_cast_kind_from_obj(cast_val))) {
        mp_raise_TypeError(MP_ERROR_TEXT("query default incompatible with cast"));
    }

    mp_obj_t dict = mp_obj_new_dict(4);
    mp_obj_dict_store(dict, mp_obj_new_str("__vhttp_query__", 14), mp_const_true);
    mp_obj_dict_store(dict, mp_obj_new_str("default", 7), default_val);
    mp_obj_dict_store(dict, mp_obj_new_str("cast", 4), cast_val);
    mp_obj_dict_store(dict, mp_obj_new_str("required", 8), mp_obj_new_bool(!default_provided));
    return dict;
}
static MP_DEFINE_CONST_FUN_OBJ_KW(viperhttp_query_obj, 0, viperhttp_query);

static mp_obj_t viperhttp_gzip_static(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    enum {
        ARG_root,
        ARG_min_size,
        ARG_level,
    };
    static const mp_arg_t allowed_args[] = {
        { MP_QSTR_root, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_min_size, MP_ARG_INT, { .u_int = VHTTP_GZIP_MIN_SIZE } },
        { MP_QSTR_level, MP_ARG_INT, { .u_int = VHTTP_GZIP_LEVEL } },
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    const char *root = VHTTP_STATIC_FS_BASE;
    size_t root_len = strlen(root);
    if (args[ARG_root].u_obj != mp_const_none) {
        if (!mp_obj_is_str(args[ARG_root].u_obj)) {
            mp_raise_TypeError(MP_ERROR_TEXT("root must be str"));
        }
        root = mp_obj_str_get_data(args[ARG_root].u_obj, &root_len);
    }

    mp_int_t min_size = args[ARG_min_size].u_int;
    mp_int_t level = args[ARG_level].u_int;
    if (min_size < 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("min_size must be >= 0"));
    }
    if (level < 0 || level > 9) {
        mp_raise_ValueError(MP_ERROR_TEXT("level must be 0..9"));
    }

    vhttp_gzip_stats_t stats;
    int rc = vhttp_mp_static_gzip(root, root_len, (size_t)min_size, (int)level, &stats);
    if (rc != 0) {
        mp_raise_OSError(MP_EIO);
    }

    mp_obj_t dict = mp_obj_new_dict(6);
    mp_obj_dict_store(dict, mp_obj_new_str("files_seen", 10), mp_obj_new_int_from_uint(stats.files_seen));
    mp_obj_dict_store(dict, mp_obj_new_str("gzipped", 7), mp_obj_new_int_from_uint(stats.files_gzipped));
    mp_obj_dict_store(dict, mp_obj_new_str("skipped_small", 13), mp_obj_new_int_from_uint(stats.skipped_small));
    mp_obj_dict_store(dict, mp_obj_new_str("skipped_existing", 16), mp_obj_new_int_from_uint(stats.skipped_existing));
    mp_obj_dict_store(dict, mp_obj_new_str("skipped_ext", 11), mp_obj_new_int_from_uint(stats.skipped_ext));
    mp_obj_dict_store(dict, mp_obj_new_str("errors", 6), mp_obj_new_int_from_uint(stats.errors));
    return dict;
}
static MP_DEFINE_CONST_FUN_OBJ_KW(viperhttp_gzip_static_obj, 0, viperhttp_gzip_static);

static mp_obj_t viperhttp_fs_lock(void) {
    vhttp_fs_lock();
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_0(viperhttp_fs_lock_obj, viperhttp_fs_lock);

static mp_obj_t viperhttp_fs_unlock(void) {
    vhttp_fs_unlock();
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_0(viperhttp_fs_unlock_obj, viperhttp_fs_unlock);

static void vhttp_tpl_trim_ws(const char **ptr, size_t *len) {
    if (!ptr || !len || !*ptr) {
        return;
    }
    const char *p = *ptr;
    size_t l = *len;
    while (l > 0 && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) {
        p++;
        l--;
    }
    while (l > 0 && (p[l - 1] == ' ' || p[l - 1] == '\t' || p[l - 1] == '\r' || p[l - 1] == '\n')) {
        l--;
    }
    *ptr = p;
    *len = l;
}

static char *vhttp_tpl_copy_slice(const char *src, size_t len) {
    char *out = m_new(char, len + 1);
    memcpy(out, src, len);
    out[len] = '\0';
    return out;
}

static int vhttp_tpl_gc_ptr_valid(const void *ptr) {
    return ptr != NULL && gc_nbytes(ptr) != 0;
}

static uint32_t vhttp_u32_add_sat(uint32_t a, uint32_t b) {
    uint32_t c = a + b;
    if (c < a) {
        return UINT32_MAX;
    }
    return c;
}

static uint32_t vhttp_size_to_u32_sat(size_t v) {
    return v > UINT32_MAX ? UINT32_MAX : (uint32_t)v;
}

static uint32_t vhttp_tpl_cache_budget_bytes(void) {
#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
    if (heap_caps_get_total_size(MALLOC_CAP_SPIRAM) > 0 &&
        heap_caps_get_free_size(MALLOC_CAP_SPIRAM) > 0) {
        return VHTTP_TEMPLATE_CACHE_BUDGET_BYTES_PSRAM;
    }
#endif
    return VHTTP_TEMPLATE_CACHE_BUDGET_BYTES;
}

static void vhttp_tpl_free_nodes(vhttp_tpl_node_t *node);

static void vhttp_tpl_free_if_branches(vhttp_tpl_if_branch_t *branch) {
    while (branch) {
        if (!vhttp_tpl_gc_ptr_valid(branch)) {
            return;
        }
        vhttp_tpl_if_branch_t *next = branch->next;
        if (branch->cond && vhttp_tpl_gc_ptr_valid(branch->cond)) {
            m_del(char, branch->cond, branch->cond_len + 1);
        }
        vhttp_tpl_free_nodes(branch->body);
        if (vhttp_tpl_gc_ptr_valid(branch)) {
            m_del_obj(vhttp_tpl_if_branch_t, branch);
        }
        branch = next;
    }
}

static void vhttp_tpl_free_nodes(vhttp_tpl_node_t *node) {
    while (node) {
        if (!vhttp_tpl_gc_ptr_valid(node)) {
            return;
        }
        vhttp_tpl_node_t *next = node->next;
        if (node->type == VHTTP_TPL_NODE_EXPR) {
            if (node->as.expr.expr && vhttp_tpl_gc_ptr_valid(node->as.expr.expr)) {
                m_del(char, node->as.expr.expr, node->as.expr.expr_len + 1);
            }
        } else if (node->type == VHTTP_TPL_NODE_IF) {
            vhttp_tpl_free_if_branches(node->as.if_stmt.branches);
            vhttp_tpl_free_nodes(node->as.if_stmt.else_body);
        } else if (node->type == VHTTP_TPL_NODE_FOR) {
            if (node->as.for_stmt.var_name && vhttp_tpl_gc_ptr_valid(node->as.for_stmt.var_name)) {
                m_del(char, node->as.for_stmt.var_name, node->as.for_stmt.var_len + 1);
            }
            if (node->as.for_stmt.var_name2 && vhttp_tpl_gc_ptr_valid(node->as.for_stmt.var_name2)) {
                m_del(char, node->as.for_stmt.var_name2, node->as.for_stmt.var_len2 + 1);
            }
            if (node->as.for_stmt.iter_expr && vhttp_tpl_gc_ptr_valid(node->as.for_stmt.iter_expr)) {
                m_del(char, node->as.for_stmt.iter_expr, node->as.for_stmt.iter_len + 1);
            }
            vhttp_tpl_free_nodes(node->as.for_stmt.body);
            vhttp_tpl_free_nodes(node->as.for_stmt.else_body);
        } else if (node->type == VHTTP_TPL_NODE_INCLUDE) {
            if (node->as.include.path && vhttp_tpl_gc_ptr_valid(node->as.include.path)) {
                m_del(char, node->as.include.path, node->as.include.path_len + 1);
            }
        } else if (node->type == VHTTP_TPL_NODE_SET) {
            if (node->as.set_stmt.var_name && vhttp_tpl_gc_ptr_valid(node->as.set_stmt.var_name)) {
                m_del(char, node->as.set_stmt.var_name, node->as.set_stmt.var_len + 1);
            }
            if (node->as.set_stmt.expr && vhttp_tpl_gc_ptr_valid(node->as.set_stmt.expr)) {
                m_del(char, node->as.set_stmt.expr, node->as.set_stmt.expr_len + 1);
            }
        }
        if (vhttp_tpl_gc_ptr_valid(node)) {
            m_del_obj(vhttp_tpl_node_t, node);
        }
        node = next;
    }
}

static uint32_t vhttp_tpl_estimate_nodes_bytes(vhttp_tpl_node_t *node);

static uint32_t vhttp_tpl_estimate_if_branches_bytes(vhttp_tpl_if_branch_t *branch) {
    uint32_t total = 0;
    while (branch) {
        total = vhttp_u32_add_sat(total, vhttp_size_to_u32_sat(sizeof(vhttp_tpl_if_branch_t)));
        total = vhttp_u32_add_sat(total, vhttp_size_to_u32_sat(branch->cond_len + 1));
        total = vhttp_u32_add_sat(total, vhttp_tpl_estimate_nodes_bytes(branch->body));
        branch = branch->next;
    }
    return total;
}

static uint32_t vhttp_tpl_estimate_nodes_bytes(vhttp_tpl_node_t *node) {
    uint32_t total = 0;
    while (node) {
        total = vhttp_u32_add_sat(total, vhttp_size_to_u32_sat(sizeof(vhttp_tpl_node_t)));
        if (node->type == VHTTP_TPL_NODE_EXPR) {
            total = vhttp_u32_add_sat(total, vhttp_size_to_u32_sat(node->as.expr.expr_len + 1));
        } else if (node->type == VHTTP_TPL_NODE_IF) {
            total = vhttp_u32_add_sat(total, vhttp_tpl_estimate_if_branches_bytes(node->as.if_stmt.branches));
            total = vhttp_u32_add_sat(total, vhttp_tpl_estimate_nodes_bytes(node->as.if_stmt.else_body));
        } else if (node->type == VHTTP_TPL_NODE_FOR) {
            total = vhttp_u32_add_sat(total, vhttp_size_to_u32_sat(node->as.for_stmt.var_len + 1));
            total = vhttp_u32_add_sat(total, vhttp_size_to_u32_sat(node->as.for_stmt.var_len2 + 1));
            total = vhttp_u32_add_sat(total, vhttp_size_to_u32_sat(node->as.for_stmt.iter_len + 1));
            total = vhttp_u32_add_sat(total, vhttp_tpl_estimate_nodes_bytes(node->as.for_stmt.body));
            total = vhttp_u32_add_sat(total, vhttp_tpl_estimate_nodes_bytes(node->as.for_stmt.else_body));
        } else if (node->type == VHTTP_TPL_NODE_INCLUDE) {
            total = vhttp_u32_add_sat(total, vhttp_size_to_u32_sat(node->as.include.path_len + 1));
        } else if (node->type == VHTTP_TPL_NODE_SET) {
            total = vhttp_u32_add_sat(total, vhttp_size_to_u32_sat(node->as.set_stmt.var_len + 1));
            total = vhttp_u32_add_sat(total, vhttp_size_to_u32_sat(node->as.set_stmt.expr_len + 1));
        }
        node = node->next;
    }
    return total;
}

static size_t vhttp_tpl_cache_used_count(void) {
    size_t used = 0;
    for (size_t i = 0; i < VHTTP_TEMPLATE_CACHE_ENTRIES; ++i) {
        if (g_tpl_cache[i].used) {
            used++;
        }
    }
    return used;
}

static int vhttp_tpl_cache_lru_slot(void) {
    int slot = -1;
    uint32_t lru_seq = UINT32_MAX;
    for (size_t i = 0; i < VHTTP_TEMPLATE_CACHE_ENTRIES; ++i) {
        vhttp_tpl_cache_entry_t *entry = &g_tpl_cache[i];
        if (!entry->used) {
            continue;
        }
        if (entry->seq <= lru_seq) {
            lru_seq = entry->seq;
            slot = (int)i;
        }
    }
    return slot;
}

static void vhttp_tpl_cache_ensure_budget(uint32_t needed_bytes) {
    uint32_t budget = vhttp_tpl_cache_budget_bytes();
    if (budget == 0) {
        return;
    }
    if (needed_bytes > budget) {
        // Keep best-effort behavior: allow one oversize entry by evicting others.
        while (vhttp_tpl_cache_used_count() > 1) {
            int lru = vhttp_tpl_cache_lru_slot();
            if (lru < 0) {
                break;
            }
            g_tpl_stats.cache_evicts++;
            vhttp_tpl_cache_entry_clear(&g_tpl_cache[lru]);
        }
        return;
    }
    while (g_tpl_cache_bytes > budget || vhttp_u32_add_sat(g_tpl_cache_bytes, needed_bytes) > budget) {
        int lru = vhttp_tpl_cache_lru_slot();
        if (lru < 0) {
            break;
        }
        g_tpl_stats.cache_evicts++;
        vhttp_tpl_cache_entry_clear(&g_tpl_cache[lru]);
    }
}

static void vhttp_tpl_cache_entry_clear(vhttp_tpl_cache_entry_t *entry) {
    if (!entry || !entry->used) {
        return;
    }
    if (entry->cache_bytes > 0) {
        if (entry->cache_bytes >= g_tpl_cache_bytes) {
            g_tpl_cache_bytes = 0;
        } else {
            g_tpl_cache_bytes -= entry->cache_bytes;
        }
        entry->cache_bytes = 0;
    }
    size_t slot = (size_t)(entry - g_tpl_cache);
    if (entry->root && vhttp_tpl_gc_ptr_valid(entry->root)) {
        vhttp_tpl_free_nodes(entry->root);
        entry->root = NULL;
    }
    if (entry->source && vhttp_tpl_gc_ptr_valid(entry->source)) {
        m_del(char, entry->source, entry->source_len + 1);
        entry->source = NULL;
    }
    vhttp_tpl_keepalive_set(slot, NULL, NULL);
    memset(entry, 0, sizeof(*entry));
}

static void vhttp_tpl_cache_clear_all(void) {
    for (size_t i = 0; i < VHTTP_TEMPLATE_CACHE_ENTRIES; ++i) {
        vhttp_tpl_cache_entry_clear(&g_tpl_cache[i]);
    }
    g_tpl_cache_bytes = 0;
    g_tpl_cache_seq = 1;
}

static void vhttp_tpl_line_col_at(
    const char *src,
    size_t src_len,
    size_t pos,
    size_t *line_out,
    size_t *col_out
) {
    size_t line = 1;
    size_t col = 1;
    size_t lim = pos <= src_len ? pos : src_len;
    for (size_t i = 0; i < lim; ++i) {
        char c = src[i];
        if (c == '\n') {
            line++;
            col = 1;
            continue;
        }
        if (c == '\r') {
            if ((i + 1) < lim && src[i + 1] == '\n') {
                i++;
            }
            line++;
            col = 1;
            continue;
        }
        col++;
    }
    if (line_out) {
        *line_out = line;
    }
    if (col_out) {
        *col_out = col;
    }
}

typedef struct {
    char *buf;
    size_t len;
    size_t used;
} vhttp_debug_print_ctx_t;

static void vhttp_debug_print_strn(void *data, const char *str, size_t len) {
    if (!data || !str || len == 0) {
        return;
    }
    vhttp_debug_print_ctx_t *ctx = (vhttp_debug_print_ctx_t *)data;
    if (!ctx->buf || ctx->len == 0 || ctx->used >= (ctx->len - 1)) {
        return;
    }
    size_t room = (ctx->len - 1) - ctx->used;
    if (len > room) {
        len = room;
    }
    memcpy(ctx->buf + ctx->used, str, len);
    ctx->used += len;
    ctx->buf[ctx->used] = '\0';
}

static void vhttp_tpl_debug_exception_to_text(mp_obj_t exc, char *buf, size_t buf_len) {
    if (!buf || buf_len == 0) {
        return;
    }
    buf[0] = '\0';
    if (exc == MP_OBJ_NULL || exc == mp_const_none) {
        return;
    }
    vhttp_debug_print_ctx_t ctx;
    ctx.buf = buf;
    ctx.len = buf_len;
    ctx.used = 0;
    mp_print_t print = {&ctx, vhttp_debug_print_strn};
    mp_obj_print_helper(&print, exc, PRINT_EXC);
}

static void vhttp_tpl_debug_append_preview(
    char *err_buf,
    size_t err_buf_len,
    const char *src,
    size_t src_len,
    size_t pos
) {
    if (!g_tpl_debug_mode || !err_buf || err_buf_len == 0 || !src || src_len == 0) {
        return;
    }
    size_t used = strlen(err_buf);
    if (used >= err_buf_len - 1) {
        return;
    }

    size_t at = pos <= src_len ? pos : src_len;
    size_t line_start = at;
    while (line_start > 0) {
        char c = src[line_start - 1];
        if (c == '\n' || c == '\r') {
            break;
        }
        line_start--;
    }
    size_t line_end = at;
    while (line_end < src_len) {
        char c = src[line_end];
        if (c == '\n' || c == '\r') {
            break;
        }
        line_end++;
    }
    if (line_end <= line_start) {
        return;
    }

    size_t preview_start = line_start;
    size_t preview_end = line_end;
    const size_t preview_max = 72;
    if ((preview_end - preview_start) > preview_max) {
        size_t pivot = at;
        if (pivot < line_start) {
            pivot = line_start;
        }
        if (pivot > line_end) {
            pivot = line_end;
        }
        size_t half = preview_max / 2;
        preview_start = (pivot > half) ? (pivot - half) : line_start;
        if (preview_start < line_start) {
            preview_start = line_start;
        }
        preview_end = preview_start + preview_max;
        if (preview_end > line_end) {
            preview_end = line_end;
            if (preview_end > preview_max) {
                preview_start = preview_end - preview_max;
            }
            if (preview_start < line_start) {
                preview_start = line_start;
            }
        }
    }

    char preview[80];
    size_t out = 0;
    for (size_t i = preview_start; i < preview_end && out < (sizeof(preview) - 1); ++i) {
        unsigned char c = (unsigned char)src[i];
        if (c == '\t') {
            c = ' ';
        } else if (c < 32 || c == 127) {
            c = '?';
        }
        preview[out++] = (char)c;
    }
    preview[out] = '\0';

    const char *prefix = (preview_start > line_start) ? "..." : "";
    const char *suffix = (preview_end < line_end) ? "..." : "";
    snprintf(
        err_buf + used,
        err_buf_len - used,
        " [near: %s%s%s]",
        prefix,
        preview,
        suffix
    );
}

static void vhttp_tpl_parser_set_error_at(vhttp_tpl_parser_t *p, size_t pos, const char *msg) {
    if (!p || p->error) {
        return;
    }
    p->error = 1;
    p->error_pos = pos <= p->len ? pos : p->len;
    snprintf(p->error_msg, sizeof(p->error_msg), "%s", msg ? msg : "template parse error");
}

static void vhttp_tpl_parser_set_error(vhttp_tpl_parser_t *p, const char *msg) {
    vhttp_tpl_parser_set_error_at(p, p ? p->pos : 0, msg);
}

static int vhttp_tpl_const_truthy(const char *expr, size_t expr_len, int *known, int *truthy) {
    if (!known || !truthy) {
        return -1;
    }
    *known = 0;
    *truthy = 0;
    if (!expr) {
        return 0;
    }
    const char *ptr = expr;
    size_t len = expr_len;
    vhttp_trim_ows(&ptr, &len);
    if (len == 0) {
        *known = 1;
        *truthy = 0;
        return 0;
    }
    if (vhttp_str_ci_equals(ptr, len, "true")) {
        *known = 1;
        *truthy = 1;
        return 0;
    }
    if (vhttp_str_ci_equals(ptr, len, "false") ||
        vhttp_str_ci_equals(ptr, len, "none") ||
        vhttp_str_ci_equals(ptr, len, "null")) {
        *known = 1;
        *truthy = 0;
        return 0;
    }
    if (len >= 2 && ((ptr[0] == '"' && ptr[len - 1] == '"') || (ptr[0] == '\'' && ptr[len - 1] == '\''))) {
        *known = 1;
        *truthy = (len > 2) ? 1 : 0;
        return 0;
    }
    if (len < 48) {
        char num_buf[48];
        memcpy(num_buf, ptr, len);
        num_buf[len] = '\0';
        char *endp = NULL;
        double val = strtod(num_buf, &endp);
        if (endp && (size_t)(endp - num_buf) == len) {
            *known = 1;
            *truthy = (val != 0.0) ? 1 : 0;
            return 0;
        }
    }
    return 0;
}

static void vhttp_tpl_optimize_nodes(vhttp_tpl_node_t **head_ref) {
    if (!head_ref || !*head_ref) {
        return;
    }

    vhttp_tpl_node_t *node = *head_ref;
    vhttp_tpl_node_t *out_head = NULL;
    vhttp_tpl_node_t *out_tail = NULL;
    *head_ref = NULL;

    while (node) {
        vhttp_tpl_node_t *next = node->next;
        node->next = NULL;

        if (node->type == VHTTP_TPL_NODE_IF) {
            for (vhttp_tpl_if_branch_t *branch = node->as.if_stmt.branches; branch != NULL; branch = branch->next) {
                vhttp_tpl_optimize_nodes(&branch->body);
            }
            vhttp_tpl_optimize_nodes(&node->as.if_stmt.else_body);

            int can_fold = 1;
            vhttp_tpl_node_t *fold_body = NULL;
            for (vhttp_tpl_if_branch_t *branch = node->as.if_stmt.branches; branch != NULL; branch = branch->next) {
                int known = 0;
                int truthy = 0;
                (void)vhttp_tpl_const_truthy(branch->cond, branch->cond_len, &known, &truthy);
                if (!known) {
                    can_fold = 0;
                    break;
                }
                if (truthy) {
                    fold_body = branch->body;
                    branch->body = NULL;
                    break;
                }
            }
            if (can_fold && !fold_body) {
                fold_body = node->as.if_stmt.else_body;
                node->as.if_stmt.else_body = NULL;
            }
            if (can_fold) {
                vhttp_tpl_free_nodes(node);
                if (fold_body) {
                    vhttp_tpl_node_t *tail = fold_body;
                    while (tail->next) {
                        tail = tail->next;
                    }
                    tail->next = next;
                    node = fold_body;
                } else {
                    node = next;
                }
                continue;
            }
        } else if (node->type == VHTTP_TPL_NODE_FOR) {
            vhttp_tpl_optimize_nodes(&node->as.for_stmt.body);
            vhttp_tpl_optimize_nodes(&node->as.for_stmt.else_body);
        }

        if (node->type == VHTTP_TPL_NODE_TEXT) {
            if (node->as.text.len == 0) {
                vhttp_tpl_free_nodes(node);
                node = next;
                continue;
            }
            if (out_tail &&
                out_tail->type == VHTTP_TPL_NODE_TEXT &&
                out_tail->as.text.off + out_tail->as.text.len >= out_tail->as.text.off &&
                (out_tail->as.text.off + out_tail->as.text.len) == node->as.text.off) {
                out_tail->as.text.len += node->as.text.len;
                vhttp_tpl_free_nodes(node);
                node = next;
                continue;
            }
        }

        if (!out_head) {
            out_head = node;
            out_tail = node;
        } else {
            out_tail->next = node;
            out_tail = node;
        }

        node = next;
    }

    *head_ref = out_head;
}

static vhttp_tpl_node_t *vhttp_tpl_new_node(vhttp_tpl_parser_t *p, vhttp_tpl_node_type_t type) {
    if (p->nodes >= VHTTP_TEMPLATE_MAX_NODES) {
        vhttp_tpl_parser_set_error(p, "template too complex");
        return NULL;
    }
    vhttp_tpl_node_t *node = m_new_obj(vhttp_tpl_node_t);
    memset(node, 0, sizeof(*node));
    node->type = type;
    p->nodes++;
    return node;
}

static const char *vhttp_tpl_find_delim(const char *src, size_t len, size_t start, const char *delim) {
    size_t dlen = strlen(delim);
    if (dlen == 0 || start >= len || len < dlen) {
        return NULL;
    }
    for (size_t i = start; i + dlen <= len; ++i) {
        if (memcmp(src + i, delim, dlen) == 0) {
            return src + i;
        }
    }
    return NULL;
}

static int vhttp_tpl_stmt_eq(const char *stmt, size_t stmt_len, const char *keyword) {
    size_t klen = strlen(keyword);
    if (stmt_len != klen) {
        return 0;
    }
    return memcmp(stmt, keyword, klen) == 0;
}

static int vhttp_tpl_stmt_starts(const char *stmt, size_t stmt_len, const char *keyword, const char **rest, size_t *rest_len) {
    size_t klen = strlen(keyword);
    if (stmt_len <= klen || memcmp(stmt, keyword, klen) != 0) {
        return 0;
    }
    const char *ptr = stmt + klen;
    size_t len = stmt_len - klen;
    vhttp_tpl_trim_ws(&ptr, &len);
    if (rest) {
        *rest = ptr;
    }
    if (rest_len) {
        *rest_len = len;
    }
    return 1;
}

static int vhttp_tpl_compile_for_path(
    const char *path,
    size_t path_len,
    vhttp_tpl_cache_entry_t **entry_out,
    char *err_buf,
    size_t err_buf_len
);

static int vhttp_tpl_parse_include_path_literal(const char *src, size_t len, char **path_out, size_t *path_len_out) {
    const char *ptr = src;
    size_t plen = len;
    vhttp_tpl_trim_ws(&ptr, &plen);
    if (plen < 2) {
        return -1;
    }
    char quote = ptr[0];
    if (!((quote == '"' || quote == '\'') && ptr[plen - 1] == quote)) {
        return -1;
    }
    const char *body = ptr + 1;
    size_t body_len = plen - 2;
    if (body_len == 0 || body_len >= VHTTP_STATIC_MAX_PATH) {
        return -1;
    }
    for (size_t i = 0; i < body_len; ++i) {
        if ((unsigned char)body[i] < 0x20) {
            return -1;
        }
    }
    *path_out = vhttp_tpl_copy_slice(body, body_len);
    *path_len_out = body_len;
    return 0;
}

static int vhttp_tpl_path_dirname(const char *path, size_t path_len, char *out, size_t out_len, size_t *out_path_len) {
    if (!path || path_len == 0 || !out || out_len < 2 || path[0] != '/') {
        return -1;
    }
    size_t slash = SIZE_MAX;
    for (size_t i = path_len; i > 0; --i) {
        if (path[i - 1] == '/') {
            slash = i - 1;
            break;
        }
    }
    if (slash == SIZE_MAX || slash == 0) {
        out[0] = '/';
        out[1] = '\0';
        if (out_path_len) {
            *out_path_len = 1;
        }
        return 0;
    }
    if (slash >= out_len) {
        return -1;
    }
    memcpy(out, path, slash);
    out[slash] = '\0';
    if (out_path_len) {
        *out_path_len = slash;
    }
    return 0;
}

static int vhttp_tpl_path_normalize(const char *path, size_t path_len, char *out, size_t out_len, size_t *out_path_len) {
    if (!path || path_len == 0 || !out || out_len < 2 || path[0] != '/') {
        return -1;
    }
    size_t oi = 1;
    out[0] = '/';
    size_t i = 0;
    while (i < path_len) {
        while (i < path_len && path[i] == '/') {
            i++;
        }
        if (i >= path_len) {
            break;
        }
        size_t seg_start = i;
        while (i < path_len && path[i] != '/') {
            i++;
        }
        size_t seg_len = i - seg_start;
        if (seg_len == 0 || (seg_len == 1 && path[seg_start] == '.')) {
            continue;
        }
        if (seg_len == 2 && path[seg_start] == '.' && path[seg_start + 1] == '.') {
            if (oi <= 1) {
                return -1;
            }
            while (oi > 1 && out[oi - 1] != '/') {
                oi--;
            }
            continue;
        }
        if (oi > 1) {
            if (oi + 1 >= out_len) {
                return -1;
            }
            out[oi++] = '/';
        }
        if (oi + seg_len >= out_len) {
            return -1;
        }
        memcpy(out + oi, path + seg_start, seg_len);
        oi += seg_len;
    }
    out[oi] = '\0';
    if (out_path_len) {
        *out_path_len = oi;
    }
    return 0;
}

static int vhttp_tpl_path_under_root(const char *path, size_t path_len, const char *root, size_t root_len) {
    if (!path || !root || root_len == 0) {
        return 0;
    }
    if (root_len == 1 && root[0] == '/') {
        return 1;
    }
    if (path_len < root_len) {
        return 0;
    }
    if (memcmp(path, root, root_len) != 0) {
        return 0;
    }
    if (path_len == root_len) {
        return 1;
    }
    return path[root_len] == '/';
}

static int vhttp_tpl_resolve_include_path(
    const char *root_path,
    size_t root_len,
    const char *current_template_path,
    size_t current_template_len,
    const char *include_path,
    size_t include_len,
    char *out,
    size_t out_len,
    size_t *out_path_len
) {
    if (!root_path || root_len == 0 || !current_template_path || current_template_len == 0 ||
        !include_path || include_len == 0 || !out || out_len < 2) {
        return -1;
    }
    char combined[VHTTP_STATIC_MAX_PATH];
    size_t combined_len = 0;
    if (include_path[0] == '/') {
        if (include_len >= sizeof(combined)) {
            return -1;
        }
        memcpy(combined, include_path, include_len);
        combined[include_len] = '\0';
        combined_len = include_len;
    } else {
        char dir[VHTTP_STATIC_MAX_PATH];
        size_t dir_len = 0;
        if (vhttp_tpl_path_dirname(current_template_path, current_template_len, dir, sizeof(dir), &dir_len) != 0) {
            return -1;
        }
        if (dir_len == 1 && dir[0] == '/') {
            if (1 + include_len >= sizeof(combined)) {
                return -1;
            }
            combined[0] = '/';
            memcpy(combined + 1, include_path, include_len);
            combined_len = 1 + include_len;
            combined[combined_len] = '\0';
        } else {
            if (dir_len + 1 + include_len >= sizeof(combined)) {
                return -1;
            }
            memcpy(combined, dir, dir_len);
            combined[dir_len] = '/';
            memcpy(combined + dir_len + 1, include_path, include_len);
            combined_len = dir_len + 1 + include_len;
            combined[combined_len] = '\0';
        }
    }
    size_t norm_len = 0;
    if (vhttp_tpl_path_normalize(combined, combined_len, out, out_len, &norm_len) != 0) {
        return -1;
    }
    if (!vhttp_tpl_path_under_root(out, norm_len, root_path, root_len)) {
        return -1;
    }
    if (out_path_len) {
        *out_path_len = norm_len;
    }
    return 0;
}

static vhttp_tpl_node_t *vhttp_tpl_parse_nodes(vhttp_tpl_parser_t *p, uint8_t stop_mask);

static vhttp_tpl_if_branch_t *vhttp_tpl_make_if_branch(const char *cond, size_t cond_len, vhttp_tpl_node_t *body) {
    vhttp_tpl_if_branch_t *branch = m_new_obj(vhttp_tpl_if_branch_t);
    memset(branch, 0, sizeof(*branch));
    branch->cond = vhttp_tpl_copy_slice(cond, cond_len);
    branch->cond_len = cond_len;
    branch->body = body;
    return branch;
}

static vhttp_tpl_node_t *vhttp_tpl_parse_if(vhttp_tpl_parser_t *p, const char *cond, size_t cond_len) {
    vhttp_tpl_node_t *if_node = vhttp_tpl_new_node(p, VHTTP_TPL_NODE_IF);
    if (!if_node) {
        return NULL;
    }
    vhttp_tpl_if_branch_t *head = NULL;
    vhttp_tpl_if_branch_t *tail = NULL;
    vhttp_tpl_node_t *else_body = NULL;
    const char *cur_cond = cond;
    size_t cur_cond_len = cond_len;

    for (;;) {
        p->stop = VHTTP_TPL_STOP_NONE;
        vhttp_tpl_node_t *branch_body = vhttp_tpl_parse_nodes(p, (1u << VHTTP_TPL_STOP_ENDIF) | (1u << VHTTP_TPL_STOP_ELSE) | (1u << VHTTP_TPL_STOP_ELIF));
        if (p->error) {
            vhttp_tpl_free_nodes(if_node);
            return NULL;
        }

        vhttp_tpl_if_branch_t *branch = vhttp_tpl_make_if_branch(cur_cond, cur_cond_len, branch_body);
        if (!head) {
            head = branch;
        } else {
            tail->next = branch;
        }
        tail = branch;

        if (p->stop == VHTTP_TPL_STOP_ELIF) {
            cur_cond = p->stop_expr;
            cur_cond_len = p->stop_expr_len;
            continue;
        }
        if (p->stop == VHTTP_TPL_STOP_ELSE) {
            p->stop = VHTTP_TPL_STOP_NONE;
            else_body = vhttp_tpl_parse_nodes(p, (1u << VHTTP_TPL_STOP_ENDIF));
            if (p->error) {
                vhttp_tpl_free_nodes(if_node);
                return NULL;
            }
            if (p->stop != VHTTP_TPL_STOP_ENDIF) {
                vhttp_tpl_parser_set_error(p, "if missing endif");
                vhttp_tpl_free_nodes(if_node);
                return NULL;
            }
            break;
        }
        if (p->stop == VHTTP_TPL_STOP_ENDIF) {
            break;
        }
        vhttp_tpl_parser_set_error(p, "if missing endif");
        vhttp_tpl_free_nodes(if_node);
        return NULL;
    }

    if_node->as.if_stmt.branches = head;
    if_node->as.if_stmt.else_body = else_body;
    p->stop = VHTTP_TPL_STOP_NONE;
    return if_node;
}

static int vhttp_tpl_parse_identifier(const char *ptr, size_t len) {
    if (!ptr || len == 0) {
        return 0;
    }
    char c0 = ptr[0];
    if (!((c0 == '_') || (c0 >= 'A' && c0 <= 'Z') || (c0 >= 'a' && c0 <= 'z'))) {
        return 0;
    }
    for (size_t i = 1; i < len; ++i) {
        char c = ptr[i];
        if (!(c == '_' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) {
            return 0;
        }
    }
    return 1;
}

static int vhttp_tpl_parse_for_header(
    const char *stmt,
    size_t stmt_len,
    char **var_out,
    size_t *var_len_out,
    char **var2_out,
    size_t *var2_len_out,
    uint8_t *unpack_two_out,
    char **iter_out,
    size_t *iter_len_out
) {
    const char *ptr = stmt;
    size_t len = stmt_len;
    const char *rest = NULL;
    size_t rest_len = 0;
    if (!vhttp_tpl_stmt_starts(ptr, len, "for", &rest, &rest_len)) {
        return -1;
    }
    const char *in_kw = NULL;
    for (size_t i = 0; i + 2 <= rest_len; ++i) {
        if (rest[i] == ' ' && rest[i + 1] == 'i' && rest[i + 2] == 'n' &&
            (i + 3 == rest_len || rest[i + 3] == ' ' || rest[i + 3] == '\t')) {
            in_kw = rest + i + 1;
            break;
        }
    }
    if (!in_kw) {
        return -1;
    }

    size_t vars_len = (size_t)((in_kw - 1) - rest);
    const char *vars_ptr = rest;
    vhttp_tpl_trim_ws(&vars_ptr, &vars_len);
    if (vars_len == 0) {
        return -1;
    }
    const char *var1_ptr = vars_ptr;
    size_t var1_len = vars_len;
    const char *var2_ptr = NULL;
    size_t var2_len = 0;
    uint8_t unpack_two = 0;

    const char *comma = memchr(vars_ptr, ',', vars_len);
    if (comma) {
        unpack_two = 1;
        var1_len = (size_t)(comma - vars_ptr);
        vhttp_tpl_trim_ws(&var1_ptr, &var1_len);

        var2_ptr = comma + 1;
        var2_len = (size_t)((vars_ptr + vars_len) - var2_ptr);
        vhttp_tpl_trim_ws(&var2_ptr, &var2_len);
        if (memchr(var2_ptr, ',', var2_len)) {
            return -1;
        }
        if (!vhttp_tpl_parse_identifier(var2_ptr, var2_len)) {
            return -1;
        }
    }
    if (!vhttp_tpl_parse_identifier(var1_ptr, var1_len)) {
        return -1;
    }

    const char *iter_ptr = in_kw + 2;
    size_t iter_len = (size_t)(rest + rest_len - iter_ptr);
    vhttp_tpl_trim_ws(&iter_ptr, &iter_len);
    if (iter_len == 0) {
        return -1;
    }

    *var_out = vhttp_tpl_copy_slice(var1_ptr, var1_len);
    *var_len_out = var1_len;
    if (unpack_two) {
        *var2_out = vhttp_tpl_copy_slice(var2_ptr, var2_len);
        *var2_len_out = var2_len;
    } else {
        *var2_out = NULL;
        *var2_len_out = 0;
    }
    *unpack_two_out = unpack_two;
    *iter_out = vhttp_tpl_copy_slice(iter_ptr, iter_len);
    *iter_len_out = iter_len;
    return 0;
}

static vhttp_tpl_node_t *vhttp_tpl_parse_for(vhttp_tpl_parser_t *p, const char *stmt, size_t stmt_len) {
    char *var_name = NULL;
    size_t var_len = 0;
    char *var_name2 = NULL;
    size_t var_len2 = 0;
    uint8_t unpack_two = 0;
    char *iter_expr = NULL;
    size_t iter_len = 0;
    if (vhttp_tpl_parse_for_header(
            stmt,
            stmt_len,
            &var_name,
            &var_len,
            &var_name2,
            &var_len2,
            &unpack_two,
            &iter_expr,
            &iter_len) != 0) {
        vhttp_tpl_parser_set_error(p, "invalid for syntax");
        return NULL;
    }

    vhttp_tpl_node_t *for_node = vhttp_tpl_new_node(p, VHTTP_TPL_NODE_FOR);
    if (!for_node) {
        m_del(char, var_name, var_len + 1);
        if (var_name2) {
            m_del(char, var_name2, var_len2 + 1);
        }
        m_del(char, iter_expr, iter_len + 1);
        return NULL;
    }
    for_node->as.for_stmt.var_name = var_name;
    for_node->as.for_stmt.var_len = var_len;
    for_node->as.for_stmt.var_name2 = var_name2;
    for_node->as.for_stmt.var_len2 = var_len2;
    for_node->as.for_stmt.unpack_two = unpack_two;
    for_node->as.for_stmt.iter_expr = iter_expr;
    for_node->as.for_stmt.iter_len = iter_len;

    p->stop = VHTTP_TPL_STOP_NONE;
    vhttp_tpl_node_t *body = vhttp_tpl_parse_nodes(p, (1u << VHTTP_TPL_STOP_ENDFOR) | (1u << VHTTP_TPL_STOP_FOR_ELSE));
    if (p->error) {
        vhttp_tpl_free_nodes(for_node);
        return NULL;
    }
    vhttp_tpl_node_t *else_body = NULL;
    if (p->stop == VHTTP_TPL_STOP_FOR_ELSE) {
        p->stop = VHTTP_TPL_STOP_NONE;
        else_body = vhttp_tpl_parse_nodes(p, (1u << VHTTP_TPL_STOP_ENDFOR));
        if (p->error) {
            vhttp_tpl_free_nodes(for_node);
            return NULL;
        }
    }
    if (p->stop != VHTTP_TPL_STOP_ENDFOR) {
        vhttp_tpl_parser_set_error(p, "for missing endfor");
        vhttp_tpl_free_nodes(for_node);
        return NULL;
    }
    for_node->as.for_stmt.body = body;
    for_node->as.for_stmt.else_body = else_body;
    p->stop = VHTTP_TPL_STOP_NONE;
    return for_node;
}

static vhttp_tpl_node_t *vhttp_tpl_parse_set(vhttp_tpl_parser_t *p, const char *stmt, size_t stmt_len) {
    const char *rest = NULL;
    size_t rest_len = 0;
    if (!vhttp_tpl_stmt_starts(stmt, stmt_len, "set", &rest, &rest_len)) {
        vhttp_tpl_parser_set_error(p, "invalid set syntax");
        return NULL;
    }
    const char *eq = memchr(rest, '=', rest_len);
    if (!eq) {
        vhttp_tpl_parser_set_error(p, "set requires '='");
        return NULL;
    }

    const char *var_ptr = rest;
    size_t var_len = (size_t)(eq - rest);
    vhttp_tpl_trim_ws(&var_ptr, &var_len);
    if (!vhttp_tpl_parse_identifier(var_ptr, var_len)) {
        vhttp_tpl_parser_set_error(p, "invalid set variable");
        return NULL;
    }

    const char *expr_ptr = eq + 1;
    size_t expr_len = (size_t)((rest + rest_len) - expr_ptr);
    vhttp_tpl_trim_ws(&expr_ptr, &expr_len);
    if (expr_len == 0) {
        vhttp_tpl_parser_set_error(p, "set expression required");
        return NULL;
    }

    vhttp_tpl_node_t *set_node = vhttp_tpl_new_node(p, VHTTP_TPL_NODE_SET);
    if (!set_node) {
        return NULL;
    }
    set_node->as.set_stmt.var_name = vhttp_tpl_copy_slice(var_ptr, var_len);
    set_node->as.set_stmt.var_len = var_len;
    set_node->as.set_stmt.expr = vhttp_tpl_copy_slice(expr_ptr, expr_len);
    set_node->as.set_stmt.expr_len = expr_len;
    return set_node;
}

static void vhttp_tpl_rstrip_tail_text_node(vhttp_tpl_node_t *tail, const char *src) {
    if (!tail || tail->type != VHTTP_TPL_NODE_TEXT || !src) {
        return;
    }
    size_t len = tail->as.text.len;
    while (len > 0) {
        unsigned char c = (unsigned char)src[tail->as.text.off + len - 1];
        if (!isspace(c)) {
            break;
        }
        len--;
    }
    tail->as.text.len = len;
}

static size_t vhttp_tpl_skip_leading_ws(const char *src, size_t len, size_t pos) {
    while (pos < len) {
        unsigned char c = (unsigned char)src[pos];
        if (!isspace(c)) {
            break;
        }
        pos++;
    }
    return pos;
}

static vhttp_tpl_node_t *vhttp_tpl_parse_nodes(vhttp_tpl_parser_t *p, uint8_t stop_mask) {
    vhttp_tpl_node_t *head = NULL;
    vhttp_tpl_node_t *tail = NULL;

    while (p->pos < p->len && !p->error) {
        const char *src = p->src;
        size_t pos = p->pos;
        const char *next = vhttp_tpl_find_delim(src, p->len, pos, "{");
        if (!next) {
            size_t text_len = p->len - pos;
            if (text_len > 0) {
                vhttp_tpl_node_t *node = vhttp_tpl_new_node(p, VHTTP_TPL_NODE_TEXT);
                if (!node) {
                    break;
                }
                node->as.text.off = pos;
                node->as.text.len = text_len;
                if (!head) {
                    head = node;
                } else {
                    tail->next = node;
                }
                tail = node;
            }
            p->pos = p->len;
            break;
        }

        size_t next_off = (size_t)(next - src);
        int is_tag = 0;
        int left_trim = 0;
        if (next_off + 2 < p->len && src[next_off] == '{' &&
            (src[next_off + 1] == '{' || src[next_off + 1] == '%' || src[next_off + 1] == '#')) {
            is_tag = 1;
            if (src[next_off + 2] == '-') {
                left_trim = 1;
            }
        }

        if (next_off > pos) {
            size_t text_len = next_off - pos;
            if (left_trim) {
                while (text_len > 0 && isspace((unsigned char)src[pos + text_len - 1])) {
                    text_len--;
                }
            }
            if (text_len == 0) {
                p->pos = next_off;
                continue;
            }
            vhttp_tpl_node_t *text_node = vhttp_tpl_new_node(p, VHTTP_TPL_NODE_TEXT);
            if (!text_node) {
                break;
            }
            text_node->as.text.off = pos;
            text_node->as.text.len = text_len;
            if (!head) {
                head = text_node;
            } else {
                tail->next = text_node;
            }
            tail = text_node;
            p->pos = next_off;
            continue;
        }

        if (next_off == pos && is_tag && left_trim) {
            vhttp_tpl_rstrip_tail_text_node(tail, src);
        }

        if (next_off + 1 >= p->len) {
            vhttp_tpl_parser_set_error_at(p, next_off, "dangling template delimiter");
            break;
        }

        char kind = src[next_off + 1];
        if (kind == '{') {
            size_t expr_start = next_off + 2;
            if (expr_start < p->len && src[expr_start] == '-') {
                expr_start++;
            }
            const char *end = vhttp_tpl_find_delim(src, p->len, expr_start, "}}");
            if (!end) {
                vhttp_tpl_parser_set_error_at(p, next_off, "missing }}");
                break;
            }
            size_t end_off = (size_t)(end - src);
            int right_trim = 0;
            if (end_off > expr_start && src[end_off - 1] == '-') {
                right_trim = 1;
                end_off--;
            }
            const char *expr_ptr = src + expr_start;
            size_t expr_len = end_off - expr_start;
            vhttp_tpl_trim_ws(&expr_ptr, &expr_len);
            if (expr_len > 0) {
                vhttp_tpl_node_t *node = vhttp_tpl_new_node(p, VHTTP_TPL_NODE_EXPR);
                if (!node) {
                    break;
                }
                node->as.expr.expr = vhttp_tpl_copy_slice(expr_ptr, expr_len);
                node->as.expr.expr_len = expr_len;
                if (!head) {
                    head = node;
                } else {
                    tail->next = node;
                }
                tail = node;
            }
            p->pos = (size_t)(end - src) + 2;
            if (right_trim) {
                p->pos = vhttp_tpl_skip_leading_ws(src, p->len, p->pos);
            }
            continue;
        }

        if (kind == '#') {
            size_t comment_start = next_off + 2;
            if (comment_start < p->len && src[comment_start] == '-') {
                comment_start++;
            }
            const char *end = vhttp_tpl_find_delim(src, p->len, comment_start, "#}");
            if (!end) {
                vhttp_tpl_parser_set_error_at(p, next_off, "missing #}");
                break;
            }
            size_t end_off = (size_t)(end - src);
            int right_trim = 0;
            if (end_off > comment_start && src[end_off - 1] == '-') {
                right_trim = 1;
            }
            p->pos = (size_t)(end - src) + 2;
            if (right_trim) {
                p->pos = vhttp_tpl_skip_leading_ws(src, p->len, p->pos);
            }
            continue;
        }

        if (kind == '%') {
            size_t stmt_start = next_off + 2;
            if (stmt_start < p->len && src[stmt_start] == '-') {
                stmt_start++;
            }
            const char *end = vhttp_tpl_find_delim(src, p->len, stmt_start, "%}");
            if (!end) {
                vhttp_tpl_parser_set_error_at(p, next_off, "missing %}");
                break;
            }
            size_t end_off = (size_t)(end - src);
            int right_trim = 0;
            if (end_off > stmt_start && src[end_off - 1] == '-') {
                right_trim = 1;
                end_off--;
            }
            const char *stmt_ptr = src + stmt_start;
            size_t stmt_len = end_off - stmt_start;
            vhttp_tpl_trim_ws(&stmt_ptr, &stmt_len);
            p->pos = (size_t)(end - src) + 2;
            if (right_trim) {
                p->pos = vhttp_tpl_skip_leading_ws(src, p->len, p->pos);
            }
            if (stmt_len == 0) {
                continue;
            }

            if ((stop_mask & (1u << VHTTP_TPL_STOP_ENDIF)) && vhttp_tpl_stmt_eq(stmt_ptr, stmt_len, "endif")) {
                p->stop = VHTTP_TPL_STOP_ENDIF;
                return head;
            }
            if ((stop_mask & (1u << VHTTP_TPL_STOP_ELSE)) && vhttp_tpl_stmt_eq(stmt_ptr, stmt_len, "else")) {
                p->stop = VHTTP_TPL_STOP_ELSE;
                return head;
            }
            if ((stop_mask & (1u << VHTTP_TPL_STOP_ELIF)) && vhttp_tpl_stmt_starts(stmt_ptr, stmt_len, "elif", NULL, NULL)) {
                const char *expr_ptr = stmt_ptr + 4;
                size_t expr_len = stmt_len - 4;
                vhttp_tpl_trim_ws(&expr_ptr, &expr_len);
                if (expr_len == 0 || expr_len >= sizeof(p->stop_expr)) {
                    vhttp_tpl_parser_set_error(p, "invalid elif");
                    return head;
                }
                memcpy(p->stop_expr, expr_ptr, expr_len);
                p->stop_expr[expr_len] = '\0';
                p->stop_expr_len = expr_len;
                p->stop = VHTTP_TPL_STOP_ELIF;
                return head;
            }
            if ((stop_mask & (1u << VHTTP_TPL_STOP_ENDFOR)) && vhttp_tpl_stmt_eq(stmt_ptr, stmt_len, "endfor")) {
                p->stop = VHTTP_TPL_STOP_ENDFOR;
                return head;
            }
            if ((stop_mask & (1u << VHTTP_TPL_STOP_FOR_ELSE)) && vhttp_tpl_stmt_eq(stmt_ptr, stmt_len, "else")) {
                p->stop = VHTTP_TPL_STOP_FOR_ELSE;
                return head;
            }

            if (vhttp_tpl_stmt_starts(stmt_ptr, stmt_len, "if", NULL, NULL)) {
                const char *cond_ptr = stmt_ptr + 2;
                size_t cond_len = stmt_len - 2;
                vhttp_tpl_trim_ws(&cond_ptr, &cond_len);
                if (cond_len == 0) {
                    vhttp_tpl_parser_set_error_at(p, next_off, "if condition required");
                    break;
                }
                vhttp_tpl_node_t *if_node = vhttp_tpl_parse_if(p, cond_ptr, cond_len);
                if (p->error || !if_node) {
                    break;
                }
                if (!head) {
                    head = if_node;
                } else {
                    tail->next = if_node;
                }
                tail = if_node;
                continue;
            }

            if (vhttp_tpl_stmt_starts(stmt_ptr, stmt_len, "for", NULL, NULL)) {
                vhttp_tpl_node_t *for_node = vhttp_tpl_parse_for(p, stmt_ptr, stmt_len);
                if (p->error || !for_node) {
                    break;
                }
                if (!head) {
                    head = for_node;
                } else {
                    tail->next = for_node;
                }
                tail = for_node;
                continue;
            }

            if (vhttp_tpl_stmt_starts(stmt_ptr, stmt_len, "set", NULL, NULL)) {
                vhttp_tpl_node_t *set_node = vhttp_tpl_parse_set(p, stmt_ptr, stmt_len);
                if (p->error || !set_node) {
                    break;
                }
                if (!head) {
                    head = set_node;
                } else {
                    tail->next = set_node;
                }
                tail = set_node;
                continue;
            }

            if (vhttp_tpl_stmt_eq(stmt_ptr, stmt_len, "raw")) {
                size_t raw_body_start = p->pos;
                size_t scan = p->pos;
                int found_endraw = 0;
                while (scan < p->len) {
                    const char *cand = vhttp_tpl_find_delim(src, p->len, scan, "{%");
                    if (!cand) {
                        break;
                    }
                    size_t cand_off = (size_t)(cand - src);
                    size_t cand_stmt_start = cand_off + 2;
                    int endraw_left_trim = 0;
                    if (cand_stmt_start < p->len && src[cand_stmt_start] == '-') {
                        endraw_left_trim = 1;
                        cand_stmt_start++;
                    }
                    const char *cand_end = vhttp_tpl_find_delim(src, p->len, cand_stmt_start, "%}");
                    if (!cand_end) {
                        vhttp_tpl_parser_set_error_at(p, cand_off, "missing %}");
                        return head;
                    }
                    size_t cand_end_off = (size_t)(cand_end - src);
                    int endraw_right_trim = 0;
                    if (cand_end_off > cand_stmt_start && src[cand_end_off - 1] == '-') {
                        endraw_right_trim = 1;
                        cand_end_off--;
                    }
                    const char *cand_stmt_ptr = src + cand_stmt_start;
                    size_t cand_stmt_len = cand_end_off - cand_stmt_start;
                    vhttp_tpl_trim_ws(&cand_stmt_ptr, &cand_stmt_len);
                    if (vhttp_tpl_stmt_eq(cand_stmt_ptr, cand_stmt_len, "endraw")) {
                        size_t raw_body_end = cand_off;
                        if (endraw_left_trim) {
                            while (raw_body_end > raw_body_start && isspace((unsigned char)src[raw_body_end - 1])) {
                                raw_body_end--;
                            }
                        }
                        if (raw_body_end > raw_body_start) {
                            vhttp_tpl_node_t *raw_text = vhttp_tpl_new_node(p, VHTTP_TPL_NODE_TEXT);
                            if (!raw_text) {
                                return head;
                            }
                            raw_text->as.text.off = raw_body_start;
                            raw_text->as.text.len = raw_body_end - raw_body_start;
                            if (!head) {
                                head = raw_text;
                            } else {
                                tail->next = raw_text;
                            }
                            tail = raw_text;
                        }
                        p->pos = (size_t)(cand_end - src) + 2;
                        if (endraw_right_trim) {
                            p->pos = vhttp_tpl_skip_leading_ws(src, p->len, p->pos);
                        }
                        found_endraw = 1;
                        break;
                    }
                    scan = (size_t)(cand_end - src) + 2;
                }
                if (!found_endraw) {
                    vhttp_tpl_parser_set_error_at(p, next_off, "raw missing endraw");
                    break;
                }
                continue;
            }

            const char *include_ptr = NULL;
            size_t include_len = 0;
            if (vhttp_tpl_stmt_starts(stmt_ptr, stmt_len, "include", &include_ptr, &include_len)) {
                char *include_path = NULL;
                size_t include_path_len = 0;
                if (vhttp_tpl_parse_include_path_literal(include_ptr, include_len, &include_path, &include_path_len) != 0) {
                    vhttp_tpl_parser_set_error_at(p, next_off, "invalid include path");
                    break;
                }
                vhttp_tpl_node_t *include_node = vhttp_tpl_new_node(p, VHTTP_TPL_NODE_INCLUDE);
                if (!include_node) {
                    m_del(char, include_path, include_path_len + 1);
                    break;
                }
                include_node->as.include.path = include_path;
                include_node->as.include.path_len = include_path_len;
                if (!head) {
                    head = include_node;
                } else {
                    tail->next = include_node;
                }
                tail = include_node;
                continue;
            }

            if (vhttp_tpl_stmt_eq(stmt_ptr, stmt_len, "endif") ||
                vhttp_tpl_stmt_eq(stmt_ptr, stmt_len, "else") ||
                vhttp_tpl_stmt_starts(stmt_ptr, stmt_len, "elif", NULL, NULL) ||
                vhttp_tpl_stmt_eq(stmt_ptr, stmt_len, "endfor")) {
                vhttp_tpl_parser_set_error_at(p, next_off, "unexpected block terminator");
                break;
            }
            vhttp_tpl_parser_set_error_at(p, next_off, "unsupported template statement");
            break;
        }

        p->pos = next_off + 1;
    }

    return head;
}

static int vhttp_tpl_compile_source(
    const char *src,
    size_t src_len,
    vhttp_tpl_node_t **root_out,
    char *err_buf,
    size_t err_buf_len
) {
    vhttp_tpl_parser_t parser;
    memset(&parser, 0, sizeof(parser));
    parser.src = src;
    parser.len = src_len;
    parser.pos = 0;
    parser.error_pos = 0;
    parser.stop = VHTTP_TPL_STOP_NONE;
    vhttp_tpl_node_t *root = vhttp_tpl_parse_nodes(&parser, 0);
    if (!parser.error && parser.stop != VHTTP_TPL_STOP_NONE) {
        vhttp_tpl_parser_set_error_at(&parser, parser.pos, "unexpected block terminator");
    }
    if (parser.error) {
        if (root) {
            vhttp_tpl_free_nodes(root);
        }
        if (err_buf && err_buf_len > 0) {
            size_t line = 1;
            size_t col = 1;
            const char *reason = parser.error_msg[0] ? parser.error_msg : "parse error";
            vhttp_tpl_line_col_at(src, src_len, parser.error_pos, &line, &col);
            int written = snprintf(
                err_buf,
                err_buf_len,
                "template parse error at line %u, column %u",
                (unsigned)line,
                (unsigned)col
            );
            if (written < 0) {
                err_buf[0] = '\0';
            } else {
                size_t used = (size_t)written;
                if (used < err_buf_len) {
                    snprintf(err_buf + used, err_buf_len - used, ": %.40s", reason);
                }
                vhttp_tpl_debug_append_preview(err_buf, err_buf_len, src, src_len, parser.error_pos);
            }
        }
        return -1;
    }
    if (root) {
        vhttp_tpl_optimize_nodes(&root);
    }
    *root_out = root;
    return 0;
}

typedef struct {
    mp_obj_t scopes[VHTTP_TEMPLATE_MAX_DEPTH];
    size_t scope_len;
    int strict;
    uint32_t loop_iters;
} vhttp_tpl_render_ctx_t;

typedef int (*vhttp_tpl_sink_write_fn_t)(void *ctx, const char *data, size_t len);

typedef struct {
    vhttp_tpl_sink_write_fn_t write;
    void *ctx;
} vhttp_tpl_sink_t;

typedef struct {
    vstr_t *out;
} vhttp_tpl_vstr_sink_ctx_t;

typedef struct {
    vhttp_ipc_state_t *ipc;
    uint32_t request_id;
    uint16_t status_code;
    vstr_t *headers_vstr;
    uint8_t *buf;
    uint8_t *gzip_buf;
    uint32_t chunk_size;
    uint32_t buf_len;
    uint32_t gzip_crc32;
    uint32_t gzip_input_size;
    tdefl_compressor *gzip_comp;
    int gzip_enabled;
    int sent_headers;
    int sent_any;
} vhttp_tpl_ipc_sink_ctx_t;

static int vhttp_tpl_sink_vstr_write(void *ctx, const char *data, size_t len) {
    if (!ctx || !data || len == 0) {
        return 0;
    }
    vhttp_tpl_vstr_sink_ctx_t *sink_ctx = (vhttp_tpl_vstr_sink_ctx_t *)ctx;
    vstr_add_strn(sink_ctx->out, data, len);
    return 0;
}

static int vhttp_tpl_ipc_sink_flush(vhttp_tpl_ipc_sink_ctx_t *ctx, int final);

static int vhttp_tpl_ipc_sink_emit(vhttp_tpl_ipc_sink_ctx_t *ctx, const uint8_t *data, size_t len) {
    if (!ctx || (!data && len > 0) || !ctx->buf || ctx->chunk_size == 0) {
        return -1;
    }
    while (len > 0) {
        uint32_t free_space = ctx->chunk_size - ctx->buf_len;
        if (free_space == 0) {
            if (vhttp_tpl_ipc_sink_flush(ctx, 0) != 0) {
                return -1;
            }
            free_space = ctx->chunk_size - ctx->buf_len;
        }
        size_t take = len;
        if (take > (size_t)free_space) {
            take = (size_t)free_space;
        }
        memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += (uint32_t)take;
        data += take;
        len -= take;
        if (ctx->buf_len == ctx->chunk_size) {
            if (vhttp_tpl_ipc_sink_flush(ctx, 0) != 0) {
                return -1;
            }
        }
    }
    return 0;
}

static int vhttp_tpl_ipc_sink_gzip_write(
    vhttp_tpl_ipc_sink_ctx_t *ctx,
    const uint8_t *data,
    size_t len,
    tdefl_flush flush_mode
) {
    if (!ctx || !ctx->gzip_comp || !ctx->gzip_buf || ctx->chunk_size == 0) {
        return -1;
    }
    for (;;) {
        size_t in_len = len;
        size_t out_len = (size_t)ctx->chunk_size;
        const uint8_t *input_ptr = data ? data : (const uint8_t *)"";
        tdefl_status status = tdefl_compress(
            ctx->gzip_comp,
            input_ptr,
            &in_len,
            ctx->gzip_buf,
            &out_len,
            flush_mode
        );
        if (in_len > 0) {
            ctx->gzip_crc32 = (uint32_t)mz_crc32((mz_ulong)ctx->gzip_crc32, data, in_len);
            ctx->gzip_input_size += (uint32_t)in_len;
            data += in_len;
            len -= in_len;
        }
        if (out_len > 0) {
            if (vhttp_tpl_ipc_sink_emit(ctx, ctx->gzip_buf, out_len) != 0) {
                return -1;
            }
        }
        if (status < 0) {
            return -1;
        }
        if (in_len == 0 && out_len == 0 && status != TDEFL_STATUS_DONE) {
            return -1;
        }
        if (flush_mode == TDEFL_NO_FLUSH) {
            if (len == 0) {
                return 0;
            }
        } else if (status == TDEFL_STATUS_DONE) {
            return 0;
        }
    }
}

static int vhttp_tpl_ipc_sink_flush(vhttp_tpl_ipc_sink_ctx_t *ctx, int final) {
    if (!ctx || !ctx->ipc) {
        return -1;
    }
    if (ctx->gzip_enabled && final) {
        if (vhttp_tpl_ipc_sink_gzip_write(ctx, NULL, 0, TDEFL_FINISH) != 0) {
            return -1;
        }
        uint8_t trailer[8];
        uint32_t crc = ctx->gzip_crc32;
        uint32_t size = ctx->gzip_input_size;
        trailer[0] = (uint8_t)(crc & 0xffu);
        trailer[1] = (uint8_t)((crc >> 8) & 0xffu);
        trailer[2] = (uint8_t)((crc >> 16) & 0xffu);
        trailer[3] = (uint8_t)((crc >> 24) & 0xffu);
        trailer[4] = (uint8_t)(size & 0xffu);
        trailer[5] = (uint8_t)((size >> 8) & 0xffu);
        trailer[6] = (uint8_t)((size >> 16) & 0xffu);
        trailer[7] = (uint8_t)((size >> 24) & 0xffu);
        if (vhttp_tpl_ipc_sink_emit(ctx, trailer, sizeof(trailer)) != 0) {
            return -1;
        }
    }
    if (!final && ctx->buf_len == 0) {
        return 0;
    }

    const uint8_t *data = NULL;
    size_t len = 0;
    if (ctx->buf_len > 0) {
        data = ctx->buf;
        len = ctx->buf_len;
    }
    if (vhttp_ipc_send_stream_chunk(
            ctx->ipc,
            ctx->request_id,
            ctx->status_code,
            data,
            len,
            ctx->headers_vstr,
            !ctx->sent_headers,
            0,
            1,
            final ? 1 : 0) != 0) {
        return -1;
    }
    ctx->sent_headers = 1;
    if (len > 0 || final) {
        ctx->sent_any = 1;
    }
    ctx->buf_len = 0;
    return 0;
}

static int vhttp_tpl_sink_ipc_write(void *ctx, const char *data, size_t len) {
    if (!ctx || !data || len == 0) {
        return 0;
    }
    vhttp_tpl_ipc_sink_ctx_t *sink_ctx = (vhttp_tpl_ipc_sink_ctx_t *)ctx;
    if (!sink_ctx->buf || sink_ctx->chunk_size == 0) {
        return -1;
    }
    if (sink_ctx->gzip_enabled) {
        return vhttp_tpl_ipc_sink_gzip_write(
            sink_ctx,
            (const uint8_t *)data,
            len,
            TDEFL_NO_FLUSH
        );
    }

    return vhttp_tpl_ipc_sink_emit(sink_ctx, (const uint8_t *)data, len);
}

static int vhttp_tpl_try_dict_get(mp_obj_t dict_obj, const char *key, size_t key_len, mp_obj_t *out_val) {
    if (!mp_obj_is_type(dict_obj, &mp_type_dict)) {
        return 0;
    }
    mp_obj_t key_obj = mp_obj_new_str(key, key_len);
    nlr_buf_t nlr;
    if (nlr_push(&nlr) == 0) {
        *out_val = mp_obj_dict_get(dict_obj, key_obj);
        nlr_pop();
        return 1;
    }
    return 0;
}

static int vhttp_tpl_scope_lookup(vhttp_tpl_render_ctx_t *ctx, const char *name, size_t name_len, mp_obj_t *out_val) {
    for (size_t i = ctx->scope_len; i > 0; --i) {
        mp_obj_t scope = ctx->scopes[i - 1];
        if (vhttp_tpl_try_dict_get(scope, name, name_len, out_val)) {
            return 1;
        }
    }
    return 0;
}

static int vhttp_tpl_parse_literal(const char *expr, size_t expr_len, mp_obj_t *out_obj) {
    if (!expr || expr_len == 0) {
        return 0;
    }
    if ((expr[0] == '"' && expr[expr_len - 1] == '"') ||
        (expr[0] == '\'' && expr[expr_len - 1] == '\'')) {
        *out_obj = mp_obj_new_str(expr + 1, expr_len - 2);
        return 1;
    }
    if (vhttp_str_ci_equals(expr, expr_len, "true")) {
        *out_obj = mp_const_true;
        return 1;
    }
    if (vhttp_str_ci_equals(expr, expr_len, "false")) {
        *out_obj = mp_const_false;
        return 1;
    }
    if (vhttp_str_ci_equals(expr, expr_len, "none") || vhttp_str_ci_equals(expr, expr_len, "null")) {
        *out_obj = mp_const_none;
        return 1;
    }

    int has_digit = 0;
    int has_dot = 0;
    size_t idx = 0;
    if (expr[0] == '-' || expr[0] == '+') {
        idx = 1;
    }
    for (; idx < expr_len; ++idx) {
        char c = expr[idx];
        if (c >= '0' && c <= '9') {
            has_digit = 1;
            continue;
        }
        if (c == '.' && !has_dot) {
            has_dot = 1;
            continue;
        }
        has_digit = 0;
        break;
    }
    if (has_digit && idx == expr_len) {
        if (has_dot) {
            *out_obj = mp_obj_new_float((mp_float_t)strtod(expr, NULL));
        } else {
            *out_obj = mp_obj_new_int((mp_int_t)strtol(expr, NULL, 10));
        }
        return 1;
    }
    return 0;
}

static int vhttp_tpl_object_get_segment(mp_obj_t base, const char *segment, size_t seg_len, mp_obj_t *out_val) {
    if (base == mp_const_none) {
        return 0;
    }
    if (mp_obj_is_type(base, &mp_type_dict)) {
        if ((seg_len == 5 && memcmp(segment, "items", 5) == 0) ||
            (seg_len == 4 && memcmp(segment, "keys", 4) == 0) ||
            (seg_len == 6 && memcmp(segment, "values", 6) == 0)) {
            mp_map_t *map = mp_obj_dict_get_map(base);
            mp_obj_t out = mp_obj_new_list(map->used, NULL);
            mp_obj_list_t *out_list = MP_OBJ_TO_PTR(out);
            size_t idx = 0;
            for (size_t i = 0; i < map->alloc; ++i) {
                if (!mp_map_slot_is_filled(map, i)) {
                    continue;
                }
                mp_map_elem_t *elem = &map->table[i];
                if (seg_len == 5) {
                    mp_obj_t pair_items[2] = { elem->key, elem->value };
                    out_list->items[idx++] = mp_obj_new_tuple(2, pair_items);
                } else if (seg_len == 4) {
                    out_list->items[idx++] = elem->key;
                } else {
                    out_list->items[idx++] = elem->value;
                }
            }
            out_list->len = idx;
            *out_val = out;
            return 1;
        }
        return vhttp_tpl_try_dict_get(base, segment, seg_len, out_val);
    }
    if (mp_obj_is_type(base, &mp_type_list) || mp_obj_is_type(base, &mp_type_tuple)) {
        int numeric = 1;
        size_t idx = 0;
        for (size_t i = 0; i < seg_len; ++i) {
            char c = segment[i];
            if (c < '0' || c > '9') {
                numeric = 0;
                break;
            }
            idx = idx * 10u + (size_t)(c - '0');
        }
        if (!numeric) {
            return 0;
        }
        size_t n = 0;
        mp_obj_t *items = NULL;
        mp_obj_get_array(base, &n, &items);
        if (idx >= n) {
            return 0;
        }
        *out_val = items[idx];
        return 1;
    }
    qstr attr = qstr_from_strn(segment, seg_len);
    nlr_buf_t nlr;
    if (nlr_push(&nlr) == 0) {
        *out_val = mp_load_attr(base, attr);
        nlr_pop();
        return 1;
    }
    return 0;
}

static int vhttp_tpl_eval_path(vhttp_tpl_render_ctx_t *ctx, const char *expr, size_t expr_len, mp_obj_t *out_obj) {
    const char *ptr = expr;
    size_t len = expr_len;
    vhttp_tpl_trim_ws(&ptr, &len);
    if (len == 0) {
        return 0;
    }
    const char *dot = memchr(ptr, '.', len);
    size_t head_len = dot ? (size_t)(dot - ptr) : len;
    mp_obj_t cur = mp_const_none;
    if (!vhttp_tpl_scope_lookup(ctx, ptr, head_len, &cur)) {
        return 0;
    }
    size_t off = head_len;
    while (off < len) {
        if (ptr[off] != '.') {
            return 0;
        }
        off++;
        size_t seg_start = off;
        while (off < len && ptr[off] != '.') {
            off++;
        }
        size_t seg_len = off - seg_start;
        if (seg_len == 0) {
            return 0;
        }
        mp_obj_t next = mp_const_none;
        if (!vhttp_tpl_object_get_segment(cur, ptr + seg_start, seg_len, &next)) {
            return 0;
        }
        cur = next;
    }
    *out_obj = cur;
    return 1;
}

static mp_obj_t vhttp_tpl_to_str_obj(mp_obj_t obj) {
    if (mp_obj_is_str(obj)) {
        return obj;
    }
    mp_obj_t args[1] = { obj };
    return mp_obj_str_make_new(&mp_type_str, 1, 0, args);
}

static mp_obj_t vhttp_tpl_apply_filter(mp_obj_t value, const char *name, size_t name_len, const char *arg, size_t arg_len, int *safe_out, vhttp_tpl_render_ctx_t *ctx) {
    if (name_len == 6 && memcmp(name, "escape", 6) == 0) {
        if (safe_out) {
            *safe_out = 0;
        }
        return value;
    }
    if (name_len == 4 && memcmp(name, "safe", 4) == 0) {
        if (safe_out) {
            *safe_out = 1;
        }
        return value;
    }
    if (name_len == 5 && memcmp(name, "upper", 5) == 0) {
        mp_obj_t s = vhttp_tpl_to_str_obj(value);
        size_t slen = 0;
        const char *sptr = mp_obj_str_get_data(s, &slen);
        char *buf = m_new(char, slen + 1);
        for (size_t i = 0; i < slen; ++i) {
            buf[i] = (char)toupper((unsigned char)sptr[i]);
        }
        buf[slen] = '\0';
        mp_obj_t out = mp_obj_new_str(buf, slen);
        m_del(char, buf, slen + 1);
        return out;
    }
    if (name_len == 5 && memcmp(name, "lower", 5) == 0) {
        mp_obj_t s = vhttp_tpl_to_str_obj(value);
        size_t slen = 0;
        const char *sptr = mp_obj_str_get_data(s, &slen);
        char *buf = m_new(char, slen + 1);
        for (size_t i = 0; i < slen; ++i) {
            buf[i] = (char)tolower((unsigned char)sptr[i]);
        }
        buf[slen] = '\0';
        mp_obj_t out = mp_obj_new_str(buf, slen);
        m_del(char, buf, slen + 1);
        return out;
    }
    if (name_len == 6 && memcmp(name, "length", 6) == 0) {
        if (mp_obj_is_type(value, &mp_type_dict)) {
            mp_map_t *map = mp_obj_dict_get_map(value);
            return mp_obj_new_int_from_uint(map->used);
        }
        if (mp_obj_is_type(value, &mp_type_list) || mp_obj_is_type(value, &mp_type_tuple)) {
            size_t n = 0;
            mp_obj_t *items = NULL;
            mp_obj_get_array(value, &n, &items);
            return mp_obj_new_int_from_uint(n);
        }
        if (mp_obj_is_str(value) || mp_obj_is_type(value, &mp_type_bytes) || mp_obj_is_type(value, &mp_type_bytearray)) {
            size_t n = 0;
            mp_obj_str_get_data(value, &n);
            return mp_obj_new_int_from_uint(n);
        }
        nlr_buf_t nlr;
        if (nlr_push(&nlr) == 0) {
            mp_obj_t len_obj = mp_obj_len(value);
            nlr_pop();
            return len_obj;
        }
        return mp_obj_new_int(0);
    }
    if (name_len == 4 && memcmp(name, "join", 4) == 0) {
        const char *sep_ptr = ", ";
        size_t sep_len = 2;
        const char *ap = arg;
        size_t al = arg_len;
        vhttp_tpl_trim_ws(&ap, &al);
        if (al > 0) {
            if ((al >= 2 && ap[0] == '"' && ap[al - 1] == '"') || (al >= 2 && ap[0] == '\'' && ap[al - 1] == '\'')) {
                sep_ptr = ap + 1;
                sep_len = al - 2;
            } else {
                sep_ptr = ap;
                sep_len = al;
            }
        }
        size_t n = 0;
        mp_obj_t *items = NULL;
        if (!(mp_obj_is_type(value, &mp_type_list) || mp_obj_is_type(value, &mp_type_tuple))) {
            return vhttp_tpl_to_str_obj(value);
        }
        mp_obj_get_array(value, &n, &items);
        if (n == 0) {
            return mp_obj_new_str("", 0);
        }
        vstr_t vs;
        vstr_init(&vs, 32);
        for (size_t i = 0; i < n; ++i) {
            mp_obj_t s = vhttp_tpl_to_str_obj(items[i]);
            size_t slen = 0;
            const char *sptr = mp_obj_str_get_data(s, &slen);
            if (i > 0 && sep_len > 0) {
                vstr_add_strn(&vs, sep_ptr, sep_len);
            }
            if (slen > 0) {
                vstr_add_strn(&vs, sptr, slen);
            }
        }
        mp_obj_t out = mp_obj_new_str(vs.buf, vs.len);
        vstr_clear(&vs);
        return out;
    }
    if (name_len == 4 && memcmp(name, "trim", 4) == 0) {
        mp_obj_t s = vhttp_tpl_to_str_obj(value);
        size_t slen = 0;
        const char *sptr = mp_obj_str_get_data(s, &slen);
        const char *tp = sptr;
        size_t tl = slen;
        vhttp_tpl_trim_ws(&tp, &tl);
        return mp_obj_new_str(tp, tl);
    }
    if (name_len == 7 && memcmp(name, "replace", 7) == 0) {
        const char *ap = arg;
        size_t al = arg_len;
        vhttp_tpl_trim_ws(&ap, &al);
        const char *old_ptr = "";
        size_t old_len = 0;
        const char *new_ptr = "";
        size_t new_len = 0;
        const char *comma = memchr(ap, ',', al);
        if (comma) {
            const char *a1 = ap;
            size_t l1 = (size_t)(comma - ap);
            const char *a2 = comma + 1;
            size_t l2 = (size_t)((ap + al) - a2);
            vhttp_tpl_trim_ws(&a1, &l1);
            vhttp_tpl_trim_ws(&a2, &l2);
            if ((l1 >= 2 && a1[0] == '"' && a1[l1 - 1] == '"') || (l1 >= 2 && a1[0] == '\'' && a1[l1 - 1] == '\'')) {
                old_ptr = a1 + 1;
                old_len = l1 - 2;
            } else {
                old_ptr = a1;
                old_len = l1;
            }
            if ((l2 >= 2 && a2[0] == '"' && a2[l2 - 1] == '"') || (l2 >= 2 && a2[0] == '\'' && a2[l2 - 1] == '\'')) {
                new_ptr = a2 + 1;
                new_len = l2 - 2;
            } else {
                new_ptr = a2;
                new_len = l2;
            }
        }
        mp_obj_t s = vhttp_tpl_to_str_obj(value);
        size_t slen = 0;
        const char *sptr = mp_obj_str_get_data(s, &slen);
        if (old_len == 0) {
            return mp_obj_new_str(sptr, slen);
        }
        vstr_t vs;
        vstr_init(&vs, slen + 8);
        size_t i = 0;
        while (i < slen) {
            if (i + old_len <= slen && memcmp(sptr + i, old_ptr, old_len) == 0) {
                if (new_len > 0) {
                    vstr_add_strn(&vs, new_ptr, new_len);
                }
                i += old_len;
                continue;
            }
            vstr_add_byte(&vs, sptr[i]);
            i++;
        }
        mp_obj_t out = mp_obj_new_str(vs.buf, vs.len);
        vstr_clear(&vs);
        return out;
    }
    if (name_len == 10 && memcmp(name, "capitalize", 10) == 0) {
        mp_obj_t s = vhttp_tpl_to_str_obj(value);
        size_t slen = 0;
        const char *sptr = mp_obj_str_get_data(s, &slen);
        char *buf = m_new(char, slen + 1);
        for (size_t i = 0; i < slen; ++i) {
            buf[i] = (char)tolower((unsigned char)sptr[i]);
        }
        if (slen > 0) {
            buf[0] = (char)toupper((unsigned char)buf[0]);
        }
        buf[slen] = '\0';
        mp_obj_t out = mp_obj_new_str(buf, slen);
        m_del(char, buf, slen + 1);
        return out;
    }
    if (name_len == 5 && memcmp(name, "title", 5) == 0) {
        mp_obj_t s = vhttp_tpl_to_str_obj(value);
        size_t slen = 0;
        const char *sptr = mp_obj_str_get_data(s, &slen);
        char *buf = m_new(char, slen + 1);
        int new_word = 1;
        for (size_t i = 0; i < slen; ++i) {
            unsigned char c = (unsigned char)sptr[i];
            if (isalnum(c)) {
                if (new_word) {
                    buf[i] = (char)toupper(c);
                    new_word = 0;
                } else {
                    buf[i] = (char)tolower(c);
                }
            } else {
                buf[i] = (char)c;
                new_word = 1;
            }
        }
        buf[slen] = '\0';
        mp_obj_t out = mp_obj_new_str(buf, slen);
        m_del(char, buf, slen + 1);
        return out;
    }
    if (name_len == 7 && memcmp(name, "default", 7) == 0) {
        int is_empty = (value == mp_const_none);
        if (!is_empty && mp_obj_is_str(value)) {
            size_t n = 0;
            mp_obj_str_get_data(value, &n);
            is_empty = (n == 0);
        }
        if (!is_empty) {
            return value;
        }
        mp_obj_t fallback = mp_const_none;
        const char *ap = arg;
        size_t al = arg_len;
        vhttp_tpl_trim_ws(&ap, &al);
        if (al > 0) {
            if (!vhttp_tpl_parse_literal(ap, al, &fallback) && !vhttp_tpl_eval_path(ctx, ap, al, &fallback)) {
                fallback = mp_obj_new_str(ap, al);
            }
        }
        return fallback;
    }
    mp_raise_ValueError(MP_ERROR_TEXT("unknown template filter"));
}

static const char *vhttp_tpl_find_filter_pipe(const char *expr, size_t len, size_t start) {
    size_t depth = 0;
    int in_single = 0;
    int in_double = 0;
    int escaped = 0;
    for (size_t i = start; i < len; ++i) {
        char c = expr[i];
        if (escaped) {
            escaped = 0;
            continue;
        }
        if ((in_single || in_double) && c == '\\') {
            escaped = 1;
            continue;
        }
        if (!in_double && c == '\'') {
            in_single = !in_single;
            continue;
        }
        if (!in_single && c == '"') {
            in_double = !in_double;
            continue;
        }
        if (in_single || in_double) {
            continue;
        }
        if (c == '(') {
            depth++;
            continue;
        }
        if (c == ')' && depth > 0) {
            depth--;
            continue;
        }
        if (c == '|' && depth == 0) {
            return expr + i;
        }
    }
    return NULL;
}

static mp_obj_t vhttp_tpl_eval_expr(vhttp_tpl_render_ctx_t *ctx, const char *expr, size_t expr_len, int *safe_out) {
    const char *ptr = expr;
    size_t len = expr_len;
    vhttp_tpl_trim_ws(&ptr, &len);
    if (len == 0) {
        if (safe_out) {
            *safe_out = 0;
        }
        return mp_const_none;
    }

    const char *base = ptr;
    size_t base_len = len;
    const char *pipe = vhttp_tpl_find_filter_pipe(ptr, len, 0);
    if (pipe) {
        base_len = (size_t)(pipe - ptr);
    }
    const char *bp = base;
    size_t bl = base_len;
    vhttp_tpl_trim_ws(&bp, &bl);

    mp_obj_t value = mp_const_none;
    if (!vhttp_tpl_parse_literal(bp, bl, &value)) {
        if (!vhttp_tpl_eval_path(ctx, bp, bl, &value)) {
            if (ctx->strict) {
                mp_raise_ValueError(MP_ERROR_TEXT("undefined template variable"));
            }
            value = mp_const_none;
        }
    }

    int safe = 0;
    size_t off = pipe ? (size_t)(pipe - ptr) : len;
    while (off < len) {
        if (ptr[off] != '|') {
            off++;
            continue;
        }
        size_t start = off + 1;
        const char *next_pipe = vhttp_tpl_find_filter_pipe(ptr, len, start);
        off = next_pipe ? (size_t)(next_pipe - ptr) : len;
        const char *fptr = ptr + start;
        size_t flen = off - start;
        vhttp_tpl_trim_ws(&fptr, &flen);
        if (flen == 0) {
            continue;
        }
        const char *colon = memchr(fptr, ':', flen);
        const char *name_ptr = fptr;
        size_t name_len = flen;
        const char *arg_ptr = NULL;
        size_t arg_len = 0;
        if (colon) {
            name_len = (size_t)(colon - fptr);
            arg_ptr = colon + 1;
            arg_len = flen - name_len - 1;
        } else {
            // Jinja-like alternate filter syntax: name(arg)
            const char *lparen = memchr(fptr, '(', flen);
            if (lparen && flen >= 2 && fptr[flen - 1] == ')' && lparen > fptr) {
                name_len = (size_t)(lparen - fptr);
                arg_ptr = lparen + 1;
                arg_len = (size_t)((fptr + flen - 1) - arg_ptr);
            }
        }
        vhttp_tpl_trim_ws(&name_ptr, &name_len);
        if (arg_ptr) {
            vhttp_tpl_trim_ws(&arg_ptr, &arg_len);
        }
        value = vhttp_tpl_apply_filter(value, name_ptr, name_len, arg_ptr, arg_len, &safe, ctx);
    }

    if (safe_out) {
        *safe_out = safe;
    }
    return value;
}

static int vhttp_tpl_write_escaped(vhttp_tpl_sink_t *sink, const char *data, size_t len) {
    if (!sink || !sink->write) {
        return -1;
    }
    for (size_t i = 0; i < len; ++i) {
        char c = data[i];
        if (c == '&') {
            if (sink->write(sink->ctx, "&amp;", 5) != 0) {
                return -1;
            }
        } else if (c == '<') {
            if (sink->write(sink->ctx, "&lt;", 4) != 0) {
                return -1;
            }
        } else if (c == '>') {
            if (sink->write(sink->ctx, "&gt;", 4) != 0) {
                return -1;
            }
        } else if (c == '"') {
            if (sink->write(sink->ctx, "&quot;", 6) != 0) {
                return -1;
            }
        } else if (c == '\'') {
            if (sink->write(sink->ctx, "&#39;", 5) != 0) {
                return -1;
            }
        } else {
            if (sink->write(sink->ctx, &c, 1) != 0) {
                return -1;
            }
        }
    }
    return 0;
}

static int vhttp_tpl_expr_defined(vhttp_tpl_render_ctx_t *ctx, const char *expr, size_t expr_len, mp_obj_t *out_obj, int *defined_out) {
    const char *ptr = expr;
    size_t len = expr_len;
    vhttp_tpl_trim_ws(&ptr, &len);
    mp_obj_t value = mp_const_none;
    if (vhttp_tpl_parse_literal(ptr, len, &value)) {
        if (out_obj) {
            *out_obj = value;
        }
        if (defined_out) {
            *defined_out = 1;
        }
        return 0;
    }
    if (vhttp_tpl_eval_path(ctx, ptr, len, &value)) {
        if (out_obj) {
            *out_obj = value;
        }
        if (defined_out) {
            *defined_out = 1;
        }
        return 0;
    }
    if (out_obj) {
        *out_obj = mp_const_none;
    }
    if (defined_out) {
        *defined_out = 0;
    }
    return 0;
}

static int vhttp_tpl_find_op_top_level(const char *src, size_t len, const char *needle, size_t needle_len, int keyword_mode, size_t *pos_out) {
    int quote = 0;
    int escape = 0;
    int paren = 0;
    for (size_t i = 0; i + needle_len <= len; ++i) {
        unsigned char c = (unsigned char)src[i];
        if (quote) {
            if (escape) {
                escape = 0;
            } else if (c == '\\') {
                escape = 1;
            } else if (c == (unsigned char)quote) {
                quote = 0;
            }
            continue;
        }
        if (c == '\'' || c == '"') {
            quote = (int)c;
            continue;
        }
        if (c == '(') {
            paren++;
            continue;
        }
        if (c == ')') {
            if (paren > 0) {
                paren--;
            }
            continue;
        }
        if (paren > 0) {
            continue;
        }
        if (memcmp(src + i, needle, needle_len) != 0) {
            continue;
        }
        if (keyword_mode) {
            int left_ok = (i == 0) || isspace((unsigned char)src[i - 1]);
            int right_ok = (i + needle_len == len) || isspace((unsigned char)src[i + needle_len]);
            if (!left_ok || !right_ok) {
                continue;
            }
        }
        if (pos_out) {
            *pos_out = i;
        }
        return 1;
    }
    return 0;
}

static int vhttp_tpl_obj_in(mp_obj_t needle, mp_obj_t haystack) {
    if (haystack == mp_const_none) {
        return 0;
    }
    if (mp_obj_is_type(haystack, &mp_type_list) || mp_obj_is_type(haystack, &mp_type_tuple)) {
        size_t n = 0;
        mp_obj_t *items = NULL;
        mp_obj_get_array(haystack, &n, &items);
        for (size_t i = 0; i < n; ++i) {
            if (mp_obj_equal(needle, items[i])) {
                return 1;
            }
        }
        return 0;
    }
    if (mp_obj_is_type(haystack, &mp_type_dict)) {
        nlr_buf_t nlr;
        if (nlr_push(&nlr) == 0) {
            mp_obj_dict_get(haystack, needle);
            nlr_pop();
            return 1;
        }
        return 0;
    }
    if (mp_obj_is_str(haystack) || mp_obj_is_type(haystack, &mp_type_bytes) || mp_obj_is_type(haystack, &mp_type_bytearray)) {
        mp_obj_t n = vhttp_tpl_to_str_obj(needle);
        mp_obj_t h = vhttp_tpl_to_str_obj(haystack);
        size_t nlen = 0;
        size_t hlen = 0;
        const char *nptr = mp_obj_str_get_data(n, &nlen);
        const char *hptr = mp_obj_str_get_data(h, &hlen);
        if (nlen == 0) {
            return 1;
        }
        if (nlen > hlen) {
            return 0;
        }
        for (size_t i = 0; i + nlen <= hlen; ++i) {
            if (memcmp(hptr + i, nptr, nlen) == 0) {
                return 1;
            }
        }
        return 0;
    }
    return 0;
}

static int vhttp_tpl_eval_test(vhttp_tpl_render_ctx_t *ctx, const char *lhs_ptr, size_t lhs_len, const char *test_ptr, size_t test_len) {
    mp_obj_t lhs = mp_const_none;
    int defined = 0;
    vhttp_tpl_expr_defined(ctx, lhs_ptr, lhs_len, &lhs, &defined);

    const char *name = test_ptr;
    size_t name_len = test_len;
    int invert = 0;
    if (name_len > 4 && memcmp(name, "not ", 4) == 0) {
        invert = 1;
        name += 4;
        name_len -= 4;
        vhttp_tpl_trim_ws(&name, &name_len);
    }

    int res = 0;
    if (name_len == 7 && memcmp(name, "defined", 7) == 0) {
        res = defined;
    } else if (name_len == 9 && memcmp(name, "undefined", 9) == 0) {
        res = !defined;
    } else if (name_len == 4 && memcmp(name, "none", 4) == 0) {
        res = defined && (lhs == mp_const_none);
    } else if (name_len == 4 && memcmp(name, "true", 4) == 0) {
        res = defined && (lhs == mp_const_true);
    } else if (name_len == 5 && memcmp(name, "false", 5) == 0) {
        res = defined && (lhs == mp_const_false);
    } else if (name_len == 6 && memcmp(name, "string", 6) == 0) {
        res = defined && mp_obj_is_str(lhs);
    } else if (name_len == 6 && memcmp(name, "number", 6) == 0) {
        res = defined && (mp_obj_is_int(lhs) || mp_obj_is_float(lhs));
    } else if (name_len == 8 && memcmp(name, "iterable", 8) == 0) {
        res = defined && (mp_obj_is_type(lhs, &mp_type_list) || mp_obj_is_type(lhs, &mp_type_tuple) || mp_obj_is_type(lhs, &mp_type_dict) || mp_obj_is_str(lhs));
    } else {
        mp_raise_ValueError(MP_ERROR_TEXT("unknown template test"));
    }
    return invert ? !res : res;
}

static int vhttp_tpl_eval_compare(vhttp_tpl_render_ctx_t *ctx, const char *expr, size_t expr_len, int *ok_out) {
    const char *ptr = expr;
    size_t len = expr_len;
    vhttp_tpl_trim_ws(&ptr, &len);
    if (len == 0) {
        *ok_out = 1;
        return 0;
    }

    size_t op_pos = 0;
    if (vhttp_tpl_find_op_top_level(ptr, len, " not in ", 8, 0, &op_pos)) {
        int safe = 0;
        mp_obj_t lhs = vhttp_tpl_eval_expr(ctx, ptr, op_pos, &safe);
        mp_obj_t rhs = vhttp_tpl_eval_expr(ctx, ptr + op_pos + 8, len - op_pos - 8, &safe);
        *ok_out = 1;
        return !vhttp_tpl_obj_in(lhs, rhs);
    }
    if (vhttp_tpl_find_op_top_level(ptr, len, " in ", 4, 0, &op_pos)) {
        int safe = 0;
        mp_obj_t lhs = vhttp_tpl_eval_expr(ctx, ptr, op_pos, &safe);
        mp_obj_t rhs = vhttp_tpl_eval_expr(ctx, ptr + op_pos + 4, len - op_pos - 4, &safe);
        *ok_out = 1;
        return vhttp_tpl_obj_in(lhs, rhs);
    }
    if (vhttp_tpl_find_op_top_level(ptr, len, " is ", 4, 0, &op_pos)) {
        *ok_out = 1;
        return vhttp_tpl_eval_test(ctx, ptr, op_pos, ptr + op_pos + 4, len - op_pos - 4);
    }
    if (vhttp_tpl_find_op_top_level(ptr, len, "==", 2, 0, &op_pos)) {
        int safe = 0;
        mp_obj_t lhs = vhttp_tpl_eval_expr(ctx, ptr, op_pos, &safe);
        mp_obj_t rhs = vhttp_tpl_eval_expr(ctx, ptr + op_pos + 2, len - op_pos - 2, &safe);
        *ok_out = 1;
        return mp_obj_equal(lhs, rhs);
    }
    if (vhttp_tpl_find_op_top_level(ptr, len, "!=", 2, 0, &op_pos)) {
        int safe = 0;
        mp_obj_t lhs = vhttp_tpl_eval_expr(ctx, ptr, op_pos, &safe);
        mp_obj_t rhs = vhttp_tpl_eval_expr(ctx, ptr + op_pos + 2, len - op_pos - 2, &safe);
        *ok_out = 1;
        return !mp_obj_equal(lhs, rhs);
    }
    if (vhttp_tpl_find_op_top_level(ptr, len, "<=", 2, 0, &op_pos) ||
        vhttp_tpl_find_op_top_level(ptr, len, ">=", 2, 0, &op_pos) ||
        vhttp_tpl_find_op_top_level(ptr, len, "<", 1, 0, &op_pos) ||
        vhttp_tpl_find_op_top_level(ptr, len, ">", 1, 0, &op_pos)) {
        size_t op_len = 1;
        mp_binary_op_t op = MP_BINARY_OP_LESS;
        if (op_pos + 1 < len && ptr[op_pos] == '<' && ptr[op_pos + 1] == '=') {
            op_len = 2;
            op = MP_BINARY_OP_LESS_EQUAL;
        } else if (op_pos + 1 < len && ptr[op_pos] == '>' && ptr[op_pos + 1] == '=') {
            op_len = 2;
            op = MP_BINARY_OP_MORE_EQUAL;
        } else if (ptr[op_pos] == '<') {
            op = MP_BINARY_OP_LESS;
        } else {
            op = MP_BINARY_OP_MORE;
        }
        int safe = 0;
        mp_obj_t lhs = vhttp_tpl_eval_expr(ctx, ptr, op_pos, &safe);
        mp_obj_t rhs = vhttp_tpl_eval_expr(ctx, ptr + op_pos + op_len, len - op_pos - op_len, &safe);
        nlr_buf_t nlr;
        if (nlr_push(&nlr) == 0) {
            mp_obj_t result = mp_binary_op(op, lhs, rhs);
            int truth = mp_obj_is_true(result);
            nlr_pop();
            *ok_out = 1;
            return truth;
        }
        *ok_out = 1;
        return 0;
    }
    *ok_out = 0;
    return 0;
}

static int vhttp_tpl_eval_bool(vhttp_tpl_render_ctx_t *ctx, const char *cond, size_t cond_len) {
    const char *ptr = cond;
    size_t len = cond_len;
    vhttp_tpl_trim_ws(&ptr, &len);
    if (len == 0) {
        return 0;
    }

    size_t pos = 0;
    if (vhttp_tpl_find_op_top_level(ptr, len, " or ", 4, 0, &pos)) {
        return vhttp_tpl_eval_bool(ctx, ptr, pos) || vhttp_tpl_eval_bool(ctx, ptr + pos + 4, len - pos - 4);
    }
    if (vhttp_tpl_find_op_top_level(ptr, len, " and ", 5, 0, &pos)) {
        return vhttp_tpl_eval_bool(ctx, ptr, pos) && vhttp_tpl_eval_bool(ctx, ptr + pos + 5, len - pos - 5);
    }
    if (len > 4 && memcmp(ptr, "not ", 4) == 0) {
        return !vhttp_tpl_eval_bool(ctx, ptr + 4, len - 4);
    }
    if (len >= 2 && ptr[0] == '(' && ptr[len - 1] == ')') {
        size_t depth = 0;
        int balanced = 1;
        for (size_t i = 0; i < len; ++i) {
            char c = ptr[i];
            if (c == '(') {
                depth++;
            } else if (c == ')') {
                if (depth == 0) {
                    balanced = 0;
                    break;
                }
                depth--;
                if (depth == 0 && i != len - 1) {
                    balanced = 0;
                    break;
                }
            }
        }
        if (balanced && depth == 0) {
            return vhttp_tpl_eval_bool(ctx, ptr + 1, len - 2);
        }
    }

    int ok = 0;
    int cmp = vhttp_tpl_eval_compare(ctx, ptr, len, &ok);
    if (ok) {
        return cmp;
    }

    int safe = 0;
    mp_obj_t val = vhttp_tpl_eval_expr(ctx, ptr, len, &safe);
    return mp_obj_is_true(val);
}

static int vhttp_tpl_render_nodes(
    vhttp_tpl_node_t *node,
    vhttp_tpl_render_ctx_t *ctx,
    vhttp_tpl_sink_t *sink,
    uint32_t depth,
    uint32_t include_depth,
    const char *source,
    size_t source_len,
    const char *current_template_path,
    size_t current_template_len,
    const char *template_root,
    size_t template_root_len
) {
    if (depth > VHTTP_TEMPLATE_MAX_DEPTH) {
        mp_raise_ValueError(MP_ERROR_TEXT("template depth exceeded"));
    }
    for (vhttp_tpl_node_t *cur = node; cur != NULL; cur = cur->next) {
        if (cur->type == VHTTP_TPL_NODE_TEXT) {
            if (!source || cur->as.text.off > source_len || cur->as.text.len > (source_len - cur->as.text.off)) {
                mp_raise_ValueError(MP_ERROR_TEXT("template text bounds"));
            }
            if (!sink || !sink->write || sink->write(sink->ctx, source + cur->as.text.off, cur->as.text.len) != 0) {
                return -1;
            }
            continue;
        }

        if (cur->type == VHTTP_TPL_NODE_EXPR) {
            int safe = 0;
            mp_obj_t val = vhttp_tpl_eval_expr(ctx, cur->as.expr.expr, cur->as.expr.expr_len, &safe);
            if (val == mp_const_none) {
                continue;
            }
            mp_obj_t s = vhttp_tpl_to_str_obj(val);
            size_t slen = 0;
            const char *sptr = mp_obj_str_get_data(s, &slen);
            if (safe) {
                if (!sink || !sink->write || sink->write(sink->ctx, sptr, slen) != 0) {
                    return -1;
                }
            } else {
                if (vhttp_tpl_write_escaped(sink, sptr, slen) != 0) {
                    return -1;
                }
            }
            continue;
        }

        if (cur->type == VHTTP_TPL_NODE_IF) {
            int matched = 0;
            for (vhttp_tpl_if_branch_t *branch = cur->as.if_stmt.branches; branch != NULL; branch = branch->next) {
                if (vhttp_tpl_eval_bool(ctx, branch->cond, branch->cond_len)) {
                    matched = 1;
                    if (vhttp_tpl_render_nodes(
                            branch->body,
                            ctx,
                            sink,
                            depth + 1,
                            include_depth,
                            source,
                            source_len,
                            current_template_path,
                            current_template_len,
                            template_root,
                            template_root_len) != 0) {
                        return -1;
                    }
                    break;
                }
            }
            if (!matched && cur->as.if_stmt.else_body) {
                if (vhttp_tpl_render_nodes(
                        cur->as.if_stmt.else_body,
                        ctx,
                        sink,
                        depth + 1,
                        include_depth,
                        source,
                        source_len,
                        current_template_path,
                        current_template_len,
                        template_root,
                        template_root_len) != 0) {
                    return -1;
                }
            }
            continue;
        }

        if (cur->type == VHTTP_TPL_NODE_SET) {
            int safe = 0;
            mp_obj_t value = vhttp_tpl_eval_expr(ctx, cur->as.set_stmt.expr, cur->as.set_stmt.expr_len, &safe);
            if (ctx->scope_len == 0) {
                mp_raise_ValueError(MP_ERROR_TEXT("template scope missing"));
            }
            mp_obj_t scope = ctx->scopes[ctx->scope_len - 1];
            if (!mp_obj_is_type(scope, &mp_type_dict)) {
                mp_raise_ValueError(MP_ERROR_TEXT("template scope invalid"));
            }
            mp_obj_dict_store(
                scope,
                mp_obj_new_str(cur->as.set_stmt.var_name, cur->as.set_stmt.var_len),
                value
            );
            continue;
        }

        if (cur->type == VHTTP_TPL_NODE_FOR) {
            int safe = 0;
            mp_obj_t iterable = vhttp_tpl_eval_expr(ctx, cur->as.for_stmt.iter_expr, cur->as.for_stmt.iter_len, &safe);
            int iterated = 0;

            size_t known_len = 0;
            int has_known_len = 0;
            if (iterable != mp_const_none) {
                if (mp_obj_is_type(iterable, &mp_type_list) || mp_obj_is_type(iterable, &mp_type_tuple)) {
                    mp_obj_t *items = NULL;
                    mp_obj_get_array(iterable, &known_len, &items);
                    has_known_len = 1;
                } else if (mp_obj_is_type(iterable, &mp_type_dict)) {
                    known_len = mp_obj_dict_get_map(iterable)->used;
                    has_known_len = 1;
                }

                mp_obj_iter_buf_t iter_buf;
                mp_obj_t iter = mp_getiter(iterable, &iter_buf);
                size_t idx = 0;
                while (1) {
                    mp_obj_t item = mp_iternext(iter);
                    if (item == MP_OBJ_STOP_ITERATION) {
                        break;
                    }
                    iterated = 1;
                    ctx->loop_iters++;
                    if (ctx->loop_iters > VHTTP_TEMPLATE_MAX_LOOP_ITERS) {
                        mp_raise_ValueError(MP_ERROR_TEXT("template loop limit exceeded"));
                    }
                    mp_obj_t scope = mp_obj_new_dict(2);
                    if (cur->as.for_stmt.unpack_two) {
                        mp_obj_t first = mp_const_none;
                        mp_obj_t second = mp_const_none;
                        int unpack_ok = 0;
                        if (mp_obj_is_type(item, &mp_type_tuple) || mp_obj_is_type(item, &mp_type_list)) {
                            size_t pair_len = 0;
                            mp_obj_t *pair_items = NULL;
                            mp_obj_get_array(item, &pair_len, &pair_items);
                            if (pair_len >= 2) {
                                first = pair_items[0];
                                second = pair_items[1];
                                unpack_ok = 1;
                            }
                        }
                        if (!unpack_ok) {
                            mp_raise_ValueError(MP_ERROR_TEXT("for unpack requires 2-item iterable"));
                        }
                        mp_obj_dict_store(scope, mp_obj_new_str(cur->as.for_stmt.var_name, cur->as.for_stmt.var_len), first);
                        mp_obj_dict_store(scope, mp_obj_new_str(cur->as.for_stmt.var_name2, cur->as.for_stmt.var_len2), second);
                    } else {
                        mp_obj_dict_store(scope, mp_obj_new_str(cur->as.for_stmt.var_name, cur->as.for_stmt.var_len), item);
                    }
                    mp_obj_t loop = mp_obj_new_dict(8);
                    mp_obj_dict_store(loop, mp_obj_new_str("index", 5), mp_obj_new_int_from_uint(idx + 1));
                    mp_obj_dict_store(loop, mp_obj_new_str("index0", 6), mp_obj_new_int_from_uint(idx));
                    mp_obj_dict_store(loop, mp_obj_new_str("first", 5), mp_obj_new_bool(idx == 0));
                    mp_obj_dict_store(loop, mp_obj_new_str("length", 6), has_known_len ? mp_obj_new_int_from_uint(known_len) : mp_const_none);
                    mp_obj_dict_store(loop, mp_obj_new_str("last", 4), mp_obj_new_bool(has_known_len ? (idx + 1 == known_len) : 0));
                    mp_obj_dict_store(loop, mp_obj_new_str("revindex", 8), has_known_len ? mp_obj_new_int_from_uint(known_len - idx) : mp_const_none);
                    mp_obj_dict_store(loop, mp_obj_new_str("revindex0", 9), has_known_len ? mp_obj_new_int_from_uint(known_len - idx - 1) : mp_const_none);
                    mp_obj_dict_store(scope, mp_obj_new_str("loop", 4), loop);

                    if (ctx->scope_len >= VHTTP_TEMPLATE_MAX_DEPTH) {
                        mp_raise_ValueError(MP_ERROR_TEXT("template scope depth exceeded"));
                    }
                    ctx->scopes[ctx->scope_len++] = scope;
                    int rc = vhttp_tpl_render_nodes(
                        cur->as.for_stmt.body,
                        ctx,
                        sink,
                        depth + 1,
                        include_depth,
                        source,
                        source_len,
                        current_template_path,
                        current_template_len,
                        template_root,
                        template_root_len
                    );
                    ctx->scope_len--;
                    if (rc != 0) {
                        return rc;
                    }
                    idx++;
                }
            }
            if (!iterated && cur->as.for_stmt.else_body) {
                if (vhttp_tpl_render_nodes(
                        cur->as.for_stmt.else_body,
                        ctx,
                        sink,
                        depth + 1,
                        include_depth,
                        source,
                        source_len,
                        current_template_path,
                        current_template_len,
                        template_root,
                        template_root_len) != 0) {
                    return -1;
                }
            }
            continue;
        }

        if (cur->type == VHTTP_TPL_NODE_INCLUDE) {
            if (include_depth >= VHTTP_TEMPLATE_MAX_INCLUDE_DEPTH) {
                mp_raise_ValueError(MP_ERROR_TEXT("template include depth exceeded"));
            }
            char include_full[VHTTP_STATIC_MAX_PATH];
            size_t include_full_len = 0;
            if (vhttp_tpl_resolve_include_path(
                    template_root,
                    template_root_len,
                    current_template_path,
                    current_template_len,
                    cur->as.include.path,
                    cur->as.include.path_len,
                    include_full,
                    sizeof(include_full),
                    &include_full_len) != 0) {
                mp_raise_ValueError(MP_ERROR_TEXT("template include path invalid"));
            }

            vhttp_tpl_cache_entry_t *include_entry = NULL;
            char include_err[96];
            include_err[0] = '\0';
            if (vhttp_tpl_compile_for_path(
                    include_full,
                    include_full_len,
                    &include_entry,
                    include_err,
                    sizeof(include_err)) != 0 || !include_entry) {
                mp_raise_msg_varg(
                    &mp_type_ValueError,
                    MP_ERROR_TEXT("template include error: %s"),
                    include_err[0] ? include_err : "compile failed"
                );
            }
            if (vhttp_tpl_render_nodes(
                    include_entry->root,
                    ctx,
                    sink,
                    depth + 1,
                    include_depth + 1,
                    include_entry->source,
                    include_entry->source_len,
                    include_entry->path,
                    include_entry->path_len,
                    template_root,
                    template_root_len) != 0) {
                return -1;
            }
            continue;
        }
    }
    return 0;
}

static int vhttp_tpl_cache_find(const char *path, size_t path_len, size_t file_size, uint32_t mtime) {
    for (size_t i = 0; i < VHTTP_TEMPLATE_CACHE_ENTRIES; ++i) {
        vhttp_tpl_cache_entry_t *entry = &g_tpl_cache[i];
        if (!entry->used) {
            continue;
        }
        if (entry->path_len != path_len || entry->file_size != file_size || entry->mtime != mtime) {
            continue;
        }
        if (memcmp(entry->path, path, path_len) != 0) {
            continue;
        }
        return (int)i;
    }
    return -1;
}

static int vhttp_tpl_cache_slot_for_store(void) {
    int free_slot = -1;
    int lru_slot = -1;
    uint32_t lru_seq = UINT32_MAX;
    for (size_t i = 0; i < VHTTP_TEMPLATE_CACHE_ENTRIES; ++i) {
        vhttp_tpl_cache_entry_t *entry = &g_tpl_cache[i];
        if (!entry->used) {
            free_slot = (int)i;
            break;
        }
        if (entry->seq < lru_seq) {
            lru_seq = entry->seq;
            lru_slot = (int)i;
        }
    }
    return free_slot >= 0 ? free_slot : lru_slot;
}

static int vhttp_tpl_compile_for_path(
    const char *path,
    size_t path_len,
    vhttp_tpl_cache_entry_t **entry_out,
    char *err_buf,
    size_t err_buf_len
) {
    if (!path || path_len == 0 || path_len >= VHTTP_STATIC_MAX_PATH) {
        if (err_buf && err_buf_len > 0) {
            snprintf(err_buf, err_buf_len, "invalid template path");
        }
        return -1;
    }
    size_t file_size = 0;
    uint32_t mtime = 0;
    int is_dir = 0;
    if (vhttp_mp_stat_path(path, path_len, &file_size, &mtime, &is_dir) != 0 || is_dir) {
        if (err_buf && err_buf_len > 0) {
            snprintf(err_buf, err_buf_len, "template not found");
        }
        return -1;
    }
    if (file_size > VHTTP_TEMPLATE_MAX_SIZE) {
        if (err_buf && err_buf_len > 0) {
            snprintf(err_buf, err_buf_len, "template too large");
        }
        return -1;
    }

    int hit = vhttp_tpl_cache_find(path, path_len, file_size, mtime);
    if (hit >= 0) {
        vhttp_tpl_cache_entry_t *entry = &g_tpl_cache[hit];
        entry->seq = g_tpl_cache_seq++;
        entry->hits++;
        g_tpl_stats.cache_hits++;
        *entry_out = entry;
        return 0;
    }

    g_tpl_stats.cache_misses++;
    mp_obj_t file_obj = mp_const_none;
    char *source = NULL;
    vhttp_tpl_node_t *root = NULL;
    int rc = -1;

    vhttp_fs_lock();
    do {
        if (vhttp_mp_open_file(path, path_len, "rb", &file_obj) != 0) {
            break;
        }
        source = m_new(char, file_size + 1);
        if (file_size > 0 && vhttp_mp_read_full(file_obj, (uint8_t *)source, file_size) != 0) {
            break;
        }
        source[file_size] = '\0';
        rc = 0;
    } while (0);
    if (file_obj != mp_const_none) {
        mp_stream_close(file_obj);
    }
    vhttp_fs_unlock();
    if (rc != 0) {
        if (source) {
            m_del(char, source, file_size + 1);
        }
        if (err_buf && err_buf_len > 0) {
            snprintf(err_buf, err_buf_len, "template read failed");
        }
        return -1;
    }

    g_tpl_stats.compiles++;
    if (vhttp_tpl_compile_source(source, file_size, &root, err_buf, err_buf_len) != 0) {
        m_del(char, source, file_size + 1);
        return -1;
    }

    uint32_t entry_bytes = 0;
    entry_bytes = vhttp_u32_add_sat(entry_bytes, vhttp_size_to_u32_sat(file_size + 1));
    entry_bytes = vhttp_u32_add_sat(entry_bytes, vhttp_tpl_estimate_nodes_bytes(root));

    vhttp_tpl_cache_ensure_budget(entry_bytes);

    int slot = vhttp_tpl_cache_slot_for_store();
    if (slot < 0) {
        vhttp_tpl_free_nodes(root);
        m_del(char, source, file_size + 1);
        if (err_buf && err_buf_len > 0) {
            snprintf(err_buf, err_buf_len, "template cache unavailable");
        }
        return -1;
    }

    vhttp_tpl_cache_entry_t *entry = &g_tpl_cache[slot];
    if (entry->used) {
        g_tpl_stats.cache_evicts++;
        vhttp_tpl_cache_entry_clear(entry);
    }
    memset(entry, 0, sizeof(*entry));
    entry->used = 1;
    memcpy(entry->path, path, path_len);
    entry->path[path_len] = '\0';
    entry->path_len = path_len;
    entry->file_size = file_size;
    entry->source_len = file_size;
    entry->mtime = mtime;
    entry->cache_bytes = entry_bytes;
    entry->source = source;
    entry->root = root;
    vhttp_tpl_keepalive_set((size_t)slot, entry->source, entry->root);
    entry->seq = g_tpl_cache_seq++;
    entry->hits = 0;
    g_tpl_cache_bytes = vhttp_u32_add_sat(g_tpl_cache_bytes, entry->cache_bytes);
    *entry_out = entry;
    return 0;
}

static int vhttp_tpl_is_template_ext(const char *path, size_t path_len) {
    static const char *k_tpl_exts[] = {
        ".html", ".htm", ".tpl", ".j2", ".jinja", ".jinja2"
    };
    for (size_t i = 0; i < (sizeof(k_tpl_exts) / sizeof(k_tpl_exts[0])); ++i) {
        if (vhttp_path_has_suffix_ci(path, path_len, k_tpl_exts[i])) {
            return 1;
        }
    }
    return 0;
}

static int vhttp_tpl_join_path(
    const char *dir,
    size_t dir_len,
    const char *name,
    size_t name_len,
    char *out,
    size_t out_len,
    size_t *out_path_len
) {
    int plen = -1;
    if (dir_len == 1 && dir[0] == '/') {
        plen = snprintf(out, out_len, "/%.*s", (int)name_len, name);
    } else {
        plen = snprintf(out, out_len, "%.*s/%.*s", (int)dir_len, dir, (int)name_len, name);
    }
    if (plen <= 0 || (size_t)plen >= out_len) {
        return -1;
    }
    if (out_path_len) {
        *out_path_len = (size_t)plen;
    }
    return 0;
}

static int vhttp_tpl_warmup_compile_path(const char *path, size_t path_len, vhttp_tpl_warmup_stats_t *stats) {
    char err[96];
    err[0] = '\0';
    vhttp_tpl_cache_entry_t *entry = NULL;
    uint32_t compiles_before = 0;
    uint32_t hits_before = 0;
    int rc = -1;

    vhttp_tpl_lock();
    compiles_before = g_tpl_stats.compiles;
    hits_before = g_tpl_stats.cache_hits;
    rc = vhttp_tpl_compile_for_path(path, path_len, &entry, err, sizeof(err));
    if (rc == 0 && entry) {
        if (g_tpl_stats.compiles > compiles_before) {
            if (stats) {
                stats->compiled++;
            }
        } else if (g_tpl_stats.cache_hits > hits_before) {
            if (stats) {
                stats->cached++;
            }
        } else if (stats) {
            stats->cached++;
        }
    } else if (stats) {
        stats->errors++;
    }
    vhttp_tpl_unlock();
    return rc;
}

static int vhttp_tpl_warmup_walk(
    const char *dir,
    size_t dir_len,
    int depth,
    vhttp_tpl_warmup_stats_t *stats
) {
    if (depth > VHTTP_TEMPLATE_WARMUP_MAX_DEPTH) {
        if (stats) {
            stats->errors++;
        }
        return -1;
    }

    mp_obj_t list_obj = mp_const_none;
    if (vhttp_mp_listdir(dir, dir_len, &list_obj) != 0) {
        if (stats) {
            stats->errors++;
        }
        return -1;
    }

    size_t list_len = 0;
    mp_obj_t *items = NULL;
    mp_obj_get_array(list_obj, &list_len, &items);

    char path[VHTTP_STATIC_MAX_PATH];
    for (size_t i = 0; i < list_len; ++i) {
        mp_obj_t name_obj = items[i];
        if (!mp_obj_is_str(name_obj)) {
            continue;
        }
        size_t name_len = 0;
        const char *name = mp_obj_str_get_data(name_obj, &name_len);
        if (!name || name_len == 0) {
            continue;
        }

        size_t path_len = 0;
        if (vhttp_tpl_join_path(dir, dir_len, name, name_len, path, sizeof(path), &path_len) != 0) {
            if (stats) {
                stats->errors++;
            }
            continue;
        }

        size_t file_size = 0;
        uint32_t file_mtime = 0;
        int is_dir = 0;
        if (vhttp_mp_stat_path(path, path_len, &file_size, &file_mtime, &is_dir) != 0) {
            if (stats) {
                stats->errors++;
            }
            continue;
        }

        if (is_dir) {
            if (stats) {
                stats->dirs_seen++;
            }
            vhttp_tpl_warmup_walk(path, path_len, depth + 1, stats);
            continue;
        }

        if (stats) {
            stats->files_seen++;
        }
        if (!vhttp_tpl_is_template_ext(path, path_len)) {
            continue;
        }
        if (stats) {
            stats->candidates++;
        }
        vhttp_tpl_warmup_compile_path(path, path_len, stats);
    }

    return 0;
}

static int vhttp_tpl_render_path(
    const char *path,
    size_t path_len,
    mp_obj_t context_obj,
    int strict,
    mp_obj_t *out_obj,
    char *err_buf,
    size_t err_buf_len
) {
    if (context_obj == mp_const_none) {
        context_obj = mp_obj_new_dict(0);
    }
    if (!mp_obj_is_type(context_obj, &mp_type_dict)) {
        if (err_buf && err_buf_len > 0) {
            snprintf(err_buf, err_buf_len, "context must be dict");
        }
        return -1;
    }

    vhttp_tpl_cache_entry_t *entry = NULL;
    vstr_t out;
    int out_inited = 0;
    int failed = 0;
    vhttp_tpl_vstr_sink_ctx_t sink_ctx;
    vhttp_tpl_sink_t sink;
    char template_root[VHTTP_STATIC_MAX_PATH];
    size_t template_root_len = 1;
    template_root[0] = '/';
    template_root[1] = '\0';
    if (path_len > 0 && path[0] == '/') {
        if (vhttp_tpl_path_dirname(path, path_len, template_root, sizeof(template_root), &template_root_len) != 0) {
            if (err_buf && err_buf_len > 0) {
                snprintf(err_buf, err_buf_len, "invalid template path");
            }
            return -1;
        }
    }

    vhttp_tpl_lock();
    nlr_buf_t nlr;
    if (nlr_push(&nlr) == 0) {
        if (vhttp_tpl_compile_for_path(path, path_len, &entry, err_buf, err_buf_len) != 0 || !entry) {
            failed = 1;
        } else {
            vhttp_tpl_render_ctx_t ctx;
            memset(&ctx, 0, sizeof(ctx));
            ctx.strict = strict;
            ctx.scope_len = 1;
            ctx.scopes[0] = context_obj;

            vstr_init(&out, entry->source_len + 64);
            out_inited = 1;
            sink_ctx.out = &out;
            sink.write = vhttp_tpl_sink_vstr_write;
            sink.ctx = &sink_ctx;
            if (vhttp_tpl_render_nodes(
                    entry->root,
                    &ctx,
                    &sink,
                    1,
                    0,
                    entry->source,
                    entry->source_len,
                    entry->path,
                    entry->path_len,
                    template_root,
                    template_root_len) != 0) {
                failed = 1;
                if (err_buf && err_buf_len > 0 && err_buf[0] == '\0') {
                    snprintf(err_buf, err_buf_len, "template render failed");
                }
            }
        }
        nlr_pop();
    } else {
        g_tpl_stats.errors++;
        failed = 1;
        if (err_buf && err_buf_len > 0) {
            if (g_tpl_debug_mode) {
                char exc_msg[96];
                vhttp_tpl_debug_exception_to_text(MP_OBJ_FROM_PTR(nlr.ret_val), exc_msg, sizeof(exc_msg));
                snprintf(
                    err_buf,
                    err_buf_len,
                    "template runtime error%s%s",
                    exc_msg[0] ? ": " : "",
                    exc_msg
                );
            } else {
                snprintf(err_buf, err_buf_len, "template runtime error");
            }
        }
    }
    vhttp_tpl_unlock();
    if (failed) {
        if (out_inited) {
            vstr_clear(&out);
        }
        return -1;
    }
    vhttp_tpl_lock();
    g_tpl_stats.renders++;
    vhttp_tpl_unlock();

    *out_obj = mp_obj_new_str(out.buf, out.len);
    vstr_clear(&out);
    return 0;
}

static int vhttp_tpl_render_stream_path(
    uint32_t request_id,
    uint16_t status_code,
    const char *path,
    size_t path_len,
    mp_obj_t context_obj,
    int strict,
    int gzip_enabled,
    vstr_t *headers_vstr,
    char *err_buf,
    size_t err_buf_len
) {
    if (context_obj == mp_const_none) {
        context_obj = mp_obj_new_dict(0);
    }
    if (!mp_obj_is_type(context_obj, &mp_type_dict)) {
        if (err_buf && err_buf_len > 0) {
            snprintf(err_buf, err_buf_len, "context must be dict");
        }
        return -1;
    }

    vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
    if (!ipc) {
        if (err_buf && err_buf_len > 0) {
            snprintf(err_buf, err_buf_len, "IPC unavailable");
        }
        return -1;
    }

    uint32_t chunk_size = VHTTP_STATIC_STREAM_CHUNK_SIZE;
    if (chunk_size == 0) {
        chunk_size = 1;
    }

    vhttp_tpl_cache_entry_t *entry = NULL;
    int failed = 0;
    vhttp_tpl_ipc_sink_ctx_t sink_ctx;
    memset(&sink_ctx, 0, sizeof(sink_ctx));
    sink_ctx.ipc = ipc;
    sink_ctx.request_id = request_id;
    sink_ctx.status_code = status_code;
    sink_ctx.headers_vstr = headers_vstr;
    sink_ctx.chunk_size = chunk_size;
    sink_ctx.buf = m_new(uint8_t, chunk_size);
    sink_ctx.gzip_buf = NULL;
    sink_ctx.gzip_comp = NULL;
    sink_ctx.gzip_enabled = 0;
    sink_ctx.gzip_crc32 = 0;
    sink_ctx.gzip_input_size = 0;

    if (gzip_enabled) {
        sink_ctx.gzip_buf = m_new(uint8_t, chunk_size);
        sink_ctx.gzip_comp = (tdefl_compressor *)calloc(1, sizeof(tdefl_compressor));
        if (!sink_ctx.gzip_buf || !sink_ctx.gzip_comp) {
            if (err_buf && err_buf_len > 0) {
                snprintf(err_buf, err_buf_len, "template gzip alloc failed");
            }
            if (sink_ctx.gzip_comp) {
                free(sink_ctx.gzip_comp);
            }
            if (sink_ctx.gzip_buf) {
                m_del(uint8_t, sink_ctx.gzip_buf, chunk_size);
            }
            m_del(uint8_t, sink_ctx.buf, chunk_size);
            return -1;
        }
        int probes = vhttp_map_level_to_probes(VHTTP_GZIP_LEVEL);
        int flags = probes & TDEFL_MAX_PROBES_MASK;
        if (tdefl_init(sink_ctx.gzip_comp, NULL, NULL, flags) != TDEFL_STATUS_OKAY) {
            if (err_buf && err_buf_len > 0) {
                snprintf(err_buf, err_buf_len, "template gzip init failed");
            }
            free(sink_ctx.gzip_comp);
            m_del(uint8_t, sink_ctx.gzip_buf, chunk_size);
            m_del(uint8_t, sink_ctx.buf, chunk_size);
            return -1;
        }
        sink_ctx.gzip_enabled = 1;
        sink_ctx.gzip_crc32 = (uint32_t)mz_crc32(0, NULL, 0);
        {
            static const uint8_t gzip_header[10] = {0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03};
            if (vhttp_tpl_ipc_sink_emit(&sink_ctx, gzip_header, sizeof(gzip_header)) != 0) {
                if (err_buf && err_buf_len > 0) {
                    snprintf(err_buf, err_buf_len, "template gzip header failed");
                }
                free(sink_ctx.gzip_comp);
                m_del(uint8_t, sink_ctx.gzip_buf, chunk_size);
                m_del(uint8_t, sink_ctx.buf, chunk_size);
                return -1;
            }
        }
    }

    vhttp_tpl_sink_t sink;
    sink.write = vhttp_tpl_sink_ipc_write;
    sink.ctx = &sink_ctx;

    char template_root[VHTTP_STATIC_MAX_PATH];
    size_t template_root_len = 1;
    template_root[0] = '/';
    template_root[1] = '\0';
    if (path_len > 0 && path[0] == '/') {
        if (vhttp_tpl_path_dirname(path, path_len, template_root, sizeof(template_root), &template_root_len) != 0) {
            if (err_buf && err_buf_len > 0) {
                snprintf(err_buf, err_buf_len, "invalid template path");
            }
            if (sink_ctx.gzip_comp) {
                free(sink_ctx.gzip_comp);
            }
            if (sink_ctx.gzip_buf) {
                m_del(uint8_t, sink_ctx.gzip_buf, chunk_size);
            }
            m_del(uint8_t, sink_ctx.buf, chunk_size);
            return -1;
        }
    }

    vhttp_tpl_lock();
    nlr_buf_t nlr;
    if (nlr_push(&nlr) == 0) {
        if (vhttp_tpl_compile_for_path(path, path_len, &entry, err_buf, err_buf_len) != 0 || !entry) {
            failed = 1;
        } else {
            vhttp_tpl_render_ctx_t ctx;
            memset(&ctx, 0, sizeof(ctx));
            ctx.strict = strict;
            ctx.scope_len = 1;
            ctx.scopes[0] = context_obj;

            if (vhttp_tpl_render_nodes(
                    entry->root,
                    &ctx,
                    &sink,
                    1,
                    0,
                    entry->source,
                    entry->source_len,
                    entry->path,
                    entry->path_len,
                    template_root,
                    template_root_len) != 0) {
                failed = 1;
                if (err_buf && err_buf_len > 0 && err_buf[0] == '\0') {
                    snprintf(err_buf, err_buf_len, "template render failed");
                }
            } else if (vhttp_tpl_ipc_sink_flush(&sink_ctx, 1) != 0) {
                failed = 1;
                if (err_buf && err_buf_len > 0 && err_buf[0] == '\0') {
                    snprintf(err_buf, err_buf_len, "template stream flush failed");
                }
            }
        }
        nlr_pop();
    } else {
        g_tpl_stats.errors++;
        failed = 1;
        if (err_buf && err_buf_len > 0) {
            if (g_tpl_debug_mode) {
                char exc_msg[96];
                vhttp_tpl_debug_exception_to_text(MP_OBJ_FROM_PTR(nlr.ret_val), exc_msg, sizeof(exc_msg));
                snprintf(
                    err_buf,
                    err_buf_len,
                    "template runtime error%s%s",
                    exc_msg[0] ? ": " : "",
                    exc_msg
                );
            } else {
                snprintf(err_buf, err_buf_len, "template runtime error");
            }
        }
    }
    vhttp_tpl_unlock();

    if (sink_ctx.buf) {
        m_del(uint8_t, sink_ctx.buf, chunk_size);
    }
    if (sink_ctx.gzip_buf) {
        m_del(uint8_t, sink_ctx.gzip_buf, chunk_size);
    }
    if (sink_ctx.gzip_comp) {
        free(sink_ctx.gzip_comp);
    }

    if (!failed) {
        vhttp_tpl_lock();
        g_tpl_stats.renders++;
        vhttp_tpl_unlock();
        return 0;
    }

    if (sink_ctx.sent_headers || sink_ctx.sent_any) {
        (void)vhttp_ipc_send_stream_chunk(
            ipc,
            request_id,
            status_code,
            NULL,
            0,
            headers_vstr,
            !sink_ctx.sent_headers,
            0,
            1,
            1
        );
        return -1;
    }

    const char *fallback = (err_buf && err_buf[0]) ? err_buf : "template stream error";
    return vhttp_mp_static_send_simple(request_id, 500, fallback);
}

static mp_obj_t viperhttp_render_template(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    enum {
        ARG_path,
        ARG_tpl_ctx,
        ARG_strict,
    };
    static const mp_arg_t allowed_args[] = {
        { MP_QSTR_path, MP_ARG_OBJ | MP_ARG_REQUIRED, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_tpl_ctx, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_strict, MP_ARG_BOOL, { .u_bool = true } },
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_map_t filtered;
    mp_map_t *parse_kws = kw_args;
    if (kw_args && kw_args->used > 0) {
        mp_map_init(&filtered, kw_args->used);
        for (size_t i = 0; i < kw_args->alloc; ++i) {
            if (!mp_map_slot_is_filled(kw_args, i)) {
                continue;
            }
            mp_obj_t key = kw_args->table[i].key;
            mp_obj_t val = kw_args->table[i].value;
            if (mp_obj_is_str(key)) {
                size_t key_len = 0;
                const char *key_str = mp_obj_str_get_data(key, &key_len);
                if (key_str && key_len == 7 && memcmp(key_str, "context", 7) == 0) {
                    key = MP_OBJ_NEW_QSTR(MP_QSTR_tpl_ctx);
                }
            }
            mp_map_lookup(&filtered, key, MP_MAP_LOOKUP_ADD_IF_NOT_FOUND)->value = val;
        }
        parse_kws = &filtered;
    }
    mp_arg_parse_all(n_args, pos_args, parse_kws, MP_ARRAY_SIZE(allowed_args), allowed_args, args);
    if (!mp_obj_is_str(args[ARG_path].u_obj)) {
        mp_raise_TypeError(MP_ERROR_TEXT("path must be str"));
    }
    size_t path_len = 0;
    const char *path = mp_obj_str_get_data(args[ARG_path].u_obj, &path_len);
    if (path_len == 0 || path_len >= VHTTP_STATIC_MAX_PATH) {
        mp_raise_ValueError(MP_ERROR_TEXT("invalid path"));
    }
    char err[96];
    err[0] = '\0';
    mp_obj_t rendered = mp_const_none;
    if (vhttp_tpl_render_path(path, path_len, args[ARG_tpl_ctx].u_obj, args[ARG_strict].u_bool ? 1 : 0, &rendered, err, sizeof(err)) != 0) {
        mp_raise_msg_varg(&mp_type_ValueError, MP_ERROR_TEXT("template: %s"), err[0] ? err : "render error");
    }
    return rendered;
}
static MP_DEFINE_CONST_FUN_OBJ_KW(viperhttp_render_template_obj, 0, viperhttp_render_template);

static mp_obj_t viperhttp_template_response(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    enum {
        ARG_path,
        ARG_tpl_ctx,
        ARG_status_code,
        ARG_headers,
        ARG_content_type,
        ARG_strict,
    };
    static const mp_arg_t allowed_args[] = {
        { MP_QSTR_path, MP_ARG_OBJ | MP_ARG_REQUIRED, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_tpl_ctx, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_status_code, MP_ARG_INT, { .u_int = 200 } },
        { MP_QSTR_headers, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_content_type, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_strict, MP_ARG_BOOL, { .u_bool = true } },
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    int stream_mode = 0;
    mp_map_t filtered;
    mp_map_t *parse_kws = kw_args;
    if (kw_args && kw_args->used > 0) {
        mp_map_init(&filtered, kw_args->used);
        for (size_t i = 0; i < kw_args->alloc; ++i) {
            if (!mp_map_slot_is_filled(kw_args, i)) {
                continue;
            }
            mp_obj_t key = kw_args->table[i].key;
            mp_obj_t val = kw_args->table[i].value;
            if (mp_obj_is_str(key)) {
                size_t key_len = 0;
                const char *key_str = mp_obj_str_get_data(key, &key_len);
                if (key_str && key_len == 7 && memcmp(key_str, "context", 7) == 0) {
                    key = MP_OBJ_NEW_QSTR(MP_QSTR_tpl_ctx);
                } else if (key_str && key_len == 6 && memcmp(key_str, "stream", 6) == 0) {
                    stream_mode = mp_obj_is_true(val);
                    continue;
                }
            }
            mp_map_lookup(&filtered, key, MP_MAP_LOOKUP_ADD_IF_NOT_FOUND)->value = val;
        }
        parse_kws = &filtered;
    }
    mp_arg_parse_all(n_args, pos_args, parse_kws, MP_ARRAY_SIZE(allowed_args), allowed_args, args);
    if (!mp_obj_is_str(args[ARG_path].u_obj)) {
        mp_raise_TypeError(MP_ERROR_TEXT("path must be str"));
    }
    size_t path_len = 0;
    const char *path = mp_obj_str_get_data(args[ARG_path].u_obj, &path_len);
    if (path_len == 0 || path_len >= VHTTP_STATIC_MAX_PATH) {
        mp_raise_ValueError(MP_ERROR_TEXT("invalid path"));
    }

    mp_obj_t ct = args[ARG_content_type].u_obj;
    if (ct == mp_const_none) {
        ct = mp_obj_new_str("text/html; charset=utf-8", 24);
    }

    char err[96];
    err[0] = '\0';
    if (stream_mode) {
        vhttp_tpl_cache_entry_t *entry = NULL;
        vhttp_tpl_lock();
        int compile_rc = vhttp_tpl_compile_for_path(path, path_len, &entry, err, sizeof(err));
        vhttp_tpl_unlock();
        if (compile_rc != 0 || !entry) {
            return vhttp_make_response_dict(
                500,
                mp_obj_new_str(err[0] ? err : "template render error", err[0] ? strlen(err) : 21),
                mp_const_none,
                mp_obj_new_str("text/plain; charset=utf-8", 25)
            );
        }

        mp_obj_t response = vhttp_make_response_dict(
            args[ARG_status_code].u_int,
            mp_const_none,
            args[ARG_headers].u_obj,
            ct
        );
        mp_obj_t stream_desc = mp_obj_new_dict(4);
        mp_obj_dict_store(stream_desc, mp_obj_new_str("__vhttp_template_stream__", 25), mp_const_true);
        mp_obj_dict_store(stream_desc, mp_obj_new_str("template_path", 13), args[ARG_path].u_obj);
        mp_obj_dict_store(stream_desc, mp_obj_new_str("template_context", 16), args[ARG_tpl_ctx].u_obj);
        mp_obj_dict_store(stream_desc, mp_obj_new_str("template_strict", 15), mp_obj_new_bool(args[ARG_strict].u_bool));
        mp_obj_dict_store(response, mp_obj_new_str("stream", 6), stream_desc);
        mp_obj_dict_store(response, mp_obj_new_str("chunked", 7), mp_const_true);
        mp_obj_dict_store(response, mp_obj_new_str("__vhttp_template_stream__", 25), mp_const_true);
        mp_obj_dict_store(response, mp_obj_new_str("template_path", 13), args[ARG_path].u_obj);
        mp_obj_dict_store(response, mp_obj_new_str("template_context", 16), args[ARG_tpl_ctx].u_obj);
        mp_obj_dict_store(response, mp_obj_new_str("template_strict", 15), mp_obj_new_bool(args[ARG_strict].u_bool));
        return response;
    }

    mp_obj_t rendered = mp_const_none;
    if (vhttp_tpl_render_path(path, path_len, args[ARG_tpl_ctx].u_obj, args[ARG_strict].u_bool ? 1 : 0, &rendered, err, sizeof(err)) != 0) {
        return vhttp_make_response_dict(
            500,
            mp_obj_new_str(err[0] ? err : "template render error", err[0] ? strlen(err) : 21),
            mp_const_none,
            mp_obj_new_str("text/plain; charset=utf-8", 25)
        );
    }
    return vhttp_make_response_dict(args[ARG_status_code].u_int, rendered, args[ARG_headers].u_obj, ct);
}
static MP_DEFINE_CONST_FUN_OBJ_KW(viperhttp_template_response_obj, 0, viperhttp_template_response);

static mp_obj_t viperhttp_template_clear_cache(size_t n_args, const mp_obj_t *args) {
    if (n_args > 1) {
        mp_raise_TypeError(MP_ERROR_TEXT("template_clear_cache([path])"));
    }
    if (n_args == 0 || args[0] == mp_const_none) {
        vhttp_tpl_lock();
        vhttp_tpl_cache_clear_all();
        vhttp_tpl_unlock();
        return mp_const_none;
    }
    if (!mp_obj_is_str(args[0])) {
        mp_raise_TypeError(MP_ERROR_TEXT("path must be str"));
    }
    size_t path_len = 0;
    const char *path = mp_obj_str_get_data(args[0], &path_len);
    vhttp_tpl_lock();
    for (size_t i = 0; i < VHTTP_TEMPLATE_CACHE_ENTRIES; ++i) {
        vhttp_tpl_cache_entry_t *entry = &g_tpl_cache[i];
        if (!entry->used) {
            continue;
        }
        if (entry->path_len == path_len && memcmp(entry->path, path, path_len) == 0) {
            vhttp_tpl_cache_entry_clear(entry);
        }
    }
    vhttp_tpl_unlock();
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(viperhttp_template_clear_cache_obj, 0, 1, viperhttp_template_clear_cache);

static mp_obj_t viperhttp_template_stats(void) {
    typedef struct {
        char path[VHTTP_STATIC_MAX_PATH];
        size_t path_len;
        size_t file_size;
        uint32_t mtime;
        uint32_t hits;
        uint32_t cache_bytes;
    } vhttp_tpl_entry_snapshot_t;

    vhttp_tpl_stats_t stats;
    uint32_t cache_bytes = 0;
    uint32_t cache_budget_bytes = 0;
    vhttp_tpl_entry_snapshot_t snap[VHTTP_TEMPLATE_CACHE_ENTRIES];
    size_t snap_len = 0;

    vhttp_tpl_lock();
    stats = g_tpl_stats;
    cache_bytes = g_tpl_cache_bytes;
    cache_budget_bytes = vhttp_tpl_cache_budget_bytes();
    for (size_t i = 0; i < VHTTP_TEMPLATE_CACHE_ENTRIES; ++i) {
        vhttp_tpl_cache_entry_t *entry = &g_tpl_cache[i];
        if (!entry->used) {
            continue;
        }
        if (snap_len >= VHTTP_TEMPLATE_CACHE_ENTRIES) {
            break;
        }
        vhttp_tpl_entry_snapshot_t *dst = &snap[snap_len++];
        dst->path_len = entry->path_len;
        memcpy(dst->path, entry->path, entry->path_len);
        dst->file_size = entry->file_size;
        dst->mtime = entry->mtime;
        dst->hits = entry->hits;
        dst->cache_bytes = entry->cache_bytes;
    }
    vhttp_tpl_unlock();

    mp_obj_t dict = mp_obj_new_dict(12);
    mp_obj_dict_store(dict, mp_obj_new_str("renders", 7), mp_obj_new_int_from_uint(stats.renders));
    mp_obj_dict_store(dict, mp_obj_new_str("compiles", 8), mp_obj_new_int_from_uint(stats.compiles));
    mp_obj_dict_store(dict, mp_obj_new_str("cache_hits", 10), mp_obj_new_int_from_uint(stats.cache_hits));
    mp_obj_dict_store(dict, mp_obj_new_str("cache_misses", 12), mp_obj_new_int_from_uint(stats.cache_misses));
    mp_obj_dict_store(dict, mp_obj_new_str("cache_evicts", 12), mp_obj_new_int_from_uint(stats.cache_evicts));
    mp_obj_dict_store(dict, mp_obj_new_str("errors", 6), mp_obj_new_int_from_uint(stats.errors));
    mp_obj_dict_store(dict, mp_obj_new_str("cache_bytes", 11), mp_obj_new_int_from_uint(cache_bytes));
    mp_obj_dict_store(dict, mp_obj_new_str("cache_budget_bytes", 18), mp_obj_new_int_from_uint(cache_budget_bytes));
    mp_obj_t entries = mp_obj_new_list(0, NULL);
    for (size_t i = 0; i < snap_len; ++i) {
        mp_obj_t item = mp_obj_new_dict(8);
        mp_obj_dict_store(item, mp_obj_new_str("path", 4), mp_obj_new_str(snap[i].path, snap[i].path_len));
        mp_obj_dict_store(item, mp_obj_new_str("size", 4), mp_obj_new_int_from_uint(snap[i].file_size));
        mp_obj_dict_store(item, mp_obj_new_str("mtime", 5), mp_obj_new_int_from_uint(snap[i].mtime));
        mp_obj_dict_store(item, mp_obj_new_str("hits", 4), mp_obj_new_int_from_uint(snap[i].hits));
        mp_obj_dict_store(item, mp_obj_new_str("bytes", 5), mp_obj_new_int_from_uint(snap[i].cache_bytes));
        mp_obj_list_append(entries, item);
    }
    mp_obj_dict_store(dict, mp_obj_new_str("entries", 7), entries);
    mp_obj_dict_store(dict, mp_obj_new_str("capacity", 8), mp_obj_new_int(VHTTP_TEMPLATE_CACHE_ENTRIES));
    return dict;
}
static MP_DEFINE_CONST_FUN_OBJ_0(viperhttp_template_stats_obj, viperhttp_template_stats);

static mp_obj_t viperhttp_router_stats(void) {
    mp_obj_t dict = mp_obj_new_dict(0);
    mp_obj_dict_store(dict, mp_obj_new_str("ready", 5), mp_obj_new_bool(vhttp_router_is_ready(&g_router)));
    mp_obj_dict_store(dict, mp_obj_new_str("route_count", 11), mp_obj_new_int_from_uint(g_router.route_count));
    mp_obj_dict_store(dict, mp_obj_new_str("node_count", 10), mp_obj_new_int_from_uint(g_router.node_count));
    mp_obj_dict_store(dict, mp_obj_new_str("edge_count", 10), mp_obj_new_int_from_uint(g_router.edge_count));
    mp_obj_dict_store(dict, mp_obj_new_str("route_capacity", 14), mp_obj_new_int_from_uint(g_router.route_capacity));
    mp_obj_dict_store(dict, mp_obj_new_str("node_capacity", 13), mp_obj_new_int_from_uint(g_router.node_capacity));
    mp_obj_dict_store(dict, mp_obj_new_str("edge_capacity", 13), mp_obj_new_int_from_uint(g_router.edge_capacity));
    mp_obj_dict_store(dict, mp_obj_new_str("storage_psram", 13), mp_obj_new_bool(g_router.storage_in_psram != 0));
    return dict;
}
static MP_DEFINE_CONST_FUN_OBJ_0(viperhttp_router_stats_obj, viperhttp_router_stats);

static mp_obj_t viperhttp_template_warmup(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    enum {
        ARG_root,
    };
    static const mp_arg_t allowed_args[] = {
        { MP_QSTR_root, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    const char *root = "/www";
    size_t root_len = 4;
    if (args[ARG_root].u_obj != mp_const_none) {
        if (!mp_obj_is_str(args[ARG_root].u_obj)) {
            mp_raise_TypeError(MP_ERROR_TEXT("root must be str"));
        }
        root = mp_obj_str_get_data(args[ARG_root].u_obj, &root_len);
    }
    if (!root || root_len == 0 || root_len >= VHTTP_STATIC_MAX_PATH || root[0] != '/') {
        mp_raise_ValueError(MP_ERROR_TEXT("invalid root"));
    }
    while (root_len > 1 && root[root_len - 1] == '/') {
        root_len--;
    }

    size_t root_size = 0;
    uint32_t root_mtime = 0;
    int root_is_dir = 0;
    if (vhttp_mp_stat_path(root, root_len, &root_size, &root_mtime, &root_is_dir) != 0 || !root_is_dir) {
        mp_raise_ValueError(MP_ERROR_TEXT("root must be existing directory"));
    }

    vhttp_tpl_warmup_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    vhttp_tpl_warmup_walk(root, root_len, 0, &stats);

    mp_obj_t out = mp_obj_new_dict(8);
    mp_obj_dict_store(out, mp_obj_new_str("root", 4), mp_obj_new_str(root, root_len));
    mp_obj_dict_store(out, mp_obj_new_str("dirs_seen", 9), mp_obj_new_int_from_uint(stats.dirs_seen));
    mp_obj_dict_store(out, mp_obj_new_str("files_seen", 10), mp_obj_new_int_from_uint(stats.files_seen));
    mp_obj_dict_store(out, mp_obj_new_str("candidates", 10), mp_obj_new_int_from_uint(stats.candidates));
    mp_obj_dict_store(out, mp_obj_new_str("compiled", 8), mp_obj_new_int_from_uint(stats.compiled));
    mp_obj_dict_store(out, mp_obj_new_str("cached", 6), mp_obj_new_int_from_uint(stats.cached));
    mp_obj_dict_store(out, mp_obj_new_str("errors", 6), mp_obj_new_int_from_uint(stats.errors));
    return out;
}
static MP_DEFINE_CONST_FUN_OBJ_KW(viperhttp_template_warmup_obj, 0, viperhttp_template_warmup);

static mp_obj_t viperhttp_template_debug(size_t n_args, const mp_obj_t *args) {
    if (n_args > 1) {
        mp_raise_TypeError(MP_ERROR_TEXT("template_debug([enabled])"));
    }
    vhttp_tpl_lock();
    if (n_args == 1) {
        g_tpl_debug_mode = mp_obj_is_true(args[0]) ? 1 : 0;
    }
    int enabled = g_tpl_debug_mode;
    vhttp_tpl_unlock();
    return mp_obj_new_bool(enabled);
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(viperhttp_template_debug_obj, 0, 1, viperhttp_template_debug);

static mp_obj_t viperhttp_response(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    static const mp_arg_t allowed_args[] = {
        { MP_QSTR_status_code, MP_ARG_INT, { .u_int = 200 } },
        { MP_QSTR_body, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_headers, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_content_type, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
    };
    mp_arg_val_t args[4];
    mp_arg_parse_all(n_args, pos_args, kw_args, 4, allowed_args, args);
    return vhttp_make_response_dict(
        args[0].u_int,
        args[1].u_obj,
        args[2].u_obj,
        args[3].u_obj
    );
}
static MP_DEFINE_CONST_FUN_OBJ_KW(viperhttp_response_obj, 0, viperhttp_response);

static mp_obj_t viperhttp_json_response(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    static const mp_arg_t allowed_args[] = {
        { MP_QSTR_status_code, MP_ARG_INT, { .u_int = 200 } },
        { MP_QSTR_body, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_headers, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_content_type, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
    };
    mp_arg_val_t args[4];
    mp_arg_parse_all(n_args, pos_args, kw_args, 4, allowed_args, args);
    mp_obj_t content_type = args[3].u_obj;
    if (content_type == mp_const_none) {
        content_type = mp_obj_new_str("application/json", 16);
    }
    return vhttp_make_response_dict(
        args[0].u_int,
        args[1].u_obj,
        args[2].u_obj,
        content_type
    );
}
static MP_DEFINE_CONST_FUN_OBJ_KW(viperhttp_json_response_obj, 0, viperhttp_json_response);

static mp_obj_t viperhttp_streaming_response(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    enum {
        ARG_body,
        ARG_status_code,
        ARG_headers,
        ARG_content_type,
        ARG_chunk_size,
        ARG_total_len,
    };
    static const mp_arg_t allowed_args[] = {
        { MP_QSTR_body, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_status_code, MP_ARG_INT, { .u_int = 200 } },
        { MP_QSTR_headers, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_content_type, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_chunk_size, MP_ARG_INT, { .u_int = VHTTP_STATIC_STREAM_CHUNK_SIZE } },
        { MP_QSTR_total_len, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
    };

    int chunked = 0;
    if (kw_args && kw_args->used > 0) {
        mp_map_t filtered;
        mp_map_init(&filtered, kw_args->used);
        mp_map_t *src = kw_args;
        for (size_t i = 0; i < src->alloc; ++i) {
            if (!mp_map_slot_is_filled(src, i)) {
                continue;
            }
            mp_obj_t key = src->table[i].key;
            mp_obj_t val = src->table[i].value;
            int is_chunked = 0;
            if (mp_obj_is_str(key)) {
                size_t key_len = 0;
                const char *key_str = mp_obj_str_get_data(key, &key_len);
                if (key_str && key_len == 7 && memcmp(key_str, "chunked", 7) == 0) {
                    chunked = mp_obj_is_true(val);
                    is_chunked = 1;
                }
            }
            if (!is_chunked) {
                mp_map_lookup(&filtered, key, MP_MAP_LOOKUP_ADD_IF_NOT_FOUND)->value = val;
            }
        }
        mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
        mp_arg_parse_all(n_args, pos_args, &filtered, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

        if (args[ARG_body].u_obj == mp_const_none) {
            mp_raise_TypeError(MP_ERROR_TEXT("body required"));
        }
        if (args[ARG_chunk_size].u_int <= 0) {
            mp_raise_ValueError(MP_ERROR_TEXT("chunk_size must be > 0"));
        }

        mp_obj_t dict = vhttp_make_response_dict(
            args[ARG_status_code].u_int,
            mp_const_none,
            args[ARG_headers].u_obj,
            args[ARG_content_type].u_obj
        );
        mp_obj_dict_store(dict, mp_obj_new_str("stream", 6), args[ARG_body].u_obj);
        mp_obj_dict_store(dict, mp_obj_new_str("chunk_size", 10), mp_obj_new_int(args[ARG_chunk_size].u_int));
        if (args[ARG_total_len].u_obj != mp_const_none) {
            mp_obj_dict_store(dict, mp_obj_new_str("total_len", 9), args[ARG_total_len].u_obj);
        }
        if (chunked) {
            mp_obj_dict_store(dict, mp_obj_new_str("chunked", 7), mp_const_true);
        }
        return dict;
    }

    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    if (args[ARG_body].u_obj == mp_const_none) {
        mp_raise_TypeError(MP_ERROR_TEXT("body required"));
    }
    if (args[ARG_chunk_size].u_int <= 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("chunk_size must be > 0"));
    }

    mp_obj_t dict = vhttp_make_response_dict(
        args[ARG_status_code].u_int,
        mp_const_none,
        args[ARG_headers].u_obj,
        args[ARG_content_type].u_obj
    );
    mp_obj_dict_store(dict, mp_obj_new_str("stream", 6), args[ARG_body].u_obj);
    mp_obj_dict_store(dict, mp_obj_new_str("chunk_size", 10), mp_obj_new_int(args[ARG_chunk_size].u_int));
    if (args[ARG_total_len].u_obj != mp_const_none) {
        mp_obj_dict_store(dict, mp_obj_new_str("total_len", 9), args[ARG_total_len].u_obj);
    }
    if (chunked) {
        mp_obj_dict_store(dict, mp_obj_new_str("chunked", 7), mp_const_true);
    }
    return dict;
}
static MP_DEFINE_CONST_FUN_OBJ_KW(viperhttp_streaming_response_obj, 0, viperhttp_streaming_response);

static mp_obj_t vhttp_app_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    enum {
        ARG_title,
        ARG_version,
        ARG_description,
        ARG_docs,
        ARG_openapi_url,
        ARG_docs_url,
        ARG_include_websocket_docs,
        ARG_cache_schema,
        ARG_servers,
    };
    static const mp_arg_t allowed_args[] = {
        { MP_QSTR_title, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_version, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_description, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_docs, MP_ARG_BOOL, { .u_bool = true } },
        { MP_QSTR_openapi_url, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_docs_url, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_include_websocket_docs, MP_ARG_BOOL, { .u_bool = true } },
        { MP_QSTR_cache_schema, MP_ARG_BOOL, { .u_bool = true } },
        { MP_QSTR_servers, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
    };
    mp_arg_val_t parsed[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all_kw_array(n_args, n_kw, args, MP_ARRAY_SIZE(allowed_args), allowed_args, parsed);

    vhttp_router_init(&g_router);
    g_router_ready = 1;
    vhttp_static_reset();
    vhttp_cors_reset();
    if (vhttp_active_app_ptr() != NULL) {
        mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("only one ViperHTTP instance supported"));
    }
    vhttp_app_t *app = mp_obj_malloc(vhttp_app_t, type);
    app->handlers = mp_obj_new_list(0, NULL);
    app->handler_meta = mp_obj_new_list(0, NULL);
    app->middlewares = mp_obj_new_list(0, NULL);
    app->title = parsed[ARG_title].u_obj != mp_const_none ? parsed[ARG_title].u_obj : mp_obj_new_str("ViperHTTP API", 12);
    app->version = parsed[ARG_version].u_obj != mp_const_none ? parsed[ARG_version].u_obj : mp_obj_new_str("1.0.0", 5);
    app->description = parsed[ARG_description].u_obj != mp_const_none ? parsed[ARG_description].u_obj : mp_obj_new_str("", 0);
    app->docs_enabled = mp_obj_new_bool(parsed[ARG_docs].u_bool);
    bool has_openapi_url = (n_args > ARG_openapi_url) || vhttp_kw_array_has(n_args, n_kw, args, MP_QSTR_openapi_url);
    bool has_docs_url = (n_args > ARG_docs_url) || vhttp_kw_array_has(n_args, n_kw, args, MP_QSTR_docs_url);
    app->openapi_url = has_openapi_url ? parsed[ARG_openapi_url].u_obj : mp_obj_new_str("/openapi.json", 13);
    app->docs_url = has_docs_url ? parsed[ARG_docs_url].u_obj : mp_obj_new_str("/docs", 5);
    app->include_websocket_docs = mp_obj_new_bool(parsed[ARG_include_websocket_docs].u_bool);
    app->cache_schema = mp_obj_new_bool(parsed[ARG_cache_schema].u_bool);
    app->servers = parsed[ARG_servers].u_obj;

    if (!mp_obj_is_str(app->title)) {
        mp_raise_TypeError(MP_ERROR_TEXT("title must be str"));
    }
    if (!mp_obj_is_str(app->version)) {
        mp_raise_TypeError(MP_ERROR_TEXT("version must be str"));
    }
    if (!mp_obj_is_str(app->description)) {
        mp_raise_TypeError(MP_ERROR_TEXT("description must be str"));
    }
    if (app->openapi_url != mp_const_none && !mp_obj_is_str(app->openapi_url)) {
        mp_raise_TypeError(MP_ERROR_TEXT("openapi_url must be str or None"));
    }
    if (app->docs_url != mp_const_none && !mp_obj_is_str(app->docs_url)) {
        mp_raise_TypeError(MP_ERROR_TEXT("docs_url must be str or None"));
    }

    MP_STATE_VM(viperhttp_active_app) = MP_OBJ_FROM_PTR(app);
    return MP_OBJ_FROM_PTR(app);
}

static const mp_rom_map_elem_t vhttp_app_locals_table[] = {
    { MP_ROM_QSTR(MP_QSTR_get), MP_ROM_PTR(&vhttp_app_get_obj) },
    { MP_ROM_QSTR(MP_QSTR_post), MP_ROM_PTR(&vhttp_app_post_obj) },
    { MP_ROM_QSTR(MP_QSTR_put), MP_ROM_PTR(&vhttp_app_put_obj) },
    { MP_ROM_QSTR(MP_QSTR_patch), MP_ROM_PTR(&vhttp_app_patch_obj) },
    { MP_ROM_QSTR(MP_QSTR_delete), MP_ROM_PTR(&vhttp_app_delete_obj) },
    { MP_ROM_QSTR(MP_QSTR_options), MP_ROM_PTR(&vhttp_app_options_obj) },
    { MP_ROM_QSTR(MP_QSTR_websocket), MP_ROM_PTR(&vhttp_app_websocket_obj) },
    { MP_ROM_QSTR(MP_QSTR_add_middleware), MP_ROM_PTR(&vhttp_app_add_middleware_obj) },
    { MP_ROM_QSTR(MP_QSTR_add_middleware_func), MP_ROM_PTR(&vhttp_app_add_middleware_func_obj) },
    { MP_ROM_QSTR(MP_QSTR_middleware), MP_ROM_PTR(&vhttp_app_middleware_obj) },
    { MP_ROM_QSTR(MP_QSTR__middleware_stack), MP_ROM_PTR(&vhttp_app_middleware_stack_obj) },
    { MP_ROM_QSTR(MP_QSTR_mount), MP_ROM_PTR(&vhttp_app_mount_obj) },
    { MP_ROM_QSTR(MP_QSTR_mount_file), MP_ROM_PTR(&vhttp_app_mount_file_obj) },
    { MP_ROM_QSTR(MP_QSTR_match), MP_ROM_PTR(&vhttp_app_match_obj) },
    { MP_ROM_QSTR(MP_QSTR_routes), MP_ROM_PTR(&vhttp_app_routes_obj) },
    { MP_ROM_QSTR(MP_QSTR_dispatch), MP_ROM_PTR(&vhttp_app_dispatch_obj) },
    { MP_ROM_QSTR(MP_QSTR_ws_dispatch), MP_ROM_PTR(&vhttp_app_ws_dispatch_obj) },
    { MP_ROM_QSTR(MP_QSTR_include_router), MP_ROM_PTR(&vhttp_app_include_router_obj) },
    { MP_ROM_QSTR(MP_QSTR_configure_docs), MP_ROM_PTR(&vhttp_app_configure_docs_obj) },
    { MP_ROM_QSTR(MP_QSTR__docs_config), MP_ROM_PTR(&vhttp_app_docs_config_obj) },
    { MP_ROM_QSTR(MP_QSTR_run), MP_ROM_PTR(&vhttp_app_run_obj) },
};
static MP_DEFINE_CONST_DICT(vhttp_app_locals_dict, vhttp_app_locals_table);

MP_DEFINE_CONST_OBJ_TYPE(
    vhttp_app_type,
    MP_QSTR_ViperHTTP,
    MP_TYPE_FLAG_NONE,
    make_new, vhttp_app_make_new,
    attr, vhttp_app_attr,
    locals_dict, &vhttp_app_locals_dict
);


// VFS static via IPC helpers (MicroPython thread).
static mp_obj_t vhttp_header_get_ci(mp_obj_t headers, const char *name, size_t *out_len) {
    if (!mp_obj_is_type(headers, &mp_type_dict)) {
        if (out_len) {
            *out_len = 0;
        }
        return MP_OBJ_NULL;
    }
    mp_obj_dict_t *dict = MP_OBJ_TO_PTR(headers);
    mp_map_t *map = &dict->map;
    for (size_t i = 0; i < map->alloc; ++i) {
        if (MP_MAP_SLOT_IS_FILLED(map, i)) {
            mp_obj_t key = map->table[i].key;
            if (mp_obj_is_str(key)) {
                size_t key_len = 0;
                const char *key_str = mp_obj_str_get_data(key, &key_len);
                if (vhttp_str_ci_equals(key_str, key_len, name)) {
                    mp_obj_t val = map->table[i].value;
                    if (out_len) {
                        if (mp_obj_is_str(val)) {
                            mp_obj_str_get_data(val, out_len);
                        } else if (mp_obj_is_type(val, &mp_type_bytes) || mp_obj_is_type(val, &mp_type_bytearray)) {
                            mp_buffer_info_t bufinfo;
                            mp_get_buffer_raise(val, &bufinfo, MP_BUFFER_READ);
                            *out_len = bufinfo.len;
                        } else {
                            *out_len = 0;
                        }
                    }
                    return val;
                }
            }
        }
    }
    if (out_len) {
        *out_len = 0;
    }
    return MP_OBJ_NULL;
}

static int vhttp_header_value_contains_ci(mp_obj_t headers, const char *name, const char *token) {
    size_t len = 0;
    mp_obj_t val = vhttp_header_get_ci(headers, name, &len);
    if (val == MP_OBJ_NULL || len == 0) {
        return 0;
    }
    const char *data = NULL;
    if (mp_obj_is_str(val)) {
        data = mp_obj_str_get_data(val, &len);
    } else if (mp_obj_is_type(val, &mp_type_bytes) || mp_obj_is_type(val, &mp_type_bytearray)) {
        mp_buffer_info_t bufinfo;
        mp_get_buffer_raise(val, &bufinfo, MP_BUFFER_READ);
        data = (const char *)bufinfo.buf;
        len = bufinfo.len;
    } else {
        return 0;
    }
    return vhttp_str_ci_contains(data, len, token);
}

static int vhttp_vstr_header_get_ci(const vstr_t *headers_vstr, const char *name, const char **out_value, size_t *out_len) {
    if (out_value) {
        *out_value = NULL;
    }
    if (out_len) {
        *out_len = 0;
    }
    if (!headers_vstr || !headers_vstr->buf || headers_vstr->len == 0 || !name) {
        return 0;
    }
    const char *ptr = headers_vstr->buf;
    size_t remaining = headers_vstr->len;
    while (remaining > 0) {
        const char *line = ptr;
        size_t line_len = 0;
        while (line_len < remaining && line[line_len] != '\n') {
            line_len++;
        }
        size_t consumed = line_len;
        if (consumed < remaining) {
            consumed++;
        }
        size_t useful = line_len;
        if (useful > 0 && line[useful - 1] == '\r') {
            useful--;
        }
        if (useful == 0) {
            ptr += consumed;
            remaining -= consumed;
            continue;
        }
        const char *colon = memchr(line, ':', useful);
        if (colon) {
            size_t key_len = (size_t)(colon - line);
            if (vhttp_str_ci_equals(line, key_len, name)) {
                const char *value = colon + 1;
                size_t value_len = useful - (key_len + 1);
                while (value_len > 0 && (*value == ' ' || *value == '\t')) {
                    value++;
                    value_len--;
                }
                while (value_len > 0 && (value[value_len - 1] == ' ' || value[value_len - 1] == '\t')) {
                    value_len--;
                }
                if (out_value) {
                    *out_value = value;
                }
                if (out_len) {
                    *out_len = value_len;
                }
                return 1;
            }
        }
        ptr += consumed;
        remaining -= consumed;
    }
    return 0;
}

static int vhttp_vstr_header_has_token_ci(const vstr_t *headers_vstr, const char *name, const char *token) {
    const char *value = NULL;
    size_t value_len = 0;
    if (!token) {
        return 0;
    }
    if (!vhttp_vstr_header_get_ci(headers_vstr, name, &value, &value_len) || !value || value_len == 0) {
        return 0;
    }
    return vhttp_str_ci_contains(value, value_len, token);
}

static void vhttp_vstr_add_header_cstr(vstr_t *v, const char *key, const char *value) {
    if (!v || !key || !value) {
        return;
    }
    vstr_add_str(v, key);
    vstr_add_str(v, ": ");
    vstr_add_str(v, value);
    vstr_add_str(v, "\r\n");
}

static void vhttp_etag_normalize(const char *in, size_t len, const char **out, size_t *out_len) {
    const char *ptr = in;
    size_t l = len;
    if (l >= 2 && ptr[0] == 'W' && ptr[1] == '/') {
        ptr += 2;
        l -= 2;
    }
    if (l >= 2 && ptr[0] == '"' && ptr[l - 1] == '"') {
        ptr += 1;
        l -= 2;
    }
    *out = ptr;
    *out_len = l;
}

static int vhttp_etag_matches_value(const char *value, size_t value_len, const char *etag, size_t etag_len) {
    if (!value || !etag || etag_len == 0) {
        return 0;
    }

    const char *etag_base = NULL;
    size_t etag_base_len = 0;
    vhttp_etag_normalize(etag, etag_len, &etag_base, &etag_base_len);
    if (!etag_base || etag_base_len == 0) {
        return 0;
    }

    size_t i = 0;
    for (; i < value_len; ++i) {
        if (value[i] != ' ' && value[i] != '\t') {
            break;
        }
    }
    if (i < value_len && value[i] == '*') {
        return 1;
    }

    while (i < value_len) {
        while (i < value_len && (value[i] == ' ' || value[i] == '\t' || value[i] == ',')) {
            i++;
        }
        size_t start = i;
        while (i < value_len && value[i] != ',') {
            i++;
        }
        size_t end = i;
        while (end > start && (value[end - 1] == ' ' || value[end - 1] == '\t')) {
            end--;
        }
        if (end == start) {
            continue;
        }
        size_t token_len = end - start;
        const char *token_base = NULL;
        size_t token_base_len = 0;
        vhttp_etag_normalize(value + start, token_len, &token_base, &token_base_len);
        if (token_base_len == etag_base_len &&
            memcmp(token_base, etag_base, etag_base_len) == 0) {
            return 1;
        }
    }

    return 0;
}

static int vhttp_parse_u64_dec(const char *ptr, size_t len, uint64_t *out) {
    if (!ptr || len == 0 || !out) {
        return -1;
    }
    uint64_t val = 0;
    for (size_t i = 0; i < len; ++i) {
        char c = ptr[i];
        if (c < '0' || c > '9') {
            return -1;
        }
        uint64_t digit = (uint64_t)(c - '0');
        if (val > (UINT64_MAX - digit) / 10u) {
            return -1;
        }
        val = val * 10u + digit;
    }
    *out = val;
    return 0;
}

static int vhttp_parse_u32_dec(const char *ptr, size_t len, uint32_t *out) {
    uint64_t tmp = 0;
    if (!out || vhttp_parse_u64_dec(ptr, len, &tmp) != 0 || tmp > UINT32_MAX) {
        return -1;
    }
    *out = (uint32_t)tmp;
    return 0;
}

static int vhttp_parse_http_month(const char *ptr, uint32_t *out_month) {
    static const char *months[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    };
    if (!ptr || !out_month) {
        return -1;
    }
    for (uint32_t i = 0; i < 12; ++i) {
        if (memcmp(ptr, months[i], 3) == 0) {
            *out_month = i + 1;
            return 0;
        }
    }
    return -1;
}

static int64_t vhttp_days_from_civil(int64_t y, uint32_t m, uint32_t d) {
    y -= (m <= 2) ? 1 : 0;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    uint32_t yoe = (uint32_t)(y - era * 400);
    int32_t m_adj = (int32_t)m + (m > 2 ? -3 : 9);
    uint32_t doy = (uint32_t)((153 * m_adj + 2) / 5 + (int32_t)d - 1);
    uint32_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

static int vhttp_parse_http_date_imf(const char *value, size_t value_len, uint64_t *epoch_out) {
    // IMF-fixdate: "Sun, 06 Nov 1994 08:49:37 GMT"
    if (!value || !epoch_out) {
        return -1;
    }
    vhttp_trim_ows(&value, &value_len);
    if (value_len != 29) {
        return -1;
    }
    if (value[3] != ',' || value[4] != ' ' || value[7] != ' ' || value[11] != ' ' ||
        value[16] != ' ' || value[19] != ':' || value[22] != ':' || value[25] != ' ') {
        return -1;
    }
    if (!(value[26] == 'G' && value[27] == 'M' && value[28] == 'T')) {
        return -1;
    }

    uint32_t day = 0;
    uint32_t month = 0;
    uint32_t year = 0;
    uint32_t hour = 0;
    uint32_t minute = 0;
    uint32_t second = 0;

    if (vhttp_parse_u32_dec(value + 5, 2, &day) != 0 ||
        vhttp_parse_http_month(value + 8, &month) != 0 ||
        vhttp_parse_u32_dec(value + 12, 4, &year) != 0 ||
        vhttp_parse_u32_dec(value + 17, 2, &hour) != 0 ||
        vhttp_parse_u32_dec(value + 20, 2, &minute) != 0 ||
        vhttp_parse_u32_dec(value + 23, 2, &second) != 0) {
        return -1;
    }

    if (day == 0 || day > 31 || year < 1970 || hour > 23 || minute > 59 || second > 60) {
        return -1;
    }

    int64_t days = vhttp_days_from_civil((int64_t)year, month, day);
    if (days < 0) {
        return -1;
    }

    uint64_t epoch = (uint64_t)days * 86400u +
                     (uint64_t)hour * 3600u +
                     (uint64_t)minute * 60u +
                     (uint64_t)(second > 59 ? 59 : second);
    *epoch_out = epoch;
    return 0;
}

static int vhttp_format_http_date(uint32_t timestamp, char *buf, size_t buf_len) {
    static const char *wday[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    static const char *mon[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    if (!buf || buf_len == 0) {
        return -1;
    }
    time_t t = (time_t)timestamp;
    struct tm tmv;
#if defined(_WIN32)
    if (gmtime_s(&tmv, &t) != 0) {
        return -1;
    }
#else
    if (gmtime_r(&t, &tmv) == NULL) {
        return -1;
    }
#endif
    if (tmv.tm_wday < 0 || tmv.tm_wday > 6 || tmv.tm_mon < 0 || tmv.tm_mon > 11) {
        return -1;
    }
    int n = snprintf(
        buf,
        buf_len,
        "%s, %02d %s %04d %02d:%02d:%02d GMT",
        wday[tmv.tm_wday],
        tmv.tm_mday,
        mon[tmv.tm_mon],
        tmv.tm_year + 1900,
        tmv.tm_hour,
        tmv.tm_min,
        tmv.tm_sec
    );
    if (n <= 0 || (size_t)n >= buf_len) {
        return -1;
    }
    return n;
}

static int vhttp_if_range_allows(
    const char *if_range,
    size_t if_range_len,
    const char *etag,
    size_t etag_len,
    uint32_t resource_mtime
) {
    if (!if_range || if_range_len == 0) {
        return 1;
    }
    vhttp_trim_ows(&if_range, &if_range_len);
    if (if_range_len == 0) {
        return 0;
    }

    if (if_range[0] == '"' || (if_range_len >= 2 && if_range[0] == 'W' && if_range[1] == '/')) {
        return vhttp_etag_matches_value(if_range, if_range_len, etag, etag_len);
    }

    uint64_t if_range_ts = 0;
    if (vhttp_parse_http_date_imf(if_range, if_range_len, &if_range_ts) == 0) {
        return (uint64_t)resource_mtime <= if_range_ts;
    }
    return 0;
}

static int vhttp_ci_prefix(const char *data, size_t data_len, const char *prefix) {
    size_t prefix_len = strlen(prefix);
    if (!data || data_len < prefix_len) {
        return 0;
    }
    for (size_t i = 0; i < prefix_len; ++i) {
        char a = data[i];
        char b = prefix[i];
        if (a >= 'A' && a <= 'Z') {
            a = (char)(a + ('a' - 'A'));
        }
        if (b >= 'A' && b <= 'Z') {
            b = (char)(b + ('a' - 'A'));
        }
        if (a != b) {
            return 0;
        }
    }
    return 1;
}

static void vhttp_trim_ows(const char **ptr, size_t *len) {
    if (!ptr || !len || !*ptr) {
        return;
    }
    const char *p = *ptr;
    size_t l = *len;
    while (l > 0 && (*p == ' ' || *p == '\t')) {
        p++;
        l--;
    }
    while (l > 0 && (p[l - 1] == ' ' || p[l - 1] == '\t')) {
        l--;
    }
    *ptr = p;
    *len = l;
}

static int vhttp_parse_range_bytes(
    const char *value,
    size_t value_len,
    size_t full_len,
    size_t *start_out,
    size_t *len_out
) {
    if (!value || !start_out || !len_out || full_len == 0) {
        return -1;
    }

    vhttp_trim_ows(&value, &value_len);
    if (!vhttp_ci_prefix(value, value_len, "bytes=")) {
        return -1;
    }
    value += 6;
    value_len -= 6;
    vhttp_trim_ows(&value, &value_len);
    if (value_len == 0) {
        return -1;
    }
    if (memchr(value, ',', value_len) != NULL) {
        // We intentionally reject multipart ranges and return 416 policy-wise.
        return -2;
    }

    const char *dash = memchr(value, '-', value_len);
    if (!dash) {
        return -1;
    }

    const char *left = value;
    size_t left_len = (size_t)(dash - value);
    const char *right = dash + 1;
    size_t right_len = value_len - left_len - 1;
    vhttp_trim_ows(&left, &left_len);
    vhttp_trim_ows(&right, &right_len);

    if (left_len == 0 && right_len == 0) {
        return -1;
    }

    if (left_len == 0) {
        uint64_t suffix = 0;
        if (vhttp_parse_u64_dec(right, right_len, &suffix) != 0 || suffix == 0) {
            return -1;
        }
        if (suffix >= full_len) {
            *start_out = 0;
            *len_out = full_len;
        } else {
            *start_out = full_len - (size_t)suffix;
            *len_out = (size_t)suffix;
        }
        return 0;
    }

    uint64_t first = 0;
    if (vhttp_parse_u64_dec(left, left_len, &first) != 0 || first >= full_len) {
        return -1;
    }

    uint64_t last = (uint64_t)full_len - 1u;
    if (right_len > 0) {
        if (vhttp_parse_u64_dec(right, right_len, &last) != 0) {
            return -1;
        }
        if (last < first) {
            return -1;
        }
        if (last >= full_len) {
            last = (uint64_t)full_len - 1u;
        }
    }

    *start_out = (size_t)first;
    *len_out = (size_t)(last - first + 1u);
    return 0;
}

static int vhttp_extract_header_text(mp_obj_t header_obj, size_t header_len, const char **out_data, size_t *out_len) {
    if (!out_data || !out_len || header_obj == MP_OBJ_NULL || header_obj == mp_const_none || header_len == 0) {
        return -1;
    }
    if (mp_obj_is_str(header_obj)) {
        *out_data = mp_obj_str_get_data(header_obj, out_len);
        return 0;
    }
    if (mp_obj_is_type(header_obj, &mp_type_bytes) || mp_obj_is_type(header_obj, &mp_type_bytearray)) {
        mp_buffer_info_t bufinfo;
        mp_get_buffer_raise(header_obj, &bufinfo, MP_BUFFER_READ);
        *out_data = (const char *)bufinfo.buf;
        *out_len = bufinfo.len;
        return 0;
    }
    return -1;
}

static int vhttp_mp_stat_path(const char *path, size_t path_len, size_t *size_out, uint32_t *mtime_out, int *is_dir_out) {
    nlr_buf_t nlr;
    mp_obj_t stat_obj;
    if (nlr_push(&nlr) == 0) {
        stat_obj = mp_vfs_stat(mp_obj_new_str(path, path_len));
        nlr_pop();
    } else {
        return -1;
    }

    size_t stat_len = 0;
    mp_obj_t *items = NULL;
    mp_obj_get_array(stat_obj, &stat_len, &items);
    if (stat_len < 9) {
        return -1;
    }

    mp_int_t mode = mp_obj_get_int(items[0]);
    mp_int_t size = mp_obj_get_int(items[6]);
    mp_int_t mtime = mp_obj_get_int(items[8]);
    if (size < 0) {
        return -1;
    }

    if (size_out) {
        *size_out = (size_t)size;
    }
    if (mtime_out) {
        *mtime_out = (uint32_t)mtime;
    }
    if (is_dir_out) {
        *is_dir_out = (mode & MP_S_IFDIR) != 0;
    }
    return 0;
}

static int vhttp_mp_open_file(const char *path, size_t path_len, const char *mode, mp_obj_t *out_obj) {
    mp_obj_t args[2] = {
        mp_obj_new_str(path, path_len),
        mp_obj_new_str(mode, strlen(mode)),
    };
    mp_map_t kw_args;
    mp_map_init(&kw_args, 0);
    nlr_buf_t nlr;
    if (nlr_push(&nlr) == 0) {
        *out_obj = mp_vfs_open(2, args, &kw_args);
        nlr_pop();
        return 0;
    }
    return -1;
}

static int vhttp_mp_seek_file(mp_obj_t file_obj, size_t offset) {
    mp_obj_t seek_method[4];
    mp_load_method_maybe(file_obj, MP_QSTR_seek, seek_method);
    if (seek_method[0] == MP_OBJ_NULL) {
        return -1;
    }
    seek_method[2] = mp_obj_new_int_from_uint((mp_uint_t)offset);
    seek_method[3] = MP_OBJ_NEW_SMALL_INT(0);
    nlr_buf_t nlr;
    if (nlr_push(&nlr) == 0) {
        (void)mp_call_method_n_kw(2, 0, seek_method);
        nlr_pop();
        return 0;
    }
    return -1;
}

static mp_obj_t vhttp_headers_clone_mutable(mp_obj_t headers) {
    if (headers == mp_const_none) {
        return mp_obj_new_dict(0);
    }
    if (mp_obj_is_type(headers, &mp_type_dict)) {
        mp_obj_t out = mp_obj_new_dict(0);
        mp_obj_dict_t *dict = MP_OBJ_TO_PTR(headers);
        mp_map_t *map = &dict->map;
        for (size_t i = 0; i < map->alloc; ++i) {
            if (MP_MAP_SLOT_IS_FILLED(map, i)) {
                mp_obj_dict_store(out, map->table[i].key, map->table[i].value);
            }
        }
        return out;
    }
    if (mp_obj_is_type(headers, &mp_type_list) || mp_obj_is_type(headers, &mp_type_tuple)) {
        size_t len = 0;
        mp_obj_t *items = NULL;
        mp_obj_get_array(headers, &len, &items);
        return mp_obj_new_list(len, items);
    }
    return headers;
}

static void vhttp_headers_add_kv(mp_obj_t headers, const char *key, size_t key_len, const char *value, size_t value_len) {
    if (headers == mp_const_none || !key || !value) {
        return;
    }
    mp_obj_t key_obj = mp_obj_new_str(key, key_len);
    mp_obj_t val_obj = mp_obj_new_str(value, value_len);
    if (mp_obj_is_type(headers, &mp_type_dict)) {
        mp_obj_dict_store(headers, key_obj, val_obj);
        return;
    }
    if (mp_obj_is_type(headers, &mp_type_list)) {
        mp_obj_t pair[2] = { key_obj, val_obj };
        mp_obj_list_append(headers, mp_obj_new_tuple(2, pair));
    }
}

static int vhttp_format_content_range(
    char *buf,
    size_t buf_len,
    size_t start,
    size_t range_len,
    size_t full_len
) {
    if (!buf || buf_len == 0 || range_len == 0) {
        return -1;
    }
    unsigned long first = (unsigned long)start;
    unsigned long last = (unsigned long)(start + range_len - 1u);
    unsigned long full = (unsigned long)full_len;
    int n = snprintf(buf, buf_len, "bytes %lu-%lu/%lu", first, last, full);
    if (n <= 0 || (size_t)n >= buf_len) {
        return -1;
    }
    return n;
}

static int vhttp_format_content_range_unsat(char *buf, size_t buf_len, size_t full_len) {
    if (!buf || buf_len == 0) {
        return -1;
    }
    unsigned long full = (unsigned long)full_len;
    int n = snprintf(buf, buf_len, "bytes */%lu", full);
    if (n <= 0 || (size_t)n >= buf_len) {
        return -1;
    }
    return n;
}

static int vhttp_path_ext_eq_ci(const char *path, size_t path_len, const char *ext) {
    size_t ext_len = strlen(ext);
    if (ext_len == 0 || path_len < ext_len) {
        return 0;
    }
    const char *tail = path + (path_len - ext_len);
    for (size_t i = 0; i < ext_len; ++i) {
        char a = tail[i];
        char b = ext[i];
        if (a >= 'A' && a <= 'Z') {
            a = (char)(a + ('a' - 'A'));
        }
        if (b >= 'A' && b <= 'Z') {
            b = (char)(b + ('a' - 'A'));
        }
        if (a != b) {
            return 0;
        }
    }
    return 1;
}

static const char *vhttp_guess_content_type_for_file(const char *path, size_t path_len) {
    if (vhttp_path_ext_eq_ci(path, path_len, ".html") || vhttp_path_ext_eq_ci(path, path_len, ".htm")) {
        return "text/html; charset=utf-8";
    }
    if (vhttp_path_ext_eq_ci(path, path_len, ".css")) {
        return "text/css; charset=utf-8";
    }
    if (vhttp_path_ext_eq_ci(path, path_len, ".js")) {
        return "application/javascript";
    }
    if (vhttp_path_ext_eq_ci(path, path_len, ".json")) {
        return "application/json";
    }
    if (vhttp_path_ext_eq_ci(path, path_len, ".txt")) {
        return "text/plain; charset=utf-8";
    }
    if (vhttp_path_ext_eq_ci(path, path_len, ".svg")) {
        return "image/svg+xml";
    }
    if (vhttp_path_ext_eq_ci(path, path_len, ".xml")) {
        return "application/xml";
    }
    if (vhttp_path_ext_eq_ci(path, path_len, ".png")) {
        return "image/png";
    }
    if (vhttp_path_ext_eq_ci(path, path_len, ".jpg") || vhttp_path_ext_eq_ci(path, path_len, ".jpeg")) {
        return "image/jpeg";
    }
    if (vhttp_path_ext_eq_ci(path, path_len, ".gif")) {
        return "image/gif";
    }
    if (vhttp_path_ext_eq_ci(path, path_len, ".wasm")) {
        return "application/wasm";
    }
    return "application/octet-stream";
}

static mp_obj_t viperhttp_file_response(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    enum {
        ARG_path,
        ARG_status_code,
        ARG_headers,
        ARG_content_type,
        ARG_chunk_size,
    };
    static const mp_arg_t allowed_args[] = {
        { MP_QSTR_path, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_status_code, MP_ARG_INT, { .u_int = 200 } },
        { MP_QSTR_headers, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_content_type, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_chunk_size, MP_ARG_INT, { .u_int = VHTTP_STATIC_STREAM_CHUNK_SIZE } },
    };

    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    if (args[ARG_path].u_obj == mp_const_none || !mp_obj_is_str(args[ARG_path].u_obj)) {
        mp_raise_TypeError(MP_ERROR_TEXT("path must be a string"));
    }
    if (args[ARG_chunk_size].u_int <= 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("chunk_size must be > 0"));
    }

    size_t path_len = 0;
    const char *path = mp_obj_str_get_data(args[ARG_path].u_obj, &path_len);

    size_t file_size = 0;
    uint32_t file_mtime = 0;
    int is_dir = 0;
    if (vhttp_mp_stat_path(path, path_len, &file_size, &file_mtime, &is_dir) != 0 || is_dir) {
        return vhttp_make_response_dict(
            404,
            mp_obj_new_str("Not Found", 9),
            mp_const_none,
            mp_obj_new_str("text/plain; charset=utf-8", 25)
        );
    }

    mp_obj_t file_obj;
    if (vhttp_mp_open_file(path, path_len, "rb", &file_obj) != 0) {
        return vhttp_make_response_dict(
            404,
            mp_obj_new_str("Not Found", 9),
            mp_const_none,
            mp_obj_new_str("text/plain; charset=utf-8", 25)
        );
    }

    mp_obj_t content_type = args[ARG_content_type].u_obj;
    if (content_type == mp_const_none) {
        const char *guess = vhttp_guess_content_type_for_file(path, path_len);
        content_type = mp_obj_new_str(guess, strlen(guess));
    }

    mp_obj_t response_headers = vhttp_headers_clone_mutable(args[ARG_headers].u_obj);
    vhttp_headers_add_kv(response_headers, "Accept-Ranges", 13, "bytes", 5);

    char etag_buf[64];
    int etag_len_i = snprintf(
        etag_buf,
        sizeof(etag_buf),
        "W/\"%lx-%lx\"",
        (unsigned long)file_size,
        (unsigned long)file_mtime
    );
    if (etag_len_i > 0 && (size_t)etag_len_i < sizeof(etag_buf)) {
        vhttp_headers_add_kv(response_headers, "ETag", 4, etag_buf, (size_t)etag_len_i);
    } else {
        etag_len_i = 0;
    }

    char last_modified_buf[40];
    int last_modified_len = vhttp_format_http_date(file_mtime, last_modified_buf, sizeof(last_modified_buf));
    if (last_modified_len > 0) {
        vhttp_headers_add_kv(response_headers, "Last-Modified", 13, last_modified_buf, (size_t)last_modified_len);
    }

    mp_int_t status_code = args[ARG_status_code].u_int;
    size_t response_len = file_size;

    mp_obj_t req_obj = MP_STATE_VM(viperhttp_current_request);
    vhttp_request_t *req = vhttp_request_ptr(req_obj);
    if (req != NULL) {
        size_t range_header_len = 0;
        mp_obj_t range_obj = vhttp_header_get_ci(req->headers, "range", &range_header_len);
        const char *range_data = NULL;
        size_t range_data_len = 0;
        if (range_obj != MP_OBJ_NULL &&
            range_header_len > 0 &&
            vhttp_extract_header_text(range_obj, range_header_len, &range_data, &range_data_len) == 0 &&
            range_data != NULL &&
            range_data_len > 0) {
            int allow_range = 1;
            size_t if_range_len = 0;
            mp_obj_t if_range_obj = vhttp_header_get_ci(req->headers, "if-range", &if_range_len);
            if (if_range_obj != MP_OBJ_NULL && if_range_len > 0) {
                const char *if_range_data = NULL;
                size_t if_range_data_len = 0;
                if (vhttp_extract_header_text(if_range_obj, if_range_len, &if_range_data, &if_range_data_len) == 0 &&
                    if_range_data != NULL &&
                    if_range_data_len > 0) {
                    allow_range = vhttp_if_range_allows(
                        if_range_data,
                        if_range_data_len,
                        etag_len_i > 0 ? etag_buf : NULL,
                        (size_t)etag_len_i,
                        file_mtime
                    );
                } else {
                    allow_range = 0;
                }
            }

            size_t range_start = 0;
            size_t range_len = 0;
            int parse_rc = allow_range
                ? vhttp_parse_range_bytes(range_data, range_data_len, file_size, &range_start, &range_len)
                : 0;
            if (allow_range && parse_rc != 0) {
                mp_stream_close(file_obj);
                char unsat_buf[64];
                int unsat_len = vhttp_format_content_range_unsat(unsat_buf, sizeof(unsat_buf), file_size);
                if (unsat_len > 0) {
                    vhttp_headers_add_kv(response_headers, "Content-Range", 13, unsat_buf, (size_t)unsat_len);
                }
                return vhttp_make_response_dict(
                    416,
                    mp_obj_new_str("Requested Range Not Satisfiable", 31),
                    response_headers,
                    mp_obj_new_str("text/plain; charset=utf-8", 25)
                );
            }
            if (allow_range) {
                if (range_start > 0 && vhttp_mp_seek_file(file_obj, range_start) != 0) {
                    mp_stream_close(file_obj);
                    return vhttp_make_response_dict(
                        500,
                        mp_obj_new_str("Internal Server Error", 21),
                        response_headers,
                        mp_obj_new_str("text/plain; charset=utf-8", 25)
                    );
                }
                char cr_buf[64];
                int cr_len = vhttp_format_content_range(cr_buf, sizeof(cr_buf), range_start, range_len, file_size);
                if (cr_len > 0) {
                    vhttp_headers_add_kv(response_headers, "Content-Range", 13, cr_buf, (size_t)cr_len);
                }
                status_code = 206;
                response_len = range_len;
            }
        }
    }

    // Small file/range payloads are cheaper and safer as a single body response.
    if (response_len <= 4096) {
        mp_obj_t body_obj = mp_const_none;
        if (response_len > 0) {
            uint8_t *tmp = m_new_maybe(uint8_t, response_len);
            if (tmp == NULL) {
                mp_stream_close(file_obj);
                return vhttp_make_response_dict(
                    500,
                    mp_obj_new_str("Internal Server Error", 21),
                    response_headers,
                    mp_obj_new_str("text/plain; charset=utf-8", 25)
                );
            }
            if (vhttp_mp_read_full(file_obj, tmp, response_len) != 0) {
                m_del(uint8_t, tmp, response_len);
                mp_stream_close(file_obj);
                return vhttp_make_response_dict(
                    500,
                    mp_obj_new_str("Read error", 10),
                    response_headers,
                    mp_obj_new_str("text/plain; charset=utf-8", 25)
                );
            }
            body_obj = mp_obj_new_bytes(tmp, response_len);
            m_del(uint8_t, tmp, response_len);
        }
        mp_stream_close(file_obj);
        return vhttp_make_response_dict(
            status_code,
            body_obj,
            response_headers,
            content_type
        );
    }

    mp_obj_t dict = vhttp_make_response_dict(
        status_code,
        mp_const_none,
        response_headers,
        content_type
    );
    mp_obj_dict_store(dict, mp_obj_new_str("stream", 6), file_obj);
    mp_obj_dict_store(dict, mp_obj_new_str("chunk_size", 10), mp_obj_new_int(args[ARG_chunk_size].u_int));
    mp_obj_dict_store(dict, mp_obj_new_str("total_len", 9), mp_obj_new_int_from_uint((mp_uint_t)response_len));
    return dict;
}
static MP_DEFINE_CONST_FUN_OBJ_KW(viperhttp_file_response_obj, 0, viperhttp_file_response);

static int vhttp_mp_read_full(mp_obj_t file_obj, uint8_t *dst, size_t len) {
    size_t total = 0;
    while (total < len) {
        int err = 0;
        mp_uint_t out = mp_stream_rw(
            file_obj,
            dst + total,
            (mp_uint_t)(len - total),
            &err,
            MP_STREAM_RW_READ | MP_STREAM_RW_ONCE
        );
        if (err != 0) {
            return -1;
        }
        if (out == 0) {
            break;
        }
        total += out;
    }
    return total == len ? 0 : -1;
}

static int vhttp_ipc_ring_alloc_wait(
    vhttp_ipc_ring_t *ring,
    uint32_t len,
    uint32_t *offset,
    uint8_t **ptr
) {
    uint32_t slice_ms = (uint32_t)VHTTP_IPC_RING_WAIT_SLICE_MS;
    if (slice_ms == 0) {
        slice_ms = 1;
    }
    uint32_t waited = 0;
    while (waited <= VHTTP_IPC_RING_WAIT_MS) {
        if (vhttp_ipc_ring_alloc(ring, len, offset, ptr) == 0) {
            return 0;
        }
        mp_hal_delay_ms(slice_ms);
        waited += slice_ms;
    }
    return -1;
}

static int vhttp_ipc_queue_push_wait_ms(
    vhttp_ipc_queue_t *queue,
    const vhttp_ipc_msg_t *msg,
    uint32_t timeout_ms
) {
    return vhttp_ipc_queue_push_wait(queue, msg, timeout_ms);
}

static void vhttp_ipc_stream_backpressure_yield(vhttp_ipc_state_t *ipc, size_t chunk_len) {
    (void)chunk_len;
#if VHTTP_STREAM_BACKPRESSURE_DELAY_MS > 0
    if (ipc == NULL || chunk_len == 0) {
        return;
    }

    uint32_t q_cap = vhttp_ipc_queue_capacity(&ipc->response_queue);
    uint32_t q_used = vhttp_ipc_queue_count(&ipc->response_queue);
    uint32_t ring_cap = vhttp_ipc_ring_capacity();
    uint32_t ring_used = vhttp_ipc_ring_used(&ipc->ring);

    uint32_t q_pct = 0;
    uint32_t ring_pct = 0;
    if (q_cap > 0) {
        q_pct = (q_used * 100U) / q_cap;
    }
    if (ring_cap > 0) {
        ring_pct = (ring_used * 100U) / ring_cap;
    }

    uint8_t q_over = q_pct >= (uint32_t)VHTTP_STREAM_BACKPRESSURE_QUEUE_PCT;
    uint8_t ring_over = ring_pct >= (uint32_t)VHTTP_STREAM_BACKPRESSURE_RING_PCT;
    if (q_over || ring_over) {
        uint32_t delay_ms = (uint32_t)VHTTP_STREAM_BACKPRESSURE_DELAY_MS;
        g_mp_stream_backpressure_yield_hits++;
        if (q_over) {
            g_mp_stream_backpressure_queue_hits++;
        }
        if (ring_over) {
            g_mp_stream_backpressure_ring_hits++;
        }
        if (UINT32_MAX - g_mp_stream_backpressure_delay_ms_total < delay_ms) {
            g_mp_stream_backpressure_delay_ms_total = UINT32_MAX;
        } else {
            g_mp_stream_backpressure_delay_ms_total += delay_ms;
        }
        mp_hal_delay_ms(delay_ms);
    }
#endif
}

static int vhttp_ipc_send_stream_chunk(
    vhttp_ipc_state_t *ipc,
    uint32_t request_id,
    uint16_t status_code,
    const uint8_t *data,
    size_t len,
    vstr_t *headers_vstr,
    int send_headers,
    uint32_t total_len,
    int chunked,
    int final
) {
    uint32_t body_offset = 0;
    uint8_t *body_dst = NULL;
    if (len > 0) {
        if (vhttp_ipc_ring_alloc_wait(&ipc->ring, (uint32_t)len, &body_offset, &body_dst) != 0) {
            return -1;
        }
        memcpy(body_dst, data, len);
    }

    uint16_t headers_len = 0;
    uint32_t headers_offset = 0;
    uint8_t *headers_dst = NULL;
    if (send_headers && headers_vstr && headers_vstr->len > 0) {
        headers_len = (uint16_t)headers_vstr->len;
        if (vhttp_ipc_ring_alloc_wait(&ipc->ring, (uint32_t)headers_len, &headers_offset, &headers_dst) != 0) {
            if (len > 0) {
                vhttp_ipc_ring_release(&ipc->ring, (uint32_t)len);
            }
            return -1;
        }
        memcpy(headers_dst, headers_vstr->buf, headers_len);
    }

    vhttp_ipc_msg_t msg = {0};
    msg.request_id = request_id;
    msg.type = VHTTP_IPC_RESP_HTTP;
    msg.status_code = status_code;
    msg.headers_len = headers_len;
    msg.headers_offset = headers_offset;
    msg.body_len = (uint32_t)len;
    msg.total_len = send_headers ? total_len : 0;
    msg.buffer_offset = body_offset;
    msg.flags = VHTTP_IPC_FLAG_STREAM | (chunked ? VHTTP_IPC_FLAG_CHUNKED : 0) | (final ? VHTTP_IPC_FLAG_FINAL : 0);

    if (vhttp_ipc_queue_push_wait_ms(&ipc->response_queue, &msg, VHTTP_IPC_QUEUE_WAIT_MS) != 0) {
        if (len > 0) {
            vhttp_ipc_ring_release(&ipc->ring, (uint32_t)len);
        }
        if (headers_len > 0) {
            vhttp_ipc_ring_release(&ipc->ring, (uint32_t)headers_len);
        }
        return -1;
    }
    vhttp_ipc_stream_backpressure_yield(ipc, len);

    return 0;
}

static int vhttp_send_stream_obj(
    uint32_t request_id,
    uint16_t status_code,
    mp_obj_t stream_obj,
    vstr_t *headers_vstr,
    uint32_t chunk_size,
    uint32_t total_len,
    int chunked
) {
    vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
    if (!ipc) {
        return -1;
    }

    if (chunk_size == 0) {
        chunk_size = 1;
    }

    int sent_headers = 0;
    int sent_any = 0;

    if (mp_obj_is_str(stream_obj) ||
        mp_obj_is_type(stream_obj, &mp_type_bytes) ||
        mp_obj_is_type(stream_obj, &mp_type_bytearray)) {
        mp_buffer_info_t bufinfo;
        if (mp_obj_is_str(stream_obj)) {
            const char *ptr = mp_obj_str_get_data(stream_obj, &bufinfo.len);
            bufinfo.buf = (void *)ptr;
        } else {
            mp_get_buffer_raise(stream_obj, &bufinfo, MP_BUFFER_READ);
        }
        size_t offset = 0;
        while (offset < bufinfo.len) {
            size_t chunk = bufinfo.len - offset;
            if (chunk > chunk_size) {
                chunk = chunk_size;
            }
            int final = (offset + chunk) >= bufinfo.len;
            if (vhttp_ipc_send_stream_chunk(
                ipc,
                request_id,
                status_code,
                (const uint8_t *)bufinfo.buf + offset,
                chunk,
                headers_vstr,
                !sent_headers,
                total_len,
                chunked,
                final
            ) != 0) {
                return -1;
            }
            sent_headers = 1;
            sent_any = 1;
            offset += chunk;
        }
        if (!sent_any) {
            if (vhttp_ipc_send_stream_chunk(
                ipc,
                request_id,
                status_code,
                NULL,
                0,
                headers_vstr,
                1,
                total_len,
                chunked,
                1
            ) != 0) {
                return -1;
            }
        }
        return 0;
    }

    mp_obj_t read_method[3];
    mp_load_method_maybe(stream_obj, MP_QSTR_read, read_method);
    if (read_method[0] != MP_OBJ_NULL) {
        for (;;) {
            read_method[2] = mp_obj_new_int(chunk_size);
            mp_obj_t out = mp_call_method_n_kw(1, 0, read_method);
            if (out == mp_const_none) {
                break;
            }
            if (!(mp_obj_is_str(out) ||
                  mp_obj_is_type(out, &mp_type_bytes) ||
                  mp_obj_is_type(out, &mp_type_bytearray))) {
                return -1;
            }
            mp_buffer_info_t bufinfo;
            if (mp_obj_is_str(out)) {
                const char *ptr = mp_obj_str_get_data(out, &bufinfo.len);
                bufinfo.buf = (void *)ptr;
            } else {
                mp_get_buffer_raise(out, &bufinfo, MP_BUFFER_READ);
            }
            if (bufinfo.len == 0) {
                break;
            }
            size_t offset = 0;
            while (offset < bufinfo.len) {
                size_t chunk = bufinfo.len - offset;
                if (chunk > chunk_size) {
                    chunk = chunk_size;
                }
                if (vhttp_ipc_send_stream_chunk(
                    ipc,
                    request_id,
                    status_code,
                    (const uint8_t *)bufinfo.buf + offset,
                    chunk,
                    headers_vstr,
                    !sent_headers,
                    total_len,
                    chunked,
                    0
                ) != 0) {
                    return -1;
                }
                sent_headers = 1;
                sent_any = 1;
                offset += chunk;
            }
        }

        if (vhttp_ipc_send_stream_chunk(
            ipc,
            request_id,
            status_code,
            NULL,
            0,
            headers_vstr,
            !sent_headers,
            total_len,
            chunked,
            1
        ) != 0) {
            return -1;
        }

        mp_obj_t close_method[2];
        mp_load_method_maybe(stream_obj, MP_QSTR_close, close_method);
        if (close_method[0] != MP_OBJ_NULL) {
            (void)mp_call_method_n_kw(0, 0, close_method);
        }

        return 0;
    }

    mp_obj_t iter = mp_getiter(stream_obj, NULL);
    for (;;) {
        mp_obj_t item = mp_iternext(iter);
        if (item == MP_OBJ_STOP_ITERATION) {
            break;
        }
        if (!(mp_obj_is_str(item) ||
              mp_obj_is_type(item, &mp_type_bytes) ||
              mp_obj_is_type(item, &mp_type_bytearray))) {
            return -1;
        }
        mp_buffer_info_t bufinfo;
        if (mp_obj_is_str(item)) {
            const char *ptr = mp_obj_str_get_data(item, &bufinfo.len);
            bufinfo.buf = (void *)ptr;
        } else {
            mp_get_buffer_raise(item, &bufinfo, MP_BUFFER_READ);
        }
        size_t offset = 0;
        while (offset < bufinfo.len) {
            size_t chunk = bufinfo.len - offset;
            if (chunk > chunk_size) {
                chunk = chunk_size;
            }
            if (vhttp_ipc_send_stream_chunk(
                ipc,
                request_id,
                status_code,
                (const uint8_t *)bufinfo.buf + offset,
                chunk,
                headers_vstr,
                !sent_headers,
                total_len,
                chunked,
                0
            ) != 0) {
                return -1;
            }
            sent_headers = 1;
            sent_any = 1;
            offset += chunk;
        }
    }

    if (vhttp_ipc_send_stream_chunk(
        ipc,
        request_id,
        status_code,
        NULL,
        0,
        headers_vstr,
        !sent_headers,
        total_len,
        chunked,
        1
    ) != 0) {
        return -1;
    }

    return 0;
}

static int vhttp_ipc_send_raw(
    uint32_t request_id,
    uint16_t status_code,
    const uint8_t *body,
    size_t body_len,
    const char *headers,
    size_t headers_len
) {
    vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
    if (!ipc) {
        return -1;
    }

    uint32_t body_offset = 0;
    uint8_t *body_dst = NULL;
    if (body_len > 0) {
        if (vhttp_ipc_ring_alloc_wait(&ipc->ring, (uint32_t)body_len, &body_offset, &body_dst) != 0) {
            return -1;
        }
        memcpy(body_dst, body, body_len);
    }

    uint32_t headers_offset = 0;
    uint8_t *headers_dst = NULL;
    if (headers_len > 0) {
        if (vhttp_ipc_ring_alloc_wait(&ipc->ring, (uint32_t)headers_len, &headers_offset, &headers_dst) != 0) {
            if (body_len > 0) {
                vhttp_ipc_ring_release(&ipc->ring, (uint32_t)body_len);
            }
            return -1;
        }
        memcpy(headers_dst, headers, headers_len);
    }

    vhttp_ipc_msg_t msg = {0};
    msg.request_id = request_id;
    msg.type = VHTTP_IPC_RESP_HTTP;
    msg.status_code = status_code;
    msg.headers_len = (uint16_t)headers_len;
    msg.headers_offset = (uint32_t)headers_offset;
    msg.body_len = (uint32_t)body_len;
    msg.total_len = (uint32_t)body_len;
    msg.buffer_offset = body_offset;
    msg.flags = 0;

    if (vhttp_ipc_queue_push(&ipc->response_queue, &msg) != 0) {
        if (body_len > 0) {
            vhttp_ipc_ring_release(&ipc->ring, (uint32_t)body_len);
        }
        if (headers_len > 0) {
            vhttp_ipc_ring_release(&ipc->ring, (uint32_t)headers_len);
        }
        return -1;
    }

    return 0;
}

static int vhttp_mp_static_send_simple(uint32_t request_id, uint16_t status_code, const char *body) {
    const char *ctype = "text/plain; charset=utf-8";
    vstr_t headers_vstr;
    vstr_init(&headers_vstr, 64);
    vhttp_vstr_add_header(&headers_vstr, mp_obj_new_str("Content-Type", 12), mp_obj_new_str(ctype, strlen(ctype)));
    int rc = vhttp_ipc_send_raw(
        request_id,
        status_code,
        (const uint8_t *)body,
        body ? strlen(body) : 0,
        headers_vstr.buf,
        headers_vstr.len
    );
    vstr_clear(&headers_vstr);
    return rc;
}

static int vhttp_mp_static_send_stream(
    uint32_t request_id,
    mp_obj_t file_obj,
    size_t response_len,
    vstr_t *headers_vstr,
    uint32_t chunk_size,
    int head_only,
    uint16_t status_code
) {
    vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
    if (!ipc) {
        return -1;
    }

    if (chunk_size == 0) {
        chunk_size = 1;
    }

    int sent_any = 0;
    size_t remaining = response_len;

    if (head_only || response_len == 0) {
        uint16_t headers_len = headers_vstr ? (uint16_t)headers_vstr->len : 0;
        uint32_t headers_offset = 0;
        uint8_t *headers_dst = NULL;
        if (headers_len > 0) {
            if (vhttp_ipc_ring_alloc_wait(&ipc->ring, (uint32_t)headers_len, &headers_offset, &headers_dst) != 0) {
                return -1;
            }
            memcpy(headers_dst, headers_vstr->buf, headers_len);
        }

        vhttp_ipc_msg_t msg = {0};
        msg.request_id = request_id;
        msg.type = VHTTP_IPC_RESP_HTTP;
        msg.status_code = status_code;
        msg.headers_len = headers_len;
        msg.headers_offset = headers_offset;
        msg.body_len = 0;
        msg.total_len = (uint32_t)response_len;
        msg.buffer_offset = 0;
        msg.flags = VHTTP_IPC_FLAG_STREAM | VHTTP_IPC_FLAG_FINAL;

        if (vhttp_ipc_queue_push_wait_ms(&ipc->response_queue, &msg, VHTTP_IPC_QUEUE_WAIT_MS) != 0) {
            if (headers_len > 0) {
                vhttp_ipc_ring_release(&ipc->ring, (uint32_t)headers_len);
            }
            return -1;
        }

        return 0;
    }

    while (remaining > 0) {
        uint32_t chunk = remaining > chunk_size ? chunk_size : (uint32_t)remaining;
        uint32_t body_offset = 0;
        uint8_t *body_dst = NULL;
        if (vhttp_ipc_ring_alloc_wait(&ipc->ring, chunk, &body_offset, &body_dst) != 0) {
            return sent_any ? -2 : -1;
        }

        if (vhttp_mp_read_full(file_obj, body_dst, chunk) != 0) {
            vhttp_ipc_ring_release(&ipc->ring, chunk);
            return sent_any ? -2 : -1;
        }

        uint16_t headers_len = 0;
        uint32_t headers_offset = 0;
        uint8_t *headers_dst = NULL;
        if (!sent_any && headers_vstr && headers_vstr->len > 0) {
            headers_len = (uint16_t)headers_vstr->len;
            if (vhttp_ipc_ring_alloc_wait(&ipc->ring, (uint32_t)headers_len, &headers_offset, &headers_dst) != 0) {
                vhttp_ipc_ring_release(&ipc->ring, chunk);
                return sent_any ? -2 : -1;
            }
            memcpy(headers_dst, headers_vstr->buf, headers_len);
        }

        vhttp_ipc_msg_t msg = {0};
        msg.request_id = request_id;
        msg.type = VHTTP_IPC_RESP_HTTP;
        msg.status_code = status_code;
        msg.headers_len = headers_len;
        msg.headers_offset = headers_offset;
        msg.body_len = chunk;
        msg.total_len = sent_any ? 0 : (uint32_t)response_len;
        msg.buffer_offset = body_offset;
        msg.flags = VHTTP_IPC_FLAG_STREAM | ((remaining == chunk) ? VHTTP_IPC_FLAG_FINAL : 0);

        if (vhttp_ipc_queue_push_wait_ms(&ipc->response_queue, &msg, VHTTP_IPC_QUEUE_WAIT_MS) != 0) {
            vhttp_ipc_ring_release(&ipc->ring, chunk);
            if (headers_len > 0) {
                vhttp_ipc_ring_release(&ipc->ring, (uint32_t)headers_len);
            }
            return sent_any ? -2 : -1;
        }

        sent_any = 1;
        remaining -= chunk;
        vhttp_ipc_stream_backpressure_yield(ipc, chunk);
    }

    return 0;
}

static void vhttp_static_rel_path_mp(
    const char *full_path,
    size_t full_len,
    const char **out_rel,
    size_t *out_rel_len
) {
    const char *base = VHTTP_STATIC_FS_BASE;
    size_t base_len = strlen(base);
    while (base_len > 1 && base[base_len - 1] == '/') {
        base_len--;
    }

    const char *rel = full_path;
    size_t rel_len = full_len;

    if (base_len > 0 && full_len >= base_len && memcmp(full_path, base, base_len) == 0) {
        rel = full_path + base_len;
        rel_len = full_len - base_len;
    }

    if (rel_len > 0 && rel[0] == '/') {
        rel++;
        rel_len--;
    }

    *out_rel = rel;
    *out_rel_len = rel_len;
}

static int vhttp_mp_static_handle(
    uint32_t request_id,
    uint8_t method,
    const char *path,
    size_t path_len,
    mp_obj_t headers
) {
    vhttp_static_match_t match;
    if (!vhttp_static_resolve(path, path_len, &match)) {
        return 0;
    }

    if (method != VHTTP_METHOD_GET && method != VHTTP_METHOD_HEAD) {
        vhttp_mp_static_send_simple(request_id, 405, "Method Not Allowed");
        return 1;
    }

    vhttp_fs_lock();

    int gzip_enabled = 0;
    const char *serve_path = match.path;
    size_t serve_len = match.path_len;
    size_t file_size = 0;
    size_t response_start = 0;
    size_t response_len = 0;
    uint16_t response_status = 200;
    int has_range = 0;
    uint32_t file_mtime = 0;
    int is_dir = 0;

    char gz_path[VHTTP_STATIC_MAX_PATH];
    if (VHTTP_GZIP_ENABLED && vhttp_header_value_contains_ci(headers, "accept-encoding", "gzip")) {
        if (match.path_len + 3 < sizeof(gz_path)) {
            memcpy(gz_path, match.path, match.path_len);
            memcpy(gz_path + match.path_len, ".gz", 3);
            gz_path[match.path_len + 3] = '\0';
            if (vhttp_mp_stat_path(gz_path, match.path_len + 3, &file_size, &file_mtime, &is_dir) == 0 && !is_dir) {
                gzip_enabled = 1;
                serve_path = gz_path;
                serve_len = match.path_len + 3;
            }
        }
    }

    if (!gzip_enabled) {
        if (vhttp_mp_stat_path(match.path, match.path_len, &file_size, &file_mtime, &is_dir) != 0 || is_dir) {
            vhttp_fs_unlock();
            vhttp_mp_static_send_simple(request_id, 404, "Not Found");
            return 1;
        }
    }
    response_len = file_size;

    const char *etag_ptr = NULL;
    size_t etag_len = 0;
    char etag_buf[64];

    const size_t etag_hash_min_size = (size_t)VHTTP_STATIC_ETAG_HASH_MIN_SIZE;
    if (!gzip_enabled &&
        etag_hash_min_size > 0 &&
        file_size >= etag_hash_min_size) {
        const char *rel = NULL;
        size_t rel_len = 0;
        vhttp_static_rel_path_mp(match.path, match.path_len, &rel, &rel_len);
        if (rel && rel_len > 0) {
            const vhttp_static_etag_entry_t *entry = vhttp_static_etag_lookup(rel, rel_len);
            if (entry && entry->etag && entry->etag_len > 0) {
                etag_ptr = entry->etag;
                etag_len = entry->etag_len;
            }
        }
    }

    if (!etag_ptr) {
        int etag_len_i = snprintf(
            etag_buf,
            sizeof(etag_buf),
            "W/\"%lx-%lx\"",
            (unsigned long)file_size,
            (unsigned long)file_mtime
        );
        if (etag_len_i < 0) {
            vhttp_fs_unlock();
            vhttp_mp_static_send_simple(request_id, 500, "Internal Server Error");
            return 1;
        }
        if ((size_t)etag_len_i >= sizeof(etag_buf)) {
            etag_len_i = (int)(sizeof(etag_buf) - 1);
            etag_buf[etag_len_i] = '\0';
        }
        etag_ptr = etag_buf;
        etag_len = (size_t)etag_len_i;
    }

    char last_modified_buf[40];
    int last_modified_len = vhttp_format_http_date(file_mtime, last_modified_buf, sizeof(last_modified_buf));

    size_t inm_len = 0;
    mp_obj_t inm_obj = vhttp_header_get_ci(headers, "if-none-match", &inm_len);
    if (inm_obj != MP_OBJ_NULL && inm_len > 0) {
        const char *inm_str = NULL;
        if (mp_obj_is_str(inm_obj)) {
            inm_str = mp_obj_str_get_data(inm_obj, &inm_len);
        } else if (mp_obj_is_type(inm_obj, &mp_type_bytes) || mp_obj_is_type(inm_obj, &mp_type_bytearray)) {
            mp_buffer_info_t bufinfo;
            mp_get_buffer_raise(inm_obj, &bufinfo, MP_BUFFER_READ);
            inm_str = (const char *)bufinfo.buf;
            inm_len = bufinfo.len;
        }
        if (inm_str && vhttp_etag_matches_value(inm_str, inm_len, etag_ptr, etag_len)) {
            vstr_t headers_vstr;
            vstr_init(&headers_vstr, 64);
            vhttp_vstr_add_header(&headers_vstr, mp_obj_new_str("ETag", 4), mp_obj_new_str(etag_ptr, etag_len));
            if (last_modified_len > 0) {
                vhttp_vstr_add_header(&headers_vstr, mp_obj_new_str("Last-Modified", 13), mp_obj_new_str(last_modified_buf, (size_t)last_modified_len));
            }
            vhttp_vstr_add_header(&headers_vstr, mp_obj_new_str("Accept-Ranges", 13), mp_obj_new_str("bytes", 5));
            if (VHTTP_STATIC_CACHE_MAX_AGE > 0) {
                char cache_buf[64];
                int cache_len = snprintf(
                    cache_buf,
                    sizeof(cache_buf),
                    "public, max-age=%d",
                    VHTTP_STATIC_CACHE_MAX_AGE
                );
                if (cache_len > 0 && (size_t)cache_len < sizeof(cache_buf)) {
                    vhttp_vstr_add_header(&headers_vstr, mp_obj_new_str("Cache-Control", 13), mp_obj_new_str(cache_buf, (size_t)cache_len));
                }
            }
            if (gzip_enabled) {
                vhttp_vstr_add_header(&headers_vstr, mp_obj_new_str("Content-Encoding", 16), mp_obj_new_str("gzip", 4));
                vhttp_vstr_add_header(&headers_vstr, mp_obj_new_str("Vary", 4), mp_obj_new_str("Accept-Encoding", 15));
            }
            if (vhttp_ipc_send_raw(request_id, 304, NULL, 0, headers_vstr.buf, headers_vstr.len) != 0) {
                vstr_clear(&headers_vstr);
                vhttp_fs_unlock();
                vhttp_mp_static_send_simple(request_id, 500, "Internal Server Error");
                return 1;
            }
            vstr_clear(&headers_vstr);
            vhttp_fs_unlock();
            return 1;
        }
    }

    size_t range_header_len = 0;
    mp_obj_t range_obj = vhttp_header_get_ci(headers, "range", &range_header_len);
    if (range_obj != MP_OBJ_NULL && range_header_len > 0) {
        const char *range_data = NULL;
        size_t range_data_len = 0;
        if (vhttp_extract_header_text(range_obj, range_header_len, &range_data, &range_data_len) == 0 &&
            range_data != NULL &&
            range_data_len > 0) {
            int allow_range = 1;
            size_t if_range_len = 0;
            mp_obj_t if_range_obj = vhttp_header_get_ci(headers, "if-range", &if_range_len);
            if (if_range_obj != MP_OBJ_NULL && if_range_len > 0) {
                const char *if_range_data = NULL;
                size_t if_range_data_len = 0;
                if (vhttp_extract_header_text(if_range_obj, if_range_len, &if_range_data, &if_range_data_len) == 0 &&
                    if_range_data != NULL &&
                    if_range_data_len > 0) {
                    allow_range = vhttp_if_range_allows(
                        if_range_data,
                        if_range_data_len,
                        etag_ptr,
                        etag_len,
                        file_mtime
                    );
                } else {
                    allow_range = 0;
                }
            }

            size_t parsed_start = 0;
            size_t parsed_len = 0;
            int parse_rc = allow_range
                ? vhttp_parse_range_bytes(range_data, range_data_len, file_size, &parsed_start, &parsed_len)
                : 0;
            if (allow_range && parse_rc != 0) {
                char unsat_buf[64];
                int unsat_len = vhttp_format_content_range_unsat(unsat_buf, sizeof(unsat_buf), file_size);
                vstr_t range_headers;
                vstr_init(&range_headers, 96);
                vhttp_vstr_add_header(&range_headers, mp_obj_new_str("Accept-Ranges", 13), mp_obj_new_str("bytes", 5));
                vhttp_vstr_add_header(&range_headers, mp_obj_new_str("ETag", 4), mp_obj_new_str(etag_ptr, etag_len));
                if (last_modified_len > 0) {
                    vhttp_vstr_add_header(&range_headers, mp_obj_new_str("Last-Modified", 13), mp_obj_new_str(last_modified_buf, (size_t)last_modified_len));
                }
                if (unsat_len > 0) {
                    vhttp_vstr_add_header(
                        &range_headers,
                        mp_obj_new_str("Content-Range", 13),
                        mp_obj_new_str(unsat_buf, (size_t)unsat_len)
                    );
                }
                if (vhttp_ipc_send_raw(request_id, 416, NULL, 0, range_headers.buf, range_headers.len) != 0) {
                    vstr_clear(&range_headers);
                    vhttp_fs_unlock();
                    vhttp_mp_static_send_simple(request_id, 500, "Internal Server Error");
                    return 1;
                }
                vstr_clear(&range_headers);
                vhttp_fs_unlock();
                return 1;
            }
            if (allow_range) {
                has_range = 1;
                response_status = 206;
                response_start = parsed_start;
                response_len = parsed_len;
            }
        }
    }

    uint32_t ring_capacity = vhttp_ipc_ring_capacity();
    uint32_t stream_threshold = VHTTP_STATIC_STREAM_THRESHOLD;
    if (stream_threshold == 0 || stream_threshold > ring_capacity) {
        stream_threshold = ring_capacity;
    }
    uint32_t chunk_size = VHTTP_STATIC_STREAM_CHUNK_SIZE;
    if (chunk_size == 0 || chunk_size > ring_capacity) {
        chunk_size = ring_capacity;
    }

    vstr_t headers_vstr;
    vstr_init(&headers_vstr, 128);
    const char *ctype = match.content_type ? match.content_type : "application/octet-stream";
    vhttp_vstr_add_header(&headers_vstr, mp_obj_new_str("Content-Type", 12), mp_obj_new_str(ctype, strlen(ctype)));
    vhttp_vstr_add_header(&headers_vstr, mp_obj_new_str("ETag", 4), mp_obj_new_str(etag_ptr, etag_len));
    if (last_modified_len > 0) {
        vhttp_vstr_add_header(&headers_vstr, mp_obj_new_str("Last-Modified", 13), mp_obj_new_str(last_modified_buf, (size_t)last_modified_len));
    }
    vhttp_vstr_add_header(&headers_vstr, mp_obj_new_str("Accept-Ranges", 13), mp_obj_new_str("bytes", 5));
    if (has_range) {
        char cr_buf[64];
        int cr_len = vhttp_format_content_range(cr_buf, sizeof(cr_buf), response_start, response_len, file_size);
        if (cr_len > 0) {
            vhttp_vstr_add_header(&headers_vstr, mp_obj_new_str("Content-Range", 13), mp_obj_new_str(cr_buf, (size_t)cr_len));
        }
    }
    if (VHTTP_STATIC_CACHE_MAX_AGE > 0) {
        char cache_buf[64];
        int cache_len = snprintf(
            cache_buf,
            sizeof(cache_buf),
            "public, max-age=%d",
            VHTTP_STATIC_CACHE_MAX_AGE
        );
        if (cache_len > 0 && (size_t)cache_len < sizeof(cache_buf)) {
            vhttp_vstr_add_header(&headers_vstr, mp_obj_new_str("Cache-Control", 13), mp_obj_new_str(cache_buf, (size_t)cache_len));
        }
    }
    if (gzip_enabled) {
        vhttp_vstr_add_header(&headers_vstr, mp_obj_new_str("Content-Encoding", 16), mp_obj_new_str("gzip", 4));
        vhttp_vstr_add_header(&headers_vstr, mp_obj_new_str("Vary", 4), mp_obj_new_str("Accept-Encoding", 15));
    }

    int head_only = (method == VHTTP_METHOD_HEAD);
    if (head_only || response_len > stream_threshold) {
        mp_obj_t file_obj = MP_OBJ_NULL;
        if (!head_only) {
            if (vhttp_mp_open_file(serve_path, serve_len, "rb", &file_obj) != 0) {
                vstr_clear(&headers_vstr);
                vhttp_fs_unlock();
                vhttp_mp_static_send_simple(request_id, 404, "Not Found");
                return 1;
            }
            if (response_start > 0 && vhttp_mp_seek_file(file_obj, response_start) != 0) {
                mp_stream_close(file_obj);
                vstr_clear(&headers_vstr);
                vhttp_fs_unlock();
                vhttp_mp_static_send_simple(request_id, 500, "Read error");
                return 1;
            }
        }

        int stream_rc = vhttp_mp_static_send_stream(
            request_id,
            file_obj,
            response_len,
            &headers_vstr,
            chunk_size,
            head_only,
            response_status
        );

        if (!head_only) {
            mp_stream_close(file_obj);
        }
        vstr_clear(&headers_vstr);
        vhttp_fs_unlock();

        if (stream_rc == -1) {
            vhttp_mp_static_send_simple(request_id, 500, "Internal Server Error");
        }
        return 1;
    }

    mp_obj_t file_obj;
    if (vhttp_mp_open_file(serve_path, serve_len, "rb", &file_obj) != 0) {
        vstr_clear(&headers_vstr);
        vhttp_fs_unlock();
        vhttp_mp_static_send_simple(request_id, 404, "Not Found");
        return 1;
    }
    if (response_start > 0 && vhttp_mp_seek_file(file_obj, response_start) != 0) {
        mp_stream_close(file_obj);
        vstr_clear(&headers_vstr);
        vhttp_fs_unlock();
        vhttp_mp_static_send_simple(request_id, 500, "Read error");
        return 1;
    }

    vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
    if (!ipc) {
        mp_stream_close(file_obj);
        vstr_clear(&headers_vstr);
        vhttp_fs_unlock();
        vhttp_mp_static_send_simple(request_id, 500, "IPC Unavailable");
        return 1;
    }

    uint32_t body_offset = 0;
    uint8_t *body_dst = NULL;
    if (response_len > 0) {
        if (vhttp_ipc_ring_alloc_wait(&ipc->ring, (uint32_t)response_len, &body_offset, &body_dst) != 0) {
            mp_stream_close(file_obj);
            vstr_clear(&headers_vstr);
            vhttp_fs_unlock();
            vhttp_mp_static_send_simple(request_id, 503, "IPC ring full");
            return 1;
        }
        if (vhttp_mp_read_full(file_obj, body_dst, response_len) != 0) {
            vhttp_ipc_ring_release(&ipc->ring, (uint32_t)response_len);
            mp_stream_close(file_obj);
            vstr_clear(&headers_vstr);
            vhttp_fs_unlock();
            vhttp_mp_static_send_simple(request_id, 500, "Read error");
            return 1;
        }
    }

    mp_stream_close(file_obj);
    vhttp_fs_unlock();

    uint16_t headers_len = (uint16_t)headers_vstr.len;
    uint32_t headers_offset = 0;
    uint8_t *headers_dst = NULL;
    if (headers_len > 0) {
        if (vhttp_ipc_ring_alloc_wait(&ipc->ring, (uint32_t)headers_len, &headers_offset, &headers_dst) != 0) {
            if (response_len > 0) {
                vhttp_ipc_ring_release(&ipc->ring, (uint32_t)response_len);
            }
            vstr_clear(&headers_vstr);
            vhttp_mp_static_send_simple(request_id, 503, "IPC ring full");
            return 1;
        }
        memcpy(headers_dst, headers_vstr.buf, headers_len);
    }

    vstr_clear(&headers_vstr);

    vhttp_ipc_msg_t msg = {0};
    msg.request_id = request_id;
    msg.type = VHTTP_IPC_RESP_HTTP;
    msg.status_code = response_status;
    msg.headers_len = headers_len;
    msg.headers_offset = headers_offset;
    msg.body_len = (uint32_t)response_len;
    msg.total_len = (uint32_t)response_len;
    msg.buffer_offset = body_offset;
    msg.flags = 0;

    if (vhttp_ipc_queue_push(&ipc->response_queue, &msg) != 0) {
        if (response_len > 0) {
            vhttp_ipc_ring_release(&ipc->ring, (uint32_t)response_len);
        }
        if (headers_len > 0) {
            vhttp_ipc_ring_release(&ipc->ring, (uint32_t)headers_len);
        }
        vhttp_mp_static_send_simple(request_id, 503, "response queue full");
    }
    return 1;
}


// VFS static gzip helpers.
static int vhttp_path_has_suffix_ci(const char *path, size_t path_len, const char *suffix) {
    size_t suffix_len = strlen(suffix);
    if (path_len < suffix_len) {
        return 0;
    }
    const char *tail = path + (path_len - suffix_len);
    for (size_t i = 0; i < suffix_len; ++i) {
        char a = tail[i];
        char b = suffix[i];
        if (a >= 'A' && a <= 'Z') {
            a = (char)(a + ('a' - 'A'));
        }
        if (b >= 'A' && b <= 'Z') {
            b = (char)(b + ('a' - 'A'));
        }
        if (a != b) {
            return 0;
        }
    }
    return 1;
}

static int vhttp_is_compressible_ext(const char *path, size_t path_len) {
    static const char *k_exts[] = {
        ".html", ".htm", ".css", ".js", ".json", ".txt", ".svg", ".xml"
    };
    for (size_t i = 0; i < (sizeof(k_exts) / sizeof(k_exts[0])); ++i) {
        if (vhttp_path_has_suffix_ci(path, path_len, k_exts[i])) {
            return 1;
        }
    }
    return 0;
}

static int vhttp_map_level_to_probes(int level) {
    if (level <= 0) {
        return TDEFL_HUFFMAN_ONLY;
    }
    if (level <= 3) {
        return 32;
    }
    if (level <= 6) {
        return 128;
    }
    if (level <= 8) {
        return 512;
    }
    return 1024;
}

static int vhttp_mp_write_full(mp_obj_t file_obj, const uint8_t *src, size_t len) {
    size_t total = 0;
    while (total < len) {
        int err = 0;
        mp_uint_t out = mp_stream_rw(
            file_obj,
            (void *)(src + total),
            (mp_uint_t)(len - total),
            &err,
            MP_STREAM_RW_WRITE | MP_STREAM_RW_ONCE
        );
        if (err != 0 || out == 0) {
            return -1;
        }
        total += out;
    }
    return 0;
}

static int vhttp_mp_gzip_file(const char *src, size_t src_len, const char *dst, size_t dst_len, int level) {
    mp_obj_t in_obj;
    mp_obj_t out_obj;
    if (vhttp_mp_open_file(src, src_len, "rb", &in_obj) != 0) {
        return -1;
    }
    if (vhttp_mp_open_file(dst, dst_len, "wb", &out_obj) != 0) {
        mp_stream_close(in_obj);
        return -1;
    }

    tdefl_compressor *comp = (tdefl_compressor *)calloc(1, sizeof(tdefl_compressor));
    if (!comp) {
        mp_stream_close(in_obj);
        mp_stream_close(out_obj);
        return -1;
    }

    int probes = vhttp_map_level_to_probes(level);
    int flags = probes & TDEFL_MAX_PROBES_MASK;

    if (tdefl_init(comp, NULL, NULL, flags) != TDEFL_STATUS_OKAY) {
        free(comp);
        mp_stream_close(in_obj);
        mp_stream_close(out_obj);
        return -1;
    }

    uint8_t gzip_header[10] = {0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03};
    if (vhttp_mp_write_full(out_obj, gzip_header, sizeof(gzip_header)) != 0) {
        free(comp);
        mp_stream_close(in_obj);
        mp_stream_close(out_obj);
        return -1;
    }

    uint8_t in_buf[2048];
    uint8_t out_buf[2048];
    mz_ulong crc = mz_crc32(0, NULL, 0);
    uint32_t isize = 0;

    for (;;) {
        int err = 0;
        mp_uint_t read_bytes = mp_stream_rw(
            in_obj,
            in_buf,
            (mp_uint_t)sizeof(in_buf),
            &err,
            MP_STREAM_RW_READ | MP_STREAM_RW_ONCE
        );
        if (err != 0) {
            free(comp);
            mp_stream_close(in_obj);
            mp_stream_close(out_obj);
            return -1;
        }
        if (read_bytes > 0) {
            crc = mz_crc32(crc, in_buf, read_bytes);
            isize += (uint32_t)read_bytes;
        }

        int last = read_bytes == 0;
        size_t in_off = 0;
        tdefl_status status = TDEFL_STATUS_OKAY;

        do {
            size_t in_size = (size_t)read_bytes - in_off;
            size_t out_size = sizeof(out_buf);
            tdefl_flush flush = last ? TDEFL_FINISH : TDEFL_NO_FLUSH;
            status = tdefl_compress(
                comp,
                (in_size > 0) ? (in_buf + in_off) : NULL,
                &in_size,
                out_buf,
                &out_size,
                flush
            );
            in_off += in_size;
            if (out_size > 0) {
                if (vhttp_mp_write_full(out_obj, out_buf, out_size) != 0) {
                    free(comp);
                    mp_stream_close(in_obj);
                    mp_stream_close(out_obj);
                    return -1;
                }
            }
            if (status < 0) {
                free(comp);
                mp_stream_close(in_obj);
                mp_stream_close(out_obj);
                return -1;
            }
        } while (in_off < (size_t)read_bytes || (last && status == TDEFL_STATUS_OKAY));

        if (last) {
            if (status != TDEFL_STATUS_DONE) {
                free(comp);
                mp_stream_close(in_obj);
                mp_stream_close(out_obj);
                return -1;
            }
            break;
        }
    }

    uint8_t trailer[8];
    trailer[0] = (uint8_t)(crc & 0xFF);
    trailer[1] = (uint8_t)((crc >> 8) & 0xFF);
    trailer[2] = (uint8_t)((crc >> 16) & 0xFF);
    trailer[3] = (uint8_t)((crc >> 24) & 0xFF);
    trailer[4] = (uint8_t)(isize & 0xFF);
    trailer[5] = (uint8_t)((isize >> 8) & 0xFF);
    trailer[6] = (uint8_t)((isize >> 16) & 0xFF);
    trailer[7] = (uint8_t)((isize >> 24) & 0xFF);

    if (vhttp_mp_write_full(out_obj, trailer, sizeof(trailer)) != 0) {
        free(comp);
        mp_stream_close(in_obj);
        mp_stream_close(out_obj);
        return -1;
    }

    free(comp);
    mp_stream_close(in_obj);
    mp_stream_close(out_obj);
    return 0;
}

static int vhttp_mp_listdir(const char *path, size_t path_len, mp_obj_t *out_list) {
    mp_obj_t args[1] = { mp_obj_new_str(path, path_len) };
    nlr_buf_t nlr;
    if (nlr_push(&nlr) == 0) {
        *out_list = mp_vfs_listdir(1, args);
        nlr_pop();
        return 0;
    }
    return -1;
}

static void vhttp_mp_try_remove(const char *path, size_t path_len) {
#if MICROPY_VFS_WRITABLE
    nlr_buf_t nlr;
    if (nlr_push(&nlr) == 0) {
        mp_vfs_remove(mp_obj_new_str(path, path_len));
        nlr_pop();
    }
#else
    (void)path;
    (void)path_len;
#endif
}

static int vhttp_mp_try_rename(const char *old_path, size_t old_len, const char *new_path, size_t new_len) {
#if MICROPY_VFS_WRITABLE
    nlr_buf_t nlr;
    mp_obj_t args[2] = { mp_obj_new_str(old_path, old_len), mp_obj_new_str(new_path, new_len) };
    if (nlr_push(&nlr) == 0) {
        mp_vfs_rename(args[0], args[1]);
        nlr_pop();
        return 0;
    }
    return -1;
#else
    (void)old_path;
    (void)old_len;
    (void)new_path;
    (void)new_len;
    return -1;
#endif
}

static int vhttp_mp_gzip_walk(
    const char *dir,
    size_t dir_len,
    size_t min_size,
    int level,
    vhttp_gzip_stats_t *stats,
    int depth
) {
    if (depth > VHTTP_GZIP_MAX_DEPTH) {
        if (stats) {
            stats->errors++;
        }
        return -1;
    }

    mp_obj_t list_obj;
    if (vhttp_mp_listdir(dir, dir_len, &list_obj) != 0) {
        if (stats) {
            stats->errors++;
        }
        return -1;
    }

    size_t list_len = 0;
    mp_obj_t *items = NULL;
    mp_obj_get_array(list_obj, &list_len, &items);

    char path[VHTTP_STATIC_MAX_PATH];
    char gz_path[VHTTP_STATIC_MAX_PATH];
    char tmp_path[VHTTP_STATIC_MAX_PATH];

    for (size_t i = 0; i < list_len; ++i) {
        mp_obj_t name_obj = items[i];
        if (!mp_obj_is_str(name_obj)) {
            continue;
        }
        size_t name_len = 0;
        const char *name = mp_obj_str_get_data(name_obj, &name_len);
        if (!name || name_len == 0) {
            continue;
        }

        int plen = snprintf(path, sizeof(path), "%.*s/%.*s", (int)dir_len, dir, (int)name_len, name);
        if (plen <= 0 || (size_t)plen >= sizeof(path)) {
            if (stats) {
                stats->errors++;
            }
            continue;
        }

        size_t file_size = 0;
        uint32_t file_mtime = 0;
        int is_dir = 0;
        if (vhttp_mp_stat_path(path, (size_t)plen, &file_size, &file_mtime, &is_dir) != 0) {
            if (stats) {
                stats->errors++;
            }
            continue;
        }

        if (is_dir) {
            vhttp_mp_gzip_walk(path, (size_t)plen, min_size, level, stats, depth + 1);
            continue;
        }

        if (stats) {
            stats->files_seen++;
        }

        if (vhttp_path_has_suffix_ci(path, (size_t)plen, ".gz")) {
            if (stats) {
                stats->skipped_ext++;
            }
            continue;
        }

        if (!vhttp_is_compressible_ext(path, (size_t)plen)) {
            if (stats) {
                stats->skipped_ext++;
            }
            continue;
        }

        if (min_size > 0 && file_size < min_size) {
            if (stats) {
                stats->skipped_small++;
            }
            continue;
        }

        int gz_len = snprintf(gz_path, sizeof(gz_path), "%s.gz", path);
        if (gz_len <= 0 || (size_t)gz_len >= sizeof(gz_path)) {
            if (stats) {
                stats->errors++;
            }
            continue;
        }

        size_t gz_size = 0;
        uint32_t gz_mtime = 0;
        int gz_is_dir = 0;
        if (vhttp_mp_stat_path(gz_path, (size_t)gz_len, &gz_size, &gz_mtime, &gz_is_dir) == 0 && !gz_is_dir) {
            if (gz_size > 0 && gz_mtime >= file_mtime) {
                if (stats) {
                    stats->skipped_existing++;
                }
                continue;
            }
        }

        int tmp_len = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", gz_path);
        if (tmp_len <= 0 || (size_t)tmp_len >= sizeof(tmp_path)) {
            if (stats) {
                stats->errors++;
            }
            continue;
        }

        if (vhttp_mp_gzip_file(path, (size_t)plen, tmp_path, (size_t)tmp_len, level) != 0) {
            vhttp_mp_try_remove(tmp_path, (size_t)tmp_len);
            if (stats) {
                stats->errors++;
            }
            continue;
        }

        if (vhttp_mp_try_rename(tmp_path, (size_t)tmp_len, gz_path, (size_t)gz_len) != 0) {
            vhttp_mp_try_remove(tmp_path, (size_t)tmp_len);
            if (stats) {
                stats->errors++;
            }
            continue;
        }

        if (stats) {
            stats->files_gzipped++;
        }
    }

    return 0;
}

static int vhttp_mp_static_gzip(
    const char *root,
    size_t root_len,
    size_t min_size,
    int level,
    vhttp_gzip_stats_t *stats
) {
    if (!root || root_len == 0) {
        return -1;
    }
    if (level < 0 || level > 9) {
        return -1;
    }

    if (stats) {
        memset(stats, 0, sizeof(*stats));
    }

    if (root_len >= VHTTP_STATIC_MAX_PATH) {
        if (stats) {
            stats->errors++;
        }
        return -1;
    }

    char root_buf[VHTTP_STATIC_MAX_PATH];
    memcpy(root_buf, root, root_len);
    root_buf[root_len] = '\0';

    vhttp_fs_lock();
    int rc = vhttp_mp_gzip_walk(root_buf, root_len, min_size, level, stats, 0);
    vhttp_fs_unlock();
    return rc;
}

static mp_obj_t viperhttp_poll_request(void) {
    vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
    vhttp_ipc_msg_t msg;

    if (vhttp_ipc_queue_pop(&ipc->request_queue, &msg) != 0) {
        return mp_const_none;
    }

    uint8_t *base_ptr = vhttp_ipc_ring_ptr(&ipc->ring, msg.buffer_offset);
    if (!base_ptr && msg.buffer_offset != 0) {
        return mp_const_none;
    }

    if (msg.type == VHTTP_IPC_REQ_WS_CONNECT) {
        const char *full_path = (const char *)base_ptr;
        size_t full_len = msg.uri_len;
        const char *path_only = NULL;
        size_t path_only_len = 0;
        const char *query_ptr = NULL;
        size_t query_len = 0;
        vhttp_split_path_query(full_path, full_len, &path_only, &path_only_len, &query_ptr, &query_len);

        const uint8_t *headers_ptr = NULL;
        if (msg.headers_len > 0) {
            headers_ptr = vhttp_ipc_ring_ptr(&ipc->ring, msg.headers_offset);
            if (!headers_ptr) {
                return mp_const_none;
            }
        }
        mp_obj_t headers = vhttp_parse_headers_blob(headers_ptr, msg.headers_len);

        mp_obj_t body = mp_obj_new_bytes((const byte *)"", 0);
        mp_obj_t method_obj = mp_obj_new_str("WS", 2);
        mp_obj_t request = vhttp_request_make(
            method_obj,
            mp_obj_new_str(path_only, path_only_len),
            mp_obj_new_str(query_ptr ? query_ptr : "", query_len),
            mp_const_none,
            headers,
            body
        );

        mp_obj_t dict = mp_obj_new_dict(4);
        mp_obj_dict_store(dict, mp_obj_new_str("type", 4), mp_obj_new_str("ws_connect", 10));
        mp_obj_dict_store(dict, mp_obj_new_str("conn_id", 7), mp_obj_new_int_from_uint(msg.request_id));
        mp_obj_dict_store(dict, mp_obj_new_str("path", 4), mp_obj_new_str(full_path, full_len));
        mp_obj_dict_store(dict, mp_obj_new_str("request", 7), request);

        if (msg.flags & VHTTP_IPC_FLAG_RELEASE) {
            uint32_t release_len = (uint32_t)msg.uri_len + (uint32_t)msg.headers_len + msg.body_len;
            if (release_len > 0) {
                vhttp_ipc_ring_release(&ipc->ring, release_len);
            }
        }
        return dict;
    }

    if (msg.type == VHTTP_IPC_REQ_WS_MSG) {
        mp_obj_t data = mp_obj_new_bytes((const byte *)"", 0);
        if (msg.body_len > 0 && base_ptr) {
            data = mp_obj_new_bytes(base_ptr, msg.body_len);
        }

        mp_obj_t dict = mp_obj_new_dict(5);
        mp_obj_dict_store(dict, mp_obj_new_str("type", 4), mp_obj_new_str("ws_msg", 6));
        mp_obj_dict_store(dict, mp_obj_new_str("conn_id", 7), mp_obj_new_int_from_uint(msg.request_id));
        mp_obj_dict_store(dict, mp_obj_new_str("opcode", 6), mp_obj_new_int(msg.method));
        mp_obj_dict_store(dict, mp_obj_new_str("final", 5), mp_obj_new_bool((msg.flags & VHTTP_IPC_FLAG_FINAL) != 0));
        mp_obj_dict_store(dict, mp_obj_new_str("data", 4), data);

        if (msg.flags & VHTTP_IPC_FLAG_RELEASE) {
            if (msg.body_len > 0) {
                vhttp_ipc_ring_release(&ipc->ring, msg.body_len);
            }
        }
        return dict;
    }

    if (msg.type == VHTTP_IPC_REQ_WS_DISCONNECT) {
        mp_obj_t dict = mp_obj_new_dict(3);
        mp_obj_dict_store(dict, mp_obj_new_str("type", 4), mp_obj_new_str("ws_disconnect", 13));
        mp_obj_dict_store(dict, mp_obj_new_str("conn_id", 7), mp_obj_new_int_from_uint(msg.request_id));
        mp_obj_dict_store(dict, mp_obj_new_str("code", 4), mp_obj_new_int(msg.status_code));
        return dict;
    }

    const char *method = "GET";
    switch ((vhttp_method_t)msg.method) {
        case VHTTP_METHOD_GET: method = "GET"; break;
        case VHTTP_METHOD_POST: method = "POST"; break;
        case VHTTP_METHOD_PUT: method = "PUT"; break;
        case VHTTP_METHOD_PATCH: method = "PATCH"; break;
        case VHTTP_METHOD_DELETE: method = "DELETE"; break;
        case VHTTP_METHOD_OPTIONS: method = "OPTIONS"; break;
        case VHTTP_METHOD_HEAD: method = "HEAD"; break;
        default: method = "GET"; break;
    }

    if (!base_ptr || msg.uri_len == 0) {
        return mp_const_none;
    }

    const char *full_path = (const char *)base_ptr;
    size_t full_len = msg.uri_len;
    const char *path_only = NULL;
    size_t path_only_len = 0;
    const char *query_ptr = NULL;
    size_t query_len = 0;
    vhttp_split_path_query(full_path, full_len, &path_only, &path_only_len, &query_ptr, &query_len);

    const uint8_t *headers_ptr = NULL;
    if (msg.headers_len > 0) {
        headers_ptr = vhttp_ipc_ring_ptr(&ipc->ring, msg.headers_offset);
        if (!headers_ptr) {
            return mp_const_none;
        }
    }
    mp_obj_t headers = mp_const_none;

#if VHTTP_STATIC_SERVE_VIA_IPC
    vhttp_static_match_t static_match = {0};
    if (vhttp_static_resolve(path_only, path_only_len, &static_match)) {
        headers = vhttp_parse_headers_blob(headers_ptr, msg.headers_len);
        if (vhttp_mp_static_handle(msg.request_id, msg.method, path_only, path_only_len, headers)) {
            return mp_const_none;
        }
    }
#endif

    if (headers == mp_const_none) {
        headers = vhttp_parse_headers_blob(headers_ptr, msg.headers_len);
    }

    mp_obj_t body = mp_obj_new_bytes((const byte *)"", 0);
    if (msg.body_len > 0) {
        const uint8_t *body_ptr = base_ptr + msg.uri_len + msg.headers_len;
        body = mp_obj_new_bytes(body_ptr, msg.body_len);
    }

    mp_obj_t method_obj = mp_obj_new_str(method, strlen(method));
    mp_obj_t request = vhttp_request_make(
        method_obj,
        mp_obj_new_str(path_only, path_only_len),
        mp_obj_new_str(query_ptr ? query_ptr : "", query_len),
        mp_const_none,
        headers,
        body
    );

    mp_obj_t dict = mp_obj_new_dict(4);
    mp_obj_dict_store(dict, mp_obj_new_str("request_id", 10), mp_obj_new_int_from_uint(msg.request_id));
    mp_obj_dict_store(dict, mp_obj_new_str("method", 6), method_obj);
    mp_obj_dict_store(dict, mp_obj_new_str("path", 4), mp_obj_new_str(full_path, full_len));
    mp_obj_dict_store(dict, mp_obj_new_str("request", 7), request);
    return dict;
}
static MP_DEFINE_CONST_FUN_OBJ_0(viperhttp_poll_request_obj, viperhttp_poll_request);

static mp_obj_t viperhttp_send_response(size_t n_args, const mp_obj_t *args) {
    if (n_args < 1 || n_args > 2) {
        mp_raise_TypeError(MP_ERROR_TEXT("send_response expects (response) or (request_id, response)"));
    }

    mp_int_t request_id = -1;
    mp_obj_t response = args[n_args - 1];

    if (n_args == 2) {
        request_id = mp_obj_get_int(args[0]);
    }

    if (!vhttp_is_response_dict(response)) {
        response = vhttp_normalize_result(response);
    }

    if (request_id < 0) {
        mp_obj_t key = mp_obj_new_str("request_id", 10);
        nlr_buf_t nlr;
        if (nlr_push(&nlr) == 0) {
            mp_obj_t rid = mp_obj_dict_get(response, key);
            nlr_pop();
            request_id = mp_obj_get_int(rid);
        } else {
            mp_raise_ValueError(MP_ERROR_TEXT("response missing request_id"));
        }
    }

    mp_obj_t status_key = mp_obj_new_str("status_code", 11);
    mp_obj_t body_key = mp_obj_new_str("body", 4);
    mp_obj_t headers_key = mp_obj_new_str("headers", 7);
    mp_obj_t content_type_key = mp_obj_new_str("content_type", 12);
    mp_int_t status_code = 200;
    mp_obj_t body = mp_const_none;
    mp_obj_t headers = mp_const_none;
    mp_obj_t content_type = mp_const_none;

    nlr_buf_t nlr;
    if (nlr_push(&nlr) == 0) {
        mp_obj_t status_obj = mp_obj_dict_get(response, status_key);
        status_code = mp_obj_get_int(status_obj);
        nlr_pop();
    } else {
        // ignore missing status_code
    }

    if (nlr_push(&nlr) == 0) {
        body = mp_obj_dict_get(response, body_key);
        nlr_pop();
    } else {
        body = mp_const_none;
    }

    if (nlr_push(&nlr) == 0) {
        headers = mp_obj_dict_get(response, headers_key);
        nlr_pop();
    } else {
        headers = mp_const_none;
    }

    if (nlr_push(&nlr) == 0) {
        content_type = mp_obj_dict_get(response, content_type_key);
        nlr_pop();
    } else {
        content_type = mp_const_none;
    }

    vstr_t headers_vstr;
    vstr_init(&headers_vstr, 0);
    int has_content_type = vhttp_headers_has_content_type(headers);
    if (!has_content_type) {
        mp_obj_t ct = content_type;
        if (ct == mp_const_none) {
            ct = mp_obj_new_str("text/plain; charset=utf-8", 25);
        }
        vhttp_vstr_add_header(&headers_vstr, mp_obj_new_str("Content-Type", 12), ct);
    }
    vhttp_append_headers(&headers_vstr, headers);

    if (headers_vstr.len > UINT16_MAX) {
        vstr_clear(&headers_vstr);
        mp_raise_ValueError(MP_ERROR_TEXT("headers too large"));
    }

    mp_obj_t template_stream = mp_const_false;
    mp_obj_t key_template_stream = mp_obj_new_str("__vhttp_template_stream__", 25);
    if (nlr_push(&nlr) == 0) {
        template_stream = mp_obj_dict_get(response, key_template_stream);
        nlr_pop();
    } else {
        template_stream = mp_const_false;
    }

    if (mp_obj_is_true(template_stream)) {
        mp_obj_t path_obj = mp_const_none;
        mp_obj_t context_obj = mp_const_none;
        mp_obj_t strict_obj = mp_const_true;
        mp_obj_t key_template_path = mp_obj_new_str("template_path", 13);
        mp_obj_t key_template_context = mp_obj_new_str("template_context", 16);
        mp_obj_t key_template_strict = mp_obj_new_str("template_strict", 15);
        vhttp_request_t *cur_req = vhttp_request_ptr(MP_STATE_VM(viperhttp_current_request));
        int gzip_stream = 0;

        if (status_code == 200 && cur_req != NULL) {
            const char *etag_ptr = NULL;
            size_t etag_len = 0;
            if (vhttp_vstr_header_get_ci(&headers_vstr, "ETag", &etag_ptr, &etag_len) && etag_ptr && etag_len > 0) {
                size_t inm_len = 0;
                mp_obj_t inm_obj = vhttp_header_get_ci(cur_req->headers, "if-none-match", &inm_len);
                const char *inm_ptr = NULL;
                size_t inm_ptr_len = 0;
                if (inm_obj != MP_OBJ_NULL &&
                    inm_len > 0 &&
                    vhttp_extract_header_text(inm_obj, inm_len, &inm_ptr, &inm_ptr_len) == 0 &&
                    inm_ptr &&
                    inm_ptr_len > 0 &&
                    vhttp_etag_matches_value(inm_ptr, inm_ptr_len, etag_ptr, etag_len)) {
                    if (vhttp_ipc_send_raw((uint32_t)request_id, 304, NULL, 0, headers_vstr.buf, headers_vstr.len) != 0) {
                        vstr_clear(&headers_vstr);
                        vhttp_mp_static_send_simple((uint32_t)request_id, 500, "Internal Server Error");
                        return mp_const_none;
                    }
                    vstr_clear(&headers_vstr);
                    return mp_const_none;
                }
            }
        }

        if (VHTTP_GZIP_ENABLED && status_code == 200 && cur_req != NULL) {
            const char *content_len_ptr = NULL;
            size_t content_len_len = 0;
            int has_content_len = vhttp_vstr_header_get_ci(&headers_vstr, "Content-Length", &content_len_ptr, &content_len_len);
            const char *content_encoding_ptr = NULL;
            size_t content_encoding_len = 0;
            int has_content_encoding = vhttp_vstr_header_get_ci(&headers_vstr, "Content-Encoding", &content_encoding_ptr, &content_encoding_len);

            if (!has_content_len) {
                if (has_content_encoding) {
                    if (vhttp_str_ci_contains(content_encoding_ptr, content_encoding_len, "gzip")) {
                        gzip_stream = 1;
                    }
                } else if (vhttp_header_value_contains_ci(cur_req->headers, "accept-encoding", "gzip")) {
                    gzip_stream = 1;
                    vhttp_vstr_add_header_cstr(&headers_vstr, "Content-Encoding", "gzip");
                }
                if (gzip_stream && !vhttp_vstr_header_has_token_ci(&headers_vstr, "Vary", "Accept-Encoding")) {
                    vhttp_vstr_add_header_cstr(&headers_vstr, "Vary", "Accept-Encoding");
                }
            }
        }

        if (nlr_push(&nlr) == 0) {
            path_obj = mp_obj_dict_get(response, key_template_path);
            nlr_pop();
        } else {
            vstr_clear(&headers_vstr);
            mp_raise_ValueError(MP_ERROR_TEXT("template stream missing path"));
        }
        if (nlr_push(&nlr) == 0) {
            context_obj = mp_obj_dict_get(response, key_template_context);
            nlr_pop();
        } else {
            context_obj = mp_const_none;
        }
        if (nlr_push(&nlr) == 0) {
            strict_obj = mp_obj_dict_get(response, key_template_strict);
            nlr_pop();
        } else {
            strict_obj = mp_const_true;
        }

        if (!mp_obj_is_str(path_obj)) {
            vstr_clear(&headers_vstr);
            mp_raise_ValueError(MP_ERROR_TEXT("template stream path must be str"));
        }
        size_t tpl_path_len = 0;
        const char *tpl_path = mp_obj_str_get_data(path_obj, &tpl_path_len);
        if (!tpl_path || tpl_path_len == 0 || tpl_path_len >= VHTTP_STATIC_MAX_PATH) {
            vstr_clear(&headers_vstr);
            mp_raise_ValueError(MP_ERROR_TEXT("invalid template stream path"));
        }

        char err[96];
        err[0] = '\0';
        int rc = vhttp_tpl_render_stream_path(
            (uint32_t)request_id,
            (uint16_t)status_code,
            tpl_path,
            tpl_path_len,
            context_obj,
            mp_obj_is_true(strict_obj) ? 1 : 0,
            gzip_stream,
            &headers_vstr,
            err,
            sizeof(err)
        );
        vstr_clear(&headers_vstr);
        if (rc != 0) {
            mp_raise_msg_varg(&mp_type_ValueError, MP_ERROR_TEXT("template streaming failed: %s"), err[0] ? err : "stream error");
        }
        return mp_const_none;
    }

    mp_obj_t stream = mp_const_none;
    mp_obj_t key_stream = mp_obj_new_str("stream", 6);
    if (nlr_push(&nlr) == 0) {
        stream = mp_obj_dict_get(response, key_stream);
        nlr_pop();
    } else {
        stream = mp_const_none;
    }

    if (stream != mp_const_none) {
        mp_obj_t key_chunk_size = mp_obj_new_str("chunk_size", 10);
        mp_obj_t key_total_len = mp_obj_new_str("total_len", 9);
        mp_obj_t key_chunked = mp_obj_new_str("chunked", 7);
        mp_int_t chunk_size = VHTTP_STATIC_STREAM_CHUNK_SIZE;
        uint32_t total_len = 0;
        int chunked = 0;

        if (nlr_push(&nlr) == 0) {
            mp_obj_t chunk_obj = mp_obj_dict_get(response, key_chunk_size);
            chunk_size = mp_obj_get_int(chunk_obj);
            nlr_pop();
        }
        if (chunk_size <= 0) {
            vstr_clear(&headers_vstr);
            mp_raise_ValueError(MP_ERROR_TEXT("chunk_size must be > 0"));
        }

        if (nlr_push(&nlr) == 0) {
            mp_obj_t total_obj = mp_obj_dict_get(response, key_total_len);
            if (total_obj != mp_const_none) {
                mp_int_t total_i = mp_obj_get_int(total_obj);
                if (total_i < 0) {
                    vstr_clear(&headers_vstr);
                    mp_raise_ValueError(MP_ERROR_TEXT("total_len must be >= 0"));
                }
                total_len = (uint32_t)total_i;
            }
            nlr_pop();
        }

        if (nlr_push(&nlr) == 0) {
            mp_obj_t chunked_obj = mp_obj_dict_get(response, key_chunked);
            chunked = mp_obj_is_true(chunked_obj);
            nlr_pop();
        }

        if (total_len == 0) {
            chunked = 1;
        }

        int rc = vhttp_send_stream_obj(
            (uint32_t)request_id,
            (uint16_t)status_code,
            stream,
            &headers_vstr,
            (uint32_t)chunk_size,
            total_len,
            chunked
        );
        vstr_clear(&headers_vstr);
        if (rc != 0) {
            mp_raise_ValueError(MP_ERROR_TEXT("streaming failed"));
        }
        return mp_const_none;
    }

    size_t body_len = 0;
    const uint8_t *body_ptr = NULL;
    mp_buffer_info_t bufinfo;

    if (body == mp_const_none) {
        body_len = 0;
    } else if (mp_obj_is_str(body)) {
        const char *str = mp_obj_str_get_data(body, &body_len);
        body_ptr = (const uint8_t *)str;
    } else if (mp_obj_is_type(body, &mp_type_bytes) || mp_obj_is_type(body, &mp_type_bytearray)) {
        mp_get_buffer_raise(body, &bufinfo, MP_BUFFER_READ);
        body_ptr = (const uint8_t *)bufinfo.buf;
        body_len = bufinfo.len;
    } else {
        vstr_clear(&headers_vstr);
        mp_raise_ValueError(MP_ERROR_TEXT("response body must be str/bytes/bytearray/None"));
    }

    vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
    uint32_t offset = 0;
    uint8_t *dst = NULL;
    uint32_t headers_offset = 0;
    uint8_t *headers_dst = NULL;
    uint16_t headers_len = (uint16_t)headers_vstr.len;

    if (body_len > 0) {
        if (vhttp_ipc_ring_alloc(&ipc->ring, (uint32_t)body_len, &offset, &dst) != 0) {
            vstr_clear(&headers_vstr);
            mp_raise_ValueError(MP_ERROR_TEXT("ipc ring full"));
        }
        memcpy(dst, body_ptr, body_len);
    }

    if (headers_len > 0) {
        if (vhttp_ipc_ring_alloc(&ipc->ring, (uint32_t)headers_len, &headers_offset, &headers_dst) != 0) {
            if (body_len > 0) {
                vhttp_ipc_ring_release(&ipc->ring, (uint32_t)body_len);
            }
            vstr_clear(&headers_vstr);
            mp_raise_ValueError(MP_ERROR_TEXT("ipc ring full"));
        }
        memcpy(headers_dst, headers_vstr.buf, headers_len);
    }

    vhttp_ipc_msg_t msg = {0};
    msg.request_id = (uint32_t)request_id;
    msg.type = VHTTP_IPC_RESP_HTTP;
    msg.status_code = (uint16_t)status_code;
    msg.headers_len = headers_len;
    msg.headers_offset = headers_offset;
    msg.body_len = (uint32_t)body_len;
    msg.total_len = (uint32_t)body_len;
    msg.buffer_offset = offset;
    msg.flags = 0;

    if (vhttp_ipc_queue_push_wait_ms(&ipc->response_queue, &msg, VHTTP_IPC_QUEUE_WAIT_MS) != 0) {
        if (body_len > 0) {
            vhttp_ipc_ring_release(&ipc->ring, (uint32_t)body_len);
        }
        if (headers_len > 0) {
            vhttp_ipc_ring_release(&ipc->ring, (uint32_t)headers_len);
        }
        vstr_clear(&headers_vstr);
        mp_raise_ValueError(MP_ERROR_TEXT("response queue full"));
    }

    vstr_clear(&headers_vstr);

    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(viperhttp_send_response_obj, 1, 2, viperhttp_send_response);

static int vhttp_kw_key_eq(mp_obj_t key, const char *name) {
    if (!mp_obj_is_str(key) && !mp_obj_is_qstr(key)) {
        return 0;
    }
    GET_STR_DATA_LEN(key, key_data, key_len);
    size_t name_len = strlen(name);
    if (key_len != name_len) {
        return 0;
    }
    return memcmp(key_data, name, key_len) == 0;
}

static mp_obj_t viperhttp_stream_send(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    if (n_args > 2) {
        mp_raise_TypeError(MP_ERROR_TEXT("stream_send([request_id], [data], **kwargs)"));
    }

    mp_int_t request_id = -1;
    mp_obj_t data_obj = mp_const_none;
    if (n_args >= 1) {
        request_id = mp_obj_get_int(pos_args[0]);
    }
    if (n_args >= 2) {
        data_obj = pos_args[1];
    }

    mp_int_t status_code = 200;
    mp_obj_t headers = mp_const_none;
    mp_obj_t content_type = mp_const_none;
    mp_int_t total_len_i = 0;
    int chunked = 1;
    int final = 0;
    int send_headers = 0;

    if (kw_args && kw_args->used > 0) {
        for (size_t i = 0; i < kw_args->alloc; ++i) {
            if (!mp_map_slot_is_filled(kw_args, i)) {
                continue;
            }
            mp_obj_t key = kw_args->table[i].key;
            mp_obj_t val = kw_args->table[i].value;
            if (vhttp_kw_key_eq(key, "request_id")) {
                if (request_id >= 0 && n_args >= 1) {
                    mp_raise_TypeError(MP_ERROR_TEXT("request_id specified twice"));
                }
                request_id = mp_obj_get_int(val);
            } else if (vhttp_kw_key_eq(key, "data")) {
                if (n_args >= 2) {
                    mp_raise_TypeError(MP_ERROR_TEXT("data specified twice"));
                }
                data_obj = val;
            } else if (vhttp_kw_key_eq(key, "status_code")) {
                status_code = mp_obj_get_int(val);
            } else if (vhttp_kw_key_eq(key, "headers")) {
                headers = val;
            } else if (vhttp_kw_key_eq(key, "content_type")) {
                content_type = val;
            } else if (vhttp_kw_key_eq(key, "total_len")) {
                total_len_i = mp_obj_get_int(val);
            } else if (vhttp_kw_key_eq(key, "chunked")) {
                chunked = mp_obj_is_true(val);
            } else if (vhttp_kw_key_eq(key, "final")) {
                final = mp_obj_is_true(val);
            } else if (vhttp_kw_key_eq(key, "send_headers")) {
                send_headers = mp_obj_is_true(val);
            } else {
                mp_raise_TypeError(MP_ERROR_TEXT("unexpected keyword argument"));
            }
        }
    }

    if (request_id < 0) {
        mp_raise_TypeError(MP_ERROR_TEXT("missing request_id"));
    }

    if (total_len_i < 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("total_len must be >= 0"));
    }
    uint32_t total_len = (uint32_t)total_len_i;

    const uint8_t *data_ptr = NULL;
    size_t data_len = 0;
    mp_buffer_info_t bufinfo;
    if (data_obj == mp_const_none) {
        data_len = 0;
    } else if (mp_obj_is_str(data_obj)) {
        const char *str = mp_obj_str_get_data(data_obj, &data_len);
        data_ptr = (const uint8_t *)str;
    } else if (mp_obj_is_type(data_obj, &mp_type_bytes) || mp_obj_is_type(data_obj, &mp_type_bytearray)) {
        mp_get_buffer_raise(data_obj, &bufinfo, MP_BUFFER_READ);
        data_ptr = (const uint8_t *)bufinfo.buf;
        data_len = bufinfo.len;
    } else {
        mp_raise_ValueError(MP_ERROR_TEXT("data must be str/bytes/bytearray/None"));
    }

    vstr_t headers_vstr;
    vstr_init(&headers_vstr, 0);
    vstr_t *headers_ptr = NULL;
    if (send_headers) {
        int has_content_type = vhttp_headers_has_content_type(headers);
        if (!has_content_type) {
            mp_obj_t ct = content_type;
            if (ct == mp_const_none) {
                ct = mp_obj_new_str("text/plain; charset=utf-8", 25);
            }
            vhttp_vstr_add_header(&headers_vstr, mp_obj_new_str("Content-Type", 12), ct);
        }
        vhttp_append_headers(&headers_vstr, headers);
        if (headers_vstr.len > UINT16_MAX) {
            vstr_clear(&headers_vstr);
            mp_raise_ValueError(MP_ERROR_TEXT("headers too large"));
        }
        headers_ptr = &headers_vstr;
    }

    int rc = vhttp_ipc_send_stream_chunk(
        vhttp_ipc_default_state(),
        request_id,
        (uint16_t)status_code,
        data_ptr,
        data_len,
        headers_ptr,
        send_headers,
        total_len,
        chunked,
        final
    );

    if (send_headers) {
        vstr_clear(&headers_vstr);
    }

    if (rc != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("streaming failed"));
    }

    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_KW(viperhttp_stream_send_obj, 1, viperhttp_stream_send);

static mp_obj_t viperhttp_ws_accept(size_t n_args, const mp_obj_t *args) {
    if (n_args < 1 || n_args > 2) {
        mp_raise_TypeError(MP_ERROR_TEXT("ws_accept(conn_id, [subprotocol])"));
    }
    mp_int_t conn_id = mp_obj_get_int(args[0]);
    mp_obj_t proto = n_args > 1 ? args[1] : mp_const_none;

    vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
    if (!ipc) {
        mp_raise_ValueError(MP_ERROR_TEXT("ipc unavailable"));
    }

    uint32_t offset = 0;
    uint8_t *dst = NULL;
    size_t proto_len = 0;
    if (proto != mp_const_none) {
        if (mp_obj_is_str(proto)) {
            const char *ptr = mp_obj_str_get_data(proto, &proto_len);
            if (proto_len > UINT32_MAX) {
                mp_raise_ValueError(MP_ERROR_TEXT("subprotocol too large"));
            }
            if (proto_len > 0) {
                if (vhttp_ipc_ring_alloc_wait(&ipc->ring, (uint32_t)proto_len, &offset, &dst) != 0) {
                    mp_raise_ValueError(MP_ERROR_TEXT("ipc ring full"));
                }
                memcpy(dst, ptr, proto_len);
            }
        } else if (mp_obj_is_type(proto, &mp_type_bytes) || mp_obj_is_type(proto, &mp_type_bytearray)) {
            mp_buffer_info_t bufinfo;
            mp_get_buffer_raise(proto, &bufinfo, MP_BUFFER_READ);
            proto_len = bufinfo.len;
            if (proto_len > UINT32_MAX) {
                mp_raise_ValueError(MP_ERROR_TEXT("subprotocol too large"));
            }
            if (proto_len > 0) {
                if (vhttp_ipc_ring_alloc_wait(&ipc->ring, (uint32_t)proto_len, &offset, &dst) != 0) {
                    mp_raise_ValueError(MP_ERROR_TEXT("ipc ring full"));
                }
                memcpy(dst, bufinfo.buf, proto_len);
            }
        } else {
            mp_raise_TypeError(MP_ERROR_TEXT("subprotocol must be str/bytes"));
        }
    }

    vhttp_ipc_msg_t msg = {0};
    msg.request_id = (uint32_t)conn_id;
    msg.type = VHTTP_IPC_RESP_WS_ACCEPT;
    msg.body_len = (uint32_t)proto_len;
    msg.buffer_offset = proto_len > 0 ? offset : 0;

    if (vhttp_ipc_queue_push_wait_ms(&ipc->response_queue, &msg, VHTTP_IPC_QUEUE_WAIT_MS) != 0) {
        if (proto_len > 0) {
            vhttp_ipc_ring_release(&ipc->ring, (uint32_t)proto_len);
        }
        mp_raise_ValueError(MP_ERROR_TEXT("ws accept queue full"));
    }

    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(viperhttp_ws_accept_obj, 1, 2, viperhttp_ws_accept);

static mp_obj_t viperhttp_ws_reject(size_t n_args, const mp_obj_t *args) {
    if (n_args < 1 || n_args > 3) {
        mp_raise_TypeError(MP_ERROR_TEXT("ws_reject(conn_id, [status], [body])"));
    }
    mp_int_t conn_id = mp_obj_get_int(args[0]);
    mp_int_t status = 404;
    mp_obj_t body = mp_const_none;
    if (n_args >= 2) {
        status = mp_obj_get_int(args[1]);
    }
    if (n_args >= 3) {
        body = args[2];
    }

    vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
    if (!ipc) {
        mp_raise_ValueError(MP_ERROR_TEXT("ipc unavailable"));
    }

    uint32_t offset = 0;
    uint8_t *dst = NULL;
    size_t body_len = 0;
    if (body != mp_const_none) {
        if (mp_obj_is_str(body)) {
            const char *ptr = mp_obj_str_get_data(body, &body_len);
            if (body_len > UINT32_MAX) {
                mp_raise_ValueError(MP_ERROR_TEXT("body too large"));
            }
            if (body_len > 0) {
                if (vhttp_ipc_ring_alloc_wait(&ipc->ring, (uint32_t)body_len, &offset, &dst) != 0) {
                    mp_raise_ValueError(MP_ERROR_TEXT("ipc ring full"));
                }
                memcpy(dst, ptr, body_len);
            }
        } else if (mp_obj_is_type(body, &mp_type_bytes) || mp_obj_is_type(body, &mp_type_bytearray)) {
            mp_buffer_info_t bufinfo;
            mp_get_buffer_raise(body, &bufinfo, MP_BUFFER_READ);
            body_len = bufinfo.len;
            if (body_len > UINT32_MAX) {
                mp_raise_ValueError(MP_ERROR_TEXT("body too large"));
            }
            if (body_len > 0) {
                if (vhttp_ipc_ring_alloc_wait(&ipc->ring, (uint32_t)body_len, &offset, &dst) != 0) {
                    mp_raise_ValueError(MP_ERROR_TEXT("ipc ring full"));
                }
                memcpy(dst, bufinfo.buf, body_len);
            }
        } else {
            mp_raise_TypeError(MP_ERROR_TEXT("body must be str/bytes"));
        }
    }

    vhttp_ipc_msg_t msg = {0};
    msg.request_id = (uint32_t)conn_id;
    msg.type = VHTTP_IPC_RESP_WS_REJECT;
    msg.status_code = (uint16_t)status;
    msg.body_len = (uint32_t)body_len;
    msg.buffer_offset = body_len > 0 ? offset : 0;

    if (vhttp_ipc_queue_push_wait_ms(&ipc->response_queue, &msg, VHTTP_IPC_QUEUE_WAIT_MS) != 0) {
        if (body_len > 0) {
            vhttp_ipc_ring_release(&ipc->ring, (uint32_t)body_len);
        }
        mp_raise_ValueError(MP_ERROR_TEXT("ws reject queue full"));
    }

    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(viperhttp_ws_reject_obj, 1, 3, viperhttp_ws_reject);

static mp_obj_t viperhttp_ws_send(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    enum {
        ARG_conn_id,
        ARG_data,
        ARG_opcode,
        ARG_final,
    };
    static const mp_arg_t allowed_args[] = {
        { MP_QSTR_conn_id, MP_ARG_REQUIRED | MP_ARG_INT, { .u_int = 0 } },
        { MP_QSTR_data, MP_ARG_REQUIRED | MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_opcode, MP_ARG_INT, { .u_int = 0 } },
        { MP_QSTR_final, MP_ARG_BOOL, { .u_bool = true } },
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    mp_int_t conn_id = args[ARG_conn_id].u_int;
    mp_obj_t data = args[ARG_data].u_obj;
    mp_int_t opcode = args[ARG_opcode].u_int;
    int final = args[ARG_final].u_bool ? 1 : 0;

    const uint8_t *ptr = NULL;
    size_t len = 0;
    vstr_t tmp;
    vstr_init(&tmp, 0);
    if (mp_obj_is_str(data)) {
        const char *s = mp_obj_str_get_data(data, &len);
        ptr = (const uint8_t *)s;
        if (opcode == 0) {
            opcode = 1;
        }
    } else if (mp_obj_is_type(data, &mp_type_bytes) || mp_obj_is_type(data, &mp_type_bytearray)) {
        mp_buffer_info_t bufinfo;
        mp_get_buffer_raise(data, &bufinfo, MP_BUFFER_READ);
        ptr = (const uint8_t *)bufinfo.buf;
        len = bufinfo.len;
        if (opcode == 0) {
            opcode = 2;
        }
    } else {
        mp_raise_TypeError(MP_ERROR_TEXT("data must be str/bytes"));
    }

    vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
    if (!ipc) {
        vstr_clear(&tmp);
        mp_raise_ValueError(MP_ERROR_TEXT("ipc unavailable"));
    }

    uint32_t offset = 0;
    uint8_t *dst = NULL;
    if (len > 0) {
        if (vhttp_ipc_ring_alloc_wait(&ipc->ring, (uint32_t)len, &offset, &dst) != 0) {
            vstr_clear(&tmp);
            mp_raise_ValueError(MP_ERROR_TEXT("ipc ring full"));
        }
        memcpy(dst, ptr, len);
    }

    vhttp_ipc_msg_t msg = {0};
    msg.request_id = (uint32_t)conn_id;
    msg.type = VHTTP_IPC_RESP_WS_MSG;
    msg.method = (uint8_t)opcode;
    msg.body_len = (uint32_t)len;
    msg.buffer_offset = len > 0 ? offset : 0;
    msg.flags = final ? VHTTP_IPC_FLAG_FINAL : 0;

    if (vhttp_ipc_queue_push_wait_ms(&ipc->response_queue, &msg, VHTTP_IPC_QUEUE_WAIT_MS) != 0) {
        if (len > 0) {
            vhttp_ipc_ring_release(&ipc->ring, (uint32_t)len);
        }
        mp_raise_ValueError(MP_ERROR_TEXT("ws send queue full"));
    }

    vstr_clear(&tmp);
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_KW(viperhttp_ws_send_obj, 2, viperhttp_ws_send);

static mp_obj_t viperhttp_ws_close(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    enum {
        ARG_conn_id,
        ARG_code,
        ARG_reason,
    };
    static const mp_arg_t allowed_args[] = {
        { MP_QSTR_conn_id, MP_ARG_REQUIRED | MP_ARG_INT, { .u_int = 0 } },
        { MP_QSTR_code, MP_ARG_INT, { .u_int = 1000 } },
        { MP_QSTR_reason, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    mp_int_t conn_id = args[ARG_conn_id].u_int;
    mp_int_t code = args[ARG_code].u_int;
    mp_obj_t reason = args[ARG_reason].u_obj;

    uint8_t reason_buf[125];
    size_t reason_len = 0;
    if (reason != mp_const_none) {
        if (mp_obj_is_str(reason)) {
            const char *s = mp_obj_str_get_data(reason, &reason_len);
            if (reason_len > sizeof(reason_buf) - 2) {
                reason_len = sizeof(reason_buf) - 2;
            }
            memcpy(reason_buf, s, reason_len);
        } else if (mp_obj_is_type(reason, &mp_type_bytes) || mp_obj_is_type(reason, &mp_type_bytearray)) {
            mp_buffer_info_t bufinfo;
            mp_get_buffer_raise(reason, &bufinfo, MP_BUFFER_READ);
            reason_len = bufinfo.len;
            if (reason_len > sizeof(reason_buf) - 2) {
                reason_len = sizeof(reason_buf) - 2;
            }
            memcpy(reason_buf, bufinfo.buf, reason_len);
        } else {
            mp_raise_TypeError(MP_ERROR_TEXT("reason must be str/bytes"));
        }
    }

    uint8_t payload[2 + sizeof(reason_buf)];
    payload[0] = (uint8_t)((code >> 8) & 0xff);
    payload[1] = (uint8_t)(code & 0xff);
    if (reason_len > 0) {
        memcpy(payload + 2, reason_buf, reason_len);
    }
    size_t payload_len = 2 + reason_len;

    vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
    if (!ipc) {
        mp_raise_ValueError(MP_ERROR_TEXT("ipc unavailable"));
    }

    uint32_t offset = 0;
    uint8_t *dst = NULL;
    if (payload_len > 0) {
        if (vhttp_ipc_ring_alloc_wait(&ipc->ring, (uint32_t)payload_len, &offset, &dst) != 0) {
            mp_raise_ValueError(MP_ERROR_TEXT("ipc ring full"));
        }
        memcpy(dst, payload, payload_len);
    }

    vhttp_ipc_msg_t msg = {0};
    msg.request_id = (uint32_t)conn_id;
    msg.type = VHTTP_IPC_RESP_WS_CLOSE;
    msg.status_code = (uint16_t)code;
    msg.body_len = (uint32_t)payload_len;
    msg.buffer_offset = payload_len > 0 ? offset : 0;

    if (vhttp_ipc_queue_push_wait_ms(&ipc->response_queue, &msg, VHTTP_IPC_QUEUE_WAIT_MS) != 0) {
        if (payload_len > 0) {
            vhttp_ipc_ring_release(&ipc->ring, (uint32_t)payload_len);
        }
        mp_raise_ValueError(MP_ERROR_TEXT("ws close queue full"));
    }

    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_KW(viperhttp_ws_close_obj, 1, viperhttp_ws_close);

static mp_obj_t viperhttp_set_worker_limits(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    enum {
        ARG_min_workers,
        ARG_max_workers,
    };
    static const mp_arg_t allowed_args[] = {
        { MP_QSTR_min_workers, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_max_workers, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    uint16_t min_workers = 0;
    uint16_t max_workers = 0;
    vhttp_server_get_worker_limits(&min_workers, &max_workers);

    if (args[ARG_min_workers].u_obj != mp_const_none) {
        mp_int_t value = mp_obj_get_int(args[ARG_min_workers].u_obj);
        if (value <= 0 || value > 65535) {
            mp_raise_ValueError(MP_ERROR_TEXT("min_workers out of range"));
        }
        min_workers = (uint16_t)value;
    }
    if (args[ARG_max_workers].u_obj != mp_const_none) {
        mp_int_t value = mp_obj_get_int(args[ARG_max_workers].u_obj);
        if (value <= 0 || value > 65535) {
            mp_raise_ValueError(MP_ERROR_TEXT("max_workers out of range"));
        }
        max_workers = (uint16_t)value;
    }

    int rc = vhttp_server_set_worker_limits(min_workers, max_workers);
    if (rc == -2) {
        mp_raise_OSError(MP_EBUSY);
    }
    if (rc != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("invalid worker limits"));
    }

    mp_obj_t out = mp_obj_new_dict(2);
    mp_obj_dict_store(out, mp_obj_new_str("min_workers", 11), mp_obj_new_int_from_uint(min_workers));
    mp_obj_dict_store(out, mp_obj_new_str("max_workers", 11), mp_obj_new_int_from_uint(max_workers));
    return out;
}
static MP_DEFINE_CONST_FUN_OBJ_KW(viperhttp_set_worker_limits_obj, 0, viperhttp_set_worker_limits);

static mp_obj_t viperhttp_get_worker_limits(void) {
    uint16_t min_workers = 0;
    uint16_t max_workers = 0;
    vhttp_server_get_worker_limits(&min_workers, &max_workers);
    mp_obj_t out = mp_obj_new_dict(2);
    mp_obj_dict_store(out, mp_obj_new_str("min_workers", 11), mp_obj_new_int_from_uint(min_workers));
    mp_obj_dict_store(out, mp_obj_new_str("max_workers", 11), mp_obj_new_int_from_uint(max_workers));
    return out;
}
static MP_DEFINE_CONST_FUN_OBJ_0(viperhttp_get_worker_limits_obj, viperhttp_get_worker_limits);

static int vhttp_extract_pem_arg(mp_obj_t obj, const char **out_ptr, size_t *out_len) {
    if (out_ptr) {
        *out_ptr = NULL;
    }
    if (out_len) {
        *out_len = 0;
    }
    if (obj == mp_const_none) {
        return -1;
    }
    if (mp_obj_is_str(obj)) {
        size_t len = 0;
        const char *ptr = mp_obj_str_get_data(obj, &len);
        if (!ptr || len == 0) {
            return -1;
        }
        if (out_ptr) {
            *out_ptr = ptr;
        }
        if (out_len) {
            *out_len = len;
        }
        return 0;
    }
    mp_buffer_info_t info;
    mp_get_buffer_raise(obj, &info, MP_BUFFER_READ);
    if (!info.buf || info.len == 0) {
        return -1;
    }
    if (out_ptr) {
        *out_ptr = (const char *)info.buf;
    }
    if (out_len) {
        *out_len = (size_t)info.len;
    }
    return 0;
}

static mp_obj_t viperhttp_configure_https(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    enum {
        ARG_https_enabled,
        ARG_cert_pem,
        ARG_key_pem,
    };
    static const mp_arg_t allowed_args[] = {
        { MP_QSTR_https_enabled, MP_ARG_BOOL, { .u_bool = false } },
        { MP_QSTR_cert_pem, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_key_pem, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    vhttp_https_config_t cfg = {0};
    cfg.enabled = args[ARG_https_enabled].u_bool ? 1u : 0u;
    if (cfg.enabled) {
        if (vhttp_extract_pem_arg(args[ARG_cert_pem].u_obj, &cfg.cert_pem, &cfg.cert_pem_len) != 0) {
            mp_raise_ValueError(MP_ERROR_TEXT("cert_pem required when https enabled"));
        }
        if (vhttp_extract_pem_arg(args[ARG_key_pem].u_obj, &cfg.key_pem, &cfg.key_pem_len) != 0) {
            mp_raise_ValueError(MP_ERROR_TEXT("key_pem required when https enabled"));
        }
    }

    int rc = vhttp_server_configure_https(&cfg);
    if (rc == -2) {
        mp_raise_OSError(MP_EBUSY);
    }
    if (rc != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("invalid https config"));
    }

    return mp_const_true;
}
static MP_DEFINE_CONST_FUN_OBJ_KW(viperhttp_configure_https_obj, 0, viperhttp_configure_https);

static mp_obj_t viperhttp_https_status(void) {
    uint8_t configured = 0;
    uint8_t active = 0;
    vhttp_server_get_https_status(&configured, &active);
    mp_obj_t out = mp_obj_new_dict(2);
    mp_obj_dict_store(out, MP_OBJ_NEW_QSTR(MP_QSTR_configured), mp_obj_new_bool(configured != 0));
    mp_obj_dict_store(out, MP_OBJ_NEW_QSTR(MP_QSTR_active), mp_obj_new_bool(active != 0));
    return out;
}
static MP_DEFINE_CONST_FUN_OBJ_0(viperhttp_https_status_obj, viperhttp_https_status);

static mp_obj_t viperhttp_configure_http2(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    enum {
        ARG_http2_enabled,
        ARG_max_streams,
    };
    static const mp_arg_t allowed_args[] = {
        { MP_QSTR_http2_enabled, MP_ARG_BOOL, { .u_bool = false } },
        { MP_QSTR_max_streams, MP_ARG_INT, { .u_int = 8 } },
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    int max_streams = args[ARG_max_streams].u_int;
    if (max_streams < 0 || max_streams > 64) {
        mp_raise_ValueError(MP_ERROR_TEXT("max_streams out of range"));
    }

    vhttp_http2_config_t cfg = {0};
    cfg.enabled = args[ARG_http2_enabled].u_bool ? 1u : 0u;
    cfg.max_streams = (uint16_t)max_streams;
    int rc = vhttp_server_configure_http2(&cfg);
    if (rc == -2) {
        mp_raise_OSError(MP_EBUSY);
    }
    if (rc != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("invalid http2 config"));
    }
    return mp_const_true;
}
static MP_DEFINE_CONST_FUN_OBJ_KW(viperhttp_configure_http2_obj, 0, viperhttp_configure_http2);

static mp_obj_t viperhttp_http2_status(void) {
    uint8_t configured = 0;
    uint8_t active = 0;
    vhttp_server_get_http2_status(&configured, &active);
    mp_obj_t out = mp_obj_new_dict(2);
    mp_obj_dict_store(out, MP_OBJ_NEW_QSTR(MP_QSTR_configured), mp_obj_new_bool(configured != 0));
    mp_obj_dict_store(out, MP_OBJ_NEW_QSTR(MP_QSTR_active), mp_obj_new_bool(active != 0));
    return out;
}
static MP_DEFINE_CONST_FUN_OBJ_0(viperhttp_http2_status_obj, viperhttp_http2_status);

static mp_obj_t viperhttp_start(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    enum {
        ARG_port,
        ARG_https,
        ARG_cert_pem,
        ARG_key_pem,
        ARG_http2,
        ARG_http2_max_streams,
    };
    static const mp_arg_t allowed_args[] = {
        { MP_QSTR_port, MP_ARG_INT, { .u_int = 8080 } },
        { MP_QSTR_https, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_cert_pem, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_key_pem, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_http2, MP_ARG_OBJ, { .u_rom_obj = MP_ROM_NONE } },
        { MP_QSTR_http2_max_streams, MP_ARG_INT, { .u_int = 8 } },
    };
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    int port = args[ARG_port].u_int;
    if (port <= 0 || port > 65535) {
        mp_raise_ValueError(MP_ERROR_TEXT("invalid port"));
    }

    if (args[ARG_https].u_obj != mp_const_none) {
        bool enable_https = mp_obj_is_true(args[ARG_https].u_obj);
        vhttp_https_config_t cfg = {0};
        cfg.enabled = enable_https ? 1u : 0u;
        if (cfg.enabled) {
            if (vhttp_extract_pem_arg(args[ARG_cert_pem].u_obj, &cfg.cert_pem, &cfg.cert_pem_len) != 0) {
                mp_raise_ValueError(MP_ERROR_TEXT("cert_pem required when https enabled"));
            }
            if (vhttp_extract_pem_arg(args[ARG_key_pem].u_obj, &cfg.key_pem, &cfg.key_pem_len) != 0) {
                mp_raise_ValueError(MP_ERROR_TEXT("key_pem required when https enabled"));
            }
        }
        int cfg_rc = vhttp_server_configure_https(&cfg);
        if (cfg_rc == -2) {
            return mp_const_false;
        }
        if (cfg_rc != 0) {
            mp_raise_ValueError(MP_ERROR_TEXT("invalid https config"));
        }
    } else if (args[ARG_cert_pem].u_obj != mp_const_none || args[ARG_key_pem].u_obj != mp_const_none) {
        mp_raise_ValueError(MP_ERROR_TEXT("set https flag when passing cert_pem/key_pem"));
    }

    if (args[ARG_http2].u_obj != mp_const_none) {
        bool enable_http2 = mp_obj_is_true(args[ARG_http2].u_obj);
        int max_streams = args[ARG_http2_max_streams].u_int;
        if (max_streams < 0 || max_streams > 64) {
            mp_raise_ValueError(MP_ERROR_TEXT("http2_max_streams out of range"));
        }
        vhttp_http2_config_t cfg = {0};
        cfg.enabled = enable_http2 ? 1u : 0u;
        cfg.max_streams = (uint16_t)max_streams;
        int cfg_rc = vhttp_server_configure_http2(&cfg);
        if (cfg_rc == -2) {
            return mp_const_false;
        }
        if (cfg_rc != 0) {
            mp_raise_ValueError(MP_ERROR_TEXT("invalid http2 config"));
        }
    } else if (args[ARG_http2_max_streams].u_int != 8) {
        mp_raise_ValueError(MP_ERROR_TEXT("set http2 flag when passing http2_max_streams"));
    }

    int rc = vhttp_server_start((uint16_t)port);
    if (rc == 0) {
        return mp_const_true;
    }
    if (rc == -1) {
        return mp_const_false;
    }
    mp_raise_OSError(MP_EIO);
}
static MP_DEFINE_CONST_FUN_OBJ_KW(viperhttp_start_obj, 0, viperhttp_start);

static mp_obj_t viperhttp_stop(void) {
    vhttp_server_stop();
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_0(viperhttp_stop_obj, viperhttp_stop);

static mp_obj_t viperhttp_is_running(void) {
    return mp_obj_new_bool(vhttp_server_is_running());
}
static MP_DEFINE_CONST_FUN_OBJ_0(viperhttp_is_running_obj, viperhttp_is_running);

static mp_obj_t viperhttp_ipc_stats(void) {
    vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
    mp_obj_t dict = mp_obj_new_dict(5);
    mp_obj_dict_store(dict, mp_obj_new_str("dropped_requests", 16), mp_obj_new_int_from_uint(ipc->dropped_requests));
    mp_obj_dict_store(dict, mp_obj_new_str("dropped_responses", 17), mp_obj_new_int_from_uint(ipc->dropped_responses));
    mp_obj_dict_store(dict, mp_obj_new_str("ring_full", 9), mp_obj_new_int_from_uint(ipc->ring_full));
    mp_obj_dict_store(dict, mp_obj_new_str("ring_size", 9), mp_obj_new_int_from_uint(vhttp_ipc_ring_capacity()));
    mp_obj_dict_store(dict, mp_obj_new_str("ring_psram", 10), mp_obj_new_bool(vhttp_ipc_ring_is_psram()));
    return dict;
}
static MP_DEFINE_CONST_FUN_OBJ_0(viperhttp_ipc_stats_obj, viperhttp_ipc_stats);

static mp_obj_t viperhttp_heap_stats(void) {
    mp_obj_t dict = mp_obj_new_dict(10);
#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
    multi_heap_info_t internal_info;
    memset(&internal_info, 0, sizeof(internal_info));
    heap_caps_get_info(&internal_info, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);

    multi_heap_info_t psram_info;
    memset(&psram_info, 0, sizeof(psram_info));
    heap_caps_get_info(&psram_info, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);

    size_t psram_total = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);
    mp_obj_dict_store(dict, mp_obj_new_str("psram_available", 15), mp_obj_new_bool(psram_total > 0));
    mp_obj_dict_store(dict, mp_obj_new_str("internal_total", 14), mp_obj_new_int_from_uint((mp_uint_t)internal_info.total_free_bytes + (mp_uint_t)(internal_info.total_allocated_bytes)));
    mp_obj_dict_store(dict, mp_obj_new_str("internal_free", 13), mp_obj_new_int_from_uint((mp_uint_t)internal_info.total_free_bytes));
    mp_obj_dict_store(dict, mp_obj_new_str("internal_largest", 16), mp_obj_new_int_from_uint((mp_uint_t)internal_info.largest_free_block));
    mp_obj_dict_store(dict, mp_obj_new_str("internal_min_free", 17), mp_obj_new_int_from_uint((mp_uint_t)internal_info.minimum_free_bytes));
    mp_obj_dict_store(dict, mp_obj_new_str("psram_total", 11), mp_obj_new_int_from_uint((mp_uint_t)psram_total));
    mp_obj_dict_store(dict, mp_obj_new_str("psram_free", 10), mp_obj_new_int_from_uint((mp_uint_t)psram_info.total_free_bytes));
    mp_obj_dict_store(dict, mp_obj_new_str("psram_largest", 13), mp_obj_new_int_from_uint((mp_uint_t)psram_info.largest_free_block));
    mp_obj_dict_store(dict, mp_obj_new_str("psram_min_free", 14), mp_obj_new_int_from_uint((mp_uint_t)psram_info.minimum_free_bytes));
#else
    mp_obj_dict_store(dict, mp_obj_new_str("psram_available", 15), mp_const_false);
    mp_obj_dict_store(dict, mp_obj_new_str("internal_total", 14), mp_obj_new_int(0));
    mp_obj_dict_store(dict, mp_obj_new_str("internal_free", 13), mp_obj_new_int(0));
    mp_obj_dict_store(dict, mp_obj_new_str("internal_largest", 16), mp_obj_new_int(0));
    mp_obj_dict_store(dict, mp_obj_new_str("internal_min_free", 17), mp_obj_new_int(0));
    mp_obj_dict_store(dict, mp_obj_new_str("psram_total", 11), mp_obj_new_int(0));
    mp_obj_dict_store(dict, mp_obj_new_str("psram_free", 10), mp_obj_new_int(0));
    mp_obj_dict_store(dict, mp_obj_new_str("psram_largest", 13), mp_obj_new_int(0));
    mp_obj_dict_store(dict, mp_obj_new_str("psram_min_free", 14), mp_obj_new_int(0));
#endif
    return dict;
}
static MP_DEFINE_CONST_FUN_OBJ_0(viperhttp_heap_stats_obj, viperhttp_heap_stats);

static mp_obj_t viperhttp_server_stats(void) {
    vhttp_server_stats_t stats;
    vhttp_server_get_stats(&stats);

    mp_obj_t dict = mp_obj_new_dict(47);
    mp_obj_dict_store(dict, mp_obj_new_str("accepts_total", 13), mp_obj_new_int_from_uint(stats.accepts_total));
    mp_obj_dict_store(dict, mp_obj_new_str("accepts_enqueued", 16), mp_obj_new_int_from_uint(stats.accepts_enqueued));
    mp_obj_dict_store(dict, mp_obj_new_str("accepts_rejected", 16), mp_obj_new_int_from_uint(stats.accepts_rejected));
    mp_obj_dict_store(dict, mp_obj_new_str("accept_queue_used", 17), mp_obj_new_int_from_uint(stats.accept_queue_used));
    mp_obj_dict_store(dict, mp_obj_new_str("accept_queue_peak", 17), mp_obj_new_int_from_uint(stats.accept_queue_peak));
    mp_obj_dict_store(dict, mp_obj_new_str("workers_active", 14), mp_obj_new_int_from_uint(stats.workers_active));
    mp_obj_dict_store(dict, mp_obj_new_str("workers_started", 15), mp_obj_new_int_from_uint(stats.workers_started));
    mp_obj_dict_store(dict, mp_obj_new_str("workers_limit_min", 17), mp_obj_new_int_from_uint(stats.workers_limit_min));
    mp_obj_dict_store(dict, mp_obj_new_str("workers_limit_max", 17), mp_obj_new_int_from_uint(stats.workers_limit_max));
    mp_obj_dict_store(dict, mp_obj_new_str("workers_recv_psram", 18), mp_obj_new_int_from_uint(stats.workers_recv_psram));
    mp_obj_dict_store(dict, mp_obj_new_str("workers_recv_ram", 16), mp_obj_new_int_from_uint(stats.workers_recv_ram));
    mp_obj_dict_store(dict, mp_obj_new_str("ws_handoffs", 11), mp_obj_new_int_from_uint(stats.ws_handoffs));
    mp_obj_dict_store(dict, mp_obj_new_str("ws_tasks_active", 15), mp_obj_new_int_from_uint(stats.ws_tasks_active));
    mp_obj_dict_store(dict, mp_obj_new_str("requests_handled", 16), mp_obj_new_int_from_uint(stats.requests_handled));
    mp_obj_dict_store(dict, mp_obj_new_str("requests_started", 16), mp_obj_new_int_from_uint(stats.requests_started));
    mp_obj_dict_store(dict, mp_obj_new_str("request_errors", 14), mp_obj_new_int_from_uint(stats.request_errors));
    mp_obj_dict_store(dict, mp_obj_new_str("ipc_req_ring_alloc_fail", 23), mp_obj_new_int_from_uint(stats.ipc_req_ring_alloc_fail));
    mp_obj_dict_store(dict, mp_obj_new_str("ipc_req_queue_push_fail", 23), mp_obj_new_int_from_uint(stats.ipc_req_queue_push_fail));
    mp_obj_dict_store(dict, mp_obj_new_str("backpressure_503_sent", 21), mp_obj_new_int_from_uint(stats.backpressure_503_sent));
    mp_obj_dict_store(dict, mp_obj_new_str("ipc_pending_dropped", 19), mp_obj_new_int_from_uint(stats.ipc_pending_dropped));
    mp_obj_dict_store(dict, mp_obj_new_str("ipc_pending_peak", 16), mp_obj_new_int_from_uint(stats.ipc_pending_peak));
    mp_obj_dict_store(dict, mp_obj_new_str("ipc_pending_used", 16), mp_obj_new_int_from_uint(stats.ipc_pending_used));
    mp_obj_dict_store(dict, mp_obj_new_str("ipc_wait_timeouts", 17), mp_obj_new_int_from_uint(stats.ipc_wait_timeouts));
    mp_obj_dict_store(dict, mp_obj_new_str("stream_chunks_sent", 18), mp_obj_new_int_from_uint(stats.stream_chunks_sent));
    mp_obj_dict_store(dict, mp_obj_new_str("scheduler_yields", 16), mp_obj_new_int_from_uint(stats.scheduler_yields));
    mp_obj_dict_store(dict, mp_obj_new_str("state_read_req_hits", 19), mp_obj_new_int_from_uint(stats.state_read_req_hits));
    mp_obj_dict_store(dict, mp_obj_new_str("state_wait_ipc_hits", 19), mp_obj_new_int_from_uint(stats.state_wait_ipc_hits));
    mp_obj_dict_store(dict, mp_obj_new_str("state_stream_hits", 17), mp_obj_new_int_from_uint(stats.state_stream_hits));
    mp_obj_dict_store(dict, mp_obj_new_str("event_loop_enabled", 18), mp_obj_new_int_from_uint(stats.event_loop_enabled));
    mp_obj_dict_store(dict, mp_obj_new_str("event_conn_active", 17), mp_obj_new_int_from_uint(stats.event_conn_active));
    mp_obj_dict_store(dict, mp_obj_new_str("event_conn_peak", 15), mp_obj_new_int_from_uint(stats.event_conn_peak));
    mp_obj_dict_store(dict, mp_obj_new_str("event_conn_dropped", 18), mp_obj_new_int_from_uint(stats.event_conn_dropped));
    mp_obj_dict_store(dict, mp_obj_new_str("event_state_accept_hits", 23), mp_obj_new_int_from_uint(stats.event_state_accept_hits));
    mp_obj_dict_store(dict, mp_obj_new_str("event_state_dispatched_hits", 27), mp_obj_new_int_from_uint(stats.event_state_dispatched_hits));
    mp_obj_dict_store(dict, mp_obj_new_str("event_state_closed_hits", 23), mp_obj_new_int_from_uint(stats.event_state_closed_hits));
    mp_obj_dict_store(dict, mp_obj_new_str("https_enabled", sizeof("https_enabled") - 1), mp_obj_new_int_from_uint(stats.https_enabled));
    mp_obj_dict_store(dict, mp_obj_new_str("https_handshake_ok", sizeof("https_handshake_ok") - 1), mp_obj_new_int_from_uint(stats.https_handshake_ok));
    mp_obj_dict_store(dict, mp_obj_new_str("https_handshake_fail", sizeof("https_handshake_fail") - 1), mp_obj_new_int_from_uint(stats.https_handshake_fail));
    mp_obj_dict_store(dict, mp_obj_new_str("http2_enabled", sizeof("http2_enabled") - 1), mp_obj_new_int_from_uint(stats.http2_enabled));
    mp_obj_dict_store(dict, mp_obj_new_str("http2_preface_seen", sizeof("http2_preface_seen") - 1), mp_obj_new_int_from_uint(stats.http2_preface_seen));
    mp_obj_dict_store(dict, mp_obj_new_str("http2_goaway_sent", sizeof("http2_goaway_sent") - 1), mp_obj_new_int_from_uint(stats.http2_goaway_sent));
    mp_obj_dict_store(dict, mp_obj_new_str("http2_rst_sent", sizeof("http2_rst_sent") - 1), mp_obj_new_int_from_uint(stats.http2_rst_sent));
    mp_obj_dict_store(dict, mp_obj_new_str("http2_err_protocol", sizeof("http2_err_protocol") - 1), mp_obj_new_int_from_uint(stats.http2_err_protocol));
    mp_obj_dict_store(dict, mp_obj_new_str("http2_err_flow_control", sizeof("http2_err_flow_control") - 1), mp_obj_new_int_from_uint(stats.http2_err_flow_control));
    mp_obj_dict_store(dict, mp_obj_new_str("http2_err_frame_size", sizeof("http2_err_frame_size") - 1), mp_obj_new_int_from_uint(stats.http2_err_frame_size));
    mp_obj_dict_store(dict, mp_obj_new_str("http2_err_compression", sizeof("http2_err_compression") - 1), mp_obj_new_int_from_uint(stats.http2_err_compression));
    mp_obj_dict_store(dict, mp_obj_new_str("http2_err_refused_stream", sizeof("http2_err_refused_stream") - 1), mp_obj_new_int_from_uint(stats.http2_err_refused_stream));
    mp_obj_dict_store(dict, mp_obj_new_str("http2_err_stream_closed", sizeof("http2_err_stream_closed") - 1), mp_obj_new_int_from_uint(stats.http2_err_stream_closed));
    mp_obj_dict_store(dict, mp_obj_new_str("http2_err_internal", sizeof("http2_err_internal") - 1), mp_obj_new_int_from_uint(stats.http2_err_internal));
    mp_obj_dict_store(dict, mp_obj_new_str("http2_err_http11_required", sizeof("http2_err_http11_required") - 1), mp_obj_new_int_from_uint(stats.http2_err_http11_required));
    mp_obj_dict_store(dict, mp_obj_new_str("http2_task_fallback_used", sizeof("http2_task_fallback_used") - 1), mp_obj_new_int_from_uint(stats.http2_task_fallback_used));
    mp_obj_dict_store(dict, mp_obj_new_str("http2_psram_slots", sizeof("http2_psram_slots") - 1), mp_obj_new_int_from_uint(stats.http2_psram_slots));
    mp_obj_dict_store(dict, mp_obj_new_str("mp_stream_backpressure_yield_hits", 33), mp_obj_new_int_from_uint(g_mp_stream_backpressure_yield_hits));
    mp_obj_dict_store(dict, mp_obj_new_str("mp_stream_backpressure_queue_hits", 33), mp_obj_new_int_from_uint(g_mp_stream_backpressure_queue_hits));
    mp_obj_dict_store(dict, mp_obj_new_str("mp_stream_backpressure_ring_hits", 32), mp_obj_new_int_from_uint(g_mp_stream_backpressure_ring_hits));
    mp_obj_dict_store(dict, mp_obj_new_str("mp_stream_backpressure_delay_ms_total", 37), mp_obj_new_int_from_uint(g_mp_stream_backpressure_delay_ms_total));
    return dict;
}
static MP_DEFINE_CONST_FUN_OBJ_0(viperhttp_server_stats_obj, viperhttp_server_stats);

static mp_obj_t viperhttp_server_stats_reset(void) {
    vhttp_server_reset_stats();
    g_mp_stream_backpressure_yield_hits = 0;
    g_mp_stream_backpressure_queue_hits = 0;
    g_mp_stream_backpressure_ring_hits = 0;
    g_mp_stream_backpressure_delay_ms_total = 0;
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_0(viperhttp_server_stats_reset_obj, viperhttp_server_stats_reset);

static mp_obj_t viperhttp_set_log_level(mp_obj_t level_obj) {
    uint8_t level = VHTTP_LOG_LEVEL_DEFAULT;
    if (mp_obj_is_int(level_obj)) {
        mp_int_t v = mp_obj_get_int(level_obj);
        if (v < (mp_int_t)VHTTP_LOG_LEVEL_OFF || v > (mp_int_t)VHTTP_LOG_LEVEL_TRACE) {
            mp_raise_ValueError(MP_ERROR_TEXT("log level out of range"));
        }
        level = (uint8_t)v;
    } else if (mp_obj_is_str(level_obj)) {
        size_t len = 0;
        const char *name = mp_obj_str_get_data(level_obj, &len);
        if (vhttp_log_level_from_name(name, len, &level) != 0) {
            mp_int_t parsed = 0;
            int all_digits = 1;
            if (len == 0) {
                all_digits = 0;
            }
            for (size_t i = 0; i < len; ++i) {
                if (name[i] < '0' || name[i] > '9') {
                    all_digits = 0;
                    break;
                }
                parsed = parsed * 10 + (name[i] - '0');
            }
            if (!all_digits || parsed < (mp_int_t)VHTTP_LOG_LEVEL_OFF || parsed > (mp_int_t)VHTTP_LOG_LEVEL_TRACE) {
                mp_raise_ValueError(MP_ERROR_TEXT("invalid log level"));
            }
            level = (uint8_t)parsed;
        }
    } else {
        mp_raise_TypeError(MP_ERROR_TEXT("log level must be int or str"));
    }

    vhttp_log_set_level(level);
    return mp_obj_new_int_from_uint(level);
}
static MP_DEFINE_CONST_FUN_OBJ_1(viperhttp_set_log_level_obj, viperhttp_set_log_level);

static mp_obj_t viperhttp_get_log_level(void) {
    uint8_t level = vhttp_log_get_level();
    const char *name = vhttp_log_level_name(level);
    mp_obj_t dict = mp_obj_new_dict(2);
    mp_obj_dict_store(dict, mp_obj_new_str("value", 5), mp_obj_new_int_from_uint(level));
    mp_obj_dict_store(dict, mp_obj_new_str("name", 4), mp_obj_new_str(name, strlen(name)));
    return dict;
}
static MP_DEFINE_CONST_FUN_OBJ_0(viperhttp_get_log_level_obj, viperhttp_get_log_level);

static const mp_rom_map_elem_t viperhttp_middleware_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_middleware) },
    { MP_ROM_QSTR(MP_QSTR_BaseHTTPMiddleware), MP_ROM_PTR(&vhttp_base_middleware_type) },
    { MP_ROM_QSTR(MP_QSTR_CORSMiddleware), MP_ROM_PTR(&vhttp_cors_middleware_type) },
    { MP_ROM_QSTR(MP_QSTR_RateLimitMiddleware), MP_ROM_PTR(&vhttp_ratelimit_middleware_type) },
    { MP_ROM_QSTR(MP_QSTR_TrustedHostMiddleware), MP_ROM_PTR(&vhttp_trusted_host_middleware_type) },
};
static MP_DEFINE_CONST_DICT(viperhttp_middleware_globals, viperhttp_middleware_globals_table);

const mp_obj_module_t viperhttp_middleware_module = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&viperhttp_middleware_globals,
};

static const mp_rom_map_elem_t viperhttp_module_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_viperhttp) },
    { MP_ROM_QSTR(MP_QSTR_version), MP_ROM_PTR(&viperhttp_version_obj) },
    { MP_ROM_QSTR(MP_QSTR_ViperHTTP), MP_ROM_PTR(&vhttp_app_type) },
    { MP_ROM_QSTR(MP_QSTR_Router), MP_ROM_PTR(&vhttp_router_type) },
    { MP_ROM_QSTR(MP_QSTR_Request), MP_ROM_PTR(&vhttp_request_type) },
    { MP_ROM_QSTR(MP_QSTR_BackgroundTasks), MP_ROM_PTR(&vhttp_background_tasks_type) },
    { MP_ROM_QSTR(MP_QSTR_BaseHTTPMiddleware), MP_ROM_PTR(&vhttp_base_middleware_type) },
    { MP_ROM_QSTR(MP_QSTR_middleware), MP_ROM_PTR(&viperhttp_middleware_module) },
    { MP_ROM_QSTR(MP_QSTR_active_app), MP_ROM_PTR(&viperhttp_active_app_obj) },
    { MP_ROM_QSTR(MP_QSTR_current_request), MP_ROM_PTR(&viperhttp_current_request_obj) },
    { MP_ROM_QSTR(MP_QSTR_set_current_request), MP_ROM_PTR(&viperhttp_set_current_request_obj) },
    { MP_ROM_QSTR(MP_QSTR_set_dep_resolver), MP_ROM_PTR(&viperhttp_set_dep_resolver_obj) },
    { MP_ROM_QSTR(MP_QSTR_reset), MP_ROM_PTR(&viperhttp_reset_obj) },
    { MP_ROM_QSTR(MP_QSTR_HTTPException), MP_ROM_PTR(&mp_type_HTTPException) },
    { MP_ROM_QSTR(MP_QSTR_Response), MP_ROM_PTR(&viperhttp_response_obj) },
    { MP_ROM_QSTR(MP_QSTR_JSONResponse), MP_ROM_PTR(&viperhttp_json_response_obj) },
    { MP_ROM_QSTR(MP_QSTR_StreamingResponse), MP_ROM_PTR(&viperhttp_streaming_response_obj) },
    { MP_ROM_QSTR(MP_QSTR_FileResponse), MP_ROM_PTR(&viperhttp_file_response_obj) },
    { MP_ROM_QSTR(MP_QSTR_TemplateResponse), MP_ROM_PTR(&viperhttp_template_response_obj) },
    { MP_ROM_QSTR(MP_QSTR_render_template), MP_ROM_PTR(&viperhttp_render_template_obj) },
    { MP_ROM_QSTR(MP_QSTR_template_clear_cache), MP_ROM_PTR(&viperhttp_template_clear_cache_obj) },
    { MP_ROM_QSTR(MP_QSTR_template_stats), MP_ROM_PTR(&viperhttp_template_stats_obj) },
    { MP_ROM_QSTR(MP_QSTR_router_stats), MP_ROM_PTR(&viperhttp_router_stats_obj) },
    { MP_ROM_QSTR(MP_QSTR_template_warmup), MP_ROM_PTR(&viperhttp_template_warmup_obj) },
    { MP_ROM_QSTR(MP_QSTR_template_debug), MP_ROM_PTR(&viperhttp_template_debug_obj) },
    { MP_ROM_QSTR(MP_QSTR_Depends), MP_ROM_PTR(&viperhttp_depends_obj) },
    { MP_ROM_QSTR(MP_QSTR_Query), MP_ROM_PTR(&viperhttp_query_obj) },
    { MP_ROM_QSTR(MP_QSTR_gzip_static), MP_ROM_PTR(&viperhttp_gzip_static_obj) },
    { MP_ROM_QSTR(MP_QSTR_fs_lock), MP_ROM_PTR(&viperhttp_fs_lock_obj) },
    { MP_ROM_QSTR(MP_QSTR_fs_unlock), MP_ROM_PTR(&viperhttp_fs_unlock_obj) },
    { MP_ROM_QSTR(MP_QSTR_poll_request), MP_ROM_PTR(&viperhttp_poll_request_obj) },
    { MP_ROM_QSTR(MP_QSTR_send_response), MP_ROM_PTR(&viperhttp_send_response_obj) },
    { MP_ROM_QSTR(MP_QSTR_stream_send), MP_ROM_PTR(&viperhttp_stream_send_obj) },
    { MP_ROM_QSTR(MP_QSTR_ws_accept), MP_ROM_PTR(&viperhttp_ws_accept_obj) },
    { MP_ROM_QSTR(MP_QSTR_ws_reject), MP_ROM_PTR(&viperhttp_ws_reject_obj) },
    { MP_ROM_QSTR(MP_QSTR_ws_send), MP_ROM_PTR(&viperhttp_ws_send_obj) },
    { MP_ROM_QSTR(MP_QSTR_ws_close), MP_ROM_PTR(&viperhttp_ws_close_obj) },
    { MP_ROM_QSTR(MP_QSTR_set_worker_limits), MP_ROM_PTR(&viperhttp_set_worker_limits_obj) },
    { MP_ROM_QSTR(MP_QSTR_get_worker_limits), MP_ROM_PTR(&viperhttp_get_worker_limits_obj) },
    { MP_ROM_QSTR(MP_QSTR_configure_https), MP_ROM_PTR(&viperhttp_configure_https_obj) },
    { MP_ROM_QSTR(MP_QSTR_https_status), MP_ROM_PTR(&viperhttp_https_status_obj) },
    { MP_ROM_QSTR(MP_QSTR_configure_http2), MP_ROM_PTR(&viperhttp_configure_http2_obj) },
    { MP_ROM_QSTR(MP_QSTR_http2_status), MP_ROM_PTR(&viperhttp_http2_status_obj) },
    { MP_ROM_QSTR(MP_QSTR_start), MP_ROM_PTR(&viperhttp_start_obj) },
    { MP_ROM_QSTR(MP_QSTR_stop), MP_ROM_PTR(&viperhttp_stop_obj) },
    { MP_ROM_QSTR(MP_QSTR_is_running), MP_ROM_PTR(&viperhttp_is_running_obj) },
    { MP_ROM_QSTR(MP_QSTR_ipc_stats), MP_ROM_PTR(&viperhttp_ipc_stats_obj) },
    { MP_ROM_QSTR(MP_QSTR_heap_stats), MP_ROM_PTR(&viperhttp_heap_stats_obj) },
    { MP_ROM_QSTR(MP_QSTR_server_stats), MP_ROM_PTR(&viperhttp_server_stats_obj) },
    { MP_ROM_QSTR(MP_QSTR_server_stats_reset), MP_ROM_PTR(&viperhttp_server_stats_reset_obj) },
    { MP_ROM_QSTR(MP_QSTR_set_log_level), MP_ROM_PTR(&viperhttp_set_log_level_obj) },
    { MP_ROM_QSTR(MP_QSTR_get_log_level), MP_ROM_PTR(&viperhttp_get_log_level_obj) },
    { MP_ROM_QSTR(MP_QSTR_LOG_OFF), MP_ROM_INT(VHTTP_LOG_LEVEL_OFF) },
    { MP_ROM_QSTR(MP_QSTR_LOG_ERROR), MP_ROM_INT(VHTTP_LOG_LEVEL_ERROR) },
    { MP_ROM_QSTR(MP_QSTR_LOG_WARN), MP_ROM_INT(VHTTP_LOG_LEVEL_WARN) },
    { MP_ROM_QSTR(MP_QSTR_LOG_INFO), MP_ROM_INT(VHTTP_LOG_LEVEL_INFO) },
    { MP_ROM_QSTR(MP_QSTR_LOG_DEBUG), MP_ROM_INT(VHTTP_LOG_LEVEL_DEBUG) },
    { MP_ROM_QSTR(MP_QSTR_LOG_TRACE), MP_ROM_INT(VHTTP_LOG_LEVEL_TRACE) },
};
static MP_DEFINE_CONST_DICT(viperhttp_module_globals, viperhttp_module_globals_table);

const mp_obj_module_t viperhttp_user_cmodule = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&viperhttp_module_globals,
};

MP_REGISTER_MODULE(MP_QSTR_viperhttp, viperhttp_user_cmodule);

#include "vhttp_cors.h"
#include "vhttp_router.h"

#include <string.h>
#include <stdio.h>

static vhttp_cors_config_t g_cors;

static int slice_ci_equals_n(const char *a, size_t a_len, const char *b) {
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

static const vhttp_header_t *find_header(const vhttp_parsed_request_t *req, const char *name) {
    if (!req || !name) {
        return NULL;
    }
    for (uint8_t i = 0; i < req->num_headers; ++i) {
        const vhttp_header_t *hdr = &req->headers[i];
        if (slice_ci_equals_n(hdr->name, hdr->name_len, name)) {
            return hdr;
        }
    }
    return NULL;
}

void vhttp_cors_reset(void) {
    memset(&g_cors, 0, sizeof(g_cors));
}

void vhttp_cors_configure(const vhttp_cors_config_t *cfg) {
    if (!cfg) {
        vhttp_cors_reset();
        return;
    }
    g_cors = *cfg;
    g_cors.enabled = 1;
}

int vhttp_cors_enabled(void) {
    return g_cors.enabled ? 1 : 0;
}

int vhttp_cors_get_origin(const vhttp_parsed_request_t *req, const char **out, size_t *out_len) {
    if (out) {
        *out = NULL;
    }
    if (out_len) {
        *out_len = 0;
    }
    if (!g_cors.enabled || !req) {
        return 0;
    }
    const vhttp_header_t *hdr = find_header(req, "origin");
    if (!hdr || !hdr->value || hdr->value_len == 0) {
        return 0;
    }
    if (out) {
        *out = hdr->value;
    }
    if (out_len) {
        *out_len = hdr->value_len;
    }
    return 1;
}

int vhttp_cors_origin_allowed(const char *origin, size_t origin_len) {
    if (!g_cors.enabled || !origin || origin_len == 0) {
        return 0;
    }
    if (g_cors.allow_origin_any) {
        return 1;
    }
    for (size_t i = 0; i < g_cors.origin_count; ++i) {
        const char *pat = g_cors.origins[i];
        size_t pat_len = strlen(pat);
        if (pat_len == 0) {
            continue;
        }
        if (pat[0] == '*') {
            if (pat_len == 1) {
                return 1;
            }
            size_t suffix_len = pat_len - 1;
            if (origin_len >= suffix_len &&
                memcmp(origin + (origin_len - suffix_len), pat + 1, suffix_len) == 0) {
                return 1;
            }
            continue;
        }
        if (pat_len == origin_len && memcmp(origin, pat, origin_len) == 0) {
            return 1;
        }
    }
    return 0;
}

int vhttp_cors_is_preflight(uint8_t method, const vhttp_parsed_request_t *req) {
    if (!g_cors.enabled || !req) {
        return 0;
    }
    if (method != VHTTP_METHOD_OPTIONS) {
        return 0;
    }
    const vhttp_header_t *hdr = find_header(req, "access-control-request-method");
    if (!hdr || !hdr->value || hdr->value_len == 0) {
        return 0;
    }
    return 1;
}

size_t vhttp_cors_build_headers(
    char *dst,
    size_t dst_len,
    const vhttp_parsed_request_t *req,
    const char *origin,
    size_t origin_len,
    int preflight
) {
    if (!dst || dst_len == 0 || !g_cors.enabled || !origin || origin_len == 0) {
        return 0;
    }

    const char *allow_origin_ptr = origin;
    size_t allow_origin_len = origin_len;
    int vary = 0;
    if (g_cors.allow_origin_any && !g_cors.allow_credentials) {
        allow_origin_ptr = "*";
        allow_origin_len = 1;
    } else {
        vary = 1;
    }

    size_t off = 0;
    int n = snprintf(dst + off, dst_len - off,
        "Access-Control-Allow-Origin: %.*s\r\n",
        (int)allow_origin_len, allow_origin_ptr);
    if (n < 0 || (size_t)n >= dst_len - off) {
        dst[0] = '\0';
        return 0;
    }
    off += (size_t)n;

    if (g_cors.allow_credentials) {
        n = snprintf(dst + off, dst_len - off,
            "Access-Control-Allow-Credentials: true\r\n");
        if (n < 0 || (size_t)n >= dst_len - off) {
            dst[0] = '\0';
            return 0;
        }
        off += (size_t)n;
        vary = 1;
    }

    if (g_cors.expose_headers[0] != '\0') {
        n = snprintf(dst + off, dst_len - off,
            "Access-Control-Expose-Headers: %s\r\n",
            g_cors.expose_headers);
        if (n < 0 || (size_t)n >= dst_len - off) {
            dst[0] = '\0';
            return 0;
        }
        off += (size_t)n;
    }

    if (preflight) {
        const char *methods = g_cors.allow_methods[0] ? g_cors.allow_methods : VHTTP_CORS_DEFAULT_METHODS;
        n = snprintf(dst + off, dst_len - off,
            "Access-Control-Allow-Methods: %s\r\n",
            methods);
        if (n < 0 || (size_t)n >= dst_len - off) {
            dst[0] = '\0';
            return 0;
        }
        off += (size_t)n;

        const char *allow_headers_ptr = g_cors.allow_headers;
        size_t allow_headers_len = strlen(g_cors.allow_headers);
        if (g_cors.allow_headers_any) {
            const vhttp_header_t *hdr = find_header(req, "access-control-request-headers");
            if (hdr && hdr->value && hdr->value_len > 0 && g_cors.allow_credentials) {
                allow_headers_ptr = hdr->value;
                allow_headers_len = hdr->value_len;
            } else {
                allow_headers_ptr = "*";
                allow_headers_len = 1;
            }
        }

        n = snprintf(dst + off, dst_len - off,
            "Access-Control-Allow-Headers: %.*s\r\n",
            (int)allow_headers_len, allow_headers_ptr);
        if (n < 0 || (size_t)n >= dst_len - off) {
            dst[0] = '\0';
            return 0;
        }
        off += (size_t)n;

        if (g_cors.max_age > 0) {
            n = snprintf(dst + off, dst_len - off,
                "Access-Control-Max-Age: %lu\r\n",
                (unsigned long)g_cors.max_age);
            if (n < 0 || (size_t)n >= dst_len - off) {
                dst[0] = '\0';
                return 0;
            }
            off += (size_t)n;
        }
    }

    if (vary) {
        n = snprintf(dst + off, dst_len - off, "Vary: Origin\r\n");
        if (n < 0 || (size_t)n >= dst_len - off) {
            dst[0] = '\0';
            return 0;
        }
        off += (size_t)n;
    }

    if (off < dst_len) {
        dst[off] = '\0';
    } else {
        dst[dst_len - 1] = '\0';
    }
    return off;
}

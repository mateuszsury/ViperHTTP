#include "vhttp_trusted_host.h"
#include "vhttp_config.h"
#include "vhttp_parser.h"

#include <string.h>

static vhttp_trusted_host_config_t g_trusted;

static int slice_ci_equals_n(const char *a, size_t a_len, const char *b, size_t b_len) {
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

static int slice_ci_endswith(const char *a, size_t a_len, const char *suffix, size_t suffix_len) {
    if (a_len < suffix_len) {
        return 0;
    }
    return slice_ci_equals_n(a + (a_len - suffix_len), suffix_len, suffix, suffix_len);
}

static const vhttp_header_t *find_header(const vhttp_parsed_request_t *req, const char *name) {
    if (!req || !name) {
        return NULL;
    }
    size_t name_len = strlen(name);
    for (uint8_t i = 0; i < req->num_headers; ++i) {
        const vhttp_header_t *hdr = &req->headers[i];
        if (slice_ci_equals_n(hdr->name, hdr->name_len, name, name_len)) {
            return hdr;
        }
    }
    return NULL;
}

void vhttp_trusted_host_reset(void) {
    memset(&g_trusted, 0, sizeof(g_trusted));
}

void vhttp_trusted_host_defaults(vhttp_trusted_host_config_t *cfg) {
    if (!cfg) {
        return;
    }
    memset(cfg, 0, sizeof(*cfg));
    cfg->enabled = 1;
    cfg->allow_any = 1;
}

void vhttp_trusted_host_configure(const vhttp_trusted_host_config_t *cfg) {
    if (!cfg) {
        vhttp_trusted_host_reset();
        return;
    }
    g_trusted = *cfg;
    if (g_trusted.allow_any) {
        g_trusted.enabled = 1;
        return;
    }
    if (g_trusted.host_count == 0) {
        vhttp_trusted_host_reset();
        return;
    }
    g_trusted.enabled = 1;
}

int vhttp_trusted_host_enabled(void) {
    return g_trusted.enabled ? 1 : 0;
}

int vhttp_trusted_host_allowed(const vhttp_parsed_request_t *req) {
    if (!g_trusted.enabled) {
        return 1;
    }
    if (g_trusted.allow_any) {
        return 1;
    }
    const vhttp_header_t *hdr = find_header(req, "host");
    if (!hdr || !hdr->value || hdr->value_len == 0) {
        return 0;
    }

    const char *value = hdr->value;
    size_t len = hdr->value_len;
    while (len > 0 && (*value == ' ' || *value == '\t')) {
        value++;
        len--;
    }
    while (len > 0 && (value[len - 1] == ' ' || value[len - 1] == '\t')) {
        len--;
    }
    if (len == 0) {
        return 0;
    }

    const char *full_ptr = value;
    size_t full_len = len;
    const char *host_ptr = value;
    size_t host_len = len;
    const char *bracket_ptr = NULL;
    size_t bracket_len = 0;
    int is_ipv6 = 0;

    if (value[0] == '[') {
        size_t close = 0;
        int found = 0;
        for (size_t i = 1; i < len; ++i) {
            if (value[i] == ']') {
                close = i;
                found = 1;
                break;
            }
        }
        if (!found || close <= 1) {
            return 0;
        }
        is_ipv6 = 1;
        host_ptr = value + 1;
        host_len = close - 1;
        bracket_ptr = value;
        bracket_len = close + 1;
    } else {
        for (size_t i = 0; i < len; ++i) {
            if (value[i] == ':') {
                host_len = i;
                break;
            }
        }
    }

    if (host_len == 0) {
        return 0;
    }

    for (uint8_t i = 0; i < g_trusted.host_count; ++i) {
        const char *allowed = g_trusted.hosts[i];
        size_t allowed_len = strlen(allowed);
        if (allowed_len == 0) {
            continue;
        }
        if (allowed_len == 1 && allowed[0] == '*') {
            return 1;
        }
        if (allowed_len > 2 && allowed[0] == '*' && allowed[1] == '.') {
            const char *suffix = allowed + 2;
            size_t suffix_len = allowed_len - 2;
            if (host_len > suffix_len &&
                host_ptr[host_len - suffix_len - 1] == '.' &&
                slice_ci_endswith(host_ptr, host_len, suffix, suffix_len)) {
                return 1;
            }
            continue;
        }

        if (allowed[0] == '[') {
            const char *close = strchr(allowed, ']');
            if (!close) {
                continue;
            }
            size_t bracketed_len = (size_t)(close - allowed + 1);
            int has_port = 0;
            if (allowed_len > bracketed_len && allowed[bracketed_len] == ':') {
                has_port = 1;
            }
            if (has_port) {
                if (slice_ci_equals_n(full_ptr, full_len, allowed, allowed_len)) {
                    return 1;
                }
            } else if (is_ipv6) {
                if (bracket_ptr && slice_ci_equals_n(bracket_ptr, bracket_len, allowed, allowed_len)) {
                    return 1;
                }
                if (slice_ci_equals_n(host_ptr, host_len, allowed + 1, allowed_len - 2)) {
                    return 1;
                }
            }
            continue;
        }

        if (strchr(allowed, ':')) {
            if (slice_ci_equals_n(full_ptr, full_len, allowed, allowed_len)) {
                return 1;
            }
            continue;
        }

        if (slice_ci_equals_n(host_ptr, host_len, allowed, allowed_len)) {
            return 1;
        }
    }

    return 0;
}

#include "vhttp_parser.h"

#include <string.h>

static int ascii_tolower(int c) {
    if (c >= 'A' && c <= 'Z') {
        return c + ('a' - 'A');
    }
    return c;
}

static int slice_ci_equals(const char *a, size_t a_len, const char *b) {
    size_t b_len = strlen(b);
    if (a_len != b_len) {
        return 0;
    }
    for (size_t i = 0; i < a_len; ++i) {
        if (ascii_tolower((unsigned char)a[i]) != ascii_tolower((unsigned char)b[i])) {
            return 0;
        }
    }
    return 1;
}

static int slice_ci_contains(const char *haystack, size_t hay_len, const char *needle) {
    size_t needle_len = strlen(needle);
    if (needle_len == 0 || hay_len < needle_len) {
        return 0;
    }
    for (size_t i = 0; i + needle_len <= hay_len; ++i) {
        size_t j = 0;
        for (; j < needle_len; ++j) {
            if (ascii_tolower((unsigned char)haystack[i + j]) != ascii_tolower((unsigned char)needle[j])) {
                break;
            }
        }
        if (j == needle_len) {
            return 1;
        }
    }
    return 0;
}

static const char *find_crlf(const char *p, const char *end) {
    for (const char *cur = p; cur + 1 < end; ++cur) {
        if (cur[0] == '\r' && cur[1] == '\n') {
            return cur;
        }
    }
    return NULL;
}

static int parse_content_length(const char *value, size_t len, uint32_t *out_len) {
    if (len == 0) {
        return -1;
    }
    uint32_t acc = 0;
    size_t i = 0;
    for (; i < len; ++i) {
        char c = value[i];
        if (c >= '0' && c <= '9') {
            uint32_t digit = (uint32_t)(c - '0');
            if (acc > (UINT32_MAX - digit) / 10) {
                return -1;
            }
            acc = acc * 10 + digit;
        } else if (c == ' ' || c == '\t') {
            break;
        } else {
            return -1;
        }
    }

    if (i == 0) {
        return -1;
    }

    for (; i < len; ++i) {
        char c = value[i];
        if (c != ' ' && c != '\t') {
            return -1;
        }
    }

    *out_len = acc;
    return 0;
}

static vhttp_parse_result_t parse_query_params(const char *ptr, size_t len, vhttp_parsed_request_t *out) {
    if (len == 0) {
        return VHTTP_PARSE_OK;
    }

    const char *cur = ptr;
    const char *end = ptr + len;

    while (cur < end) {
        const char *amp = memchr(cur, '&', (size_t)(end - cur));
        const char *segment_end = amp ? amp : end;
        const char *eq = memchr(cur, '=', (size_t)(segment_end - cur));

        const char *key_ptr = cur;
        size_t key_len = eq ? (size_t)(eq - cur) : (size_t)(segment_end - cur);
        const char *value_ptr = NULL;
        size_t value_len = 0;
        uint8_t has_value = 0;

        if (eq) {
            has_value = 1;
            value_ptr = eq + 1;
            value_len = (size_t)(segment_end - (eq + 1));
        }

        if (key_len > 0 || has_value) {
            if (out->num_query_params >= VHTTP_MAX_QUERY_PARAMS) {
                return VHTTP_PARSE_TOO_LARGE;
            }

            vhttp_kv_t *kv = &out->query_params[out->num_query_params++];
            kv->key.ptr = key_ptr;
            kv->key.len = (uint16_t)key_len;
            kv->value.ptr = value_ptr ? value_ptr : "";
            kv->value.len = (uint16_t)value_len;
            kv->has_value = has_value;
        }

        if (!amp) {
            break;
        }
        cur = amp + 1;
    }

    return VHTTP_PARSE_OK;
}

vhttp_parse_result_t vhttp_parse_request(
    const char *buf,
    size_t len,
    vhttp_parsed_request_t *out
) {
    if (!buf || !out || len == 0) {
        return VHTTP_PARSE_INCOMPLETE;
    }

    memset(out, 0, sizeof(*out));

    const char *end = buf + len;
    const char *line_end = find_crlf(buf, end);
    if (!line_end) {
        return VHTTP_PARSE_INCOMPLETE;
    }

    const char *sp1 = memchr(buf, ' ', (size_t)(line_end - buf));
    if (!sp1 || sp1 == buf) {
        return VHTTP_PARSE_INVALID;
    }
    const char *sp2 = memchr(sp1 + 1, ' ', (size_t)(line_end - (sp1 + 1)));
    if (!sp2 || sp2 == sp1 + 1) {
        return VHTTP_PARSE_INVALID;
    }

    const char *method_ptr = buf;
    size_t method_len = (size_t)(sp1 - buf);
    const char *uri_ptr = sp1 + 1;
    size_t uri_len = (size_t)(sp2 - (sp1 + 1));
    const char *version_ptr = sp2 + 1;
    size_t version_len = (size_t)(line_end - version_ptr);

    if (method_len == 0 || uri_len == 0 || version_len == 0) {
        return VHTTP_PARSE_INVALID;
    }
    if (uri_len > VHTTP_MAX_URI_LEN) {
        return VHTTP_PARSE_TOO_LARGE;
    }
    if (version_len != 8 || memcmp(version_ptr, "HTTP/1.1", 8) != 0) {
        return VHTTP_PARSE_INVALID;
    }

    out->method.ptr = method_ptr;
    out->method.len = (uint16_t)method_len;
    out->uri.ptr = uri_ptr;
    out->uri.len = (uint16_t)uri_len;

    const char *qmark = memchr(uri_ptr, '?', uri_len);
    if (qmark) {
        out->path.ptr = uri_ptr;
        out->path.len = (uint16_t)(qmark - uri_ptr);
        out->query.ptr = qmark + 1;
        out->query.len = (uint16_t)(uri_ptr + uri_len - (qmark + 1));
    } else {
        out->path.ptr = uri_ptr;
        out->path.len = (uint16_t)uri_len;
        out->query.ptr = "";
        out->query.len = 0;
    }

    const char *p = line_end + 2;
    size_t header_bytes_total = 0;
    uint8_t saw_content_length = 0;
    uint32_t content_length = 0;

    while (1) {
        if (p >= end) {
            return VHTTP_PARSE_INCOMPLETE;
        }
        if (p + 1 < end && p[0] == '\r' && p[1] == '\n') {
            p += 2;
            break;
        }

        const char *hdr_end = find_crlf(p, end);
        if (!hdr_end) {
            return VHTTP_PARSE_INCOMPLETE;
        }

        size_t line_len = (size_t)(hdr_end - p);
        header_bytes_total += line_len;
        if (header_bytes_total > VHTTP_MAX_HEADER_SIZE) {
            return VHTTP_PARSE_TOO_LARGE;
        }

        const char *colon = memchr(p, ':', line_len);
        if (!colon || colon == p) {
            return VHTTP_PARSE_INVALID;
        }

        const char *name_ptr = p;
        size_t name_len = (size_t)(colon - p);

        const char *value_ptr = colon + 1;
        while (value_ptr < hdr_end && (*value_ptr == ' ' || *value_ptr == '\t')) {
            value_ptr++;
        }
        size_t value_len = (size_t)(hdr_end - value_ptr);

        if (out->num_headers >= VHTTP_MAX_HEADERS) {
            return VHTTP_PARSE_TOO_LARGE;
        }

        vhttp_header_t *hdr = &out->headers[out->num_headers++];
        hdr->name = name_ptr;
        hdr->name_len = (uint8_t)name_len;
        hdr->value = value_ptr;
        hdr->value_len = (uint16_t)value_len;

        if (slice_ci_equals(name_ptr, name_len, "content-length")) {
            uint32_t parsed = 0;
            if (parse_content_length(value_ptr, value_len, &parsed) != 0) {
                return VHTTP_PARSE_INVALID;
            }
            if (saw_content_length && parsed != content_length) {
                return VHTTP_PARSE_INVALID;
            }
            saw_content_length = 1;
            content_length = parsed;
        } else if (slice_ci_equals(name_ptr, name_len, "transfer-encoding")) {
            if (slice_ci_contains(value_ptr, value_len, "chunked")) {
                out->is_chunked = 1;
            }
        } else if (slice_ci_equals(name_ptr, name_len, "upgrade")) {
            if (slice_ci_contains(value_ptr, value_len, "websocket")) {
                out->is_websocket = 1;
            }
        }

        p = hdr_end + 2;
    }

    out->content_length = content_length;

    vhttp_parse_result_t qres = parse_query_params(out->query.ptr, out->query.len, out);
    if (qres != VHTTP_PARSE_OK) {
        return qres;
    }

    if (out->is_chunked) {
        return VHTTP_PARSE_UNSUPPORTED;
    }

    if (out->content_length > VHTTP_MAX_BODY_SIZE) {
        return VHTTP_PARSE_TOO_LARGE;
    }

    size_t remaining = (size_t)(end - p);
    if (out->content_length > 0) {
        if (remaining < out->content_length) {
            return VHTTP_PARSE_INCOMPLETE;
        }
        out->body = p;
        out->body_len = out->content_length;
    } else {
        out->body = NULL;
        out->body_len = 0;
    }

    out->total_len = (uint32_t)((p - buf) + out->body_len);

    return VHTTP_PARSE_OK;
}

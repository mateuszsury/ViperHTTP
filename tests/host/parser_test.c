#include <stdio.h>
#include <string.h>

#include "vhttp_parser.h"
#include "parser_vectors.h"

static int slice_equals(vhttp_slice_t slice, const char *expected) {
    size_t exp_len = strlen(expected);
    if (slice.len != exp_len) {
        return 0;
    }
    if (exp_len == 0) {
        return 1;
    }
    if (!slice.ptr) {
        return 0;
    }
    return memcmp(slice.ptr, expected, exp_len) == 0;
}

static int header_equals(const vhttp_header_t *got, const vhttp_expect_header_t *exp) {
    size_t name_len = strlen(exp->name);
    size_t value_len = strlen(exp->value);

    if (got->name_len != name_len || got->value_len != value_len) {
        return 0;
    }
    if (name_len > 0 && memcmp(got->name, exp->name, name_len) != 0) {
        return 0;
    }
    if (value_len > 0 && memcmp(got->value, exp->value, value_len) != 0) {
        return 0;
    }
    return 1;
}

static int query_equals(const vhttp_kv_t *got, const vhttp_expect_query_t *exp) {
    size_t key_len = strlen(exp->key);
    size_t value_len = strlen(exp->value);

    if (got->key.len != key_len) {
        return 0;
    }
    if (key_len > 0 && memcmp(got->key.ptr, exp->key, key_len) != 0) {
        return 0;
    }

    if ((got->has_value ? 1 : 0) != (exp->has_value ? 1 : 0)) {
        return 0;
    }
    if (exp->has_value) {
        if (got->value.len != value_len) {
            return 0;
        }
        if (value_len > 0 && memcmp(got->value.ptr, exp->value, value_len) != 0) {
            return 0;
        }
    }
    return 1;
}

static int check_ok_case(const vhttp_test_case_t *tc, const vhttp_parsed_request_t *req) {
    if (!slice_equals(req->method, tc->method)) {
        return 0;
    }
    if (!slice_equals(req->uri, tc->uri)) {
        return 0;
    }
    if (!slice_equals(req->path, tc->path)) {
        return 0;
    }
    if (!slice_equals(req->query, tc->query)) {
        return 0;
    }

    if (req->num_headers != tc->num_headers) {
        return 0;
    }
    for (size_t i = 0; i < tc->num_headers; ++i) {
        if (!header_equals(&req->headers[i], &tc->headers[i])) {
            return 0;
        }
    }

    if (req->num_query_params != tc->num_query_params) {
        return 0;
    }
    for (size_t i = 0; i < tc->num_query_params; ++i) {
        if (!query_equals(&req->query_params[i], &tc->query_params[i])) {
            return 0;
        }
    }

    if (req->content_length != tc->content_length) {
        return 0;
    }
    if (req->is_chunked != tc->is_chunked) {
        return 0;
    }
    if (req->is_websocket != tc->is_websocket) {
        return 0;
    }

    if (req->body_len != tc->body_len) {
        return 0;
    }
    if (tc->body_len > 0) {
        if (!req->body) {
            return 0;
        }
        if (memcmp(req->body, tc->body, tc->body_len) != 0) {
            return 0;
        }
    }

    return 1;
}

int main(void) {
    size_t passed = 0;
    size_t failed = 0;

    for (size_t i = 0; i < vhttp_test_case_count; ++i) {
        const vhttp_test_case_t *tc = &vhttp_test_cases[i];
        vhttp_parsed_request_t req;
        memset(&req, 0, sizeof(req));

        vhttp_parse_result_t result = vhttp_parse_request(tc->raw, tc->raw_len, &req);

        if (result != tc->result) {
            printf("[FAIL] %s: expected result %d got %d\n", tc->name, (int)tc->result, (int)result);
            failed++;
            continue;
        }

        if (result == VHTTP_PARSE_OK) {
            if (!check_ok_case(tc, &req)) {
                printf("[FAIL] %s: content mismatch\n", tc->name);
                failed++;
                continue;
            }
        }

        passed++;
    }

    printf("Parser tests: %zu passed, %zu failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}

#include <stdio.h>
#include <string.h>

#include "vhttp_router.h"
#include "router_vectors.h"

static const char *result_name(vhttp_router_result_t result) {
    switch (result) {
        case VHTTP_ROUTER_OK: return "OK";
        case VHTTP_ROUTER_NOT_FOUND: return "NOT_FOUND";
        case VHTTP_ROUTER_ERR_INVALID: return "INVALID";
        case VHTTP_ROUTER_ERR_CONFLICT: return "CONFLICT";
        case VHTTP_ROUTER_ERR_FULL: return "FULL";
        case VHTTP_ROUTER_ERR_UNSUPPORTED: return "UNSUPPORTED";
        case VHTTP_ROUTER_ERR_TOO_LARGE: return "TOO_LARGE";
        default: return "UNKNOWN";
    }
}

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

static int check_params(const vhttp_match_t *match, const vhttp_expect_param_t *params, size_t num_params) {
    if (match->num_params != num_params) {
        return 0;
    }
    for (size_t i = 0; i < num_params; ++i) {
        const vhttp_path_param_t *got = &match->params[i];
        const vhttp_expect_param_t *exp = &params[i];
        if (!slice_equals(got->name, exp->name)) {
            return 0;
        }
        if (!slice_equals(got->value, exp->value)) {
            return 0;
        }
        if (got->type != exp->type) {
            return 0;
        }
    }
    return 1;
}

int main(void) {
    size_t passed = 0;
    size_t failed = 0;

    for (size_t i = 0; i < vhttp_router_case_count; ++i) {
        const vhttp_router_case_t *tc = &vhttp_router_cases[i];
        vhttp_router_t router;
        vhttp_router_init(&router);

        for (size_t r = 0; r < tc->num_routes; ++r) {
            const vhttp_route_case_t *route = &tc->routes[r];
            vhttp_route_target_t target = {0};
            target.handler_id = route->handler;
            vhttp_router_result_t res = vhttp_router_add(
                &router,
                route->method,
                strlen(route->method),
                route->pattern,
                strlen(route->pattern),
                target
            );
            if (res != route->result) {
                printf("[FAIL] %s add route %zu: expected %s got %s\n",
                       tc->name, r, result_name(route->result), result_name(res));
                failed++;
            }
        }

        for (size_t q = 0; q < tc->num_queries; ++q) {
            const vhttp_query_case_t *query = &tc->queries[q];
            vhttp_match_t match;
            vhttp_slice_t path = {query->path, (uint16_t)strlen(query->path)};
            vhttp_router_result_t res = vhttp_router_match(
                &router,
                query->method,
                strlen(query->method),
                path,
                &match
            );
            if (res != query->result) {
                printf("[FAIL] %s query %zu: expected %s got %s\n",
                       tc->name, q, result_name(query->result), result_name(res));
                failed++;
                continue;
            }
            if (res == VHTTP_ROUTER_OK) {
                if (match.target.handler_id != query->handler) {
                    printf("[FAIL] %s query %zu: handler mismatch expected %u got %u\n",
                           tc->name, q, query->handler, match.target.handler_id);
                    failed++;
                    continue;
                }
                if (!check_params(&match, query->params, query->num_params)) {
                    printf("[FAIL] %s query %zu: params mismatch\n", tc->name, q);
                    failed++;
                    continue;
                }
            }
        }

        passed++;
    }

    printf("Router tests: %zu cases passed, %zu failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}

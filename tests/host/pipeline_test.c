#include <stdio.h>
#include <string.h>

#include "vhttp_server.h"

static int starts_with(const char *buf, size_t len, const char *prefix) {
    size_t prefix_len = strlen(prefix);
    if (len < prefix_len) {
        return 0;
    }
    return memcmp(buf, prefix, prefix_len) == 0;
}

static int contains_body(const char *buf, size_t len, const char *body) {
    size_t body_len = strlen(body);
    if (body_len == 0) {
        return 1;
    }
    if (len < body_len) {
        return 0;
    }
    const char *start = buf + (len - body_len);
    return memcmp(start, body, body_len) == 0;
}

int main(void) {
    vhttp_router_t router;
    vhttp_router_init(&router);

    vhttp_route_target_t target = {0};
    target.handler_id = 42;
    if (vhttp_router_add(&router, "GET", 3, "/hello", 6, target) != VHTTP_ROUTER_OK) {
        printf("[FAIL] add route\n");
        return 1;
    }

    char response[512];
    size_t resp_len = 0;

    const char *req_ok = "GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n";
    vhttp_handle_result_t res = vhttp_handle_request(
        &router,
        req_ok,
        strlen(req_ok),
        response,
        sizeof(response),
        &resp_len
    );

    if (res != VHTTP_HANDLE_OK || !starts_with(response, resp_len, "HTTP/1.1 200 OK")) {
        printf("[FAIL] expected 200 OK\n");
        return 1;
    }
    if (!contains_body(response, resp_len, "OK")) {
        printf("[FAIL] expected body OK\n");
        return 1;
    }

    const char *req_404 = "GET /missing HTTP/1.1\r\nHost: example.com\r\n\r\n";
    res = vhttp_handle_request(&router, req_404, strlen(req_404), response, sizeof(response), &resp_len);
    if (res != VHTTP_HANDLE_OK || !starts_with(response, resp_len, "HTTP/1.1 404 Not Found")) {
        printf("[FAIL] expected 404\n");
        return 1;
    }

    const char *req_bad = "GET /bad\r\nHost: example.com\r\n\r\n";
    res = vhttp_handle_request(&router, req_bad, strlen(req_bad), response, sizeof(response), &resp_len);
    if (res != VHTTP_HANDLE_OK || !starts_with(response, resp_len, "HTTP/1.1 400 Bad Request")) {
        printf("[FAIL] expected 400\n");
        return 1;
    }

    const char *req_chunked = "POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";
    res = vhttp_handle_request(&router, req_chunked, strlen(req_chunked), response, sizeof(response), &resp_len);
    if (res != VHTTP_HANDLE_OK || !starts_with(response, resp_len, "HTTP/1.1 501 Not Implemented")) {
        printf("[FAIL] expected 501\n");
        return 1;
    }

    const char *req_large = "POST /big HTTP/1.1\r\nHost: example.com\r\nContent-Length: 70000\r\n\r\n";
    res = vhttp_handle_request(&router, req_large, strlen(req_large), response, sizeof(response), &resp_len);
    if (res != VHTTP_HANDLE_OK || !starts_with(response, resp_len, "HTTP/1.1 413 Payload Too Large")) {
        printf("[FAIL] expected 413\n");
        return 1;
    }

    printf("Pipeline tests: OK\n");
    return 0;
}

#include "vhttp_server.h"

#include <stdio.h>
#include <string.h>

static vhttp_handle_result_t write_response(
    char *out,
    size_t cap,
    int status,
    const char *reason,
    const char *body,
    size_t body_len,
    size_t *out_len
) {
    if (!out || !out_len || !reason || !body) {
        return VHTTP_HANDLE_ERROR;
    }

    int header_len = snprintf(
        out,
        cap,
        "HTTP/1.1 %d %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
        status,
        reason,
        body_len
    );

    if (header_len < 0) {
        return VHTTP_HANDLE_ERROR;
    }

    size_t total = (size_t)header_len + body_len;
    if (total > cap) {
        return VHTTP_HANDLE_OUTPUT_TOO_SMALL;
    }

    if (body_len > 0) {
        memcpy(out + header_len, body, body_len);
    }

    *out_len = total;
    return VHTTP_HANDLE_OK;
}

void vhttp_server_init(vhttp_server_t *server) {
    if (!server) {
        return;
    }
    vhttp_router_init(&server->router);
    vhttp_pool_init(&server->pool);
}

vhttp_handle_result_t vhttp_handle_request(
    const vhttp_router_t *router,
    const char *req_buf,
    size_t req_len,
    char *resp_buf,
    size_t resp_cap,
    size_t *resp_len
) {
    if (!router || !req_buf || !resp_buf || !resp_len) {
        return VHTTP_HANDLE_ERROR;
    }

    vhttp_parsed_request_t req;
    vhttp_parse_result_t pres = vhttp_parse_request(req_buf, req_len, &req);

    if (pres == VHTTP_PARSE_INCOMPLETE) {
        return VHTTP_HANDLE_INCOMPLETE;
    }

    if (pres != VHTTP_PARSE_OK) {
        int status = 400;
        const char *reason = "Bad Request";
        const char *body = "Bad Request";

        if (pres == VHTTP_PARSE_TOO_LARGE) {
            status = 413;
            reason = "Payload Too Large";
            body = "Payload Too Large";
        } else if (pres == VHTTP_PARSE_UNSUPPORTED) {
            status = 501;
            reason = "Not Implemented";
            body = "Not Implemented";
        }

        return write_response(resp_buf, resp_cap, status, reason, body, strlen(body), resp_len);
    }

    vhttp_match_t match;
    vhttp_router_result_t mres = vhttp_router_match(
        router,
        req.method.ptr,
        req.method.len,
        req.path,
        &match
    );

    if (mres != VHTTP_ROUTER_OK) {
        const char *reason = "Not Found";
        return write_response(resp_buf, resp_cap, 404, reason, reason, strlen(reason), resp_len);
    }

    const char *body = "OK";
    return write_response(resp_buf, resp_cap, 200, "OK", body, strlen(body), resp_len);
}

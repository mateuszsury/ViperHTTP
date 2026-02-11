#ifndef VHTTP_CONNECTION_H
#define VHTTP_CONNECTION_H

#include <stddef.h>
#include <stdint.h>

#include "vhttp_config.h"
#include "vhttp_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    VHTTP_CONN_IDLE = 0,
    VHTTP_CONN_READING,
    VHTTP_CONN_PROCESSING,
    VHTTP_CONN_WRITING,
    VHTTP_CONN_CLOSED
} vhttp_conn_state_t;

typedef enum {
    VHTTP_CONN_FLAG_KEEPALIVE = 1 << 0,
    VHTTP_CONN_FLAG_WEBSOCKET = 1 << 1,
    VHTTP_CONN_FLAG_SSE = 1 << 2
} vhttp_conn_flags_t;

typedef struct {
    int sockfd;
    uint32_t last_activity;
    uint16_t requests_served;
    uint8_t state;
    uint8_t flags;
    uint8_t pool_index;

    vhttp_parsed_request_t current_req;

    uint8_t *recv_buf;
    uint8_t *send_buf;
    size_t recv_pos;
    size_t send_pos;
    size_t send_len;
} vhttp_conn_t;

typedef struct {
    vhttp_conn_t connections[VHTTP_MAX_CONNECTIONS];
    uint8_t recv_bufs[VHTTP_MAX_CONNECTIONS][VHTTP_RECV_BUF_SIZE];
    uint8_t send_bufs[VHTTP_MAX_CONNECTIONS][VHTTP_SEND_BUF_SIZE];
    uint32_t free_mask;
} vhttp_pool_t;

void vhttp_pool_init(vhttp_pool_t *pool);

vhttp_conn_t *vhttp_pool_alloc(vhttp_pool_t *pool);

void vhttp_pool_free(vhttp_pool_t *pool, vhttp_conn_t *conn);

void vhttp_conn_reset(vhttp_conn_t *conn);

#ifdef __cplusplus
}
#endif

#endif // VHTTP_CONNECTION_H

#include "vhttp_connection.h"

#include <string.h>

#if VHTTP_MAX_CONNECTIONS > 32
#error "VHTTP_MAX_CONNECTIONS > 32 is not supported by the current pool implementation"
#endif

static uint32_t make_free_mask(void) {
    if (VHTTP_MAX_CONNECTIONS >= 32) {
        return 0xFFFFFFFFu;
    }
    return (uint32_t)((1u << VHTTP_MAX_CONNECTIONS) - 1u);
}

static int find_free_index(uint32_t mask) {
    if (mask == 0) {
        return -1;
    }
    for (int i = 0; i < VHTTP_MAX_CONNECTIONS; ++i) {
        if (mask & (1u << i)) {
            return i;
        }
    }
    return -1;
}

void vhttp_conn_reset(vhttp_conn_t *conn) {
    if (!conn) {
        return;
    }
    uint8_t *recv_buf = conn->recv_buf;
    uint8_t *send_buf = conn->send_buf;
    uint8_t pool_index = conn->pool_index;
    memset(conn, 0, sizeof(*conn));
    conn->recv_buf = recv_buf;
    conn->send_buf = send_buf;
    conn->pool_index = pool_index;
    conn->sockfd = -1;
    conn->state = VHTTP_CONN_IDLE;
}

void vhttp_pool_init(vhttp_pool_t *pool) {
    if (!pool) {
        return;
    }
    memset(pool, 0, sizeof(*pool));
    pool->free_mask = make_free_mask();

    for (uint8_t i = 0; i < VHTTP_MAX_CONNECTIONS; ++i) {
        vhttp_conn_t *conn = &pool->connections[i];
        conn->pool_index = i;
        conn->recv_buf = pool->recv_bufs[i];
        conn->send_buf = pool->send_bufs[i];
        vhttp_conn_reset(conn);
    }
}

vhttp_conn_t *vhttp_pool_alloc(vhttp_pool_t *pool) {
    if (!pool) {
        return NULL;
    }
    int idx = find_free_index(pool->free_mask);
    if (idx < 0) {
        return NULL;
    }
    pool->free_mask &= ~(1u << idx);
    vhttp_conn_t *conn = &pool->connections[idx];
    vhttp_conn_reset(conn);
    return conn;
}

void vhttp_pool_free(vhttp_pool_t *pool, vhttp_conn_t *conn) {
    if (!pool || !conn) {
        return;
    }
    uint8_t idx = conn->pool_index;
    if (idx >= VHTTP_MAX_CONNECTIONS) {
        return;
    }
    pool->free_mask |= (1u << idx);
    vhttp_conn_reset(conn);
}

#include <stdio.h>
#include <string.h>

#include "vhttp_connection.h"

static int pointer_unique(void **ptrs, size_t count, void *candidate) {
    for (size_t i = 0; i < count; ++i) {
        if (ptrs[i] == candidate) {
            return 0;
        }
    }
    return 1;
}

int main(void) {
    vhttp_pool_t pool;
    vhttp_pool_init(&pool);

    vhttp_conn_t *conns[VHTTP_MAX_CONNECTIONS];
    void *recv_ptrs[VHTTP_MAX_CONNECTIONS];
    void *send_ptrs[VHTTP_MAX_CONNECTIONS];

    memset(conns, 0, sizeof(conns));
    memset(recv_ptrs, 0, sizeof(recv_ptrs));
    memset(send_ptrs, 0, sizeof(send_ptrs));

    for (uint8_t i = 0; i < VHTTP_MAX_CONNECTIONS; ++i) {
        conns[i] = vhttp_pool_alloc(&pool);
        if (!conns[i]) {
            printf("[FAIL] alloc %u returned NULL\n", i);
            return 1;
        }
        if (!pointer_unique(recv_ptrs, i, conns[i]->recv_buf)) {
            printf("[FAIL] recv buffer reused at %u\n", i);
            return 1;
        }
        if (!pointer_unique(send_ptrs, i, conns[i]->send_buf)) {
            printf("[FAIL] send buffer reused at %u\n", i);
            return 1;
        }
        recv_ptrs[i] = conns[i]->recv_buf;
        send_ptrs[i] = conns[i]->send_buf;
    }

    if (vhttp_pool_alloc(&pool) != NULL) {
        printf("[FAIL] pool alloc should fail when full\n");
        return 1;
    }

    vhttp_pool_free(&pool, conns[0]);
    vhttp_conn_t *again = vhttp_pool_alloc(&pool);
    if (!again) {
        printf("[FAIL] alloc after free returned NULL\n");
        return 1;
    }

    printf("Pool tests: OK\n");
    return 0;
}

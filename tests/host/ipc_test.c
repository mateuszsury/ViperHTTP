#include <stdio.h>

#include "vhttp_ipc.h"

static void expect(int cond, const char *msg) {
    if (!cond) {
        printf("[FAIL] %s\n", msg);
    }
}

int main(void) {
    uint8_t buffer[32];
    vhttp_ipc_ring_t ring;

    vhttp_ipc_ring_init(&ring, buffer, sizeof(buffer));

    uint32_t off1 = 0;
    uint8_t *ptr1 = NULL;
    if (vhttp_ipc_ring_alloc(&ring, 10, &off1, &ptr1) != 0) {
        printf("[FAIL] alloc 1\n");
        return 1;
    }

    uint32_t off2 = 0;
    uint8_t *ptr2 = NULL;
    if (vhttp_ipc_ring_alloc(&ring, 8, &off2, &ptr2) != 0) {
        printf("[FAIL] alloc 2\n");
        return 1;
    }

    if (ring.used != 18) {
        printf("[FAIL] used expected 18 got %u\n", ring.used);
        return 1;
    }

    vhttp_ipc_ring_release(&ring, 10);
    if (ring.used != 8) {
        printf("[FAIL] release expected 8 got %u\n", ring.used);
        return 1;
    }

    uint32_t off3 = 0;
    uint8_t *ptr3 = NULL;
    if (vhttp_ipc_ring_alloc(&ring, 12, &off3, &ptr3) != 0) {
        printf("[FAIL] alloc 3\n");
        return 1;
    }

    if (off3 == 0 && ring.head == 12) {
        // wrapped allocation
    } else if (off3 == 18 && ring.head == 30) {
        // contiguous allocation
    } else {
        printf("[FAIL] unexpected wrap state off3=%u head=%u\n", off3, ring.head);
        return 1;
    }

    uint32_t off4 = 0;
    uint8_t *ptr4 = NULL;
    if (vhttp_ipc_ring_alloc(&ring, 20, &off4, &ptr4) == 0) {
        printf("[FAIL] alloc 4 should fail\n");
        return 1;
    }

    vhttp_ipc_ring_release(&ring, 8);
    vhttp_ipc_ring_release(&ring, 12);

    if (ring.used != 0) {
        printf("[FAIL] expected empty ring\n");
        return 1;
    }

    vhttp_ipc_queue_t queue;
    vhttp_ipc_msg_t items[2];
    vhttp_ipc_queue_init(&queue, items, 2);

    vhttp_ipc_msg_t msg1 = {0};
    msg1.request_id = 1;
    vhttp_ipc_msg_t msg2 = {0};
    msg2.request_id = 2;

    expect(vhttp_ipc_queue_push(&queue, &msg1) == 0, "queue push 1");
    expect(vhttp_ipc_queue_push(&queue, &msg2) == 0, "queue push 2");
    expect(vhttp_ipc_queue_push(&queue, &msg2) != 0, "queue full");

    vhttp_ipc_msg_t out = {0};
    expect(vhttp_ipc_queue_pop(&queue, &out) == 0, "queue pop 1");
    expect(out.request_id == 1, "queue order 1");
    expect(vhttp_ipc_queue_pop(&queue, &out) == 0, "queue pop 2");
    expect(out.request_id == 2, "queue order 2");
    expect(vhttp_ipc_queue_pop(&queue, &out) != 0, "queue empty");

    printf("IPC ring tests: OK\n");
    return 0;
}

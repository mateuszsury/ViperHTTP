#ifndef VHTTP_IPC_H
#define VHTTP_IPC_H

#include <stddef.h>
#include <stdint.h>

#include "vhttp_config.h"

#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    VHTTP_IPC_REQ_HTTP = 0,
    VHTTP_IPC_REQ_WS_CONNECT,
    VHTTP_IPC_REQ_WS_MSG,
    VHTTP_IPC_REQ_WS_DISCONNECT,
    VHTTP_IPC_RESP_HTTP,
    VHTTP_IPC_RESP_WS_ACCEPT,
    VHTTP_IPC_RESP_WS_REJECT,
    VHTTP_IPC_RESP_WS_MSG,
    VHTTP_IPC_RESP_WS_CLOSE
} vhttp_ipc_type_t;

typedef enum {
    VHTTP_IPC_FLAG_NONE = 0,
    VHTTP_IPC_FLAG_GZIP_OK = 1 << 0,
    VHTTP_IPC_FLAG_KEEPALIVE = 1 << 1,
    VHTTP_IPC_FLAG_CHUNKED = 1 << 2,
    VHTTP_IPC_FLAG_STREAM = 1 << 3,
    VHTTP_IPC_FLAG_FINAL = 1 << 4,
    VHTTP_IPC_FLAG_RELEASE = 1 << 5
} vhttp_ipc_flags_t;

typedef struct {
    uint32_t request_id;
    uint8_t type;
    uint8_t method;
    uint16_t status_code;
    uint16_t uri_len;
    uint16_t query_len;
    uint16_t headers_len;
    uint32_t headers_offset;
    uint32_t body_len;
    uint32_t total_len;
    uint32_t buffer_offset;
    uint8_t flags;
} vhttp_ipc_msg_t;

typedef struct {
    uint8_t *buf;
    uint32_t size;
    uint32_t head;
    uint32_t tail;
    uint32_t used;
} vhttp_ipc_ring_t;

#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
typedef struct {
    QueueHandle_t handle;
} vhttp_ipc_queue_t;
#else
typedef struct {
    vhttp_ipc_msg_t *items;
    uint16_t capacity;
    uint16_t head;
    uint16_t tail;
    uint16_t count;
} vhttp_ipc_queue_t;
#endif

typedef struct {
    vhttp_ipc_ring_t ring;
    vhttp_ipc_queue_t request_queue;
    vhttp_ipc_queue_t response_queue;
    uint32_t dropped_requests;
    uint32_t dropped_responses;
    uint32_t ring_full;
#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
    StaticQueue_t request_queue_storage;
    StaticQueue_t response_queue_storage;
    uint8_t request_queue_buf[VHTTP_IPC_REQUEST_QUEUE_LEN * sizeof(vhttp_ipc_msg_t)];
    uint8_t response_queue_buf[VHTTP_IPC_RESPONSE_QUEUE_LEN * sizeof(vhttp_ipc_msg_t)];
#else
    vhttp_ipc_msg_t request_items[VHTTP_IPC_REQUEST_QUEUE_LEN];
    vhttp_ipc_msg_t response_items[VHTTP_IPC_RESPONSE_QUEUE_LEN];
#endif
} vhttp_ipc_state_t;

void vhttp_ipc_queue_init(vhttp_ipc_queue_t *queue, vhttp_ipc_msg_t *items, uint16_t capacity);

int vhttp_ipc_queue_push(vhttp_ipc_queue_t *queue, const vhttp_ipc_msg_t *msg);

int vhttp_ipc_queue_pop(vhttp_ipc_queue_t *queue, vhttp_ipc_msg_t *out);

int vhttp_ipc_queue_pop_wait(vhttp_ipc_queue_t *queue, vhttp_ipc_msg_t *out, uint32_t timeout_ms);

int vhttp_ipc_queue_push_wait(vhttp_ipc_queue_t *queue, const vhttp_ipc_msg_t *msg, uint32_t timeout_ms);

uint32_t vhttp_ipc_queue_count(const vhttp_ipc_queue_t *queue);

uint32_t vhttp_ipc_queue_capacity(const vhttp_ipc_queue_t *queue);

void vhttp_ipc_ring_init(vhttp_ipc_ring_t *ring, uint8_t *buffer, uint32_t size);

int vhttp_ipc_ring_alloc(
    vhttp_ipc_ring_t *ring,
    uint32_t len,
    uint32_t *offset,
    uint8_t **ptr
);

void vhttp_ipc_ring_release(vhttp_ipc_ring_t *ring, uint32_t len);

uint8_t *vhttp_ipc_ring_ptr(vhttp_ipc_ring_t *ring, uint32_t offset);

uint32_t vhttp_ipc_ring_used(const vhttp_ipc_ring_t *ring);

uint32_t vhttp_ipc_ring_capacity(void);

uint8_t vhttp_ipc_ring_is_psram(void);

vhttp_ipc_state_t *vhttp_ipc_default_state(void);

#ifdef __cplusplus
}
#endif

#endif // VHTTP_IPC_H

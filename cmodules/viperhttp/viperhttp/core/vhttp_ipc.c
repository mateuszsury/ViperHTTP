#include "vhttp_ipc.h"

#include <string.h>

#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
#include "esp_attr.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/portmacro.h"

static DRAM_ATTR uint8_t g_ipc_ring_buffer_static[VHTTP_IPC_RINGBUF_SIZE];
static uint8_t *g_ipc_ring_buffer = g_ipc_ring_buffer_static;
static uint32_t g_ipc_ring_buffer_size = VHTTP_IPC_RINGBUF_SIZE;
static uint8_t g_ipc_ring_buffer_psram = 0;
static DRAM_ATTR vhttp_ipc_state_t g_ipc_state;
static portMUX_TYPE g_ipc_ring_mux = portMUX_INITIALIZER_UNLOCKED;
#else
static uint8_t g_ipc_ring_buffer_static[VHTTP_IPC_RINGBUF_SIZE];
static uint8_t *g_ipc_ring_buffer = g_ipc_ring_buffer_static;
static uint32_t g_ipc_ring_buffer_size = VHTTP_IPC_RINGBUF_SIZE;
static uint8_t g_ipc_ring_buffer_psram = 0;
static vhttp_ipc_state_t g_ipc_state;
#endif
static uint8_t g_ipc_inited = 0;

static void ipc_record_queue_drop(vhttp_ipc_queue_t *queue) {
    if (queue == &g_ipc_state.request_queue) {
        g_ipc_state.dropped_requests++;
    } else if (queue == &g_ipc_state.response_queue) {
        g_ipc_state.dropped_responses++;
    }
}

static void ipc_record_ring_full(vhttp_ipc_ring_t *ring) {
    if (ring == &g_ipc_state.ring) {
        g_ipc_state.ring_full++;
    }
}

void vhttp_ipc_queue_init(vhttp_ipc_queue_t *queue, vhttp_ipc_msg_t *items, uint16_t capacity) {
#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
    (void)queue;
    (void)items;
    (void)capacity;
#else
    if (!queue || !items || capacity == 0) {
        return;
    }
    queue->items = items;
    queue->capacity = capacity;
    queue->head = 0;
    queue->tail = 0;
    queue->count = 0;
#endif
}

int vhttp_ipc_queue_push(vhttp_ipc_queue_t *queue, const vhttp_ipc_msg_t *msg) {
    if (!queue || !msg) {
        return -1;
    }
#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
    if (queue->handle == NULL) {
        ipc_record_queue_drop(queue);
        return -1;
    }
    if (xQueueSend(queue->handle, msg, 0) == pdTRUE) {
        return 0;
    }
    ipc_record_queue_drop(queue);
    return -1;
#else
    if (queue->count >= queue->capacity) {
        ipc_record_queue_drop(queue);
        return -1;
    }
    queue->items[queue->head] = *msg;
    queue->head = (uint16_t)((queue->head + 1) % queue->capacity);
    queue->count++;
    return 0;
#endif
}

int vhttp_ipc_queue_pop(vhttp_ipc_queue_t *queue, vhttp_ipc_msg_t *out) {
    if (!queue || !out) {
        return -1;
    }
#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
    if (queue->handle == NULL) {
        return -1;
    }
    return xQueueReceive(queue->handle, out, 0) == pdTRUE ? 0 : -1;
#else
    if (queue->count == 0) {
        return -1;
    }
    *out = queue->items[queue->tail];
    queue->tail = (uint16_t)((queue->tail + 1) % queue->capacity);
    queue->count--;
    return 0;
#endif
}

int vhttp_ipc_queue_pop_wait(vhttp_ipc_queue_t *queue, vhttp_ipc_msg_t *out, uint32_t timeout_ms) {
    if (!queue || !out) {
        return -1;
    }
#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
    if (queue->handle == NULL) {
        return -1;
    }
    TickType_t ticks = timeout_ms == 0 ? 0 : pdMS_TO_TICKS(timeout_ms);
    return xQueueReceive(queue->handle, out, ticks) == pdTRUE ? 0 : -1;
#else
    (void)timeout_ms;
    return vhttp_ipc_queue_pop(queue, out);
#endif
}

int vhttp_ipc_queue_push_wait(vhttp_ipc_queue_t *queue, const vhttp_ipc_msg_t *msg, uint32_t timeout_ms) {
    if (!queue || !msg) {
        return -1;
    }
#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
    if (queue->handle == NULL) {
        ipc_record_queue_drop(queue);
        return -1;
    }
    TickType_t ticks = timeout_ms == 0 ? 0 : pdMS_TO_TICKS(timeout_ms);
    if (xQueueSend(queue->handle, msg, ticks) == pdTRUE) {
        return 0;
    }
    ipc_record_queue_drop(queue);
    return -1;
#else
    (void)timeout_ms;
    return vhttp_ipc_queue_push(queue, msg);
#endif
}

uint32_t vhttp_ipc_queue_count(const vhttp_ipc_queue_t *queue) {
    if (!queue) {
        return 0;
    }
#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
    if (queue->handle == NULL) {
        return 0;
    }
    return (uint32_t)uxQueueMessagesWaiting(queue->handle);
#else
    return (uint32_t)queue->count;
#endif
}

uint32_t vhttp_ipc_queue_capacity(const vhttp_ipc_queue_t *queue) {
    if (!queue) {
        return 0;
    }
#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
    if (queue->handle == NULL) {
        return 0;
    }
    return (uint32_t)uxQueueMessagesWaiting(queue->handle) + (uint32_t)uxQueueSpacesAvailable(queue->handle);
#else
    return (uint32_t)queue->capacity;
#endif
}

void vhttp_ipc_ring_init(vhttp_ipc_ring_t *ring, uint8_t *buffer, uint32_t size) {
    if (!ring || !buffer || size == 0) {
        return;
    }
    ring->buf = buffer;
    ring->size = size;
    ring->head = 0;
    ring->tail = 0;
    ring->used = 0;
}

int vhttp_ipc_ring_alloc(
    vhttp_ipc_ring_t *ring,
    uint32_t len,
    uint32_t *offset,
    uint8_t **ptr
) {
    if (!ring || !offset || !ptr) {
        return -1;
    }
    if (len == 0 || len > ring->size) {
        return -1;
    }

#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
    portENTER_CRITICAL(&g_ipc_ring_mux);
#endif
    uint32_t free_space = ring->size - ring->used;
    if (len > free_space) {
#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
        portEXIT_CRITICAL(&g_ipc_ring_mux);
#endif
        ipc_record_ring_full(ring);
        return -1;
    }

    if (ring->head + len <= ring->size) {
        *offset = ring->head;
        *ptr = ring->buf + ring->head;
        ring->head += len;
        ring->used += len;
        if (ring->head == ring->size) {
            ring->head = 0;
        }
#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
        portEXIT_CRITICAL(&g_ipc_ring_mux);
#endif
        return 0;
    }

    if (ring->tail > len) {
        *offset = 0;
        *ptr = ring->buf;
        ring->head = len;
        ring->used += len;
#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
        portEXIT_CRITICAL(&g_ipc_ring_mux);
#endif
        return 0;
    }

#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
    portEXIT_CRITICAL(&g_ipc_ring_mux);
#endif
    ipc_record_ring_full(ring);
    return -1;
}

void vhttp_ipc_ring_release(vhttp_ipc_ring_t *ring, uint32_t len) {
    if (!ring || len == 0 || len > ring->used) {
        return;
    }

#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
    portENTER_CRITICAL(&g_ipc_ring_mux);
#endif
    ring->tail += len;
    ring->used -= len;

    if (ring->tail >= ring->size) {
        ring->tail %= ring->size;
    }

    if (ring->used == 0) {
        ring->head = ring->tail;
    }
#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
    portEXIT_CRITICAL(&g_ipc_ring_mux);
#endif
}

uint8_t *vhttp_ipc_ring_ptr(vhttp_ipc_ring_t *ring, uint32_t offset) {
    if (!ring || offset >= ring->size) {
        return NULL;
    }
    return ring->buf + offset;
}

uint32_t vhttp_ipc_ring_used(const vhttp_ipc_ring_t *ring) {
    if (!ring) {
        return 0;
    }
#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
    uint32_t used = 0;
    portENTER_CRITICAL(&g_ipc_ring_mux);
    used = ring->used;
    portEXIT_CRITICAL(&g_ipc_ring_mux);
    return used;
#else
    return ring->used;
#endif
}

uint32_t vhttp_ipc_ring_capacity(void) {
    return g_ipc_ring_buffer_size;
}

uint8_t vhttp_ipc_ring_is_psram(void) {
    return g_ipc_ring_buffer_psram;
}

vhttp_ipc_state_t *vhttp_ipc_default_state(void) {
    if (!g_ipc_inited) {
        memset(&g_ipc_state, 0, sizeof(g_ipc_state));
#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
#if VHTTP_IPC_USE_PSRAM
        if (heap_caps_get_free_size(MALLOC_CAP_SPIRAM) >= VHTTP_IPC_RINGBUF_SIZE_PSRAM) {
            uint8_t *psram_buf = (uint8_t *)heap_caps_malloc(
                VHTTP_IPC_RINGBUF_SIZE_PSRAM,
                MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT
            );
            if (psram_buf) {
                g_ipc_ring_buffer = psram_buf;
                g_ipc_ring_buffer_size = VHTTP_IPC_RINGBUF_SIZE_PSRAM;
                g_ipc_ring_buffer_psram = 1;
            }
        }
#endif
#endif
        vhttp_ipc_ring_init(&g_ipc_state.ring, g_ipc_ring_buffer, g_ipc_ring_buffer_size);
#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
        g_ipc_state.request_queue.handle = xQueueCreateStatic(
            VHTTP_IPC_REQUEST_QUEUE_LEN,
            sizeof(vhttp_ipc_msg_t),
            g_ipc_state.request_queue_buf,
            &g_ipc_state.request_queue_storage
        );
        g_ipc_state.response_queue.handle = xQueueCreateStatic(
            VHTTP_IPC_RESPONSE_QUEUE_LEN,
            sizeof(vhttp_ipc_msg_t),
            g_ipc_state.response_queue_buf,
            &g_ipc_state.response_queue_storage
        );
#else
        vhttp_ipc_queue_init(&g_ipc_state.request_queue, g_ipc_state.request_items, VHTTP_IPC_REQUEST_QUEUE_LEN);
        vhttp_ipc_queue_init(&g_ipc_state.response_queue, g_ipc_state.response_items, VHTTP_IPC_RESPONSE_QUEUE_LEN);
#endif
        g_ipc_inited = 1;
    }
    return &g_ipc_state;
}

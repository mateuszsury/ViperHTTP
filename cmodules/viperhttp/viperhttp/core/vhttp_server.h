#ifndef VHTTP_SERVER_H
#define VHTTP_SERVER_H

#include <stddef.h>
#include <stdint.h>

#include "vhttp_connection.h"
#include "vhttp_router.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    VHTTP_HANDLE_OK = 0,
    VHTTP_HANDLE_INCOMPLETE,
    VHTTP_HANDLE_ERROR,
    VHTTP_HANDLE_OUTPUT_TOO_SMALL
} vhttp_handle_result_t;

typedef struct {
    vhttp_router_t router;
    vhttp_pool_t pool;
} vhttp_server_t;

typedef struct {
    uint32_t accepts_total;
    uint32_t accepts_enqueued;
    uint32_t accepts_rejected;
    uint32_t accept_queue_used;
    uint32_t accept_queue_peak;
    uint32_t workers_active;
    uint32_t workers_started;
    uint32_t workers_limit_min;
    uint32_t workers_limit_max;
    uint32_t workers_recv_psram;
    uint32_t workers_recv_ram;
    uint32_t ws_handoffs;
    uint32_t ws_tasks_active;
    uint32_t requests_handled;
    uint32_t requests_started;
    uint32_t request_errors;
    uint32_t ipc_req_ring_alloc_fail;
    uint32_t ipc_req_queue_push_fail;
    uint32_t backpressure_503_sent;
    uint32_t ipc_pending_dropped;
    uint32_t ipc_pending_peak;
    uint32_t ipc_pending_used;
    uint32_t ipc_wait_timeouts;
    uint32_t stream_chunks_sent;
    uint32_t scheduler_yields;
    uint32_t state_read_req_hits;
    uint32_t state_wait_ipc_hits;
    uint32_t state_stream_hits;
    uint32_t event_loop_enabled;
    uint32_t event_conn_active;
    uint32_t event_conn_peak;
    uint32_t event_conn_dropped;
    uint32_t event_state_accept_hits;
    uint32_t event_state_dispatched_hits;
    uint32_t event_state_closed_hits;
    uint32_t https_enabled;
    uint32_t https_handshake_ok;
    uint32_t https_handshake_fail;
    uint32_t http2_enabled;
    uint32_t http2_preface_seen;
    uint32_t http2_goaway_sent;
    uint32_t http2_rst_sent;
    uint32_t http2_err_protocol;
    uint32_t http2_err_flow_control;
    uint32_t http2_err_frame_size;
    uint32_t http2_err_compression;
    uint32_t http2_err_refused_stream;
    uint32_t http2_err_stream_closed;
    uint32_t http2_err_internal;
    uint32_t http2_err_http11_required;
    uint32_t http2_task_fallback_used;
    uint32_t http2_psram_slots;
} vhttp_server_stats_t;

typedef struct {
    uint8_t enabled;
    const char *cert_pem;
    size_t cert_pem_len;
    const char *key_pem;
    size_t key_pem_len;
} vhttp_https_config_t;

typedef struct {
    uint8_t enabled;
    uint16_t max_streams;
} vhttp_http2_config_t;

void vhttp_server_init(vhttp_server_t *server);

vhttp_handle_result_t vhttp_handle_request(
    const vhttp_router_t *router,
    const char *req_buf,
    size_t req_len,
    char *resp_buf,
    size_t resp_cap,
    size_t *resp_len
);

int vhttp_server_start(uint16_t port);

void vhttp_server_stop(void);

uint8_t vhttp_server_is_running(void);

int vhttp_server_configure_https(const vhttp_https_config_t *cfg);

void vhttp_server_get_https_status(uint8_t *out_configured, uint8_t *out_active);

int vhttp_server_configure_http2(const vhttp_http2_config_t *cfg);

void vhttp_server_get_http2_status(uint8_t *out_configured, uint8_t *out_runtime_enabled);

int vhttp_server_set_worker_limits(uint16_t min_workers, uint16_t max_workers);

void vhttp_server_get_worker_limits(uint16_t *out_min_workers, uint16_t *out_max_workers);

void vhttp_server_get_stats(vhttp_server_stats_t *out);

void vhttp_server_reset_stats(void);

#ifdef __cplusplus
}
#endif

#endif // VHTTP_SERVER_H

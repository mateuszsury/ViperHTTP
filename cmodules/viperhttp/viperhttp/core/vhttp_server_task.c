#include "vhttp_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vhttp_ipc.h"
#include "vhttp_logger.h"
#include "vhttp_parser.h"
#include "vhttp_config.h"
#include "vhttp_static.h"
#include "vhttp_static_etag.h"
#include "vhttp_fs_lock.h"
#include "vhttp_cors.h"
#include "vhttp_ratelimit.h"
#include "vhttp_trusted_host.h"
#include "vhttp_hpack_huffman_table.h"

#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/idf_additions.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/netdb.h"
#include "lwip/tcp.h"
#include "mbedtls/sha1.h"
#include "mbedtls/base64.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/pk.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/version.h"
#include "esp_heap_caps.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>

#ifndef VHTTP_SERVER_STACK_SIZE
#define VHTTP_SERVER_STACK_SIZE 24576
#endif

#ifndef VHTTP_SERVER_ACCEPTOR_STACK_SIZE
#define VHTTP_SERVER_ACCEPTOR_STACK_SIZE VHTTP_SERVER_STACK_SIZE
#endif

#ifndef VHTTP_SERVER_WORKER_STACK_SIZE
#define VHTTP_SERVER_WORKER_STACK_SIZE 10240
#endif

#ifndef VHTTP_SERVER_HTTP2_TASK_STACK_SIZE
#define VHTTP_SERVER_HTTP2_TASK_STACK_SIZE 24576
#endif

#ifndef VHTTP_SERVER_WS_STACK_SIZE
#define VHTTP_SERVER_WS_STACK_SIZE VHTTP_SERVER_STACK_SIZE
#endif

#ifndef VHTTP_SERVER_DISPATCHER_STACK_SIZE
#define VHTTP_SERVER_DISPATCHER_STACK_SIZE 8192
#endif

#ifndef VHTTP_SERVER_TASK_PRIO
#define VHTTP_SERVER_TASK_PRIO (tskIDLE_PRIORITY + 4)
#endif

#ifndef VHTTP_SERVER_WORKERS
#define VHTTP_SERVER_WORKERS 12
#endif

#ifndef VHTTP_SERVER_MIN_WORKERS
#define VHTTP_SERVER_MIN_WORKERS 4
#endif

#ifndef VHTTP_SERVER_ACCEPT_QUEUE_LEN
#define VHTTP_SERVER_ACCEPT_QUEUE_LEN (VHTTP_SERVER_WORKERS * 2)
#endif

#ifndef VHTTP_SERVER_SCALE_UP_QUEUE_THRESHOLD
#define VHTTP_SERVER_SCALE_UP_QUEUE_THRESHOLD 2
#endif

#ifndef VHTTP_SERVER_SCALE_UP_COOLDOWN_MS
#define VHTTP_SERVER_SCALE_UP_COOLDOWN_MS 500
#endif

#ifndef VHTTP_SERVER_SCALE_UP_FAIL_COOLDOWN_MS
#define VHTTP_SERVER_SCALE_UP_FAIL_COOLDOWN_MS 5000
#endif

#ifndef VHTTP_SERVER_START_TIMEOUT_MS
#define VHTTP_SERVER_START_TIMEOUT_MS 2000
#endif

#ifndef VHTTP_SERVER_RESP_TIMEOUT_MS
#define VHTTP_SERVER_RESP_TIMEOUT_MS 5000
#endif

#ifndef VHTTP_SERVER_IDLE_TIMEOUT_MS
#define VHTTP_SERVER_IDLE_TIMEOUT_MS 5000
#endif

#ifndef VHTTP_SERVER_IO_WAIT_SLICE_MS
#define VHTTP_SERVER_IO_WAIT_SLICE_MS 25
#endif

#ifndef VHTTP_SERVER_KEEPALIVE_IDLE_TIMEOUT_MS
#define VHTTP_SERVER_KEEPALIVE_IDLE_TIMEOUT_MS 10000
#endif

#ifndef VHTTP_SERVER_KEEPALIVE_PRESSURE_QUEUE
#define VHTTP_SERVER_KEEPALIVE_PRESSURE_QUEUE (VHTTP_SERVER_ACCEPT_QUEUE_LEN - 2)
#endif

#ifndef VHTTP_SERVER_REQ_QUEUE_WAIT_MS
#define VHTTP_SERVER_REQ_QUEUE_WAIT_MS 10
#endif

#ifndef VHTTP_HTTP_EVENT_LOOP
#define VHTTP_HTTP_EVENT_LOOP 0
#endif

#ifndef VHTTP_EVENT_LOOP_MAX_CONNS
#define VHTTP_EVENT_LOOP_MAX_CONNS VHTTP_SERVER_ACCEPT_QUEUE_LEN
#endif

#ifndef VHTTP_EVENT_LOOP_SELECT_IDLE_USEC
#define VHTTP_EVENT_LOOP_SELECT_IDLE_USEC 20000
#endif

#ifndef VHTTP_EVENT_LOOP_SELECT_WAIT_IPC_USEC
#define VHTTP_EVENT_LOOP_SELECT_WAIT_IPC_USEC 2000
#endif

#ifndef VHTTP_EVENT_LOOP_SELECT_TX_USEC
#define VHTTP_EVENT_LOOP_SELECT_TX_USEC 2000
#endif

#ifndef VHTTP_EVENT_LOOP_ACCEPT_BUDGET
#define VHTTP_EVENT_LOOP_ACCEPT_BUDGET 8
#endif

#ifndef VHTTP_EVENT_LOOP_REQ_QUEUE_RETRY_TIMEOUT_MS
#define VHTTP_EVENT_LOOP_REQ_QUEUE_RETRY_TIMEOUT_MS 1000
#endif

#ifndef VHTTP_HTTPS_HANDSHAKE_TIMEOUT_MS
#define VHTTP_HTTPS_HANDSHAKE_TIMEOUT_MS 4000
#endif

#ifndef VHTTP_SELECT_SAFE_FD_MAX
#define VHTTP_SELECT_SAFE_FD_MAX 64
#endif

#ifndef VHTTP_HTTP2_FRAME_PAYLOAD_MAX
#define VHTTP_HTTP2_FRAME_PAYLOAD_MAX 16384
#endif

#ifndef VHTTP_HTTP2_HEADER_BLOCK_MAX
#define VHTTP_HTTP2_HEADER_BLOCK_MAX 8192
#endif

#ifndef VHTTP_HTTP2_SESSION_IDLE_TIMEOUT_MS
#define VHTTP_HTTP2_SESSION_IDLE_TIMEOUT_MS 15000
#endif

#ifndef VHTTP_HTTP2_RECV_SLICE_MS
#define VHTTP_HTTP2_RECV_SLICE_MS 25
#endif

#ifndef VHTTP_HTTP2_EVENT_LOOP_FIRST_REQ_WAIT_MS
#define VHTTP_HTTP2_EVENT_LOOP_FIRST_REQ_WAIT_MS 1000
#endif

#ifndef VHTTP_HTTP2_EVENT_LOOP_FRAME_BUDGET
#define VHTTP_HTTP2_EVENT_LOOP_FRAME_BUDGET 4
#endif

#ifndef VHTTP_HTTP2_EVENT_LOOP_TX_MAX_BYTES
#define VHTTP_HTTP2_EVENT_LOOP_TX_MAX_BYTES (128u * 1024u)
#endif

#ifndef VHTTP_HTTP2_EVENT_LOOP_TX_BUDGET_BYTES
#define VHTTP_HTTP2_EVENT_LOOP_TX_BUDGET_BYTES 16384u
#endif

#ifndef VHTTP_HTTP2_STREAM_STATE_SLOTS
#define VHTTP_HTTP2_STREAM_STATE_SLOTS 16
#endif

#ifndef VHTTP_HTTP2_BUFFERED_REQ_SLOTS
#define VHTTP_HTTP2_BUFFERED_REQ_SLOTS 4
#endif

#ifndef VHTTP_HTTP2_BODY_INITIAL_CAP
#define VHTTP_HTTP2_BODY_INITIAL_CAP 4096
#endif

#ifndef VHTTP_HTTP2_HPACK_TABLE_SIZE
#define VHTTP_HTTP2_HPACK_TABLE_SIZE 4096
#endif

#ifndef VHTTP_HTTP2_HPACK_DYN_MAX_ENTRIES
#define VHTTP_HTTP2_HPACK_DYN_MAX_ENTRIES 96
#endif

#ifndef VHTTP_HTTP2_HPACK_HUFF_MAX_NODES
#define VHTTP_HTTP2_HPACK_HUFF_MAX_NODES 1024
#endif

#ifndef VHTTP_HTTP2_HPACK_HUFF_MAX_STR_LEN
#define VHTTP_HTTP2_HPACK_HUFF_MAX_STR_LEN VHTTP_HTTP2_HEADER_BLOCK_MAX
#endif

#ifndef VHTTP_HTTP2_EVENT_LOOP_TASK_FALLBACK
#define VHTTP_HTTP2_EVENT_LOOP_TASK_FALLBACK 0
#endif

#ifndef VHTTP_HTTP2_FLOW_WINDOW_INITIAL
#define VHTTP_HTTP2_FLOW_WINDOW_INITIAL 65535
#endif

#ifndef VHTTP_HTTP2_FLOW_WINDOW_MAX
#define VHTTP_HTTP2_FLOW_WINDOW_MAX 0x7fffffffu
#endif

typedef enum {
    VHTTP_SERVER_START_OK = 0,
    VHTTP_SERVER_START_ERR_SOCKET = 1,
    VHTTP_SERVER_START_ERR_BIND = 2,
    VHTTP_SERVER_START_ERR_LISTEN = 3
} vhttp_server_start_status_t;

typedef struct {
    uint16_t port;
    TaskHandle_t caller;
} vhttp_server_start_args_t;

typedef struct {
    int sock;
    uint32_t client_ip;
} vhttp_accepted_conn_t;

typedef struct {
    size_t index;
    uint8_t *recv_buf;
    size_t recv_cap;
    uint8_t recv_in_psram;
} vhttp_worker_ctx_t;

typedef struct {
    uint8_t enabled;
    char *cert_pem;
    size_t cert_pem_len;
    char *key_pem;
    size_t key_pem_len;
} vhttp_https_runtime_cfg_t;

typedef struct {
    uint8_t enabled;
    uint16_t max_streams;
} vhttp_http2_runtime_cfg_t;

typedef struct {
    uint8_t initialized;
    mbedtls_x509_crt cert;
    mbedtls_pk_context key;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
} vhttp_https_server_ctx_t;

typedef struct {
    uint8_t active;
    uint8_t alpn_h2;
    int sock;
    mbedtls_ssl_context ssl;
} vhttp_https_conn_t;

typedef struct {
    uint8_t used;
    uint32_t stream_id;
} vhttp_http2_stream_slot_t;

typedef struct {
    const char *name;
    const char *value;
} vhttp_http2_hpack_static_t;

typedef struct {
    uint8_t *buf;
    uint16_t name_len;
    uint16_t value_len;
    uint32_t size;
} vhttp_http2_hpack_dyn_entry_t;

typedef enum {
    VHTTP_HTTP2_STREAM_STATE_IDLE = 0,
    VHTTP_HTTP2_STREAM_STATE_OPEN = 1,
    VHTTP_HTTP2_STREAM_STATE_HALF_CLOSED_LOCAL = 2,
    VHTTP_HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE = 3,
    VHTTP_HTTP2_STREAM_STATE_CLOSED = 4
} vhttp_http2_stream_state_t;

typedef struct {
    uint8_t used;
    uint8_t state;
    uint32_t stream_id;
    int32_t rx_window;
    int32_t tx_window;
} vhttp_http2_stream_state_slot_t;

typedef struct {
    int16_t next[2];
    int16_t sym;
    uint8_t valid_end;
} vhttp_http2_hpack_huff_node_t;

typedef struct {
    uint8_t active;
    uint8_t headers_complete;
    uint8_t end_stream;
    uint8_t method;
    uint32_t stream_id;
    char uri[VHTTP_MAX_URI_LEN + 1];
    uint16_t uri_len;
    uint16_t query_len;
    vhttp_header_t headers[VHTTP_MAX_HEADERS];
    uint8_t num_headers;
    uint8_t *header_block;
    uint32_t header_block_len;
    uint32_t header_block_cap;
    uint8_t *body;
    uint32_t body_len;
    uint32_t body_cap;
    uint8_t body_in_psram;
    char header_store[VHTTP_MAX_HEADER_SIZE];
    uint16_t header_store_used;
} vhttp_http2_stream_req_t;

typedef struct {
    uint8_t used;
    vhttp_http2_stream_req_t req;
} vhttp_http2_buffered_req_t;

typedef struct {
    int sock;
    uint32_t client_ip;
    uint8_t *recv_buf;
    size_t recv_cap;
    size_t buffered;
    uint8_t recv_in_psram;
    uint8_t expect_continuation;
    uint32_t continuation_stream_id;
    uint32_t hpack_dyn_size;
    uint32_t hpack_dyn_max_size;
    vhttp_http2_hpack_dyn_entry_t hpack_dyn[VHTTP_HTTP2_HPACK_DYN_MAX_ENTRIES];
    uint16_t hpack_dyn_count;
    uint32_t last_client_stream_id;
    int32_t conn_rx_window;
    int32_t conn_tx_window;
    int32_t peer_initial_window;
    vhttp_http2_stream_state_slot_t stream_states[VHTTP_HTTP2_STREAM_STATE_SLOTS];
    vhttp_http2_stream_req_t req;
    vhttp_http2_buffered_req_t buffered_reqs[VHTTP_HTTP2_BUFFERED_REQ_SLOTS];
} vhttp_http2_session_t;

typedef enum {
    VHTTP_CONN_STATE_READ_REQ = 0,
    VHTTP_CONN_STATE_WAIT_IPC = 1,
    VHTTP_CONN_STATE_STREAM = 2
} vhttp_runtime_state_t;

typedef enum {
    VHTTP_EV_CONN_FREE = 0,
    VHTTP_EV_CONN_ACCEPTED = 1,
    VHTTP_EV_CONN_DISPATCHED = 2,
    VHTTP_EV_CONN_CLOSED = 3
} vhttp_ev_conn_state_t;

typedef struct {
    uint8_t used;
    int sock;
    uint32_t client_ip;
    TickType_t last_tick;
    vhttp_ev_conn_state_t state;
} vhttp_ev_conn_t;

typedef enum {
    VHTTP_EVRT_FREE = 0,
    VHTTP_EVRT_READ_REQ = 1,
    VHTTP_EVRT_WAIT_REQ_QUEUE = 2,
    VHTTP_EVRT_WAIT_IPC = 3
} vhttp_evrt_state_t;

typedef struct vhttp_http2_event_ctx_s vhttp_http2_event_ctx_t;
typedef struct vhttp_http2_pending_ipc_s vhttp_http2_pending_ipc_t;

typedef struct {
    uint8_t used;
    int sock;
    uint32_t client_ip;
    vhttp_evrt_state_t state;
    uint8_t *recv_buf;
    size_t recv_cap;
    uint8_t recv_in_psram;
    size_t buffered;
    uint32_t served_requests;
    uint8_t keep_alive;
    uint8_t head_only;
    uint8_t stream_active;
    uint8_t stream_use_chunked;
    uint8_t stream_header_sent;
    uint8_t tx_active;
    uint8_t tx_stream;
    uint8_t tx_final;
    uint8_t tx_close_after;
    uint8_t tx_chunked;
    uint8_t tx_send_final_chunk;
    uint8_t tx_chunk_suffix_len;
    uint8_t tx_chunk_suffix_sent;
    uint8_t tx_chunk_prefix_len;
    uint8_t tx_chunk_prefix_sent;
    uint16_t tx_header_len;
    uint16_t tx_header_sent;
    uint32_t tx_body_offset;
    uint32_t tx_body_len;
    uint32_t tx_body_sent;
    uint32_t tx_release_body_len;
    uint16_t tx_release_headers_len;
    char tx_header[VHTTP_HEADER_BUF_SIZE];
    char tx_chunk_prefix[16];
    vhttp_ipc_msg_t pending_msg;
    uint32_t request_id;
    uint32_t request_blob_len;
    TickType_t state_since;
    uint16_t cors_headers_len;
    char cors_headers[VHTTP_CORS_HEADER_MAX];
    vhttp_http2_event_ctx_t *h2_ctx;
} vhttp_evrt_conn_t;

typedef enum {
    VHTTP_EV_DISPATCH_CLOSE = 0,
    VHTTP_EV_DISPATCH_CONTINUE = 1,
    VHTTP_EV_DISPATCH_WAIT_IPC = 2,
    VHTTP_EV_DISPATCH_HANDOFF = 3,
    VHTTP_EV_DISPATCH_WAIT_REQ_QUEUE = 4
} vhttp_ev_dispatch_result_t;

typedef struct {
    uint8_t used;
    uint32_t request_id;
    TaskHandle_t task;
} vhttp_resp_waiter_t;

static TaskHandle_t g_server_task = NULL;
static TaskHandle_t g_worker_tasks[VHTTP_SERVER_WORKERS];
static vhttp_worker_ctx_t g_worker_ctx[VHTTP_SERVER_WORKERS];
static TaskHandle_t g_resp_dispatcher_task = NULL;
static size_t g_worker_count = 0;
static size_t g_worker_limit_min = (size_t)VHTTP_SERVER_MIN_WORKERS;
static size_t g_worker_limit_max = (size_t)VHTTP_SERVER_WORKERS;
static TickType_t g_worker_scale_last_tick = 0;
static TickType_t g_worker_scale_block_until = 0;
static uint8_t g_psram_checked = 0;
static uint8_t g_psram_available = 0;
static volatile int g_server_running = 0;
static volatile int g_server_starting = 0;
static int g_listen_fd = -1;
static uint32_t g_request_id = 0;
static vhttp_server_start_args_t g_start_args;
static QueueHandle_t g_accept_queue = NULL;
static StaticQueue_t g_accept_queue_storage;
static uint8_t g_accept_queue_buf[VHTTP_SERVER_ACCEPT_QUEUE_LEN * sizeof(vhttp_accepted_conn_t)];
static portMUX_TYPE g_req_id_lock = portMUX_INITIALIZER_UNLOCKED;
static portMUX_TYPE g_stats_lock = portMUX_INITIALIZER_UNLOCKED;
static portMUX_TYPE g_worker_cfg_lock = portMUX_INITIALIZER_UNLOCKED;
static portMUX_TYPE g_ev_conn_lock = portMUX_INITIALIZER_UNLOCKED;
static portMUX_TYPE g_https_cfg_lock = portMUX_INITIALIZER_UNLOCKED;
static portMUX_TYPE g_http2_cfg_lock = portMUX_INITIALIZER_UNLOCKED;
static SemaphoreHandle_t g_resp_mux = NULL;
static StaticSemaphore_t g_resp_mux_storage;
static SemaphoreHandle_t g_waiter_mux = NULL;
static StaticSemaphore_t g_waiter_mux_storage;
static vhttp_ev_conn_t g_ev_conns[VHTTP_EVENT_LOOP_MAX_CONNS];
static vhttp_evrt_conn_t g_evrt_conns[VHTTP_EVENT_LOOP_MAX_CONNS];
static uint32_t g_ev_conn_peak = 0;

typedef struct {
    uint8_t used;
    uint64_t seq;
    vhttp_ipc_msg_t msg;
} vhttp_pending_resp_t;

static vhttp_pending_resp_t g_pending_resp[VHTTP_PENDING_RESP_SLOTS];
static vhttp_resp_waiter_t g_resp_waiters[VHTTP_PENDING_RESP_SLOTS];
static uint64_t g_pending_resp_seq = 0;
static uint32_t g_canceled_req_ids[VHTTP_CANCELED_REQ_SLOTS];
static uint32_t g_canceled_req_head = 0;
static vhttp_server_stats_t g_server_stats;
static vhttp_https_runtime_cfg_t g_https_cfg = {0};
static vhttp_http2_runtime_cfg_t g_http2_cfg = {0};
static vhttp_https_server_ctx_t g_https_server = {0};
static vhttp_https_conn_t *g_https_conn = NULL;
static vhttp_http2_stream_slot_t *g_http2_stream_slots = NULL;
static uint8_t g_http2_stream_slots_in_psram = 0;
static vhttp_http2_hpack_huff_node_t g_http2_hpack_huff_nodes[VHTTP_HTTP2_HPACK_HUFF_MAX_NODES];
static uint16_t g_http2_hpack_huff_nodes_used = 0;
static uint8_t g_http2_hpack_huff_ready = 0;

#if defined(MBEDTLS_SSL_ALPN)
static const char *g_vhttp_alpn_http11[] = { "http/1.1", NULL };
static const char *g_vhttp_alpn_h2[] = { "h2", "http/1.1", NULL };
#endif

#define VHTTP_CONN_HANDOFF 1
#define VHTTP_HTTP2_PREFACE_LEN 24

enum {
    VHTTP_HTTP2_FRAME_DATA = 0x0,
    VHTTP_HTTP2_FRAME_HEADERS = 0x1,
    VHTTP_HTTP2_FRAME_PRIORITY = 0x2,
    VHTTP_HTTP2_FRAME_RST_STREAM = 0x3,
    VHTTP_HTTP2_FRAME_SETTINGS = 0x4,
    VHTTP_HTTP2_FRAME_PUSH_PROMISE = 0x5,
    VHTTP_HTTP2_FRAME_PING = 0x6,
    VHTTP_HTTP2_FRAME_GOAWAY = 0x7,
    VHTTP_HTTP2_FRAME_WINDOW_UPDATE = 0x8,
    VHTTP_HTTP2_FRAME_CONTINUATION = 0x9
};

enum {
    VHTTP_HTTP2_FLAG_END_STREAM = 0x1,
    VHTTP_HTTP2_FLAG_END_HEADERS = 0x4,
    VHTTP_HTTP2_FLAG_PADDED = 0x8,
    VHTTP_HTTP2_FLAG_PRIORITY = 0x20,
    VHTTP_HTTP2_FLAG_ACK = 0x1
};

enum {
    VHTTP_HTTP2_ERR_NO_ERROR = 0x0,
    VHTTP_HTTP2_ERR_PROTOCOL = 0x1,
    VHTTP_HTTP2_ERR_INTERNAL = 0x2,
    VHTTP_HTTP2_ERR_FLOW_CONTROL = 0x3,
    VHTTP_HTTP2_ERR_SETTINGS_TIMEOUT = 0x4,
    VHTTP_HTTP2_ERR_STREAM_CLOSED = 0x5,
    VHTTP_HTTP2_ERR_FRAME_SIZE = 0x6,
    VHTTP_HTTP2_ERR_REFUSED_STREAM = 0x7,
    VHTTP_HTTP2_ERR_CANCEL = 0x8,
    VHTTP_HTTP2_ERR_COMPRESSION = 0x9,
    VHTTP_HTTP2_ERR_CONNECT = 0xa,
    VHTTP_HTTP2_ERR_ENHANCE_YOUR_CALM = 0xb,
    VHTTP_HTTP2_ERR_INADEQUATE_SECURITY = 0xc,
    VHTTP_HTTP2_ERR_HTTP_1_1_REQUIRED = 0xd
};

enum {
    VHTTP_HTTP2_SETTINGS_HEADER_TABLE_SIZE = 0x1,
    VHTTP_HTTP2_SETTINGS_ENABLE_PUSH = 0x2,
    VHTTP_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x3,
    VHTTP_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE = 0x4,
    VHTTP_HTTP2_SETTINGS_MAX_FRAME_SIZE = 0x5,
    VHTTP_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE = 0x6
};

static const vhttp_http2_hpack_static_t g_http2_hpack_static[] = {
    { ":authority", "" },
    { ":method", "GET" },
    { ":method", "POST" },
    { ":path", "/" },
    { ":path", "/index.html" },
    { ":scheme", "http" },
    { ":scheme", "https" },
    { ":status", "200" },
    { ":status", "204" },
    { ":status", "206" },
    { ":status", "304" },
    { ":status", "400" },
    { ":status", "404" },
    { ":status", "500" },
    { "accept-charset", "" },
    { "accept-encoding", "gzip, deflate" },
    { "accept-language", "" },
    { "accept-ranges", "" },
    { "accept", "" },
    { "access-control-allow-origin", "" },
    { "age", "" },
    { "allow", "" },
    { "authorization", "" },
    { "cache-control", "" },
    { "content-disposition", "" },
    { "content-encoding", "" },
    { "content-language", "" },
    { "content-length", "" },
    { "content-location", "" },
    { "content-range", "" },
    { "content-type", "" },
    { "cookie", "" },
    { "date", "" },
    { "etag", "" },
    { "expect", "" },
    { "expires", "" },
    { "from", "" },
    { "host", "" },
    { "if-match", "" },
    { "if-modified-since", "" },
    { "if-none-match", "" },
    { "if-range", "" },
    { "if-unmodified-since", "" },
    { "last-modified", "" },
    { "link", "" },
    { "location", "" },
    { "max-forwards", "" },
    { "proxy-authenticate", "" },
    { "proxy-authorization", "" },
    { "range", "" },
    { "referer", "" },
    { "refresh", "" },
    { "retry-after", "" },
    { "server", "" },
    { "set-cookie", "" },
    { "strict-transport-security", "" },
    { "transfer-encoding", "" },
    { "user-agent", "" },
    { "vary", "" },
    { "via", "" },
    { "www-authenticate", "" }
};

typedef struct {
    int sock;
    uint32_t req_len;
    uint8_t req_buf[];
} vhttp_ws_task_ctx_t;

typedef struct {
    int sock;
    uint32_t client_ip;
    uint32_t recv_len;
    uint32_t recv_cap;
    uint8_t recv_buf[];
} vhttp_http2_task_ctx_t;

static uint32_t vhttp_next_request_id(void) {
    uint32_t id = 0;
    taskENTER_CRITICAL(&g_req_id_lock);
    id = ++g_request_id;
    if (id == 0) {
        id = ++g_request_id;
    }
    taskEXIT_CRITICAL(&g_req_id_lock);
    return id;
}

static void vhttp_stats_inc(uint32_t *field) {
    if (!field) {
        return;
    }
    taskENTER_CRITICAL(&g_stats_lock);
    (*field)++;
    taskEXIT_CRITICAL(&g_stats_lock);
}

static void vhttp_stats_conn_state_hit(vhttp_runtime_state_t state) {
    switch (state) {
        case VHTTP_CONN_STATE_READ_REQ:
            vhttp_stats_inc(&g_server_stats.state_read_req_hits);
            break;
        case VHTTP_CONN_STATE_WAIT_IPC:
            vhttp_stats_inc(&g_server_stats.state_wait_ipc_hits);
            break;
        case VHTTP_CONN_STATE_STREAM:
            vhttp_stats_inc(&g_server_stats.state_stream_hits);
            break;
        default:
            break;
    }
}

static uint32_t vhttp_ws_tasks_active_count(void) {
    uint32_t active = 0;
    taskENTER_CRITICAL(&g_stats_lock);
    active = g_server_stats.ws_tasks_active;
    taskEXIT_CRITICAL(&g_stats_lock);
    return active;
}

static void vhttp_wait_ws_tasks_quiesce(uint32_t timeout_ms) {
    TickType_t start = xTaskGetTickCount();
    TickType_t timeout = pdMS_TO_TICKS(timeout_ms);
    if (timeout == 0) {
        timeout = 1;
    }
    while (vhttp_ws_tasks_active_count() > 0) {
        if ((TickType_t)(xTaskGetTickCount() - start) >= timeout) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

static uint32_t vhttp_ev_conn_active_count_nolock(void) {
    uint32_t active = 0;
    for (size_t i = 0; i < (size_t)VHTTP_EVENT_LOOP_MAX_CONNS; ++i) {
        if (g_ev_conns[i].used) {
            active++;
        }
    }
    return active;
}

static void vhttp_ev_conn_reset(void) {
    taskENTER_CRITICAL(&g_ev_conn_lock);
    memset(g_ev_conns, 0, sizeof(g_ev_conns));
    for (size_t i = 0; i < (size_t)VHTTP_EVENT_LOOP_MAX_CONNS; ++i) {
        g_ev_conns[i].sock = -1;
        g_ev_conns[i].state = VHTTP_EV_CONN_FREE;
    }
    g_ev_conn_peak = 0;
    taskEXIT_CRITICAL(&g_ev_conn_lock);
}

static void vhttp_ev_stats_store_active(uint32_t active, uint32_t peak) {
    taskENTER_CRITICAL(&g_stats_lock);
    g_server_stats.event_conn_active = active;
    if (peak > g_server_stats.event_conn_peak) {
        g_server_stats.event_conn_peak = peak;
    }
    taskEXIT_CRITICAL(&g_stats_lock);
}

static void vhttp_ev_conn_on_accept(int sock, uint32_t client_ip) {
    uint32_t active = 0;
    uint32_t peak = 0;
    int tracked = 0;

    taskENTER_CRITICAL(&g_ev_conn_lock);
    for (size_t i = 0; i < (size_t)VHTTP_EVENT_LOOP_MAX_CONNS; ++i) {
        if (!g_ev_conns[i].used) {
            g_ev_conns[i].used = 1;
            g_ev_conns[i].sock = sock;
            g_ev_conns[i].client_ip = client_ip;
            g_ev_conns[i].last_tick = xTaskGetTickCount();
            g_ev_conns[i].state = VHTTP_EV_CONN_ACCEPTED;
            tracked = 1;
            break;
        }
    }
    active = vhttp_ev_conn_active_count_nolock();
    if (active > g_ev_conn_peak) {
        g_ev_conn_peak = active;
    }
    peak = g_ev_conn_peak;
    taskEXIT_CRITICAL(&g_ev_conn_lock);

    vhttp_ev_stats_store_active(active, peak);
    taskENTER_CRITICAL(&g_stats_lock);
    g_server_stats.event_state_accept_hits++;
    if (!tracked) {
        g_server_stats.event_conn_dropped++;
    }
    taskEXIT_CRITICAL(&g_stats_lock);
}

static void vhttp_ev_conn_on_dispatched(int sock) {
    taskENTER_CRITICAL(&g_ev_conn_lock);
    for (size_t i = 0; i < (size_t)VHTTP_EVENT_LOOP_MAX_CONNS; ++i) {
        if (g_ev_conns[i].used && g_ev_conns[i].sock == sock) {
            g_ev_conns[i].state = VHTTP_EV_CONN_DISPATCHED;
            g_ev_conns[i].last_tick = xTaskGetTickCount();
            break;
        }
    }
    taskEXIT_CRITICAL(&g_ev_conn_lock);

    taskENTER_CRITICAL(&g_stats_lock);
    g_server_stats.event_state_dispatched_hits++;
    taskEXIT_CRITICAL(&g_stats_lock);
}

static void vhttp_ev_conn_on_closed(int sock) {
    uint32_t active = 0;
    uint32_t peak = 0;

    taskENTER_CRITICAL(&g_ev_conn_lock);
    for (size_t i = 0; i < (size_t)VHTTP_EVENT_LOOP_MAX_CONNS; ++i) {
        if (g_ev_conns[i].used && g_ev_conns[i].sock == sock) {
            g_ev_conns[i].used = 0;
            g_ev_conns[i].sock = -1;
            g_ev_conns[i].client_ip = 0;
            g_ev_conns[i].state = VHTTP_EV_CONN_CLOSED;
            g_ev_conns[i].last_tick = xTaskGetTickCount();
            break;
        }
    }
    active = vhttp_ev_conn_active_count_nolock();
    peak = g_ev_conn_peak;
    taskEXIT_CRITICAL(&g_ev_conn_lock);

    vhttp_ev_stats_store_active(active, peak);
    taskENTER_CRITICAL(&g_stats_lock);
    g_server_stats.event_state_closed_hits++;
    taskEXIT_CRITICAL(&g_stats_lock);
}

static uint32_t vhttp_pending_resp_used_nolock(void) {
    uint32_t used = 0;
    for (size_t i = 0; i < (sizeof(g_pending_resp) / sizeof(g_pending_resp[0])); ++i) {
        if (g_pending_resp[i].used) {
            used++;
        }
    }
    return used;
}

static void vhttp_ipc_release_response_payload(vhttp_ipc_state_t *ipc, const vhttp_ipc_msg_t *msg) {
    if (!ipc || !msg) {
        return;
    }
    if (msg->body_len > 0) {
        vhttp_ipc_ring_release(&ipc->ring, msg->body_len);
    }
    if (msg->headers_len > 0) {
        vhttp_ipc_ring_release(&ipc->ring, msg->headers_len);
    }
}

static void vhttp_pending_resp_reset(void) {
    memset(g_pending_resp, 0, sizeof(g_pending_resp));
    g_pending_resp_seq = 0;
    memset(g_canceled_req_ids, 0, sizeof(g_canceled_req_ids));
    g_canceled_req_head = 0;
}

static void vhttp_resp_waiters_reset(void) {
    memset(g_resp_waiters, 0, sizeof(g_resp_waiters));
}

static int vhttp_request_canceled_nolock(uint32_t request_id) {
    if (request_id == 0) {
        return 0;
    }
    for (size_t i = 0; i < (sizeof(g_canceled_req_ids) / sizeof(g_canceled_req_ids[0])); ++i) {
        if (g_canceled_req_ids[i] == request_id) {
            return 1;
        }
    }
    return 0;
}

static void vhttp_request_cancel_mark_nolock(uint32_t request_id) {
    if (request_id == 0) {
        return;
    }
    if (vhttp_request_canceled_nolock(request_id)) {
        return;
    }
    if (sizeof(g_canceled_req_ids) / sizeof(g_canceled_req_ids[0]) == 0) {
        return;
    }
    size_t slot = (size_t)(g_canceled_req_head % (uint32_t)(sizeof(g_canceled_req_ids) / sizeof(g_canceled_req_ids[0])));
    g_canceled_req_ids[slot] = request_id;
    g_canceled_req_head++;
}

static void vhttp_request_cancel_clear_nolock(uint32_t request_id) {
    if (request_id == 0) {
        return;
    }
    for (size_t i = 0; i < (sizeof(g_canceled_req_ids) / sizeof(g_canceled_req_ids[0])); ++i) {
        if (g_canceled_req_ids[i] == request_id) {
            g_canceled_req_ids[i] = 0;
        }
    }
}

static void vhttp_pending_resp_drop_request_nolock(vhttp_ipc_state_t *ipc, uint32_t request_id) {
    if (!ipc || request_id == 0) {
        return;
    }
    for (size_t i = 0; i < (sizeof(g_pending_resp) / sizeof(g_pending_resp[0])); ++i) {
        if (!g_pending_resp[i].used || g_pending_resp[i].msg.request_id != request_id) {
            continue;
        }
        vhttp_ipc_release_response_payload(ipc, &g_pending_resp[i].msg);
        g_pending_resp[i].used = 0;
        g_pending_resp[i].seq = 0;
    }
}

static void vhttp_abort_inflight_request(vhttp_ipc_state_t *ipc, uint32_t request_id, uint32_t *request_blob_len) {
    if (!ipc) {
        return;
    }
    if (request_blob_len && *request_blob_len > 0) {
        vhttp_ipc_ring_release(&ipc->ring, *request_blob_len);
        *request_blob_len = 0;
    }
    if (request_id == 0 || !g_resp_mux) {
        return;
    }
    int lock_ok = 0;
    for (int attempt = 0; attempt < 4; ++attempt) {
        if (xSemaphoreTake(g_resp_mux, 0) == pdTRUE) {
            lock_ok = 1;
            break;
        }
        taskYIELD();
    }
    if (!lock_ok) {
        return;
    }
    vhttp_request_cancel_mark_nolock(request_id);
    vhttp_pending_resp_drop_request_nolock(ipc, request_id);
    xSemaphoreGive(g_resp_mux);
}

static int vhttp_resp_waiter_register(uint32_t request_id, TaskHandle_t task) {
    if (!task || !g_waiter_mux) {
        return -1;
    }
    if (xSemaphoreTake(g_waiter_mux, pdMS_TO_TICKS(5)) != pdTRUE) {
        return -1;
    }
    int rc = -1;
    for (size_t i = 0; i < (sizeof(g_resp_waiters) / sizeof(g_resp_waiters[0])); ++i) {
        if (g_resp_waiters[i].used &&
            g_resp_waiters[i].request_id == request_id &&
            g_resp_waiters[i].task == task) {
            rc = 0;
            break;
        }
    }
    if (rc != 0) {
        for (size_t i = 0; i < (sizeof(g_resp_waiters) / sizeof(g_resp_waiters[0])); ++i) {
            if (!g_resp_waiters[i].used) {
                g_resp_waiters[i].used = 1;
                g_resp_waiters[i].request_id = request_id;
                g_resp_waiters[i].task = task;
                rc = 0;
                break;
            }
        }
    }
    xSemaphoreGive(g_waiter_mux);
    return rc;
}

static void vhttp_resp_waiter_unregister(uint32_t request_id, TaskHandle_t task) {
    if (!task || !g_waiter_mux) {
        return;
    }
    if (xSemaphoreTake(g_waiter_mux, pdMS_TO_TICKS(5)) != pdTRUE) {
        return;
    }
    for (size_t i = 0; i < (sizeof(g_resp_waiters) / sizeof(g_resp_waiters[0])); ++i) {
        if (g_resp_waiters[i].used &&
            g_resp_waiters[i].request_id == request_id &&
            g_resp_waiters[i].task == task) {
            g_resp_waiters[i].used = 0;
            g_resp_waiters[i].request_id = 0;
            g_resp_waiters[i].task = NULL;
            break;
        }
    }
    xSemaphoreGive(g_waiter_mux);
}

static void vhttp_resp_waiter_notify(uint32_t request_id) {
    if (!g_waiter_mux) {
        return;
    }
    TaskHandle_t task = NULL;
    if (xSemaphoreTake(g_waiter_mux, pdMS_TO_TICKS(5)) == pdTRUE) {
        for (size_t i = 0; i < (sizeof(g_resp_waiters) / sizeof(g_resp_waiters[0])); ++i) {
            if (g_resp_waiters[i].used && g_resp_waiters[i].request_id == request_id) {
                task = g_resp_waiters[i].task;
                break;
            }
        }
        xSemaphoreGive(g_waiter_mux);
    }
    if (task) {
        (void)xTaskNotifyGive(task);
    }
}

static int vhttp_pending_resp_take(uint32_t request_id, vhttp_ipc_msg_t *out) {
    if (!out) {
        return -1;
    }
    size_t best_idx = (size_t)-1;
    uint64_t best_seq = 0;
    for (size_t i = 0; i < (sizeof(g_pending_resp) / sizeof(g_pending_resp[0])); ++i) {
        if (g_pending_resp[i].used && g_pending_resp[i].msg.request_id == request_id) {
            if (best_idx == (size_t)-1 || g_pending_resp[i].seq < best_seq) {
                best_idx = i;
                best_seq = g_pending_resp[i].seq;
            }
        }
    }
    if (best_idx != (size_t)-1) {
        *out = g_pending_resp[best_idx].msg;
        g_pending_resp[best_idx].used = 0;
        g_pending_resp[best_idx].seq = 0;
        return 0;
    }
    return -1;
}

static int vhttp_pending_resp_store(const vhttp_ipc_msg_t *msg) {
    if (!msg) {
        return -1;
    }
    for (size_t i = 0; i < (sizeof(g_pending_resp) / sizeof(g_pending_resp[0])); ++i) {
        if (!g_pending_resp[i].used) {
            g_pending_resp[i].used = 1;
            g_pending_resp[i].seq = ++g_pending_resp_seq;
            g_pending_resp[i].msg = *msg;
            uint32_t used_now = vhttp_pending_resp_used_nolock();
            taskENTER_CRITICAL(&g_stats_lock);
            if (used_now > g_server_stats.ipc_pending_peak) {
                g_server_stats.ipc_pending_peak = used_now;
            }
            taskEXIT_CRITICAL(&g_stats_lock);
            return 0;
        }
    }
    return -1;
}

static void vhttp_pending_store_or_drop(vhttp_ipc_state_t *ipc, const vhttp_ipc_msg_t *msg) {
    if (!ipc || !msg) {
        return;
    }
    if (!g_resp_mux) {
        VHTTP_LOGW("dropping IPC response id=%lu type=%u (pending lock timeout)",
            (unsigned long)msg->request_id,
            (unsigned int)msg->type);
        vhttp_stats_inc(&g_server_stats.ipc_pending_dropped);
        vhttp_ipc_release_response_payload(ipc, msg);
        return;
    }
    int lock_ok = 0;
    for (int attempt = 0; attempt < 5; ++attempt) {
        if (xSemaphoreTake(g_resp_mux, 0) == pdTRUE) {
            lock_ok = 1;
            break;
        }
        taskYIELD();
    }
    if (!lock_ok) {
        VHTTP_LOGW("dropping IPC response id=%lu type=%u (pending lock timeout)",
            (unsigned long)msg->request_id,
            (unsigned int)msg->type);
        vhttp_stats_inc(&g_server_stats.ipc_pending_dropped);
        vhttp_ipc_release_response_payload(ipc, msg);
        return;
    }
    if (vhttp_request_canceled_nolock(msg->request_id)) {
        uint8_t terminal = ((msg->flags & VHTTP_IPC_FLAG_STREAM) == 0) ||
                           ((msg->flags & VHTTP_IPC_FLAG_FINAL) != 0);
        vhttp_ipc_release_response_payload(ipc, msg);
        if (terminal) {
            vhttp_request_cancel_clear_nolock(msg->request_id);
        }
        xSemaphoreGive(g_resp_mux);
        return;
    }
    if (vhttp_pending_resp_store(msg) != 0) {
        VHTTP_LOGW("dropping IPC response id=%lu type=%u (pending full)",
            (unsigned long)msg->request_id,
            (unsigned int)msg->type);
        vhttp_stats_inc(&g_server_stats.ipc_pending_dropped);
        vhttp_ipc_release_response_payload(ipc, msg);
    } else {
        vhttp_resp_waiter_notify(msg->request_id);
    }
    xSemaphoreGive(g_resp_mux);
}

static int vhttp_ipc_try_response_for(vhttp_ipc_state_t *ipc, uint32_t request_id, vhttp_ipc_msg_t *out) {
    if (!ipc || !out) {
        return -1;
    }
    // Event-loop path must never block on pending-response lock.
    if (g_resp_mux && xSemaphoreTake(g_resp_mux, 0) == pdTRUE) {
        if (vhttp_pending_resp_take(request_id, out) == 0) {
            xSemaphoreGive(g_resp_mux);
            return 0;
        }
        xSemaphoreGive(g_resp_mux);
    }

    return -1;
}

static int vhttp_ipc_wait_response_for(
    vhttp_ipc_state_t *ipc,
    uint32_t request_id,
    uint32_t timeout_ms,
    vhttp_ipc_msg_t *out
) {
    if (!ipc || !out) {
        return -1;
    }
    if (timeout_ms == 0 && vhttp_ipc_try_response_for(ipc, request_id, out) == 0) {
        return 0;
    }

    TaskHandle_t self_task = xTaskGetCurrentTaskHandle();
    int waiter_registered = 0;
    if (self_task && vhttp_resp_waiter_register(request_id, self_task) == 0) {
        waiter_registered = 1;
    }

    uint32_t waited_ms = 0;
    while (waited_ms < timeout_ms) {
        if (vhttp_ipc_try_response_for(ipc, request_id, out) == 0) {
            if (waiter_registered) {
                vhttp_resp_waiter_unregister(request_id, self_task);
            }
            return 0;
        }

        uint32_t wait_slice = timeout_ms - waited_ms;
        if (wait_slice > 50) {
            wait_slice = 50;
        }
        if (waiter_registered) {
            (void)ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(wait_slice));
        } else {
            vTaskDelay(pdMS_TO_TICKS(wait_slice));
        }
        waited_ms += wait_slice;
    }

    if (waiter_registered) {
        vhttp_resp_waiter_unregister(request_id, self_task);
    }

    if (vhttp_ipc_try_response_for(ipc, request_id, out) == 0) {
            return 0;
    }
    return -1;
}

static void vhttp_ipc_response_dispatcher_task(void *arg) {
    (void)arg;
    vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
    if (!ipc) {
        g_resp_dispatcher_task = NULL;
        vTaskDelete(NULL);
        return;
    }
    while (g_server_running) {
        vhttp_ipc_msg_t msg = {0};
        if (vhttp_ipc_queue_pop_wait(&ipc->response_queue, &msg, 100) == 0) {
            vhttp_pending_store_or_drop(ipc, &msg);
        }
    }
    g_resp_dispatcher_task = NULL;
    vTaskDelete(NULL);
}

static int vhttp_server_dispatcher_start(void) {
    g_resp_dispatcher_task = NULL;
    BaseType_t ok = pdFAIL;
#if defined(MALLOC_CAP_SPIRAM)
    ok = xTaskCreatePinnedToCoreWithCaps(
        vhttp_ipc_response_dispatcher_task,
        "vhttp_resp",
        VHTTP_SERVER_DISPATCHER_STACK_SIZE,
        NULL,
        VHTTP_SERVER_TASK_PRIO,
        &g_resp_dispatcher_task,
        0,
        MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT
    );
#endif
    if (ok != pdPASS) {
        ok = xTaskCreatePinnedToCore(
            vhttp_ipc_response_dispatcher_task,
            "vhttp_resp",
            VHTTP_SERVER_DISPATCHER_STACK_SIZE,
            NULL,
            VHTTP_SERVER_TASK_PRIO,
            &g_resp_dispatcher_task,
            0
        );
    }
    if (ok != pdPASS) {
        g_resp_dispatcher_task = NULL;
        return -1;
    }
    return 0;
}

static const char *status_reason(int status) {
    switch (status) {
        case 101: return "Switching Protocols";
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 400: return "Bad Request";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 413: return "Payload Too Large";
        case 426: return "Upgrade Required";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        default: return "OK";
    }
}

static void vhttp_client_ip_to_str(uint32_t client_ip, char *out, size_t out_len) {
    if (!out || out_len == 0) {
        return;
    }
    uint32_t host_ip = ntohl(client_ip);
    unsigned int a = (host_ip >> 24) & 0xffu;
    unsigned int b = (host_ip >> 16) & 0xffu;
    unsigned int c = (host_ip >> 8) & 0xffu;
    unsigned int d = host_ip & 0xffu;
    (void)snprintf(out, out_len, "%u.%u.%u.%u", a, b, c, d);
}

static void vhttp_log_http_request(const vhttp_parsed_request_t *req, uint32_t client_ip) {
    if (!req) {
        return;
    }
    char ip[20];
    vhttp_client_ip_to_str(client_ip, ip, sizeof(ip));
    VHTTP_LOGD("req %s %.*s %.*s", ip, (int)req->method.len, req->method.ptr, (int)req->uri.len, req->uri.ptr);
}

static void vhttp_log_http_response(const vhttp_parsed_request_t *req, int status, int keep_alive, const char *source) {
    if (!req) {
        return;
    }
    const char *src = source ? source : "resp";
    VHTTP_LOGI("%s %.*s %.*s -> %d keep=%d", src, (int)req->method.len, req->method.ptr, (int)req->uri.len, req->uri.ptr, status, keep_alive ? 1 : 0);
}

static int slice_ci_equals_n(const char *a, size_t a_len, const char *b) {
    size_t b_len = strlen(b);
    if (a_len != b_len) {
        return 0;
    }
    for (size_t i = 0; i < a_len; ++i) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z') {
            ca = (char)(ca + ('a' - 'A'));
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (char)(cb + ('a' - 'A'));
        }
        if (ca != cb) {
            return 0;
        }
    }
    return 1;
}

static int slice_ci_contains_n(const char *haystack, size_t hay_len, const char *needle) {
    size_t needle_len = strlen(needle);
    if (needle_len == 0 || hay_len < needle_len) {
        return 0;
    }
    for (size_t i = 0; i + needle_len <= hay_len; ++i) {
        size_t j = 0;
        for (; j < needle_len; ++j) {
            char ca = haystack[i + j];
            char cb = needle[j];
            if (ca >= 'A' && ca <= 'Z') {
                ca = (char)(ca + ('a' - 'A'));
            }
            if (cb >= 'A' && cb <= 'Z') {
                cb = (char)(cb + ('a' - 'A'));
            }
            if (ca != cb) {
                break;
            }
        }
        if (j == needle_len) {
            return 1;
        }
    }
    return 0;
}

static int header_value_contains(const vhttp_parsed_request_t *req, const char *name, const char *token) {
    if (!req || !name || !token) {
        return 0;
    }
    for (uint8_t i = 0; i < req->num_headers; ++i) {
        const vhttp_header_t *hdr = &req->headers[i];
        if (slice_ci_equals_n(hdr->name, hdr->name_len, name)) {
            if (slice_ci_contains_n(hdr->value, hdr->value_len, token)) {
                return 1;
            }
        }
    }
    return 0;
}

static const vhttp_header_t *find_header(const vhttp_parsed_request_t *req, const char *name);
static int send_all(int sock, const uint8_t *buf, size_t len);
static int vhttp_http2_send_goaway(int sock, uint32_t error_code);
static int vhttp_http2_send_frame(int sock, uint8_t type, uint8_t flags, uint32_t stream_id, const uint8_t *payload, uint32_t payload_len);
static int vhttp_http2_send_server_settings(vhttp_http2_session_t *sess);
static int vhttp_http2_buffer_starts_with_preface(const uint8_t *buf, size_t len);
static uint8_t vhttp_http2_enabled_runtime(void);
static int vhttp_http2_dispatch_request(vhttp_http2_session_t *sess, vhttp_http2_stream_req_t *req);
static int vhttp_http2_dispatch_request_async_start(
    vhttp_http2_session_t *sess,
    vhttp_http2_stream_req_t *req,
    vhttp_http2_pending_ipc_t *pending
);
static int vhttp_http2_handle_preface_if_needed(int sock, const uint8_t *buf, size_t len);
static int vhttp_http2_prepare_slots(void);
static void vhttp_http2_free_slots(void);
static int vhttp_http2_run_session(
    int sock,
    uint32_t client_ip,
    uint8_t *recv_buf,
    size_t recv_cap,
    size_t initial_buffered,
    uint8_t short_idle_after_response
);
static int vhttp_spawn_http2_task(
    int sock,
    uint32_t client_ip,
    const uint8_t *recv_buf,
    uint32_t recv_len,
    uint32_t recv_cap
);
static void vhttp_http2_task_ctx_free(vhttp_http2_task_ctx_t *ctx);
static uint8_t *vhttp_http2_alloc_buf(size_t len, uint8_t *out_psram);
static uint8_t *vhttp_http2_realloc_buf(uint8_t *old_ptr, size_t len, uint8_t *inout_psram);
static int vhttp_http2_hpack_huff_prepare(void);
static void vhttp_http2_session_dyn_reset(vhttp_http2_session_t *sess);
static int vhttp_http2_try_h2c_upgrade(
    int sock,
    uint32_t client_ip,
    uint8_t *recv_buf,
    size_t recv_cap,
    size_t buffered,
    const vhttp_parsed_request_t *req,
    uint8_t prefer_handoff,
    uint8_t short_idle_after_response
);
static int ws_is_upgrade_request(const vhttp_parsed_request_t *req);
static int handle_connection(vhttp_worker_ctx_t *ctx, int sock, uint32_t client_ip);
static int vhttp_wait_socket(int sock, int writable, uint32_t timeout_ms);
static int vhttp_recv_with_timeout(int sock, uint8_t *buf, size_t cap, uint32_t timeout_ms);
static int vhttp_sock_send(int sock, const uint8_t *buf, size_t len);
static int vhttp_sock_recv(int sock, uint8_t *buf, size_t len);
static int vhttp_https_server_init(void);
static void vhttp_https_server_deinit(void);
static int vhttp_https_session_open(int sock);
static void vhttp_https_session_close(int sock);
static uint8_t vhttp_https_session_is_h2(int sock);
static uint8_t vhttp_https_enabled_runtime(void);
static void vhttp_https_close_socket_if_open(int sock);
static void vhttp_evrt_h2_detach(vhttp_evrt_conn_t *conn);
static int vhttp_evrt_h2_activate(vhttp_evrt_conn_t *conn);
static int vhttp_evrt_h2_tick(vhttp_evrt_conn_t *conn, int socket_writable);
static int vhttp_http2_event_tx_has_pending(const vhttp_http2_event_ctx_t *ctx);
static int vhttp_http2_event_tx_queue_frame_for_sock(
    int sock,
    uint8_t type,
    uint8_t flags,
    uint32_t stream_id,
    const uint8_t *payload,
    uint32_t payload_len
);
static void vhttp_server_worker_task(void *arg);
static int vhttp_server_event_loop_run(void);
static vhttp_https_conn_t *vhttp_https_slot_for_sock(int sock);

static int vhttp_socket_fd_valid(int sock) {
    if (sock < 0) {
        return 0;
    }
    if (sock >= VHTTP_SELECT_SAFE_FD_MAX) {
        return 0;
    }
    errno = 0;
    if (fcntl(sock, F_GETFL, 0) < 0 && errno == EBADF) {
        return 0;
    }
    return 1;
}

static uint8_t vhttp_https_enabled_runtime(void) {
    uint8_t enabled = 0;
    taskENTER_CRITICAL(&g_https_cfg_lock);
    enabled = g_https_cfg.enabled ? 1u : 0u;
    taskEXIT_CRITICAL(&g_https_cfg_lock);
    return enabled;
}

static uint8_t vhttp_http2_enabled_runtime(void) {
    uint8_t enabled = 0;
    taskENTER_CRITICAL(&g_http2_cfg_lock);
    enabled = g_http2_cfg.enabled ? 1u : 0u;
    taskEXIT_CRITICAL(&g_http2_cfg_lock);
    return enabled;
}

static int vhttp_http2_prepare_slots(void) {
    if (g_http2_stream_slots) {
        return 0;
    }
    uint16_t max_streams = 0;
    taskENTER_CRITICAL(&g_http2_cfg_lock);
    max_streams = g_http2_cfg.max_streams;
    taskEXIT_CRITICAL(&g_http2_cfg_lock);
    if (max_streams == 0) {
        max_streams = 8;
    }

    size_t slots = (size_t)max_streams;
    vhttp_http2_stream_slot_t *mem = NULL;
    g_http2_stream_slots_in_psram = 0;
    #if defined(MALLOC_CAP_SPIRAM)
    mem = (vhttp_http2_stream_slot_t *)heap_caps_calloc(
        slots,
        sizeof(vhttp_http2_stream_slot_t),
        MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT
    );
    if (mem) {
        g_http2_stream_slots_in_psram = 1;
    }
    #endif
    if (!mem) {
        mem = (vhttp_http2_stream_slot_t *)heap_caps_calloc(
            slots,
            sizeof(vhttp_http2_stream_slot_t),
            MALLOC_CAP_8BIT
        );
    }
    if (!mem) {
        return -1;
    }
    g_http2_stream_slots = mem;
    return 0;
}

static void vhttp_http2_free_slots(void) {
    if (g_http2_stream_slots) {
        heap_caps_free(g_http2_stream_slots);
        g_http2_stream_slots = NULL;
    }
    g_http2_stream_slots_in_psram = 0;
}

static int vhttp_http2_hpack_huff_prepare(void) {
    if (g_http2_hpack_huff_ready) {
        return 0;
    }

    memset(g_http2_hpack_huff_nodes, 0, sizeof(g_http2_hpack_huff_nodes));
    g_http2_hpack_huff_nodes_used = 1;
    g_http2_hpack_huff_nodes[0].next[0] = -1;
    g_http2_hpack_huff_nodes[0].next[1] = -1;
    g_http2_hpack_huff_nodes[0].sym = -1;
    g_http2_hpack_huff_nodes[0].valid_end = 1u;

    for (uint16_t sym = 0; sym < 257; ++sym) {
        uint32_t code = g_http2_hpack_huff_code[sym];
        uint8_t nbits = g_http2_hpack_huff_nbits[sym];
        int16_t node = 0;
        if (nbits == 0 || nbits > 30) {
            return -1;
        }
        for (int bit_pos = (int)nbits - 1; bit_pos >= 0; --bit_pos) {
            uint8_t bit = (uint8_t)((code >> bit_pos) & 0x1u);
            int16_t next = g_http2_hpack_huff_nodes[node].next[bit];
            if (next < 0) {
                if (g_http2_hpack_huff_nodes_used >= VHTTP_HTTP2_HPACK_HUFF_MAX_NODES) {
                    return -1;
                }
                next = (int16_t)g_http2_hpack_huff_nodes_used++;
                g_http2_hpack_huff_nodes[next].next[0] = -1;
                g_http2_hpack_huff_nodes[next].next[1] = -1;
                g_http2_hpack_huff_nodes[next].sym = -1;
                g_http2_hpack_huff_nodes[next].valid_end = 0;
                g_http2_hpack_huff_nodes[node].next[bit] = next;
            }
            node = next;
        }
        if (g_http2_hpack_huff_nodes[node].sym >= 0) {
            return -1;
        }
        g_http2_hpack_huff_nodes[node].sym = (int16_t)sym;
    }

    int16_t node = 0;
    for (uint8_t depth = 0; depth < 7; ++depth) {
        int16_t next = g_http2_hpack_huff_nodes[node].next[1];
        if (next < 0) {
            break;
        }
        if (g_http2_hpack_huff_nodes[next].sym < 0) {
            g_http2_hpack_huff_nodes[next].valid_end = 1u;
        }
        node = next;
    }

    g_http2_hpack_huff_ready = 1u;
    return 0;
}

static void vhttp_http2_session_dyn_free_entry(vhttp_http2_hpack_dyn_entry_t *entry) {
    if (!entry || !entry->buf) {
        return;
    }
    heap_caps_free(entry->buf);
    memset(entry, 0, sizeof(*entry));
}

static void vhttp_http2_session_dyn_evict_last(vhttp_http2_session_t *sess) {
    if (!sess || sess->hpack_dyn_count == 0) {
        return;
    }
    uint16_t idx = (uint16_t)(sess->hpack_dyn_count - 1u);
    vhttp_http2_hpack_dyn_entry_t *entry = &sess->hpack_dyn[idx];
    if (sess->hpack_dyn_size >= entry->size) {
        sess->hpack_dyn_size -= entry->size;
    } else {
        sess->hpack_dyn_size = 0;
    }
    vhttp_http2_session_dyn_free_entry(entry);
    sess->hpack_dyn_count--;
}

static void vhttp_http2_session_dyn_trim(vhttp_http2_session_t *sess) {
    if (!sess) {
        return;
    }
    while (sess->hpack_dyn_count > 0 && sess->hpack_dyn_size > sess->hpack_dyn_max_size) {
        vhttp_http2_session_dyn_evict_last(sess);
    }
}

static void vhttp_http2_session_dyn_reset(vhttp_http2_session_t *sess) {
    if (!sess) {
        return;
    }
    while (sess->hpack_dyn_count > 0) {
        vhttp_http2_session_dyn_evict_last(sess);
    }
    sess->hpack_dyn_size = 0;
    sess->hpack_dyn_max_size = VHTTP_HTTP2_HPACK_TABLE_SIZE;
}

static int vhttp_http2_session_dyn_insert(
    vhttp_http2_session_t *sess,
    const uint8_t *name,
    size_t name_len,
    const uint8_t *value,
    size_t value_len
) {
    if (!sess || !name || name_len == 0 || !value) {
        return -1;
    }
    if (name_len > UINT16_MAX || value_len > UINT16_MAX) {
        return -1;
    }

    uint32_t entry_size = (uint32_t)name_len + (uint32_t)value_len + 32u;
    if (entry_size > sess->hpack_dyn_max_size) {
        vhttp_http2_session_dyn_reset(sess);
        return 0;
    }
    if (sess->hpack_dyn_count >= VHTTP_HTTP2_HPACK_DYN_MAX_ENTRIES) {
        vhttp_http2_session_dyn_evict_last(sess);
    }
    while (sess->hpack_dyn_count > 0 && (sess->hpack_dyn_size + entry_size) > sess->hpack_dyn_max_size) {
        vhttp_http2_session_dyn_evict_last(sess);
    }

    size_t total = name_len + value_len;
    if (total == 0) {
        return -1;
    }
    uint8_t *buf = vhttp_http2_alloc_buf(total, NULL);
    if (!buf) {
        return -1;
    }
    memcpy(buf, name, name_len);
    if (value_len > 0) {
        memcpy(buf + name_len, value, value_len);
    }

    if (sess->hpack_dyn_count > 0) {
        memmove(
            &sess->hpack_dyn[1],
            &sess->hpack_dyn[0],
            sizeof(sess->hpack_dyn[0]) * sess->hpack_dyn_count
        );
    }
    sess->hpack_dyn[0].buf = buf;
    sess->hpack_dyn[0].name_len = (uint16_t)name_len;
    sess->hpack_dyn[0].value_len = (uint16_t)value_len;
    sess->hpack_dyn[0].size = entry_size;
    sess->hpack_dyn_count++;
    sess->hpack_dyn_size += entry_size;
    vhttp_http2_session_dyn_trim(sess);
    return 0;
}

static vhttp_https_conn_t *vhttp_https_slot_for_sock(int sock) {
    if (sock < 0 || sock >= VHTTP_SELECT_SAFE_FD_MAX) {
        return NULL;
    }
    if (!g_https_conn) {
        return NULL;
    }
    return &g_https_conn[sock];
}

static int vhttp_https_bio_send(void *ctx, const unsigned char *buf, size_t len) {
    if (!ctx || !buf || len == 0) {
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    int sock = *((int *)ctx);
    int rc = send(sock, buf, len, MSG_DONTWAIT);
    if (rc >= 0) {
        return rc;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    return MBEDTLS_ERR_NET_SEND_FAILED;
}

static int vhttp_https_bio_recv(void *ctx, unsigned char *buf, size_t len) {
    if (!ctx || !buf || len == 0) {
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    int sock = *((int *)ctx);
    int rc = recv(sock, buf, len, MSG_DONTWAIT);
    if (rc > 0) {
        return rc;
    }
    if (rc == 0) {
        return MBEDTLS_ERR_SSL_CONN_EOF;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    return MBEDTLS_ERR_NET_RECV_FAILED;
}

static void vhttp_https_server_deinit(void) {
    if (g_https_conn) {
        for (size_t i = 0; i < (size_t)VHTTP_SELECT_SAFE_FD_MAX; ++i) {
            if (!g_https_conn[i].active) {
                continue;
            }
            (void)mbedtls_ssl_close_notify(&g_https_conn[i].ssl);
            mbedtls_ssl_free(&g_https_conn[i].ssl);
            g_https_conn[i].active = 0;
            g_https_conn[i].alpn_h2 = 0;
            g_https_conn[i].sock = -1;
        }
        heap_caps_free(g_https_conn);
        g_https_conn = NULL;
    }
    if (!g_https_server.initialized) {
        return;
    }
    mbedtls_ssl_config_free(&g_https_server.conf);
    mbedtls_pk_free(&g_https_server.key);
    mbedtls_x509_crt_free(&g_https_server.cert);
    mbedtls_ctr_drbg_free(&g_https_server.ctr_drbg);
    mbedtls_entropy_free(&g_https_server.entropy);
    memset(&g_https_server, 0, sizeof(g_https_server));
}

static int vhttp_https_server_init(void) {
    if (!vhttp_https_enabled_runtime()) {
        vhttp_https_server_deinit();
        return 0;
    }
    if (g_https_server.initialized) {
        return 0;
    }
    if (!g_https_conn) {
        size_t slots = (size_t)VHTTP_SELECT_SAFE_FD_MAX;
        vhttp_https_conn_t *conn_slots = NULL;
        #if defined(MALLOC_CAP_SPIRAM)
        conn_slots = (vhttp_https_conn_t *)heap_caps_calloc(
            slots,
            sizeof(vhttp_https_conn_t),
            MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT
        );
        #endif
        if (!conn_slots) {
            conn_slots = (vhttp_https_conn_t *)heap_caps_calloc(
                slots,
                sizeof(vhttp_https_conn_t),
                MALLOC_CAP_8BIT
            );
        }
        if (!conn_slots) {
            return -1;
        }
        for (size_t i = 0; i < slots; ++i) {
            conn_slots[i].sock = -1;
        }
        g_https_conn = conn_slots;
    }

    int rc = 0;
    const char *pers = "viperhttp_https";
    memset(&g_https_server, 0, sizeof(g_https_server));
    mbedtls_x509_crt_init(&g_https_server.cert);
    mbedtls_pk_init(&g_https_server.key);
    mbedtls_ssl_config_init(&g_https_server.conf);
    mbedtls_ctr_drbg_init(&g_https_server.ctr_drbg);
    mbedtls_entropy_init(&g_https_server.entropy);

    taskENTER_CRITICAL(&g_https_cfg_lock);
    const char *cert = g_https_cfg.cert_pem;
    size_t cert_len = g_https_cfg.cert_pem_len;
    const char *key = g_https_cfg.key_pem;
    size_t key_len = g_https_cfg.key_pem_len;
    taskEXIT_CRITICAL(&g_https_cfg_lock);

    if (!cert || !key || cert_len == 0 || key_len == 0) {
        return -1;
    }

    rc = mbedtls_ctr_drbg_seed(
        &g_https_server.ctr_drbg,
        mbedtls_entropy_func,
        &g_https_server.entropy,
        (const unsigned char *)pers,
        strlen(pers)
    );
    if (rc != 0) {
        vhttp_https_server_deinit();
        return -1;
    }
    rc = mbedtls_x509_crt_parse(
        &g_https_server.cert,
        (const unsigned char *)cert,
        cert_len
    );
    if (rc != 0) {
        vhttp_https_server_deinit();
        return -1;
    }
    #if defined(MBEDTLS_VERSION_MAJOR) && (MBEDTLS_VERSION_MAJOR >= 3)
    rc = mbedtls_pk_parse_key(
        &g_https_server.key,
        (const unsigned char *)key,
        key_len,
        NULL,
        0,
        mbedtls_ctr_drbg_random,
        &g_https_server.ctr_drbg
    );
    #else
    rc = mbedtls_pk_parse_key(
        &g_https_server.key,
        (const unsigned char *)key,
        key_len,
        NULL,
        0
    );
    #endif
    if (rc != 0) {
        vhttp_https_server_deinit();
        return -1;
    }
    rc = mbedtls_ssl_config_defaults(
        &g_https_server.conf,
        MBEDTLS_SSL_IS_SERVER,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT
    );
    if (rc != 0) {
        vhttp_https_server_deinit();
        return -1;
    }
    mbedtls_ssl_conf_rng(&g_https_server.conf, mbedtls_ctr_drbg_random, &g_https_server.ctr_drbg);
    rc = mbedtls_ssl_conf_own_cert(&g_https_server.conf, &g_https_server.cert, &g_https_server.key);
    if (rc != 0) {
        vhttp_https_server_deinit();
        return -1;
    }
#if defined(MBEDTLS_SSL_ALPN)
    const char **alpn = vhttp_http2_enabled_runtime() ? g_vhttp_alpn_h2 : g_vhttp_alpn_http11;
    rc = mbedtls_ssl_conf_alpn_protocols(&g_https_server.conf, alpn);
    if (rc != 0) {
        vhttp_https_server_deinit();
        return -1;
    }
#endif

    g_https_server.initialized = 1;
    return 0;
}

static int vhttp_https_session_open(int sock) {
    if (!g_https_server.initialized || !vhttp_socket_fd_valid(sock)) {
        return -1;
    }
    vhttp_https_conn_t *slot = vhttp_https_slot_for_sock(sock);
    if (!slot) {
        return -1;
    }
    if (slot->active) {
        (void)mbedtls_ssl_close_notify(&slot->ssl);
        mbedtls_ssl_free(&slot->ssl);
        slot->active = 0;
        slot->alpn_h2 = 0;
    }
    mbedtls_ssl_init(&slot->ssl);
    slot->sock = sock;
    slot->alpn_h2 = 0;
    int rc = mbedtls_ssl_setup(&slot->ssl, &g_https_server.conf);
    if (rc != 0) {
        mbedtls_ssl_free(&slot->ssl);
        slot->sock = -1;
        return -1;
    }
    mbedtls_ssl_set_bio(&slot->ssl, &slot->sock, vhttp_https_bio_send, vhttp_https_bio_recv, NULL);

    TickType_t started = xTaskGetTickCount();
    TickType_t timeout = pdMS_TO_TICKS(VHTTP_HTTPS_HANDSHAKE_TIMEOUT_MS);
    if (timeout == 0) {
        timeout = 1;
    }
    for (;;) {
        rc = mbedtls_ssl_handshake(&slot->ssl);
        if (rc == 0) {
            slot->active = 1;
#if defined(MBEDTLS_SSL_ALPN)
            const char *alpn = mbedtls_ssl_get_alpn_protocol(&slot->ssl);
            if (alpn && strcmp(alpn, "h2") == 0) {
                slot->alpn_h2 = 1u;
            }
#endif
            vhttp_stats_inc(&g_server_stats.https_handshake_ok);
            return 0;
        }
        if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
            if ((TickType_t)(xTaskGetTickCount() - started) >= timeout) {
                break;
            }
            int writable = (rc == MBEDTLS_ERR_SSL_WANT_WRITE) ? 1 : 0;
            int wait_rc = vhttp_wait_socket(sock, writable, VHTTP_SERVER_IO_WAIT_SLICE_MS);
            if (wait_rc < 0) {
                break;
            }
            continue;
        }
        break;
    }

    vhttp_stats_inc(&g_server_stats.https_handshake_fail);
    mbedtls_ssl_free(&slot->ssl);
    slot->active = 0;
    slot->alpn_h2 = 0;
    slot->sock = -1;
    return -1;
}

static void vhttp_https_session_close(int sock) {
    vhttp_https_conn_t *slot = vhttp_https_slot_for_sock(sock);
    if (!slot) {
        return;
    }
    if (!slot->active) {
        return;
    }
    (void)mbedtls_ssl_close_notify(&slot->ssl);
    mbedtls_ssl_free(&slot->ssl);
    slot->active = 0;
    slot->alpn_h2 = 0;
    slot->sock = -1;
}

static uint8_t vhttp_https_session_is_h2(int sock) {
    vhttp_https_conn_t *slot = vhttp_https_slot_for_sock(sock);
    if (!slot || !slot->active) {
        return 0;
    }
    return slot->alpn_h2 ? 1u : 0u;
}

static void vhttp_https_close_socket_if_open(int sock) {
    vhttp_https_session_close(sock);
}

static int vhttp_sock_send(int sock, const uint8_t *buf, size_t len) {
    vhttp_https_conn_t *slot = vhttp_https_slot_for_sock(sock);
    if (slot && slot->active) {
        int rc = mbedtls_ssl_write(&slot->ssl, buf, len);
        if (rc > 0) {
            return rc;
        }
        if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
            errno = EAGAIN;
            return -1;
        }
        if (rc == MBEDTLS_ERR_SSL_CONN_EOF
#ifdef MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY
            || rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY
#endif
        ) {
            errno = ECONNRESET;
            return 0;
        }
        errno = EIO;
        return -1;
    }
    return send(sock, buf, len, MSG_DONTWAIT);
}

static int vhttp_sock_recv(int sock, uint8_t *buf, size_t len) {
    vhttp_https_conn_t *slot = vhttp_https_slot_for_sock(sock);
    if (slot && slot->active) {
        int rc = mbedtls_ssl_read(&slot->ssl, buf, len);
        if (rc > 0) {
            return rc;
        }
        if (rc == 0 || rc == MBEDTLS_ERR_SSL_CONN_EOF
#ifdef MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY
            || rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY
#endif
        ) {
            return 0;
        }
        if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
            errno = EAGAIN;
            return -1;
        }
        errno = EIO;
        return -1;
    }
    return recv(sock, buf, len, MSG_DONTWAIT);
}

static size_t vhttp_server_target_max_workers(void) {
    size_t max_workers = g_worker_limit_max;
    if (max_workers == 0 || max_workers > (size_t)VHTTP_SERVER_WORKERS) {
        max_workers = (size_t)VHTTP_SERVER_WORKERS;
    }
    return max_workers;
}

static size_t vhttp_server_target_min_workers(void) {
    size_t max_workers = vhttp_server_target_max_workers();
    size_t min_workers = g_worker_limit_min;
    if (min_workers == 0) {
        min_workers = 1;
    }
    if (min_workers > max_workers) {
        min_workers = max_workers;
    }
    return min_workers;
}

static int vhttp_psram_available_cached(void) {
    if (!g_psram_checked) {
        size_t total = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);
        g_psram_available = total > 0 ? 1 : 0;
        g_psram_checked = 1;
    }
    return g_psram_available ? 1 : 0;
}

static void vhttp_evrt_conn_reset_slot(vhttp_evrt_conn_t *conn) {
    if (!conn) {
        return;
    }
    memset(conn, 0, sizeof(*conn));
    conn->sock = -1;
    conn->state = VHTTP_EVRT_FREE;
}

static void vhttp_evrt_reset_all(void) {
    for (size_t i = 0; i < (size_t)VHTTP_EVENT_LOOP_MAX_CONNS; ++i) {
        vhttp_evrt_conn_reset_slot(&g_evrt_conns[i]);
    }
}

static uint8_t *vhttp_evrt_alloc_recv_buf(uint8_t *out_in_psram) {
    uint8_t *buf = NULL;
    uint8_t in_psram = 0;
    if (vhttp_psram_available_cached()) {
        buf = (uint8_t *)heap_caps_malloc(VHTTP_RECV_BUF_SIZE, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (buf) {
            in_psram = 1;
        }
    }
    if (!buf) {
        buf = (uint8_t *)heap_caps_malloc(VHTTP_RECV_BUF_SIZE, MALLOC_CAP_8BIT);
        in_psram = 0;
    }
    if (out_in_psram) {
        *out_in_psram = in_psram;
    }
    return buf;
}

static void vhttp_evrt_consume_buffer(vhttp_evrt_conn_t *conn, size_t consumed) {
    if (!conn || consumed == 0) {
        return;
    }
    if (consumed >= conn->buffered) {
        conn->buffered = 0;
        return;
    }
    memmove(conn->recv_buf, conn->recv_buf + consumed, conn->buffered - consumed);
    conn->buffered -= consumed;
}

static void vhttp_evrt_close_socket(vhttp_evrt_conn_t *conn) {
    if (!conn || conn->sock < 0) {
        return;
    }
    vhttp_https_close_socket_if_open(conn->sock);
    shutdown(conn->sock, SHUT_RDWR);
    close(conn->sock);
    vhttp_ev_conn_on_closed(conn->sock);
    conn->sock = -1;
}

static void vhttp_evrt_release_slot(vhttp_evrt_conn_t *conn) {
    if (!conn) {
        return;
    }
    if (conn->h2_ctx) {
        vhttp_evrt_h2_detach(conn);
    }
    vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
    if (ipc) {
        if (conn->tx_release_body_len > 0) {
            vhttp_ipc_ring_release(&ipc->ring, conn->tx_release_body_len);
            conn->tx_release_body_len = 0;
        }
        if (conn->tx_release_headers_len > 0) {
            vhttp_ipc_ring_release(&ipc->ring, conn->tx_release_headers_len);
            conn->tx_release_headers_len = 0;
        }
    }
    if (conn->request_id != 0 || conn->request_blob_len > 0) {
        if (ipc) {
            vhttp_abort_inflight_request(ipc, conn->request_id, &conn->request_blob_len);
        } else {
            conn->request_blob_len = 0;
        }
        conn->request_id = 0;
    }
    if (conn->sock >= 0) {
        vhttp_evrt_close_socket(conn);
    }
    if (conn->recv_buf) {
        free(conn->recv_buf);
        conn->recv_buf = NULL;
    }
    vhttp_evrt_conn_reset_slot(conn);
}

static int vhttp_evrt_claim_slot(int sock, uint32_t client_ip) {
    for (size_t i = 0; i < (size_t)VHTTP_EVENT_LOOP_MAX_CONNS; ++i) {
        vhttp_evrt_conn_t *conn = &g_evrt_conns[i];
        if (conn->used) {
            continue;
        }
        uint8_t in_psram = 0;
        uint8_t *buf = vhttp_evrt_alloc_recv_buf(&in_psram);
        if (!buf) {
            return -1;
        }
        vhttp_evrt_conn_reset_slot(conn);
        conn->used = 1;
        conn->sock = sock;
        conn->client_ip = client_ip;
        conn->state = VHTTP_EVRT_READ_REQ;
        conn->recv_buf = buf;
        conn->recv_cap = VHTTP_RECV_BUF_SIZE;
        conn->recv_in_psram = in_psram;
        conn->state_since = xTaskGetTickCount();
        conn->cors_headers_len = 0;
        conn->cors_headers[0] = '\0';
        return (int)i;
    }
    return -1;
}

static void vhttp_evrt_tx_reset(vhttp_evrt_conn_t *conn) {
    if (!conn) {
        return;
    }
    conn->tx_active = 0;
    conn->tx_stream = 0;
    conn->tx_final = 0;
    conn->tx_close_after = 0;
    conn->tx_chunked = 0;
    conn->tx_send_final_chunk = 0;
    conn->tx_chunk_suffix_len = 0;
    conn->tx_chunk_suffix_sent = 0;
    conn->tx_chunk_prefix_len = 0;
    conn->tx_chunk_prefix_sent = 0;
    conn->tx_header_len = 0;
    conn->tx_header_sent = 0;
    conn->tx_body_offset = 0;
    conn->tx_body_len = 0;
    conn->tx_body_sent = 0;
    conn->tx_release_body_len = 0;
    conn->tx_release_headers_len = 0;
}

static int vhttp_evrt_send_partial(int sock, const uint8_t *buf, size_t len, size_t *sent) {
    if (!buf || !sent) {
        return -1;
    }
    if (*sent >= len) {
        return 1;
    }
    int rc = vhttp_sock_send(sock, buf + *sent, len - *sent);
    if (rc > 0) {
        *sent += (size_t)rc;
        return (*sent >= len) ? 1 : 2;
    }
    if (rc == 0) {
        return -1;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        return 0;
    }
    return -1;
}

static int vhttp_evrt_prepare_chunk_frame(vhttp_evrt_conn_t *conn, uint32_t body_len) {
    if (!conn) {
        return -1;
    }
    conn->tx_chunk_prefix_len = 0;
    conn->tx_chunk_prefix_sent = 0;
    conn->tx_chunk_suffix_len = 0;
    conn->tx_chunk_suffix_sent = 0;

    if (!conn->tx_chunked) {
        return 0;
    }

    int n = snprintf(conn->tx_chunk_prefix, sizeof(conn->tx_chunk_prefix), "%x\r\n", (unsigned int)body_len);
    if (n < 0 || (size_t)n >= sizeof(conn->tx_chunk_prefix)) {
        return -1;
    }
    conn->tx_chunk_prefix_len = (uint8_t)n;
    conn->tx_chunk_suffix_len = 2;
    conn->tx_chunk_suffix_sent = 0;
    return 0;
}

static int vhttp_evrt_prepare_tx_from_ipc(vhttp_evrt_conn_t *conn, const vhttp_ipc_msg_t *resp, vhttp_ipc_state_t *ipc) {
    if (!conn || !resp || !ipc) {
        return -1;
    }
    if (conn->tx_active) {
        return -1;
    }

    uint32_t resp_body_len = resp->body_len;
    uint16_t resp_headers_len = resp->headers_len;
    const uint8_t *headers_ptr = NULL;
    if (resp_headers_len > 0) {
        headers_ptr = vhttp_ipc_ring_ptr(&ipc->ring, resp->headers_offset);
        if (!headers_ptr) {
            return -1;
        }
    }
    if (resp_body_len > 0) {
        if (!vhttp_ipc_ring_ptr(&ipc->ring, resp->buffer_offset)) {
            return -1;
        }
    }

    uint8_t is_stream = (resp->flags & VHTTP_IPC_FLAG_STREAM) ? 1u : 0u;
    if (is_stream && !conn->stream_active) {
        conn->stream_active = 1;
        conn->stream_use_chunked = ((resp->flags & VHTTP_IPC_FLAG_CHUNKED) && !conn->head_only) ? 1u : 0u;
        conn->stream_header_sent = 0;
        vhttp_stats_conn_state_hit(VHTTP_CONN_STATE_STREAM);
    }

    vhttp_evrt_tx_reset(conn);
    conn->tx_active = 1;
    conn->tx_stream = is_stream;
    conn->tx_final = is_stream ? ((resp->flags & VHTTP_IPC_FLAG_FINAL) ? 1u : 0u) : 1u;
    conn->tx_close_after = conn->keep_alive ? 0u : 1u;
    conn->tx_chunked = is_stream ? conn->stream_use_chunked : 0u;
    conn->tx_body_offset = resp->buffer_offset;
    conn->tx_body_len = conn->head_only ? 0u : resp_body_len;
    conn->tx_body_sent = 0;
    conn->tx_release_body_len = resp_body_len;
    conn->tx_release_headers_len = resp_headers_len;

    if ((!is_stream) || (is_stream && !conn->stream_header_sent)) {
        const char *conn_hdr = conn->keep_alive ? "keep-alive" : "close";
        int final_status = resp->status_code == 0 ? 200 : resp->status_code;
        int header_len = 0;

        if (conn->tx_chunked) {
            header_len = snprintf(
                conn->tx_header,
                sizeof(conn->tx_header),
                "HTTP/1.1 %d %s\r\nTransfer-Encoding: chunked\r\n%.*s%.*sConnection: %s\r\n\r\n",
                final_status,
                status_reason(final_status),
                (int)resp_headers_len,
                resp_headers_len > 0 ? (const char *)headers_ptr : "",
                (int)conn->cors_headers_len,
                conn->cors_headers_len > 0 ? conn->cors_headers : "",
                conn_hdr
            );
        } else {
            uint32_t content_len = resp_body_len;
            if (is_stream) {
                content_len = resp->total_len ? resp->total_len : resp_body_len;
            }
            header_len = snprintf(
                conn->tx_header,
                sizeof(conn->tx_header),
                "HTTP/1.1 %d %s\r\nContent-Length: %u\r\n%.*s%.*sConnection: %s\r\n\r\n",
                final_status,
                status_reason(final_status),
                (unsigned int)content_len,
                (int)resp_headers_len,
                resp_headers_len > 0 ? (const char *)headers_ptr : "",
                (int)conn->cors_headers_len,
                conn->cors_headers_len > 0 ? conn->cors_headers : "",
                conn_hdr
            );
        }
        if (header_len < 0 || (size_t)header_len >= sizeof(conn->tx_header)) {
            vhttp_evrt_tx_reset(conn);
            return -1;
        }
        conn->tx_header_len = (uint16_t)header_len;
        conn->tx_header_sent = 0;
        if (is_stream) {
            conn->stream_header_sent = 1;
        }
    }

    if (conn->tx_chunked) {
        if (conn->tx_body_len > 0) {
            if (vhttp_evrt_prepare_chunk_frame(conn, conn->tx_body_len) != 0) {
                vhttp_evrt_tx_reset(conn);
                return -1;
            }
            if (conn->tx_final) {
                conn->tx_send_final_chunk = 1;
            }
        } else if (conn->tx_final) {
            if (vhttp_evrt_prepare_chunk_frame(conn, 0) != 0) {
                vhttp_evrt_tx_reset(conn);
                return -1;
            }
        }
    }

    return 0;
}

static void vhttp_evrt_release_tx_payload(vhttp_evrt_conn_t *conn, vhttp_ipc_state_t *ipc) {
    if (!conn || !ipc) {
        return;
    }
    if (conn->tx_release_body_len > 0) {
        vhttp_ipc_ring_release(&ipc->ring, conn->tx_release_body_len);
        conn->tx_release_body_len = 0;
    }
    if (conn->tx_release_headers_len > 0) {
        vhttp_ipc_ring_release(&ipc->ring, conn->tx_release_headers_len);
        conn->tx_release_headers_len = 0;
    }
}

static int vhttp_evrt_flush_tx(vhttp_evrt_conn_t *conn, vhttp_ipc_state_t *ipc) {
    if (!conn || !ipc) {
        return -1;
    }
    if (!conn->tx_active) {
        return 0;
    }

    uint32_t progressed = 0;
    for (uint32_t budget = 0; budget < 32; ++budget) {
        if (conn->tx_header_sent < conn->tx_header_len) {
            size_t sent = conn->tx_header_sent;
            int rc = vhttp_evrt_send_partial(conn->sock, (const uint8_t *)conn->tx_header, conn->tx_header_len, &sent);
            conn->tx_header_sent = (uint16_t)sent;
            if (rc < 0) {
                return -1;
            }
            if (rc == 0) {
                break;
            }
            progressed = 1;
            continue;
        }

        if (conn->tx_chunk_prefix_sent < conn->tx_chunk_prefix_len) {
            size_t sent = conn->tx_chunk_prefix_sent;
            int rc = vhttp_evrt_send_partial(conn->sock, (const uint8_t *)conn->tx_chunk_prefix, conn->tx_chunk_prefix_len, &sent);
            conn->tx_chunk_prefix_sent = (uint8_t)sent;
            if (rc < 0) {
                return -1;
            }
            if (rc == 0) {
                break;
            }
            progressed = 1;
            continue;
        }

        if (conn->tx_body_sent < conn->tx_body_len) {
            const uint8_t *body_ptr = vhttp_ipc_ring_ptr(&ipc->ring, conn->tx_body_offset);
            if (!body_ptr) {
                return -1;
            }
            size_t sent = conn->tx_body_sent;
            int rc = vhttp_evrt_send_partial(conn->sock, body_ptr, conn->tx_body_len, &sent);
            conn->tx_body_sent = (uint32_t)sent;
            if (rc < 0) {
                return -1;
            }
            if (rc == 0) {
                break;
            }
            progressed = 1;
            if (conn->tx_stream && conn->tx_chunked && conn->tx_body_sent == conn->tx_body_len) {
                vhttp_stats_inc(&g_server_stats.stream_chunks_sent);
            }
            continue;
        }

        if (conn->tx_chunk_suffix_sent < conn->tx_chunk_suffix_len) {
            static const uint8_t crlf[2] = {'\r', '\n'};
            size_t sent = conn->tx_chunk_suffix_sent;
            int rc = vhttp_evrt_send_partial(conn->sock, crlf, conn->tx_chunk_suffix_len, &sent);
            conn->tx_chunk_suffix_sent = (uint8_t)sent;
            if (rc < 0) {
                return -1;
            }
            if (rc == 0) {
                break;
            }
            progressed = 1;
            continue;
        }

        vhttp_evrt_release_tx_payload(conn, ipc);

        if (conn->tx_send_final_chunk) {
            conn->tx_send_final_chunk = 0;
            conn->tx_body_offset = 0;
            conn->tx_body_len = 0;
            conn->tx_body_sent = 0;
            conn->tx_release_body_len = 0;
            conn->tx_release_headers_len = 0;
            if (vhttp_evrt_prepare_chunk_frame(conn, 0) != 0) {
                return -1;
            }
            continue;
        }

        uint8_t request_complete = conn->tx_final;
        uint8_t close_after = conn->tx_close_after;
        uint8_t was_stream = conn->tx_stream;
        uint32_t req_id = conn->request_id;
        vhttp_evrt_tx_reset(conn);

        if (!request_complete) {
            conn->state_since = xTaskGetTickCount();
            return progressed ? 1 : 0;
        }

        if (was_stream) {
            conn->stream_active = 0;
            conn->stream_use_chunked = 0;
            conn->stream_header_sent = 0;
        }
        if (g_resp_mux && req_id != 0 && xSemaphoreTake(g_resp_mux, 0) == pdTRUE) {
            vhttp_request_cancel_clear_nolock(req_id);
            xSemaphoreGive(g_resp_mux);
        }
        vhttp_stats_inc(&g_server_stats.requests_handled);
        conn->state = VHTTP_EVRT_READ_REQ;
        conn->request_id = 0;
        conn->state_since = xTaskGetTickCount();
        return close_after ? -1 : 1;
    }

    if (progressed) {
        conn->state_since = xTaskGetTickCount();
    }
    return 0;
}

static int vhttp_worker_buffer_alloc(size_t index) {
    if (index >= (size_t)VHTTP_SERVER_WORKERS) {
        return -1;
    }
    if (g_worker_ctx[index].recv_buf) {
        return 0;
    }

    uint8_t *buf = NULL;
    uint8_t in_psram = 0;
    if (vhttp_psram_available_cached()) {
        buf = (uint8_t *)heap_caps_malloc(VHTTP_RECV_BUF_SIZE, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (buf) {
            in_psram = 1;
        }
    }
    if (!buf) {
        buf = (uint8_t *)heap_caps_malloc(VHTTP_RECV_BUF_SIZE, MALLOC_CAP_8BIT);
        in_psram = 0;
    }
    if (!buf) {
        return -1;
    }
    g_worker_ctx[index].recv_buf = buf;
    g_worker_ctx[index].recv_cap = VHTTP_RECV_BUF_SIZE;
    g_worker_ctx[index].recv_in_psram = in_psram;
    return 0;
}

static void vhttp_worker_buffer_free(size_t index) {
    if (index >= (size_t)VHTTP_SERVER_WORKERS) {
        return;
    }
    if (g_worker_ctx[index].recv_buf) {
        free(g_worker_ctx[index].recv_buf);
        g_worker_ctx[index].recv_buf = NULL;
    }
    g_worker_ctx[index].recv_cap = 0;
    g_worker_ctx[index].recv_in_psram = 0;
}

static int vhttp_server_start_worker_at(size_t index) {
    size_t max_workers = vhttp_server_target_max_workers();
    if (index >= max_workers || index >= (size_t)VHTTP_SERVER_WORKERS) {
        return -1;
    }
    if (g_worker_tasks[index]) {
        if (index + 1 > g_worker_count) {
            g_worker_count = index + 1;
        }
        return 0;
    }
    if (vhttp_worker_buffer_alloc(index) != 0) {
        return -1;
    }
    g_worker_ctx[index].index = index;

    char name[16];
    (void)snprintf(name, sizeof(name), "vhttp_w%u", (unsigned int)index);
    BaseType_t ok = xTaskCreatePinnedToCore(
        vhttp_server_worker_task,
        name,
        VHTTP_SERVER_WORKER_STACK_SIZE,
        &g_worker_ctx[index],
        VHTTP_SERVER_TASK_PRIO,
        &g_worker_tasks[index],
        0
    );
    if (ok != pdPASS) {
        g_worker_tasks[index] = NULL;
        vhttp_worker_buffer_free(index);
        return -1;
    }
    g_worker_count = index + 1;
    taskENTER_CRITICAL(&g_stats_lock);
    g_server_stats.workers_started = (uint32_t)g_worker_count;
    taskEXIT_CRITICAL(&g_stats_lock);
    return 0;
}

static void vhttp_server_try_scale_workers(void) {
    if (!g_server_running || !g_accept_queue) {
        return;
    }
    size_t max_workers = vhttp_server_target_max_workers();
    if (g_worker_count >= max_workers) {
        return;
    }

    UBaseType_t q_used = uxQueueMessagesWaiting(g_accept_queue);
    if (q_used < (UBaseType_t)VHTTP_SERVER_SCALE_UP_QUEUE_THRESHOLD) {
        return;
    }

    TickType_t now = xTaskGetTickCount();
    if (g_worker_scale_block_until != 0 && now < g_worker_scale_block_until) {
        return;
    }
    TickType_t cooldown = pdMS_TO_TICKS(VHTTP_SERVER_SCALE_UP_COOLDOWN_MS);
    if (cooldown == 0) {
        cooldown = 1;
    }
    if (g_worker_scale_last_tick != 0 &&
        (TickType_t)(now - g_worker_scale_last_tick) < cooldown) {
        return;
    }
    g_worker_scale_last_tick = now;

    size_t threshold = (size_t)VHTTP_SERVER_SCALE_UP_QUEUE_THRESHOLD;
    if (threshold == 0) {
        threshold = 1;
    }
    size_t burst = 1;
    if ((size_t)q_used >= threshold * 8u) {
        burst = 3;
    } else if ((size_t)q_used >= threshold * 4u) {
        burst = 2;
    }
    size_t target = g_worker_count + burst;
    size_t pressure_target = (size_t)q_used + 1u;
    if (pressure_target > target) {
        target = pressure_target;
    }
    if (target > max_workers) {
        target = max_workers;
    }

    size_t to_start = target > g_worker_count ? (target - g_worker_count) : 0;
    size_t started = 0;
    for (size_t i = 0; i < to_start; ++i) {
        size_t next_index = g_worker_count;
        if (vhttp_server_start_worker_at(next_index) != 0) {
            break;
        }
        started++;
    }

    if (started > 0) {
        g_worker_scale_block_until = 0;
        VHTTP_LOGI(
            "worker scale-up: +%u active=%u/%u queue=%u",
            (unsigned int)started,
            (unsigned int)g_worker_count,
            (unsigned int)max_workers,
            (unsigned int)q_used
        );
    } else {
        TickType_t fail_cooldown = pdMS_TO_TICKS(VHTTP_SERVER_SCALE_UP_FAIL_COOLDOWN_MS);
        if (fail_cooldown == 0) {
            fail_cooldown = cooldown;
        }
        g_worker_scale_block_until = now + fail_cooldown;
        VHTTP_LOGW(
            "worker scale-up failed idx=%u queue=%u cooldown_ms=%u",
            (unsigned int)g_worker_count,
            (unsigned int)q_used,
            (unsigned int)VHTTP_SERVER_SCALE_UP_FAIL_COOLDOWN_MS
        );
    }
}

static int vhttp_set_socket_nonblocking(int sock) {
    // Favor low-latency interactive HTTP over coalescing tiny packets.
#ifdef TCP_NODELAY
    int nodelay = 1;
    (void)setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
#endif

    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    if ((flags & O_NONBLOCK) != 0) {
        return 0;
    }
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

static int vhttp_wait_socket(int sock, int writable, uint32_t timeout_ms) {
    if (!vhttp_socket_fd_valid(sock)) {
        return -1;
    }

    uint32_t waited_ms = 0;
    while (g_server_running && waited_ms < timeout_ms) {
        uint32_t slice_ms = timeout_ms - waited_ms;
        if (slice_ms > VHTTP_SERVER_IO_WAIT_SLICE_MS) {
            slice_ms = VHTTP_SERVER_IO_WAIT_SLICE_MS;
        }
        struct timeval tv;
        tv.tv_sec = (int)(slice_ms / 1000u);
        tv.tv_usec = (int)((slice_ms % 1000u) * 1000u);

        fd_set rfds;
        fd_set wfds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        if (writable) {
            FD_SET(sock, &wfds);
        } else {
            FD_SET(sock, &rfds);
        }

        int rc = select(
            sock + 1,
            writable ? NULL : &rfds,
            writable ? &wfds : NULL,
            NULL,
            &tv
        );
        if (rc > 0) {
            return 1;
        }
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        waited_ms += slice_ms;
    }
    return 0;
}

static int vhttp_recv_with_timeout(int sock, uint8_t *buf, size_t cap, uint32_t timeout_ms) {
    if (!buf || cap == 0) {
        return -1;
    }
    if (!vhttp_socket_fd_valid(sock)) {
        return -1;
    }

    for (;;) {
        int rc = vhttp_sock_recv(sock, buf, cap);
        if (rc > 0 || rc == 0) {
            return rc;
        }

        if (errno == EINTR) {
            continue;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            int ready = vhttp_wait_socket(sock, 0, timeout_ms);
            if (ready <= 0) {
                return (ready == 0) ? -2 : -1;
            }
            continue;
        }

        return -1;
    }
}

#if !VHTTP_STATIC_SERVE_VIA_IPC
static int header_accepts_gzip(const vhttp_parsed_request_t *req) {
    const vhttp_header_t *hdr = find_header(req, "accept-encoding");
    if (!hdr || !hdr->value || hdr->value_len == 0) {
        return 0;
    }

    const char *p = hdr->value;
    size_t len = hdr->value_len;
    size_t i = 0;
    while (i < len) {
        while (i < len && (p[i] == ' ' || p[i] == '\t' || p[i] == ',')) {
            i++;
        }
        size_t start = i;
        while (i < len && p[i] != ',') {
            i++;
        }
        size_t end = i;
        while (end > start && (p[end - 1] == ' ' || p[end - 1] == '\t')) {
            end--;
        }
        if (end <= start) {
            continue;
        }

        size_t token_len = end - start;
        const char *token = p + start;

        size_t name_len = 0;
        while (name_len < token_len && token[name_len] != ';' &&
               token[name_len] != ' ' && token[name_len] != '\t') {
            name_len++;
        }
        if (name_len >= 4 &&
            slice_ci_equals_n(token, name_len, "gzip")) {
            size_t params_start = name_len;
            while (params_start < token_len) {
                while (params_start < token_len &&
                       (token[params_start] == ' ' || token[params_start] == '\t')) {
                    params_start++;
                }
                if (params_start >= token_len) {
                    break;
                }
                if (token[params_start] != ';') {
                    break;
                }
                params_start++;
                while (params_start < token_len &&
                       (token[params_start] == ' ' || token[params_start] == '\t')) {
                    params_start++;
                }
                if (params_start + 2 <= token_len &&
                    (token[params_start] == 'q' || token[params_start] == 'Q') &&
                    token[params_start + 1] == '=') {
                    const char *qval = token + params_start + 2;
                    size_t qlen = token_len - (params_start + 2);
                    while (qlen > 0 && (*qval == ' ' || *qval == '\t')) {
                        qval++;
                        qlen--;
                    }
                    if (qlen == 1 && qval[0] == '0') {
                        return 0;
                    }
                    if (qlen >= 2 && qval[0] == '0' && qval[1] == '.') {
                        int all_zero = 1;
                        for (size_t j = 2; j < qlen; ++j) {
                            if (qval[j] != '0') {
                                all_zero = 0;
                                break;
                            }
                        }
                        if (all_zero) {
                            return 0;
                        }
                    }
                    return 1;
                }
                while (params_start < token_len && token[params_start] != ';') {
                    params_start++;
                }
            }
            return 1;
        }
    }

    return 0;
}
#endif

static int method_from_str(const char *method, size_t len, uint8_t *out) {
    if (len == 3 && memcmp(method, "GET", 3) == 0) {
        *out = VHTTP_METHOD_GET;
        return 0;
    }
    if (len == 4 && memcmp(method, "POST", 4) == 0) {
        *out = VHTTP_METHOD_POST;
        return 0;
    }
    if (len == 3 && memcmp(method, "PUT", 3) == 0) {
        *out = VHTTP_METHOD_PUT;
        return 0;
    }
    if (len == 5 && memcmp(method, "PATCH", 5) == 0) {
        *out = VHTTP_METHOD_PATCH;
        return 0;
    }
    if (len == 6 && memcmp(method, "DELETE", 6) == 0) {
        *out = VHTTP_METHOD_DELETE;
        return 0;
    }
    if (len == 7 && memcmp(method, "OPTIONS", 7) == 0) {
        *out = VHTTP_METHOD_OPTIONS;
        return 0;
    }
    if (len == 4 && memcmp(method, "HEAD", 4) == 0) {
        *out = VHTTP_METHOD_HEAD;
        return 0;
    }
    return -1;
}

static int send_all(int sock, const uint8_t *buf, size_t len) {
    uint32_t waited_ms = 0;
    size_t sent = 0;
    while (sent < len) {
        int rc = vhttp_sock_send(sock, buf + sent, len - sent);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (waited_ms >= VHTTP_SERVER_RESP_TIMEOUT_MS) {
                    return -1;
                }
                uint32_t remain_ms = VHTTP_SERVER_RESP_TIMEOUT_MS - waited_ms;
                uint32_t wait_ms = remain_ms > VHTTP_SERVER_IO_WAIT_SLICE_MS
                    ? VHTTP_SERVER_IO_WAIT_SLICE_MS
                    : remain_ms;
                int ready = vhttp_wait_socket(sock, 1, wait_ms);
                if (ready < 0) {
                    return -1;
                }
                waited_ms += wait_ms;
                continue;
            }
            return -1;
        }
        if (rc == 0) {
            return -1;
        }
        sent += (size_t)rc;
        // Timeout tracks lack of forward progress, not total transfer time.
        waited_ms = 0;
    }
    return 0;
}

static int vhttp_http2_send_frame(
    int sock,
    uint8_t type,
    uint8_t flags,
    uint32_t stream_id,
    const uint8_t *payload,
    uint32_t payload_len
) {
    if (payload_len > 0x00ffffffu) {
        return -1;
    }
    int qrc = vhttp_http2_event_tx_queue_frame_for_sock(
        sock,
        type,
        flags,
        stream_id,
        payload,
        payload_len
    );
    if (qrc == 0) {
        return 0;
    }
    if (qrc < 0) {
        return -1;
    }
    uint8_t hdr[9];
    hdr[0] = (uint8_t)((payload_len >> 16) & 0xffu);
    hdr[1] = (uint8_t)((payload_len >> 8) & 0xffu);
    hdr[2] = (uint8_t)(payload_len & 0xffu);
    hdr[3] = type;
    hdr[4] = flags;
    hdr[5] = (uint8_t)((stream_id >> 24) & 0x7fu);
    hdr[6] = (uint8_t)((stream_id >> 16) & 0xffu);
    hdr[7] = (uint8_t)((stream_id >> 8) & 0xffu);
    hdr[8] = (uint8_t)(stream_id & 0xffu);
    if (send_all(sock, hdr, sizeof(hdr)) != 0) {
        return -1;
    }
    if (payload_len > 0 && payload) {
        if (send_all(sock, payload, payload_len) != 0) {
            return -1;
        }
    }
    return 0;
}

static void vhttp_http2_note_error_code(uint32_t error_code) {
    switch (error_code) {
        case VHTTP_HTTP2_ERR_PROTOCOL:
            vhttp_stats_inc(&g_server_stats.http2_err_protocol);
            break;
        case VHTTP_HTTP2_ERR_FLOW_CONTROL:
            vhttp_stats_inc(&g_server_stats.http2_err_flow_control);
            break;
        case VHTTP_HTTP2_ERR_FRAME_SIZE:
            vhttp_stats_inc(&g_server_stats.http2_err_frame_size);
            break;
        case VHTTP_HTTP2_ERR_COMPRESSION:
            vhttp_stats_inc(&g_server_stats.http2_err_compression);
            break;
        case VHTTP_HTTP2_ERR_REFUSED_STREAM:
            vhttp_stats_inc(&g_server_stats.http2_err_refused_stream);
            break;
        case VHTTP_HTTP2_ERR_STREAM_CLOSED:
            vhttp_stats_inc(&g_server_stats.http2_err_stream_closed);
            break;
        case VHTTP_HTTP2_ERR_INTERNAL:
            vhttp_stats_inc(&g_server_stats.http2_err_internal);
            break;
        case VHTTP_HTTP2_ERR_HTTP_1_1_REQUIRED:
            vhttp_stats_inc(&g_server_stats.http2_err_http11_required);
            break;
        default:
            break;
    }
}

static int vhttp_http2_send_goaway(int sock, uint32_t error_code) {
    uint8_t settings_payload[12] = {
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // SETTINGS_HEADER_TABLE_SIZE=0
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00  // SETTINGS_ENABLE_PUSH=0
    };
    uint8_t goaway_payload[8] = {
        0x00, 0x00, 0x00, 0x00,
        (uint8_t)((error_code >> 24) & 0xffu),
        (uint8_t)((error_code >> 16) & 0xffu),
        (uint8_t)((error_code >> 8) & 0xffu),
        (uint8_t)(error_code & 0xffu)
    };
    if (vhttp_http2_send_frame(sock, VHTTP_HTTP2_FRAME_SETTINGS, 0, 0, settings_payload, sizeof(settings_payload)) != 0) {
        return -1;
    }
    if (vhttp_http2_send_frame(sock, VHTTP_HTTP2_FRAME_GOAWAY, 0, 0, goaway_payload, sizeof(goaway_payload)) != 0) {
        return -1;
    }
    vhttp_http2_note_error_code(error_code);
    return 0;
}

static int vhttp_http2_buffer_starts_with_preface(const uint8_t *buf, size_t len) {
    static const uint8_t k_preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    size_t preface_len = sizeof(k_preface) - 1u;
    if (!buf || len < preface_len) {
        return 0;
    }
    return memcmp(buf, k_preface, preface_len) == 0 ? 1 : 0;
}

static int vhttp_http2_handle_preface_if_needed(int sock, const uint8_t *buf, size_t len) {
    if (!vhttp_http2_buffer_starts_with_preface(buf, len)) {
        return 0;
    }
    vhttp_stats_inc(&g_server_stats.http2_preface_seen);
    if (!vhttp_http2_enabled_runtime()) {
        if (vhttp_http2_send_goaway(sock, VHTTP_HTTP2_ERR_HTTP_1_1_REQUIRED) == 0) {
            vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
        }
    }
    return 1;
}

static size_t vhttp_http2_slot_count(void) {
    uint16_t max_streams = 0;
    taskENTER_CRITICAL(&g_http2_cfg_lock);
    max_streams = g_http2_cfg.max_streams;
    taskEXIT_CRITICAL(&g_http2_cfg_lock);
    if (max_streams == 0) {
        max_streams = 8;
    }
    return (size_t)max_streams;
}

static int vhttp_http2_slot_acquire(uint32_t stream_id) {
    if (!g_http2_stream_slots || stream_id == 0) {
        return 0;
    }
    int rc = -1;
    size_t slots = vhttp_http2_slot_count();
    taskENTER_CRITICAL(&g_http2_cfg_lock);
    for (size_t i = 0; i < slots; ++i) {
        if (g_http2_stream_slots[i].used && g_http2_stream_slots[i].stream_id == stream_id) {
            rc = 0;
            break;
        }
    }
    if (rc != 0) {
        for (size_t i = 0; i < slots; ++i) {
            if (!g_http2_stream_slots[i].used) {
                g_http2_stream_slots[i].used = 1u;
                g_http2_stream_slots[i].stream_id = stream_id;
                rc = 0;
                break;
            }
        }
    }
    taskEXIT_CRITICAL(&g_http2_cfg_lock);
    return rc;
}

static void vhttp_http2_slot_release(uint32_t stream_id) {
    if (!g_http2_stream_slots || stream_id == 0) {
        return;
    }
    size_t slots = vhttp_http2_slot_count();
    taskENTER_CRITICAL(&g_http2_cfg_lock);
    for (size_t i = 0; i < slots; ++i) {
        if (g_http2_stream_slots[i].used && g_http2_stream_slots[i].stream_id == stream_id) {
            g_http2_stream_slots[i].used = 0u;
            g_http2_stream_slots[i].stream_id = 0;
            break;
        }
    }
    taskEXIT_CRITICAL(&g_http2_cfg_lock);
}

static uint8_t *vhttp_http2_alloc_buf(size_t len, uint8_t *out_psram) {
    if (out_psram) {
        *out_psram = 0;
    }
    if (len == 0) {
        return NULL;
    }
    uint8_t *ptr = NULL;
#if defined(MALLOC_CAP_SPIRAM)
    ptr = (uint8_t *)heap_caps_malloc(len, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (ptr && out_psram) {
        *out_psram = 1;
    }
#endif
    if (!ptr) {
        ptr = (uint8_t *)heap_caps_malloc(len, MALLOC_CAP_8BIT);
    }
    return ptr;
}

static uint8_t *vhttp_http2_realloc_buf(uint8_t *old_ptr, size_t len, uint8_t *inout_psram) {
    if (len == 0) {
        if (old_ptr) {
            heap_caps_free(old_ptr);
        }
        if (inout_psram) {
            *inout_psram = 0;
        }
        return NULL;
    }
    uint8_t psram = inout_psram ? *inout_psram : 0;
    uint8_t *ptr = NULL;
#if defined(MALLOC_CAP_SPIRAM)
    ptr = (uint8_t *)heap_caps_realloc(old_ptr, len, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (ptr && inout_psram) {
        *inout_psram = 1;
    }
#endif
    if (!ptr) {
        ptr = (uint8_t *)heap_caps_realloc(old_ptr, len, MALLOC_CAP_8BIT);
        if (ptr && inout_psram) {
            *inout_psram = psram;
        }
    }
    return ptr;
}

static void vhttp_http2_req_reset(vhttp_http2_stream_req_t *req) {
    if (!req) {
        return;
    }
    uint8_t *header_block = req->header_block;
    uint32_t header_block_cap = req->header_block_cap;
    uint8_t *body = req->body;
    uint32_t body_cap = req->body_cap;
    uint8_t body_in_psram = req->body_in_psram;
    memset(req, 0, sizeof(*req));
    req->header_block = header_block;
    req->header_block_cap = header_block_cap;
    req->body = body;
    req->body_cap = body_cap;
    req->body_in_psram = body_in_psram;
    req->method = 0xffu;
}

static void vhttp_http2_req_free(vhttp_http2_stream_req_t *req) {
    if (!req) {
        return;
    }
    if (req->header_block) {
        heap_caps_free(req->header_block);
        req->header_block = NULL;
        req->header_block_cap = 0;
    }
    if (req->body) {
        heap_caps_free(req->body);
        req->body = NULL;
        req->body_cap = 0;
    }
    req->body_in_psram = 0;
    memset(req, 0, sizeof(*req));
}

static int vhttp_http2_req_ensure_header_block(vhttp_http2_stream_req_t *req, uint32_t need) {
    if (!req) {
        return -1;
    }
    if (need > VHTTP_HTTP2_HEADER_BLOCK_MAX) {
        return -1;
    }
    if (need <= req->header_block_cap && req->header_block) {
        return 0;
    }
    uint32_t new_cap = req->header_block_cap ? req->header_block_cap : 1024u;
    while (new_cap < need && new_cap < VHTTP_HTTP2_HEADER_BLOCK_MAX) {
        uint32_t doubled = new_cap * 2u;
        if (doubled < new_cap) {
            new_cap = VHTTP_HTTP2_HEADER_BLOCK_MAX;
            break;
        }
        new_cap = doubled;
    }
    if (new_cap > VHTTP_HTTP2_HEADER_BLOCK_MAX) {
        new_cap = VHTTP_HTTP2_HEADER_BLOCK_MAX;
    }
    uint8_t in_psram = 0;
    uint8_t *buf = req->header_block;
    if (buf) {
        buf = vhttp_http2_realloc_buf(buf, new_cap, &in_psram);
    } else {
        buf = vhttp_http2_alloc_buf(new_cap, &in_psram);
    }
    if (!buf) {
        return -1;
    }
    req->header_block = buf;
    req->header_block_cap = new_cap;
    (void)in_psram;
    return 0;
}

static int vhttp_http2_req_ensure_body(vhttp_http2_stream_req_t *req, uint32_t need) {
    if (!req) {
        return -1;
    }
    if (need > VHTTP_MAX_BODY_SIZE) {
        return -1;
    }
    if (need <= req->body_cap && req->body) {
        return 0;
    }
    uint32_t new_cap = req->body_cap ? req->body_cap : VHTTP_HTTP2_BODY_INITIAL_CAP;
    while (new_cap < need && new_cap < VHTTP_MAX_BODY_SIZE) {
        uint32_t doubled = new_cap * 2u;
        if (doubled < new_cap) {
            new_cap = VHTTP_MAX_BODY_SIZE;
            break;
        }
        new_cap = doubled;
    }
    if (new_cap > VHTTP_MAX_BODY_SIZE) {
        new_cap = VHTTP_MAX_BODY_SIZE;
    }
    uint8_t *buf = req->body;
    if (buf) {
        buf = vhttp_http2_realloc_buf(buf, new_cap, &req->body_in_psram);
    } else {
        buf = vhttp_http2_alloc_buf(new_cap, &req->body_in_psram);
    }
    if (!buf) {
        return -1;
    }
    req->body = buf;
    req->body_cap = new_cap;
    return 0;
}

static void vhttp_http2_rx_consume(vhttp_http2_session_t *sess, size_t consumed) {
    if (!sess || consumed == 0 || sess->buffered == 0) {
        return;
    }
    if (consumed >= sess->buffered) {
        sess->buffered = 0;
        return;
    }
    memmove(sess->recv_buf, sess->recv_buf + consumed, sess->buffered - consumed);
    sess->buffered -= consumed;
}

static int vhttp_http2_read_exact(vhttp_http2_session_t *sess, uint8_t *dst, uint32_t len, uint32_t timeout_ms) {
    if (!sess || (!dst && len > 0)) {
        return -1;
    }
    uint32_t copied = 0;
    while (copied < len) {
        if (sess->buffered > 0) {
            size_t take = (size_t)(len - copied);
            if (take > sess->buffered) {
                take = sess->buffered;
            }
            if (take > 0) {
                memcpy(dst + copied, sess->recv_buf, take);
                copied += (uint32_t)take;
                vhttp_http2_rx_consume(sess, take);
                continue;
            }
        }
        int rc = vhttp_recv_with_timeout(
            sess->sock,
            sess->recv_buf,
            sess->recv_cap,
            timeout_ms
        );
        if (rc == -2) {
            return -2;
        }
        if (rc <= 0) {
            return -1;
        }
        sess->buffered = (size_t)rc;
    }
    return 0;
}

typedef struct {
    uint8_t type;
    uint8_t flags;
    uint32_t stream_id;
    uint8_t *payload;
    uint32_t payload_len;
    uint8_t payload_in_psram;
} vhttp_http2_frame_t;

static void vhttp_http2_frame_free(vhttp_http2_frame_t *frame) {
    if (!frame) {
        return;
    }
    if (frame->payload) {
        heap_caps_free(frame->payload);
    }
    memset(frame, 0, sizeof(*frame));
}

static int vhttp_http2_read_frame(vhttp_http2_session_t *sess, vhttp_http2_frame_t *out, uint32_t timeout_ms) {
    if (!sess || !out) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    uint8_t hdr[9];
    int rrc = vhttp_http2_read_exact(sess, hdr, sizeof(hdr), timeout_ms);
    if (rrc == -2) {
        return -3;
    }
    if (rrc != 0) {
        return -1;
    }

    uint32_t payload_len = ((uint32_t)hdr[0] << 16) | ((uint32_t)hdr[1] << 8) | (uint32_t)hdr[2];
    out->type = hdr[3];
    out->flags = hdr[4];
    out->stream_id = ((uint32_t)(hdr[5] & 0x7f) << 24) | ((uint32_t)hdr[6] << 16) | ((uint32_t)hdr[7] << 8) | (uint32_t)hdr[8];
    out->payload_len = payload_len;

    if (payload_len > VHTTP_HTTP2_FRAME_PAYLOAD_MAX) {
        return -2;
    }
    if (payload_len == 0) {
        return 0;
    }
    uint8_t in_psram = 0;
    out->payload = vhttp_http2_alloc_buf(payload_len, &in_psram);
    if (!out->payload) {
        return -1;
    }
    out->payload_in_psram = in_psram;
    rrc = vhttp_http2_read_exact(sess, out->payload, payload_len, timeout_ms);
    if (rrc == -2) {
        vhttp_http2_frame_free(out);
        return -3;
    }
    if (rrc != 0) {
        vhttp_http2_frame_free(out);
        return -1;
    }
    return 0;
}

static int vhttp_http2_try_read_buffered_frame(vhttp_http2_session_t *sess, vhttp_http2_frame_t *out) {
    if (!sess || !out || !sess->recv_buf || sess->recv_cap == 0) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    if (sess->buffered < 9u) {
        return 1;
    }

    const uint8_t *hdr = sess->recv_buf;
    uint32_t payload_len = ((uint32_t)hdr[0] << 16) | ((uint32_t)hdr[1] << 8) | (uint32_t)hdr[2];
    if (payload_len > VHTTP_HTTP2_FRAME_PAYLOAD_MAX) {
        return -2;
    }

    size_t frame_len = 9u + (size_t)payload_len;
    if (sess->buffered < frame_len) {
        return 1;
    }

    out->type = hdr[3];
    out->flags = hdr[4];
    out->stream_id = ((uint32_t)(hdr[5] & 0x7f) << 24) | ((uint32_t)hdr[6] << 16) | ((uint32_t)hdr[7] << 8) | (uint32_t)hdr[8];
    out->payload_len = payload_len;

    if (payload_len > 0) {
        uint8_t in_psram = 0;
        out->payload = vhttp_http2_alloc_buf(payload_len, &in_psram);
        if (!out->payload) {
            return -1;
        }
        out->payload_in_psram = in_psram;
        memcpy(out->payload, sess->recv_buf + 9u, payload_len);
    }
    vhttp_http2_rx_consume(sess, frame_len);
    return 0;
}

static vhttp_http2_stream_state_slot_t *vhttp_http2_stream_state_find_slot(vhttp_http2_session_t *sess, uint32_t stream_id) {
    if (!sess || stream_id == 0) {
        return NULL;
    }
    for (size_t i = 0; i < (size_t)VHTTP_HTTP2_STREAM_STATE_SLOTS; ++i) {
        vhttp_http2_stream_state_slot_t *slot = &sess->stream_states[i];
        if (slot->used && slot->stream_id == stream_id) {
            return slot;
        }
    }
    return NULL;
}

static void vhttp_http2_flow_init(vhttp_http2_session_t *sess) {
    if (!sess) {
        return;
    }
    sess->conn_rx_window = (int32_t)VHTTP_HTTP2_FLOW_WINDOW_INITIAL;
    sess->conn_tx_window = (int32_t)VHTTP_HTTP2_FLOW_WINDOW_INITIAL;
    sess->peer_initial_window = (int32_t)VHTTP_HTTP2_FLOW_WINDOW_INITIAL;
}

static vhttp_http2_stream_state_slot_t *vhttp_http2_stream_state_ensure_slot(vhttp_http2_session_t *sess, uint32_t stream_id) {
    if (!sess || stream_id == 0) {
        return NULL;
    }
    vhttp_http2_stream_state_slot_t *slot = vhttp_http2_stream_state_find_slot(sess, stream_id);
    if (slot) {
        return slot;
    }
    vhttp_http2_stream_state_slot_t *reclaim = NULL;
    for (size_t i = 0; i < (size_t)VHTTP_HTTP2_STREAM_STATE_SLOTS; ++i) {
        slot = &sess->stream_states[i];
        if (!slot->used) {
            slot->used = 1u;
            slot->stream_id = stream_id;
            slot->state = VHTTP_HTTP2_STREAM_STATE_IDLE;
            slot->rx_window = (int32_t)VHTTP_HTTP2_FLOW_WINDOW_INITIAL;
            slot->tx_window = (sess && sess->peer_initial_window > 0)
                ? sess->peer_initial_window
                : (int32_t)VHTTP_HTTP2_FLOW_WINDOW_INITIAL;
            return slot;
        }
        if (slot->state == VHTTP_HTTP2_STREAM_STATE_CLOSED) {
            if (!reclaim || slot->stream_id < reclaim->stream_id) {
                reclaim = slot;
            }
        }
    }
    if (reclaim) {
        reclaim->used = 1u;
        reclaim->stream_id = stream_id;
        reclaim->state = VHTTP_HTTP2_STREAM_STATE_IDLE;
        reclaim->rx_window = (int32_t)VHTTP_HTTP2_FLOW_WINDOW_INITIAL;
        reclaim->tx_window = (sess && sess->peer_initial_window > 0)
            ? sess->peer_initial_window
            : (int32_t)VHTTP_HTTP2_FLOW_WINDOW_INITIAL;
        return reclaim;
    }
    return NULL;
}

static int vhttp_http2_flow_apply_peer_initial_window(vhttp_http2_session_t *sess, int32_t new_window) {
    if (!sess || new_window < 0 || (uint32_t)new_window > VHTTP_HTTP2_FLOW_WINDOW_MAX) {
        return -1;
    }
    int32_t old_window = sess->peer_initial_window;
    int64_t delta = (int64_t)new_window - (int64_t)old_window;
    for (size_t i = 0; i < (size_t)VHTTP_HTTP2_STREAM_STATE_SLOTS; ++i) {
        vhttp_http2_stream_state_slot_t *slot = &sess->stream_states[i];
        if (!slot->used) {
            continue;
        }
        int64_t next = (int64_t)slot->tx_window + delta;
        if (next < (int64_t)(-2147483647 - 1) || next > (int64_t)VHTTP_HTTP2_FLOW_WINDOW_MAX) {
            return -1;
        }
    }
    for (size_t i = 0; i < (size_t)VHTTP_HTTP2_STREAM_STATE_SLOTS; ++i) {
        vhttp_http2_stream_state_slot_t *slot = &sess->stream_states[i];
        if (!slot->used) {
            continue;
        }
        slot->tx_window = (int32_t)((int64_t)slot->tx_window + delta);
    }
    sess->peer_initial_window = new_window;
    return 0;
}

static int vhttp_http2_send_window_update_frame(int sock, uint32_t stream_id, uint32_t increment) {
    if (increment == 0 || increment > VHTTP_HTTP2_FLOW_WINDOW_MAX) {
        return -1;
    }
    uint32_t val = increment & VHTTP_HTTP2_FLOW_WINDOW_MAX;
    uint8_t payload[4] = {
        (uint8_t)((val >> 24) & 0x7fu),
        (uint8_t)((val >> 16) & 0xffu),
        (uint8_t)((val >> 8) & 0xffu),
        (uint8_t)(val & 0xffu)
    };
    return vhttp_http2_send_frame(sock, VHTTP_HTTP2_FRAME_WINDOW_UPDATE, 0, stream_id, payload, sizeof(payload));
}

static int vhttp_http2_flow_consume_rx(
    vhttp_http2_session_t *sess,
    uint32_t stream_id,
    uint32_t data_len,
    uint8_t *conn_error
) {
    if (conn_error) {
        *conn_error = 0;
    }
    if (!sess || stream_id == 0) {
        if (conn_error) {
            *conn_error = 1u;
        }
        return -1;
    }
    if (data_len == 0) {
        return 0;
    }
    if (sess->conn_rx_window < 0 || (uint32_t)sess->conn_rx_window < data_len) {
        if (conn_error) {
            *conn_error = 1u;
        }
        return -1;
    }
    vhttp_http2_stream_state_slot_t *slot = vhttp_http2_stream_state_find_slot(sess, stream_id);
    if (!slot || !slot->used) {
        return -2;
    }
    if (slot->rx_window < 0 || (uint32_t)slot->rx_window < data_len) {
        return -1;
    }
    sess->conn_rx_window -= (int32_t)data_len;
    slot->rx_window -= (int32_t)data_len;
    return 0;
}

static int vhttp_http2_flow_replenish_rx(vhttp_http2_session_t *sess, uint32_t stream_id, uint32_t increment) {
    if (!sess || stream_id == 0) {
        return -1;
    }
    if (increment == 0) {
        return 0;
    }
    vhttp_http2_stream_state_slot_t *slot = vhttp_http2_stream_state_find_slot(sess, stream_id);
    if (!slot || !slot->used) {
        return -1;
    }
    if (vhttp_http2_send_window_update_frame(sess->sock, 0, increment) != 0) {
        return -1;
    }
    if (vhttp_http2_send_window_update_frame(sess->sock, stream_id, increment) != 0) {
        return -1;
    }
    if ((uint32_t)sess->conn_rx_window > (VHTTP_HTTP2_FLOW_WINDOW_MAX - increment)) {
        return -1;
    }
    if ((uint32_t)slot->rx_window > (VHTTP_HTTP2_FLOW_WINDOW_MAX - increment)) {
        return -1;
    }
    sess->conn_rx_window += (int32_t)increment;
    slot->rx_window += (int32_t)increment;
    return 0;
}

static int vhttp_http2_flow_on_window_update(vhttp_http2_session_t *sess, uint32_t stream_id, uint32_t increment) {
    if (!sess) {
        return -1;
    }
    if (increment == 0 || increment > VHTTP_HTTP2_FLOW_WINDOW_MAX) {
        return stream_id == 0 ? -1 : -2;
    }
    if (stream_id == 0) {
        if ((uint32_t)sess->conn_tx_window > (VHTTP_HTTP2_FLOW_WINDOW_MAX - increment)) {
            return -1;
        }
        sess->conn_tx_window += (int32_t)increment;
        return 0;
    }
    vhttp_http2_stream_state_slot_t *slot = vhttp_http2_stream_state_find_slot(sess, stream_id);
    if (!slot || !slot->used) {
        return 0;
    }
    if ((uint32_t)slot->tx_window > (VHTTP_HTTP2_FLOW_WINDOW_MAX - increment)) {
        return -2;
    }
    slot->tx_window += (int32_t)increment;
    return 0;
}

static int vhttp_http2_flow_tx_available(vhttp_http2_session_t *sess, uint32_t stream_id, uint32_t *out_available) {
    if (!sess || !out_available || stream_id == 0) {
        return -1;
    }
    vhttp_http2_stream_state_slot_t *slot = vhttp_http2_stream_state_find_slot(sess, stream_id);
    if (!slot || !slot->used) {
        /* Keep TX path resilient across async handoffs: recreate missing stream slot lazily. */
        slot = vhttp_http2_stream_state_ensure_slot(sess, stream_id);
        if (!slot || !slot->used) {
            return -1;
        }
    }
    int32_t conn = sess->conn_tx_window;
    int32_t stream = slot->tx_window;
    if (conn <= 0 || stream <= 0) {
        *out_available = 0;
        return 0;
    }
    *out_available = (uint32_t)((conn < stream) ? conn : stream);
    return 0;
}

static int vhttp_http2_flow_consume_tx(vhttp_http2_session_t *sess, uint32_t stream_id, uint32_t amount) {
    if (!sess || stream_id == 0) {
        return -1;
    }
    if (amount == 0) {
        return 0;
    }
    vhttp_http2_stream_state_slot_t *slot = vhttp_http2_stream_state_find_slot(sess, stream_id);
    if (!slot || !slot->used) {
        slot = vhttp_http2_stream_state_ensure_slot(sess, stream_id);
        if (!slot || !slot->used) {
            return -1;
        }
    }
    if (sess->conn_tx_window > 0) {
        if ((uint32_t)sess->conn_tx_window <= amount) {
            sess->conn_tx_window = 0;
        } else {
            sess->conn_tx_window -= (int32_t)amount;
        }
    }
    if (slot->tx_window > 0) {
        if ((uint32_t)slot->tx_window <= amount) {
            slot->tx_window = 0;
        } else {
            slot->tx_window -= (int32_t)amount;
        }
    }
    return 0;
}

static uint8_t vhttp_http2_stream_state_get(vhttp_http2_session_t *sess, uint32_t stream_id) {
    vhttp_http2_stream_state_slot_t *slot = vhttp_http2_stream_state_find_slot(sess, stream_id);
    if (!slot) {
        return VHTTP_HTTP2_STREAM_STATE_IDLE;
    }
    return slot->state;
}

static int vhttp_http2_stream_state_set(vhttp_http2_session_t *sess, uint32_t stream_id, uint8_t state) {
    vhttp_http2_stream_state_slot_t *slot = vhttp_http2_stream_state_ensure_slot(sess, stream_id);
    if (!slot) {
        return -1;
    }
    slot->state = state;
    return 0;
}

static int vhttp_http2_stream_state_on_new_headers(vhttp_http2_session_t *sess, uint32_t stream_id, uint8_t end_stream) {
    if (!sess || stream_id == 0) {
        return -1;
    }
    if ((stream_id & 1u) == 0u) {
        return -2;
    }
    vhttp_http2_stream_state_slot_t *slot = vhttp_http2_stream_state_find_slot(sess, stream_id);
    if (!slot) {
        if (stream_id <= sess->last_client_stream_id) {
            return -2;
        }
        slot = vhttp_http2_stream_state_ensure_slot(sess, stream_id);
        if (!slot) {
            return -3;
        }
        sess->last_client_stream_id = stream_id;
    } else if (slot->state != VHTTP_HTTP2_STREAM_STATE_IDLE) {
        return -4;
    }
    slot->state = end_stream ? VHTTP_HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE : VHTTP_HTTP2_STREAM_STATE_OPEN;
    return 0;
}

static int vhttp_http2_stream_state_on_remote_end(vhttp_http2_session_t *sess, uint32_t stream_id) {
    if (!sess || stream_id == 0) {
        return -1;
    }
    uint8_t state = vhttp_http2_stream_state_get(sess, stream_id);
    if (state == VHTTP_HTTP2_STREAM_STATE_OPEN) {
        return vhttp_http2_stream_state_set(sess, stream_id, VHTTP_HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE);
    }
    if (state == VHTTP_HTTP2_STREAM_STATE_HALF_CLOSED_LOCAL) {
        return vhttp_http2_stream_state_set(sess, stream_id, VHTTP_HTTP2_STREAM_STATE_CLOSED);
    }
    if (state == VHTTP_HTTP2_STREAM_STATE_IDLE) {
        return vhttp_http2_stream_state_set(sess, stream_id, VHTTP_HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE);
    }
    return 0;
}

static int vhttp_http2_stream_state_on_local_end(vhttp_http2_session_t *sess, uint32_t stream_id) {
    if (!sess || stream_id == 0) {
        return -1;
    }
    uint8_t state = vhttp_http2_stream_state_get(sess, stream_id);
    if (state == VHTTP_HTTP2_STREAM_STATE_OPEN) {
        return vhttp_http2_stream_state_set(sess, stream_id, VHTTP_HTTP2_STREAM_STATE_HALF_CLOSED_LOCAL);
    }
    if (state == VHTTP_HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE) {
        return vhttp_http2_stream_state_set(sess, stream_id, VHTTP_HTTP2_STREAM_STATE_CLOSED);
    }
    if (state == VHTTP_HTTP2_STREAM_STATE_IDLE) {
        return vhttp_http2_stream_state_set(sess, stream_id, VHTTP_HTTP2_STREAM_STATE_CLOSED);
    }
    return 0;
}

static void vhttp_http2_stream_state_on_rst(vhttp_http2_session_t *sess, uint32_t stream_id) {
    if (!sess || stream_id == 0) {
        return;
    }
    (void)vhttp_http2_stream_state_set(sess, stream_id, VHTTP_HTTP2_STREAM_STATE_CLOSED);
}

static void vhttp_http2_req_clear_active(vhttp_http2_session_t *sess) {
    if (!sess) {
        return;
    }
    vhttp_http2_req_reset(&sess->req);
    sess->expect_continuation = 0;
    sess->continuation_stream_id = 0;
}

static void vhttp_http2_req_abort_stream(vhttp_http2_session_t *sess, uint32_t stream_id) {
    if (!sess || stream_id == 0) {
        return;
    }
    vhttp_http2_stream_state_on_rst(sess, stream_id);
    vhttp_http2_slot_release(stream_id);
}

static void vhttp_http2_req_finish_stream(vhttp_http2_session_t *sess, uint32_t stream_id) {
    if (!sess || stream_id == 0) {
        return;
    }
    (void)vhttp_http2_stream_state_on_local_end(sess, stream_id);
    vhttp_http2_slot_release(stream_id);
}

static void vhttp_http2_req_move(vhttp_http2_stream_req_t *dst, vhttp_http2_stream_req_t *src) {
    if (!dst || !src || dst == src) {
        return;
    }
    vhttp_http2_req_free(dst);
    memcpy(dst, src, sizeof(*dst));
    memset(src, 0, sizeof(*src));
    src->method = 0xffu;
}

static vhttp_http2_buffered_req_t *vhttp_http2_buffered_req_find(vhttp_http2_session_t *sess, uint32_t stream_id) {
    if (!sess || stream_id == 0) {
        return NULL;
    }
    for (size_t i = 0; i < (size_t)VHTTP_HTTP2_BUFFERED_REQ_SLOTS; ++i) {
        vhttp_http2_buffered_req_t *slot = &sess->buffered_reqs[i];
        if (slot->used && slot->req.active && slot->req.stream_id == stream_id) {
            return slot;
        }
    }
    return NULL;
}

static int vhttp_http2_buffered_req_enqueue_current(vhttp_http2_session_t *sess) {
    if (!sess || !sess->req.active) {
        return -1;
    }
    vhttp_http2_buffered_req_t *existing = vhttp_http2_buffered_req_find(sess, sess->req.stream_id);
    if (existing) {
        existing->used = 1u;
        vhttp_http2_req_move(&existing->req, &sess->req);
        sess->expect_continuation = 0;
        sess->continuation_stream_id = 0;
        return 0;
    }
    for (size_t i = 0; i < (size_t)VHTTP_HTTP2_BUFFERED_REQ_SLOTS; ++i) {
        vhttp_http2_buffered_req_t *slot = &sess->buffered_reqs[i];
        if (slot->used) {
            continue;
        }
        slot->used = 1u;
        vhttp_http2_req_move(&slot->req, &sess->req);
        sess->expect_continuation = 0;
        sess->continuation_stream_id = 0;
        return 0;
    }
    return -1;
}

static int vhttp_http2_buffered_req_take_stream(vhttp_http2_session_t *sess, uint32_t stream_id) {
    vhttp_http2_buffered_req_t *slot = vhttp_http2_buffered_req_find(sess, stream_id);
    if (!slot) {
        return 0;
    }
    vhttp_http2_req_move(&sess->req, &slot->req);
    slot->used = 0u;
    return 1;
}

static int vhttp_http2_buffered_req_activate_next(vhttp_http2_session_t *sess) {
    if (!sess || sess->req.active) {
        return 0;
    }
    vhttp_http2_buffered_req_t *selected = NULL;
    for (size_t i = 0; i < (size_t)VHTTP_HTTP2_BUFFERED_REQ_SLOTS; ++i) {
        vhttp_http2_buffered_req_t *slot = &sess->buffered_reqs[i];
        if (!slot->used) {
            continue;
        }
        if (!slot->req.active || !slot->req.headers_complete || !slot->req.end_stream) {
            continue;
        }
        if (!selected || slot->req.stream_id < selected->req.stream_id) {
            selected = slot;
        }
    }
    if (!selected) {
        return 0;
    }
    vhttp_http2_req_move(&sess->req, &selected->req);
    selected->used = 0u;
    return 1;
}

static int vhttp_http2_prepare_active_req_for_stream(
    vhttp_http2_session_t *sess,
    uint32_t stream_id,
    uint8_t create_if_missing
) {
    if (!sess || stream_id == 0) {
        return -1;
    }
    if (sess->req.active && sess->req.stream_id == stream_id) {
        return 0;
    }
    if (sess->req.active) {
        if (vhttp_http2_buffered_req_enqueue_current(sess) != 0) {
            return -2;
        }
    }
    if (vhttp_http2_buffered_req_take_stream(sess, stream_id) > 0) {
        return 0;
    }
    if (!create_if_missing) {
        return -3;
    }
    if (vhttp_http2_slot_acquire(stream_id) != 0) {
        return -4;
    }
    vhttp_http2_req_reset(&sess->req);
    sess->req.active = 1u;
    sess->req.stream_id = stream_id;
    return 1;
}

static int vhttp_http2_buffered_req_drop_stream(vhttp_http2_session_t *sess, uint32_t stream_id) {
    if (!sess || stream_id == 0) {
        return 0;
    }
    for (size_t i = 0; i < (size_t)VHTTP_HTTP2_BUFFERED_REQ_SLOTS; ++i) {
        vhttp_http2_buffered_req_t *slot = &sess->buffered_reqs[i];
        if (!slot->used || slot->req.stream_id != stream_id) {
            continue;
        }
        vhttp_http2_req_free(&slot->req);
        slot->used = 0u;
        if (sess->expect_continuation && sess->continuation_stream_id == stream_id) {
            sess->expect_continuation = 0;
            sess->continuation_stream_id = 0;
        }
        return 1;
    }
    return 0;
}

static void vhttp_http2_buffered_req_release_all(vhttp_http2_session_t *sess, uint8_t release_slots) {
    if (!sess) {
        return;
    }
    for (size_t i = 0; i < (size_t)VHTTP_HTTP2_BUFFERED_REQ_SLOTS; ++i) {
        vhttp_http2_buffered_req_t *slot = &sess->buffered_reqs[i];
        if (!slot->used) {
            continue;
        }
        if (release_slots && slot->req.stream_id != 0) {
            vhttp_http2_slot_release(slot->req.stream_id);
        }
        vhttp_http2_req_free(&slot->req);
        slot->used = 0u;
    }
}

static int vhttp_http2_hpack_decode_int(
    const uint8_t *src,
    size_t len,
    uint8_t prefix_bits,
    uint32_t *out_value,
    size_t *out_used
) {
    if (!src || len == 0 || !out_value || !out_used || prefix_bits == 0 || prefix_bits > 8) {
        return -1;
    }
    uint32_t max_prefix = ((uint32_t)1u << prefix_bits) - 1u;
    uint32_t value = (uint32_t)(src[0] & max_prefix);
    size_t used = 1;
    if (value < max_prefix) {
        *out_value = value;
        *out_used = used;
        return 0;
    }

    uint32_t m = 0;
    value = max_prefix;
    while (used < len) {
        uint8_t b = src[used++];
        if (m >= 28 && (b & 0x7f) > 0x0f) {
            return -1;
        }
        value += (uint32_t)(b & 0x7f) << m;
        if ((b & 0x80u) == 0) {
            *out_value = value;
            *out_used = used;
            return 0;
        }
        m += 7;
    }
    return -1;
}

static int vhttp_http2_hpack_lookup_header(
    vhttp_http2_session_t *sess,
    uint32_t index,
    const uint8_t **out_name_ptr,
    size_t *out_name_len,
    const uint8_t **out_value_ptr,
    size_t *out_value_len
) {
    if (!out_name_ptr || !out_name_len || !out_value_ptr || !out_value_len || index == 0) {
        return -1;
    }
    uint32_t static_count = (uint32_t)(sizeof(g_http2_hpack_static) / sizeof(g_http2_hpack_static[0]));
    if (index <= static_count) {
        const vhttp_http2_hpack_static_t *entry = &g_http2_hpack_static[index - 1u];
        *out_name_ptr = (const uint8_t *)entry->name;
        *out_name_len = strlen(entry->name);
        *out_value_ptr = (const uint8_t *)entry->value;
        *out_value_len = strlen(entry->value);
        return 0;
    }
    if (!sess) {
        return -1;
    }
    uint32_t dyn_idx = index - static_count - 1u;
    if (dyn_idx >= sess->hpack_dyn_count) {
        return -1;
    }
    const vhttp_http2_hpack_dyn_entry_t *entry = &sess->hpack_dyn[dyn_idx];
    if (!entry->buf || entry->name_len == 0) {
        return -1;
    }
    *out_name_ptr = entry->buf;
    *out_name_len = entry->name_len;
    *out_value_ptr = entry->buf + entry->name_len;
    *out_value_len = entry->value_len;
    return 0;
}

static int vhttp_http2_hpack_decode_huffman(
    const uint8_t *src,
    size_t len,
    uint8_t *dst,
    size_t dst_cap,
    size_t *out_len
) {
    if (!src || !out_len) {
        return -1;
    }
    if (vhttp_http2_hpack_huff_prepare() != 0) {
        return -1;
    }
    int16_t node = 0;
    size_t out_off = 0;

    for (size_t i = 0; i < len; ++i) {
        uint8_t byte = src[i];
        for (int b = 7; b >= 0; --b) {
            uint8_t bit = (uint8_t)((byte >> b) & 0x1u);
            node = g_http2_hpack_huff_nodes[node].next[bit];
            if (node < 0) {
                return -1;
            }
            int16_t sym = g_http2_hpack_huff_nodes[node].sym;
            if (sym >= 0) {
                if (sym == 256) {
                    return -1;
                }
                if (dst) {
                    if (out_off >= dst_cap) {
                        return -1;
                    }
                    dst[out_off] = (uint8_t)sym;
                }
                out_off++;
                node = 0;
            }
        }
    }

    if (!g_http2_hpack_huff_nodes[node].valid_end) {
        return -1;
    }
    *out_len = out_off;
    return 0;
}

static int vhttp_http2_hpack_decode_string(
    const uint8_t *src,
    size_t len,
    const uint8_t **out_ptr,
    size_t *out_len,
    size_t *out_used,
    uint8_t **out_alloc
) {
    if (!src || len == 0 || !out_ptr || !out_len || !out_used) {
        return -1;
    }
    if (out_alloc) {
        *out_alloc = NULL;
    }
    uint8_t huffman = (src[0] & 0x80u) ? 1u : 0u;
    uint32_t str_len = 0;
    size_t int_used = 0;
    if (vhttp_http2_hpack_decode_int(src, len, 7, &str_len, &int_used) != 0) {
        return -1;
    }
    if (int_used + (size_t)str_len > len) {
        return -1;
    }
    const uint8_t *raw = src + int_used;
    if (!huffman) {
        *out_ptr = raw;
        *out_len = (size_t)str_len;
        *out_used = int_used + (size_t)str_len;
        return 0;
    }

    size_t decoded_len = 0;
    if (vhttp_http2_hpack_decode_huffman(raw, (size_t)str_len, NULL, 0, &decoded_len) != 0) {
        return -1;
    }
    if (decoded_len > VHTTP_HTTP2_HPACK_HUFF_MAX_STR_LEN) {
        return -1;
    }
    if (decoded_len == 0) {
        *out_ptr = (const uint8_t *)"";
        *out_len = 0;
        *out_used = int_used + (size_t)str_len;
        return 0;
    }
    uint8_t *decoded = vhttp_http2_alloc_buf(decoded_len, NULL);
    if (!decoded) {
        return -1;
    }
    if (vhttp_http2_hpack_decode_huffman(raw, (size_t)str_len, decoded, decoded_len, &decoded_len) != 0) {
        heap_caps_free(decoded);
        return -1;
    }
    *out_ptr = decoded;
    *out_len = decoded_len;
    *out_used = int_used + (size_t)str_len;
    if (out_alloc) {
        *out_alloc = decoded;
    }
    return 0;
}

static int vhttp_http2_header_store_alloc(
    vhttp_http2_stream_req_t *req,
    const uint8_t *src,
    size_t len,
    char **out_ptr
) {
    if (!req || (!src && len > 0) || !out_ptr) {
        return -1;
    }
    if (len + 1u > (size_t)(sizeof(req->header_store) - req->header_store_used)) {
        return -1;
    }
    char *dst = req->header_store + req->header_store_used;
    if (len > 0) {
        memcpy(dst, src, len);
    }
    dst[len] = '\0';
    req->header_store_used += (uint16_t)(len + 1u);
    *out_ptr = dst;
    return 0;
}

static int vhttp_http2_req_add_header(
    vhttp_http2_stream_req_t *req,
    const uint8_t *name,
    size_t name_len,
    const uint8_t *value,
    size_t value_len
) {
    if (!req || !name || name_len == 0 || name_len > UINT8_MAX || !value) {
        return -1;
    }
    if (req->num_headers >= VHTTP_MAX_HEADERS) {
        return -1;
    }
    char *name_ptr = NULL;
    char *value_ptr = NULL;
    if (vhttp_http2_header_store_alloc(req, name, name_len, &name_ptr) != 0) {
        return -1;
    }
    if (vhttp_http2_header_store_alloc(req, value, value_len, &value_ptr) != 0) {
        return -1;
    }
    vhttp_header_t *hdr = &req->headers[req->num_headers++];
    hdr->name = name_ptr;
    hdr->name_len = (uint8_t)name_len;
    hdr->value = value_ptr;
    hdr->value_len = (uint16_t)value_len;
    return 0;
}

static int vhttp_http2_req_set_uri(vhttp_http2_stream_req_t *req, const uint8_t *path, size_t path_len) {
    if (!req || !path || path_len == 0 || path_len > VHTTP_MAX_URI_LEN) {
        return -1;
    }
    memcpy(req->uri, path, path_len);
    req->uri[path_len] = '\0';
    req->uri_len = (uint16_t)path_len;
    req->query_len = 0;
    for (size_t i = 0; i < path_len; ++i) {
        if (req->uri[i] == '?') {
            req->query_len = (uint16_t)(path_len - i - 1u);
            break;
        }
    }
    return 0;
}

static int vhttp_http2_req_apply_header(
    vhttp_http2_stream_req_t *req,
    const uint8_t *name,
    size_t name_len,
    const uint8_t *value,
    size_t value_len
) {
    if (!req || !name || name_len == 0 || !value) {
        return -1;
    }
    if (name[0] == ':') {
        if (name_len == 7 && memcmp(name, ":method", 7) == 0) {
            uint8_t method = 0;
            if (method_from_str((const char *)value, value_len, &method) != 0) {
                return -1;
            }
            req->method = method;
            return 0;
        }
        if (name_len == 5 && memcmp(name, ":path", 5) == 0) {
            return vhttp_http2_req_set_uri(req, value, value_len);
        }
        if (name_len == 10 && memcmp(name, ":authority", 10) == 0) {
            return vhttp_http2_req_add_header(req, (const uint8_t *)"host", 4, value, value_len);
        }
        if (name_len == 7 && memcmp(name, ":scheme", 7) == 0) {
            return 0;
        }
        return -1;
    }
    return vhttp_http2_req_add_header(req, name, name_len, value, value_len);
}

static int vhttp_http2_hpack_decode_headers(vhttp_http2_session_t *sess, vhttp_http2_stream_req_t *req) {
    if (!sess || !req || !req->header_block || req->header_block_len == 0) {
        return -1;
    }
    size_t off = 0;
    uint8_t seen_header_rep = 0;
    while (off < req->header_block_len) {
        uint8_t b = req->header_block[off];
        uint32_t index = 0;
        size_t used = 0;
        const uint8_t *name_ptr = NULL;
        size_t name_len = 0;
        const uint8_t *value_ptr = NULL;
        size_t value_len = 0;
        uint8_t *name_alloc = NULL;
        uint8_t *value_alloc = NULL;
        uint8_t add_to_dyn = 0;
        int rc = -1;

        if (b & 0x80u) {
            if (vhttp_http2_hpack_decode_int(req->header_block + off, req->header_block_len - off, 7, &index, &used) != 0) {
                return -1;
            }
            off += used;
            if (vhttp_http2_hpack_lookup_header(sess, index, &name_ptr, &name_len, &value_ptr, &value_len) != 0) {
                return -1;
            }
            if (vhttp_http2_req_apply_header(req, name_ptr, name_len, value_ptr, value_len) != 0) {
                return -1;
            }
            seen_header_rep = 1u;
            continue;
        }

        uint8_t prefix = 0;
        if ((b & 0x20u) == 0x20u) {
            if (seen_header_rep) {
                return -1;
            }
            if (vhttp_http2_hpack_decode_int(req->header_block + off, req->header_block_len - off, 5, &index, &used) != 0) {
                return -1;
            }
            off += used;
            if (index > VHTTP_HTTP2_HPACK_TABLE_SIZE) {
                return -1;
            }
            sess->hpack_dyn_max_size = index;
            vhttp_http2_session_dyn_trim(sess);
            continue;
        } else if ((b & 0x40u) == 0x40u) {
            prefix = 6;
            add_to_dyn = 1u;
        } else if ((b & 0xf0u) == 0x00u || (b & 0xf0u) == 0x10u) {
            prefix = 4;
        } else {
            return -1;
        }

        if (vhttp_http2_hpack_decode_int(req->header_block + off, req->header_block_len - off, prefix, &index, &used) != 0) {
            return -1;
        }
        off += used;

        if (index > 0) {
            if (vhttp_http2_hpack_lookup_header(sess, index, &name_ptr, &name_len, &value_ptr, &value_len) != 0) {
                return -1;
            }
        } else {
            size_t str_used = 0;
            int src_rc = vhttp_http2_hpack_decode_string(
                req->header_block + off,
                req->header_block_len - off,
                &name_ptr,
                &name_len,
                &str_used,
                &name_alloc
            );
            if (src_rc != 0) {
                return -1;
            }
            off += str_used;
        }

        size_t val_used = 0;
        int vrc = vhttp_http2_hpack_decode_string(
            req->header_block + off,
            req->header_block_len - off,
            &value_ptr,
            &value_len,
            &val_used,
            &value_alloc
        );
        if (vrc != 0) {
            if (name_alloc) {
                heap_caps_free(name_alloc);
            }
            return -1;
        }
        off += val_used;

        rc = vhttp_http2_req_apply_header(req, name_ptr, name_len, value_ptr, value_len);
        if (rc == 0 && add_to_dyn) {
            rc = vhttp_http2_session_dyn_insert(sess, name_ptr, name_len, value_ptr, value_len);
        }
        if (name_alloc) {
            heap_caps_free(name_alloc);
        }
        if (value_alloc) {
            heap_caps_free(value_alloc);
        }
        if (rc != 0) {
            return -1;
        }
        seen_header_rep = 1u;
    }

    if (req->method == 0xffu || req->uri_len == 0) {
        return -1;
    }
    req->headers_complete = 1u;
    return 0;
}

static int vhttp_http2_hpack_emit_int(
    uint8_t *dst,
    size_t cap,
    size_t *off,
    uint8_t prefix_bits,
    uint8_t first_mask,
    uint32_t value
) {
    if (!dst || !off || prefix_bits == 0 || prefix_bits > 8) {
        return -1;
    }
    uint32_t max_prefix = ((uint32_t)1u << prefix_bits) - 1u;
    if (*off >= cap) {
        return -1;
    }
    if (value < max_prefix) {
        dst[(*off)++] = (uint8_t)(first_mask | value);
        return 0;
    }
    dst[(*off)++] = (uint8_t)(first_mask | max_prefix);
    value -= max_prefix;
    while (value >= 128u) {
        if (*off >= cap) {
            return -1;
        }
        dst[(*off)++] = (uint8_t)((value & 0x7fu) | 0x80u);
        value >>= 7;
    }
    if (*off >= cap) {
        return -1;
    }
    dst[(*off)++] = (uint8_t)(value & 0x7fu);
    return 0;
}

static int vhttp_http2_hpack_emit_string(
    uint8_t *dst,
    size_t cap,
    size_t *off,
    const uint8_t *src,
    size_t len
) {
    if (!dst || !off || (!src && len > 0)) {
        return -1;
    }
    if (vhttp_http2_hpack_emit_int(dst, cap, off, 7, 0x00u, (uint32_t)len) != 0) {
        return -1;
    }
    if (*off + len > cap) {
        return -1;
    }
    if (len > 0) {
        memcpy(dst + *off, src, len);
    }
    *off += len;
    return 0;
}

static int vhttp_http2_hpack_emit_header(
    uint8_t *dst,
    size_t cap,
    size_t *off,
    const uint8_t *name,
    size_t name_len,
    const uint8_t *value,
    size_t value_len
) {
    if (vhttp_http2_hpack_emit_int(dst, cap, off, 4, 0x00u, 0) != 0) {
        return -1;
    }
    if (vhttp_http2_hpack_emit_string(dst, cap, off, name, name_len) != 0) {
        return -1;
    }
    if (vhttp_http2_hpack_emit_string(dst, cap, off, value, value_len) != 0) {
        return -1;
    }
    return 0;
}

static int vhttp_http2_status_index(int status) {
    switch (status) {
        case 200: return 8;
        case 204: return 9;
        case 206: return 10;
        case 304: return 11;
        case 400: return 12;
        case 404: return 13;
        case 500: return 14;
        default: return 0;
    }
}

static int vhttp_http2_parse_header_lines(
    const uint8_t *raw,
    uint16_t raw_len,
    uint8_t *block,
    size_t cap,
    size_t *off
) {
    if (!block || !off) {
        return -1;
    }
    if (!raw || raw_len == 0) {
        return 0;
    }
    size_t p = 0;
    while (p < raw_len) {
        size_t line_end = p;
        while (line_end < raw_len && raw[line_end] != '\n') {
            line_end++;
        }
        size_t line_len = line_end - p;
        if (line_len > 0 && raw[p + line_len - 1] == '\r') {
            line_len--;
        }
        if (line_len > 0) {
            const uint8_t *line = raw + p;
            const uint8_t *colon = memchr(line, ':', line_len);
            if (colon && colon > line) {
                size_t name_len = (size_t)(colon - line);
                const uint8_t *value = colon + 1;
                size_t value_len = line_len - name_len - 1u;
                while (value_len > 0 && (*value == ' ' || *value == '\t')) {
                    value++;
                    value_len--;
                }
                while (value_len > 0 && (value[value_len - 1] == ' ' || value[value_len - 1] == '\t')) {
                    value_len--;
                }
                if (!slice_ci_equals_n((const char *)line, name_len, "connection") &&
                    !slice_ci_equals_n((const char *)line, name_len, "transfer-encoding") &&
                    !slice_ci_equals_n((const char *)line, name_len, "upgrade") &&
                    !slice_ci_equals_n((const char *)line, name_len, "keep-alive") &&
                    !slice_ci_equals_n((const char *)line, name_len, "proxy-connection")) {
                    if (vhttp_http2_hpack_emit_header(block, cap, off, line, name_len, value, value_len) != 0) {
                        return -1;
                    }
                }
            }
        }
        p = line_end < raw_len ? line_end + 1u : raw_len;
    }
    return 0;
}

static int vhttp_http2_send_response_simple(
    vhttp_http2_session_t *sess,
    int sock,
    uint32_t stream_id,
    int status,
    const uint8_t *body,
    uint32_t body_len,
    const uint8_t *raw_headers,
    uint16_t raw_headers_len
) {
    uint8_t *block = vhttp_http2_alloc_buf(VHTTP_HTTP2_HEADER_BLOCK_MAX, NULL);
    if (!block) {
        return -1;
    }
    size_t off = 0;
    int idx = vhttp_http2_status_index(status);
    if (idx > 0) {
        if (vhttp_http2_hpack_emit_int(block, VHTTP_HTTP2_HEADER_BLOCK_MAX, &off, 7, 0x80u, (uint32_t)idx) != 0) {
            goto fail;
        }
    } else {
        char status_buf[4];
        int n = snprintf(status_buf, sizeof(status_buf), "%d", status);
        if (n <= 0 || n >= (int)sizeof(status_buf)) {
            goto fail;
        }
        if (vhttp_http2_hpack_emit_int(block, VHTTP_HTTP2_HEADER_BLOCK_MAX, &off, 4, 0x00u, 8) != 0) {
            goto fail;
        }
        if (vhttp_http2_hpack_emit_string(block, VHTTP_HTTP2_HEADER_BLOCK_MAX, &off, (const uint8_t *)status_buf, (size_t)n) != 0) {
            goto fail;
        }
    }
    if (body_len > 0) {
        char len_buf[16];
        int n = snprintf(len_buf, sizeof(len_buf), "%u", (unsigned int)body_len);
        if (n <= 0 || n >= (int)sizeof(len_buf)) {
            goto fail;
        }
        if (vhttp_http2_hpack_emit_header(
            block, VHTTP_HTTP2_HEADER_BLOCK_MAX, &off,
            (const uint8_t *)"content-length", 14,
            (const uint8_t *)len_buf, (size_t)n
        ) != 0) {
            goto fail;
        }
    }
    if (vhttp_http2_parse_header_lines(raw_headers, raw_headers_len, block, VHTTP_HTTP2_HEADER_BLOCK_MAX, &off) != 0) {
        goto fail;
    }

    uint8_t hflags = VHTTP_HTTP2_FLAG_END_HEADERS;
    if (body_len == 0) {
        hflags |= VHTTP_HTTP2_FLAG_END_STREAM;
    }
    if (vhttp_http2_send_frame(sock, VHTTP_HTTP2_FRAME_HEADERS, hflags, stream_id, block, (uint32_t)off) != 0) {
        goto fail;
    }
    if (body_len > 0 && body) {
        uint32_t sent = 0;
        while (sent < body_len) {
            uint32_t chunk = body_len - sent;
            if (chunk > VHTTP_HTTP2_FRAME_PAYLOAD_MAX) {
                chunk = VHTTP_HTTP2_FRAME_PAYLOAD_MAX;
            }
            if (sess) {
                uint32_t avail = 0;
                if (vhttp_http2_flow_tx_available(sess, stream_id, &avail) != 0 || avail == 0) {
                    goto fail;
                }
                if (chunk > avail) {
                    chunk = avail;
                }
            }
            uint8_t dflags = ((sent + chunk) >= body_len) ? VHTTP_HTTP2_FLAG_END_STREAM : 0;
            if (vhttp_http2_send_frame(sock, VHTTP_HTTP2_FRAME_DATA, dflags, stream_id, body + sent, chunk) != 0) {
                goto fail;
            }
            if (sess && vhttp_http2_flow_consume_tx(sess, stream_id, chunk) != 0) {
                goto fail;
            }
            sent += chunk;
        }
    }
    heap_caps_free(block);
    return 0;
fail:
    heap_caps_free(block);
    return -1;
}

static int vhttp_http2_send_rst_stream(int sock, uint32_t stream_id, uint32_t error_code) {
    uint8_t payload[4] = {
        (uint8_t)((error_code >> 24) & 0xffu),
        (uint8_t)((error_code >> 16) & 0xffu),
        (uint8_t)((error_code >> 8) & 0xffu),
        (uint8_t)(error_code & 0xffu)
    };
    if (vhttp_http2_send_frame(sock, VHTTP_HTTP2_FRAME_RST_STREAM, 0, stream_id, payload, sizeof(payload)) != 0) {
        return -1;
    }
    vhttp_stats_inc(&g_server_stats.http2_rst_sent);
    vhttp_http2_note_error_code(error_code);
    return 0;
}

static int vhttp_http2_enqueue_ipc_request(
    vhttp_ipc_state_t *ipc,
    const vhttp_parsed_request_t *parsed,
    uint8_t method,
    uint32_t *out_req_id,
    uint32_t *out_request_blob_len
) {
    if (!ipc || !parsed || !out_req_id || !out_request_blob_len) {
        return 500;
    }
    uint16_t uri_len = parsed->uri.len;
    uint16_t query_len = parsed->query.len;
    uint32_t req_headers_len = 0;
    for (uint8_t i = 0; i < parsed->num_headers; ++i) {
        req_headers_len += (uint32_t)parsed->headers[i].name_len + 1u;
        req_headers_len += (uint32_t)parsed->headers[i].value_len + 1u;
    }
    uint32_t req_body_len = parsed->body_len;
    uint32_t request_blob_len = (uint32_t)uri_len + req_headers_len + req_body_len;
    if (request_blob_len == 0 || req_headers_len > 65535u) {
        return 400;
    }

    uint32_t path_offset = 0;
    uint8_t *path_dst = NULL;
    if (vhttp_ipc_ring_alloc(&ipc->ring, request_blob_len, &path_offset, &path_dst) != 0) {
        vhttp_stats_inc(&g_server_stats.ipc_req_ring_alloc_fail);
        return 503;
    }

    memcpy(path_dst, parsed->uri.ptr, uri_len);
    if (req_headers_len > 0) {
        uint8_t *hdr_dst = path_dst + uri_len;
        uint32_t hdr_written = 0;
        for (uint8_t i = 0; i < parsed->num_headers; ++i) {
            const vhttp_header_t *hdr = &parsed->headers[i];
            if (hdr->name_len > 0) {
                memcpy(hdr_dst + hdr_written, hdr->name, hdr->name_len);
                hdr_written += hdr->name_len;
            }
            hdr_dst[hdr_written++] = '\0';
            if (hdr->value_len > 0) {
                memcpy(hdr_dst + hdr_written, hdr->value, hdr->value_len);
                hdr_written += hdr->value_len;
            }
            hdr_dst[hdr_written++] = '\0';
        }
    }
    if (req_body_len > 0) {
        memcpy(path_dst + uri_len + req_headers_len, parsed->body, req_body_len);
    }

    uint32_t req_id = vhttp_next_request_id();
    vhttp_ipc_msg_t msg = {0};
    msg.request_id = req_id;
    msg.type = VHTTP_IPC_REQ_HTTP;
    msg.method = method;
    msg.uri_len = uri_len;
    msg.query_len = query_len;
    msg.headers_len = (uint16_t)req_headers_len;
    msg.headers_offset = req_headers_len > 0 ? (path_offset + uri_len) : 0;
    msg.body_len = req_body_len;
    msg.buffer_offset = path_offset;

    if (vhttp_ipc_queue_push_wait(&ipc->request_queue, &msg, VHTTP_SERVER_REQ_QUEUE_WAIT_MS) != 0) {
        vhttp_stats_inc(&g_server_stats.ipc_req_queue_push_fail);
        vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
        return 503;
    }

    *out_req_id = req_id;
    *out_request_blob_len = request_blob_len;
    return 0;
}

static int vhttp_http2_wait_ipc_response(vhttp_ipc_state_t *ipc, uint32_t req_id, vhttp_ipc_msg_t *out) {
    if (!ipc || req_id == 0 || !out) {
        return -1;
    }
    uint32_t waited_ms = 0;
    while (waited_ms < VHTTP_SERVER_RESP_TIMEOUT_MS) {
        if (vhttp_ipc_wait_response_for(ipc, req_id, VHTTP_SERVER_WAIT_IPC_SLICE_MS, out) == 0) {
            return 0;
        }
        waited_ms += VHTTP_SERVER_WAIT_IPC_SLICE_MS;
        vhttp_stats_inc(&g_server_stats.scheduler_yields);
        taskYIELD();
    }
    vhttp_stats_inc(&g_server_stats.ipc_wait_timeouts);
    return -1;
}

struct vhttp_http2_pending_ipc_s {
    uint8_t active;
    uint8_t head_only;
    uint8_t headers_sent;
    uint8_t tx_final;
    uint32_t req_id;
    uint32_t request_blob_len;
    uint32_t stream_id;
    uint32_t tx_body_offset;
    uint32_t tx_body_len;
    uint32_t tx_body_sent;
    TickType_t wait_since;
};

static void vhttp_http2_pending_tx_reset(vhttp_http2_pending_ipc_t *pending) {
    if (!pending) {
        return;
    }
    pending->tx_body_offset = 0;
    pending->tx_body_len = 0;
    pending->tx_body_sent = 0;
    pending->tx_final = 0;
}

static int vhttp_http2_pending_tx_flush_body(
    vhttp_http2_session_t *sess,
    vhttp_http2_pending_ipc_t *pending,
    vhttp_ipc_state_t *ipc,
    uint8_t *out_final
) {
    if (!sess || !pending || !ipc || !out_final) {
        return -1;
    }
    *out_final = 0u;
    if (pending->tx_body_len == 0 || pending->tx_body_sent >= pending->tx_body_len) {
        return 1;
    }

    const uint8_t *body_ptr = vhttp_ipc_ring_ptr(&ipc->ring, pending->tx_body_offset);
    if (!body_ptr) {
        vhttp_ipc_ring_release(&ipc->ring, pending->tx_body_len);
        vhttp_http2_pending_tx_reset(pending);
        return -1;
    }

    while (pending->tx_body_sent < pending->tx_body_len) {
        uint32_t chunk = pending->tx_body_len - pending->tx_body_sent;
        if (chunk > VHTTP_HTTP2_FRAME_PAYLOAD_MAX) {
            chunk = VHTTP_HTTP2_FRAME_PAYLOAD_MAX;
        }
        uint32_t avail = 0;
        if (vhttp_http2_flow_tx_available(sess, pending->stream_id, &avail) != 0) {
            return -1;
        }
        if (avail == 0) {
            return 0;
        }
        if (chunk > avail) {
            chunk = avail;
        }
        uint8_t dflags = 0u;
        if (pending->tx_final && ((pending->tx_body_sent + chunk) >= pending->tx_body_len)) {
            dflags |= VHTTP_HTTP2_FLAG_END_STREAM;
        }
        if (vhttp_http2_send_frame(
            sess->sock,
            VHTTP_HTTP2_FRAME_DATA,
            dflags,
            pending->stream_id,
            body_ptr + pending->tx_body_sent,
            chunk
        ) != 0) {
            return -1;
        }
        if (vhttp_http2_flow_consume_tx(sess, pending->stream_id, chunk) != 0) {
            return -1;
        }
        pending->tx_body_sent += chunk;
    }

    vhttp_ipc_ring_release(&ipc->ring, pending->tx_body_len);
    if (pending->tx_final) {
        *out_final = 1u;
    }
    vhttp_http2_pending_tx_reset(pending);
    return 1;
}

static void vhttp_http2_pending_release_request_blob(vhttp_http2_pending_ipc_t *pending, vhttp_ipc_state_t *ipc) {
    if (!pending) {
        return;
    }
    if (ipc && pending->request_blob_len > 0) {
        vhttp_ipc_ring_release(&ipc->ring, pending->request_blob_len);
    }
    if (ipc && pending->tx_body_len > 0) {
        vhttp_ipc_ring_release(&ipc->ring, pending->tx_body_len);
    }
    vhttp_http2_pending_tx_reset(pending);
    pending->headers_sent = 0;
    pending->head_only = 0;
    pending->request_blob_len = 0;
    pending->req_id = 0;
    pending->stream_id = 0;
    pending->wait_since = 0;
    pending->active = 0;
}

static void vhttp_http2_pending_abort(vhttp_http2_pending_ipc_t *pending, vhttp_ipc_state_t *ipc) {
    if (!pending) {
        return;
    }
    if (ipc && pending->req_id != 0) {
        uint32_t request_blob_len = pending->request_blob_len;
        vhttp_abort_inflight_request(ipc, pending->req_id, &request_blob_len);
        pending->request_blob_len = request_blob_len;
    } else if (ipc && pending->request_blob_len > 0) {
        vhttp_ipc_ring_release(&ipc->ring, pending->request_blob_len);
        pending->request_blob_len = 0;
    }
    if (ipc && pending->tx_body_len > 0) {
        vhttp_ipc_ring_release(&ipc->ring, pending->tx_body_len);
    }
    vhttp_http2_pending_tx_reset(pending);
    pending->headers_sent = 0;
    pending->head_only = 0;
    pending->req_id = 0;
    pending->stream_id = 0;
    pending->wait_since = 0;
    pending->active = 0;
}

static int vhttp_http2_try_dispatch_ready_req(
    vhttp_http2_session_t *sess,
    vhttp_http2_pending_ipc_t *pending,
    uint8_t *served_any,
    uint8_t short_idle_after_response
) {
    if (!sess || !pending || !served_any) {
        return -1;
    }
    if (!sess->req.active) {
        (void)vhttp_http2_buffered_req_activate_next(sess);
    }
    if (!sess->req.active) {
        return 0;
    }
    if (pending->active) {
        if (sess->req.headers_complete && sess->req.end_stream) {
            if (vhttp_http2_buffered_req_enqueue_current(sess) == 0) {
                return 1;
            }
        }
        return 0;
    }
    if (!sess->req.active || !sess->req.headers_complete || !sess->req.end_stream) {
        return 0;
    }

    if (short_idle_after_response) {
        int src = vhttp_http2_dispatch_request_async_start(sess, &sess->req, pending);
        if (src < 0) {
            return -1;
        }
        if (src == 0) {
            vhttp_http2_req_clear_active(sess);
            return 1;
        }
        *served_any = 1;
        vhttp_http2_req_finish_stream(sess, sess->req.stream_id);
        vhttp_http2_req_clear_active(sess);
        return 1;
    }

    int drc = vhttp_http2_dispatch_request(sess, &sess->req);
    if (drc == 0) {
        *served_any = 1;
    }
    vhttp_http2_req_finish_stream(sess, sess->req.stream_id);
    vhttp_http2_req_clear_active(sess);
    if (drc != 0) {
        return -1;
    }
    return 1;
}

static int vhttp_http2_send_ipc_message_to_stream(
    vhttp_http2_session_t *sess,
    vhttp_http2_pending_ipc_t *pending,
    const vhttp_ipc_msg_t *msg,
    vhttp_ipc_state_t *ipc,
    uint8_t *out_final
) {
    if (!sess || !pending || !msg || !ipc || !out_final) {
        return -1;
    }

    uint32_t body_len = msg->body_len;
    const uint8_t *body_ptr = NULL;
    if (body_len > 0) {
        body_ptr = vhttp_ipc_ring_ptr(&ipc->ring, msg->buffer_offset);
        if (!body_ptr) {
            vhttp_ipc_ring_release(&ipc->ring, body_len);
            return -1;
        }
    }

    uint16_t headers_len = msg->headers_len;
    const uint8_t *headers_ptr = NULL;
    if (headers_len > 0) {
        headers_ptr = vhttp_ipc_ring_ptr(&ipc->ring, msg->headers_offset);
        if (!headers_ptr) {
            if (body_len > 0) {
                vhttp_ipc_ring_release(&ipc->ring, body_len);
            }
            vhttp_ipc_ring_release(&ipc->ring, headers_len);
            return -1;
        }
    }

    int rc = -1;
    uint8_t release_body = body_len > 0 ? 1u : 0u;
    uint8_t release_headers = headers_len > 0 ? 1u : 0u;
    uint8_t end_stream_sent_in_headers = 0u;
    if (msg->flags & VHTTP_IPC_FLAG_STREAM) {
        if (!pending->headers_sent) {
            int status = msg->status_code == 0 ? 200 : msg->status_code;
            uint8_t *block = vhttp_http2_alloc_buf(VHTTP_HTTP2_HEADER_BLOCK_MAX, NULL);
            if (!block) {
                goto done;
            }
            size_t off = 0;
            int idx = vhttp_http2_status_index(status);
            if (idx > 0) {
                if (vhttp_http2_hpack_emit_int(block, VHTTP_HTTP2_HEADER_BLOCK_MAX, &off, 7, 0x80u, (uint32_t)idx) != 0) {
                    heap_caps_free(block);
                    goto done;
                }
            } else {
                char status_buf[4];
                int n = snprintf(status_buf, sizeof(status_buf), "%d", status);
                if (n <= 0 || n >= (int)sizeof(status_buf)) {
                    heap_caps_free(block);
                    goto done;
                }
                if (vhttp_http2_hpack_emit_int(block, VHTTP_HTTP2_HEADER_BLOCK_MAX, &off, 4, 0x00u, 8) != 0) {
                    heap_caps_free(block);
                    goto done;
                }
                if (vhttp_http2_hpack_emit_string(block, VHTTP_HTTP2_HEADER_BLOCK_MAX, &off, (const uint8_t *)status_buf, (size_t)n) != 0) {
                    heap_caps_free(block);
                    goto done;
                }
            }
            if (msg->total_len > 0) {
                char len_buf[16];
                int n = snprintf(len_buf, sizeof(len_buf), "%u", (unsigned int)msg->total_len);
                if (n > 0 && n < (int)sizeof(len_buf)) {
                    if (vhttp_http2_hpack_emit_header(
                        block, VHTTP_HTTP2_HEADER_BLOCK_MAX, &off,
                        (const uint8_t *)"content-length", 14,
                        (const uint8_t *)len_buf, (size_t)n
                    ) != 0) {
                        heap_caps_free(block);
                        goto done;
                    }
                }
            }
            if (vhttp_http2_parse_header_lines(headers_ptr, headers_len, block, VHTTP_HTTP2_HEADER_BLOCK_MAX, &off) != 0) {
                heap_caps_free(block);
                goto done;
            }
            uint8_t hflags = VHTTP_HTTP2_FLAG_END_HEADERS;
            if ((msg->flags & VHTTP_IPC_FLAG_FINAL) && (pending->head_only || body_len == 0)) {
                hflags |= VHTTP_HTTP2_FLAG_END_STREAM;
                end_stream_sent_in_headers = 1u;
            }
            if (vhttp_http2_send_frame(sess->sock, VHTTP_HTTP2_FRAME_HEADERS, hflags, pending->stream_id, block, (uint32_t)off) != 0) {
                heap_caps_free(block);
                goto done;
            }
            heap_caps_free(block);
            pending->headers_sent = 1u;
        }

        if (!pending->head_only && body_len > 0) {
            pending->tx_body_offset = msg->buffer_offset;
            pending->tx_body_len = body_len;
            pending->tx_body_sent = 0;
            pending->tx_final = (msg->flags & VHTTP_IPC_FLAG_FINAL) ? 1u : 0u;
            uint8_t tx_final = 0u;
            int txrc = vhttp_http2_pending_tx_flush_body(sess, pending, ipc, &tx_final);
            if (txrc < 0) {
                goto done;
            }
            release_body = 0u;
            if (txrc == 0) {
                rc = 0;
                goto done;
            }
            if (tx_final) {
                *out_final = 1u;
            }
            rc = 0;
            goto done;
        }
        if ((msg->flags & VHTTP_IPC_FLAG_FINAL) &&
            !pending->head_only &&
            body_len == 0 &&
            pending->headers_sent &&
            !end_stream_sent_in_headers) {
            if (vhttp_http2_send_frame(
                sess->sock,
                VHTTP_HTTP2_FRAME_DATA,
                VHTTP_HTTP2_FLAG_END_STREAM,
                pending->stream_id,
                NULL,
                0
            ) != 0) {
                goto done;
            }
        }
        *out_final = (msg->flags & VHTTP_IPC_FLAG_FINAL) ? 1u : 0u;
        rc = 0;
        goto done;
    }

    {
        int status = msg->status_code == 0 ? 200 : msg->status_code;
        if (vhttp_http2_send_response_simple(
            sess,
            sess->sock,
            pending->stream_id,
            status,
            pending->head_only ? NULL : body_ptr,
            pending->head_only ? 0u : body_len,
            headers_ptr,
            headers_len
        ) != 0) {
            goto done;
        }
        *out_final = 1u;
        rc = 0;
    }

done:
    if (release_body && body_len > 0) {
        vhttp_ipc_ring_release(&ipc->ring, body_len);
    }
    if (release_headers && headers_len > 0) {
        vhttp_ipc_ring_release(&ipc->ring, headers_len);
    }
    return rc;
}

static int vhttp_http2_dispatch_request_async_start(
    vhttp_http2_session_t *sess,
    vhttp_http2_stream_req_t *req,
    vhttp_http2_pending_ipc_t *pending
) {
    if (!sess || !req || !pending || pending->active || !req->headers_complete || !req->active || req->method == 0xffu || req->uri_len == 0) {
        return -1;
    }

    vhttp_parsed_request_t parsed;
    memset(&parsed, 0, sizeof(parsed));

    const char *method_name = "GET";
    size_t method_len = 3;
    switch (req->method) {
        case VHTTP_METHOD_GET: method_name = "GET"; method_len = 3; break;
        case VHTTP_METHOD_POST: method_name = "POST"; method_len = 4; break;
        case VHTTP_METHOD_PUT: method_name = "PUT"; method_len = 3; break;
        case VHTTP_METHOD_PATCH: method_name = "PATCH"; method_len = 5; break;
        case VHTTP_METHOD_DELETE: method_name = "DELETE"; method_len = 6; break;
        case VHTTP_METHOD_OPTIONS: method_name = "OPTIONS"; method_len = 7; break;
        case VHTTP_METHOD_HEAD: method_name = "HEAD"; method_len = 4; break;
        default: break;
    }

    parsed.method.ptr = method_name;
    parsed.method.len = (uint16_t)method_len;
    parsed.uri.ptr = req->uri;
    parsed.uri.len = req->uri_len;
    parsed.path.ptr = req->uri;
    parsed.path.len = req->uri_len;
    parsed.query.ptr = "";
    parsed.query.len = 0;
    for (uint16_t i = 0; i < req->uri_len; ++i) {
        if (req->uri[i] == '?') {
            parsed.path.len = i;
            parsed.query.ptr = req->uri + i + 1u;
            parsed.query.len = (uint16_t)(req->uri_len - i - 1u);
            break;
        }
    }
    parsed.num_headers = req->num_headers;
    for (uint8_t i = 0; i < req->num_headers; ++i) {
        parsed.headers[i] = req->headers[i];
    }
    parsed.body = (const char *)req->body;
    parsed.body_len = req->body_len;
    parsed.content_length = req->body_len;
    parsed.total_len = 0;

    vhttp_log_http_request(&parsed, sess->client_ip);

    if (vhttp_trusted_host_enabled() && !vhttp_trusted_host_allowed(&parsed)) {
        (void)vhttp_http2_send_response_simple(sess, sess->sock, req->stream_id, 400, (const uint8_t *)"Invalid Host", 12, NULL, 0);
        return 1;
    }
    if (req->method == VHTTP_METHOD_GET && ws_is_upgrade_request(&parsed)) {
        (void)vhttp_http2_send_response_simple(sess, sess->sock, req->stream_id, 426, (const uint8_t *)"Upgrade Required", 16, NULL, 0);
        return 1;
    }
    if (vhttp_ratelimit_enabled()) {
        uint32_t retry_ms = 0;
        if (!vhttp_ratelimit_check(sess->client_ip, &retry_ms)) {
            char extra[64];
            uint32_t retry_sec = (retry_ms + 999u) / 1000u;
            int n = snprintf(extra, sizeof(extra), "retry-after: %lu\r\n", (unsigned long)retry_sec);
            if (n < 0 || (size_t)n >= sizeof(extra)) {
                extra[0] = '\0';
                n = 0;
            }
            (void)vhttp_http2_send_response_simple(
                sess,
                sess->sock,
                req->stream_id,
                429,
                (const uint8_t *)"Too Many Requests",
                17,
                (const uint8_t *)extra,
                (uint16_t)n
            );
            return 1;
        }
    }

    vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
    if (!ipc) {
        (void)vhttp_http2_send_response_simple(
            sess,
            sess->sock,
            req->stream_id,
            500,
            (const uint8_t *)"IPC Unavailable",
            15,
            NULL,
            0
        );
        return -1;
    }

    uint32_t req_id = 0;
    uint32_t request_blob_len = 0;
    int qrc = vhttp_http2_enqueue_ipc_request(ipc, &parsed, req->method, &req_id, &request_blob_len);
    if (qrc != 0) {
        const uint8_t *msg = (const uint8_t *)"Bad Request";
        uint16_t msg_len = 11;
        if (qrc == 503) {
            msg = (const uint8_t *)"Backpressure";
            msg_len = 12;
        } else if (qrc >= 500) {
            msg = (const uint8_t *)"Internal Server Error";
            msg_len = 21;
        }
        (void)vhttp_http2_send_response_simple(sess, sess->sock, req->stream_id, qrc, msg, msg_len, NULL, 0);
        return qrc >= 500 ? -1 : 1;
    }

    pending->active = 1u;
    pending->head_only = (req->method == VHTTP_METHOD_HEAD) ? 1u : 0u;
    pending->headers_sent = 0u;
    pending->tx_final = 0u;
    pending->req_id = req_id;
    pending->request_blob_len = request_blob_len;
    pending->stream_id = req->stream_id;
    pending->tx_body_offset = 0u;
    pending->tx_body_len = 0u;
    pending->tx_body_sent = 0u;
    pending->wait_since = xTaskGetTickCount();
    return 0;
}

static int vhttp_http2_dispatch_request_async_poll(
    vhttp_http2_session_t *sess,
    vhttp_http2_pending_ipc_t *pending
) {
    if (!sess || !pending || !pending->active || pending->req_id == 0) {
        return -1;
    }

    vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
    if (!ipc) {
        return -1;
    }

    if (pending->tx_body_len > 0 && pending->tx_body_sent < pending->tx_body_len) {
        uint8_t tx_final = 0u;
        int txrc = vhttp_http2_pending_tx_flush_body(sess, pending, ipc, &tx_final);
        if (txrc < 0) {
            vhttp_http2_pending_abort(pending, ipc);
            return -1;
        }
        pending->wait_since = xTaskGetTickCount();
        if (tx_final) {
            vhttp_http2_pending_release_request_blob(pending, ipc);
            return 1;
        }
        if (txrc == 0) {
            return 0;
        }
    }

    vhttp_ipc_msg_t resp = {0};
    if (vhttp_ipc_try_response_for(ipc, pending->req_id, &resp) != 0) {
        TickType_t timeout = pdMS_TO_TICKS(VHTTP_SERVER_RESP_TIMEOUT_MS);
        if (timeout == 0) {
            timeout = 1;
        }
        if ((TickType_t)(xTaskGetTickCount() - pending->wait_since) >= timeout) {
            uint32_t stream_id = pending->stream_id;
            vhttp_http2_pending_abort(pending, ipc);
            (void)vhttp_http2_send_response_simple(
                sess,
                sess->sock,
                stream_id,
                504,
                (const uint8_t *)"Gateway Timeout",
                15,
                NULL,
                0
            );
            vhttp_stats_inc(&g_server_stats.ipc_wait_timeouts);
            return 1;
        }
        return 0;
    }

    uint8_t final_chunk = 0;
    if (vhttp_http2_send_ipc_message_to_stream(sess, pending, &resp, ipc, &final_chunk) != 0) {
        vhttp_http2_pending_abort(pending, ipc);
        return -1;
    }
    pending->wait_since = xTaskGetTickCount();
    if (final_chunk) {
        vhttp_http2_pending_release_request_blob(pending, ipc);
        return 1;
    }
    return 0;
}

static int vhttp_http2_process_frame(
    vhttp_http2_session_t *sess,
    vhttp_http2_frame_t *frame,
    vhttp_http2_pending_ipc_t *pending,
    uint8_t *served_any,
    uint8_t short_idle_after_response
);

struct vhttp_http2_event_ctx_s {
    vhttp_http2_session_t *sess;
    vhttp_http2_pending_ipc_t pending;
    uint8_t served_any;
    uint8_t *tx_buf;
    uint32_t tx_len;
    uint32_t tx_sent;
    uint8_t tx_in_psram;
};

static int vhttp_http2_event_tx_has_pending(const vhttp_http2_event_ctx_t *ctx) {
    if (!ctx) {
        return 0;
    }
    return ctx->tx_len > ctx->tx_sent ? 1 : 0;
}

static void vhttp_http2_event_tx_compact(vhttp_http2_event_ctx_t *ctx) {
    if (!ctx || !ctx->tx_buf || ctx->tx_sent == 0) {
        return;
    }
    if (ctx->tx_sent >= ctx->tx_len) {
        ctx->tx_len = 0;
        ctx->tx_sent = 0;
        return;
    }
    uint32_t remaining = ctx->tx_len - ctx->tx_sent;
    memmove(ctx->tx_buf, ctx->tx_buf + ctx->tx_sent, remaining);
    ctx->tx_len = remaining;
    ctx->tx_sent = 0;
}

static int vhttp_http2_event_tx_append(vhttp_http2_event_ctx_t *ctx, const uint8_t *src, uint32_t len) {
    if (!ctx || (!src && len > 0)) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    vhttp_http2_event_tx_compact(ctx);
    uint32_t current = ctx->tx_len;
    uint32_t next = current + len;
    if (next < current || next > VHTTP_HTTP2_EVENT_LOOP_TX_MAX_BYTES) {
        return -1;
    }
    if (!ctx->tx_buf) {
        ctx->tx_buf = vhttp_http2_alloc_buf(next, &ctx->tx_in_psram);
        if (!ctx->tx_buf) {
            return -1;
        }
    } else if (next > current) {
        uint8_t *grown = vhttp_http2_realloc_buf(ctx->tx_buf, next, &ctx->tx_in_psram);
        if (!grown) {
            return -1;
        }
        ctx->tx_buf = grown;
    }
    memcpy(ctx->tx_buf + current, src, len);
    ctx->tx_len = next;
    return 0;
}

static int vhttp_http2_event_tx_queue_frame(
    vhttp_http2_event_ctx_t *ctx,
    uint8_t type,
    uint8_t flags,
    uint32_t stream_id,
    const uint8_t *payload,
    uint32_t payload_len
) {
    if (!ctx || payload_len > 0x00ffffffu) {
        return -1;
    }
    uint8_t hdr[9];
    hdr[0] = (uint8_t)((payload_len >> 16) & 0xffu);
    hdr[1] = (uint8_t)((payload_len >> 8) & 0xffu);
    hdr[2] = (uint8_t)(payload_len & 0xffu);
    hdr[3] = type;
    hdr[4] = flags;
    hdr[5] = (uint8_t)((stream_id >> 24) & 0x7fu);
    hdr[6] = (uint8_t)((stream_id >> 16) & 0xffu);
    hdr[7] = (uint8_t)((stream_id >> 8) & 0xffu);
    hdr[8] = (uint8_t)(stream_id & 0xffu);
    if (vhttp_http2_event_tx_append(ctx, hdr, sizeof(hdr)) != 0) {
        return -1;
    }
    if (payload_len > 0 && payload) {
        if (vhttp_http2_event_tx_append(ctx, payload, payload_len) != 0) {
            return -1;
        }
    }
    return 0;
}

static int vhttp_http2_event_tx_queue_frame_for_sock(
    int sock,
    uint8_t type,
    uint8_t flags,
    uint32_t stream_id,
    const uint8_t *payload,
    uint32_t payload_len
) {
    if (sock < 0) {
        return -1;
    }
    if (xTaskGetCurrentTaskHandle() != g_server_task) {
        return 1;
    }
    for (size_t i = 0; i < (size_t)VHTTP_EVENT_LOOP_MAX_CONNS; ++i) {
        vhttp_evrt_conn_t *conn = &g_evrt_conns[i];
        if (!conn->used || conn->sock != sock || !conn->h2_ctx) {
            continue;
        }
        return vhttp_http2_event_tx_queue_frame(conn->h2_ctx, type, flags, stream_id, payload, payload_len);
    }
    return 1;
}

static int vhttp_http2_event_tx_flush(vhttp_http2_event_ctx_t *ctx, int socket_writable) {
    if (!ctx || !ctx->sess) {
        return -1;
    }
    if (!vhttp_http2_event_tx_has_pending(ctx)) {
        return 1;
    }
    if (!socket_writable) {
        return 0;
    }

    uint32_t budget = VHTTP_HTTP2_EVENT_LOOP_TX_BUDGET_BYTES;
    if (budget == 0) {
        budget = 1;
    }
    while (vhttp_http2_event_tx_has_pending(ctx) && budget > 0) {
        uint32_t remaining = ctx->tx_len - ctx->tx_sent;
        size_t chunk = remaining;
        if (chunk > (size_t)budget) {
            chunk = (size_t)budget;
        }
        int rc = vhttp_sock_send(ctx->sess->sock, ctx->tx_buf + ctx->tx_sent, chunk);
        if (rc > 0) {
            ctx->tx_sent += (uint32_t)rc;
            if ((uint32_t)rc >= budget) {
                budget = 0;
            } else {
                budget -= (uint32_t)rc;
            }
            continue;
        }
        if (rc == 0) {
            return -1;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        return -1;
    }
    vhttp_http2_event_tx_compact(ctx);
    return vhttp_http2_event_tx_has_pending(ctx) ? 0 : 1;
}

static void vhttp_http2_event_ctx_free(vhttp_http2_event_ctx_t *ctx) {
    if (!ctx) {
        return;
    }
    if (ctx->sess) {
        if (ctx->pending.active) {
            vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
            uint32_t stream_id = ctx->pending.stream_id;
            vhttp_http2_pending_abort(&ctx->pending, ipc);
            if (stream_id != 0) {
                vhttp_http2_slot_release(stream_id);
            }
        }
        if (ctx->sess->req.active) {
            vhttp_http2_slot_release(ctx->sess->req.stream_id);
        }
        vhttp_http2_buffered_req_release_all(ctx->sess, 1u);
        vhttp_http2_req_free(&ctx->sess->req);
        vhttp_http2_session_dyn_reset(ctx->sess);
        heap_caps_free(ctx->sess);
        ctx->sess = NULL;
    }
    if (ctx->tx_buf) {
        heap_caps_free(ctx->tx_buf);
        ctx->tx_buf = NULL;
    }
    ctx->tx_len = 0;
    ctx->tx_sent = 0;
    ctx->tx_in_psram = 0;
    heap_caps_free(ctx);
}

static void vhttp_evrt_h2_detach(vhttp_evrt_conn_t *conn) {
    if (!conn || !conn->h2_ctx) {
        return;
    }
    vhttp_http2_event_ctx_free(conn->h2_ctx);
    conn->h2_ctx = NULL;
}

static int vhttp_evrt_h2_activate(vhttp_evrt_conn_t *conn) {
    if (!conn || conn->sock < 0 || !conn->recv_buf || conn->recv_cap == 0) {
        return -1;
    }
    if (conn->h2_ctx) {
        return 0;
    }
    if (conn->buffered < VHTTP_HTTP2_PREFACE_LEN ||
        !vhttp_http2_buffer_starts_with_preface(conn->recv_buf, conn->buffered)) {
        return -1;
    }
    if (vhttp_http2_hpack_huff_prepare() != 0) {
        return -1;
    }

    vhttp_http2_event_ctx_t *ctx = (vhttp_http2_event_ctx_t *)heap_caps_malloc(
        sizeof(vhttp_http2_event_ctx_t),
        MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT
    );
    if (!ctx) {
        ctx = (vhttp_http2_event_ctx_t *)heap_caps_malloc(sizeof(vhttp_http2_event_ctx_t), MALLOC_CAP_8BIT);
    }
    if (!ctx) {
        return -1;
    }
    memset(ctx, 0, sizeof(*ctx));

    ctx->sess = (vhttp_http2_session_t *)vhttp_http2_alloc_buf(sizeof(vhttp_http2_session_t), NULL);
    if (!ctx->sess) {
        heap_caps_free(ctx);
        return -1;
    }
    memset(ctx->sess, 0, sizeof(*ctx->sess));
    ctx->sess->sock = conn->sock;
    ctx->sess->client_ip = conn->client_ip;
    ctx->sess->recv_buf = conn->recv_buf;
    ctx->sess->recv_cap = conn->recv_cap;
    ctx->sess->buffered = conn->buffered;
    ctx->sess->hpack_dyn_max_size = VHTTP_HTTP2_HPACK_TABLE_SIZE;
    vhttp_http2_session_dyn_reset(ctx->sess);
    vhttp_http2_flow_init(ctx->sess);
    vhttp_http2_req_reset(&ctx->sess->req);

    vhttp_stats_inc(&g_server_stats.http2_preface_seen);
    vhttp_http2_rx_consume(ctx->sess, VHTTP_HTTP2_PREFACE_LEN);
    conn->h2_ctx = ctx;
    if (vhttp_http2_send_server_settings(ctx->sess) != 0) {
        vhttp_evrt_h2_detach(conn);
        return -1;
    }

    conn->buffered = ctx->sess->buffered;
    conn->state_since = xTaskGetTickCount();
    return 0;
}

static int vhttp_evrt_h2_tick(vhttp_evrt_conn_t *conn, int socket_writable) {
    if (!conn || !conn->h2_ctx || !conn->h2_ctx->sess) {
        return -1;
    }
    vhttp_http2_event_ctx_t *ctx = conn->h2_ctx;
    vhttp_http2_session_t *sess = ctx->sess;
    sess->sock = conn->sock;
    sess->client_ip = conn->client_ip;
    sess->recv_buf = conn->recv_buf;
    sess->recv_cap = conn->recv_cap;
    sess->buffered = conn->buffered;
    int tx_rc = vhttp_http2_event_tx_flush(ctx, socket_writable);
    if (tx_rc < 0) {
        return -1;
    }
    if (tx_rc == 0) {
        conn->buffered = sess->buffered;
        TickType_t timeout = pdMS_TO_TICKS(VHTTP_SERVER_RESP_TIMEOUT_MS);
        if (timeout == 0) {
            timeout = 1;
        }
        if ((TickType_t)(xTaskGetTickCount() - conn->state_since) >= timeout) {
            return -1;
        }
        return 0;
    }

    uint32_t budget = (uint32_t)VHTTP_HTTP2_EVENT_LOOP_FRAME_BUDGET;
    if (budget == 0) {
        budget = 1;
    }
    uint8_t progressed = 0;

    for (uint32_t i = 0; i < budget; ++i) {
        if (ctx->pending.active) {
            uint32_t pending_stream_id = ctx->pending.stream_id;
            int prc = vhttp_http2_dispatch_request_async_poll(sess, &ctx->pending);
            if (prc < 0) {
                vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
                vhttp_http2_pending_abort(&ctx->pending, ipc);
                if (pending_stream_id != 0) {
                    vhttp_http2_stream_state_on_rst(sess, pending_stream_id);
                    vhttp_http2_slot_release(pending_stream_id);
                }
                return -1;
            }
            if (prc > 0) {
                ctx->served_any = 1;
                progressed = 1;
                if (pending_stream_id != 0) {
                    (void)vhttp_http2_stream_state_on_local_end(sess, pending_stream_id);
                    vhttp_http2_slot_release(pending_stream_id);
                }
                if (sess->req.active && sess->req.stream_id == pending_stream_id) {
                    vhttp_http2_req_clear_active(sess);
                }
                {
                    int drc = vhttp_http2_try_dispatch_ready_req(sess, &ctx->pending, &ctx->served_any, 1u);
                    if (drc < 0) {
                        return -1;
                    }
                    if (drc > 0) {
                        progressed = 1;
                    }
                }
                conn->state_since = xTaskGetTickCount();
                continue;
            }
        }

        vhttp_http2_frame_t frame;
        int frc = vhttp_http2_try_read_buffered_frame(sess, &frame);
        if (frc == 1) {
            break;
        }
        if (frc == -2) {
            (void)vhttp_http2_send_goaway(sess->sock, VHTTP_HTTP2_ERR_FRAME_SIZE);
            vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
            return -1;
        }
        if (frc != 0) {
            return -1;
        }

        if (vhttp_http2_process_frame(sess, &frame, &ctx->pending, &ctx->served_any, 1u) != 0) {
            return -1;
        }
        progressed = 1;
        conn->state_since = xTaskGetTickCount();
    }

    conn->buffered = sess->buffered;
    if (!progressed) {
        uint32_t idle_ms = VHTTP_HTTP2_SESSION_IDLE_TIMEOUT_MS;
        if (!ctx->served_any &&
            !ctx->pending.active &&
            conn->buffered == 0 &&
            !sess->req.active &&
            !sess->expect_continuation) {
            idle_ms = VHTTP_HTTP2_EVENT_LOOP_FIRST_REQ_WAIT_MS;
        }
        TickType_t timeout = pdMS_TO_TICKS(idle_ms);
        if (timeout == 0) {
            timeout = 1;
        }
        if ((TickType_t)(xTaskGetTickCount() - conn->state_since) >= timeout) {
            return -1;
        }
    }

    return 0;
}

static int vhttp_http2_dispatch_request(vhttp_http2_session_t *sess, vhttp_http2_stream_req_t *req) {
    if (!sess || !req || !req->headers_complete || !req->active || req->method == 0xffu || req->uri_len == 0) {
        return -1;
    }
    vhttp_parsed_request_t parsed;
    memset(&parsed, 0, sizeof(parsed));

    const char *method_name = "GET";
    size_t method_len = 3;
    switch (req->method) {
        case VHTTP_METHOD_GET: method_name = "GET"; method_len = 3; break;
        case VHTTP_METHOD_POST: method_name = "POST"; method_len = 4; break;
        case VHTTP_METHOD_PUT: method_name = "PUT"; method_len = 3; break;
        case VHTTP_METHOD_PATCH: method_name = "PATCH"; method_len = 5; break;
        case VHTTP_METHOD_DELETE: method_name = "DELETE"; method_len = 6; break;
        case VHTTP_METHOD_OPTIONS: method_name = "OPTIONS"; method_len = 7; break;
        case VHTTP_METHOD_HEAD: method_name = "HEAD"; method_len = 4; break;
        default: break;
    }

    parsed.method.ptr = method_name;
    parsed.method.len = (uint16_t)method_len;
    parsed.uri.ptr = req->uri;
    parsed.uri.len = req->uri_len;
    parsed.path.ptr = req->uri;
    parsed.path.len = req->uri_len;
    parsed.query.ptr = "";
    parsed.query.len = 0;
    for (uint16_t i = 0; i < req->uri_len; ++i) {
        if (req->uri[i] == '?') {
            parsed.path.len = i;
            parsed.query.ptr = req->uri + i + 1u;
            parsed.query.len = (uint16_t)(req->uri_len - i - 1u);
            break;
        }
    }
    parsed.num_headers = req->num_headers;
    for (uint8_t i = 0; i < req->num_headers; ++i) {
        parsed.headers[i] = req->headers[i];
    }
    parsed.body = (const char *)req->body;
    parsed.body_len = req->body_len;
    parsed.content_length = req->body_len;
    parsed.total_len = 0;

    vhttp_log_http_request(&parsed, sess->client_ip);

    if (vhttp_trusted_host_enabled() && !vhttp_trusted_host_allowed(&parsed)) {
        (void)vhttp_http2_send_response_simple(sess, sess->sock, req->stream_id, 400, (const uint8_t *)"Invalid Host", 12, NULL, 0);
        return 0;
    }
    if (req->method == VHTTP_METHOD_GET && ws_is_upgrade_request(&parsed)) {
        (void)vhttp_http2_send_response_simple(sess, sess->sock, req->stream_id, 426, (const uint8_t *)"Upgrade Required", 16, NULL, 0);
        return 0;
    }
    if (vhttp_ratelimit_enabled()) {
        uint32_t retry_ms = 0;
        if (!vhttp_ratelimit_check(sess->client_ip, &retry_ms)) {
            char extra[64];
            uint32_t retry_sec = (retry_ms + 999u) / 1000u;
            int n = snprintf(extra, sizeof(extra), "retry-after: %lu\r\n", (unsigned long)retry_sec);
            if (n < 0 || (size_t)n >= sizeof(extra)) {
                extra[0] = '\0';
                n = 0;
            }
            (void)vhttp_http2_send_response_simple(
                sess,
                sess->sock,
                req->stream_id,
                429,
                (const uint8_t *)"Too Many Requests",
                17,
                (const uint8_t *)extra,
                (uint16_t)n
            );
            return 0;
        }
    }
    vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
    if (!ipc) {
        (void)vhttp_http2_send_response_simple(
            sess,
            sess->sock,
            req->stream_id,
            500,
            (const uint8_t *)"IPC Unavailable",
            15,
            NULL,
            0
        );
        return -1;
    }

    uint32_t req_id = 0;
    uint32_t request_blob_len = 0;
    int qrc = vhttp_http2_enqueue_ipc_request(ipc, &parsed, req->method, &req_id, &request_blob_len);
    if (qrc != 0) {
        const uint8_t *msg = (const uint8_t *)"Bad Request";
        uint16_t msg_len = 11;
        if (qrc == 503) {
            msg = (const uint8_t *)"Backpressure";
            msg_len = 12;
        } else if (qrc >= 500) {
            msg = (const uint8_t *)"Internal Server Error";
            msg_len = 21;
        }
        (void)vhttp_http2_send_response_simple(sess, sess->sock, req->stream_id, qrc, msg, msg_len, NULL, 0);
        return qrc >= 500 ? -1 : 0;
    }

    vhttp_ipc_msg_t resp;
    if (vhttp_http2_wait_ipc_response(ipc, req_id, &resp) != 0) {
        vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
        (void)vhttp_http2_send_response_simple(
            sess,
            sess->sock,
            req->stream_id,
            504,
            (const uint8_t *)"Gateway Timeout",
            15,
            NULL,
            0
        );
        return 0;
    }

    int head_only = req->method == VHTTP_METHOD_HEAD;
    if (resp.flags & VHTTP_IPC_FLAG_STREAM) {
        vhttp_ipc_msg_t stream_resp = resp;
        uint8_t headers_sent = 0;
        for (;;) {
            uint32_t body_len = stream_resp.body_len;
            const uint8_t *body_ptr = NULL;
            if (body_len > 0) {
                body_ptr = vhttp_ipc_ring_ptr(&ipc->ring, stream_resp.buffer_offset);
                if (!body_ptr) {
                    vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
                    return -1;
                }
            }
            uint16_t headers_len = stream_resp.headers_len;
            const uint8_t *headers_ptr = NULL;
            if (headers_len > 0) {
                headers_ptr = vhttp_ipc_ring_ptr(&ipc->ring, stream_resp.headers_offset);
                if (!headers_ptr) {
                    if (body_len > 0) {
                        vhttp_ipc_ring_release(&ipc->ring, body_len);
                    }
                    vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
                    return -1;
                }
            }

            if (!headers_sent) {
                int status = stream_resp.status_code == 0 ? 200 : stream_resp.status_code;
                uint8_t *block = vhttp_http2_alloc_buf(VHTTP_HTTP2_HEADER_BLOCK_MAX, NULL);
                if (!block) {
                    return -1;
                }
                size_t off = 0;
                int idx = vhttp_http2_status_index(status);
                if (idx > 0) {
                    if (vhttp_http2_hpack_emit_int(block, VHTTP_HTTP2_HEADER_BLOCK_MAX, &off, 7, 0x80u, (uint32_t)idx) != 0) {
                        heap_caps_free(block);
                        return -1;
                    }
                } else {
                    char status_buf[4];
                    int n = snprintf(status_buf, sizeof(status_buf), "%d", status);
                    if (n <= 0 || n >= (int)sizeof(status_buf)) {
                        heap_caps_free(block);
                        return -1;
                    }
                    if (vhttp_http2_hpack_emit_int(block, VHTTP_HTTP2_HEADER_BLOCK_MAX, &off, 4, 0x00u, 8) != 0) {
                        heap_caps_free(block);
                        return -1;
                    }
                    if (vhttp_http2_hpack_emit_string(block, VHTTP_HTTP2_HEADER_BLOCK_MAX, &off, (const uint8_t *)status_buf, (size_t)n) != 0) {
                        heap_caps_free(block);
                        return -1;
                    }
                }
                if (stream_resp.total_len > 0) {
                    char len_buf[16];
                    int n = snprintf(len_buf, sizeof(len_buf), "%u", (unsigned int)stream_resp.total_len);
                    if (n > 0 && n < (int)sizeof(len_buf)) {
                        if (vhttp_http2_hpack_emit_header(
                            block, VHTTP_HTTP2_HEADER_BLOCK_MAX, &off,
                            (const uint8_t *)"content-length", 14,
                            (const uint8_t *)len_buf, (size_t)n
                        ) != 0) {
                            heap_caps_free(block);
                            return -1;
                        }
                    }
                }
                if (vhttp_http2_parse_header_lines(headers_ptr, headers_len, block, VHTTP_HTTP2_HEADER_BLOCK_MAX, &off) != 0) {
                    heap_caps_free(block);
                    return -1;
                }
                uint8_t hflags = VHTTP_HTTP2_FLAG_END_HEADERS;
                if ((stream_resp.flags & VHTTP_IPC_FLAG_FINAL) && (head_only || body_len == 0)) {
                    hflags |= VHTTP_HTTP2_FLAG_END_STREAM;
                }
                if (vhttp_http2_send_frame(sess->sock, VHTTP_HTTP2_FRAME_HEADERS, hflags, req->stream_id, block, (uint32_t)off) != 0) {
                    heap_caps_free(block);
                    return -1;
                }
                heap_caps_free(block);
                headers_sent = 1;
            }

            if (!head_only && body_len > 0) {
                uint32_t sent = 0;
                while (sent < body_len) {
                    uint32_t chunk = body_len - sent;
                    if (chunk > VHTTP_HTTP2_FRAME_PAYLOAD_MAX) {
                        chunk = VHTTP_HTTP2_FRAME_PAYLOAD_MAX;
                    }
                    uint32_t avail = 0;
                    if (vhttp_http2_flow_tx_available(sess, req->stream_id, &avail) != 0 || avail == 0) {
                        return -1;
                    }
                    if (chunk > avail) {
                        chunk = avail;
                    }
                    uint8_t dflags = 0;
                    if ((stream_resp.flags & VHTTP_IPC_FLAG_FINAL) && ((sent + chunk) >= body_len)) {
                        dflags |= VHTTP_HTTP2_FLAG_END_STREAM;
                    }
                    if (vhttp_http2_send_frame(
                        sess->sock,
                        VHTTP_HTTP2_FRAME_DATA,
                        dflags,
                        req->stream_id,
                        body_ptr + sent,
                        chunk
                    ) != 0) {
                        return -1;
                    }
                    if (vhttp_http2_flow_consume_tx(sess, req->stream_id, chunk) != 0) {
                        return -1;
                    }
                    sent += chunk;
                }
            }

            if (body_len > 0) {
                vhttp_ipc_ring_release(&ipc->ring, body_len);
            }
            if (headers_len > 0) {
                vhttp_ipc_ring_release(&ipc->ring, headers_len);
            }

            if (stream_resp.flags & VHTTP_IPC_FLAG_FINAL) {
                break;
            }

            if (vhttp_http2_wait_ipc_response(ipc, req_id, &stream_resp) != 0) {
                vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
                return -1;
            }
        }
        vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
        return 0;
    }

    uint32_t body_len = resp.body_len;
    const uint8_t *body_ptr = NULL;
    if (body_len > 0) {
        body_ptr = vhttp_ipc_ring_ptr(&ipc->ring, resp.buffer_offset);
        if (!body_ptr) {
            vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
            return -1;
        }
    }
    uint16_t headers_len = resp.headers_len;
    const uint8_t *headers_ptr = NULL;
    if (headers_len > 0) {
        headers_ptr = vhttp_ipc_ring_ptr(&ipc->ring, resp.headers_offset);
        if (!headers_ptr) {
            if (body_len > 0) {
                vhttp_ipc_ring_release(&ipc->ring, body_len);
            }
            vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
            return -1;
        }
    }

    int status = resp.status_code == 0 ? 200 : resp.status_code;
    int src = vhttp_http2_send_response_simple(
        sess,
        sess->sock,
        req->stream_id,
        status,
        head_only ? NULL : body_ptr,
        head_only ? 0u : body_len,
        headers_ptr,
        headers_len
    );
    vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
    if (body_len > 0) {
        vhttp_ipc_ring_release(&ipc->ring, body_len);
    }
    if (headers_len > 0) {
        vhttp_ipc_ring_release(&ipc->ring, headers_len);
    }
    return src;
}

static int vhttp_http2_send_server_settings(vhttp_http2_session_t *sess) {
    if (!sess) {
        return -1;
    }
    uint16_t max_streams = 8;
    taskENTER_CRITICAL(&g_http2_cfg_lock);
    if (g_http2_cfg.max_streams > 0) {
        max_streams = g_http2_cfg.max_streams;
    }
    taskEXIT_CRITICAL(&g_http2_cfg_lock);

    uint32_t table_size = VHTTP_HTTP2_HPACK_TABLE_SIZE;
    if (table_size > 0xffffu) {
        table_size = 0xffffu;
    }
    uint8_t payload[18] = {
        0x00, 0x01, // HEADER_TABLE_SIZE
        (uint8_t)((table_size >> 24) & 0xffu),
        (uint8_t)((table_size >> 16) & 0xffu),
        (uint8_t)((table_size >> 8) & 0xffu),
        (uint8_t)(table_size & 0xffu),
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // ENABLE_PUSH=0
        0x00, 0x03, 0x00, 0x00,             // MAX_CONCURRENT_STREAMS
        (uint8_t)((max_streams >> 8) & 0xffu),
        (uint8_t)(max_streams & 0xffu)
    };
    return vhttp_http2_send_frame(sess->sock, VHTTP_HTTP2_FRAME_SETTINGS, 0, 0, payload, sizeof(payload));
}

static int vhttp_http2_process_frame(
    vhttp_http2_session_t *sess,
    vhttp_http2_frame_t *frame,
    vhttp_http2_pending_ipc_t *pending,
    uint8_t *served_any,
    uint8_t short_idle_after_response
) {
    if (!sess || !frame || !pending || !served_any) {
        return -1;
    }
    if (sess->expect_continuation &&
        (frame->type != VHTTP_HTTP2_FRAME_CONTINUATION || frame->stream_id != sess->continuation_stream_id)) {
        (void)vhttp_http2_send_goaway(sess->sock, VHTTP_HTTP2_ERR_PROTOCOL);
        vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
        vhttp_http2_frame_free(frame);
        return -1;
    }

    if (frame->type == VHTTP_HTTP2_FRAME_SETTINGS) {
        if (frame->stream_id != 0 ||
            ((frame->flags & VHTTP_HTTP2_FLAG_ACK) && frame->payload_len != 0) ||
            ((frame->payload_len % 6u) != 0u)) {
            (void)vhttp_http2_send_goaway(sess->sock, VHTTP_HTTP2_ERR_PROTOCOL);
            vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
            vhttp_http2_frame_free(frame);
            return -1;
        }
        if ((frame->flags & VHTTP_HTTP2_FLAG_ACK) == 0) {
            int32_t next_peer_initial_window = sess->peer_initial_window;
            for (uint32_t i = 0; i + 6u <= frame->payload_len; i += 6u) {
                uint16_t setting_id = ((uint16_t)frame->payload[i] << 8) | (uint16_t)frame->payload[i + 1u];
                uint32_t setting_val = ((uint32_t)frame->payload[i + 2u] << 24) |
                                       ((uint32_t)frame->payload[i + 3u] << 16) |
                                       ((uint32_t)frame->payload[i + 4u] << 8) |
                                       (uint32_t)frame->payload[i + 5u];
                if (setting_id == VHTTP_HTTP2_SETTINGS_ENABLE_PUSH && setting_val > 1u) {
                    (void)vhttp_http2_send_goaway(sess->sock, VHTTP_HTTP2_ERR_PROTOCOL);
                    vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
                    vhttp_http2_frame_free(frame);
                    return -1;
                }
                if (setting_id == VHTTP_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE && setting_val > 0x7fffffffu) {
                    (void)vhttp_http2_send_goaway(sess->sock, VHTTP_HTTP2_ERR_FLOW_CONTROL);
                    vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
                    vhttp_http2_frame_free(frame);
                    return -1;
                }
                if (setting_id == VHTTP_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE) {
                    next_peer_initial_window = (int32_t)setting_val;
                }
                if (setting_id == VHTTP_HTTP2_SETTINGS_MAX_FRAME_SIZE &&
                    (setting_val < 16384u || setting_val > 16777215u)) {
                    (void)vhttp_http2_send_goaway(sess->sock, VHTTP_HTTP2_ERR_PROTOCOL);
                    vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
                    vhttp_http2_frame_free(frame);
                    return -1;
                }
            }
            if (next_peer_initial_window != sess->peer_initial_window) {
                if (vhttp_http2_flow_apply_peer_initial_window(sess, next_peer_initial_window) != 0) {
                    (void)vhttp_http2_send_goaway(sess->sock, VHTTP_HTTP2_ERR_FLOW_CONTROL);
                    vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
                    vhttp_http2_frame_free(frame);
                    return -1;
                }
            }
            if (vhttp_http2_send_frame(sess->sock, VHTTP_HTTP2_FRAME_SETTINGS, VHTTP_HTTP2_FLAG_ACK, 0, NULL, 0) != 0) {
                vhttp_http2_frame_free(frame);
                return -1;
            }
        }
        vhttp_http2_frame_free(frame);
        return 0;
    }

    if (frame->type == VHTTP_HTTP2_FRAME_PING) {
        if (frame->stream_id != 0 || frame->payload_len != 8) {
            (void)vhttp_http2_send_goaway(sess->sock, VHTTP_HTTP2_ERR_PROTOCOL);
            vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
            vhttp_http2_frame_free(frame);
            return -1;
        }
        if ((frame->flags & VHTTP_HTTP2_FLAG_ACK) == 0) {
            if (vhttp_http2_send_frame(sess->sock, VHTTP_HTTP2_FRAME_PING, VHTTP_HTTP2_FLAG_ACK, 0, frame->payload, 8) != 0) {
                vhttp_http2_frame_free(frame);
                return -1;
            }
        }
        vhttp_http2_frame_free(frame);
        return 0;
    }

    if (frame->type == VHTTP_HTTP2_FRAME_WINDOW_UPDATE) {
        if (frame->payload_len != 4) {
            (void)vhttp_http2_send_goaway(sess->sock, VHTTP_HTTP2_ERR_FRAME_SIZE);
            vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
            vhttp_http2_frame_free(frame);
            return -1;
        }
        uint32_t increment = ((uint32_t)(frame->payload[0] & 0x7fu) << 24) |
                             ((uint32_t)frame->payload[1] << 16) |
                             ((uint32_t)frame->payload[2] << 8) |
                             (uint32_t)frame->payload[3];
        int wrc = vhttp_http2_flow_on_window_update(sess, frame->stream_id, increment);
        if (wrc < 0) {
            if (wrc == -1 || frame->stream_id == 0) {
                (void)vhttp_http2_send_goaway(sess->sock, VHTTP_HTTP2_ERR_FLOW_CONTROL);
                vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
                vhttp_http2_frame_free(frame);
                return -1;
            }
            (void)vhttp_http2_send_rst_stream(sess->sock, frame->stream_id, VHTTP_HTTP2_ERR_FLOW_CONTROL);
        }
        vhttp_http2_frame_free(frame);
        return 0;
    }

    if (frame->type == VHTTP_HTTP2_FRAME_GOAWAY) {
        vhttp_http2_frame_free(frame);
        return -1;
    }

    if (frame->type == VHTTP_HTTP2_FRAME_RST_STREAM) {
        if (frame->stream_id == 0) {
            (void)vhttp_http2_send_goaway(sess->sock, VHTTP_HTTP2_ERR_PROTOCOL);
            vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
            vhttp_http2_frame_free(frame);
            return -1;
        }
        if (frame->payload_len != 4) {
            (void)vhttp_http2_send_goaway(sess->sock, VHTTP_HTTP2_ERR_FRAME_SIZE);
            vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
            vhttp_http2_frame_free(frame);
            return -1;
        }
        vhttp_http2_stream_state_on_rst(sess, frame->stream_id);
        if (pending->active && pending->stream_id == frame->stream_id) {
            vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
            vhttp_http2_pending_abort(pending, ipc);
            vhttp_http2_slot_release(frame->stream_id);
            if (sess->req.active && frame->stream_id == sess->req.stream_id) {
                vhttp_http2_req_clear_active(sess);
            }
        } else if (sess->req.active && frame->stream_id == sess->req.stream_id) {
            vhttp_http2_req_abort_stream(sess, sess->req.stream_id);
            vhttp_http2_req_clear_active(sess);
        } else if (vhttp_http2_buffered_req_drop_stream(sess, frame->stream_id)) {
            vhttp_http2_slot_release(frame->stream_id);
        }
        vhttp_http2_frame_free(frame);
        return 0;
    }

    if (frame->type == VHTTP_HTTP2_FRAME_HEADERS) {
        if (frame->stream_id == 0) {
            (void)vhttp_http2_send_goaway(sess->sock, VHTTP_HTTP2_ERR_PROTOCOL);
            vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
            vhttp_http2_frame_free(frame);
            return -1;
        }
        if (pending->active && frame->stream_id == pending->stream_id) {
            (void)vhttp_http2_send_rst_stream(sess->sock, frame->stream_id, VHTTP_HTTP2_ERR_STREAM_CLOSED);
            vhttp_http2_frame_free(frame);
            return 0;
        }
        int shrc = vhttp_http2_stream_state_on_new_headers(
            sess,
            frame->stream_id,
            (frame->flags & VHTTP_HTTP2_FLAG_END_STREAM) ? 1u : 0u
        );
        if (shrc == -2) {
            (void)vhttp_http2_send_rst_stream(sess->sock, frame->stream_id, VHTTP_HTTP2_ERR_PROTOCOL);
            vhttp_http2_frame_free(frame);
            return 0;
        }
        if (shrc == -4) {
            (void)vhttp_http2_send_rst_stream(sess->sock, frame->stream_id, VHTTP_HTTP2_ERR_STREAM_CLOSED);
            vhttp_http2_frame_free(frame);
            return 0;
        }
        if (shrc != 0) {
            (void)vhttp_http2_send_rst_stream(sess->sock, frame->stream_id, VHTTP_HTTP2_ERR_REFUSED_STREAM);
            vhttp_http2_frame_free(frame);
            return 0;
        }
        int arc = vhttp_http2_prepare_active_req_for_stream(sess, frame->stream_id, 1u);
        if (arc == -2 || arc == -4) {
            (void)vhttp_http2_send_rst_stream(sess->sock, frame->stream_id, VHTTP_HTTP2_ERR_REFUSED_STREAM);
            vhttp_http2_stream_state_on_rst(sess, frame->stream_id);
            vhttp_http2_frame_free(frame);
            return 0;
        }
        if (arc < 0) {
            (void)vhttp_http2_send_rst_stream(sess->sock, frame->stream_id, VHTTP_HTTP2_ERR_STREAM_CLOSED);
            vhttp_http2_stream_state_on_rst(sess, frame->stream_id);
            vhttp_http2_frame_free(frame);
            return 0;
        }

        size_t off = 0;
        if (frame->flags & VHTTP_HTTP2_FLAG_PADDED) {
            if (frame->payload_len == 0) {
                vhttp_http2_frame_free(frame);
                return -1;
            }
            uint8_t pad = frame->payload[off++];
            if ((uint32_t)off + (uint32_t)pad > frame->payload_len) {
                (void)vhttp_http2_send_rst_stream(sess->sock, frame->stream_id, VHTTP_HTTP2_ERR_PROTOCOL);
                vhttp_http2_frame_free(frame);
                if (sess->req.active && sess->req.stream_id == frame->stream_id) {
                    vhttp_http2_req_abort_stream(sess, sess->req.stream_id);
                    vhttp_http2_req_clear_active(sess);
                }
                return 0;
            }
            frame->payload_len -= pad;
        }
        if (frame->flags & VHTTP_HTTP2_FLAG_PRIORITY) {
            if ((uint32_t)off + 5u > frame->payload_len) {
                (void)vhttp_http2_send_rst_stream(sess->sock, frame->stream_id, VHTTP_HTTP2_ERR_FRAME_SIZE);
                vhttp_http2_frame_free(frame);
                if (sess->req.active && sess->req.stream_id == frame->stream_id) {
                    vhttp_http2_req_abort_stream(sess, sess->req.stream_id);
                    vhttp_http2_req_clear_active(sess);
                }
                return 0;
            }
            off += 5u;
        }
        size_t frag_len = frame->payload_len >= (uint32_t)off ? (size_t)(frame->payload_len - (uint32_t)off) : 0;
        uint32_t need = sess->req.header_block_len + (uint32_t)frag_len;
        if (vhttp_http2_req_ensure_header_block(&sess->req, need) != 0) {
            (void)vhttp_http2_send_rst_stream(sess->sock, frame->stream_id, VHTTP_HTTP2_ERR_COMPRESSION);
            vhttp_http2_frame_free(frame);
            if (sess->req.active && sess->req.stream_id == frame->stream_id) {
                vhttp_http2_req_abort_stream(sess, sess->req.stream_id);
                vhttp_http2_req_clear_active(sess);
            }
            return 0;
        }
        if (frag_len > 0) {
            memcpy(sess->req.header_block + sess->req.header_block_len, frame->payload + off, frag_len);
            sess->req.header_block_len += (uint32_t)frag_len;
        }
        if (frame->flags & VHTTP_HTTP2_FLAG_END_HEADERS) {
            if (vhttp_http2_hpack_decode_headers(sess, &sess->req) != 0) {
                (void)vhttp_http2_send_rst_stream(sess->sock, frame->stream_id, VHTTP_HTTP2_ERR_COMPRESSION);
                vhttp_http2_frame_free(frame);
                vhttp_http2_req_abort_stream(sess, sess->req.stream_id);
                vhttp_http2_req_clear_active(sess);
                return 0;
            }
            sess->expect_continuation = 0;
            sess->continuation_stream_id = 0;
        } else {
            sess->expect_continuation = 1u;
            sess->continuation_stream_id = frame->stream_id;
        }
        if (frame->flags & VHTTP_HTTP2_FLAG_END_STREAM) {
            (void)vhttp_http2_stream_state_on_remote_end(sess, frame->stream_id);
            sess->req.end_stream = 1u;
        }
        vhttp_http2_frame_free(frame);

        {
            int drc = vhttp_http2_try_dispatch_ready_req(sess, pending, served_any, short_idle_after_response);
            if (drc < 0) {
                return -1;
            }
        }
        return 0;
    }

    if (frame->type == VHTTP_HTTP2_FRAME_CONTINUATION) {
        if (!sess->expect_continuation || frame->stream_id != sess->continuation_stream_id) {
            (void)vhttp_http2_send_goaway(sess->sock, VHTTP_HTTP2_ERR_PROTOCOL);
            vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
            vhttp_http2_frame_free(frame);
            return -1;
        }
        int arc = vhttp_http2_prepare_active_req_for_stream(sess, frame->stream_id, 0u);
        if (arc < 0) {
            (void)vhttp_http2_send_goaway(sess->sock, VHTTP_HTTP2_ERR_PROTOCOL);
            vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
            vhttp_http2_frame_free(frame);
            return -1;
        }
        uint32_t need = sess->req.header_block_len + frame->payload_len;
        if (vhttp_http2_req_ensure_header_block(&sess->req, need) != 0) {
            (void)vhttp_http2_send_rst_stream(sess->sock, frame->stream_id, VHTTP_HTTP2_ERR_COMPRESSION);
            vhttp_http2_frame_free(frame);
            if (sess->req.active && sess->req.stream_id == frame->stream_id) {
                vhttp_http2_req_abort_stream(sess, sess->req.stream_id);
                vhttp_http2_req_clear_active(sess);
            }
            return -1;
        }
        if (frame->payload_len > 0) {
            memcpy(sess->req.header_block + sess->req.header_block_len, frame->payload, frame->payload_len);
            sess->req.header_block_len += frame->payload_len;
        }
        if (frame->flags & VHTTP_HTTP2_FLAG_END_HEADERS) {
            if (vhttp_http2_hpack_decode_headers(sess, &sess->req) != 0) {
                (void)vhttp_http2_send_rst_stream(sess->sock, frame->stream_id, VHTTP_HTTP2_ERR_COMPRESSION);
                vhttp_http2_frame_free(frame);
                vhttp_http2_req_abort_stream(sess, sess->req.stream_id);
                vhttp_http2_req_clear_active(sess);
                return 0;
            }
            sess->expect_continuation = 0;
            sess->continuation_stream_id = 0;
        }
        vhttp_http2_frame_free(frame);

        {
            int drc = vhttp_http2_try_dispatch_ready_req(sess, pending, served_any, short_idle_after_response);
            if (drc < 0) {
                return -1;
            }
        }
        return 0;
    }

    if (frame->type == VHTTP_HTTP2_FRAME_DATA) {
        if (frame->stream_id == 0) {
            (void)vhttp_http2_send_goaway(sess->sock, VHTTP_HTTP2_ERR_PROTOCOL);
            vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
            vhttp_http2_frame_free(frame);
            return -1;
        }
        int arc = vhttp_http2_prepare_active_req_for_stream(sess, frame->stream_id, 0u);
        if (arc < 0) {
            uint32_t err = (arc == -2) ? VHTTP_HTTP2_ERR_REFUSED_STREAM : VHTTP_HTTP2_ERR_STREAM_CLOSED;
            (void)vhttp_http2_send_rst_stream(sess->sock, frame->stream_id, err);
            vhttp_http2_frame_free(frame);
            return 0;
        }
        uint8_t stream_state = vhttp_http2_stream_state_get(sess, frame->stream_id);
        if (stream_state == VHTTP_HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE ||
            stream_state == VHTTP_HTTP2_STREAM_STATE_CLOSED) {
            (void)vhttp_http2_send_rst_stream(sess->sock, frame->stream_id, VHTTP_HTTP2_ERR_STREAM_CLOSED);
            vhttp_http2_frame_free(frame);
            if (sess->req.active && sess->req.stream_id == frame->stream_id) {
                vhttp_http2_req_abort_stream(sess, sess->req.stream_id);
                vhttp_http2_req_clear_active(sess);
            }
            return 0;
        }
        if (!sess->req.headers_complete || sess->expect_continuation) {
            (void)vhttp_http2_send_rst_stream(sess->sock, frame->stream_id, VHTTP_HTTP2_ERR_PROTOCOL);
            vhttp_http2_frame_free(frame);
            vhttp_http2_req_abort_stream(sess, sess->req.stream_id);
            vhttp_http2_req_clear_active(sess);
            return 0;
        }

        size_t off = 0;
        if (frame->flags & VHTTP_HTTP2_FLAG_PADDED) {
            if (frame->payload_len == 0) {
                vhttp_http2_frame_free(frame);
                return -1;
            }
            uint8_t pad = frame->payload[off++];
            if ((uint32_t)off + (uint32_t)pad > frame->payload_len) {
                (void)vhttp_http2_send_rst_stream(sess->sock, frame->stream_id, VHTTP_HTTP2_ERR_PROTOCOL);
                vhttp_http2_frame_free(frame);
                vhttp_http2_req_abort_stream(sess, sess->req.stream_id);
                vhttp_http2_req_clear_active(sess);
                return 0;
            }
            frame->payload_len -= pad;
        }
        uint32_t data_len = frame->payload_len >= (uint32_t)off ? (frame->payload_len - (uint32_t)off) : 0;
        if (data_len > 0) {
            uint8_t conn_fc_err = 0;
            int crc = vhttp_http2_flow_consume_rx(sess, frame->stream_id, data_len, &conn_fc_err);
            if (crc != 0) {
                if (conn_fc_err) {
                    (void)vhttp_http2_send_goaway(sess->sock, VHTTP_HTTP2_ERR_FLOW_CONTROL);
                    vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
                    vhttp_http2_frame_free(frame);
                    return -1;
                }
                (void)vhttp_http2_send_rst_stream(sess->sock, frame->stream_id, VHTTP_HTTP2_ERR_FLOW_CONTROL);
                vhttp_http2_frame_free(frame);
                if (sess->req.active && sess->req.stream_id == frame->stream_id) {
                    vhttp_http2_req_abort_stream(sess, sess->req.stream_id);
                    vhttp_http2_req_clear_active(sess);
                }
                return 0;
            }
        }
        if (data_len > 0) {
            uint32_t need = sess->req.body_len + data_len;
            if (vhttp_http2_req_ensure_body(&sess->req, need) != 0) {
                (void)vhttp_http2_send_rst_stream(sess->sock, frame->stream_id, VHTTP_HTTP2_ERR_FLOW_CONTROL);
                vhttp_http2_frame_free(frame);
                vhttp_http2_req_abort_stream(sess, sess->req.stream_id);
                vhttp_http2_req_clear_active(sess);
                return 0;
            }
            memcpy(sess->req.body + sess->req.body_len, frame->payload + off, data_len);
            sess->req.body_len += data_len;
            if (vhttp_http2_flow_replenish_rx(sess, frame->stream_id, data_len) != 0) {
                vhttp_http2_frame_free(frame);
                return -1;
            }
        }
        if (frame->flags & VHTTP_HTTP2_FLAG_END_STREAM) {
            (void)vhttp_http2_stream_state_on_remote_end(sess, frame->stream_id);
            sess->req.end_stream = 1u;
        }
        vhttp_http2_frame_free(frame);

        {
            int drc = vhttp_http2_try_dispatch_ready_req(sess, pending, served_any, short_idle_after_response);
            if (drc < 0) {
                return -1;
            }
        }
        return 0;
    }

    if (frame->type == VHTTP_HTTP2_FRAME_PRIORITY || frame->type == VHTTP_HTTP2_FRAME_PUSH_PROMISE) {
        (void)vhttp_http2_send_goaway(sess->sock, VHTTP_HTTP2_ERR_PROTOCOL);
        vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
        vhttp_http2_frame_free(frame);
        return -1;
    }

    vhttp_http2_frame_free(frame);
    return 0;
}

static int vhttp_http2_run_session(
    int sock,
    uint32_t client_ip,
    uint8_t *recv_buf,
    size_t recv_cap,
    size_t initial_buffered,
    uint8_t short_idle_after_response
) {
    if (!recv_buf || recv_cap == 0 || !vhttp_http2_enabled_runtime()) {
        return -1;
    }
    if (vhttp_http2_hpack_huff_prepare() != 0) {
        return -1;
    }
    vhttp_http2_session_t *sess_ptr = (vhttp_http2_session_t *)vhttp_http2_alloc_buf(sizeof(vhttp_http2_session_t), NULL);
    if (!sess_ptr) {
        return -1;
    }
    memset(sess_ptr, 0, sizeof(*sess_ptr));
#define sess (*sess_ptr)
    int ret = 0;
    sess.sock = sock;
    sess.client_ip = client_ip;
    sess.recv_buf = recv_buf;
    sess.recv_cap = recv_cap;
    sess.buffered = initial_buffered;
    sess.hpack_dyn_max_size = VHTTP_HTTP2_HPACK_TABLE_SIZE;
    vhttp_http2_session_dyn_reset(&sess);
    vhttp_http2_flow_init(&sess);
    vhttp_http2_req_reset(&sess.req);
    uint8_t served_any = 0;
    vhttp_http2_pending_ipc_t pending;
    memset(&pending, 0, sizeof(pending));
    uint32_t first_req_wait_ms = VHTTP_HTTP2_EVENT_LOOP_FIRST_REQ_WAIT_MS;
    if (first_req_wait_ms == 0) {
        first_req_wait_ms = VHTTP_HTTP2_RECV_SLICE_MS;
    }
    if (first_req_wait_ms == 0) {
        first_req_wait_ms = 1;
    }

    while (sess.buffered < VHTTP_HTTP2_PREFACE_LEN) {
        int rc = vhttp_recv_with_timeout(
            sess.sock,
            sess.recv_buf + sess.buffered,
            sess.recv_cap - sess.buffered,
            VHTTP_HTTP2_SESSION_IDLE_TIMEOUT_MS
        );
        if (rc <= 0) {
            ret = -1;
            goto h2_done;
        }
        sess.buffered += (size_t)rc;
    }
    if (!vhttp_http2_buffer_starts_with_preface(sess.recv_buf, sess.buffered)) {
        ret = -1;
        goto h2_done;
    }
    vhttp_stats_inc(&g_server_stats.http2_preface_seen);
    vhttp_http2_rx_consume(&sess, VHTTP_HTTP2_PREFACE_LEN);

    if (vhttp_http2_send_server_settings(&sess) != 0) {
        ret = -1;
        goto h2_done;
    }

    for (;;) {
        if (short_idle_after_response && pending.active) {
            uint32_t pending_stream_id = pending.stream_id;
            int prc = vhttp_http2_dispatch_request_async_poll(&sess, &pending);
            if (prc < 0) {
                vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
                vhttp_http2_pending_abort(&pending, ipc);
                if (pending_stream_id != 0) {
                    vhttp_http2_stream_state_on_rst(&sess, pending_stream_id);
                    vhttp_http2_slot_release(pending_stream_id);
                }
                break;
            }
            if (prc > 0) {
                served_any = 1;
                if (pending_stream_id != 0) {
                    (void)vhttp_http2_stream_state_on_local_end(&sess, pending_stream_id);
                    vhttp_http2_slot_release(pending_stream_id);
                }
                if (sess.req.active && sess.req.stream_id == pending_stream_id) {
                    vhttp_http2_req_clear_active(&sess);
                }
                {
                    int drc = vhttp_http2_try_dispatch_ready_req(&sess, &pending, &served_any, short_idle_after_response);
                    if (drc < 0) {
                        break;
                    }
                }
                continue;
            }
        }

        vhttp_http2_frame_t frame;
        uint32_t read_timeout_ms = VHTTP_HTTP2_SESSION_IDLE_TIMEOUT_MS;
        if (short_idle_after_response) {
            if (pending.active || (served_any && sess.buffered == 0)) {
                read_timeout_ms = VHTTP_HTTP2_RECV_SLICE_MS;
                if (read_timeout_ms == 0) {
                    read_timeout_ms = 1;
                }
            } else if (!served_any &&
                       sess.buffered == 0 &&
                       !sess.req.active &&
                       !sess.expect_continuation) {
                read_timeout_ms = first_req_wait_ms;
            }
        }
        int frc = vhttp_http2_read_frame(&sess, &frame, read_timeout_ms);
        if (frc == -2) {
            (void)vhttp_http2_send_goaway(sess.sock, VHTTP_HTTP2_ERR_FRAME_SIZE);
            vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
            ret = -1;
            goto h2_done;
        }
        if (frc == -3) {
            if (short_idle_after_response && pending.active) {
                continue;
            }
            break;
        }
        if (frc != 0) {
            break;
        }

        if (frame.type == VHTTP_HTTP2_FRAME_SETTINGS) {
            if (frame.stream_id != 0 || ((frame.flags & VHTTP_HTTP2_FLAG_ACK) && frame.payload_len != 0) || ((frame.payload_len % 6u) != 0u)) {
                (void)vhttp_http2_send_goaway(sess.sock, VHTTP_HTTP2_ERR_PROTOCOL);
                vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
                vhttp_http2_frame_free(&frame);
                break;
            }
            if ((frame.flags & VHTTP_HTTP2_FLAG_ACK) == 0) {
                for (uint32_t i = 0; i + 6u <= frame.payload_len; i += 6u) {
                    uint16_t setting_id = ((uint16_t)frame.payload[i] << 8) | (uint16_t)frame.payload[i + 1u];
                    uint32_t setting_val = ((uint32_t)frame.payload[i + 2u] << 24) |
                                           ((uint32_t)frame.payload[i + 3u] << 16) |
                                           ((uint32_t)frame.payload[i + 4u] << 8) |
                                           (uint32_t)frame.payload[i + 5u];
                    if (setting_id == VHTTP_HTTP2_SETTINGS_ENABLE_PUSH && setting_val > 1u) {
                        (void)vhttp_http2_send_goaway(sess.sock, VHTTP_HTTP2_ERR_PROTOCOL);
                        vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
                        vhttp_http2_frame_free(&frame);
                        goto h2_done;
                    }
                    if (setting_id == VHTTP_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE && setting_val > 0x7fffffffu) {
                        (void)vhttp_http2_send_goaway(sess.sock, VHTTP_HTTP2_ERR_FLOW_CONTROL);
                        vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
                        vhttp_http2_frame_free(&frame);
                        goto h2_done;
                    }
                    if (setting_id == VHTTP_HTTP2_SETTINGS_MAX_FRAME_SIZE &&
                        (setting_val < 16384u || setting_val > 16777215u)) {
                        (void)vhttp_http2_send_goaway(sess.sock, VHTTP_HTTP2_ERR_PROTOCOL);
                        vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
                        vhttp_http2_frame_free(&frame);
                        goto h2_done;
                    }
                }
                if (vhttp_http2_send_frame(sess.sock, VHTTP_HTTP2_FRAME_SETTINGS, VHTTP_HTTP2_FLAG_ACK, 0, NULL, 0) != 0) {
                    vhttp_http2_frame_free(&frame);
                    break;
                }
            }
            vhttp_http2_frame_free(&frame);
            continue;
        }

        if (frame.type == VHTTP_HTTP2_FRAME_PING) {
            if (frame.stream_id != 0 || frame.payload_len != 8) {
                (void)vhttp_http2_send_goaway(sess.sock, VHTTP_HTTP2_ERR_PROTOCOL);
                vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
                vhttp_http2_frame_free(&frame);
                break;
            }
            if ((frame.flags & VHTTP_HTTP2_FLAG_ACK) == 0) {
                if (vhttp_http2_send_frame(sess.sock, VHTTP_HTTP2_FRAME_PING, VHTTP_HTTP2_FLAG_ACK, 0, frame.payload, 8) != 0) {
                    vhttp_http2_frame_free(&frame);
                    break;
                }
            }
            vhttp_http2_frame_free(&frame);
            continue;
        }

        if (frame.type == VHTTP_HTTP2_FRAME_WINDOW_UPDATE) {
            if (frame.payload_len != 4) {
                (void)vhttp_http2_send_goaway(sess.sock, VHTTP_HTTP2_ERR_FRAME_SIZE);
                vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
                vhttp_http2_frame_free(&frame);
                break;
            }
            vhttp_http2_frame_free(&frame);
            continue;
        }

        if (frame.type == VHTTP_HTTP2_FRAME_GOAWAY) {
            vhttp_http2_frame_free(&frame);
            break;
        }

        if (frame.type == VHTTP_HTTP2_FRAME_RST_STREAM) {
            if (frame.payload_len == 4) {
                if (pending.active && pending.stream_id == frame.stream_id) {
                    vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
                    vhttp_http2_pending_abort(&pending, ipc);
                    vhttp_http2_slot_release(frame.stream_id);
                    if (sess.req.active && frame.stream_id == sess.req.stream_id) {
                        vhttp_http2_req_reset(&sess.req);
                        sess.expect_continuation = 0;
                        sess.continuation_stream_id = 0;
                    }
                } else if (sess.req.active && frame.stream_id == sess.req.stream_id) {
                    vhttp_http2_slot_release(sess.req.stream_id);
                    vhttp_http2_req_reset(&sess.req);
                    sess.expect_continuation = 0;
                    sess.continuation_stream_id = 0;
                }
            }
            vhttp_http2_frame_free(&frame);
            continue;
        }

        if (frame.type == VHTTP_HTTP2_FRAME_HEADERS) {
            if (frame.stream_id == 0) {
                (void)vhttp_http2_send_goaway(sess.sock, VHTTP_HTTP2_ERR_PROTOCOL);
                vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
                vhttp_http2_frame_free(&frame);
                break;
            }
            if (pending.active) {
                uint32_t err = (frame.stream_id == pending.stream_id)
                    ? VHTTP_HTTP2_ERR_STREAM_CLOSED
                    : VHTTP_HTTP2_ERR_REFUSED_STREAM;
                (void)vhttp_http2_send_rst_stream(sess.sock, frame.stream_id, err);
                vhttp_http2_frame_free(&frame);
                continue;
            }
            if ((frame.stream_id & 1u) == 0u) {
                (void)vhttp_http2_send_rst_stream(sess.sock, frame.stream_id, VHTTP_HTTP2_ERR_PROTOCOL);
                vhttp_http2_frame_free(&frame);
                continue;
            }
            if (sess.req.active && sess.req.stream_id != frame.stream_id) {
                (void)vhttp_http2_send_rst_stream(sess.sock, frame.stream_id, VHTTP_HTTP2_ERR_REFUSED_STREAM);
                vhttp_http2_frame_free(&frame);
                continue;
            }
            if (!sess.req.active) {
                if (vhttp_http2_slot_acquire(frame.stream_id) != 0) {
                    (void)vhttp_http2_send_rst_stream(sess.sock, frame.stream_id, VHTTP_HTTP2_ERR_REFUSED_STREAM);
                    vhttp_http2_frame_free(&frame);
                    continue;
                }
                vhttp_http2_req_reset(&sess.req);
                sess.req.active = 1u;
                sess.req.stream_id = frame.stream_id;
            }

            size_t off = 0;
            if (frame.flags & VHTTP_HTTP2_FLAG_PADDED) {
                if (frame.payload_len == 0) {
                    vhttp_http2_frame_free(&frame);
                    break;
                }
                uint8_t pad = frame.payload[off++];
                if ((uint32_t)off + (uint32_t)pad > frame.payload_len) {
                    (void)vhttp_http2_send_rst_stream(sess.sock, frame.stream_id, VHTTP_HTTP2_ERR_PROTOCOL);
                    vhttp_http2_frame_free(&frame);
                    continue;
                }
                frame.payload_len -= pad;
            }
            if (frame.flags & VHTTP_HTTP2_FLAG_PRIORITY) {
                if ((uint32_t)off + 5u > frame.payload_len) {
                    (void)vhttp_http2_send_rst_stream(sess.sock, frame.stream_id, VHTTP_HTTP2_ERR_FRAME_SIZE);
                    vhttp_http2_frame_free(&frame);
                    continue;
                }
                off += 5u;
            }
            size_t frag_len = frame.payload_len >= (uint32_t)off ? (size_t)(frame.payload_len - (uint32_t)off) : 0;
            uint32_t need = sess.req.header_block_len + (uint32_t)frag_len;
            if (vhttp_http2_req_ensure_header_block(&sess.req, need) != 0) {
                (void)vhttp_http2_send_rst_stream(sess.sock, frame.stream_id, VHTTP_HTTP2_ERR_COMPRESSION);
                vhttp_http2_frame_free(&frame);
                continue;
            }
            if (frag_len > 0) {
                memcpy(sess.req.header_block + sess.req.header_block_len, frame.payload + off, frag_len);
                sess.req.header_block_len += (uint32_t)frag_len;
            }
            if (frame.flags & VHTTP_HTTP2_FLAG_END_HEADERS) {
                if (vhttp_http2_hpack_decode_headers(&sess, &sess.req) != 0) {
                    (void)vhttp_http2_send_rst_stream(sess.sock, frame.stream_id, VHTTP_HTTP2_ERR_COMPRESSION);
                    vhttp_http2_frame_free(&frame);
                    vhttp_http2_slot_release(sess.req.stream_id);
                    vhttp_http2_req_reset(&sess.req);
                    sess.expect_continuation = 0;
                    sess.continuation_stream_id = 0;
                    continue;
                }
                sess.expect_continuation = 0;
                sess.continuation_stream_id = 0;
            } else {
                sess.expect_continuation = 1u;
                sess.continuation_stream_id = frame.stream_id;
            }
            if (frame.flags & VHTTP_HTTP2_FLAG_END_STREAM) {
                sess.req.end_stream = 1u;
            }
            vhttp_http2_frame_free(&frame);

            if (sess.req.active && sess.req.headers_complete && sess.req.end_stream) {
                if (short_idle_after_response) {
                    int src = vhttp_http2_dispatch_request_async_start(&sess, &sess.req, &pending);
                    if (src < 0) {
                        break;
                    }
                    if (src == 0) {
                        vhttp_http2_req_reset(&sess.req);
                        sess.expect_continuation = 0;
                        sess.continuation_stream_id = 0;
                    }
                    if (src > 0) {
                        served_any = 1;
                        vhttp_http2_slot_release(sess.req.stream_id);
                        vhttp_http2_req_reset(&sess.req);
                        sess.expect_continuation = 0;
                        sess.continuation_stream_id = 0;
                    }
                } else {
                    int drc = vhttp_http2_dispatch_request(&sess, &sess.req);
                    if (drc == 0) {
                        served_any = 1;
                    }
                    vhttp_http2_slot_release(sess.req.stream_id);
                    vhttp_http2_req_reset(&sess.req);
                    sess.expect_continuation = 0;
                    sess.continuation_stream_id = 0;
                    if (drc != 0) {
                        break;
                    }
                }
            }
            continue;
        }

        if (frame.type == VHTTP_HTTP2_FRAME_CONTINUATION) {
            if (!sess.expect_continuation || frame.stream_id != sess.continuation_stream_id || !sess.req.active) {
                (void)vhttp_http2_send_goaway(sess.sock, VHTTP_HTTP2_ERR_PROTOCOL);
                vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
                vhttp_http2_frame_free(&frame);
                break;
            }
            uint32_t need = sess.req.header_block_len + frame.payload_len;
            if (vhttp_http2_req_ensure_header_block(&sess.req, need) != 0) {
                (void)vhttp_http2_send_rst_stream(sess.sock, frame.stream_id, VHTTP_HTTP2_ERR_COMPRESSION);
                vhttp_http2_frame_free(&frame);
                break;
            }
            if (frame.payload_len > 0) {
                memcpy(sess.req.header_block + sess.req.header_block_len, frame.payload, frame.payload_len);
                sess.req.header_block_len += frame.payload_len;
            }
            if (frame.flags & VHTTP_HTTP2_FLAG_END_HEADERS) {
                if (vhttp_http2_hpack_decode_headers(&sess, &sess.req) != 0) {
                    (void)vhttp_http2_send_rst_stream(sess.sock, frame.stream_id, VHTTP_HTTP2_ERR_COMPRESSION);
                    vhttp_http2_frame_free(&frame);
                    vhttp_http2_slot_release(sess.req.stream_id);
                    vhttp_http2_req_reset(&sess.req);
                    sess.expect_continuation = 0;
                    sess.continuation_stream_id = 0;
                    continue;
                }
                sess.expect_continuation = 0;
                sess.continuation_stream_id = 0;
            }
            vhttp_http2_frame_free(&frame);

            if (sess.req.active && sess.req.headers_complete && sess.req.end_stream) {
                if (short_idle_after_response) {
                    int src = vhttp_http2_dispatch_request_async_start(&sess, &sess.req, &pending);
                    if (src < 0) {
                        break;
                    }
                    if (src == 0) {
                        vhttp_http2_req_reset(&sess.req);
                        sess.expect_continuation = 0;
                        sess.continuation_stream_id = 0;
                    }
                    if (src > 0) {
                        served_any = 1;
                        vhttp_http2_slot_release(sess.req.stream_id);
                        vhttp_http2_req_reset(&sess.req);
                    }
                } else {
                    int drc = vhttp_http2_dispatch_request(&sess, &sess.req);
                    if (drc == 0) {
                        served_any = 1;
                    }
                    vhttp_http2_slot_release(sess.req.stream_id);
                    vhttp_http2_req_reset(&sess.req);
                    if (drc != 0) {
                        break;
                    }
                }
            }
            continue;
        }

        if (frame.type == VHTTP_HTTP2_FRAME_DATA) {
            if (frame.stream_id == 0 || !sess.req.active || frame.stream_id != sess.req.stream_id) {
                if (frame.stream_id != 0) {
                    (void)vhttp_http2_send_rst_stream(sess.sock, frame.stream_id, VHTTP_HTTP2_ERR_STREAM_CLOSED);
                } else {
                    (void)vhttp_http2_send_goaway(sess.sock, VHTTP_HTTP2_ERR_PROTOCOL);
                    vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
                }
                vhttp_http2_frame_free(&frame);
                if (frame.stream_id == 0) {
                    break;
                }
                continue;
            }
            if (!sess.req.headers_complete || sess.expect_continuation) {
                (void)vhttp_http2_send_rst_stream(sess.sock, frame.stream_id, VHTTP_HTTP2_ERR_PROTOCOL);
                vhttp_http2_frame_free(&frame);
                vhttp_http2_slot_release(sess.req.stream_id);
                vhttp_http2_req_reset(&sess.req);
                sess.expect_continuation = 0;
                sess.continuation_stream_id = 0;
                continue;
            }

            size_t off = 0;
            if (frame.flags & VHTTP_HTTP2_FLAG_PADDED) {
                if (frame.payload_len == 0) {
                    vhttp_http2_frame_free(&frame);
                    break;
                }
                uint8_t pad = frame.payload[off++];
                if ((uint32_t)off + (uint32_t)pad > frame.payload_len) {
                    (void)vhttp_http2_send_rst_stream(sess.sock, frame.stream_id, VHTTP_HTTP2_ERR_PROTOCOL);
                    vhttp_http2_frame_free(&frame);
                    continue;
                }
                frame.payload_len -= pad;
            }
            uint32_t data_len = frame.payload_len >= (uint32_t)off ? (frame.payload_len - (uint32_t)off) : 0;
            if (data_len > 0) {
                uint32_t need = sess.req.body_len + data_len;
                if (vhttp_http2_req_ensure_body(&sess.req, need) != 0) {
                    (void)vhttp_http2_send_rst_stream(sess.sock, frame.stream_id, VHTTP_HTTP2_ERR_FLOW_CONTROL);
                    vhttp_http2_frame_free(&frame);
                    vhttp_http2_slot_release(sess.req.stream_id);
                    vhttp_http2_req_reset(&sess.req);
                    sess.expect_continuation = 0;
                    sess.continuation_stream_id = 0;
                    continue;
                }
                memcpy(sess.req.body + sess.req.body_len, frame.payload + off, data_len);
                sess.req.body_len += data_len;
            }
            if (frame.flags & VHTTP_HTTP2_FLAG_END_STREAM) {
                sess.req.end_stream = 1u;
            }
            vhttp_http2_frame_free(&frame);

            if (sess.req.active && sess.req.headers_complete && sess.req.end_stream) {
                if (short_idle_after_response) {
                    int src = vhttp_http2_dispatch_request_async_start(&sess, &sess.req, &pending);
                    if (src < 0) {
                        break;
                    }
                    if (src == 0) {
                        vhttp_http2_req_reset(&sess.req);
                        sess.expect_continuation = 0;
                        sess.continuation_stream_id = 0;
                    }
                    if (src > 0) {
                        served_any = 1;
                        vhttp_http2_slot_release(sess.req.stream_id);
                        vhttp_http2_req_reset(&sess.req);
                        sess.expect_continuation = 0;
                        sess.continuation_stream_id = 0;
                    }
                } else {
                    int drc = vhttp_http2_dispatch_request(&sess, &sess.req);
                    if (drc == 0) {
                        served_any = 1;
                    }
                    vhttp_http2_slot_release(sess.req.stream_id);
                    vhttp_http2_req_reset(&sess.req);
                    sess.expect_continuation = 0;
                    sess.continuation_stream_id = 0;
                    if (drc != 0) {
                        break;
                    }
                }
            }
            continue;
        }

        if (frame.type == VHTTP_HTTP2_FRAME_PRIORITY || frame.type == VHTTP_HTTP2_FRAME_PUSH_PROMISE) {
            (void)vhttp_http2_send_goaway(sess.sock, VHTTP_HTTP2_ERR_PROTOCOL);
            vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
            vhttp_http2_frame_free(&frame);
            break;
        }

        vhttp_http2_frame_free(&frame);
    }

h2_done:
    if (pending.active) {
        vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
        uint32_t stream_id = pending.stream_id;
        vhttp_http2_pending_abort(&pending, ipc);
        if (stream_id != 0) {
            vhttp_http2_slot_release(stream_id);
        }
    }
    if (sess.req.active) {
        vhttp_http2_slot_release(sess.req.stream_id);
    }
    vhttp_http2_buffered_req_release_all(&sess, 1u);
    vhttp_http2_req_free(&sess.req);
    vhttp_http2_session_dyn_reset(&sess);
    heap_caps_free(sess_ptr);
#undef sess
    return ret;
}

static void vhttp_http2_task_ctx_free(vhttp_http2_task_ctx_t *ctx) {
    if (!ctx) {
        return;
    }
    heap_caps_free(ctx);
}

static void vhttp_http2_connection_task(void *arg) {
    vhttp_http2_task_ctx_t *ctx = (vhttp_http2_task_ctx_t *)arg;
    if (!ctx) {
        vTaskDelete(NULL);
        return;
    }
    (void)vhttp_http2_run_session(ctx->sock, ctx->client_ip, ctx->recv_buf, ctx->recv_cap, ctx->recv_len, 0u);
    shutdown(ctx->sock, SHUT_RDWR);
    vhttp_https_close_socket_if_open(ctx->sock);
    close(ctx->sock);
    vhttp_ev_conn_on_closed(ctx->sock);
    vhttp_http2_task_ctx_free(ctx);
    vTaskDelete(NULL);
}

static int vhttp_spawn_http2_task(
    int sock,
    uint32_t client_ip,
    const uint8_t *recv_buf,
    uint32_t recv_len,
    uint32_t recv_cap
) {
    if ((!recv_buf && recv_len > 0u) || recv_cap < recv_len) {
        return -1;
    }
    if (recv_cap < (uint32_t)VHTTP_RECV_BUF_SIZE) {
        recv_cap = (uint32_t)VHTTP_RECV_BUF_SIZE;
    }
    size_t total = sizeof(vhttp_http2_task_ctx_t) + (size_t)recv_cap;
    vhttp_http2_task_ctx_t *ctx = (vhttp_http2_task_ctx_t *)vhttp_http2_alloc_buf(total, NULL);
    if (!ctx) {
        return -1;
    }
    ctx->sock = sock;
    ctx->client_ip = client_ip;
    ctx->recv_len = recv_len;
    ctx->recv_cap = recv_cap;
    if (recv_len > 0 && recv_buf) {
        memcpy(ctx->recv_buf, recv_buf, recv_len);
    }

    BaseType_t ok = pdFAIL;
#if defined(MALLOC_CAP_SPIRAM)
    ok = xTaskCreatePinnedToCoreWithCaps(
        vhttp_http2_connection_task,
        "vhttp_h2",
        VHTTP_SERVER_HTTP2_TASK_STACK_SIZE,
        ctx,
        VHTTP_SERVER_TASK_PRIO,
        NULL,
        0,
        MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT
    );
#endif
    if (ok != pdPASS) {
        ok = xTaskCreatePinnedToCore(
            vhttp_http2_connection_task,
            "vhttp_h2",
            VHTTP_SERVER_HTTP2_TASK_STACK_SIZE,
            ctx,
            VHTTP_SERVER_TASK_PRIO,
            NULL,
            0
        );
    }
    if (ok != pdPASS) {
        VHTTP_LOGW("http2 task create failed stack=%u free=%u", (unsigned int)VHTTP_SERVER_HTTP2_TASK_STACK_SIZE, (unsigned int)xPortGetFreeHeapSize());
        vhttp_http2_task_ctx_free(ctx);
        return -1;
    }
    vhttp_stats_inc(&g_server_stats.http2_task_fallback_used);
    return 0;
}

static int send_simple_response(int sock, int status, const char *body, int keep_alive, const char *extra_headers) {
    if (!body) {
        body = "";
    }
    if (!extra_headers) {
        extra_headers = "";
    }
    char header[VHTTP_HEADER_BUF_SIZE];
    size_t body_len = strlen(body);
    unsigned int body_len_u = (body_len > UINT_MAX) ? UINT_MAX : (unsigned int)body_len;
    const char *conn = keep_alive ? "keep-alive" : "close";
    int header_len = snprintf(
        header,
        sizeof(header),
        "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %u\r\n%sConnection: %s\r\n\r\n",
        status,
        status_reason(status),
        body_len_u,
        extra_headers,
        conn
    );
    if (header_len < 0 || (size_t)header_len >= sizeof(header)) {
        return -1;
    }
    if (send_all(sock, (const uint8_t *)header, (size_t)header_len) != 0) {
        return -1;
    }
    if (body_len > 0) {
        if (send_all(sock, (const uint8_t *)body, body_len) != 0) {
            return -1;
        }
    }
    VHTTP_LOGD("simple status=%d keep=%d", status, keep_alive ? 1 : 0);
    return 0;
}

static int send_chunked_payload(int sock, const uint8_t *body, uint32_t len) {
    char chunk_hdr[16];
    int hdr_len = snprintf(chunk_hdr, sizeof(chunk_hdr), "%x\r\n", (unsigned int)len);
    if (hdr_len < 0 || (size_t)hdr_len >= sizeof(chunk_hdr)) {
        return -1;
    }
    if (send_all(sock, (const uint8_t *)chunk_hdr, (size_t)hdr_len) != 0) {
        return -1;
    }
    if (len > 0) {
        if (send_all(sock, body, len) != 0) {
            return -1;
        }
    }
    if (send_all(sock, (const uint8_t *)"\r\n", 2) != 0) {
        return -1;
    }
    return 0;
}

static uint32_t vhttp_now_ms(void) {
    return (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
}

static int ws_trim_value(const char **ptr, size_t *len) {
    if (!ptr || !*ptr || !len) {
        return -1;
    }
    while (*len > 0 && (**ptr == ' ' || **ptr == '\t' || **ptr == '\r' || **ptr == '\n')) {
        (*ptr)++;
        (*len)--;
    }
    while (*len > 0) {
        char c = (*ptr)[*len - 1];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
            break;
        }
        (*len)--;
    }
    return 0;
}

static int ws_value_equals(const vhttp_header_t *hdr, const char *value) {
    if (!hdr || !value) {
        return 0;
    }
    const char *ptr = hdr->value;
    size_t len = hdr->value_len;
    ws_trim_value(&ptr, &len);
    return slice_ci_equals_n(ptr, len, value);
}

static int ws_compute_accept_key(const char *key, size_t key_len, char *out, size_t out_len, size_t *out_used) {
    static const char *ws_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    static const size_t ws_guid_len = 36;
    if (!key || key_len == 0 || !out || out_len == 0) {
        return -1;
    }
    if (key_len > 64) {
        return -1;
    }

    uint8_t sha_input[128];
    size_t total_len = key_len + ws_guid_len;
    if (total_len > sizeof(sha_input)) {
        return -1;
    }
    memcpy(sha_input, key, key_len);
    memcpy(sha_input + key_len, ws_guid, ws_guid_len);

    uint8_t sha_out[20];
    if (mbedtls_sha1(sha_input, total_len, sha_out) != 0) {
        return -1;
    }

    size_t base64_len = 0;
    if (mbedtls_base64_encode((unsigned char *)out, out_len, &base64_len, sha_out, sizeof(sha_out)) != 0) {
        return -1;
    }
    if (out_used) {
        *out_used = base64_len;
    }
    return 0;
}

static int ws_send_raw_response(int sock, int status, const uint8_t *body, size_t body_len, const char *extra_headers) {
    char header[VHTTP_HEADER_BUF_SIZE];
    const char *headers = extra_headers ? extra_headers : "";
    int header_len = snprintf(
        header,
        sizeof(header),
        "HTTP/1.1 %d %s\r\nContent-Length: %u\r\nContent-Type: text/plain; charset=utf-8\r\n%.*sConnection: close\r\n\r\n",
        status,
        status_reason(status),
        (unsigned int)body_len,
        (int)strlen(headers),
        headers
    );
    if (header_len < 0 || (size_t)header_len >= sizeof(header)) {
        return -1;
    }
    if (send_all(sock, (const uint8_t *)header, (size_t)header_len) != 0) {
        return -1;
    }
    if (body_len > 0 && body) {
        if (send_all(sock, body, body_len) != 0) {
            return -1;
        }
    }
    return 0;
}

static int ws_send_handshake(int sock, const char *accept_key, size_t accept_len, const char *subprotocol, size_t subproto_len) {
    char header[VHTTP_HEADER_BUF_SIZE];
    int header_len = 0;
    if (subprotocol && subproto_len > 0) {
        header_len = snprintf(
            header,
            sizeof(header),
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %.*s\r\nSec-WebSocket-Protocol: %.*s\r\n\r\n",
            (int)accept_len,
            accept_key,
            (int)subproto_len,
            subprotocol
        );
    } else {
        header_len = snprintf(
            header,
            sizeof(header),
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %.*s\r\n\r\n",
            (int)accept_len,
            accept_key
        );
    }
    if (header_len < 0 || (size_t)header_len >= sizeof(header)) {
        return -1;
    }
    return send_all(sock, (const uint8_t *)header, (size_t)header_len);
}

static int ws_send_frame(int sock, uint8_t opcode, const uint8_t *payload, size_t payload_len, int fin) {
    uint8_t header[14];
    size_t header_len = 0;
    uint8_t b0 = (uint8_t)((fin ? 0x80 : 0x00) | (opcode & 0x0f));
    header[0] = b0;
    if (payload_len <= 125) {
        header[1] = (uint8_t)payload_len;
        header_len = 2;
    } else if (payload_len <= 65535) {
        header[1] = 126;
        header[2] = (uint8_t)((payload_len >> 8) & 0xff);
        header[3] = (uint8_t)(payload_len & 0xff);
        header_len = 4;
    } else {
        header[1] = 127;
        uint64_t len64 = (uint64_t)payload_len;
        header[2] = (uint8_t)((len64 >> 56) & 0xff);
        header[3] = (uint8_t)((len64 >> 48) & 0xff);
        header[4] = (uint8_t)((len64 >> 40) & 0xff);
        header[5] = (uint8_t)((len64 >> 32) & 0xff);
        header[6] = (uint8_t)((len64 >> 24) & 0xff);
        header[7] = (uint8_t)((len64 >> 16) & 0xff);
        header[8] = (uint8_t)((len64 >> 8) & 0xff);
        header[9] = (uint8_t)(len64 & 0xff);
        header_len = 10;
    }

    if (send_all(sock, header, header_len) != 0) {
        return -1;
    }
    if (payload_len > 0 && payload) {
        if (send_all(sock, payload, payload_len) != 0) {
            return -1;
        }
    }
    return 0;
}

static void ws_unmask(uint8_t *data, size_t len, const uint8_t *mask_key) {
    if (!data || !mask_key || len == 0) {
        return;
    }
    for (size_t i = 0; i < len; ++i) {
        data[i] ^= mask_key[i & 0x03];
    }
}

static int ws_validate_utf8(const uint8_t *data, size_t len) {
    size_t i = 0;
    while (i < len) {
        uint8_t c = data[i];
        if (c <= 0x7f) {
            i++;
            continue;
        }
        if ((c & 0xe0) == 0xc0) {
            if (i + 1 >= len) return -1;
            if ((data[i + 1] & 0xc0) != 0x80) return -1;
            i += 2;
            continue;
        }
        if ((c & 0xf0) == 0xe0) {
            if (i + 2 >= len) return -1;
            if ((data[i + 1] & 0xc0) != 0x80 || (data[i + 2] & 0xc0) != 0x80) return -1;
            i += 3;
            continue;
        }
        if ((c & 0xf8) == 0xf0) {
            if (i + 3 >= len) return -1;
            if ((data[i + 1] & 0xc0) != 0x80 || (data[i + 2] & 0xc0) != 0x80 ||
                (data[i + 3] & 0xc0) != 0x80) return -1;
            i += 4;
            continue;
        }
        return -1;
    }
    return 0;
}

static const vhttp_header_t *find_header(const vhttp_parsed_request_t *req, const char *name) {
    if (!req || !name) {
        return NULL;
    }
    for (uint8_t i = 0; i < req->num_headers; ++i) {
        const vhttp_header_t *hdr = &req->headers[i];
        if (slice_ci_equals_n(hdr->name, hdr->name_len, name)) {
            return hdr;
        }
    }
    return NULL;
}

#if !VHTTP_STATIC_SERVE_VIA_IPC
static void etag_normalize(const char *in, size_t len, const char **out, size_t *out_len) {
    const char *ptr = in;
    size_t l = len;
    if (l >= 2 && ptr[0] == 'W' && ptr[1] == '/') {
        ptr += 2;
        l -= 2;
    }
    if (l >= 2 && ptr[0] == '"' && ptr[l - 1] == '"') {
        ptr += 1;
        l -= 2;
    }
    *out = ptr;
    *out_len = l;
}

static int etag_matches(const vhttp_parsed_request_t *req, const char *etag, size_t etag_len) {
    const vhttp_header_t *hdr = find_header(req, "if-none-match");
    if (!hdr || !etag || etag_len == 0) {
        return 0;
    }

    const char *etag_base = NULL;
    size_t etag_base_len = 0;
    etag_normalize(etag, etag_len, &etag_base, &etag_base_len);
    if (!etag_base || etag_base_len == 0) {
        return 0;
    }

    const char *p = hdr->value;
    size_t len = hdr->value_len;
    size_t i = 0;

    // Special case: "*" matches any current representation.
    for (; i < len; ++i) {
        if (p[i] != ' ' && p[i] != '\t') {
            break;
        }
    }
    if (i < len && p[i] == '*') {
        return 1;
    }

    while (i < len) {
        while (i < len && (p[i] == ' ' || p[i] == '\t' || p[i] == ',')) {
            i++;
        }
        size_t start = i;
        while (i < len && p[i] != ',') {
            i++;
        }
        size_t end = i;

        while (end > start && (p[end - 1] == ' ' || p[end - 1] == '\t')) {
            end--;
        }

        if (end == start) {
            continue;
        }

        size_t token_len = end - start;
        const char *token_base = NULL;
        size_t token_base_len = 0;
        etag_normalize(p + start, token_len, &token_base, &token_base_len);

        if (token_base_len == etag_base_len &&
            memcmp(token_base, etag_base, etag_base_len) == 0) {
            return 1;
        }
    }
    return 0;
}
#endif

static int ws_is_upgrade_request(const vhttp_parsed_request_t *req) {
    if (!req) {
        return 0;
    }
    if (!header_value_contains(req, "upgrade", "websocket")) {
        return 0;
    }
    if (!header_value_contains(req, "connection", "upgrade")) {
        return 0;
    }
    return 1;
}

static int vhttp_http2_h2c_upgrade_requested(const vhttp_parsed_request_t *req) {
    if (!req) {
        return 0;
    }
    if (!header_value_contains(req, "upgrade", "h2c")) {
        return 0;
    }
    if (!header_value_contains(req, "connection", "upgrade")) {
        return 0;
    }
    if (!header_value_contains(req, "connection", "http2-settings")) {
        return 0;
    }
    const vhttp_header_t *settings = find_header(req, "http2-settings");
    if (!settings || settings->value_len == 0) {
        return 0;
    }
    return 1;
}

static int vhttp_http2_h2c_validate_settings(const vhttp_parsed_request_t *req) {
    const vhttp_header_t *settings = find_header(req, "http2-settings");
    if (!settings || settings->value_len == 0) {
        return -1;
    }
    if (settings->value_len > 512) {
        return -1;
    }

    char b64_buf[768];
    size_t in_len = 0;
    for (uint16_t i = 0; i < settings->value_len; ++i) {
        char ch = settings->value[i];
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
            continue;
        }
        if (ch == '-') {
            ch = '+';
        } else if (ch == '_') {
            ch = '/';
        }
        if (in_len >= sizeof(b64_buf) - 4u) {
            return -1;
        }
        b64_buf[in_len++] = ch;
    }
    if (in_len == 0) {
        return -1;
    }
    while ((in_len % 4u) != 0u) {
        b64_buf[in_len++] = '=';
    }

    uint8_t decoded[256];
    size_t decoded_len = 0;
    int rc = mbedtls_base64_decode(decoded, sizeof(decoded), &decoded_len, (const unsigned char *)b64_buf, in_len);
    if (rc != 0) {
        return -1;
    }
    if ((decoded_len % 6u) != 0u) {
        return -1;
    }
    return 0;
}

static int vhttp_http2_try_h2c_upgrade(
    int sock,
    uint32_t client_ip,
    uint8_t *recv_buf,
    size_t recv_cap,
    size_t buffered,
    const vhttp_parsed_request_t *req,
    uint8_t prefer_handoff,
    uint8_t short_idle_after_response
) {
    if (!req || !recv_buf || recv_cap == 0 || !vhttp_http2_enabled_runtime()) {
        return 0;
    }
    if (!vhttp_http2_h2c_upgrade_requested(req)) {
        return 0;
    }
    if (vhttp_http2_h2c_validate_settings(req) != 0) {
        (void)send_simple_response(sock, 400, "Bad Request", 0, NULL);
        return -1;
    }

    static const char upgrade_resp[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: h2c\r\n\r\n";
    if (send_all(sock, (const uint8_t *)upgrade_resp, sizeof(upgrade_resp) - 1u) != 0) {
        return -1;
    }

    size_t consumed = req->total_len;
    size_t remaining = 0;
    if (buffered > consumed) {
        remaining = buffered - consumed;
        memmove(recv_buf, recv_buf + consumed, remaining);
    }
    if (prefer_handoff) {
        if (vhttp_spawn_http2_task(sock, client_ip, recv_buf, (uint32_t)remaining, (uint32_t)recv_cap) == 0) {
            return 2;
        }
    }
    (void)vhttp_http2_run_session(sock, client_ip, recv_buf, recv_cap, remaining, short_idle_after_response);
    return 1;
}

static uint8_t *ws_alloc_buf(size_t size) {
#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
    uint8_t *buf = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!buf) {
        buf = heap_caps_malloc(size, MALLOC_CAP_8BIT);
    }
    return buf;
#else
    return (uint8_t *)malloc(size);
#endif
}

static uint8_t *ws_alloc_frag_buf(void) {
    return ws_alloc_buf(VHTTP_WS_MAX_MESSAGE_SIZE);
}

static void ws_free_buf(uint8_t *buf) {
    if (!buf) {
        return;
    }
#if defined(ESP_PLATFORM) || defined(VHTTP_ESP_PLATFORM)
    heap_caps_free(buf);
#else
    free(buf);
#endif
}

static int ws_send_ipc_message(vhttp_ipc_state_t *ipc, uint32_t conn_id, uint8_t opcode, const uint8_t *payload, size_t payload_len, int fin) {
    if (!ipc) {
        return -1;
    }

    uint32_t offset = 0;
    uint8_t *dst = NULL;
    if (payload_len > 0) {
        if (vhttp_ipc_ring_alloc(&ipc->ring, (uint32_t)payload_len, &offset, &dst) != 0) {
            return -1;
        }
        memcpy(dst, payload, payload_len);
    }

    vhttp_ipc_msg_t msg = {0};
    msg.request_id = conn_id;
    msg.type = VHTTP_IPC_REQ_WS_MSG;
    msg.method = opcode;
    msg.body_len = (uint32_t)payload_len;
    msg.buffer_offset = payload_len > 0 ? offset : 0;
    msg.flags = (uint8_t)(VHTTP_IPC_FLAG_RELEASE | (fin ? VHTTP_IPC_FLAG_FINAL : 0));

    if (vhttp_ipc_queue_push(&ipc->request_queue, &msg) != 0) {
        if (payload_len > 0) {
            vhttp_ipc_ring_release(&ipc->ring, (uint32_t)payload_len);
        }
        return -1;
    }
    return 0;
}

static void ws_send_disconnect_ipc(vhttp_ipc_state_t *ipc, uint32_t conn_id, uint16_t code) {
    if (!ipc) {
        return;
    }
    vhttp_ipc_msg_t msg = {0};
    msg.request_id = conn_id;
    msg.type = VHTTP_IPC_REQ_WS_DISCONNECT;
    msg.status_code = code;
    (void)vhttp_ipc_queue_push(&ipc->request_queue, &msg);
}

static int ws_run_loop(int sock, vhttp_ipc_state_t *ipc, uint32_t conn_id) {
    size_t rx_cap = VHTTP_WS_MAX_FRAME_SIZE + 16;
    uint8_t *rx_buf = ws_alloc_buf(rx_cap);
    size_t rx_len = 0;
    uint8_t *frag_buf = NULL;
    size_t frag_len = 0;
    uint8_t frag_opcode = 0;
    int frag_active = 0;

    uint32_t last_ping = vhttp_now_ms();
    int awaiting_pong = 0;
    int running = 1;
    uint16_t close_code = 1000;

    if (!rx_buf) {
        ws_send_disconnect_ipc(ipc, conn_id, 1011);
        return 0;
    }

    while (running && g_server_running) {
        uint32_t ipc_burst = 0;
        vhttp_ipc_msg_t resp;
        while (vhttp_ipc_try_response_for(ipc, conn_id, &resp) == 0) {
            if (resp.type == VHTTP_IPC_RESP_WS_MSG) {
                const uint8_t *payload = NULL;
                if (resp.body_len > 0) {
                    payload = vhttp_ipc_ring_ptr(&ipc->ring, resp.buffer_offset);
                    if (!payload) {
                        if (resp.body_len > 0) {
                            vhttp_ipc_ring_release(&ipc->ring, resp.body_len);
                        }
                        close_code = 1011;
                        running = 0;
                        break;
                    }
                }
                int fin = (resp.flags & VHTTP_IPC_FLAG_FINAL) != 0;
                if (ws_send_frame(sock, resp.method, payload, resp.body_len, fin) != 0) {
                    if (resp.body_len > 0) {
                        vhttp_ipc_ring_release(&ipc->ring, resp.body_len);
                    }
                    close_code = 1006;
                    running = 0;
                    break;
                }
                if (resp.body_len > 0) {
                    vhttp_ipc_ring_release(&ipc->ring, resp.body_len);
                }
            } else if (resp.type == VHTTP_IPC_RESP_WS_CLOSE) {
                const uint8_t *payload = NULL;
                if (resp.body_len > 0) {
                    payload = vhttp_ipc_ring_ptr(&ipc->ring, resp.buffer_offset);
                }
                if (payload) {
                    (void)ws_send_frame(sock, 0x8, payload, resp.body_len, 1);
                    vhttp_ipc_ring_release(&ipc->ring, resp.body_len);
                } else {
                    uint8_t close_payload[2] = {
                        (uint8_t)((resp.status_code >> 8) & 0xff),
                        (uint8_t)(resp.status_code & 0xff),
                    };
                    (void)ws_send_frame(sock, 0x8, close_payload, sizeof(close_payload), 1);
                }
                close_code = resp.status_code ? resp.status_code : 1000;
                running = 0;
                break;
            } else {
                vhttp_ipc_release_response_payload(ipc, &resp);
            }

            ipc_burst++;
            if (ipc_burst >= VHTTP_WS_FAIR_IPC_BUDGET) {
                vhttp_stats_inc(&g_server_stats.scheduler_yields);
                taskYIELD();
                ipc_burst = 0;
                break;
            }
        }

        if (!running) {
            break;
        }

        if (rx_len >= rx_cap) {
            close_code = 1009;
            break;
        }

        int r = vhttp_sock_recv(sock, rx_buf + rx_len, rx_cap - rx_len);
        if (r > 0) {
            rx_len += (size_t)r;
        } else if (r == 0) {
            close_code = 1006;
            break;
        } else {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                close_code = 1006;
                break;
            }
        }

        size_t offset = 0;
        uint32_t rx_frame_burst = 0;
        while (rx_len - offset >= 2) {
            uint8_t b0 = rx_buf[offset];
            uint8_t b1 = rx_buf[offset + 1];
            uint8_t opcode = (uint8_t)(b0 & 0x0f);
            int fin = (b0 & 0x80) != 0;
            int masked = (b1 & 0x80) != 0;
            size_t payload_len = (size_t)(b1 & 0x7f);
            size_t header_len = 2;

            if ((b0 & 0x70) != 0) {
                close_code = 1002;
                running = 0;
                break;
            }
            if (!masked) {
                close_code = 1002;
                running = 0;
                break;
            }

            if (payload_len == 126) {
                if (rx_len - offset < 4) {
                    break;
                }
                payload_len = ((size_t)rx_buf[offset + 2] << 8) | rx_buf[offset + 3];
                header_len = 4;
            } else if (payload_len == 127) {
                if (rx_len - offset < 10) {
                    break;
                }
                uint64_t len64 = 0;
                for (int i = 0; i < 8; ++i) {
                    len64 = (len64 << 8) | rx_buf[offset + 2 + i];
                }
                if (len64 > 0xffffffffu) {
                    close_code = 1009;
                    running = 0;
                    break;
                }
                payload_len = (size_t)len64;
                header_len = 10;
            }

            if (payload_len > VHTTP_WS_MAX_FRAME_SIZE) {
                close_code = 1009;
                running = 0;
                break;
            }

            if (rx_len - offset < header_len + 4) {
                break;
            }
            const uint8_t *mask_key = rx_buf + offset + header_len;
            header_len += 4;

            if (rx_len - offset < header_len + payload_len) {
                break;
            }

            uint8_t *payload = rx_buf + offset + header_len;
            if (payload_len > 0) {
                ws_unmask(payload, payload_len, mask_key);
            }

            if (opcode == 0x8) {
                uint16_t code = 1000;
                if (payload_len >= 2) {
                    code = ((uint16_t)payload[0] << 8) | payload[1];
                }
                (void)ws_send_frame(sock, 0x8, payload, payload_len, 1);
                close_code = code;
                running = 0;
                offset += header_len + payload_len;
                break;
            } else if (opcode == 0x9) {
                (void)ws_send_frame(sock, 0xA, payload, payload_len, 1);
            } else if (opcode == 0xA) {
                awaiting_pong = 0;
            } else if (opcode == 0x0) {
                if (!frag_active || !frag_buf) {
                    close_code = 1002;
                    running = 0;
                    break;
                }
                if (frag_len + payload_len > VHTTP_WS_MAX_MESSAGE_SIZE) {
                    close_code = 1009;
                    running = 0;
                    break;
                }
                if (payload_len > 0) {
                    memcpy(frag_buf + frag_len, payload, payload_len);
                    frag_len += payload_len;
                }
                if (fin) {
                    if (frag_opcode == 1 && ws_validate_utf8(frag_buf, frag_len) != 0) {
                        close_code = 1007;
                        running = 0;
                        break;
                    }
                    if (ws_send_ipc_message(ipc, conn_id, frag_opcode, frag_buf, frag_len, 1) != 0) {
                        close_code = 1013;
                        running = 0;
                        break;
                    }
                    frag_len = 0;
                    frag_opcode = 0;
                    frag_active = 0;
                }
            } else if (opcode == 0x1 || opcode == 0x2) {
                if (!fin) {
                    if (!frag_buf) {
                        frag_buf = ws_alloc_frag_buf();
                        if (!frag_buf) {
                            close_code = 1011;
                            running = 0;
                            break;
                        }
                    }
                    frag_len = 0;
                    frag_opcode = opcode;
                    frag_active = 1;
                    if (payload_len > 0) {
                        if (payload_len > VHTTP_WS_MAX_MESSAGE_SIZE) {
                            close_code = 1009;
                            running = 0;
                            break;
                        }
                        memcpy(frag_buf, payload, payload_len);
                        frag_len = payload_len;
                    }
                } else {
                    if (payload_len > VHTTP_WS_MAX_MESSAGE_SIZE) {
                        close_code = 1009;
                        running = 0;
                        break;
                    }
                    if (opcode == 1 && payload_len > 0 && ws_validate_utf8(payload, payload_len) != 0) {
                        close_code = 1007;
                        running = 0;
                        break;
                    }
                    if (ws_send_ipc_message(ipc, conn_id, opcode, payload, payload_len, 1) != 0) {
                        close_code = 1013;
                        running = 0;
                        break;
                    }
                }
            } else {
                close_code = 1002;
                running = 0;
                break;
            }

            offset += header_len + payload_len;
            rx_frame_burst++;
            if (rx_frame_burst >= VHTTP_WS_FAIR_FRAME_BUDGET) {
                vhttp_stats_inc(&g_server_stats.scheduler_yields);
                taskYIELD();
                rx_frame_burst = 0;
                break;
            }
        }

        if (offset > 0) {
            memmove(rx_buf, rx_buf + offset, rx_len - offset);
            rx_len -= offset;
        }

        uint32_t now = vhttp_now_ms();
        if (!awaiting_pong && (now - last_ping) >= VHTTP_WS_PING_INTERVAL_MS) {
            (void)ws_send_frame(sock, 0x9, NULL, 0, 1);
            last_ping = now;
            awaiting_pong = 1;
        } else if (awaiting_pong && (now - last_ping) >= VHTTP_WS_PONG_TIMEOUT_MS) {
            close_code = 1002;
            running = 0;
        }

        if (r <= 0 && !awaiting_pong) {
            vTaskDelay(pdMS_TO_TICKS(1));
        }
    }

    if (frag_buf) {
        ws_free_buf(frag_buf);
    }
    ws_free_buf(rx_buf);
    if (!g_server_running && close_code == 1000) {
        close_code = 1001;
    }
    ws_send_disconnect_ipc(ipc, conn_id, close_code);
    return 0;
}

static int ws_handle_connection(int sock, const vhttp_parsed_request_t *req) {
    const vhttp_header_t *key_hdr = find_header(req, "sec-websocket-key");
    if (!key_hdr || key_hdr->value_len == 0) {
        VHTTP_LOGW("ws reject: missing key");
        (void)ws_send_raw_response(sock, 400, (const uint8_t *)"Missing Sec-WebSocket-Key", 27, NULL);
        return 0;
    }
    const vhttp_header_t *ver_hdr = find_header(req, "sec-websocket-version");
    if (!ver_hdr || !ws_value_equals(ver_hdr, "13")) {
        VHTTP_LOGW("ws reject: unsupported version");
        (void)ws_send_raw_response(sock, 426, (const uint8_t *)"Upgrade Required", 16, "Sec-WebSocket-Version: 13\r\n");
        return 0;
    }

    char accept_key[64];
    size_t accept_len = 0;
    if (ws_compute_accept_key(key_hdr->value, key_hdr->value_len, accept_key, sizeof(accept_key), &accept_len) != 0) {
        VHTTP_LOGW("ws reject: bad key");
        (void)ws_send_raw_response(sock, 400, (const uint8_t *)"Bad Request", 11, NULL);
        return 0;
    }

    vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
    if (!ipc) {
        VHTTP_LOGE("ws reject: ipc unavailable");
        (void)ws_send_raw_response(sock, 500, (const uint8_t *)"IPC Unavailable", 15, NULL);
        return 0;
    }

    uint32_t conn_id = vhttp_next_request_id();

    uint16_t uri_len = req->uri.len;
    if (uri_len == 0) {
        (void)ws_send_raw_response(sock, 400, (const uint8_t *)"Bad Request", 11, NULL);
        return 0;
    }

    uint32_t req_headers_len = 0;
    for (uint8_t i = 0; i < req->num_headers; ++i) {
        const vhttp_header_t *hdr = &req->headers[i];
        req_headers_len += (uint32_t)hdr->name_len + 1u;
        req_headers_len += (uint32_t)hdr->value_len + 1u;
    }

    uint32_t request_blob_len = (uint32_t)uri_len + req_headers_len;
    uint32_t path_offset = 0;
    uint8_t *path_dst = NULL;
    if (vhttp_ipc_ring_alloc(&ipc->ring, request_blob_len, &path_offset, &path_dst) != 0) {
        (void)ws_send_raw_response(sock, 503, (const uint8_t *)"Backpressure", 12, NULL);
        return 0;
    }
    memcpy(path_dst, req->uri.ptr, uri_len);

    if (req_headers_len > 0) {
        uint8_t *hdr_dst = path_dst + uri_len;
        uint32_t hdr_written = 0;
        for (uint8_t i = 0; i < req->num_headers; ++i) {
            const vhttp_header_t *hdr = &req->headers[i];
            if (hdr->name_len > 0) {
                memcpy(hdr_dst + hdr_written, hdr->name, hdr->name_len);
                hdr_written += hdr->name_len;
            }
            hdr_dst[hdr_written++] = '\0';
            if (hdr->value_len > 0) {
                memcpy(hdr_dst + hdr_written, hdr->value, hdr->value_len);
                hdr_written += hdr->value_len;
            }
            hdr_dst[hdr_written++] = '\0';
        }
    }

    vhttp_ipc_msg_t msg = {0};
    msg.request_id = conn_id;
    msg.type = VHTTP_IPC_REQ_WS_CONNECT;
    msg.method = VHTTP_METHOD_WS;
    msg.uri_len = uri_len;
    msg.query_len = req->query.len;
    msg.headers_len = (uint16_t)req_headers_len;
    msg.headers_offset = req_headers_len > 0 ? (path_offset + uri_len) : 0;
    msg.body_len = 0;
    msg.buffer_offset = path_offset;
    msg.flags = VHTTP_IPC_FLAG_RELEASE;

    if (vhttp_ipc_queue_push(&ipc->request_queue, &msg) != 0) {
        vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
        (void)ws_send_raw_response(sock, 503, (const uint8_t *)"Queue Full", 10, NULL);
        return 0;
    }

    vhttp_ipc_msg_t resp;
    int got_resp = 0;
    uint32_t waited_ms = 0;
    while (waited_ms < VHTTP_WS_HANDSHAKE_TIMEOUT_MS) {
        if (vhttp_ipc_wait_response_for(ipc, conn_id, 100, &resp) == 0) {
            if (resp.type == VHTTP_IPC_RESP_WS_ACCEPT || resp.type == VHTTP_IPC_RESP_WS_REJECT) {
                got_resp = 1;
                break;
            }
            vhttp_ipc_release_response_payload(ipc, &resp);
        }
        waited_ms += 100;
    }

    if (!got_resp) {
        VHTTP_LOGW("ws reject: handshake timeout");
        (void)ws_send_raw_response(sock, 504, (const uint8_t *)"Gateway Timeout", 15, NULL);
        return 0;
    }

    if (resp.type == VHTTP_IPC_RESP_WS_REJECT) {
        const uint8_t *body_ptr = NULL;
        if (resp.body_len > 0) {
            body_ptr = vhttp_ipc_ring_ptr(&ipc->ring, resp.buffer_offset);
        }
        int status = resp.status_code ? resp.status_code : 404;
        VHTTP_LOGW("ws rejected by app status=%d", status);
        (void)ws_send_raw_response(sock, status, body_ptr, resp.body_len, NULL);
        if (resp.body_len > 0) {
            vhttp_ipc_ring_release(&ipc->ring, resp.body_len);
        }
        return 0;
    }

    const uint8_t *proto_ptr = NULL;
    if (resp.body_len > 0) {
        proto_ptr = vhttp_ipc_ring_ptr(&ipc->ring, resp.buffer_offset);
    }
    if (ws_send_handshake(sock, accept_key, accept_len, (const char *)proto_ptr, resp.body_len) != 0) {
        if (resp.body_len > 0) {
            vhttp_ipc_ring_release(&ipc->ring, resp.body_len);
        }
        return 0;
    }
    VHTTP_LOGI("ws handshake accepted");
    if (resp.body_len > 0) {
        vhttp_ipc_ring_release(&ipc->ring, resp.body_len);
    }

    return ws_run_loop(sock, ipc, conn_id);
}

static vhttp_ws_task_ctx_t *vhttp_ws_task_ctx_alloc(int sock, const uint8_t *req_buf, uint32_t req_len) {
    if (!req_buf || req_len == 0) {
        return NULL;
    }
    size_t total = sizeof(vhttp_ws_task_ctx_t) + (size_t)req_len;
    vhttp_ws_task_ctx_t *ctx = heap_caps_malloc(total, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!ctx) {
        ctx = heap_caps_malloc(total, MALLOC_CAP_8BIT);
    }
    if (!ctx) {
        return NULL;
    }
    ctx->sock = sock;
    ctx->req_len = req_len;
    memcpy(ctx->req_buf, req_buf, req_len);
    return ctx;
}

static void vhttp_ws_task_ctx_free(vhttp_ws_task_ctx_t *ctx) {
    if (!ctx) {
        return;
    }
    heap_caps_free(ctx);
}

static void vhttp_ws_connection_task(void *arg) {
    vhttp_ws_task_ctx_t *ctx = (vhttp_ws_task_ctx_t *)arg;
    if (!ctx) {
        vTaskDelete(NULL);
        return;
    }
    vhttp_stats_inc(&g_server_stats.ws_tasks_active);

    vhttp_parsed_request_t req;
    vhttp_parse_result_t pres = vhttp_parse_request((const char *)ctx->req_buf, (size_t)ctx->req_len, &req);
    if (pres == VHTTP_PARSE_OK) {
        (void)ws_handle_connection(ctx->sock, &req);
    } else {
        (void)ws_send_raw_response(ctx->sock, 400, (const uint8_t *)"Bad Request", 11, NULL);
    }
    shutdown(ctx->sock, SHUT_RDWR);
    vhttp_https_close_socket_if_open(ctx->sock);
    close(ctx->sock);
    taskENTER_CRITICAL(&g_stats_lock);
    if (g_server_stats.ws_tasks_active > 0) {
        g_server_stats.ws_tasks_active--;
    }
    taskEXIT_CRITICAL(&g_stats_lock);
    vhttp_ws_task_ctx_free(ctx);
    vTaskDelete(NULL);
}

static int vhttp_spawn_ws_task(int sock, const uint8_t *req_buf, uint32_t req_len) {
    vhttp_ws_task_ctx_t *ctx = vhttp_ws_task_ctx_alloc(sock, req_buf, req_len);
    if (!ctx) {
        return -1;
    }
    BaseType_t ok = xTaskCreatePinnedToCore(
        vhttp_ws_connection_task,
        "vhttp_ws",
        VHTTP_SERVER_WS_STACK_SIZE,
        ctx,
        VHTTP_SERVER_TASK_PRIO,
        NULL,
        0
    );
    if (ok != pdPASS) {
        vhttp_ws_task_ctx_free(ctx);
        return -1;
    }
    vhttp_stats_inc(&g_server_stats.ws_handoffs);
    return 0;
}

#if !VHTTP_STATIC_SERVE_VIA_IPC
static void vhttp_static_rel_path(
    const char *full_path,
    size_t full_len,
    const char **out_rel,
    size_t *out_rel_len
) {
    const char *base = VHTTP_STATIC_FS_BASE;
    size_t base_len = strlen(base);
    while (base_len > 1 && base[base_len - 1] == '/') {
        base_len--;
    }

    const char *rel = full_path;
    size_t rel_len = full_len;

    if (base_len > 0 && full_len >= base_len && memcmp(full_path, base, base_len) == 0) {
        rel = full_path + base_len;
        rel_len = full_len - base_len;
    }

    if (rel_len > 0 && rel[0] == '/') {
        rel++;
        rel_len--;
    }

    *out_rel = rel;
    *out_rel_len = rel_len;
}
#endif

#if !VHTTP_STATIC_SERVE_VIA_IPC
static int send_file_response(
    int sock,
    const vhttp_static_match_t *match,
    int keep_alive,
    int head_only,
    const vhttp_parsed_request_t *req,
    const char *cors_headers,
    size_t cors_headers_len
) {
    if (!match || !match->path[0]) {
        return -2;
    }

    int fd = -1;
    int fs_locked = 0;
    int result = -1;
    vhttp_fs_lock();
    fs_locked = 1;
    int gzip_enabled = 0;
    char gz_path[VHTTP_STATIC_MAX_PATH];
    if (VHTTP_GZIP_ENABLED && req && header_accepts_gzip(req)) {
        if (match->path_len + 3 < sizeof(gz_path)) {
            memcpy(gz_path, match->path, match->path_len);
            memcpy(gz_path + match->path_len, ".gz", 3);
            gz_path[match->path_len + 3] = '\0';
            fd = open(gz_path, O_RDONLY);
            if (fd >= 0) {
                gzip_enabled = 1;
            }
        }
    }

    if (fd < 0) {
        fd = open(match->path, O_RDONLY);
    }
    if (fd < 0) {
        result = -2;
        goto cleanup;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 0) {
        result = -2;
        goto cleanup;
    }
    if (!S_ISREG(st.st_mode)) {
        result = -2;
        goto cleanup;
    }
    vhttp_fs_unlock();
    fs_locked = 0;

    const char *content_type = match->content_type ? match->content_type : "application/octet-stream";
    const char *conn = keep_alive ? "keep-alive" : "close";
    char header[512];
    char cache_buf[64];
    const char *cache_header = "";
    if (VHTTP_STATIC_CACHE_MAX_AGE > 0) {
        int cache_len = snprintf(
            cache_buf,
            sizeof(cache_buf),
            "Cache-Control: public, max-age=%d\r\n",
            VHTTP_STATIC_CACHE_MAX_AGE
        );
        if (cache_len > 0 && (size_t)cache_len < sizeof(cache_buf)) {
            cache_header = cache_buf;
        }
    }

    const char *etag_ptr = NULL;
    size_t etag_len = 0;
    char etag_buf[64];

    const size_t etag_hash_min_size = (size_t)VHTTP_STATIC_ETAG_HASH_MIN_SIZE;
    if (!gzip_enabled &&
        etag_hash_min_size > 0 &&
        (size_t)st.st_size >= etag_hash_min_size) {
        const char *rel = NULL;
        size_t rel_len = 0;
        vhttp_static_rel_path(match->path, match->path_len, &rel, &rel_len);
        if (rel && rel_len > 0) {
            const vhttp_static_etag_entry_t *entry = vhttp_static_etag_lookup(rel, rel_len);
            if (entry && entry->etag && entry->etag_len > 0) {
                etag_ptr = entry->etag;
                etag_len = entry->etag_len;
            }
        }
    }

    if (!etag_ptr) {
        int etag_len_i = snprintf(
            etag_buf,
            sizeof(etag_buf),
            "W/\"%lx-%lx\"",
            (unsigned long)st.st_size,
            (unsigned long)st.st_mtime
        );
        if (etag_len_i < 0) {
            result = -1;
            goto cleanup;
        }
        if ((size_t)etag_len_i >= sizeof(etag_buf)) {
            etag_len_i = (int)(sizeof(etag_buf) - 1);
            etag_buf[etag_len_i] = '\0';
        }
        etag_ptr = etag_buf;
        etag_len = (size_t)etag_len_i;
    }

    if (etag_matches(req, etag_ptr, etag_len)) {
        int header_len = snprintf(
            header,
            sizeof(header),
            "HTTP/1.1 304 Not Modified\r\nETag: %.*s\r\n%s%s%.*sContent-Length: 0\r\nConnection: %s\r\n\r\n",
            (int)etag_len,
            etag_ptr,
            cache_header,
            gzip_enabled ? "Content-Encoding: gzip\r\nVary: Accept-Encoding\r\n" : "",
            (int)cors_headers_len,
            cors_headers_len > 0 ? cors_headers : "",
            conn
        );
        if (header_len < 0 || (size_t)header_len >= sizeof(header)) {
            result = -1;
            goto cleanup;
        }
        if (send_all(sock, (const uint8_t *)header, (size_t)header_len) != 0) {
            result = -1;
            goto cleanup;
        }
        result = 0;
        goto cleanup;
    }

    int header_len = 0;
    if (!gzip_enabled) {
        header_len = snprintf(
            header,
            sizeof(header),
            "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %lu\r\nETag: %.*s\r\n%s%.*sConnection: %s\r\n\r\n",
            content_type,
            (unsigned long)st.st_size,
            (int)etag_len,
            etag_ptr,
            cache_header,
            (int)cors_headers_len,
            cors_headers_len > 0 ? cors_headers : "",
            conn
        );
    } else {
        header_len = snprintf(
            header,
            sizeof(header),
            "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Encoding: gzip\r\nVary: Accept-Encoding\r\nContent-Length: %lu\r\nETag: %.*s\r\n%s%.*sConnection: %s\r\n\r\n",
            content_type,
            (unsigned long)st.st_size,
            (int)etag_len,
            etag_ptr,
            cache_header,
            (int)cors_headers_len,
            cors_headers_len > 0 ? cors_headers : "",
            conn
        );
    }
    if (header_len < 0 || (size_t)header_len >= sizeof(header)) {
        result = -1;
        goto cleanup;
    }
    if (send_all(sock, (const uint8_t *)header, (size_t)header_len) != 0) {
        result = -1;
        goto cleanup;
    }

    if (head_only) {
        result = 0;
        goto cleanup;
    }

    uint8_t buf[1024];
    for (;;) {
        vhttp_fs_lock();
        fs_locked = 1;
        ssize_t rd = read(fd, buf, sizeof(buf));
        vhttp_fs_unlock();
        fs_locked = 0;
        if (rd < 0) {
            result = -1;
            goto cleanup;
        }
        if (rd == 0) {
            break;
        }
        if (send_all(sock, buf, (size_t)rd) != 0) {
            result = -1;
            goto cleanup;
        }
    }

    result = 0;

cleanup:
    if (fd >= 0) {
        if (!fs_locked) {
            vhttp_fs_lock();
            fs_locked = 1;
        }
        close(fd);
    }
    if (fs_locked) {
        vhttp_fs_unlock();
    }
    return result;
}
#endif

static vhttp_ev_dispatch_result_t vhttp_evrt_dispatch_request(
    vhttp_evrt_conn_t *conn,
    const vhttp_parsed_request_t *req
) {
    if (!conn || !req) {
        return VHTTP_EV_DISPATCH_CLOSE;
    }

    conn->served_requests++;
    vhttp_stats_inc(&g_server_stats.requests_started);

    int keep_alive = header_value_contains(req, "connection", "close") ? 0 : 1;
    if (keep_alive && conn->served_requests >= VHTTP_MAX_KEEPALIVE_REQUESTS) {
        keep_alive = 0;
    }
    if (keep_alive && conn->served_requests > 1 && g_accept_queue) {
        UBaseType_t queued = uxQueueMessagesWaiting(g_accept_queue);
        uint32_t pressure_threshold = 1;
        if ((size_t)VHTTP_SERVER_WORKERS > 2) {
            pressure_threshold = (uint32_t)((size_t)VHTTP_SERVER_WORKERS / 2);
            if (pressure_threshold == 0) {
                pressure_threshold = 1;
            }
        }
        if ((uint32_t)queued >= pressure_threshold) {
            keep_alive = 0;
        }
    }
    conn->keep_alive = keep_alive ? 1u : 0u;
    conn->head_only = 0;
    conn->stream_active = 0;
    conn->stream_use_chunked = 0;
    conn->stream_header_sent = 0;
    conn->cors_headers_len = 0;
    conn->cors_headers[0] = '\0';

    uint8_t method = VHTTP_METHOD_GET;
    if (method_from_str(req->method.ptr, req->method.len, &method) != 0) {
        send_simple_response(conn->sock, 405, "Method Not Allowed", keep_alive, NULL);
        vhttp_log_http_response(req, 405, keep_alive, "simple");
        return keep_alive ? VHTTP_EV_DISPATCH_CONTINUE : VHTTP_EV_DISPATCH_CLOSE;
    }
    conn->head_only = (method == VHTTP_METHOD_HEAD) ? 1u : 0u;

    vhttp_log_http_request(req, conn->client_ip);

    if (vhttp_trusted_host_enabled() && !vhttp_trusted_host_allowed(req)) {
        send_simple_response(conn->sock, 400, "Invalid Host", keep_alive, NULL);
        vhttp_log_http_response(req, 400, keep_alive, "trusted-host");
        return keep_alive ? VHTTP_EV_DISPATCH_CONTINUE : VHTTP_EV_DISPATCH_CLOSE;
    }

    size_t cors_headers_len = 0;
    char cors_headers[VHTTP_CORS_HEADER_MAX];
    cors_headers[0] = '\0';
    if (vhttp_cors_enabled()) {
        const char *cors_origin = NULL;
        size_t cors_origin_len = 0;
        if (vhttp_cors_get_origin(req, &cors_origin, &cors_origin_len)) {
            int cors_allowed = vhttp_cors_origin_allowed(cors_origin, cors_origin_len);
            if (vhttp_cors_is_preflight(method, req)) {
                if (!cors_allowed) {
                    send_simple_response(conn->sock, 403, "CORS Forbidden", keep_alive, NULL);
                    vhttp_log_http_response(req, 403, keep_alive, "cors");
                    return keep_alive ? VHTTP_EV_DISPATCH_CONTINUE : VHTTP_EV_DISPATCH_CLOSE;
                }
                cors_headers_len = vhttp_cors_build_headers(
                    cors_headers, sizeof(cors_headers), req, cors_origin, cors_origin_len, 1
                );
                send_simple_response(
                    conn->sock, 204, "", keep_alive, cors_headers_len > 0 ? cors_headers : NULL
                );
                vhttp_log_http_response(req, 204, keep_alive, "cors-preflight");
                return keep_alive ? VHTTP_EV_DISPATCH_CONTINUE : VHTTP_EV_DISPATCH_CLOSE;
            }
            if (cors_allowed) {
                cors_headers_len = vhttp_cors_build_headers(
                    cors_headers, sizeof(cors_headers), req, cors_origin, cors_origin_len, 0
                );
            }
        }
    }
    const char *cors_extra = cors_headers_len > 0 ? cors_headers : NULL;
    if (cors_headers_len > 0) {
        if (cors_headers_len >= sizeof(conn->cors_headers)) {
            cors_headers_len = sizeof(conn->cors_headers) - 1;
        }
        memcpy(conn->cors_headers, cors_headers, cors_headers_len);
        conn->cors_headers[cors_headers_len] = '\0';
        conn->cors_headers_len = (uint16_t)cors_headers_len;
    }

    if (vhttp_ratelimit_enabled()) {
        uint32_t retry_ms = 0;
        if (!vhttp_ratelimit_check(conn->client_ip, &retry_ms)) {
            char rl_headers[VHTTP_CORS_HEADER_MAX + 64];
            size_t off = 0;
            if (cors_headers_len > 0) {
                size_t copy_len = cors_headers_len;
                if (copy_len >= sizeof(rl_headers)) {
                    copy_len = sizeof(rl_headers) - 1;
                }
                memcpy(rl_headers, cors_headers, copy_len);
                off += copy_len;
            }
            uint32_t retry_sec = (retry_ms + 999u) / 1000u;
            int n = snprintf(
                rl_headers + off,
                sizeof(rl_headers) - off,
                "Retry-After: %lu\r\n",
                (unsigned long)retry_sec
            );
            if (n < 0 || (size_t)n >= sizeof(rl_headers) - off) {
                send_simple_response(conn->sock, 429, "Too Many Requests", keep_alive, cors_extra);
            } else {
                send_simple_response(conn->sock, 429, "Too Many Requests", keep_alive, rl_headers);
            }
            vhttp_log_http_response(req, 429, keep_alive, "rate-limit");
            return keep_alive ? VHTTP_EV_DISPATCH_CONTINUE : VHTTP_EV_DISPATCH_CLOSE;
        }
    }

    uint8_t h2c_prefer_handoff = 0u;
#if VHTTP_HTTP2_EVENT_LOOP_TASK_FALLBACK
    h2c_prefer_handoff = 1u;
#endif
    int h2c_rc = vhttp_http2_try_h2c_upgrade(
        conn->sock,
        conn->client_ip,
        conn->recv_buf,
        conn->recv_cap,
        conn->buffered,
        req,
        h2c_prefer_handoff,
        1u
    );
    if (h2c_rc == 2) {
        vhttp_ev_conn_on_closed(conn->sock);
        conn->sock = -1;
        return VHTTP_EV_DISPATCH_HANDOFF;
    }
    if (h2c_rc == 1) {
        return VHTTP_EV_DISPATCH_CLOSE;
    }
    if (h2c_rc < 0) {
        return VHTTP_EV_DISPATCH_CLOSE;
    }

    if (method == VHTTP_METHOD_GET && ws_is_upgrade_request(req)) {
        if (vhttp_spawn_ws_task(conn->sock, conn->recv_buf, (uint32_t)req->total_len) == 0) {
            vhttp_ev_conn_on_closed(conn->sock);
            conn->sock = -1;
            return VHTTP_EV_DISPATCH_HANDOFF;
        }
        (void)ws_handle_connection(conn->sock, req);
        return VHTTP_EV_DISPATCH_HANDOFF;
    }

#if !VHTTP_STATIC_SERVE_VIA_IPC
    vhttp_static_match_t static_match;
    if (vhttp_static_resolve(req->path.ptr, req->path.len, &static_match)) {
        if (method != VHTTP_METHOD_GET && method != VHTTP_METHOD_HEAD) {
            send_simple_response(conn->sock, 405, "Method Not Allowed", keep_alive, cors_extra);
            vhttp_log_http_response(req, 405, keep_alive, "static");
            return keep_alive ? VHTTP_EV_DISPATCH_CONTINUE : VHTTP_EV_DISPATCH_CLOSE;
        }
        int sres = send_file_response(
            conn->sock,
            &static_match,
            keep_alive,
            method == VHTTP_METHOD_HEAD,
            req,
            cors_headers,
            cors_headers_len
        );
        if (sres == -2) {
            send_simple_response(conn->sock, 404, "Not Found", keep_alive, cors_extra);
            vhttp_log_http_response(req, 404, keep_alive, "static");
        } else if (sres != 0) {
            send_simple_response(conn->sock, 500, "Internal Server Error", keep_alive, cors_extra);
            vhttp_log_http_response(req, 500, keep_alive, "static");
        } else {
            vhttp_log_http_response(req, 200, keep_alive, "static");
        }
        return keep_alive ? VHTTP_EV_DISPATCH_CONTINUE : VHTTP_EV_DISPATCH_CLOSE;
    }
#endif

    vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
    if (!ipc) {
        send_simple_response(conn->sock, 500, "IPC Unavailable", keep_alive, cors_extra);
        vhttp_log_http_response(req, 500, keep_alive, "ipc");
        return keep_alive ? VHTTP_EV_DISPATCH_CONTINUE : VHTTP_EV_DISPATCH_CLOSE;
    }

    uint32_t req_id = vhttp_next_request_id();
    uint16_t uri_len = req->uri.len;
    uint16_t query_len = req->query.len;
    uint32_t req_headers_len = 0;
    uint32_t req_body_len = req->body_len;
    for (uint8_t i = 0; i < req->num_headers; ++i) {
        const vhttp_header_t *hdr = &req->headers[i];
        req_headers_len += (uint32_t)hdr->name_len + 1u;
        req_headers_len += (uint32_t)hdr->value_len + 1u;
    }
    if (uri_len == 0 || req_headers_len > 65535u) {
        send_simple_response(conn->sock, 413, "Headers Too Large", keep_alive, cors_extra);
        vhttp_log_http_response(req, 413, keep_alive, "ipc");
        return keep_alive ? VHTTP_EV_DISPATCH_CONTINUE : VHTTP_EV_DISPATCH_CLOSE;
    }
    uint32_t request_blob_len = (uint32_t)uri_len + req_headers_len + req_body_len;
    if (request_blob_len == 0) {
        send_simple_response(conn->sock, 400, "Bad Request", keep_alive, cors_extra);
        vhttp_log_http_response(req, 400, keep_alive, "ipc");
        return keep_alive ? VHTTP_EV_DISPATCH_CONTINUE : VHTTP_EV_DISPATCH_CLOSE;
    }

    uint32_t path_offset = 0;
    uint8_t *path_dst = NULL;
    if (vhttp_ipc_ring_alloc(&ipc->ring, request_blob_len, &path_offset, &path_dst) != 0) {
        vhttp_stats_inc(&g_server_stats.ipc_req_ring_alloc_fail);
        vhttp_stats_inc(&g_server_stats.backpressure_503_sent);
        send_simple_response(conn->sock, 503, "Backpressure", 0, cors_extra);
        vhttp_log_http_response(req, 503, 0, "ipc");
        conn->keep_alive = 0;
        return VHTTP_EV_DISPATCH_CLOSE;
    }

    memcpy(path_dst, req->uri.ptr, uri_len);
    if (req_headers_len > 0) {
        uint8_t *hdr_dst = path_dst + uri_len;
        uint32_t hdr_written = 0;
        for (uint8_t i = 0; i < req->num_headers; ++i) {
            const vhttp_header_t *hdr = &req->headers[i];
            if (hdr->name_len > 0) {
                memcpy(hdr_dst + hdr_written, hdr->name, hdr->name_len);
                hdr_written += hdr->name_len;
            }
            hdr_dst[hdr_written++] = '\0';
            if (hdr->value_len > 0) {
                memcpy(hdr_dst + hdr_written, hdr->value, hdr->value_len);
                hdr_written += hdr->value_len;
            }
            hdr_dst[hdr_written++] = '\0';
        }
    }
    if (req_body_len > 0) {
        memcpy(path_dst + uri_len + req_headers_len, req->body, req_body_len);
    }

    vhttp_ipc_msg_t msg = {0};
    msg.request_id = req_id;
    msg.type = VHTTP_IPC_REQ_HTTP;
    msg.method = method;
    msg.uri_len = uri_len;
    msg.query_len = query_len;
    msg.headers_len = (uint16_t)req_headers_len;
    msg.headers_offset = req_headers_len > 0 ? (path_offset + uri_len) : 0;
    msg.body_len = req_body_len;
    msg.buffer_offset = path_offset;

    int enqueued = 0;
    for (int attempt = 0; attempt < 2; ++attempt) {
        if (vhttp_ipc_queue_push(&ipc->request_queue, &msg) == 0) {
            enqueued = 1;
            break;
        }
        taskYIELD();
    }
    if (!enqueued) {
        memset(&conn->pending_msg, 0, sizeof(conn->pending_msg));
        conn->pending_msg = msg;
        conn->state = VHTTP_EVRT_WAIT_REQ_QUEUE;
        conn->request_id = req_id;
        conn->request_blob_len = request_blob_len;
        conn->state_since = xTaskGetTickCount();
        return VHTTP_EV_DISPATCH_WAIT_REQ_QUEUE;
    }

    conn->state = VHTTP_EVRT_WAIT_IPC;
    conn->request_id = req_id;
    conn->request_blob_len = request_blob_len;
    conn->state_since = xTaskGetTickCount();
    vhttp_ev_conn_on_dispatched(conn->sock);
    return VHTTP_EV_DISPATCH_WAIT_IPC;
}

static int vhttp_evrt_process_read(vhttp_evrt_conn_t *conn, int socket_writable) {
    if (!conn || conn->sock < 0 || !conn->recv_buf || conn->recv_cap == 0) {
        return -1;
    }

    if (conn->buffered < conn->recv_cap) {
        int rc = vhttp_sock_recv(conn->sock, conn->recv_buf + conn->buffered, conn->recv_cap - conn->buffered);
        if (rc > 0) {
            conn->buffered += (size_t)rc;
            conn->state_since = xTaskGetTickCount();
        } else if (rc == 0) {
            return -1;
        } else if (!(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            return -1;
        }
    }

    if (conn->h2_ctx) {
        return vhttp_evrt_h2_tick(conn, socket_writable);
    }

    // Allow small per-socket batching to raise throughput under keep-alive load.
    for (uint32_t budget = 0; budget < 2; ++budget) {
        if (conn->buffered == 0) {
            return 0;
        }
        if (vhttp_http2_buffer_starts_with_preface(conn->recv_buf, conn->buffered)) {
            if (vhttp_http2_enabled_runtime()) {
                if (vhttp_evrt_h2_activate(conn) != 0) {
                    (void)vhttp_http2_send_goaway(conn->sock, VHTTP_HTTP2_ERR_INTERNAL);
                    vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
                    return -1;
                }
                return vhttp_evrt_h2_tick(conn, socket_writable);
            }
            if (vhttp_http2_handle_preface_if_needed(conn->sock, conn->recv_buf, conn->buffered)) {
                return -1;
            }
        }
        if (vhttp_https_session_is_h2(conn->sock)) {
            if (conn->buffered < VHTTP_HTTP2_PREFACE_LEN) {
                return 0;
            }
            if (vhttp_http2_buffer_starts_with_preface(conn->recv_buf, conn->buffered)) {
                if (vhttp_http2_enabled_runtime()) {
                    if (vhttp_evrt_h2_activate(conn) != 0) {
                        (void)vhttp_http2_send_goaway(conn->sock, VHTTP_HTTP2_ERR_INTERNAL);
                        vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
                        return -1;
                    }
                    return vhttp_evrt_h2_tick(conn, socket_writable);
                }
            }
            (void)vhttp_http2_send_goaway(conn->sock, VHTTP_HTTP2_ERR_PROTOCOL);
            vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
            return -1;
        }

        vhttp_parsed_request_t req;
        vhttp_parse_result_t pres = vhttp_parse_request((const char *)conn->recv_buf, conn->buffered, &req);
        if (pres == VHTTP_PARSE_INCOMPLETE) {
            if (conn->buffered >= conn->recv_cap) {
                (void)send_simple_response(conn->sock, 413, "Payload Too Large", 0, NULL);
                return -1;
            }
            return 0;
        }
        if (pres != VHTTP_PARSE_OK) {
            int status = pres == VHTTP_PARSE_TOO_LARGE ? 413 : 400;
            const char *body = status == 413 ? "Payload Too Large" : "Bad Request";
            (void)send_simple_response(conn->sock, status, body, 0, NULL);
            return -1;
        }

        vhttp_stats_conn_state_hit(VHTTP_CONN_STATE_READ_REQ);
        vhttp_ev_dispatch_result_t dres = vhttp_evrt_dispatch_request(conn, &req);
        if (dres != VHTTP_EV_DISPATCH_HANDOFF) {
            vhttp_evrt_consume_buffer(conn, req.total_len);
        }

        if (dres == VHTTP_EV_DISPATCH_CLOSE) {
            return -1;
        }
        if (dres == VHTTP_EV_DISPATCH_HANDOFF) {
            return 1;
        }
        if (dres == VHTTP_EV_DISPATCH_WAIT_IPC) {
            vhttp_stats_conn_state_hit(VHTTP_CONN_STATE_WAIT_IPC);
            return 0;
        }
        if (dres == VHTTP_EV_DISPATCH_WAIT_REQ_QUEUE) {
            vhttp_stats_conn_state_hit(VHTTP_CONN_STATE_WAIT_IPC);
            return 0;
        }
        conn->state_since = xTaskGetTickCount();
    }
    return 0;
}

static int vhttp_evrt_process_wait_req_queue(vhttp_evrt_conn_t *conn) {
    if (!conn || conn->state != VHTTP_EVRT_WAIT_REQ_QUEUE) {
        return 0;
    }
    vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
    if (!ipc) {
        return -1;
    }

    if (vhttp_ipc_queue_push(&ipc->request_queue, &conn->pending_msg) == 0) {
        conn->state = VHTTP_EVRT_WAIT_IPC;
        conn->state_since = xTaskGetTickCount();
        vhttp_ev_conn_on_dispatched(conn->sock);
        return 0;
    }

    TickType_t timeout = pdMS_TO_TICKS(VHTTP_EVENT_LOOP_REQ_QUEUE_RETRY_TIMEOUT_MS);
    if (timeout == 0) {
        timeout = 1;
    }
    if ((TickType_t)(xTaskGetTickCount() - conn->state_since) >= timeout) {
        vhttp_stats_inc(&g_server_stats.ipc_req_queue_push_fail);
        vhttp_stats_inc(&g_server_stats.backpressure_503_sent);
        if (conn->request_blob_len > 0) {
            vhttp_ipc_ring_release(&ipc->ring, conn->request_blob_len);
            conn->request_blob_len = 0;
        }
        conn->request_id = 0;
        conn->pending_msg.request_id = 0;
        (void)send_simple_response(
            conn->sock,
            503,
            "Queue Full",
            0,
            conn->cors_headers_len > 0 ? conn->cors_headers : NULL
        );
        conn->keep_alive = 0;
        return -1;
    }
    return 0;
}

static int vhttp_evrt_process_wait_ipc(vhttp_evrt_conn_t *conn, int socket_writable) {
    if (!conn || conn->state != VHTTP_EVRT_WAIT_IPC) {
        return 0;
    }
    vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
    if (!ipc) {
        return -1;
    }

    TickType_t timeout = pdMS_TO_TICKS(VHTTP_SERVER_RESP_TIMEOUT_MS);
    if (timeout == 0) {
        timeout = 1;
    }

    if (conn->tx_active) {
        if (socket_writable) {
            int frc = vhttp_evrt_flush_tx(conn, ipc);
            if (frc < 0) {
                return -1;
            }
            if (conn->state != VHTTP_EVRT_WAIT_IPC) {
                return 0;
            }
        }
        if (conn->tx_active && (TickType_t)(xTaskGetTickCount() - conn->state_since) >= timeout) {
            vhttp_abort_inflight_request(ipc, conn->request_id, &conn->request_blob_len);
            conn->request_id = 0;
            vhttp_stats_inc(&g_server_stats.ipc_wait_timeouts);
            return -1;
        }
        if (conn->tx_active) {
            return 0;
        }
    }

    uint32_t budget = (uint32_t)VHTTP_EVENT_LOOP_WAIT_IPC_DRAIN_BUDGET;
    if (budget == 0) {
        budget = 1;
    }
    uint8_t got_response = 0;

    while (budget-- > 0) {
        vhttp_ipc_msg_t resp = {0};
        if (vhttp_ipc_try_response_for(ipc, conn->request_id, &resp) != 0) {
            break;
        }
        got_response = 1;

        if (conn->request_blob_len > 0) {
            vhttp_ipc_ring_release(&ipc->ring, conn->request_blob_len);
            conn->request_blob_len = 0;
        }

        if (vhttp_evrt_prepare_tx_from_ipc(conn, &resp, ipc) != 0) {
            vhttp_ipc_release_response_payload(ipc, &resp);
            return -1;
        }
        int frc = vhttp_evrt_flush_tx(conn, ipc);
        if (frc < 0) {
            return -1;
        }
        if (conn->state != VHTTP_EVRT_WAIT_IPC) {
            return 0;
        }
        if (conn->tx_active) {
            if (!socket_writable && (TickType_t)(xTaskGetTickCount() - conn->state_since) >= timeout) {
                vhttp_abort_inflight_request(ipc, conn->request_id, &conn->request_blob_len);
                conn->request_id = 0;
                vhttp_stats_inc(&g_server_stats.ipc_wait_timeouts);
                return -1;
            }
            return 0;
        }
    }

    if (!got_response && (TickType_t)(xTaskGetTickCount() - conn->state_since) >= timeout) {
        vhttp_abort_inflight_request(ipc, conn->request_id, &conn->request_blob_len);
        conn->request_id = 0;
        if (!conn->stream_active) {
            (void)send_simple_response(conn->sock, 504, "Gateway Timeout", 0, conn->cors_headers_len ? conn->cors_headers : NULL);
        }
        vhttp_stats_inc(&g_server_stats.ipc_wait_timeouts);
        return -1;
    }

    return 0;
}

static int vhttp_server_event_loop_run(void) {
    if (!vhttp_socket_fd_valid(g_listen_fd) || vhttp_set_socket_nonblocking(g_listen_fd) != 0) {
        VHTTP_LOGE("event-loop listen socket nonblocking setup failed fd=%d", g_listen_fd);
        return -1;
    }
    vhttp_evrt_reset_all();

    while (g_server_running) {
        fd_set rfds;
        fd_set wfds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        int max_fd = -1;
        uint32_t tx_active_count = 0;
        uint32_t wait_ipc_count = 0;
        uint32_t wait_req_queue_count = 0;
        if (vhttp_socket_fd_valid(g_listen_fd)) {
            FD_SET(g_listen_fd, &rfds);
            max_fd = g_listen_fd;
        }
        for (size_t i = 0; i < (size_t)VHTTP_EVENT_LOOP_MAX_CONNS; ++i) {
            const vhttp_evrt_conn_t *conn = &g_evrt_conns[i];
            if (!conn->used || conn->sock < 0) {
                continue;
            }
            if (conn->state == VHTTP_EVRT_WAIT_IPC) {
                wait_ipc_count++;
                if (conn->tx_active) {
                    tx_active_count++;
                }
            } else if (conn->state == VHTTP_EVRT_WAIT_REQ_QUEUE) {
                wait_req_queue_count++;
            }
            if (vhttp_socket_fd_valid(conn->sock)) {
                if (conn->state == VHTTP_EVRT_READ_REQ) {
                    FD_SET(conn->sock, &rfds);
                    if (conn->h2_ctx && vhttp_http2_event_tx_has_pending(conn->h2_ctx)) {
                        FD_SET(conn->sock, &wfds);
                        tx_active_count++;
                    }
                } else if (conn->state == VHTTP_EVRT_WAIT_IPC && conn->tx_active) {
                    FD_SET(conn->sock, &wfds);
                }
                if (conn->sock > max_fd) {
                    max_fd = conn->sock;
                }
            }
        }

        struct timeval tv = {0};
        if (tx_active_count > 0) {
            tv.tv_usec = VHTTP_EVENT_LOOP_SELECT_TX_USEC;
        } else if (wait_ipc_count > 0 || wait_req_queue_count > 0) {
            tv.tv_usec = VHTTP_EVENT_LOOP_SELECT_WAIT_IPC_USEC;
        } else {
            tv.tv_usec = VHTTP_EVENT_LOOP_SELECT_IDLE_USEC;
        }
        int rc = max_fd >= 0 ? select(max_fd + 1, &rfds, &wfds, NULL, &tv) : 0;
        if (rc < 0 && errno != EINTR) {
            vTaskDelay(pdMS_TO_TICKS(5));
        }

        if (max_fd >= 0 && FD_ISSET(g_listen_fd, &rfds)) {
            uint32_t accept_budget = (uint32_t)VHTTP_EVENT_LOOP_ACCEPT_BUDGET;
            if (accept_budget == 0) {
                accept_budget = 1;
            }
            for (uint32_t i = 0; i < accept_budget; ++i) {
                struct sockaddr_in client_addr;
                socklen_t socklen = sizeof(client_addr);
                int sock = accept(g_listen_fd, (struct sockaddr *)&client_addr, &socklen);
                if (sock < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                        break;
                    }
                    break;
                }
                if (!vhttp_socket_fd_valid(sock) || vhttp_set_socket_nonblocking(sock) != 0) {
                    close(sock);
                    continue;
                }
                uint32_t client_ip = client_addr.sin_family == AF_INET ? (uint32_t)client_addr.sin_addr.s_addr : 0;
                vhttp_stats_inc(&g_server_stats.accepts_total);
                vhttp_ev_conn_on_accept(sock, client_ip);
                if (vhttp_https_enabled_runtime()) {
                    if (vhttp_https_session_open(sock) != 0) {
                        shutdown(sock, SHUT_RDWR);
                        vhttp_https_close_socket_if_open(sock);
                        close(sock);
                        vhttp_ev_conn_on_closed(sock);
                        continue;
                    }
                }
                if (vhttp_evrt_claim_slot(sock, client_ip) < 0) {
                    vhttp_stats_inc(&g_server_stats.accepts_rejected);
                    (void)send_simple_response(sock, 503, "Server Busy", 0, NULL);
                    shutdown(sock, SHUT_RDWR);
                    vhttp_https_close_socket_if_open(sock);
                    close(sock);
                    vhttp_ev_conn_on_closed(sock);
                } else {
                    vhttp_stats_inc(&g_server_stats.accepts_enqueued);
                }
            }
        }

        for (size_t i = 0; i < (size_t)VHTTP_EVENT_LOOP_MAX_CONNS; ++i) {
            vhttp_evrt_conn_t *conn = &g_evrt_conns[i];
            if (!conn->used) {
                continue;
            }
            int release = 0;
            if (conn->state == VHTTP_EVRT_READ_REQ && conn->sock >= 0) {
                TickType_t timeout = pdMS_TO_TICKS(
                    conn->served_requests == 0 ? VHTTP_SERVER_IDLE_TIMEOUT_MS : VHTTP_SERVER_KEEPALIVE_IDLE_TIMEOUT_MS
                );
                if (timeout == 0) {
                    timeout = 1;
                }
                if (!conn->h2_ctx &&
                    conn->buffered == 0 &&
                    (TickType_t)(xTaskGetTickCount() - conn->state_since) >= timeout) {
                    release = 1;
                }

                int should_read = conn->buffered > 0 ? 1 : 0;
                if (conn->h2_ctx) {
                    should_read = 1;
                }
                if (!should_read && rc > 0 && FD_ISSET(conn->sock, &rfds)) {
                    should_read = 1;
                }
                if (!release && should_read) {
                    int writable = (rc > 0 && FD_ISSET(conn->sock, &wfds)) ? 1 : 0;
                    int prc = vhttp_evrt_process_read(conn, writable);
                    if (prc < 0) {
                        release = 1;
                    } else if (prc == 1) {
                        vhttp_evrt_release_slot(conn);
                        continue;
                    }
                }
            } else if (conn->state == VHTTP_EVRT_WAIT_IPC) {
                int writable = (rc > 0 && FD_ISSET(conn->sock, &wfds)) ? 1 : 0;
                if (vhttp_evrt_process_wait_ipc(conn, writable) < 0) {
                    release = 1;
                }
            } else if (conn->state == VHTTP_EVRT_WAIT_REQ_QUEUE) {
                if (vhttp_evrt_process_wait_req_queue(conn) < 0) {
                    release = 1;
                }
            }
            if (release) {
                vhttp_evrt_release_slot(conn);
            }
        }
    }

    for (size_t i = 0; i < (size_t)VHTTP_EVENT_LOOP_MAX_CONNS; ++i) {
        vhttp_evrt_release_slot(&g_evrt_conns[i]);
    }
    return 0;
}

static int handle_connection(vhttp_worker_ctx_t *ctx, int sock, uint32_t client_ip) {
    if (!ctx || !ctx->recv_buf || ctx->recv_cap == 0) {
        return -1;
    }
    uint8_t *recv_buf = ctx->recv_buf;
    size_t recv_cap = ctx->recv_cap;
    size_t buffered = 0;
    uint32_t served_requests = 0;
    vhttp_runtime_state_t conn_state = VHTTP_CONN_STATE_READ_REQ;

    for (;;) {
        conn_state = VHTTP_CONN_STATE_READ_REQ;
        vhttp_stats_conn_state_hit(conn_state);
        if (buffered == 0) {
            uint32_t idle_timeout_ms = (served_requests == 0)
                ? VHTTP_SERVER_IDLE_TIMEOUT_MS
                : VHTTP_SERVER_KEEPALIVE_IDLE_TIMEOUT_MS;
            int rc = vhttp_recv_with_timeout(sock, recv_buf, recv_cap, idle_timeout_ms);
            if (rc < 0) {
                if (rc == -2) {
                    return 0;
                }
                return -1;
            }
            if (rc == 0) {
                return 0;
            }
            buffered = (size_t)rc;
        }

        if (vhttp_http2_buffer_starts_with_preface(recv_buf, buffered)) {
            if (vhttp_http2_enabled_runtime()) {
                (void)vhttp_http2_run_session(sock, client_ip, recv_buf, recv_cap, buffered, 0u);
                return 0;
            }
            if (vhttp_http2_handle_preface_if_needed(sock, recv_buf, buffered)) {
                return 0;
            }
        }
        if (vhttp_https_session_is_h2(sock)) {
            if (buffered < VHTTP_HTTP2_PREFACE_LEN) {
                if (buffered >= recv_cap) {
                    (void)vhttp_http2_send_goaway(sock, VHTTP_HTTP2_ERR_PROTOCOL);
                    vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
                    return 0;
                }
                int rc = vhttp_recv_with_timeout(
                    sock,
                    recv_buf + buffered,
                    recv_cap - buffered,
                    VHTTP_HTTP2_SESSION_IDLE_TIMEOUT_MS
                );
                if (rc <= 0) {
                    return 0;
                }
                buffered += (size_t)rc;
                continue;
            }
            (void)vhttp_http2_send_goaway(sock, VHTTP_HTTP2_ERR_PROTOCOL);
            vhttp_stats_inc(&g_server_stats.http2_goaway_sent);
            return 0;
        }

        vhttp_parsed_request_t req;
        vhttp_parse_result_t pres = vhttp_parse_request((const char *)recv_buf, buffered, &req);
        if (pres == VHTTP_PARSE_INCOMPLETE) {
            if (buffered >= recv_cap) {
                send_simple_response(sock, 413, "Payload Too Large", 0, NULL);
                return 0;
            }
            int rc = vhttp_recv_with_timeout(
                sock,
                recv_buf + buffered,
                recv_cap - buffered,
                VHTTP_SERVER_IDLE_TIMEOUT_MS
            );
            if (rc < 0) {
                if (rc == -2) {
                    return 0;
                }
                return -1;
            }
            if (rc == 0) {
                return 0;
            }
            buffered += (size_t)rc;
            continue;
        }
        if (pres != VHTTP_PARSE_OK) {
            int status = 400;
            const char *body = "Bad Request";
            if (pres == VHTTP_PARSE_TOO_LARGE) {
                status = 413;
                body = "Payload Too Large";
            } else if (pres == VHTTP_PARSE_UNSUPPORTED) {
                status = 501;
                body = "Not Implemented";
            }
            send_simple_response(sock, status, body, 0, NULL);
            VHTTP_LOGW("parse error pres=%d status=%d", (int)pres, status);
            return 0;
        }

        served_requests++;
        vhttp_stats_inc(&g_server_stats.requests_started);

        int keep_alive = header_value_contains(&req, "connection", "close") ? 0 : 1;
        if (keep_alive && served_requests >= VHTTP_MAX_KEEPALIVE_REQUESTS) {
            keep_alive = 0;
        }
        // Under queue pressure, prefer connection turnover over long keep-alive
        // so workers can service waiting sockets instead of idling on one client.
        if (keep_alive && served_requests > 1 && g_accept_queue) {
            UBaseType_t queued = uxQueueMessagesWaiting(g_accept_queue);
            uint32_t pressure_threshold = 1;
            if (g_worker_count > 2) {
                pressure_threshold = (uint32_t)(g_worker_count / 2);
                if (pressure_threshold == 0) {
                    pressure_threshold = 1;
                }
            }
            if ((uint32_t)queued >= pressure_threshold) {
                keep_alive = 0;
            }
        }

        uint8_t method = VHTTP_METHOD_GET;
        if (method_from_str(req.method.ptr, req.method.len, &method) != 0) {
            send_simple_response(sock, 405, "Method Not Allowed", keep_alive, NULL);
            vhttp_log_http_response(&req, 405, keep_alive, "simple");
            if (!keep_alive) {
                return 0;
            }
            goto consume_next;
        }

        vhttp_log_http_request(&req, client_ip);

        if (vhttp_trusted_host_enabled()) {
            if (!vhttp_trusted_host_allowed(&req)) {
                send_simple_response(sock, 400, "Invalid Host", keep_alive, NULL);
                vhttp_log_http_response(&req, 400, keep_alive, "trusted-host");
                if (!keep_alive) {
                    return 0;
                }
                goto consume_next;
            }
        }

        const char *cors_origin = NULL;
        size_t cors_origin_len = 0;
        int cors_allowed = 0;
        size_t cors_headers_len = 0;
        char cors_headers[VHTTP_CORS_HEADER_MAX];
        cors_headers[0] = '\0';

        if (vhttp_cors_enabled()) {
            if (vhttp_cors_get_origin(&req, &cors_origin, &cors_origin_len)) {
                cors_allowed = vhttp_cors_origin_allowed(cors_origin, cors_origin_len);
                if (vhttp_cors_is_preflight(method, &req)) {
                    if (!cors_allowed) {
                        send_simple_response(sock, 403, "CORS Forbidden", keep_alive, NULL);
                        vhttp_log_http_response(&req, 403, keep_alive, "cors");
                        if (!keep_alive) {
                            return 0;
                        }
                        goto consume_next;
                    }
                    cors_headers_len = vhttp_cors_build_headers(
                        cors_headers,
                        sizeof(cors_headers),
                        &req,
                        cors_origin,
                        cors_origin_len,
                        1
                    );
                    send_simple_response(
                        sock,
                        204,
                        "",
                        keep_alive,
                        cors_headers_len > 0 ? cors_headers : NULL
                    );
                    vhttp_log_http_response(&req, 204, keep_alive, "cors-preflight");
                    if (!keep_alive) {
                        return 0;
                    }
                    goto consume_next;
                }
                if (cors_allowed) {
                    cors_headers_len = vhttp_cors_build_headers(
                        cors_headers,
                        sizeof(cors_headers),
                        &req,
                        cors_origin,
                        cors_origin_len,
                        0
                    );
                }
            }
        }
        const char *cors_extra = cors_headers_len > 0 ? cors_headers : NULL;

        if (vhttp_ratelimit_enabled()) {
            uint32_t retry_ms = 0;
            if (!vhttp_ratelimit_check(client_ip, &retry_ms)) {
                char rl_headers[VHTTP_CORS_HEADER_MAX + 64];
                size_t off = 0;
                if (cors_headers_len > 0) {
                    size_t copy_len = cors_headers_len;
                    if (copy_len >= sizeof(rl_headers)) {
                        copy_len = sizeof(rl_headers) - 1;
                    }
                    memcpy(rl_headers, cors_headers, copy_len);
                    off += copy_len;
                }
                uint32_t retry_sec = (retry_ms + 999u) / 1000u;
                int n = snprintf(
                    rl_headers + off,
                    sizeof(rl_headers) - off,
                    "Retry-After: %lu\r\n",
                    (unsigned long)retry_sec
                );
                if (n < 0 || (size_t)n >= sizeof(rl_headers) - off) {
                    rl_headers[0] = '\0';
                    send_simple_response(sock, 429, "Too Many Requests", keep_alive, cors_extra);
                } else {
                    send_simple_response(sock, 429, "Too Many Requests", keep_alive, rl_headers);
                }
                vhttp_log_http_response(&req, 429, keep_alive, "rate-limit");
                if (!keep_alive) {
                    return 0;
                }
                goto consume_next;
            }
        }

        int h2c_rc = vhttp_http2_try_h2c_upgrade(sock, client_ip, recv_buf, recv_cap, buffered, &req, 0u, 0u);
        if (h2c_rc == 2) {
            return VHTTP_CONN_HANDOFF;
        }
        if (h2c_rc != 0) {
            return 0;
        }

        if (method == VHTTP_METHOD_GET && ws_is_upgrade_request(&req)) {
            VHTTP_LOGI("ws upgrade requested");
            if (vhttp_spawn_ws_task(sock, recv_buf, (uint32_t)req.total_len) == 0) {
                return VHTTP_CONN_HANDOFF;
            }
            VHTTP_LOGW("ws handoff failed, falling back to inline handling");
            return ws_handle_connection(sock, &req);
        }

#if !VHTTP_STATIC_SERVE_VIA_IPC
        vhttp_static_match_t static_match;
        int static_hit = vhttp_static_resolve(req.path.ptr, req.path.len, &static_match);
        if (static_hit) {
            if (method != VHTTP_METHOD_GET && method != VHTTP_METHOD_HEAD) {
                send_simple_response(sock, 405, "Method Not Allowed", keep_alive, cors_extra);
                vhttp_log_http_response(&req, 405, keep_alive, "static");
                if (!keep_alive) {
                    return 0;
                }
                goto consume_next;
            }

            int sres = send_file_response(
                sock,
                &static_match,
                keep_alive,
                method == VHTTP_METHOD_HEAD,
                &req,
                cors_headers,
                cors_headers_len
            );
            if (sres == -2) {
                send_simple_response(sock, 404, "Not Found", keep_alive, cors_extra);
                vhttp_log_http_response(&req, 404, keep_alive, "static");
            } else if (sres != 0) {
                send_simple_response(sock, 500, "Internal Server Error", keep_alive, cors_extra);
                vhttp_log_http_response(&req, 500, keep_alive, "static");
            } else {
                vhttp_log_http_response(&req, 200, keep_alive, "static");
            }
            if (!keep_alive) {
                return 0;
            }
            goto consume_next;
        }
#endif

        vhttp_ipc_state_t *ipc = vhttp_ipc_default_state();
        if (!ipc) {
            send_simple_response(sock, 500, "IPC Unavailable", keep_alive, cors_extra);
            vhttp_log_http_response(&req, 500, keep_alive, "ipc");
            if (!keep_alive) {
                return 0;
            }
            goto consume_next;
        }

        uint32_t req_id = vhttp_next_request_id();

        uint32_t path_offset = 0;
        uint8_t *path_dst = NULL;
        uint16_t uri_len = req.uri.len;
        uint16_t query_len = req.query.len;
        uint32_t req_headers_len = 0;
        uint32_t req_body_len = req.body_len;

        if (uri_len == 0) {
            send_simple_response(sock, 400, "Bad Request", keep_alive, cors_extra);
            vhttp_log_http_response(&req, 400, keep_alive, "ipc");
            if (!keep_alive) {
                return 0;
            }
            goto consume_next;
        }

        for (uint8_t i = 0; i < req.num_headers; ++i) {
            const vhttp_header_t *hdr = &req.headers[i];
            req_headers_len += (uint32_t)hdr->name_len + 1u;
            req_headers_len += (uint32_t)hdr->value_len + 1u;
        }

        if (req_headers_len > 65535u) {
            send_simple_response(sock, 413, "Headers Too Large", keep_alive, cors_extra);
            vhttp_log_http_response(&req, 413, keep_alive, "ipc");
            if (!keep_alive) {
                return 0;
            }
            goto consume_next;
        }

        uint32_t request_blob_len = (uint32_t)uri_len + req_headers_len + req_body_len;
        if (request_blob_len == 0) {
            send_simple_response(sock, 400, "Bad Request", keep_alive, cors_extra);
            vhttp_log_http_response(&req, 400, keep_alive, "ipc");
            if (!keep_alive) {
                return 0;
            }
            goto consume_next;
        }

        if (vhttp_ipc_ring_alloc(&ipc->ring, request_blob_len, &path_offset, &path_dst) != 0) {
            vhttp_stats_inc(&g_server_stats.ipc_req_ring_alloc_fail);
            vhttp_stats_inc(&g_server_stats.backpressure_503_sent);
            /* Under overload, close the connection to avoid keep-alive retry storms. */
            send_simple_response(sock, 503, "Backpressure", 0, cors_extra);
            vhttp_log_http_response(&req, 503, 0, "ipc");
            return 0;
        }
        memcpy(path_dst, req.uri.ptr, uri_len);

        if (req_headers_len > 0) {
            uint8_t *hdr_dst = path_dst + uri_len;
            uint32_t hdr_written = 0;
            for (uint8_t i = 0; i < req.num_headers; ++i) {
                const vhttp_header_t *hdr = &req.headers[i];
                if (hdr->name_len > 0) {
                    memcpy(hdr_dst + hdr_written, hdr->name, hdr->name_len);
                    hdr_written += hdr->name_len;
                }
                hdr_dst[hdr_written++] = '\0';
                if (hdr->value_len > 0) {
                    memcpy(hdr_dst + hdr_written, hdr->value, hdr->value_len);
                    hdr_written += hdr->value_len;
                }
                hdr_dst[hdr_written++] = '\0';
            }
        }

        if (req_body_len > 0) {
            uint8_t *body_dst = path_dst + uri_len + req_headers_len;
            memcpy(body_dst, req.body, req_body_len);
        }

        vhttp_ipc_msg_t msg = {0};
        msg.request_id = req_id;
        msg.type = VHTTP_IPC_REQ_HTTP;
        msg.method = method;
        msg.uri_len = uri_len;
        msg.query_len = query_len;
        msg.headers_len = (uint16_t)req_headers_len;
        msg.headers_offset = req_headers_len > 0 ? (path_offset + uri_len) : 0;
        msg.body_len = req_body_len;
        msg.buffer_offset = path_offset;

        if (vhttp_ipc_queue_push_wait(&ipc->request_queue, &msg, VHTTP_SERVER_REQ_QUEUE_WAIT_MS) != 0) {
            vhttp_stats_inc(&g_server_stats.ipc_req_queue_push_fail);
            vhttp_stats_inc(&g_server_stats.backpressure_503_sent);
            vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
            send_simple_response(sock, 503, "Queue Full", 0, cors_extra);
            vhttp_log_http_response(&req, 503, 0, "ipc");
            return 0;
        }

        conn_state = VHTTP_CONN_STATE_WAIT_IPC;
        vhttp_stats_conn_state_hit(conn_state);
        vhttp_ipc_msg_t resp;
        uint32_t waited_ms = 0;
        int got_resp = 0;
        while (waited_ms < VHTTP_SERVER_RESP_TIMEOUT_MS) {
            if (vhttp_ipc_wait_response_for(ipc, req_id, VHTTP_SERVER_WAIT_IPC_SLICE_MS, &resp) == 0) {
                got_resp = 1;
                break;
            }
            waited_ms += VHTTP_SERVER_WAIT_IPC_SLICE_MS;
            vhttp_stats_inc(&g_server_stats.scheduler_yields);
            taskYIELD();
        }

        if (!got_resp) {
            vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
            send_simple_response(sock, 504, "Gateway Timeout", 0, cors_extra);
            vhttp_log_http_response(&req, 504, 0, "ipc");
            vhttp_stats_inc(&g_server_stats.ipc_wait_timeouts);
            return 0;
        }

        int head_only = (method == VHTTP_METHOD_HEAD);

        if (resp.flags & VHTTP_IPC_FLAG_STREAM) {
            conn_state = VHTTP_CONN_STATE_STREAM;
            vhttp_stats_conn_state_hit(conn_state);
            int sent_header = 0;
            int use_chunked = (resp.flags & VHTTP_IPC_FLAG_CHUNKED) && !head_only;
            vhttp_ipc_msg_t stream_resp = resp;
            uint32_t waited_ms = 0;
            uint32_t stream_chunk_budget = 0;

            for (;;) {
                uint32_t resp_body_len = stream_resp.body_len;
                const uint8_t *body_ptr = NULL;
                if (resp_body_len > 0) {
                    body_ptr = vhttp_ipc_ring_ptr(&ipc->ring, stream_resp.buffer_offset);
                    if (!body_ptr) {
                        vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
                        vhttp_ipc_ring_release(&ipc->ring, resp_body_len);
                        send_simple_response(sock, 500, "IPC Error", keep_alive, cors_extra);
                        return 0;
                    }
                }

                uint16_t resp_headers_len = stream_resp.headers_len;
                const uint8_t *headers_ptr = NULL;
                if (resp_headers_len > 0) {
                    headers_ptr = vhttp_ipc_ring_ptr(&ipc->ring, stream_resp.headers_offset);
                    if (!headers_ptr) {
                        vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
                        if (resp_body_len > 0) {
                            vhttp_ipc_ring_release(&ipc->ring, resp_body_len);
                        }
                        vhttp_ipc_ring_release(&ipc->ring, resp_headers_len);
                        send_simple_response(sock, 500, "IPC Error", keep_alive, cors_extra);
                        return 0;
                    }
                }

                if (!sent_header) {
                    int stream_status = stream_resp.status_code == 0 ? 200 : stream_resp.status_code;
                    vhttp_log_http_response(&req, stream_status, keep_alive, "ipc-stream");
                    char header[VHTTP_HEADER_BUF_SIZE];
                    const char *conn = keep_alive ? "keep-alive" : "close";
                    uint32_t total_len = stream_resp.total_len ? stream_resp.total_len : stream_resp.body_len;
                    int header_len = 0;
                    if (use_chunked) {
                        header_len = snprintf(
                            header,
                            sizeof(header),
                            "HTTP/1.1 %d %s\r\nTransfer-Encoding: chunked\r\n%.*s%.*sConnection: %s\r\n\r\n",
                            stream_resp.status_code == 0 ? 200 : stream_resp.status_code,
                            status_reason(stream_resp.status_code == 0 ? 200 : stream_resp.status_code),
                            (int)resp_headers_len,
                            resp_headers_len > 0 ? (const char *)headers_ptr : "",
                            (int)cors_headers_len,
                            cors_headers_len > 0 ? cors_headers : "",
                            conn
                        );
                    } else {
                        header_len = snprintf(
                            header,
                            sizeof(header),
                            "HTTP/1.1 %d %s\r\nContent-Length: %u\r\n%.*s%.*sConnection: %s\r\n\r\n",
                            stream_resp.status_code == 0 ? 200 : stream_resp.status_code,
                            status_reason(stream_resp.status_code == 0 ? 200 : stream_resp.status_code),
                            (unsigned int)total_len,
                            (int)resp_headers_len,
                            resp_headers_len > 0 ? (const char *)headers_ptr : "",
                            (int)cors_headers_len,
                            cors_headers_len > 0 ? cors_headers : "",
                            conn
                        );
                    }
                    if (header_len < 0 || (size_t)header_len >= sizeof(header)) {
                        vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
                        if (resp_body_len > 0) {
                            vhttp_ipc_ring_release(&ipc->ring, resp_body_len);
                        }
                        if (resp_headers_len > 0) {
                            vhttp_ipc_ring_release(&ipc->ring, resp_headers_len);
                        }
                        return -1;
                    }
                    if (send_all(sock, (const uint8_t *)header, (size_t)header_len) != 0) {
                        vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
                        if (resp_body_len > 0) {
                            vhttp_ipc_ring_release(&ipc->ring, resp_body_len);
                        }
                        if (resp_headers_len > 0) {
                            vhttp_ipc_ring_release(&ipc->ring, resp_headers_len);
                        }
                        return -1;
                    }
                    sent_header = 1;
                }

                if (!head_only && resp_body_len > 0) {
                    if (use_chunked) {
                        if (send_chunked_payload(sock, body_ptr, resp_body_len) != 0) {
                            vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
                            if (resp_body_len > 0) {
                                vhttp_ipc_ring_release(&ipc->ring, resp_body_len);
                            }
                            if (resp_headers_len > 0) {
                                vhttp_ipc_ring_release(&ipc->ring, resp_headers_len);
                            }
                            return -1;
                        }
                    } else {
                        if (send_all(sock, body_ptr, resp_body_len) != 0) {
                            vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
                            if (resp_body_len > 0) {
                                vhttp_ipc_ring_release(&ipc->ring, resp_body_len);
                            }
                            if (resp_headers_len > 0) {
                                vhttp_ipc_ring_release(&ipc->ring, resp_headers_len);
                            }
                            return -1;
                        }
                    }
                    vhttp_stats_inc(&g_server_stats.stream_chunks_sent);
                }

                if (resp_body_len > 0) {
                    vhttp_ipc_ring_release(&ipc->ring, resp_body_len);
                }
                if (resp_headers_len > 0) {
                    vhttp_ipc_ring_release(&ipc->ring, resp_headers_len);
                }

                if (stream_resp.flags & VHTTP_IPC_FLAG_FINAL) {
                    if (use_chunked && !head_only) {
                        if (send_chunked_payload(sock, NULL, 0) != 0) {
                            vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
                            return -1;
                        }
                    }
                    break;
                }

                stream_chunk_budget++;
                if (stream_chunk_budget >= VHTTP_SERVER_STREAM_FAIR_CHUNK_BUDGET) {
                    stream_chunk_budget = 0;
                    vhttp_stats_inc(&g_server_stats.scheduler_yields);
                    taskYIELD();
                }

                int got_next = 0;
                waited_ms = 0;
                while (waited_ms < VHTTP_SERVER_RESP_TIMEOUT_MS) {
                    if (vhttp_ipc_wait_response_for(ipc, req_id, VHTTP_SERVER_WAIT_IPC_SLICE_MS, &stream_resp) == 0) {
                        got_next = 1;
                        break;
                    }
                    waited_ms += VHTTP_SERVER_WAIT_IPC_SLICE_MS;
                    vhttp_stats_inc(&g_server_stats.scheduler_yields);
                    taskYIELD();
                }
                if (!got_next) {
                    vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
                    vhttp_stats_inc(&g_server_stats.ipc_wait_timeouts);
                    return -1;
                }
            }

            vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
        } else {
            uint32_t resp_body_len = resp.body_len;
            const uint8_t *body_ptr = NULL;
            if (resp_body_len > 0) {
                body_ptr = vhttp_ipc_ring_ptr(&ipc->ring, resp.buffer_offset);
                if (!body_ptr) {
                    vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
                    send_simple_response(sock, 500, "IPC Error", keep_alive, cors_extra);
                    if (!keep_alive) {
                        return 0;
                    }
                    goto consume_next;
                }
            }

            uint16_t resp_headers_len = resp.headers_len;
            const uint8_t *headers_ptr = NULL;
            if (resp_headers_len > 0) {
                headers_ptr = vhttp_ipc_ring_ptr(&ipc->ring, resp.headers_offset);
                if (!headers_ptr) {
                    vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
                    if (resp_body_len > 0) {
                        vhttp_ipc_ring_release(&ipc->ring, resp_body_len);
                    }
                    vhttp_ipc_ring_release(&ipc->ring, resp_headers_len);
                    send_simple_response(sock, 500, "IPC Error", keep_alive, cors_extra);
                    if (!keep_alive) {
                        return 0;
                    }
                    goto consume_next;
                }
            }

            char header[VHTTP_HEADER_BUF_SIZE];
            const char *conn = keep_alive ? "keep-alive" : "close";
            int final_status = resp.status_code == 0 ? 200 : resp.status_code;
            vhttp_log_http_response(&req, final_status, keep_alive, "ipc");
            int header_len = snprintf(
                header,
                sizeof(header),
                "HTTP/1.1 %d %s\r\nContent-Length: %u\r\n%.*s%.*sConnection: %s\r\n\r\n",
                resp.status_code == 0 ? 200 : resp.status_code,
                status_reason(resp.status_code == 0 ? 200 : resp.status_code),
                (unsigned int)resp_body_len,
                (int)resp_headers_len,
                resp_headers_len > 0 ? (const char *)headers_ptr : "",
                (int)cors_headers_len,
                cors_headers_len > 0 ? cors_headers : "",
                conn
            );
            if (header_len < 0 || (size_t)header_len >= sizeof(header)) {
                vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
                if (resp_body_len > 0) {
                    vhttp_ipc_ring_release(&ipc->ring, resp_body_len);
                }
                if (resp_headers_len > 0) {
                    vhttp_ipc_ring_release(&ipc->ring, resp_headers_len);
                }
                return -1;
            }

            if (send_all(sock, (const uint8_t *)header, (size_t)header_len) != 0) {
                vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
                if (resp_body_len > 0) {
                    vhttp_ipc_ring_release(&ipc->ring, resp_body_len);
                }
                if (resp_headers_len > 0) {
                    vhttp_ipc_ring_release(&ipc->ring, resp_headers_len);
                }
                return -1;
            }
            if (resp_body_len > 0 && method != VHTTP_METHOD_HEAD) {
                if (send_all(sock, body_ptr, resp_body_len) != 0) {
                    vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
                    if (resp_body_len > 0) {
                        vhttp_ipc_ring_release(&ipc->ring, resp_body_len);
                    }
                    if (resp_headers_len > 0) {
                        vhttp_ipc_ring_release(&ipc->ring, resp_headers_len);
                    }
                    return -1;
                }
            }

            vhttp_ipc_ring_release(&ipc->ring, request_blob_len);
            if (resp_body_len > 0) {
                vhttp_ipc_ring_release(&ipc->ring, resp_body_len);
            }
            if (resp_headers_len > 0) {
                vhttp_ipc_ring_release(&ipc->ring, resp_headers_len);
            }
        }

        if (!keep_alive) {
            return 0;
        }

consume_next:
        if (req.total_len >= buffered) {
            buffered = 0;
            continue;
        }
        memmove(recv_buf, recv_buf + req.total_len, buffered - req.total_len);
        buffered -= req.total_len;
    }
}

static void vhttp_server_worker_task(void *arg) {
    vhttp_worker_ctx_t *ctx = (vhttp_worker_ctx_t *)arg;
    if (!ctx) {
        vTaskDelete(NULL);
        return;
    }
    while (g_server_running) {
        vhttp_accepted_conn_t conn = {0};
        if (xQueueReceive(g_accept_queue, &conn, pdMS_TO_TICKS(100)) != pdTRUE) {
            continue;
        }
        if (!vhttp_socket_fd_valid(conn.sock)) {
            VHTTP_LOGW("drop invalid socket fd=%d", conn.sock);
            if (conn.sock >= 0) {
                vhttp_https_close_socket_if_open(conn.sock);
                close(conn.sock);
                vhttp_ev_conn_on_closed(conn.sock);
            }
            continue;
        }

        if (vhttp_https_enabled_runtime()) {
            if (vhttp_https_session_open(conn.sock) != 0) {
                VHTTP_LOGW("https handshake failed fd=%d", conn.sock);
                shutdown(conn.sock, SHUT_RDWR);
                vhttp_https_close_socket_if_open(conn.sock);
                close(conn.sock);
                vhttp_ev_conn_on_closed(conn.sock);
                continue;
            }
        }

        vhttp_ev_conn_on_dispatched(conn.sock);
        vhttp_stats_inc(&g_server_stats.workers_active);
        int hrc = handle_connection(ctx, conn.sock, conn.client_ip);
        vhttp_stats_inc(&g_server_stats.requests_handled);
        if (hrc < 0) {
            vhttp_stats_inc(&g_server_stats.request_errors);
        }
        taskENTER_CRITICAL(&g_stats_lock);
        if (g_server_stats.workers_active > 0) {
            g_server_stats.workers_active--;
        }
        taskEXIT_CRITICAL(&g_stats_lock);
        if (hrc != VHTTP_CONN_HANDOFF) {
            if (hrc < 0) {
                shutdown(conn.sock, SHUT_RDWR);
            }
            vhttp_https_close_socket_if_open(conn.sock);
            close(conn.sock);
        }
        vhttp_ev_conn_on_closed(conn.sock);
    }
    vTaskDelete(NULL);
}

static int vhttp_server_workers_start(void) {
    memset(g_worker_tasks, 0, sizeof(g_worker_tasks));
    memset(g_worker_ctx, 0, sizeof(g_worker_ctx));
    g_worker_count = 0;
    g_worker_scale_last_tick = 0;
    g_worker_scale_block_until = 0;

    size_t max_workers = vhttp_server_target_max_workers();
    size_t min_workers = vhttp_server_target_min_workers();
    size_t failed_attempts = 0;
    size_t max_failed_attempts = (min_workers * 3u) + 2u;
    while (g_worker_count < min_workers && failed_attempts < max_failed_attempts) {
        size_t next = g_worker_count;
        if (vhttp_server_start_worker_at(next) == 0) {
            failed_attempts = 0;
            continue;
        }
        failed_attempts++;
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    if (g_worker_count < min_workers) {
        VHTTP_LOGW(
            "worker warm-start partial started=%u min=%u fail_attempts=%u",
            (unsigned int)g_worker_count,
            (unsigned int)min_workers,
            (unsigned int)failed_attempts
        );
    }
    if (g_worker_count == 0) {
        VHTTP_LOGE("worker create failed: zero workers");
        return -1;
    }
    VHTTP_LOGI(
        "worker pool active=%u min=%u max=%u",
        (unsigned int)g_worker_count,
        (unsigned int)min_workers,
        (unsigned int)max_workers
    );
    return 0;
}

static void vhttp_server_workers_stop(void) {
    for (size_t i = 0; i < g_worker_count; ++i) {
        g_worker_tasks[i] = NULL;
    }
    for (size_t i = 0; i < (size_t)VHTTP_SERVER_WORKERS; ++i) {
        vhttp_worker_buffer_free(i);
        g_worker_ctx[i].index = 0;
    }
    g_worker_count = 0;
    g_worker_scale_last_tick = 0;
    g_worker_scale_block_until = 0;
}

static void vhttp_server_task(void *arg) {
    vhttp_server_start_args_t *args = (vhttp_server_start_args_t *)arg;
    int port = args ? (int)args->port : 0;
    TaskHandle_t caller = args ? args->caller : NULL;
    uint8_t https_mode = vhttp_https_enabled_runtime();
    uint8_t http2_mode = vhttp_http2_enabled_runtime();

    g_listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (g_listen_fd < 0) {
        VHTTP_LOGE("server socket failed");
        g_server_running = 0;
        g_server_starting = 0;
        if (caller) {
            xTaskNotify(caller, VHTTP_SERVER_START_ERR_SOCKET, eSetValueWithOverwrite);
        }
        g_listen_fd = -1;
        vTaskDelete(NULL);
        return;
    }

    int opt = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        VHTTP_LOGE("server bind failed port=%d", port);
        close(g_listen_fd);
        g_listen_fd = -1;
        g_server_running = 0;
        g_server_starting = 0;
        if (caller) {
            xTaskNotify(caller, VHTTP_SERVER_START_ERR_BIND, eSetValueWithOverwrite);
        }
        vTaskDelete(NULL);
        return;
    }

    int listen_backlog = VHTTP_SERVER_ACCEPT_QUEUE_LEN;
    if (listen_backlog < 4) {
        listen_backlog = 4;
    }
    if (listen(g_listen_fd, listen_backlog) < 0) {
        VHTTP_LOGE("server listen failed");
        close(g_listen_fd);
        g_listen_fd = -1;
        g_server_running = 0;
        g_server_starting = 0;
        if (caller) {
            xTaskNotify(caller, VHTTP_SERVER_START_ERR_LISTEN, eSetValueWithOverwrite);
        }
        vTaskDelete(NULL);
        return;
    }

    g_accept_queue = xQueueCreateStatic(
        VHTTP_SERVER_ACCEPT_QUEUE_LEN,
        sizeof(vhttp_accepted_conn_t),
        g_accept_queue_buf,
        &g_accept_queue_storage
    );
    if (!g_accept_queue) {
        VHTTP_LOGE("accept queue init failed");
        close(g_listen_fd);
        g_listen_fd = -1;
        g_server_running = 0;
        g_server_starting = 0;
        if (caller) {
            xTaskNotify(caller, VHTTP_SERVER_START_ERR_SOCKET, eSetValueWithOverwrite);
        }
        vTaskDelete(NULL);
        return;
    }

    g_resp_mux = xSemaphoreCreateMutexStatic(&g_resp_mux_storage);
    if (!g_resp_mux) {
        VHTTP_LOGE("response mux init failed");
        g_accept_queue = NULL;
        close(g_listen_fd);
        g_listen_fd = -1;
        g_server_running = 0;
        g_server_starting = 0;
        if (caller) {
            xTaskNotify(caller, VHTTP_SERVER_START_ERR_SOCKET, eSetValueWithOverwrite);
        }
        vTaskDelete(NULL);
        return;
    }

    g_waiter_mux = xSemaphoreCreateMutexStatic(&g_waiter_mux_storage);
    if (!g_waiter_mux) {
        VHTTP_LOGE("waiter mux init failed");
        g_resp_mux = NULL;
        g_accept_queue = NULL;
        close(g_listen_fd);
        g_listen_fd = -1;
        g_server_running = 0;
        g_server_starting = 0;
        if (caller) {
            xTaskNotify(caller, VHTTP_SERVER_START_ERR_SOCKET, eSetValueWithOverwrite);
        }
        vTaskDelete(NULL);
        return;
    }

    g_server_running = 1;
    if (http2_mode) {
        if (vhttp_http2_prepare_slots() != 0) {
            VHTTP_LOGE("http2 slot init failed");
            g_server_running = 0;
            g_waiter_mux = NULL;
            g_resp_mux = NULL;
            g_accept_queue = NULL;
            close(g_listen_fd);
            g_listen_fd = -1;
            g_server_starting = 0;
            if (caller) {
                xTaskNotify(caller, VHTTP_SERVER_START_ERR_SOCKET, eSetValueWithOverwrite);
            }
            vTaskDelete(NULL);
            return;
        }
        if (vhttp_http2_hpack_huff_prepare() != 0) {
            VHTTP_LOGE("http2 hpack init failed");
            g_server_running = 0;
            g_waiter_mux = NULL;
            g_resp_mux = NULL;
            g_accept_queue = NULL;
            vhttp_http2_free_slots();
            close(g_listen_fd);
            g_listen_fd = -1;
            g_server_starting = 0;
            if (caller) {
                xTaskNotify(caller, VHTTP_SERVER_START_ERR_SOCKET, eSetValueWithOverwrite);
            }
            vTaskDelete(NULL);
            return;
        }
    }
    if (https_mode) {
        if (vhttp_https_server_init() != 0) {
            VHTTP_LOGE("https init failed");
            g_server_running = 0;
            g_waiter_mux = NULL;
            g_resp_mux = NULL;
            g_accept_queue = NULL;
            vhttp_http2_free_slots();
            close(g_listen_fd);
            g_listen_fd = -1;
            g_server_starting = 0;
            if (caller) {
                xTaskNotify(caller, VHTTP_SERVER_START_ERR_SOCKET, eSetValueWithOverwrite);
            }
            vTaskDelete(NULL);
            return;
        }
    }
    vhttp_ev_conn_reset();
    taskENTER_CRITICAL(&g_stats_lock);
    g_server_stats.event_loop_enabled = VHTTP_HTTP_EVENT_LOOP ? 1u : 0u;
    g_server_stats.https_enabled = https_mode ? 1u : 0u;
    g_server_stats.http2_enabled = http2_mode ? 1u : 0u;
    g_server_stats.http2_psram_slots = (http2_mode && g_http2_stream_slots_in_psram) ? 1u : 0u;
    taskEXIT_CRITICAL(&g_stats_lock);
    vhttp_resp_waiters_reset();
    if (vhttp_server_dispatcher_start() != 0) {
        VHTTP_LOGE("response dispatcher init failed");
        g_server_running = 0;
        g_waiter_mux = NULL;
        g_resp_mux = NULL;
        g_accept_queue = NULL;
        vhttp_https_server_deinit();
        vhttp_http2_free_slots();
        close(g_listen_fd);
        g_listen_fd = -1;
        g_server_starting = 0;
        if (caller) {
            xTaskNotify(caller, VHTTP_SERVER_START_ERR_SOCKET, eSetValueWithOverwrite);
        }
        vTaskDelete(NULL);
        return;
    }

    if (!VHTTP_HTTP_EVENT_LOOP) {
        if (vhttp_server_workers_start() != 0) {
            VHTTP_LOGE("worker pool init failed");
            g_server_running = 0;
            g_resp_dispatcher_task = NULL;
            g_waiter_mux = NULL;
            g_resp_mux = NULL;
            g_accept_queue = NULL;
            vhttp_https_server_deinit();
            vhttp_http2_free_slots();
            close(g_listen_fd);
            g_listen_fd = -1;
            g_server_starting = 0;
            if (caller) {
                xTaskNotify(caller, VHTTP_SERVER_START_ERR_SOCKET, eSetValueWithOverwrite);
            }
            vTaskDelete(NULL);
            return;
        }
    } else {
        g_worker_count = 0;
    }

    g_server_starting = 0;
    VHTTP_LOGI(
        "server started port=%d workers=%u mode=%s",
        port,
        (unsigned int)g_worker_count,
        (VHTTP_HTTP_EVENT_LOOP
            ? (https_mode ? "https-event-loop-stage-b" : "event-loop-stage-b")
            : (https_mode ? "https-worker-compat" : "worker-compat"))
    );
    if (caller) {
        xTaskNotify(caller, VHTTP_SERVER_START_OK, eSetValueWithOverwrite);
    }

    if (VHTTP_HTTP_EVENT_LOOP) {
        (void)vhttp_server_event_loop_run();
    } else {
        while (g_server_running) {
            struct sockaddr_in client_addr;
            socklen_t socklen = sizeof(client_addr);
            int sock = accept(g_listen_fd, (struct sockaddr *)&client_addr, &socklen);
            if (sock < 0) {
                if (!g_server_running) {
                    break;
                }
                vTaskDelay(pdMS_TO_TICKS(10));
                continue;
            }
            if (!vhttp_socket_fd_valid(sock)) {
                VHTTP_LOGW("reject socket outside select range fd=%d", sock);
                close(sock);
                continue;
            }
            vhttp_stats_inc(&g_server_stats.accepts_total);

            if (vhttp_set_socket_nonblocking(sock) != 0) {
                VHTTP_LOGW("failed to set nonblocking socket");
                shutdown(sock, SHUT_RDWR);
                close(sock);
                continue;
            }

            uint32_t client_ip = 0;
            if (client_addr.sin_family == AF_INET) {
                client_ip = (uint32_t)client_addr.sin_addr.s_addr;
            }
            vhttp_ev_conn_on_accept(sock, client_ip);
            vhttp_accepted_conn_t conn = {
                .sock = sock,
                .client_ip = client_ip,
            };
            BaseType_t enqueued = xQueueSend(g_accept_queue, &conn, 0);
            if (enqueued != pdTRUE) {
                vhttp_server_try_scale_workers();
                enqueued = xQueueSend(g_accept_queue, &conn, pdMS_TO_TICKS(1));
            } else {
                vhttp_server_try_scale_workers();
            }

            if (enqueued != pdTRUE) {
                VHTTP_LOGW("accept queue full, rejecting socket");
                vhttp_stats_inc(&g_server_stats.accepts_rejected);
                (void)send_simple_response(sock, 503, "Server Busy", 0, NULL);
                shutdown(sock, SHUT_RDWR);
                close(sock);
                vhttp_ev_conn_on_closed(sock);
            } else {
                vhttp_stats_inc(&g_server_stats.accepts_enqueued);
                UBaseType_t q_used = uxQueueMessagesWaiting(g_accept_queue);
                taskENTER_CRITICAL(&g_stats_lock);
                g_server_stats.accept_queue_used = (uint32_t)q_used;
                if ((uint32_t)q_used > g_server_stats.accept_queue_peak) {
                    g_server_stats.accept_queue_peak = (uint32_t)q_used;
                }
                taskEXIT_CRITICAL(&g_stats_lock);
            }
        }
    }

    if (g_listen_fd >= 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
    }
    vhttp_server_workers_stop();
    vhttp_resp_waiters_reset();
    g_resp_dispatcher_task = NULL;
    g_waiter_mux = NULL;
    g_accept_queue = NULL;
    g_resp_mux = NULL;
    VHTTP_LOGI("server stopped");
    vhttp_pending_resp_reset();
    vhttp_ev_conn_reset();
    vhttp_wait_ws_tasks_quiesce(2000);
    vhttp_https_server_deinit();
    vhttp_http2_free_slots();
    g_server_running = 0;
    g_server_starting = 0;
    g_server_task = NULL;
    vTaskDelete(NULL);
}

static void vhttp_https_cfg_clear_locked(void) {
    g_https_cfg.cert_pem = NULL;
    g_https_cfg.key_pem = NULL;
    g_https_cfg.enabled = 0;
    g_https_cfg.cert_pem_len = 0;
    g_https_cfg.key_pem_len = 0;
}

static void vhttp_http2_cfg_clear_locked(void) {
    g_http2_cfg.enabled = 0;
    g_http2_cfg.max_streams = 0;
}

int vhttp_server_configure_https(const vhttp_https_config_t *cfg) {
    if (!cfg) {
        return -1;
    }
    if (g_server_running || g_server_starting) {
        return -2;
    }

    uint8_t enabled = cfg->enabled ? 1u : 0u;
    char *cert_dup = NULL;
    char *key_dup = NULL;
    size_t cert_len = 0;
    size_t key_len = 0;

    if (enabled) {
        if (!cfg->cert_pem || !cfg->key_pem) {
            return -1;
        }
        cert_len = cfg->cert_pem_len;
        key_len = cfg->key_pem_len;
        if (cert_len == 0 || key_len == 0) {
            return -1;
        }
        cert_dup = (char *)malloc(cert_len + 1u);
        key_dup = (char *)malloc(key_len + 1u);
        if (!cert_dup || !key_dup) {
            if (cert_dup) {
                free(cert_dup);
            }
            if (key_dup) {
                free(key_dup);
            }
            return -1;
        }
        memcpy(cert_dup, cfg->cert_pem, cert_len);
        cert_dup[cert_len] = '\0';
        memcpy(key_dup, cfg->key_pem, key_len);
        key_dup[key_len] = '\0';
        cert_len += 1u;
        key_len += 1u;
    }

    char *old_cert = NULL;
    char *old_key = NULL;
    taskENTER_CRITICAL(&g_https_cfg_lock);
    old_cert = g_https_cfg.cert_pem;
    old_key = g_https_cfg.key_pem;
    vhttp_https_cfg_clear_locked();
    if (enabled) {
        g_https_cfg.enabled = 1u;
        g_https_cfg.cert_pem = cert_dup;
        g_https_cfg.cert_pem_len = cert_len;
        g_https_cfg.key_pem = key_dup;
        g_https_cfg.key_pem_len = key_len;
    }
    taskEXIT_CRITICAL(&g_https_cfg_lock);
    if (old_cert) {
        free(old_cert);
    }
    if (old_key) {
        free(old_key);
    }
    return 0;
}

int vhttp_server_configure_http2(const vhttp_http2_config_t *cfg) {
    if (!cfg) {
        return -1;
    }
    if (g_server_running || g_server_starting) {
        return -2;
    }
    uint8_t enabled = cfg->enabled ? 1u : 0u;
    uint16_t max_streams = cfg->max_streams;
    if (enabled && max_streams == 0) {
        max_streams = 8;
    }
    if (enabled && max_streams > 64) {
        return -1;
    }
    taskENTER_CRITICAL(&g_http2_cfg_lock);
    vhttp_http2_cfg_clear_locked();
    if (enabled) {
        g_http2_cfg.enabled = 1u;
        g_http2_cfg.max_streams = max_streams;
    }
    taskEXIT_CRITICAL(&g_http2_cfg_lock);
    return 0;
}

void vhttp_server_get_https_status(uint8_t *out_configured, uint8_t *out_active) {
    if (out_configured) {
        *out_configured = 0;
    }
    if (out_active) {
        *out_active = 0;
    }
    taskENTER_CRITICAL(&g_https_cfg_lock);
    uint8_t configured = (g_https_cfg.enabled && g_https_cfg.cert_pem && g_https_cfg.key_pem) ? 1u : 0u;
    taskEXIT_CRITICAL(&g_https_cfg_lock);
    if (out_configured) {
        *out_configured = configured;
    }
    if (out_active) {
        *out_active = g_https_server.initialized ? 1u : 0u;
    }
}

void vhttp_server_get_http2_status(uint8_t *out_configured, uint8_t *out_runtime_enabled) {
    if (out_configured) {
        *out_configured = 0;
    }
    if (out_runtime_enabled) {
        *out_runtime_enabled = 0;
    }
    uint8_t configured = 0;
    taskENTER_CRITICAL(&g_http2_cfg_lock);
    configured = g_http2_cfg.enabled ? 1u : 0u;
    taskEXIT_CRITICAL(&g_http2_cfg_lock);
    if (out_configured) {
        *out_configured = configured;
    }
    if (out_runtime_enabled) {
        *out_runtime_enabled = (configured && g_server_running) ? 1u : 0u;
    }
}

int vhttp_server_start(uint16_t port) {
    if (g_server_running || g_server_starting) {
        VHTTP_LOGW("server start ignored; already running");
        return -1;
    }

    taskENTER_CRITICAL(&g_req_id_lock);
    g_request_id = 0;
    taskEXIT_CRITICAL(&g_req_id_lock);
    vhttp_server_reset_stats();
    vhttp_pending_resp_reset();
    vhttp_resp_waiters_reset();
    g_server_starting = 1;
    g_start_args.port = port;
    g_start_args.caller = xTaskGetCurrentTaskHandle();

    BaseType_t ok = xTaskCreatePinnedToCore(
        vhttp_server_task,
        "vhttp_server",
        VHTTP_SERVER_ACCEPTOR_STACK_SIZE,
        &g_start_args,
        VHTTP_SERVER_TASK_PRIO,
        &g_server_task,
        0
    );

    if (ok != pdPASS) {
        VHTTP_LOGE("server task create failed");
        g_server_running = 0;
        g_server_starting = 0;
        g_server_task = NULL;
        return -2;
    }

    uint32_t status = 0;
    if (xTaskNotifyWait(0, UINT32_MAX, &status, pdMS_TO_TICKS(VHTTP_SERVER_START_TIMEOUT_MS)) != pdTRUE) {
        VHTTP_LOGE("server start timeout");
        g_server_running = 0;
        g_server_starting = 0;
        vhttp_server_stop();
        return -2;
    }

    if (status != VHTTP_SERVER_START_OK) {
        VHTTP_LOGE("server start failed status=%lu", (unsigned long)status);
        g_server_running = 0;
        g_server_starting = 0;
        return -2;
    }

    return 0;
}

void vhttp_server_stop(void) {
    g_server_running = 0;
    g_server_starting = 0;
    if (g_listen_fd >= 0) {
        shutdown(g_listen_fd, SHUT_RDWR);
        close(g_listen_fd);
        g_listen_fd = -1;
    }
}

uint8_t vhttp_server_is_running(void) {
    return g_server_running ? 1 : 0;
}

int vhttp_server_set_worker_limits(uint16_t min_workers, uint16_t max_workers) {
    size_t min_value = (size_t)min_workers;
    size_t max_value = (size_t)max_workers;
    if (min_value == 0 || max_value == 0) {
        return -1;
    }
    if (min_value > max_value || max_value > (size_t)VHTTP_SERVER_WORKERS) {
        return -1;
    }
    if (g_server_running || g_server_starting) {
        return -2;
    }
    taskENTER_CRITICAL(&g_worker_cfg_lock);
    g_worker_limit_min = min_value;
    g_worker_limit_max = max_value;
    taskEXIT_CRITICAL(&g_worker_cfg_lock);
    return 0;
}

void vhttp_server_get_worker_limits(uint16_t *out_min_workers, uint16_t *out_max_workers) {
    size_t min_value = 1;
    size_t max_value = (size_t)VHTTP_SERVER_WORKERS;
    taskENTER_CRITICAL(&g_worker_cfg_lock);
    min_value = g_worker_limit_min;
    max_value = g_worker_limit_max;
    taskEXIT_CRITICAL(&g_worker_cfg_lock);

    if (max_value == 0 || max_value > (size_t)VHTTP_SERVER_WORKERS) {
        max_value = (size_t)VHTTP_SERVER_WORKERS;
    }
    if (min_value == 0) {
        min_value = 1;
    }
    if (min_value > max_value) {
        min_value = max_value;
    }

    if (out_min_workers) {
        *out_min_workers = (uint16_t)min_value;
    }
    if (out_max_workers) {
        *out_max_workers = (uint16_t)max_value;
    }
}

void vhttp_server_get_stats(vhttp_server_stats_t *out) {
    if (!out) {
        return;
    }
    taskENTER_CRITICAL(&g_stats_lock);
    *out = g_server_stats;
    taskEXIT_CRITICAL(&g_stats_lock);

    uint32_t pending_used = 0;
    if (g_resp_mux && xSemaphoreTake(g_resp_mux, pdMS_TO_TICKS(5)) == pdTRUE) {
        pending_used = vhttp_pending_resp_used_nolock();
        xSemaphoreGive(g_resp_mux);
    }
    out->ipc_pending_used = pending_used;
    out->workers_started = (uint32_t)g_worker_count;
    out->workers_limit_min = (uint32_t)vhttp_server_target_min_workers();
    out->workers_limit_max = (uint32_t)vhttp_server_target_max_workers();
    uint32_t recv_psram = 0;
    uint32_t recv_ram = 0;
    for (size_t i = 0; i < g_worker_count && i < VHTTP_SERVER_WORKERS; ++i) {
        if (!g_worker_ctx[i].recv_buf) {
            continue;
        }
        if (g_worker_ctx[i].recv_in_psram) {
            recv_psram++;
        } else {
            recv_ram++;
        }
    }
    out->workers_recv_psram = recv_psram;
    out->workers_recv_ram = recv_ram;

    uint32_t accept_used = 0;
    if (g_accept_queue) {
        accept_used = (uint32_t)uxQueueMessagesWaiting(g_accept_queue);
    }
    out->accept_queue_used = accept_used;
    if (accept_used > out->accept_queue_peak) {
        out->accept_queue_peak = accept_used;
    }

    taskENTER_CRITICAL(&g_ev_conn_lock);
    uint32_t ev_active = vhttp_ev_conn_active_count_nolock();
    uint32_t ev_peak = g_ev_conn_peak;
    taskEXIT_CRITICAL(&g_ev_conn_lock);
    out->https_enabled = g_https_server.initialized ? 1u : 0u;
    out->http2_enabled = vhttp_http2_enabled_runtime() ? 1u : 0u;
    out->http2_psram_slots = g_http2_stream_slots_in_psram ? 1u : 0u;
    out->event_loop_enabled = VHTTP_HTTP_EVENT_LOOP ? 1u : 0u;
    out->event_conn_active = ev_active;
    if (ev_peak > out->event_conn_peak) {
        out->event_conn_peak = ev_peak;
    }
}

void vhttp_server_reset_stats(void) {
    taskENTER_CRITICAL(&g_stats_lock);
    memset(&g_server_stats, 0, sizeof(g_server_stats));
    taskEXIT_CRITICAL(&g_stats_lock);
    taskENTER_CRITICAL(&g_ev_conn_lock);
    g_ev_conn_peak = vhttp_ev_conn_active_count_nolock();
    taskEXIT_CRITICAL(&g_ev_conn_lock);
}

#else

int vhttp_server_start(uint16_t port) {
    (void)port;
    return -1;
}

void vhttp_server_stop(void) {
}

uint8_t vhttp_server_is_running(void) {
    return 0;
}

int vhttp_server_configure_https(const vhttp_https_config_t *cfg) {
    (void)cfg;
    return -1;
}

void vhttp_server_get_https_status(uint8_t *out_configured, uint8_t *out_active) {
    if (out_configured) {
        *out_configured = 0;
    }
    if (out_active) {
        *out_active = 0;
    }
}

int vhttp_server_configure_http2(const vhttp_http2_config_t *cfg) {
    (void)cfg;
    return -1;
}

void vhttp_server_get_http2_status(uint8_t *out_configured, uint8_t *out_runtime_enabled) {
    if (out_configured) {
        *out_configured = 0;
    }
    if (out_runtime_enabled) {
        *out_runtime_enabled = 0;
    }
}

int vhttp_server_set_worker_limits(uint16_t min_workers, uint16_t max_workers) {
    (void)min_workers;
    (void)max_workers;
    return -1;
}

void vhttp_server_get_worker_limits(uint16_t *out_min_workers, uint16_t *out_max_workers) {
    if (out_min_workers) {
        *out_min_workers = 1;
    }
    if (out_max_workers) {
        *out_max_workers = 1;
    }
}

void vhttp_server_get_stats(vhttp_server_stats_t *out) {
    if (!out) {
        return;
    }
    memset(out, 0, sizeof(*out));
}

void vhttp_server_reset_stats(void) {
}

#endif

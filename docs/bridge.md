# ViperHTTP IPC Bridge (MicroPython)

This bridge connects Core 0 (C server) with Core 1 (MicroPython) using the IPC queues.
It polls incoming requests, dispatches them via the ViperHTTP app, serializes responses,
and sends them back through IPC.

For normal applications, you do not need to import this module directly.
`app.run(...)` starts bridge runtime automatically.

## Optional Manual Example

```python
import viperhttp
import viperhttp_bridge

app = viperhttp.ViperHTTP()

@app.get("/hello")
def hello():
    return {"msg": "ok"}

@app.get("/plain")
def plain():
    return "hello"

viperhttp_bridge.run(app, port=8080, wifi=False)
```

## Wi-Fi + app.run()
`app.run()` uses the bridge and starts the C server automatically, but it does not connect to Wi-Fi.
Connect first, then run:

```python
import network
import viperhttp

wlan = network.WLAN(network.STA_IF)
wlan.active(True)
wlan.connect("SSID", "PASSWORD")
while not wlan.isconnected():
    pass

app = viperhttp.ViperHTTP()

@app.get("/hello")
def hello():
    return {"message": "ok"}

app.run(port=8080, wifi=False)
```

## IPC Request Payload Layout
The request IPC message carries offsets and lengths for a contiguous blob in the ring buffer:

- `buffer_offset`: start of the blob
- `uri_len`: length of the raw URI (path + optional `?query`)
- `query_len`: length of the query string (no leading `?`)
- `headers_len`: length of the headers blob
- `headers_offset`: start of the headers blob
- `body_len`: length of the raw body

Blob layout:
`[URI][HEADERS][BODY]`

Headers blob encoding:
`name\0value\0name\0value\0...`

## IPC Response Payload Layout
Responses use the same ring buffer for headers and body:

- `headers_len` + `headers_offset`: header blob (`Name: value\r\n` lines).
- `body_len` + `buffer_offset`: response body bytes.
- `total_len`: total body length for streamed responses (Content-Length).
- `flags`: `VHTTP_IPC_FLAG_STREAM` + `VHTTP_IPC_FLAG_FINAL` mark streaming chunks.

Streaming behavior:
- The first response for a request includes headers and `total_len`.
- Subsequent chunks include only `body_len` and `buffer_offset`.
- The final chunk sets `VHTTP_IPC_FLAG_FINAL`.

## Notes
- `serialize_response()` converts dict/list to JSON using `ujson`.
- Body sent over IPC must be `str`, `bytes`, or `bytearray`.
- This bridge is intentionally minimal and will evolve alongside IPC.
- `viperhttp.poll_request()` now includes a `request` object with headers, query params, and body bytes.
- The bridge passes `request` into `app.dispatch(method, path, request)` and exposes it via `viperhttp.current_request()`.
- Query params are parsed from the URL and passed to handlers as kwargs.
- Typed query params are supported via `Query()` and `query={...}` in decorators.
- Query strings are not URL-decoded.
- Async handlers and async middleware are awaited in the bridge loop.
- Async stream responses are supported (`async for` body chunks over IPC stream frames).
- Bridge worker tuning is available in `viperhttp_bridge.run(...)`:
  - `bridge_min_workers`, `bridge_max_workers`, `bridge_queue_size`
  - `bridge_autoscale` (optional; defaults to `True` when `bridge_max_workers > bridge_min_workers`)
  - `bridge_enqueue_wait_ms` (bounded wait when queue is full before returning overload)
  - `bridge_worker_yield_every` (worker cooperative-yield cadence for better throughput/fairness balance)
  - `bridge_scale_up_max_burst` (max workers spawned in one scale-up cycle)
  - `min_workers`, `max_workers` (C runtime worker limits API)
- Bridge dispatcher behavior:
  - If `bridge_min_workers == bridge_max_workers`, bridge workers stay fixed.
  - If `bridge_min_workers < bridge_max_workers`, bridge can scale up under queue pressure and scale back to `bridge_min_workers` after idle periods.
  - Queue size is clamped to at least `bridge_max_workers`.
- Background tasks are lazy-allocated in the bridge hot path, so requests that do not use
  `background_tasks.add_task(...)` avoid unnecessary object allocation overhead.
- Under load, the C event-loop runtime may defer request queue push and retry asynchronously
  before returning `503 Queue Full` (reduces burst-time drops without blocking the event-loop).

## Startup Hook (ESP32S3_N16R8)
For the custom board build, a frozen `main.py` is included. It attempts to import
`viperhttp_app` and start the bridge automatically if an `app` object is present.

Create `viperhttp_app.py` on the device with:

```python
import viperhttp

app = viperhttp.ViperHTTP()

@app.get("/hello")
def hello():
    return {"msg": "ok"}
```

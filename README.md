<p align="center">
  <img src="assets/banner.svg" alt="ViperHTTP" width="800">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/MicroPython-%E2%89%A51.24-green.svg" alt="MicroPython">
  <img src="https://img.shields.io/badge/platform-ESP32-orange.svg" alt="ESP32">
  <img src="https://img.shields.io/badge/HTTP%2F2-ready-blueviolet.svg" alt="HTTP/2">
  <a href="https://mateuszsury.github.io/ViperHTTP/"><img src="https://img.shields.io/badge/docs-GitHub%20Pages-58A6FF.svg" alt="Docs"></a>
  <a href="CONTRIBUTING.md"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome"></a>
</p>

<p align="center">
  <b>Blazing-fast async HTTP server for MicroPython on ESP32.</b><br>
  Native C core + FastAPI-style Python API. Dual-core architecture. ~6200 LOC Python, 34 C source files.
</p>

---

## Why ViperHTTP?

ViperHTTP splits work across both ESP32 cores: a **native C runtime** handles parsing, routing, static file serving, and TLS on Core 0, while **MicroPython** runs your application logic with a FastAPI-style API on Core 1.

- **Dual-Core C + Python** — Performance-critical path in C, developer-facing API in Python
- **FastAPI-Style DX** — Decorators, `Depends()`, typed params, router groups, middleware chain
- **HTTPS + HTTP/2** — TLS transport, HPACK compression, stream multiplexing
- **WebSocket** — Real-time bidirectional communication with rooms and broadcast
- **Security Stack** — Sessions, CSRF, auth backends, trusted host, rate limiting
- **OTA Updates** — SHA256-verified over-the-air firmware with begin/write/finalize flow
- **Auto API Docs** — OpenAPI 3.0 schema generation + interactive Swagger/ReDoc UI
- **Template Engine** — C-native engine with caching, loops, conditionals, includes
- **SSE + Streaming** — Server-sent events, chunked transfer, file streaming, range requests
- **Async First** — uasyncio event loop, async generators, non-blocking I/O

## Architecture

<p align="center">
  <img src="assets/architecture.svg" alt="Architecture" width="700">
</p>

| Core | Runtime | Modules | Responsibility |
|------|---------|---------|----------------|
| **0** | C / FreeRTOS | `vhttp_parser` `vhttp_router` `vhttp_static` `vhttp_ipc` `vhttp_cors` `vhttp_ratelimit` | HTTP parsing, routing, static serving, TLS, CORS, rate limiting |
| **1** | MicroPython | `viperhttp_bridge` `viperhttp_app` `viperhttp_session` `viperhttp_auth` `viperhttp_ws` | Request dispatch, middleware, DI, sessions, auth, WebSocket |
| **IPC** | FreeRTOS Queue | `vhttp_ipc` ↔ `viperhttp_bridge` | Lock-free inter-core request/response passing |

## Quick Start

```python
import network
import viperhttp

# Connect to WiFi
wlan = network.WLAN(network.STA_IF)
wlan.active(True)
wlan.connect("SSID", "PASSWORD")
while not wlan.isconnected():
    pass

# Create application
app = viperhttp.ViperHTTP(title="Device API", version="1.0.0")

@app.get("/hello")
def hello():
    return {"message": "Hello from ESP32!"}

@app.get("/items/{item_id:int}")
def get_item(item_id=0):
    return {"item_id": item_id, "name": f"Item {item_id}"}

# Start the server — bridge and runtime are automatic
app.run(port=8080, wifi=False)
```

## Features

### Routing and Parameters

```python
router = viperhttp.Router(prefix="/api/v1", tags=["api"])

@router.get("/search", query={
    "q": viperhttp.Query("", str),
    "page": viperhttp.Query(1, int),
})
def search(q="", page=1):
    return {"query": q, "page": page}

app.include_router(router)
```

### Dependency Injection

```python
def get_db():
    return {"connection": "active"}

@app.get("/data", deps={"db": viperhttp.Depends(get_db)})
def read_data(db=None):
    return {"status": db["connection"]}
```

### Middleware

```python
from viperhttp import middleware as mw

app.add_middleware(mw.CORSMiddleware, allow_origins=["*"], allow_methods=["*"])
app.add_middleware(mw.SessionMiddleware, secret_key="your-secret")
app.add_middleware(mw.CSRFMiddleware)
app.add_middleware(mw.TrustedHostMiddleware, allowed_hosts=["192.168.*"])
app.add_middleware(mw.RateLimitMiddleware, max_requests=100, window_sec=60)
```

### WebSocket

```python
ws_manager = viperhttp.ConnectionManager()

@app.websocket("/ws/chat")
async def chat(ws):
    await ws_manager.connect(ws, room="general")
    try:
        while True:
            msg = await ws.receive()
            if msg.get("type") == "close":
                break
            await ws_manager.broadcast_json(
                {"text": msg.get("text", "")},
                room="general",
            )
    finally:
        ws_manager.disconnect(ws)
```

### SSE (Server-Sent Events)

```python
@app.get("/events")
async def events():
    async def stream():
        while True:
            data = await read_sensor()
            yield {"event": "sensor", "data": json.dumps(data)}
    return viperhttp.StreamingResponse(stream(), media_type="text/event-stream")
```

### HTTPS + HTTP/2

```python
app.run(
    port=8443,
    https=True,
    http2=True,
    tls_cert="/certs/server.crt",
    tls_key="/certs/server.key",
)
```

### OTA Firmware Updates

```python
app.run(port=8080, ota=True, ota_token="secure-token-here")
```

### Static Files and Templates

```python
app.mount("/static", "www")
app.mount_file("/favicon.ico", "www/favicon.ico")
```

## Configuration

| Area | API Surface | What you can set |
|------|-------------|-----------------|
| App metadata | `viperhttp.ViperHTTP(...)` | `title`, `version`, `description`, docs defaults |
| Runtime transport | `app.run(...)` | `port`, `https`, `http2`, TLS cert/key, OTA |
| Route behavior | `@app.get(...)` | path, query, deps, OpenAPI metadata |
| Router grouping | `viperhttp.Router(...)` | `prefix`, `tags`, `deps` |
| Static files | `app.mount(...)` | path mappings, HTML mode |
| Middleware | `app.add_middleware(...)` | CORS, sessions, CSRF, rate limit, trusted host |

## Project Structure

```
viperhttp/
  cmodules/viperhttp/         Native C module
    viperhttp/core/
      vhttp_parser.c/h          Zero-copy HTTP/1.1 parser
      vhttp_router.c/h          URL routing + typed params
      vhttp_server.c/h          Core server event-loop (FreeRTOS)
      vhttp_ipc.c/h             Inter-core IPC queue
      vhttp_static.c/h          Static file serving
      vhttp_static_etag.c/h     ETag / 304 Not Modified
      vhttp_static_gzip.c/h     Gzip compression
      vhttp_cors.c/h            CORS enforcement
      vhttp_ratelimit.c/h       Rate limiting
      vhttp_trusted_host.c/h    Host validation
      vhttp_connection.c/h      Client connection pool
      vhttp_logger.c/h          Logging
      mod_viperhttp.c           MicroPython module binding
  docs/                       Documentation site (MkDocs Material)
  tests/                      Host-side test vectors and C tests
  tools/                      Build, flash, test, benchmark scripts
  viperhttp_app.py            Main app class, decorators, routing
  viperhttp_bridge.py         IPC bridge, request dispatch
  viperhttp_session.py        Session middleware, CSRF
  viperhttp_auth.py           Auth backends (Bearer, Basic, API Key)
  viperhttp_responses.py      Response helpers (JSON, SSE, Stream, File)
  viperhttp_ws.py             WebSocket connection manager
  viperhttp_ota.py            OTA firmware updates
  viperhttp_autodocs.py       OpenAPI schema + Swagger UI
  viperhttp_lifespan.py       Startup/shutdown event hooks
  assets/                     SVG logo, banner, architecture diagrams
```

## Build and Flash

WSL build:

```bash
./tools/build_firmware.sh
```

PowerShell end-to-end pipeline (build, flash, VFS sync, tests, bench):

```powershell
powershell -ExecutionPolicy Bypass -File tools/com14_pipeline.ps1 -Port COM14
```

Host tests (C core):

```bash
./tools/run_parser_tests.sh
./tools/run_router_tests.sh
./tools/run_pool_tests.sh
./tools/run_pipeline_tests.sh
./tools/run_ipc_tests.sh
```

## Documentation

Full docs at **[mateuszsury.github.io/ViperHTTP](https://mateuszsury.github.io/ViperHTTP/)**.

- [Getting Started](https://mateuszsury.github.io/ViperHTTP/getting-started/) — WiFi setup, first route, testing
- [API Reference](https://mateuszsury.github.io/ViperHTTP/api_reference/) — Complete API surface
- [Features](https://mateuszsury.github.io/ViperHTTP/features/) — All 50+ features
- [Middleware](https://mateuszsury.github.io/ViperHTTP/middleware/) — Middleware chain guide
- [Authentication](https://mateuszsury.github.io/ViperHTTP/authentication/) — Auth backends
- [WebSocket](https://mateuszsury.github.io/ViperHTTP/websocket/) — Real-time guide
- [Security](https://mateuszsury.github.io/ViperHTTP/security/) — Security best practices
- [OTA Updates](https://mateuszsury.github.io/ViperHTTP/ota/) — Firmware update flow
- [Architecture](https://mateuszsury.github.io/ViperHTTP/bridge/) — Bridge, IPC, dual-core design

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

For security concerns and vulnerability reporting, see [SECURITY.md](SECURITY.md).

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [MicroPython](https://micropython.org/) — Python runtime for microcontrollers
- [ESP-IDF](https://github.com/espressif/esp-idf) — Espressif IoT Development Framework
- [FreeRTOS](https://www.freertos.org/) — Real-time OS for ESP32 dual-core architecture

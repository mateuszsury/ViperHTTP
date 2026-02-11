# ViperHTTP API Reference

This is the full configuration-oriented reference for the MicroPython-facing ViperHTTP API.

## 1. Configuration Map

| Area | API Surface | What you can set |
| --- | --- | --- |
| App metadata + docs defaults | `viperhttp.ViperHTTP(...)` | `title`, `version`, `description`, docs defaults |
| Docs defaults update | `app.configure_docs(...)` | same docs fields as constructor |
| Runtime transport | `app.run(...)` | `port`, `https`, `http2`, TLS cert/key, worker/runtime tuning |
| OTA (optional) | `app.run(..., ota=...)`, `viperhttp_ota.install_ota_routes(app, ...)` | OTA routes, token auth, OTA session lifecycle |
| Route behavior | `@app.get(...)`, `@router.get(...)`, etc. | path, query, deps, OpenAPI metadata |
| Router grouping | `viperhttp.Router(...)` | `prefix`, `tags`, `deps` |
| Static files | `app.mount(...)`, `app.mount_file(...)` | path mappings + html mode |

Important:
- `https` and `http2` are runtime settings (`app.run(...)`), not constructor settings.
- OTA routes are optional and disabled by default (`ota=False`).
- `servers` is OpenAPI metadata only; it does not open sockets.

## 2. Minimal App

```python
import viperhttp

app = viperhttp.ViperHTTP(title="Demo API", version="1.0.0")

@app.get("/hello")
def hello():
    return {"message": "ok"}

app.run(port=8080, wifi=False)
```

## 3. `ViperHTTP(...)` Constructor

```python
app = viperhttp.ViperHTTP(
    title="My Device API",
    version="1.2.3",
    description="API for telemetry and control",
    docs=True,
    openapi_url="/openapi.json",
    docs_url="/docs",
    include_websocket_docs=True,
    cache_schema=True,
    servers=[{"url": "https://192.168.0.135:8443"}],
)
```

Supported kwargs:

| kwarg | type | default | notes |
| --- | --- | --- | --- |
| `title` | `str` | `"ViperHTTP API"` | OpenAPI info title |
| `version` | `str` | `"1.0.0"` | OpenAPI info version |
| `description` | `str` | `""` | OpenAPI info description |
| `docs` | `bool` | `True` | default switch for auto docs installation in `run()` |
| `openapi_url` | `str \| None` | `"/openapi.json"` | `None` disables OpenAPI route |
| `docs_url` | `str \| None` | `"/docs"` | `None` disables docs UI route |
| `include_websocket_docs` | `bool` | `True` | include websocket docs extensions |
| `cache_schema` | `bool` | `True` | cache generated OpenAPI schema |
| `servers` | `list \| tuple \| None` | `None` | OpenAPI `servers` metadata |

Notes:
- Constructor does not accept `https`, `http2`, `port`, `tls_*`.
- `openapi_url=None` and `docs_url=None` are valid.

## 4. `app.configure_docs(...)` and `app._docs_config()`

`configure_docs` updates docs defaults already stored on the app.

```python
app.configure_docs(
    title="Updated API",
    version="2.0.0",
    description="Updated docs metadata",
    docs=True,
    openapi_url="/openapi.json",
    docs_url="/docs",
    include_websocket_docs=True,
    cache_schema=True,
    servers=[
        {"url": "https://device.local:8443"},
        {"url": "https://api.example.com"},
    ],
)
```

Disable docs endpoints explicitly:

```python
app.configure_docs(openapi_url=None, docs_url=None)
```

Inspect effective docs defaults:

```python
print(app._docs_config())
```

`configure_docs(...)` kwargs:
- `title: str`
- `version: str`
- `description: str`
- `docs: bool`
- `openapi_url: str|None`
- `docs_url: str|None`
- `include_websocket_docs: bool`
- `cache_schema: bool`
- `servers: list|tuple|None`

## 5. Routes and Route-Level Settings

Supported app decorators:
- `@app.get(...)`
- `@app.post(...)`
- `@app.put(...)`
- `@app.patch(...)`
- `@app.delete(...)`
- `@app.options(...)`
- `@app.head(...)`
- `@app.websocket(...)`

Supported router decorators:
- `@router.get(...)`
- `@router.post(...)`
- `@router.put(...)`
- `@router.patch(...)`
- `@router.delete(...)`
- `@router.options(...)`
- `@router.head(...)`
- `@router.websocket(...)`

Common decorator kwargs:

| kwarg | type | notes |
| --- | --- | --- |
| `path` | `str` | required route path |
| `query` | `dict \| None` | typed query spec |
| `deps` | `dict \| None` | dependencies spec |
| `summary` | `str \| None` | OpenAPI metadata |
| `description` | `str \| None` | OpenAPI metadata |
| `tags` | `str \| list[str] \| tuple[str] \| None` | OpenAPI metadata |
| `responses` | `dict \| None` | OpenAPI metadata |
| `operation_id` | `str \| None` | OpenAPI metadata |
| `name` | `str \| None` | OpenAPI metadata |
| `request_body` | `dict \| None` | OpenAPI metadata |
| `deprecated` | `bool` | OpenAPI metadata |
| `include_in_schema` | `bool` | hide route from OpenAPI when `False` |

WebSocket-only extra kwarg:
- `protocols: list|tuple|None`

Typed path params:

```python
@app.get("/items/{item_id:int}")
def get_item(item_id=0):
    return {"item_id": item_id}
```

Supported path casts:
- `str`
- `int`
- `float`
- `bool`
- `path`

Typed query params:

```python
@app.get(
    "/search",
    query={
        "q": viperhttp.Query("", str),
        "page": viperhttp.Query(1, int),
        "ratio": float,
        "active": viperhttp.Query(False, bool),
    },
)
def search(q="", page=1, ratio=0.0, active=False):
    return {"q": q, "page": page, "ratio": ratio, "active": active}
```

Dependencies:

```python
def get_user():
    return {"id": 1, "name": "alice"}

@app.get("/me", deps={"user": viperhttp.Depends(get_user)})
def me(user=None):
    return user
```

## 6. Router Configuration

```python
api = viperhttp.Router(
    prefix="/api",
    tags=["api"],
    deps={"user": viperhttp.Depends(get_user)},
)

@api.get("/ping")
def ping(user=None):
    return {"pong": True}

app.include_router(api)
```

Router constructor kwargs:
- `prefix: str` (default `""`)
- `tags: str|list|tuple|None` (default `None`)
- `deps: dict|None` (default `None`)

`include_router(...)` behavior:
- applies router `prefix` to all router paths
- merges router-level deps with route deps
- merges router tags into route docs metadata

## 7. Request / Response Helpers

Request access:

```python
req = viperhttp.current_request()
```

Return styles:
- `dict` / `list` -> JSON auto-response
- `str` -> text response
- helper responses:
  - `viperhttp.Response(...)`
  - `viperhttp.JSONResponse(...)`
  - `viperhttp.StreamingResponse(...)`
  - `viperhttp.FileResponse(...)`
  - `viperhttp.TemplateResponse(...)`

## 8. Middleware, Exceptions, Lifespan, WebSocket

Middleware:

```python
@app.middleware("http")
async def add_header(request, call_next):
    resp = await call_next(request)
    return resp
```

```python
class MyMW(viperhttp.BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        return await call_next(request)

app.add_middleware(MyMW)
```

Exceptions:

```python
raise viperhttp.HTTPException(status_code=404, detail="Not found")
```

```python
@app.exception_handler(Exception)
def handle_any(request, exc):
    return viperhttp.JSONResponse(status_code=500, body={"detail": str(exc)})
```

Lifespan:

```python
@app.on_event("startup")
def startup():
    pass

@app.on_event("shutdown")
async def shutdown():
    pass
```

WebSocket:

```python
@app.websocket("/ws/echo")
async def ws_echo(ws):
    await ws.accept()
    while True:
        msg = await ws.receive()
        if msg.get("type") == "close":
            break
        await ws.send_text("echo:" + msg.get("text", ""))
```

## 9. Static and Templates

```python
app.mount("/static", "/www", html=True)
app.mount_file("/file", "/www/large.txt")
```

```python
return viperhttp.TemplateResponse("/www/index.html", {"name": "ViperHTTP"})
```

Mount settings:
- `app.mount(prefix: str, root: str, html: bool=False)`
- `app.mount_file(path: str, file: str)`

## 10. `app.run(...)` Full Runtime Settings

`app.run(...)` automatically:
- starts C server runtime
- starts bridge dispatch/event loop
- auto-installs OpenAPI/docs routes unless disabled

Full signature:

```python
app.run(
    port=8080,
    loop=None,
    wifi=True,
    https=False,
    http2=False,
    http2_max_streams=8,
    tls_cert_pem=None,
    tls_key_pem=None,
    tls_cert_path=None,
    tls_key_path=None,
    ota=False,
    ota_prefix="/ota",
    ota_token=None,
    ota_token_header="X-OTA-Token",
    ota_token_query="token",
    min_workers=None,
    max_workers=None,
    bridge_min_workers=None,
    bridge_max_workers=None,
    bridge_queue_size=None,
    bridge_poll_burst=None,
    bridge_idle_sleep_ms=None,
    bridge_autoscale=None,
    bridge_enqueue_wait_ms=None,
    bridge_worker_yield_every=None,
    bridge_scale_up_max_burst=None,
    auto_docs=None,
    title=None,
    version=None,
    description=None,
    openapi_url=<inherit>,
    docs_url=<inherit>,
    include_websocket_docs=None,
    cache_schema=None,
    servers=None,
)
```

Runtime kwargs:

| kwarg | type | default | notes |
| --- | --- | --- | --- |
| `port` | `int` | `8080` | listener port |
| `loop` | `uasyncio loop \| None` | `None` | use current loop when omitted |
| `wifi` | `bool` | `True` | if `True`, bridge touches WLAN STA mode |
| `https` | `bool` | `False` | enable TLS on the same listener port |
| `http2` | `bool` | `False` | enable HTTP/2 runtime support |
| `http2_max_streams` | `int` | `8` | valid range: `0..64` |
| `tls_cert_pem` | `str/bytes \| None` | `None` | PEM cert bytes/text |
| `tls_key_pem` | `str/bytes \| None` | `None` | PEM private key bytes/text |
| `tls_cert_path` | `str \| None` | `None` | read cert from file when `https=True` |
| `tls_key_path` | `str \| None` | `None` | read key from file when `https=True` |
| `ota` | `bool` | `False` | auto-install OTA endpoints |
| `ota_prefix` | `str` | `"/ota"` | OTA route prefix |
| `ota_token` | `str \| None` | `None` | when set, OTA endpoints require token |
| `ota_token_header` | `str` | `"X-OTA-Token"` | auth header for OTA token |
| `ota_token_query` | `str` | `"token"` | auth query fallback key |
| `min_workers` | `int \| None` | `None` | C server worker minimum limit override |
| `max_workers` | `int \| None` | `None` | C server worker maximum limit override |
| `bridge_min_workers` | `int \| None` | `None` | Python bridge worker minimum |
| `bridge_max_workers` | `int \| None` | `None` | Python bridge worker maximum |
| `bridge_queue_size` | `int \| None` | `None` | Python bridge queue size |
| `bridge_poll_burst` | `int \| None` | `None` | bridge poll burst; values `<1` clamp to `1` |
| `bridge_idle_sleep_ms` | `int \| None` | `None` | bridge idle sleep; values `<0` clamp to `0` |
| `bridge_autoscale` | `bool \| None` | `None` | bridge worker autoscale toggle |
| `bridge_enqueue_wait_ms` | `int \| None` | `None` | values `<0` clamp to `0` |
| `bridge_worker_yield_every` | `int \| None` | `None` | values `<1` clamp to `1` |
| `bridge_scale_up_max_burst` | `int \| None` | `None` | values `<1` clamp to `1` |
| `auto_docs` | `bool \| None` | `None` | when `None`, uses app docs default (`docs`) |
| `title` | `str \| None` | `None` | docs metadata override for this run |
| `version` | `str \| None` | `None` | docs metadata override for this run |
| `description` | `str \| None` | `None` | docs metadata override for this run |
| `openapi_url` | `str \| None` | inherit app config | `None` disables OpenAPI route |
| `docs_url` | `str \| None` | inherit app config | `None` disables docs UI route |
| `include_websocket_docs` | `bool \| None` | inherit app config | include websocket docs extension |
| `cache_schema` | `bool \| None` | inherit app config | schema caching |
| `servers` | `list \| tuple \| None` | inherit app config | OpenAPI `servers` metadata |

Docs behavior:
- `auto_docs=False` disables auto docs install entirely.
- `openapi_url=None` disables OpenAPI route; docs UI is also not installed.
- `docs_url=None` disables docs UI only; OpenAPI can remain enabled.

## 11. HTTPS / HTTP2 and Port Behavior

Examples:

```python
# HTTPS on a single listener port
app.run(
    port=8443,
    https=True,
    tls_cert_path="/certs/cert.pem",
    tls_key_path="/certs/key.pem",
    wifi=False,
)
```

```python
# HTTPS + HTTP/2
app.run(
    port=8443,
    https=True,
    http2=True,
    http2_max_streams=16,
    tls_cert_path="/certs/cert.pem",
    tls_key_path="/certs/key.pem",
    wifi=False,
)
```

Rules:
- `port` is always the real listener port.
- With `https=True`, that port serves HTTPS.
- With `https=False`, that port serves HTTP.
- One app instance listens on one port; there is no dual HTTP+HTTPS listener in a single `run()` call.
- If `https=True`, cert and key are required (direct PEM or file paths).

## 12. OpenAPI `servers`

`servers` is metadata in generated OpenAPI schema (`spec["servers"]`), not socket configuration.

Multiple entries are supported:

```python
app.configure_docs(
    servers=[
        {"url": "https://192.168.1.50:8443"},
        {"url": "https://api.example.com"},
    ]
)
```

Accepted items:
- string URL, e.g. `"https://api.example.com"`
- dict with at least `url`, e.g. `{"url": "https://api.example.com", "description": "prod"}`

## 13. Advanced: Manual Bridge (Optional)

Manual `viperhttp_bridge.run(...)` is still available for custom startup pipelines, but not required for normal applications.

## 14. OTA API

Core OTA manager API (`viperhttp_ota`):

- `ota_status()`
- `ota_begin(expected_size=None, expected_sha256=None, force=False)`
- `ota_write(data, offset=None)`
- `ota_finalize(set_boot=True, reboot=False, strict_size=True)`
- `ota_abort()`
- `ota_apply(data, expected_sha256=None, set_boot=True, reboot=False)`
- `ota_mark_app_valid()`

Manual helpers:

- `viperhttp_ota.install_ota_routes(app, prefix="/ota", token=None, token_header="X-OTA-Token", token_query="token")`
- `viperhttp_ota.ota_status()`

Installed OTA endpoints (when enabled by `app.run(..., ota=True)` or manual install):

- `GET /ota/status`
- `POST /ota/begin`
- `POST /ota/chunk`
- `POST /ota/finalize`
- `POST /ota/abort`
- `POST /ota/upload`
- `POST /ota/mark-valid`

Notes:
- OTA writes target the next update partition (`esp32.Partition.get_next_update()`).
- Boot partition changes only when `set_boot=True` in finalize/upload.
- `ota_finalize(..., reboot=True)` triggers `machine.reset()`.
- Token auth can be provided by header (`X-OTA-Token`) or query key (`token` by default).

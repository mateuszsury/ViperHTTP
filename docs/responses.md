# Responses and Streaming

ViperHTTP provides multiple response types for different use cases: JSON, HTML, streaming, file serving, Server-Sent Events, templates, and redirects.

## Automatic JSON Response

Return a `dict` or `list` from a route handler for automatic JSON serialization:

```python
@app.get("/data")
def get_data():
    return {"temperature": 23.5, "humidity": 68}

@app.get("/items")
def list_items():
    return [{"id": 1, "name": "Sensor A"}, {"id": 2, "name": "Sensor B"}]
```

## Text Response

Return a `str` for a plain text response:

```python
@app.get("/health")
def health():
    return "OK"
```

## JSONResponse

For explicit control over status code and headers:

```python
@app.post("/items")
def create_item():
    return viperhttp.JSONResponse(
        status_code=201,
        body={"id": 42, "created": True},
    )
```

## Response

Generic response with custom content type:

```python
@app.get("/page")
def page():
    return viperhttp.Response(
        content="<h1>Hello</h1>",
        media_type="text/html",
        status_code=200,
    )
```

## StreamingResponse

For chunked transfer encoding with generators:

```python
@app.get("/stream")
async def stream():
    async def generate():
        for i in range(10):
            yield f"chunk {i}\n"
    return viperhttp.StreamingResponse(generate(), media_type="text/plain")
```

## FileResponse

Serve a single file:

```python
@app.get("/download")
def download():
    return viperhttp.FileResponse("/data/report.csv")
```

## TemplateResponse

Render a template with context:

```python
@app.get("/dashboard")
def dashboard():
    return viperhttp.TemplateResponse(
        "dashboard.html",
        {"title": "Device Dashboard", "temp": 23.5},
    )
```

See [Template Engine Design](template_engine_design.md) for template syntax.

## RedirectResponse

```python
@app.get("/old-path")
def redirect():
    return viperhttp.RedirectResponse("/new-path", status_code=301)
```

## Server-Sent Events (SSE)

SSE allows the server to push events to the client over a long-lived HTTP connection:

```python
@app.get("/events")
async def events():
    async def event_stream():
        while True:
            reading = await get_sensor_reading()
            yield {
                "event": "sensor",
                "data": json.dumps(reading),
                "id": str(reading["seq"]),
            }
    return viperhttp.StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
    )
```

SSE event format supports:

| Field | Description |
|---|---|
| `event` | Event type name |
| `data` | Event payload (JSON string) |
| `id` | Event ID for reconnection |
| `retry` | Reconnection interval (ms) |
| `comment` | SSE comment (prefixed with `:`) |

## Static File Serving

Mount directories for C-native static serving:

```python
# Serve entire directory
app.mount("/static", "www")

# Serve single file
app.mount_file("/favicon.ico", "www/favicon.ico")
```

Features handled in C:
- **ETag/304** — Automatic cache validation
- **Gzip** — Transparent compression for supported clients
- **Range requests** — Partial content for large files
- **HTML mode** — Automatic `index.html` resolution

## Response Headers

Add custom headers to any response:

```python
@app.get("/custom")
def custom():
    return viperhttp.JSONResponse(
        body={"data": "value"},
        headers={"X-Custom-Header": "custom-value"},
    )
```

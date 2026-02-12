# Getting Started

This guide walks you through setting up ViperHTTP on your ESP32, connecting to WiFi, creating your first routes, and testing them.

## Prerequisites

- ESP32 board (ESP32-WROOM, ESP32-S3, or compatible)
- MicroPython 1.24+ firmware with ViperHTTP module
- USB cable for initial flashing
- WiFi network for testing

## Building and Flashing Firmware

Follow the [Build and Flash](build.md) guide to compile and flash ViperHTTP firmware to your ESP32.

Quick version:

```bash
# Build firmware in WSL
./tools/build_firmware.sh

# Flash via PowerShell
powershell -ExecutionPolicy Bypass -File tools/com14_pipeline.ps1 -Port COM14
```

## WiFi Setup

Every ViperHTTP application starts with a WiFi connection:

```python
import network

wlan = network.WLAN(network.STA_IF)
wlan.active(True)
wlan.connect("YourSSID", "YourPassword")

# Wait for connection
while not wlan.isconnected():
    pass

print("Connected:", wlan.ifconfig())
```

## Your First Application

Create a `main.py` on the device:

```python
import network
import viperhttp

# WiFi
wlan = network.WLAN(network.STA_IF)
wlan.active(True)
wlan.connect("YourSSID", "YourPassword")
while not wlan.isconnected():
    pass

# Create the app
app = viperhttp.ViperHTTP(title="My Device", version="1.0.0")

@app.get("/")
def index():
    return {"status": "running", "ip": wlan.ifconfig()[0]}

@app.get("/hello/{name}")
def hello(name="world"):
    return {"message": f"Hello, {name}!"}

# Start server on port 8080
app.run(port=8080, wifi=False)
```

## Testing Your Routes

Once the server is running, test from any machine on the same network:

```bash
# Basic GET request
curl http://<device-ip>:8080/

# Path parameter
curl http://<device-ip>:8080/hello/ESP32

# JSON response
curl -s http://<device-ip>:8080/ | python -m json.tool
```

## Adding Query Parameters

```python
@app.get("/search", query={
    "q": viperhttp.Query("", str),
    "limit": viperhttp.Query(10, int),
})
def search(q="", limit=10):
    return {"query": q, "limit": limit}
```

Test with:

```bash
curl "http://<device-ip>:8080/search?q=sensor&limit=5"
```

## Adding Dependencies

```python
def get_device_info():
    import machine
    return {
        "freq": machine.freq(),
        "unique_id": machine.unique_id().hex(),
    }

@app.get("/device", deps={"info": viperhttp.Depends(get_device_info)})
def device(info=None):
    return info
```

## Enabling HTTPS

```python
app.run(
    port=8443,
    https=True,
    tls_cert="/certs/server.crt",
    tls_key="/certs/server.key",
    wifi=False,
)
```

## Enabling Auto API Docs

API documentation is enabled by default. Visit:

- **Swagger UI**: `http://<device-ip>:8080/docs`
- **OpenAPI schema**: `http://<device-ip>:8080/openapi.json`

To customize:

```python
app = viperhttp.ViperHTTP(
    title="Sensor API",
    version="2.0.0",
    description="Telemetry and control API",
    docs=True,
    docs_url="/docs",
    openapi_url="/openapi.json",
)
```

## Next Steps

- [Features](features.md) — Explore the full feature set
- [Middleware](middleware.md) — Add CORS, rate limiting, sessions
- [Authentication](authentication.md) — Secure your endpoints
- [WebSocket](websocket.md) — Add real-time communication
- [API Reference](api_reference.md) — Complete API documentation

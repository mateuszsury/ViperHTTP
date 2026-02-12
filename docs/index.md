# ViperHTTP

<p align="center">
  <img src="logo.svg" alt="ViperHTTP Logo" width="160"/>
</p>

<p align="center">
  <strong>Blazing-fast async HTTP server for MicroPython on ESP32</strong><br/>
  Native C core + FastAPI-style Python API
</p>

---

## What is ViperHTTP?

ViperHTTP is a high-performance HTTP server stack designed for ESP32 microcontrollers. It splits work across both ESP32 cores — a **native C runtime** handles parsing, routing, and static serving on Core 0, while **MicroPython** runs your application logic on Core 1 with a familiar, FastAPI-style developer API.

## Key Features

<div class="grid cards" markdown>

-   **:zap: 10x Performance**

    ---

    Native C parser, router, and static server with zero-copy parsing and compile-time buffer limits.

-   **:electric_plug: WebSocket**

    ---

    Real-time bidirectional communication with connection manager, rooms, and broadcast.

-   **:lock: HTTPS + HTTP/2**

    ---

    TLS encryption, HPACK header compression, and stream multiplexing.

-   **:shield: Security Stack**

    ---

    Sessions, CSRF tokens, auth backends, trusted host validation, and rate limiting.

-   **:satellite: OTA Updates**

    ---

    SHA256-verified over-the-air firmware updates with progress tracking.

-   **:wrench: FastAPI-Style DX**

    ---

    Decorators, `Depends()`, typed parameters, router groups, and middleware chain.

</div>

## Quick Start

```python
import network
import viperhttp

wlan = network.WLAN(network.STA_IF)
wlan.active(True)
wlan.connect("SSID", "PASSWORD")
while not wlan.isconnected():
    pass

app = viperhttp.ViperHTTP(title="Device API", version="1.0.0")

@app.get("/hello")
def hello():
    return {"message": "Hello from ESP32!"}

app.run(port=8080, wifi=False)
```

## Documentation

| Section | Description |
|---|---|
| [Getting Started](getting-started.md) | WiFi setup, first route, testing |
| [API Reference](api_reference.md) | Complete configuration and API surface |
| [Features](features.md) | Overview of all features |
| [Middleware](middleware.md) | Middleware chain and built-in middleware |
| [Authentication](authentication.md) | Auth backends and session-based auth |
| [WebSocket](websocket.md) | Real-time communication guide |
| [Security](security.md) | Security features and best practices |
| [Responses](responses.md) | JSON, streaming, SSE, templates |
| [OTA Updates](ota.md) | Firmware update lifecycle |

## Architecture

| | Description |
|---|---|
| [Bridge & IPC](bridge.md) | Dual-core communication and request dispatch |
| [Parser Contract](parser_contract.md) | HTTP parser specification and limits |
| [Performance](performance.md) | Benchmarking methodology and regression testing |

## Build & Run

| | Description |
|---|---|
| [Build and Flash](build.md) | Firmware compilation and flashing |
| [Operations](ops-com14-checklist.md) | Device operations checklist |
| [Examples](examples/README.md) | Runnable example applications |

## Project Links

- **Repository**: [github.com/mateuszsury/ViperHTTP](https://github.com/mateuszsury/ViperHTTP)
- **Security Policy**: [SECURITY.md](https://github.com/mateuszsury/ViperHTTP/blob/main/SECURITY.md)
- **Contributing**: [CONTRIBUTING.md](https://github.com/mateuszsury/ViperHTTP/blob/main/CONTRIBUTING.md)

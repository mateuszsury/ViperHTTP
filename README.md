# ViperHTTP

High-performance HTTP server stack for MicroPython on ESP32, with a FastAPI-style developer experience and native C core.

## Why ViperHTTP

- Fast path in C for parser, router, static, IPC, and transport.
- High-level Python API with decorators, dependencies, middleware, sessions, auth, WebSocket, OTA.
- Optional HTTPS and HTTP/2 runtime support.
- Event-loop-first runtime with bridge automation through `app.run(...)`.
- Production-oriented tooling for firmware build, flash, device tests, and performance regression checks.

## Key Features

- Routing: typed path parameters, typed query handling, router grouping.
- DI + middleware: `Depends`, middleware chain, exception handlers, lifespan hooks.
- Responses: JSON, file/stream, SSE, WebSocket helpers.
- Static serving: caching, ETag/304, range support, gzip integration.
- Security building blocks: session middleware, CSRF controls, auth backends, trusted host/rate-limit primitives.
- OTA: optional OTA route setup and session/status flow.
- Transport options: HTTP/1.1 default, optional HTTPS and HTTP/2.

## Repository Layout

```text
cmodules/viperhttp/        Native C module and HTTP core
docs/                      API reference, architecture notes, operations docs
tests/                     Host-side vectors and C tests
tools/                     Build/flash/test/benchmark scripts
viperhttp_*.py             High-level API modules for MicroPython runtime
```

## Documentation

- API reference: `docs/api_reference.md`
- Bridge/runtime internals: `docs/bridge.md`
- Build and flash flow: `docs/build.md`
- Performance methodology: `docs/performance.md`
- Parser contract: `docs/parser_contract.md`
- Examples: `docs/examples/README.md`

## Quick Start (High-Level API)

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
    return {"message": "ok"}

# Starts runtime and bridge automatically.
app.run(port=8080, wifi=False)
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

## Host Tests (Core C)

```bash
./tools/run_parser_tests.sh
./tools/run_router_tests.sh
./tools/run_pool_tests.sh
./tools/run_pipeline_tests.sh
./tools/run_ipc_tests.sh
```

## Roadmap and Planning

- Active planning and execution log: `plan.md`

## Contributing

Please read `CONTRIBUTING.md` before opening a PR.

## Security

To report a vulnerability, follow `SECURITY.md`.

## License

This project is licensed under the MIT License. See `LICENSE`.

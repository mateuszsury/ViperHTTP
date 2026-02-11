# COM14 Operational Checklist

## Purpose
One repeatable flow for build, flash, sync VFS, start server, run full tests, and run benchmark on ESP32-S3 (`COM14`).

## One-Command Pipeline
Run from repo root:

```powershell
powershell -ExecutionPolicy Bypass -File tools/com14_pipeline.ps1 -Port COM14
```

Useful variants:

```powershell
# only tests + benchmark against existing running firmware
powershell -ExecutionPolicy Bypass -File tools/com14_pipeline.ps1 -Port COM14 -SkipBuild -SkipFlash -SkipSyncVfs

# skip benchmark
powershell -ExecutionPolicy Bypass -File tools/com14_pipeline.ps1 -Port COM14 -SkipBench

# force explicit device IP (if auto-detection from logs fails)
powershell -ExecutionPolicy Bypass -File tools/com14_pipeline.ps1 -Port COM14 -Ip 192.168.0.135
```

## What the pipeline does
1. Stops stale device server and frees COM lock.
2. Builds firmware in WSL (`./tools/build_firmware.sh`).
3. Flashes firmware with `esptool` from `build-ESP32S3_N16R8`.
4. Syncs VFS (`/www`) and regenerates gzip assets.
5. Uploads app files (`viperhttp_app.py`, bridge/auth/session/responses).
6. Starts Wi-Fi server (`tools/run_server_wifi.py`) and discovers device IP.
7. Runs:
`tools/host_full_test.py`
`tools/ws_test.py`
`tools/run_device_all_tests.ps1`
8. Runs benchmark (`tools/http_bench.py`).
9. Optional async runtime stress:
`python tools/http_concurrency_test.py <ip> --clients 12 --duration 20 --path /hello`
`python tools/http_mixed_stress_test.py <ip> --clients 12 --duration 30`

## Verification targets
- HTTP core: status codes, JSON, middleware, DI, query typing.
- Static + VFS: html, gzip, ETag/304, range/416, stream path.
- Sessions/auth: cookie, CSRF flow, role guards.
- WebSocket: handshake + echo.
- Async runtime: concurrent keep-alive load + `server_stats`/`ipc_stats` counters.
- `FileResponse`: content type, `Range`, `If-Range`, `Last-Modified`.
- Templates: include/parse/warmup + cache invalidation/eviction/leak regression.

Template regression command:

```powershell
powershell -ExecutionPolicy Bypass -File tools/run_device_template_tests.ps1 -Port COM14
```

## Troubleshooting
- COM busy:
Kill stale `mpremote`/Python processes, then rerun pipeline.
- No IP in logs:
Check `tools/server.out.log`, then rerun with `-Ip`.
- Slow/unresponsive session endpoints:
Clean stale `/sessions` entries on device and retry tests.
- WSL clock skew warnings:
Run `wsl --shutdown` and rebuild.
- `sdkconfig.board` changes not applied in build output:
Remove `vendor/micropython/ports/esp32/build-ESP32S3_N16R8` and rebuild, because existing `sdkconfig` in `build-*` has precedence over defaults.

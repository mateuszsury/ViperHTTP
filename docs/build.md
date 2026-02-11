# Build and Flash (WSL)

## Assumptions
- Board: ESP32-S3 N16R8 (16MB flash, 8MB Octal PSRAM)
- MicroPython: v1.27.0 (vendor/micropython)
- User C module: cmodules/viperhttp
- IPC ring buffer uses PSRAM automatically when available
  (`VHTTP_IPC_RINGBUF_SIZE_PSRAM`), otherwise falls back to SRAM
  (`VHTTP_IPC_RINGBUF_SIZE`).

## Prerequisites (WSL)
- ESP-IDF installed inside WSL and `idf.py` available in PATH.
- Python 3 and build tools installed in WSL.

## Build
Run from WSL in the repo root:

```bash
./tools/build_firmware.sh
```

Build output:
- `vendor/micropython/ports/esp32/build-ESP32S3_N16R8/`
- Firmware image typically `firmware.bin` or `micropython.bin`

## Flash
Use the helper script (adjust `PORT`):

```bash
./tools/flash_firmware.sh /dev/ttyUSB0
```

Or run esptool directly:

```bash
PORT=/dev/ttyUSB0
BIN=vendor/micropython/ports/esp32/build-ESP32S3_N16R8/firmware.bin

python3 -m esptool --chip esp32s3 --port $PORT --baud 460800 write_flash -z 0x0 $BIN
```

If WSL cannot see the USB device, enable USB pass-through (usbipd) and map the COM port into WSL.

## VFS Static Assets
Static files are served from the MicroPython VFS (FAT). Sync the assets from
`tools/www/` into `/www` on the device:

```powershell
powershell -ExecutionPolicy Bypass -File tools/sync_vfs.ps1 -Port COM14
```

## Full COM14 Pipeline
For one-command build + flash + sync + server start + full tests + benchmark:

```powershell
powershell -ExecutionPolicy Bypass -File tools/com14_pipeline.ps1 -Port COM14
```

## Performance Regression Runs
For repeatable multi-run stress benchmarks with persisted history and deltas:

```powershell
python tools/perf_regression.py 192.168.0.135 `
  --profiles c_static_only,python_light,python_heavy `
  --runs 3 `
  --burst-duration 12 `
  --long-duration 30 `
  --heartbeat-ms 3000 `
  --hard-timeout-s 1800 `
  --tag baseline
```

Artifacts are written to `tools/perf_history/` (`latest.json` + historical `perf_*.json/.md`).
See `docs/performance.md` for full details.

## Gzip (Static)
- At runtime, if the client sends `Accept-Encoding: gzip` and a `.gz` asset
  exists, the server responds with `Content-Encoding: gzip` and `Vary:
  Accept-Encoding`.
- Compile-time toggles: `VHTTP_GZIP_ENABLED`, `VHTTP_GZIP_MIN_SIZE`,
  `VHTTP_GZIP_LEVEL`.

On-device gzip generation:
```python
import viperhttp
viperhttp.gzip_static(root="/www", min_size=1024, level=6)
```
This scans the filesystem and creates missing or stale `.gz` files next to
eligible assets. Use it after copying or updating files on the device.

## Smoke Test (REPL)
```python
import viperhttp
viperhttp.version()
```

Optional memory sanity:
```python
import gc
print(gc.mem_free())
```

## Notes
- Board uses `partitions-16MiBplus.csv` with 16MB flash and OTA layout.
  - Slots: `factory` and `ota_0`, each 3MB.
  - `otadata` enabled for slot switching.
  - `vfs` uses the remaining flash for the MicroPython filesystem.
- On first boot after a partition change, the MicroPython filesystem is formatted (data loss).
  Use `mpremote` to recreate your directories/files under `/`.
- C static serving reads from the MicroPython VFS at `VHTTP_STATIC_FS_BASE`
  (default `/`). On ESP32 builds we use `VHTTP_STATIC_SERVE_VIA_IPC=1`, so the
  read happens on Core 1 and the body is sent to Core 0 via IPC.
  `app.mount("/static", "/www", ...)` maps to `/www/index.html`.
- Dual-core must be enabled; `CONFIG_FREERTOS_UNICORE` should be off in sdkconfig.

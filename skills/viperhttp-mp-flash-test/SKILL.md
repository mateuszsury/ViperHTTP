---
name: viperhttp-mp-flash-test
description: Build, flash, and test ViperHTTP MicroPython firmware on ESP32-S3 using WSL/ESP-IDF, esptool, and mpremote. Use when asked to rebuild firmware, flash to a COM port, sync VFS static files, generate gzip, start the server, run host_full_test, or troubleshoot device connectivity/COM locking.
---

# ViperHTTP MicroPython Flash & Test

## Overview
Use this workflow to build in WSL, flash ESP32-S3, sync VFS assets, start the bridge server, and run end-to-end HTTP tests with minimal COM-port issues.

## Workflow (WSL build + Windows PowerShell flash/test)

### 0) Preflight (free COM, stop running server)
Stop the background server (if running) and free the COM port.

```powershell
$procid = Get-Content -ErrorAction SilentlyContinue tools/esp_server.pid
if ($procid) { Get-Process -Id $procid -ErrorAction SilentlyContinue | Stop-Process -Force }
```

If mpremote is stuck holding COM, stop any stray Python processes:

```powershell
Get-Process python | Where-Object { $_.Path -like '*Python*' } | Stop-Process -Force
```

### 1) Build firmware in WSL
Run from repo root. This is the canonical build step.

```powershell
wsl bash -lc "cd /mnt/c/Users/thete/OneDrive/Dokumenty/PyCharm/ViperHTTP && ./tools/build_firmware.sh"
```

If you see repeated "clock skew detected" warnings, run `wsl --shutdown` and rebuild.

### 2) Flash firmware to device
Run from the ESP32 build directory.

```powershell
python -m esptool --chip esp32s3 -b 460800 --before default_reset --after hard_reset write_flash "@flash_args"
```

Default build path:
`vendor/micropython/ports/esp32/build-ESP32S3_N16R8`

### 3) Sync MicroPython VFS assets
Copy the app and static files to VFS and regenerate gzip assets.

```powershell
python -m mpremote connect COM14 fs cp viperhttp_bridge.py :/viperhttp_bridge.py
python -m mpremote connect COM14 fs cp viperhttp_app.py :/viperhttp_app.py
python -m mpremote connect COM14 fs rm -r :/www
python -m mpremote connect COM14 fs cp -r tools\www :/
python -m mpremote connect COM14 exec "import viperhttp; print(viperhttp.gzip_static('/www', 0, 6))"
```

### 4) Start the server (keep running)
Launch the Wi-Fi server and keep it alive in the background. Logs go to `tools/server.out.log`.

```powershell
$p = Start-Process -FilePath "python" -ArgumentList "-m","mpremote","connect","COM14","run","tools/run_server_wifi.py" -NoNewWindow -PassThru -RedirectStandardOutput "tools/server.out.log" -RedirectStandardError "tools/server.err.log"
$p.Id | Set-Content tools/esp_server.pid
```

Check IP in the log:

```powershell
Get-Content tools/server.out.log -Tail 20
```

### 5) Run host E2E tests

```powershell
python tools/host_full_test.py 192.168.0.135
```

## Troubleshooting
- **COM port busy**: stop the background server and any lingering mpremote process, then retry.
- **Device stuck in ROM download**: run `python -m esptool --chip esp32s3 -p COM14 flash_id` to reset.
- **Wi-Fi connected but no HTTP**: restart the server (Step 4) and re-check `tools/server.out.log` for the IP.
- **Static tests fail**: re-run VFS sync + gzip (Step 3).

## Expected Artifacts
- Firmware build: `vendor/micropython/ports/esp32/build-ESP32S3_N16R8/micropython.bin`
- Flash args: `vendor/micropython/ports/esp32/build-ESP32S3_N16R8/flash_args`
- Logs: `tools/server.out.log`, `tools/server.err.log`
- PID file: `tools/esp_server.pid`

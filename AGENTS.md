# AGENTS

This repo uses Codex skills to generate and maintain the ViperHTTP library.
Canonical skill locations are under `C:\Users\thete\.codex\skills` and are mirrored locally in `skills/` for versioning.

## Available Skills
- $viperhttp-core-c: C server core (parser, router, middleware, WebSocket, gzip, serialization)
- $viperhttp-ipc-runtime: Cross-core IPC runtime (queues, ring buffers, envelopes)
- $viperhttp-micropython-api: FastAPI-like MicroPython API (Depends, routers, middleware, responses)
- $viperhttp-di-middleware: Depends, middleware stack, exceptions, routers
- $viperhttp-build-bench: ESP-IDF build config and benchmarks
- $viperhttp-mp-flash-test: Build/flash/test MicroPython firmware on ESP32-S3 (WSL, esptool, mpremote, VFS sync, gzip, host tests)

## Usage
Prefix requests with the skill name. Example:
- "Use $viperhttp-core-c to implement typed path params and router changes"
- "Use $viperhttp-micropython-api to add Depends and HTTPException"

## Sync Rule
Update the canonical skill under `C:\Users\thete\.codex\skills` and re-copy to `skills/` after changes.

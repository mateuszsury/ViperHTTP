---
name: viperhttp-micropython-api
description: Implement and maintain the MicroPython-facing API for ViperHTTP with FastAPI-like decorators, Depends, routers, middleware, responses, WebSocket, SSE, streaming, and uploads. Use when generating or modifying Python bindings or async handler behavior.
---

# ViperHTTP MicroPython API

## Overview
Provide a clean, FastAPI-like API for MicroPython users while keeping the C core in control of IO. Align all behavior to plan.md.

## Workflow
1. Read references/mp-api-spec.md for the expected public API.
2. Keep handler invocation async-safe and non-blocking.
3. Use IPC for all cross-core data transfer.
4. Minimize Python allocations for hot paths.
5. Update docs and examples when signatures change.

## Hard Requirements
- Do not call C socket APIs from Python handlers.
- All network IO remains on Core 0.
- Support sync and async handlers consistently.
- Preserve Request and Response shape as specified.
- Prefer streaming for large payloads.

## Definition of Done
- Public API matches references/mp-api-spec.md.
- Async handlers work with uasyncio.
- WebSocket and SSE APIs function end-to-end.
- Examples compile and run without edits.

## References
- Read references/mp-api-spec.md for signatures and examples.
- Use plan.md in repo as the source of truth for architecture.

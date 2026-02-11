---
name: viperhttp-core-c
description: Implement and modify the ViperHTTP C server core with FastAPI-like routing (typed path params), auto JSON serialization, middleware, static files, gzip, WebSocket, and response serialization. Use when editing any C-side networking/protocol code, performance-critical hot paths, or core module interfaces.
---

# ViperHTTP Core C

## Overview
Build and maintain the C server core that runs on Core 0. Keep it non-blocking, zero-copy where possible, and aligned to the FastAPI-like design in plan.md.

## Workflow
1. Read references/core-spec.md.
2. Decide data ownership and lifetime (zero-copy vs copy, pool vs malloc).
3. Implement with no dynamic allocs on hot path.
4. Add minimal tests or a host-side harness if feasible.
5. Update headers and compile-time config in vhttp_config.h when needed.

## Module Map
- core/vhttp_server.c: accept loop, socket IO, state machine
- core/vhttp_parser.c: zero-copy HTTP parser, typed path/query params
- core/vhttp_router.c: trie router with param types and DI metadata
- core/vhttp_connection.c: pool, keepalive, timeouts
- core/vhttp_response.c: headers, body serialization, chunked, auto JSON
- optimization/vhttp_static.c: file IO, gzip, etag, range
- optimization/vhttp_gzip.c: miniz gzip
- protocols/vhttp_websocket.c: upgrade, frames, ping/pong
- middleware/*: C-native middleware

## Hard Requirements
- Keep server task pinned to Core 0 and keep operations non-blocking.
- Do not call into MicroPython from Core 0 directly; use IPC.
- Prefer pool allocators and fixed buffers; avoid malloc on hot path.
- Maintain zero-copy parsing and store pointers into the recv buffer.
- Guard max sizes for headers, body, URI, path params, and dependencies.
- Parse typed path params in C and pass type tags over IPC.

## Definition of Done
- Build passes and no new warnings.
- Parser or router tests run, or a minimal host-side test passes.
- No new allocations in hot path, or the exception is documented.
- IPC boundary unchanged or documented and versioned.

## References
- Read references/core-spec.md for key design decisions and sizes.
- Use plan.md in repo as the source of truth for architecture.

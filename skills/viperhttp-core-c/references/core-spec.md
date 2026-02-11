# Core Spec Extract (ViperHTTP)

## Responsibilities
- Run the HTTP server task on Core 0 alongside WiFi and lwIP.
- Parse HTTP requests zero-copy and route via trie.
- Support FastAPI-like typed path params and query params parsing.
- Serve static files directly from flash with optional gzip and cache.
- Handle WebSocket upgrade and frames in C, including ping/pong.
- Keep MicroPython off the hot path unless explicitly required.

## Data Flow Summary
- Accept loop reads into recv buffers from pool.
- Parser points into recv buffer, no allocations.
- Router selects handler or static path and attaches DI metadata.
- C-native handlers run fully on Core 0.
- Python handlers are invoked via IPC; response returns via IPC.
- Response serializer writes headers and body to send buffer.
- Auto JSON serialization for dict/list responses (Python side signals type).

## Core Modules
- core/vhttp_server.c: accept loop, select or poll, connection state machine
- core/vhttp_parser.c: method, uri, headers, body, typed params
- core/vhttp_router.c: trie with param types and dependency metadata
- core/vhttp_connection.c: pool, keepalive, timeouts, flags
- core/vhttp_response.c: status line, headers, chunked, ws frames
- optimization/vhttp_static.c: file IO, gzip, etag, range
- optimization/vhttp_gzip.c: miniz wrapper
- optimization/vhttp_pool.c: memory pool allocator
- protocols/vhttp_websocket.c: rfc6455 upgrade, frames, ping/pong
- protocols/vhttp_sse.c: SSE framing
- middleware/*: C-native middleware (cors, gzip, ratelimit, security)

## Typed Path Params
- Supported types: str, int, float, path
- Store param name and type tag in trie node.
- Extract raw value in C and attach type tag for MicroPython conversion.

## Limits (from plan)
- Max connections: 8
- Max headers: 24
- Max URI length: 512
- Max header size: 4096
- Max body size: 65536
- Max path params: 8
- Max dependencies: 16
- Max dependency chain depth: 8
- Keep-alive timeout: 30s
- Keep-alive max requests: 100
- WebSocket max connections: 4
- WebSocket max frame size: 4096
- WebSocket ping interval: 30s
- WebSocket pong timeout: 10s

## Performance Targets
- Static 1KB: > 500 req/s
- Static 100KB: > 50 req/s
- JSON (C-only): > 200 req/s
- JSON (Python handler + DI): > 40 req/s
- WebSocket throughput: > 500 msg/s
- p95 latency: < 5ms C-only, < 50ms Python handler
- DI overhead: < 10ms per chain (3 deep)

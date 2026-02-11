# IPC Spec Extract (ViperHTTP)

## Core Roles
- Core 0: C server, WiFi, lwIP, static files, websocket ping/pong
- Core 1: MicroPython handlers and user logic

## IPC Mechanisms
- FreeRTOS queues for request and response envelopes
- Ring buffer for payloads and streamed bodies

## Queue and Buffer Sizes (from plan)
- Request queue length: 16
- Response queue length: 16
- Ring buffer size: 32768 bytes

## Message Flow
1. Core 0 parses request and selects handler.
2. C-native handler runs immediately if available.
3. For Python handler, Core 0 enqueues request envelope.
4. Core 1 dequeues, builds Request object, resolves Depends chain.
5. Core 1 enqueues response envelope and payload location.
6. Core 0 dequeues response and serializes to socket.

## Request Envelope (conceptual)
- route_id or handler pointer
- method, path
- headers (view or copy)
- path params: name + raw value + type tag
- query params: name + raw value + type tag + default flag
- body descriptor: inline, ring buffer offset, or streaming handle
- expected_status or response class hint
- dependency metadata id (for Depends chain resolution)

## Response Envelope (conceptual)
- status code
- headers list
- body descriptor (inline, ring buffer offset, stream)
- body_type hint (text, bytes, json)
- websocket / sse flags if applicable

## Backpressure
- If queues are full, respond 503 or drop with counter.
- If ring buffer is full, reject large body or stream in chunks.

## Data Ownership
- Parser points into recv buffer owned by Core 0.
- Python receives copies or ring buffer slices only.
- Response body from Python is either copied or streamed via ring buffer.

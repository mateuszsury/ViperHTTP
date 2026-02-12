# WebSocket

ViperHTTP provides WebSocket support with a connection manager, named rooms, and broadcast capabilities. This guide covers the full WebSocket lifecycle.

## Basic WebSocket Route

```python
@app.websocket("/ws/echo")
async def ws_echo(ws):
    await ws.accept()
    while True:
        msg = await ws.receive()
        if msg.get("type") == "close":
            break
        await ws.send_text("echo:" + msg.get("text", ""))
```

## Connection Manager

The `ConnectionManager` class tracks connected clients and provides room-based messaging:

```python
import viperhttp

ws_manager = viperhttp.ConnectionManager()
```

### Connecting Clients

```python
@app.websocket("/ws/chat")
async def chat(ws):
    # Accept and register — optionally join a room
    await ws_manager.connect(ws, room="general")
    try:
        while True:
            msg = await ws.receive()
            if msg.get("type") == "close":
                break
            await ws_manager.broadcast_json(
                {"user": "anon", "text": msg.get("text", "")},
                room="general",
            )
    finally:
        ws_manager.disconnect(ws)
```

### Room Management

```python
# Join a room after connection
ws_manager.join_room(ws, "notifications")

# Leave a room
ws_manager.leave_room(ws, "notifications")

# Disconnect from all rooms
ws_manager.disconnect(ws)
```

### Broadcasting

```python
# Broadcast text to all connected clients
await ws_manager.broadcast_text("Hello everyone!")

# Broadcast text to a specific room
await ws_manager.broadcast_text("Room update", room="general")

# Broadcast JSON to all clients
await ws_manager.broadcast_json({"type": "update", "data": sensor_reading})

# Broadcast JSON to a specific room
await ws_manager.broadcast_json({"alert": True}, room="alerts")
```

### Connection Stats

```python
stats = ws_manager.stats()
# Returns: {"connections": 5, "rooms": {"general": 3, "alerts": 2}}
```

## Message Format

Messages received from `ws.receive()` have the following structure:

```python
# Text message
{"type": "text", "text": "hello"}

# Binary message
{"type": "bytes", "bytes": b"\x01\x02"}

# Close message
{"type": "close", "code": 1000}
```

## Sending Messages

```python
# Send text
await ws.send_text("Hello")

# Send JSON (manual)
import json
await ws.send_text(json.dumps({"key": "value"}))
```

## Protocol Negotiation

Specify supported WebSocket sub-protocols:

```python
@app.websocket("/ws/mqtt", protocols=["mqtt", "mqttv5"])
async def ws_mqtt(ws):
    await ws.accept()
    # ...
```

## Error Handling

Always wrap the message loop in try/finally to ensure cleanup:

```python
@app.websocket("/ws/safe")
async def safe_ws(ws):
    await ws_manager.connect(ws)
    try:
        while True:
            msg = await ws.receive()
            if msg.get("type") == "close":
                break
            # Handle message...
    except Exception:
        pass  # Connection lost
    finally:
        ws_manager.disconnect(ws)
```

## OpenAPI Documentation

WebSocket endpoints are included in auto-generated API docs when `include_websocket_docs=True` (the default):

```python
app = viperhttp.ViperHTTP(
    title="Real-Time API",
    include_websocket_docs=True,
)
```

## Combining with SSE

For clients that don't support WebSocket (or for server-to-client only), use SSE:

```python
@app.get("/events")
async def events():
    async def event_stream():
        while True:
            data = await get_sensor_data()
            yield {"event": "sensor", "data": json.dumps(data)}
    return viperhttp.StreamingResponse(event_stream(), media_type="text/event-stream")
```

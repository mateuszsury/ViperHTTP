# Benchmark Plan Extract (ViperHTTP)

## Tools
- wrk or ab from a PC on the same LAN
- ESP-IDF task monitor runtime stats
- heap_caps_get_info for RAM tracking
- SystemView for timing

## Scenarios
- Static small: 1KB file, keep-alive
- Static large: 100KB file, gzip
- JSON API (no deps): GET, return dict
- JSON API (with DI): GET + 2x Depends chain
- Python handler: sensor read + JSON
- WebSocket: echo, 64B messages
- Concurrent: 8 clients
- Long-running: 1h stability

## Targets
- Static 1KB: > 500 req/s
- Static 100KB: > 50 req/s
- JSON (C-only): > 200 req/s
- JSON (Python handler + DI): > 40 req/s
- WebSocket throughput: > 500 msg/s
- p95 latency: < 5ms C-only, < 50ms Python handler
- DI overhead: < 10ms per chain (3 deep)
- Memory overhead: < 64KB over baseline MicroPython

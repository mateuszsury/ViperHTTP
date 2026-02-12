# Features

ViperHTTP provides a comprehensive feature set for building production-quality HTTP services on ESP32. This page summarizes all major features with links to detailed guides.

## Routing

- **Typed path parameters** — `{id:int}`, `{name:str}`, `{ratio:float}`, `{flag:bool}`, `{path:path}`
- **Typed query parameters** — `viperhttp.Query(default, type)` with automatic casting
- **HTTP method decorators** — `@app.get`, `@app.post`, `@app.put`, `@app.patch`, `@app.delete`, `@app.options`, `@app.head`
- **Router groups** — `viperhttp.Router(prefix=..., tags=..., deps=...)` with `app.include_router()`
- **WebSocket routes** — `@app.websocket("/ws")` with protocol negotiation

See: [API Reference](api_reference.md)

## Dependency Injection

- **`Depends()` function** — Composable dependency injection for route handlers
- **Shared dependencies** — Router-level deps applied to all routes in the group
- **Chain depth limit** — Configurable max dependency chain depth (default: 8)

See: [API Reference](api_reference.md)

## Middleware

- **Decorator middleware** — `@app.middleware("http")` for simple cases
- **Class-based middleware** — Extend `BaseHTTPMiddleware` for complex logic
- **Built-in middleware**:
    - `CORSMiddleware` — Cross-origin resource sharing (C-accelerated)
    - `SessionMiddleware` — VFS-backed session storage
    - `CSRFMiddleware` — CSRF token protection
    - `TrustedHostMiddleware` — Host header validation (C-accelerated)
    - `RateLimitMiddleware` — Request rate limiting (C-accelerated)
- **Exception handlers** — `@app.exception_handler(ExcType)` for custom error responses

See: [Middleware Guide](middleware.md)

## Responses

- **JSON** — Return `dict` or `list` for automatic JSON serialization, or use `JSONResponse`
- **HTML/Text** — Return `str` or use `Response(content, media_type=...)`
- **Streaming** — `StreamingResponse` with async generators for chunked transfer
- **File** — `FileResponse` for serving individual files
- **SSE** — Server-Sent Events via `StreamingResponse` with SSE formatting
- **Template** — `TemplateResponse` using the C-native template engine
- **Redirect** — `RedirectResponse` with configurable status codes

See: [Responses Guide](responses.md)

## Static File Serving

- **Directory mounting** — `app.mount("/static", "www")` for serving file trees
- **Single file mounting** — `app.mount_file("/favicon.ico", "www/favicon.ico")`
- **ETag/304** — Automatic ETag generation and `304 Not Modified` handling
- **Gzip compression** — Transparent gzip for supported clients
- **Range requests** — Partial content serving for large files
- **HTML mode** — Automatic `index.html` resolution

All implemented in C for maximum performance.

## Security

- **Session middleware** — Server-side sessions stored on VFS with configurable expiry
- **CSRF protection** — Token-based CSRF with constant-time comparison
- **Auth backends** — Bearer token, Basic auth, API key authentication
- **Trusted host** — Host header validation against allowlist
- **Rate limiting** — Per-client request rate enforcement
- **CORS** — Configurable cross-origin resource sharing

See: [Security Guide](security.md) | [Authentication Guide](authentication.md)

## WebSocket

- **Connection manager** — `ConnectionManager` with connect/disconnect lifecycle
- **Rooms** — Named rooms for grouped message delivery
- **Broadcast** — `broadcast_text()` and `broadcast_json()` to all or room members
- **Stats** — `stats()` for connection and room counts

See: [WebSocket Guide](websocket.md)

## Transport

- **HTTP/1.1** — Default transport with keep-alive
- **HTTPS** — TLS encryption with certificate/key configuration
- **HTTP/2** — Stream multiplexing with HPACK header compression
- **WebSocket upgrade** — Protocol upgrade from HTTP/1.1

## OTA Updates

- **Begin/Write/Finalize flow** — Three-phase firmware update lifecycle
- **SHA256 verification** — Integrity check on uploaded firmware
- **Token auth** — Configurable OTA access token
- **Progress tracking** — Session-based upload progress

See: [OTA Guide](ota.md)

## Auto API Documentation

- **OpenAPI 3.0** — Automatic schema generation from route decorators
- **Swagger UI** — Interactive API explorer at `/docs`
- **ReDoc** — Alternative documentation viewer
- **WebSocket docs** — Optional WebSocket endpoint documentation
- **Schema caching** — Configurable schema cache

## Template Engine

- **C-native implementation** — Fast template rendering
- **Caching** — Compiled template cache
- **Control flow** — Loops, conditionals, variable substitution
- **Includes** — Template composition via includes
- **Filters** — Value transformation filters

See: [Template Engine Design](template_engine_design.md) | [Template Best Practices](template_best_practices.md)

## Lifespan Events

- **Startup hooks** — `@app.on_event("startup")` for initialization
- **Shutdown hooks** — `@app.on_event("shutdown")` for cleanup
- **App state** — `app.state` dictionary for shared application data

## C Runtime

- **Zero-copy parser** — HTTP/1.1 request parsing without buffer copies
- **Native router** — URL matching and parameter extraction in C
- **Connection pool** — Managed client connection lifecycle
- **Filesystem lock** — Thread-safe VFS access from both cores
- **Configurable limits** — Compile-time constants for headers, URI length, body size

See: [Parser Contract](parser_contract.md) | [Bridge Internals](bridge.md)

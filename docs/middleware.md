# Middleware

ViperHTTP supports a middleware chain that processes every request before it reaches route handlers and every response before it is sent back. Middleware can be added via decorators or class-based patterns.

## Decorator Middleware

The simplest way to add middleware:

```python
@app.middleware("http")
async def timing_middleware(request, call_next):
    import time
    start = time.ticks_ms()
    response = await call_next(request)
    elapsed = time.ticks_diff(time.ticks_ms(), start)
    print(f"Request took {elapsed}ms")
    return response
```

## Class-Based Middleware

For more complex logic, extend `BaseHTTPMiddleware`:

```python
class AuthMiddleware(viperhttp.BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        token = request.headers.get("Authorization")
        if not token:
            return viperhttp.JSONResponse(
                status_code=401,
                body={"detail": "Missing token"},
            )
        return await call_next(request)

app.add_middleware(AuthMiddleware)
```

## Built-In Middleware

### CORS Middleware

Cross-Origin Resource Sharing, enforced at the C layer for performance:

```python
from viperhttp import middleware as mw

app.add_middleware(
    mw.CORSMiddleware,
    allow_origins=["https://dashboard.local"],
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    allow_credentials=True,
    max_age=600,
)
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `allow_origins` | `list[str]` | `[]` | Allowed origin domains |
| `allow_methods` | `list[str]` | `["GET"]` | Allowed HTTP methods |
| `allow_headers` | `list[str]` | `[]` | Allowed request headers |
| `allow_credentials` | `bool` | `False` | Allow credentials (cookies) |
| `max_age` | `int` | `600` | Preflight cache duration (seconds) |

### Session Middleware

Server-side sessions stored on VFS:

```python
app.add_middleware(
    mw.SessionMiddleware,
    secret_key="generate-a-strong-key-here",
)
```

Access session data in route handlers:

```python
@app.get("/profile")
def profile():
    req = viperhttp.current_request()
    session = req.session
    return {"user": session.get("username", "anonymous")}

@app.post("/login")
def login():
    req = viperhttp.current_request()
    req.session["username"] = "alice"
    return {"logged_in": True}
```

### CSRF Middleware

Token-based CSRF protection:

```python
app.add_middleware(mw.CSRFMiddleware)
```

- Automatically generates CSRF tokens bound to sessions
- Validates tokens on state-changing methods (POST, PUT, PATCH, DELETE)
- Uses constant-time comparison to prevent timing attacks

### Trusted Host Middleware

Validates the `Host` header against an allowlist:

```python
app.add_middleware(
    mw.TrustedHostMiddleware,
    allowed_hosts=["192.168.1.100", "device.local"],
)
```

Enforced in C before the request reaches Python middleware.

### Rate Limit Middleware

Per-client request rate limiting:

```python
app.add_middleware(
    mw.RateLimitMiddleware,
    max_requests=100,
    window_sec=60,
)
```

Enforced in C for native-speed protection.

## Exception Handlers

Handle specific exception types with custom responses:

```python
class ItemNotFound(Exception):
    pass

@app.exception_handler(ItemNotFound)
def handle_not_found(request, exc):
    return viperhttp.JSONResponse(
        status_code=404,
        body={"detail": str(exc)},
    )
```

General exception handler:

```python
@app.exception_handler(Exception)
def handle_any(request, exc):
    return viperhttp.JSONResponse(
        status_code=500,
        body={"detail": "Internal server error"},
    )
```

Built-in exception:

```python
raise viperhttp.HTTPException(status_code=403, detail="Forbidden")
```

## Middleware Order

Middleware executes in the order it is added. The first middleware added is the outermost layer:

```
Request → CORS → RateLimit → TrustedHost → Session → CSRF → Auth → Route Handler
Response ← CORS ← RateLimit ← TrustedHost ← Session ← CSRF ← Auth ← Route Handler
```

Place security middleware early (CORS, rate limiting, trusted host) and application middleware later (sessions, auth).

## Custom Middleware Pattern

A complete middleware pattern with configuration:

```python
class LoggingMiddleware(viperhttp.BaseHTTPMiddleware):
    def __init__(self, app, log_headers=False):
        super().__init__(app)
        self.log_headers = log_headers

    async def dispatch(self, request, call_next):
        print(f"{request.method} {request.path}")
        if self.log_headers:
            print(f"Headers: {request.headers}")
        response = await call_next(request)
        print(f"Status: {response.status_code}")
        return response

app.add_middleware(LoggingMiddleware, log_headers=True)
```

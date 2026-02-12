# Security

ViperHTTP provides multiple layers of security for ESP32 applications. This guide covers the built-in security features, configuration best practices, and threat model considerations.

## Security Architecture

Security enforcement happens at two levels:

1. **C Runtime (Core 0)** — CORS, trusted host validation, and rate limiting are enforced before requests reach Python, providing native-speed protection.
2. **Python Middleware (Core 1)** — Sessions, CSRF, and authentication are handled in the middleware chain with full application context.

## HTTPS / TLS

Enable encrypted transport:

```python
app.run(
    port=8443,
    https=True,
    tls_cert="/certs/server.crt",
    tls_key="/certs/server.key",
)
```

When HTTP/2 is enabled alongside HTTPS, HPACK header compression and stream multiplexing are automatically activated:

```python
app.run(port=8443, https=True, http2=True, tls_cert="...", tls_key="...")
```

## CORS (Cross-Origin Resource Sharing)

CORS is enforced at the C layer for performance:

```python
from viperhttp import middleware as mw

app.add_middleware(
    mw.CORSMiddleware,
    allow_origins=["https://dashboard.local"],
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
    allow_credentials=True,
    max_age=600,
)
```

## Trusted Host Validation

Reject requests with unexpected `Host` headers:

```python
app.add_middleware(
    mw.TrustedHostMiddleware,
    allowed_hosts=["192.168.1.100", "device.local"],
)
```

Enforced in C before the request reaches Python.

## Rate Limiting

Protect against request flooding:

```python
app.add_middleware(
    mw.RateLimitMiddleware,
    max_requests=100,
    window_sec=60,
)
```

Per-client tracking with C-native enforcement.

## Session Middleware

Server-side sessions stored on VFS:

```python
app.add_middleware(
    mw.SessionMiddleware,
    secret_key="generate-a-strong-random-key",
)
```

Sessions are stored as files on the ESP32 filesystem with configurable expiry. Session IDs are generated using cryptographic randomness where available.

## CSRF Protection

Token-based CSRF protection with constant-time string comparison:

```python
app.add_middleware(mw.CSRFMiddleware)
```

- Tokens are bound to sessions
- Validation uses constant-time comparison to prevent timing attacks
- Configurable token header/field names

## Authentication

ViperHTTP supports multiple authentication backends:

### Bearer Token

```python
auth = vhttp_auth.BearerAuth(token="your-api-token")

@app.get("/protected", deps={"user": viperhttp.Depends(auth)})
def protected(user=None):
    return {"authenticated": True}
```

### Basic Auth

```python
auth = vhttp_auth.BasicAuth(users={"admin": "password"})
```

### API Key

```python
auth = vhttp_auth.APIKeyAuth(api_key="your-key", header="X-API-Key")
```

See the [Authentication Guide](authentication.md) for detailed usage.

## Best Practices

1. **Always use HTTPS** in production — unencrypted HTTP exposes all traffic
2. **Generate strong secrets** — use `os.urandom()` for session keys and tokens
3. **Restrict CORS origins** — avoid `allow_origins=["*"]` in production
4. **Set trusted hosts** — prevent host header injection attacks
5. **Enable rate limiting** — protect against denial-of-service
6. **Use CSRF protection** — required for any state-changing browser requests
7. **Keep firmware updated** — use OTA updates with SHA256 verification
8. **Limit exposed endpoints** — use `include_in_schema=False` to hide internal routes

## Threat Model

ViperHTTP is designed for **IoT devices on local networks or secured environments**. Consider:

| Threat | Mitigation |
|---|---|
| Eavesdropping | HTTPS/TLS encryption |
| Request flooding | C-native rate limiting |
| CSRF attacks | Token-based CSRF middleware |
| Host header injection | Trusted host validation |
| Session hijacking | Secure session IDs, configurable expiry |
| Unauthorized access | Auth backends (Bearer, Basic, API Key) |
| Firmware tampering | SHA256-verified OTA updates |
| Cross-origin attacks | CORS enforcement |

## Reporting Vulnerabilities

See [SECURITY.md](https://github.com/mateuszsury/ViperHTTP/blob/main/SECURITY.md) for responsible disclosure instructions.

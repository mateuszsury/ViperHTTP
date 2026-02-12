# Authentication

ViperHTTP supports multiple authentication backends that integrate with the dependency injection system. This guide covers Bearer tokens, Basic auth, API keys, and combining auth with route protection.

## Authentication as Dependencies

All auth backends work through `Depends()`, making them composable with other dependencies:

```python
import viperhttp
import viperhttp_auth as vhttp_auth
```

## Bearer Token Auth

Validates an `Authorization: Bearer <token>` header:

```python
auth = vhttp_auth.BearerAuth(token="my-secret-token")

@app.get("/protected", deps={"user": viperhttp.Depends(auth)})
def protected(user=None):
    return {"authenticated": True, "user": user}
```

Requests without a valid token receive a `401 Unauthorized` response.

## Basic Auth

HTTP Basic Authentication with username/password:

```python
auth = vhttp_auth.BasicAuth(users={"admin": "password123", "reader": "readonly"})

@app.get("/admin", deps={"user": viperhttp.Depends(auth)})
def admin_panel(user=None):
    return {"user": user}
```

Credentials are validated using constant-time comparison to prevent timing attacks.

## API Key Auth

Validates a custom header containing an API key:

```python
auth = vhttp_auth.APIKeyAuth(api_key="my-api-key", header="X-API-Key")

@app.get("/data", deps={"key": viperhttp.Depends(auth)})
def get_data(key=None):
    return {"data": "sensor readings"}
```

## Protecting Router Groups

Apply authentication to all routes in a router:

```python
auth = vhttp_auth.BearerAuth(token="api-token")

api = viperhttp.Router(
    prefix="/api/v1",
    tags=["api"],
    deps={"auth": viperhttp.Depends(auth)},
)

@api.get("/users")
def list_users(auth=None):
    return {"users": ["alice", "bob"]}

@api.get("/settings")
def get_settings(auth=None):
    return {"theme": "dark"}

app.include_router(api)
```

All routes under `/api/v1/` require Bearer authentication.

## Combining Auth with Sessions

Use session middleware alongside auth for stateful authentication:

```python
from viperhttp import middleware as mw

app.add_middleware(mw.SessionMiddleware, secret_key="session-secret")

@app.post("/login")
def login():
    req = viperhttp.current_request()
    body = req.json()
    # Validate credentials...
    req.session["user_id"] = body.get("user_id")
    req.session["role"] = "admin"
    return {"logged_in": True}

def require_session():
    req = viperhttp.current_request()
    user_id = req.session.get("user_id")
    if not user_id:
        raise viperhttp.HTTPException(status_code=401, detail="Not logged in")
    return {"user_id": user_id, "role": req.session.get("role")}

@app.get("/dashboard", deps={"user": viperhttp.Depends(require_session)})
def dashboard(user=None):
    return {"welcome": user["user_id"], "role": user["role"]}
```

## OTA Token Auth

OTA endpoints have built-in token authentication:

```python
app.run(port=8080, ota=True, ota_token="firmware-update-token")
```

OTA requests must include the token to begin firmware updates.

## Custom Auth Backend

Create a custom authentication dependency:

```python
def jwt_auth():
    req = viperhttp.current_request()
    header = req.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise viperhttp.HTTPException(status_code=401, detail="Missing token")
    token = header[7:]
    # Decode and validate JWT...
    return {"sub": "user_id", "role": "admin"}

@app.get("/secure", deps={"user": viperhttp.Depends(jwt_auth)})
def secure(user=None):
    return {"user": user["sub"]}
```

## Security Considerations

1. **Use HTTPS** — Auth tokens and credentials are sent in headers; always encrypt transport
2. **Strong tokens** — Generate tokens with `os.urandom()` and encode with `ubinascii.hexlify()`
3. **Constant-time comparison** — Built-in auth backends use constant-time comparison; maintain this in custom backends
4. **Session expiry** — Configure session timeouts to limit token lifetime
5. **Rate limiting** — Combine with `RateLimitMiddleware` to prevent brute-force attacks

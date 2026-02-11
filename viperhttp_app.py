import viperhttp
import uos
import uasyncio as asyncio
import viperhttp_lifespan
import viperhttp_session as vhttp_session
import viperhttp_auth as vhttp_auth
import viperhttp_responses as vhttp_responses
import viperhttp_ws
import viperhttp_autodocs as vhttp_autodocs
try:
    import viperhttp_ota as vhttp_ota
except Exception:
    vhttp_ota = None

INDEX_HTML = (
    b"<!doctype html>\n"
    b"<html>\n"
    b"<head><meta charset=\"utf-8\"><title>ViperHTTP</title></head>\n"
    b"<body>\n"
    b"<h1>ViperHTTP</h1>\n"
    b"<p>Device is up.</p>\n"
    b"<p><a href=\"/ui\">Open Control Hub</a></p>\n"
    b"</body>\n"
    b"</html>\n"
)

try:
    viperhttp.reset()
    app = viperhttp.ViperHTTP()
except Exception:
    app = viperhttp.active_app()
    if app is None:
        app = viperhttp.ViperHTTP()


def _app_state():
    try:
        return app.state
    except Exception:
        return viperhttp_lifespan.get_app_state(app)


class DemoAppError(Exception):
    pass


_state_ref = _app_state()
_on_event = app.on_event if hasattr(app, "on_event") else (lambda event_name: viperhttp_lifespan.on_event(app, event_name))
_exception_handler = app.exception_handler if hasattr(app, "exception_handler") else (lambda exc_type: viperhttp_lifespan.exception_handler(app, exc_type))

if not _state_ref.get("_startup_registered"):
    @_on_event("startup")
    def _startup_event():
        st = _app_state()
        st["startup_ran"] = True
        st["startup_calls"] = int(st.get("startup_calls", 0)) + 1
    _state_ref["_startup_registered"] = True

if not _state_ref.get("_exception_handler_registered"):
    @_exception_handler(DemoAppError)
    def _handle_demo_error(request, exc):
        return viperhttp.JSONResponse(
            status_code=418,
            body={"detail": str(exc), "type": "DemoAppError"},
        )
    _state_ref["_exception_handler_registered"] = True

_ws_manager = viperhttp_ws.ConnectionManager()

try:
    from viperhttp import middleware as _mw
    app.add_middleware(
        _mw.CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=False,
        max_age=600,
    )
    app.add_middleware(
        _mw.RateLimitMiddleware,
        rate=200,
        burst=400,
    )
except Exception:
    pass

_SESSION_SECRET = "dev-secret-change-me"
_session_store = vhttp_session.VFSSessionStore(
    base_path="/sessions",
    ttl_ms=3600_000,
    max_sessions=256,
    max_bytes=4096,
)
app.add_middleware(
    vhttp_session.SessionMiddleware,
    secret_key=_SESSION_SECRET,
    store=_session_store,
    cookie_name="vhttp_session",
    same_site="Lax",
    http_only=True,
    secure=False,
    csrf_exempt_paths=["/session/login"],
    csrf_check_origin=True,
    csrf_allow_missing_origin=True,
)

_auth_backends = [
    vhttp_auth.SessionAuth(),
    vhttp_auth.BearerAuth(tokens={
        "testtoken": {"sub": "bearer-user", "roles": ["user"], "source": "bearer"},
        "admintoken": {"sub": "bearer-admin", "roles": ["admin"], "source": "bearer"},
    }),
    vhttp_auth.APIKeyAuth(keys={"testkey": {"sub": "apikey-user", "source": "apikey"}}),
    vhttp_auth.BasicAuth(users={"admin": "secret"}),
]
_auth_rl = vhttp_auth.AuthRateLimiter(max_fails=5, window_ms=60000, ban_ms=300000)
app.add_middleware(vhttp_auth.AuthMiddleware, backends=_auth_backends, enforce=False, rate_limiter=_auth_rl)

def _route_exists(method, path):
    if method == "WS":
        try:
            routes = app.ws_routes()
        except Exception:
            routes = None
        if routes:
            for entry in routes:
                route_path = None
                if isinstance(entry, dict):
                    route_path = entry.get("path")
                elif isinstance(entry, (list, tuple)) and entry:
                    route_path = entry[0]
                else:
                    route_path = getattr(entry, "path", None)
                if route_path == path:
                    return True
    try:
        return app.match(method, path) is not None
    except Exception:
        return False


def _ui_test_groups():
    return [
        {
            "title": "Core & Middleware",
            "description": "Core health, middleware chain and basic routing checks.",
            "tests": [
                {"name": "Index", "method": "GET", "url": "/", "expect": "200 HTML"},
                {"name": "Hello", "method": "GET", "url": "/hello", "expect": "{\"message\":\"ok\"}"},
                {"name": "State", "method": "GET", "url": "/state", "expect": "startup flags"},
                {"name": "Custom Exception", "method": "GET", "url": "/raise-custom", "expect": "418 JSON"},
                {"name": "Redirect", "method": "GET", "url": "/redirect", "expect": "307 -> /hello"},
                {"name": "Middleware Headers", "method": "GET", "url": "/mw", "expect": "X-MW-1/X-MW-2"},
                {"name": "Middleware Order", "method": "GET", "url": "/mw-order", "expect": "A:pre,B:pre,B:post,A:post"},
                {"name": "Middleware Block", "method": "GET", "url": "/mw-block", "expect": "418 blocked"},
                {"name": "OTA Status", "method": "GET", "url": "/debug/ota-status", "expect": "ota status dict"},
            ],
        },
        {
            "title": "Routing, Query, Dependencies",
            "description": "Typed params, dependency injection and router-level checks.",
            "tests": [
                {"name": "Path Param", "method": "GET", "url": "/items/42", "expect": "{\"item_id\":42}"},
                {"name": "Query Params", "method": "GET", "url": "/query?q=foo&page=2", "expect": "q/page"},
                {"name": "Typed Query", "method": "GET", "url": "/query-typed?q=hi&page=3&ratio=1.5&active=true", "expect": "typed values"},
                {"name": "Async Handler", "method": "GET", "url": "/async-test", "expect": "{\"ok\":true}"},
                {"name": "Deps", "method": "GET", "url": "/deps", "expect": "42"},
                {"name": "Deps Async", "method": "GET", "url": "/deps/async", "expect": "42"},
                {"name": "Deps Class", "method": "GET", "url": "/deps/class", "expect": "42"},
                {"name": "Deps Class Async", "method": "GET", "url": "/deps/class-async", "expect": "42"},
                {"name": "Deps Yield", "method": "GET", "url": "/deps/yield", "expect": "yield-resource"},
                {"name": "Deps Async Yield", "method": "GET", "url": "/deps/async-yield", "expect": "async-yield-resource"},
                {"name": "Router Ping", "method": "GET", "url": "/api/ping", "expect": "{\"pong\":true}"},
            ],
        },
        {
            "title": "Templates & Docs",
            "description": "C-side template rendering, compatibility matrix and docs.",
            "tests": [
                {"name": "Template Basic", "method": "GET", "url": "/template?name=Ana&show_items=true&items=alpha,%3Cb%3E", "expect": "escaped + safe"},
                {"name": "Template Stream", "method": "GET", "url": "/template?name=Ana&show_items=true&items=alpha,%3Cb%3E&stream=true", "expect": "chunked/streamed"},
                {"name": "Template Compat", "method": "GET", "url": "/template-compat?name=%20Ana%20&count=2&role=user&roles=user,viewer&items=a,%3Cb%3E,c", "expect": "COND_OK etc"},
                {"name": "OpenAPI JSON", "method": "GET", "url": "/openapi.json", "expect": "3.0.3 schema"},
                {"name": "Swagger-like Docs", "method": "GET", "url": "/docs", "expect": "interactive docs"},
                {"name": "Control Hub", "method": "GET", "url": "/ui", "expect": "this dashboard"},
            ],
        },
        {
            "title": "Static, Streams, Files",
            "description": "Static serving (gzip/cache/range), file and stream endpoints.",
            "tests": [
                {"name": "Static Index", "method": "GET", "url": "/static/", "expect": "ViperHTTP Static"},
                {"name": "Large Static", "method": "GET", "url": "/static/large.txt", "expect": "range-capable"},
                {"name": "Large Static Range", "method": "GET", "url": "/static/large.txt", "expect": "Use custom headers Range: bytes=0-63"},
                {"name": "Stream", "method": "GET", "url": "/stream", "expect": "text/plain stream"},
                {"name": "File", "method": "GET", "url": "/file", "expect": "file response"},
                {"name": "File HTML", "method": "GET", "url": "/file-html", "expect": "html file"},
                {"name": "Chunked Stream", "method": "GET", "url": "/stream-chunked", "expect": "Transfer-Encoding: chunked"},
                {"name": "SSE", "method": "GET", "url": "/sse", "expect": "text/event-stream"},
            ],
        },
        {
            "title": "Body, Form, Upload",
            "description": "JSON/form/multipart parsing and request object inspection.",
            "tests": [
                {
                    "name": "JSON Echo",
                    "method": "POST",
                    "url": "/json",
                    "headers_json": "{\"Content-Type\":\"application/json\"}",
                    "body": "{\"msg\":\"hi\",\"count\":3}",
                    "expect": "ok + echoed JSON",
                },
                {
                    "name": "Form Echo",
                    "method": "POST",
                    "url": "/form",
                    "headers_json": "{\"Content-Type\":\"application/x-www-form-urlencoded\"}",
                    "body": "name=alice&role=admin",
                    "expect": "parsed form",
                },
                {"name": "Multipart Echo", "method": "POST", "url": "/multipart", "expect": "use host_full_test multipart payload"},
                {"name": "Upload File Echo", "method": "POST", "url": "/uploadfile", "expect": "use host_full_test multipart payload"},
                {
                    "name": "Request Info",
                    "method": "POST",
                    "url": "/request-info?foo=1&bar=test",
                    "headers_json": "{\"X-Test\":\"yes\"}",
                    "body": "payload",
                    "expect": "method/path/query/headers/body",
                },
                {"name": "Background Queue", "method": "POST", "url": "/background?msg=ui-task", "expect": "queued true"},
                {"name": "Background Status", "method": "GET", "url": "/background/status", "expect": "task log"},
            ],
        },
        {
            "title": "Session & Auth",
            "description": "Session middleware, CSRF, cookies and auth backends.",
            "tests": [
                {"name": "Cookies Parse", "method": "GET", "url": "/cookies", "expect": "send Cookie header manually"},
                {
                    "name": "Session Login",
                    "method": "POST",
                    "url": "/session/login",
                    "headers_json": "{\"Content-Type\":\"application/json\"}",
                    "body": "{\"username\":\"alice\"}",
                    "expect": "Set-Cookie vhttp_session",
                },
                {"name": "Session CSRF", "method": "GET", "url": "/session/csrf", "expect": "requires session cookie"},
                {"name": "Session WhoAmI", "method": "GET", "url": "/session/whoami", "expect": "requires session cookie"},
                {"name": "Session Protected", "method": "POST", "url": "/session/protected", "expect": "requires cookie + X-CSRF-Token"},
                {"name": "Session Logout", "method": "POST", "url": "/session/logout", "expect": "requires cookie + csrf"},
                {"name": "Bearer Auth", "method": "GET", "url": "/auth/bearer", "expect": "Authorization: Bearer testtoken"},
                {"name": "API Key Auth", "method": "GET", "url": "/auth/apikey", "expect": "X-API-Key: testkey"},
                {"name": "Basic Auth", "method": "GET", "url": "/auth/basic", "expect": "Authorization: Basic admin:secret"},
                {"name": "Admin Guard", "method": "GET", "url": "/auth/admin", "expect": "Bearer admintoken"},
            ],
        },
        {
            "title": "WebSocket",
            "description": "Echo and room broadcast scenarios from ws_test.py.",
            "tests": [
                {"name": "WS Echo", "method": "WS", "url": "/ws/echo", "ws_message": "hi", "expect": "echo:hi"},
                {"name": "WS Room", "method": "WS", "url": "/ws/room", "ws_message": "join:alpha", "expect": "connected/joined/message"},
            ],
        },
    ]


app.mount("/static", "/www", html=True)

_file_mount_ok = False
_mount_file = getattr(app, "mount_file", None)
if callable(_mount_file):
    try:
        _mount_file("/file", "/www/large.txt")
        _mount_file("/file-html", "/www/veilcord.html")
        _mount_file("/file-missing", "/www/__missing__.txt")
        _file_mount_ok = True
    except Exception as exc:
        print("mount_file_error", repr(exc))

if not _route_exists("GET", "/mw"):
    @app.get("/mw")
    def mw_ok():
        return {"ok": True}


if not _route_exists("GET", "/mw-order"):
    @app.get("/mw-order")
    def mw_order():
        req = viperhttp.current_request()
        order = []
        if req is not None:
            try:
                state = req.state
            except Exception:
                state = None
            if isinstance(state, dict):
                order = state.get("mw_order") or []
        return {"order": order}


class _HeaderMiddleware(viperhttp.BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        resp = await call_next(request)
        if resp is None:
            return resp
        headers = resp.get("headers")
        if headers is None:
            headers = {}
        if isinstance(headers, list):
            headers.append(("X-MW-1", "on"))
        elif isinstance(headers, dict):
            headers["X-MW-1"] = "on"
        else:
            headers = [("X-MW-1", "on")]
        resp["headers"] = headers
        return resp


app.add_middleware(_HeaderMiddleware)


@app.middleware("http")
async def _decorator_middleware(request, call_next):
    if getattr(request, "path", "") == "/mw-block":
        return viperhttp.Response(status_code=418, body="blocked")
    resp = await call_next(request)
    if resp is None:
        return resp
    headers = resp.get("headers")
    if headers is None:
        headers = {}
    if isinstance(headers, list):
        headers.append(("X-MW-2", "on"))
    elif isinstance(headers, dict):
        headers["X-MW-2"] = "on"
    else:
        headers = [("X-MW-2", "on")]
    resp["headers"] = headers
    return resp


def _mw_order_append(request, value):
    try:
        state = getattr(request, "state", None)
    except Exception:
        state = None
    if not isinstance(state, dict):
        state = {}
        try:
            request.state = state
        except Exception:
            return None
    order = state.get("mw_order")
    if order is None:
        order = []
        state["mw_order"] = order
    order.append(value)
    return order


async def _mw_order_a(request, call_next):
    if getattr(request, "path", "") == "/mw-order":
        _mw_order_append(request, "A:pre")
        resp = await call_next(request)
        _mw_order_append(request, "A:post")
        return resp
    return await call_next(request)


async def _mw_order_b(request, call_next):
    if getattr(request, "path", "") == "/mw-order":
        _mw_order_append(request, "B:pre")
        resp = await call_next(request)
        _mw_order_append(request, "B:post")
        return resp
    return await call_next(request)


try:
    app.add_middleware_func(_mw_order_b, priority=10)
    app.add_middleware_func(_mw_order_a, priority=-10)
except Exception:
    pass


if not _route_exists("GET", "/hello"):
    @app.get("/hello")
    def hello():
        return {"message": "ok"}


if not _route_exists("GET", "/state"):
    @app.get("/state")
    def app_state_route():
        st = _app_state()
        startup_handlers = 0
        has_demo_handler = False
        try:
            startup_handlers = len(viperhttp_lifespan.get_event_handlers(app, "startup"))
        except Exception:
            startup_handlers = 0
        try:
            has_demo_handler = viperhttp_lifespan.resolve_exception_handler(app, DemoAppError("probe")) is not None
        except Exception:
            has_demo_handler = False
        return {
            "startup_ran": bool(st.get("startup_ran")),
            "startup_calls": int(st.get("startup_calls", 0)),
            "startup_handlers": startup_handlers,
            "has_demo_handler": has_demo_handler,
        }


if not _route_exists("GET", "/raise-custom"):
    @app.get("/raise-custom")
    def raise_custom():
        raise DemoAppError("custom failure")


if not _route_exists("GET", "/redirect"):
    @app.get("/redirect")
    def redirect_to_hello():
        return vhttp_responses.RedirectResponse("/hello", status_code=307)


if not _route_exists("GET", "/"):
    @app.get("/")
    def index():
        return viperhttp.Response(
            status_code=200,
            body=INDEX_HTML,
            content_type="text/html; charset=utf-8",
        )


if not _route_exists("GET", "/items/1"):
    @app.get("/items/{item_id:int}")
    def get_item(item_id):
        return {"item_id": item_id}


if not _route_exists("GET", "/query"):
    @app.get("/query")
    def query(q="", page=""):
        return {"q": q, "page": page}


if not _route_exists("GET", "/async-test"):
    @app.get("/async-test")
    async def async_test():
        await asyncio.sleep_ms(0)
        return {"ok": True}


if not _route_exists("GET", "/query-typed"):
    @app.get(
        "/query-typed",
        query={
            "q": viperhttp.Query("", str),
            "page": viperhttp.Query(1, int),
            "ratio": float,
            "active": viperhttp.Query(False, bool),
        },
    )
    def query_typed(q="", page=1, ratio=0.0, active=False):
        return {"q": q, "page": page, "ratio": ratio, "active": active}


if not _route_exists("GET", "/template"):
    @app.get(
        "/template",
        query={
            "name": viperhttp.Query("World", str),
            "show_items": viperhttp.Query(True, bool),
            "items": viperhttp.Query("alpha,beta,<script>", str),
            "stream": viperhttp.Query(False, bool),
            "version": viperhttp.Query("", str),
        },
        summary="Template demo route",
        description="Renders HTML via C-side template engine",
        tags=["template"],
    )
    def template_demo(name="World", show_items=True, items="alpha,beta,<script>", stream=False, version=""):
        item_list = []
        for part in str(items).split(","):
            p = part.strip()
            if p:
                item_list.append(p)
        context = {
            "title": "ViperHTTP Template Demo",
            "name": name,
            "show_items": bool(show_items),
            "items": item_list,
            "raw_html": "<em>raw-fragment</em>",
        }
        headers = None
        version_str = str(version or "").strip()
        if version_str:
            headers = {
                "ETag": 'W/"tpl-%s"' % version_str,
                "Cache-Control": "public, max-age=60",
            }
        return viperhttp.TemplateResponse(
            "/www/template_demo.html",
            context=context,
            headers=headers,
            stream=bool(stream),
        )


if not _route_exists("GET", "/template-compat"):
    @app.get(
        "/template-compat",
        query={
            "name": viperhttp.Query("Ana", str),
            "count": viperhttp.Query(2, int),
            "role": viperhttp.Query("user", str),
            "roles": viperhttp.Query("user,viewer", str),
            "items": viperhttp.Query("a,<b>,c", str),
        },
        summary="Template compatibility route",
        tags=["template"],
    )
    def template_compat(name="Ana", count=2, role="user", roles="user,viewer", items="a,<b>,c"):
        role_list = []
        for part in str(roles).split(","):
            p = part.strip()
            if p:
                role_list.append(p)
        item_list = []
        raw_items = str(items).strip()
        if raw_items:
            for part in raw_items.split(","):
                item_list.append(part.strip())
        context = {
            "name": name,
            "count": int(count),
            "role": role,
            "roles": role_list,
            "items": item_list,
            "none_val": None,
        }
        return viperhttp.TemplateResponse(
            "/www/template_compat.html",
            context=context,
        )


if not _route_exists("GET", "/ui"):
    @app.get(
        "/ui",
        summary="Interactive server control hub",
        description="Template-based dashboard with links and quick checks for all demo/test endpoints.",
        tags=["ui", "template"],
    )
    def ui_dashboard():
        groups = _ui_test_groups()
        normalized_groups = []
        for group in groups:
            tests = []
            for test in group.get("tests", []):
                item = dict(test)
                if "headers_json" not in item:
                    item["headers_json"] = "{}"
                if "body" not in item:
                    item["body"] = ""
                if "ws_message" not in item:
                    item["ws_message"] = ""
                if "expect" not in item:
                    item["expect"] = ""
                tests.append(item)
            normalized_group = dict(group)
            normalized_group["tests"] = tests
            normalized_groups.append(normalized_group)
        groups = normalized_groups
        endpoint_count = 0
        for group in groups:
            tests = group.get("tests", [])
            endpoint_count += len(tests)
        tpl_stats = {
            "renders": 0,
            "compiles": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "cache_evicts": 0,
            "errors": 0,
        }
        try:
            raw_stats = viperhttp.template_stats()
            if isinstance(raw_stats, dict):
                for key in tpl_stats:
                    if key in raw_stats:
                        tpl_stats[key] = raw_stats.get(key)
        except Exception:
            pass
        context = {
            "title": "ViperHTTP Control Hub",
            "subtitle": "Interactive endpoint matrix and diagnostics",
            "version": viperhttp.version(),
            "groups": groups,
            "group_count": len(groups),
            "endpoint_count": endpoint_count,
            "template_stats": tpl_stats,
        }
        return viperhttp.TemplateResponse(
            "/www/ui_dashboard.html",
            context=context,
        )


if not _route_exists("POST", "/json"):
    @app.post("/json")
    def json_echo():
        req = viperhttp.current_request()
        if req is None:
            return viperhttp.Response(status_code=500, body="Missing request")
        data = req.json()
        return {"ok": True, "data": data}


_BG_LOG = []


def _bg_add(message):
    _BG_LOG.append(message)


if not _route_exists("POST", "/background"):
    @app.post("/background")
    def background(background_tasks=None, msg=""):
        if background_tasks is None:
            return {"queued": False}
        background_tasks.add_task(_bg_add, msg)
        return {"queued": True}


if not _route_exists("GET", "/background/status"):
    @app.get("/background/status")
    def background_status():
        return {"log": _BG_LOG}


if not _route_exists("POST", "/form"):
    @app.post("/form")
    def form_echo():
        req = viperhttp.current_request()
        if req is None:
            return viperhttp.Response(status_code=500, body="Missing request")
        return {"form": req.form()}


if not _route_exists("POST", "/multipart"):
    @app.post("/multipart")
    def multipart_echo():
        req = viperhttp.current_request()
        if req is None:
            return viperhttp.Response(status_code=500, body="Missing request")
        form = req.form()
        file_info = {}
        file_obj = form.get("file", None)
        if isinstance(file_obj, dict):
            data = file_obj.get("data", b"")
            file_info = {
                "filename": file_obj.get("filename", ""),
                "content_type": file_obj.get("content_type", ""),
                "size": len(data) if data is not None else 0,
            }
        return {"title": form.get("title", ""), "file": file_info}


if not _route_exists("POST", "/uploadfile"):
    @app.post("/uploadfile")
    def uploadfile_echo():
        req = viperhttp.current_request()
        if req is None:
            return viperhttp.Response(status_code=500, body="Missing request")
        form = req.form()
        upload = vhttp_responses.form_upload(form, "file")
        if upload is None:
            return viperhttp.Response(status_code=400, body="Missing file")
        head = upload.read_sync(4)
        upload.seek_sync(0)
        all_data = upload.read_sync()
        return {
            "filename": upload.filename,
            "content_type": upload.content_type,
            "size": upload.size,
            "head": head.decode("utf-8", "ignore"),
            "body": all_data.decode("utf-8", "ignore"),
        }


if not _route_exists("POST", "/request-info"):
    @app.post("/request-info")
    def request_info(**_ignored):
        def _to_text(value):
            if isinstance(value, (bytes, bytearray, memoryview)):
                try:
                    return bytes(value).decode("utf-8", "ignore")
                except Exception:
                    return ""
            if value is None:
                return ""
            if isinstance(value, str):
                return value
            return str(value)

        def _iter_kv(value):
            if value is None:
                return
            if hasattr(value, "items"):
                for item in value.items():
                    yield item
                return
            if isinstance(value, (list, tuple)):
                for item in value:
                    if isinstance(item, (list, tuple)) and len(item) == 2:
                        yield item
                return

        req = viperhttp.current_request()
        if req is None:
            return {"ok": False}
        body = _to_text(req.body)
        headers = {}
        for key, value in _iter_kv(getattr(req, "headers", None)):
            headers[_to_text(key)] = _to_text(value)
        query_params = {}
        raw_qp = getattr(req, "query_params", None)
        if raw_qp is not None:
            for key, value in _iter_kv(raw_qp):
                query_params[_to_text(key)] = _to_text(value)
        else:
            raw_query = _to_text(getattr(req, "query", ""))
            if raw_query:
                for pair in raw_query.split("&"):
                    if not pair:
                        continue
                    if "=" in pair:
                        key, value = pair.split("=", 1)
                    else:
                        key, value = pair, ""
                    if key not in query_params:
                        query_params[key] = value
        return {
            "method": _to_text(getattr(req, "method", "")),
            "path": _to_text(getattr(req, "path", "")),
            "query": _to_text(getattr(req, "query", "")),
            "query_params": query_params,
            "headers": headers,
            "body": body,
        }


if not _route_exists("GET", "/cookies"):
    @app.get("/cookies")
    def cookies_route():
        req = viperhttp.current_request()
        cookies = {}
        if req is not None:
            cookies = vhttp_session.get_request_cookies(req)
        return {"cookies": cookies}


if not _route_exists("POST", "/session/login"):
    @app.post("/session/login")
    def session_login():
        req = viperhttp.current_request()
        if req is None:
            return viperhttp.Response(status_code=500, body="Missing request")
        payload = {}
        try:
            payload = req.json()
        except Exception:
            try:
                payload = req.form()
            except Exception:
                payload = {}
        username = ""
        if isinstance(payload, dict):
            username = payload.get("username", "")
        if not username:
            username = "user"
        session = vhttp_session.get_request_session(req)
        if session is None:
            return viperhttp.Response(status_code=500, body="Missing session")
        session["user"] = {"username": username, "roles": ["user"], "source": "session"}
        session.rotate()
        return {"ok": True, "user": username}


if not _route_exists("GET", "/session/csrf"):
    @app.get("/session/csrf", deps={"user": viperhttp.Depends(vhttp_auth.get_current_user)})
    def session_csrf(user=None):
        req = viperhttp.current_request()
        if req is None:
            return viperhttp.Response(status_code=500, body="Missing request")
        token = vhttp_session.get_csrf_token(req)
        return {"token": token}


if not _route_exists("GET", "/session/whoami"):
    @app.get("/session/whoami", deps={"user": viperhttp.Depends(vhttp_auth.get_current_user)})
    def session_whoami(user=None):
        return {"user": user}


if not _route_exists("POST", "/session/protected"):
    @app.post("/session/protected", deps={"user": viperhttp.Depends(vhttp_auth.get_current_user)})
    def session_protected(user=None):
        return {"ok": True, "user": user}


if not _route_exists("POST", "/session/logout"):
    @app.post("/session/logout")
    def session_logout():
        req = viperhttp.current_request()
        if req is None:
            return viperhttp.Response(status_code=500, body="Missing request")
        session = vhttp_session.get_request_session(req)
        if session is not None:
            try:
                session.invalidate()
            except Exception:
                pass
        return {"ok": True}


if not _route_exists("GET", "/auth/bearer"):
    @app.get("/auth/bearer", deps={"user": viperhttp.Depends(lambda: vhttp_auth.get_current_user(scheme="bearer"))})
    def auth_bearer(user=None):
        return {"user": user}


if not _route_exists("GET", "/auth/apikey"):
    @app.get("/auth/apikey", deps={"user": viperhttp.Depends(lambda: vhttp_auth.get_current_user(scheme="apikey"))})
    def auth_apikey(user=None):
        return {"user": user}


if not _route_exists("GET", "/auth/basic"):
    @app.get("/auth/basic", deps={"user": viperhttp.Depends(lambda: vhttp_auth.get_current_user(scheme="basic"))})
    def auth_basic(user=None):
        return {"user": user}


if not _route_exists("GET", "/auth/admin"):
    @app.get("/auth/admin", deps={"user": viperhttp.Depends(vhttp_auth.require_roles(["admin"]))})
    def auth_admin(user=None):
        return {"user": user}


if not _route_exists("GET", "/debug/headers-type"):
    @app.get("/debug/headers-type")
    def headers_type():
        req = viperhttp.current_request()
        if req is None:
            return {"ok": False}
        try:
            headers_obj = req.headers
        except Exception:
            return {"ok": False}
        return {
            "ok": True,
            "is_dict": isinstance(headers_obj, dict),
            "type": str(type(headers_obj)),
        }


if not _route_exists("GET", "/debug/log-level"):
    @app.get("/debug/log-level")
    def debug_log_level(level=""):
        if level not in (None, ""):
            try:
                viperhttp.set_log_level(level)
            except Exception as exc:
                return viperhttp.JSONResponse(
                    status_code=400,
                    body={"detail": str(exc)},
                )
        try:
            return viperhttp.get_log_level()
        except Exception as exc:
            return viperhttp.JSONResponse(
                status_code=500,
                body={"detail": str(exc)},
            )


if not _route_exists("GET", "/debug/server-stats"):
    @app.get("/debug/server-stats")
    def debug_server_stats(reset=""):
        try:
            if str(reset).lower() in ("1", "true", "yes", "on"):
                viperhttp.server_stats_reset()
            stats = viperhttp.server_stats()
            ipc = viperhttp.ipc_stats()
            return {"server": stats, "ipc": ipc}
        except Exception as exc:
            return viperhttp.JSONResponse(
                status_code=500,
                body={"detail": str(exc)},
            )


if not _route_exists("GET", "/debug/memory-stats"):
    @app.get("/debug/memory-stats")
    def debug_memory_stats():
        gc_free = None
        gc_alloc = None
        try:
            import gc
            gc_free = gc.mem_free()
            gc_alloc = gc.mem_alloc()
        except Exception:
            pass
        try:
            heap = viperhttp.heap_stats()
        except Exception as exc:
            return viperhttp.JSONResponse(
                status_code=500,
                body={"detail": str(exc)},
            )
        return {
            "gc_mem_free": gc_free,
            "gc_mem_alloc": gc_alloc,
            "heap": heap,
        }


if not _route_exists("GET", "/debug/ota-status"):
    @app.get("/debug/ota-status")
    def debug_ota_status():
        if vhttp_ota is None:
            return {"supported": False, "detail": "viperhttp_ota module unavailable"}
        try:
            return vhttp_ota.ota_status()
        except Exception as exc:
            return viperhttp.JSONResponse(
                status_code=500,
                body={"detail": str(exc)},
            )


if not _route_exists("POST", "/debug/reboot"):
    @app.post("/debug/reboot")
    def debug_reboot(delay_ms="150"):
        try:
            import machine
        except Exception as exc:
            return viperhttp.JSONResponse(
                status_code=500,
                body={"detail": "machine module unavailable: " + str(exc)},
            )

        try:
            delay = int(delay_ms)
        except Exception:
            delay = 150
        if delay < 0:
            delay = 0

        async def _reboot_task():
            try:
                await asyncio.sleep_ms(delay)
            except Exception:
                pass
            machine.reset()

        try:
            asyncio.get_event_loop().create_task(_reboot_task())
            return {"ok": True, "scheduled": True, "delay_ms": delay}
        except Exception:
            machine.reset()
            return {"ok": True, "scheduled": False, "delay_ms": 0}


def _dep_base():
    return 41


def _dep_plus(base=0):
    return base + 1


if not _route_exists("GET", "/deps"):
    dep_value = viperhttp.Depends(_dep_plus, deps={"base": viperhttp.Depends(_dep_base)})

    @app.get("/deps", deps={"value": dep_value})
    def deps_route(value=0):
        return {"value": value}


class _DepClassAdd:
    def __init__(self, delta):
        self._delta = int(delta)

    def __call__(self, base=0):
        return int(base) + self._delta


class _DepClassAsyncAdd:
    def __init__(self, delta):
        self._delta = int(delta)

    async def __call__(self, base=0):
        await asyncio.sleep_ms(0)
        return int(base) + self._delta


async def _dep_async_base():
    await asyncio.sleep_ms(0)
    return 41


async def _dep_async_plus(base=0):
    await asyncio.sleep_ms(0)
    return base + 1


def _runtime_supports_async_generators():
    async def _probe():
        if False:
            yield None

    obj = None
    try:
        obj = _probe()
        return hasattr(obj, "__anext__") and hasattr(obj, "aclose")
    except Exception:
        return False
    finally:
        try:
            if obj is not None and hasattr(obj, "close"):
                obj.close()
        except Exception:
            pass


if not _route_exists("GET", "/deps/async"):
    dep_async_value = viperhttp.Depends(
        _dep_async_plus,
        deps={"base": viperhttp.Depends(_dep_async_base)},
    )

    @app.get("/deps/async", deps={"value": dep_async_value})
    async def deps_async_route(value=0):
        await asyncio.sleep_ms(0)
        return {"value": value}


_DEP_ASYNC_GEN_SUPPORTED = _runtime_supports_async_generators()


if not _route_exists("GET", "/deps/features"):
    @app.get("/deps/features")
    def deps_features():
        return {
            "async_generator_supported": bool(_DEP_ASYNC_GEN_SUPPORTED),
            "async_yield_mode": "native" if _DEP_ASYNC_GEN_SUPPORTED else "yield-fallback",
        }


if not _route_exists("GET", "/deps/class"):
    dep_class_value = viperhttp.Depends(
        _DepClassAdd(1),
        deps={"base": viperhttp.Depends(_dep_base)},
    )

    @app.get("/deps/class", deps={"value": dep_class_value})
    def deps_class_route(value=0):
        return {"value": value}


if not _route_exists("GET", "/deps/class-async"):
    dep_class_async_value = viperhttp.Depends(
        _DepClassAsyncAdd(1),
        deps={"base": viperhttp.Depends(_dep_async_base)},
    )

    @app.get("/deps/class-async", deps={"value": dep_class_async_value})
    async def deps_class_async_route(value=0):
        await asyncio.sleep_ms(0)
        return {"value": value}


_DEP_YIELD_STATE = {"enter": 0, "exit": 0}


def _dep_yield_resource():
    _DEP_YIELD_STATE["enter"] = int(_DEP_YIELD_STATE.get("enter", 0)) + 1
    try:
        yield "yield-resource"
    finally:
        _DEP_YIELD_STATE["exit"] = int(_DEP_YIELD_STATE.get("exit", 0)) + 1


if not _route_exists("GET", "/deps/yield"):
    @app.get("/deps/yield", deps={"resource": viperhttp.Depends(_dep_yield_resource, mode="yield")})
    def deps_yield_route(resource=""):
        return {"resource": resource}


if not _route_exists("GET", "/deps/yield-state"):
    @app.get("/deps/yield-state")
    def deps_yield_state():
        return dict(_DEP_YIELD_STATE)


_DEP_ASYNC_YIELD_STATE = {"enter": 0, "exit": 0}


if _DEP_ASYNC_GEN_SUPPORTED:
    async def _dep_async_yield_resource():
        _DEP_ASYNC_YIELD_STATE["enter"] = int(_DEP_ASYNC_YIELD_STATE.get("enter", 0)) + 1
        try:
            await asyncio.sleep_ms(0)
            yield "async-yield-resource"
        finally:
            _DEP_ASYNC_YIELD_STATE["exit"] = int(_DEP_ASYNC_YIELD_STATE.get("exit", 0)) + 1
else:
    def _dep_async_yield_resource():
        _DEP_ASYNC_YIELD_STATE["enter"] = int(_DEP_ASYNC_YIELD_STATE.get("enter", 0)) + 1
        try:
            yield "async-yield-resource"
        finally:
            _DEP_ASYNC_YIELD_STATE["exit"] = int(_DEP_ASYNC_YIELD_STATE.get("exit", 0)) + 1


if not _route_exists("GET", "/deps/async-yield"):
    @app.get(
        "/deps/async-yield",
        deps={
            "resource": viperhttp.Depends(
                _dep_async_yield_resource,
                mode="async_yield" if _DEP_ASYNC_GEN_SUPPORTED else "yield",
            )
        },
    )
    async def deps_async_yield_route(resource=""):
        await asyncio.sleep_ms(0)
        return {"resource": resource}


if not _route_exists("GET", "/deps/async-yield-state"):
    @app.get("/deps/async-yield-state")
    def deps_async_yield_state():
        return dict(_DEP_ASYNC_YIELD_STATE)


if not _route_exists("GET", "/api/ping"):
    api = viperhttp.Router(prefix="/api")

    @api.get("/ping")
    def ping():
        return {"pong": True}

    app.include_router(api)

if not _route_exists("WS", "/ws/echo"):
    @app.websocket("/ws/echo")
    async def ws_echo(ws):
        await ws.accept()
        while True:
            msg = await ws.receive()
            if msg.get("type") == "close":
                break
            opcode = msg.get("opcode", 2)
            if opcode == 1:
                await ws.send_text("echo:" + msg.get("text", ""))
            elif opcode == 2:
                await ws.send_bytes(msg.get("data", b""))


if not _route_exists("WS", "/ws/room"):
    @app.websocket("/ws/room")
    async def ws_room(ws):
        await _ws_manager.connect(ws)
        room = None
        try:
            await ws.send_json({"event": "connected"})
            while True:
                msg = await ws.receive()
                if msg.get("type") == "close":
                    break
                if msg.get("opcode", 2) != 1:
                    continue
                text = msg.get("text", "")
                if text.startswith("join:"):
                    new_room = text[5:] or "default"
                    if room is not None:
                        _ws_manager.leave_room(ws, room)
                    room = new_room
                    _ws_manager.join_room(ws, room)
                    await ws.send_json({"event": "joined", "room": room})
                    continue
                if text.startswith("say:"):
                    payload = {
                        "event": "message",
                        "room": room or "",
                        "text": text[4:],
                    }
                    await _ws_manager.broadcast_json(payload, room=room)
                    continue
                if text == "stats":
                    await ws.send_json({"event": "stats", "data": _ws_manager.stats()})
        finally:
            _ws_manager.disconnect(ws, room=room)


if not _route_exists("GET", "/stream"):
    @app.get("/stream")
    def stream_file():
        path = "/www/large.txt"
        try:
            size = uos.stat(path)[6]
        except Exception:
            size = 0
        def gen():
            f = open(path, "rb")
            try:
                while True:
                    chunk = f.read(16384)
                    if not chunk:
                        break
                    yield chunk
            finally:
                try:
                    f.close()
                except Exception:
                    pass
        return viperhttp.StreamingResponse(
            body=gen(),
            content_type="text/plain; charset=utf-8",
            total_len=size if size > 0 else None,
        )


if (not _file_mount_ok) and (not _route_exists("GET", "/file")):
    @app.get("/file")
    def file_response():
        return viperhttp.FileResponse("/www/large.txt")


if (not _file_mount_ok) and (not _route_exists("GET", "/file-html")):
    @app.get("/file-html")
    def file_response_html():
        return viperhttp.FileResponse("/www/veilcord.html")


if (not _file_mount_ok) and (not _route_exists("GET", "/file-missing")):
    @app.get("/file-missing")
    def file_response_missing():
        return viperhttp.FileResponse("/www/__missing__.txt")


if not _route_exists("GET", "/stream-chunked"):
    @app.get("/stream-chunked")
    def stream_chunked():
        def gen():
            for i in range(100):
                yield "chunk-%03d\n" % i
        return viperhttp.StreamingResponse(
            body=gen(),
            content_type="text/plain; charset=utf-8",
            chunked=True,
        )


if not _route_exists("GET", "/sse"):
    @app.get("/sse")
    def sse_demo():
        class _SSEGen:
            def __init__(self):
                self._i = 0
            def __aiter__(self):
                return self
            async def __anext__(self):
                if self._i >= 3:
                    raise StopAsyncIteration
                i = self._i
                self._i += 1
                await asyncio.sleep_ms(0)
                return {
                    "event": "tick",
                    "id": str(i),
                    "data": {"i": i},
                }
        return vhttp_responses.EventSourceResponse(_SSEGen(), retry=1000)


try:
    vhttp_autodocs.install(
        app,
        title="ViperHTTP Demo API",
        version=viperhttp.version(),
        description="Auto-generated OpenAPI and interactive docs for ViperHTTP demo app.",
        openapi_url="/openapi.json",
        docs_url="/docs",
        include_websocket=True,
        cache_schema=True,
    )
except Exception as exc:
    print("autodocs_install_error", repr(exc))

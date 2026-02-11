import viperhttp
import viperhttp_autodocs


def _require(condition, message):
    if not condition:
        raise AssertionError(message)


def _assert_method_route(app, method, path, expected):
    match = app.match(method, path)
    _require(match is not None, "match missing for %s %s" % (method, path))
    result = app.dispatch(method, path)
    _require(isinstance(result, dict), "dispatch result must be dict for %s %s" % (method, path))
    _require(result.get("method") == expected, "dispatch method mismatch for %s %s" % (method, path))


viperhttp.reset()
app = viperhttp.ViperHTTP(docs=False)


@app.get("/method-check")
def method_get():
    return {"method": "GET"}


@app.head("/method-check")
def method_head():
    return {"method": "HEAD"}


@app.options("/method-check")
def method_options():
    return {"method": "OPTIONS"}


router = viperhttp.Router(prefix="/r")


@router.head("/h")
def router_head():
    return {"method": "RHEAD"}


@router.options("/o")
def router_options():
    return {"method": "ROPTIONS"}


app.include_router(router)

_assert_method_route(app, "GET", "/method-check", "GET")
_assert_method_route(app, "HEAD", "/method-check", "HEAD")
_assert_method_route(app, "OPTIONS", "/method-check", "OPTIONS")
_assert_method_route(app, "HEAD", "/r/h", "RHEAD")
_assert_method_route(app, "OPTIONS", "/r/o", "ROPTIONS")

installed = viperhttp_autodocs.install(
    app,
    title="Method API",
    version="1.0.0",
    openapi_url="/openapi.json",
    docs_url=None,
)
_require(installed.get("openapi_url") == "/openapi.json", "openapi_url install mismatch")
_require(installed.get("docs_url") is None, "docs_url install mismatch")

spec_resp = app.dispatch("GET", "/openapi.json")
_require(isinstance(spec_resp, dict), "openapi dispatch response must be dict")
spec_body = spec_resp.get("body")
_require(isinstance(spec_body, dict), "openapi response body must be dict")

paths = spec_body.get("paths", {})
_require(isinstance(paths, dict), "openapi paths must be dict")

method_ops = paths.get("/method-check", {})
_require("get" in method_ops, "openapi missing get /method-check")
_require("head" in method_ops, "openapi missing head /method-check")
_require("options" in method_ops, "openapi missing options /method-check")

router_head_ops = paths.get("/r/h", {})
_require("head" in router_head_ops, "openapi missing head /r/h")
router_options_ops = paths.get("/r/o", {})
_require("options" in router_options_ops, "openapi missing options /r/o")

print("PASS: HEAD/OPTIONS decorators and OpenAPI entries work")

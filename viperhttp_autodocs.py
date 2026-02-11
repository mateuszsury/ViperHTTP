import viperhttp

try:
    import ujson as _json
except Exception:
    import json as _json


def _html_escape(value):
    text = str(value)
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    text = text.replace('"', "&quot;")
    return text


def _json_safe(value):
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (bytes, bytearray)):
        try:
            return value.decode("utf-8")
        except Exception:
            return str(value)
    if isinstance(value, dict):
        out = {}
        for key, val in value.items():
            out[str(key)] = _json_safe(val)
        return out
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    return str(value)


def _route_exists(app, method, path):
    try:
        return app.match(method, path) is not None
    except Exception:
        return False


def _docstring_parts(handler):
    raw = getattr(handler, "__doc__", None)
    if not raw:
        return None, None
    text = str(raw).strip()
    if not text:
        return None, None
    lines = text.split("\n")
    summary = lines[0].strip()
    description = "\n".join(line.rstrip() for line in lines[1:]).strip()
    if not description:
        description = None
    return summary or None, description


def _cast_to_schema(cast_obj):
    if cast_obj is int:
        return {"type": "integer", "format": "int64"}
    if cast_obj is float:
        return {"type": "number", "format": "float"}
    if cast_obj is bool:
        return {"type": "boolean"}
    return {"type": "string"}


def _path_type_to_schema(path_type):
    if path_type == "int":
        return {"type": "integer", "format": "int64"}
    if path_type == "float":
        return {"type": "number", "format": "float"}
    if path_type == "bool":
        return {"type": "boolean"}
    return {"type": "string"}


def _parse_path(path):
    text = str(path or "")
    out = []
    params = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch != "{":
            out.append(ch)
            i += 1
            continue
        j = text.find("}", i + 1)
        if j < 0:
            out.append(text[i:])
            break
        token = text[i + 1:j].strip()
        if not token:
            out.append("{}")
            i = j + 1
            continue
        if ":" in token:
            name, ptype = token.split(":", 1)
            name = name.strip() or "param"
            ptype = ptype.strip() or "str"
        else:
            name = token
            ptype = "str"
        out.append("{%s}" % name)
        params.append((name, ptype))
        i = j + 1
    return "".join(out), params


def _default_tag(path):
    parts = [p for p in str(path).split("/") if p]
    if not parts:
        return "root"
    head = parts[0]
    if head.startswith("{"):
        return "default"
    return head


def _operation_id(method, path):
    method = str(method).lower()
    cleaned = str(path).strip("/")
    if not cleaned:
        cleaned = "root"
    cleaned = cleaned.replace("/", "_")
    cleaned = cleaned.replace("{", "")
    cleaned = cleaned.replace("}", "")
    cleaned = cleaned.replace(":", "_")
    cleaned = cleaned.replace("-", "_")
    while "__" in cleaned:
        cleaned = cleaned.replace("__", "_")
    return "%s_%s" % (method, cleaned)


def _query_parameters(query_spec):
    if not isinstance(query_spec, dict):
        return []
    out = []
    for key, spec in query_spec.items():
        name = str(key)
        required = True
        schema = {"type": "string"}
        default = None
        has_default = False

        if isinstance(spec, dict) and spec.get("__vhttp_query__"):
            cast_obj = spec.get("cast")
            if cast_obj is not None:
                schema = _cast_to_schema(cast_obj)
            required = bool(spec.get("required", True))
            if "default" in spec:
                has_default = True
                default = spec.get("default")
        else:
            schema = _cast_to_schema(spec)

        item = {
            "name": name,
            "in": "query",
            "required": required,
            "schema": _json_safe(schema),
        }
        if has_default and default is not None:
            item["schema"]["default"] = _json_safe(default)
        out.append(item)
    return out


def _path_parameters(path_params):
    out = []
    for name, ptype in path_params:
        out.append(
            {
                "name": str(name),
                "in": "path",
                "required": True,
                "schema": _path_type_to_schema(str(ptype)),
            }
        )
    return out


def _responses_map(meta_responses):
    out = {}
    if isinstance(meta_responses, dict):
        for status, spec in meta_responses.items():
            key = str(status)
            if isinstance(spec, dict):
                out[key] = _json_safe(spec)
            elif isinstance(spec, str):
                out[key] = {"description": spec}
            else:
                out[key] = {"description": str(spec)}
    if "200" not in out and "201" not in out:
        out["200"] = {"description": "Successful Response"}
    if "422" not in out:
        out["422"] = {"description": "Validation Error"}
    return out


def _merge_docs(handler, route_docs):
    merged = {}
    handler_docs = getattr(handler, "__vhttp_docs__", None)
    if isinstance(handler_docs, dict):
        merged.update(handler_docs)
    if isinstance(route_docs, dict):
        merged.update(route_docs)
    return merged


def _iter_routes(app):
    try:
        rows = app.routes()
    except Exception:
        rows = []
    if not isinstance(rows, (list, tuple)):
        return []
    out = []
    for row in rows:
        if isinstance(row, dict):
            out.append(row)
    return out


def generate_openapi(app, title="ViperHTTP API", version="1.0.0", description="", servers=None, include_websocket=True):
    paths = {}
    ws_routes = []

    for row in _iter_routes(app):
        method = str(row.get("method", "")).upper()
        raw_path = str(row.get("path", ""))
        handler = row.get("handler")
        docs = _merge_docs(handler, row.get("docs"))
        if docs.get("include_in_schema") is False:
            continue

        openapi_path, path_params = _parse_path(raw_path)
        query_spec = row.get("query")
        deps_spec = row.get("deps")

        summary = docs.get("summary")
        description_text = docs.get("description")
        if not summary or not description_text:
            ds, dd = _docstring_parts(handler)
            if not summary:
                summary = ds
            if not description_text:
                description_text = dd

        tags = docs.get("tags")
        if isinstance(tags, str):
            tags = [tags]
        elif not isinstance(tags, (list, tuple)):
            tags = [_default_tag(raw_path)]

        op_id = docs.get("operation_id") or _operation_id(method, openapi_path)
        deprecated = bool(docs.get("deprecated", False))
        responses = _responses_map(docs.get("responses"))

        parameters = []
        parameters.extend(_path_parameters(path_params))
        parameters.extend(_query_parameters(query_spec))

        dep_names = []
        if isinstance(deps_spec, dict):
            dep_names = [str(k) for k in deps_spec.keys()]

        if method == "WS":
            if include_websocket:
                ws_routes.append(
                    {
                        "path": openapi_path,
                        "summary": summary or "",
                        "description": description_text or "",
                        "tags": _json_safe(tags),
                        "operationId": op_id,
                        "protocols": _json_safe(row.get("protocols") or []),
                    }
                )
            continue

        if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"):
            continue

        op = {
            "operationId": op_id,
            "tags": _json_safe(tags),
            "responses": _json_safe(responses),
        }
        if summary:
            op["summary"] = str(summary)
        if description_text:
            op["description"] = str(description_text)
        if deprecated:
            op["deprecated"] = True
        if parameters:
            op["parameters"] = _json_safe(parameters)
        if dep_names:
            op["x-dependencies"] = dep_names

        request_body = docs.get("request_body")
        if isinstance(request_body, dict):
            op["requestBody"] = _json_safe(request_body)
        elif method in ("POST", "PUT", "PATCH"):
            if op_id.startswith("post_json") or raw_path.endswith("/json"):
                op["requestBody"] = {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"type": "object"}
                        }
                    },
                }

        method_key = method.lower()
        if openapi_path not in paths:
            paths[openapi_path] = {}
        paths[openapi_path][method_key] = op

    info = {
        "title": str(title),
        "version": str(version),
    }
    if description:
        info["description"] = str(description)

    spec = {
        "openapi": "3.0.3",
        "info": info,
        "paths": paths,
        "components": {"schemas": {}},
        "x-viperhttp": {
            "generator": "viperhttp_autodocs",
            "route_count": len(paths),
        },
    }

    if servers:
        server_items = []
        for item in servers:
            if isinstance(item, str):
                server_items.append({"url": item})
            elif isinstance(item, dict) and "url" in item:
                server_items.append(_json_safe(item))
        if server_items:
            spec["servers"] = server_items

    if include_websocket and ws_routes:
        spec["x-websocket"] = ws_routes
    return _json_safe(spec)


def docs_meta(**kwargs):
    def _decorator(handler):
        existing = getattr(handler, "__vhttp_docs__", None)
        if not isinstance(existing, dict):
            existing = {}
        merged = dict(existing)
        merged.update(kwargs)
        setattr(handler, "__vhttp_docs__", merged)
        return handler
    return _decorator


def _build_docs_html(title, openapi_url):
    safe_title = _html_escape(title)
    safe_openapi_url = _html_escape(openapi_url)
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>%s</title>
  <style>
    :root { --bg:#f6f8fb; --card:#ffffff; --text:#1b2530; --muted:#5e6b78; --line:#d8e0ea; --accent:#0c7bdc; }
    body { margin:0; background:linear-gradient(180deg,#f6f8fb 0,#edf2f8 100%%); color:var(--text); font:14px/1.45 Consolas, "Cascadia Mono", monospace; }
    header { padding:20px; border-bottom:1px solid var(--line); background:#fff; position:sticky; top:0; }
    .wrap { max-width:1100px; margin:0 auto; padding:16px; }
    .path { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:12px; margin-bottom:10px; }
    .method { display:inline-block; min-width:56px; text-align:center; font-weight:700; border-radius:6px; color:#fff; padding:2px 8px; margin-right:8px; }
    .get{background:#0c7bdc}.post{background:#2e9f4d}.put{background:#8d5adf}.patch{background:#d98916}.delete{background:#cf3f3f}
    .muted { color:var(--muted); }
    pre { overflow:auto; background:#0f1720; color:#d6e7ff; padding:12px; border-radius:8px; }
    code { font-family:inherit; }
    .row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
    .tag { border:1px solid var(--line); border-radius:999px; padding:1px 8px; color:var(--muted); }
  </style>
</head>
<body>
  <header>
    <div class="wrap">
      <h2 style="margin:0 0 8px 0;">%s</h2>
      <div class="muted">Source: <code>%s</code></div>
    </div>
  </header>
  <div class="wrap">
    <div id="summary" class="muted">Loading OpenAPI schema...</div>
    <div id="routes"></div>
    <h3>Raw OpenAPI</h3>
    <pre id="raw"></pre>
  </div>
  <script>
    const url = "%s";
    const routesEl = document.getElementById("routes");
    const summaryEl = document.getElementById("summary");
    const rawEl = document.getElementById("raw");
    function esc(v){ return String(v).replace(/[&<>"]/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[s])); }
    function methodClass(m){ return String(m).toLowerCase(); }
    fetch(url).then(r => r.json()).then(spec => {
      const paths = spec.paths || {};
      const pathKeys = Object.keys(paths).sort();
      summaryEl.textContent = "Operations: " + pathKeys.length + " paths";
      let html = "";
      for (const p of pathKeys) {
        const item = paths[p] || {};
        for (const m of Object.keys(item)) {
          const op = item[m] || {};
          const tags = Array.isArray(op.tags) ? op.tags : [];
          html += '<div class="path">';
          html += '<div class="row"><span class="method ' + methodClass(m) + '">' + esc(m.toUpperCase()) + '</span><code>' + esc(p) + '</code></div>';
          if (op.summary) html += '<div style="margin-top:6px;">' + esc(op.summary) + '</div>';
          if (op.description) html += '<div class="muted" style="margin-top:4px;">' + esc(op.description) + '</div>';
          if (tags.length) html += '<div class="row" style="margin-top:6px;">' + tags.map(t => '<span class="tag">' + esc(t) + '</span>').join('') + '</div>';
          html += '</div>';
        }
      }
      routesEl.innerHTML = html || '<div class="muted">No routes in schema.</div>';
      rawEl.textContent = JSON.stringify(spec, null, 2);
    }).catch(err => {
      summaryEl.textContent = "Failed to load schema: " + err;
      routesEl.innerHTML = "";
      rawEl.textContent = "";
    });
  </script>
</body>
</html>
""" % (safe_title, safe_title, safe_openapi_url, safe_openapi_url)


def install(
    app,
    title="ViperHTTP API",
    version="1.0.0",
    description="",
    openapi_url="/openapi.json",
    docs_url="/docs",
    servers=None,
    include_websocket=True,
    cache_schema=True,
):
    cache = {"spec": None}

    def _normalize_optional_url(value):
        if value is None:
            return None
        value = str(value).strip()
        if not value:
            return None
        return value

    openapi_url = _normalize_optional_url(openapi_url)
    docs_url = _normalize_optional_url(docs_url)

    def _current_spec(force=False):
        if force or (not cache_schema) or cache["spec"] is None:
            cache["spec"] = generate_openapi(
                app=app,
                title=title,
                version=version,
                description=description,
                servers=servers,
                include_websocket=include_websocket,
            )
        return cache["spec"]

    if openapi_url is not None and not _route_exists(app, "GET", openapi_url):
        @app.get(
            openapi_url,
            include_in_schema=False,
            summary="OpenAPI schema",
            description="Machine-readable OpenAPI 3.0 schema",
            tags=["docs"],
        )
        def _openapi_json(refresh=""):
            force = str(refresh).lower() in ("1", "true", "yes", "on")
            body = _current_spec(force=force)
            return viperhttp.JSONResponse(
                body=body,
                headers={"Cache-Control": "no-store"},
            )

    # Match FastAPI semantics: docs UI requires an OpenAPI endpoint.
    if openapi_url is not None and docs_url is not None and not _route_exists(app, "GET", docs_url):
        @app.get(
            docs_url,
            include_in_schema=False,
            summary="Interactive API docs",
            description="Human-readable documentation page",
            tags=["docs"],
        )
        def _docs_html():
            html = _build_docs_html(title, openapi_url)
            return viperhttp.Response(
                body=html,
                content_type="text/html; charset=utf-8",
            )

    return {
        "openapi_url": openapi_url,
        "docs_url": docs_url,
    }

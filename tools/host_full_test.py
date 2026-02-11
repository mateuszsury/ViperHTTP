import argparse
import json
import base64
import sys
import time
import ssl
import http.client
import email.utils
import urllib.error
import urllib.parse
import urllib.request

URLLIB_SSL_CONTEXT = None


def fetch(url, data=None, headers=None, method=None):
    try:
        req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        with urllib.request.urlopen(req, timeout=5, context=URLLIB_SSL_CONTEXT) as resp:
            status = resp.status
            body = resp.read().decode("utf-8")
            return status, body, resp.headers
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8")
        return err.code, body, err.headers


def fetch_bytes(url, data=None, headers=None, method=None):
    try:
        req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        with urllib.request.urlopen(req, timeout=5, context=URLLIB_SSL_CONTEXT) as resp:
            status = resp.status
            body = resp.read()
            return status, body, resp.headers
    except urllib.error.HTTPError as err:
        body = err.read()
        return err.code, body, err.headers


def fetch_no_redirect(url, data=None, headers=None, method=None):
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    is_https = (parsed.scheme or "").lower() == "https"
    default_port = 443 if is_https else 80
    if is_https:
        conn = http.client.HTTPSConnection(
            parsed.hostname,
            parsed.port or default_port,
            timeout=5,
            context=URLLIB_SSL_CONTEXT,
        )
    else:
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port or default_port, timeout=5)
    try:
        conn.request(method or ("POST" if data is not None else "GET"), path, body=data, headers=headers or {})
        resp = conn.getresponse()
        status = resp.status
        body = resp.read()
        header_map = {k: v for k, v in resp.getheaders()}
        return status, body, header_map
    finally:
        conn.close()


def require(condition, message):
    if not condition:
        print("FAIL:", message)
        return False
    return True


def parse_json(body):
    try:
        return json.loads(body)
    except Exception:
        return None


def parse_content_range(value):
    if not value:
        return None
    if not value.startswith("bytes "):
        return None
    spec = value[6:].strip()
    if "/" not in spec:
        return None
    left, total = spec.split("/", 1)
    total = total.strip()
    if left == "*":
        return ("*", None, int(total)) if total.isdigit() else None
    if "-" not in left:
        return None
    start, end = left.split("-", 1)
    if not start.isdigit() or not end.isdigit() or not total.isdigit():
        return None
    return (int(start), int(end), int(total))


def shift_http_date(value, delta_seconds):
    if not value:
        return None
    try:
        dt = email.utils.parsedate_to_datetime(value)
        if dt is None:
            return None
        ts = int(dt.timestamp()) + int(delta_seconds)
        if ts < 0:
            ts = 0
        return email.utils.formatdate(ts, usegmt=True)
    except Exception:
        return None


def extract_cookie(headers, name):
    try:
        values = headers.get_all("Set-Cookie") or []
    except Exception:
        values = []
    for value in values:
        parts = value.split(";", 1)
        if not parts:
            continue
        if parts[0].startswith(name + "="):
            return parts[0].split("=", 1)[1]
    return None


def main():
    ap = argparse.ArgumentParser(description="ViperHTTP full host regression test")
    ap.add_argument("ip", help="Device IP address")
    ap.add_argument("--scheme", choices=["http", "https"], default="http")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--insecure", action="store_true", default=False, help="disable TLS cert verification")
    args = ap.parse_args()

    global URLLIB_SSL_CONTEXT
    if args.scheme == "https":
        if args.insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            URLLIB_SSL_CONTEXT = ctx
        else:
            URLLIB_SSL_CONTEXT = ssl.create_default_context()
    else:
        URLLIB_SSL_CONTEXT = None

    ip = args.ip
    base = f"{args.scheme}://{ip}:{args.port}"

    ok = True

    status, body, headers = fetch(base + "/")
    ok &= require(status == 200, f"index expected 200, got {status}")
    ctype = headers.get("Content-Type", "")
    ok &= require("text/html" in ctype, "index content-type mismatch")
    ok &= require("<h1>ViperHTTP</h1>" in body, "index body mismatch")

    status, body, headers = fetch(base + "/static/", headers={"Accept-Encoding": "identity"})
    ok &= require(status == 200, f"static index expected 200, got {status}")
    ctype = headers.get("Content-Type", "")
    ok &= require("text/html" in ctype, "static content-type mismatch")
    ok &= require("ViperHTTP Static" in body, "static index body mismatch")
    etag = headers.get("ETag", "")
    ok &= require(bool(etag), "static ETag missing")
    cache_control = headers.get("Cache-Control", "")
    ok &= require("max-age=" in cache_control, "static Cache-Control missing")
    if etag:
        status, body, _ = fetch(
            base + "/static/",
            headers={"If-None-Match": etag, "Accept-Encoding": "identity"},
        )
        ok &= require(status == 304, f"static ETag expected 304, got {status}")

    status, body, headers = fetch_bytes(base + "/static/large.txt", headers={"Accept-Encoding": "gzip"})
    ok &= require(status == 200, f"static gzip expected 200, got {status}")
    ok &= require(headers.get("Content-Encoding", "") == "gzip", "static gzip encoding missing")
    ok &= require(headers.get("Content-Length", ""), "static gzip length missing")
    try:
        import gzip as _gzip
        decoded = _gzip.decompress(body).decode("utf-8")
    except Exception:
        decoded = ""
    ok &= require("Line 0000" in decoded, "static gzip body mismatch")

    status, body, headers = fetch_bytes(base + "/static/large.txt")
    ok &= require(status == 200, f"static large expected 200, got {status}")
    ok &= require(b"Line 0000" in body, "static large body mismatch")
    static_large_len = len(body)
    clen = headers.get("Content-Length", "")
    if clen:
        try:
            ok &= require(int(clen) == len(body), "static large Content-Length mismatch")
        except Exception:
            ok &= require(False, "static large Content-Length parse failed")
    etag_large = headers.get("ETag", "")
    ok &= require(bool(etag_large), "static large ETag missing")
    static_large_lm = headers.get("Last-Modified", "")
    ok &= require(bool(static_large_lm), "static large Last-Modified missing")
    if etag_large:
        status, body, _ = fetch(base + "/static/large.txt", headers={"If-None-Match": etag_large})
        ok &= require(status == 304, f"static large ETag expected 304, got {status}")

        status, body, _ = fetch_bytes(
            base + "/static/large.txt",
            headers={"Range": "bytes=0-63", "If-Range": etag_large, "Accept-Encoding": "identity"},
        )
        ok &= require(status == 206, f"static If-Range ETag expected 206, got {status}")
        ok &= require(len(body) == 64, f"static If-Range ETag expected 64 bytes, got {len(body)}")

        status, body, _ = fetch_bytes(
            base + "/static/large.txt",
            headers={"Range": "bytes=0-63", "If-Range": "\"non-matching\"", "Accept-Encoding": "identity"},
        )
        ok &= require(status == 200, f"static If-Range mismatch expected 200, got {status}")
        ok &= require(len(body) == static_large_len, "static If-Range mismatch should return full body")

    if static_large_lm:
        status, body, _ = fetch_bytes(
            base + "/static/large.txt",
            headers={"Range": "bytes=0-63", "If-Range": static_large_lm, "Accept-Encoding": "identity"},
        )
        ok &= require(status == 206, f"static If-Range date expected 206, got {status}")

    stale_static_lm = shift_http_date(static_large_lm, -1)
    if stale_static_lm:
        status, body, _ = fetch_bytes(
            base + "/static/large.txt",
            headers={"Range": "bytes=0-63", "If-Range": stale_static_lm, "Accept-Encoding": "identity"},
        )
        ok &= require(status == 200, f"static stale If-Range date expected 200, got {status}")
        ok &= require(len(body) == static_large_len, "static stale If-Range date should return full body")

    status, body, headers = fetch_bytes(
        base + "/static/large.txt",
        headers={"Range": "bytes=0-63", "Accept-Encoding": "identity"},
    )
    ok &= require(status == 206, f"static range expected 206, got {status}")
    ok &= require(len(body) == 64, f"static range expected 64 bytes, got {len(body)}")
    ok &= require(headers.get("Accept-Ranges", "").lower() == "bytes", "static range Accept-Ranges missing")
    cr = parse_content_range(headers.get("Content-Range", ""))
    ok &= require(isinstance(cr, tuple) and cr[0] == 0 and cr[1] == 63, "static range Content-Range mismatch")

    status, body, headers = fetch_bytes(
        base + "/static/large.txt",
        headers={"Range": "bytes=-32", "Accept-Encoding": "identity"},
    )
    ok &= require(status == 206, f"static suffix range expected 206, got {status}")
    ok &= require(len(body) == 32, f"static suffix range expected 32 bytes, got {len(body)}")

    status, body, headers = fetch_bytes(
        base + "/static/large.txt",
        headers={"Range": "bytes=999999999-", "Accept-Encoding": "identity"},
    )
    ok &= require(status == 416, f"static invalid range expected 416, got {status}")
    cr = parse_content_range(headers.get("Content-Range", ""))
    ok &= require(isinstance(cr, tuple) and cr[0] == "*", "static invalid range Content-Range mismatch")

    status, body, headers = fetch_bytes(
        base + "/static/large.txt",
        headers={"Range": "bytes=0-3,8-15", "Accept-Encoding": "identity"},
    )
    ok &= require(status == 416, f"static multi-range expected 416, got {status}")

    status, body, headers = fetch_bytes(base + "/stream")
    ok &= require(status == 200, f"stream expected 200, got {status}")
    ok &= require(b"Line 0000" in body, "stream body mismatch")
    clen = headers.get("Content-Length", "")
    if clen:
        try:
            ok &= require(int(clen) == len(body), "stream Content-Length mismatch")
        except Exception:
            ok &= require(False, "stream Content-Length parse failed")

    status, body, headers = fetch_bytes(base + "/file")
    ok &= require(status == 200, f"file expected 200, got {status}")
    ok &= require(b"Line 0000" in body, "file body mismatch")
    file_len = len(body)
    ctype = headers.get("Content-Type", "")
    ok &= require("text/plain" in ctype, "file content-type mismatch")
    clen = headers.get("Content-Length", "")
    if clen:
        try:
            ok &= require(int(clen) == len(body), "file Content-Length mismatch")
        except Exception:
            ok &= require(False, "file Content-Length parse failed")
    file_etag = headers.get("ETag", "")
    ok &= require(bool(file_etag), "file ETag missing")
    file_lm = headers.get("Last-Modified", "")
    ok &= require(bool(file_lm), "file Last-Modified missing")
    file_cache_control = headers.get("Cache-Control", "")
    ok &= require("max-age=" in file_cache_control, "file Cache-Control missing (expected C static path)")

    status, body, headers = fetch_bytes(base + "/file", headers={"Accept-Encoding": "gzip"})
    ok &= require(status == 200, f"file gzip expected 200, got {status}")
    ok &= require(headers.get("Content-Encoding", "") == "gzip", "file gzip encoding missing (expected C static path)")
    ok &= require(headers.get("Vary", "") == "Accept-Encoding", "file gzip vary header mismatch")
    try:
        import gzip as _gzip
        decoded = _gzip.decompress(body).decode("utf-8")
    except Exception:
        decoded = ""
    ok &= require("Line 0000" in decoded, "file gzip body mismatch")

    if file_etag:
        status, body, _ = fetch_bytes(base + "/file", headers={"Range": "bytes=0-63", "If-Range": file_etag})
        ok &= require(status == 206, f"file If-Range ETag expected 206, got {status}")
        ok &= require(len(body) == 64, f"file If-Range ETag expected 64 bytes, got {len(body)}")

        status, body, _ = fetch_bytes(base + "/file", headers={"Range": "bytes=0-63", "If-Range": "\"file-nope\""})
        ok &= require(status == 200, f"file If-Range mismatch expected 200, got {status}")
        ok &= require(len(body) == file_len, "file If-Range mismatch should return full body")

    if file_lm:
        status, body, _ = fetch_bytes(base + "/file", headers={"Range": "bytes=0-63", "If-Range": file_lm})
        ok &= require(status == 206, f"file If-Range date expected 206, got {status}")

    stale_file_lm = shift_http_date(file_lm, -1)
    if stale_file_lm:
        status, body, _ = fetch_bytes(base + "/file", headers={"Range": "bytes=0-63", "If-Range": stale_file_lm})
        ok &= require(status == 200, f"file stale If-Range date expected 200, got {status}")
        ok &= require(len(body) == file_len, "file stale If-Range date should return full body")

    status, body, headers = fetch_bytes(base + "/file", headers={"Range": "bytes=0-63"})
    ok &= require(status == 206, f"file range expected 206, got {status}")
    ok &= require(len(body) == 64, f"file range expected 64 bytes, got {len(body)}")
    ok &= require(headers.get("Accept-Ranges", "").lower() == "bytes", "file range Accept-Ranges missing")
    cr = parse_content_range(headers.get("Content-Range", ""))
    ok &= require(isinstance(cr, tuple) and cr[0] == 0 and cr[1] == 63, "file range Content-Range mismatch")

    status, body, headers = fetch_bytes(base + "/file", headers={"Range": "bytes=999999999-"})
    ok &= require(status == 416, f"file invalid range expected 416, got {status}")
    cr = parse_content_range(headers.get("Content-Range", ""))
    ok &= require(isinstance(cr, tuple) and cr[0] == "*", "file invalid range Content-Range mismatch")

    status, body, headers = fetch_bytes(base + "/file", headers={"Range": "bytes=0-3,8-15"})
    ok &= require(status == 416, f"file multi-range expected 416, got {status}")

    status, body, headers = fetch_bytes(base + "/file-html")
    ok &= require(status == 200, f"file-html expected 200, got {status}")
    ok &= require(b"<html" in body.lower(), "file-html body mismatch")
    ctype = headers.get("Content-Type", "")
    ok &= require("text/html" in ctype, "file-html content-type mismatch")

    status, body, headers = fetch_bytes(base + "/stream-chunked")
    ok &= require(status == 200, f"stream-chunked expected 200, got {status}")
    te = headers.get("Transfer-Encoding", "")
    ok &= require("chunked" in te.lower(), "stream-chunked missing chunked encoding")
    ok &= require(b"chunk-000" in body, "stream-chunked body mismatch")

    status, body, headers = fetch_bytes(base + "/sse")
    ok &= require(status == 200, f"sse expected 200, got {status}")
    ctype = headers.get("Content-Type", "")
    ok &= require("text/event-stream" in ctype, "sse content-type mismatch")
    ok &= require(b"event: tick" in body, "sse event name missing")
    ok &= require(b"data: {\"i\": 0}" in body, "sse data missing")

    status, body, _ = fetch(base + "/hello")
    ok &= require(status == 200, f"hello expected 200, got {status}")
    data = parse_json(body)
    ok &= require(isinstance(data, dict), "hello response not JSON")
    ok &= require(data.get("message") == "ok", "hello message mismatch")

    status, body, _ = fetch(base + "/state")
    ok &= require(status == 200, f"state expected 200, got {status}")
    data = parse_json(body)
    ok &= require(isinstance(data, dict), "state response not JSON")
    if isinstance(data, dict):
        ok &= require(data.get("startup_ran") is True, "startup_ran mismatch")
        ok &= require(int(data.get("startup_calls", 0)) >= 1, "startup_calls mismatch")

    status, body, _ = fetch(base + "/raise-custom")
    ok &= require(status == 418, f"raise-custom expected 418, got {status}")
    data = parse_json(body)
    ok &= require(isinstance(data, dict), "raise-custom response not JSON")
    if isinstance(data, dict):
        ok &= require(data.get("type") == "DemoAppError", "raise-custom type mismatch")
        ok &= require("custom failure" in str(data.get("detail", "")), "raise-custom detail mismatch")

    status, body, headers = fetch_no_redirect(base + "/redirect")
    ok &= require(status == 307, f"redirect expected 307, got {status}")
    ok &= require(headers.get("Location") == "/hello", "redirect location mismatch")

    status, body, headers = fetch(base + "/mw")
    ok &= require(status == 200, f"mw expected 200, got {status}")
    ok &= require(headers.get("X-MW-1") == "on", "mw header X-MW-1 missing")
    ok &= require(headers.get("X-MW-2") == "on", "mw header X-MW-2 missing")
    data = parse_json(body)
    ok &= require(data.get("ok") is True, "mw body mismatch")

    status, body, _ = fetch(base + "/mw-block")
    ok &= require(status == 418, f"mw-block expected 418, got {status}")
    ok &= require("blocked" in body, "mw-block body mismatch")

    status, body, _ = fetch(base + "/mw-order")
    ok &= require(status == 200, f"mw-order expected 200, got {status}")
    data = parse_json(body)
    order = data.get("order", []) if isinstance(data, dict) else []
    ok &= require(order == ["A:pre", "B:pre", "B:post", "A:post"], "mw-order mismatch")

    status, body, _ = fetch(base + "/hello", headers={"Host": "evil.com"})
    ok &= require(status == 400, f"trusted host expected 400, got {status}")

    cors_headers = {
        "Origin": "http://example.com",
    }
    status, body, headers = fetch(base + "/hello", headers=cors_headers)
    ok &= require(status == 200, f"cors hello expected 200, got {status}")
    ok &= require(headers.get("Access-Control-Allow-Origin") == "*", "cors allow-origin mismatch")

    preflight_headers = {
        "Origin": "http://example.com",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "X-Test",
    }
    status, body, headers = fetch(base + "/hello", headers=preflight_headers, method="OPTIONS")
    ok &= require(status == 204, f"cors preflight expected 204, got {status}")
    ok &= require(headers.get("Access-Control-Allow-Origin") == "*", "cors preflight allow-origin mismatch")
    ok &= require("GET" in headers.get("Access-Control-Allow-Methods", ""), "cors preflight allow-methods missing")
    ok &= require(headers.get("Access-Control-Allow-Headers") in ("*", "X-Test"), "cors preflight allow-headers mismatch")

    status, body, _ = fetch(base + "/items/42")
    ok &= require(status == 200, f"items expected 200, got {status}")
    data = parse_json(body)
    ok &= require(data.get("item_id") == 42, "path param mismatch")

    status, body, _ = fetch(base + "/query?q=foo&page=2")
    ok &= require(status == 200, f"query expected 200, got {status}")
    data = parse_json(body)
    ok &= require(data.get("q") == "foo", "query q mismatch")
    ok &= require(data.get("page") == "2", "query page mismatch")

    status, body, _ = fetch(base + "/query-typed?q=hi&page=3&ratio=1.5&active=true")
    ok &= require(status == 200, f"query-typed expected 200, got {status}")
    data = parse_json(body)
    ok &= require(data.get("q") == "hi", "typed q mismatch")
    ok &= require(data.get("page") == 3, "typed page mismatch")
    ok &= require(abs(data.get("ratio", 0) - 1.5) < 1e-6, "typed ratio mismatch")
    ok &= require(data.get("active") is True, "typed active mismatch")

    status, body, _ = fetch(base + "/query-typed?q=hi")
    ok &= require(status == 422, f"query-typed missing expected 422, got {status}")
    ok &= require("Missing query param" in body, "missing detail mismatch")

    status, body, _ = fetch(base + "/query-typed?q=hi&page=bad&ratio=1.2")
    ok &= require(status == 422, f"query-typed invalid expected 422, got {status}")
    ok &= require("Invalid query param" in body, "invalid detail mismatch")

    status, body, headers = fetch(base + "/template?name=Ana&show_items=true&items=alpha,%3Cb%3E")
    ok &= require(status == 200, f"template expected 200, got {status}")
    ctype = headers.get("Content-Type", "")
    ok &= require("text/html" in ctype, "template content-type mismatch")
    ok &= require("Hello Ana" in body, "template name mismatch")
    ok &= require("&lt;b&gt;" in body, "template escape mismatch")
    ok &= require("<em>raw-fragment</em>" in body, "template safe filter mismatch")

    status, body, _ = fetch(base + "/template?show_items=false")
    ok &= require(status == 200, f"template hide expected 200, got {status}")
    ok &= require("No items" in body, "template if/else mismatch")

    status, body, headers = fetch(base + "/template?name=Ana&show_items=true&items=alpha,%3Cb%3E&stream=true")
    ok &= require(status == 200, f"template stream expected 200, got {status}")
    ctype = headers.get("Content-Type", "")
    ok &= require("text/html" in ctype, "template stream content-type mismatch")
    ok &= require("Hello Ana" in body, "template stream name mismatch")
    ok &= require("&lt;b&gt;" in body, "template stream escape mismatch")
    ok &= require("<em>raw-fragment</em>" in body, "template stream safe filter mismatch")
    transfer_encoding = (headers.get("Transfer-Encoding") or "").lower()
    content_length = headers.get("Content-Length")
    ok &= require(("chunked" in transfer_encoding) or (content_length in (None, "")), "template stream should be chunked or without Content-Length")

    status, body_bytes, headers = fetch_bytes(
        base + "/template?name=Ana&show_items=true&items=alpha,%3Cb%3E&stream=true&version=1",
        headers={"Accept-Encoding": "gzip"},
    )
    ok &= require(status == 200, f"template stream gzip expected 200, got {status}")
    ok &= require(headers.get("Content-Encoding", "") == "gzip", "template stream gzip encoding missing")
    vary = headers.get("Vary", "")
    ok &= require("accept-encoding" in vary.lower(), "template stream gzip vary missing")
    etag_tpl = headers.get("ETag", "")
    ok &= require(bool(etag_tpl), "template stream ETag missing")
    try:
        import gzip as _gzip
        body = _gzip.decompress(body_bytes).decode("utf-8")
    except Exception as exc:
        ok &= require(False, f"template stream gzip decode failed: {exc}")
        body = ""
    ok &= require("Hello Ana" in body, "template stream gzip body mismatch")
    ok &= require("public, max-age=60" in (headers.get("Cache-Control", "").lower()), "template stream cache-control missing")

    if etag_tpl:
        status, body, headers = fetch(
            base + "/template?name=Ana&show_items=true&items=alpha,%3Cb%3E&stream=true&version=1",
            headers={"If-None-Match": etag_tpl, "Accept-Encoding": "identity"},
        )
        ok &= require(status == 304, f"template stream if-none-match expected 304, got {status}")
        ok &= require(body == "", "template stream 304 body should be empty")

    status, body, headers = fetch(
        base + "/template-compat?name=%20Ana%20&count=2&role=user&roles=user,viewer&items=a,%3Cb%3E,c"
    )
    ok &= require(status == 200, f"template-compat expected 200, got {status}")
    ok &= require("COND_OK" in body, "template-compat comparison/and mismatch")
    ok &= require("ROLE_IN" in body, "template-compat in mismatch")
    ok &= require("NO_ADMIN" in body, "template-compat not in mismatch")
    ok &= require("MISSING_UNDEFINED" in body, "template-compat is undefined mismatch")
    ok &= require("NONE_OK" in body, "template-compat is none mismatch")
    ok &= require("LOCAL_STRING" in body, "template-compat is string mismatch")
    ok &= require("ITEM=1/3/2:a" in body, "template-compat loop metadata mismatch")
    ok &= require("ITEM=2/3/1:(b)" in body, "template-compat replace mismatch")
    ok &= require("JOIN=a | &lt;b&gt; | c" in body, "template-compat join/escape mismatch")
    ok &= require("TITLE=Ana" in body, "template-compat title mismatch")
    ok &= require("CAP=Ana" in body, "template-compat capitalize mismatch")

    status, body, _ = fetch(base + "/template-compat?items=")
    ok &= require(status == 200, f"template-compat empty items expected 200, got {status}")
    ok &= require("NO_ITEMS" in body, "template-compat for-else mismatch")

    status, body, headers = fetch(base + "/ui")
    ok &= require(status == 200, f"ui expected 200, got {status}")
    ctype = headers.get("Content-Type", "")
    ok &= require("text/html" in ctype, "ui content-type mismatch")
    ok &= require("ViperHTTP Control Hub" in body, "ui title mismatch")
    ok &= require("/ws/echo" in body, "ui websocket links missing")
    ok &= require("/session/login" in body, "ui session links missing")

    status, body, headers = fetch(base + "/openapi.json")
    ok &= require(status == 200, f"openapi expected 200, got {status}")
    ctype = headers.get("Content-Type", "")
    ok &= require("application/json" in ctype, "openapi content-type mismatch")
    data = parse_json(body)
    ok &= require(isinstance(data, dict), "openapi response not JSON")
    if isinstance(data, dict):
        ok &= require(data.get("openapi") == "3.0.3", "openapi version mismatch")
        paths = data.get("paths")
        ok &= require(isinstance(paths, dict), "openapi paths missing")
        if isinstance(paths, dict):
            ok &= require("/hello" in paths, "openapi missing /hello")
            hello_item = paths.get("/hello", {})
            ok &= require(isinstance(hello_item, dict) and "get" in hello_item, "openapi missing /hello get")
            ok &= require("/docs" not in paths, "docs route should not be in schema")
            ok &= require("/openapi.json" not in paths, "openapi route should not be in schema")
        ws = data.get("x-websocket")
        ok &= require(isinstance(ws, list), "openapi websocket extension missing")
        if isinstance(ws, list):
            ok &= require(any(isinstance(item, dict) and item.get("path") == "/ws/echo" for item in ws), "openapi missing ws /ws/echo")

    status, body, headers = fetch(base + "/docs")
    ok &= require(status == 200, f"docs expected 200, got {status}")
    ctype = headers.get("Content-Type", "")
    ok &= require("text/html" in ctype, "docs content-type mismatch")
    ok &= require("OpenAPI schema" in body or "Loading OpenAPI schema" in body, "docs html content mismatch")

    status, body, _ = fetch(base + "/debug/log-level")
    ok &= require(status == 200, f"debug/log-level expected 200, got {status}")
    data = parse_json(body)
    ok &= require(isinstance(data, dict), "debug/log-level response not JSON")
    if isinstance(data, dict):
        ok &= require(isinstance(data.get("value"), int), "debug/log-level value type mismatch")
        ok &= require(isinstance(data.get("name"), str), "debug/log-level name type mismatch")

    status, body, _ = fetch(base + "/debug/log-level?level=debug")
    ok &= require(status == 200, f"debug/log-level set debug expected 200, got {status}")
    data = parse_json(body)
    ok &= require(data.get("name") == "debug", "debug/log-level set debug mismatch")

    status, body, _ = fetch(base + "/debug/log-level?level=2")
    ok &= require(status == 200, f"debug/log-level set 2 expected 200, got {status}")
    data = parse_json(body)
    ok &= require(data.get("value") == 2, "debug/log-level set 2 mismatch")

    status, body, _ = fetch(base + "/debug/log-level?level=bogus")
    ok &= require(status == 400, f"debug/log-level invalid expected 400, got {status}")

    status, body, _ = fetch(base + "/debug/log-level?level=info")
    ok &= require(status == 200, f"debug/log-level restore info expected 200, got {status}")
    data = parse_json(body)
    ok &= require(data.get("name") == "info", "debug/log-level restore mismatch")

    status, body, _ = fetch(base + "/debug/server-stats?reset=1")
    ok &= require(status == 200, f"debug/server-stats reset expected 200, got {status}")
    data = parse_json(body)
    ok &= require(isinstance(data, dict), "debug/server-stats response not JSON")
    server_stats = data.get("server", {}) if isinstance(data, dict) else {}
    ipc_stats = data.get("ipc", {}) if isinstance(data, dict) else {}
    ok &= require(isinstance(server_stats, dict), "debug/server-stats.server not JSON object")
    ok &= require(isinstance(ipc_stats, dict), "debug/server-stats.ipc not JSON object")
    if isinstance(server_stats, dict):
        ok &= require(isinstance(server_stats.get("accepts_total"), int), "server_stats.accepts_total type mismatch")
        ok &= require(isinstance(server_stats.get("accepts_enqueued"), int), "server_stats.accepts_enqueued type mismatch")
        ok &= require(isinstance(server_stats.get("accepts_rejected"), int), "server_stats.accepts_rejected type mismatch")
        ok &= require(isinstance(server_stats.get("accept_queue_used"), int), "server_stats.accept_queue_used type mismatch")
        ok &= require(isinstance(server_stats.get("accept_queue_peak"), int), "server_stats.accept_queue_peak type mismatch")
        ok &= require(isinstance(server_stats.get("workers_active"), int), "server_stats.workers_active type mismatch")
        ok &= require(isinstance(server_stats.get("workers_started"), int), "server_stats.workers_started type mismatch")
        ok &= require(isinstance(server_stats.get("workers_limit_min"), int), "server_stats.workers_limit_min type mismatch")
        ok &= require(isinstance(server_stats.get("workers_limit_max"), int), "server_stats.workers_limit_max type mismatch")
        ok &= require(isinstance(server_stats.get("workers_recv_psram"), int), "server_stats.workers_recv_psram type mismatch")
        ok &= require(isinstance(server_stats.get("workers_recv_ram"), int), "server_stats.workers_recv_ram type mismatch")
        ok &= require(isinstance(server_stats.get("ws_handoffs"), int), "server_stats.ws_handoffs type mismatch")
        ok &= require(isinstance(server_stats.get("ws_tasks_active"), int), "server_stats.ws_tasks_active type mismatch")
        ok &= require(isinstance(server_stats.get("requests_handled"), int), "server_stats.requests_handled type mismatch")
        ok &= require(isinstance(server_stats.get("request_errors"), int), "server_stats.request_errors type mismatch")
        ok &= require(isinstance(server_stats.get("ipc_req_ring_alloc_fail"), int), "server_stats.ipc_req_ring_alloc_fail type mismatch")
        ok &= require(isinstance(server_stats.get("ipc_req_queue_push_fail"), int), "server_stats.ipc_req_queue_push_fail type mismatch")
        ok &= require(isinstance(server_stats.get("backpressure_503_sent"), int), "server_stats.backpressure_503_sent type mismatch")
        ok &= require(isinstance(server_stats.get("ipc_pending_peak"), int), "server_stats.ipc_pending_peak type mismatch")
        workers_started = server_stats.get("workers_started")
        workers_limit_min = server_stats.get("workers_limit_min")
        workers_limit_max = server_stats.get("workers_limit_max")
        workers_recv_psram = server_stats.get("workers_recv_psram")
        workers_recv_ram = server_stats.get("workers_recv_ram")
        if isinstance(workers_started, int) and isinstance(workers_recv_psram, int) and isinstance(workers_recv_ram, int):
            ok &= require(
                workers_recv_psram + workers_recv_ram <= workers_started,
                "server_stats worker recv memory counters exceed workers_started",
            )
        if isinstance(workers_limit_min, int) and isinstance(workers_limit_max, int):
            ok &= require(workers_limit_min >= 1, "server_stats workers_limit_min must be >= 1")
            ok &= require(workers_limit_min <= workers_limit_max, "server_stats worker limits ordering invalid")
    if isinstance(ipc_stats, dict):
        ok &= require(isinstance(ipc_stats.get("ring_size"), int), "ipc_stats.ring_size type mismatch")

    status, body, _ = fetch(base + "/debug/memory-stats")
    ok &= require(status == 200, f"debug/memory-stats expected 200, got {status}")
    data = parse_json(body)
    ok &= require(isinstance(data, dict), "debug/memory-stats response not JSON")
    if isinstance(data, dict):
        heap = data.get("heap")
        ok &= require(isinstance(heap, dict), "debug/memory-stats heap not JSON object")
        if isinstance(heap, dict):
            ok &= require(isinstance(heap.get("psram_available"), bool), "heap_stats.psram_available type mismatch")
            ok &= require(isinstance(heap.get("internal_free"), int), "heap_stats.internal_free type mismatch")
            ok &= require(isinstance(heap.get("internal_largest"), int), "heap_stats.internal_largest type mismatch")
            ok &= require(isinstance(heap.get("psram_free"), int), "heap_stats.psram_free type mismatch")

    status, body, _ = fetch(base + "/deps")
    ok &= require(status == 200, f"deps expected 200, got {status}")
    data = parse_json(body)
    ok &= require(data.get("value") == 42, "deps value mismatch")

    status, body, _ = fetch(base + "/deps/async")
    ok &= require(status == 200, f"deps/async expected 200, got {status}")
    data = parse_json(body)
    ok &= require(data.get("value") == 42, "deps/async value mismatch")

    status, body, _ = fetch(base + "/deps/features")
    ok &= require(status == 200, f"deps/features expected 200, got {status}")
    data = parse_json(body)
    ok &= require(isinstance(data, dict), "deps/features response not JSON")
    if isinstance(data, dict):
        ok &= require(isinstance(data.get("async_generator_supported"), bool), "deps/features async_generator_supported must be bool")
        mode = data.get("async_yield_mode")
        ok &= require(mode in ("native", "yield-fallback"), "deps/features async_yield_mode invalid")

    status, body, _ = fetch(base + "/deps/class")
    ok &= require(status == 200, f"deps/class expected 200, got {status}")
    data = parse_json(body)
    ok &= require(data.get("value") == 42, "deps/class value mismatch")

    status, body, _ = fetch(base + "/deps/class-async")
    ok &= require(status == 200, f"deps/class-async expected 200, got {status}")
    data = parse_json(body)
    ok &= require(data.get("value") == 42, "deps/class-async value mismatch")

    status, body, _ = fetch(base + "/deps/yield-state")
    ok &= require(status == 200, f"deps/yield-state expected 200, got {status}")
    before_yield_state = parse_json(body) or {}
    before_yield_enter = int(before_yield_state.get("enter", 0))
    before_yield_exit = int(before_yield_state.get("exit", 0))

    status, body, _ = fetch(base + "/deps/yield")
    ok &= require(status == 200, f"deps/yield expected 200, got {status}")
    data = parse_json(body)
    ok &= require(data.get("resource") == "yield-resource", "deps/yield resource mismatch")

    status, body, _ = fetch(base + "/deps/yield-state")
    ok &= require(status == 200, f"deps/yield-state after expected 200, got {status}")
    after_yield_state = parse_json(body) or {}
    after_yield_enter = int(after_yield_state.get("enter", 0))
    after_yield_exit = int(after_yield_state.get("exit", 0))
    ok &= require(after_yield_enter == before_yield_enter + 1, "deps/yield enter counter mismatch")
    ok &= require(after_yield_exit == before_yield_exit + 1, "deps/yield exit counter mismatch")

    status, body, _ = fetch(base + "/deps/async-yield-state")
    ok &= require(status == 200, f"deps/async-yield-state expected 200, got {status}")
    before_async_yield_state = parse_json(body) or {}
    before_async_yield_enter = int(before_async_yield_state.get("enter", 0))
    before_async_yield_exit = int(before_async_yield_state.get("exit", 0))

    status, body, _ = fetch(base + "/deps/async-yield")
    ok &= require(status == 200, f"deps/async-yield expected 200, got {status}")
    data = parse_json(body)
    ok &= require(data.get("resource") == "async-yield-resource", "deps/async-yield resource mismatch")

    status, body, _ = fetch(base + "/deps/async-yield-state")
    ok &= require(status == 200, f"deps/async-yield-state after expected 200, got {status}")
    after_async_yield_state = parse_json(body) or {}
    after_async_yield_enter = int(after_async_yield_state.get("enter", 0))
    after_async_yield_exit = int(after_async_yield_state.get("exit", 0))
    ok &= require(after_async_yield_enter == before_async_yield_enter + 1, "deps/async-yield enter counter mismatch")
    ok &= require(after_async_yield_exit == before_async_yield_exit + 1, "deps/async-yield exit counter mismatch")

    status, body, _ = fetch(base + "/api/ping")
    ok &= require(status == 200, f"router expected 200, got {status}")
    data = parse_json(body)
    ok &= require(data.get("pong") is True, "router pong mismatch")

    payload = json.dumps({"msg": "hi", "count": 3}).encode("utf-8")
    status, body, _ = fetch(
        base + "/json",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    ok &= require(status == 200, f"json expected 200, got {status}")
    data = parse_json(body)
    ok &= require(data.get("ok") is True, "json ok mismatch")
    json_body = data.get("data", {})
    ok &= require(json_body.get("msg") == "hi", "json msg mismatch")
    ok &= require(json_body.get("count") == 3, "json count mismatch")

    status, body, _ = fetch(
        base + "/json",
        data=b"{bad",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    ok &= require(status == 400, f"json invalid expected 400, got {status}")
    ok &= require("Invalid JSON" in body, "json invalid detail mismatch")

    form_body = b"name=alice&role=admin"
    status, body, _ = fetch(
        base + "/form",
        data=form_body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    ok &= require(status == 200, f"form expected 200, got {status}")
    data = parse_json(body)
    form = data.get("form", {}) if isinstance(data, dict) else {}
    ok &= require(form.get("name") == "alice", "form name mismatch")
    ok &= require(form.get("role") == "admin", "form role mismatch")

    boundary = "----viperhttpboundary"
    mp_parts = [
        f"--{boundary}\r\n".encode("utf-8"),
        b'Content-Disposition: form-data; name="title"\r\n\r\n',
        b"hello\r\n",
        f"--{boundary}\r\n".encode("utf-8"),
        b'Content-Disposition: form-data; name="file"; filename="note.txt"\r\n',
        b"Content-Type: text/plain\r\n\r\n",
        b"filedata\r\n",
        f"--{boundary}--\r\n".encode("utf-8"),
    ]
    mp_body = b"".join(mp_parts)
    status, body, _ = fetch(
        base + "/multipart",
        data=mp_body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    ok &= require(status == 200, f"multipart expected 200, got {status}")
    data = parse_json(body)
    ok &= require(data.get("title") == "hello", "multipart title mismatch")
    file_info = data.get("file", {}) if isinstance(data, dict) else {}
    ok &= require(file_info.get("filename") == "note.txt", "multipart filename mismatch")
    ok &= require(file_info.get("content_type") == "text/plain", "multipart content-type mismatch")
    ok &= require(file_info.get("size") == 8, "multipart size mismatch")

    status, body, _ = fetch(
        base + "/uploadfile",
        data=mp_body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    ok &= require(status == 200, f"uploadfile expected 200, got {status}")
    data = parse_json(body)
    ok &= require(isinstance(data, dict), "uploadfile response not JSON")
    if isinstance(data, dict):
        ok &= require(data.get("filename") == "note.txt", "uploadfile filename mismatch")
        ok &= require(data.get("content_type") == "text/plain", "uploadfile content-type mismatch")
        ok &= require(data.get("size") == 8, "uploadfile size mismatch")
        ok &= require(data.get("head") == "file", "uploadfile head mismatch")
        ok &= require(data.get("body") == "filedata", "uploadfile body mismatch")

    status, body, _ = fetch(base + "/background?msg=bg-ok", method="POST")
    ok &= require(status == 200, f"background expected 200, got {status}")
    time.sleep(0.2)
    status, body, _ = fetch(base + "/background/status")
    ok &= require(status == 200, f"background status expected 200, got {status}")
    data = parse_json(body)
    log = data.get("log", []) if isinstance(data, dict) else []
    ok &= require("bg-ok" in log, "background task not executed")

    headers = {"X-Test": "yes"}
    status, body, _ = fetch(
        base + "/request-info?foo=1&bar=test",
        data=b"payload",
        headers=headers,
        method="POST",
    )
    ok &= require(status == 200, f"request-info expected 200, got {status}")
    data = parse_json(body)
    ok &= require(data.get("method") == "POST", "request method mismatch")
    ok &= require(data.get("path") == "/request-info", "request path mismatch")
    qparams = data.get("query_params", {})
    ok &= require(qparams.get("foo") == "1", "request query foo mismatch")
    ok &= require(qparams.get("bar") == "test", "request query bar mismatch")
    headers_out = data.get("headers", {})
    header_value = None
    for key, value in headers_out.items():
        if isinstance(key, str) and key.lower() == "x-test":
            header_value = value
            break
    ok &= require(header_value == "yes", "request header mismatch")
    ok &= require(data.get("body") == "payload", "request body mismatch")

    status, body, _ = fetch(
        base + "/cookies",
        headers={"Cookie": "session=abc; theme=dark; empty=; spaced = value"},
    )
    ok &= require(status == 200, f"cookies expected 200, got {status}")
    data = parse_json(body)
    cookies = data.get("cookies", {}) if isinstance(data, dict) else {}
    ok &= require(cookies.get("session") == "abc", "cookie session mismatch")
    ok &= require(cookies.get("theme") == "dark", "cookie theme mismatch")
    ok &= require(cookies.get("empty") == "", "cookie empty mismatch")
    ok &= require(cookies.get("spaced") == "value", "cookie spaced mismatch")

    payload = json.dumps({"username": "alice"}).encode("utf-8")
    status, body, headers = fetch(
        base + "/session/login",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    ok &= require(status == 200, f"session login expected 200, got {status}")
    session_cookie = extract_cookie(headers, "vhttp_session")
    ok &= require(bool(session_cookie), "session cookie missing")

    if session_cookie:
        origin = f"http://{ip}:8080"
        status, body, _ = fetch(
            base + "/session/csrf",
            headers={"Cookie": f"vhttp_session={session_cookie}"},
        )
        ok &= require(status == 200, f"session csrf expected 200, got {status}")
        data = parse_json(body)
        csrf_token = data.get("token") if isinstance(data, dict) else None
        ok &= require(bool(csrf_token), "csrf token missing")

        status, body, _ = fetch(
            base + "/session/protected",
            headers={"Cookie": f"vhttp_session={session_cookie}", "Origin": origin},
            method="POST",
        )
        ok &= require(status == 403, f"csrf protected expected 403, got {status}")

        if csrf_token:
            status, body, _ = fetch(
                base + "/session/protected",
                headers={
                    "Cookie": f"vhttp_session={session_cookie}",
                    "X-CSRF-Token": csrf_token,
                    "Origin": origin,
                },
                method="POST",
            )
            ok &= require(status == 200, f"csrf protected expected 200, got {status}")

        status, body, _ = fetch(
            base + "/session/whoami",
            headers={"Cookie": f"vhttp_session={session_cookie}"},
        )
        ok &= require(status == 200, f"session whoami expected 200, got {status}")
        data = parse_json(body)
        user = data.get("user", {}) if isinstance(data, dict) else {}
        ok &= require(user.get("username") == "alice", "session user mismatch")
        ok &= require(user.get("source") == "session", "session source mismatch")

        status, body, _ = fetch(
            base + "/session/logout",
            headers={
                "Cookie": f"vhttp_session={session_cookie}",
                "X-CSRF-Token": csrf_token or "",
                "Origin": origin,
            },
            method="POST",
        )
        ok &= require(status == 200, f"session logout expected 200, got {status}")

        status, body, _ = fetch(
            base + "/session/whoami",
            headers={"Cookie": f"vhttp_session={session_cookie}"},
        )
        ok &= require(status == 401, f"session whoami expected 401, got {status}")

    status, body, _ = fetch(
        base + "/auth/bearer",
        headers={"Authorization": "Bearer testtoken"},
    )
    ok &= require(status == 200, f"bearer expected 200, got {status}")
    data = parse_json(body)
    user = data.get("user", {}) if isinstance(data, dict) else {}
    ok &= require(user.get("source") == "bearer", "bearer source mismatch")

    status, body, _ = fetch(
        base + "/auth/admin",
        headers={"Authorization": "Bearer testtoken"},
    )
    ok &= require(status == 403, f"admin expected 403, got {status}")

    status, body, _ = fetch(
        base + "/auth/admin",
        headers={"Authorization": "Bearer admintoken"},
    )
    ok &= require(status == 200, f"admin expected 200, got {status}")
    data = parse_json(body)
    user = data.get("user", {}) if isinstance(data, dict) else {}
    ok &= require("admin" in (user.get("roles") or []), "admin role missing")

    status, body, _ = fetch(
        base + "/auth/apikey",
        headers={"X-API-Key": "testkey"},
    )
    ok &= require(status == 200, f"apikey expected 200, got {status}")
    data = parse_json(body)
    user = data.get("user", {}) if isinstance(data, dict) else {}
    ok &= require(user.get("source") == "apikey", "apikey source mismatch")

    basic = base64.b64encode(b"admin:secret").decode("ascii")
    status, body, _ = fetch(
        base + "/auth/basic",
        headers={"Authorization": f"Basic {basic}"},
    )
    ok &= require(status == 200, f"basic expected 200, got {status}")
    data = parse_json(body)
    user = data.get("user", {}) if isinstance(data, dict) else {}
    ok &= require(user.get("source") == "basic", "basic source mismatch")

    if ok:
        print("PASS")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

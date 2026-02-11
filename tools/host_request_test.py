import json
import sys
import urllib.error
import urllib.request


def fetch(url, data=None, headers=None, method=None):
    try:
        req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        with urllib.request.urlopen(req, timeout=5) as resp:
            status = resp.status
            body = resp.read().decode("utf-8")
            return status, body
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8")
        return err.code, body


def require(condition, message):
    if not condition:
        print("FAIL:", message)
        return False
    return True


def main():
    if len(sys.argv) != 2:
        print("usage: python tools/host_request_test.py <ip>")
        return 2

    ip = sys.argv[1]
    base = f"http://{ip}:8080"
    url = base + "/request-info?foo=1&bar=test"
    headers = {"X-Test": "yes"}
    status, body = fetch(url, data=b"payload", headers=headers, method="POST")

    ok = True
    ok &= require(status == 200, f"expected 200, got {status}")
    try:
        data = json.loads(body)
    except Exception:
        print("FAIL: response is not JSON")
        return 1

    ok &= require(data.get("method") == "POST", "method mismatch")
    ok &= require(data.get("path") == "/request-info", "path mismatch")
    qparams = data.get("query_params", {})
    ok &= require(qparams.get("foo") == "1", "query foo mismatch")
    ok &= require(qparams.get("bar") == "test", "query bar mismatch")

    headers_out = data.get("headers", {})
    header_value = None
    for key, value in headers_out.items():
        if isinstance(key, str) and key.lower() == "x-test":
            header_value = value
            break
    ok &= require(header_value == "yes", "header mismatch")

    ok &= require(data.get("body") == "payload", "body mismatch")

    if ok:
        print("PASS")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

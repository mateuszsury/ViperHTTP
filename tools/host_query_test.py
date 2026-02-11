import json
import sys
import urllib.error
import urllib.request


def fetch(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
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
        print("usage: python tools/host_query_test.py <ip>")
        return 2

    ip = sys.argv[1]
    base = f"http://{ip}:8080"

    ok = True
    status, body = fetch(base + "/query-typed?q=hi&page=3&ratio=1.5&active=true")
    ok &= require(status == 200, f"expected 200, got {status}")
    try:
        data = json.loads(body)
    except Exception:
        print("FAIL: response is not JSON")
        return 1
    ok &= require(data.get("q") == "hi", "q mismatch")
    ok &= require(data.get("page") == 3, "page mismatch")
    ok &= require(abs(data.get("ratio", 0) - 1.5) < 1e-6, "ratio mismatch")
    ok &= require(data.get("active") is True, "active mismatch")

    status, body = fetch(base + "/query-typed?q=hi")
    ok &= require(status == 422, f"expected 422 for missing, got {status}")
    ok &= require("Missing query param" in body, "missing detail mismatch")

    status, body = fetch(base + "/query-typed?q=hi&page=bad&ratio=1.2")
    ok &= require(status == 422, f"expected 422 for invalid, got {status}")
    ok &= require("Invalid query param" in body, "invalid detail mismatch")

    if ok:
        print("PASS")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

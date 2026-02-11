import argparse
import json
import ssl
import subprocess
import sys
import urllib.request


def run_step(name, cmd):
    print(f"\n== {name} ==")
    print(" ".join(cmd))
    rc = subprocess.call(cmd)
    if rc != 0:
        print(f"FAIL: {name} (exit {rc})")
        return False
    print(f"OK: {name}")
    return True


def fetch_server_stats(ip, port, insecure):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    url = f"https://{ip}:{port}/debug/server-stats"
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
        body = resp.read().decode("utf-8", "ignore")
        return json.loads(body)


def main():
    ap = argparse.ArgumentParser(description="Run HTTPS + WSS regression suite on device")
    ap.add_argument("ip", help="Device IP address")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--wss-repeat", type=int, default=1, help="repeat WSS test cycles")
    ap.add_argument("--insecure", action="store_true", default=False, help="disable TLS cert verification")
    args = ap.parse_args()

    py = sys.executable
    ok = True

    cmd_http = [
        py,
        "tools/host_full_test.py",
        args.ip,
        "--scheme",
        "https",
        "--port",
        str(args.port),
    ]
    if args.insecure:
        cmd_http.append("--insecure")
    ok &= run_step("HTTPS full host test", cmd_http)

    cmd_ws = [
        py,
        "tools/ws_test.py",
        args.ip,
        "--scheme",
        "wss",
        "--port",
        str(args.port),
        "--repeat",
        str(max(1, int(args.wss_repeat))),
    ]
    if args.insecure:
        cmd_ws.append("--insecure")
    ok &= run_step("WSS test", cmd_ws)

    cmd_h2 = [
        py,
        "tools/http2_request_test.py",
        args.ip,
        "--scheme",
        "https",
        "--port",
        str(args.port),
        "--alpn-h2",
        "--expect-status",
        "200",
        "--expect-substring",
        "http2",
    ]
    if args.insecure:
        cmd_h2.append("--insecure")
    ok &= run_step("HTTPS HTTP/2 ALPN test", cmd_h2)

    print("\n== HTTPS stats verification ==")
    try:
        payload = fetch_server_stats(args.ip, args.port, args.insecure)
        server = payload.get("server", {})
        https_enabled = int(server.get("https_enabled", 0))
        hs_ok = int(server.get("https_handshake_ok", 0))
        hs_fail = int(server.get("https_handshake_fail", 0))
        print(f"https_enabled={https_enabled} handshake_ok={hs_ok} handshake_fail={hs_fail}")
        if https_enabled != 1:
            print("FAIL: https_enabled != 1")
            ok = False
        if hs_ok < 1:
            print("FAIL: https_handshake_ok < 1")
            ok = False
    except Exception as exc:
        print(f"FAIL: unable to read HTTPS stats: {exc!r}")
        ok = False

    if ok:
        print("\nHTTPS TESTS PASS")
        return 0
    print("\nHTTPS TESTS FAIL")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

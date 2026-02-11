#!/usr/bin/env python3
import argparse
import http.client
import json
import ssl
import statistics
import subprocess
import sys
import time
import urllib.request

from http_bench import bench_endpoint


def build_ssl_context(insecure):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch_server_stats(ip, port, insecure, reset=False):
    ctx = build_ssl_context(insecure)
    suffix = "?reset=1" if reset else ""
    url = f"https://{ip}:{port}/debug/server-stats{suffix}"
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
        return json.loads(resp.read().decode("utf-8", "ignore"))


def percentile(values, p):
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    idx = max(0, min(len(values) - 1, int(round((len(values) - 1) * p))))
    ordered = sorted(values)
    return float(ordered[idx])


def handshake_latency_profile(ip, port, insecure, count, timeout):
    out = []
    ctx = build_ssl_context(insecure)
    for _ in range(max(1, int(count))):
        conn = http.client.HTTPSConnection(ip, port=port, timeout=timeout, context=ctx)
        t0 = time.perf_counter()
        conn.request("GET", "/hello", headers={"Connection": "close"})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        out.append((time.perf_counter() - t0) * 1000.0)
    return out


def keepalive_latency_profile(ip, port, insecure, count, timeout):
    out = []
    ctx = build_ssl_context(insecure)
    conn = http.client.HTTPSConnection(ip, port=port, timeout=timeout, context=ctx)
    try:
        for _ in range(max(1, int(count))):
            t0 = time.perf_counter()
            conn.request("GET", "/hello")
            resp = conn.getresponse()
            resp.read()
            out.append((time.perf_counter() - t0) * 1000.0)
    finally:
        conn.close()
    return out


def profile_from_values(values):
    if not values:
        return {"count": 0, "p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0, "mean_ms": 0.0}
    return {
        "count": len(values),
        "p50_ms": percentile(values, 0.50),
        "p95_ms": percentile(values, 0.95),
        "p99_ms": percentile(values, 0.99),
        "mean_ms": float(statistics.mean(values)),
    }


def main():
    ap = argparse.ArgumentParser(description="HTTPS/WSS stability and performance profile for ViperHTTP")
    ap.add_argument("ip")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--insecure", action="store_true", default=False)
    ap.add_argument("--wss-repeat", type=int, default=30)
    ap.add_argument("--bench-duration", type=int, default=10)
    ap.add_argument("--bench-workers", type=int, default=4)
    ap.add_argument("--handshake-count", type=int, default=40)
    ap.add_argument("--keepalive-count", type=int, default=120)
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument(
        "--include-http-baseline",
        action="store_true",
        default=False,
        help="run HTTP baseline benchmarks (requires plain HTTP server on target port)",
    )
    ap.add_argument("--output", default="tools/https_profile.last.json")
    args = ap.parse_args()

    py = sys.executable
    cmd = [
        py,
        "tools/run_https_tests.py",
        args.ip,
        "--port",
        str(args.port),
        "--wss-repeat",
        str(max(1, int(args.wss_repeat))),
    ]
    if args.insecure:
        cmd.append("--insecure")
    print("== HTTPS regression suite ==")
    print(" ".join(cmd))
    rc = subprocess.call(cmd)
    if rc != 0:
        print("FAIL: run_https_tests.py")
        return 1

    print("\n== HTTPS stats reset ==")
    reset_payload = fetch_server_stats(args.ip, args.port, args.insecure, reset=True)
    reset_server = reset_payload.get("server", {})
    print(
        "after_reset https_ok={} https_fail={}".format(
            int(reset_server.get("https_handshake_ok", 0)),
            int(reset_server.get("https_handshake_fail", 0)),
        )
    )

    print("\n== HTTPS handshake profile (new connection) ==")
    hs_vals = handshake_latency_profile(
        args.ip, args.port, args.insecure, args.handshake_count, args.timeout
    )
    hs = profile_from_values(hs_vals)
    print(
        "handshake_ms p50={:.2f} p95={:.2f} p99={:.2f} mean={:.2f} count={}".format(
            hs["p50_ms"], hs["p95_ms"], hs["p99_ms"], hs["mean_ms"], hs["count"]
        )
    )

    print("\n== HTTPS keep-alive profile (single TLS session) ==")
    ka_vals = keepalive_latency_profile(
        args.ip, args.port, args.insecure, args.keepalive_count, args.timeout
    )
    ka = profile_from_values(ka_vals)
    print(
        "keepalive_ms p50={:.2f} p95={:.2f} p99={:.2f} mean={:.2f} count={}".format(
            ka["p50_ms"], ka["p95_ms"], ka["p99_ms"], ka["mean_ms"], ka["count"]
        )
    )

    print("\n== Throughput profile ==")
    bench_paths = ["/hello", "/file"]
    http_rows = None
    https_rows = []
    if args.include_http_baseline:
        http_rows = []
        for path in bench_paths:
            http_rows.append(
                bench_endpoint(
                    f"http://{args.ip}:{args.port}",
                    path,
                    args.bench_duration,
                    args.bench_workers,
                    args.timeout,
                    ssl_context=None,
                )
            )
    https_ctx = build_ssl_context(args.insecure)
    for path in bench_paths:
        https_rows.append(
            bench_endpoint(
                f"https://{args.ip}:{args.port}",
                path,
                args.bench_duration,
                args.bench_workers,
                args.timeout,
                ssl_context=https_ctx,
            )
        )

    if http_rows is not None:
        for row in http_rows:
            print(
                "http {} req_s={:.2f} p95_ms={:.2f} err={}".format(
                    row["path"], row["req_s"], row["p95_ms"], row["err"]
                )
            )
    else:
        print("http baseline skipped (use --include-http-baseline with plain HTTP server)")
    for row in https_rows:
        print(
            "https {} req_s={:.2f} p95_ms={:.2f} err={}".format(
                row["path"], row["req_s"], row["p95_ms"], row["err"]
            )
        )

    print("\n== HTTPS stats final ==")
    final_payload = fetch_server_stats(args.ip, args.port, args.insecure, reset=False)
    final_server = final_payload.get("server", {})
    hs_ok = int(final_server.get("https_handshake_ok", 0))
    hs_fail = int(final_server.get("https_handshake_fail", 0))
    print(f"https_enabled={int(final_server.get('https_enabled', 0))} handshake_ok={hs_ok} handshake_fail={hs_fail}")

    out = {
        "ip": args.ip,
        "port": args.port,
        "wss_repeat": int(args.wss_repeat),
        "bench_duration": int(args.bench_duration),
        "bench_workers": int(args.bench_workers),
        "handshake_profile": hs,
        "keepalive_profile": ka,
        "bench_http": http_rows,
        "bench_https": https_rows,
        "server_stats": final_server,
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, sort_keys=True)
    print(f"\nWrote profile: {args.output}")

    if hs_fail != 0:
        print("FAIL: HTTPS handshake failures detected")
        return 1
    if http_rows is not None and any(int(row.get("err", 0)) != 0 for row in http_rows):
        print("FAIL: HTTP baseline benchmark errors detected")
        return 1
    if any(int(row.get("err", 0)) != 0 for row in https_rows):
        print("FAIL: HTTPS benchmark errors detected")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

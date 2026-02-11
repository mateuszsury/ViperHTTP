#!/usr/bin/env python3
import argparse
import json
import time
import urllib.error
import urllib.request

from http_bench import bench_endpoint


def fetch_once(base_url, path, timeout):
    req = urllib.request.Request(base_url + path, method="GET")
    started = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return resp.status, elapsed_ms, len(body)


def main():
    parser = argparse.ArgumentParser(description="Template benchmark gates for ViperHTTP.")
    parser.add_argument("ip")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--duration", type=int, default=20, help="Seconds per warm benchmark path")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=4.0)
    parser.add_argument("--soak-seconds", type=int, default=180, help="Sustained template load window")
    parser.add_argument("--overhead-gate", type=float, default=20.0, help="Allowed warm p95 overhead (%) vs static")
    args = parser.parse_args()

    base = f"http://{args.ip}:{args.port}"
    results = {}

    # Cold cache sample on first template render after boot.
    template_path = "/template?name=Ana&show_items=true&items=alpha,%3Cb%3E"
    template_stream_path = template_path + "&stream=true"
    static_path = "/static/template_demo.html"
    plain_path = "/"

    status, cold_ms, cold_size = fetch_once(base, template_path, args.timeout)
    if status != 200:
        print("FAIL: cold template fetch failed:", status)
        return 2
    results["cold_template"] = {"status": status, "latency_ms": cold_ms, "size": cold_size}

    # Warmup phase.
    for _ in range(5):
        status, _, _ = fetch_once(base, template_path, args.timeout)
        if status != 200:
            print("FAIL: warmup template fetch failed:", status)
            return 2

    warm_paths = [
        static_path,
        plain_path,
        template_path,
        template_stream_path,
    ]
    for path in warm_paths:
        results[path] = bench_endpoint(base, path, args.duration, args.workers, args.timeout)

    static_p95 = results[static_path]["p95_ms"] or 0.0
    template_p95 = results[template_path]["p95_ms"] or 0.0
    if static_p95 > 0:
        overhead_pct = ((template_p95 - static_p95) / static_p95) * 100.0
    else:
        overhead_pct = 0.0
    results["warm_overhead_pct_vs_static"] = overhead_pct

    soak = bench_endpoint(base, template_stream_path, args.soak_seconds, args.workers, args.timeout)
    results["soak_template_stream"] = soak

    gate_overhead = overhead_pct <= args.overhead_gate
    gate_soak = soak["err"] == 0 and soak["ok"] > 0
    results["gate_overhead_pass"] = gate_overhead
    results["gate_soak_pass"] = gate_soak

    print(json.dumps(results, indent=2))
    if gate_overhead and gate_soak:
        print("PASS")
        return 0
    print("FAIL")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

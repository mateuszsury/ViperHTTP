#!/usr/bin/env python3
import argparse
import statistics
import threading
import time
import ssl
import urllib.error
import urllib.request


def bench_endpoint(base_url, path, duration_s, workers, timeout_s, ssl_context=None):
    stop_at = time.monotonic() + duration_s
    lock = threading.Lock()
    latencies_ms = []
    total_bytes = 0
    total_ok = 0
    total_err = 0

    def worker():
        nonlocal total_bytes, total_ok, total_err
        url = base_url + path
        req = urllib.request.Request(url, method="GET")
        while time.monotonic() < stop_at:
            started = time.perf_counter()
            try:
                with urllib.request.urlopen(req, timeout=timeout_s, context=ssl_context) as resp:
                    body = resp.read()
                    if 200 <= resp.status < 400:
                        latency = (time.perf_counter() - started) * 1000.0
                        with lock:
                            latencies_ms.append(latency)
                            total_ok += 1
                            total_bytes += len(body)
                    else:
                        with lock:
                            total_err += 1
            except (urllib.error.URLError, TimeoutError, OSError):
                with lock:
                    total_err += 1

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    elapsed = max(duration_s, 0.001)
    req_s = total_ok / elapsed
    mbps = (total_bytes / elapsed) / (1024.0 * 1024.0)
    p50 = statistics.median(latencies_ms) if latencies_ms else 0.0
    if len(latencies_ms) >= 2:
        p95 = statistics.quantiles(latencies_ms, n=100, method="inclusive")[94]
    else:
        p95 = p50
    return {
        "path": path,
        "ok": total_ok,
        "err": total_err,
        "req_s": req_s,
        "mb_s": mbps,
        "p50_ms": p50,
        "p95_ms": p95,
    }


def main():
    parser = argparse.ArgumentParser(description="Simple HTTP benchmark for ViperHTTP device.")
    parser.add_argument("ip", help="Device IP address")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--scheme", choices=["http", "https"], default="http")
    parser.add_argument("--insecure", action="store_true", default=False, help="disable TLS cert verification")
    parser.add_argument("--duration", type=int, default=10, help="Duration per endpoint in seconds")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument(
        "--paths",
        default="/hello,/static/large.txt,/file",
        help="Comma-separated endpoint paths",
    )
    args = parser.parse_args()

    base = f"{args.scheme}://{args.ip}:{args.port}"
    ssl_context = None
    if args.scheme == "https":
        ssl_context = ssl.create_default_context()
        if args.insecure:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
    paths = [p.strip() for p in args.paths.split(",") if p.strip()]
    if not paths:
        print("No paths provided")
        return 2

    print(f"Benchmark base={base} duration={args.duration}s workers={args.workers}")
    print("path,ok,err,req_s,mb_s,p50_ms,p95_ms")
    overall_err = 0
    for path in paths:
        result = bench_endpoint(base, path, args.duration, args.workers, args.timeout, ssl_context=ssl_context)
        overall_err += result["err"]
        print(
            f"{result['path']},{result['ok']},{result['err']},"
            f"{result['req_s']:.2f},{result['mb_s']:.3f},{result['p50_ms']:.2f},{result['p95_ms']:.2f}"
        )

    return 0 if overall_err == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

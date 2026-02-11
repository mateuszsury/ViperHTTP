#!/usr/bin/env python3
import argparse
import json
import statistics
import threading
import time
from http.client import HTTPConnection


def percentile(values, pct):
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    ordered = sorted(values)
    rank = (len(ordered) - 1) * pct
    lo = int(rank)
    hi = min(lo + 1, len(ordered) - 1)
    frac = rank - lo
    return float(ordered[lo] * (1.0 - frac) + ordered[hi] * frac)


def worker(host, port, path, duration_s, timeout_s, out):
    lat_ms = []
    ok = 0
    err = 0
    started = time.perf_counter()
    conn = HTTPConnection(host, port=port, timeout=timeout_s)
    while (time.perf_counter() - started) < duration_s:
        t0 = time.perf_counter()
        try:
            conn.request("GET", path, headers={"Connection": "keep-alive"})
            resp = conn.getresponse()
            _ = resp.read()
            elapsed = (time.perf_counter() - t0) * 1000.0
            lat_ms.append(elapsed)
            if 200 <= resp.status < 400:
                ok += 1
            else:
                err += 1
        except Exception:
            err += 1
            try:
                conn.close()
            except Exception:
                pass
            conn = HTTPConnection(host, port=port, timeout=timeout_s)
    try:
        conn.close()
    except Exception:
        pass
    out["lat_ms"] = lat_ms
    out["ok"] = ok
    out["err"] = err


def fetch_json(host, port, path, timeout_s):
    conn = HTTPConnection(host, port=port, timeout=timeout_s)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        if resp.status != 200:
            return {"status": resp.status, "body": body.decode("utf-8", "ignore")}
        return json.loads(body.decode("utf-8", "ignore"))
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser(description="Concurrent HTTP stress test for ViperHTTP runtime.")
    ap.add_argument("host", help="Device IP")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--path", default="/hello")
    ap.add_argument("--clients", type=int, default=24)
    ap.add_argument("--duration", type=int, default=20, help="seconds")
    ap.add_argument("--timeout", type=float, default=3.0, help="request timeout seconds")
    ap.add_argument("--stats-path", default="/debug/server-stats")
    args = ap.parse_args()

    try:
        _ = fetch_json(args.host, args.port, args.stats_path + "?reset=1", args.timeout)
    except Exception:
        pass

    slots = [{} for _ in range(args.clients)]
    threads = []
    t0 = time.perf_counter()
    for i in range(args.clients):
        t = threading.Thread(
            target=worker,
            args=(args.host, args.port, args.path, args.duration, args.timeout, slots[i]),
            daemon=True,
        )
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - t0

    all_lat = []
    ok = 0
    err = 0
    for slot in slots:
        all_lat.extend(slot.get("lat_ms", []))
        ok += int(slot.get("ok", 0))
        err += int(slot.get("err", 0))

    total = ok + err
    rps = (total / elapsed) if elapsed > 0 else 0.0
    ok_rps = (ok / elapsed) if elapsed > 0 else 0.0

    print("=== HTTP Concurrency Test ===")
    print(f"target={args.host}:{args.port}{args.path}")
    print(f"clients={args.clients} duration={args.duration}s elapsed={elapsed:.2f}s")
    print(f"requests_total={total} ok={ok} err={err} error_rate={(err / total * 100.0) if total else 0.0:.2f}%")
    print(f"rps_total={rps:.2f} rps_ok={ok_rps:.2f}")
    if all_lat:
        print(f"latency_ms p50={percentile(all_lat, 0.50):.2f} p95={percentile(all_lat, 0.95):.2f} p99={percentile(all_lat, 0.99):.2f} mean={statistics.mean(all_lat):.2f}")
    else:
        print("latency_ms unavailable")

    try:
        stats = fetch_json(args.host, args.port, args.stats_path, args.timeout)
        print("server_stats:")
        print(json.dumps(stats, indent=2, sort_keys=True))
    except Exception as exc:
        print(f"server_stats unavailable: {exc}")

    return 0 if err == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

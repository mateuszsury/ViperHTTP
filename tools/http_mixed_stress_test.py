#!/usr/bin/env python3
import argparse
import json
import random
import statistics
import threading
import time
from http.client import HTTPConnection


MIX_CASES = (
    ("GET", "/hello", None, {"Connection": "keep-alive"}),
    ("GET", "/state", None, {"Connection": "keep-alive"}),
    ("GET", "/template?name=Load&show_items=true&items=a,b,c", None, {"Connection": "keep-alive"}),
    ("POST", "/json", b'{"load":true}', {"Connection": "keep-alive", "Content-Type": "application/json"}),
)


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


def worker(host, port, duration_s, timeout_s, seed, out):
    lat_ms = []
    ok = 0
    err = 0
    by_case = {}
    rnd = random.Random(seed)
    started = time.perf_counter()
    conn = HTTPConnection(host, port=port, timeout=timeout_s)

    while (time.perf_counter() - started) < duration_s:
        method, path, body, headers = MIX_CASES[rnd.randrange(0, len(MIX_CASES))]
        case_key = method + " " + path.split("?", 1)[0]
        if case_key not in by_case:
            by_case[case_key] = {"ok": 0, "err": 0}

        t0 = time.perf_counter()
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            _ = resp.read()
            elapsed = (time.perf_counter() - t0) * 1000.0
            lat_ms.append(elapsed)
            if 200 <= resp.status < 400:
                ok += 1
                by_case[case_key]["ok"] += 1
            else:
                err += 1
                by_case[case_key]["err"] += 1
        except Exception:
            err += 1
            by_case[case_key]["err"] += 1
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
    out["by_case"] = by_case


def main():
    ap = argparse.ArgumentParser(description="Mixed HTTP load gate for ViperHTTP.")
    ap.add_argument("host", help="Device IP")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--clients", type=int, default=12)
    ap.add_argument("--duration", type=int, default=30, help="seconds")
    ap.add_argument("--timeout", type=float, default=5.0, help="request timeout seconds")
    ap.add_argument("--stats-path", default="/debug/server-stats")
    ap.add_argument("--max-error-rate", type=float, default=0.15, help="gate threshold, 0..1")
    ap.add_argument("--max-p95-ms", type=float, default=1800.0)
    ap.add_argument("--max-p99-ms", type=float, default=3000.0)
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
            args=(args.host, args.port, args.duration, args.timeout, i + 1, slots[i]),
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
    by_case = {}
    for slot in slots:
        all_lat.extend(slot.get("lat_ms", []))
        ok += int(slot.get("ok", 0))
        err += int(slot.get("err", 0))
        case_stats = slot.get("by_case", {})
        for key, val in case_stats.items():
            if key not in by_case:
                by_case[key] = {"ok": 0, "err": 0}
            by_case[key]["ok"] += int(val.get("ok", 0))
            by_case[key]["err"] += int(val.get("err", 0))

    total = ok + err
    err_rate = (err / total) if total else 0.0
    p95 = percentile(all_lat, 0.95) if all_lat else 0.0
    p99 = percentile(all_lat, 0.99) if all_lat else 0.0
    mean = statistics.mean(all_lat) if all_lat else 0.0
    rps_total = (total / elapsed) if elapsed > 0 else 0.0
    rps_ok = (ok / elapsed) if elapsed > 0 else 0.0

    print("=== HTTP Mixed Stress Gate ===")
    print(f"target={args.host}:{args.port}")
    print(f"clients={args.clients} duration={args.duration}s elapsed={elapsed:.2f}s")
    print(f"requests_total={total} ok={ok} err={err} error_rate={err_rate * 100.0:.2f}%")
    print(f"rps_total={rps_total:.2f} rps_ok={rps_ok:.2f}")
    if all_lat:
        print(f"latency_ms p95={p95:.2f} p99={p99:.2f} mean={mean:.2f}")
    else:
        print("latency_ms unavailable")

    print("by_case:")
    for key in sorted(by_case.keys()):
        c_ok = by_case[key]["ok"]
        c_err = by_case[key]["err"]
        c_total = c_ok + c_err
        c_err_rate = (c_err / c_total * 100.0) if c_total else 0.0
        print(f"  {key}: ok={c_ok} err={c_err} err_rate={c_err_rate:.2f}%")

    try:
        stats = fetch_json(args.host, args.port, args.stats_path, args.timeout)
        print("server_stats:")
        print(json.dumps(stats, indent=2, sort_keys=True))
    except Exception as exc:
        print(f"server_stats unavailable: {exc}")

    gate_ok = True
    if total == 0:
        gate_ok = False
    if err_rate > args.max_error_rate:
        gate_ok = False
    if p95 > args.max_p95_ms:
        gate_ok = False
    if p99 > args.max_p99_ms:
        gate_ok = False

    print(
        "gate="
        + ("PASS" if gate_ok else "FAIL")
        + f" thresholds(error_rate<={args.max_error_rate:.2f}, p95<={args.max_p95_ms:.0f}ms, p99<={args.max_p99_ms:.0f}ms)"
    )
    return 0 if gate_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

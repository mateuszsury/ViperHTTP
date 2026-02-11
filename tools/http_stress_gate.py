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


def fetch_json(host, port, path, timeout_s, retries=0, retry_delay_s=0.1):
    attempts = int(retries) + 1
    if attempts < 1:
        attempts = 1
    last_exc = None
    for attempt in range(attempts):
        conn = HTTPConnection(host, port=port, timeout=timeout_s)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            body = resp.read()
            if resp.status == 200:
                return json.loads(body.decode("utf-8", "ignore"))
            retriable = resp.status in (429, 503, 504)
            if retriable and attempt + 1 < attempts:
                time.sleep(retry_delay_s * (attempt + 1))
                continue
            raise RuntimeError(f"{path} status={resp.status} body={body[:120]!r}")
        except Exception as exc:
            last_exc = exc
            if attempt + 1 < attempts:
                time.sleep(retry_delay_s * (attempt + 1))
                continue
            raise
        finally:
            conn.close()
    if last_exc:
        raise last_exc
    raise RuntimeError("fetch_json failed")


def worker(host, port, paths, duration_s, timeout_s, start_t, out):
    samples = []
    ok = 0
    err = 0
    status_counts = {}
    path_lat = {}
    path_ok = {}
    path_err = {}
    path_status = {}
    conn = HTTPConnection(host, port=port, timeout=timeout_s)
    req_idx = 0
    while (time.perf_counter() - start_t) < duration_s:
        t0 = time.perf_counter()
        path = paths[req_idx % len(paths)]
        req_idx += 1
        try:
            conn.request("GET", path, headers={"Connection": "keep-alive"})
            resp = conn.getresponse()
            _ = resp.read()
            status_key = str(int(resp.status))
            status_counts[status_key] = int(status_counts.get(status_key, 0)) + 1
            t1 = time.perf_counter()
            lat_ms = (t1 - t0) * 1000.0
            rel_s = t1 - start_t
            samples.append((rel_s, lat_ms, path))
            per_path = path_lat.get(path)
            if per_path is None:
                per_path = []
                path_lat[path] = per_path
            per_path.append(lat_ms)
            path_status_bucket = path_status.get(path)
            if path_status_bucket is None:
                path_status_bucket = {}
                path_status[path] = path_status_bucket
            path_status_bucket[status_key] = int(path_status_bucket.get(status_key, 0)) + 1
            if 200 <= resp.status < 400:
                ok += 1
                path_ok[path] = int(path_ok.get(path, 0)) + 1
            else:
                err += 1
                path_err[path] = int(path_err.get(path, 0)) + 1
        except Exception:
            err += 1
            path_err[path] = int(path_err.get(path, 0)) + 1
            try:
                conn.close()
            except Exception:
                pass
            conn = HTTPConnection(host, port=port, timeout=timeout_s)
    try:
        conn.close()
    except Exception:
        pass
    out["samples"] = samples
    out["ok"] = ok
    out["err"] = err
    out["status_counts"] = status_counts
    out["path_lat"] = path_lat
    out["path_ok"] = path_ok
    out["path_err"] = path_err
    out["path_status"] = path_status


def summarize_path_metrics(path_bucket, elapsed):
    out = {}
    for path, data in path_bucket.items():
        lats = data.get("latencies", [])
        ok = int(data.get("ok", 0))
        err = int(data.get("err", 0))
        total = ok + err
        err_rate = (err / total * 100.0) if total > 0 else 0.0
        out[path] = {
            "requests_total": total,
            "ok": ok,
            "err": err,
            "error_rate": err_rate,
            "rps_ok": (ok / elapsed) if elapsed > 0 else 0.0,
            "p50_ms": percentile(lats, 0.50) if lats else 0.0,
            "p95_ms": percentile(lats, 0.95) if lats else 0.0,
            "p99_ms": percentile(lats, 0.99) if lats else 0.0,
            "mean_ms": statistics.mean(lats) if lats else 0.0,
            "status_counts": data.get("status_counts", {}),
        }
    return out


def run_phase(
    host,
    port,
    paths,
    clients,
    duration_s,
    timeout_s,
    stats_path,
    mem_path,
    metrics_retries,
    metrics_retry_delay_s,
    post_phase_settle_s,
):
    fetch_json(
        host,
        port,
        stats_path + "?reset=1",
        timeout_s,
        retries=metrics_retries,
        retry_delay_s=metrics_retry_delay_s,
    )
    mem_before = fetch_json(
        host,
        port,
        mem_path,
        timeout_s,
        retries=metrics_retries,
        retry_delay_s=metrics_retry_delay_s,
    )

    slots = [{} for _ in range(clients)]
    threads = []
    t0 = time.perf_counter()
    for i in range(clients):
        t = threading.Thread(
            target=worker,
            args=(host, port, paths, duration_s, timeout_s, t0, slots[i]),
            daemon=True,
        )
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - t0

    all_samples = []
    ok = 0
    err = 0
    status_counts = {}
    path_bucket = {}
    for slot in slots:
        all_samples.extend(slot.get("samples", []))
        ok += int(slot.get("ok", 0))
        err += int(slot.get("err", 0))
        for key, value in (slot.get("status_counts", {}) or {}).items():
            status_counts[str(key)] = int(status_counts.get(str(key), 0)) + int(value)
        for path, lats in (slot.get("path_lat", {}) or {}).items():
            b = path_bucket.get(path)
            if b is None:
                b = {"latencies": [], "ok": 0, "err": 0, "status_counts": {}}
                path_bucket[path] = b
            b["latencies"].extend(lats)
        for path, count in (slot.get("path_ok", {}) or {}).items():
            b = path_bucket.get(path)
            if b is None:
                b = {"latencies": [], "ok": 0, "err": 0, "status_counts": {}}
                path_bucket[path] = b
            b["ok"] += int(count)
        for path, count in (slot.get("path_err", {}) or {}).items():
            b = path_bucket.get(path)
            if b is None:
                b = {"latencies": [], "ok": 0, "err": 0, "status_counts": {}}
                path_bucket[path] = b
            b["err"] += int(count)
        for path, statuses in (slot.get("path_status", {}) or {}).items():
            b = path_bucket.get(path)
            if b is None:
                b = {"latencies": [], "ok": 0, "err": 0, "status_counts": {}}
                path_bucket[path] = b
            for skey, sval in (statuses or {}).items():
                b["status_counts"][str(skey)] = int(b["status_counts"].get(str(skey), 0)) + int(sval)

    total = ok + err
    lat_all = [lat for _, lat, _ in all_samples]
    cutoff = elapsed * 0.75
    lat_tail = [lat for rel, lat, _ in all_samples if rel >= cutoff]
    path_metrics = summarize_path_metrics(path_bucket, elapsed)

    if post_phase_settle_s > 0:
        time.sleep(post_phase_settle_s)

    stats_after = fetch_json(
        host,
        port,
        stats_path,
        timeout_s,
        retries=metrics_retries,
        retry_delay_s=metrics_retry_delay_s,
    )
    mem_after = fetch_json(
        host,
        port,
        mem_path,
        timeout_s,
        retries=metrics_retries,
        retry_delay_s=metrics_retry_delay_s,
    )

    return {
        "clients": clients,
        "duration": duration_s,
        "elapsed": elapsed,
        "requests_total": total,
        "ok": ok,
        "err": err,
        "error_rate": (err / total * 100.0) if total else 0.0,
        "rps_total": (total / elapsed) if elapsed > 0 else 0.0,
        "rps_ok": (ok / elapsed) if elapsed > 0 else 0.0,
        "p50_ms": percentile(lat_all, 0.50) if lat_all else 0.0,
        "p95_ms": percentile(lat_all, 0.95) if lat_all else 0.0,
        "p99_ms": percentile(lat_all, 0.99) if lat_all else 0.0,
        "p95_tail_ms": percentile(lat_tail, 0.95) if lat_tail else 0.0,
        "mean_ms": statistics.mean(lat_all) if lat_all else 0.0,
        "status_counts": status_counts,
        "path_metrics": path_metrics,
        "stats_after": stats_after,
        "mem_before": mem_before,
        "mem_after": mem_after,
    }


def internal_free(mem_obj):
    try:
        return int(mem_obj.get("heap", {}).get("internal_free", 0))
    except Exception:
        return 0


def psram_free(mem_obj):
    try:
        return int(mem_obj.get("heap", {}).get("psram_free", 0))
    except Exception:
        return 0


def profile_paths(profile_name):
    profile = str(profile_name or "mixed").strip().lower()
    if profile == "c_static_only":
        return [
            "/file",
            "/static/large.txt",
        ]
    if profile == "python_light":
        return [
            "/hello",
            "/api/ping",
            "/deps",
            "/query-typed?q=abc&page=2&ratio=1.5&active=true",
        ]
    if profile == "python_heavy":
        return [
            "/template",
            "/template-compat?name=Ana&count=2&role=user&roles=user,viewer&items=a,b,c",
        ]
    if profile == "api":
        return [
            "/hello",
            "/api/ping",
            "/query-typed?q=abc&page=2&ratio=1.5&active=true",
            "/deps",
            "/template",
        ]
    if profile == "static":
        return [
            "/file",
            "/template",
        ]
    return [
        "/hello",
        "/api/ping",
        "/query-typed?q=abc&page=2&ratio=1.5&active=true",
        "/deps",
        "/template",
        "/file",
    ]


def main():
    ap = argparse.ArgumentParser(description="Stress gate for ViperHTTP concurrency and memory stability.")
    ap.add_argument("host", help="Device IP")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument(
        "--profile",
        default="mixed",
        choices=["mixed", "api", "static", "c_static_only", "python_light", "python_heavy"],
        help="Predefined route profile when --paths is not provided",
    )
    ap.add_argument(
        "--paths",
        default="",
        help="Comma-separated GET paths override (if set, --profile is ignored)",
    )
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--stats-path", default="/debug/server-stats")
    ap.add_argument("--mem-path", default="/debug/memory-stats")
    ap.add_argument("--burst-clients", type=int, default=12)
    ap.add_argument("--burst-duration", type=int, default=30)
    ap.add_argument("--long-clients", type=int, default=8)
    ap.add_argument("--long-duration", type=int, default=180)
    ap.add_argument("--max-error-rate", type=float, default=2.0)
    ap.add_argument("--max-p95-ms", type=float, default=2000.0)
    ap.add_argument("--max-p99-ms", type=float, default=3000.0)
    ap.add_argument("--max-tail-p95-ratio", type=float, default=1.8)
    ap.add_argument("--max-internal-free-drop", type=int, default=131072)
    ap.add_argument("--max-psram-free-drop", type=int, default=524288)
    ap.add_argument("--metrics-retries", type=int, default=20)
    ap.add_argument("--metrics-retry-delay-ms", type=int, default=100)
    ap.add_argument("--post-phase-settle-ms", type=int, default=250)
    ap.add_argument("--print-path-metrics", action="store_true", default=False)
    args = ap.parse_args()

    phases = [
        ("burst", args.burst_clients, args.burst_duration),
        ("long", args.long_clients, args.long_duration),
    ]

    overall_ok = True
    reports = []

    print("=== HTTP Stress Gate ===")
    raw_paths = [p.strip() for p in str(args.paths).split(",") if p.strip()]
    paths = raw_paths if raw_paths else profile_paths(args.profile)
    print(f"target={args.host}:{args.port}")
    print(f"profile={args.profile}")
    print(f"paths={paths}")

    for name, clients, duration in phases:
        print(f"\\n--- phase={name} clients={clients} duration={duration}s ---")
        rep = run_phase(
            args.host,
            args.port,
            paths,
            clients,
            duration,
            args.timeout,
            args.stats_path,
            args.mem_path,
            args.metrics_retries,
            max(0.001, args.metrics_retry_delay_ms / 1000.0),
            max(0.0, args.post_phase_settle_ms / 1000.0),
        )
        reports.append((name, rep))

        print(
            "requests_total={requests_total} ok={ok} err={err} error_rate={error_rate:.2f}% rps_ok={rps_ok:.2f}".format(
                **rep
            )
        )
        print(
            "latency_ms p50={p50_ms:.2f} p95={p95_ms:.2f} p99={p99_ms:.2f} p95_tail={p95_tail_ms:.2f} mean={mean_ms:.2f}".format(
                **rep
            )
        )

        s = rep.get("stats_after", {}).get("server", {})
        print(
            "server accepts_rejected={ar} request_errors={re} ipc_pending_dropped={pd} ipc_req_ring_alloc_fail={rf} ipc_req_queue_push_fail={qf} backpressure_503_sent={bp} workers_started={ws} limit={wmin}-{wmax}".format(
                ar=s.get("accepts_rejected"),
                re=s.get("request_errors"),
                pd=s.get("ipc_pending_dropped"),
                rf=s.get("ipc_req_ring_alloc_fail"),
                qf=s.get("ipc_req_queue_push_fail"),
                bp=s.get("backpressure_503_sent"),
                ws=s.get("workers_started"),
                wmin=s.get("workers_limit_min"),
                wmax=s.get("workers_limit_max"),
            )
        )
        print(
            "server ipc_wait_timeouts={iw} requests_started={rs} requests_handled={rh}".format(
                iw=s.get("ipc_wait_timeouts"),
                rs=s.get("requests_started"),
                rh=s.get("requests_handled"),
            )
        )
        print(f"http status_counts={rep.get('status_counts', {})}")
        if args.print_path_metrics:
            pmetrics = rep.get("path_metrics", {}) or {}
            if pmetrics:
                print("path_metrics:")
                ordered_paths = sorted(
                    pmetrics.items(),
                    key=lambda kv: int(kv[1].get("requests_total", 0)),
                    reverse=True,
                )
                for path, pstat in ordered_paths:
                    print(
                        "  {} total={} ok={} err={} err_rate={:.2f}% p95={:.2f}ms p99={:.2f}ms rps_ok={:.2f}".format(
                            path,
                            int(pstat.get("requests_total", 0)),
                            int(pstat.get("ok", 0)),
                            int(pstat.get("err", 0)),
                            float(pstat.get("error_rate", 0.0)),
                            float(pstat.get("p95_ms", 0.0)),
                            float(pstat.get("p99_ms", 0.0)),
                            float(pstat.get("rps_ok", 0.0)),
                        )
                    )

        before_i = internal_free(rep.get("mem_before", {}))
        after_i = internal_free(rep.get("mem_after", {}))
        before_p = psram_free(rep.get("mem_before", {}))
        after_p = psram_free(rep.get("mem_after", {}))
        drop_i = before_i - after_i
        drop_p = before_p - after_p
        print(f"memory internal_free {before_i} -> {after_i} (drop={drop_i})")
        print(f"memory psram_free    {before_p} -> {after_p} (drop={drop_p})")

        phase_ok = True
        if rep["error_rate"] > args.max_error_rate:
            print(f"GATE FAIL: error_rate {rep['error_rate']:.2f}% > {args.max_error_rate:.2f}%")
            phase_ok = False
        if rep["p95_ms"] > args.max_p95_ms:
            print(f"GATE FAIL: p95 {rep['p95_ms']:.2f}ms > {args.max_p95_ms:.2f}ms")
            phase_ok = False
        if rep["p99_ms"] > args.max_p99_ms:
            print(f"GATE FAIL: p99 {rep['p99_ms']:.2f}ms > {args.max_p99_ms:.2f}ms")
            phase_ok = False
        if rep["p95_ms"] > 0:
            tail_ratio = rep["p95_tail_ms"] / rep["p95_ms"]
            if tail_ratio > args.max_tail_p95_ratio:
                print(f"GATE FAIL: tail p95 ratio {tail_ratio:.2f} > {args.max_tail_p95_ratio:.2f}")
                phase_ok = False
        if drop_i > args.max_internal_free_drop:
            print(f"GATE FAIL: internal_free drop {drop_i} > {args.max_internal_free_drop}")
            phase_ok = False
        if drop_p > args.max_psram_free_drop:
            print(f"GATE FAIL: psram_free drop {drop_p} > {args.max_psram_free_drop}")
            phase_ok = False

        if phase_ok:
            print("GATE PASS")
        overall_ok = overall_ok and phase_ok

    print("\\n=== SUMMARY ===")
    for name, rep in reports:
        print(
            f"{name}: err_rate={rep['error_rate']:.2f}% p95={rep['p95_ms']:.2f} p99={rep['p99_ms']:.2f} rps_ok={rep['rps_ok']:.2f}"
        )

    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
import argparse
import json
import os
import statistics
import threading
import time
from http.client import HTTPConnection
from datetime import datetime, timezone

import http_stress_gate as gate


def _now_utc():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _safe_float(value):
    try:
        return float(value)
    except Exception:
        return 0.0


def _safe_int(value):
    try:
        return int(value)
    except Exception:
        return 0


def _write_json(path, payload):
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as fp:
        json.dump(payload, fp, indent=2, sort_keys=True)
        fp.write("\n")
        fp.flush()
        try:
            os.fsync(fp.fileno())
        except Exception:
            pass
    os.replace(tmp_path, path)


def _pid_alive(pid):
    try:
        pid = int(pid)
    except Exception:
        return False
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def _acquire_lock(lock_path):
    current_pid = os.getpid()
    existing = None
    if os.path.exists(lock_path):
        try:
            with open(lock_path, "r", encoding="utf-8") as fp:
                existing = json.load(fp)
        except Exception:
            existing = None
    if isinstance(existing, dict):
        old_pid = existing.get("pid")
        if old_pid != current_pid and _pid_alive(old_pid):
            raise SystemExit(
                f"perf runner already active (pid={old_pid}, started={existing.get('started_utc')})"
            )
    lock_payload = {
        "pid": current_pid,
        "started_utc": _now_utc(),
        "cwd": os.getcwd(),
    }
    _write_json(lock_path, lock_payload)
    return lock_payload


def _release_lock(lock_path):
    if not os.path.exists(lock_path):
        return
    try:
        with open(lock_path, "r", encoding="utf-8") as fp:
            payload = json.load(fp)
    except Exception:
        payload = None
    if isinstance(payload, dict):
        if int(payload.get("pid", -1)) != int(os.getpid()):
            return
    try:
        os.remove(lock_path)
    except Exception:
        pass


def _run_phase_with_watchdog(
    args,
    paths,
    clients,
    duration,
    timeout_budget_s,
    heartbeat_s,
):
    state = {"report": None, "error": None}

    def _target():
        try:
            state["report"] = gate.run_phase(
                args.host,
                args.port,
                paths,
                clients,
                duration,
                args.timeout,
                "/debug/server-stats",
                "/debug/memory-stats",
                args.metrics_retries,
                max(0.001, args.metrics_retry_delay_ms / 1000.0),
                max(0.0, args.post_phase_settle_ms / 1000.0),
            )
        except Exception as exc:
            state["error"] = exc

    t = threading.Thread(target=_target, daemon=True)
    t0 = time.monotonic()
    t.start()
    last_heartbeat = t0

    while t.is_alive():
        now = time.monotonic()
        elapsed = now - t0
        if elapsed >= timeout_budget_s:
            return None, f"phase timeout after {elapsed:.1f}s (budget={timeout_budget_s:.1f}s)", elapsed
        if (now - last_heartbeat) >= heartbeat_s:
            print(
                "heartbeat phase_running elapsed={:.1f}s budget={:.1f}s".format(
                    elapsed, timeout_budget_s
                )
            )
            last_heartbeat = now
        t.join(timeout=0.5)

    elapsed = time.monotonic() - t0
    if state["error"] is not None:
        return None, f"phase exception: {repr(state['error'])}", elapsed
    return state["report"], None, elapsed


def _probe_http_ok(host, port, path, timeout_s, retries=10, retry_delay_s=0.25):
    if not path.startswith("/"):
        path = "/" + path
    last_err = None
    for attempt in range(1, int(retries) + 1):
        conn = HTTPConnection(host, port=port, timeout=timeout_s)
        try:
            conn.request("GET", path, headers={"Connection": "close"})
            resp = conn.getresponse()
            _ = resp.read()
            if 200 <= int(resp.status) < 500:
                return True
            last_err = RuntimeError(f"probe status={resp.status} path={path}")
        except Exception as exc:
            last_err = exc
        finally:
            try:
                conn.close()
            except Exception:
                pass
        if attempt < int(retries):
            time.sleep(retry_delay_s * attempt)
    return False if last_err is None else last_err


def _phase_pass(rep, args):
    ok = True
    reasons = []
    err_rate = _safe_float(rep.get("error_rate"))
    p95 = _safe_float(rep.get("p95_ms"))
    p99 = _safe_float(rep.get("p99_ms"))
    p95_tail = _safe_float(rep.get("p95_tail_ms"))
    if err_rate > args.max_error_rate:
        ok = False
        reasons.append(f"error_rate {err_rate:.2f}% > {args.max_error_rate:.2f}%")
    if p95 > args.max_p95_ms:
        ok = False
        reasons.append(f"p95 {p95:.2f}ms > {args.max_p95_ms:.2f}ms")
    if p99 > args.max_p99_ms:
        ok = False
        reasons.append(f"p99 {p99:.2f}ms > {args.max_p99_ms:.2f}ms")
    if p95 > 0:
        ratio = p95_tail / p95
        if ratio > args.max_tail_p95_ratio:
            ok = False
            reasons.append(f"tail ratio {ratio:.2f} > {args.max_tail_p95_ratio:.2f}")

    before_i = gate.internal_free(rep.get("mem_before", {}))
    after_i = gate.internal_free(rep.get("mem_after", {}))
    before_p = gate.psram_free(rep.get("mem_before", {}))
    after_p = gate.psram_free(rep.get("mem_after", {}))
    drop_i = before_i - after_i
    drop_p = before_p - after_p
    if drop_i > args.max_internal_free_drop:
        ok = False
        reasons.append(f"internal_free drop {drop_i} > {args.max_internal_free_drop}")
    if drop_p > args.max_psram_free_drop:
        ok = False
        reasons.append(f"psram_free drop {drop_p} > {args.max_psram_free_drop}")

    return ok, reasons


def _calc_summary(values):
    if not values:
        return {"median": 0.0, "best": 0.0, "worst": 0.0, "mean": 0.0}
    ordered = sorted(float(v) for v in values)
    return {
        "median": float(statistics.median(ordered)),
        "best": float(ordered[0]),
        "worst": float(ordered[-1]),
        "mean": float(statistics.mean(ordered)),
    }


def _calc_summary_higher_better(values):
    if not values:
        return {"median": 0.0, "best": 0.0, "worst": 0.0, "mean": 0.0}
    ordered = sorted(float(v) for v in values)
    return {
        "median": float(statistics.median(ordered)),
        "best": float(ordered[-1]),
        "worst": float(ordered[0]),
        "mean": float(statistics.mean(ordered)),
    }


def _profile_phase_key(profile, phase):
    return f"{profile}:{phase}"


def _aggregate(raw_runs):
    buckets = {}
    for run in raw_runs:
        for item in run.get("results", []):
            profile = item.get("profile")
            phase = item.get("phase")
            key = _profile_phase_key(profile, phase)
            rep = item.get("report", {})
            slot = buckets.setdefault(
                key,
                {
                    "profile": profile,
                    "phase": phase,
                    "error_rate": [],
                    "p95_ms": [],
                    "p99_ms": [],
                    "p95_tail_ms": [],
                    "rps_ok": [],
                    "ok": [],
                    "path_metrics": {},
                },
            )
            slot["error_rate"].append(_safe_float(rep.get("error_rate")))
            slot["p95_ms"].append(_safe_float(rep.get("p95_ms")))
            slot["p99_ms"].append(_safe_float(rep.get("p99_ms")))
            slot["p95_tail_ms"].append(_safe_float(rep.get("p95_tail_ms")))
            slot["rps_ok"].append(_safe_float(rep.get("rps_ok")))
            slot["ok"].append(bool(item.get("pass", False)))
            for path, pstat in (rep.get("path_metrics", {}) or {}).items():
                pslot = slot["path_metrics"].setdefault(
                    path,
                    {
                        "requests_total": [],
                        "error_rate": [],
                        "p95_ms": [],
                        "p99_ms": [],
                        "rps_ok": [],
                    },
                )
                pslot["requests_total"].append(_safe_float(pstat.get("requests_total")))
                pslot["error_rate"].append(_safe_float(pstat.get("error_rate")))
                pslot["p95_ms"].append(_safe_float(pstat.get("p95_ms")))
                pslot["p99_ms"].append(_safe_float(pstat.get("p99_ms")))
                pslot["rps_ok"].append(_safe_float(pstat.get("rps_ok")))

    out = {}
    for key, bucket in buckets.items():
        path_out = {}
        for path, pslot in bucket["path_metrics"].items():
            path_out[path] = {
                "requests_total": _calc_summary_higher_better(pslot["requests_total"]),
                "error_rate": _calc_summary(pslot["error_rate"]),
                "p95_ms": _calc_summary(pslot["p95_ms"]),
                "p99_ms": _calc_summary(pslot["p99_ms"]),
                "rps_ok": _calc_summary_higher_better(pslot["rps_ok"]),
            }
        out[key] = {
            "profile": bucket["profile"],
            "phase": bucket["phase"],
            "sample_count": len(bucket["error_rate"]),
            "pass_rate": (sum(1 for x in bucket["ok"] if x) / len(bucket["ok"])) if bucket["ok"] else 0.0,
            "error_rate": _calc_summary(bucket["error_rate"]),
            "p95_ms": _calc_summary(bucket["p95_ms"]),
            "p99_ms": _calc_summary(bucket["p99_ms"]),
            "p95_tail_ms": _calc_summary(bucket["p95_tail_ms"]),
            "rps_ok": _calc_summary_higher_better(bucket["rps_ok"]),
            "path_metrics": path_out,
        }
    return out


def _load_previous(history_dir, latest_path):
    prev = None
    if os.path.exists(latest_path):
        try:
            with open(latest_path, "r", encoding="utf-8") as fp:
                prev = json.load(fp)
        except Exception:
            prev = None
    if prev is not None:
        return prev

    candidates = []
    try:
        for name in os.listdir(history_dir):
            if name.endswith(".json") and name.startswith("perf_"):
                candidates.append(name)
    except Exception:
        return None
    if not candidates:
        return None
    candidates.sort()
    prev_file = os.path.join(history_dir, candidates[-1])
    try:
        with open(prev_file, "r", encoding="utf-8") as fp:
            return json.load(fp)
    except Exception:
        return None


def _compare(current_agg, previous_agg):
    if not previous_agg:
        return {}
    prev_map = previous_agg.get("aggregated", {})
    out = {}
    for key, cur in current_agg.items():
        prev = prev_map.get(key)
        if not prev:
            continue
        out[key] = {
            "p95_ms_median_delta": cur["p95_ms"]["median"] - prev.get("p95_ms", {}).get("median", 0.0),
            "p99_ms_median_delta": cur["p99_ms"]["median"] - prev.get("p99_ms", {}).get("median", 0.0),
            "error_rate_median_delta": cur["error_rate"]["median"] - prev.get("error_rate", {}).get("median", 0.0),
            "rps_ok_median_delta": cur["rps_ok"]["median"] - prev.get("rps_ok", {}).get("median", 0.0),
        }
    return out


def _write_markdown(path, payload):
    lines = []
    lines.append("# Performance Regression Report")
    lines.append("")
    lines.append(f"- timestamp_utc: `{payload.get('timestamp_utc')}`")
    lines.append(f"- target: `{payload.get('target')}`")
    lines.append(f"- profiles: `{','.join(payload.get('profiles', []))}`")
    lines.append(f"- runs_per_profile: `{payload.get('runs_per_profile')}`")
    lines.append(f"- overall_pass: `{payload.get('overall_pass')}`")
    lines.append("")
    lines.append("## Aggregated (median)")
    lines.append("")
    lines.append("| profile:phase | pass_rate | err% | p95 ms | p99 ms | rps_ok |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for key in sorted(payload.get("aggregated", {}).keys()):
        row = payload["aggregated"][key]
        lines.append(
            f"| {key} | {row['pass_rate']*100.0:.1f}% | {row['error_rate']['median']:.2f} | "
            f"{row['p95_ms']['median']:.2f} | {row['p99_ms']['median']:.2f} | {row['rps_ok']['median']:.2f} |"
        )
    lines.append("")
    lines.append("## Per Path (median)")
    lines.append("")
    for key in sorted(payload.get("aggregated", {}).keys()):
        row = payload["aggregated"][key]
        pmetrics = row.get("path_metrics", {}) or {}
        lines.append(f"### {key}")
        lines.append("")
        if not pmetrics:
            lines.append("- no path metrics")
            lines.append("")
            continue
        lines.append("| path | err% | p95 ms | p99 ms | rps_ok | req_total |")
        lines.append("|---|---:|---:|---:|---:|---:|")
        ordered = sorted(
            pmetrics.items(),
            key=lambda kv: kv[1].get("requests_total", {}).get("median", 0.0),
            reverse=True,
        )
        for ppath, pstat in ordered:
            lines.append(
                f"| {ppath} | {pstat['error_rate']['median']:.2f} | {pstat['p95_ms']['median']:.2f} | "
                f"{pstat['p99_ms']['median']:.2f} | {pstat['rps_ok']['median']:.2f} | "
                f"{pstat['requests_total']['median']:.1f} |"
            )
        lines.append("")

    cmp_obj = payload.get("comparison_to_previous") or {}
    if cmp_obj:
        lines.append("")
        lines.append("## Delta vs Previous (median)")
        lines.append("")
        lines.append("| profile:phase | delta err% | delta p95 ms | delta p99 ms | delta rps_ok |")
        lines.append("|---|---:|---:|---:|---:|")
        for key in sorted(cmp_obj.keys()):
            row = cmp_obj[key]
            lines.append(
                f"| {key} | {row['error_rate_median_delta']:+.2f} | {row['p95_ms_median_delta']:+.2f} | "
                f"{row['p99_ms_median_delta']:+.2f} | {row['rps_ok_median_delta']:+.2f} |"
            )

    with open(path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser(description="Repeatable performance runner with persisted history and deltas.")
    ap.add_argument("host", help="Device IP")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--profiles", default="api,mixed,static", help="Comma-separated: api,mixed,static")
    ap.add_argument("--runs", type=int, default=3, help="Runs per profile")
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--burst-clients", type=int, default=12)
    ap.add_argument("--burst-duration", type=int, default=20)
    ap.add_argument("--long-clients", type=int, default=8)
    ap.add_argument("--long-duration", type=int, default=60)
    ap.add_argument("--metrics-retries", type=int, default=20)
    ap.add_argument("--metrics-retry-delay-ms", type=int, default=100)
    ap.add_argument("--post-phase-settle-ms", type=int, default=250)
    ap.add_argument("--between-runs-sleep-ms", type=int, default=500)
    ap.add_argument("--history-dir", default="tools/perf_history")
    ap.add_argument("--lock-file", default="")
    ap.add_argument("--heartbeat-ms", type=int, default=5000)
    ap.add_argument("--phase-timeout-multiplier", type=float, default=2.5)
    ap.add_argument("--phase-timeout-min-s", type=float, default=45.0)
    ap.add_argument("--hard-timeout-s", type=float, default=0.0)
    ap.add_argument("--probe-path", default="/hello")
    ap.add_argument("--probe-retries", type=int, default=12)
    ap.add_argument("--tag", default="")
    ap.add_argument("--max-error-rate", type=float, default=2.0)
    ap.add_argument("--max-p95-ms", type=float, default=2000.0)
    ap.add_argument("--max-p99-ms", type=float, default=3000.0)
    ap.add_argument("--max-tail-p95-ratio", type=float, default=1.8)
    ap.add_argument("--max-internal-free-drop", type=int, default=131072)
    ap.add_argument("--max-psram-free-drop", type=int, default=524288)
    args = ap.parse_args()

    profiles = [x.strip().lower() for x in str(args.profiles).split(",") if x.strip()]
    supported_profiles = (
        "api",
        "mixed",
        "static",
        "c_static_only",
        "python_light",
        "python_heavy",
    )
    for p in profiles:
        if p not in supported_profiles:
            raise SystemExit(f"unsupported profile: {p}")
    if not profiles:
        raise SystemExit("no profiles selected")
    if args.runs < 1:
        raise SystemExit("runs must be >= 1")

    os.makedirs(args.history_dir, exist_ok=True)
    if not args.lock_file:
        args.lock_file = os.path.join(args.history_dir, ".perf_regression.lock")
    stamp = _now_utc()
    tag_suffix = ""
    if args.tag:
        cleaned = "".join(ch for ch in args.tag if ch.isalnum() or ch in ("-", "_")).strip()
        if cleaned:
            tag_suffix = "_" + cleaned

    target = f"{args.host}:{args.port}"
    raw_runs = []
    overall_pass = True
    hard_stop_reason = ""
    partial_path = os.path.join(args.history_dir, "latest.partial.json")
    heartbeat_s = max(0.5, args.heartbeat_ms / 1000.0)
    suite_started = time.monotonic()

    _acquire_lock(args.lock_file)

    try:
        print("=== PERF REGRESSION RUNNER ===")
        print(f"target={target}")
        print(f"profiles={profiles}")
        print(f"runs_per_profile={args.runs}")
        print(f"durations burst={args.burst_duration}s long={args.long_duration}s")
        print(f"heartbeat={heartbeat_s:.1f}s phase_timeout_multiplier={args.phase_timeout_multiplier:.2f}")

        stop = False
        for profile in profiles:
            if stop:
                break
            paths = gate.profile_paths(profile)
            for run_idx in range(1, args.runs + 1):
                if stop:
                    break
                print(f"\n--- profile={profile} run={run_idx}/{args.runs} ---")
                run_record = {"profile": profile, "run_index": run_idx, "results": []}
                for phase_name, clients, duration in (
                    ("burst", args.burst_clients, args.burst_duration),
                    ("long", args.long_clients, args.long_duration),
                ):
                    probe_path = args.probe_path or (paths[0] if paths else "/")
                    probe_rc = _probe_http_ok(
                        args.host,
                        args.port,
                        probe_path,
                        timeout_s=max(2.0, args.timeout),
                        retries=max(1, int(args.probe_retries)),
                    )
                    if probe_rc is not True:
                        phase_name = str(phase_name)
                        hard_stop_reason = f"probe failed before {profile}:{phase_name}: {probe_rc!r}"
                        print("probe_fail", hard_stop_reason)
                        stop = True
                        break

                    if args.hard_timeout_s > 0:
                        total_elapsed = time.monotonic() - suite_started
                        if total_elapsed >= args.hard_timeout_s:
                            hard_stop_reason = (
                                f"hard timeout reached after {total_elapsed:.1f}s "
                                f"(budget={args.hard_timeout_s:.1f}s)"
                            )
                            print("hard_timeout", hard_stop_reason)
                            stop = True
                            break

                    timeout_budget = max(
                        float(args.phase_timeout_min_s),
                        float(duration) * float(args.phase_timeout_multiplier) + float(args.timeout) * 2.0 + 10.0,
                    )
                    print(
                        "phase={} clients={} duration={}s timeout_budget={:.1f}s".format(
                            phase_name, clients, duration, timeout_budget
                        )
                    )
                    rep, phase_error, phase_elapsed = _run_phase_with_watchdog(
                        args=args,
                        paths=paths,
                        clients=clients,
                        duration=duration,
                        timeout_budget_s=timeout_budget,
                        heartbeat_s=heartbeat_s,
                    )
                    if rep is None:
                        rep = {
                            "clients": clients,
                            "duration": duration,
                            "elapsed": phase_elapsed,
                            "requests_total": 0,
                            "ok": 0,
                            "err": 1,
                            "error_rate": 100.0,
                            "rps_total": 0.0,
                            "rps_ok": 0.0,
                            "p50_ms": 0.0,
                            "p95_ms": 99999.0,
                            "p99_ms": 99999.0,
                            "p95_tail_ms": 99999.0,
                            "mean_ms": 0.0,
                            "status_counts": {},
                            "stats_after": {},
                            "mem_before": {},
                            "mem_after": {},
                        }
                        phase_ok = False
                        reasons = [phase_error or "phase failed"]
                    else:
                        phase_ok, reasons = _phase_pass(rep, args)
                        if phase_error:
                            phase_ok = False
                            reasons.append(phase_error)

                    run_record["results"].append(
                        {
                            "profile": profile,
                            "phase": phase_name,
                            "report": rep,
                            "pass": phase_ok,
                            "fail_reasons": reasons,
                        }
                    )
                    overall_pass = overall_pass and phase_ok
                    print(
                        "result pass={p} err={e:.2f}% p95={p95:.2f}ms p99={p99:.2f}ms rps_ok={rps:.2f}".format(
                            p=phase_ok,
                            e=_safe_float(rep.get("error_rate")),
                            p95=_safe_float(rep.get("p95_ms")),
                            p99=_safe_float(rep.get("p99_ms")),
                            rps=_safe_float(rep.get("rps_ok")),
                        )
                    )
                    if reasons:
                        print("fail_reasons=" + "; ".join(reasons))
                    path_metrics = rep.get("path_metrics", {}) or {}
                    if path_metrics:
                        ordered = sorted(
                            path_metrics.items(),
                            key=lambda kv: int(kv[1].get("requests_total", 0)),
                            reverse=True,
                        )
                        for ppath, pstat in ordered:
                            print(
                                "path={} total={} err={:.2f}% p95={:.2f} p99={:.2f} rps_ok={:.2f}".format(
                                    ppath,
                                    int(pstat.get("requests_total", 0)),
                                    float(pstat.get("error_rate", 0.0)),
                                    float(pstat.get("p95_ms", 0.0)),
                                    float(pstat.get("p99_ms", 0.0)),
                                    float(pstat.get("rps_ok", 0.0)),
                                )
                            )

                    partial_payload = {
                        "timestamp_utc": stamp,
                        "target": target,
                        "profiles": profiles,
                        "runs_per_profile": args.runs,
                        "partial": True,
                        "overall_pass_so_far": bool(overall_pass),
                        "raw_runs": raw_runs + [run_record],
                    }
                    _write_json(partial_path, partial_payload)

                raw_runs.append(run_record)
                _write_json(
                    partial_path,
                    {
                        "timestamp_utc": stamp,
                        "target": target,
                        "profiles": profiles,
                        "runs_per_profile": args.runs,
                        "partial": True,
                        "overall_pass_so_far": bool(overall_pass),
                        "raw_runs": raw_runs,
                    },
                )
                time.sleep(max(0.0, args.between_runs_sleep_ms / 1000.0))
    finally:
        _release_lock(args.lock_file)

    aggregated = _aggregate(raw_runs)
    latest_path = os.path.join(args.history_dir, "latest.json")
    previous = _load_previous(args.history_dir, latest_path)
    deltas = _compare(aggregated, previous)

    payload = {
        "timestamp_utc": stamp,
        "target": target,
        "profiles": profiles,
        "runs_per_profile": args.runs,
        "overall_pass": bool(overall_pass),
        "raw_runs": raw_runs,
        "aggregated": aggregated,
        "comparison_to_previous": deltas,
        "hard_stop_reason": hard_stop_reason,
        "thresholds": {
            "max_error_rate": args.max_error_rate,
            "max_p95_ms": args.max_p95_ms,
            "max_p99_ms": args.max_p99_ms,
            "max_tail_p95_ratio": args.max_tail_p95_ratio,
            "max_internal_free_drop": args.max_internal_free_drop,
            "max_psram_free_drop": args.max_psram_free_drop,
        },
    }

    json_name = f"perf_{stamp}{tag_suffix}.json"
    md_name = f"perf_{stamp}{tag_suffix}.md"
    json_path = os.path.join(args.history_dir, json_name)
    md_path = os.path.join(args.history_dir, md_name)
    _write_json(json_path, payload)
    _write_json(latest_path, payload)
    _write_markdown(md_path, payload)
    try:
        if os.path.exists(partial_path):
            os.remove(partial_path)
    except Exception:
        pass

    print("\n=== PERF SUMMARY (median) ===")
    for key in sorted(aggregated.keys()):
        row = aggregated[key]
        print(
            f"{key}: pass_rate={row['pass_rate']*100.0:.1f}% err={row['error_rate']['median']:.2f}% "
            f"p95={row['p95_ms']['median']:.2f} p99={row['p99_ms']['median']:.2f} rps_ok={row['rps_ok']['median']:.2f}"
        )
    print(f"saved_json={json_path}")
    print(f"saved_md={md_path}")
    if deltas:
        print("comparison=available")
    else:
        print("comparison=not_available")
    print(f"overall_pass={overall_pass}")

    return 0 if overall_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())

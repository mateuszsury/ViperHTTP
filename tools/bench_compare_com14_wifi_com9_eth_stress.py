#!/usr/bin/env python3
import argparse
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone


IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
SAVED_JSON_RE = re.compile(r"^saved_json=(.+)$", re.MULTILINE)


def now_stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def run_cmd(cmd, cwd, timeout=300, check=True):
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            "command failed rc=%s\ncmd=%s\nstdout:\n%s\nstderr:\n%s"
            % (proc.returncode, " ".join(cmd), proc.stdout, proc.stderr)
        )
    return proc


def sync_python_files(repo_root, port):
    files = [
        "viperhttp_app.py",
        "viperhttp_bridge.py",
        "viperhttp_auth.py",
        "viperhttp_session.py",
        "viperhttp_responses.py",
        "viperhttp_lifespan.py",
        "viperhttp_ws.py",
        "viperhttp_autodocs.py",
        "viperhttp_ota.py",
        "tools/bench_server_highlevel.py",
    ]
    for rel in files:
        src = os.path.join(repo_root, rel)
        dst = ":/" + os.path.basename(rel)
        run_cmd(
            [sys.executable, "-m", "mpremote", "connect", port, "fs", "cp", src, dst],
            cwd=repo_root,
            timeout=120,
            check=True,
        )


def sync_www(repo_root, port):
    run_cmd(
        [
            "powershell",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            os.path.join(repo_root, "tools", "sync_vfs.ps1"),
            "-Port",
            port,
            "-Source",
            os.path.join(repo_root, "tools", "www"),
            "-Target",
            "/www",
            "-GzipMinSize",
            "0",
            "-GzipLevel",
            "6",
        ],
        cwd=repo_root,
        timeout=900,
        check=True,
    )


class DeviceServerSession:
    def __init__(self, repo_root, port, run_script, label):
        self.repo_root = repo_root
        self.port = port
        self.run_script = run_script
        self.label = label
        self.proc = None
        self.queue = queue.Queue()
        self.log_lines = []
        self.ip = None

    def _pump(self, stream, stream_name):
        try:
            for line in iter(stream.readline, ""):
                text = line.rstrip("\n")
                self.queue.put((stream_name, text))
        finally:
            self.queue.put((stream_name, None))

    def _extract_ip(self, text):
        for match in IP_RE.findall(text):
            if match != "0.0.0.0":
                return match
        return None

    def start(self, timeout_s=120):
        cmd = [
            sys.executable,
            "-m",
            "mpremote",
            "connect",
            self.port,
            "run",
            self.run_script,
        ]
        self.proc = subprocess.Popen(
            cmd,
            cwd=self.repo_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        threading.Thread(target=self._pump, args=(self.proc.stdout, "OUT"), daemon=True).start()
        threading.Thread(target=self._pump, args=(self.proc.stderr, "ERR"), daemon=True).start()

        deadline = time.time() + timeout_s
        server_ready = False
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    "%s process exited early rc=%s\n%s"
                    % (self.label, self.proc.returncode, "\n".join(self.log_lines[-80:]))
                )
            try:
                stream_name, line = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if line is None:
                continue
            prefixed = "[%s %s] %s" % (self.label, stream_name, line)
            self.log_lines.append(prefixed)
            print(prefixed)
            ip = self._extract_ip(line)
            if ip:
                self.ip = ip
            if "server_running True" in line:
                server_ready = True
            if server_ready and self.ip:
                return self.ip

        raise RuntimeError("%s startup timeout, last logs:\n%s" % (self.label, "\n".join(self.log_lines[-120:])))

    def stop(self):
        try:
            run_cmd(
                [
                    sys.executable,
                    "-m",
                    "mpremote",
                    "connect",
                    self.port,
                    "exec",
                    "import viperhttp; viperhttp.stop(); print('stopped')",
                ],
                cwd=self.repo_root,
                timeout=30,
                check=False,
            )
        except Exception:
            pass
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=8)
            except Exception:
                self.proc.kill()
        self.proc = None


def _parse_saved_json_path(stdout_text, repo_root):
    match = SAVED_JSON_RE.search(stdout_text or "")
    if match:
        candidate = match.group(1).strip()
        if os.path.isabs(candidate):
            return candidate
        return os.path.abspath(os.path.join(repo_root, candidate))
    return None


def _load_json(path):
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp)


def _run_perf_regression(repo_root, ip, tag, args):
    profiles = ",".join([x.strip() for x in str(args.profiles).split(",") if x.strip()])
    if not profiles:
        raise RuntimeError("empty profiles")

    phase_total_s = int(args.runs) * len(profiles.split(",")) * (int(args.burst_duration) + int(args.long_duration))
    timeout_s = max(
        900,
        int(phase_total_s * float(args.timeout_factor)) + 300,
    )

    cmd = [
        sys.executable,
        os.path.join("tools", "perf_regression.py"),
        ip,
        "--port",
        str(args.bench_port),
        "--profiles",
        profiles,
        "--runs",
        str(args.runs),
        "--timeout",
        str(args.request_timeout),
        "--burst-clients",
        str(args.burst_clients),
        "--burst-duration",
        str(args.burst_duration),
        "--long-clients",
        str(args.long_clients),
        "--long-duration",
        str(args.long_duration),
        "--metrics-retries",
        str(args.metrics_retries),
        "--metrics-retry-delay-ms",
        str(args.metrics_retry_delay_ms),
        "--post-phase-settle-ms",
        str(args.post_phase_settle_ms),
        "--between-runs-sleep-ms",
        str(args.between_runs_sleep_ms),
        "--phase-timeout-multiplier",
        str(args.phase_timeout_multiplier),
        "--phase-timeout-min-s",
        str(args.phase_timeout_min_s),
        "--heartbeat-ms",
        str(args.heartbeat_ms),
        "--probe-retries",
        str(args.probe_retries),
        "--tag",
        tag,
        "--max-error-rate",
        str(args.max_error_rate),
        "--max-p95-ms",
        str(args.max_p95_ms),
        "--max-p99-ms",
        str(args.max_p99_ms),
        "--max-tail-p95-ratio",
        str(args.max_tail_p95_ratio),
        "--max-internal-free-drop",
        str(args.max_internal_free_drop),
        "--max-psram-free-drop",
        str(args.max_psram_free_drop),
    ]
    proc = run_cmd(cmd, cwd=repo_root, timeout=timeout_s, check=False)
    report_path = _parse_saved_json_path(proc.stdout, repo_root)
    if not report_path or not os.path.exists(report_path):
        raise RuntimeError(
            "cannot locate perf_regression json for tag=%s\nstdout:\n%s\nstderr:\n%s"
            % (tag, proc.stdout, proc.stderr)
        )
    report = _load_json(report_path)
    return {
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "report_path": report_path,
        "report": report,
    }


def _compare_aggregated(wifi_report, eth_report):
    wifi_map = (wifi_report or {}).get("aggregated", {}) or {}
    eth_map = (eth_report or {}).get("aggregated", {}) or {}
    common = sorted(set(wifi_map.keys()) & set(eth_map.keys()))
    out = {}
    for key in common:
        w = wifi_map[key]
        e = eth_map[key]
        wrps = float((w.get("rps_ok") or {}).get("median", 0.0))
        erps = float((e.get("rps_ok") or {}).get("median", 0.0))
        wp95 = float((w.get("p95_ms") or {}).get("median", 0.0))
        ep95 = float((e.get("p95_ms") or {}).get("median", 0.0))
        wp99 = float((w.get("p99_ms") or {}).get("median", 0.0))
        ep99 = float((e.get("p99_ms") or {}).get("median", 0.0))
        werr = float((w.get("error_rate") or {}).get("median", 0.0))
        eerr = float((e.get("error_rate") or {}).get("median", 0.0))

        gain = 0.0
        if wrps > 0.0:
            gain = ((erps / wrps) - 1.0) * 100.0
        out[key] = {
            "wifi_rps_ok_median": wrps,
            "eth_rps_ok_median": erps,
            "rps_gain_pct_eth_vs_wifi": gain,
            "wifi_p95_ms_median": wp95,
            "eth_p95_ms_median": ep95,
            "p95_ms_delta_eth_minus_wifi": ep95 - wp95,
            "wifi_p99_ms_median": wp99,
            "eth_p99_ms_median": ep99,
            "p99_ms_delta_eth_minus_wifi": ep99 - wp99,
            "wifi_error_rate_median": werr,
            "eth_error_rate_median": eerr,
            "error_rate_delta_eth_minus_wifi": eerr - werr,
            "wifi_pass_rate": float(w.get("pass_rate", 0.0)),
            "eth_pass_rate": float(e.get("pass_rate", 0.0)),
        }
    return out


def main():
    parser = argparse.ArgumentParser(
        description="High-load Wi-Fi vs Ethernet comparator using perf_regression (burst + soak + profile matrix)."
    )
    parser.add_argument("--wifi-port", default="COM14")
    parser.add_argument("--eth-port", default="COM9")
    parser.add_argument("--bench-port", type=int, default=8080)
    parser.add_argument("--startup-timeout", type=int, default=140)
    parser.add_argument("--sync-python", action="store_true", default=False)
    parser.add_argument("--sync-www", action="store_true", default=False)
    parser.add_argument("--verify-full-test", action="store_true", default=False)
    parser.add_argument("--require-pass", action="store_true", default=False)

    # High-load defaults: multi-profile and multi-phase.
    parser.add_argument("--profiles", default="mixed,api,static,c_static_only")
    parser.add_argument("--runs", type=int, default=2)
    parser.add_argument("--burst-clients", type=int, default=24)
    parser.add_argument("--burst-duration", type=int, default=30)
    parser.add_argument("--long-clients", type=int, default=14)
    parser.add_argument("--long-duration", type=int, default=120)

    parser.add_argument("--request-timeout", type=float, default=8.0)
    parser.add_argument("--metrics-retries", type=int, default=24)
    parser.add_argument("--metrics-retry-delay-ms", type=int, default=120)
    parser.add_argument("--post-phase-settle-ms", type=int, default=400)
    parser.add_argument("--between-runs-sleep-ms", type=int, default=700)
    parser.add_argument("--phase-timeout-multiplier", type=float, default=3.0)
    parser.add_argument("--phase-timeout-min-s", type=float, default=60.0)
    parser.add_argument("--heartbeat-ms", type=int, default=5000)
    parser.add_argument("--probe-retries", type=int, default=16)
    parser.add_argument("--timeout-factor", type=float, default=4.0)

    parser.add_argument("--max-error-rate", type=float, default=8.0)
    parser.add_argument("--max-p95-ms", type=float, default=6000.0)
    parser.add_argument("--max-p99-ms", type=float, default=9000.0)
    parser.add_argument("--max-tail-p95-ratio", type=float, default=2.2)
    parser.add_argument("--max-internal-free-drop", type=int, default=262144)
    parser.add_argument("--max-psram-free-drop", type=int, default=1048576)
    args = parser.parse_args()

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(os.path.join(repo_root, "tools", "perf_history"), exist_ok=True)

    if args.sync_python:
        print("sync_python", args.wifi_port)
        sync_python_files(repo_root, args.wifi_port)
        print("sync_python", args.eth_port)
        sync_python_files(repo_root, args.eth_port)
    if args.sync_www:
        print("sync_www", args.wifi_port)
        sync_www(repo_root, args.wifi_port)
        print("sync_www", args.eth_port)
        sync_www(repo_root, args.eth_port)

    stamp = now_stamp()
    wifi = DeviceServerSession(repo_root, args.wifi_port, "tools/run_server_bench_wifi_highlevel.py", "wifi")
    eth = DeviceServerSession(repo_root, args.eth_port, "tools/run_server_bench_eth_w5500_highlevel.py", "ethernet")

    try:
        wifi_ip = wifi.start(timeout_s=args.startup_timeout)
        print("wifi_ip", wifi_ip)
        if args.verify_full_test:
            run_cmd(
                [sys.executable, os.path.join("tools", "host_full_test.py"), wifi_ip, "--scheme", "http", "--port", str(args.bench_port)],
                cwd=repo_root,
                timeout=1200,
                check=True,
            )
        wifi_perf = _run_perf_regression(repo_root, wifi_ip, "wifi_%s" % stamp, args)
        print("wifi_perf_done rc=%s json=%s" % (wifi_perf["returncode"], wifi_perf["report_path"]))
    finally:
        wifi.stop()

    try:
        eth_ip = eth.start(timeout_s=args.startup_timeout)
        print("eth_ip", eth_ip)
        if args.verify_full_test:
            run_cmd(
                [sys.executable, os.path.join("tools", "host_full_test.py"), eth_ip, "--scheme", "http", "--port", str(args.bench_port)],
                cwd=repo_root,
                timeout=1200,
                check=True,
            )
        eth_perf = _run_perf_regression(repo_root, eth_ip, "eth_%s" % stamp, args)
        print("eth_perf_done rc=%s json=%s" % (eth_perf["returncode"], eth_perf["report_path"]))
    finally:
        eth.stop()

    comparison = _compare_aggregated(wifi_perf["report"], eth_perf["report"])
    out_payload = {
        "timestamp_utc": stamp,
        "settings": {
            "wifi_port": args.wifi_port,
            "eth_port": args.eth_port,
            "bench_port": args.bench_port,
            "profiles": args.profiles,
            "runs": args.runs,
            "burst_clients": args.burst_clients,
            "burst_duration": args.burst_duration,
            "long_clients": args.long_clients,
            "long_duration": args.long_duration,
        },
        "wifi": {
            "ip": wifi_ip,
            "returncode": wifi_perf["returncode"],
            "report_path": wifi_perf["report_path"],
            "overall_pass": bool((wifi_perf["report"] or {}).get("overall_pass", False)),
        },
        "ethernet": {
            "ip": eth_ip,
            "returncode": eth_perf["returncode"],
            "report_path": eth_perf["report_path"],
            "overall_pass": bool((eth_perf["report"] or {}).get("overall_pass", False)),
        },
        "comparison": comparison,
    }

    out_path = os.path.join(repo_root, "tools", "perf_history", "wifi_eth_stress_compare_%s.json" % stamp)
    with open(out_path, "w", encoding="utf-8") as fp:
        json.dump(out_payload, fp, indent=2, sort_keys=True)
        fp.write("\n")

    print("")
    print("=== WIFI vs ETHERNET STRESS (median per profile:phase) ===")
    for key in sorted(comparison.keys()):
        row = comparison[key]
        print(
            "%s | wifi rps %.2f | eth rps %.2f | eth gain %+0.2f%% | wifi p95 %.2f | eth p95 %.2f | wifi err %.2f%% | eth err %.2f%%"
            % (
                key,
                row["wifi_rps_ok_median"],
                row["eth_rps_ok_median"],
                row["rps_gain_pct_eth_vs_wifi"],
                row["wifi_p95_ms_median"],
                row["eth_p95_ms_median"],
                row["wifi_error_rate_median"],
                row["eth_error_rate_median"],
            )
        )
    print("saved", out_path)

    wifi_ok = wifi_perf["returncode"] == 0
    eth_ok = eth_perf["returncode"] == 0
    if args.require_pass:
        return 0 if (wifi_ok and eth_ok) else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

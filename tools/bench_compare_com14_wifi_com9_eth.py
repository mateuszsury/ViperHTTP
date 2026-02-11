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
                timeout=20,
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


def parse_http_bench(stdout_text):
    rows = {}
    for raw_line in stdout_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("Benchmark base=") or line.startswith("path,ok,err,req_s,mb_s,p50_ms,p95_ms"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) != 7:
            continue
        path = parts[0]
        try:
            rows[path] = {
                "ok": int(parts[1]),
                "err": int(parts[2]),
                "req_s": float(parts[3]),
                "mb_s": float(parts[4]),
                "p50_ms": float(parts[5]),
                "p95_ms": float(parts[6]),
            }
        except Exception:
            continue
    if not rows:
        raise RuntimeError("failed to parse http_bench output:\n%s" % stdout_text)
    return rows


def run_bench(repo_root, ip, port, duration, workers, paths):
    proc = run_cmd(
        [
            sys.executable,
            os.path.join("tools", "http_bench.py"),
            ip,
            "--port",
            str(port),
            "--scheme",
            "http",
            "--duration",
            str(duration),
            "--workers",
            str(workers),
            "--paths",
            paths,
        ],
        cwd=repo_root,
        timeout=max(180, duration * 40),
        check=False,
    )
    rows = parse_http_bench(proc.stdout)
    return {
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "metrics": rows,
    }


def compare_metrics(wifi_metrics, eth_metrics):
    common = sorted(set(wifi_metrics.keys()) & set(eth_metrics.keys()))
    out = {}
    for path in common:
        w = wifi_metrics[path]
        e = eth_metrics[path]
        req_gain_pct = 0.0
        if w["req_s"] > 0:
            req_gain_pct = ((e["req_s"] / w["req_s"]) - 1.0) * 100.0
        out[path] = {
            "wifi_req_s": w["req_s"],
            "eth_req_s": e["req_s"],
            "req_s_gain_pct_eth_vs_wifi": req_gain_pct,
            "wifi_p95_ms": w["p95_ms"],
            "eth_p95_ms": e["p95_ms"],
            "p95_ms_delta_eth_minus_wifi": e["p95_ms"] - w["p95_ms"],
            "wifi_err": w["err"],
            "eth_err": e["err"],
            "err_delta_eth_minus_wifi": e["err"] - w["err"],
        }
    return out


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark compare COM14 Wi-Fi vs COM9 Ethernet with identical high-level ViperHTTP runtime."
    )
    parser.add_argument("--wifi-port", default="COM14")
    parser.add_argument("--eth-port", default="COM9")
    parser.add_argument("--bench-port", type=int, default=8080)
    parser.add_argument("--duration", type=int, default=12)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--paths", default="/hello,/file,/static/large.txt")
    parser.add_argument("--startup-timeout", type=int, default=120)
    parser.add_argument("--sync-python", action="store_true", default=False)
    parser.add_argument("--sync-www", action="store_true", default=False)
    parser.add_argument("--verify-full-test", action="store_true", default=False)
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

    wifi = DeviceServerSession(repo_root, args.wifi_port, "tools/run_server_bench_wifi_highlevel.py", "wifi")
    eth = DeviceServerSession(repo_root, args.eth_port, "tools/run_server_bench_eth_w5500_highlevel.py", "ethernet")

    try:
        wifi_ip = wifi.start(timeout_s=args.startup_timeout)
        print("wifi_ip", wifi_ip)
        if args.verify_full_test:
            run_cmd(
                [sys.executable, os.path.join("tools", "host_full_test.py"), wifi_ip, "--scheme", "http", "--port", str(args.bench_port)],
                cwd=repo_root,
                timeout=900,
                check=True,
            )
        wifi_bench = run_bench(
            repo_root=repo_root,
            ip=wifi_ip,
            port=args.bench_port,
            duration=args.duration,
            workers=args.workers,
            paths=args.paths,
        )
        print("wifi_bench_done rc=%s" % wifi_bench["returncode"])
    finally:
        wifi.stop()

    try:
        eth_ip = eth.start(timeout_s=args.startup_timeout)
        print("eth_ip", eth_ip)
        if args.verify_full_test:
            run_cmd(
                [sys.executable, os.path.join("tools", "host_full_test.py"), eth_ip, "--scheme", "http", "--port", str(args.bench_port)],
                cwd=repo_root,
                timeout=900,
                check=True,
            )
        eth_bench = run_bench(
            repo_root=repo_root,
            ip=eth_ip,
            port=args.bench_port,
            duration=args.duration,
            workers=args.workers,
            paths=args.paths,
        )
        print("eth_bench_done rc=%s" % eth_bench["returncode"])
    finally:
        eth.stop()

    comparison = compare_metrics(wifi_bench["metrics"], eth_bench["metrics"])
    payload = {
        "timestamp_utc": now_stamp(),
        "wifi": {
            "port": args.wifi_port,
            "ip": wifi_ip,
            "bench": wifi_bench,
        },
        "ethernet": {
            "port": args.eth_port,
            "ip": eth_ip,
            "bench": eth_bench,
        },
        "settings": {
            "bench_port": args.bench_port,
            "duration": args.duration,
            "workers": args.workers,
            "paths": args.paths,
        },
        "comparison": comparison,
    }

    out_name = "wifi_eth_compare_%s.json" % now_stamp()
    out_path = os.path.join(repo_root, "tools", "perf_history", out_name)
    with open(out_path, "w", encoding="utf-8") as fp:
        json.dump(payload, fp, indent=2, sort_keys=True)
        fp.write("\n")

    print("")
    print("=== WIFI vs ETHERNET ===")
    for path in sorted(comparison.keys()):
        row = comparison[path]
        print(
            "%s | wifi req/s %.2f | eth req/s %.2f | eth gain %+0.2f%% | wifi p95 %.2f ms | eth p95 %.2f ms"
            % (
                path,
                row["wifi_req_s"],
                row["eth_req_s"],
                row["req_s_gain_pct_eth_vs_wifi"],
                row["wifi_p95_ms"],
                row["eth_p95_ms"],
            )
        )
    print("saved", out_path)

    if wifi_bench["returncode"] != 0 or eth_bench["returncode"] != 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
import argparse
import subprocess
import sys


def run_step(name, cmd):
    print(f"\n== {name} ==")
    print(" ".join(cmd))
    rc = subprocess.call(cmd)
    if rc != 0:
        print(f"FAIL: {name} (exit {rc})")
        return False
    print(f"OK: {name}")
    return True


def main():
    ap = argparse.ArgumentParser(description="Run HTTP/2 regression suite")
    ap.add_argument("ip")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()

    py = sys.executable
    ok = True

    ok &= run_step(
        "HTTP/2 preface",
        [py, "tools/http2_preface_test.py", args.ip, "--port", str(args.port)],
    )
    ok &= run_step(
        "HTTP/2 continuation ordering guard",
        [py, "tools/http2_continuation_guard_test.py", args.ip, "--port", str(args.port)],
    )
    ok &= run_step(
        "HTTP/2 WINDOW_UPDATE validation",
        [py, "tools/http2_window_update_validation_test.py", args.ip, "--port", str(args.port)],
    )
    ok &= run_step(
        "HTTP/2 stream backpressure resume",
        [py, "tools/http2_stream_backpressure_test.py", args.ip, "--port", str(args.port)],
    )
    ok &= run_step(
        "HTTP/2 prior-knowledge request",
        [py, "tools/http2_request_test.py", args.ip, "--port", str(args.port)],
    )
    ok &= run_step(
        "HTTP/2 h2c upgrade request",
        [
            py,
            "tools/http2_request_test.py",
            args.ip,
            "--port",
            str(args.port),
            "--upgrade-h2c",
            "--stream-id",
            "3",
        ],
    )
    ok &= run_step(
        "HTTP/2 interleaving (three streams / one connection)",
        [py, "tools/http2_interleave_test.py", args.ip, "--port", str(args.port)],
    )
    ok &= run_step(
        "HTTP/2 interleaving with DATA body (POST+GET, one connection)",
        [py, "tools/http2_interleave_data_test.py", args.ip, "--port", str(args.port)],
    )

    if ok:
        print("\nHTTP2 TESTS PASS")
        return 0
    print("\nHTTP2 TESTS FAIL")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

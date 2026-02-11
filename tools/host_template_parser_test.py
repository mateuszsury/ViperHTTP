import argparse
import subprocess
import sys


def run_mpremote(port, script_path):
    cmd = [sys.executable, "-m", "mpremote", "connect", port, "run", script_path]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)
    return proc.returncode


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("port", nargs="?", default="COM14")
    args = parser.parse_args()

    rc = run_mpremote(args.port, "tools/device_template_parser_vectors_test.py")
    if rc != 0:
        print("FAIL: parser/compiler vectors")
        return rc
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


import argparse
import hashlib
import http.client
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request


def _require(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _normalize_prefix(prefix):
    text = str(prefix or "").strip()
    if not text:
        return "/ota"
    if not text.startswith("/"):
        text = "/" + text
    if len(text) > 1 and text.endswith("/"):
        text = text[:-1]
    return text


def _parse_json_bytes(data):
    if not data:
        return {}
    return json.loads(data.decode("utf-8", "ignore"))


class _HttpClient:
    def __init__(self, base_url, insecure=False, timeout=20):
        self.base_url = base_url.rstrip("/")
        self.timeout = int(timeout)
        self.ctx = None
        if self.base_url.startswith("https://"):
            self.ctx = ssl.create_default_context()
            if insecure:
                self.ctx.check_hostname = False
                self.ctx.verify_mode = ssl.CERT_NONE

    def close(self):
        return

    def request(self, method, path, body=None, headers=None):
        req = urllib.request.Request(
            url=self.base_url + path,
            data=body,
            headers=headers or {},
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                status = int(resp.status)
                data = resp.read()
                out_headers = {k: v for (k, v) in resp.getheaders()}
                return status, data, out_headers
        except urllib.error.HTTPError as err:
            data = err.read()
            out_headers = dict(getattr(err, "headers", {}) or {})
            return int(err.code), data, out_headers

    def request_json(self, method, path, payload=None, headers=None):
        req_headers = dict(headers or {})
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            req_headers["Content-Type"] = "application/json"
        status, data, out_headers = self.request(method, path, body=body, headers=req_headers)
        parsed = None
        if data:
            try:
                parsed = _parse_json_bytes(data)
            except Exception:
                parsed = None
        return status, parsed, out_headers


def _firmware_info(path):
    size = 0
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            size += len(chunk)
            h.update(chunk)
    return size, h.hexdigest()


def _wait_for_status(client, status_path, auth_headers, timeout_s, poll_s):
    deadline = time.time() + float(timeout_s)
    last_exc = None
    while time.time() < deadline:
        try:
            status, payload, _ = client.request_json("GET", status_path, headers=auth_headers)
            if status == 200 and isinstance(payload, dict):
                return payload
        except Exception as exc:
            last_exc = exc
        time.sleep(float(poll_s))
    if last_exc is not None:
        raise RuntimeError("device did not recover after reboot: " + repr(last_exc))
    raise RuntimeError("device did not recover after reboot")


def _safe_label(part):
    if not isinstance(part, dict):
        return None
    lbl = part.get("label")
    if lbl is None:
        return None
    return str(lbl)


def _start_server_relay(serial_port, script_path, out_log, err_log):
    cmd = [
        sys.executable,
        "-m",
        "mpremote",
        "connect",
        str(serial_port),
        "run",
        str(script_path),
    ]
    out_f = open(out_log, "ab")
    err_f = open(err_log, "ab")
    proc = subprocess.Popen(cmd, stdout=out_f, stderr=err_f)
    print("relaunch_pid", proc.pid)
    return proc


def _kill_mpremote_holders(serial_port, script_hint=""):
    if os.name != "nt":
        return 0
    port = str(serial_port or "").strip()
    if not port:
        return 0
    hint = str(script_hint or "").strip()
    ps_script = (
        "$port='%s'; $hint='%s'; "
        "Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | "
        "Where-Object { "
        "$_.Name -match '^python(\\.exe)?$' -and "
        "$_.CommandLine -match 'mpremote' -and "
        "$_.CommandLine -match [regex]::Escape($port) -and "
        "($hint -eq '' -or $_.CommandLine -match [regex]::Escape($hint)) "
        "} | ForEach-Object { "
        "Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; "
        "Write-Output $_.ProcessId "
        "}"
    ) % (port.replace("'", "''"), hint.replace("'", "''"))
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", ps_script],
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
        )
    except Exception as exc:
        print("kill_mpremote_warn", repr(exc))
        return 0
    killed = 0
    for line in (out or "").splitlines():
        t = line.strip()
        if not t:
            continue
        try:
            int(t)
            killed += 1
        except Exception:
            pass
    if killed > 0:
        print("killed_mpremote", killed)
    return killed


def main():
    ap = argparse.ArgumentParser(description="OTA E2E test over HTTP(S) with reboot/rollback check")
    ap.add_argument("ip", help="Device IP address")
    ap.add_argument("--scheme", choices=["http", "https"], default="https")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--insecure", action="store_true", default=False, help="disable TLS cert verification")
    ap.add_argument("--ota-prefix", default="/ota")
    ap.add_argument("--token", default="ota-e2e-token")
    ap.add_argument("--token-header", default="X-OTA-Token")
    ap.add_argument("--firmware", default="vendor/micropython/ports/esp32/build-ESP32S3_N16R8/micropython.bin")
    ap.add_argument("--chunk-size", type=int, default=3840)
    ap.add_argument("--chunk-retries", type=int, default=4)
    ap.add_argument("--reboot-timeout", type=int, default=120)
    ap.add_argument("--poll-interval", type=float, default=2.0)
    ap.add_argument("--reboot-path", default="/debug/reboot", help="HTTP path used for second reboot check")
    ap.add_argument("--serial-port", default="", help="Optional COM port for second reboot check")
    ap.add_argument("--restart-script", default="", help="Optional device run script to relaunch server after reboot")
    ap.add_argument("--restart-out-log", default="tools/server.ota.e2e.out.log")
    ap.add_argument("--restart-err-log", default="tools/server.ota.e2e.err.log")
    ap.add_argument("--skip-mark-valid", action="store_true", default=False)
    ap.add_argument("--skip-second-reboot-check", action="store_true", default=False)
    args = ap.parse_args()

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    firmware_path = args.firmware
    if not os.path.isabs(firmware_path):
        firmware_path = os.path.join(repo_root, firmware_path)
    firmware_path = os.path.abspath(firmware_path)
    _require(os.path.exists(firmware_path), "firmware file missing: " + firmware_path)
    _require(args.chunk_size > 0, "chunk-size must be > 0")
    _require(args.chunk_retries >= 0, "chunk-retries must be >= 0")
    restart_script = str(args.restart_script or "").strip()
    if restart_script:
        if not os.path.isabs(restart_script):
            restart_script = os.path.join(repo_root, restart_script)
        restart_script = os.path.abspath(restart_script)
        _require(os.path.exists(restart_script), "restart script missing: " + restart_script)
    restart_out_log = str(args.restart_out_log or "tools/server.ota.e2e.out.log")
    restart_err_log = str(args.restart_err_log or "tools/server.ota.e2e.err.log")
    if not os.path.isabs(restart_out_log):
        restart_out_log = os.path.join(repo_root, restart_out_log)
    if not os.path.isabs(restart_err_log):
        restart_err_log = os.path.join(repo_root, restart_err_log)
    launched = []

    base_url = "%s://%s:%d" % (args.scheme, args.ip, int(args.port))
    prefix = _normalize_prefix(args.ota_prefix)
    client = _HttpClient(base_url, insecure=bool(args.insecure), timeout=25)
    auth_headers = {}
    token = str(args.token or "")
    if token:
        auth_headers[str(args.token_header)] = token

    firmware_size, firmware_sha = _firmware_info(firmware_path)
    print("firmware_path", firmware_path)
    print("firmware_size", firmware_size)
    print("firmware_sha256", firmware_sha)

    status_path = prefix + "/status"
    begin_path = prefix + "/begin"
    chunk_path = prefix + "/chunk"
    finalize_path = prefix + "/finalize"
    abort_path = prefix + "/abort"
    mark_valid_path = prefix + "/mark-valid"

    if token:
        st_code, _, _ = client.request_json("GET", status_path, headers={})
        _require(st_code == 401, "token guard expected 401 without token, got %s" % st_code)

    st_code, st_payload, _ = client.request_json("GET", status_path, headers=auth_headers)
    _require(st_code == 200, "status expected 200, got %s" % st_code)
    _require(isinstance(st_payload, dict), "status payload is not JSON object")
    _require(st_payload.get("supported") is True, "OTA unsupported on target")

    before_running = _safe_label(st_payload.get("running_partition"))
    before_boot = _safe_label(st_payload.get("boot_partition"))
    expected_target = _safe_label(st_payload.get("next_update_partition"))
    print("partition_before_running", before_running)
    print("partition_before_boot", before_boot)
    print("partition_expected_target", expected_target)
    _require(expected_target is not None, "next_update_partition.label missing")
    _require(
        before_running != expected_target,
        "next_update_partition matches running_partition; reflash baseline first (ota_data_initial)",
    )

    _ = client.request_json("POST", abort_path, headers=auth_headers)

    begin_payload = {
        "expected_size": firmware_size,
        "expected_sha256": firmware_sha,
        "force": True,
    }
    st_code, begin_data, _ = client.request_json("POST", begin_path, payload=begin_payload, headers=auth_headers)
    _require(st_code == 200, "begin expected 200, got %s" % st_code)
    _require(isinstance(begin_data, dict) and begin_data.get("active") is True, "begin did not activate OTA")

    sent = 0
    next_report = 0
    with open(firmware_path, "rb") as f:
        while True:
            chunk = f.read(int(args.chunk_size))
            if not chunk:
                break
            chunk_headers = dict(auth_headers)
            chunk_headers["Content-Type"] = "application/octet-stream"
            path = "%s?offset=%d" % (chunk_path, sent)
            status_raw = None
            body_raw = b""
            attempts = 0
            while True:
                try:
                    status_raw, body_raw, _ = client.request("POST", path, body=chunk, headers=chunk_headers)
                except (urllib.error.URLError, TimeoutError, ConnectionResetError, http.client.RemoteDisconnected, ssl.SSLError, OSError) as exc:
                    attempts += 1
                    if attempts > int(args.chunk_retries):
                        raise RuntimeError("chunk write transport error at %d: %r" % (sent, exc))
                    print("chunk_retry_transport", sent, attempts, repr(exc))
                    time.sleep(0.5)
                    continue
                if status_raw == 200:
                    break
                attempts += 1
                if status_raw in (500, 502, 503, 504) and attempts <= int(args.chunk_retries):
                    print("chunk_retry_status", sent, attempts, status_raw)
                    time.sleep(0.5)
                    continue
                _require(status_raw == 200, "chunk write failed at %d, status=%s body=%r" % (sent, status_raw, body_raw[:160]))
            try:
                chunk_data = _parse_json_bytes(body_raw)
            except Exception:
                chunk_data = None
            sent += len(chunk)
            sess = (chunk_data or {}).get("session", {})
            written = int(sess.get("written_bytes", sent))
            _require(written == sent, "written_bytes mismatch: expected %d got %d" % (sent, written))
            if sent >= next_report or sent == firmware_size:
                pct = (100.0 * float(sent)) / float(firmware_size)
                print("upload_progress", "%d/%d" % (sent, firmware_size), "%.2f%%" % pct)
                next_report = sent + (256 * 1024)

    _require(sent == firmware_size, "sent bytes mismatch")

    finalize_payload = {"set_boot": True, "strict_size": True, "reboot": True}
    finalize_reboot_observed = False
    finalize_ok = False
    try:
        st_code, fin_data, _ = client.request_json("POST", finalize_path, payload=finalize_payload, headers=auth_headers)
        if st_code == 200 and isinstance(fin_data, dict) and fin_data.get("ok") is True:
            finalize_ok = True
    except (urllib.error.URLError, TimeoutError, ConnectionResetError, http.client.RemoteDisconnected, ssl.SSLError, OSError):
        finalize_reboot_observed = True

    _require(finalize_ok or finalize_reboot_observed, "finalize with reboot did not succeed")
    print("finalize_result", "ok" if finalize_ok else "reboot_disconnect")

    try:
        recovered = _wait_for_status(
            client,
            status_path=status_path,
            auth_headers=auth_headers,
            timeout_s=args.reboot_timeout,
            poll_s=args.poll_interval,
        )
    except Exception as first_recover_exc:
        if args.serial_port and restart_script:
            print("relaunch_after_reboot", repr(first_recover_exc))
            _kill_mpremote_holders(args.serial_port, os.path.basename(restart_script))
            proc = _start_server_relay(
                serial_port=args.serial_port,
                script_path=restart_script,
                out_log=restart_out_log,
                err_log=restart_err_log,
            )
            launched.append(proc)
            time.sleep(5.0)
            recovered = _wait_for_status(
                client,
                status_path=status_path,
                auth_headers=auth_headers,
                timeout_s=args.reboot_timeout,
                poll_s=args.poll_interval,
            )
        else:
            raise
    _require(recovered.get("supported") is True, "status after reboot missing OTA support")
    after_running = _safe_label(recovered.get("running_partition"))
    after_boot = _safe_label(recovered.get("boot_partition"))
    print("partition_after_reboot_running", after_running)
    print("partition_after_reboot_boot", after_boot)

    if expected_target:
        _require(after_boot == expected_target, "boot partition mismatch after OTA reboot")
        _require(after_running == expected_target, "running partition mismatch after OTA reboot")
    if before_running and expected_target and before_running != expected_target:
        _require(after_running != before_running, "running partition did not change after OTA reboot")

    if not args.skip_mark_valid:
        st_code, mark_data, _ = client.request_json("POST", mark_valid_path, payload={}, headers=auth_headers)
        _require(st_code == 200, "mark-valid expected 200, got %s" % st_code)
        _require(isinstance(mark_data, dict) and mark_data.get("ok") is True, "mark-valid failed")
        print("mark_valid", "ok")

    if not args.skip_second_reboot_check:
        reboot_path = str(args.reboot_path or "/debug/reboot")
        if not reboot_path.startswith("/"):
            reboot_path = "/" + reboot_path
        reboot_sent = False
        try:
            status_reboot, _, _ = client.request_json("POST", reboot_path, payload={"delay_ms": 120}, headers={})
            if status_reboot == 200:
                reboot_sent = True
        except (urllib.error.URLError, TimeoutError, ConnectionResetError, http.client.RemoteDisconnected, ssl.SSLError, OSError):
            reboot_sent = True

        if not reboot_sent and args.serial_port:
            cmd = [
                sys.executable,
                "-m",
                "mpremote",
                "connect",
                str(args.serial_port),
                "exec",
                "import machine; machine.reset()",
            ]
            print("second_reboot_cmd", " ".join(cmd))
            rc = subprocess.call(cmd)
            _require(rc == 0, "second reboot command failed: rc=%d" % rc)
            reboot_sent = True

        _require(reboot_sent, "unable to trigger second reboot over HTTP or serial fallback")

        try:
            recovered2 = _wait_for_status(
                client,
                status_path=status_path,
                auth_headers=auth_headers,
                timeout_s=args.reboot_timeout,
                poll_s=args.poll_interval,
            )
        except Exception as second_recover_exc:
            if args.serial_port and restart_script:
                print("relaunch_after_second_reboot", repr(second_recover_exc))
                _kill_mpremote_holders(args.serial_port, os.path.basename(restart_script))
                proc = _start_server_relay(
                    serial_port=args.serial_port,
                    script_path=restart_script,
                    out_log=restart_out_log,
                    err_log=restart_err_log,
                )
                launched.append(proc)
                time.sleep(5.0)
                recovered2 = _wait_for_status(
                    client,
                    status_path=status_path,
                    auth_headers=auth_headers,
                    timeout_s=args.reboot_timeout,
                    poll_s=args.poll_interval,
                )
            else:
                raise
        running2 = _safe_label(recovered2.get("running_partition"))
        boot2 = _safe_label(recovered2.get("boot_partition"))
        print("partition_after_second_reboot_running", running2)
        print("partition_after_second_reboot_boot", boot2)
        if expected_target:
            _require(running2 == expected_target, "rollback detected after second reboot")
            _require(boot2 == expected_target, "boot partition changed after second reboot")

    print("PASS: OTA E2E test")
    client.close()
    print("relaunch_count", len(launched))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

try:
    import ubinascii as binascii
except Exception:
    import binascii

try:
    import uhashlib as hashlib
except Exception:
    import hashlib

try:
    import machine
except Exception:
    machine = None

try:
    import esp32
except Exception:
    esp32 = None

import time


_OTA_SESSION = None
_OTA_LAST_RESULT = None
_OTA_LAST_ERROR = None
_OTA_SESSION_SEQ = 0


class OTAError(Exception):
    def __init__(self, detail, status_code=400):
        super().__init__(str(detail))
        self.status_code = int(status_code)
        self.detail = str(detail)


def _ticks_ms():
    if hasattr(time, "ticks_ms"):
        return time.ticks_ms()
    return int(time.time() * 1000)


def _ticks_diff(a, b):
    if hasattr(time, "ticks_diff"):
        return time.ticks_diff(a, b)
    return a - b


def _is_ota_supported():
    return esp32 is not None and hasattr(esp32, "Partition")


def _new_sha256():
    try:
        return hashlib.sha256()
    except Exception:
        return None


def _sha256_digest_hex(ctx):
    if ctx is None:
        return None
    try:
        return binascii.hexlify(ctx.digest()).decode("utf-8")
    except Exception:
        return None


def _to_bytes(value):
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, memoryview):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError("expected bytes-like value")


def _to_text(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            return bytes(value).decode("utf-8")
        except Exception:
            return ""
    return str(value)


def _ct_eq_text(a, b):
    if a is None or b is None:
        return False
    a = _to_text(a).encode("utf-8")
    b = _to_text(b).encode("utf-8")
    if len(a) != len(b):
        return False
    acc = 0
    for i in range(len(a)):
        acc |= a[i] ^ b[i]
    return acc == 0


def _parse_expected_sha256(value):
    if value is None:
        return None
    text = _to_text(value).strip().lower()
    if not text:
        return None
    if len(text) != 64:
        raise OTAError("expected_sha256 must be 64 hex chars", 400)
    for ch in text:
        if ch not in "0123456789abcdef":
            raise OTAError("expected_sha256 must be lowercase/uppercase hex", 400)
    return text


def _parse_positive_int(value, field_name, allow_none=True):
    if value is None:
        if allow_none:
            return None
        raise OTAError(field_name + " is required", 400)
    try:
        iv = int(value)
    except Exception:
        raise OTAError(field_name + " must be int", 400)
    if iv < 0:
        raise OTAError(field_name + " must be >= 0", 400)
    return iv


def _partition_info_dict(part):
    if part is None:
        return None
    try:
        info = part.info()
    except Exception:
        return None
    out = {"raw": info}
    try:
        if isinstance(info, (tuple, list)) and len(info) >= 6:
            out["type"] = int(info[0])
            out["subtype"] = int(info[1])
            out["address"] = int(info[2])
            out["size"] = int(info[3])
            out["label"] = _to_text(info[4])
            out["encrypted"] = bool(info[5])
    except Exception:
        pass
    return out


def _get_running_partition():
    if not _is_ota_supported():
        return None
    P = esp32.Partition
    try:
        return P(P.RUNNING)
    except Exception:
        return None


def _get_boot_partition():
    if not _is_ota_supported():
        return None
    P = esp32.Partition
    try:
        return P(P.BOOT)
    except Exception:
        return None


def _get_next_update_partition():
    running = _get_running_partition()
    if running is None:
        return None
    try:
        return running.get_next_update()
    except Exception:
        return None


def _status_snapshot():
    global _OTA_SESSION
    sess = _OTA_SESSION
    running = _partition_info_dict(_get_running_partition())
    boot = _partition_info_dict(_get_boot_partition())
    next_update = _partition_info_dict(_get_next_update_partition())

    out = {
        "supported": _is_ota_supported(),
        "active": bool(sess is not None and sess.get("active")),
        "running_partition": running,
        "boot_partition": boot,
        "next_update_partition": next_update,
        "last_result": _OTA_LAST_RESULT,
        "last_error": _OTA_LAST_ERROR,
    }
    if sess is None:
        out["session"] = None
        return out

    expected_size = sess.get("expected_size")
    written = int(sess.get("written", 0))
    remaining = None
    progress_pct = None
    if expected_size is not None:
        remaining = int(expected_size) - written
        if remaining < 0:
            remaining = 0
        if expected_size > 0:
            progress_pct = (written * 100.0) / float(expected_size)

    elapsed_ms = _ticks_diff(_ticks_ms(), int(sess.get("started_ms", 0)))
    if elapsed_ms < 0:
        elapsed_ms = 0

    out["session"] = {
        "id": sess.get("id"),
        "active": bool(sess.get("active")),
        "partition": sess.get("partition_info"),
        "capacity_bytes": int(sess.get("capacity", 0)),
        "block_size": int(sess.get("block_size", 0)),
        "block_count": int(sess.get("block_count", 0)),
        "written_bytes": written,
        "expected_size": expected_size,
        "remaining_bytes": remaining,
        "progress_pct": progress_pct,
        "expected_sha256": sess.get("expected_sha256"),
        "elapsed_ms": elapsed_ms,
    }
    return out


def ota_status():
    return _status_snapshot()


def _require_session(active=True):
    global _OTA_SESSION
    sess = _OTA_SESSION
    if active:
        if sess is None or not sess.get("active"):
            raise OTAError("ota session is not active", 409)
    return sess


def ota_begin(expected_size=None, expected_sha256=None, force=False):
    global _OTA_SESSION
    global _OTA_LAST_ERROR
    global _OTA_SESSION_SEQ

    if not _is_ota_supported():
        raise OTAError("OTA unsupported on this platform", 501)

    if _OTA_SESSION is not None and _OTA_SESSION.get("active"):
        if not force:
            raise OTAError("ota session already active", 409)
        ota_abort()

    part = _get_next_update_partition()
    if part is None:
        raise OTAError("next update partition unavailable", 500)

    try:
        block_count = int(part.ioctl(4, 0))
        block_size = int(part.ioctl(5, 0))
    except Exception as exc:
        raise OTAError("failed to read partition geometry: " + repr(exc), 500)

    if block_count <= 0 or block_size <= 0:
        raise OTAError("invalid partition geometry", 500)
    capacity = block_count * block_size

    expected_size = _parse_positive_int(expected_size, "expected_size", allow_none=True)
    if expected_size is not None and expected_size > capacity:
        raise OTAError("expected_size exceeds update partition capacity", 400)
    expected_sha256 = _parse_expected_sha256(expected_sha256)

    sha_ctx = _new_sha256()
    if expected_sha256 is not None and sha_ctx is None:
        raise OTAError("sha256 unavailable on this build", 500)

    _OTA_SESSION_SEQ += 1
    _OTA_SESSION = {
        "id": _OTA_SESSION_SEQ,
        "active": True,
        "started_ms": _ticks_ms(),
        "partition": part,
        "partition_info": _partition_info_dict(part),
        "block_size": block_size,
        "block_count": block_count,
        "capacity": capacity,
        "erased": bytearray(block_count),
        "written": 0,
        "expected_size": expected_size,
        "expected_sha256": expected_sha256,
        "sha_ctx": sha_ctx,
    }
    _OTA_LAST_ERROR = None
    return _status_snapshot()


def _erase_blocks_for_write(sess, start_offset, length):
    part = sess["partition"]
    block_size = int(sess["block_size"])
    erased = sess["erased"]
    first = int(start_offset // block_size)
    last = int((start_offset + length - 1) // block_size)
    for block in range(first, last + 1):
        if erased[block]:
            continue
        try:
            part.ioctl(6, block)
        except Exception as exc:
            raise OTAError("erase failed at block " + str(block) + ": " + repr(exc), 500)
        erased[block] = 1


def ota_write(data, offset=None):
    sess = _require_session(active=True)
    payload = _to_bytes(data)
    payload_len = len(payload)
    if payload_len == 0:
        return _status_snapshot()

    written = int(sess["written"])
    if offset is None:
        offset = written
    else:
        offset = _parse_positive_int(offset, "offset", allow_none=False)
    if offset != written:
        raise OTAError("offset mismatch; only sequential writes are supported", 409)

    expected_size = sess.get("expected_size")
    if expected_size is not None and (written + payload_len) > int(expected_size):
        raise OTAError("chunk exceeds expected_size", 400)
    if (written + payload_len) > int(sess["capacity"]):
        raise OTAError("chunk exceeds update partition capacity", 400)

    _erase_blocks_for_write(sess, written, payload_len)

    part = sess["partition"]
    block_size = int(sess["block_size"])
    pos = 0
    while pos < payload_len:
        abs_off = written + pos
        block_index = int(abs_off // block_size)
        block_off = int(abs_off % block_size)
        step = block_size - block_off
        remain = payload_len - pos
        if step > remain:
            step = remain
        chunk = payload[pos:pos + step]
        try:
            part.writeblocks(block_index, chunk, block_off)
        except Exception as exc:
            raise OTAError("write failed at offset " + str(abs_off) + ": " + repr(exc), 500)
        pos += step

    ctx = sess.get("sha_ctx")
    if ctx is not None:
        try:
            ctx.update(payload)
        except Exception:
            pass

    sess["written"] = written + payload_len
    return _status_snapshot()


def ota_finalize(set_boot=True, reboot=False, strict_size=True):
    global _OTA_SESSION
    global _OTA_LAST_RESULT
    global _OTA_LAST_ERROR

    sess = _require_session(active=True)
    written = int(sess.get("written", 0))
    expected_size = sess.get("expected_size")
    if strict_size and expected_size is not None and written != int(expected_size):
        raise OTAError("written size does not match expected_size", 409)
    if written <= 0:
        raise OTAError("no firmware bytes written", 409)

    digest_hex = _sha256_digest_hex(sess.get("sha_ctx"))
    expected_sha = sess.get("expected_sha256")
    if expected_sha is not None:
        if digest_hex is None:
            raise OTAError("sha256 verification unavailable", 500)
        if digest_hex.lower() != expected_sha.lower():
            raise OTAError("sha256 mismatch", 409)

    if set_boot:
        try:
            sess["partition"].set_boot()
        except Exception as exc:
            raise OTAError("failed to set boot partition: " + repr(exc), 500)

    _OTA_LAST_RESULT = {
        "ok": True,
        "session_id": sess.get("id"),
        "written_bytes": written,
        "expected_size": expected_size,
        "sha256": digest_hex,
        "set_boot": bool(set_boot),
        "reboot": bool(reboot),
        "partition": sess.get("partition_info"),
    }
    _OTA_LAST_ERROR = None
    _OTA_SESSION = None

    if reboot:
        if machine is None or not hasattr(machine, "reset"):
            raise OTAError("machine.reset unavailable", 500)
        machine.reset()
    return _OTA_LAST_RESULT


def ota_abort():
    global _OTA_SESSION
    global _OTA_LAST_ERROR
    if _OTA_SESSION is None or not _OTA_SESSION.get("active"):
        return {"ok": True, "aborted": False, "active": False}
    sid = _OTA_SESSION.get("id")
    _OTA_SESSION = None
    _OTA_LAST_ERROR = "aborted"
    return {"ok": True, "aborted": True, "session_id": sid, "active": False}


def ota_mark_app_valid():
    if not _is_ota_supported():
        raise OTAError("OTA unsupported on this platform", 501)
    try:
        esp32.Partition.mark_app_valid_cancel_rollback()
    except Exception as exc:
        raise OTAError("mark_app_valid failed: " + repr(exc), 500)
    return {"ok": True}


def ota_apply(data, expected_sha256=None, set_boot=True, reboot=False):
    payload = _to_bytes(data)
    ota_begin(expected_size=len(payload), expected_sha256=expected_sha256, force=True)
    try:
        ota_write(payload)
        return ota_finalize(set_boot=set_boot, reboot=reboot, strict_size=True)
    except Exception:
        ota_abort()
        raise


def _get_query_value(req, key):
    try:
        q = getattr(req, "query_params", None)
    except Exception:
        q = None
    if isinstance(q, dict):
        return q.get(key)
    if isinstance(q, (list, tuple)):
        for item in q:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                continue
            if _to_text(item[0]) == key:
                return item[1]
    try:
        raw = _to_text(getattr(req, "query", ""))
    except Exception:
        raw = ""
    if not raw:
        return None
    pairs = raw.split("&")
    for pair in pairs:
        if not pair:
            continue
        if "=" in pair:
            k, v = pair.split("=", 1)
        else:
            k, v = pair, ""
        if k == key:
            return v
    return None


def _get_header_value(headers, name):
    lname = _to_text(name).lower()
    if isinstance(headers, dict):
        for k, v in headers.items():
            if _to_text(k).lower() == lname:
                return v
        return None
    if isinstance(headers, (list, tuple)):
        for item in headers:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                continue
            if _to_text(item[0]).lower() == lname:
                return item[1]
    return None


def _request_payload(req):
    payload = {}
    try:
        obj = req.json()
        if isinstance(obj, dict):
            payload.update(obj)
    except Exception:
        pass
    if not payload:
        try:
            obj = req.form()
            if isinstance(obj, dict):
                payload.update(obj)
        except Exception:
            pass
    return payload


def _request_body_bytes(req):
    try:
        body = getattr(req, "body", b"")
    except Exception:
        body = b""
    if isinstance(body, memoryview):
        return bytes(body)
    if isinstance(body, (bytes, bytearray)):
        return bytes(body)
    if body is None:
        return b""
    if isinstance(body, str):
        return body.encode("utf-8")
    return _to_text(body).encode("utf-8")


def _parse_bool(value, default=False):
    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return value
    text = _to_text(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    return bool(default)


def _parse_chunk_payload(req):
    payload = _request_payload(req)
    body = _request_body_bytes(req)
    data = body
    if "data_base64" in payload:
        b64 = payload.get("data_base64")
        try:
            data = binascii.a2b_base64(_to_text(b64))
        except Exception as exc:
            raise OTAError("invalid data_base64: " + repr(exc), 400)
    elif "data_hex" in payload:
        text = _to_text(payload.get("data_hex")).strip()
        try:
            data = binascii.unhexlify(text)
        except Exception as exc:
            raise OTAError("invalid data_hex: " + repr(exc), 400)
    if not isinstance(data, (bytes, bytearray)):
        data = _to_bytes(data)
    return payload, bytes(data)


def _ota_error_response(viperhttp_mod, exc):
    status = getattr(exc, "status_code", 500)
    detail = getattr(exc, "detail", str(exc))
    return viperhttp_mod.JSONResponse(status_code=int(status), body={"detail": detail})


def _route_exists(app, method, path):
    try:
        return app.match(method, path) is not None
    except Exception:
        return False


def install_ota_routes(
    app,
    prefix="/ota",
    token=None,
    token_header="X-OTA-Token",
    token_query="token",
):
    try:
        import viperhttp
    except Exception as exc:
        raise OTAError("viperhttp module unavailable: " + repr(exc), 500)

    if app is None:
        raise OTAError("app is required", 400)

    route_prefix = _to_text(prefix).strip()
    if not route_prefix:
        route_prefix = "/ota"
    if not route_prefix.startswith("/"):
        route_prefix = "/" + route_prefix
    if len(route_prefix) > 1 and route_prefix.endswith("/"):
        route_prefix = route_prefix[:-1]

    token_text = None if token is None else _to_text(token)
    header_name = _to_text(token_header or "X-OTA-Token")
    query_name = _to_text(token_query or "token")
    installed = []
    skipped = []

    def _authorize():
        if token_text is None:
            return None
        req = viperhttp.current_request()
        provided = None
        if req is not None:
            try:
                headers = getattr(req, "headers", None)
            except Exception:
                headers = None
            provided = _get_header_value(headers, header_name)
            if provided is None:
                provided = _get_query_value(req, query_name)
        if _ct_eq_text(provided, token_text):
            return None
        return viperhttp.JSONResponse(status_code=401, body={"detail": "invalid ota token"})

    status_path = route_prefix + "/status"
    begin_path = route_prefix + "/begin"
    chunk_path = route_prefix + "/chunk"
    finalize_path = route_prefix + "/finalize"
    abort_path = route_prefix + "/abort"
    upload_path = route_prefix + "/upload"
    mark_valid_path = route_prefix + "/mark-valid"

    if not _route_exists(app, "GET", status_path):
        @app.get(status_path, tags=["ota"], summary="OTA status")
        def _ota_status_route(**_ignored):
            deny = _authorize()
            if deny is not None:
                return deny
            try:
                return ota_status()
            except Exception as exc:
                return _ota_error_response(viperhttp, exc)
        installed.append("GET " + status_path)
    else:
        skipped.append("GET " + status_path)

    if not _route_exists(app, "POST", begin_path):
        @app.post(begin_path, tags=["ota"], summary="Start OTA session")
        def _ota_begin_route(**_ignored):
            deny = _authorize()
            if deny is not None:
                return deny
            req = viperhttp.current_request()
            payload = _request_payload(req) if req is not None else {}
            if req is not None:
                if "expected_size" not in payload:
                    payload["expected_size"] = _get_query_value(req, "expected_size")
                if "expected_sha256" not in payload:
                    payload["expected_sha256"] = _get_query_value(req, "expected_sha256")
                if "force" not in payload:
                    payload["force"] = _get_query_value(req, "force")
            try:
                return ota_begin(
                    expected_size=payload.get("expected_size"),
                    expected_sha256=payload.get("expected_sha256"),
                    force=_parse_bool(payload.get("force"), False),
                )
            except Exception as exc:
                return _ota_error_response(viperhttp, exc)
        installed.append("POST " + begin_path)
    else:
        skipped.append("POST " + begin_path)

    if not _route_exists(app, "POST", chunk_path):
        @app.post(chunk_path, tags=["ota"], summary="Write OTA chunk")
        def _ota_chunk_route(**_ignored):
            deny = _authorize()
            if deny is not None:
                return deny
            req = viperhttp.current_request()
            try:
                payload, data = _parse_chunk_payload(req)
                if req is not None and "offset" not in payload:
                    payload["offset"] = _get_query_value(req, "offset")
                if len(data) == 0:
                    raise OTAError("empty chunk", 400)
                return ota_write(data, offset=payload.get("offset"))
            except Exception as exc:
                return _ota_error_response(viperhttp, exc)
        installed.append("POST " + chunk_path)
    else:
        skipped.append("POST " + chunk_path)

    if not _route_exists(app, "POST", finalize_path):
        @app.post(finalize_path, tags=["ota"], summary="Finalize OTA")
        def _ota_finalize_route(**_ignored):
            deny = _authorize()
            if deny is not None:
                return deny
            req = viperhttp.current_request()
            payload = _request_payload(req) if req is not None else {}
            if req is not None:
                if "set_boot" not in payload:
                    payload["set_boot"] = _get_query_value(req, "set_boot")
                if "reboot" not in payload:
                    payload["reboot"] = _get_query_value(req, "reboot")
                if "strict_size" not in payload:
                    payload["strict_size"] = _get_query_value(req, "strict_size")
            try:
                return ota_finalize(
                    set_boot=_parse_bool(payload.get("set_boot"), True),
                    reboot=_parse_bool(payload.get("reboot"), False),
                    strict_size=_parse_bool(payload.get("strict_size"), True),
                )
            except Exception as exc:
                return _ota_error_response(viperhttp, exc)
        installed.append("POST " + finalize_path)
    else:
        skipped.append("POST " + finalize_path)

    if not _route_exists(app, "POST", abort_path):
        @app.post(abort_path, tags=["ota"], summary="Abort OTA session")
        def _ota_abort_route(**_ignored):
            deny = _authorize()
            if deny is not None:
                return deny
            try:
                return ota_abort()
            except Exception as exc:
                return _ota_error_response(viperhttp, exc)
        installed.append("POST " + abort_path)
    else:
        skipped.append("POST " + abort_path)

    if not _route_exists(app, "POST", upload_path):
        @app.post(upload_path, tags=["ota"], summary="Upload firmware in one request")
        def _ota_upload_route(**_ignored):
            deny = _authorize()
            if deny is not None:
                return deny
            req = viperhttp.current_request()
            try:
                payload, data = _parse_chunk_payload(req)
                if req is not None:
                    if "expected_sha256" not in payload:
                        payload["expected_sha256"] = _get_query_value(req, "expected_sha256")
                    if "set_boot" not in payload:
                        payload["set_boot"] = _get_query_value(req, "set_boot")
                    if "reboot" not in payload:
                        payload["reboot"] = _get_query_value(req, "reboot")
                if len(data) == 0:
                    raise OTAError("empty upload body", 400)
                return ota_apply(
                    data,
                    expected_sha256=payload.get("expected_sha256"),
                    set_boot=_parse_bool(payload.get("set_boot"), True),
                    reboot=_parse_bool(payload.get("reboot"), False),
                )
            except Exception as exc:
                return _ota_error_response(viperhttp, exc)
        installed.append("POST " + upload_path)
    else:
        skipped.append("POST " + upload_path)

    if not _route_exists(app, "POST", mark_valid_path):
        @app.post(mark_valid_path, tags=["ota"], summary="Mark current app valid")
        def _ota_mark_valid_route(**_ignored):
            deny = _authorize()
            if deny is not None:
                return deny
            try:
                return ota_mark_app_valid()
            except Exception as exc:
                return _ota_error_response(viperhttp, exc)
        installed.append("POST " + mark_valid_path)
    else:
        skipped.append("POST " + mark_valid_path)

    return {
        "ok": True,
        "prefix": route_prefix,
        "token_required": token_text is not None,
        "token_header": header_name,
        "token_query": query_name,
        "installed": installed,
        "skipped": skipped,
    }

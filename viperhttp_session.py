try:
    import uos as os
except Exception:
    import os

try:
    import ujson as json
except Exception:
    import json

try:
    import ubinascii as binascii
except Exception:
    import binascii

try:
    import uhashlib as hashlib
except Exception:
    import hashlib

import time
import viperhttp


def _ticks_ms():
    if hasattr(time, "ticks_ms"):
        return time.ticks_ms()
    return int(time.time() * 1000)


def _ticks_add(a, b):
    if hasattr(time, "ticks_add"):
        return time.ticks_add(a, b)
    return a + b


def _ticks_diff(a, b):
    if hasattr(time, "ticks_diff"):
        return time.ticks_diff(a, b)
    return a - b


def _is_expired(now_ms, exp_ms):
    return _ticks_diff(now_ms, exp_ms) >= 0


def _ct_eq(a, b):
    if a is None or b is None:
        return False
    if len(a) != len(b):
        return False
    result = 0
    for i in range(len(a)):
        result |= a[i] ^ b[i]
    return result == 0


def _ct_eq_text(a, b):
    if a is None or b is None:
        return False
    if isinstance(a, str):
        a = a.encode("utf-8")
    elif isinstance(a, (bytes, bytearray)):
        a = bytes(a)
    else:
        a = str(a).encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    elif isinstance(b, (bytes, bytearray)):
        b = bytes(b)
    else:
        b = str(b).encode("utf-8")
    return _ct_eq(a, b)


def _new_token_hex():
    try:
        raw = os.urandom(16)
    except Exception:
        raw = b""
        for _ in range(16):
            raw += bytes([int(_ticks_ms()) & 0xFF])
    return binascii.hexlify(raw).decode("utf-8")


def _hmac_sha256(key, msg):
    if isinstance(key, str):
        key = key.encode("utf-8")
    if isinstance(msg, str):
        msg = msg.encode("utf-8")
    if len(key) > 64:
        key = hashlib.sha256(key).digest()
    if len(key) < 64:
        key = key + b"\x00" * (64 - len(key))
    o_key = bytes([b ^ 0x5C for b in key])
    i_key = bytes([b ^ 0x36 for b in key])
    inner = hashlib.sha256(i_key + msg).digest()
    return hashlib.sha256(o_key + inner).digest()


def _hmac_hex(key, msg):
    return binascii.hexlify(_hmac_sha256(key, msg)).decode("utf-8")


def _estimate_size(data):
    try:
        return len(json.dumps(data))
    except Exception:
        try:
            return len(str(data))
        except Exception:
            return 0


def _get_header(headers, name):
    if headers is None:
        return None
    lname = name.lower()
    if isinstance(headers, dict):
        for k, v in headers.items():
            if isinstance(k, str) and k.lower() == lname:
                return v
        return None
    if isinstance(headers, (list, tuple)):
        for item in headers:
            try:
                k, v = item
            except Exception:
                continue
            if isinstance(k, str) and k.lower() == lname:
                return v
        return None
    return None


def _parse_cookie_header(value):
    text = _ensure_text(value)
    out = {}
    if not text:
        return out
    parts = text.split(";")
    for part in parts:
        item = part.strip()
        if not item:
            continue
        if "=" in item:
            key, val = item.split("=", 1)
            key = key.strip()
            val = val.strip()
        else:
            key = item.strip()
            val = ""
        if key:
            out[key] = val
    return out


def _ensure_text(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        try:
            return value.decode("utf-8")
        except Exception:
            return ""
    return str(value)


class SessionStore:
    def get(self, sid):
        raise NotImplementedError

    def set(self, sid, data, ttl_ms):
        raise NotImplementedError

    def delete(self, sid):
        raise NotImplementedError

    def touch(self, sid, ttl_ms):
        return None

    def gc(self):
        return 0

    def compact(self, force=False):
        return 0


class MemorySessionStore(SessionStore):
    def __init__(self, ttl_ms=3600_000, max_sessions=256, max_bytes=4096):
        self.ttl_ms = ttl_ms
        self.max_sessions = max_sessions
        self.max_bytes = max_bytes
        self._data = {}

    def _evict_if_needed(self):
        self.gc()
        if self.max_sessions and len(self._data) > self.max_sessions:
            items = list(self._data.items())
            items.sort(key=lambda kv: kv[1][0])
            while len(items) > self.max_sessions:
                sid, _ = items.pop(0)
                self._data.pop(sid, None)

    def get(self, sid):
        entry = self._data.get(sid)
        if not entry:
            return None
        exp_ms, data = entry
        if _is_expired(_ticks_ms(), exp_ms):
            self._data.pop(sid, None)
            return None
        return data

    def set(self, sid, data, ttl_ms):
        if self.max_bytes and _estimate_size(data) > self.max_bytes:
            raise ValueError("session too large")
        ttl = ttl_ms if ttl_ms is not None else self.ttl_ms
        exp_ms = _ticks_add(_ticks_ms(), ttl)
        self._data[sid] = (exp_ms, data)
        self._evict_if_needed()

    def delete(self, sid):
        self._data.pop(sid, None)

    def touch(self, sid, ttl_ms):
        entry = self._data.get(sid)
        if not entry:
            return
        ttl = ttl_ms if ttl_ms is not None else self.ttl_ms
        exp_ms = _ticks_add(_ticks_ms(), ttl)
        self._data[sid] = (exp_ms, entry[1])

    def gc(self):
        now = _ticks_ms()
        expired = [sid for sid, (exp_ms, _) in self._data.items() if _is_expired(now, exp_ms)]
        for sid in expired:
            self._data.pop(sid, None)
        return len(expired)


class VFSSessionStore(SessionStore):
    def __init__(
        self,
        base_path="/sessions",
        ttl_ms=3600_000,
        max_sessions=256,
        max_bytes=4096,
        max_total_bytes=None,
        write_at_interval_ms=30000,
        gc_interval_ms=60000,
        compact_interval_ms=60000,
        compact_on_load=True,
    ):
        self.base_path = base_path.rstrip("/") or "/sessions"
        self.ttl_ms = ttl_ms
        self.max_sessions = max_sessions
        self.max_bytes = max_bytes
        self.max_total_bytes = max_total_bytes
        self.write_at_interval_ms = write_at_interval_ms
        self.gc_interval_ms = gc_interval_ms
        self.compact_interval_ms = compact_interval_ms
        self._index = {}
        self._total_bytes = 0
        self._last_write = {}
        self._last_gc_ms = 0
        self._last_compact_ms = 0
        self._index_loaded = False
        self._compact_on_load = compact_on_load
        self._fs_lock = getattr(viperhttp, "fs_lock", None)
        self._fs_unlock = getattr(viperhttp, "fs_unlock", None)
        self._ensure_dir()

    def _lock(self):
        if self._fs_lock:
            try:
                self._fs_lock()
            except Exception:
                pass

    def _unlock(self):
        if self._fs_unlock:
            try:
                self._fs_unlock()
            except Exception:
                pass

    def _ensure_dir(self):
        try:
            st = os.stat(self.base_path)
            if st[0] & 0x4000:
                return
        except Exception:
            pass
        try:
            os.mkdir(self.base_path)
        except Exception:
            pass

    def _path(self, sid):
        return "%s/%s.json" % (self.base_path, sid)

    def _load_index(self):
        if self._index_loaded:
            return
        self._index_loaded = True
        self._total_bytes = 0
        try:
            files = os.listdir(self.base_path)
        except Exception:
            files = []
        self._lock()
        try:
            for name in files:
                if not name.endswith(".json"):
                    continue
                sid = name[:-5]
                path = self._path(sid)
                try:
                    with open(path, "r") as fp:
                        raw = fp.read()
                    payload = json.loads(raw)
                    exp_ms = payload.get("exp", 0)
                    at_ms = payload.get("at", exp_ms)
                    size = len(raw) if raw is not None else 0
                    self._index[sid] = (exp_ms, at_ms, size)
                    self._total_bytes += size
                except Exception:
                    try:
                        os.remove(path)
                    except Exception:
                        pass
        finally:
            self._unlock()
        if self._compact_on_load:
            self._compact_on_load = False
            self.compact(force=True)

    def _write_session(self, sid, exp_ms, at_ms, data):
        path = self._path(sid)
        tmp = path + ".tmp"
        payload = json.dumps({"exp": exp_ms, "at": at_ms, "data": data})
        with open(tmp, "w") as fp:
            fp.write(payload)
        try:
            os.remove(path)
        except Exception:
            pass
        os.rename(tmp, path)
        self._last_write[sid] = _ticks_ms()
        return len(payload)

    def _evict_if_needed(self):
        self._gc_expired(force=True)
        self._evict_lru()

    def _evict_lru(self):
        needs_sessions = self.max_sessions and len(self._index) > self.max_sessions
        needs_bytes = self.max_total_bytes and self._total_bytes > self.max_total_bytes
        if not needs_sessions and not needs_bytes:
            return 0
        items = list(self._index.items())
        items.sort(key=lambda kv: kv[1][1] if len(kv[1]) > 1 else kv[1][0])
        removed = 0
        while items:
            if self.max_sessions and len(self._index) <= self.max_sessions:
                if not self.max_total_bytes or self._total_bytes <= self.max_total_bytes:
                    break
            if self.max_total_bytes and self._total_bytes <= self.max_total_bytes:
                if not self.max_sessions or len(self._index) <= self.max_sessions:
                    break
            sid, _ = items.pop(0)
            self.delete(sid)
            removed += 1
        return removed

    def _gc_expired(self, force=False):
        self._load_index()
        now = _ticks_ms()
        if not force and self.gc_interval_ms is not None:
            if self.gc_interval_ms <= 0:
                return 0
            if _ticks_diff(now, self._last_gc_ms) < self.gc_interval_ms:
                return 0
        self._last_gc_ms = now
        expired = [sid for sid, meta in self._index.items() if _is_expired(now, meta[0])]
        for sid in expired:
            self.delete(sid)
        return len(expired)

    def get(self, sid):
        self._load_index()
        path = self._path(sid)
        self._lock()
        try:
            with open(path, "r") as fp:
                raw = fp.read()
            payload = json.loads(raw)
            exp_ms = payload.get("exp", 0)
            if _is_expired(_ticks_ms(), exp_ms):
                entry = self._index.pop(sid, None)
                if entry and len(entry) > 2:
                    self._total_bytes -= entry[2]
                self._last_write.pop(sid, None)
                try:
                    os.remove(path)
                except Exception:
                    pass
                return None
            at_ms = _ticks_ms()
            size = len(raw) if raw is not None else 0
            last_write = self._last_write.get(sid, 0)
            if self.write_at_interval_ms and _ticks_diff(at_ms, last_write) >= self.write_at_interval_ms:
                try:
                    size = self._write_session(sid, exp_ms, at_ms, payload.get("data", None))
                except Exception:
                    pass
            prev = self._index.get(sid)
            if prev:
                self._total_bytes -= prev[2] if len(prev) > 2 else 0
            self._index[sid] = (exp_ms, at_ms, size)
            self._total_bytes += size
            return payload.get("data", None)
        except Exception:
            return None
        finally:
            self._unlock()

    def set(self, sid, data, ttl_ms):
        self._load_index()
        if self.max_bytes and _estimate_size(data) > self.max_bytes:
            raise ValueError("session too large")
        ttl = ttl_ms if ttl_ms is not None else self.ttl_ms
        now_ms = _ticks_ms()
        exp_ms = _ticks_add(now_ms, ttl)
        self._lock()
        try:
            size = self._write_session(sid, exp_ms, now_ms, data)
        finally:
            self._unlock()
        prev = self._index.get(sid)
        if prev:
            self._total_bytes -= prev[2] if len(prev) > 2 else 0
        self._index[sid] = (exp_ms, now_ms, size)
        self._total_bytes += size
        self._evict_if_needed()
        self.compact()

    def delete(self, sid):
        entry = self._index.pop(sid, None)
        if entry and len(entry) > 2:
            self._total_bytes -= entry[2]
        self._last_write.pop(sid, None)
        path = self._path(sid)
        self._lock()
        try:
            os.remove(path)
        except Exception:
            pass
        finally:
            self._unlock()

    def touch(self, sid, ttl_ms):
        self._load_index()
        path = self._path(sid)
        self._lock()
        try:
            try:
                with open(path, "r") as fp:
                    raw = fp.read()
                payload = json.loads(raw)
                size = len(raw) if raw is not None else 0
            except Exception:
                return
            ttl = ttl_ms if ttl_ms is not None else self.ttl_ms
            now_ms = _ticks_ms()
            exp_ms = _ticks_add(now_ms, ttl)
            payload["exp"] = exp_ms
            last_write = self._last_write.get(sid, 0)
            if self.write_at_interval_ms and _ticks_diff(now_ms, last_write) < self.write_at_interval_ms:
                prev = self._index.get(sid)
                if prev:
                    self._total_bytes -= prev[2] if len(prev) > 2 else 0
                self._index[sid] = (exp_ms, now_ms, size)
                self._total_bytes += size
                return
            try:
                size = self._write_session(sid, exp_ms, now_ms, payload.get("data", None))
            except Exception:
                pass
            prev = self._index.get(sid)
            if prev:
                self._total_bytes -= prev[2] if len(prev) > 2 else 0
            self._index[sid] = (exp_ms, now_ms, size)
            self._total_bytes += size
        finally:
            self._unlock()
        self.compact()

    def gc(self):
        return self._gc_expired(force=False)

    def compact(self, force=False):
        self._load_index()
        now = _ticks_ms()
        if not force and self.compact_interval_ms is not None:
            if self.compact_interval_ms <= 0:
                return 0
            if _ticks_diff(now, self._last_compact_ms) < self.compact_interval_ms:
                return 0
        self._last_compact_ms = now
        removed = self._gc_expired(force=True)
        removed += self._evict_lru()
        return removed


class Session:
    def __init__(self, sid, data, ttl_ms, sid_generator=None):
        self._sid = sid
        self._data = data if isinstance(data, dict) else {}
        self._dirty = False
        self._new = False
        self._rotated = False
        self._invalidated = False
        self._ttl_ms = ttl_ms
        self._sid_generator = sid_generator
        self._prev_sid = None

    @property
    def sid(self):
        return self._sid

    def mark_dirty(self):
        self._dirty = True

    def invalidate(self):
        self._invalidated = True
        self._dirty = True

    def rotate(self):
        if self._sid_generator:
            self._prev_sid = self._sid
            self._sid = self._sid_generator()
            self._rotated = True
            self._dirty = True

    def get(self, key, default=None):
        return self._data.get(key, default)

    def set(self, key, value):
        self._data[key] = value
        self._dirty = True

    def pop(self, key, default=None):
        if key in self._data:
            self._dirty = True
        return self._data.pop(key, default)

    def clear(self):
        if self._data:
            self._dirty = True
        self._data.clear()

    def to_dict(self):
        return self._data

    def items(self):
        return self._data.items()

    def keys(self):
        return self._data.keys()

    def values(self):
        return self._data.values()

    def __getitem__(self, key):
        return self._data[key]

    def __setitem__(self, key, value):
        self._data[key] = value
        self._dirty = True

    def __contains__(self, key):
        return key in self._data

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)


def _get_cookie(cookies, name):
    if cookies is None:
        return None
    try:
        return cookies.get(name)
    except Exception:
        return None


def _make_cookie_value(sid, sig):
    if sig:
        return "%s.%s" % (sid, sig)
    return sid


def _parse_cookie_value(value):
    if not value:
        return None, None
    if "." in value:
        sid, sig = value.split(".", 1)
        return sid, sig
    return value, None


def _build_set_cookie(name, value, max_age=None, path="/", http_only=True, same_site="Lax", secure=False, domain=None):
    parts = ["%s=%s" % (name, value)]
    if max_age is not None:
        parts.append("Max-Age=%d" % int(max_age))
    if path:
        parts.append("Path=%s" % path)
    if domain:
        parts.append("Domain=%s" % domain)
    if http_only:
        parts.append("HttpOnly")
    if secure:
        parts.append("Secure")
    if same_site:
        parts.append("SameSite=%s" % same_site)
    return "; ".join(parts)


def _delete_cookie(name, path="/"):
    return _build_set_cookie(name, "", max_age=0, path=path)


def _append_header(resp, key, value):
    headers = resp.get("headers", None)
    if headers is None:
        resp["headers"] = [(key, value)]
        return
    if isinstance(headers, dict):
        # For Set-Cookie we must support multiple values.
        if key.lower() == "set-cookie" and key in headers:
            items = [(k, v) for k, v in headers.items()]
            items.append((key, value))
            resp["headers"] = items
        else:
            headers[key] = value
        return
    if isinstance(headers, list):
        headers.append((key, value))
        return
    resp["headers"] = [(key, value)]


def _set_request_session(request, session):
    try:
        request.session = session
        return
    except Exception:
        pass
    try:
        state = request.state
    except Exception:
        state = None
    if not isinstance(state, dict):
        state = {}
        try:
            request.state = state
        except Exception:
            return
    state["_vhttp_session"] = session


def get_request_session(request):
    if request is None:
        return None
    state_session = None
    try:
        state = request.state
    except Exception:
        state = None
    if isinstance(state, dict):
        state_session = state.get("_vhttp_session")
    try:
        session = request.session
        if session is not None:
            # Some runtimes expose request.session as a plain dict while middleware
            # stores the rich Session object in request.state.
            if state_session is not None and not hasattr(session, "rotate") and hasattr(state_session, "rotate"):
                return state_session
            return session
    except Exception:
        pass
    if state_session is not None:
        return state_session
    return None


def get_request_cookies(request):
    if request is None:
        return {}
    try:
        cookies = request.cookies
        if isinstance(cookies, dict) and cookies:
            return cookies
    except Exception:
        pass
    headers = getattr(request, "headers", None)
    return _parse_cookie_header(_get_header(headers, "cookie"))


class SessionMiddleware:
    def __init__(
        self,
        app=None,
        secret_key=None,
        store=None,
        cookie_name="vhttp_session",
        ttl_ms=3600_000,
        same_site="Lax",
        http_only=True,
        secure=False,
        path="/",
        domain=None,
        sign=True,
        touch_on_read=True,
        csrf_protect=True,
        csrf_header="X-CSRF-Token",
        csrf_methods=None,
        csrf_require_user=True,
        csrf_exempt_paths=None,
        csrf_token_key="_csrf",
        csrf_check_origin=True,
        csrf_allow_missing_origin=True,
        csrf_trusted_origins=None,
    ):
        if sign and not secret_key:
            raise ValueError("secret_key required when sign=True")
        self.secret_key = secret_key
        self.store = store if store is not None else VFSSessionStore(ttl_ms=ttl_ms)
        self.cookie_name = cookie_name
        self.ttl_ms = ttl_ms
        self.same_site = same_site
        self.http_only = http_only
        self.secure = secure
        self.path = path
        self.domain = domain
        self.sign = sign
        self.touch_on_read = touch_on_read
        self.csrf_protect = csrf_protect
        self.csrf_header = csrf_header
        self.csrf_methods = csrf_methods or ("POST", "PUT", "PATCH", "DELETE")
        self.csrf_require_user = csrf_require_user
        self.csrf_exempt_paths = csrf_exempt_paths or []
        self.csrf_token_key = csrf_token_key
        self.csrf_check_origin = csrf_check_origin
        self.csrf_allow_missing_origin = csrf_allow_missing_origin
        self.csrf_trusted_origins = csrf_trusted_origins

    def _make_sid(self):
        return _new_token_hex()

    def _sign(self, sid):
        if not self.sign:
            return None
        return _hmac_hex(self.secret_key, sid)

    def _verify(self, sid, sig):
        if not self.sign:
            return True
        if not sig:
            return False
        expected = _hmac_hex(self.secret_key, sid)
        return _ct_eq(expected.encode("utf-8"), sig.encode("utf-8"))

    def _is_csrf_exempt(self, path):
        if not path:
            return False
        for entry in self.csrf_exempt_paths:
            if entry.endswith("*"):
                if path.startswith(entry[:-1]):
                    return True
            elif path == entry:
                return True
        return False

    def _origin_host(self, value):
        value = _ensure_text(value).strip().lower()
        if not value:
            return ""
        if "://" in value:
            value = value.split("://", 1)[1]
        if "/" in value:
            value = value.split("/", 1)[0]
        return value

    def _origin_allowed(self, request):
        headers = getattr(request, "headers", None)
        origin = _get_header(headers, "origin")
        referer = _get_header(headers, "referer")
        if not origin and not referer:
            return self.csrf_allow_missing_origin
        host = _get_header(headers, "host")
        host = self._origin_host(host)
        origin_host = self._origin_host(origin) if origin else ""
        referer_host = self._origin_host(referer) if referer else ""
        if self.csrf_trusted_origins:
            trusted = [self._origin_host(x) for x in self.csrf_trusted_origins]
            if origin_host and origin_host in trusted:
                return True
            if referer_host and referer_host in trusted:
                return True
        if host:
            if origin_host and origin_host == host:
                return True
            if referer_host and referer_host == host:
                return True
        return False

    async def dispatch(self, request, call_next):
        cookies = get_request_cookies(request)

        cookie_val = _get_cookie(cookies, self.cookie_name)
        sid, sig = _parse_cookie_value(cookie_val)
        if sid and not self._verify(sid, sig):
            sid = None

        data = None
        if sid:
            data = self.store.get(sid)
        if data is None:
            sid = None
            data = {}
            new_session = True
        else:
            new_session = False

        session = Session(sid, data, self.ttl_ms, sid_generator=self._make_sid)
        session._new = new_session
        _set_request_session(request, session)

        if self.csrf_protect:
            method = ""
            path = ""
            try:
                method = request.method
            except Exception:
                method = ""
            try:
                path = request.path
            except Exception:
                path = ""

            needs_check = method in self.csrf_methods and not self._is_csrf_exempt(path)
            should_enforce = needs_check and (not self.csrf_require_user or session.get("user"))
            token = session.get(self.csrf_token_key)
            if should_enforce:
                if not token:
                    token = self._make_sid()
                    session.set(self.csrf_token_key, token)
                try:
                    state = request.state
                    if isinstance(state, dict):
                        state["csrf_token"] = token
                except Exception:
                    pass
                if token:
                    if self.csrf_check_origin and not self._origin_allowed(request):
                        return viperhttp.Response(status_code=403, body="Invalid CSRF origin")
                    header_val = _get_header(getattr(request, "headers", None), self.csrf_header)
                    header_val = _ensure_text(header_val).strip()
                    if not header_val or not _ct_eq_text(header_val, token):
                        return viperhttp.Response(status_code=403, body="Invalid CSRF token")
            elif token:
                try:
                    state = request.state
                    if isinstance(state, dict):
                        state["csrf_token"] = token
                except Exception:
                    pass

        resp = await call_next(request)
        if resp is None:
            return resp

        if session._invalidated:
            if session._prev_sid:
                self.store.delete(session._prev_sid)
            if session.sid:
                self.store.delete(session.sid)
            _append_header(resp, "Set-Cookie", _delete_cookie(self.cookie_name, path=self.path))
            return resp

        if session._rotated and session._prev_sid:
            self.store.delete(session._prev_sid)

        should_persist = session._dirty or session._rotated
        if session._new and session.to_dict():
            should_persist = True
        if should_persist:
            if not session.sid:
                session._sid = self._make_sid()
            self.store.set(session.sid, session.to_dict(), self.ttl_ms)
            sig = self._sign(session.sid)
            value = _make_cookie_value(session.sid, sig)
            _append_header(
                resp,
                "Set-Cookie",
                _build_set_cookie(
                    self.cookie_name,
                    value,
                    max_age=int(self.ttl_ms / 1000),
                    path=self.path,
                    http_only=self.http_only,
                    same_site=self.same_site,
                    secure=self.secure,
                    domain=self.domain,
                ),
            )
        elif self.touch_on_read and sid and not session._new:
            self.store.touch(session.sid, self.ttl_ms)

        return resp


def get_csrf_token(request=None):
    if request is None:
        return None
    try:
        state = request.state
        if isinstance(state, dict) and state.get("csrf_token"):
            return state.get("csrf_token")
    except Exception:
        pass
    session = get_request_session(request)
    if session:
        try:
            token = session.get("_csrf")
            if token:
                return token
            token = _new_token_hex()
            session.set("_csrf", token)
            try:
                state = request.state
                if isinstance(state, dict):
                    state["csrf_token"] = token
            except Exception:
                pass
            return token
        except Exception:
            return None
    return None

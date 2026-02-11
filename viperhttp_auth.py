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

try:
    import viperhttp_session
except Exception:
    viperhttp_session = None


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


def _ct_eq(a, b):
    if a is None or b is None:
        return False
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    if len(a) != len(b):
        return False
    result = 0
    for i in range(len(a)):
        result |= a[i] ^ b[i]
    return result == 0


def _hash_hex(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return binascii.hexlify(hashlib.sha256(value).digest()).decode("utf-8")


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


def _add_header(resp, key, value):
    headers = resp.get("headers", None)
    if headers is None:
        resp["headers"] = [(key, value)]
        return
    if isinstance(headers, dict):
        items = [(k, v) for k, v in headers.items()]
        items.append((key, value))
        resp["headers"] = items
        return
    if isinstance(headers, list):
        headers.append((key, value))
        return
    resp["headers"] = [(key, value)]


def _get_session_from_request(request):
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
            if state_session is not None and not hasattr(session, "rotate") and hasattr(state_session, "rotate"):
                return state_session
            return session
    except Exception:
        pass
    if state_session is not None:
        return state_session
    if viperhttp_session is not None and hasattr(viperhttp_session, "get_request_session"):
        try:
            return viperhttp_session.get_request_session(request)
        except Exception:
            return None
    return None


class AuthBackend:
    name = "auth"
    challenge = None

    def authenticate(self, request):
        return None


class SessionAuth(AuthBackend):
    name = "session"

    def __init__(self, user_key="user"):
        self.user_key = user_key

    def authenticate(self, request):
        session = _get_session_from_request(request)
        if session is None:
            return None
        try:
            user = session.get(self.user_key)
        except Exception:
            user = None
        if user:
            return user
        return None


class BearerAuth(AuthBackend):
    name = "bearer"
    challenge = "Bearer"

    def __init__(self, tokens=None, validator=None, tokens_hashed=False):
        self.tokens = tokens or {}
        self.validator = validator
        self.tokens_hashed = tokens_hashed

    def authenticate(self, request):
        auth = _get_header(getattr(request, "headers", None), "authorization")
        auth = _ensure_text(auth)
        if not auth.lower().startswith("bearer "):
            return None
        token = auth[7:].strip()
        if self.validator:
            return self.validator(token)
        if self.tokens_hashed:
            token = _hash_hex(token)
        return self.tokens.get(token)


class APIKeyAuth(AuthBackend):
    name = "apikey"
    challenge = "ApiKey"

    def __init__(self, header_name="x-api-key", query_name="api_key", keys=None, validator=None, keys_hashed=False):
        self.header_name = header_name
        self.query_name = query_name
        self.keys = keys or {}
        self.validator = validator
        self.keys_hashed = keys_hashed

    def authenticate(self, request):
        value = _get_header(getattr(request, "headers", None), self.header_name)
        if value is None:
            try:
                qp = request.query_params
                if isinstance(qp, dict):
                    value = qp.get(self.query_name)
            except Exception:
                value = None
        value = _ensure_text(value).strip()
        if not value:
            return None
        if self.validator:
            return self.validator(value)
        if self.keys_hashed:
            value = _hash_hex(value)
        return self.keys.get(value)


class BasicAuth(AuthBackend):
    name = "basic"
    challenge = "Basic"

    def __init__(self, users=None, validator=None):
        self.users = users or {}
        self.validator = validator

    def authenticate(self, request):
        auth = _get_header(getattr(request, "headers", None), "authorization")
        auth = _ensure_text(auth)
        if not auth.lower().startswith("basic "):
            return None
        token = auth[6:].strip()
        try:
            raw = binascii.a2b_base64(token)
            pair = raw.decode("utf-8")
        except Exception:
            return None
        if ":" not in pair:
            return None
        user, pwd = pair.split(":", 1)
        if self.validator:
            return self.validator(user, pwd)
        expected = self.users.get(user)
        if expected is None:
            return None
        if isinstance(expected, dict):
            expected = expected.get("hash") or expected.get("password")
        if isinstance(expected, str) and expected.startswith("sha256:"):
            expected_hash = expected[7:]
            if not _ct_eq(_hash_hex(pwd), expected_hash):
                return None
        else:
            if not _ct_eq(expected, pwd):
                return None
        return {"username": user, "source": "basic"}


class AuthMiddleware:
    def __init__(self, app=None, backends=None, enforce=False, rate_limiter=None, strict_challenge=False):
        self.backends = list(backends or [])
        self.enforce = enforce
        self.rate_limiter = rate_limiter
        self.strict_challenge = strict_challenge

    async def dispatch(self, request, call_next):
        auth_header = _get_header(getattr(request, "headers", None), "authorization")
        api_key = _get_header(getattr(request, "headers", None), "x-api-key")
        auth_present = bool(auth_header) or bool(api_key)
        if self.rate_limiter and not self.rate_limiter.check(request):
            return viperhttp.Response(status_code=429, body="Too Many Requests")
        user = None
        scheme = None
        for backend in self.backends:
            try:
                user = backend.authenticate(request)
            except Exception:
                user = None
            if user:
                scheme = getattr(backend, "name", None)
                break
        try:
            request.user = user
        except Exception:
            pass
        try:
            state = request.state
            if isinstance(state, dict):
                state["auth_scheme"] = scheme
        except Exception:
            pass
        if self.rate_limiter:
            if user:
                self.rate_limiter.record_success(request)
            elif auth_present or self.enforce:
                self.rate_limiter.record_failure(request)
        if self.enforce and not user:
            resp = viperhttp.Response(status_code=401, body="Not authenticated")
            challenges = []
            for backend in self.backends:
                challenge = getattr(backend, "challenge", None)
                if challenge:
                    challenges.append(challenge)
            if challenges:
                if self.strict_challenge:
                    for challenge in challenges:
                        _add_header(resp, "WWW-Authenticate", challenge)
                else:
                    _add_header(resp, "WWW-Authenticate", challenges[0])
            return resp
        return await call_next(request)


class AuthRateLimiter:
    def __init__(self, max_fails=5, window_ms=60000, ban_ms=300000, key_fn=None):
        self.max_fails = max_fails
        self.window_ms = window_ms
        self.ban_ms = ban_ms
        self.key_fn = key_fn
        self._state = {}

    def _key(self, request):
        if self.key_fn:
            try:
                custom = self.key_fn(request)
                if custom:
                    return custom
            except Exception:
                pass
        headers = getattr(request, "headers", None)
        ip = _get_header(headers, "x-forwarded-for")
        if ip:
            ip = _ensure_text(ip).split(",", 1)[0].strip()
        if not ip:
            ip = _ensure_text(_get_header(headers, "x-real-ip")).strip()
        if not ip:
            ip = _ensure_text(_get_header(headers, "cf-connecting-ip")).strip()
        auth = _get_header(headers, "authorization")
        api_key = _get_header(headers, "x-api-key")
        auth = _ensure_text(auth).strip()
        api_key = _ensure_text(api_key).strip()
        key_parts = []
        if ip:
            key_parts.append("ip:" + ip)
        if auth:
            key_parts.append("auth:" + _hash_hex(auth))
        elif api_key:
            key_parts.append("key:" + _hash_hex(api_key))
        if key_parts:
            return "|".join(key_parts)
        ua = _ensure_text(_get_header(headers, "user-agent")).strip()
        if ua:
            return "ua:" + _hash_hex(ua)
        return "anon"

    def check(self, request):
        key = self._key(request)
        entry = self._state.get(key)
        if not entry:
            return True
        fails, first_ms, banned_until = entry
        if banned_until and _ticks_diff(_ticks_ms(), banned_until) < 0:
            return False
        return True

    def record_failure(self, request):
        key = self._key(request)
        now = _ticks_ms()
        entry = self._state.get(key)
        if not entry:
            self._state[key] = (1, now, 0)
            return
        fails, first_ms, banned_until = entry
        if _ticks_diff(now, first_ms) > self.window_ms:
            fails = 0
            first_ms = now
        fails += 1
        if fails >= self.max_fails:
            banned_until = _ticks_add(now, self.ban_ms)
        self._state[key] = (fails, first_ms, banned_until)

    def record_success(self, request):
        key = self._key(request)
        if key in self._state:
            self._state.pop(key, None)


def get_current_user(scheme=None):
    req = viperhttp.current_request()
    if req is None:
        raise viperhttp.HTTPException(500, "Missing request")
    user = getattr(req, "user", None)
    if not user:
        raise viperhttp.HTTPException(401, "Not authenticated")
    if scheme:
        state = getattr(req, "state", None)
        if not isinstance(state, dict) or state.get("auth_scheme") != scheme:
            raise viperhttp.HTTPException(401, "Not authenticated")
    return user


def require_roles(roles, scheme=None):
    roles = roles or []

    def _dep():
        user = get_current_user(scheme=scheme)
        user_roles = []
        if isinstance(user, dict):
            user_roles = user.get("roles") or []
        for role in roles:
            if role not in user_roles:
                raise viperhttp.HTTPException(403, "Forbidden")
        return user

    return _dep

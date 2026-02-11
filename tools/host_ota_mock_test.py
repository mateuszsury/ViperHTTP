import hashlib
import importlib
import os
import sys
import types

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def _require(cond, msg):
    if not cond:
        raise AssertionError(msg)


class _FakePartitionObj:
    def __init__(self, owner, subtype, address, size, label):
        self._owner = owner
        self._type = 0
        self._subtype = int(subtype)
        self._address = int(address)
        self._size = int(size)
        self._label = str(label)
        self._encrypted = False
        self._block_size = 4096
        self._block_count = self._size // self._block_size
        self._data = bytearray(b"\xff" * self._size)

    def info(self):
        return (
            self._type,
            self._subtype,
            self._address,
            self._size,
            self._label,
            self._encrypted,
        )

    def get_next_update(self):
        if self._label == "factory":
            return self._owner._ota0
        return self._owner._factory

    def ioctl(self, op, arg):
        if op == 4:
            return self._block_count
        if op == 5:
            return self._block_size
        if op == 6:
            idx = int(arg)
            if idx < 0 or idx >= self._block_count:
                raise OSError("invalid block")
            start = idx * self._block_size
            end = start + self._block_size
            self._data[start:end] = b"\xff" * self._block_size
            return 0
        raise OSError("unsupported ioctl")

    def readblocks(self, block_num, buf, offset=0):
        block = int(block_num)
        off = int(offset)
        start = (block * self._block_size) + off
        end = start + len(buf)
        if start < 0 or end > self._size:
            raise OSError("read out of range")
        mv = memoryview(buf)
        mv[:] = self._data[start:end]
        return 0

    def writeblocks(self, block_num, buf, offset=0):
        data = bytes(buf)
        block = int(block_num)
        off = int(offset)
        start = (block * self._block_size) + off
        end = start + len(data)
        if start < 0 or end > self._size:
            raise OSError("write out of range")
        for i in range(len(data)):
            cur = self._data[start + i]
            nxt = data[i]
            if (cur & nxt) != nxt:
                raise OSError("flash write requires erase")
            self._data[start + i] = cur & nxt
        return 0

    def set_boot(self):
        self._owner._boot = self


class _FakePartitionFactory:
    RUNNING = 100
    BOOT = 101
    TYPE_APP = 0
    TYPE_DATA = 1
    _mark_valid_calls = 0

    _factory = _FakePartitionObj(None, 0, 0x10000, 0x380000, "factory")
    _ota0 = _FakePartitionObj(None, 16, 0x390000, 0x380000, "ota_0")
    _boot = _factory
    _running = _factory
    _factory._owner = None
    _ota0._owner = None

    def __new__(cls, selector):
        if cls._factory._owner is None:
            cls._factory._owner = cls
            cls._ota0._owner = cls
        if selector == cls.RUNNING:
            return cls._running
        if selector == cls.BOOT:
            return cls._boot
        if isinstance(selector, _FakePartitionObj):
            return selector
        raise ValueError("invalid selector")

    @classmethod
    def find(cls, *_args, **_kwargs):
        return [cls._factory, cls._ota0]

    @classmethod
    def mark_app_valid_cancel_rollback(cls):
        cls._mark_valid_calls += 1
        return None


class _FakeRequest:
    def __init__(self, headers=None, query_params=None, body=b"", payload=None):
        self.headers = headers or {}
        self.query_params = query_params or {}
        self.query = "&".join(
            [str(k) + "=" + str(v) for k, v in self.query_params.items()]
        )
        self.body = body
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload

    def form(self):
        if self._payload is None:
            raise ValueError("no form")
        return self._payload


class _FakeApp:
    def __init__(self):
        self._routes = {}

    def match(self, method, path):
        return self._routes.get((method, path))

    def _reg(self, method, path):
        def deco(fn):
            self._routes[(method, path)] = fn
            return fn
        return deco

    def get(self, path, **_kwargs):
        return self._reg("GET", path)

    def post(self, path, **_kwargs):
        return self._reg("POST", path)


def _install_fakes():
    fake_esp32 = types.ModuleType("esp32")
    fake_esp32.Partition = _FakePartitionFactory
    sys.modules["esp32"] = fake_esp32

    fake_machine = types.ModuleType("machine")
    fake_machine.reset_calls = 0

    def _reset():
        fake_machine.reset_calls += 1

    fake_machine.reset = _reset
    sys.modules["machine"] = fake_machine

    req_holder = {"req": None}
    fake_viperhttp = types.ModuleType("viperhttp")

    def _current_request():
        return req_holder["req"]

    def _json_response(status_code=200, body=None):
        return {"status_code": int(status_code), "body": body}

    fake_viperhttp.current_request = _current_request
    fake_viperhttp.JSONResponse = _json_response
    sys.modules["viperhttp"] = fake_viperhttp
    return req_holder, fake_machine


def main():
    req_holder, fake_machine = _install_fakes()
    if "viperhttp_ota" in sys.modules:
        del sys.modules["viperhttp_ota"]
    ota = importlib.import_module("viperhttp_ota")

    st = ota.ota_status()
    _require(st.get("supported") is True, "ota support should be true")
    _require(st.get("active") is False, "ota should be inactive at start")

    app = _FakeApp()
    info = ota.install_ota_routes(app, prefix="/ota", token="secret-token")
    _require(info.get("ok") is True, "install_ota_routes must return ok")
    _require(len(info.get("installed", [])) >= 6, "routes should be installed")

    req_holder["req"] = _FakeRequest(query_params={})
    denied = app._routes[("GET", "/ota/status")]()
    _require(isinstance(denied, dict) and denied.get("status_code") == 401, "status should require token")

    req_holder["req"] = _FakeRequest(query_params={"token": "secret-token"}, payload={"expected_size": 8})
    begin_res = app._routes[("POST", "/ota/begin")]()
    _require(isinstance(begin_res, dict) and begin_res.get("active") is True, "begin should activate session")

    req_holder["req"] = _FakeRequest(query_params={"token": "secret-token"}, body=b"ABCD")
    chunk_res = app._routes[("POST", "/ota/chunk")]()
    _require(chunk_res.get("session", {}).get("written_bytes") == 4, "first chunk write mismatch")

    req_holder["req"] = _FakeRequest(query_params={"token": "secret-token"}, body=b"EFGH")
    chunk_res2 = app._routes[("POST", "/ota/chunk")]()
    _require(chunk_res2.get("session", {}).get("written_bytes") == 8, "second chunk write mismatch")

    req_holder["req"] = _FakeRequest(query_params={"token": "secret-token"}, payload={"set_boot": False})
    fin_res = app._routes[("POST", "/ota/finalize")]()
    _require(fin_res.get("ok") is True, "finalize should succeed")
    _require(fin_res.get("set_boot") is False, "set_boot should be false")

    digest = hashlib.sha256(b"UPLOAD-OK").hexdigest()
    req_holder["req"] = _FakeRequest(
        query_params={"token": "secret-token"},
        body=b"UPLOAD-OK",
        payload={"expected_sha256": digest, "set_boot": True, "reboot": False},
    )
    upload_res = app._routes[("POST", "/ota/upload")]()
    _require(upload_res.get("ok") is True, "upload route should succeed")
    _require(upload_res.get("set_boot") is True, "upload should set boot")
    _require(_FakePartitionFactory._boot._label == "ota_0", "boot partition should switch to ota_0")

    req_holder["req"] = _FakeRequest(query_params={"token": "secret-token"})
    mark_res = app._routes[("POST", "/ota/mark-valid")]()
    _require(mark_res.get("ok") is True, "mark-valid should succeed")
    _require(_FakePartitionFactory._mark_valid_calls >= 1, "mark-valid call counter mismatch")

    req_holder["req"] = _FakeRequest(query_params={"token": "secret-token"}, payload={"expected_size": 4})
    _ = app._routes[("POST", "/ota/begin")]()
    req_holder["req"] = _FakeRequest(query_params={"token": "secret-token"}, body=b"ab")
    _ = app._routes[("POST", "/ota/chunk")]()
    req_holder["req"] = _FakeRequest(query_params={"token": "secret-token"}, payload={"set_boot": False, "strict_size": True})
    bad_final = app._routes[("POST", "/ota/finalize")]()
    _require(bad_final.get("status_code") == 409, "strict finalize should fail on short image")
    req_holder["req"] = _FakeRequest(query_params={"token": "secret-token"})
    abort_res = app._routes[("POST", "/ota/abort")]()
    _require(abort_res.get("ok") is True, "abort should return ok")
    _require(fake_machine.reset_calls == 0, "reset should not be called")

    print("PASS: host OTA mock test")


if __name__ == "__main__":
    main()

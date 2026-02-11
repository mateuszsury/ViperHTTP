import uasyncio as asyncio
import ujson
import time
import viperhttp
try:
    import viperhttp_ota as vhttp_ota
except Exception:
    vhttp_ota = None
try:
    import viperhttp_lifespan as vhttp_lifespan
except Exception:
    vhttp_lifespan = None

_bridge_task = None
_bridge_debug = True
_ws_connections = {}
_middleware_cache = {}
_http_req_queue = None
_http_worker_tasks = []
_http_scaler_task = None
_DEFAULT_STREAM_CHUNK = 16384
_MAX_DEPENDENCIES = 16
_MAX_DEP_CHAIN_DEPTH = 8
_DEP_SPEC_FLAG = "__vhttp_dep__"
_HTTP_WORKER_MIN = 4
_HTTP_WORKER_MAX = 4
_HTTP_QUEUE_SIZE = 16
_HTTP_QUEUE_RETRY_LIMIT = 3
_HTTP_AUTOSCALE = False
_HTTP_SCALE_CHECK_MS = 100
_HTTP_SCALE_UP_STEP = 1
_HTTP_SCALE_UP_MAX_BURST = 4
_HTTP_SCALE_DOWN_IDLE_TICKS = 20
_HTTP_ENQUEUE_WAIT_MS = 8
_HTTP_ENQUEUE_RETRY_SLEEP_MS = 1
_HTTP_WORKER_YIELD_EVERY = 4
_BRIDGE_POLL_BURST = 4
_BRIDGE_IDLE_SLEEP_MS = 1
_BRIDGE_ACTIVE_SLEEP_MS = 0
_BRIDGE_ERROR_SLEEP_MS = 10
_UNSET = object()


def _runtime_supports_async_generators():
    # MicroPython support is build/runtime dependent. Probe once at startup.
    async def _probe():
        if False:
            yield None

    obj = None
    try:
        obj = _probe()
        return hasattr(obj, "__anext__") and hasattr(obj, "aclose")
    except Exception:
        return False
    finally:
        try:
            if obj is not None and hasattr(obj, "close"):
                obj.close()
        except Exception:
            pass


_ASYNC_GEN_SUPPORTED = _runtime_supports_async_generators()

def _is_generator(obj):
    try:
        import types
        gen_type = getattr(types, "GeneratorType", None)
        if gen_type is not None:
            return isinstance(obj, gen_type)
    except Exception:
        pass
    try:
        return type(obj).__name__ == "generator"
    except Exception:
        return False


def _is_async_iter(obj):
    try:
        if hasattr(obj, "__aiter__") or hasattr(obj, "__anext__"):
            return True
    except Exception:
        pass
    return False


def _iscoro(obj):
    return _is_awaitable(obj)


def _is_awaitable(obj):
    # MicroPython often represents async coroutines as generator objects.
    if _is_generator(obj):
        return True
    try:
        if hasattr(obj, "__await__"):
            return True
    except Exception:
        pass
    return False


def _is_async_generator(obj):
    try:
        if not hasattr(obj, "__anext__"):
            return False
        # async generators expose aclose/asend; generic async iterables usually do not.
        return hasattr(obj, "aclose") or hasattr(obj, "asend")
    except Exception:
        return False


def _is_dep_spec(spec):
    if not isinstance(spec, dict):
        return False
    return bool(spec.get(_DEP_SPEC_FLAG))


def _push_request_context(request):
    setter = getattr(viperhttp, "set_current_request", None)
    if setter is None:
        return None
    try:
        prev = setter(request)
    except Exception:
        return None
    return (setter, prev)


def _pop_request_context(ctx):
    if ctx is None:
        return
    setter, prev = ctx
    try:
        setter(prev)
    except Exception:
        pass


def _is_unexpected_background_kw(exc):
    if not isinstance(exc, TypeError):
        return False
    msg = str(exc)
    return ("unexpected keyword argument" in msg) and ("background_tasks" in msg)


def _make_sync_dep_finalizer(gen):
    async def _finalize():
        try:
            next(gen)
            raise RuntimeError("dependency generator must yield exactly once")
        except StopIteration:
            return
        finally:
            try:
                gen.close()
            except Exception:
                pass
    return _finalize


def _make_async_dep_finalizer(agen):
    async def _finalize():
        try:
            await agen.__anext__()
            raise RuntimeError("dependency async generator must yield exactly once")
        except StopAsyncIteration:
            return
        finally:
            try:
                close_fn = getattr(agen, "aclose", None)
                if close_fn is not None:
                    out = close_fn()
                    if _is_awaitable(out):
                        await out
            except Exception:
                pass
    return _finalize


async def _resolve_dep_value(dep_spec, depth, finalizers):
    if depth > _MAX_DEP_CHAIN_DEPTH:
        raise ValueError("dependency chain too deep")
    if not _is_dep_spec(dep_spec):
        raise TypeError("dependency must be Depends()")

    callable_obj = dep_spec.get("callable")
    if not callable(callable_obj):
        raise TypeError("dependency callable required")
    mode = dep_spec.get("mode", "value")
    if mode == "auto":
        mode = "value"
    if mode not in ("value", "yield", "async_yield"):
        raise ValueError("dependency mode invalid")
    if mode == "async_yield" and not _ASYNC_GEN_SUPPORTED:
        raise NotImplementedError("async generator dependencies unsupported on this MicroPython build")

    deps_map = dep_spec.get("deps")
    kwargs = {}
    if deps_map is not None:
        if not isinstance(deps_map, dict):
            raise TypeError("dependency deps must be dict")
        if len(deps_map) > _MAX_DEPENDENCIES:
            raise ValueError("dependency list too large")
        for key, spec in deps_map.items():
            if not isinstance(key, str):
                raise TypeError("dependency keys must be str")
            kwargs[key] = await _resolve_dep_value(spec, depth + 1, finalizers)

    value = callable_obj(**kwargs)
    if _is_async_generator(value):
        if mode not in ("value", "async_yield"):
            raise TypeError("dependency mode=yield does not accept async generator")
        try:
            entered = await value.__anext__()
        except StopAsyncIteration:
            raise RuntimeError("dependency async generator did not yield")
        finalizers.append(_make_async_dep_finalizer(value))
        return entered

    if mode == "async_yield":
        raise TypeError("dependency mode=async_yield requires async generator")

    if mode == "yield":
        if not _is_generator(value):
            raise TypeError("dependency mode=yield requires generator")
        try:
            entered = next(value)
        except StopIteration:
            raise RuntimeError("dependency generator did not yield")
        finalizers.append(_make_sync_dep_finalizer(value))
        return entered

    if _is_awaitable(value):
        value = await value

    return value


async def _apply_dep_specs(params, deps_spec, finalizers):
    if deps_spec is None:
        return
    if not isinstance(deps_spec, dict):
        raise TypeError("deps spec must be dict")
    if len(deps_spec) > _MAX_DEPENDENCIES:
        raise ValueError("deps spec too large")
    for key, spec in deps_spec.items():
        if not isinstance(key, str):
            raise TypeError("deps spec keys must be str")
        if key in params:
            raise ValueError("dependency name conflicts with params")
        params[key] = await _resolve_dep_value(spec, 1, finalizers)


async def _run_dep_finalizers(finalizers):
    first_exc = None
    while finalizers:
        fin = finalizers.pop()
        try:
            out = fin()
            if _is_awaitable(out):
                await out
        except Exception as exc:
            if first_exc is None:
                first_exc = exc
    if first_exc is not None:
        raise first_exc


async def _invoke_handler_with_dependencies(handler, params, deps_spec, request, background_tasks=None):
    ctx = _push_request_context(request)
    finalizers = []
    primary_exc = None
    result = None
    try:
        await _apply_dep_specs(params, deps_spec, finalizers)
        added_background = False
        if background_tasks is not None and "background_tasks" not in params:
            params["background_tasks"] = background_tasks
            added_background = True

        for _ in range(2):
            try:
                result = handler(**params)
                if _is_awaitable(result):
                    result = await result
                return _normalize_response(result)
            except TypeError as exc:
                if added_background and _is_unexpected_background_kw(exc):
                    params.pop("background_tasks", None)
                    added_background = False
                    continue
                raise
    except Exception as exc:
        primary_exc = exc
    finally:
        cleanup_exc = None
        try:
            await _run_dep_finalizers(finalizers)
        except Exception as exc:
            cleanup_exc = exc
        _pop_request_context(ctx)
        if primary_exc is not None:
            raise primary_exc
        if cleanup_exc is not None:
            raise cleanup_exc


def _configure_dep_resolver():
    setter = getattr(viperhttp, "set_dep_resolver", None)
    if setter is None:
        return
    try:
        setter(_invoke_handler_with_dependencies)
    except Exception:
        pass


def runtime_features():
    return {
        "async_generator_supported": bool(_ASYNC_GEN_SUPPORTED),
    }


def _coerce_stream_chunk(item):
    if item is None:
        return b""
    if isinstance(item, bytes):
        return item
    if isinstance(item, bytearray):
        return bytes(item)
    if isinstance(item, memoryview):
        try:
            return item.tobytes()
        except Exception:
            return bytes(item)
    if isinstance(item, str):
        return item.encode("utf-8")
    raise TypeError("stream chunk must be bytes or str")


async def _run_background_task(func, args, kwargs):
    try:
        result = func(*args, **kwargs)
        if _iscoro(result):
            await result
    except Exception as exc:
        try:
            print("bg_task_error", repr(exc))
        except Exception:
            pass


class _LazyBackgroundTasks:
    __slots__ = ("_inner",)

    def __init__(self):
        self._inner = None

    def _get(self):
        inner = self._inner
        if inner is not None:
            return inner
        try:
            inner = viperhttp.BackgroundTasks()
        except Exception:
            inner = None
        self._inner = inner
        return inner

    def add_task(self, func, *args, **kwargs):
        inner = self._get()
        if inner is None:
            return
        return inner.add_task(func, *args, **kwargs)

    def drain_tasks(self):
        inner = self._inner
        if inner is None:
            return []
        try:
            return inner.drain_tasks()
        except Exception:
            return []


def _schedule_background(bg):
    if bg is None:
        return
    try:
        tasks = bg.drain_tasks()
    except Exception:
        return
    if not tasks:
        return
    for entry in tasks:
        try:
            func, args, kwargs = entry
        except Exception:
            continue
        if kwargs is None:
            kwargs = {}
        asyncio.create_task(_run_background_task(func, args, kwargs))


try:
    _Queue = asyncio.Queue
except Exception:
    class _Queue:
        def __init__(self, maxsize=0):
            self._maxsize = maxsize
            self._items = []

        def put_nowait(self, item):
            if self._maxsize and len(self._items) >= self._maxsize:
                raise Exception("Queue full")
            self._items.append(item)

        async def get(self):
            while not self._items:
                await asyncio.sleep_ms(1)
            return self._items.pop(0)

class WebSocket:
    def __init__(self, conn_id, request=None):
        self.conn_id = conn_id
        self.request = request
        self._queue = _Queue(8)
        self._accepted = False
        self._closed = False

    async def accept(self, subprotocol=None):
        if self._closed or self._accepted:
            return
        viperhttp.ws_accept(self.conn_id, subprotocol)
        self._accepted = True

    async def send_text(self, text):
        if self._closed:
            return
        viperhttp.ws_send(self.conn_id, text, opcode=1)

    async def send_bytes(self, data):
        if self._closed:
            return
        viperhttp.ws_send(self.conn_id, data, opcode=2)

    async def send_json(self, obj):
        if self._closed:
            return
        payload = ujson.dumps(obj)
        viperhttp.ws_send(self.conn_id, payload, opcode=1)

    async def send(self, data, opcode=0, final=True):
        if self._closed:
            return
        viperhttp.ws_send(self.conn_id, data, opcode=opcode, final=final)

    async def close(self, code=1000, reason=""):
        if self._closed:
            return
        viperhttp.ws_close(self.conn_id, code=code, reason=reason)
        self._closed = True

    async def receive(self):
        return await self._queue.get()

    async def receive_text(self):
        while True:
            msg = await self._queue.get()
            if msg.get("type") == "message" and msg.get("opcode") == 1:
                return msg.get("text", "")
            if msg.get("type") == "close":
                return None

    async def receive_bytes(self):
        while True:
            msg = await self._queue.get()
            if msg.get("type") == "message" and msg.get("opcode") == 2:
                return msg.get("data", b"")
            if msg.get("type") == "close":
                return None

    def _enqueue(self, msg):
        try:
            self._queue.put_nowait(msg)
        except Exception:
            pass

    def _notify_disconnect(self, code=1000):
        if self._closed:
            return
        self._closed = True
        self._enqueue({"type": "close", "code": code})


async def _run_ws_handler(conn_id, coro):
    try:
        await coro
    except Exception as exc:
        try:
            print("ws_handler_error", repr(exc))
        except Exception:
            pass
        try:
            viperhttp.ws_close(conn_id, code=1011, reason="Handler error")
        except Exception:
            pass
    finally:
        ws = _ws_connections.pop(conn_id, None)
        if ws is not None and not ws._closed:
            try:
                viperhttp.ws_close(conn_id, code=1000, reason="")
            except Exception:
                pass
            ws._closed = True


def _normalize_response(resp):
    if isinstance(resp, dict) and resp.get("__vhttp_response__"):
        return resp

    def _mk(status_code=200, body=None, headers=None, content_type=None):
        return {
            "__vhttp_response__": True,
            "status_code": status_code,
            "body": body,
            "headers": headers,
            "content_type": content_type,
        }

    if isinstance(resp, (dict, list)):
        return _mk(status_code=200, body=resp, content_type="application/json")
    return _mk(status_code=200, body=resp)

def _http_exception_to_response(exc):
    status = 500
    detail = "Internal Server Error"
    try:
        args = getattr(exc, "args", ())
        if args:
            try:
                status = int(args[0])
            except Exception:
                status = 500
        if len(args) > 1:
            detail = args[1]
    except Exception:
        pass
    return {
        "__vhttp_response__": True,
        "status_code": status,
        "body": {"detail": detail},
        "headers": None,
        "content_type": "application/json",
    }


async def _dispatch_exception(app, request, exc):
    if vhttp_lifespan is not None:
        try:
            handler = vhttp_lifespan.resolve_exception_handler(app, exc)
        except Exception:
            handler = None
        if handler is not None:
            try:
                result = handler(request, exc)
            except TypeError:
                result = handler(exc)
            if _iscoro(result):
                result = await result
            return _normalize_response(result)
    try:
        if isinstance(exc, viperhttp.HTTPException):
            return _http_exception_to_response(exc)
    except Exception:
        pass
    return None


async def _run_lifespan_event(app, event_name):
    if vhttp_lifespan is None:
        return
    try:
        handlers = list(vhttp_lifespan.get_event_handlers(app, event_name))
    except Exception:
        handlers = []
    for handler in handlers:
        try:
            result = handler()
            if _iscoro(result):
                await result
        except Exception as exc:
            try:
                print("lifespan_handler_error", event_name, repr(exc))
            except Exception:
                pass


def _run_startup_handlers_sync(app):
    if vhttp_lifespan is None:
        return
    try:
        handlers = list(vhttp_lifespan.get_event_handlers(app, "startup"))
    except Exception:
        handlers = []
    for handler in handlers:
        try:
            result = handler()
            if _iscoro(result):
                asyncio.get_event_loop().create_task(result)
        except Exception as exc:
            try:
                print("lifespan_handler_error", "startup", repr(exc))
            except Exception:
                pass


def _get_middleware_entries(app):
    try:
        return app._middleware_stack()
    except Exception:
        return None


def _entry_priority(entry):
    try:
        if len(entry) > 3:
            return int(entry[3])
    except Exception:
        pass
    return 0


def _entry_unpack(entry):
    kind = entry[0] if len(entry) > 0 else None
    target = entry[1] if len(entry) > 1 else None
    kwargs = entry[2] if len(entry) > 2 else None
    return kind, target, kwargs


def _build_middleware_chain(app, entries):
    chain = []
    if not entries:
        return chain
    for entry in entries:
        try:
            kind, target, kwargs = _entry_unpack(entry)
        except Exception:
            continue
        if kind == "class":
            if kwargs is None:
                kwargs = {}
            try:
                inst = target(app, **kwargs)
            except Exception:
                inst = target(**kwargs)
            if hasattr(inst, "dispatch"):
                chain.append(inst.dispatch)
            else:
                chain.append(inst)
        elif kind == "func":
            chain.append(target)
    return chain


def _get_middleware_chain(app):
    entries = _get_middleware_entries(app)
    if entries is None:
        return []
    cache = _middleware_cache.get(app)
    sig = None
    try:
        sig = tuple(_entry_priority(entry) for entry in entries)
    except Exception:
        sig = None
    if cache is not None:
        cached_entries, cached_len, cached_sig, cached_chain = cache
        if cached_entries is entries and cached_len == len(entries) and cached_sig == sig:
            return cached_chain
    try:
        ordered = sorted(enumerate(entries), key=lambda item: (_entry_priority(item[1]), item[0]))
        ordered_entries = [entry for _, entry in ordered]
    except Exception:
        ordered_entries = entries
    chain = _build_middleware_chain(app, ordered_entries)
    _middleware_cache[app] = (entries, len(entries), sig, chain)
    return chain


async def _call_handler(app, method, path, request, bg_tasks):
    try:
        if request is not None:
            if bg_tasks is not None:
                result = app.dispatch(method, path, request, bg_tasks)
            else:
                result = app.dispatch(method, path, request)
        else:
            result = app.dispatch(method, path)
        if isinstance(result, dict) and result.get("__vhttp_dep_call__"):
            result = await _invoke_handler_with_dependencies(
                result.get("handler"),
                result.get("params") or {},
                result.get("deps"),
                result.get("request", request),
                result.get("background", bg_tasks),
            )
            return _normalize_response(result)
        if _iscoro(result):
            result = await result
        return _normalize_response(result)
    except Exception as exc:
        handled = await _dispatch_exception(app, request, exc)
        if handled is not None:
            return handled
        try:
            print("handler_error", repr(exc))
        except Exception:
            pass
        return {
            "__vhttp_response__": True,
            "status_code": 500,
            "body": "Internal Server Error",
            "headers": None,
            "content_type": None,
        }


async def _run_middleware_chain(app, method, path, request, bg_tasks):
    chain = _get_middleware_chain(app)

    async def call_next_at(idx, req):
        if idx >= len(chain):
            return await _call_handler(app, method, path, req, bg_tasks)
        mw = chain[idx]
        try:
            result = mw(req, lambda r=req: call_next_at(idx + 1, r))
            if _iscoro(result):
                result = await result
            return result
        except Exception as exc:
            handled = await _dispatch_exception(app, req, exc)
            if handled is not None:
                return handled
            try:
                print("middleware_error", repr(exc))
            except Exception:
                pass
            return {
                "__vhttp_response__": True,
                "status_code": 500,
                "body": "Internal Server Error",
                "headers": None,
                "content_type": None,
            }

    if not chain:
        return await _call_handler(app, method, path, request, bg_tasks)
    return await call_next_at(0, request)


def serialize_response(resp):
    resp = _normalize_response(resp)

    if isinstance(resp, dict) and resp.get("__vhttp_response__") and resp.get("stream") is not None:
        return resp

    status_code = resp.get("status_code", 200)
    body = resp.get("body", None)
    headers = resp.get("headers", None)
    content_type = resp.get("content_type", None)

    if body is None:
        body_bytes = b""
    elif isinstance(body, (bytes, bytearray)):
        body_bytes = body
    elif isinstance(body, str):
        body_bytes = body.encode("utf-8")
        if content_type is None:
            content_type = "text/plain; charset=utf-8"
    elif isinstance(body, (dict, list)):
        body_bytes = ujson.dumps(body).encode("utf-8")
        if content_type is None:
            content_type = "application/json"
    else:
        body_bytes = str(body).encode("utf-8")
        if content_type is None:
            content_type = "text/plain; charset=utf-8"

    return {
        "__vhttp_response__": True,
        "status_code": status_code,
        "body": body_bytes,
        "headers": headers,
        "content_type": content_type,
    }


def _is_async_stream_response(resp):
    if not isinstance(resp, dict):
        return False
    if not resp.get("__vhttp_response__"):
        return False
    stream = resp.get("stream")
    if stream is None:
        return False
    return _is_async_iter(stream)


async def _run_async_stream(request_id, resp, bg_tasks):
    stream = resp.get("stream")
    status_code = resp.get("status_code", 200)
    headers = resp.get("headers")
    content_type = resp.get("content_type")
    chunk_size = resp.get("chunk_size") or _DEFAULT_STREAM_CHUNK
    total_len = resp.get("total_len", 0)
    chunked = resp.get("chunked", False)
    if total_len == 0:
        chunked = True

    try:
        viperhttp.stream_send(
            request_id,
            b"",
            status_code=status_code,
            headers=headers,
            content_type=content_type,
            total_len=total_len,
            chunked=chunked,
            final=False,
            send_headers=True,
        )
    except Exception as exc:
        try:
            print("async_stream_error", repr(exc))
        except Exception:
            pass
        _schedule_background(bg_tasks)
        return

    try:
        if _is_async_iter(stream):
            async for item in stream:
                data = _coerce_stream_chunk(item)
                if not data:
                    await asyncio.sleep_ms(0)
                    continue
                offset = 0
                data_len = len(data)
                while offset < data_len:
                    chunk = data[offset:offset + chunk_size]
                    viperhttp.stream_send(
                        request_id,
                        chunk,
                        chunked=chunked,
                        final=False,
                    )
                    offset += len(chunk)
                    await asyncio.sleep_ms(0)
        else:
            for item in stream:
                data = _coerce_stream_chunk(item)
                if not data:
                    await asyncio.sleep_ms(0)
                    continue
                offset = 0
                data_len = len(data)
                while offset < data_len:
                    chunk = data[offset:offset + chunk_size]
                    viperhttp.stream_send(
                        request_id,
                        chunk,
                        chunked=chunked,
                        final=False,
                    )
                    offset += len(chunk)
                    await asyncio.sleep_ms(0)
    except Exception as exc:
        try:
            print("async_stream_error", repr(exc))
        except Exception:
            pass
    finally:
        try:
            viperhttp.stream_send(
                request_id,
                b"",
                chunked=chunked,
                final=True,
            )
        except Exception:
            pass
        _schedule_background(bg_tasks)


def _send_overload_response(request_id):
    try:
        payload = serialize_response({
            "__vhttp_response__": True,
            "status_code": 503,
            "body": "Server Busy",
            "headers": None,
            "content_type": None,
        })
        viperhttp.send_response(request_id, payload)
    except Exception:
        pass


async def _enqueue_http_request(app, msg):
    if _http_req_queue is None:
        return False

    try:
        _http_req_queue.put_nowait(msg)
        return True
    except Exception:
        pass

    deadline_ms = time_ms = 0
    ticks_ms = getattr(time, "ticks_ms", None)
    ticks_diff = getattr(time, "ticks_diff", None)
    if callable(ticks_ms) and callable(ticks_diff):
        now = ticks_ms()
        deadline_ms = now + int(_HTTP_ENQUEUE_WAIT_MS)
        time_ms = now

    for attempt in range(int(_HTTP_QUEUE_RETRY_LIMIT)):
        if bool(_HTTP_AUTOSCALE):
            try:
                loop = asyncio.get_event_loop()
                queued = _queue_size(_http_req_queue)
                desired = _target_workers_for_queue_depth(
                    queue_depth=queued + 1,
                    min_workers=int(_HTTP_WORKER_MIN),
                    max_workers=int(_HTTP_WORKER_MAX),
                )
                _spawn_http_workers_until(
                    app,
                    loop,
                    desired,
                    max_burst=int(_HTTP_SCALE_UP_MAX_BURST),
                )
            except Exception:
                pass

        try:
            _http_req_queue.put_nowait(msg)
            return True
        except Exception:
            pass

        if attempt + 1 >= int(_HTTP_QUEUE_RETRY_LIMIT):
            break

        if deadline_ms:
            try:
                time_ms = ticks_ms()
                if ticks_diff(deadline_ms, time_ms) <= 0:
                    break
            except Exception:
                pass

        sleep_ms = int(_HTTP_ENQUEUE_RETRY_SLEEP_MS)
        if sleep_ms < 0:
            sleep_ms = 0
        await asyncio.sleep_ms(sleep_ms)

    return False


async def _handle_http_message(app, msg):
    bg_tasks = _LazyBackgroundTasks()

    request = msg.get("request")
    req_id = msg.get("request_id")
    resp = await _run_middleware_chain(
        app,
        msg["method"],
        msg["path"],
        request,
        bg_tasks,
    )
    if resp is None:
        resp = {
            "__vhttp_response__": True,
            "status_code": 404,
            "body": "Not Found",
            "headers": None,
            "content_type": None,
        }

    send_ctx = _push_request_context(request)
    try:
        resp = serialize_response(resp)
        if _is_async_stream_response(resp):
            asyncio.create_task(_run_async_stream(req_id, resp, bg_tasks))
        else:
            viperhttp.send_response(req_id, resp)
            _schedule_background(bg_tasks)
    finally:
        _pop_request_context(send_ctx)


async def _http_worker_loop(app):
    processed_since_yield = 0
    while True:
        msg = await _http_req_queue.get()
        if msg is None:
            return
        try:
            await _handle_http_message(app, msg)
        except Exception as exc:
            try:
                print("http_worker_error", repr(exc))
            except Exception:
                pass
            req_id = msg.get("request_id") if isinstance(msg, dict) else None
            if req_id is not None:
                try:
                    payload = serialize_response({
                        "__vhttp_response__": True,
                        "status_code": 500,
                        "body": "Internal Server Error",
                        "headers": None,
                        "content_type": None,
                    })
                    viperhttp.send_response(req_id, payload)
                except Exception:
                    pass
        processed_since_yield += 1
        if processed_since_yield >= int(_HTTP_WORKER_YIELD_EVERY):
            processed_since_yield = 0
            await asyncio.sleep_ms(0)


def _queue_size(q):
    if q is None:
        return 0
    try:
        fn = getattr(q, "qsize", None)
        if callable(fn):
            size = fn()
            if size is not None:
                return int(size)
    except Exception:
        pass
    try:
        inner = getattr(q, "_queue", None)
        if inner is not None:
            return len(inner)
    except Exception:
        pass
    try:
        inner = getattr(q, "_items", None)
        if inner is not None:
            return len(inner)
    except Exception:
        pass
    return 0


def _prune_http_workers():
    global _http_worker_tasks
    if not _http_worker_tasks:
        return
    alive = []
    for task in _http_worker_tasks:
        try:
            if task.done():
                continue
        except Exception:
            pass
        alive.append(task)
    _http_worker_tasks = alive


def _spawn_http_worker(app, loop):
    try:
        task = loop.create_task(_http_worker_loop(app))
    except Exception as exc:
        try:
            print("bridge_worker_create_error", repr(exc))
        except Exception:
            pass
        return False
    _http_worker_tasks.append(task)
    return True


def _spawn_http_workers_until(app, loop, target_workers, max_burst=None):
    _prune_http_workers()
    current = len(_http_worker_tasks)
    target = int(target_workers)
    if target <= current:
        return 0
    if max_burst is None:
        burst = target - current
    else:
        burst = int(max_burst)
    if burst < 1:
        burst = 1
    spawned = 0
    while len(_http_worker_tasks) < target and spawned < burst:
        if not _spawn_http_worker(app, loop):
            break
        spawned += 1
    return spawned


def _stop_one_http_worker():
    if _http_req_queue is None:
        return False
    try:
        _http_req_queue.put_nowait(None)
        return True
    except Exception:
        return False


def _target_workers_for_queue_depth(queue_depth, min_workers, max_workers):
    q = int(queue_depth)
    wmin = int(min_workers)
    wmax = int(max_workers)
    if wmin < 1:
        wmin = 1
    if wmax < wmin:
        wmax = wmin
    # Keep at least one worker for every queued request while bounded by max.
    target = wmin
    if q > target:
        target = q
    if target > wmax:
        target = wmax
    return target


async def _http_scaler_loop(app):
    idle_ticks = 0
    while True:
        try:
            _prune_http_workers()
            workers = len(_http_worker_tasks)
            queued = _queue_size(_http_req_queue)

            if workers < int(_HTTP_WORKER_MIN):
                loop = asyncio.get_event_loop()
                _spawn_http_workers_until(app, loop, int(_HTTP_WORKER_MIN))
                idle_ticks = 0
            elif queued > workers and workers < int(_HTTP_WORKER_MAX):
                loop = asyncio.get_event_loop()
                desired = _target_workers_for_queue_depth(
                    queue_depth=queued,
                    min_workers=int(_HTTP_WORKER_MIN),
                    max_workers=int(_HTTP_WORKER_MAX),
                )
                scale_budget = int(_HTTP_SCALE_UP_STEP)
                if scale_budget < 1:
                    scale_budget = 1
                if scale_budget < int(_HTTP_SCALE_UP_MAX_BURST):
                    scale_budget = int(_HTTP_SCALE_UP_MAX_BURST)
                _spawn_http_workers_until(app, loop, desired, max_burst=scale_budget)
                idle_ticks = 0
            elif queued == 0 and workers > int(_HTTP_WORKER_MIN):
                idle_ticks += 1
                if idle_ticks >= int(_HTTP_SCALE_DOWN_IDLE_TICKS):
                    if _stop_one_http_worker():
                        idle_ticks = 0
            else:
                idle_ticks = 0
        except Exception as exc:
            try:
                print("bridge_scaler_error", repr(exc))
            except Exception:
                pass
        await asyncio.sleep_ms(_HTTP_SCALE_CHECK_MS)


def _start_http_workers(app, loop):
    global _http_scaler_task
    global _http_req_queue
    if _http_req_queue is None:
        _http_req_queue = _Queue(_HTTP_QUEUE_SIZE)

    _prune_http_workers()
    target_min = int(_HTTP_WORKER_MIN)
    if target_min < 1:
        target_min = 1
    _spawn_http_workers_until(app, loop, target_min)

    if bool(_HTTP_AUTOSCALE) and int(_HTTP_WORKER_MAX) > int(_HTTP_WORKER_MIN):
        if _http_scaler_task is None:
            try:
                _http_scaler_task = loop.create_task(_http_scaler_loop(app))
            except Exception as exc:
                try:
                    print("bridge_scaler_create_error", repr(exc))
                except Exception:
                    pass

    started_workers = len(_http_worker_tasks)
    try:
        import gc as _gc
        print(
            "bridge_workers_started",
            started_workers,
            "min",
            int(_HTTP_WORKER_MIN),
            "max",
            int(_HTTP_WORKER_MAX),
            "queue",
            int(_HTTP_QUEUE_SIZE),
            "autoscale",
            bool(_HTTP_AUTOSCALE),
            "mem_free",
            _gc.mem_free(),
        )
    except Exception:
        try:
            print(
                "bridge_workers_started",
                started_workers,
                "min",
                int(_HTTP_WORKER_MIN),
                "max",
                int(_HTTP_WORKER_MAX),
                "queue",
                int(_HTTP_QUEUE_SIZE),
                "autoscale",
                bool(_HTTP_AUTOSCALE),
            )
        except Exception:
            pass


async def _bridge_handle_message(app, msg):
    global _bridge_debug
    if _bridge_debug:
        try:
            print("bridge_request", msg.get("method"), msg.get("path"))
        except Exception:
            pass
        _bridge_debug = False

    msg_type = msg.get("type", None)
    if msg_type == "ws_connect":
        conn_id = msg.get("conn_id")
        path = msg.get("path", "")
        request = msg.get("request")
        ws = WebSocket(conn_id, request=request)
        _ws_connections[conn_id] = ws
        try:
            result = app.ws_dispatch(path, ws, request)
            matched = True
            if isinstance(result, (list, tuple)) and len(result) == 2:
                matched = bool(result[0])
                result = result[1]
            elif result is None:
                matched = False
            if not matched:
                viperhttp.ws_reject(conn_id, 404, "Not Found")
                _ws_connections.pop(conn_id, None)
                return
            if _iscoro(result):
                asyncio.create_task(_run_ws_handler(conn_id, result))
            else:
                # Handler is expected to be async; close if it returned a response dict.
                if isinstance(result, dict) and result.get("__vhttp_response__"):
                    viperhttp.ws_reject(conn_id, result.get("status_code", 400), result.get("body", ""))
                    _ws_connections.pop(conn_id, None)
        except Exception as exc:
            try:
                print("ws_dispatch_error", repr(exc))
            except Exception:
                pass
            try:
                viperhttp.ws_reject(conn_id, 500, "Internal Server Error")
            except Exception:
                pass
            _ws_connections.pop(conn_id, None)
        return

    if msg_type == "ws_msg":
        conn_id = msg.get("conn_id")
        ws = _ws_connections.get(conn_id)
        if ws is None:
            return
        opcode = msg.get("opcode", 2)
        data = msg.get("data", b"")
        final = msg.get("final", True)
        payload = {
            "type": "message",
            "opcode": opcode,
            "data": data,
            "final": final,
        }
        if opcode == 1:
            try:
                payload["text"] = data.decode("utf-8")
            except Exception:
                payload["text"] = ""
        ws._enqueue(payload)
        return

    if msg_type == "ws_disconnect":
        conn_id = msg.get("conn_id")
        code = msg.get("code", 1000)
        ws = _ws_connections.pop(conn_id, None)
        if ws is not None:
            ws._notify_disconnect(code)
        return

    if await _enqueue_http_request(app, msg):
        return
    _send_overload_response(msg.get("request_id"))


async def _bridge_loop(app):
    while True:
        try:
            processed = 0
            while processed < _BRIDGE_POLL_BURST:
                msg = viperhttp.poll_request()
                if msg is None:
                    break
                await _bridge_handle_message(app, msg)
                processed += 1
            if processed == 0:
                await asyncio.sleep_ms(_BRIDGE_IDLE_SLEEP_MS)
                continue
            await asyncio.sleep_ms(_BRIDGE_ACTIVE_SLEEP_MS)
        except Exception as exc:
            try:
                print("bridge_loop_error", repr(exc))
            except Exception:
                pass
            await asyncio.sleep_ms(_BRIDGE_ERROR_SLEEP_MS)


def start(app, loop=None):
    global _bridge_task
    if loop is None:
        loop = asyncio.get_event_loop()
    _configure_dep_resolver()
    _start_http_workers(app, loop)
    if _bridge_task is None:
        _bridge_task = loop.create_task(_bridge_loop(app))
    return loop


def _cancel_dispatch_tasks():
    global _bridge_task
    global _http_req_queue
    global _http_worker_tasks
    global _http_scaler_task
    if _bridge_task is not None:
        try:
            _bridge_task.cancel()
        except Exception:
            pass
        _bridge_task = None
    if _http_scaler_task is not None:
        try:
            _http_scaler_task.cancel()
        except Exception:
            pass
        _http_scaler_task = None
    if _http_worker_tasks:
        for task in _http_worker_tasks:
            try:
                task.cancel()
            except Exception:
                pass
    _http_worker_tasks = []
    _http_req_queue = None
    _ws_connections.clear()


def _set_bridge_worker_limits(worker_count=None, queue_size=None):
    global _HTTP_WORKER_MIN
    global _HTTP_WORKER_MAX
    global _HTTP_QUEUE_SIZE
    global _HTTP_AUTOSCALE

    current_min = int(_HTTP_WORKER_MIN)
    current_max = int(_HTTP_WORKER_MAX)
    current_q = int(_HTTP_QUEUE_SIZE)
    current_auto = bool(_HTTP_AUTOSCALE)

    if worker_count is not None:
        fixed = int(worker_count)
        current_min = fixed
        current_max = fixed
    if queue_size is not None:
        current_q = int(queue_size)

    if current_min < 1:
        current_min = 1
    if current_max < current_min:
        current_max = current_min
    if current_q < current_max:
        current_q = current_max

    _HTTP_WORKER_MIN = current_min
    _HTTP_WORKER_MAX = current_max
    _HTTP_QUEUE_SIZE = current_q
    _HTTP_AUTOSCALE = current_auto


def _set_bridge_worker_range(min_workers=None, max_workers=None, queue_size=None, autoscale=None):
    global _HTTP_WORKER_MIN
    global _HTTP_WORKER_MAX
    global _HTTP_QUEUE_SIZE
    global _HTTP_AUTOSCALE

    current_min = int(_HTTP_WORKER_MIN)
    current_max = int(_HTTP_WORKER_MAX)
    current_q = int(_HTTP_QUEUE_SIZE)

    if min_workers is not None:
        current_min = int(min_workers)
    if max_workers is not None:
        current_max = int(max_workers)
    if queue_size is not None:
        current_q = int(queue_size)

    if current_min < 1:
        current_min = 1
    if current_max < current_min:
        current_max = current_min
    if current_q < current_max:
        current_q = current_max

    if autoscale is None:
        auto = current_max > current_min
    else:
        auto = bool(autoscale)
        if current_max == current_min:
            auto = False

    _HTTP_WORKER_MIN = current_min
    _HTTP_WORKER_MAX = current_max
    _HTTP_QUEUE_SIZE = current_q
    _HTTP_AUTOSCALE = auto


def _set_bridge_loop_limits(poll_burst=None, idle_sleep_ms=None):
    global _BRIDGE_POLL_BURST
    global _BRIDGE_IDLE_SLEEP_MS

    if poll_burst is not None:
        value = int(poll_burst)
        if value < 1:
            value = 1
        _BRIDGE_POLL_BURST = value

    if idle_sleep_ms is not None:
        value = int(idle_sleep_ms)
        if value < 0:
            value = 0
        _BRIDGE_IDLE_SLEEP_MS = value


def _set_bridge_dispatch_limits(enqueue_wait_ms=None, worker_yield_every=None, scale_up_max_burst=None):
    global _HTTP_ENQUEUE_WAIT_MS
    global _HTTP_WORKER_YIELD_EVERY
    global _HTTP_SCALE_UP_MAX_BURST

    if enqueue_wait_ms is not None:
        value = int(enqueue_wait_ms)
        if value < 0:
            value = 0
        _HTTP_ENQUEUE_WAIT_MS = value

    if worker_yield_every is not None:
        value = int(worker_yield_every)
        if value < 1:
            value = 1
        _HTTP_WORKER_YIELD_EVERY = value

    if scale_up_max_burst is not None:
        value = int(scale_up_max_burst)
        if value < 1:
            value = 1
        _HTTP_SCALE_UP_MAX_BURST = value


def _get_app_docs_config(app):
    try:
        getter = getattr(app, "_docs_config", None)
    except Exception:
        getter = None
    if getter is None:
        return {}
    try:
        cfg = getter()
    except Exception:
        return {}
    if isinstance(cfg, dict):
        return cfg
    return {}


def _auto_install_docs(
    app,
    auto_docs=None,
    title=None,
    version=None,
    description=None,
    openapi_url=_UNSET,
    docs_url=_UNSET,
    include_websocket_docs=None,
    cache_schema=None,
    servers=None,
):
    cfg = _get_app_docs_config(app)
    default_enabled = bool(cfg.get("docs", True))
    enabled = default_enabled if auto_docs is None else bool(auto_docs)
    if not enabled:
        return
    try:
        import viperhttp_autodocs as _autodocs
    except Exception:
        return

    resolved_title = title if title is not None else cfg.get("title", "ViperHTTP API")
    resolved_version = version if version is not None else cfg.get("version", "1.0.0")
    resolved_description = description if description is not None else cfg.get("description", "")
    resolved_openapi_url = cfg.get("openapi_url", "/openapi.json") if openapi_url is _UNSET else openapi_url
    resolved_docs_url = cfg.get("docs_url", "/docs") if docs_url is _UNSET else docs_url
    resolved_include_ws = include_websocket_docs if include_websocket_docs is not None else cfg.get("include_websocket_docs", True)
    resolved_cache_schema = cache_schema if cache_schema is not None else cfg.get("cache_schema", True)
    resolved_servers = servers if servers is not None else cfg.get("servers", None)

    try:
        _autodocs.install(
            app,
            title=str(resolved_title),
            version=str(resolved_version),
            description=str(resolved_description),
            openapi_url=resolved_openapi_url,
            docs_url=resolved_docs_url,
            servers=resolved_servers,
            include_websocket=bool(resolved_include_ws),
            cache_schema=bool(resolved_cache_schema),
        )
    except Exception as exc:
        try:
            print("autodocs_install_error", repr(exc))
        except Exception:
            pass


def _auto_install_ota(
    app,
    ota=None,
    ota_prefix="/ota",
    ota_token=None,
    ota_token_header="X-OTA-Token",
    ota_token_query="token",
):
    if not ota:
        return
    if vhttp_ota is None:
        try:
            print("ota_install_error", "viperhttp_ota module unavailable")
        except Exception:
            pass
        return
    try:
        vhttp_ota.install_ota_routes(
            app,
            prefix=ota_prefix,
            token=ota_token,
            token_header=ota_token_header,
            token_query=ota_token_query,
        )
    except Exception as exc:
        try:
            print("ota_install_error", repr(exc))
        except Exception:
            pass


def run(
    app,
    port=8080,
    loop=None,
    wifi=True,
    https=False,
    http2=False,
    http2_max_streams=8,
    tls_cert_pem=None,
    tls_key_pem=None,
    tls_cert_path=None,
    tls_key_path=None,
    ota=False,
    ota_prefix="/ota",
    ota_token=None,
    ota_token_header="X-OTA-Token",
    ota_token_query="token",
    min_workers=None,
    max_workers=None,
    bridge_min_workers=None,
    bridge_max_workers=None,
    bridge_queue_size=None,
    bridge_poll_burst=None,
    bridge_idle_sleep_ms=None,
    bridge_autoscale=None,
    bridge_enqueue_wait_ms=None,
    bridge_worker_yield_every=None,
    bridge_scale_up_max_burst=None,
    auto_docs=None,
    title=None,
    version=None,
    description=None,
    openapi_url=_UNSET,
    docs_url=_UNSET,
    include_websocket_docs=None,
    cache_schema=None,
    servers=None,
):
    if wifi:
        import network
        wlan = network.WLAN(network.STA_IF)
        wlan.active(True)
        try:
            pm_none = getattr(network.WLAN, "PM_NONE", None)
            if pm_none is not None:
                wlan.config(pm=pm_none)
            else:
                wlan.config(pm=0)
        except Exception:
            pass
    _auto_install_docs(
        app,
        auto_docs=auto_docs,
        title=title,
        version=version,
        description=description,
        openapi_url=openapi_url,
        docs_url=docs_url,
        include_websocket_docs=include_websocket_docs,
        cache_schema=cache_schema,
        servers=servers,
    )
    _auto_install_ota(
        app,
        ota=ota,
        ota_prefix=ota_prefix,
        ota_token=ota_token,
        ota_token_header=ota_token_header,
        ota_token_query=ota_token_query,
    )
    _run_startup_handlers_sync(app)
    if bridge_min_workers is None and bridge_max_workers is not None:
        bridge_min_workers = bridge_max_workers
    if bridge_max_workers is None and bridge_min_workers is not None:
        bridge_max_workers = bridge_min_workers
    _set_bridge_worker_range(
        min_workers=bridge_min_workers,
        max_workers=bridge_max_workers,
        queue_size=bridge_queue_size,
        autoscale=bridge_autoscale,
    )
    _set_bridge_loop_limits(
        poll_burst=bridge_poll_burst,
        idle_sleep_ms=bridge_idle_sleep_ms,
    )
    _set_bridge_dispatch_limits(
        enqueue_wait_ms=bridge_enqueue_wait_ms,
        worker_yield_every=bridge_worker_yield_every,
        scale_up_max_burst=bridge_scale_up_max_burst,
    )
    _cancel_dispatch_tasks()
    viperhttp.stop()
    if min_workers is not None or max_workers is not None:
        current = {}
        try:
            current = viperhttp.get_worker_limits()
        except Exception:
            current = {}
        cfg_min = min_workers if min_workers is not None else current.get("min_workers")
        cfg_max = max_workers if max_workers is not None else current.get("max_workers")
        if cfg_min is None or cfg_max is None:
            raise ValueError("worker limits unavailable")
        viperhttp.set_worker_limits(min_workers=cfg_min, max_workers=cfg_max)
    cert_pem = tls_cert_pem
    key_pem = tls_key_pem
    if https:
        if cert_pem is None and tls_cert_path:
            with open(tls_cert_path, "rb") as _f:
                cert_pem = _f.read()
        if key_pem is None and tls_key_path:
            with open(tls_key_path, "rb") as _f:
                key_pem = _f.read()

    viperhttp.start(
        port=port,
        https=https,
        cert_pem=cert_pem,
        key_pem=key_pem,
        http2=http2,
        http2_max_streams=http2_max_streams,
    )
    return start(app, loop)


async def shutdown(app):
    await _run_lifespan_event(app, "shutdown")


_configure_dep_resolver()


try:
    setattr(viperhttp.ViperHTTP, "run", run)
except Exception:
    pass
try:
    setattr(viperhttp.ViperHTTP, "shutdown", shutdown)
except Exception:
    pass

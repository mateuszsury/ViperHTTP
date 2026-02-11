try:
    import ujson as json
except Exception:
    import json

try:
    import sys
except Exception:
    sys = None

import viperhttp
try:
    import uasyncio as asyncio
except Exception:
    asyncio = None

try:
    StopAsyncIteration
except Exception:
    class StopAsyncIteration(Exception):
        pass


def _ensure_text(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode("utf-8")
        except Exception:
            return ""
    return str(value)


def _append_header(headers, key, value):
    if isinstance(headers, dict):
        headers[key] = value
        return headers
    if isinstance(headers, list):
        headers.append((key, value))
        return headers
    return [(key, value)]


def _format_sse_event(item):
    if isinstance(item, dict):
        lines = []
        comment = item.get("comment")
        if comment:
            for line in _ensure_text(comment).splitlines():
                lines.append(":" + line)
        event = item.get("event")
        if event:
            lines.append("event: " + _ensure_text(event))
        event_id = item.get("id")
        if event_id:
            lines.append("id: " + _ensure_text(event_id))
        retry = item.get("retry")
        if retry is not None:
            try:
                retry_val = int(retry)
                lines.append("retry: %d" % retry_val)
            except Exception:
                pass
        data = item.get("data")
        if isinstance(data, (dict, list)):
            data = json.dumps(data)
        data = _ensure_text(data)
        if data:
            for line in data.splitlines():
                lines.append("data: " + line)
        else:
            lines.append("data:")
        lines.append("")
        return "\n".join(lines) + "\n"

    data = item
    if isinstance(data, (dict, list)):
        data = json.dumps(data)
    data = _ensure_text(data)
    lines = []
    if data:
        for line in data.splitlines():
            lines.append("data: " + line)
    else:
        lines.append("data:")
    lines.append("")
    return "\n".join(lines) + "\n"


def EventSourceResponse(
    stream,
    headers=None,
    retry=None,
    chunk_size=1024,
):
    if stream is None:
        stream = []

    if isinstance(headers, dict):
        base_headers = dict(headers)
    elif isinstance(headers, list):
        base_headers = list(headers)
    elif isinstance(headers, tuple):
        base_headers = list(headers)
    else:
        base_headers = {}
    base_headers = _append_header(base_headers, "Cache-Control", "no-cache")
    base_headers = _append_header(base_headers, "X-Accel-Buffering", "no")

    def _is_async_iter(obj):
        try:
            if hasattr(obj, "__aiter__") or hasattr(obj, "__anext__"):
                return True
        except Exception:
            pass
        return False

    class _SSEIter:
        def __init__(self, source, retry_val):
            self._source = source
            self._retry = retry_val
            self._sent_retry = False
            self._aiter = None
            self._iter = None

        def __aiter__(self):
            if _is_async_iter(self._source):
                try:
                    self._aiter = self._source.__aiter__()
                except Exception:
                    self._aiter = self._source
            else:
                self._iter = iter(self._source)
            return self

        async def __anext__(self):
            if not self._sent_retry:
                self._sent_retry = True
                if self._retry is not None:
                    try:
                        retry_val = int(self._retry)
                        return "retry: %d\n\n" % retry_val
                    except Exception:
                        pass
            if self._aiter is not None:
                try:
                    item = await self._aiter.__anext__()
                except StopAsyncIteration:
                    raise
            else:
                try:
                    item = next(self._iter)
                except StopIteration:
                    raise StopAsyncIteration
                if asyncio is not None:
                    try:
                        await asyncio.sleep_ms(0)
                    except Exception:
                        pass
            return _format_sse_event(item)

    return viperhttp.StreamingResponse(
        body=_SSEIter(stream, retry),
        headers=base_headers,
        content_type="text/event-stream; charset=utf-8",
        chunk_size=chunk_size,
        chunked=True,
    )


def RedirectResponse(url, status_code=307, headers=None):
    if not isinstance(url, str) or not url:
        raise ValueError("url must be a non-empty string")
    if status_code not in (301, 302, 303, 307, 308):
        raise ValueError("status_code must be one of 301, 302, 303, 307, 308")

    if isinstance(headers, dict):
        out_headers = dict(headers)
    elif isinstance(headers, list):
        out_headers = list(headers)
    elif isinstance(headers, tuple):
        out_headers = list(headers)
    elif headers is None:
        out_headers = {}
    else:
        out_headers = headers
    out_headers = _append_header(out_headers, "Location", url)

    return viperhttp.Response(
        status_code=status_code,
        body="",
        headers=out_headers,
        content_type="text/plain; charset=utf-8",
    )


class UploadFile:
    def __init__(self, filename="", content_type="", data=b""):
        self.filename = _ensure_text(filename)
        self.content_type = _ensure_text(content_type)
        if data is None:
            data = b""
        if isinstance(data, str):
            data = data.encode("utf-8")
        elif isinstance(data, memoryview):
            data = data.tobytes()
        elif isinstance(data, bytearray):
            data = bytes(data)
        elif not isinstance(data, bytes):
            data = bytes(data)
        self._buf = bytearray(data)
        self._pos = 0
        self.closed = False

    @property
    def size(self):
        return len(self._buf)

    @property
    def file(self):
        return self

    @classmethod
    def from_multipart(cls, value):
        if not isinstance(value, dict):
            return None
        if "data" not in value:
            return None
        return cls(
            filename=value.get("filename", ""),
            content_type=value.get("content_type", ""),
            data=value.get("data", b""),
        )

    async def read(self, size=-1):
        return self.read_sync(size)

    def read_sync(self, size=-1):
        if self.closed:
            return b""
        if size is None or size < 0:
            out = bytes(self._buf[self._pos:])
            self._pos = len(self._buf)
            return out
        size = int(size)
        if size <= 0:
            return b""
        end = self._pos + size
        out = bytes(self._buf[self._pos:end])
        self._pos += len(out)
        return out

    async def write(self, data):
        return self.write_sync(data)

    def write_sync(self, data):
        if self.closed:
            raise ValueError("I/O operation on closed UploadFile")
        if data is None:
            data = b""
        if isinstance(data, str):
            data = data.encode("utf-8")
        elif isinstance(data, memoryview):
            data = data.tobytes()
        elif isinstance(data, bytearray):
            data = bytes(data)
        elif not isinstance(data, bytes):
            data = bytes(data)

        end_pos = self._pos + len(data)
        if self._pos > len(self._buf):
            self._buf.extend(b"\x00" * (self._pos - len(self._buf)))
        if end_pos > len(self._buf):
            self._buf.extend(b"\x00" * (end_pos - len(self._buf)))
        self._buf[self._pos:end_pos] = data
        self._pos = end_pos
        return len(data)

    async def seek(self, offset, whence=0):
        return self.seek_sync(offset, whence)

    def seek_sync(self, offset, whence=0):
        if self.closed:
            raise ValueError("I/O operation on closed UploadFile")
        offset = int(offset)
        whence = int(whence)
        if whence == 0:
            new_pos = offset
        elif whence == 1:
            new_pos = self._pos + offset
        elif whence == 2:
            new_pos = len(self._buf) + offset
        else:
            raise ValueError("invalid whence")
        if new_pos < 0:
            raise ValueError("negative seek position")
        self._pos = new_pos
        return self._pos

    async def tell(self):
        return self.tell_sync()

    def tell_sync(self):
        return self._pos

    async def close(self):
        self.close_sync()

    def close_sync(self):
        self.closed = True
        self._buf = bytearray()
        self._pos = 0


def form_upload(form, field_name):
    if not isinstance(form, dict):
        return None
    return UploadFile.from_multipart(form.get(field_name))


if sys is not None:
    try:
        sys.modules["viperhttp.responses"] = sys.modules[__name__]
    except Exception:
        pass
    try:
        setattr(viperhttp, "responses", sys.modules[__name__])
    except Exception:
        pass
    try:
        setattr(viperhttp, "EventSourceResponse", EventSourceResponse)
    except Exception:
        pass
    try:
        setattr(viperhttp, "RedirectResponse", RedirectResponse)
    except Exception:
        pass
    try:
        setattr(viperhttp, "UploadFile", UploadFile)
    except Exception:
        pass
    try:
        setattr(viperhttp, "form_upload", form_upload)
    except Exception:
        pass
    try:
        if not hasattr(viperhttp, "__path__"):
            viperhttp.__path__ = []
    except Exception:
        pass

#!/usr/bin/env python3
import argparse
import socket


H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_RST_STREAM = 0x3
FRAME_SETTINGS = 0x4
FRAME_PING = 0x6
FRAME_GOAWAY = 0x7
FRAME_CONTINUATION = 0x9

FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4
FLAG_ACK = 0x1

STATIC_TABLE = {
    1: (":authority", ""),
    2: (":method", "GET"),
    3: (":method", "POST"),
    4: (":path", "/"),
    5: (":path", "/index.html"),
    6: (":scheme", "http"),
    7: (":scheme", "https"),
    8: (":status", "200"),
}


def encode_int(value: int, prefix_bits: int, first_mask: int) -> bytes:
    max_prefix = (1 << prefix_bits) - 1
    if value < max_prefix:
        return bytes([first_mask | value])
    out = bytearray([first_mask | max_prefix])
    value -= max_prefix
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value & 0x7F)
    return bytes(out)


def encode_str_raw(s: bytes) -> bytes:
    return encode_int(len(s), 7, 0x00) + s


def encode_lit_idx_name(index: int, value: str) -> bytes:
    return encode_int(index, 4, 0x00) + encode_str_raw(value.encode("utf-8"))


def encode_lit_name_value(name: str, value: str) -> bytes:
    n = name.encode("utf-8")
    v = value.encode("utf-8")
    return encode_int(0, 4, 0x00) + encode_str_raw(n) + encode_str_raw(v)


def build_frame(ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    ln = len(payload)
    return bytes(
        [
            (ln >> 16) & 0xFF,
            (ln >> 8) & 0xFF,
            ln & 0xFF,
            ftype & 0xFF,
            flags & 0xFF,
            (stream_id >> 24) & 0x7F,
            (stream_id >> 16) & 0xFF,
            (stream_id >> 8) & 0xFF,
            stream_id & 0xFF,
        ]
    ) + payload


def recv_exact(sock: socket.socket, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise ConnectionError("socket closed")
        out.extend(chunk)
    return bytes(out)


def recv_frame(sock: socket.socket):
    hdr = recv_exact(sock, 9)
    ln = (hdr[0] << 16) | (hdr[1] << 8) | hdr[2]
    ftype = hdr[3]
    flags = hdr[4]
    sid = ((hdr[5] & 0x7F) << 24) | (hdr[6] << 16) | (hdr[7] << 8) | hdr[8]
    payload = recv_exact(sock, ln) if ln else b""
    return ftype, flags, sid, payload


def decode_int(buf: bytes, off: int, prefix_bits: int):
    if off >= len(buf):
        raise ValueError("int decode overflow")
    max_prefix = (1 << prefix_bits) - 1
    value = buf[off] & max_prefix
    off += 1
    if value < max_prefix:
        return value, off
    m = 0
    while True:
        if off >= len(buf):
            raise ValueError("int continuation overflow")
        b = buf[off]
        off += 1
        value += (b & 0x7F) << m
        if (b & 0x80) == 0:
            return value, off
        m += 7


def decode_str(buf: bytes, off: int):
    if off >= len(buf):
        raise ValueError("string decode overflow")
    if (buf[off] & 0x80) != 0:
        raise ValueError("huffman string unsupported in test client")
    ln, off = decode_int(buf, off, 7)
    end = off + ln
    if end > len(buf):
        raise ValueError("string length overflow")
    return buf[off:end].decode("utf-8", "replace"), end


def decode_header_block(block: bytes):
    headers = []
    off = 0
    while off < len(block):
        b = block[off]
        if b & 0x80:
            idx, off = decode_int(block, off, 7)
            name, value = STATIC_TABLE.get(idx, (f"idx-{idx}", ""))
            headers.append((name, value))
            continue
        if (b & 0x20) == 0x20:
            _, off = decode_int(block, off, 5)
            continue
        prefix = 6 if (b & 0x40) == 0x40 else 4
        idx, off = decode_int(block, off, prefix)
        if idx:
            name, _ = STATIC_TABLE.get(idx, (f"idx-{idx}", ""))
        else:
            name, off = decode_str(block, off)
        value, off = decode_str(block, off)
        headers.append((name, value))
    return headers


def build_get_headers(path: str, authority: str) -> bytes:
    return b"".join(
        [
            bytes([0x82]),  # :method GET
            bytes([0x86]),  # :scheme http
            encode_lit_idx_name(4, path),  # :path
            encode_lit_idx_name(1, authority),  # :authority
            encode_lit_name_value("user-agent", "viperhttp-h2-interleave"),
        ]
    )


def main():
    ap = argparse.ArgumentParser(description="HTTP/2 interleaving test (two streams, one connection)")
    ap.add_argument("ip")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()

    authority = f"{args.ip}:{args.port}"
    stream_paths = {
        1: "/debug/server-stats",
        3: "/hello",
        5: "/debug/server-stats",
    }
    expected_substr = {1: "http2", 3: "message", 5: "http2"}
    stream_state = {
        sid: {"status": None, "headers_block": bytearray(), "body": bytearray(), "done": False}
        for sid in stream_paths
    }

    client_settings = build_frame(FRAME_SETTINGS, 0, 0, b"")
    ack_settings = build_frame(FRAME_SETTINGS, FLAG_ACK, 0, b"")

    s = socket.create_connection((args.ip, args.port), timeout=4)
    s.settimeout(3.0)
    try:
        s.sendall(H2_PREFACE + client_settings)

        ftype, flags, sid, _ = recv_frame(s)
        if ftype != FRAME_SETTINGS or sid != 0:
            raise RuntimeError(f"unexpected first frame type={ftype} sid={sid}")
        if (flags & FLAG_ACK) == 0:
            s.sendall(ack_settings)

        for stream_id in (1, 3, 5):
            hdrs = build_get_headers(stream_paths[stream_id], authority)
            s.sendall(build_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, stream_id, hdrs))

        while not all(st["done"] for st in stream_state.values()):
            ftype, flags, sid, payload = recv_frame(s)
            if ftype == FRAME_SETTINGS and (flags & FLAG_ACK) == 0:
                s.sendall(ack_settings)
                continue
            if ftype == FRAME_PING and (flags & FLAG_ACK) == 0:
                s.sendall(build_frame(FRAME_PING, FLAG_ACK, 0, payload))
                continue
            if ftype == FRAME_GOAWAY:
                raise RuntimeError("received GOAWAY before streams completed")
            if sid not in stream_state:
                continue
            if ftype == FRAME_RST_STREAM:
                err = None
                if len(payload) == 4:
                    err = (payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3]
                raise RuntimeError(f"stream {sid} reset by peer err={err}")
            st = stream_state[sid]
            if ftype in (FRAME_HEADERS, FRAME_CONTINUATION):
                st["headers_block"].extend(payload)
                if flags & FLAG_END_HEADERS:
                    headers = decode_header_block(bytes(st["headers_block"]))
                    st["headers_block"].clear()
                    for name, value in headers:
                        if name == ":status":
                            try:
                                st["status"] = int(value)
                            except ValueError:
                                st["status"] = None
                if flags & FLAG_END_STREAM:
                    st["done"] = True
            elif ftype == FRAME_DATA:
                st["body"].extend(payload)
                if flags & FLAG_END_STREAM:
                    st["done"] = True
    finally:
        try:
            s.close()
        except Exception:
            pass

    for sid, st in stream_state.items():
        body_text = bytes(st["body"]).decode("utf-8", "replace")
        print(f"stream={sid} status={st['status']} body_len={len(st['body'])}")
        if st["status"] != 200:
            raise RuntimeError(f"stream {sid} unexpected status {st['status']}")
        if expected_substr[sid] not in body_text:
            raise RuntimeError(f"stream {sid} missing substring {expected_substr[sid]!r}")

    print("HTTP2 INTERLEAVE TEST PASS")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import argparse
import socket


H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_SETTINGS = 0x4
FRAME_PING = 0x6
FRAME_GOAWAY = 0x7
FRAME_WINDOW_UPDATE = 0x8
FRAME_CONTINUATION = 0x9

FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4
FLAG_ACK = 0x1

STATIC_TABLE = {
    1: (":authority", ""),
    2: (":method", "GET"),
    4: (":path", "/"),
    6: (":scheme", "http"),
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
    raw = value.encode("utf-8")
    return encode_int(index, 4, 0x00) + encode_str_raw(raw)


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
    huffman = (buf[off] & 0x80) != 0
    if huffman:
        raise ValueError("huffman string unsupported in test client")
    ln, off = decode_int(buf, off, 7)
    end = off + ln
    if end > len(buf):
        raise ValueError("string length overflow")
    raw = buf[off:end]
    return raw.decode("utf-8", "replace"), end


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


def build_window_update(stream_id: int, increment: int) -> bytes:
    payload = (increment & 0x7FFFFFFF).to_bytes(4, "big")
    return build_frame(FRAME_WINDOW_UPDATE, 0, stream_id, payload)


def main():
    ap = argparse.ArgumentParser(description="HTTP/2 stream backpressure resume test")
    ap.add_argument("ip")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--path", default="/stream-chunked")
    ap.add_argument("--stream-id", type=int, default=1)
    ap.add_argument("--initial-window", type=int, default=64)
    ap.add_argument("--update-window", type=int, default=4096)
    args = ap.parse_args()

    authority = f"{args.ip}:{args.port}"
    req_block = b"".join(
        [
            bytes([0x82]),  # :method GET
            bytes([0x86]),  # :scheme http
            encode_lit_idx_name(4, args.path),  # :path
            encode_lit_idx_name(1, authority),  # :authority
            encode_lit_name_value("user-agent", "viperhttp-h2-backpressure-test"),
        ]
    )
    req_frame = build_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, args.stream_id, req_block)

    # SETTINGS_INITIAL_WINDOW_SIZE
    client_settings = build_frame(FRAME_SETTINGS, 0, 0, b"\x00\x04" + args.initial_window.to_bytes(4, "big"))
    ack_settings = build_frame(FRAME_SETTINGS, FLAG_ACK, 0, b"")

    status = None
    headers_block = bytearray()
    body = bytearray()
    got_end_stream = False
    sent_window_update = False

    s = socket.create_connection((args.ip, args.port), timeout=4)
    s.settimeout(3.0)
    try:
        s.sendall(H2_PREFACE + client_settings)
        ftype, flags, sid, _ = recv_frame(s)
        if ftype != FRAME_SETTINGS or sid != 0:
            raise RuntimeError(f"unexpected first frame type={ftype} sid={sid}")
        if (flags & FLAG_ACK) == 0:
            s.sendall(ack_settings)

        s.sendall(req_frame)
        while not got_end_stream:
            ftype, flags, sid, payload = recv_frame(s)
            if ftype == FRAME_SETTINGS and (flags & FLAG_ACK) == 0:
                s.sendall(ack_settings)
                continue
            if ftype == FRAME_PING and (flags & FLAG_ACK) == 0:
                s.sendall(build_frame(FRAME_PING, FLAG_ACK, 0, payload))
                continue
            if ftype == FRAME_GOAWAY:
                raise RuntimeError("received GOAWAY during stream backpressure test")
            if sid != args.stream_id:
                continue

            if ftype in (FRAME_HEADERS, FRAME_CONTINUATION):
                headers_block.extend(payload)
                if flags & FLAG_END_HEADERS:
                    decoded = decode_header_block(bytes(headers_block))
                    headers_block.clear()
                    for n, v in decoded:
                        if n == ":status":
                            status = int(v)
                if flags & FLAG_END_STREAM:
                    got_end_stream = True
                continue

            if ftype == FRAME_DATA:
                body.extend(payload)
                if not sent_window_update and len(body) >= args.initial_window:
                    s.sendall(
                        build_window_update(0, args.update_window)
                        + build_window_update(args.stream_id, args.update_window)
                    )
                    sent_window_update = True
                if flags & FLAG_END_STREAM:
                    got_end_stream = True
                continue
    finally:
        try:
            s.close()
        except Exception:
            pass

    text = body.decode("utf-8", "replace")
    print(f"status={status} body_len={len(body)} sent_window_update={sent_window_update}")
    print(f"has_chunk0={'chunk-000' in text} has_chunk9={'chunk-009' in text}")

    if status != 200:
        raise RuntimeError(f"unexpected status {status}")
    if not sent_window_update:
        raise RuntimeError("test did not enter backpressure phase")
    if "chunk-000" not in text:
        raise RuntimeError("expected stream payload not found")

    print("HTTP2 STREAM BACKPRESSURE TEST PASS")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import argparse
import json
import socket
import ssl
import urllib.request


H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_RST_STREAM = 0x3
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
    3: (":method", "POST"),
    4: (":path", "/"),
    5: (":path", "/index.html"),
    6: (":scheme", "http"),
    7: (":scheme", "https"),
    8: (":status", "200"),
    9: (":status", "204"),
    10: (":status", "206"),
    11: (":status", "304"),
    12: (":status", "400"),
    13: (":status", "404"),
    14: (":status", "500"),
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
        if (b & 0x40) == 0x40:
            prefix = 6
        else:
            prefix = 4
        idx, off = decode_int(block, off, prefix)
        if idx:
            name, _ = STATIC_TABLE.get(idx, (f"idx-{idx}", ""))
        else:
            name, off = decode_str(block, off)
        value, off = decode_str(block, off)
        headers.append((name, value))
    return headers


def open_client(args):
    raw = socket.create_connection((args.ip, args.port), timeout=4)
    raw.settimeout(3.0)
    if args.scheme == "https":
        ctx = ssl.create_default_context()
        if args.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if args.alpn_h2:
            ctx.set_alpn_protocols(["h2"])
        tls = ctx.wrap_socket(raw, server_hostname=args.sni or args.ip)
        if args.alpn_h2:
            selected = tls.selected_alpn_protocol()
            if selected != "h2":
                raise RuntimeError(f"ALPN selected={selected!r}, expected 'h2'")
        tls.settimeout(3.0)
        return tls
    return raw


def do_h2c_upgrade(sock: socket.socket, authority: str, path: str):
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {authority}\r\n"
        "Connection: Upgrade, HTTP2-Settings\r\n"
        "Upgrade: h2c\r\n"
        "HTTP2-Settings: AAIAAAAA\r\n"
        "\r\n"
    ).encode("ascii")
    sock.sendall(req)
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("upgrade response closed")
        data.extend(chunk)
        if len(data) > 16384:
            raise RuntimeError("upgrade response too large")
    head, _ = bytes(data).split(b"\r\n\r\n", 1)
    first = head.split(b"\r\n", 1)[0].decode("ascii", "replace")
    if "101" not in first:
        raise RuntimeError(f"unexpected upgrade status: {first}")


def fetch_stats(ip: str, port: int, scheme: str, insecure: bool):
    url = f"{scheme}://{ip}:{port}/debug/server-stats"
    ctx = None
    if scheme == "https":
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(url, timeout=5, context=ctx) as resp:
        data = json.loads(resp.read().decode("utf-8", "ignore"))
        return data.get("server", {})


def main():
    ap = argparse.ArgumentParser(description="HTTP/2 request/response smoke test")
    ap.add_argument("ip")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--scheme", choices=("http", "https"), default="http")
    ap.add_argument("--path", default="/debug/server-stats")
    ap.add_argument("--authority", default=None)
    ap.add_argument("--expect-status", type=int, default=200)
    ap.add_argument("--expect-substring", default="http2")
    ap.add_argument("--stream-id", type=int, default=None)
    ap.add_argument("--upgrade-h2c", action="store_true", default=False)
    ap.add_argument("--alpn-h2", action="store_true", default=False)
    ap.add_argument("--insecure", action="store_true", default=False)
    ap.add_argument("--sni", default=None)
    args = ap.parse_args()

    if args.upgrade_h2c and args.scheme != "http":
        raise RuntimeError("--upgrade-h2c is only valid with --scheme http")

    authority = args.authority or f"{args.ip}:{args.port}"
    stream_id = args.stream_id
    if stream_id is None:
        stream_id = 3 if args.upgrade_h2c else 1
    scheme_idx = 7 if args.scheme == "https" else 6

    hpack_req = b"".join(
        [
            bytes([0x82]),  # :method GET
            bytes([0x80 | scheme_idx]),  # :scheme
            encode_lit_idx_name(4, args.path),  # :path
            encode_lit_idx_name(1, authority),  # :authority
            encode_lit_name_value("user-agent", "viperhttp-h2-test"),
        ]
    )
    req_frame = build_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, stream_id, hpack_req)
    client_settings = build_frame(FRAME_SETTINGS, 0, 0, b"")
    ack_settings = build_frame(FRAME_SETTINGS, FLAG_ACK, 0, b"")

    status = None
    headers = []
    body = bytearray()
    hdr_block = bytearray()
    got_end_stream = False

    s = open_client(args)
    try:
        if args.upgrade_h2c:
            do_h2c_upgrade(s, authority, args.path)

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
                raise RuntimeError("received GOAWAY before response complete")
            if sid != stream_id:
                continue
            if ftype == FRAME_HEADERS or ftype == FRAME_CONTINUATION:
                hdr_block.extend(payload)
                if flags & FLAG_END_HEADERS:
                    headers = decode_header_block(bytes(hdr_block))
                    hdr_block.clear()
                    for n, v in headers:
                        if n == ":status":
                            try:
                                status = int(v)
                            except ValueError:
                                status = None
                if flags & FLAG_END_STREAM:
                    got_end_stream = True
            elif ftype == FRAME_DATA:
                body.extend(payload)
                if flags & FLAG_END_STREAM:
                    got_end_stream = True
            elif ftype == FRAME_RST_STREAM:
                err = None
                if len(payload) == 4:
                    err = (payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3]
                raise RuntimeError(f"received RST_STREAM err={err}")
            elif ftype == FRAME_WINDOW_UPDATE:
                continue
    finally:
        try:
            s.close()
        except Exception:
            pass

    body_text = body.decode("utf-8", "replace")
    print(f"stream={stream_id} status={status} headers={headers}")
    print(f"body_len={len(body)}")

    if status != args.expect_status:
        raise RuntimeError(f"unexpected status {status}, expected {args.expect_status}")
    if args.expect_substring and args.expect_substring not in body_text:
        raise RuntimeError(f"expected substring not found: {args.expect_substring!r}")

    try:
        stats = fetch_stats(args.ip, args.port, args.scheme, args.insecure)
        print(
            "stats http2_enabled={} preface_seen={} goaway_sent={} psram_slots={}".format(
                int(stats.get("http2_enabled", 0)),
                int(stats.get("http2_preface_seen", 0)),
                int(stats.get("http2_goaway_sent", 0)),
                int(stats.get("http2_psram_slots", 0)),
            )
        )
    except Exception as exc:
        print(f"stats_fetch_warning={exc!r}")

    print("HTTP2 REQUEST TEST PASS")


if __name__ == "__main__":
    main()

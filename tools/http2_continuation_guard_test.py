#!/usr/bin/env python3
import argparse
import json
import socket
import urllib.request


H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_SETTINGS = 0x4
FRAME_GOAWAY = 0x7

FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4
FLAG_ACK = 0x1

ERR_PROTOCOL = 0x1


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


def main():
    ap = argparse.ArgumentParser(description="HTTP/2 CONTINUATION ordering guard test")
    ap.add_argument("ip")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()

    # Minimal valid pseudo-header fragment (without END_HEADERS on purpose).
    header_frag = bytes([0x82, 0x86, 0x84])  # :method GET, :scheme http, :path /
    client_settings = build_frame(FRAME_SETTINGS, 0, 0, b"")
    ack_settings = build_frame(FRAME_SETTINGS, FLAG_ACK, 0, b"")
    bad_data = build_frame(FRAME_DATA, FLAG_END_STREAM, 3, b"x")

    got_goaway = False
    goaway_err = None
    stats_before = None
    stats_after = None

    def read_goaway_counter():
        url = f"http://{args.ip}:{args.port}/debug/server-stats"
        with urllib.request.urlopen(url, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        if isinstance(data, dict):
            if "http2_goaway_sent" in data:
                return int(data.get("http2_goaway_sent", 0))
            server_stats = data.get("server")
            if isinstance(server_stats, dict):
                return int(server_stats.get("http2_goaway_sent", 0))
        return 0

    try:
        stats_before = read_goaway_counter()
    except Exception:
        stats_before = None

    s = socket.create_connection((args.ip, args.port), timeout=4)
    s.settimeout(3.0)
    try:
        s.sendall(H2_PREFACE + client_settings)
        ftype, flags, sid, _ = recv_frame(s)
        if ftype != FRAME_SETTINGS or sid != 0:
            raise RuntimeError(f"unexpected first frame type={ftype} sid={sid}")
        if (flags & FLAG_ACK) == 0:
            s.sendall(ack_settings)

        # Start HEADERS and intentionally keep END_HEADERS unset.
        s.sendall(build_frame(FRAME_HEADERS, 0, 1, header_frag))
        # Violate RFC: send non-CONTINUATION frame while continuation is expected.
        s.sendall(bad_data)

        for _ in range(8):
            try:
                ftype, flags, sid, payload = recv_frame(s)
            except (ConnectionError, TimeoutError, OSError):
                break
            if ftype == FRAME_SETTINGS and (flags & FLAG_ACK) == 0:
                s.sendall(ack_settings)
                continue
            if ftype == FRAME_GOAWAY:
                got_goaway = True
                if len(payload) >= 8:
                    goaway_err = (
                        (payload[4] << 24)
                        | (payload[5] << 16)
                        | (payload[6] << 8)
                        | payload[7]
                    )
                break
    finally:
        try:
            s.close()
        except Exception:
            pass

    try:
        stats_after = read_goaway_counter()
    except Exception:
        stats_after = None

    print(f"goaway={got_goaway} err={goaway_err}")
    print(f"http2_goaway_sent before={stats_before} after={stats_after}")
    if got_goaway:
        if goaway_err != ERR_PROTOCOL:
            raise RuntimeError(f"expected GOAWAY PROTOCOL_ERROR({ERR_PROTOCOL}), got {goaway_err}")
    else:
        if stats_before is None or stats_after is None or stats_after <= stats_before:
            raise RuntimeError("expected GOAWAY evidence (frame or goaway counter increment)")
    print("HTTP2 CONTINUATION GUARD TEST PASS")


if __name__ == "__main__":
    main()

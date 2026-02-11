#!/usr/bin/env python3
import argparse
import json
import socket
import urllib.request


H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FRAME_SETTINGS = 0x4
FRAME_GOAWAY = 0x7
FRAME_WINDOW_UPDATE = 0x8

FLAG_ACK = 0x1

ERR_FLOW_CONTROL = 0x3


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


def read_stats(ip: str, port: int):
    url = f"http://{ip}:{port}/debug/server-stats"
    with urllib.request.urlopen(url, timeout=3) as resp:
        data = json.loads(resp.read().decode("utf-8", "replace"))
    server = data.get("server", {})
    return int(server.get("http2_goaway_sent", 0)), int(server.get("http2_err_flow_control", 0))


def main():
    ap = argparse.ArgumentParser(description="HTTP/2 WINDOW_UPDATE validation test")
    ap.add_argument("ip")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()

    goaway_before, flow_before = read_stats(args.ip, args.port)

    client_settings = build_frame(FRAME_SETTINGS, 0, 0, b"")
    ack_settings = build_frame(FRAME_SETTINGS, FLAG_ACK, 0, b"")
    bad_window_update = build_frame(FRAME_WINDOW_UPDATE, 0, 0, b"\x00\x00\x00\x00")

    got_goaway = False
    goaway_err = None

    s = socket.create_connection((args.ip, args.port), timeout=4)
    s.settimeout(3.0)
    try:
        s.sendall(H2_PREFACE + client_settings)
        ftype, flags, sid, _ = recv_frame(s)
        if ftype != FRAME_SETTINGS or sid != 0:
            raise RuntimeError(f"unexpected first frame type={ftype} sid={sid}")
        if (flags & FLAG_ACK) == 0:
            s.sendall(ack_settings)

        s.sendall(bad_window_update)
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

    goaway_after, flow_after = read_stats(args.ip, args.port)
    print(f"goaway_frame={got_goaway} goaway_err={goaway_err}")
    print(
        "stats goaway {}->{} flow_control {}->{}".format(
            goaway_before, goaway_after, flow_before, flow_after
        )
    )

    if got_goaway and goaway_err is not None and goaway_err != ERR_FLOW_CONTROL:
        raise RuntimeError(
            f"expected GOAWAY FLOW_CONTROL_ERROR({ERR_FLOW_CONTROL}), got {goaway_err}"
        )
    if goaway_after <= goaway_before or flow_after <= flow_before:
        raise RuntimeError("expected goaway/flow-control counters to increase")

    print("HTTP2 WINDOW_UPDATE VALIDATION TEST PASS")


if __name__ == "__main__":
    main()

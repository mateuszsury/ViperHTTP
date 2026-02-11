#!/usr/bin/env python3
import argparse
import json
import socket
import urllib.request


H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def recv_some(sock, max_bytes=128):
    out = b""
    while len(out) < max_bytes:
        try:
            chunk = sock.recv(max_bytes - len(out))
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk
    return out


def parse_frame_types(payload):
    types = []
    i = 0
    while i + 9 <= len(payload):
        length = (payload[i] << 16) | (payload[i + 1] << 8) | payload[i + 2]
        ftype = payload[i + 3]
        i += 9
        if i + length > len(payload):
            break
        types.append(ftype)
        i += length
    return types


def fetch_stats(ip, port):
    url = f"http://{ip}:{port}/debug/server-stats"
    with urllib.request.urlopen(url, timeout=5) as resp:
        data = json.loads(resp.read().decode("utf-8", "ignore"))
        return data.get("server", {})


def main():
    ap = argparse.ArgumentParser(description="HTTP/2 preface/goaway smoke test")
    ap.add_argument("ip")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--expect-goaway", action="store_true", default=False)
    args = ap.parse_args()

    s = socket.create_connection((args.ip, args.port), timeout=4)
    s.settimeout(0.8)
    try:
        s.sendall(H2_PREFACE)
        data = recv_some(s, max_bytes=96)
    finally:
        try:
            s.close()
        except Exception:
            pass

    types = parse_frame_types(data)
    has_settings = 4 in types
    has_goaway = 7 in types
    print(f"frames={types} raw_len={len(data)}")

    if args.expect_goaway:
        if not (has_settings and has_goaway):
            print("FAIL: expected SETTINGS+GOAWAY")
            return 1
    else:
        if has_goaway:
            print("FAIL: unexpected GOAWAY")
            return 1

    try:
        stats = fetch_stats(args.ip, args.port)
        print(
            "http2_enabled={} preface_seen={} goaway_sent={} psram_slots={}".format(
                int(stats.get("http2_enabled", 0)),
                int(stats.get("http2_preface_seen", 0)),
                int(stats.get("http2_goaway_sent", 0)),
                int(stats.get("http2_psram_slots", 0)),
            )
        )
    except Exception as exc:
        print(f"stats_unavailable={exc!r}")

    print("HTTP2 PREFACE TEST PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

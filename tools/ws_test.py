import json
import base64
import os
import socket
import struct
import sys
import time
import ssl
import argparse

host = "192.168.0.135"
port = 8080
scheme = "ws"
ssl_context = None


class _BufferedSock:
    def __init__(self, sock, prefetched=b""):
        self._sock = sock
        self._buf = prefetched or b""

    def recv(self, n):
        if self._buf:
            out = self._buf[:n]
            self._buf = self._buf[n:]
            return out
        return self._sock.recv(n)

    def sendall(self, data):
        return self._sock.sendall(data)

    def settimeout(self, timeout):
        return self._sock.settimeout(timeout)

    def close(self):
        return self._sock.close()


def recv_exact(sock, n):
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise RuntimeError("socket closed")
        out += chunk
    return out


def ws_connect(path):
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode("ascii")
    sock = socket.create_connection((host, port), timeout=5)
    if scheme == "wss":
        sock = ssl_context.wrap_socket(sock, server_hostname=host)
    sock.sendall(req)
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("Handshake failed: socket closed")
        resp += chunk
        if len(resp) > 65536:
            raise RuntimeError("Handshake failed: response too large")
    header, tail = resp.split(b"\r\n\r\n", 1)
    if b"101" not in header:
        raise RuntimeError("Handshake failed: " + header.decode("latin1", "ignore"))
    return _BufferedSock(sock, prefetched=tail)


def ws_send_text(sock, text):
    payload = text.encode("utf-8")
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    frame = bytes([0x81, 0x80 | len(payload)]) + mask + masked
    sock.sendall(frame)


def ws_recv_frame(sock):
    b1 = recv_exact(sock, 1)
    b2 = recv_exact(sock, 1)
    opcode = b1[0] & 0x0F
    masked = (b2[0] & 0x80) != 0
    length = b2[0] & 0x7F
    if length == 126:
        length = struct.unpack("!H", recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", recv_exact(sock, 8))[0]
    if masked:
        mask = recv_exact(sock, 4)
        payload = recv_exact(sock, length)
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    else:
        data = recv_exact(sock, length)
    return opcode, data


def ws_recv_text(sock, timeout_s=5):
    sock.settimeout(timeout_s)
    while True:
        opcode, data = ws_recv_frame(sock)
        if opcode == 1:
            return data.decode("utf-8", "ignore")
        if opcode == 8:
            return None


def ws_close(sock):
    try:
        close_payload = struct.pack("!H", 1000)
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(close_payload))
        close_frame = bytes([0x88, 0x80 | len(close_payload)]) + mask + masked
        sock.sendall(close_frame)
    except Exception:
        pass
    try:
        sock.close()
    except Exception:
        pass


def test_echo():
    sock = ws_connect("/ws/echo")
    try:
        ws_send_text(sock, "hi")
        text = ws_recv_text(sock)
        if text != "echo:hi":
            raise RuntimeError(f"Unexpected echo payload: {text!r}")
    finally:
        ws_close(sock)


def test_room_broadcast():
    a = ws_connect("/ws/room")
    try:
        text = ws_recv_text(a)
        msg = json.loads(text)
        if msg.get("event") != "connected":
            raise RuntimeError(f"Unexpected room connect message A: {text!r}")

        ws_send_text(a, "join:alpha")
        msg = json.loads(ws_recv_text(a))
        if msg.get("event") != "joined" or msg.get("room") != "alpha":
            raise RuntimeError(f"Unexpected join ack A: {msg!r}")

        ws_send_text(a, "say:hello")
        msg = json.loads(ws_recv_text(a))
        if msg.get("event") != "message" or msg.get("room") != "alpha" or msg.get("text") != "hello":
            raise RuntimeError(f"Unexpected broadcast payload: {msg!r}")

        ws_send_text(a, "stats")
        msg = json.loads(ws_recv_text(a))
        if msg.get("event") != "stats":
            raise RuntimeError(f"Unexpected stats payload: {msg!r}")
        data = msg.get("data", {})
        rooms = data.get("rooms", {})
        if int(data.get("connections", 0)) < 1:
            raise RuntimeError(f"Unexpected connection count: {msg!r}")
        if int(rooms.get("alpha", 0)) < 1:
            raise RuntimeError(f"Unexpected room count: {msg!r}")
    finally:
        ws_close(a)


def main():
    global host
    global port
    global scheme
    global ssl_context

    ap = argparse.ArgumentParser(description="WebSocket/WSS test for ViperHTTP")
    ap.add_argument("host", nargs="?", default="192.168.0.135")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--scheme", choices=["ws", "wss"], default="ws")
    ap.add_argument("--repeat", type=int, default=1, help="number of full ws test cycles")
    ap.add_argument("--insecure", action="store_true", default=False, help="disable TLS cert verification")
    args = ap.parse_args()

    host = args.host
    port = int(args.port)
    scheme = args.scheme
    if scheme == "wss":
        ctx = ssl.create_default_context()
        if args.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        ssl_context = ctx

    repeat = int(args.repeat)
    if repeat < 1:
        repeat = 1
    for i in range(repeat):
        test_echo()
        time.sleep(0.05)
        test_room_broadcast()
        if i + 1 < repeat:
            time.sleep(0.05)
    print("WS PASS")


if __name__ == "__main__":
    main()

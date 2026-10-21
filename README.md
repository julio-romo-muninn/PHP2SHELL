# PHP2SHELL — Verification Lab for CVE-2026-109618 / CVE-2026-109619

An **isolated Docker lab** to verify the two PHP RCE vulnerabilities published on
**21 October 2026** (patch released at 14:00 UTC), their real reach, and the
conditions under which they reproduce.

| | CVE-2026-109618 | CVE-2026-109619 |
|---|---|---|
| Official name | RCE via **OOM corruption** | RCE via **stale global state** |
| Advisory | GHSA-w8hw-w9fx-j79w | GHSA-6wmf-4rv5-p3rp |
| CVSS v4 | 9.2 | 9.2 |
| Affected versions | < 8.2.35, < 8.3.36, < 8.4.27, < 8.5.12 | same |
| Maximum risk | mod_php, FPM, php-cgi, FrankenPHP, LiteSpeed | same |

> **This repository contains research and verification tooling only.** Every PoC
> targets loopback inside the lab container, the forged handler is always planted
> at a poison address (`0x4141414141414141`), and the only command ever executed
> is `id`. See [Scope & safety](#scope--safety).

---

## Verdict at a glance

**CVE-2026-109619 is REPRODUCED with a clean vulnerable/patched differential** in
this lab: request 2 kills the worker with a SEGV in `tmp_var` (deserializer) on
8.4.26, and answers 200 without touching anything on 8.4.27. The official
mechanism is *cross-request*: global state owned by one request survives in the
worker after the heap is freed, and a **later** request consumes it before normal
initialisation. The OOM is the trigger.

**What does NOT hold up: the narrative that circulated before the release**
("stale bucket pointer" in `php_session_rfc1867_progress`, a spray of 149 `t[]`
fields, a forged `zend_fcall_info`). It is an accurate description of the code,
but its premise does not hold in released PHP, and the public PoC (~62 KB) **did
not achieve code execution** (reproduced here: HTTP 200, no ASAN, and the forged
handler pointing at `0x4141414141414141` was never interpreted).

| Scenario | Version | Result |
|---|---|---|
| **Real cross-request (2 requests, huge session + OOM)** | **8.4.26** | **worker dead: SEGV in `tmp_var` with ASAN trace** |
| Same | **8.4.27** | **HTTP 200, worker survives** — no ASAN |
| Canonical 258 B trigger (within a single request) | 8.4.4, 8.5.4 | HTTP 200, no ASAN |
| Published request shape (62,929 B, **poisoned** handler) | 8.4.4 | HTTP 200, no ASAN; the handler was never interpreted |
| Same, **ablated** build (without `Z_TRY_ADDREF(progress->data)`) | 8.4.4 | **ASAN heap-use-after-free** (`zend_array_count` ← serialize ← `php_session_flush` ← `update` ← `callback`) |
| OOM via huge field (variant of the trigger) | 8.4.26 / 8.4.27 | OOM at `main/rfc1867.c:632` on both; no UAF in the consumer |

**Second finding — patching is not enough.** Chain A (session file injection +
LFI sink) still yields **RCE with `uid=33(www-data)` on the patched 8.4.27**.
The patch fixes the memory corruption of 109618/109619 but does **not** close the
session file injection nor the body-borne session fixation. See
[docs/lab-report.md](docs/lab-report.md#6-rce-verified-chain-a-session-file-injection--lfi).

---

## Repository layout

```
.
├── Dockerfile                  # PHP built from source; ARGs: PHP_VERSION, PHP_SHA256,
│                               #   PHP_SAPI, ASAN, APPLY_ABLATION
├── docker-compose.yml          # everything parameterised through the environment
├── docs/
│   ├── lab-report.md           # full technical report (mechanism, results, limits)
│   └── vulnerability-mechanics.jpg
├── lab/
│   ├── php.ini                 # upload_progress On, freq=1, min_freq=0, cleanup=Off
│   ├── conf.d/99-lab-memory.ini# memory_limit=32M (for the OOM trigger)
│   ├── index.php               # victim endpoint (seeds the session)
│   ├── lfi.php                 # LAB-ONLY LFI sink (restricted to the session dir)
│   ├── _lab_mutator.php        # LAB-ONLY: mutates the live session file
│   └── start-lab.sh            # startup (CLI server or Apache/mod_php)
└── poc/
    ├── trigger_258.py                  # canonical 258 B trigger
    ├── trigger_published_shape.py      # published request shape (poisoned handler)
    ├── repro_109619_two_requests.py    # CVE-2026-109619: producer (OOM) + consumer
    ├── stale_state_cross_request.py    # variant: OOM via a huge field
    ├── upload_uaf_poc.py               # stalls + mutator + benign spray
    └── rce_chain_a_id.py               # Chain A: session injection + LFI -> `id`
```

---

## Quick start

```bash
# ASAN profile (UAF detection)
PHP_VERSION=8.4.26 PHP_SHA256=c248abaebc4bb777b80968f0760da0da8e989836e896c9ff637b6775d7d37662 \
LAB_TAG=8.4.26-asan ASAN=1 docker compose build && \
PHP_VERSION=8.4.26 LAB_TAG=8.4.26-asan docker compose up -d

# Non-ASAN profile (real OOM, Zend MM active)
PHP_VERSION=8.4.26 PHP_SHA256=c248abaebc4bb777b80968f0760da0da8e989836e896c9ff637b6775d7d37662 \
LAB_TAG=8.4.26-noasan ASAN=0 USE_ZEND_ALLOC=1 docker compose build && \
PHP_VERSION=8.4.26 LAB_TAG=8.4.26-noasan ASAN=0 USE_ZEND_ALLOC=1 \
PHP_CLI_SERVER_WORKERS=1 docker compose up -d

# Cross-request differential test (1 worker => producer and consumer share it)
python3 poc/repro_109619_two_requests.py
python3 poc/stale_state_cross_request.py --rounds 3

# Canonical trigger and published shape
python3 poc/trigger_258.py --self-test
python3 poc/trigger_published_shape.py

# Chain A: session file injection + LFI -> `id`
python3 poc/rce_chain_a_id.py

# ASAN reports
docker logs php-uaf-lab 2>&1 | grep -B5 -A45 AddressSanitizer
```

### Build arguments

| Argument | Values | Meaning |
|---|---|---|
| `PHP_VERSION` | `8.4.4`, `8.4.26`, `8.4.27`, `8.5.4`, `8.5.11`, `8.5.12` | PHP release to build |
| `PHP_SHA256` | official sha256 | checksum from <https://www.php.net/releases> |
| `PHP_SAPI` | `cli`, `apache` | embedded server vs Apache prefork + mod_php |
| `ASAN` | `0`, `1` | AddressSanitizer (no real `memory_limit`) vs real OOM |
| `APPLY_ABLATION` | `0`, `1` | removes `Z_TRY_ADDREF(progress->data);` to prove root cause |
| `USE_ZEND_ALLOC` | `0`, `1` | system malloc (ASAN sees UAFs) vs Zend MM (real `memory_limit`) |
| `PHP_CLI_SERVER_WORKERS` | `1`, `4` | **must be 1** for the cross-request test |

> **Compatibility note discovered in this lab:** with `USE_ZEND_ALLOC=0` PHP stops
> accounting for `memory_limit`, so an OOM cannot be provoked on an ASAN build.
> That is why there are two profiles: `ASAN=1 USE_ZEND_ALLOC=0` (intra-request UAF
> detection) and `ASAN=0 USE_ZEND_ALLOC=1` (the real 109619 OOM trigger).

---

## PoC index

| Script | Purpose | Risk |
|---|---|---|
| `poc/trigger_258.py` | Canonical 258 B single-request trigger | benign |
| `poc/trigger_published_shape.py` | Published request shape, poison handler | benign (poisoned) |
| `poc/repro_109619_two_requests.py` | **CVE-2026-109619** producer + consumer | OOM / crash |
| `poc/stale_state_cross_request.py` | Cross-request variant with a huge field | OOM / crash |
| `poc/upload_uaf_poc.py` | Stall + mutator + benign spray choreography | crash |
| `poc/rce_chain_a_id.py` | Chain A: injection + LFI → `id` | **code execution** (lab only) |

---

## Results in one paragraph

On 8.4.26 request 1 (upload progress + a session with 1,048,576 elements) OOMs
during startup (`array_init_size` exceeds `memory_limit`), `zend_bailout()` skips
`PHP_VAR_UNSERIALIZE_DESTROY` and the `BG(unserialize)` global keeps pointing at
the freed request heap; request 2 (upload progress, same worker) reuses that
pointer and the worker dies with `SEGV on unknown address 0x134 (READ)` in
`tmp_var` (`ext/standard/var_unserializer.c:168`). On 8.4.27 the same sequence
yields HTTP 500 then HTTP 200, and the worker survives. Full traces, the
mechanism walkthrough and the limitations are in
[docs/lab-report.md](docs/lab-report.md).

---

## Mitigation summary

- **Update** to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 — the only complete fix
  ("There are no complete mitigations, updating is the only safe choice").
- `session.upload_progress.enabled=0` **administratively** (php.ini, pool or
  server config applied **before** request parsing; not `ini_set()`, not
  `.user.ini`) **and restart every worker**.
- On PHP 8.5: `fatal_error_backtraces=0` plus a worker restart (removes the
  backtrace producer).
- Remove attacker-reachable fatal errors (including timeouts) and pre-init INI
  diagnostics.
- Server/proxy limits: decoded body size, number of fields, multipart parts,
  headers and nesting depth.
- `post_max_size` low (8M without uploads, 32M with), `upload_max_filesize`
  below `post_max_size`; generous or unlimited `memory_limit`.
- Container/cgroup as the availability boundary (not `RLIMIT_AS`).
- Consider `pm.max_requests=1` on FPM.
- Log auditing: `log_errors=On`, working `error_log`, `error_reporting=E_ALL`;
  look for repeated warnings/deprecations before the script, fatal errors and
  `Maximum execution time exceeded`.
- Public detection rules: `break-the-build/php-uploadprogress-waf`.
- **Application side:** fix any `include()`/`require()` on the session file, and
  reject a body-supplied `PHPSESSID`.

---

## Documentation

- [docs/lab-report.md](docs/lab-report.md) — full technical report: official
  mechanism, differential testing, the Chain A RCE, residual risk, known
  limitations and provenance.
- [docs/vulnerability-mechanics.jpg](docs/vulnerability-mechanics.jpg) — the
  original "2a/2b/2c" description of the vulnerability mechanics (the narrative
  this lab partially disproves).

---

## Scope & safety

- Everything runs inside the Docker lab; the PoCs bind to `127.0.0.1` only.
- `poc/trigger_published_shape.py` never computes real addresses: the forged
  handler is planted at `0x4141414141414141`, so an accidental interpretation
  would crash the worker instead of executing code.
- `poc/rce_chain_a_id.py` executes exactly one command, `id`, and refuses to run
  against anything other than loopback.
- `lab/lfi.php` only includes files matching `/tmp/sessions/sess_*` inside the
  container.
- `lab/_lab_mutator.php` is a lab-only helper and must never be exposed.
- No external system was contacted: all experiments ran against locally built
  PHP binaries.

---

## Provenance

- Official advisory: `php.net/archive/2026.php#2026-10-21-5` (21 Oct 2026).
- GHSA-6wmf-4rv5-p3rp (CVE-2026-109619) and GHSA-w8hw-w9fx-j79w
  (CVE-2026-109618) in `php/php-src/security/advisories`.
- Code: official tags `php-8.4.4`, `8.4.26`, `8.4.27`, `8.5.4`, `8.5.11`, `8.5.12`
  and the `session.c` file from the Ubuntu package (Launchpad).
- Public audit: `xuehuolll/CVE-2026-109618-109619-audit` (same ablation
  experiment, same verdict on the intra-request UAF).
- Published request shape: `Zer061/CVE-2026-109618` and `0ldbaby/php2shell`,
  re-implemented here with a **poisoned** handler.
- Detection rules: `break-the-build/php-uploadprogress-waf`.
- Context: GMO Flatt Security blog (21 Oct 2026), watchTowr FAQ, CERT-EU
  2026-018.

## License

MIT — see [LICENSE](LICENSE).

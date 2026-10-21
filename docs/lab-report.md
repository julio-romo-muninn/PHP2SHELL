# Lab report — CVE-2026-109618 / CVE-2026-109619 ("php2shell")

**Target:** PHP `ext/session` upload-progress handler (`session.upload_progress`,
RFC1867 callback) — cross-request use-after-free leading to RCE.
**Patch under test:** 8.4.26 (vulnerable) vs 8.4.27 (patched).
**Method:** differential testing with AddressSanitizer on locally built PHP
binaries. No external system was contacted.

---

## 1. Lab verdict

**CVE-2026-109619 is REPRODUCED with a clean vulnerable/patched differential**
in this lab: request 2 leaves the worker dead with a SEGV in `tmp_var`
(deserializer) on 8.4.26, and answers 200 without touching anything on 8.4.27.
The official mechanism is *cross-request*: global state owned by one request
survives in the worker after the heap is freed, and a **later** request consumes
it before normal initialisation. The OOM is the trigger.

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

---

## 2. Official mechanism (reading the patched code)

The 8.4.27 fix in `ext/session/session.c` states it explicitly:

```c
/* The upload progress handler (php_session_rfc1867_update()) decodes and
 * re-encodes the session during request startup, before RINIT, when no user
 * code may run. Objects are then kept as __PHP_Incomplete_Class: no
 * autoloading, no unserialize_callback_func, no __wakeup() or __unserialize(),
 * and they are written back unchanged. */
static void php_session_unserialize_init(php_unserialize_data_t *var_hash)
{
    PHP_VAR_UNSERIALIZE_INIT(*var_hash);
    if (PS(in_rfc1867_update)) {
        php_var_unserialize_set_incomplete_classes_only(*var_hash, true);
    }
}
```

And the advisory (GHSA-6wmf-4rv5-p3rp) describes the lifecycle:

1. **Producer**: the upload progress hook decodes the session **during startup,
   before RINIT**. That state (session and decoder) is owned by the request.
2. An **OOM** (or another fatal error) after it is published prevents the
   corresponding reset → PHP frees the request heap while the worker's
   persistent global still points to it.
3. **Consumer**: a later request served by **the same worker** reaches that
   state (another upload-progress operation, or a pre-initialisation INI
   diagnostic) and treats it as valid → **use-after-free** → with a
   controlled heap layout: **RCE**.

Confirmations from the advisory itself: "Session upload progress lifecycle:
confirmed"; "PHP 8.5 fatal error backtrace: confirmed" (the mod_php exploitation
basis is demonstrated); producer and consumer in **different HTTP requests** of
the same worker.

CVE-2026-109618 is the other side of the coin: OOM handling can interrupt PHP
with half-initialised request data, and the cleanup treats invalid data as
valid. The 8.4.27 release is therefore a global OOM-hardening campaign
(`ZEND_HAS_OOM()`, `delayed_oom`, `memory_hard_limit_percent`,
`zend_mm_oom_info_dtor`, and hundreds of new `oom_*.phpt` tests).

### What is NOT the bug (the pre-release narrative)

The "2a/2b" mechanics of the image (two `zval*` cached in the progress struct)
**are** an accurate description of the code — verified on 8.4.4 / 8.4.26 / 8.5.4 /
8.5.11 and in the Ubuntu package — but the premise that the decoded tree frees
the cached arrays **does not hold in released PHP**:

```c
progress->cancel_upload |= php_check_cancel_upload(progress);
Z_TRY_ADDREF(progress->data);      /* <-- the switch */
zend_hash_update(Z_ARRVAL_P(sess_var), progress->key.s, &progress->data);
```

`zend_hash_update()` moves the zval **without** an addref (`ZVAL_COPY_VALUE`),
so that line is what gives the progress array its own reference: with it,
`track_init()` frees the **deserialised copy** and not the live array, and the
cached pointers never dangle. Without it (ablation), the same 258-byte request
produces the UAF immediately — reproduced here with a stack trace matching the
published one.

---

## 3. Lab structure

```
.
├── Dockerfile                  # PHP from source; ARGs: PHP_VERSION, PHP_SHA256,
│                               #   PHP_SAPI, ASAN, APPLY_ABLATION
├── docker-compose.yml          # everything through the environment
├── docs/
│   ├── lab-report.md           # this document
│   └── vulnerability-mechanics.jpg
├── lab/
│   ├── php.ini                 # upload_progress On, freq=1, min_freq=0, cleanup=Off
│   ├── conf.d/99-lab-memory.ini# memory_limit=32M (for the OOM trigger)
│   ├── index.php               # victim endpoint (seeds the session)
│   ├── lfi.php                 # LAB-ONLY LFI sink
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

Build highlights:

- `--enable-address-sanitizer` + `--enable-debug` → symbolised traces.
- `USE_ZEND_ALLOC=0` at runtime: without it, Zend's own allocator hides the
  `emalloc` UAFs from ASAN.
- **Compatibility issue discovered in this lab:** with `USE_ZEND_ALLOC=0` PHP
  stops accounting for `memory_limit` → it is impossible to provoke an OOM on an
  ASAN build. That is why there are two profiles: `ASAN=1 USE_ZEND_ALLOC=0`
  (intra-request UAF detection) and `ASAN=0 USE_ZEND_ALLOC=1` (the real 109619
  OOM trigger).
- `APPLY_ABLATION=1` → removes `Z_TRY_ADDREF(progress->data);` to validate the
  detector's sensitivity and pin down the root cause.

---

## 4. Execution

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
python3 poc/trigger_258.py
python3 poc/trigger_published_shape.py

# Chain A
python3 poc/rce_chain_a_id.py
```

---

## 5. Differential test results (8.4.26 vs 8.4.27)

### 5.1 CVE-2026-109619 reproduction (cross-request) — SUCCESSFUL

Sequence: request 1 = multipart with `PHP_SESSION_UPLOAD_PROGRESS` and a
**huge session** (1,048,576 elements) whose decode OOMs during startup
(`array_init_size` > `memory_limit`) → `zend_bailout()` skips the
`PHP_VAR_UNSERIALIZE_DESTROY` → the `BG(unserialize)` global keeps pointing at
the freed heap; request 2 = upload-progress multipart **on the same worker** →
the deserializer reuses the freed pointer.

| Version | Request 1 | Request 2 | ASAN |
|---|---|---|---|
| **8.4.26 (vulnerable)** | HTTP 500 (OOM) | **no response: worker dead** | `SEGV on unknown address 0x134` with full trace |
| **8.4.27 (patched)** | HTTP 500 (OOM) | **HTTP 200**, the worker survives | no report |

Trace of the vulnerable case (matches the public reproduction
`santihabib/CVE-2026-109619`, with per-version line offsets):

```
==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000134 (READ)
    #0 tmp_var                 ext/standard/var_unserializer.c:168
    #1 var_tmp_var             ext/standard/var_unserializer.c:190
    #2 ps_srlzr_decode_php     ext/session/session.c:1134
    #3 php_session_decode      ext/session/session.c:279
    #4 php_session_initialize  ext/session/session.c:502
    #5 php_session_rfc1867_update  ext/session/session.c:3196
    #6 php_session_rfc1867_callback ext/session/session.c:3381
    #7 rfc1867_post_handler    main/rfc1867.c:1273
   #10 php_auto_globals_create_post main/php_variables.c:818
```

This establishes a **cross-request UAF with a clean vulnerable/patched
differential** in this lab.

### 5.2 Cross-request test with an OOM in the field (variant)

Alternative sequence: request 1 = upload progress + file field (publishes the
state) + huge field (OOM at `main/rfc1867.c:632`, i.e. already inside the
rfc1867 processing) → request 2 = upload progress on the same worker.

| Build | Profile | Producer (OOM) | Consumer (UAF) |
|---|---|---|---|
| 8.4.26 (vulnerable) | `ASAN=0, USE_ZEND_ALLOC=1` | **HTTP 500** — `Allowed memory size of 33554432 bytes exhausted at main/rfc1867.c:632` | HTTP 200, no crash |
| 8.4.27 (patched) | `ASAN=0, USE_ZEND_ALLOC=1` | **HTTP 500** — same OOM | HTTP 200, no crash |

Reading: the field-sized OOM reproduces, but the state that survives is not the
one the second request consumes: the stale global is **`BG(unserialize)`** (from
the deserializer), and it is published when the session is **decoded**, not when
the body is parsed. That is why the variant that does reproduce is the one in
§5.1 (§5.2 is kept for its value as a check of the OOM trigger).

Notes:

- The producer and the consumer **must land on the same worker**: with
  `PHP_CLI_SERVER_WORKERS=1` that is guaranteed (on real FPM it depends on the
  pool).
- The OOM requires a real `memory_limit` → non-ASAN profile or
  `USE_ZEND_ALLOC=1` (with `USE_ZEND_ALLOC=0` PHP does not account for it).
- **Decisive detail of the reproduction:** the consumer's small session must be
  written **out of band** (`docker exec` or direct volume access). If it is
  planted with an HTTP request, that request is served by the same worker and
  its normal RINIT **resets the stale state** (`BG(unserialize)`) before the
  consumer arrives → the consumer answers 200 and there is no crash. This is the
  nuance behind the "almost reproduces" false negatives.
- The upload-progress "consumer" acts **before** RINIT: that is why the 8.4.27
  fix changes the behaviour of the decode in that phase (`incomplete classes
  only`).

---

## 6. RCE verified (Chain A: session file injection + LFI)

**Reproduced end to end with `uid=33(www-data)`:**

1. `POST multipart/form-data` with `PHPSESSID` **in the body** (session
   fixation: the `MULTIPART_EVENT_FORMDATA` handler does not check
   `use_only_cookies`) and a file field whose **name** carries PHP code.
2. The rfc1867 handler stores the name **unsanitised** in the session file.
3. An `include()` of that file (LFI sink) executes the injected PHP.

| Scenario | Result |
|---|---|
| 8.4.26 (vulnerable) | **RCE: `uid=33(www-data)`** |
| 8.4.27 (patched) | **RCE: `uid=33(www-data)`** — the chain is still live |
| 8.4.27 + `session.upload_progress.enabled=Off` | **blocked** |

**Operational implication:** the patch fixes the memory corruption of
109618/109619 but **does not close the session file injection nor the
body-borne session fixation** (fix PR #22113 is not part of 8.4.27). Patching is
not enough: the `session.upload_progress.enabled=Off` mitigation must be applied
on top, and application-level LFI issues must be fixed.

---

## 7. What is actually exploitable in released PHP (residual risk)

Verified in this lab: the canonical request creates the session file with the
**attacker-chosen SID** and writes attacker-controlled bytes inside it:

```
/tmp/sessions/sess_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
upload_progress_x|a:5:{s:10:"start_time";...;s:5:"files";a:1:{i:0;a:7:{
   s:4:"name";s:1:"a"; ...}}}
```

1. **Session fixation**: the attacker chooses the SID (`PHPSESSID` field in the
   body, not in a cookie).
2. **Content injection** into the session file (the progress key and the file
   name are written literally).
3. **RCE only with an application sink**: if the app `include()`s the session
   file, the injected bytes are executed.

Mitigations (per the official advisory and this lab's own verification):

- **Update** to 8.4.27 / 8.5.12 / 8.3.36 / 8.2.35: the only complete solution
  ("There are no complete mitigations, updating is the only safe choice").
- `session.upload_progress.enabled=0` **administratively** (php.ini, pool or
  server configuration applied **before** request parsing; not `ini_set()`, not
  `.user.ini`) **and restart every worker**: it cuts the confirmed session
  routes, not the others.
- On PHP 8.5: `fatal_error_backtraces=0` plus a worker restart (removes the
  backtrace producer).
- Remove attacker-reachable fatal errors (including timeouts) and pre-init INI
  diagnostics.
- Server/proxy limits: decoded body size, number of fields, multipart parts,
  headers and nesting depth.
- `post_max_size` low (8M without uploads, 32M with) and `upload_max_filesize`
  below `post_max_size`; generous or unlimited `memory_limit`.
- Container/cgroup as the availability boundary (not `RLIMIT_AS`).
- Consider `pm.max_requests=1` on FPM.
- Log auditing: `log_errors=On`, working `error_log`,
  `error_reporting=E_ALL`; look for repeated warnings/deprecations before the
  script, fatal errors, `Maximum execution time exceeded`.
- Public detection rules (Suricata/ModSecurity/nginx-njs) in
  `break-the-build/php-uploadprogress-waf`.

---

## 8. Known limitation

The `PHP_SAPI=apache` variant (Apache prefork + mod_php, the SAPI of the
exploitation video) **does not complete**: the from-source build with
`--with-apxs` does not produce the `apache2handler` module in this image and
Apache fails to start. The code path exercised
(`rfc1867_post_handler` → `php_session_rfc1867_callback` → `update`) is
identical on any SAPI, but the advisory demonstrates exploitation on **mod_php**
and **FPM**, and on FPM the exact sequence differs (FPM kills the child if
startup fails), so the lab environment (CLI server) does not cover those two
exact paths.

---

## 9. Cleanup

```bash
docker compose down -v --rmi local
```

---

## 10. Provenance

- Official advisory: `php.net/archive/2026.php#2026-10-21-5` (21 Oct 2026).
- GHSA-6wmf-4rv5-p3rp (CVE-2026-109619) and GHSA-w8hw-w9fx-j79w
  (CVE-2026-109618) in `php/php-src/security/advisories`.
- Code: official tags `php-8.4.4`, `8.4.26`, `8.4.27`, `8.5.4`, `8.5.11`,
  `8.5.12` and the `session.c` file from the Ubuntu package (Launchpad).
- Public audit: `xuehuolll/CVE-2026-109618-109619-audit` (same ablation
  experiment, same verdict on the intra-request UAF).
- Published request shape: `Zer061/CVE-2026-109618` and `0ldbaby/php2shell`,
  re-implemented here with a **poisoned** handler.
- Detection rules: `break-the-build/php-uploadprogress-waf`.
- Context: GMO Flatt Security blog (21 Oct 2026), watchTowr FAQ, CERT-EU
  2026-018.
- All experiments were run against locally built PHP binaries inside Docker,
  without contacting external systems. The lab does not implement any RCE
  chain: the forged handler is always planted at a poison address.

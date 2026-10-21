# Security Policy

## Scope

This repository is a **verification lab and research artefact** for
CVE-2026-109618 and CVE-2026-109619, the PHP `session.upload_progress`
vulnerabilities published on 21 October 2026 (fixed in 8.2.35 / 8.3.36 / 8.4.27 /
8.5.12).

It intentionally contains:

- a Docker lab that builds PHP from source with AddressSanitizer,
- PoC scripts that reproduce the crash / use-after-free conditions,
- one PoC (`poc/rce_chain_a_id.py`) that demonstrates a session-file injection
  reaching an `include()` sink.

## Safety rules baked into the code

| Rule | Where |
|---|---|
| The PoCs only target `127.0.0.1` / loopback | all `poc/*.py` |
| The forged handler is always planted at the poison address `0x4141414141414141` | `poc/trigger_published_shape.py` |
| No address calculation, no ASLR bypass, no shellcode | `poc/trigger_published_shape.py` |
| The only command ever executed is `id`, and the PoC refuses non-loopback targets | `poc/rce_chain_a_id.py` |
| The LFI sink only includes `/tmp/sessions/sess_*` inside the container | `lab/lfi.php` |
| The session mutator is a lab-only helper and must not be exposed | `lab/_lab_mutator.php` |

## Intended use

Reproducing the published vulnerabilities on systems you own or are authorised to
test, in the isolated Docker lab provided here.

## Out of scope / not provided

- Working exploits against real-world heap layouts.
- Guidance for attacking third-party systems.
- Bypassing detection rules or post-exploitation tooling.

## Reporting

If you find a problem in this repository (a broken lab, an inaccurate claim in
the report, or code that could escape the loopback-only scope), please open an
issue or contact the maintainer privately.

Upstream PHP security issues must be reported to the PHP security team, not
here — see <https://www.php.net/security/>.

## License

MIT — see [LICENSE](LICENSE).

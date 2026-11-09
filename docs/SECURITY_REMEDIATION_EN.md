# Security review and remediation report

## Scope and release status

Repository: PRVTPRO/Amnezia-Web-Panel. Baseline: `f90cc5c` (1.7.0).
Its embedded data contains **18 groups / 30 occurrences**, all reviewed. Report line numbers refer to the scanned revision, not current source. Review includes additional local authentication/security findings.

**Status: fixes in the local working tree, not committed, published, deployed or rescanned by ScanGit.** “Fixed” below means locally implemented and regression-tested, not closed by the scanner. This is a bounded source review, not a comprehensive penetration test or a guarantee that the application has no vulnerabilities.

## ScanGit findings disposition

| Group (zero-based) | Finding / occurrences | Assessment and action |
|---|---|---|
| 0 | Insecure HTTP / 1 | Fixed loopback ngrok API (`127.0.0.1:4040`), not external cleartext transport. No remote transport vulnerability established. Unchanged. |
| 1 | Unrestricted file upload / 1 | Administrator-only JSON restore, not an arbitrary executable upload. Hardened with a 32 MiB bounded read, object validation and malformed-encoding handling. Multipart parsing happens earlier: proxy/body limits remain required. |
| 2 | Cookie missing HttpOnly / 1 | Language preference, not an authentication secret. Defense-in-depth fix: HttpOnly enabled. |
| 3 | Cookie missing Secure / 1 | Language preference. Secure enabled on HTTPS; HTTP localhost operation deliberately preserved. This does not enforce HTTPS globally or change the session-cookie policy. |
| 4 | Telemt curl SSRF / 1 | Arbitrary destination SSRF not established: destination is fixed loopback. A real shell-argument injection boundary was found and fixed: quote each argument, disable URL globbing and use `--` before URL. |
| 5 | Critical command injection / 1 | Reported `taskkill` invocation uses an argument list without a shell. The indicated occurrence does not establish shell injection. Not relabeled as a repaired critical vulnerability. |
| 6 | Path traversal / 5 | Flagged reads use local translations, fixed application paths, allowlisted tunnel providers and fixed archive output filenames. Archive member names are not used as extraction destinations in this tunnel path. No request-controlled traversal established at these occurrences. |
| 7 | Template XSS / 7 | Generic template/redirect/response sinks are not proof of XSS. Jinja autoescaping and fixed redirects cover the reported ordinary cases. The language Referer redirect was a real open redirect, now restricted to a same-origin local path. No claim that all client-side/template XSS has been exhaustively excluded. |
| 8 | AST path traversal / 2 | `/proc` enumeration of process entries, not request-controlled paths. No web traversal established. |
| 9 | Predictable temporary paths / 2 | Fixed SSH privileged staging: atomic private `mktemp -d` directories, quoted paths and finally cleanup. Also fixed destination injection in privileged uploads and checked move failure. |
| 10 | click 8.3.1 / 1 | CVE-2026-7246 is disputed in its CNA/project record; application use of `click.edit` was not found. Pin unchanged; not counted as confirmed application injection. |
| 11 | cryptography 44.0.0 / 1 | Updated to 44.0.1 for the reported bundled-OpenSSL issue CVE-2024-12797. **Additional newer cryptography advisories remain open**; this is not a clean dependency bill of health. |
| 12 | Flask 3.1.0 / 1 | Updated to 3.1.3. Reported CVE-2025-47278 fixed from 3.1.1. Flask/fallback-key feature use not found in this FastAPI application. |
| 13 | idna 3.11 / 1 | Updated to 3.15, covering CVE-2026-45409, including alternate label/codec paths. |
| 14 | Paramiko 3.5.1 / 1 | **Open**: CVE-2026-44405, legacy RSA SHA-1 negotiation. Fix commit is included in 5.0.0; major-version upgrade or algorithm restrictions require testing against managed servers. No silent compatibility-breaking change. |
| 15 | Pillow 12.1.1 / 1 | Updated to 12.3.0, covering reported CVE-2026-42311 and additional identified Pillow fixes. Untrusted PSD decoding was not found in current application paths. |
| 16 | python-multipart 0.0.20 / 1 | Updated to 0.0.32, covering reported CVE-2026-53539 and later identified parser fixes. |
| 17 | Starlette 0.46.2 / 1 | Updated to 0.49.1 with compatible FastAPI 0.120.1; fixes reported CVE-2025-62727 Range-header DoS and multipart blocking fix. **Newer Starlette advisories remain open**, see below. |

AnyIO additionally updated from 4.12.1 to 4.14.2 for identified newer advisories. Unrelated pins were not mass-upgraded.

## Additional implemented fixes

- **Disabled/record-only accounts:** existing cookie sessions no longer authorize disabled users or `role=none`. Legacy missing-enabled defaults remain supported.
- **Configuration ownership:** ordinary-user access now matches server, client ID, protocol family and instance. Legitimate AWG aliases remain supported. Only explicit administrator/support roles bypass ownership. The original cross-instance disclosure required a coincident client ID.
- **CAPTCHA disclosure/replay:** answers are no longer stored in client-readable signed cookies. Cookies carry opaque random IDs; answers stay in a locked, bounded, server-side store. Five-minute TTL, single-use consumption, refresh invalidation and maximum 4,096 entries. Failed attempts consume the challenge.
- **Public-share password changes:** revision-bound authorization invalidates old share sessions after password changes/clearing or disabling sharing. Stable share URLs and passwordless sharing are preserved. Legacy Boolean authorization cookies require reauthentication.
- **Language redirect/input:** rejects unsupported languages and off-site Referer redirects while preserving valid local path/query navigation.
- **Backup validation:** malformed JSON encodings and non-object roots return client errors, with no data writes.

The earlier `/sw.js` bundled-resource fix remains in the working tree and was regression-tested; it is not counted as a security closure.

## Independent review follow-up

Independent review identified another retained high-risk issue in remote backup downloads: predictable `/tmp/<filename>` staging exposed archive secrets and allowed a conditional symlink attack. Fixed by allocating a private mode-0700 directory owned by the SSH/SFTP user before the privileged copy. Remote cleanup now runs from the outer finally block, including local-temp and SFTP-open failures, and cleanup failures are logged. Two new regression tests failed before this change and pass afterward. The review's sudo-test fixture blocker was also resolved as described below. The final follow-up itself was locally tested, not subjected to a second independent review.

## Verification

- Focused combined run: **59 tests passed**, zero failures/errors (auth, CAPTCHA, managers, share, web hardening, scanner trust-boundary tests, PWA resource paths and sudo-password regression).
- Full suite: **459 tests**, `failures=1, errors=9, skipped=1`. These final failure names match existing baseline server-template failures; baseline `HEAD` run had 401 tests with the same 1 failure / 9 errors / 1 skip. A separate earlier AWG randomized-default failure was also observed, not attributed to this patch.
- `uv pip check --python .venv/Scripts/python.exe`: all 42 installed packages compatible.
- `git diff --check` passes after normalizing requirements line endings.
- Existing password-leak test fixture was adapted to the new `mktemp` command and now checks every executed command for password disclosure, not merely the last command.
- Validation is local/in-process and mocked SSH, not a live managed-server test. No frozen EXE or Linux/macOS build was exercised. No external attack traffic was sent to deployed panels.

## Open risks and deployment notes

1. **Do not declare all dependencies clean.** Newer cryptography fixes require a larger migration (audit candidate 50.0.0); newer Starlette fixes include Windows UNC static-file handling, method dispatch and URL-encoded form limits (audit candidate Starlette 1.3.1 with compatible FastAPI). These were deliberately not silently installed under the minimal-change scope. Windows EXE deployments should treat the static-file issue as a priority follow-up, not a false positive.
2. Paramiko legacy algorithms and `AutoAddPolicy` host-key trust need compatibility-tested hardening. No live SSH compatibility certification is claimed.
3. Remote backup extraction symlink/hardlink containment needs a separate design review; a post-extraction path check is not a sufficient general guarantee. Administrator-only access limits but does not eliminate the risk of importing an untrusted archive.
4. CAPTCHA storage assumes **one application worker/process**. Multiple workers require shared TTL storage with atomic consumption (or equivalent design); restarts invalidate outstanding challenges. Rate limiting remains separate and flooding can evict valid challenges.
5. Configure HTTPS and reverse-proxy request limits. The JSON restore limit bounds application reads, not all multipart ingestion/disk usage before endpoint authorization.
6. Password changes for ordinary panel accounts are not given general session-version revocation by this patch. Disabled-user enforcement is immediate while the account is disabled; global session revocation remains separate work.
7. Existing `server.html` rendering/JavaScript test failures remain unresolved and prevent a claim that the complete suite passes.
8. Before release: review local diff, test SSH against representative root/sudo hosts, test login/sharing/CAPTCHA and restore with a disposable backup, rebuild Windows/Linux/macOS artifacts, then rerun ScanGit. Preserve a rollback backup. Nothing was pushed automatically.

## Advisory references

- https://github.com/encode/starlette/security/advisories/GHSA-7f5h-v6xp-fcq8
- https://github.com/pyca/cryptography/security/advisories/GHSA-79v4-65xg-pq4g
- https://github.com/kjd/idna/security/advisories/GHSA-65pc-fj4g-8rjx
- https://github.com/advisories/GHSA-4grg-w6v8-c28g
- https://github.com/advisories/GHSA-r374-rxx8-8654
- https://github.com/advisories/GHSA-pwv6-vv43-88gr
- https://github.com/advisories/GHSA-5rvq-cxj2-64vf

Dependency applicability was compared to advisory version ranges; an affected installed version is not by itself proof of a remotely exploitable application path. Some supplementary upstream API queries were rate-limited; this is not an exhaustive current/transitive CVE audit.

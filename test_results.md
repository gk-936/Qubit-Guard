# Qubit-Guard — Verification Record

**Date**: 2026-07-31
**Scope**: Direct function-level and API-level verification of the backend, plus a
frontend build check.

This document records **only checks that were actually executed**, with their observed
output. Section 3 lists what has *not* been verified. No overall score is given: there is
no automated test suite, so any single figure would imply coverage that does not exist.

---

## 1. Checks Executed

### 1.1 TLS probe — real certificate retrieval
`_get_tls_info("github.com")`:

| Field | Observed |
| :--- | :--- |
| Common Name | `github.com` |
| Issuer | `Sectigo Limited` |
| Cipher suite | `TLS_AES_128_GCM_SHA256` |
| TLS version | `TLSv1.3` |
| Key exchange | `ECDHE` (group: not exposed by this Python runtime) |
| Certificate key | `ECDSA-256`, read from the certificate public key |
| Expiry | `Sep 30 23:59:59 2026 GMT` |

**Result**: PASS. Live certificate data retrieved over a real handshake.

**Regression note**: before the current fix this same host reported
`key_exchange: RSA` and `auth: RSA`, scoring QVS 100. TLS 1.3 cipher suite names encode
neither the key exchange nor the authentication algorithm, so inferring them from the
suite name misclassified every TLS 1.3 host as RSA. Authentication is now read from the
certificate's public key.

### 1.2 Cipher suite parsing — TLS 1.2
| Input | Key exchange | Auth |
| :--- | :--- | :--- |
| `ECDHE-RSA-AES256-GCM-SHA384` | ECDHE | RSA |
| `ECDHE-ECDSA-AES128-GCM-SHA256` | ECDHE | ECDSA |

**Result**: PASS. Suite-name parsing is retained for TLS 1.2, where it is authoritative.

### 1.3 Pillar A — reachable host
`_scan_web_tls("github.com")` → QVS **85**, `scanned: True`, handshake 94 ms.

Findings: `info` certificate detected · `high` quantum-vulnerable key exchange (ECDHE) ·
`high` quantum-vulnerable certificate key (ECDSA-256).

**Result**: PASS.

### 1.4 Pillar A — unreachable host
`_scan_web_tls("nonexistent-host-xyz.invalid")` → QVS **None**, `scanned: False`,
one `info` finding: *"TLS Probe Failed — Host Not Assessed"*.

**Result**: PASS. No cryptographic claim is made about a host that was never reached.

**Regression note**: this path previously emitted three fabricated findings
("Assumed RSA-2048 Certificate (Industry Default)", "Classical ECDHE Key Exchange
Assumed") at critical/high severity and scored QVS 100 — indistinguishable from a real
measurement.

### 1.5 QVS severity mapping
| Input | Score |
| :--- | :--- |
| `RSA-2048` | 100 |
| `ECDHE-RSA` | 90 |
| `ECDSA-256` | 85 |
| `ECDHE` | 85 |
| `ML-KEM-768` | 0 |

**Result**: PASS. `ECDHE-RSA` previously scored 100 because lookup matched substrings in
dictionary order and hit `RSA` first; matching is now longest-key-first.

### 1.6 Full Triad scan — reachable target
`perform_triad_scan("github.com", ...)`:
- `riskScores`: web 85 · vpn 85 · api 90 · firmware 90 · archival 85 · **overall 87**
- `pillarsAssessed`: 5
- Selector latency input: **78 ms**, source `"measured TLS handshake"`
- Firmware pillar device type `IoT` → recommended `FN-DSA-512`

**Result**: PASS. Selector inputs are now scan-derived rather than fixed constants;
bandwidth remains a constant and is labelled `"assumed — not measurable from a TLS
handshake"`.

### 1.7 Full Triad scan — unreachable target
`riskScores`: web **null** · vpn 75 · api 90 · firmware 75 · archival 75 ·
**overall 79**, `pillarsAssessed: 4`.

**Result**: PASS. The unassessable pillar is excluded from the mean rather than
contributing a default score.

### 1.8 Email — SMTP not configured
`send_scan_report()` with empty `SMTP_USER` / `SMTP_PASS`
→ `(False, "NOT_CONFIGURED")`, console logs `NO EMAIL SENT`.

API response: `success: false`, `delivered: false`, message *"Report generated but NOT
sent to {email} — SMTP credentials are not configured on the server. Use Download PDF to
retrieve it."*

**Result**: PASS. Previously this path returned success and the UI displayed
*"Professional PQC audit report generated and sent to {email}"* when no email had been
sent.

### 1.9 Startup — missing `JWT_SECRET`
Importing `security.py` with `JWT_SECRET` unset raises:
`RuntimeError: JWT_SECRET is not set. Refusing to start with a fallback signing key.`

**Result**: PASS. The previously committed fallback signing key is gone.

### 1.10 Authentication enforcement
Unauthenticated requests:

| Status | Endpoint |
| :--- | :--- |
| 200 | `GET /api/health` *(open by design)* |
| 401 | `GET /api/data/dashboard` |
| 401 | `GET /api/data/inventory` |
| 401 | `GET /api/data/cbom` |
| 401 | `GET /api/scan/history` |
| 401 | `GET /api/pqc/algorithms` |
| 401 | `GET /api/pqc/audit` |
| 401 | `GET /api/scheduler/list` |
| 401 | `GET /api/mobile/search` |
| 401 | `GET /api/data/cbom/export/json` |
| 401 | `POST /api/discovery/` |
| 401 | `POST /api/remediation/chat` |

Authenticated session: login `200` → protected endpoints `200` with a bare token and with
a `Bearer` prefix. Garbage token → `401`. Wrong password → `401`.

**Result**: PASS. All of the above returned 200 unauthenticated before this change;
authentication was enforced only in the React client.

### 1.11 Frontend build
`npm run build` — succeeds, 1963 modules transformed. Two pre-existing warnings
(chunk size, a mixed static/dynamic import) unrelated to these changes.

**Result**: PASS.

---

## 2. Domain Resolution Check

`pnb.bank.in`, `manipurrural.bank.in` and `bankofbaroda.in` were confirmed to resolve in
DNS. **They were not scanned.** No cryptographic result for any bank domain is claimed in
this document.

---

## 3. Not Verified

The following are explicitly **untested**. Do not represent them as working.

1. **No automated test suite exists.** `run_tests.py` invokes a virtualenv path that does
   not exist on any machine but the one it was authored on; `test_pqc.py` requires a
   running server; `test_discovery.py` did not complete within 5 minutes. All three fail
   the same way on unmodified code. Verification above was performed by direct function
   and API calls.
2. **No UI testing.** The 14 pages have not been click-tested in a browser. Only the
   production build was verified.
3. **Bank target domains have not been scanned** in this cycle.
4. **Email delivery with working SMTP credentials** — only the unconfigured path was
   exercised. A real send has not been observed.
5. **Sarvam AI chat** — not exercised; no API key was used.
6. **Scheduler** — no scheduled job was observed firing end to end.
7. **Pillars B, C, D and E** were exercised only as part of a full scan, not verified
   individually against known-good targets.
8. **CBOM output has not been validated** against the CycloneDX 1.5 JSON schema.
9. **Concurrency and load** — untested. SQLite has no retry/backoff, so concurrent writes
   are expected to surface as "database is locked".

---

## 4. Assessment

**Verified working**: TLS probing and certificate parsing, QVS mapping and aggregation,
the not-assessed path, scan-derived selector inputs, honest email failure reporting,
server-side authentication, and the frontend build.

**Principal risk**: none of it is protected by automated tests. Every check in section 1
was run by hand and would need re-running by hand after the next change. Standing up a
pytest suite around sections 1.1–1.10 is the highest-value next step, and would let a
figure like "95/100" mean something.

---
**Status**: Verification record for the codebase as of 2026-07-31.

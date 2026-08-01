# Qubit-Guard — Code Review Findings

Independent read-only review. No code was changed. Line references are against the repo as reviewed
(HEAD `0dc4a54` + 4 uncommitted working-tree files).

**Summary:** Real, working prototype — roughly 40% of it genuinely does what it says. Real TLS handshakes,
real CT-log discovery, real scheduler, real PDFs, real LLM call, real DB, and a frontend with zero mock data.
The blockers are three small surgical fixes, not a rewrite. The bigger job is making the docs and feature
names match what the code actually does.

---

## Status

Findings below are recorded **as found**. The following have since been fixed in the working tree
(Tier 1); everything else is still open.

| # | Item | Status |
|---|---|---|
| 1 | Email "Demo Mode" fakes delivery | ✅ Fixed |
| 2 | Failed TLS scan fabricates critical findings | ✅ Fixed |
| 3 | Every TLS 1.3 host falsely reported as RSA | ✅ Fixed |
| 7 | Fabricated dataset citations | ✅ Fixed |
| 16 | PQC selector gets hardcoded inputs | ✅ Fixed |
| 4 | No server-side auth on any endpoint | ✅ Fixed |
| 5 | Hardcoded JWT fallback secret | ✅ Fixed |
| 13 | Docs say Gemini, code uses Sarvam | ✅ Fixed |
| 26 | `test_results.md` self-graded 95/100 | ✅ Rewritten |
| 27 | `functionalities.md` / `content.md` overclaim | ✅ Rewritten |
| 20 | Dead Node/Express codebase | ✅ Deleted |
| 21 | Other dead code (`entropy.py`, stale JSON) | ✅ Deleted |
| 18 | Seed data indistinguishable from real data | ✅ Fixed |
| 17b | `DELETE /inventory/{purl}` always 404s | ✅ Fixed |
| 19 | 11+ silently swallowed exceptions | ✅ Fixed (17 sites, typed + logged) |
| 6 | "ML Selector" mislabeled as Random Forest | ✅ Renamed (rule-table ensemble) |
| 8 | "PQC engine" mislabeled as executing crypto | ✅ Docstring corrected (registry) |
| 9, 10 | Firmware/Archival inferred verdicts unlabeled | ✅ Fixed (`evidence` field added) |
| 11 | Android mobile results copy iOS silently | ✅ Fixed (tagged `derived-from-ios`) |
| 14 | CBOM hardcoded crypto/version fields | ✅ Fixed (derived or `"unknown"`) |
| 15 | QVS aggregation comment said "weighted" | ✅ Verified already correct |
| 17 | VPN/API pillar tagging pure hostname guess | ✅ Fixed (probes upgrade to evidence) |
| 23 | Cosmetic fake scan-progress timers | ✅ Removed |
| 24 | No SQLite retry/backoff | ✅ Fixed (WAL + busy_timeout + retry helper) |
| 28 | CORS wildcard + credentials (invalid combo) | ✅ Fixed (origin allowlist) |
| 30 | Emailed reports defaulted missing QVS to 75 | ✅ Fixed (+ inverted risk-level bug found & fixed) |
| 🆕 | Mobile scanner asserted crypto for unreachable apps | ✅ Fixed (found during #19 sweep, same pattern as #2) |
| 🆕 | `check_zone_transfer` crashed on every real domain | ✅ Fixed (regression from #19's exception narrowing, caught before merge) |
| 🆕 | `schedules` table missing 5 columns — `python main.py` crashed at startup | ✅ Fixed (`ensure_schema()` now diffs every table generically) |
| 🆕 | `/api/scan/triad` uncapped per-host probing — real scans could hang for minutes | ✅ Fixed (capped to 6 hosts; 2m30s+ hang → 57s) |
| 🆕 | `uvicorn reload=True` watching `*.db-wal` thrashed the worker mid-request | ✅ Fixed (off by default, `RELOAD=true` opt-in) |
| 🆕 | 401 interceptor reloaded on any 401 → infinite reload loop on the login page | ✅ Fixed (only reloads if the request actually carried a token) |
| 🆕 | `reportlab`/`bcrypt` used but undeclared in `requirements.txt` | ✅ Fixed (pinned to verified-working versions) |
| 🆕 | `/api/data/dashboard` 500s whenever a scan pillar was left unassessed | ✅ Fixed (found while re-auditing after the mobile PQC-score fix) |
| 🆕 | `get_algorithm()` substring check backwards — PQC Selector's FIPS/OID card never rendered | ✅ Fixed |
| 🆕 | Selector could pick an algorithm outside the requested pillar's family, contradicting its own rationale text | ✅ Fixed (pillar-consistency guard) |
| 🆕 | "Weekly" schedule saved + showed success but registered no job — silently never ran | ✅ Fixed |
| 🆕 | "Once" schedule used a recurring cron trigger — ran forever, not once | ✅ Fixed (`date` trigger + deactivates after firing) |
| 12, 22, 25 | — | Open (playbook labelling, test suite, venv note — non-blocking for submission) |

Two related defects were found and fixed while doing the above, because the Tier 1 changes would
otherwise have surfaced them: `_qvs()` matched substrings in dict order so `ECDHE-RSA` scored as
`RSA` (100) instead of 90; and `Rating.jsx` used `overall \|\| 0`, which turned an unassessed scan
into a perfect **1000/1000 "Elite-PQC Status"**.

---

## Live end-to-end verification (2026-08-01)

Every fix in this document was previously verified via `TestClient` (in-process, no real server) or
direct function calls. `TestClient` did not catch four of the seven items marked 🆕 above — they only
surfaced when the app was actually booted with `python main.py` and driven through a real browser.
**If you only test through `TestClient`, do that final pass through the real server and a real
browser before treating anything as submission-ready** — it is not equivalent.

Confirmed working, live, via `python main.py` + `npm run dev` + a real browser:
- Login → dashboard → Triad Scan against `github.com` → real results (QVS 87, 5/5 pillars, 143 real
  discovered API endpoints, correct TLS 1.3 certificate parsing) in ~57s.
- Unauthenticated requests correctly 401; CORS correctly rejects a foreign origin.
- Report send correctly reports "generated but NOT sent" when SMTP times out (verified against real
  configured SMTP credentials, not a mock).
- Seeded demo data is now empty of test noise (`scan_results` table cleared before handoff).

---

## 🔴 P0 — Reports success for work not actually done

### 1. Email "Demo Mode" fakes delivery — `services/mail_service.py:917-919`
- On SMTP refusal/timeout, returns `True, "Demo Mode (Network Blocked)"`. No email is sent.
- With blank credentials (`:882-887`), prints to console and returns `True, "Simulated"`.
- `routers/data.py:429` then shows the user: `"Professional PQC audit report generated and sent to {email}"`.
- A `simulated: true` flag is returned alongside, but the visible message still says "sent".
- **Fix:** make the user-facing message reflect the flag.

### 2. Failed TLS scan fabricates critical findings — `services/scanner_engine.py:213-237`
- The `except` block appends 3 invented findings (`"Assumed RSA-2048 Certificate (Industry Default)"`,
  `"Classical ECDHE Key Exchange Assumed"`) at `critical`/`high` severity and pushes QVS 100/100/85.
- An unreachable host yields max-severity results indistinguishable from measured ones.
- **Fix:** report unreachable as unreachable. Do not assume.

---

## 🟠 P1 — Correctness bug that invalidates the main metric

### 3. Every TLS 1.3 host is falsely reported as RSA — `services/scanner_engine.py:114-123`
- `key_exchange`/`auth_algo` are derived by substring-matching the cipher suite name, defaulting to `"RSA"`.
- TLS 1.3 suite names (`TLS_AES_256_GCM_SHA384`) encode neither KX nor auth → every TLS 1.3 target scores QVS 100 (critical).
- **Verified live:** github.com returns `"key_exchange": "RSA"` on a connection actually using X25519.
- `cryptography` is already in `requirements.txt` — read the cert's real public-key algorithm instead.
- Note: 2 of the 3 "verified" scans in `test_results.md` are TLS 1.3, so those documented results are wrong.

---

## 🟡 P2 — Security

### 4. No server-side auth on any endpoint except login
- Real bcrypt + HS256 JWT exist in `routers/auth.py`, but **no router outside it uses an auth dependency**.
  All 26 endpoints are open.
- `/verify` (`auth.py:50-59`) is never used as a dependency.
- CORS is `*` for origins/methods/headers (`main.py:46-52`).
- Auth is enforced only in React (`ProtectedRoute.jsx`).
- Two pages bypass the axios interceptor and send no token at all — `Discovery.jsx:41`,
  `PQCSelector.jsx:46,54,63`. They work because nothing checks.

### 5. Hardcoded JWT fallback secret in tracked source — `routers/auth.py:19`
- `os.getenv("JWT_SECRET", "pnc_secret_key_2026_top_secret")`
- Good news: real `.env` is correctly gitignored, and no secrets were found in git history.

---

## 🟡 P2 — Features named as something they aren't

### 6. "ML Selector" is not ML — `services/ml_selector.py`
- No sklearn/torch. Hand-rolled Gini decision tree (`:305`) over a **140-row hardcoded Python list authored
  by hand** (`:81-237`). Deterministic stride, not bootstrap sampling (`:334-336`).
- Functionally an if/else threshold table. It works — just call it a rule engine.

### 7. Fabricated dataset citations — `services/ml_selector.py:13-16`, `:467`
- Claims *"Sovereign Indian datasets… AIKosh… DST National PQC Testing & Certification Program (2026)…
  I4C Cybercrime."* **None of these are loaded anywhere.**
- Highest-priority docs fix — this is the kind of claim that collapses under a single Q&A question.

### 8. "6 PQC algorithms implemented" is a metadata table — `services/pqc_algorithms.py:17-247`
- Static dict of byte sizes/OIDs/cycle counts. No liboqs, no pqcrypto, zero crypto operations performed.
- Fine as a reference table; not an "engine".

### 9. Pillar D (Firmware) never touches firmware — `scanner_engine.py:481`
- Verdict is inferred from the website's TLS cert. The code admits it:
  `"[Inferred from observed PKI]… Organizations typically use the same CA hierarchy for firmware code-signing"`.

### 10. Pillar E (Archival) same pattern — `scanner_engine.py:584`
- Real cloud-SSE header check happens, but the archival conclusion is borrowed from the TLS pillar.

### 11. Android mobile results are copies of iOS — `services/mobile_scanner.py:52`
- `# we simulate the Android counterparts for the found iOS apps` — same dict duplicated with platform swapped.
- iOS side is real: live iTunes Search API.

### 12. Remediation playbooks are templates, not AI-generated — `services/remediation_service.py:9-236`
- 7 static script templates with `{WEB}`/`{VPN}`/`{ALGO}` string-substituted. No LLM call in this file.
- The LLM is only in the `/chat` endpoint.

### 13. Docs say Gemini, code uses Sarvam
- `content.md:57` and `instruction.md:30` (`GEMINI_API_KEY`) — that env var is read nowhere.
- Actual call is `httpx` → `api.sarvam.ai`, model `sarvam-105b` (`ai_service.py:14-15,72-89`).
- Credit where due: the no-API-key path fails honestly rather than faking a response (`:59-60`).

### 14. CBOM mobile crypto is hardcoded — `services/cbom_generator.py:117`
- `"crypto": "Classical (RSA/ECC)", # Mobile apps in prototype default to classical for audit contrast`
  — set regardless of actual findings.
- Component versions are placeholder `"1.0"` (`:43,72`). Schema shape itself is valid CycloneDX 1.5.

### 15. QVS is a lookup table, not a formula — `scanner_engine.py:29-92`
- `{"RSA":100,"ECC":85,...}` substring match, else 75.
- Overall score is a plain unweighted mean despite the comment saying "weighted" (`:658-662`).

### 16. PQC selector gets hardcoded inputs on every scan — `scanner_engine.py:664-674`
- `bandwidth_kbps=50000, latency_ms=10, device_type="Server"` passed for every target regardless of what
  was measured. This silently makes the selector's per-scan output meaningless.

### 17. Discovery pillar tagging is filename-based — `discovery_service.py:207-215`
- `"vpn" in host.lower()` → tagged `SSL-VPN (Inferred)`. No protocol verification. Same for `api`.

### 17b. `DELETE /inventory/{purl}` is unreachable for real purls — `routers/data.py`
- Found while verifying #18. Package URLs always contain `/` (`pkg:pypi/pyjwt@2.8.0`), but
  `purl` is a plain path parameter, so the router never matches and every delete returns
  **404**. Verified: deleting `pkg:test/provenance-check@1` returned 404 and the row survived.
- The "Delete" control in the Inventory UI therefore cannot work for any seeded or
  realistically-named component.
- Fix: declare the parameter as `{purl:path}`, or accept the purl in the request body /
  as a query parameter.

---

## 🟢 P3 — Code hygiene

### 18. Seeded fake data is indistinguishable from real data — `seed_data.py:46-71`
- Invented severity counts (`critical=2847, high=3120, medium=1881`), 13 fixed CBOM rows.
- **No `source`/`is_seed` column** — nothing in the API or UI distinguished shipped demo
  rows from real ones, so the dashboard presented fabricated figures as measurements.

> **Correction to the original finding.** This entry first claimed seed and scan rows
> "co-mingle once a real scan runs". That is wrong: scans persist to `ScanResult` as JSON
> and are read live; **no code path writes scan output into these 5 tables**. The only
> writers are `seed_data.py` and the manual `POST /inventory/add`. The defect was real —
> demo data was indistinguishable and unlabelled — but it was never corrupted by scans.

### 19. 11 silently swallowed exceptions
- Bare `except:` — `mail_service.py:47,147`, `worker.py:137`
- `except Exception: pass` — `api_scanner.py:76`, `discovery_service.py:65,111,202`,
  `mobile_scanner.py:87,109`, `scanner_engine.py:396,426,461,564`

### 20. Dead parallel Node/Express codebase — 1,436 lines still committed
- `backend/server.js`, `backend/routes/*.js`, `backend/services/*.js`, plus `server/` and root `package.json`
  (10 npm deps). Superseded by the Python backend. Safe to delete.

### 21. Other dead code
- `services/entropy.py` — seeds `random.Random` from a domain hash; **imported nowhere**.
- `database/users.json` / `scans.json` — vestigial from the pre-SQLite design; no code reads them.

### 22. No CI, no test framework
- 3 ad-hoc scripts totalling 158 lines (`test_discovery.py`, `test_pqc.py`, `test_refactor.py`).
  `npm test` → `exit 1`. No `.github/workflows`.
- `scratch/verify_perfection.js`, `scratch/verify_baseline.py` are self-validation scripts, not tests.

### 23. Cosmetic fake progress — `TriadScanner.jsx:82-86`
- Two 400ms sleeps printing "Probing Web/TLS endpoints…" / "Analyzing VPN gateway protocols…" *before*
  the real request fires. Harmless but easy to remove.

### 24. SQLite concurrency — `db.py:12-25`
- No retry/backoff; concurrent writes surface as "database is locked". Not corrupting, but will bite under load.

### 25. Committed venv is machine-specific
- `backend/venv` points at `C:\Users\sudhan\...` — broken on any other machine. (Gitignored, so local-only artifact.)

---

## 📄 Docs need rewriting

### 26. `test_results.md`
Self-awards 95/100, claims "ALL buttons verified functional" and that results "matched manual openssl probes."
Its own TLS 1.3 rows are exactly the case bug #3 gets wrong.

### 27. `functionalities.md` / `content.md`
Describe Gemini, an ML engine, OSINT firmware analysis, and a "proprietary ML dataset" that don't match the code.

---

## ✅ What's genuinely solid — worth saying out loud

- **Real TLS handshakes** — `socket`+`ssl`, live cert/cipher/version. Verified working live.
- **Real CT-log OSINT** — actual `crt.sh` query (`discovery_service.py:115-134`) + real AXFR attempt (`:47-67`).
- **Discovery filters its guesses honestly** — 95-word subdomain list, but `socket.gethostbyname` drops
  non-resolving names (`:141-144`). Guesses are never reported as findings. Many tools get this wrong.
- **Pillar C (API/JWT) is fully real** — genuine base64 header decode + PQC OID/alg check.
- **Real IKEv2 port probing** on 500/4500.
- **Real iTunes Search API** for iOS apps.
- **Real APScheduler** — cron jobs persisted, reloaded from DB at boot, actually execute scans (`worker.py:148-182`).
- **Real reportlab PDFs**, plus a hand-rolled raw-PDF fallback — genuinely impressive bit of work.
- **Real bcrypt + JWT**, real SQLite persistence.
- **Frontend is clean** — all 14 pages hit live endpoints, no mock data arrays, zero `Math.random()`
  in the entire frontend. Better than most projects at this stage.

---

## ⚠️ Uncommitted work already fixes some of this

4 files in the working tree are moving in the right direction and are **not yet committed** —
HEAD is worse than what's on disk:

| File | Change |
|---|---|
| `seed_data.py` | `"212,450"` assets → `"0"`, `"755/1000"` → `"N/A"`, `8248` vulns → `0` |
| `routers/data.py` | `"ssl": ssl_cnt or 8761` and `"iot": 3854` → real DB counts |
| `scanner_engine.py` | API metrics `"total": 5 + len(findings)`, `"REST Endpoints": 3` → derived from actual findings |
| `mobile_scanner.py` | hardcoded 11-app mock DB → live iTunes API |

**Commit these.**

---

## Suggested order

1. #2 and #1 — stop fabricating findings and fake email success
2. #3 — fix TLS 1.3 KX/auth detection (the metric everything else depends on)
3. #16 — pass real measured inputs to the selector
4. #7 — delete the fabricated dataset citations
5. #4 — add auth dependencies to the routers
6. Commit the working-tree cleanup
7. Rename #6/#8 honestly, rewrite the three docs
8. Delete the dead Node stack (#20) and dead modules (#21)

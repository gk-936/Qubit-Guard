# Qubit-Guard — 3-Tier Architecture

Qubit-Guard follows a classic **3-tier architecture**: a React presentation
tier, a FastAPI application tier, and a SQLite data tier, with a background
worker for scheduled jobs sitting inside the application tier. This document
maps each tier to the actual modules in the repo.

```
┌─────────────────────────────────────────────────────────────┐
│  PRESENTATION TIER — React 18 + Vite (localhost:5173)        │
│  frontend/src/                                               │
└───────────────────────────┬────────────────────────────────┘
                             │ HTTPS/HTTP + JSON
                             │ Authorization: Bearer <JWT>
┌───────────────────────────▼────────────────────────────────┐
│  APPLICATION TIER — FastAPI + Uvicorn (localhost:5006)       │
│  backend/main.py, routers/, services/                        │
│                                                               │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │ Routers      │  │ Services      │  │ Background Worker  │  │
│  │ (HTTP layer) │─▶│ (business     │  │ (APScheduler)       │  │
│  │              │  │  logic)       │  │                     │  │
│  └─────────────┘  └──────┬───────┘  └──────────┬──────────┘  │
└─────────────────────────┼─────────────────────┼──────────────┘
                           │ SQLAlchemy ORM       │
┌──────────────────────────▼─────────────────────▼─────────────┐
│  DATA TIER — SQLite (WAL mode)                                │
│  backend/database/quantumshield.db                            │
└─────────────────────────────────────────────────────────────┘
                           │
                           │ outbound only
┌──────────────────────────▼─────────────────────────────────┐
│  EXTERNAL SYSTEMS (not a tier — third-party services reached  │
│  by the application tier during scans)                        │
│  Scan targets (TLS) · crt.sh · iTunes API · Sarvam AI · SMTP  │
└───────────────────────────────────────────────────────────────┘
```

---

## 1. Presentation Tier

**Location**: [frontend/](frontend/) · **Stack**: React 18, React Router 7, Vite 8, Chart.js, Axios

Responsible for rendering the dashboard, capturing user input (scan targets,
schedules, remediation queries), and calling the application tier's REST API.
Holds no business logic — every number displayed is either fetched from the
backend or computed client-side purely for display formatting.

| Concern | Implementation |
|---|---|
| Routing | `react-router-dom`, one route per page in [App.jsx](frontend/src/App.jsx) |
| Pages | 14 route components in `frontend/src/pages/` — Home, TriadScanner, CBOM, Inventory, Discovery, MobileScanner, Posture, PQCSelector, QDaySimulator, Rating, Remediation, Reporting, History, OwaspAudit |
| API client | [api.js](frontend/src/api.js) — Axios instance, pulls JWT from `localStorage`, sets `Authorization: Bearer <token>` on every request, plus `X-Scan-Id` for scan-scoped calls |
| Auth state | `frontend/src/context/` — session/login state shared across routes |
| Charts | Chart.js via `react-chartjs-2` for QVS scores, posture breakdowns, CBOM severity |
| Markdown rendering | `react-markdown` for the AI remediation chat's responses |
| Build/dev server | Vite — `npm run dev` (localhost:5173, or `--host` for LAN access) |

**Auth model**: token-based, not cookie-based. `allow_credentials=False` is set
on the backend CORS middleware deliberately (see [main.py](backend/main.py))
because the frontend never relies on cookies — this also sidesteps the
CORS spec's invalid wildcard-origin + credentials combination.

---

## 2. Application Tier

**Location**: [backend/](backend/) · **Stack**: FastAPI, Uvicorn (ASGI), SQLAlchemy 2.0, APScheduler

This tier is split into three internal layers:

### 2a. HTTP layer — Routers

[backend/routers/](backend/routers/), each mounted in [main.py](backend/main.py):

| Router | Responsibility |
|---|---|
| `auth.py` | Login, JWT issuance — the only routes not behind `require_auth` (plus `/api/health`) |
| `scan.py` | Triggers the Triad Scanner against web/VPN/API targets |
| `discovery.py` | Asset discovery (crt.sh, DNS zone transfer, subdomain probing) |
| `mobile.py` | Mobile app search (iTunes API) + backend TLS probing |
| `pqc_selector.py` | PQC Smart Selector recommendation endpoint |
| `remediation.py` | Remediation playbooks + AI chat proxy (Sarvam AI) |
| `scheduler.py` | CRUD for scheduled scans (feeds the background worker) |
| `data.py` | Dashboard/inventory/posture/CBOM read endpoints |

Every router except `auth` and `/api/health` is wrapped in
`Depends(require_auth)` at the app level ([main.py](backend/main.py):23) —
authentication is enforced server-side, not just hidden by the React client.

### 2b. Business logic — Services

[backend/services/](backend/services/), called by routers, contain all actual
scanning and analysis logic:

| Service | Responsibility |
|---|---|
| `scanner_engine.py` (971 lines) | Core Triad Scanner — live TLS handshakes, certificate parsing via `cryptography`, QVS scoring for web/VPN/API/firmware/archival pillars |
| `discovery_service.py` | crt.sh certificate-transparency lookups, DNS zone transfer, dictionary subdomain probing |
| `mobile_scanner.py` | iTunes Search/Lookup API + reuses `scanner_engine`'s crypto-derivation and QVS logic for app backend TLS probes |
| `ml_selector.py` (515 lines) | PQC Smart Selector — rule-table decision-tree ensemble over latency/bandwidth/device-tier/compliance inputs |
| `pqc_algorithms.py` | Reference registry of PQC algorithms (ML-KEM, ML-DSA, SLH-DSA, FN-DSA, XMSS/LMS, BIKE/HQC) per NIST FIPS 203/204/205 |
| `cbom_generator.py` | CycloneDX 1.5 CBOM generation from real scan findings |
| `remediation_service.py` | Expert-authored fix-template selection (Bash/Nginx/Python) |
| `ai_service.py` | Sarvam AI (`sarvam-105b`) chat integration via `httpx` |
| `mail_service.py` (1001 lines) | SMTP report dispatch, honest failure reporting |
| `audit_service.py` | Audit-trail logging for scans/actions |
| `worker.py` | APScheduler wiring — see below |

### 2c. Background processing — Scheduler/Worker

[services/worker.py](backend/services/worker.py) runs an `AsyncIOScheduler`
(APScheduler) inside the same process as the API server, started from the
FastAPI `lifespan` hook ([main.py](backend/main.py):34-35). It:
- Loads active `Schedule` rows from the data tier on startup
- Fires `run_automated_scan_and_email()` on each schedule's cron trigger
- Reuses the same `scanner_engine`, `cbom_generator`, `remediation_service`, and `discovery_service` functions the interactive API routes use — no duplicated scan logic between manual and scheduled scans
- Calls `mail_service.send_scan_report()`, which reports delivery failure honestly rather than silently

This is an **in-process** worker, not a separate service — there is no message
queue or task broker. It shares the FastAPI process's memory and the same
SQLAlchemy `SessionLocal`.

### Server/security concerns

| Concern | Implementation |
|---|---|
| Auth | JWT (`python-jose`/`pyjwt`), bcrypt password hashing (`passlib`) |
| CORS | Explicit origin allowlist via `CORS_ORIGINS` env var; no wildcard; credentials off (see [main.py](backend/main.py):55-93) |
| Secrets | `JWT_SECRET` mandatory from environment — server refuses to boot without it, no committed fallback key |
| ASGI server | Uvicorn (`standard` extras — includes `uvloop`/`httptools` where available) |

---

## 3. Data Tier

**Location**: [backend/db.py](backend/db.py), [backend/models.py](backend/models.py) · **Stack**: SQLite 3 (via SQLAlchemy 2.0 ORM), WAL mode

### Storage engine choice

SQLite was chosen for a single-server hackathon/audit-tool deployment profile —
no separate database server to provision, file-based backup, zero-config. Two
concurrency hardening measures are applied on every connection
([db.py](backend/db.py):42-86):

- **`PRAGMA journal_mode=WAL`** — readers (dashboard queries) proceed concurrently with a single writer (an in-progress scan), instead of blocking on SQLite's default exclusive rollback-journal lock
- **`PRAGMA busy_timeout=5000`** — a connection that finds the DB locked retries internally for up to 5s instead of raising immediately
- **`PRAGMA synchronous=NORMAL`** — the standard WAL companion; trades a small durability window (last transaction lost on power-loss-at-exact-checkpoint) for materially faster writes, an acceptable trade for a locally-hosted scan-results DB
- **`PRAGMA foreign_keys=ON`** — referential integrity enforced

A `with_retry()` helper ([db.py](backend/db.py):98-157) exists for callers that
need extra resilience against lock contention beyond what `busy_timeout`
covers, using exponential backoff on genuine "database is locked"/"busy" errors
only — other errors are never swallowed.

### Schema

[models.py](backend/models.py) — 8 tables:

| Table | Purpose |
|---|---|
| `users` | Login credentials (bcrypt hash), role |
| `dashboard_summary` | Home dashboard key/value stats |
| `inventory_stats` | Asset inventory counts by category (ssl, software, iot, logins) |
| `posture_stats` | Security posture metrics |
| `cbom_vulnerability_summary` | CBOM findings grouped by severity |
| `cbom_items` | Individual CBOM entries (component, algorithm, quantum-safe flag, risk, PURL) |
| `scan_results` | Full scan record — findings/risk-scores/CBOM/API-metrics as JSON blobs, plus `overall_qvs` |
| `schedules` | Scheduled-scan configuration (frequency, targets, email, report type) consumed by `worker.py` |

**Provenance tracking**: five tables carry a `source` column
(`seed`/`scan`/`manual`) so the UI can distinguish shipped demo data from a
real measurement — see `_PROVENANCE_TABLES` in [db.py](backend/db.py):160-167.

**Migrations**: `ensure_schema()` ([db.py](backend/db.py):170-229) is a
lightweight idempotent migrator run at startup — it `ALTER TABLE ADD COLUMN`s
anything the ORM models declare that's missing from the on-disk file, so an
older `quantumshield.db` from a previous version doesn't need a manual migration
step. NOT NULL columns without a safe default are logged, not auto-added.

### Scaling note

SQLite's single-writer model is adequate for this app's actual write pattern
(one scan writing at a time, occasional scheduled jobs) but would become a
bottleneck under multiple concurrent writers. If Qubit-Guard were deployed for
many simultaneous users/scans rather than a single audit team, the natural next
step is swapping `DATABASE_URL` in [db.py](backend/db.py):19 for a PostgreSQL
connection string — the SQLAlchemy ORM layer above it is already
database-agnostic (the WAL/PRAGMA hardening is explicitly guarded to a no-op on
non-SQLite dialects).

---

## 4. Cross-Tier Data Flow (example: running a Triad Scan)

1. **Presentation** — user submits target URLs on the TriadScanner page; Axios POSTs to `/api/scan/triad` with the JWT bearer token
2. **Application (router)** — `scan.py` validates the request, calls `services/scanner_engine.perform_triad_scan()`
3. **Application (service)** — `scanner_engine.py` opens real TLS sockets to each target, parses the certificate via `cryptography`, computes per-pillar QVS scores
4. **Application (service)** — `cbom_generator.py` builds a CycloneDX CBOM from the findings; `audit_service.py` logs the action
5. **Data** — the full result (findings, risk scores, CBOM, metrics) is persisted as a `ScanResult` row via SQLAlchemy, inside a WAL-mode transaction
6. **Application → Presentation** — the router returns the scan result JSON; the frontend renders QVS scores and charts

Scheduled scans follow the same steps 3–5 but are triggered by
`worker.py`'s APScheduler job instead of a live HTTP request, then additionally
call `mail_service.py` to email the report.

---

## 5. External Systems (outside all three tiers)

Not part of the application's own architecture, but essential dependencies the
application tier reaches over the network during normal operation:

| System | Reached by | Purpose |
|---|---|---|
| Scan targets (arbitrary web/VPN/API hosts) | `scanner_engine.py` | The actual thing being audited — live TLS handshake |
| `crt.sh` | `discovery_service.py` | Certificate-transparency log search for asset discovery |
| Apple iTunes Search/Lookup API | `mobile_scanner.py` | Mobile app metadata + inferred backend host |
| Sarvam AI (`sarvam-105b`) | `ai_service.py` via `httpx` | Remediation chat — optional, degrades to "AI Expert Offline" if unreachable |
| SMTP server (e.g. Gmail) | `mail_service.py` | Scheduled report email delivery — optional, degrades to "generated but NOT sent" |

None of these are required for the app to start or for manual (non-scheduled,
non-AI-chat) scanning to work against reachable targets.

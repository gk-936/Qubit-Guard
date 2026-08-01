# Qubit-Guard — Installation Guide

Comprehensive setup reference for the Qubit-Guard PQC Audit Platform: hardware,
software, supported operating systems, and every dependency the app pulls in.
For the quick-start version, see [instruction.md](instruction.md); this document
goes deeper on *why* each requirement exists.

---

## 1. Hardware Requirements

Qubit-Guard is a network-scanning application — its resource profile is driven by
concurrent TLS handshakes, DNS lookups, and PDF generation, not by heavy local
compute or storage.

### Minimum

| Component | Minimum |
|---|---|
| CPU | 2 cores (x86_64 or ARM64) |
| RAM | 2 GB |
| Storage | 1 GB free (app + venv + node_modules + growing SQLite DB) |
| Network | Outbound internet access (see §4) |
| Display | Any — web UI, no GPU required |

### Recommended

| Component | Recommended |
|---|---|
| CPU | 4+ cores — parallel TLS probes across Triad Scanner pillars and mobile scans benefit directly |
| RAM | 4–8 GB — headroom for concurrent scans, PDF report generation (ReportLab), and the Vite dev server running alongside the backend |
| Storage | 10+ GB SSD — scan history, PDF reports, and email logs accumulate in `backend/database/quantumshield.db` over time |
| Network | Stable, low-latency outbound connection — scan duration is dominated by round-trip time to each target, not local CPU |

### Why network dominates the profile

Every core feature performs real outbound I/O rather than local computation:
- **Triad Scanner** — live TLS handshakes against web/VPN/API endpoints per scan target
- **Asset Discovery** — certificate-transparency (`crt.sh`) queries, DNS zone-transfer attempts, dictionary subdomain probing
- **Mobile Scanner** — iTunes Search/Lookup API calls, then TLS probes of each app's backend
- **Reporting** — SMTP dispatch for scheduled/emailed reports

A CPU/RAM upgrade will not meaningfully speed up a scan against a slow or
high-latency target; more concurrent scan capacity is the main thing extra cores buy you.

---

## 2. Supported Operating Systems

The stack is pure Python + Node with no native/compiled OS-specific extensions,
so it runs anywhere both runtimes are available:

| OS | Status | Notes |
|---|---|---|
| **Windows 10/11** | ✅ Primary / developed on | PowerShell commands in this doc and [instruction.md](instruction.md) target this |
| **Linux** (Ubuntu 20.04+, Debian, RHEL-family) | ✅ Fully supported | Replace `.\venv\Scripts\activate` with `source venv/bin/activate` |
| **macOS** (12+) | ✅ Fully supported | Same as Linux for shell commands |

No OS-specific code paths exist in the backend or frontend. `python-dotenv`,
`sqlite3`, `ssl`/`socket` (stdlib) and all pinned packages are cross-platform wheels.

---

## 3. Software Prerequisites

| Requirement | Version | Purpose |
|---|---|---|
| **Python** | 3.9+ | Backend runtime (FastAPI). Uses only stdlib `ssl`/`socket`/`urllib` plus the packages in §5 — no version-specific syntax beyond 3.9 |
| **Node.js** | LTS (18.x or 20.x recommended) | Frontend build tooling — Vite 8 requires Node 18+ |
| **npm** | Bundled with Node | Frontend package management |
| **pip** | Bundled with Python | Backend package management |
| **Git** | Any recent version | Cloning/updating the repository (not required if deploying from a ZIP export) |

No database server, no Redis, no message broker, no reverse proxy is required to
run the app — SQLite and the two dev servers (Uvicorn + Vite) are self-contained.

---

## 4. Network Requirements

This is the most operationally important section — a network that blocks the
wrong outbound port makes the app *look* broken even though it's running fine.

| Traffic | Direction | Port | Required for |
|---|---|---|---|
| HTTPS | Outbound | 443 | TLS handshake scanning (Triad Scanner web/API pillars), crt.sh certificate-transparency lookups, iTunes Search/Lookup API, Sarvam AI chat |
| DNS | Outbound | 53 | Subdomain discovery, zone-transfer attempts, general hostname resolution |
| IKE/VPN | Outbound | UDP 500, 4500 | Triad Scanner's VPN pillar. If blocked, that pillar honestly reports `N/A`, not a fabricated score |
| SMTP | Outbound | 587 (or 465) | Emailed scheduled reports. If blocked, reports still generate and are downloadable — email delivery just reports "generated but NOT sent" |
| HTTP (dev) | Inbound (local/LAN) | 5006 (backend), 5173 (frontend) | Browser access to the app itself |

On a locked-down bank network, some of the above may be blocked. This is a known,
handled condition (see [instruction.md](instruction.md) → "Known
environment-dependent behaviour") — the app degrades honestly per-pillar rather
than failing or fabricating results.

**Exposing to evaluators on another machine:** run `npm run dev -- --host` and
set `CORS_ORIGINS` in `backend/.env` to the exact origin the evaluator's browser
will use. Full steps in [instruction.md](instruction.md).

---

## 5. Backend Dependencies

Pinned in [backend/requirements.txt](backend/requirements.txt):

| Package | Version | Role |
|---|---|---|
| `fastapi` | 0.115.12 | Web framework / routing / request validation |
| `uvicorn[standard]` | 0.34.2 | ASGI server |
| `sqlalchemy` | 2.0.40 | ORM + database engine (SQLite) |
| `passlib[bcrypt]` | 1.7.4 | Password hashing |
| `bcrypt` | 5.0.0 | Bcrypt backend for passlib |
| `python-jose[cryptography]` | 3.4.0 | JWT signing/verification (auth) |
| `pyjwt` | 2.10.1 | JWT handling |
| `python-dotenv` | 1.1.0 | `.env` file loading |
| `httpx` | 0.28.1 | Async HTTP client — Sarvam AI chat calls |
| `apscheduler` | 3.11.0 | Cron-style scheduled scans |
| `python-multipart` | 0.0.20 | Multipart form parsing (FastAPI dependency) |
| `dnspython` | 2.6.1 | DNS queries, zone-transfer attempts (asset discovery) |
| `cryptography` | 42.0.5 | Certificate parsing, public-key algorithm/size extraction from DER certs |
| `reportlab` | 5.0.0 | PDF report generation |

Standard library only, no extra install: `ssl`, `socket`, `urllib`, `sqlite3`, `json`, `logging`.

Install with:
```powershell
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

---

## 6. Frontend Dependencies

Pinned in [frontend/package.json](frontend/package.json):

### Runtime dependencies

| Package | Version | Role |
|---|---|---|
| `react` / `react-dom` | ^19.2.4 | UI framework |
| `react-router-dom` | ^7.13.2 | Client-side routing across the 14 pages (Home, TriadScanner, CBOM, Inventory, Discovery, MobileScanner, Posture, PQCSelector, QDaySimulator, Rating, Remediation, Reporting, History, OwaspAudit) |
| `axios` | ^1.13.6 | HTTP client for all `/api/*` calls, bearer-token auth header |
| `chart.js` / `react-chartjs-2` | ^4.4.1 / ^5.2.0 | Dashboard charts and posture visualizations |
| `react-markdown` | ^9.0.1 | Rendering AI remediation chat responses |
| `lucide-react` | ^1.8.0 | Icon set |

### Dev/build dependencies

| Package | Version | Role |
|---|---|---|
| `vite` | ^8.0.1 | Dev server + production bundler |
| `@vitejs/plugin-react` | ^6.0.1 | React fast-refresh/JSX support in Vite |
| `eslint` + plugins | ^9.39.4 | Linting |

Install with:
```powershell
cd frontend
npm install
```

---

## 7. Data & Storage

- **Database**: SQLite file at `backend/database/quantumshield.db`, created automatically on first run (`Base.metadata.create_all` + `ensure_schema()` migration pass — see [db.py](backend/db.py))
- **WAL mode** enabled so dashboard reads don't block on an in-progress scan write
- **No external database server required.** SQLite is adequate for the single-server, single-writer profile this app runs under (see Architecture doc §3 for scaling notes)
- **Generated artifacts**: PDF reports (ReportLab) are written to disk and also offered as a browser download; not automatically cleaned up

---

## 8. Configuration

`backend/.env` (see [instruction.md](instruction.md) for the full template):

| Variable | Required? | Effect if missing |
|---|---|---|
| `JWT_SECRET` | **Required** | Backend refuses to start — no fallback signing key is shipped in the repo |
| `PORT` | Optional (default 5006) | Backend listens on default port |
| `SARVAM_API_KEY` | Optional | AI remediation chat replies "AI Expert Offline"; every other feature works |
| `SMTP_HOST`/`PORT`/`USER`/`PASS` | Optional | Reports still generate/download; email says "generated but NOT sent" |
| `CORS_ORIGINS` | Required only for non-localhost access | Browser silently blocks all API calls from an unlisted origin |

---

## 9. Verifying the Install

```powershell
# Backend
cd backend
.\venv\Scripts\activate
python main.py
# Expect: "[*] Qubit-Guard.AI Backend is up!" and no traceback, listening on :5006

# Frontend (separate terminal)
cd frontend
npm run dev
# Expect: Vite prints Local: http://localhost:5173
```

Then log in at `http://localhost:5173` with `admin` / `pnb_password_2026` and
confirm `/api/health` returns 200 (visit `http://localhost:5006/api/health` directly).

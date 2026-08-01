# Qubit-Guard — Post-Quantum Cryptography Audit Platform

Built for **PNB Hackathon 2026**. Qubit-Guard scans a bank's external attack surface — web,
VPN, API, firmware-adjacent, and archival infrastructure, plus mobile apps — and reports
which of it still relies on cryptography that quantum computers will eventually break
(RSA, ECC/ECDSA), versus what has already migrated to NIST-standardized post-quantum
algorithms (ML-KEM, ML-DSA, SLH-DSA, and friends).

Login: `admin` / `pnb_password_2026`. Full setup steps (including how to expose it to
evaluators on another machine): **[instruction.md](instruction.md)**.

## What it does

- **Multi-pillar Triad Scanner** — real TLS handshakes against a target's web, VPN, and API
  endpoints; reads the actual certificate to determine key-exchange and signature algorithms
  (not guessed from the TLS cipher-suite name, which for TLS 1.3 reveals neither).
- **Asset discovery** — live certificate-transparency (`crt.sh`) lookups, DNS zone-transfer
  attempts, and dictionary subdomain probing; only DNS-resolving hosts are ever reported.
- **Quantum Vulnerability Score (QVS)** — a transparent 0–100 severity table (RSA = 100,
  ECC/ECDSA = 85, hybrid PQC = 20, full PQC = 0) applied to what was actually observed.
  Pillars that couldn't be probed report `N/A`, never a fabricated default.
- **Mobile app auditor** — live iTunes Search/Lookup API queries per bank, TLS-probes each
  app's inferred backend, and scores it from the real certificate presented.
- **CBOM export** — CycloneDX 1.5 bill-of-materials generated from real scan findings.
- **PQC Smart Selector** — recommends ML-KEM/ML-DSA/FN-DSA/SLH-DSA/LMS/BIKE-HQC from
  measured latency, bandwidth, device tier, and compliance inputs, via a rule-table
  decision-tree ensemble.
- **Remediation playbooks + AI chat** — expert-authored Bash/Nginx/Python fix templates,
  plus a live Sarvam AI (`sarvam-105b`) chat for open Q&A.
- **Scheduled scans and PDF/email reporting** — APScheduler cron jobs, `reportlab` PDFs,
  SMTP dispatch that honestly reports "generated but NOT sent" when delivery fails.
- **Auth** — bcrypt + JWT, enforced server-side on every route except `/api/auth` and
  `/api/health`.

Every one of these is tagged **LIVE / PARTIAL / STATIC** in **[features.md](features.md)**
depending on how much of the result is a real measurement versus an inference or a
reference table — read that file for the honest per-feature breakdown, and
**[functionalities.md](functionalities.md)** for the full module-by-module catalog.

## Tech stack

- **Backend**: Python 3.9+, FastAPI, Uvicorn, SQLAlchemy + SQLite (WAL mode)
- **Frontend**: React 18 (Vite), Chart.js
- **Scanning**: `ssl` / `socket` / `urllib`, `cryptography`, `dnspython`
- **AI**: Sarvam AI (`sarvam-105b`) via `httpx` — chat only
- **Scheduling**: APScheduler · **Reporting**: `reportlab`, `smtplib`
- **Standards referenced**: NIST FIPS 203/204/205, NIST SP 800-208, CycloneDX 1.5

## Quick start

```powershell
# backend
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
# create backend/.env with JWT_SECRET set — see instruction.md, the server refuses to start without it
python main.py          # http://localhost:5006

# frontend (separate terminal)
cd frontend
npm install
npm run dev              # http://localhost:5173
```

See **[instruction.md](instruction.md)** for `.env` options (SMTP, Sarvam AI, CORS for
network access), and for what's environment-dependent-but-not-broken (SMTP blocked on a
locked-down bank network, VPN pillar needing outbound UDP 500/4500, etc).

## Project status

This started as a hackathon prototype and has been through a full audit-and-repair pass:
every page was checked against what its backend actually measures, and every place where a
plausible-looking number was fabricated, guessed, or silently defaulted has either been
fixed to report the real measurement or relabeled as `N/A`/"inferred". The full findings
list — what was found, what was fixed, and how each fix was verified live — is in
**[CODE_REVIEW.md](CODE_REVIEW.md)**.

**Known, deliberate limitations** (not bugs — see CODE_REVIEW.md and features.md for why):
Pillars D (firmware) and E (archival) infer their verdict from the target's web TLS
certificate rather than contacting a firmware or archival system directly, since neither is
reachable from outside. Android mobile results are derived from the same app's iOS App
Store listing where no independent Android storefront data exists. The PQC Smart Selector
is a hand-authored rule table over published FIPS parameter sizes, not a model trained on
collected data. There is no automated CI test suite.

## Docs index

| File | Contents |
|---|---|
| [instruction.md](instruction.md) | Deployment guide, `.env` config, network-access setup, troubleshooting |
| [features.md](features.md) | Every feature tagged LIVE / PARTIAL / STATIC — what's measured vs. inferred vs. reference data |
| [functionalities.md](functionalities.md) | Module-by-module functional catalog and known limitations |
| [content.md](content.md) | Page-by-page UI content and copy |
| [CODE_REVIEW.md](CODE_REVIEW.md) | Full audit findings, fixes, and live verification log |
| [test_results.md](test_results.md) | What has and hasn't been manually verified |

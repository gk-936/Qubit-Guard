# Qubit-Guard — Prototype Features & Overview

**Qubit-Guard** is a cybersecurity prototype for the Post-Quantum Cryptography (PQC)
migration era. It gives Punjab National Bank (PNB) a unified way to identify
quantum-vulnerable cryptography across its external attack surface and plan a
migration path.

Every capability below is tagged with how it actually works:

| Tag | Meaning |
| :--- | :--- |
| **LIVE** | A real network call or computation produces the result. |
| **PARTIAL** | A real probe runs, but part of the stated conclusion is *inferred* rather than directly observed. |
| **STATIC** | Reference data, templates, or fixed logic. No measurement takes place. |

---

## 🚀 Prototype Functionality

### ⚡ 1. Multi-Pillar PQC Scanning Engine
The scanning engine categorizes cryptographic exposure across five infrastructure pillars.

- **Pillar A (Web/TLS) [LIVE]**: Performs a real TLS handshake via Python sockets. Reads
  the live certificate, issuer, cipher suite, TLS version and expiry. The **key exchange**
  is determined from the protocol and the **authentication algorithm is read from the
  certificate's public key** using the `cryptography` library — it is *not* guessed from
  the cipher suite name, which for TLS 1.3 encodes neither.
- **Pillar B (VPN/TLS) [PARTIAL]**: Real TLS probe plus real TCP connects to IKE ports
  500 and 4500. Vendor identification is a keyword heuristic over the certificate CN/SAN.
- **Pillar C (API/JWT) [LIVE]**: Decodes a user-supplied JWT header and classifies the
  signing algorithm as quantum-forgeable (RS256/ES256) or PQC-safe (ML-DSA OIDs). Also
  performs a real mTLS handshake check.
- **Pillar D (Firmware) [PARTIAL]**: Runs a real TLS probe and real HTTP HEAD requests
  against common firmware/OTA paths. **The firmware-signing verdict is inferred from the
  organisation's web PKI**, on the assumption that the same CA hierarchy is used for
  code-signing. No firmware image is retrieved or verified.
- **Pillar E (Archival) [PARTIAL]**: Real TLS probe and a real check for cloud
  server-side-encryption headers. **The archival key-wrapping verdict is inferred from the
  observed TLS key exchange.** No archival system is contacted.

> Pillars that cannot be probed report `N/A` and are excluded from the overall score.
> They are never assigned an assumed score.

### 🔍 2. PQC-Aware Asset Discovery
- **Certificate Transparency [LIVE]**: Queries **two independent CT log sources** —
  `crt.sh` and Cert Spotter — for certificates issued to the target domain, so an
  outage of either source doesn't silently drop this discovery channel.
- **DNS Zone Transfer [LIVE]**: Attempts an AXFR against the domain's nameservers, and
  separately records the nameservers themselves if they're on the same domain (e.g.
  `ns1.pnb.bank.in`) — infrastructure invisible to every certificate-based method
  since nameservers don't serve HTTPS.
- **DNS Record Enumeration [LIVE]**: Queries the domain's real MX and TXT (SPF)
  records and extracts any self-referencing hostnames — published infrastructure
  data, not a guess.
- **Historical Discovery [LIVE]**: Queries the Wayback Machine's archive for every
  host ever crawled under the domain — the only method here that can surface a
  subdomain that's no longer referenced anywhere current (decommissioned but
  possibly still live), which every other method by definition cannot find.
- **Reverse DNS [LIVE]**: PTR-looks-up the IP of every host already found, which can
  surface a hostname that was never in the wordlist, a certificate, or a CT log.
- **Dictionary Probing [LIVE]**: Tries a 130+-entry subdomain wordlist. **Every
  candidate must resolve in DNS before it is reported** — unresolved guesses are
  discarded, not listed as discovered assets.
- **Pillar Bucketing [STATIC]**: Discovered hosts are bucketed into Web/VPN/API by
  hostname keyword (`vpn.*`, `api.*`). This is a naming heuristic, not protocol detection,
  and is labelled "Inferred" in the output.

### 📦 3. CycloneDX 1.5 CBOM Export
- **JSON Export [LIVE]**: Generates a schema-shaped CycloneDX 1.5 document from actual
  scan findings and discovered assets, downloadable in one click.
- **Component versions [STATIC]**: Library version fields are placeholders. The CBOM
  accurately reflects *which* algorithms were observed, not which library versions
  implement them.

### 📊 4. Quantum Vulnerability Scoring & Q-Day Simulator
- **QVS Scoring [LIVE LOGIC]**: A fixed severity table (RSA = 100, ECC/ECDSA = 85,
  Hybrid PQC = 20, full PQC = 0) applied to observed algorithms. The overall score is an
  unweighted mean of the pillars that were actually assessed. It is a transparent
  severity mapping, not a statistical model.
- **HNDL Threat Simulator [UI]**: A client-side visualisation of "Time To Exposure"
  under Harvest-Now-Decrypt-Later assumptions. Illustrative, driven by the scan's
  vulnerability count — it is not a forecast.

### 🤖 5. AI-Assisted Remediation
- **Remediation Playbooks [STATIC]**: The Bash/Nginx/Python playbooks are expert-authored
  templates selected by pillar and detected algorithm, with the target domain substituted
  in. They are deterministic and reviewable — no model generates them.
- **PQC Expert Chat [LIVE]**: A real API call to **Sarvam AI (`sarvam-105b`)** for
  interactive Q&A. Without `SARVAM_API_KEY` the chat reports "AI Expert Offline" rather
  than returning canned text.

### 📱 6. Mobile App Presence Auditor
- **iOS Discovery [LIVE]**: Real queries against the iTunes Search API.
- **Android Discovery [STATIC]**: Android entries are derived from the iOS results.
  There is no free official Play Store API; these are **not** independent findings.
- **App TLS Probe [LIVE]**: Candidate API domains are guessed but only reported as
  reachable after a real TLS handshake succeeds.

### 📅 7. Automated Audit Reporting & Scheduling
- **Task Scheduling [LIVE]**: APScheduler cron jobs, persisted to the database and
  reloaded at startup, genuinely execute scans at the scheduled time.
- **PDF Generation [LIVE]**: Real PDF rendering via `reportlab`, with a hand-rolled
  raw-PDF fallback if `reportlab` fails.
- **Email Dispatch [LIVE]**: Real SMTP over STARTTLS with an SSL/465 fallback. **If
  delivery fails or SMTP is unconfigured, the UI says the report was generated but not
  sent.** It never reports a successful send that did not occur.

### 🛡️ 8. Authentication
- **JWT & Bcrypt [LIVE]**: Bcrypt password verification and HS256 JWTs with a 1-hour
  expiry. **Enforced server-side** on every route except `/api/auth/*` and `/api/health`.
  `JWT_SECRET` is required at startup; there is no fallback signing key.

### 🧠 9. PQC Smart Selector
- **Constraint-Based Selection [LIVE]**: Recommends an algorithm (ML-KEM, ML-DSA,
  FN-DSA, SLH-DSA, LMS/XMSS, BIKE/HQC) from pillar, bandwidth, latency, device tier,
  retention and compliance mandate.
- **How it works [STATIC]**: A pure-Python decision-tree ensemble over a **140-row
  hand-authored rule table** encoding published FIPS 203/204/205 parameter sizes and
  security levels. It is an expert rule set, not a model trained on collected data, and
  no external dataset is loaded at runtime.
- **Scan-driven inputs**: Latency is the measured TLS handshake round-trip. Bandwidth is
  a documented assumption — it is not observable from a handshake — and is labelled as
  such in the output.

### 📋 10. OWASP Top 10 (2025) Mapping
- **Risk Mapping [LIVE]**: Maps real Triad findings onto cryptographic-failure categories.
- **Category Content [STATIC]**: The attack/prevention guidance cards are authored
  reference text matched by keyword.

### 🗄️ 11. Asset Inventory & Scan History
- **Asset Management [LIVE]**: Filter, manually add and delete cryptographic components
  with risk ratings.
- **Audit Trails [LIVE]**: Every Triad scan is persisted and replayable from the dashboard.
- **Known limitation**: The database ships with seeded demonstration rows that are not
  yet distinguishable from scan-derived rows. Treat dashboard aggregates as
  demonstration data until a real scan has been run.

---

## 🛠 Technology Stack
- **Frontend**: React 18 (Vite), Chart.js, vanilla CSS.
- **Backend**: Python 3.9+, FastAPI, Uvicorn.
- **Scanning**: Python `ssl` / `socket` / `urllib`, `cryptography`, `dnspython`.
- **AI Integration**: Sarvam AI (`sarvam-105b`) via `httpx`, chat only.
- **Scheduling**: APScheduler. **Reporting**: reportlab, smtplib.
- **Database**: SQLite via SQLAlchemy.
- **Standards Referenced**: NIST FIPS 203 / 204 / 205, NIST SP 800-208, CycloneDX 1.5.

> The backend was originally written in Node.js/Express and later rewritten in Python.
> The superseded implementation has been removed; `backend/main.py` is the only entry point.

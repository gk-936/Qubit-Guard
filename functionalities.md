# Qubit-Guard Prototype — Feature & Functionality Catalog

This document lists every module, menu, and functional component in the Qubit-Guard
prototype, and states for each what is measured versus what is inferred or authored.

See `features.md` for the LIVE / PARTIAL / STATIC tag definitions.

---

## 🛠️ Core Infrastructure Features

### 1. Multi-Pillar Scanning Engine (Triad Scanner)
- **Pillar A (Web/TLS)** — *measured*: real TLS handshake; certificate common name,
  issuer, cipher suite, TLS version, expiry. Key exchange derived from the protocol;
  signature algorithm read from the certificate's public key.
- **Pillar B (VPN/TLS)** — *measured*: TLS probe and TCP connects on IKE ports 500/4500.
  *Inferred*: VPN vendor, via keyword matching on the certificate CN/SAN.
- **Pillar C (API/JWT)** — *measured*: JWT header decoded and its `alg`/OID checked
  against PQC-compliant identifiers (ML-DSA); real mTLS enforcement probe.
- **Pillar D (Firmware)** — *measured*: TLS probe and HTTP HEAD requests to common
  firmware paths. *Inferred*: the firmware-signing verdict, extrapolated from the
  organisation's web PKI. No firmware is fetched or verified.
- **Pillar E (Archival)** — *measured*: TLS probe and cloud SSE response headers.
  *Inferred*: the archival key-wrapping verdict, extrapolated from the TLS key exchange.
  No archival system is contacted.

**Unassessable pillars report `N/A`** and are excluded from the overall QVS. A pillar
that could not be probed is never assigned a default or assumed score.

### 2. Asset Discovery
- **Certificate Transparency (OSINT)** — real `crt.sh` queries against the target domain.
- **DNS Zone Transfer** — real AXFR attempt; normally refused, which is expected.
- **Dictionary Probing** — a 95-entry subdomain wordlist. Candidates are reported only
  if they resolve in DNS; unresolved guesses are discarded.
- **Interactive Graphing** — nodes-and-edges visualisation of the discovered hosts.
- **Pillar Bucketing** — hostname keyword heuristic (`vpn.*`, `api.*`), labelled
  "Inferred". Not protocol detection.

### 3. Remediation
- **Playbook Generation** — expert-authored Bash / Nginx / Python templates, selected by
  pillar and detected algorithm, with the target domain substituted in. Deterministic
  and reviewable; not model-generated.
- **PQC Expert Chat (Sarvam AI `sarvam-105b`)** — a real API call for interactive Q&A.
  Reports "AI Expert Offline" when `SARVAM_API_KEY` is absent.

---

## 📊 Analytics & Reporting

### 4. Quantum Vulnerability Scoring (QVS)
- **Grading Scale**: 0–100 severity mapping — RSA = 100, ECC/ECDSA = 85, hybrid PQC = 20,
  full PQC = 0. A transparent lookup, not a statistical model.
- **Aggregation**: unweighted mean across the pillars that were actually assessed.
- **Temporal Tracking**: history charts across persisted scans.

### 5. CBOM Export (CycloneDX 1.5)
- **JSON Export** — one-click download of a schema-shaped CycloneDX 1.5 document, built
  from real scan findings, for CERT-In compliance workflows.
- **Component Inventory** — lists observed algorithms per component. *Library version
  fields are placeholders*; the document is authoritative about algorithms, not versions.

### 6. PQC Posture & Smart Selector
- **Migration Roadmap** — visual alignment against DST and NIST timelines.
- **Algorithm Selector** — recommends ML-KEM / ML-DSA / FN-DSA / SLH-DSA / LMS / BIKE-HQC
  from bandwidth, latency, device tier, retention and compliance inputs. Implemented as a
  decision-tree ensemble over a 140-row hand-authored rule table encoding published FIPS
  parameter sizes. No external or collected dataset is used.
- **Scan-driven inputs** — latency is the measured handshake round-trip; bandwidth is a
  documented assumption and is labelled as one.

---

## 🏛️ Navigation & UI Elements

### Sidebar Navigation
Dashboard, Inventory, Discovery, CBOM, Posture, Rating, Reporting, History, Scanner,
Mobile, Remediation, Q-Day, PQC Selector. Every route is wired to a live backend
endpoint; none render mock data arrays.

- **Audit Button**: "Audit New Bank" primary action trigger.

### Header Actions
- **User Profile**: session settings.
- **Logout**: clears the session token.
- **Status Indicators**: backend connectivity and engine status.

### Authentication
Bcrypt + HS256 JWT with a 1-hour expiry, enforced **server-side** on every route except
`/api/auth/*` and `/api/health`. An expired token returns the user to the login screen.

---

## 🛡️ Emerging Threat Simulation

### 7. Q-Day Simulator
- **TTE (Time to Exposure)** — an illustrative calculation over Harvest-Now-Decrypt-Later
  assumptions, seeded by the scan's vulnerability count. A visualisation, not a forecast.
- **Interactive Sliders** — client-side parameters for data sensitivity and quantum
  development speed.

### 8. OWASP Audit (2025)
- **Risk Mapping** — real Triad findings mapped onto cryptographic-failure categories.
- **Guidance Cards** — authored reference text matched to findings by keyword.

---

## Known Limitations

1. **Seeded demonstration data** — the database ships with seed rows that are not yet
   distinguishable from scan-derived rows. Dashboard aggregates should be read as
   demonstration data until a real scan has been run.
2. **Android mobile results** — derived from the iOS results, not independently
   discovered. There is no free official Play Store API.
3. **Pillars D and E** — their headline verdicts are inferred from web PKI and TLS
   observations respectively, not from firmware or archival systems.
4. **TLS 1.3 key exchange group** — Python's `ssl` module does not expose the negotiated
   group before 3.13, so it is reported as unknown rather than guessed.
5. **No automated test suite** — see `test_results.md` for what has and has not been
   verified.

---
**Document Status**: Reflects the codebase as of 2026-07-31.

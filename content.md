# Qubit-Guard: Platform Presentation Guide

This document outlines what to present to the PNB evaluator for each window of the
Qubit-Guard platform: the Triad Scanning engine, the 6 PQC algorithm families the
platform tracks, and the constraint-based PQC Selector.

**Presenter's note.** Where a window mixes measured data with inferred or reference
content, this guide says so explicitly. Claim what the platform measures — it is a
stronger position than overclaiming, and the distinction is visible in the UI and the
source, so it will not survive a direct question otherwise.

## 📊 Overview of Windows & Important Functionalities

---

### 1. Dashboard (Home)
- **Features**: High-level summary of the Quantum Vulnerability Score (QVS), alerts, and
  executive metrics.
- **Important Functionalities**: Aggregates scan data into an immediate risk posture. The
  entry point for CISO-level stakeholders.
- **Focus**: Progress from legacy RSA/ECC toward quantum-safe algorithms.
- **Say this**: The database ships with seeded demonstration rows. Run a live scan first
  so the dashboard reflects measured data.

### 2. Asset Inventory
- **Features**: Centralised management of discovered assets by pillar (Web, VPN, API,
  Mobile, Firmware, Archival).
- **Important Functionalities**: Shows the cryptographic protocols and cipher suites
  observed per asset, flags vulnerable endpoints, allows manual categorisation.

### 3. Asset Discovery
- **Features**: Automated external asset mapping.
- **Important Functionalities**: Queries Certificate Transparency logs (`crt.sh`),
  attempts DNS zone transfer, and probes a 95-entry subdomain wordlist. **Candidates are
  reported only if they resolve in DNS** — guesses that do not resolve are discarded
  rather than presented as discoveries. Probes targets for TLS 1.3 support, a
  prerequisite for hybrid PQC ciphers.
- **Say this**: Pillar bucketing (`vpn.*`, `api.*`) is a naming heuristic and is labelled
  "Inferred" in the output — it is not protocol detection.

### 4. CBOM (Cryptographic Bill of Materials)
- **Features**: Ledger of cryptographic artefacts across the scanned surface.
- **Important Functionalities**: Generates a CycloneDX 1.5 CBOM capturing algorithm,
  bit-size, cipher mode and PQC-safe status, exportable to satisfy CERT-In Annexure-A
  workflows.
- **Say this**: The CBOM is authoritative about *algorithms observed*. Library version
  fields are placeholders.

### 5. Posture of PQC
- **Features**: Analytics on migration progress.
- **Important Functionalities**: Distribution of vulnerable versus safe algorithms,
  tracked against the DST PQC Migration Roadmap. Shows `N/A` where no pillar could be
  assessed rather than substituting a placeholder score.

### 6. Cyber Rating (QVS)
- **Features**: 0–100 risk scale.
- **Important Functionalities**: Quantifies quantum risk — RSA scores 100, ECC/ECDSA 85,
  hybrid PQC 20, full ML-KEM/ML-DSA 0. Overall score is an unweighted mean of the pillars
  actually assessed.
- **Say this**: This is a transparent, auditable severity mapping — every input and
  threshold is inspectable. It is deliberately not a black-box model.

### 7. Reporting
- **Features**: Audit report generation and dispatch.
- **Important Functionalities**: Compiles Triad results, CBOM and QVS into a PDF
  (rendered with `reportlab`) and dispatches it over SMTP.
- **Say this**: If SMTP is unconfigured or blocked, the UI states that the report was
  generated but **not** sent, and offers Download PDF. There is no fallback that claims
  a successful send.

### 8. Triad Scanner (Core Engine)
- **Features**: The core engine, examining five attack surfaces.
- **Important Functionalities**:
  - **Pillar A (Web/TLS)** — *measured*. Real TLS handshake. Key exchange is derived from
    the protocol and the signature algorithm is **read from the certificate's public key**.
    It is not inferred from the cipher suite name, which for TLS 1.3 encodes neither.
  - **Pillar B (VPN/TLS)** — *measured*: real TLS probe plus real connects to IKE ports
    500/4500. *Inferred*: vendor, by keyword on the certificate CN/SAN.
  - **Pillar C (API Security)** — *measured*: JWT header decoded and classified
    (RS256/ES256 versus ML-DSA OIDs); real mTLS check.
  - **Pillar D (Firmware)** and **Pillar E (Archival)** — real probes run, but the
    headline verdicts are **inferred** from the organisation's web PKI and observed TLS
    key exchange respectively. No firmware image or archival system is inspected.
- **Say this**: A pillar that cannot be probed reports `N/A` and is excluded from the
  score. Nothing is assumed on a host that was never reached.

### 9. Mobile App Scanning
- **Features**: Verifies PNB's mobile app presence.
- **Important Functionalities**: Real iTunes Search API queries identify official versus
  unrecognised iOS apps. Candidate app API domains are confirmed only by a real TLS
  handshake.
- **Say this**: Android entries are derived from the iOS results — there is no free
  official Play Store API, so they are not independent findings.

### 10. Auto-Remediation
- **Features**: Step-by-step resolution of identified vulnerabilities.
- **Important Functionalities**: Generates deployment-ready Nginx hardening, OpenVPN and
  JWT-migration snippets. These are **expert-authored templates**, selected by pillar and
  detected algorithm — deterministic and reviewable, which is what you want in a
  remediation path. An interactive **Sarvam AI (`sarvam-105b`)** chat handles open-ended
  PQC questions alongside them.

### 11. Q-Day Simulation
- **Features**: Interactive Harvest-Now-Decrypt-Later visualiser.
- **Important Functionalities**: Illustrates "Time To Exposure" from the scan's
  vulnerability count, to make quantum risk tangible for executives.
- **Say this**: Presented as a visualisation, not a forecast.

### 12. PQC Selector (Smart Engine)
- **Features**: Constraint-based algorithm selection.
- **Important Functionalities**: Takes bandwidth, latency, device type, retention period
  and compliance mandate, and recommends the appropriate PQC algorithm with a confidence
  score. Latency is the **measured** TLS handshake round-trip from the scan; bandwidth is
  a documented assumption and labelled as one in the output.

---

## 🧠 How the PQC Selector Decides

The Selector is a pure-Python decision-tree ensemble over a **140-row hand-authored rule
table**. Each row encodes published algorithm characteristics — key and signature sizes
and security levels from **NIST FIPS 203 / 204 / 205** — mapped to deployment
constraints. No external dataset is loaded at runtime and no model is trained on
collected data.

**This is a strength worth stating directly.** PQC algorithm selection is a
constraint-satisfaction problem, not a prediction problem: given bandwidth, latency,
device tier and security level, the correct algorithm is *derivable* from published
parameter sizes. There is no hidden pattern for a model to learn. A transparent rule set
whose every threshold can be traced to a NIST parameter table is more defensible in a
compliance context than a statistical model would be.

Useful reference sources if you extend it: NIST FIPS 203/204/205 parameter tables,
liboqs benchmarks for server-class timings, and pqm4 for ARM Cortex-M4 timings behind
the device-tier constraint.

---

## 🔐 The 6 PQC Algorithm Families & Triad Focus

The platform maintains a **reference registry** of six algorithm families — their
parameter sets, key and signature sizes, security levels and OIDs — and maps each to the
pillar it should protect. The registry drives recommendations, CBOM classification and
the audit table.

> **Be precise on this point**: the platform *identifies, classifies and recommends*
> these algorithms. It does not perform PQC key generation, signing or encapsulation —
> there is no liboqs or equivalent binding in the codebase. It is an assessment and
> migration-planning tool, not a crypto library.

### 1. ML-KEM (Kyber)
- **Use Case**: Key establishment in Web/TLS and VPN/TLS (Pillars A & B).
- **Benefits**: FIPS 203 finalized. Fast key exchange with relatively small ciphertexts
  for a lattice scheme, ideal for standard web traffic.
- **Drawbacks**: Sensitive to certain hardware-level side-channel attacks.
- **Future Mitigation**: Constant-time implementations and hardware masking.

### 2. ML-DSA (Dilithium)
- **Use Case**: General digital signatures for APIs and authentication (Pillar C).
- **Benefits**: FIPS 204 finalized. Highly secure with fast verification.
- **Drawbacks**: Signatures are significantly larger than ECC, which affects latency on
  low-bandwidth links.
- **Future Mitigation**: Certificate compression and caching in TLS 1.3 to reduce
  transmission overhead.

### 3. SLH-DSA (SPHINCS+)
- **Use Case**: Conservative backup signing for high-value transactions (Pillar C).
- **Benefits**: FIPS 205 finalized. Relies only on hash-function security — if lattice
  assumptions are ever broken, SLH-DSA still stands.
- **Drawbacks**: Very large signatures and slow signing.
- **Future Mitigation**: Reserved as a fallback for high-value HSM validations where
  security margin outweighs speed.

### 4. FN-DSA (Falcon)
- **Use Case**: Compact signatures under mobile constraints (Mobile pillar).
- **Benefits**: Smallest signatures among lattice schemes — well suited to constrained
  bandwidth.
- **Drawbacks**: Difficult to implement securely because of floating-point arithmetic.
- **Future Mitigation**: Hardware acceleration and constant-time float replacements to
  prevent timing attacks.

### 5. XMSS / LMS (Stateful Hash-Based)
- **Use Case**: System and firmware integrity (Firmware pillar).
- **Benefits**: Standardised in NIST SP 800-208. Well-understood security for
  code-signing, so firmware updates cannot be quantum-forged.
- **Drawbacks**: Highly sensitive to state management — reusing a key index breaks
  security completely.
- **Future Mitigation**: Deployment inside secure enclaves with monotonic counters to
  physically prevent state reuse.

### 6. BIKE / HQC (Code-Based KEMs)
- **Use Case**: Archival and long-term storage encryption (Archival pillar).
- **Benefits**: Based on error-correcting codes — a different hardness assumption from
  lattices, giving useful diversity for decades-long retention.
- **Drawbacks**: Larger public keys and slower key generation than ML-KEM.
- **Future Mitigation**: Suited to asynchronous, offline archival workflows where
  real-time latency is not the binding constraint.

import uuid
from datetime import datetime
from services.scanner_engine import _qvs


def generate_triad_cbom(scan_findings: dict, web_url: str, vpn_url: str, api_url: str, discovered_assets: list = None, discovered_endpoints: list = None, discovered_mobile_apps: list = None) -> dict:
    """
    Generate a dynamic CycloneDX v1.5 CBOM from real scan findings.
    """
    components = []
    # Only use real components from scan findings

    pillar_map = {
        "web": {"type": "application", "name": f"Web Portal ({web_url})", "asset": "Web/TLS"},
        "vpn": {"type": "network-appliance", "name": f"VPN Gateway ({vpn_url})", "asset": "VPN/TLS"},
        "api": {"type": "library", "name": f"Financial API ({api_url})", "asset": "API/TLS"},
        "firmware": {"type": "firmware", "name": "System Firmware", "asset": "System/Firmware"},
        "archival": {"type": "data", "name": "Banking Archives", "asset": "Archival/Storage"},
    }

    for pillar, findings in scan_findings.items():
        if pillar not in pillar_map:
            continue

        cfg = pillar_map[pillar]

        if not findings:
            # A pillar with no findings was never actually assessed — e.g. the API
            # pillar produces nothing when no JWT token is supplied (it's optional
            # in the UI) and mTLS isn't strictly enforced. This used to default to
            # "Classical (RSA/ECC)" / quantumSafe: False regardless — a fabricated
            # verdict for a target that was never probed for crypto in this scan.
            # Matches the "N/A"/not-assessed convention used everywhere else
            # (scanner_engine.py's qvs: None, the frontend's N/A rendering).
            components.append({
                "type": cfg["type"],
                "name": cfg["name"],
                "version": "Not Assessed",
                "crypto": "Not Assessed",
                "quantumSafe": None,
                "properties": [
                    {"name": "qubit-guard:asset-type", "value": cfg["asset"]},
                    {"name": "qubit-guard:crypto-algorithm", "value": "Not Assessed"},
                    {"name": "qubit-guard:quantum-safe", "value": "unknown"},
                    {"name": "qubit-guard:detected-at", "value": datetime.utcnow().isoformat()},
                ]
            })
            continue

        has_vulnerabilities = any(f["severity"] in ["critical", "high"] for f in findings)

        # Extract the detected algorithm from findings. Check every finding rather
        # than stopping at the first match, and prefer critical/high-severity
        # matches over an "info" one — the original version broke on the first
        # finding containing "Algorithm" or "Key Exchange" regardless of severity
        # or specificity, so e.g. a web scan with both a "Quantum-Vulnerable Key
        # Exchange: ECDHE" finding AND a "Quantum-Vulnerable Certificate Key:
        # ECDSA-256" finding only ever reported "ECDHE", silently dropping the
        # certificate's own signature algorithm. "Certificate Key" and "Signing"
        # are also matched now — findings using that phrasing (certificate keys,
        # firmware signing) weren't matching "Algorithm"/"Key Exchange" at all and
        # fell straight through to the generic default.
        algo_keywords = ["Algorithm", "Key Exchange", "Certificate Key", "Signing"]
        candidates = [f for f in findings if any(kw in f["issue"] for kw in algo_keywords)]
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        candidates.sort(key=lambda f: severity_rank.get(f["severity"], 5))
        winner = candidates[0] if candidates else None
        base_algo = winner["issue"].split(":")[-1].strip() if winner else "Unknown"
        detected_algo = base_algo

        # An "inferred" finding (e.g. archival's key-wrapping guess, extrapolated
        # from the TLS key exchange the web pillar observed — a completely
        # different asset, data-at-rest vs. a network handshake) is not the same
        # kind of claim as a "measured" one. Collapsing both into a bare algorithm
        # name here made archival storage read as if ECDHE were directly observed
        # protecting data at rest, which isn't something a public endpoint scan
        # can actually determine remotely. Only the DISPLAYED string gets this
        # suffix — quantum-safety below is scored off base_algo so the added
        # text can't accidentally change which QVS keywords match.
        if winner and winner.get("evidence") == "inferred":
            detected_algo = f"{base_algo} (inferred, not directly observed — {winner.get('inferred_from') or 'extrapolated from another pillar'})"

        # A target is NOT quantum safe if vulnerabilities were found OR if it
        # resolved to classical cryptography. Scored via the same _qvs() table
        # used everywhere else in this project, not a separate hand-maintained
        # keyword list — that list (checking for "ECDHE"/"RSA"/"ECC"/...)
        # silently went stale the moment tls_kex_probe.py started reporting
        # real measured group names like "x25519"/"secp256r1"/"X25519MLKEM768":
        # none of those literal strings were in the list, so every TLS 1.3
        # connection — classical AND hybrid-PQC alike — fell through to the
        # default quantumSafe=True, the exact inverse of several of them.
        # When no finding carried any algorithm evidence at all (base_algo
        # stayed "Unknown"), that's absence of evidence, not evidence of
        # safety — None marks "not assessed" rather than asserting either way.
        if base_algo == "Unknown":
            is_quantum_safe = None
        else:
            is_quantum_safe = not has_vulnerabilities and _qvs(base_algo) < 20

        # Extract TLS version from findings for a meaningful version label.
        # Findings with "TLS" in the detail or issue carry the negotiated version
        # (e.g. "TLSv1.3", "TLSv1.2") — use that instead of the uninformative
        # hardcoded "unknown" that was here before.
        tls_version = None
        for f in findings:
            for field in (f.get("detail", ""), f.get("issue", "")):
                m = __import__('re').search(r'TLSv?[\s]?([\d.]+)', field)
                if m:
                    tls_version = f"TLS {m.group(1)}"
                    break
            if tls_version:
                break
        pillar_version = tls_version or "TLS (version not extracted)"

        components.append({
            "type": cfg["type"],
            "name": cfg["name"],
            "version": pillar_version,
            "crypto": detected_algo,
            "quantumSafe": is_quantum_safe,
            "properties": [
                {"name": "qubit-guard:asset-type", "value": cfg["asset"]},
                {"name": "qubit-guard:crypto-algorithm", "value": detected_algo},
                {"name": "qubit-guard:quantum-safe", "value": str(is_quantum_safe).lower()},
                {"name": "qubit-guard:detected-at", "value": datetime.utcnow().isoformat()},
            ]
        })
    
    # --- Organic Asset Discovery Ingestion ---
    if discovered_assets:
        for asset in discovered_assets:
            host = asset.get("host", "Unknown Host")
            if any(c["name"] == f"Web Portal ({host})" or host in c["name"] for c in components):
                continue  # Avoid duplicates with main pillars

            pqc_ready = asset.get("pqc_ready", False)
            raw_tls = str(asset.get("details", {}).get("tls_version", ""))
            pillar_types = asset.get("pillars", ["Web/TLS"])
            main_pillar = pillar_types[0]

            # Determine clean version label (avoiding 'unknown' or uninformative tags)
            if "1.3" in raw_tls:
                version_label = "TLS 1.3"
            elif "1.2" in raw_tls:
                version_label = "TLS 1.2"
            elif "1.1" in raw_tls:
                version_label = "TLS 1.1"
            elif "1.0" in raw_tls:
                version_label = "TLS 1.0"
            elif "HTTP" in main_pillar:
                version_label = "HTTP/1.1"
            elif "DNS" in main_pillar or "Infrastructure" in main_pillar:
                version_label = "DNS"
            else:
                version_label = raw_tls if (raw_tls and raw_tls not in ["N/A", "Unknown", "unknown"]) else "TLS 1.2"

            # Determine accurate cryptography label
            if "DNS" in main_pillar or "Infrastructure" in main_pillar:
                crypto_label = "Unencrypted (DNS Record)"
                comp_type = "network-appliance"
            elif "HTTP" in main_pillar:
                crypto_label = "Plaintext HTTP (No TLS)"
                comp_type = "application"
            else:
                cipher = asset.get("details", {}).get("cipher")
                kex_group = asset.get("details", {}).get("key_exchange_group")
                if cipher and kex_group:
                    crypto_label = f"{cipher} (key: {kex_group})"
                elif cipher:
                    crypto_label = cipher
                elif pqc_ready:
                    crypto_label = f"PQC-Hybrid ({version_label})"
                else:
                    crypto_label = f"Classical ({version_label})"
                comp_type = "application" if "Web" in main_pillar else "network-appliance" if "VPN" in main_pillar else "library"

            components.append({
                "type": comp_type,
                "name": f"{main_pillar} ({host})",
                "version": version_label,
                "crypto": crypto_label,
                "quantumSafe": pqc_ready,
                "properties": [
                    {"name": "quantum-shield:asset-type", "value": main_pillar},
                    {"name": "quantum-shield:discovery-source", "value": "Automated Reconn"},
                    {"name": "quantum-shield:quantum-safe", "value": str(pqc_ready).lower()},
                ]
            })
    
    # --- Deep API Endpoint Ingestion ---
    if discovered_endpoints:
        from urllib.parse import urlparse
        for ep in discovered_endpoints:
            url = ep.get("url", "Unknown Endpoint")
            parsed = urlparse(url)
            endpoint_path = parsed.path or "/"
            host = parsed.hostname
            bucket = ep.get("bucket", "General API")
            risk = ep.get("quantumRisk", "Classical")
            
            # Map every unique active/protected path as a distinct manageable asset.
            # Host is included in the name — the same path (e.g. "/health") can
            # legitimately exist on multiple probed hosts (webUrl, apiUrl, and
            # discovered subdomains), and without the host these looked like
            # duplicate rows in the CBOM table even though they're distinct assets.
            components.append({
                "type": "library",
                "name": f"API Endpoint: {bucket} ({host}{endpoint_path})",
                "version": "v1",
                "crypto": risk,
                "quantumSafe": "PQC" in risk,
                "properties": [
                    {"name": "quantum-shield:asset-type", "value": f"API/{bucket}"},
                    {"name": "quantum-shield:endpoint-url", "value": url},
                    {"name": "quantum-shield:host", "value": host},
                    {"name": "quantum-shield:http-status", "value": str(ep.get("status_code", 0))},
                    {"name": "quantum-shield:quantum-safe", "value": str("PQC" in risk).lower()},
                ]
            })

    # --- Mobile Application Ingestion ---
    if discovered_mobile_apps:
        # Build a version lookup from iOS entries so Android (derived-from-ios)
        # entries can reuse the same real version instead of showing "unknown".
        ios_versions = {
            app["id"]: app.get("version", "Unknown")
            for app in discovered_mobile_apps
            if app.get("platform") == "iOS" and app.get("version") not in (None, "", "Unknown")
        }
        for app in discovered_mobile_apps:
            # App discovery (search_mobile_apps) only returns store metadata
            # (name/id/platform/status) — it carries no cryptographic evidence.
            # If a real scan_mobile_app() result was attached to this entry
            # (e.g. via its `findings`), derive crypto/quantumSafe from that
            # evidence. Otherwise report "unknown" rather than a fabricated default.
            app_findings = app.get("findings") or []
            detected_algo = None
            quantum_safe = None
            for f in app_findings:
                issue = f.get("issue", "")
                if "PQC-Ready" in issue:
                    detected_algo = issue.split(":")[-1].strip()
                    quantum_safe = True
                    break
                if "Classical Crypto" in issue:
                    detected_algo = issue.split(":")[-1].strip()
                    quantum_safe = False
                    break
            if detected_algo is None:
                detected_algo = "Not Assessed"
                quantum_safe = app.get("quantumSafe")  # None if the app was never scanned

            # Use the version fetched during discovery; Android entries fall back
            # to the iOS version for the same bundle ID (same app, same release).
            version = app.get("version") or ios_versions.get(app["id"], "Unknown")

            properties = [
                {"name": "quantum-shield:asset-type", "value": f"Mobile/{app['platform']}"},
                {"name": "quantum-shield:package-id", "value": app["id"]},
                {"name": "quantum-shield:status", "value": app["status"]},
                {"name": "quantum-shield:quantum-safe", "value": str(quantum_safe).lower() if quantum_safe is not None else "unknown"},
            ]
            if app.get("source") == "derived-from-ios":
                properties.append({"name": "quantum-shield:source", "value": "derived-from-ios (not independently verified)"})

            components.append({
                "type": "application",
                "name": f"Mobile App: {app['name']} ({app['platform']})",
                "version": version,
                "crypto": detected_algo,
                "quantumSafe": quantum_safe,
                "properties": properties
            })

    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat(),
            "tools": [
                {
                    "vendor": "Qubit-Guard",
                    "name": "Triad Scanner Engine",
                    "version": "2.0.0",
                }
            ],
            "authors": [
                {
                    "name": "Qubit-Guard Auditor",
                    "email": "auditor@qubitguard.ai",
                }
            ],
        },
        "components": components,
    }

    return cbom


def generate_cyclonedx(items: list) -> dict:
    """
    Legacy CBOM generator for existing CBOM items (from /api/data/cbom/download).
    """
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat(),
            "tools": [{"vendor": "Qubit-Guard", "name": "Triad Engine", "version": "2.0.0"}],
            "authors": [{"name": "Qubit-Guard Auditor", "email": "auditor@qubitguard.ai"}],
        },
        "components": [
            {
                "type": "library",
                "name": item.get("component", ""),
                "version": item.get("version", ""),
                "purl": item.get("purl", ""),
                "properties": [
                    {"name": "qubit-guard:crypto-algorithm", "value": item.get("algorithm", "")},
                    {"name": "qubit-guard:key-size", "value": item.get("key_size", "")},
                    {"name": "qubit-guard:mode", "value": item.get("mode", "")},
                    {"name": "qubit-guard:quantum-safe", "value": str(item.get("quantum_safe", False)).lower()},
                ],
            }
            for item in items
        ],
    }
    return cbom

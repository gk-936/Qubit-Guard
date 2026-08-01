"""
Discovery Service — Probes domains/IPs to classify assets and detect PQC readiness.
Fulfills FR-01: Triad Asset Discovery with advanced reconnaissance.
"""

import socket
import ssl
import re
import logging
import urllib.request
import urllib.error
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import dns.zone
import dns.query
import dns.exception
import json
import ssl

log = logging.getLogger(__name__)

# --- 3. The Fuel: Expanded Dictionary Scope ---
COMMON_SUBDOMAINS = [
    # Infrastructure & Environments
    "", "www", "api", "vpn", "gate", "gw", "secure", "portal", "test", "dev", 
    "mail", "auth", "login", "mobile", "services", "m", "stg", "staging", 
    "uat", "preprod", "sandbox", "qa", "prod", "internal", "int",
    # DevOps & Observability
    "grafana", "kibana", "prometheus", "jenkins", "gitlab", "git", "harbor", 
    "argocd", "docker", "registry", "nexus", "status", "monitor", "logs",
    # Cloud & Tech
    "s3", "k8s", "ingress", "bastion", "vault", "cdn", "assets", "static", 
    "media", "db", "database", "sql", "redis", "elastic", "cloud", "aws", 
    "azure", "gcp", "iot", "edge", "proxy", "lb", "balancer",
    # Banking Specific (Added for higher discovery depth)
    "netbanking", "online", "pib", "mbs", "corp", "ebank", "payment", "card", 
    "loan", "mortgage", "invest", "wealth", "trade", "b2b", "swift", "rtgs",
    # Business & Apps
    "shop", "blog", "news", "support", "help", "docs", "kb", "wiki", "remote",
    "desktop", "meet", "chat", "office", "hr", "admin", "manage", "billing"
]

def generate_permutations(found_sub: str):
    """
    --- 4. The Intelligence: Dynamic Permutations ---
    Generates variations of a successfully discovered subdomain.
    """
    suffixes = ["-dev", "-stg", "-test", "-prod", "-v1", "-v2", "internal", "-api"]
    return [f"{found_sub}{s}" for s in suffixes]

def check_zone_transfer(domain: str) -> list:
    """
    --- 6. The Jackpot: Automated Zone Transfer Check ---
    Attempts to download the entire DNS zone map (AXFR).
    """
    discovered = []
    try:
        # Get NS records for the domain
        ns_query = dns.resolver.resolve(domain, 'NS')
        for ns in ns_query:
            ns_host = str(ns.target)
            try:
                # dns.query.xfr requires a literal IP address — passing the
                # nameserver's hostname raises a bare ValueError. Resolve it first.
                ns_addr = str(dns.resolver.resolve(ns_host, 'A')[0])
                zone = dns.zone.from_xfr(dns.query.xfr(ns_addr, domain, timeout=2))
                if zone:
                    for name in zone.nodes.keys():
                        discovered.append(f"{name}.{domain}".strip('.'))
            except (dns.exception.DNSException, OSError, EOFError, ValueError, IndexError) as e:
                # Refusal is the normal, expected outcome for a well-configured zone.
                log.debug("AXFR zone transfer failed against %s for %s: %s", ns_host, domain, e)
                continue
    except (dns.exception.DNSException, OSError, ValueError) as e:
        log.debug("NS lookup failed for %s: %s", domain, e)
    return list(set(discovered))

def extract_sans(cert) -> list:
    """
    --- 2. The Brain: SAN Extraction from TLS ---
    Parses the Subject Alternative Name field from a peer certificate.
    """
    sans = []
    if not cert:
        return []
    
    # Python's ssl.getpeercert() returns a dict if validated
    # We look for 'subjectAltName' which is a tuple of (('DNS', 'sub.domain.com'), ...)
    alt_names = cert.get('subjectAltName', ())
    for (name_type, value) in alt_names:
        if name_type == 'DNS':
            sans.append(value)
    return sans

def scrape_web_hints(url: str) -> list:
    """
    --- 5. The Recon: Passive Web Scraping (Pillar D) ---
    Parses CSP headers and robots.txt for additional subdomain leaks.
    """
    hints = set()
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'QuantumShield-Discovery/1.0'})
        with urllib.request.urlopen(req, timeout=2) as response:
            # Check Content-Security-Policy
            csp = response.headers.get('Content-Security-Policy', '')
            # Regex to find domain-like strings in CSP
            domain_matches = re.findall(r'([a-z0-9]+(?:-[a-z0-9]+)*\.[a-z0-9]+(?:-[a-z0-9]+)*\.[a-z]{2,})', csp.lower())
            for d in domain_matches:
                hints.add(d)
        
        # Check robots.txt (minimalistic)
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        with urllib.request.urlopen(robots_url, timeout=1) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
            # Extract links/domains from robots.txt
            matches = re.findall(r'https?://([a-z0-9]+(?:-[a-z0-9]+)*\.[a-z0-9]+(?:-[a-z0-9]+)*\.[a-z]{2,})', content.lower())
            for m in matches:
                hints.add(m)
    except (urllib.error.URLError, OSError) as e:
        log.debug("Web hint scrape failed for %s: %s", url, e)
    return list(hints)

def fetch_ct_logs(domain: str) -> list:
    """
    --- 1. The Shadow: Passive CT Log Harvesting ---
    Queries public Certificate Transparency logs to find subdomains.
    """
    discovered = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={'User-Agent': 'QuantumShield-OSINT/1.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            for entry in data:
                # Name value can contain multiple domains separated by \n
                names = entry.get('name_value', '').split('\n')
                for name in names:
                    if domain in name and "*" not in name:
                        discovered.add(name.strip())
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        log.debug("CT log query failed for %s (crt.sh may be down): %s", domain, e)
    return list(discovered)

def probe_host(host: str, base_domain: str) -> dict:
    """
    Worker function to probe a single host.
    """
    # 1. DNS Resolution (Pillar 0)
    try:
        socket.gethostbyname(host)
    except socket.gaierror:
        return None

    asset_info = {
        "host": host,
        "pillars": [],
        "pqc_ready": False,
        "details": {}
    }

    # 1. Check for Web/HTTPS (Pillar A)
    web_active = False
    try:
        # Check TLS 1.3 (PQC Marker) and extract SANs
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Discovery mode: accept all certs to extract data
        
        with socket.create_connection((host, 443), timeout=1) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                web_active = True
                asset_info["pillars"].append("Web/TLS")
                
                # Check TLS version
                if tls_sock.version() == "TLSv1.3":
                    asset_info["pqc_ready"] = True
                    asset_info["details"]["tls_version"] = "1.3 (PQC-Ready)"
                else:
                    asset_info["details"]["tls_version"] = tls_sock.version()
                
                # SAN Extraction
                cert = tls_sock.getpeercert()
                if not cert:
                    # In some configurations, we might need a binary cert
                    cert = ssl.DER_cert_to_PEM_cert(tls_sock.getpeercert(binary_form=True))
                    # Note: parsing PEM requires cryptography, let's stick to dict if available
                
                sans = extract_sans(tls_sock.getpeercert())
                if sans:
                    asset_info["details"]["discovered_sans"] = sans
                
                # ── Service Fingerprinting (Phase 4/5) ──
                try:
                    # Capture Server Banner and Security Headers
                    req = urllib.request.Request(f"https://{host}", method="HEAD", headers={'User-Agent': 'QuantumShield-Audit/1.0'})
                    with urllib.request.urlopen(req, timeout=1) as resp:
                        headers = resp.headers
                        asset_info["details"]["server_banner"] = headers.get('Server', 'Unknown')
                        
                        # Security Header Audit
                        sec_headers = {
                            "HSTS": "Strict-Transport-Security" in headers,
                            "CSP": "Content-Security-Policy" in headers,
                            "X-Frame-Options": "X-Frame-Options" in headers
                        }
                        asset_info["details"]["security_audit"] = sec_headers
                        
                        if sec_headers["HSTS"]:
                            asset_info["details"]["hsts_policy"] = headers.get("Strict-Transport-Security")
                except (urllib.error.URLError, OSError) as e:
                    log.debug("Banner probe failed for %s: %s", host, e)
    except (OSError, ssl.SSLError, ValueError) as e:
        log.debug("TLS probe failed for %s: %s", host, e)

    # 2. Check for VPN (Pillar B) - hostname heuristic narrows candidates, then a
    # cheap IKE port probe (≤3s, only run on hosts the heuristic already flagged —
    # no extra hosts are probed) tries to upgrade the tag from a guess to evidence.
    if "vpn" in host.lower() or "gate" in host.lower() or "remote" in host.lower():
        asset_info["pillars"].append("VPN/TLS")
        ike_open_port = None
        for ike_port in (500, 4500):
            try:
                with socket.create_connection((host, ike_port), timeout=3):
                    ike_open_port = ike_port
                    break
            except OSError as e:
                log.debug("IKE port %s not responsive on %s: %s", ike_port, host, e)
                continue
        if ike_open_port:
            asset_info["details"]["vpn_type"] = f"IPsec/IKE VPN Gateway (port {ike_open_port} open)"
            asset_info["details"]["vpn_classification_evidence"] = "probed"
        else:
            # IKE ports closed doesn't rule out an SSL-VPN (those live on 443), so the
            # hostname match remains the only basis for this classification.
            asset_info["details"]["vpn_type"] = "SSL-VPN (Inferred)"
            asset_info["details"]["vpn_classification_evidence"] = "hostname heuristic"

    # 3. Check for API (Pillar C) - hostname heuristic narrows candidates, then a
    # cheap HEAD request (≤3s, same narrowed set — no extra hosts are probed) checks
    # for an API-shaped Content-Type to upgrade the tag from a guess to evidence.
    if web_active and ("api" in host.lower() or "gw" in host.lower() or "services" in host.lower()):
        asset_info["pillars"].append("API/TLS")
        content_type = ""
        try:
            req = urllib.request.Request(
                f"https://{host}/", method="HEAD",
                headers={'User-Agent': 'QuantumShield-Audit/1.0'},
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                content_type = resp.headers.get('Content-Type', '')
        except (urllib.error.URLError, OSError) as e:
            log.debug("API content-type probe failed for %s: %s", host, e)

        if content_type and ("json" in content_type.lower() or "api" in content_type.lower()):
            asset_info["details"]["api_type"] = f"REST/JSON API (Content-Type: {content_type})"
            asset_info["details"]["api_classification_evidence"] = "probed"
        else:
            # A non-API Content-Type (or no response) doesn't disprove an API host
            # behind a HEAD-unfriendly gateway, so this stays a hostname guess.
            asset_info["details"]["api_type"] = "REST/JWT (Inferred)"
            asset_info["details"]["api_classification_evidence"] = "hostname heuristic"
    
    if web_active and not asset_info["pillars"]:
        asset_info["pillars"].append("Web/TLS")

    return asset_info if asset_info["pillars"] else None

def discover_pnb_assets(target_base: str) -> dict:
    """
    Real asset discovery engine — DNS brute-force, zone transfer,
    TLS SAN extraction, and CSP/robots.txt scraping.
    Returns only genuinely discovered assets.
    """
    if not target_base:
        return {"error": "Invalid target"}

    # Normalize target
    parsed_base = urlparse(target_base if target_base.startswith("http") else f"https://{target_base}")
    base_domain = parsed_base.hostname or target_base

    # 1. Zone transfer attempt (jackpot if it works)
    axfr_results = check_zone_transfer(base_domain)

    # 2. Build probe targets from ALL common subdomains + AXFR results
    targets_to_probe = set()
    for sub in COMMON_SUBDOMAINS:  # Probe the full dictionary
        targets_to_probe.add(f"{sub}.{base_domain}" if sub else base_domain)
    for axfr_host in axfr_results:
        targets_to_probe.add(axfr_host)

    # 3. Web scraping for additional subdomain hints
    web_hints = scrape_web_hints(f"https://{base_domain}")
    for hint in web_hints:
        if base_domain in hint:
            targets_to_probe.add(hint)

    # 4. Passive OSINT: Certificate Transparency Logs
    ct_results = fetch_ct_logs(base_domain)
    for ct_host in ct_results:
        targets_to_probe.add(ct_host)

    discovered_assets = []
    seen_hosts = set()

    # 5. Threaded probing across all targets
    with ThreadPoolExecutor(max_workers=30) as executor:
        future_to_host = {executor.submit(probe_host, host, base_domain): host for host in targets_to_probe}
        for future in as_completed(future_to_host):
            asset = future.result()
            if asset and asset["host"] not in seen_hosts:
                discovered_assets.append(asset)
                seen_hosts.add(asset["host"])

                # 5. Dynamic permutation: generate variants of found subdomains
                found_sub = asset["host"].replace(f".{base_domain}", "")
                for perm in generate_permutations(found_sub):
                    perm_host = f"{perm}.{base_domain}"
                    if perm_host not in seen_hosts:
                        targets_to_probe.add(perm_host)

        # 6. Probe permuted targets (second pass)
        new_targets = targets_to_probe - seen_hosts
        if new_targets:
            perm_futures = {executor.submit(probe_host, host, base_domain): host for host in new_targets}
            for future in as_completed(perm_futures):
                asset = future.result()
                if asset and asset["host"] not in seen_hosts:
                    discovered_assets.append(asset)
                    seen_hosts.add(asset["host"])

    # 7. Extract SANs from discovered TLS assets for additional hosts
    san_hosts = set()
    for asset in discovered_assets:
        for san in asset.get("details", {}).get("discovered_sans", []):
            if base_domain in san and san not in seen_hosts:
                san_hosts.add(san)

    if san_hosts:
        with ThreadPoolExecutor(max_workers=20) as executor:
            san_futures = {executor.submit(probe_host, host, base_domain): host for host in san_hosts}
            for future in as_completed(san_futures):
                asset = future.result()
                if asset and asset["host"] not in seen_hosts:
                    discovered_assets.append(asset)
                    seen_hosts.add(asset["host"])

    return {
        "base_domain": base_domain,
        "assets": discovered_assets,
        "total_found": len(discovered_assets),
        "axfr_success": len(axfr_results) > 0,
        "notes": f"Probed {len(targets_to_probe)} candidates. {len(axfr_results)} AXFR records. {len(san_hosts)} SAN-derived hosts.",
        "mobile_apps": fetch_mobile_apps_for_discovery(base_domain)
    }

def fetch_mobile_apps_for_discovery(domain: str) -> list:
    """Helper to find mobile apps relevant to the domain."""
    from services.mobile_scanner import search_mobile_apps
    # Extract organization keyword (e.g., 'pnb' from 'pnb.bank.in')
    org = domain.split('.')[0]
    apps = search_mobile_apps(org)
    return [
        {
            "name": app["name"],
            "id": app["id"],
            "platform": app["platform"],
            "status": app["status"]
        }
        for app in apps
    ]

"""
Discovery Service — Probes domains/IPs to classify assets and detect PQC readiness.
Fulfills FR-01: Triad Asset Discovery with advanced reconnaissance.
"""

import socket
import ssl
import re
import logging
import ipaddress
import urllib.request
import urllib.error
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import dns.zone
import dns.query
import dns.exception
import dns.reversename
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
    "ibanking", "internetbanking", "upi", "netbank", "neft", "imps", "kyc",
    "atm", "branch", "digital", "wallet", "recharge", "insurance",
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
    Attempts to download the entire DNS zone map (AXFR). Also harvests the
    nameserver hostnames themselves: an organization that runs its own DNS
    (e.g. "ns1.pnb.bank.in" instead of an outsourced registrar's
    nameserver) is a real, currently-resolving asset, and the NS lookup
    needed for the AXFR attempt already has it in hand — this was being
    thrown away before.
    """
    discovered = []
    try:
        # Get NS records for the domain
        ns_query = dns.resolver.resolve(domain, 'NS')
        for ns in ns_query:
            ns_host = str(ns.target).rstrip('.')
            if domain in ns_host:
                discovered.append(ns_host)
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

        # Check sitemap.xml — same idea as robots.txt, different real file
        # sites publish that routinely links to other subdomains (a CDN
        # host for images, a separate blog/support subdomain, etc.).
        sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
        with urllib.request.urlopen(sitemap_url, timeout=2) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
            matches = re.findall(r'https?://([a-z0-9]+(?:-[a-z0-9]+)*\.[a-z0-9]+(?:-[a-z0-9]+)*\.[a-z]{2,})', content.lower())
            for m in matches:
                hints.add(m)
    except (urllib.error.URLError, OSError) as e:
        log.debug("Web hint scrape failed for %s: %s", url, e)
    return list(hints)

def fetch_wayback_hosts(domain: str) -> list:
    """
    --- 8. Historical discovery via the Wayback Machine ---
    Every method above only finds what's *currently* live (a subdomain has
    to be resolving right now, or hold a currently/previously-issued
    certificate, to show up in CT logs, DNS, or a live scrape). archive.org's
    free CDX API instead returns every unique host it has ever crawled and
    archived under this domain, including subdomains that were decommissioned
    and stopped resolving years ago. A forgotten-but-still-live legacy
    system is exactly the kind of asset a security audit is supposed to
    catch, and none of the other methods here can find one that's no longer
    referenced anywhere current.
    """
    discovered = set()
    try:
        url = (
            f"https://web.archive.org/cdx/search/cdx?url=*.{domain}"
            f"&output=json&fl=original&collapse=urlkey&limit=2000"
        )
        req = urllib.request.Request(url, headers={'User-Agent': 'QuantumShield-OSINT/1.0'})
        with urllib.request.urlopen(req, timeout=6) as response:
            rows = json.loads(response.read().decode('utf-8'))
            # First row is the header (["original"]); skip it.
            for row in rows[1:] if rows else []:
                host = urlparse(row[0]).hostname
                if host and domain in host:
                    discovered.add(host.lower())
    except (urllib.error.URLError, OSError, json.JSONDecodeError, IndexError) as e:
        log.debug("Wayback Machine query failed for %s: %s", domain, e)
    return list(discovered)

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

def fetch_certspotter_ct(domain: str) -> list:
    """
    --- 1b. A second, independent CT log source ---
    crt.sh aggregates most public CT logs but is a single point of failure
    (already seen going down/timing out in practice — see the comment on
    fetch_ct_logs). Cert Spotter (sslmate.com) indexes CT logs independently
    and exposes a free, unauthenticated JSON endpoint for exactly this
    query, so if crt.sh is unreachable this still returns real results
    instead of silently losing an entire discovery channel.
    """
    discovered = set()
    try:
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        req = urllib.request.Request(url, headers={'User-Agent': 'QuantumShield-OSINT/1.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            for entry in data:
                for name in entry.get('dns_names', []):
                    if domain in name and "*" not in name:
                        discovered.add(name.strip().lower())
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        log.debug("Cert Spotter query failed for %s: %s", domain, e)
    return list(discovered)

def fetch_dns_record_hints(domain: str) -> list:
    """
    --- 1c. Active DNS record enumeration (MX/TXT) ---
    MX records name a domain's real mail infrastructure hostnames directly
    (e.g. "mx1.mailgateway.bank.in"), and TXT records — particularly SPF
    ("v=spf1 include:...") — routinely reference other real subdomains
    authorized to send mail for the domain. Both are standard, publicly
    published DNS data (not a guess), and dnspython is already a
    dependency, so this costs two extra DNS queries for a genuinely
    different discovery signal than dictionary guessing.
    """
    discovered = set()
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    try:
        for rdata in resolver.resolve(domain, 'MX'):
            host = str(rdata.exchange).rstrip('.').lower()
            if domain in host:
                discovered.add(host)
    except (dns.exception.DNSException, OSError) as e:
        log.debug("MX lookup failed for %s: %s", domain, e)

    try:
        for rdata in resolver.resolve(domain, 'TXT'):
            txt = str(rdata).strip('"')
            for match in re.findall(r'(?:include|redirect)[:=]([a-z0-9.\-]+)', txt.lower()):
                if domain in match:
                    discovered.add(match.rstrip('.'))
    except (dns.exception.DNSException, OSError) as e:
        log.debug("TXT lookup failed for %s: %s", domain, e)

    return list(discovered)

def _ptr_lookup(ip: str, domain: str) -> str:
    """Single PTR lookup — the per-IP worker used by reverse_dns_hosts() and
    the ASN sweep below. A 1.5s resolver timeout is enough for a PTR query
    (a single UDP round trip to a resolver, not a TCP+TLS handshake like the
    host probes elsewhere in this file); most non-existent PTR records come
    back as a fast NXDOMAIN rather than actually timing out."""
    try:
        rev_name = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.5
        resolver.lifetime = 1.5
        for rdata in resolver.resolve(rev_name, 'PTR'):
            host = str(rdata).rstrip('.').lower()
            if domain in host:
                return host
    except (dns.exception.DNSException, OSError, ValueError) as e:
        log.debug("Reverse DNS lookup failed for %s: %s", ip, e)
    return None

def reverse_dns_hosts(ips: set, domain: str, max_workers: int = 25) -> list:
    """
    --- 7. Reverse-DNS on already-discovered IPs ---
    A completely different discovery vector from everything above: given
    the real IP addresses of hosts already found, ask DNS "what hostname
    points here?" (a PTR lookup). This sometimes reveals an internal or
    alternate hostname for the same server that was never in the wordlist
    and was never mentioned in a certificate or CT log — e.g. a load
    balancer's real hostname behind a CNAME. Passive from the target's
    perspective (a PTR query only touches public DNS, never the host
    itself), so it adds signal at negligible cost.

    Parallelized across a thread pool — this used to be a plain `for ip in
    ips: ...` loop, so a target with many discovered IPs (a real bank can
    easily have 60-70+) meant up to ~1.5-2s of sequential wait *per IP*,
    which was very likely the single largest contributor to total scan time
    for exactly the targets this tool matters most for.
    """
    if not ips:
        return []
    discovered = set()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_ptr_lookup, ip, domain): ip for ip in ips}
        for future in as_completed(futures):
            host = future.result()
            if host:
                discovered.add(host)
    return list(discovered)

def fetch_asn_ip_range_hosts(domain: str, max_ips_to_sweep: int = 150) -> list:
    """
    --- 9. ASN/BGP IP-range discovery ---
    Finds the IP address space the organization's own network (its
    Autonomous System) actually announces to the internet, via RIPEstat's
    free, unauthenticated public data API, then reverse-DNS sweeps a
    bounded sample of those addresses. This is a fundamentally different
    starting point from
    every method above: instead of starting from a hostname and checking
    whether it resolves, it starts from "which IP space does this
    organization actually own" and asks what's running there — the
    technique real recon tooling (Amass, etc.) uses to find infrastructure
    that has no public DNS name pointing at it from anywhere else yet (a
    freshly-provisioned host, an internal load balancer, a backup node
    reachable only by IP).

    Deliberately bounded: a bank's announced ranges can span tens of
    thousands of addresses, and reverse-DNS-ing all of them would turn a
    few-second lookup into a scan lasting minutes. Only the first
    `max_ips_to_sweep` addresses across all announced prefixes are checked
    — the discovery response's notes field reports exactly how many, so
    this trade-off is visible to the caller, not silently hidden.
    """
    # Uses RIPEstat's free, unauthenticated public data API (stat.ripe.net) —
    # aggregates routing data across all 5 RIRs (ARIN/RIPE/APNIC/LACNIC/
    # AFRINIC), so it isn't limited to European-registered address space
    # despite the "RIPE" name. Verified reachable directly before using it
    # here; an earlier draft of this function targeted a BGPView hostname
    # that turned out not to resolve at all.
    try:
        seed_ip = socket.gethostbyname(domain)
    except socket.gaierror:
        return []

    try:
        req = urllib.request.Request(
            f"https://stat.ripe.net/data/network-info/data.json?resource={seed_ip}",
            headers={'User-Agent': 'QuantumShield-OSINT/1.0'},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            net_info = json.loads(resp.read().decode('utf-8'))
        asns = net_info.get("data", {}).get("asns", [])
        if not asns:
            return []
        asn = asns[0]

        req2 = urllib.request.Request(
            f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}",
            headers={'User-Agent': 'QuantumShield-OSINT/1.0'},
        )
        with urllib.request.urlopen(req2, timeout=8) as resp2:
            prefix_data = json.loads(resp2.read().decode('utf-8'))
        prefixes = prefix_data.get("data", {}).get("prefixes", [])
    except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError, IndexError) as e:
        log.debug("ASN/BGP lookup failed for %s (seed IP %s): %s", domain, seed_ip, e)
        return []

    # Skip IPv6 prefixes (ip_network(strict=False) parses them fine, but a
    # sweep of individual /48-style IPv6 host addresses would go nowhere
    # inside a bounded budget) and only take a bounded sample of hosts,
    # smallest prefixes first — a /24 has 254 usable addresses to fully
    # cover for the sample budget, a /18 has 16,382 and would otherwise
    # eat the entire budget on one prefix out of what can be 100+.
    ipv4_prefixes = []
    for pfx in prefixes:
        cidr = pfx.get("prefix", "")
        if ":" in cidr:
            continue
        try:
            ipv4_prefixes.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    ipv4_prefixes.sort(key=lambda n: n.num_addresses)

    candidate_ips = []
    for network in ipv4_prefixes:
        for ip in network.hosts():
            candidate_ips.append(str(ip))
            if len(candidate_ips) >= max_ips_to_sweep:
                break
        if len(candidate_ips) >= max_ips_to_sweep:
            break

    if not candidate_ips:
        return []
    return reverse_dns_hosts(set(candidate_ips), domain, max_workers=30)

def probe_host(host: str, base_domain: str) -> dict:
    """
    Worker function to probe a single host.
    """
    # 1. DNS Resolution (Pillar 0)
    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror:
        return None

    asset_info = {
        "host": host,
        "ip": resolved_ip,
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
        
        # This is the probe that gates whether a candidate is counted as "found" at
        # all. Was 1s originally (too tight under 30-way concurrent load), then 4s,
        # then 8s to match the Triad Scanner's own per-host timeout. Brought back
        # down to 3s: with the passive DNS/CT-based discovery methods below now
        # doing most of the real subdomain-finding work, the dictionary probe's
        # job is narrower (confirm which of ~130 guessed candidates are live) and
        # doesn't need to individually wait as long per host — keeping the whole
        # scan responsive matters more here than squeezing out the last few
        # slow-to-handshake dictionary guesses.
        with socket.create_connection((host, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                web_active = True
                asset_info["pillars"].append("Web/TLS")

                # Captured here so the QVS step below can score off the cipher
                # this same handshake already negotiated, instead of opening a
                # second TLS connection to the same host just to ask again.
                cipher = tls_sock.cipher()
                asset_info["_cipher_name"] = cipher[0] if cipher else None

                # TLS 1.3 alone is NOT evidence of post-quantum readiness — it
                # just means the TLS 1.3 protocol was negotiated, which almost
                # always still uses a classical (X25519/ECDHE) key exchange
                # today. Python's stdlib ssl module doesn't expose the
                # negotiated key-share group, so this code has no way to
                # confirm a real PQC hybrid group (e.g. x25519_kyber768) was
                # used. pqc_ready is set later, from the actual cipher name via
                # _qvs() — the only evidence-based signal available here.
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
                    with urllib.request.urlopen(req, timeout=3) as resp:
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

    # Compute per-asset QVS score and Tag (LEGACY, STANDARD, ELITEPQC).
    # Scored off the cipher the Web/TLS probe above already negotiated —
    # NOT a second handshake. A per-host re-probe here would double the
    # network round-trips across the ~130+ dictionary candidates (plus
    # permutation/SAN/PTR passes), which is exactly what made discovery slow.
    cipher_name = asset_info.pop("_cipher_name", None)
    if web_active and cipher_name:
        from services.scanner_engine import _qvs

        # A TLS 1.3 cipher name alone never reveals the key-exchange group
        # (classical vs. real hybrid-PQC) — only a TLS 1.3 host gets this
        # extra raw-socket probe (tls_kex_probe.py), which reads that group
        # directly off the wire. TLS 1.2 hosts skip it entirely: their cipher
        # name already names the key exchange unambiguously, so a second
        # connection would just be the redundant round-trip already fixed once.
        score_target = cipher_name
        tls_ver_for_kex = asset_info["details"].get("tls_version", "")
        if "1.3" in tls_ver_for_kex:
            try:
                from services.tls_kex_probe import probe_key_exchange
                kex = probe_key_exchange(host)
                if kex["reachable"] and kex["group"]:
                    score_target = kex["group"]
                    asset_info["details"]["key_exchange_group"] = kex["group"]
            except Exception as e:
                log.debug("TLS 1.3 key-exchange probe failed for %s: %s", host, e)

        asset_info["qvs"] = _qvs(score_target)
        asset_info["qvs_evidence"] = "measured"
        # Surfaced so downstream consumers (CBOM generation) can report what
        # was actually negotiated instead of guessing/fabricating an algorithm.
        asset_info["details"]["cipher"] = cipher_name

        # Explains WHY the tag below landed where it did — "LEGACY" alone reads
        # identically for a genuinely outdated TLS 1.2 host and a fully current
        # TLS 1.3 host that just happens to use classical (non-PQC) key
        # exchange, which are very different situations a user can't tell
        # apart from the bare tag. This makes the actual measured reason visible.
        kex_group = asset_info["details"].get("key_exchange_group")
        if kex_group:
            asset_info["tag_reason"] = f"Classical {kex_group} key exchange measured over {tls_ver_for_kex} (quantum-vulnerable)" if asset_info["qvs"] >= 20 \
                else f"Hybrid-PQC {kex_group} key exchange measured over {tls_ver_for_kex}"
        else:
            asset_info["tag_reason"] = f"{cipher_name} cipher suite measured over {tls_ver_for_kex or asset_info['details'].get('tls_version', 'TLS')}"
    else:
        # No cipher was captured (probe never reached the handshake, or the
        # host isn't web-active at all) — nothing measured, so this can only
        # ever be a rough guess, never a "ready" claim.
        tls_ver = asset_info["details"].get("tls_version", "")
        if "1.2" in tls_ver:
            asset_info["qvs"] = 85
        else:
            asset_info["qvs"] = 95
        asset_info["qvs_evidence"] = "heuristic"
        asset_info["tag_reason"] = f"Estimated from {tls_ver or 'no TLS response'} alone — cipher suite not captured"

    # pqc_ready is now purely evidence-based: only true if the negotiated
    # cipher actually matched a known PQC/hybrid-PQC entry in QVS_MAP (score
    # < 20). Given Python's stdlib ssl module can't see the real key-share
    # group, this will honestly read False for virtually all hosts today —
    # which is correct: claiming a host is "PQC-Ready" off TLS 1.3 alone (the
    # old behavior) was a guess, not a measurement.
    asset_info["pqc_ready"] = asset_info["qvs"] < 20

    # Assign Tag
    q = asset_info["qvs"]
    if q < 20:
        asset_info["tag"] = "ELITEPQC"
    elif q < 80:
        asset_info["tag"] = "STANDARD"
    else:
        asset_info["tag"] = "LEGACY"

    return asset_info if asset_info["pillars"] else None

def normalize_host(url_or_host: str) -> str:
    """Strip a URL down to its bare hostname, the same way discover_pnb_assets
    keys its host set — so callers can match a Triad-scan target against a
    discovered host without worrying about scheme/path differences."""
    parsed = urlparse(url_or_host if url_or_host.startswith("http") else f"https://{url_or_host}")
    return parsed.hostname or url_or_host


def discover_pnb_assets(target_base: str, prescanned: dict = None, progress_cb=None) -> dict:
    """
    Real asset discovery engine — DNS brute-force, zone transfer,
    TLS SAN extraction, and CSP/robots.txt scraping.
    Returns only genuinely discovered assets.

    prescanned, if given, maps normalized hostname -> {"qvs": int, "pqc_ready": bool,
    "tls_version": str}. Hosts already covered by perform_triad_scan (the
    caller's web/vpn/api targets) can be passed here so this function skips
    re-probing them with a second TLS handshake and instead reuses the
    Triad scan's own measured result for that host.

    progress_cb, if given, is called as progress_cb(percent: int, stage: str)
    at each phase boundary — purely a UI progress hook, behavior and results
    are identical whether or not it's passed.
    """
    def _report(pct, stage):
        if progress_cb:
            try:
                progress_cb(pct, stage)
            except Exception:
                pass

    prescanned = prescanned or {}
    if not target_base:
        return {"error": "Invalid target"}

    # Normalize target
    parsed_base = urlparse(target_base if target_base.startswith("http") else f"https://{target_base}")
    base_domain = parsed_base.hostname or target_base

    # 1. Run every independent OSINT/gathering source in parallel. These are
    # 7 separate network calls to 6 different external services (local DNS,
    # the target's own web server, crt.sh, Cert Spotter, archive.org,
    # RIPEstat) with zero dependency on each other — running them one after
    # another (as this used to) meant total gathering time was roughly the
    # SUM of every method's latency instead of the MAX of the slowest one.
    # This was very likely the single largest driver of total scan time as
    # more discovery methods were added; the actual host-probing rounds
    # below still have to run sequentially after this (permutations/SAN
    # hosts/reverse-DNS all depend on what the previous round found), but
    # the gathering phase itself has no such dependency.
    gather_sources = {
        "axfr": check_zone_transfer,
        "web_hints": lambda d: scrape_web_hints(f"https://{d}"),
        "ct_crtsh": fetch_ct_logs,
        "ct_certspotter": fetch_certspotter_ct,
        "dns_hints": fetch_dns_record_hints,
        "wayback": fetch_wayback_hosts,
        "asn": fetch_asn_ip_range_hosts,
    }
    _report(3, "Gathering OSINT sources (DNS, crt.sh, Cert Spotter, Wayback, RIPEstat)...")
    gathered = {}
    with ThreadPoolExecutor(max_workers=len(gather_sources)) as executor:
        future_to_source = {executor.submit(fn, base_domain): name for name, fn in gather_sources.items()}
        for future in as_completed(future_to_source):
            name = future_to_source[future]
            try:
                gathered[name] = future.result()
            except Exception as e:
                log.debug("Discovery source '%s' raised: %s", name, e)
                gathered[name] = []

    axfr_results = gathered["axfr"]
    web_hints = gathered["web_hints"]
    ct_results = set(gathered["ct_crtsh"]) | set(gathered["ct_certspotter"])
    dns_hint_results = gathered["dns_hints"]
    wayback_results = gathered["wayback"]
    asn_results = gathered["asn"]

    # 2. Build probe targets from every gathered source + the dictionary
    targets_to_probe = set()
    for sub in COMMON_SUBDOMAINS:  # Probe the full dictionary
        targets_to_probe.add(f"{sub}.{base_domain}" if sub else base_domain)
    for axfr_host in axfr_results:
        targets_to_probe.add(axfr_host)
    for hint in web_hints:
        if base_domain in hint:
            targets_to_probe.add(hint)
    for ct_host in ct_results:
        targets_to_probe.add(ct_host)
    for hint_host in dns_hint_results:
        targets_to_probe.add(hint_host)
    for wb_host in wayback_results:
        targets_to_probe.add(wb_host)
    for asn_host in asn_results:
        targets_to_probe.add(asn_host)

    # Hosts perform_triad_scan already scanned (the caller's web/vpn/api
    # targets) get skipped here — no point re-opening a TLS connection to
    # get a QVS score we already measured a moment ago.
    targets_to_probe -= set(prescanned.keys())

    discovered_assets = []
    seen_hosts = set()

    # 5. Threaded probing across all targets
    _report(10, f"Probing {len(targets_to_probe)} candidate subdomains...")
    with ThreadPoolExecutor(max_workers=30) as executor:
        future_to_host = {executor.submit(probe_host, host, base_domain): host for host in targets_to_probe}
        total_pass1 = len(future_to_host) or 1
        done_pass1 = 0
        for future in as_completed(future_to_host):
            asset = future.result()
            done_pass1 += 1
            if done_pass1 % 10 == 0 or done_pass1 == total_pass1:
                # Dictionary probing is the single slowest phase, so it gets
                # the widest percent band (10%-55%) to keep the bar moving
                # smoothly instead of sitting still for most of the scan.
                _report(10 + int(45 * done_pass1 / total_pass1), f"Probing candidate subdomains ({done_pass1}/{total_pass1})...")
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
            _report(58, f"Probing {len(new_targets)} permutation variants...")
            perm_futures = {executor.submit(probe_host, host, base_domain): host for host in new_targets}
            for future in as_completed(perm_futures):
                asset = future.result()
                if asset and asset["host"] not in seen_hosts:
                    discovered_assets.append(asset)
                    seen_hosts.add(asset["host"])

    # 7. Extract SANs from discovered TLS assets for additional hosts
    _report(70, "Extracting SANs from discovered certificates...")
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

    _report(82, "Running reverse-DNS on discovered IPs...")
    # 8. Reverse-DNS on every IP found so far — a genuinely different signal
    # from everything above (asks DNS directly, doesn't guess a name and
    # check it), can surface hostnames never in the wordlist, a certificate,
    # or a CT log.
    discovered_ips = {a["ip"] for a in discovered_assets if a.get("ip")}
    ptr_hosts = set(reverse_dns_hosts(discovered_ips, base_domain)) - seen_hosts if discovered_ips else set()

    if ptr_hosts:
        with ThreadPoolExecutor(max_workers=10) as executor:
            ptr_futures = {executor.submit(probe_host, host, base_domain): host for host in ptr_hosts}
            for future in as_completed(ptr_futures):
                asset = future.result()
                if asset and asset["host"] not in seen_hosts:
                    discovered_assets.append(asset)
                    seen_hosts.add(asset["host"])

    _report(92, "Compiling asset inventory and QVS scores...")
    # Fold the prescanned (Triad-scan-covered) hosts into the result set,
    # reusing their already-measured QVS instead of a fresh probe. A plain
    # DNS lookup (no TLS handshake) is still fine here just to show an IP.
    for host, info in prescanned.items():
        if host in seen_hosts:
            continue
        try:
            ip = socket.gethostbyname(host)
        except OSError:
            ip = None
        qvs = info.get("qvs")
        qvs = qvs if qvs is not None else 95
        tag = "ELITEPQC" if qvs < 20 else ("STANDARD" if qvs < 80 else "LEGACY")
        discovered_assets.append({
            "host": host,
            "ip": ip,
            "pillars": ["Web/TLS"],
            "pqc_ready": bool(info.get("pqc_ready", False)),
            "details": {"tls_version": info.get("tls_version", "N/A")},
            "qvs": qvs,
            "qvs_evidence": "measured (triad scan)",
            "tag": tag,
            "tag_reason": f"QVS {qvs} from the Triad scan's own {info.get('tls_version', 'TLS')} handshake for this host",
        })
        seen_hosts.add(host)

    # Aggregate overall bank score across all discovered subdomains
    qvs_scores = [a.get("qvs", 95) for a in discovered_assets if a.get("qvs") is not None]
    overall_bank_qvs = round(sum(qvs_scores) / len(qvs_scores)) if qvs_scores else 95

    tag_counts = {
        "LEGACY": sum(1 for a in discovered_assets if a.get("tag") == "LEGACY"),
        "STANDARD": sum(1 for a in discovered_assets if a.get("tag") == "STANDARD"),
        "ELITEPQC": sum(1 for a in discovered_assets if a.get("tag") == "ELITEPQC")
    }

    _report(97, "Fetching mobile app inventory...")
    result = {
        "base_domain": base_domain,
        "assets": discovered_assets,
        "total_found": len(discovered_assets),
        "overall_bank_qvs": overall_bank_qvs,
        "tag_counts": tag_counts,
        "axfr_success": len(axfr_results) > 0,
        "notes": (
            f"Probed {len(targets_to_probe)} candidates. {len(axfr_results)} AXFR/NS records. "
            f"{len(ct_results)} CT-log hosts (crt.sh + Cert Spotter). {len(dns_hint_results)} "
            f"MX/TXT-derived hosts. {len(wayback_results)} Wayback-Machine-derived hosts. "
            f"{len(asn_results)} ASN/BGP-range-derived hosts. {len(san_hosts)} SAN-derived hosts. "
            f"{len(ptr_hosts)} reverse-DNS-derived hosts."
        ),
        "mobile_apps": fetch_mobile_apps_for_discovery(base_domain)
    }
    _report(100, "Discovery complete.")
    return result

def fetch_mobile_apps_for_discovery(domain: str) -> list:
    """Helper to find mobile apps relevant to the domain."""
    from services.mobile_scanner import search_mobile_apps, _fetch_store_metadata
    # Extract organization keyword (e.g., 'pnb' from 'www.pnb.bank.in').
    # Strip the "www" label first — scanning "www.pnb.bank.in" (a completely
    # normal way to type a target) otherwise took the FIRST label as the
    # organization keyword and searched the App Store for "www" itself,
    # returning unrelated apps (confirmed: returned WWE wrestling games).
    labels = [p for p in domain.lower().split('.') if p and p != "www"]
    org = labels[0] if labels else domain
    apps = search_mobile_apps(org)
    result = []
    for app in apps:
        # Fetch real version from the store so CBOM/Inventory don't show "unknown".
        # Only fetch for iOS entries (Android entries share the same bundle ID and
        # the iTunes lookup already covers both — avoids a duplicate network call).
        version = "Unknown"
        if app["platform"] == "iOS":
            meta = _fetch_store_metadata(app["id"], "iOS")
            version = meta.get("version", "Unknown")
        result.append({
            "name": app["name"],
            "id": app["id"],
            "platform": app["platform"],
            "status": app["status"],
            "version": version,
            "source": app.get("source"),
        })
    return result

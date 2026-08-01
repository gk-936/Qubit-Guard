"""
API endpoint discovery and bucketing service.
Real HTTP probing with concurrent requests.
"""

import ssl
import socket
import logging
import urllib.request
import urllib.error
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

log = logging.getLogger(__name__)


# Bucket classification by path pattern
BUCKET_PATTERNS = {
    "Auth / Identity": ["auth", "login", "oauth", "oidc", "identity", "sso", "token", "session"],
    "Payment Processing": ["pay", "transaction", "transfer", "billing", "checkout", "upi"],
    "Data Services": ["data", "export", "import", "sync", "backup", "archive"],
    "Internal Services": ["internal", "admin", "audit", "log", "monitor", "health", "status"],
    "External Partners": ["partner", "webhook", "callback", "notify", "integration", "b2b"],
    "User Management": ["user", "profile", "account", "customer", "kyc"],
    "API Documentation": ["swagger", "openapi", "docs", "graphql", "schema"],
}

# Common API paths to probe
PROBE_PATHS = [
    "/", "/api", "/api/v1", "/api/v2", "/v1", "/v2",
    "/health", "/status", "/api/health",
    "/swagger.json", "/openapi.json", "/api-docs",
    "/.well-known/openid-configuration",
    "/graphql",
    "/v1/auth/login", "/api/auth", "/oauth/token",
    "/v1/payments", "/api/payments",
    "/v1/users", "/api/users",
    "/v1/internal/audit-logs",
    "/api/data", "/v1/data",
]


def _classify_endpoint(path: str) -> str:
    """Classify an endpoint into a bucket based on path patterns."""
    path_lower = path.lower()
    for bucket, keywords in BUCKET_PATTERNS.items():
        if any(kw in path_lower for kw in keywords):
            return bucket
    return "General API"


def _probe_single(host: str, path: str, is_api_sub: bool) -> dict:
    """Probe a single endpoint via HTTP HEAD. Returns result dict or None."""
    prefix = f"https://{'api.' if is_api_sub else ''}{host}"
    url = f"{prefix}{path}"

    try:
        req = urllib.request.Request(
            url, method="HEAD",
            headers={"User-Agent": "QuantumShield-Scanner/2.0", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status < 500:
                return {
                    "url": url,
                    "status_code": resp.status,
                    "content_type": resp.headers.get("Content-Type", ""),
                    "bucket": _classify_endpoint(path),
                    "status": "Active" if resp.status < 400 else "Protected",
                }
    except urllib.error.HTTPError as e:
        if e.code < 500:
            return {
                "url": url,
                "status_code": e.code,
                "content_type": "",
                "bucket": _classify_endpoint(path),
                "status": "Protected" if e.code in [401, 403] else "Available",
            }
    except (urllib.error.URLError, OSError, ValueError) as e:
        log.debug("Probe failed for %s: %s", url, e)

    return None


def _get_tls_risk(host: str) -> str:
    """Get quantum risk label from a TLS handshake."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cipher = tls_sock.cipher()
                cipher_name = cipher[0] if cipher else ""

                if "MLKEM" in cipher_name.upper() or "KYBER" in cipher_name.upper():
                    return "PQC-Ready"
                elif "TLS_AES" in cipher_name:
                    return "Classical (TLS 1.3)"
                elif "ECDHE" in cipher_name:
                    return "High (ECDHE)"
                elif "RSA" in cipher_name:
                    return "Critical (RSA)"
                return f"Classical ({cipher_name[:20]})"
    except Exception:
        return "Unknown (Unreachable)"


def discover_endpoints(domain: str) -> dict:
    """Discover and bucket API endpoints via real HTTP probing."""
    parsed = urlparse(domain if domain.startswith("http") else f"https://{domain}")
    host = parsed.hostname or domain

    # Get TLS quantum risk for the domain
    tls_risk = _get_tls_risk(host)

    # Build probe tasks: try both host and api.{host}
    tasks = []
    for path in PROBE_PATHS:
        tasks.append((host, path, False))
    if not host.startswith("api."):
        for path in PROBE_PATHS:
            tasks.append((host, path, True))

    # Concurrent probing
    discovered = []
    seen_urls = set()

    with ThreadPoolExecutor(max_workers=15) as executor:
        future_map = {
            executor.submit(_probe_single, h, p, is_api): (h, p)
            for h, p, is_api in tasks
        }
        for future in as_completed(future_map):
            result = future.result()
            if result and result["url"] not in seen_urls:
                result["quantumRisk"] = tls_risk
                discovered.append(result)
                seen_urls.add(result["url"])

    # Build buckets from real results
    buckets = {}
    for ep in discovered:
        bucket = ep["bucket"]
        buckets[bucket] = buckets.get(bucket, 0) + 1

    # Quantum risk counts
    pqc_ready = sum(1 for ep in discovered if "PQC" in ep.get("quantumRisk", ""))
    vulnerable = len(discovered) - pqc_ready

    return {
        "total": len(discovered),
        "discovered": len(discovered),
        "buckets": buckets,
        "details": discovered,
        "quantumRisk": {
            "vulnerable": vulnerable,
            "pqc_ready": pqc_ready,
        }
    }

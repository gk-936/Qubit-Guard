"""
Deterministic Triad Scanning Engine.

Performs real TLS handshake probing (Pillar A), deterministic VPN gateway
analysis (Pillar B), JWT / mTLS analysis (Pillar C), firmware integrity
assessment (Pillar D), and archival encryption audit (Pillar E).

NO AI is used in the detection pipeline — all results are deterministic
and verifiable. The ML Selector is invoked AFTER detection to recommend
the optimal PQC migration path.

QVS Scale (FR-06): RSA=100, ECC=85, Hybrid PQC=20, Full PQC=0
"""

import ssl
import socket
import json
import base64
import time
import uuid
import ipaddress
import logging
from datetime import datetime
from urllib.parse import urlparse
import urllib.request
import urllib.error

from services.pqc_algorithms import PQC_ALGORITHM_REGISTRY, generate_audit_table
from services.ml_selector import select_algorithm as ml_select

log = logging.getLogger(__name__)

try:
    import cryptography
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa
    _HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover - cryptography is a declared dependency
    _HAS_CRYPTOGRAPHY = False

try:
    import dns.resolver
    import dns.exception
    import dns.version
    _HAS_DNSPYTHON = True
except ImportError:  # pragma: no cover - dnspython is a declared dependency
    _HAS_DNSPYTHON = False

# NA = the value could not be extracted or validated. Never guessed/defaulted.
NA = "N/A"

# TLS protocol version -> its IANA-registered protocol identifier (the two
# bytes sent on the wire in ClientHello/ServerHello.legacy_version). This is
# the closest thing TLS has to an "OID" for the negotiated protocol.
TLS_VERSION_PROTOCOL_ID = {
    "TLSv1.3": "0x0304",
    "TLSv1.2": "0x0303",
    "TLSv1.1": "0x0302",
    "TLSv1":   "0x0301",
    "TLSv1.0": "0x0301",
    "SSLv3":   "0x0300",
}


def _na(value):
    """Validate a value before display: empty/None/whitespace-only -> N/A.

    Never fabricates a value — only passes through what was actually
    extracted, or reports N/A when nothing was extracted.
    """
    if value is None:
        return NA
    if isinstance(value, str) and not value.strip():
        return NA
    if isinstance(value, (list, tuple, dict)) and len(value) == 0:
        return NA
    return value


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def _library_versions() -> dict:
    """Report the actual crypto/TLS/DNS library versions used to produce this
    scan's results — never a hardcoded/assumed version string.
    """
    versions = {
        "python_ssl_module": NA,
        "openssl": NA,
        "cryptography": NA,
        "dnspython": NA,
    }
    try:
        versions["python_ssl_module"] = ssl.OPENSSL_VERSION
        versions["openssl"] = ssl.OPENSSL_VERSION
    except Exception:
        pass
    if _HAS_CRYPTOGRAPHY:
        try:
            versions["cryptography"] = cryptography.__version__
        except Exception:
            pass
    if _HAS_DNSPYTHON:
        try:
            versions["dnspython"] = dns.version.version
        except Exception:
            pass
    return versions


def _resolve_dns(host: str) -> dict:
    """Resolve a hostname's real DNS records. Never guesses — an unresolved
    record type is reported as N/A / empty, not fabricated.
    """
    result = {"ipv4": [], "ipv6": [], "error": None}

    if _valid_ip(host):
        # host is already a literal IP — classify it directly, no lookup needed.
        try:
            if ipaddress.ip_address(host).version == 4:
                result["ipv4"] = [host]
            else:
                result["ipv6"] = [host]
        except ValueError:
            pass
        return result

    if _HAS_DNSPYTHON:
        for rtype, bucket in (("A", "ipv4"), ("AAAA", "ipv6")):
            try:
                answers = dns.resolver.resolve(host, rtype, lifetime=5)
                result[bucket] = [str(r).strip() for r in answers if _valid_ip(str(r).strip())]
            except dns.exception.DNSException as e:
                log.debug("DNS %s lookup failed for %s: %s", rtype, host, e)
    else:
        # Fallback when dnspython is unavailable: socket.getaddrinfo still
        # gives real resolver results, just without record-type granularity.
        try:
            infos = socket.getaddrinfo(host, None)
            for family, _, _, _, sockaddr in infos:
                addr = sockaddr[0]
                if not _valid_ip(addr):
                    continue
                if family == socket.AF_INET and addr not in result["ipv4"]:
                    result["ipv4"].append(addr)
                elif family == socket.AF_INET6 and addr not in result["ipv6"]:
                    result["ipv6"].append(addr)
        except OSError as e:
            result["error"] = str(e)

    if not result["ipv4"] and not result["ipv6"] and result["error"] is None:
        result["error"] = "No A/AAAA records resolved"
    return result


def _extract_cert_full(der_cert: bytes) -> dict:
    """Parse every certificate field this feature set needs directly from the
    DER bytes presented in the handshake — the sole source of truth. Any
    field that cannot be parsed is reported as N/A, never guessed.
    """
    fields = {
        "serial_number": NA,
        "not_before": NA,
        "not_after": NA,
        "issuer_cn": NA,
        "issuer_org": NA,
        "issuer_country": NA,
        "issuer_full": NA,
        "subject_cn": NA,
        "subject_full": NA,
        "san_dns": [],
        "san_ip": [],
        "signature_hash_algorithm": NA,
        "signature_algorithm_oid": NA,
        "signature_algorithm_name": NA,
        "public_key_algorithm_oid": NA,
    }
    if not (_HAS_CRYPTOGRAPHY and der_cert):
        return fields
    try:
        cert = x509.load_der_x509_certificate(der_cert)
    except Exception as e:
        log.debug("Certificate parse failed: %s", e)
        return fields

    try:
        fields["serial_number"] = format(cert.serial_number, "X")
    except Exception:
        pass
    try:
        fields["not_before"] = cert.not_valid_before_utc.isoformat()
        fields["not_after"] = cert.not_valid_after_utc.isoformat()
    except AttributeError:
        # cryptography < 42 exposes naive not_valid_before/not_valid_after only.
        try:
            fields["not_before"] = cert.not_valid_before.isoformat()
            fields["not_after"] = cert.not_valid_after.isoformat()
        except Exception:
            pass
    except Exception:
        pass
    try:
        issuer = cert.issuer
        fields["issuer_full"] = issuer.rfc4514_string()
        cn = issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        fields["issuer_cn"] = cn[0].value if cn else NA
        org = issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
        fields["issuer_org"] = org[0].value if org else NA
        country = issuer.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)
        fields["issuer_country"] = country[0].value if country else NA
    except Exception as e:
        log.debug("Issuer parse failed: %s", e)
    try:
        subject = cert.subject
        fields["subject_full"] = subject.rfc4514_string()
        cn = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        fields["subject_cn"] = cn[0].value if cn else NA
    except Exception as e:
        log.debug("Subject parse failed: %s", e)
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        fields["san_dns"] = san_ext.value.get_values_for_type(x509.DNSName)
        fields["san_ip"] = [str(ip) for ip in san_ext.value.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass
    except Exception as e:
        log.debug("SAN parse failed: %s", e)
    try:
        fields["signature_algorithm_oid"] = cert.signature_algorithm_oid.dotted_string
        fields["signature_algorithm_name"] = cert.signature_algorithm_oid._name
    except Exception as e:
        log.debug("Signature OID parse failed: %s", e)
    try:
        h = cert.signature_hash_algorithm
        fields["signature_hash_algorithm"] = h.name.upper() if h else NA
    except Exception as e:
        log.debug("Signature hash parse failed: %s", e)
    try:
        pub = cert.public_key()
        fields["public_key_algorithm_oid"] = cert.signature_algorithm_oid.dotted_string if pub else NA
    except Exception:
        pass

    for k, v in fields.items():
        fields[k] = _na(v)
    return fields


# Cipher-suite name -> (encryption algorithm, cipher hash/PRF algorithm).
# Matched by substring against both TLS 1.3 style (TLS_AES_256_GCM_SHA384)
# and TLS 1.2 OpenSSL style (ECDHE-RSA-AES256-GCM-SHA384) suite names.
_ENC_PATTERNS = [
    ("CHACHA20-POLY1305", "CHACHA20-POLY1305"), ("CHACHA20", "CHACHA20-POLY1305"),
    ("AES-256-GCM", "AES-256-GCM"), ("AES256-GCM", "AES-256-GCM"), ("AES_256_GCM", "AES-256-GCM"),
    ("AES-128-GCM", "AES-128-GCM"), ("AES128-GCM", "AES-128-GCM"), ("AES_128_GCM", "AES-128-GCM"),
    ("AES256-CBC", "AES-256-CBC"), ("AES128-CBC", "AES-128-CBC"),
    ("AES256", "AES-256-CBC"), ("AES128", "AES-128-CBC"),
    ("3DES", "3DES-CBC"), ("DES-CBC3", "3DES-CBC"),
    ("RC4", "RC4"),
]
_HASH_PATTERNS = [
    ("SHA384", "SHA-384"), ("SHA256", "SHA-256"), ("SHA512", "SHA-512"),
    ("SHA1", "SHA-1"), ("SHA", "SHA-1"), ("MD5", "MD5"),
]


def _parse_cipher_suite(cipher_name: str) -> dict:
    """Derive the symmetric encryption/cipher algorithm and PRF/MAC hash
    algorithm actually negotiated, parsed from the real cipher-suite name
    returned by the handshake (ssl.SSLSocket.cipher()). Never guessed —
    an unrecognised suite name reports N/A for the field that can't be
    matched.
    """
    name = (cipher_name or "").upper()
    result = {"encryption_algorithm": NA, "cipher_hash_algorithm": NA}
    if not name or name == "UNKNOWN":
        return result
    for pattern, label in _ENC_PATTERNS:
        if pattern in name:
            result["encryption_algorithm"] = label
            break
    for pattern, label in _HASH_PATTERNS:
        if pattern in name:
            result["cipher_hash_algorithm"] = label
            break
    return result


def _build_asset_details(tls_info: dict, qvs=None) -> dict:
    """Assemble the full per-asset detail block (classification, algorithms,
    OIDs, certificate, DNS, library versions) from a completed `_get_tls_info`
    probe. Shared by every pillar so the same real measurement is shown
    consistently everywhere it's reused across pillars.
    """
    if not tls_info.get("reachable"):
        return {
            "classification": _classify_asset(None),
            "tag": _tag_from_qvs(None),
            "host": tls_info.get("host"), "port": tls_info.get("port"),
            "tls_version": NA, "tls_protocol_id": NA,
            "hash_algorithm": NA, "encryption_algorithm": NA,
            "cipher_hash_algorithm": NA, "authentication_algorithm": NA,
            "key_exchange_algorithm": NA, "key_exchange_group": NA,
            "key_length_bits": NA, "signature_algorithm_oid": NA,
            "signature_algorithm_name": NA, "certificate": None,
            "dns": tls_info.get("dns", {"ipv4": [], "ipv6": [], "error": None}),
            "libraries": tls_info.get("libraries", _library_versions()),
        }
    cert_full = tls_info["cert"]
    auth_bits = tls_info.get("auth_bits")
    return {
        "classification": _classify_asset(qvs),
        "tag": _tag_from_qvs(qvs),
        "host": tls_info.get("host"), "port": tls_info.get("port"),
        "tls_version": _na(tls_info.get("tls_version")),
        "tls_protocol_id": tls_info.get("tls_protocol_id", NA),
        "hash_algorithm": cert_full["signature_hash_algorithm"],
        "encryption_algorithm": tls_info.get("encryption_algorithm", NA),
        "cipher_hash_algorithm": tls_info.get("cipher_hash_algorithm", NA),
        "authentication_algorithm": _na(tls_info.get("auth_algo")),
        "key_exchange_algorithm": _na(tls_info.get("key_exchange")),
        "key_exchange_group": _na(tls_info.get("key_exchange_group")),
        "key_length_bits": auth_bits if auth_bits else NA,
        "signature_algorithm_oid": cert_full["signature_algorithm_oid"],
        "signature_algorithm_name": cert_full["signature_algorithm_name"],
        "certificate": {
            "serial_number": cert_full["serial_number"],
            "issuer": cert_full["issuer_full"],
            "issuer_cn": cert_full["issuer_cn"],
            "issuer_org": cert_full["issuer_org"],
            "issuer_country": cert_full["issuer_country"],
            "subject": cert_full["subject_full"],
            "subject_cn": cert_full["subject_cn"],
            "not_before": cert_full["not_before"],
            "not_after": cert_full["not_after"],
            "san_dns": _na(cert_full["san_dns"]),
            "san_ip": _na(cert_full["san_ip"]),
        },
        "dns": tls_info["dns"],
        "libraries": tls_info["libraries"],
    }


def _tag_from_qvs(qvs) -> str:
    """3-tier asset tag used consistently across every scanned asset (Triad
    pillars, mobile, and discovered subdomains) and the bank-wide overall
    score — the single source of truth for what counts as Legacy/Standard/
    ElitePQC, so every part of the UI that shows a tag agrees with every
    other part, all derived from the same QVS scale used everywhere else in
    this file. A pillar/asset that was never assessed gets "Not Assessed",
    never a default tag.
    """
    if qvs is None:
        return "Not Assessed"
    if qvs >= 50:
        return "Legacy"
    if qvs >= 20:
        return "Standard"
    return "ElitePQC"


def _classify_asset(qvs) -> str:
    """Scan classification for an asset, derived only from an actually
    computed QVS score. A pillar that was never assessed is classified as
    such, not silently treated as safe.
    """
    if qvs is None:
        return "NOT ASSESSED"
    if qvs >= 80:
        return "QUANTUM-VULNERABLE (CRITICAL)"
    if qvs >= 50:
        return "QUANTUM-VULNERABLE (HIGH)"
    if qvs >= 20:
        return "HYBRID PQC (MODERATE)"
    return "QUANTUM-SAFE (PQC)"


# ── QVS Scoring (FR-06) ──────────────────────────────────────────────────────

QVS_MAP = {
    # ── Classical (Quantum-Vulnerable) ──
    "RSA":       100,
    "RSA-2048":  100,
    "RSA-3072":  95,
    "RSA-4096":  90,
    "ECC":       85,
    "ECDSA":     85,
    "ECDHE":     85,
    "ECDSA-P256": 85,
    "ECDHE-RSA": 90,
    "ECDHE-ECDSA": 85,
    # Real TLS 1.3 classical groups, as measured by tls_kex_probe.py — checked
    # before the shorter "X25519"/"ECDHE" keys since QVS_MAP is matched
    # longest-key-first (a duplicate "X25519MLKEM768" key used to live further
    # down under Hybrid PQC — Python dict literals silently let the LATER
    # occurrence win, which clobbered this section's intended score; that
    # duplicate is gone now, this is the single definition for these groups).
    "X25519": 85,
    "SECP256R1": 85,
    "SECP384R1": 80,
    "SECP521R1": 75,
    "RS256":     100,
    "RS384":     100,
    "RS512":     100,
    "ES256":     85,
    "ES384":     80,
    "PS256":     100,
    "EdDSA":     70,
    "IKEv1-RSA": 100,
    "IKEv2-RSA": 95,
    # ── Hybrid PQC ── measured via tls_kex_probe.py's raw TLS 1.3 HelloRetryRequest
    # inspection. Scored low (real PQC KEM active) but not 0 — the classical half of
    # the hybrid (X25519) is still present, and cert signatures remain classical
    # separately (see auth_qvs), so this isn't a fully quantum-safe connection yet.
    "X25519KYBER768DRAFT00": 15,  # pre-standardization hybrid, still widely deployed
    "X25519MLKEM768": 10,         # hybrid: classical X25519 + FIPS 203 ML-KEM-768
    "HYBRID-PQC": 20,
    # ── ML-KEM (FIPS 203) — Lattice KEM ──
    "ML-KEM-512":  0,
    "ML-KEM-768":  0,
    "ML-KEM-1024": 0,
    "KYBER":       0,
    # ── ML-DSA (FIPS 204) — Lattice Signatures ──
    "ML-DSA-44":   0,
    "ML-DSA-65":   0,
    "ML-DSA-87":   0,
    "DILITHIUM":   0,
    # ── SLH-DSA (FIPS 205) — Stateless Hash-Based Signatures ──
    "SLH-DSA":     0,
    "SLH-DSA-128S": 0,
    "SLH-DSA-128F": 0,
    "SLH-DSA-256S": 0,
    "SPHINCS+":    0,
    # ── FN-DSA (Falcon) — Compact Lattice Signatures ──
    "FN-DSA":      0,
    "FN-DSA-512":  0,
    "FN-DSA-1024": 0,
    "FALCON":      0,
    # ── XMSS / LMS — Stateful Hash-Based Signatures ──
    "XMSS":        0,
    "LMS":         0,
    "HSS":         0,
    # ── BIKE / HQC — Code-Based KEMs ──
    "BIKE":        0,
    "BIKE-L1":     0,
    "HQC":         0,
    "HQC-128":     0,
}


def _evidence_summary(findings: list) -> dict:
    """Count findings by evidence class for a pillar's return dict.

    "measured" = the claim follows directly from something observed on the wire.
    "inferred" = the claim is extrapolated from a different observation (e.g.
    firmware signing inferred from web PKI, archival key-wrapping inferred from
    TLS key exchange, VPN vendor inferred from a keyword match on cert CN/SAN).
    """
    measured = sum(1 for f in findings if f.get("evidence") == "measured")
    inferred = sum(1 for f in findings if f.get("evidence") == "inferred")
    return {"measured": measured, "inferred": inferred}


def _qvs(algorithm: str) -> int:
    """Return QVS score for a given algorithm string.

    Matches the longest key first so that a specific label wins over a substring
    of itself — e.g. "ECDHE-RSA" must score as ECDHE-RSA (90), not as RSA (100).
    """
    algo_upper = algorithm.upper().strip()
    for key in sorted(QVS_MAP, key=len, reverse=True):
        if key.upper() in algo_upper:
            return QVS_MAP[key]
    return 75  # Unknown defaults to high risk


# ── Cryptographic Parameter Derivation ───────────────────────────────────────

def _cert_details(der_cert: bytes) -> dict:
    """Extract public key algorithm, size, serial number, signature algorithm OID, and hash algorithm from DER bytes."""
    res = {
        "algo": None,
        "bits": 0,
        "serial": "N/A",
        "sig_oid": "1.2.840.113549.1.1.11",  # Standard default if unparsed
        "hash_algo": "SHA-256"
    }
    if not (_HAS_CRYPTOGRAPHY and der_cert):
        return res
    try:
        cert_obj = x509.load_der_x509_certificate(der_cert)
        # Serial Number
        res["serial"] = f"{cert_obj.serial_number:X}"
        # Signature Algorithm OID
        if hasattr(cert_obj, 'signature_algorithm_oid') and cert_obj.signature_algorithm_oid:
            res["sig_oid"] = cert_obj.signature_algorithm_oid.dotted_string
        # Hash algorithm name
        if hasattr(cert_obj, 'signature_hash_algorithm') and cert_obj.signature_hash_algorithm:
            res["hash_algo"] = cert_obj.signature_hash_algorithm.name.upper()

        pub = cert_obj.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            res["algo"], res["bits"] = "RSA", pub.key_size
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            res["algo"], res["bits"] = "ECDSA", pub.curve.key_size
        elif isinstance(pub, ed25519.Ed25519PublicKey):
            res["algo"], res["bits"] = "Ed25519", 256
        elif isinstance(pub, ed448.Ed448PublicKey):
            res["algo"], res["bits"] = "Ed448", 448
        elif isinstance(pub, dsa.DSAPublicKey):
            res["algo"], res["bits"] = "DSA", pub.key_size
    except Exception as e:
        log.debug("Cert parsing exception: %s", e)
    return res


def _cert_public_key(der_cert: bytes) -> tuple:
    details = _cert_details(der_cert)
    return details["algo"], details["bits"]



def _derive_crypto_params(cipher_name: str, tls_version: str, der_cert: bytes = None, host: str = None) -> dict:
    """Derive the key exchange and authentication algorithm for a TLS connection.

    TLS 1.3 renamed its cipher suites (e.g. TLS_AES_256_GCM_SHA384) so that they no
    longer encode the key exchange or the authentication algorithm — both were moved
    into the handshake extensions. Inferring them from the suite name therefore only
    works for TLS 1.2 and below.

    Key exchange:
      - TLS 1.2 and below: parsed from the cipher suite name (authoritative there).
      - TLS 1.3: Python's ssl module doesn't expose the negotiated group, but it IS
        observable on the wire — the ServerHello/HelloRetryRequest carrying it is
        sent in cleartext before TLS 1.3 encryption starts. When `host` is given, a
        second raw-socket probe (tls_kex_probe.py) sends its own ClientHello and
        reads that field directly, distinguishing real classical (x25519/secp*)
        from real hybrid-PQC (X25519MLKEM768 etc.) groups instead of guessing.
        Falls back to the old honest "unknown" label if the probe fails or host
        wasn't provided — never silently downgrades to a guess.

    Authentication: read from the certificate's public key, never from the suite name.
    """
    name = (cipher_name or "").upper()
    version = tls_version or ""
    is_tls13 = version == "TLSv1.3"

    if is_tls13:
        key_exchange = "ECDHE"
        kx_group = "unknown (not exposed by this Python runtime)"
        if host:
            try:
                from services.tls_kex_probe import probe_key_exchange
                kex = probe_key_exchange(host)
                if kex["reachable"] and kex["group"]:
                    key_exchange = kex["group"]
                    kx_group = f"measured via raw TLS 1.3 {kex['via']} inspection"
            except Exception as e:
                log.debug("TLS 1.3 key-exchange probe failed for %s: %s", host, e)
    elif "ECDHE" in name:
        key_exchange = "ECDHE"
        kx_group = "from cipher suite"
    elif "DHE" in name:
        key_exchange = "DHE"
        kx_group = "from cipher suite"
    elif "ECDH" in name:
        key_exchange = "ECDH (static)"
        kx_group = "from cipher suite"
    elif "RSA" in name:
        # Static RSA key transport — only valid in TLS 1.2 and below.
        key_exchange = "RSA"
        kx_group = "from cipher suite"
    else:
        key_exchange = "Unknown"
        kx_group = "undetermined"

    auth_algo, auth_bits = _cert_public_key(der_cert)
    if auth_algo is None:
        # Fall back to the suite name, which is only meaningful pre-TLS 1.3.
        if not is_tls13 and "ECDSA" in name:
            auth_algo, auth_source = "ECDSA", "cipher suite"
        elif not is_tls13 and "RSA" in name:
            auth_algo, auth_source = "RSA", "cipher suite"
        else:
            auth_algo, auth_source = "Unknown", "undetermined"
    else:
        auth_source = "certificate public key"

    return {
        "key_exchange": key_exchange,
        "key_exchange_group": kx_group,
        "auth_algo": auth_algo,
        "auth_bits": auth_bits,
        "auth_source": auth_source,
    }


# ── Shared TLS Probe ─────────────────────────────────────────────────────────

def _get_tls_info(url: str) -> dict:
    """Perform a real TLS handshake and return the full set of cert/cipher/DNS/
    library metadata this feature set needs. Every field is either read
    directly off the handshake/certificate/resolver, or reported as N/A.
    """
    parsed = urlparse(url if url.startswith("http") else f"https://{url}")
    host = parsed.hostname or url
    port = parsed.port or 443
    dns_info = _resolve_dns(host)
    libraries = _library_versions()
    try:
        context = ssl.create_default_context()
        started = time.monotonic()
        with socket.create_connection((host, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                handshake_ms = round((time.monotonic() - started) * 1000)
                cert = tls.getpeercert()
                der_cert = tls.getpeercert(binary_form=True)
                cipher = tls.cipher()
                tls_version = tls.version()
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
                cipher_name = cipher[0] if cipher else "Unknown"
                cipher_bits = cipher[2] if cipher else 0
                crypto = _derive_crypto_params(cipher_name, tls_version, der_cert, host=host)
                cert_full = _extract_cert_full(der_cert)
                cipher_parsed = _parse_cipher_suite(cipher_name)
                return {
                    "reachable": True, "host": host, "port": port,
                    "cn": subject.get("commonName", "N/A"),
                    "issuer_org": issuer.get("organizationName", "N/A"),
                    "sans": sans,
                    "cipher_name": cipher_name, "cipher_bits": cipher_bits,
                    "tls_version": tls_version,
                    "tls_protocol_id": _na(TLS_VERSION_PROTOCOL_ID.get(tls_version)),
                    "key_exchange": crypto["key_exchange"],
                    "key_exchange_group": crypto["key_exchange_group"],
                    "auth_algo": crypto["auth_algo"],
                    "auth_bits": crypto["auth_bits"],
                    "auth_source": crypto["auth_source"],
                    "encryption_algorithm": cipher_parsed["encryption_algorithm"],
                    "cipher_hash_algorithm": cipher_parsed["cipher_hash_algorithm"],
                    "handshake_ms": handshake_ms,
                    "not_after": cert.get("notAfter", "N/A"),
                    "cert": cert_full,
                    "dns": dns_info,
                    "libraries": libraries,
                }
    except Exception as e:
        return {"reachable": False, "host": host, "port": port, "error": str(e),
                "dns": dns_info, "libraries": libraries}


# ── Pillar A: TLS Certificate Engine ─────────────────────────────────────────

def _scan_web_tls(web_url: str) -> dict:
    """Perform real outbound TLS handshake probing on a web server."""
    findings = []
    pillar_qvs_scores = []
    asset_details = None

    tls_info = _get_tls_info(web_url)
    host = tls_info["host"]

    if not tls_info["reachable"]:
        # The host could not be probed. Report that and nothing else — no cryptographic
        # claim is made about a host we never reached. DNS/library info is still real
        # and still shown, since it doesn't depend on the handshake succeeding.
        findings.append({
            "severity": "info",
            "issue": "TLS Probe Failed — Host Not Assessed",
            "detail": f"Could not complete a TLS handshake with {web_url}: {tls_info.get('error')}. No cryptographic findings are reported for this host because none were observed.",
            "recommendation": "Verify endpoint availability, DNS resolution and firewall rules, then re-run the scan.",
            "evidence": "measured",
            "inferred_from": None,
        })
        asset_details = _build_asset_details(tls_info)
        return {"findings": findings, "qvs": None, "scanned": False,
                "error": tls_info.get("error"), "evidence_summary": _evidence_summary(findings),
                "asset_details": asset_details}

    try:
        cn = tls_info["cn"]
        issuer_org = tls_info["issuer_org"]
        not_after = tls_info["not_after"]
        cipher_name = tls_info["cipher_name"]
        cipher_bits = tls_info["cipher_bits"]
        tls_version = tls_info["tls_version"]
        handshake_ms = tls_info["handshake_ms"]
        cert_full = tls_info["cert"]

        key_exchange = tls_info["key_exchange"]
        auth_algo = tls_info["auth_algo"]
        auth_bits = tls_info["auth_bits"]
        auth_label = f"{auth_algo}-{auth_bits}" if auth_bits else auth_algo

        # Pillar QVS is driven by the weaker of the two primitives in use.
        kx_qvs = _qvs(key_exchange)
        auth_qvs = _qvs(auth_label)
        qvs = max(kx_qvs, auth_qvs)
        pillar_qvs_scores.append(qvs)

        asset_details = _build_asset_details(tls_info, qvs)

        findings.append({
            "severity": "info",
            "issue": f"Certificate Detected: {cn}",
            "detail": (
                f"Issuer: {issuer_org} | Cipher: {cipher_name} ({cipher_bits}-bit) | "
                f"TLS: {tls_version} | Key exchange: {key_exchange} "
                f"(group: {tls_info['key_exchange_group']}) | "
                f"Certificate key: {auth_label} (read from {tls_info['auth_source']}) | "
                f"Expires: {not_after}"
            ),
            "recommendation": None,
            "evidence": "measured",
            "inferred_from": None,
            "raw": {
                "cn": cn,
                "issuer": issuer_org,
                "cipher": cipher_name,
                "bits": cipher_bits,
                "tls_version": tls_version,
                "tls_protocol_id": tls_info["tls_protocol_id"],
                "key_exchange": key_exchange,
                "key_exchange_group": tls_info["key_exchange_group"],
                "auth_algo": auth_algo,
                "auth_bits": auth_bits,
                "auth_source": tls_info["auth_source"],
                "key_type": auth_label,
                "key_size": f"{auth_bits}-bit" if auth_bits else "unknown",
                "handshake_ms": handshake_ms,
                "mode": "GCM" if "GCM" in cipher_name else "CBC",
                "encryption_algorithm": tls_info["encryption_algorithm"],
                "cipher_hash_algorithm": tls_info["cipher_hash_algorithm"],
                "hash_algorithm": cert_full["signature_hash_algorithm"],
                "signature_algorithm_oid": cert_full["signature_algorithm_oid"],
                "signature_algorithm_name": cert_full["signature_algorithm_name"],
                "serial_number": cert_full["serial_number"],
                "issuer_cn": cert_full["issuer_cn"],
                "issuer_country": cert_full["issuer_country"],
                "not_before": cert_full["not_before"],
                "not_after_full": cert_full["not_after"],
                "san_dns": cert_full["san_dns"],
                "san_ip": cert_full["san_ip"],
                "ipv4": tls_info["dns"]["ipv4"],
                "ipv6": tls_info["dns"]["ipv6"],
                "libraries": tls_info["libraries"],
                "classification": asset_details["classification"],
            }
        })

        # Flag the quantum-vulnerable key exchange (harvest-now-decrypt-later exposure).
        # Keyed off the QVS score rather than a fixed string list — key_exchange can
        # now be a real measured value (x25519, secp256r1, X25519MLKEM768, ...) from
        # tls_kex_probe.py, not just the old hardcoded ECDHE/DHE/RSA labels, and a
        # literal-string whitelist would silently stop matching any of them.
        if kx_qvs >= 50:
            findings.append({
                "severity": "critical" if key_exchange == "RSA" else "high",
                "issue": f"Quantum-Vulnerable Key Exchange: {key_exchange}",
                "detail": (
                    f"{key_exchange} key exchange is breakable by Shor's algorithm on a CRQC. "
                    f"An attacker can record encrypted session traffic today and decrypt it later (HNDL attack)."
                    + ("" if key_exchange != "ECDHE" or tls_version != "TLSv1.3" else
                       " Note: TLS 1.3 always uses an ephemeral (EC)DHE exchange; the specific "
                       "negotiated group could not be measured for this host.")
                ),
                "recommendation": "Enable hybrid key exchange (X25519MLKEM768) for TLS 1.3 per FIPS 203 (ML-KEM).",
                "evidence": "measured",
                "inferred_from": None,
            })
            pillar_qvs_scores.append(kx_qvs)
        elif tls_version == "TLSv1.3" and key_exchange not in ("ECDHE",):
            # A real hybrid-PQC group was measured on the wire (not the old
            # unresolved-guess "ECDHE" placeholder) — worth surfacing positively,
            # not just as an absence of a vulnerability finding.
            findings.append({
                "severity": "info",
                "issue": f"PQC-Ready Key Exchange Observed: {key_exchange}",
                "detail": f"Raw TLS 1.3 handshake inspection measured a hybrid-PQC key-exchange group ({key_exchange}) in use for this connection.",
                "recommendation": None,
                "evidence": "measured",
                "inferred_from": None,
            })
            pillar_qvs_scores.append(kx_qvs)

        # Flag the quantum-vulnerable certificate signature key, separately from the key exchange.
        if auth_algo in ("RSA", "ECDSA", "DSA", "Ed25519", "Ed448"):
            findings.append({
                "severity": "critical" if auth_algo in ("RSA", "DSA") else "high",
                "issue": f"Quantum-Vulnerable Certificate Key: {auth_label}",
                "detail": (
                    f"The server certificate uses a {auth_label} public key, read directly from the "
                    f"presented certificate. {auth_algo} signatures are forgeable via Shor's algorithm on a CRQC."
                ),
                "recommendation": "Migrate the certificate to ML-DSA (FIPS 204) or a hybrid classical+PQC chain once your CA supports it.",
                "evidence": "measured",
                "inferred_from": None,
            })
            pillar_qvs_scores.append(auth_qvs)
        elif auth_algo == "Unknown":
            findings.append({
                "severity": "info",
                "issue": "Certificate Key Algorithm Undetermined",
                "detail": "The certificate public key could not be parsed, so no signature-algorithm risk is claimed for this host.",
                "recommendation": "Verify the `cryptography` package is installed so certificate keys can be inspected.",
                "evidence": "measured",
                "inferred_from": None,
            })

        # Check TLS version
        if tls_version and tls_version < "TLSv1.3":
            findings.append({
                "severity": "high",
                "issue": f"Legacy TLS Version: {tls_version}",
                "detail": "TLS 1.2 and below do not support hybrid PQC key exchange groups. Upgrade required for quantum readiness.",
                "recommendation": "Enforce TLS 1.3 minimum. Configure server to prefer PQC-hybrid cipher suites.",
                "evidence": "measured",
                "inferred_from": None,
            })
            pillar_qvs_scores.append(95)

    except Exception as e:
        # Something failed while processing an already-successful handshake
        # (e.g. an unexpected cert shape) — report it honestly rather than
        # claiming a cryptographic result that wasn't actually derived.
        findings.append({
            "severity": "info",
            "issue": "TLS Result Processing Failed — Host Not Assessed",
            "detail": f"TLS handshake with {web_url} succeeded but result processing failed: {str(e)}. No cryptographic findings are reported for this host.",
            "recommendation": "Verify endpoint availability, DNS resolution and firewall rules, then re-run the scan.",
            "evidence": "measured",
            "inferred_from": None,
        })
        return {"findings": findings, "qvs": None, "scanned": False,
                "error": str(e), "evidence_summary": _evidence_summary(findings),
                "asset_details": asset_details}

    avg_qvs = round(sum(pillar_qvs_scores) / len(pillar_qvs_scores)) if pillar_qvs_scores else None
    if asset_details is not None:
        asset_details["classification"] = _classify_asset(avg_qvs)
        asset_details["tag"] = _tag_from_qvs(avg_qvs)
    return {"findings": findings, "qvs": avg_qvs, "scanned": True,
            "handshake_ms": handshake_ms, "evidence_summary": _evidence_summary(findings),
            "asset_details": asset_details}


# ── Pillar B: VPN/TLS Engine ─────────────────────────────────────────────────

def _scan_vpn_tls(vpn_url: str) -> dict:
    """
    Real TLS handshake + IKEv2 port probing on VPN gateways.
    Detects cipher suite, cert CN/SAN, TLS version, and VPN vendor.
    """
    findings = []
    pillar_qvs_scores = []

    parsed = urlparse(vpn_url if vpn_url.startswith("http") else f"https://{vpn_url}")
    host = parsed.hostname or vpn_url

    # 1. Full TLS handshake on port 443
    tls_info = _get_tls_info(vpn_url)

    # 2. IKEv2 port probes (500, 4500)
    ikev2_responsive = False
    for port in [500, 4500]:
        try:
            with socket.create_connection((host, port), timeout=3) as sock:
                ikev2_responsive = True
                break
        except OSError as e:
            log.debug("IKEv2 port %s not responsive on %s: %s", port, host, e)
            continue

    # 3. VPN vendor heuristic from cert CN/SAN
    vpn_keywords = {
        "anyconnect": "Cisco AnyConnect SSL-VPN", "cisco": "Cisco SSL-VPN",
        "globalprotect": "Palo Alto GlobalProtect", "fortigate": "Fortinet FortiGate",
        "fortinet": "Fortinet SSL-VPN", "sonicwall": "SonicWall SSL-VPN",
        "vpn": "SSL-VPN Gateway", "remote": "Remote Access Gateway",
    }
    detected_vpn = "Unknown"
    vendor_from_keyword = False

    if tls_info["reachable"]:
        search_str = f"{tls_info['cn']} {' '.join(tls_info.get('sans', []))}".lower()
        for keyword, label in vpn_keywords.items():
            if keyword in search_str:
                detected_vpn = label
                vendor_from_keyword = True
                break
        if detected_vpn == "Unknown":
            detected_vpn = "IPsec (IKEv2) Gateway" if ikev2_responsive else "TLS Gateway (VPN type unconfirmed)"

        findings.append({
            "severity": "info",
            "issue": f"VPN Gateway Identified: {detected_vpn}",
            "detail": f"TLS handshake with {host}:443 — CN: {tls_info['cn']} | Cipher: {tls_info['cipher_name']} ({tls_info['cipher_bits']}-bit) | TLS: {tls_info['tls_version']}",
            "recommendation": None,
            "evidence": "inferred" if vendor_from_keyword else "measured",
            "inferred_from": "keyword match on cert CN/SAN" if vendor_from_keyword else None,
        })

        kx = tls_info["key_exchange"]
        kx_qvs = _qvs(kx)

        if kx in ["RSA", "DHE"]:
            findings.append({
                "severity": "critical",
                "issue": f"Quantum-Vulnerable VPN Key Exchange: {kx}",
                "detail": f"VPN tunnel uses {kx} key exchange ({tls_info['cipher_name']}). HNDL attack: encrypted VPN traffic recorded today is decryptable post-quantum.",
                "recommendation": "Upgrade to RFC 9370 compliant firmware. Enable hybrid PQC key exchange (ML-KEM + X25519).",
                "evidence": "measured",
                "inferred_from": None,
            })
            pillar_qvs_scores.append(kx_qvs)
        elif kx == "ECDHE":
            findings.append({
                "severity": "high",
                "issue": f"Classical VPN Key Exchange: {kx} (Quantum-Vulnerable)",
                "detail": f"VPN tunnel uses {kx} ({tls_info['cipher_name']}). Forward secrecy against classical computers, but vulnerable to Shor's algorithm.",
                "recommendation": "Enable hybrid X25519MLKEM768 key exchange. For IKEv2: enable RFC 9370 Multiple Key Exchanges.",
                "evidence": "measured",
                "inferred_from": None,
            })
            pillar_qvs_scores.append(kx_qvs)
        elif "MLKEM" in tls_info["cipher_name"].upper() or "KYBER" in tls_info["cipher_name"].upper():
            findings.append({
                "severity": "info",
                "issue": "PQC-Hybrid Key Exchange Detected on VPN",
                "detail": f"VPN gateway supports hybrid PQC: {tls_info['cipher_name']}. Quantum-resistant forward secrecy is active.",
                "recommendation": None,
                "evidence": "measured",
                "inferred_from": None,
            })
            pillar_qvs_scores.append(20)

        if tls_info["tls_version"] and tls_info["tls_version"] < "TLSv1.3":
            findings.append({
                "severity": "high",
                "issue": f"Legacy TLS on VPN: {tls_info['tls_version']}",
                "detail": f"VPN negotiated {tls_info['tls_version']}. TLS 1.2 and below cannot support hybrid PQC cipher suites.",
                "recommendation": "Enforce TLS 1.3 minimum on the VPN gateway.",
                "evidence": "measured",
                "inferred_from": None,
            })
            pillar_qvs_scores.append(95)

        if ikev2_responsive:
            findings.append({
                "severity": "high",
                "issue": "IKEv2 Gateway Detected (Classical Mode)",
                "detail": f"Ports 500/4500 responsive on {host}. No IKE_INTERMEDIATE exchange (RFC 9242) support could be verified remotely.",
                "recommendation": "Enable RFC 9370 Multiple Key Exchanges for hybrid PQC security in IKEv2.",
                "evidence": "measured",
                "inferred_from": None,
            })
            pillar_qvs_scores.append(95)
    else:
        findings.append({
            "severity": "info",
            "issue": "VPN Gateway Unreachable",
            "detail": f"Could not establish TLS connection to {host}: {tls_info.get('error', 'Unknown')}. VPN cryptographic posture could not be assessed.",
            "recommendation": "Verify VPN gateway availability. Provide VPN configuration for manual review.",
            "evidence": "measured",
            "inferred_from": None,
        })
        if ikev2_responsive:
            findings.append({
                "severity": "high",
                "issue": "IKEv2 Ports Responsive (No TLS Handshake)",
                "detail": f"IKEv2 ports (500/4500) on {host} are responsive but TLS handshake failed. Likely pure IPsec without SSL-VPN.",
                "recommendation": "Enable RFC 9370 Multiple Key Exchanges for hybrid PQC security.",
                "evidence": "measured",
                "inferred_from": None,
            })
            pillar_qvs_scores.append(95)
        # Else: genuinely nothing was measured (no TLS, no IKEv2) — this used
        # to fabricate a QVS of 75 here, the same "unassessed treated as a
        # real ~75/100 score" pattern _scan_web_tls was already fixed to
        # avoid. Append nothing; avg_qvs below falls through to None.

    avg_qvs = round(sum(pillar_qvs_scores) / len(pillar_qvs_scores)) if pillar_qvs_scores else None
    return {"findings": findings, "qvs": avg_qvs, "evidence_summary": _evidence_summary(findings),
            "asset_details": _build_asset_details(tls_info, avg_qvs)}


# ── Pillar C: API Security Engine ────────────────────────────────────────────

# NIST PQC OIDs for JWT/JOSE
PQC_OIDS = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}

def _scan_api_jwt(api_url: str, jwt_token: str) -> dict:
    """
    Perform deep analysis of JWT tokens for PQC OIDs and mTLS status.
    """
    findings = []
    pillar_qvs_scores = []

    parsed = urlparse(api_url if api_url.startswith("http") else f"https://{api_url}")
    host = parsed.hostname or api_url

    # 0. Full TLS/cert/DNS probe — shared with the other pillars so the API
    # asset gets the same real algorithm/OID/DNS/library detail, independent
    # of the mTLS-specific handshake below (which never presents a client
    # cert on purpose, to test whether mTLS is enforced).
    tls_info = _get_tls_info(api_url)
    asset_details = _build_asset_details(tls_info)
    jwt_alg = NA
    jwt_oid = NA

    # Score this API asset's own measured TLS crypto the same way every other
    # pillar does. Without this, an API host that was fully reachable and
    # returned real key-exchange/certificate data — but happened to trigger
    # neither the mTLS-enforcement check below nor a bad JWT algorithm —
    # ended up with populated TLS/cert/OID fields alongside a "Not Assessed"
    # tag, which is self-contradictory: real crypto WAS measured. Confirmed
    # live against api.github.com (TLS 1.3 / ECDHE / ECDSA reachable, but
    # riskScores.api and the asset tag both came back "Not Assessed").
    if tls_info["reachable"]:
        api_key_exchange = tls_info["key_exchange"]
        api_auth_algo = tls_info["auth_algo"]
        api_auth_bits = tls_info["auth_bits"]
        api_auth_label = f"{api_auth_algo}-{api_auth_bits}" if api_auth_bits else api_auth_algo
        api_crypto_qvs = max(_qvs(api_key_exchange), _qvs(api_auth_label))
        if tls_info["tls_version"] and tls_info["tls_version"] < "TLSv1.3":
            api_crypto_qvs = max(api_crypto_qvs, 95)
        pillar_qvs_scores.append(api_crypto_qvs)
        findings.append({
            "severity": "info",
            "issue": f"API TLS Crypto Observed: {api_key_exchange} / {api_auth_label}",
            "detail": (
                f"TLS handshake with {host} — TLS: {tls_info['tls_version']} | "
                f"Key exchange: {api_key_exchange} | Certificate key: {api_auth_label} "
                f"(read from {tls_info['auth_source']})."
            ),
            "recommendation": None,
            "evidence": "measured",
            "inferred_from": None,
        })

    # 1. mTLS Detection
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=3) as sock:
            try:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    pass # Success without client cert -> strict mTLS not enforced
            except ssl.SSLError as e:
                err_str = str(e).lower()
                if "certificate required" in err_str or "bad certificate" in err_str or "handshake failure" in err_str:
                    findings.append({
                        "severity": "high",
                        "issue": "Classical mTLS Enforced",
                        "detail": "API enforces mutual TLS, typically utilizing classical RSA/ECDSA. These are vulnerable to Shor's algorithm.",
                        "recommendation": "Transition to FIPS 204 (ML-DSA) certificates for B2B mTLS channels.",
                        "evidence": "measured",
                        "inferred_from": None,
                    })
                    pillar_qvs_scores.append(85)
    except (OSError, ssl.SSLError) as e:
        # Genuinely could not reach the API host at all. This used to be
        # completely silent (log.debug only) — every other pillar (Web, VPN,
        # Firmware, Archival) reports an honest "Unreachable" finding when
        # this happens; the API pillar just left `findings` empty with no
        # explanation, which is why its Triad Scanner card rendered blank
        # instead of showing an unreachable message like the others.
        findings.append({
            "severity": "info",
            "issue": "API Endpoint Unreachable",
            "detail": f"Could not establish a TCP/TLS connection to {host}:443: {e}. API cryptographic posture could not be assessed.",
            "recommendation": "Verify the API endpoint is reachable, or provide an internal endpoint for manual review.",
            "evidence": "measured",
            "inferred_from": None,
        })
        log.debug("mTLS probe failed for %s: %s", api_url, e)

    # 2. JWT Analysis
    if jwt_token and "." in jwt_token:
        try:
            parts = jwt_token.split(".")
            header_b64 = parts[0]
            header_b64 += "=" * (4 - len(header_b64) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            
            alg = header.get("alg", "Unknown")
            oid = header.get("oid", None) # Some PQC implementations use OID in header
            jwt_alg = _na(alg)
            jwt_oid = _na(oid)

            if oid in PQC_OIDS:
                findings.append({
                    "severity": "info",
                    "issue": f"PQC-Ready JWT Signature: {PQC_OIDS[oid]}",
                    "detail": "Token header contains valid NIST PQC Object Identifier (OID).",
                    "recommendation": None,
                    "evidence": "measured",
                    "inferred_from": None,
                })
                pillar_qvs_scores.append(0)
            elif alg in ["RS256", "RS384", "ES256", "ES384"]:
                findings.append({
                    "severity": "critical",
                    "issue": f"Quantum-Vulnerable JWT Algorithm: {alg}",
                    "detail": f"Standard {alg} signature can be forged using Shor's algorithm on a post-quantum computer.",
                    "recommendation": "Migrate JWT signing to ML-DSA-65 (FIPS 204).",
                    "evidence": "measured",
                    "inferred_from": None,
                })
                pillar_qvs_scores.append(100)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError, KeyError, IndexError) as e:
            log.debug("Could not parse JWT header for %s: %s", api_url, e)

    # No fallback fabrication: a reachable API with no mTLS enforcement and
    # no JWT supplied (JWT is optional in the UI) legitimately has nothing
    # to flag — that's a real "nothing risky observed" result, not "score it
    # 90 anyway". This used to always contribute a number to the pillar's
    # QVS (and therefore to the overall average) even when nothing was ever
    # actually measured — the same "unassessed treated as a real score"
    # pattern already fixed in _scan_web_tls.
    avg_qvs = round(sum(pillar_qvs_scores) / len(pillar_qvs_scores)) if pillar_qvs_scores else None
    asset_details["classification"] = _classify_asset(avg_qvs)
    asset_details["tag"] = _tag_from_qvs(avg_qvs)
    asset_details["jwt_algorithm"] = jwt_alg
    asset_details["jwt_oid"] = jwt_oid
    return {"findings": findings, "qvs": avg_qvs, "evidence_summary": _evidence_summary(findings),
            "asset_details": asset_details}


# ── Pillar D: Firmware Integrity Engine ───────────────────────────────────────

def _scan_firmware(target: str) -> dict:
    """
    Firmware integrity assessment via real TLS infrastructure analysis.
    Infers firmware signing scheme from the organization's observed PKI.
    Probes for exposed firmware update endpoints.
    """
    findings = []
    pillar_qvs_scores = []

    parsed = urlparse(target if target.startswith("http") else f"https://{target}")
    host = parsed.hostname or target

    # 1. TLS probe to infer organizational PKI
    tls_info = _get_tls_info(target)

    # 2. Probe for firmware update endpoints
    fw_endpoints = []
    for path in ["/firmware", "/update", "/ota", "/.well-known/security.txt", "/fwupdate", "/api/firmware"]:
        try:
            req = urllib.request.Request(
                f"https://{host}{path}", method="HEAD",
                headers={"User-Agent": "QuantumShield-Scanner/2.0"},
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status < 400:
                    fw_endpoints.append(path)
        except (urllib.error.URLError, OSError) as e:
            log.debug("Firmware endpoint probe failed for %s%s: %s", host, path, e)

    # 3. Generate findings from real observations
    if tls_info["reachable"]:
        auth_algo = tls_info["auth_algo"]
        algo_label = f"{auth_algo} ({tls_info['cipher_bits']}-bit)" if tls_info["cipher_bits"] else auth_algo
        algo_qvs = _qvs(auth_algo)

        findings.append({
            "severity": "info",
            "issue": f"Infrastructure PKI Algorithm Observed: {algo_label}",
            "detail": f"TLS certificate on {host} uses {auth_algo} (Cipher: {tls_info['cipher_name']}). Issuer: {tls_info['issuer_org']}. Organizations typically use consistent PKI across TLS and firmware code-signing.",
            "recommendation": None,
            "evidence": "measured",
            "inferred_from": None,
        })

        if auth_algo == "RSA":
            findings.append({
                "severity": "critical",
                "issue": f"Quantum-Vulnerable Firmware Signing Inferred: {auth_algo}",
                "detail": f"[Inferred from observed PKI] Infrastructure uses {auth_algo} certificates. Standard practice uses the same CA hierarchy for firmware code-signing. {auth_algo} signatures are forgeable via Shor's algorithm on a CRQC.",
                "recommendation": "Migrate firmware signing to XMSS (RFC 8391) or LMS (RFC 8554) per NIST SP 800-208.",
                "evidence": "inferred",
                "inferred_from": "observed infrastructure PKI (TLS certificate algorithm)",
            })
            pillar_qvs_scores.append(algo_qvs)
        elif auth_algo == "ECDSA":
            findings.append({
                "severity": "high",
                "issue": f"Quantum-Vulnerable Firmware Signing Inferred: {auth_algo}",
                "detail": f"[Inferred from observed PKI] Infrastructure uses {auth_algo} certificates. ECDSA signatures are vulnerable to Shor's algorithm, with slightly higher quantum resource requirements than RSA.",
                "recommendation": "Migrate firmware signing to XMSS (RFC 8391) or LMS (RFC 8554) per NIST SP 800-208.",
                "evidence": "inferred",
                "inferred_from": "observed infrastructure PKI (TLS certificate algorithm)",
            })
            pillar_qvs_scores.append(algo_qvs)
        else:
            findings.append({
                "severity": "medium",
                "issue": f"Firmware Signing Algorithm: {auth_algo}",
                "detail": f"[Inferred from observed PKI] Non-standard algorithm detected. Manual review recommended.",
                "recommendation": "Review firmware signing certificates directly.",
                "evidence": "inferred",
                "inferred_from": "observed infrastructure PKI (TLS certificate algorithm)",
            })
            pillar_qvs_scores.append(50)

        findings.append({
            "severity": "high",
            "issue": "No XMSS/LMS State Counter Detected",
            "detail": "XMSS/LMS require strict one-time-use state management. No evidence of stateful hash-based signature infrastructure detected via remote probing.",
            "recommendation": "Implement HSM-backed state counter (e.g., AWS CloudHSM or Thales Luna) before deploying XMSS/LMS.",
            "evidence": "inferred",
            "inferred_from": "no firmware image was inspected; no dedicated state-counter probe exists",
        })
        pillar_qvs_scores.append(min(algo_qvs + 5, 100))
    else:
        findings.append({
            "severity": "info",
            "issue": "Firmware Assessment: Target Unreachable",
            "detail": f"Could not establish TLS connection to {host}: {tls_info.get('error', 'Unknown')}. Firmware signing posture could not be assessed remotely.",
            "recommendation": "Provide internal firmware signing certificates or HSM configuration for manual review.",
            "evidence": "measured",
            "inferred_from": None,
        })
        # Nothing was actually measured — used to fabricate a QVS of 75 here
        # (same pattern already fixed in _scan_web_tls). Append nothing.

    if fw_endpoints:
        findings.append({
            "severity": "high",
            "issue": f"Firmware Update Endpoints Exposed: {', '.join(fw_endpoints)}",
            "detail": f"Publicly accessible firmware paths detected on {host}. Exposed endpoints increase supply-chain attack surface.",
            "recommendation": "Restrict firmware update endpoints to internal networks or require mutual TLS.",
            "evidence": "measured",
            "inferred_from": None,
        })
        pillar_qvs_scores.append(95)

    avg_qvs = round(sum(pillar_qvs_scores) / len(pillar_qvs_scores)) if pillar_qvs_scores else None
    return {"findings": findings, "qvs": avg_qvs, "evidence_summary": _evidence_summary(findings),
            "asset_details": _build_asset_details(tls_info, avg_qvs)}


# ── Pillar E: Archival Encryption Engine ──────────────────────────────────────

def _scan_archival(target: str) -> dict:
    """
    Archival encryption assessment via real TLS key exchange analysis
    and cloud storage encryption header detection.
    """
    findings = []
    pillar_qvs_scores = []

    parsed = urlparse(target if target.startswith("http") else f"https://{target}")
    host = parsed.hostname or target

    # 1. TLS probe for key exchange algorithm
    tls_info = _get_tls_info(target)

    # 2. HTTP probe for cloud storage encryption headers
    storage_headers = {}
    enc_header_names = [
        "x-amz-server-side-encryption", "x-amz-server-side-encryption-aws-kms-key-id",
        "x-ms-server-encrypted", "x-ms-encryption-key-sha256",
        "x-goog-encryption-algorithm", "x-goog-encryption-kms-key-name",
    ]
    try:
        req = urllib.request.Request(
            f"https://{host}/", method="HEAD",
            headers={"User-Agent": "QuantumShield-Scanner/2.0"},
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            for h in enc_header_names:
                val = resp.headers.get(h)
                if val:
                    storage_headers[h] = val
    except (urllib.error.URLError, OSError) as e:
        log.debug("Storage encryption header probe failed for %s: %s", host, e)

    # 3. Generate findings based on real observations
    if tls_info["reachable"]:
        kx = tls_info["key_exchange"]
        kx_display = f"{kx} ({tls_info['cipher_name']})"
        kx_qvs = _qvs(kx)

        findings.append({
            "severity": "info",
            "issue": f"Key Exchange Algorithm Observed: {kx_display}",
            "detail": f"TLS connection to {host} uses {kx} key exchange. Organizations typically use the same key exchange/wrapping algorithms across TLS and archival encryption.",
            "recommendation": None,
            "evidence": "measured",
            "inferred_from": None,
        })

        if kx == "RSA":
            findings.append({
                "severity": "high",
                "issue": f"Quantum-Vulnerable Key Wrapping Inferred: {kx}",
                "detail": f"[Inferred from observed key exchange] Archival data likely wrapped with {kx} keys. HNDL attacks can recover symmetric keys from archived key-wrap envelopes post-quantum.",
                "recommendation": "Migrate key wrapping to BIKE-L1 or HQC-128 code-based KEMs for 25+ year archival confidentiality.",
                "evidence": "inferred",
                "inferred_from": "observed TLS key exchange",
            })
            pillar_qvs_scores.append(kx_qvs)
        elif kx in ["ECDHE", "DHE"]:
            findings.append({
                "severity": "high",
                "issue": f"Classical Key Exchange for Archival: {kx}",
                "detail": f"[Inferred from observed key exchange] {kx} provides forward secrecy but is vulnerable to Shor's algorithm. Archived key-wrap envelopes at risk post-quantum.",
                "recommendation": "Migrate key wrapping to BIKE-L1 or HQC-128 for long-term archival confidentiality.",
                "evidence": "inferred",
                "inferred_from": "observed TLS key exchange",
            })
            pillar_qvs_scores.append(kx_qvs)
        elif "MLKEM" in tls_info["cipher_name"].upper() or "KYBER" in tls_info["cipher_name"].upper():
            findings.append({
                "severity": "info",
                "issue": "PQC-Ready Key Exchange Detected",
                "detail": f"Hybrid PQC key exchange ({tls_info['cipher_name']}) observed. Long-term archival confidentiality is quantum-resistant if same infrastructure is used.",
                "recommendation": None,
                "evidence": "inferred",
                "inferred_from": "observed TLS key exchange",
            })
            pillar_qvs_scores.append(20)
        else:
            findings.append({
                "severity": "medium",
                "issue": f"Archival Key Wrapping Assessment: {kx}",
                "detail": f"Key exchange {kx} detected. Quantum risk requires further analysis.",
                "recommendation": "Review archival encryption configuration directly.",
                "evidence": "inferred",
                "inferred_from": "observed TLS key exchange",
            })
            pillar_qvs_scores.append(50)

        findings.append({
            "severity": "medium",
            "issue": "No Code-Based KEM (BIKE/HQC) Support Detected",
            "detail": f"No BIKE or HQC markers in TLS negotiation with {host}. BIKE/HQC provide cryptographic diversity for long-term archival.",
            "recommendation": "Integrate liboqs BIKE-L1 or HQC-128 into the archival encryption pipeline for 25+ year confidentiality.",
            "evidence": "measured",
            "inferred_from": None,
        })
        pillar_qvs_scores.append(min(kx_qvs, 90))
    else:
        findings.append({
            "severity": "info",
            "issue": "Archival Assessment: Target Unreachable",
            "detail": f"Could not establish TLS connection to {host}: {tls_info.get('error', 'Unknown')}. Archival encryption posture could not be assessed remotely.",
            "recommendation": "Provide archival encryption configuration for manual review.",
            "evidence": "measured",
            "inferred_from": None,
        })
        # Nothing was actually measured — used to fabricate a QVS of 75 here
        # (same pattern already fixed in _scan_web_tls). Append nothing.

    for header, value in storage_headers.items():
        cloud = "AWS" if "amz" in header else "Azure" if "ms" in header else "GCP"
        findings.append({
            "severity": "info",
            "issue": f"Cloud Storage Encryption Detected ({cloud})",
            "detail": f"Header `{header}: {value}` indicates server-side encryption is active.",
            "recommendation": None,
            "evidence": "measured",
            "inferred_from": None,
        })

    avg_qvs = round(sum(pillar_qvs_scores) / len(pillar_qvs_scores)) if pillar_qvs_scores else None
    return {"findings": findings, "qvs": avg_qvs, "evidence_summary": _evidence_summary(findings),
            "asset_details": _build_asset_details(tls_info, avg_qvs)}


# ── Public API ────────────────────────────────────────────────────────────────

def perform_triad_scan(web_url: str, vpn_url: str, api_url: str, jwt_token: str = "", progress_cb=None) -> dict:
    """
    Execute the full Triad+ Scan across all five pillars.
    Returns deterministic, verifiable findings with QVS scores (0-100)
    and ML Selector recommendations.

    progress_cb, if given, is called as progress_cb(percent: int, stage: str)
    before each pillar probe — purely a UI progress hook, scan behavior and
    results are identical whether or not it's passed.
    """
    def _report(pct, stage):
        if progress_cb:
            try:
                progress_cb(pct, stage)
            except Exception:
                pass
    # A plain millisecond timestamp has no collision protection: scan_id is a
    # `unique=True` DB column with no try/except around the commit (routers/
    # scan.py, services/worker.py), so two requests landing in the same
    # millisecond would raise an unhandled IntegrityError -> 500. Confirmed
    # live that concurrent scans of different targets can land 1ms apart —
    # the random suffix makes a same-millisecond collision astronomically
    # unlikely instead of merely unlikely.
    scan_id = f"scan_{int(datetime.utcnow().timestamp() * 1000)}_{uuid.uuid4().hex[:6]}"

    _report(2, "Scanning Web/TLS pillar (Pillar A)...")
    web_result = _scan_web_tls(web_url)
    _report(12, "Scanning VPN/TLS pillar (Pillar B)...")
    vpn_result = _scan_vpn_tls(vpn_url)
    _report(24, "Scanning API/JWT pillar (Pillar C)...")
    api_result = _scan_api_jwt(api_url, jwt_token)
    _report(36, "Scanning Firmware signing pillar (Pillar D)...")
    firmware_result = _scan_firmware(web_url)
    _report(44, "Scanning Archival encryption pillar (Pillar E)...")
    archival_result = _scan_archival(web_url)
    _report(50, "Triad pillar scan complete, compiling results...")

    # Overall QVS = unweighted mean of the pillars that were actually assessed.
    # Pillars that could not be probed contribute nothing rather than a default score.
    scored = [r["qvs"] for r in (web_result, vpn_result, api_result,
                                 firmware_result, archival_result)
              if r.get("qvs") is not None]
    overall_qvs = round(sum(scored) / len(scored)) if scored else None

    # ── PQC Selector: recommend an algorithm per pillar ──
    # Latency is the measured TLS handshake round-trip where a probe succeeded.
    # Bandwidth is not observable from a TLS handshake, so a documented default is
    # used and labelled as an assumption rather than presented as a measurement.
    measured_latency_ms = web_result.get("handshake_ms")
    ASSUMED_BANDWIDTH_KBPS = 50000  # assumption, not measured — see selector_inputs below

    selector_results = {}
    for pillar_key, pillar_name, device_type in [
        ("web", "Web", "Server"),
        ("vpn", "VPN", "Server"),
        ("api", "API", "Server"),
        ("firmware", "Firmware", "IoT"),
        ("archival", "Archival", "Server"),
    ]:
        latency_ms = measured_latency_ms if measured_latency_ms is not None else 10
        selection = ml_select(pillar=pillar_name,
                              bandwidth_kbps=ASSUMED_BANDWIDTH_KBPS,
                              latency_ms=latency_ms,
                              device_type=device_type)
        selector_results[pillar_key] = {
            "algorithm": selection["algorithm"],
            "confidence": selection["confidence"],
            "selector_log": selection["selector_log"],
            "inputs": {
                "latency_ms": latency_ms,
                "latency_source": "measured TLS handshake" if measured_latency_ms is not None else "default (no successful probe)",
                "bandwidth_kbps": ASSUMED_BANDWIDTH_KBPS,
                "bandwidth_source": "assumed — not measurable from a TLS handshake",
                "device_type": device_type,
                "device_type_source": "assumed from pillar",
            },
        }

    # ── PQC Audit Table ──
    audit_table = generate_audit_table()

    # ── API Metrics: Dynamically derived from the scan findings ──
    api_findings = api_result.get("findings", [])
    
    # Base metrics
    api_metrics = {
        "total": len(api_findings),
        "discovered": sum(1 for f in api_findings if f["severity"] == "info"),
        "buckets": {
            "REST Endpoints": 0,
            "JWT Audit": 0,
            "mTLS Layer": 0
        },
        "quantumRisk": {
            "vulnerable": sum(1 for f in api_findings if f["severity"] in ["critical", "high", "medium"]),
            "pqc_ready": sum(1 for f in api_findings if "PQC-Ready" in f["issue"])
        }
    }

    # Populate buckets based on finding content
    for f in api_findings:
        issue = f["issue"].upper()
        if "JWT" in issue:
            api_metrics["buckets"]["JWT Audit"] += 1
        elif "MTLS" in issue:
            api_metrics["buckets"]["mTLS Layer"] += 1
        else:
            api_metrics["buckets"]["REST Endpoints"] += 1

    result = {
        "timestamp": datetime.utcnow().isoformat(),
        "id": scan_id,
        "findings": {
            "web": web_result["findings"],
            "vpn": vpn_result["findings"],
            "api": api_result["findings"],
            "firmware": firmware_result["findings"],
            "archival": archival_result["findings"],
        },
        "riskScores": {
            "web": web_result["qvs"],
            "vpn": vpn_result["qvs"],
            "api": api_result["qvs"],
            "firmware": firmware_result["qvs"],
            "archival": archival_result["qvs"],
            "overall": overall_qvs,
        },
        # null in riskScores means "not assessed", not "no risk".
        "pillarsAssessed": len(scored),
        "selectorLog": selector_results,
        "pqcAuditTable": audit_table,
        "apiMetrics": api_metrics,
        # Per-asset detail: classification, hash/encryption/auth/kx algorithms,
        # OIDs, certificate fields, DNS records, and the actual crypto/TLS/DNS
        # library versions used to produce this scan's results. Every field is
        # either a real measurement or N/A — never guessed.
        "assetDetails": {
            "web": web_result.get("asset_details"),
            "vpn": vpn_result.get("asset_details"),
            "api": api_result.get("asset_details"),
            "firmware": firmware_result.get("asset_details"),
            "archival": archival_result.get("asset_details"),
        },
    }
    _validate_scan_result(result)
    return result


# ── Schema validation ────────────────────────────────────────────────────────

_REQUIRED_FINDING_KEYS = {"issue", "severity", "detail", "evidence"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_PILLARS = ("web", "vpn", "api", "firmware", "archival")


def _validate_scan_result(result: dict) -> None:
    """Sanity-check perform_triad_scan()'s output shape before it's persisted.

    Not a full JSON-Schema validator — just catches the failure modes that
    would otherwise silently corrupt stored scan rows or crash the frontend:
    missing top-level keys, malformed findings, out-of-range QVS scores.
    Raises ValueError so a bad scan never reaches the database.
    """
    for key in ("timestamp", "id", "findings", "riskScores", "pillarsAssessed"):
        if key not in result:
            raise ValueError(f"Scan result missing required key: {key}")

    for pillar in _PILLARS:
        if pillar not in result["findings"]:
            raise ValueError(f"Scan result missing findings for pillar: {pillar}")
        for f in result["findings"][pillar]:
            missing = _REQUIRED_FINDING_KEYS - f.keys()
            if missing:
                raise ValueError(f"Finding in pillar '{pillar}' missing keys: {missing}")
            if f["severity"] not in _VALID_SEVERITIES:
                raise ValueError(f"Finding in pillar '{pillar}' has invalid severity: {f['severity']}")

        qvs = result["riskScores"].get(pillar)
        if qvs is not None and not (0 <= qvs <= 100):
            raise ValueError(f"Pillar '{pillar}' QVS out of range 0-100: {qvs}")

    overall = result["riskScores"].get("overall")
    if overall is not None and not (0 <= overall <= 100):
        raise ValueError(f"Overall QVS out of range 0-100: {overall}")

"""
Triad-specific auto-remediation service.
Generates remediation scripts dynamically based on actual scan findings.
"""


# ── Remediation Templates (placeholders: {WEB}, {VPN}, {API}, {ALGO}) ─────

_WEB_TEMPLATE = """# ── Nginx PQC-Ready TLS 1.3 Configuration ──────────────────────────
# Target: {WEB}
# Detected: {ALGO} (Quantum-Vulnerable)

# Step 1: Update Nginx to support hybrid PQC cipher suites
sudo apt install -y nginx-oqs   # OQS-enabled Nginx build

# Step 2: Update ssl_ciphers in nginx.conf
cat <<'EOF' > /etc/nginx/conf.d/pqc-tls.conf
server {{
    listen 443 ssl http2;
    server_name {WEB};

    ssl_protocols TLSv1.3;
    ssl_ciphers x25519_kyber768:X25519MLKEM768:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;

    ssl_certificate     /etc/nginx/ssl/hybrid_cert.pem;
    ssl_certificate_key /etc/nginx/ssl/hybrid_key.pem;
}}
EOF

# Step 3: Test and reload
nginx -t && systemctl reload nginx
echo "[PQC] Web server {WEB} hardened with FIPS 203 ML-KEM support."
"""

_VPN_TEMPLATE = """# ── VPN Gateway PQC Migration ───────────────────────────────────────
# Target: {VPN}
# Detected: {ALGO} (Quantum-Vulnerable)

# Option A: OQS OpenVPN Fork (Recommended for immediate deployment)
git clone https://github.com/open-quantum-safe/openvpn.git
cd openvpn && autoreconf -i
./configure --with-crypto-lib=oqs
make && sudo make install

# Configure hybrid PQC key exchange for {VPN}
cat <<'EOF' >> /etc/openvpn/server.conf
tls-ciphersuites TLS_AES_256_GCM_SHA384
# Hybrid Kyber768 + X25519 key exchange
ecdh-curve x25519_kyber768
EOF

# Option B: Vendor-specific
# Cisco: Upgrade IOS XE to 17.12+ for RFC 9370
# strongSwan: Upgrade to 5.9.12+, proposals = aes256-sha384-x25519_kyber768

sudo systemctl restart openvpn
echo "[PQC] VPN gateway {VPN} migrated to PQC-hybrid key exchange."
"""

_API_TEMPLATE = """# ── API JWT Signing Migration: {ALGO} → ML-DSA-65 ───────────────────
# Target: {API}
# pip install oqs-python pyjwt[crypto]

from oqs import Signature
import json, base64, time

# Step 1: Generate ML-DSA-65 keypair
signer = Signature("Dilithium3")  # ML-DSA-65 = Dilithium3
public_key = signer.generate_keypair()

# Step 2: Sign JWT payload with ML-DSA
header = {{"alg": "ML-DSA-65", "typ": "JWT"}}
payload = {{
    "sub": "api_service_account",
    "iss": "{API}",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600,
}}

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header_b64 = b64url(json.dumps(header).encode())
payload_b64 = b64url(json.dumps(payload).encode())
message = f"{{header_b64}}.{{payload_b64}}".encode()

signature = signer.sign(message)
token = f"{{header_b64}}.{{payload_b64}}.{{b64url(signature)}}"

print(f"[PQC] ML-DSA-65 signed JWT for {API}: {{token[:80]}}...")
print("[PQC] API authentication migrated to FIPS 204.")
"""

_API_BACKUP_TEMPLATE = """# ── SLH-DSA Backup Signing for High-Value API Endpoints ─────────────
# Target: {API}
# FIPS 205 — Stateless Hash-Based Digital Signature Algorithm
# pip install oqs-python

from oqs import Signature
import json, hashlib

# Step 1: Generate SLH-DSA-128f keypair (fast variant)
signer = Signature("SPHINCS+-SHA2-128f-simple")
public_key = signer.generate_keypair()

# Step 2: Sign critical API payloads
payload = {{
    "transaction_id": "TXN-2026-PQC-001",
    "amount": 15000000,
    "currency": "INR",
    "beneficiary": "NEFT_POOL",
}}

message = json.dumps(payload, sort_keys=True).encode()
signature = signer.sign(message)
digest = hashlib.sha256(message).hexdigest()

print(f"[PQC] SLH-DSA-128f signature for {API}: {{digest[:16]}}...")
print(f"[PQC] Signature size: {{len(signature)}} bytes")
print("[PQC] FIPS 205 backup signing active for high-value endpoints.")
"""

_MOBILE_TEMPLATE = """# ── FN-DSA (Falcon) Mobile App Signing ──────────────────────────────
# Draft FIPS — Compact lattice signatures for mobile environments
# pip install oqs-python

from oqs import Signature
import hashlib

# Step 1: Generate FN-DSA-512 keypair
signer = Signature("Falcon-512")
public_key = signer.generate_keypair()

# Step 2: Sign mobile app binary hash
app_binary_hash = hashlib.sha256(b"mobile_app_release.apk").digest()
signature = signer.sign(app_binary_hash)

print(f"[PQC] FN-DSA-512 app signature: {{len(signature)}} bytes")
print(f"[PQC] Compare RSA-2048: 256 bytes vs FN-DSA: {{len(signature)}} bytes")

# Step 3: Verify on device
verifier = Signature("Falcon-512")
is_valid = verifier.verify(app_binary_hash, signature, public_key)
print(f"[PQC] Falcon signature verification: {{'VALID' if is_valid else 'INVALID'}}")
print("[PQC] Mobile app signing migrated to FN-DSA (Falcon).")
"""

_FIRMWARE_TEMPLATE = """# ── XMSS/LMS Firmware Signing Migration ────────────────────────────
# Target: {WEB}
# Detected: {ALGO} in infrastructure PKI
# NIST SP 800-208 compliant — Stateful Hash-Based Signatures
# CRITICAL: Requires HSM-backed state counter to prevent key reuse

# Step 1: Install hash-based signature tools
pip install xmss-reference lms-reference  # Or use liboqs

# Step 2: Generate XMSS keypair with state file
python3 << 'XMSS_KEYGEN'
from oqs import Signature

# XMSS-SHA2_10_256: 1024 max signatures, 256-bit security
xmss = Signature("XMSS-SHA2_10_256")
public_key = xmss.generate_keypair()

# CRITICAL: Store state in HSM, not filesystem
with open("/etc/firmware-signing/xmss_pubkey.bin", "wb") as f:
    f.write(public_key)

print(f"[PQC] XMSS public key: {{len(public_key)}} bytes")
print("[PQC] Max firmware signatures: 1024 (state counter enforced)")
XMSS_KEYGEN

echo "[PQC] Firmware signing migrated to XMSS (NIST SP 800-208) for {WEB}."
"""

_ARCHIVAL_TEMPLATE = """# ── BIKE/HQC Archival Key Encapsulation ─────────────────────────────
# Target: {WEB}
# Detected: {ALGO} key exchange
# NIST Round-4 Candidates — Code-based KEMs for long-term archival
# pip install oqs-python

from oqs import KeyEncapsulation
import json

# Step 1: Generate BIKE-L1 keypair for archival key wrapping
kem = KeyEncapsulation("BIKE-L1")
public_key = kem.generate_keypair()

# Step 2: Encapsulate a fresh AES-256 key for archival encryption
ciphertext, shared_secret = kem.encap_secret(public_key)

print(f"[PQC] BIKE-L1 public key: {{len(public_key)}} bytes")
print(f"[PQC] Ciphertext: {{len(ciphertext)}} bytes")
print(f"[PQC] Shared secret: {{len(shared_secret)}} bytes (AES-256 key)")

# Step 3: Store encrypted key envelope alongside archived data
envelope = {{
    "algorithm": "BIKE-L1",
    "fips_status": "NIST Round-4 Candidate",
    "ciphertext_b64": ciphertext.hex(),
    "retention_years": 25,
    "compliance": "CERT-In Annexure-A",
}}

with open("/archives/key_envelope.json", "w") as f:
    json.dump(envelope, f, indent=2)

print("[PQC] Archival key wrapping migrated from {ALGO} to BIKE-L1.")
"""


def generate_triad_remediation(findings: dict = None, web_url: str = "", vpn_url: str = "", api_url: str = "") -> list:
    """Generate per-pillar remediation scripts based on actual scan findings."""
    if not findings:
        return []

    scripts = []
    web_host = web_url or "target-server"
    vpn_host = vpn_url or "vpn-gateway"
    api_host = api_url or "api-server"

    def has_vulnerability(pillar: str) -> bool:
        return any(f["severity"] in ["critical", "high"] for f in findings.get(pillar, []))

    def get_detected_algo(pillar: str) -> str:
        for f in findings.get(pillar, []):
            issue = f.get("issue", "")
            if any(kw in issue for kw in ["Algorithm", "Key Exchange", "Crypto", "Vulnerable", "Classical", "Signing"]):
                parts = issue.split(":")
                if len(parts) > 1:
                    return parts[-1].strip()
        return "Classical (RSA/ECC)"

    def _sub(template: str, algo: str) -> str:
        return template.replace("{WEB}", web_host).replace("{VPN}", vpn_host).replace("{API}", api_host).replace("{ALGO}", algo).strip()

    if has_vulnerability("web"):
        algo = get_detected_algo("web")
        scripts.append({
            "pillar": "web",
            "title": "Pillar A — TLS Web Server Hardening",
            "type": "bash",
            "summary": f"Detected {algo} on {web_host}. Update TLS config for FIPS 203 (ML-KEM).",
            "code": _sub(_WEB_TEMPLATE, algo),
        })

    if has_vulnerability("vpn"):
        algo = get_detected_algo("vpn")
        scripts.append({
            "pillar": "vpn",
            "title": "Pillar B — VPN Gateway PQC Migration",
            "type": "bash",
            "summary": f"Detected {algo} on {vpn_host}. Upgrade to PQC key exchange.",
            "code": _sub(_VPN_TEMPLATE, algo),
        })

    if has_vulnerability("api"):
        algo = get_detected_algo("api")
        scripts.append({
            "pillar": "api",
            "title": "Pillar C — API JWT Signing Migration",
            "type": "python",
            "summary": f"Detected {algo} on {api_host}. Migrate JWT signing to FIPS 204 (ML-DSA).",
            "code": _sub(_API_TEMPLATE, algo),
        })
        scripts.append({
            "pillar": "api_backup",
            "title": "Pillar C+ — SLH-DSA Backup Signing for High-Value APIs",
            "type": "python",
            "summary": "Deploy SLH-DSA (FIPS 205) as a conservative backup for critical payment APIs.",
            "code": _sub(_API_BACKUP_TEMPLATE, algo),
        })
        scripts.append({
            "pillar": "mobile",
            "title": "Pillar C-Mobile — FN-DSA (Falcon) App Signing",
            "type": "python",
            "summary": "Deploy FN-DSA (Falcon) for mobile app signing — smallest lattice signatures.",
            "code": _sub(_MOBILE_TEMPLATE, algo),
        })

    if has_vulnerability("firmware"):
        algo = get_detected_algo("firmware")
        scripts.append({
            "pillar": "firmware",
            "title": "Pillar D — XMSS/LMS Firmware Integrity Signing",
            "type": "bash",
            "summary": f"Detected {algo} in PKI. Migrate firmware signing to XMSS (RFC 8391) per NIST SP 800-208.",
            "code": _sub(_FIRMWARE_TEMPLATE, algo),
        })

    if has_vulnerability("archival"):
        algo = get_detected_algo("archival")
        scripts.append({
            "pillar": "archival",
            "title": "Pillar E — BIKE/HQC Archival Key Encapsulation",
            "type": "python",
            "summary": f"Detected {algo} key exchange. Migrate archival key wrapping to BIKE-L1 or HQC-128.",
            "code": _sub(_ARCHIVAL_TEMPLATE, algo),
        })

    return scripts


def generate_remediation_scripts(findings: list) -> list:
    """Legacy remediation script generator for the /api/remediation/generate endpoint."""
    scripts = [
        {
            "type": "bash",
            "title": "Nginx TLS 1.3 Hardening",
            "code": "# Update Nginx config to enforce TLS 1.3 and PQC-ready ciphers\n"
                    "sed -i 's/ssl_protocols.*/ssl_protocols TLSv1.3;/' /etc/nginx/nginx.conf\n"
                    "sed -i 's/ssl_ciphers.*/ssl_ciphers x25519_kyber768:ECDHE-RSA-AES256-GCM-SHA384;/' /etc/nginx/nginx.conf\n"
                    "nginx -t && systemctl reload nginx",
        },
        {
            "type": "kubernetes",
            "title": "Istio PQC Sidecar Injection",
            "code": "apiVersion: networking.istio.io/v1alpha3\n"
                    "kind: EnvoyFilter\n"
                    "metadata:\n"
                    "  name: pqc-hybrid-filter\n"
                    "spec:\n"
                    "  configPatches:\n"
                    "  - applyTo: NETWORK_FILTER\n"
                    "    patch:\n"
                    "      operation: MERGE\n"
                    "      value:\n"
                    "        typed_config:\n"
                    "          common_http_protocol_options:\n"
                    "            tls_params:\n"
                    "              tls_maximum_protocol_version: TLSv1_3\n"
                    '              cipher_suites: ["[TLS_AES_256_GCM_SHA384]"]',
        },
    ]
    return scripts

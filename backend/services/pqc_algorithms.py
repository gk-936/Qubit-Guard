from typing import Union

"""
PQC Algorithm Registry — Canonical source of truth for all 6 NIST PQC algorithms.

This module is a static reference registry, not a cryptographic engine: it holds
authoritative metadata (parameter sizes, OIDs, cycle-count estimates) sourced from
NIST FIPS 203/204/205 and related standards. It performs no cryptographic
operations — key generation, signing, verification, encapsulation and
decapsulation are NOT implemented here, and there is no liboqs (or equivalent)
binding in this codebase. Consumers use this data to identify, classify and
recommend algorithms, not to execute them.

Covers:
  1. ML-KEM     (FIPS 203)  — Lattice KEM for Web/VPN key exchange
  2. ML-DSA     (FIPS 204)  — Lattice signatures for general digital signing
  3. SLH-DSA    (FIPS 205)  — Stateless hash-based backup signatures
  4. FN-DSA     (Falcon)    — Compact lattice signatures for mobile/bandwidth-constrained
  5. XMSS / LMS             — Stateful hash-based signatures for firmware integrity
  6. BIKE / HQC             — Code-based KEMs for long-term archival encryption

Aligned with DST PQC Migration Roadmap (March 2026) and CERT-In Annexure-A.
"""

PQC_ALGORITHM_REGISTRY = {
    "ML-KEM": {
        "fips_standard": "FIPS 203",
        "formal_name": "Module-Lattice-Based Key-Encapsulation Mechanism",
        "aliases": ["Kyber", "ML-KEM", "CRYSTALS-Kyber"],
        "oid": "1.3.6.1.4.1.2.267.12",
        "fips_status": "Finalized",
        "fips_date": "2024-08-13",
        "algorithm_type": "KEM",
        "family": "Lattice",
        "applicable_pillars": ["Web/TLS", "VPN/TLS"],
        "parameter_sets": {
            "ML-KEM-512": {
                "security_level": 1,
                "public_key_bytes": 800,
                "ciphertext_bytes": 768,
                "shared_secret_bytes": 32,
                "keygen_cycles": 37_000,
                "encaps_cycles": 48_000,
                "decaps_cycles": 52_000,
            },
            "ML-KEM-768": {
                "security_level": 3,
                "public_key_bytes": 1184,
                "ciphertext_bytes": 1088,
                "shared_secret_bytes": 32,
                "keygen_cycles": 60_000,
                "encaps_cycles": 78_000,
                "decaps_cycles": 82_000,
            },
            "ML-KEM-1024": {
                "security_level": 5,
                "public_key_bytes": 1568,
                "ciphertext_bytes": 1568,
                "shared_secret_bytes": 32,
                "keygen_cycles": 90_000,
                "encaps_cycles": 112_000,
                "decaps_cycles": 118_000,
            },
        },
        "qvs_score": 0,
        "hybrid_qvs_score": 20,
        "recommended_for": "Primary key exchange in TLS 1.3 and IKEv2 VPN tunnels.",
        "dst_roadmap_phase": "Phase 1 — Immediate Deployment (2024–2025)",
    },
    "ML-DSA": {
        "fips_standard": "FIPS 204",
        "formal_name": "Module-Lattice-Based Digital Signature Algorithm",
        "aliases": ["Dilithium", "ML-DSA", "CRYSTALS-Dilithium"],
        "oid": "1.3.6.1.4.1.2.267.12",
        "fips_status": "Finalized",
        "fips_date": "2024-08-13",
        "algorithm_type": "Signature",
        "family": "Lattice",
        "applicable_pillars": ["Web/TLS", "API/TLS", "VPN/TLS"],
        "parameter_sets": {
            "ML-DSA-44": {
                "security_level": 2,
                "public_key_bytes": 1312,
                "signature_bytes": 2420,
                "keygen_cycles": 38_000,
                "sign_cycles": 120_000,
                "verify_cycles": 42_000,
            },
            "ML-DSA-65": {
                "security_level": 3,
                "public_key_bytes": 1952,
                "signature_bytes": 3293,
                "keygen_cycles": 60_000,
                "sign_cycles": 180_000,
                "verify_cycles": 62_000,
            },
            "ML-DSA-87": {
                "security_level": 5,
                "public_key_bytes": 2592,
                "signature_bytes": 4595,
                "keygen_cycles": 95_000,
                "sign_cycles": 280_000,
                "verify_cycles": 98_000,
            },
        },
        "qvs_score": 0,
        "hybrid_qvs_score": 20,
        "recommended_for": "JWT signing, certificate signing, mTLS authentication.",
        "dst_roadmap_phase": "Phase 1 — Immediate Deployment (2024–2025)",
    },
    "SLH-DSA": {
        "fips_standard": "FIPS 205",
        "formal_name": "Stateless Hash-Based Digital Signature Algorithm",
        "aliases": ["SPHINCS+", "SLH-DSA"],
        "oid": "1.3.6.1.4.1.2.267.11",
        "fips_status": "Finalized",
        "fips_date": "2024-08-13",
        "algorithm_type": "Signature",
        "family": "Hash-based (Stateless)",
        "applicable_pillars": ["API/TLS"],
        "parameter_sets": {
            "SLH-DSA-128s": {
                "security_level": 1,
                "public_key_bytes": 32,
                "signature_bytes": 7856,
                "keygen_cycles": 3_600_000,
                "sign_cycles": 72_000_000,
                "verify_cycles": 3_200_000,
            },
            "SLH-DSA-128f": {
                "security_level": 1,
                "public_key_bytes": 32,
                "signature_bytes": 17088,
                "keygen_cycles": 800_000,
                "sign_cycles": 12_000_000,
                "verify_cycles": 800_000,
            },
            "SLH-DSA-256s": {
                "security_level": 5,
                "public_key_bytes": 64,
                "signature_bytes": 29792,
                "keygen_cycles": 14_000_000,
                "sign_cycles": 280_000_000,
                "verify_cycles": 5_600_000,
            },
        },
        "qvs_score": 0,
        "hybrid_qvs_score": 15,
        "recommended_for": "Backup signature scheme for high-value API endpoints. Conservative security — relies only on hash function security.",
        "dst_roadmap_phase": "Phase 2 — Backup Signatures (2025–2026)",
    },
    "FN-DSA": {
        "fips_standard": "Draft FIPS (Pending)",
        "formal_name": "FFT over NTRU-Lattice-Based Digital Signature Algorithm",
        "aliases": ["Falcon", "FN-DSA"],
        "oid": "1.3.9999.3.1",
        "fips_status": "Draft",
        "fips_date": None,
        "algorithm_type": "Signature",
        "family": "Lattice (NTRU)",
        "applicable_pillars": ["Mobile/App", "API/TLS"],
        "parameter_sets": {
            "FN-DSA-512": {
                "security_level": 1,
                "public_key_bytes": 897,
                "signature_bytes": 666,
                "keygen_cycles": 8_000_000,
                "sign_cycles": 300_000,
                "verify_cycles": 50_000,
            },
            "FN-DSA-1024": {
                "security_level": 5,
                "public_key_bytes": 1793,
                "signature_bytes": 1280,
                "keygen_cycles": 28_000_000,
                "sign_cycles": 600_000,
                "verify_cycles": 90_000,
            },
        },
        "qvs_score": 0,
        "hybrid_qvs_score": 20,
        "recommended_for": "Mobile app signing and bandwidth-constrained environments. Smallest signatures among lattice schemes.",
        "dst_roadmap_phase": "Phase 2 — Mobile & IoT (2025–2026)",
    },
    "XMSS-LMS": {
        "fips_standard": "NIST SP 800-208 / RFC 8391 / RFC 8554",
        "formal_name": "eXtended Merkle Signature Scheme / Leighton-Micali Signatures",
        "aliases": ["XMSS", "LMS", "HSS", "Stateful Hash-Based Signatures"],
        "oid": "1.3.6.1.4.1.8301.3.1.3.5.1",
        "fips_status": "Finalized",
        "fips_date": "2020-10-29",
        "algorithm_type": "Signature",
        "family": "Hash-based (Stateful)",
        "applicable_pillars": ["System/Firmware"],
        "parameter_sets": {
            "XMSS-SHA2_10_256": {
                "security_level": 1,
                "public_key_bytes": 64,
                "signature_bytes": 2500,
                "max_signatures": 1024,
                "keygen_cycles": 2_000_000,
                "sign_cycles": 4_000_000,
                "verify_cycles": 200_000,
            },
            "LMS-SHA256_M32_H10": {
                "security_level": 1,
                "public_key_bytes": 60,
                "signature_bytes": 1616,
                "max_signatures": 1024,
                "keygen_cycles": 1_500_000,
                "sign_cycles": 3_000_000,
                "verify_cycles": 150_000,
            },
        },
        "qvs_score": 0,
        "hybrid_qvs_score": 10,
        "recommended_for": "Firmware signing, secure boot, and system integrity verification. MUST maintain state counter to prevent key reuse.",
        "dst_roadmap_phase": "Phase 3 — Infrastructure Integrity (2026–2027)",
    },
    "BIKE-HQC": {
        "fips_standard": "NIST PQC Round 4",
        "formal_name": "Bit Flipping Key Encapsulation / Hamming Quasi-Cyclic",
        "aliases": ["BIKE", "HQC", "Code-based KEM", "Secondary KEM"],
        "oid": "1.3.6.1.4.1.22554.5.1",
        "fips_status": "Round-4 Candidate",
        "fips_date": None,
        "algorithm_type": "KEM",
        "family": "Code-based",
        "applicable_pillars": ["Archival/Storage"],
        "parameter_sets": {
            "BIKE-L1": {
                "security_level": 1,
                "public_key_bytes": 1541,
                "ciphertext_bytes": 1573,
                "shared_secret_bytes": 32,
                "keygen_cycles": 600_000,
                "encaps_cycles": 400_000,
                "decaps_cycles": 4_000_000,
            },
            "HQC-128": {
                "security_level": 1,
                "public_key_bytes": 2249,
                "ciphertext_bytes": 4481,
                "shared_secret_bytes": 64,
                "keygen_cycles": 200_000,
                "encaps_cycles": 400_000,
                "decaps_cycles": 600_000,
            },
        },
        "qvs_score": 0,
        "hybrid_qvs_score": 25,
        "recommended_for": "Long-term archival encryption of banking records, SWIFT logs, and regulatory data requiring 25+ year confidentiality.",
        "dst_roadmap_phase": "Phase 3 — Archival & Long-term Storage (2026–2027)",
    },
}


def get_algorithm(name: str) -> Union[dict, None]:
    """Look up an algorithm by name or alias."""
    name_upper = name.upper().strip()
    for key, algo in PQC_ALGORITHM_REGISTRY.items():
        if name_upper in key.upper():
            return {**algo, "id": key}
        for alias in algo["aliases"]:
            if name_upper in alias.upper():
                return {**algo, "id": key}
    return None


def get_all_algorithms() -> list:
    """Return all algorithms as a list with IDs."""
    return [{"id": key, **val} for key, val in PQC_ALGORITHM_REGISTRY.items()]


def get_algorithm_for_pillar(pillar: str) -> list:
    """Return algorithms applicable to a given pillar."""
    results = []
    for key, algo in PQC_ALGORITHM_REGISTRY.items():
        for p in algo["applicable_pillars"]:
            if pillar.lower() in p.lower():
                results.append({"id": key, **algo})
                break
    return results


def generate_audit_table() -> list:
    """Generate the 6-row verification audit table for the Qubit-Guard Auditor."""
    table = []
    for key, algo in PQC_ALGORITHM_REGISTRY.items():
        fips_score = 10 if algo["fips_status"] == "Finalized" else 0
        table.append({
            "algorithm": key,
            "fips_standard": algo["fips_standard"],
            "oid": algo["oid"],
            "fips_status": algo["fips_status"],
            "compliance_score": fips_score,
            "pillars": algo["applicable_pillars"],
            "recommended_parameter": list(algo["parameter_sets"].keys())[0],
            "qvs_score": algo["qvs_score"],
            "dst_phase": algo["dst_roadmap_phase"],
        })
    return table

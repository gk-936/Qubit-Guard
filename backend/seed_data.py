"""
Seeds the SQLite database with initial data matching the existing JSON fixtures.
Run once: python seed_data.py
"""

import bcrypt
from db import engine, SessionLocal, Base
from models import (
    User, DashboardSummary, InventoryStat, PostureStat,
    CbomVulnerabilitySummary, CbomItem
)


def seed():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    # ---------- Users ----------
    if not db.query(User).first():
        salt = bcrypt.gensalt()
        hashed_pw = bcrypt.hashpw(b"pnb_password_2026", salt).decode('utf-8')
        db.add(User(
            username="admin",
            password=hashed_pw,
            role="admin",
            email="admin@pnb.bank.in"
        ))

    # ---------- Dashboard Summary ----------
    if not db.query(DashboardSummary).first():
        for key, val, lbl, sub in [
            ("assetsDiscovery", "0", "Assets Discovery", "Domains, IPs & Subdomains"),
            ("cyberRating", "N/A", "Cyber Rating", "Elite-PQC Status"),
            ("sslCerts", "0", "Active SSL Certs", "Weak cryptography findings"),
            ("cbomVulnerabilities", "0", "CBOM Vulnerabilities", "Requiring immediate action"),
        ]:
            db.add(DashboardSummary(key=key, value=val, label=lbl, subtext=sub, source="seed"))

    # ---------- Inventory Stats ----------
    if not db.query(InventoryStat).first():
        for cat, cnt in [("ssl", 0), ("software", 0), ("iot", 0), ("logins", 0)]:
            db.add(InventoryStat(category=cat, count=cnt, source="seed"))

    # ---------- Posture Stats ----------
    if not db.query(PostureStat).first():
        for metric, val in [("mlKemAdoption", 33), ("mlDsaTransition", 22), ("legacyRemoval", 8),
                            ("slhDsaBackup", 5), ("fnDsaMobile", 3), ("xmssLmsFirmware", 2), ("bikeHqcArchival", 1)]:
            db.add(PostureStat(metric=metric, value=val, source="seed"))

    # ---------- CBOM Vulnerability Summary ----------
    if not db.query(CbomVulnerabilitySummary).first():
        for sev, cnt in [("critical", 2847), ("high", 3120), ("medium", 1881), ("low", 400)]:
            db.add(CbomVulnerabilitySummary(severity=sev, count=cnt, source="seed"))

    # ---------- CBOM Items ----------
    if not db.query(CbomItem).first():
        items = [
            ("OpenSSL", "1.1.1w", "RSA-2048", False, "Critical", "TLS", "pkg:generic/openssl@1.1.1w"),
            ("BouncyCastle", "1.76", "ECDSA-P256", False, "High", "Code Signing", "pkg:maven/org.bouncycastle/bcprov@1.76"),
            ("liboqs", "0.9.0", "ML-KEM-768", True, "Safe", "PQC", "pkg:generic/liboqs@0.9.0"),
            ("PyJWT", "2.8.0", "RS256", False, "High", "JWT", "pkg:pypi/pyjwt@2.8.0"),
            ("Nginx", "1.24.0", "ECDHE-RSA-AES256", False, "High", "TLS", "pkg:generic/nginx@1.24.0"),
            ("strongSwan", "5.9.11", "IKEv2-RSA", False, "Critical", "VPN", "pkg:generic/strongswan@5.9.11"),
            ("AWS ACM", "2024", "RSA-2048", False, "High", "Certificate", "pkg:generic/aws-acm@2024"),
            ("Istio", "1.20", "mTLS-ECDSA", False, "Medium", "Service Mesh", "pkg:generic/istio@1.20"),
            ("liboqs-sphincs", "0.9.0", "SLH-DSA-128f", True, "Safe", "PQC Signatures", "pkg:generic/liboqs-sphincs@0.9.0"),
            ("liboqs-falcon", "0.9.0", "FN-DSA-512", True, "Safe", "PQC Mobile", "pkg:generic/liboqs-falcon@0.9.0"),
            ("hash-sigs", "1.0.0", "XMSS-SHA2_10_256", True, "Safe", "Firmware", "pkg:generic/hash-sigs@1.0.0"),
            ("liboqs-bike", "0.9.0", "BIKE-L1", True, "Safe", "Archival KEM", "pkg:generic/liboqs-bike@0.9.0"),
            ("liboqs-hqc", "0.9.0", "HQC-128", True, "Safe", "Archival KEM", "pkg:generic/liboqs-hqc@0.9.0"),
        ]
        for comp, ver, alg, qs, risk, cat, purl in items:
            db.add(CbomItem(
                component=comp, version=ver, algorithm=alg,
                quantum_safe=qs, risk=risk, category=cat, purl=purl,
                source="seed"
            ))

    db.commit()
    db.close()
    print("[SEED] Database seeded successfully.")


if __name__ == "__main__":
    seed()

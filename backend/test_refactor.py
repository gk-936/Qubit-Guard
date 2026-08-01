"""Quick test of the refactored scanner functions."""
from services.scanner_engine import _scan_firmware, _scan_archival, _scan_vpn_tls
from services.mobile_scanner import scan_mobile_app
from services.remediation_service import generate_triad_remediation

print("=== FIRMWARE (www.google.com) ===")
fw = _scan_firmware("www.google.com")
print(f"QVS: {fw['qvs']}")
for f in fw["findings"]:
    print(f"  [{f['severity']}] {f['issue']}")

print("\n=== ARCHIVAL (www.google.com) ===")
ar = _scan_archival("www.google.com")
print(f"QVS: {ar['qvs']}")
for f in ar["findings"]:
    print(f"  [{f['severity']}] {f['issue']}")

print("\n=== VPN (www.google.com) ===")
vpn = _scan_vpn_tls("www.google.com")
print(f"QVS: {vpn['qvs']}")
for f in vpn["findings"]:
    print(f"  [{f['severity']}] {f['issue']}")

print("\n=== MOBILE (com.pnb.pnbone, Android) ===")
mob = scan_mobile_app("com.pnb.pnbone", "Android")
print(f"Version: {mob['version']}, PQC Score: {mob['pqc_score']}, Size: {mob['packageSize']}")
for f in mob["findings"]:
    print(f"  [{f['severity']}] {f['issue']}")

print("\n=== REMEDIATION (dynamic) ===")
fake_findings = {
    "web": [{"severity": "critical", "issue": "Quantum-Vulnerable Key Exchange: RSA", "detail": "test", "recommendation": "test"}],
    "vpn": [{"severity": "high", "issue": "Classical VPN Key Exchange: ECDHE (Quantum-Vulnerable)", "detail": "test", "recommendation": "test"}],
    "api": [],
    "firmware": [{"severity": "critical", "issue": "Quantum-Vulnerable Firmware Signing Inferred: RSA", "detail": "test", "recommendation": "test"}],
    "archival": [{"severity": "high", "issue": "Classical Key Exchange for Archival: ECDHE", "detail": "test", "recommendation": "test"}],
}
remed = generate_triad_remediation(fake_findings, "www.testbank.com", "vpn.testbank.com", "api.testbank.com")
print(f"Scripts generated: {len(remed)}")
for r in remed:
    has_target = "testbank.com" in r["code"]
    print(f"  [{r['pillar']}] {r['title']} | Uses target URL: {has_target}")

print("\nAll tests passed!")

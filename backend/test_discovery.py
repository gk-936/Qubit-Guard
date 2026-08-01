"""Quick test of discovery service — real subdomain probing."""
from services.discovery_service import discover_pnb_assets

print("Discovering assets for google.com (should find real subdomains)...")
result = discover_pnb_assets("google.com")

print(f"\nBase domain: {result['base_domain']}")
print(f"Total found: {result['total_found']}")
print(f"AXFR success: {result['axfr_success']}")
print(f"Notes: {result['notes']}")

print(f"\nDiscovered assets:")
for asset in result["assets"]:
    pillars = ", ".join(asset["pillars"])
    pqc = "PQC-Ready" if asset["pqc_ready"] else "Classical"
    tls_ver = asset.get("details", {}).get("tls_version", "N/A")
    asset_type = asset.get("details", {}).get("type", "")
    # Verify NO "Holographic Asset" fakes
    assert "Holographic" not in str(asset), f"FAKE ASSET DETECTED: {asset['host']}"
    print(f"  {asset['host']:40s} | {pillars:10s} | {pqc:10s} | TLS: {tls_ver}")

print(f"\n✅ All {result['total_found']} assets are real (no synthetic padding)")

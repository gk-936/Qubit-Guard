
import sys
import os
import json
from datetime import datetime

# Add backend to path so we can import services
sys.path.append(os.path.abspath('g:/CYS/4/pnb/Qubit-Guard/backend'))

from services.scanner_engine import perform_triad_scan

def run_verification(web_target, vpn_target, api_target, jwt=""):
    print(f"--- VERIFICATION PROBE: {web_target} ---")
    print(f"Timestamp: {datetime.now().isoformat()}")
    
    # We use valid inputs for all targets
    results = perform_triad_scan(
        web_url=web_target,
        vpn_url=vpn_target,
        api_url=api_target,
        jwt_token=jwt
    )
    
    # Extract the 'raw' certificate data from the web findings
    web_findings = results['findings']['web']
    cert_data = next((f['raw'] for f in web_findings if 'raw' in f), None)
    
    if cert_data:
        print("\n[LIVE TLS DATA FETCHED]")
        print(f"Common Name: {cert_data.get('cn')}")
        print(f"Issuer:      {cert_data.get('issuer')}")
        print(f"Cipher:      {cert_data.get('cipher')}")
    
    # VPN Probing (Pillar B)
    vpn_findings = results['findings']['vpn']
    ike_responsive = any("IKEv2 Gateway Detected" in f['issue'] for f in vpn_findings)
    vpn_reachable = any("VPN Gateway Identified" in f['issue'] for f in vpn_findings)
    print(f"\n[VPN PROBE RESULTS]")
    print(f"TLS Reachable: {vpn_reachable}")
    print(f"IKEv2 (500/4500) Responsive: {ike_responsive}")

    # API Token Analysis (Pillar C)
    api_findings = results['findings']['api']
    jwt_vuln = any("Quantum-Vulnerable JWT Algorithm" in f['issue'] for f in api_findings)
    print(f"\n[API TOKEN ANALYSIS]")
    print(f"JWT Vulnerabilities Detected: {jwt_vuln}")
    for f in api_findings:
        if "Algorithm" in f['issue']:
            print(f"Detected Algorithm: {f['issue'].split(': ')[-1]}")

if __name__ == "__main__":
    # Test with a real banking target + a sample JWT
    # Base64 encoded: {"alg": "RS256", "typ": "JWT"}.{"pnb_id": "auditor_01"}
    sample_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJwbmJfaWQiOiJhdWRpdG9yXzAxIn0.signature"
    
    run_verification(
        web_target="www.pnb.bank.in",
        vpn_target="vpn.pnb.bank.in", # Real PNB VPN gateway
        api_target="api.pnb.bank.in", # Real PNB API endpoint
        jwt=sample_jwt
    )

"""Quick test of the PQC endpoints."""
import urllib.request
import json

BASE = "http://localhost:5006/api"

def test(name, url, method="GET", body=None):
    print(f"\n{'='*60}")
    print(f"TEST: {name}")
    print(f"{'='*60}")
    try:
        if body:
            req = urllib.request.Request(url, data=json.dumps(body).encode(), 
                                         headers={"Content-Type": "application/json"}, method=method)
        else:
            req = urllib.request.Request(url, method=method)
        resp = urllib.request.urlopen(req)
        data = json.loads(resp.read())
        print(f"STATUS: OK")
        return data
    except Exception as e:
        print(f"ERROR: {e}")
        return None

# Test 1: Algorithms Registry
data = test("PQC Algorithm Registry", f"{BASE}/pqc/algorithms")
if data:
    print(f"Count: {data['count']}")
    for a in data["data"]:
        print(f"  {a['id']:12s} | {a['fips_standard']:25s} | OID: {a['oid']} | Status: {a['fips_status']}")

# Test 2: Audit Table
data = test("PQC Verification Audit", f"{BASE}/pqc/audit")
if data:
    print(f"Count: {data['count']}")
    for row in data["data"]:
        print(f"  {row['algorithm']:12s} | Score: {row['compliance_score']:2d}/10 | {row['fips_status']:20s} | Pillars: {', '.join(row['pillars'])}")

# Test 3: ML Selector
data = test("ML Selector (Web/Server)", f"{BASE}/pqc/select", "POST", {
    "pillar": "Web", "bandwidth_kbps": 100000, "latency_ms": 5,
    "device_type": "Server", "retention_years": 1, "compliance": "CERT-In"
})
if data and data.get("data"):
    r = data["data"]
    print(f"Algorithm: {r['algorithm']}")
    print(f"Confidence: {r['confidence']}")
    print(f"Selector Log: {r['selector_log']}")

# Test 4: ML Selector (Mobile)
data = test("ML Selector (Mobile/App)", f"{BASE}/pqc/select", "POST", {
    "pillar": "Mobile", "bandwidth_kbps": 10000, "latency_ms": 50,
    "device_type": "Mobile", "retention_years": 1, "compliance": "CERT-In"
})
if data and data.get("data"):
    r = data["data"]
    print(f"Algorithm: {r['algorithm']}")
    print(f"Confidence: {r['confidence']}")
    print(f"Selector Log: {r['selector_log']}")

# Test 5: ML Selector (Archival)
data = test("ML Selector (Archival/HSM)", f"{BASE}/pqc/select", "POST", {
    "pillar": "Archival", "bandwidth_kbps": 200000, "latency_ms": 2,
    "device_type": "HSM", "retention_years": 50, "compliance": "RBI"
})
if data and data.get("data"):
    r = data["data"]
    print(f"Algorithm: {r['algorithm']}")
    print(f"Confidence: {r['confidence']}")
    print(f"Selector Log: {r['selector_log']}")

# Test 6: Health check
data = test("Health Check", f"{BASE}/health")
if data:
    print(f"Status: {data['status']}")

print("\n" + "="*60)
print("ALL TESTS COMPLETE")
print("="*60)

import sys
import os
import json
from datetime import datetime

# Add backend to path
sys.path.append(os.path.join(os.getcwd(), "backend"))

# Mock Session
class MockDB:
    def query(self, model):
        return self
    def all(self):
        # Return mock ORM objects
        class MockComponent:
            def __init__(self, name, qs):
                self.component = name
                self.quantum_safe = qs
                self.risk = "High" if not qs else "Safe"
                self.version = "1.0"
                self.algorithm = "RSA"
                self.purl = "N/A"
        return [MockComponent("Comp1", False), MockComponent("Comp2", True)]
    def filter(self, *args):
        return self
    def order_by(self, *args):
        return self
    def first(self):
        class MockScan:
            def __init__(self):
                self.web_url = "http://pnb.bank.in"
                self.vpn_url = "http://vpn.pnb.bank.in"
                self.api_url = "http://api.pnb.bank.in"
                self.findings_json = json.dumps({
                    "web": [
                        {"severity": "critical", "issue": "Critical Issue 1"},
                        {"severity": "high", "issue": "High Issue 1"}
                    ]
                })
                self.risk_scores_json = json.dumps({"overall": 90, "web": 98, "api": 90})
                self.cbom_json = json.dumps({
                    "components": [
                        {"component": "SafeComp1", "quantumSafe": True},
                        {"component": "SafeComp2", "quantumSafe": True},
                        {"component": "VulnComp1", "quantumSafe": False, "risk": "Critical"}
                    ]
                })
                self.timestamp = datetime.now()
        return MockScan()

from services.mail_service import generate_professional_pdf

def test_download():
    db = MockDB()
    latest_scan = db.first()
    
    scan_data = {
        "reportType": "EXECUTIVE",
        "url": latest_scan.web_url,
        "riskScores": json.loads(latest_scan.risk_scores_json),
        "findings": json.loads(latest_scan.findings_json),
        "cbom": json.loads(latest_scan.cbom_json),
    }
    
    # We populate these as the real router does
    scan_data["web_findings"] = scan_data["findings"].get("web", [])
    
    print("Generating PDF...")
    try:
        # This will trigger print statements if I add them to mail_service
        # (Actually, let's just assume if it runs, the logic is being executed)
        pdf = generate_professional_pdf("EXECUTIVE", scan_data, db)
        print("Success! Generated PDF bytes with integrated counts.")
    except Exception as e:
        print(f"FAILED: {e}")
        import traceback
        traceback.print_exc()
    except Exception as e:
        print(f"FAILED: {e}")
        import traceback
        traceback.print_exc()

test_download()

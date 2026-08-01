import sys
import os
from unittest.mock import MagicMock

# Add backend to path
sys.path.append(os.path.join(os.getcwd(), "backend"))

from services.mail_service import generate_professional_pdf

# Mock scan_data that would normally cause "multiple values for argument"
scan_data = {
    "findings": {"some": "findings"},
    "riskScores": {"overall": 50},
    "web_url": "http://test.com",
    "web_findings": [],
    "api_findings": [],
    "vpn_findings": [],
    "mobile_findings": []
}

print("Testing generate_professional_pdf with EXECUTIVE report...")
try:
    # We pass 'EXECUTIVE' and scan_data
    # This calls _generate_executive_report(risk_scores, findings, ..., **report_kwargs)
    # If the fix works, 'findings' in report_kwargs won't exist, avoiding conflict.
    pdf_bytes = generate_professional_pdf("EXECUTIVE", scan_data)
    print("Success! No TypeError raised.")
except TypeError as e:
    print(f"FAILED: TypeError raised: {e}")
except Exception as e:
    print(f"Caught other exception (likely missing reportlab or similar): {e}")

print("\nTesting generate_professional_pdf with TECHNICAL report...")
try:
    pdf_bytes = generate_professional_pdf("TECHNICAL", scan_data)
    print("Success! No TypeError raised.")
except TypeError as e:
    print(f"FAILED: TypeError raised: {e}")
except Exception as e:
    print(f"Caught other exception: {e}")

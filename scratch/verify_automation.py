import asyncio
import os
import sys
import json
from datetime import datetime

# Add backend to path
sys.path.append(os.path.join(os.getcwd(), "backend"))

from db import SessionLocal, Base, engine
from models import Schedule, ScanResult
from services.worker import run_automated_scan_and_email

async def test_automation():
    print("[TEST] Setting up mock schedule...")
    db = SessionLocal()
    
    # Create a mock schedule
    new_schedule = Schedule(
        frequency="once",
        targets_json=json.dumps({
            "webUrl": "www.google.com", 
            "vpnUrl": "", 
            "apiUrl": ""
        }),
        email="test-scheduled@example.com",
        scheduled_time="23:59",
        report_type="executive",
        is_active=True
    )
    db.add(new_schedule)
    db.commit()
    db.refresh(new_schedule)
    
    print(f"[TEST] Created schedule ID: {new_schedule.id}. Triggering run...")
    
    try:
        # Manually trigger the worker function
        await run_automated_scan_and_email(new_schedule.id)
        print("[TEST] worker function returned successfully.")
        
        # Verify the scan result was created
        latest_scan = db.query(ScanResult).order_by(ScanResult.timestamp.desc()).first()
        if latest_scan and latest_scan.web_url == "www.google.com":
            print(f"[TEST] SUCCESS: ScanResult created for {latest_scan.web_url}")
        else:
            print("[TEST] FAILURE: ScanResult not found or incorrect.")
            
    except Exception as e:
        print(f"[TEST] ERROR: {e}")
    finally:
        # Cleanup
        db.delete(new_schedule)
        db.commit()
        db.close()

if __name__ == "__main__":
    asyncio.run(test_automation())

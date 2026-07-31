import json
import logging
import asyncio
from datetime import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy.orm import Session
from db import SessionLocal
from models import Schedule, ScanResult
from services.scanner_engine import perform_triad_scan
from services.api_scanner import discover_endpoints
from services.cbom_generator import generate_triad_cbom
from services.remediation_service import generate_triad_remediation
from services.discovery_service import discover_pnb_assets
from services.mail_service import send_scan_report

log = logging.getLogger(__name__)

# Global scheduler instance
scheduler = AsyncIOScheduler()

async def run_automated_scan_and_email(schedule_id: int):
    """
    Background job:
    1. Triggers a fresh triad scan
    2. Persists the result
    3. Sends the email report
    """
    print(f"[WORKER] Starting scheduled scan for schedule ID: {schedule_id}")
    db: Session = SessionLocal()
    try:
        schedule = db.query(Schedule).filter(Schedule.id == schedule_id).first()
        if not schedule or not schedule.is_active:
            print(f"[WORKER] Schedule {schedule_id} not found or inactive.")
            return

        targets = json.loads(schedule.targets_json)
        web_url = targets.get("webUrl", "www.pnb.bank.in")
        vpn_url = targets.get("vpnUrl", "vpn.pnb.bank.in")
        api_url = targets.get("apiUrl", "api.pnb.bank.in")
        recipient = schedule.email or "admin@pnb.co.in"
        report_type = schedule.report_type or "executive"

        # 1. Perform Scan (Logic mirrored from routers/scan.py)
        scan_results = perform_triad_scan(web_url, vpn_url, api_url, "")
        discovery_results = discover_pnb_assets(web_url)
        discovered_assets = discovery_results.get("assets", [])

        all_endpoints = []
        seen_endpoint_urls = set()
        hosts_to_probe = [web_url, api_url] if api_url else [web_url]
        for asset in discovered_assets:
            if "Web/TLS" in asset.get("pillars", []):
                hosts_to_probe.append(asset["host"])
        
        for host in set(hosts_to_probe):
            if not host: continue
            res = discover_endpoints(host)
            for ep in res.get("details", []):
                if ep["url"] not in seen_endpoint_urls:
                    all_endpoints.append(ep)
                    seen_endpoint_urls.add(ep["url"])

        api_metrics = {
            "total": len(all_endpoints),
            "discovered": len(all_endpoints),
            "details": all_endpoints,
            "buckets": {},
            "quantumRisk": {
                "vulnerable": sum(1 for ep in all_endpoints if "PQC" not in ep.get("quantumRisk", "")), 
                "pqc_ready": sum(1 for ep in all_endpoints if "PQC" in ep.get("quantumRisk", ""))
            }
        }
        for ep in all_endpoints:
            b = ep.get("bucket", "General API")
            api_metrics["buckets"][b] = api_metrics["buckets"].get(b, 0) + 1

        cbom = generate_triad_cbom(
            scan_results["findings"], 
            web_url, vpn_url, api_url,
            discovered_assets=discovered_assets,
            discovered_endpoints=all_endpoints,
            discovered_mobile_apps=discovery_results.get("mobile_apps", [])
        )

        # 2. Persist
        scan_record = ScanResult(
            scan_id=scan_results["id"],
            web_url=web_url,
            vpn_url=vpn_url,
            api_url=api_url,
            findings_json=json.dumps(scan_results["findings"]),
            risk_scores_json=json.dumps(scan_results["riskScores"]),
            cbom_json=json.dumps(cbom),
            api_metrics_json=json.dumps(api_metrics),
            overall_qvs=scan_results["riskScores"]["overall"],
        )
        db.add(scan_record)
        
        # 3. Update Schedule metadata
        schedule.last_run_at = datetime.utcnow()
        db.commit()

        # 4. Prepare scan_data for email
        # We need to map some fields to what the mail service expects
        scan_data = {
            "reportType": report_type.upper(),
            "formats": ["pdf"],
            "riskScores": scan_results["riskScores"],
            "cbom": cbom,
            "findings": scan_results["findings"], # The raw ones
            "url": web_url,
            "web_url": web_url,
            "vpn_url": vpn_url,
            "api_url": api_url,
            "web_findings": scan_results["findings"].get("web", []),
            "api_findings": scan_results["findings"].get("api", []),
            "vpn_findings": scan_results["findings"].get("vpn", []),
            "mobile_findings": scan_results["findings"].get("mobile", []),
        }

        # 5. Send Email
        success, message = send_scan_report(recipient, scan_data)
        print(f"[WORKER] Scheduled scan complete for {web_url}. Email success: {success}, {message}")

    except Exception as e:
        print(f"[WORKER] Error in automated scan: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()

def register_schedule(schedule_obj: Schedule):
    """Adds a job to the running scheduler based on a Schedule object."""
    if not schedule_obj.scheduled_time:
        return

    # Parse HH:MM
    try:
        hour, minute = map(int, schedule_obj.scheduled_time.split(':'))
    except (ValueError, AttributeError) as e:
        log.warning("Invalid schedule time format %r: %s", schedule_obj.scheduled_time, e, exc_info=True)
        return

    job_id = f"job_schedule_{schedule_obj.id}"
    
    # Remove existing job if it exists (for updates)
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)

    if schedule_obj.frequency == "daily":
        scheduler.add_job(
            run_automated_scan_and_email,
            'cron',
            hour=hour,
            minute=minute,
            args=[schedule_obj.id],
            id=job_id
        )
    elif schedule_obj.frequency == "once":
        # Run once at the specified time today (or tomorrow if time passed)
        scheduler.add_job(
            run_automated_scan_and_email,
            'cron',
            hour=hour,
            minute=minute,
            args=[schedule_obj.id],
            id=job_id
        )
    # Add more frequencies (weekly, etc.) if needed

def start_worker():
    """Initializes and starts the background scheduler."""
    if not scheduler.running:
        scheduler.start()
        print("[WORKER] APScheduler started.")
        
        # Load existing active schedules from DB
        db = SessionLocal()
        try:
            active_schedules = db.query(Schedule).filter(Schedule.is_active == True).all()
            for s in active_schedules:
                register_schedule(s)
            print(f"[WORKER] Registered {len(active_schedules)} existing schedules.")
        finally:
            db.close()

import json
import logging
import asyncio
from datetime import datetime, timedelta
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy.orm import Session
from db import SessionLocal, with_retry
from models import Schedule, ScanResult
from services.scanner_engine import perform_triad_scan
from services.api_scanner import discover_endpoints
from services.cbom_generator import generate_triad_cbom
from services.remediation_service import generate_triad_remediation
from services.discovery_service import discover_pnb_assets
from services.mail_service import send_scan_report
from services import report_service

log = logging.getLogger(__name__)

# Global scheduler instance
scheduler = AsyncIOScheduler()

# Minimum gap between two runs of the SAME schedule before a second trigger is
# treated as a duplicate rather than a genuine re-fire. Guards against the one
# scenario APScheduler itself can't fully prevent: this job function being
# invoked twice in quick succession (e.g. a schedule registered twice by a
# bug elsewhere, or a misfire replay landing seconds after a normal fire).
# A legitimate "daily"/"weekly" re-run is always far larger than this.
_MIN_RERUN_GAP = timedelta(minutes=2)


async def run_automated_scan_and_email(schedule_id: int):
    """
    Background job:
    1. Triggers a fresh triad scan
    2. Persists the result
    3. Sends the email report — ONLY if that fresh scan actually produced a
       measured result. Never emails a stale scan pulled from the database;
       the scan performed in step 1, right here, right now, is the only data
       this function ever sends.
    """
    fire_time = datetime.utcnow()
    print(f"[WORKER] Starting scheduled scan for schedule ID: {schedule_id} at {fire_time.isoformat()}")
    db: Session = SessionLocal()
    try:
        schedule = db.query(Schedule).filter(Schedule.id == schedule_id).first()
        if not schedule or not schedule.is_active:
            print(f"[WORKER] Schedule {schedule_id} not found or inactive.")
            return

        # Duplicate-run guard: if this exact schedule already ran within the
        # last _MIN_RERUN_GAP, this invocation is a duplicate trigger, not a
        # legitimate new fire (a real daily/weekly cadence is always hours to
        # days apart) — skip it rather than scanning and emailing twice.
        if schedule.last_run_at and (fire_time - schedule.last_run_at) < _MIN_RERUN_GAP:
            print(f"[WORKER] Schedule {schedule_id} already ran at {schedule.last_run_at.isoformat()} "
                  f"({(fire_time - schedule.last_run_at).total_seconds():.0f}s ago) — skipping duplicate trigger.")
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
            asset_details_json=json.dumps(scan_results.get("assetDetails", {})),
            overall_qvs=scan_results["riskScores"]["overall"],
        )
        db.add(scan_record)

        # 3. Update Schedule metadata — recorded regardless of whether the
        # scan measured anything, so a schedule that keeps hitting an
        # unreachable target doesn't re-fire early or duplicate-guard-trip
        # against itself.
        run_completed_at = datetime.utcnow()
        schedule.last_run_at = run_completed_at
        if schedule.frequency == "once":
            # Without this, a restart re-registers a "once" schedule as a fresh
            # "next occurrence of HH:MM" job (register_schedule/start_worker only
            # skip inactive schedules) — so a one-time scan would silently start
            # firing again after every server restart.
            schedule.is_active = False
        with_retry(lambda: db.commit())

        # 4. Only generate/send a report if this fresh scan actually measured
        # something. A scan where every pillar came back unreachable
        # (pillarsAssessed == 0) is not "a successful scan completed" — sending
        # an all-N/A report on a schedule would be indistinguishable from a
        # real (but boring) "everything's fine" result, which is worse than
        # not sending anything. The scan is still persisted above either way
        # (so History shows the attempt), just not emailed.
        if scan_results.get("pillarsAssessed", 0) == 0:
            print(f"[WORKER] Scheduled scan for {web_url} completed but assessed 0 pillars "
                  f"(target unreachable) — report NOT generated or sent.")
            return

        # Build the SAME canonical report the manual /report/export/{fmt}
        # endpoint would build for this scan_id, straight from the row just
        # committed above — never a separately-reconstructed or older scan.
        canonical_report = report_service.build_canonical_report(db, scan_results["id"])

        # 5. Prepare scan_data for email (legacy shape, kept for the fallback
        # path in mail_service when canonical_report can't be built)
        scan_data = {
            "reportType": report_type.upper(),
            "formats": ["pdf", "json", "xml", "csv"],
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
            "canonical_report": canonical_report,
        }

        # 6. Send Email — this scan (scan_results["id"]) was completed at
        # run_completed_at, strictly after fire_time (when this scheduled
        # trigger fired), so the report can never be an older scan than the
        # schedule that produced it.
        success, message = send_scan_report(recipient, scan_data)
        print(f"[WORKER] Scheduled scan complete for {web_url} (scan_id={scan_results['id']}, "
              f"completed_at={run_completed_at.isoformat()}). Email success: {success}, {message}")

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

    # Remove existing job if it exists (for updates) — combined with the
    # deterministic job_id and `replace_existing=True` below, re-registering
    # the same schedule (e.g. on every app restart, via start_worker()) can
    # never result in two jobs for one schedule.
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)

    # max_instances=1: if a previous run of this exact job is somehow still
    # executing when the next trigger fires, APScheduler refuses the overlap
    # instead of running two scans/emails concurrently for the same schedule.
    # coalesce=True + misfire_grace_time=3600: if the process was down when a
    # trigger should have fired, run it ONCE (not once per missed occurrence)
    # as long as we're back within an hour of the scheduled time — this is
    # what "handle application restarts correctly" means for a cron-style
    # schedule: a missed daily/weekly run still eventually happens, but never
    # replays as a burst of catch-up runs, and (per run_automated_scan_and_email)
    # always performs a fresh scan rather than emailing anything stale.
    common_kwargs = dict(
        args=[schedule_obj.id], id=job_id, replace_existing=True,
        max_instances=1, coalesce=True, misfire_grace_time=3600,
    )

    if schedule_obj.frequency == "daily":
        scheduler.add_job(
            run_automated_scan_and_email,
            'cron',
            hour=hour,
            minute=minute,
            **common_kwargs,
        )
    elif schedule_obj.frequency == "weekly":
        # The UI offers no day-of-week picker, so "weekly" anchors to the
        # weekday this job is (re-)registered on — either the day the
        # schedule was created, or the day the server was last restarted.
        # Previously this frequency matched no branch at all: the schedule
        # row saved fine and the UI reported success, but no job was ever
        # registered, so a "Weekly Compliance Pulse" schedule silently
        # never ran.
        scheduler.add_job(
            run_automated_scan_and_email,
            'cron',
            day_of_week=datetime.now().weekday(),
            hour=hour,
            minute=minute,
            **common_kwargs,
        )
    elif schedule_obj.frequency == "once":
        # A 'cron' trigger with only hour/minute set recurs every day —
        # indistinguishable from "daily" — so a schedule the UI labels
        # "Once (Scheduled Single Run)" was actually running forever. A
        # 'date' trigger fires exactly once, at the next occurrence of the
        # requested time (today if not yet passed, else tomorrow).
        run_at = datetime.now().replace(hour=hour, minute=minute, second=0, microsecond=0)
        if run_at <= datetime.now():
            run_at += timedelta(days=1)
        scheduler.add_job(
            run_automated_scan_and_email,
            'date',
            run_date=run_at,
            **common_kwargs,
        )

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

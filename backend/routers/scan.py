"""
Triad Scan router — deterministic scanning, NO AI in the pipeline.
"""

import json
import uuid
import logging
import threading
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from db import get_db, with_retry, SessionLocal
from models import ScanResult
from services.scanner_engine import perform_triad_scan
from services.api_scanner import discover_endpoints
from services.cbom_generator import generate_triad_cbom
from services.remediation_service import generate_triad_remediation
from services.discovery_service import discover_pnb_assets, normalize_host
from services.audit_service import log_audit_event
from services import scan_progress

router = APIRouter()
log = logging.getLogger(__name__)


@router.get("/history")
def get_scan_history(db: Session = Depends(get_db)):
    scans = db.query(ScanResult).order_by(ScanResult.timestamp.desc()).all()
    data = [
        {
            "id": s.scan_id,
            "timestamp": s.timestamp.isoformat(),
            "target": s.web_url,
            "qvs": s.overall_qvs,
        }
        for s in scans
    ]
    return {"success": True, "data": data}


@router.get("/{scan_id}")
def get_scan_detail(scan_id: str, db: Session = Depends(get_db)):
    from fastapi.responses import JSONResponse
    scan = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).first()
    if not scan:
        return JSONResponse(status_code=404, content={"success": False, "message": "Scan not found"})
    
    return {
        "success": True,
        "data": {
            "id": scan.scan_id,
            "timestamp": scan.timestamp.isoformat(),
            "findings": json.loads(scan.findings_json or '{}'),
            "riskScores": json.loads(scan.risk_scores_json or '{}'),
            "cbom": json.loads(scan.cbom_json or '{}'),
            "apiMetrics": json.loads(scan.api_metrics_json or '{}'),
            "assetDetails": json.loads(scan.asset_details_json or '{}'),
            "webUrl": scan.web_url,
            "vpnUrl": scan.vpn_url,
            "apiUrl": scan.api_url,
        }
    }


class TriadScanRequest(BaseModel):
    webUrl: str = "www.pnb.bank.in"
    vpnUrl: str = "vpn.pnb.bank.in"
    apiUrl: str = "api.pnb.bank.in"
    jwtToken: Optional[str] = ""


def _run_triad_pipeline(body: TriadScanRequest, db: Session, job_id: Optional[str] = None) -> dict:
    """The full scan pipeline: 5-pillar scan, discovery, deep API probing,
    CBOM + remediation generation, and persistence. Shared by the synchronous
    /triad endpoint and the background job kicked off by /triad/start.

    job_id, if given, drives scan_progress updates the frontend polls.
    """
    def _report(pct, stage):
        if job_id:
            scan_progress.update_progress(job_id, pct, stage)

    log_audit_event({"action": "START_TRIAD_SCAN", "target": body.webUrl, "user": "hackathon_user"})

    # 1. Deterministic Triad Scan (no AI) — reports 2%-50% internally, per pillar.
    scan_results = perform_triad_scan(
        body.webUrl, body.vpnUrl, body.apiUrl, body.jwtToken or "",
        progress_cb=_report if job_id else None,
    )

    # 2. Organic Infrastructure Discovery (Find all subdomains first).
    # Hosts the Triad scan just measured (web/vpn/api targets) are passed in
    # as prescanned so discovery reuses that QVS instead of re-probing them —
    # avoids a redundant second TLS handshake per already-scanned host.
    prescanned = {}
    for target, pillar_key in ((body.webUrl, "web"), (body.vpnUrl, "vpn"), (body.apiUrl, "api")):
        if not target:
            continue
        qvs = scan_results["riskScores"].get(pillar_key)
        if qvs is None:
            continue
        prescanned[normalize_host(target)] = {"qvs": qvs, "pqc_ready": qvs < 20}

    _report(55, "Discovering subdomains and infrastructure assets...")
    discovery_results = discover_pnb_assets(body.webUrl, prescanned=prescanned)
    discovered_assets = discovery_results.get("assets", [])

    # 3. Deep Multi-Host API Probing
    # We probe the main API URL AND a bounded set of discovered web-active
    # subdomains. discover_endpoints() probes ~44 paths per host (worst case
    # ~15s if every probe times out); a target with many real subdomains
    # (a large bank, github.com in testing) can surface dozens of assets, and
    # probing all of them serially turns one scan into minutes. Capped to
    # keep total scan time bounded and predictable for the caller.
    MAX_DEEP_PROBE_HOSTS = 3
    all_endpoints = []
    seen_endpoint_urls = set()

    hosts_to_probe = [body.webUrl, body.apiUrl] if body.apiUrl else [body.webUrl]
    for asset in discovered_assets:
        if "Web/TLS" in asset.get("pillars", []):
            hosts_to_probe.append(asset["host"])

    target_hosts = [h for h in list(dict.fromkeys(hosts_to_probe)) if h][:MAX_DEEP_PROBE_HOSTS]

    _report(75, "Probing discovered API endpoints...")
    # Parallelize host endpoint discovery
    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=len(target_hosts) or 1) as executor:
        future_to_host = {executor.submit(discover_endpoints, h): h for h in target_hosts}
        for future in as_completed(future_to_host):
            try:
                res = future.result()
                for ep in res.get("details", []):
                    if ep["url"] not in seen_endpoint_urls:
                        all_endpoints.append(ep)
                        seen_endpoint_urls.add(ep["url"])
            except Exception as e:
                pass

    # Update api_metrics for the UI summary
    api_metrics = {
        "total": len(all_endpoints),
        "discovered": len(all_endpoints),
        "details": all_endpoints,
        "buckets": {}, # Calculated from all_endpoints
        "quantumRisk": {"vulnerable": sum(1 for ep in all_endpoints if "PQC" not in ep.get("quantumRisk", "")), "pqc_ready": sum(1 for ep in all_endpoints if "PQC" in ep.get("quantumRisk", ""))}
    }
    for ep in all_endpoints:
        b = ep.get("bucket", "General API")
        api_metrics["buckets"][b] = api_metrics["buckets"].get(b, 0) + 1

    _report(88, "Generating unified CBOM...")
    # 4. Unified CBOM Generation (Ingests discovered hosts AND deep API endpoints)
    cbom = generate_triad_cbom(
        scan_results["findings"], 
        body.webUrl, 
        body.vpnUrl, 
        body.apiUrl,
        discovered_assets=discovered_assets,
        discovered_endpoints=all_endpoints,
        discovered_mobile_apps=discovery_results.get("mobile_apps", [])
    )

    _report(94, "Generating remediation recommendations...")
    # 5. Triad-Specific Remediation
    remediation = generate_triad_remediation(scan_results["findings"], body.webUrl, body.vpnUrl, body.apiUrl)

    _report(98, "Persisting scan results...")
    # 5. Persist scan result to SQLite
    scan_record = ScanResult(
        scan_id=scan_results["id"],
        web_url=body.webUrl,
        vpn_url=body.vpnUrl,
        api_url=body.apiUrl,
        findings_json=json.dumps(scan_results["findings"]),
        risk_scores_json=json.dumps(scan_results["riskScores"]),
        cbom_json=json.dumps(cbom),
        api_metrics_json=json.dumps(api_metrics),
        asset_details_json=json.dumps(scan_results.get("assetDetails", {})),
        overall_qvs=scan_results["riskScores"]["overall"],
    )
    db.add(scan_record)
    with_retry(lambda: db.commit())

    log_audit_event({"action": "COMPLETE_TRIAD_SCAN", "scan_id": scan_results["id"], "qvs": scan_results["riskScores"]["overall"]})

    return {
        **scan_results,
        "apiMetrics": api_metrics,
        "cbom": cbom,
        "remediation": remediation,
    }


@router.post("/triad")
def triad_scan(body: TriadScanRequest, db: Session = Depends(get_db)):
    return {"success": True, "data": _run_triad_pipeline(body, db)}


@router.post("/triad/start")
def triad_scan_start(body: TriadScanRequest):
    """Kick off the scan pipeline in a background thread and return a job_id
    immediately. Poll GET /api/scan/progress/{job_id} for live status; once
    done, the same response carries the final result under "result" (same
    shape POST /triad returns under "data")."""
    job_id = uuid.uuid4().hex
    scan_progress.start_job(job_id)

    def _run():
        db = SessionLocal()
        try:
            result = _run_triad_pipeline(body, db, job_id=job_id)
            scan_progress.finish_job(job_id, result=result)
        except Exception as e:
            log.error("Background triad scan %s failed: %s", job_id, e, exc_info=True)
            scan_progress.finish_job(job_id, error=str(e))
        finally:
            db.close()

    threading.Thread(target=_run, daemon=True).start()
    return {"success": True, "data": {"job_id": job_id}}


@router.get("/progress/{job_id}")
def triad_scan_progress(job_id: str):
    job = scan_progress.get_job(job_id)
    if job is None:
        return JSONResponse(status_code=404, content={"success": False, "message": "Job not found"})
    return {
        "success": True,
        "data": {
            "percent": job["percent"],
            "stage": job["stage"],
            "done": job["done"],
            "error": job["error"],
            "result": job["result"],
        },
    }

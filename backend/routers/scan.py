"""
Triad Scan router — deterministic scanning, NO AI in the pipeline.
"""

import json
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from db import get_db, with_retry
from models import ScanResult
from services.scanner_engine import perform_triad_scan
from services.api_scanner import discover_endpoints
from services.cbom_generator import generate_triad_cbom
from services.remediation_service import generate_triad_remediation
from services.discovery_service import discover_pnb_assets
from services.audit_service import log_audit_event

router = APIRouter()


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


@router.post("/triad")
def triad_scan(body: TriadScanRequest, db: Session = Depends(get_db)):
    log_audit_event({"action": "START_TRIAD_SCAN", "target": body.webUrl, "user": "hackathon_user"})

    # 1. Deterministic Triad Scan (no AI)
    scan_results = perform_triad_scan(body.webUrl, body.vpnUrl, body.apiUrl, body.jwtToken or "")

    # 2. Organic Infrastructure Discovery (Find all subdomains first)
    discovery_results = discover_pnb_assets(body.webUrl)
    discovered_assets = discovery_results.get("assets", [])

    # 3. Deep Multi-Host API Probing
    # We probe the main API URL AND a bounded set of discovered web-active
    # subdomains. discover_endpoints() probes ~44 paths per host (worst case
    # ~15s if every probe times out); a target with many real subdomains
    # (a large bank, github.com in testing) can surface dozens of assets, and
    # probing all of them serially turns one scan into minutes. Capped to
    # keep total scan time bounded and predictable for the caller.
    MAX_DEEP_PROBE_HOSTS = 6
    all_endpoints = []
    seen_endpoint_urls = set()

    hosts_to_probe = [body.webUrl, body.apiUrl] if body.apiUrl else [body.webUrl]
    for asset in discovered_assets:
        if "Web/TLS" in asset.get("pillars", []):
            hosts_to_probe.append(asset["host"])

    # Run API discovery across the found surface area (bounded)
    for host in list(dict.fromkeys(hosts_to_probe))[:MAX_DEEP_PROBE_HOSTS]:
        if not host: continue
        res = discover_endpoints(host)
        for ep in res.get("details", []):
            if ep["url"] not in seen_endpoint_urls:
                all_endpoints.append(ep)
                seen_endpoint_urls.add(ep["url"])

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

    # 5. Triad-Specific Remediation
    remediation = generate_triad_remediation(scan_results["findings"], body.webUrl, body.vpnUrl, body.apiUrl)

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
        overall_qvs=scan_results["riskScores"]["overall"],
    )
    db.add(scan_record)
    with_retry(lambda: db.commit())

    log_audit_event({"action": "COMPLETE_TRIAD_SCAN", "scan_id": scan_results["id"], "qvs": scan_results["riskScores"]["overall"]})

    return {
        "success": True,
        "data": {
            **scan_results,
            "apiMetrics": api_metrics,
            "cbom": cbom,
            "remediation": remediation,
        },
    }

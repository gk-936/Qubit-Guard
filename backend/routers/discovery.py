"""
Discovery Router — API endpoints for asset discovery and pillar classification.
"""

import uuid
import logging
import threading
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from db import get_db
from services.discovery_service import discover_pnb_assets
from services import scan_progress

router = APIRouter()
log = logging.getLogger(__name__)

class DiscoveryRequest(BaseModel):
    target: str

@router.post("/")
def perform_discovery(body: DiscoveryRequest):
    """
    Triggers a discovery scan for a targeting domain (and its subdomains).
    Classifies assets across Triad pillars (Web/VPN/API).
    """
    result = discover_pnb_assets(body.target)
    return {"success": True, "data": result}


@router.post("/start")
def start_discovery(body: DiscoveryRequest):
    """Kick off discovery in a background thread and return a job_id
    immediately — discovery can take several minutes (live DNS/CT-log/OSINT
    probing), so the frontend polls GET /api/discovery/progress/{job_id}
    instead of holding one long-lived request open."""
    job_id = uuid.uuid4().hex
    scan_progress.start_job(job_id)

    def _run():
        try:
            result = discover_pnb_assets(body.target, progress_cb=lambda pct, stage: scan_progress.update_progress(job_id, pct, stage))
            scan_progress.finish_job(job_id, result=result)
        except Exception as e:
            log.error("Background discovery %s failed: %s", job_id, e, exc_info=True)
            scan_progress.finish_job(job_id, error=str(e))

    threading.Thread(target=_run, daemon=True).start()
    return {"success": True, "data": {"job_id": job_id}}


@router.get("/progress/{job_id}")
def discovery_progress(job_id: str):
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

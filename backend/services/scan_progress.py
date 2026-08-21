"""
In-memory progress tracker for long-running Triad scans.

The scan pipeline (5 pillars + subdomain discovery + deep API probing) is a
single blocking call that can take up to a few minutes. Since the frontend
needs a live percentage/status instead of staring at a spinner for that long,
scans run in a background thread keyed by a job_id, and this module holds
the shared state the frontend polls via GET /api/scan/progress/{job_id}.

Single-process, in-memory by design — matches this app's SQLite/single-worker
deployment model. Not meant to survive a process restart or scale across
multiple backend workers; if this ever runs behind >1 uvicorn worker, this
needs to move to something shared (Redis, DB row) instead.
"""

import time
import threading
from typing import Optional

_lock = threading.Lock()
_jobs: dict = {}

# A job's entry is kept around for a while after completion so a client that
# polls right after the final update still sees the result, then swept away
# on the next access so the dict doesn't grow unbounded over a long-lived
# process.
_TTL_SECONDS = 15 * 60


def _sweep_locked():
    cutoff = time.time() - _TTL_SECONDS
    stale = [jid for jid, j in _jobs.items() if j.get("done") and j.get("updated_at", 0) < cutoff]
    for jid in stale:
        del _jobs[jid]


def start_job(job_id: str) -> None:
    with _lock:
        _sweep_locked()
        _jobs[job_id] = {
            "percent": 0,
            "stage": "Queued",
            "done": False,
            "error": None,
            "result": None,
            "updated_at": time.time(),
        }


def update_progress(job_id: str, percent: int, stage: str) -> None:
    with _lock:
        job = _jobs.get(job_id)
        if job is None:
            return
        job["percent"] = max(0, min(100, percent))
        job["stage"] = stage
        job["updated_at"] = time.time()


def finish_job(job_id: str, result: Optional[dict] = None, error: Optional[str] = None) -> None:
    with _lock:
        job = _jobs.get(job_id)
        if job is None:
            return
        job["done"] = True
        job["percent"] = 100 if error is None else job["percent"]
        job["stage"] = "Complete" if error is None else "Failed"
        job["error"] = error
        job["result"] = result
        job["updated_at"] = time.time()


def get_job(job_id: str) -> Optional[dict]:
    with _lock:
        job = _jobs.get(job_id)
        return dict(job) if job else None

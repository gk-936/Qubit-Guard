"""
Qubit-Guard — FastAPI Backend Entry Point
"""

import os
import logging
import threading
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(levelname)s [%(name)s] %(message)s")

from db import engine, Base, ensure_schema
from seed_data import seed
from security import require_auth
from routers import auth, scan, data, remediation, mobile, discovery, scheduler, pqc_selector

# Applied to every router below except /api/auth, so authentication is enforced
# server-side and not just by the React client.
PROTECTED = [Depends(require_auth)]

# --- Stability Fixes for Render (Multi-worker environment) ---
_seed_lock = threading.Lock()
_has_seeded = False

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _has_seeded
    
    # 1. Create tables safely (only if they don't exist)
    Base.metadata.create_all(bind=engine, checkfirst=True)
    
    # 2. Ensure schema integrity
    ensure_schema()
    
    # 3. Seed data ONLY ONCE across all workers to prevent race conditions
    if not _has_seeded:
        with _seed_lock:
            # Double-check pattern to ensure only one worker seeds
            if not _has_seeded:
                try:
                    seed()
                    _has_seeded = True
                    print("[INIT] Database seeded successfully.")
                except Exception as e:
                    print(f"[ERROR] Seeding failed: {e}")
                    # We don't raise here to allow the app to start even if seeding fails
                    # (e.g., if DB is locked by another process momentarily)

    # 4. Start the background reporting worker
    from services.worker import start_worker
    start_worker()

    print("""
    [*] Qubit-Guard.AI Backend is up!
    [>] Framework: FastAPI + Uvicorn
    [>] PQC Scanning Engine: ONLINE (Deterministic)
    [>] PQC Smart Selector: ONLINE (Deterministic Rule-Table Ensemble)
    [>] Storage: SQLite via SQLAlchemy
    """)
    yield
    # Shutdown
    print("[SERVER] Shutting down.")


app = FastAPI(
    title="Qubit-Guard.AI",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS_ORIGINS is a comma-separated allowlist (e.g.
# "https://app.example.com,https://admin.example.com"). Defaults to the
# Vite dev server origins this project actually uses locally. Note:
# allow_origins=["*"] together with allow_credentials=True is an invalid
# combination per the CORS spec — browsers reject it outright — so a
# wildcard was never actually working safely here to begin with.
#
# Deliberately falls back to the default on an EMPTY value too, not just an
# absent one: os.getenv("CORS_ORIGINS", default) only applies the default
# when the key is unset. A deployer copying the .env template with
# `CORS_ORIGINS=` left blank would otherwise get os.getenv() back an empty
# string, split into an empty allowlist — silently blocking every origin,
# including localhost. Blank is treated as "not configured", same as unset.
_default_cors_origins = "http://localhost:5173,http://127.0.0.1:5173"
CORS_ORIGINS = [
    origin.strip()
    for origin in (os.getenv("CORS_ORIGINS") or _default_cors_origins).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    # The frontend authenticates with a Bearer token in the Authorization
    # header (see frontend/src/api.js — token pulled from localStorage and
    # set on config.headers.Authorization) and never sets
    # `withCredentials`/relies on cookies. So there is nothing here that
    # needs cookies to cross an origin, and allow_credentials can stay off —
    # which also sidesteps the wildcard-plus-credentials invalid combination
    # noted above.
    allow_credentials=False,
    # Only the HTTP methods the frontend actually issues (see
    # frontend/src/api.js: get/post/delete). Add PUT/PATCH here if a future
    # endpoint needs them.
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    # Only the headers the frontend actually sends: JSON bodies, the bearer
    # token, and the active-scan context header.
    allow_headers=["Content-Type", "Authorization", "X-Scan-Id"],
)


# ── Health Check ──────────────────────────────────────────────────────────────
@app.get("/api/health")
def health():
    from datetime import datetime
    return {
        "status": "Qubit-Guard AI Backend v2.0 Active",
        "pqc_engine": "Ready (Deterministic)",
        "storage": "SQLite",
        "timestamp": datetime.utcnow().isoformat(),
    }


# ── Mount Routers ─────────────────────────────────────────────────────────────
app.include_router(auth.router,        prefix="/api/auth",        tags=["Auth"])
app.include_router(scan.router,        prefix="/api/scan",        tags=["Scan"],        dependencies=PROTECTED)
app.include_router(data.router,        prefix="/api/data",        tags=["Data"],        dependencies=PROTECTED)
app.include_router(remediation.router, prefix="/api/remediation", tags=["Remediation"], dependencies=PROTECTED)
app.include_router(discovery.router,   prefix="/api/discovery",   tags=["discovery"],   dependencies=PROTECTED)
app.include_router(mobile.router,      prefix="/api/mobile",      tags=["Mobile"],      dependencies=PROTECTED)
app.include_router(scheduler.router,   prefix="/api/scheduler",   tags=["Scheduler"],   dependencies=PROTECTED)
app.include_router(pqc_selector.router, prefix="/api/pqc",        tags=["PQC Selector"], dependencies=PROTECTED)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 5006))
    # Auto-reload watches the whole backend/ tree by default, which includes
    # backend/database/*.db*. In WAL mode SQLite writes to *.db-wal on every
    # transaction, so the watcher sees constant "file changed" events and
    # thrashes/restarts the worker mid-request — a real scan (multiple
    # network probes, several seconds each) then hangs or times out client
    # side instead of completing in the ~15s it takes standalone. Off by
    # default; opt in for active development with RELOAD=true, and if you
    # do, exclude backend/database/ from the watch.
    reload_enabled = os.getenv("RELOAD", "false").strip().lower() == "true"
    print(f"[*] Starting backend on port {port} (reload={reload_enabled})...")
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=reload_enabled)

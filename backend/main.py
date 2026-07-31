"""
Qubit-Guard — FastAPI Backend Entry Point
"""

import os
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

from db import engine, Base, ensure_schema
from seed_data import seed
from security import require_auth
from routers import auth, scan, data, remediation, mobile, discovery, scheduler, pqc_selector

# Applied to every router below except /api/auth, so authentication is enforced
# server-side and not just by the React client.
PROTECTED = [Depends(require_auth)]


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: create tables, migrate existing DBs, & seed
    Base.metadata.create_all(bind=engine)
    ensure_schema()
    seed()

    # Start the background reporting worker
    from services.worker import start_worker
    start_worker()

    print("""
    [*] Qubit-Guard.AI Backend is up!
    [>] Framework: FastAPI + Uvicorn
    [>] PQC Scanning Engine: ONLINE (Deterministic)
    [>] PQC Smart Selector: ONLINE (ML Random Forest)
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
    print(f"[*] Starting backend on port {port}...")
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)

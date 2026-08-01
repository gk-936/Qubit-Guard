"""
Scheduler router — create and list automated scan schedules.
"""

import json
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel

from db import get_db
from models import Schedule

router = APIRouter()


class ScheduleCreateRequest(BaseModel):
    frequency: str = "daily"
    targets: dict = {}
    scheduled_time: str = "09:00"
    email: str = "admin@pnb.co.in"
    report_type: str = "executive"


@router.post("/create")
def create_schedule(body: ScheduleCreateRequest, db: Session = Depends(get_db)):
    schedule = Schedule(
        frequency=body.frequency,
        targets_json=json.dumps(body.targets),
        scheduled_time=body.scheduled_time,
        email=body.email,
        report_type=body.report_type,
        is_active=True
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    
    # Live-register the job with APScheduler
    try:
        from services.worker import register_schedule
        register_schedule(schedule)
    except Exception as e:
        print(f"[SCHEDULER] Failed to register live job: {e}")

    return {
        "success": True, 
        "schedule": {
            "id": schedule.id, 
            "frequency": body.frequency, 
            "targets": body.targets,
            "time": body.scheduled_time,
            "email": body.email
        }
    }


@router.get("/list")
def list_schedules(db: Session = Depends(get_db)):
    schedules = db.query(Schedule).all()
    return [
        {
            "id": s.id, 
            "frequency": s.frequency, 
            "targets": json.loads(s.targets_json),
            "time": s.scheduled_time,
            "email": s.email,
            "report_type": s.report_type,
            "last_run": s.last_run_at.isoformat() if s.last_run_at else None,
            "is_active": s.is_active
        }
        for s in schedules
    ]

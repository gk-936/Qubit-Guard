"""
Auth router — login and token verification.
"""

from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
import bcrypt
from jose import jwt, JWTError
from pydantic import BaseModel

from db import get_db
from models import User
from security import JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRE_HOURS
from services.audit_service import log_audit_event

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == body.username).first()
    if user:
        # Pydantic strings to bytes, max 72 bytes for native bcrypt
        password_bytes = body.password.encode('utf-8')[:72]
        hash_bytes = user.password.encode('utf-8')
        if bcrypt.checkpw(password_bytes, hash_bytes):
            token = jwt.encode(
                {
                    "username": user.username,
                    "role": user.role,
                    "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS),
                },
                JWT_SECRET,
                algorithm=JWT_ALGORITHM,
            )
            log_audit_event({"action": "LOGIN_SUCCESS", "user": user.username})
            return {"success": True, "token": token, "user": {"username": user.username, "role": user.role}}
    # audit_service.py bills itself as being "for non-repudiation and
    # compliance", but login — the one event that claim is most obviously
    # about — was never logged at all before this. Logging the attempted
    # username on failure too (not just successes) so a real auditor can see
    # brute-force/guessing attempts, not only successful sessions.
    log_audit_event({"action": "LOGIN_FAILURE", "user": body.username})
    return JSONResponse(status_code=401, content={"success": False, "message": "Invalid credentials"})


@router.get("/verify")
def verify(request: Request):
    token = request.headers.get("authorization", "")
    if not token:
        return JSONResponse(status_code=401, content={"success": False})
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return {"success": True, "user": decoded}
    except JWTError:
        return JSONResponse(status_code=401, content={"success": False})

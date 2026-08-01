"""
Authentication configuration and the shared request dependency.

Every router except /api/auth and the health check mounts `require_auth`, so
authentication is enforced on the server rather than only in the React client.
"""

import os

from fastapi import Header, HTTPException
from jose import jwt, JWTError

JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 1

JWT_SECRET = os.getenv("JWT_SECRET", "").strip()

if not JWT_SECRET:
    # Fail at startup rather than silently signing tokens with a key that is
    # committed to the repository — anyone who has read the source could then
    # forge a valid session.
    raise RuntimeError(
        "JWT_SECRET is not set. Refusing to start with a fallback signing key. "
        "Set JWT_SECRET in backend/.env (see backend/.env.example)."
    )


def require_auth(authorization: str = Header(default="")) -> dict:
    """Reject any request that does not carry a valid, unexpired session token.

    Accepts either a bare token or a `Bearer <token>` header — the frontend
    currently sends it bare.

    Returns the decoded claims so routes can depend on the caller's identity.
    """
    token = authorization.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

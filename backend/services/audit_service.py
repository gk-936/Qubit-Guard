"""
Audit logging service for non-repudiation and compliance.
"""

import os
import json
from datetime import datetime

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "audit.log")


def log_audit_event(event: dict):
    """Append a structured audit event to the log file."""
    try:
        entry = {"timestamp": datetime.utcnow().isoformat(), **event}
        # default=str: a non-JSON-serializable value (e.g. a datetime) used to
        # raise inside this same try and get silently swallowed by the except
        # below — the whole audit line was just dropped, console-only. Falling
        # back to str() keeps the event on record instead of losing it.
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception as e:
        print(f"[AUDIT] Failed to write log: {e}")

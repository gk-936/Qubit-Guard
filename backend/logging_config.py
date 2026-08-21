"""
Application-wide debug logging configuration.

Separate from services/audit_service.py, which is a compliance/non-repudiation
event trail (structured JSON, one line per business event). This module is for
developer-facing debugging: request/response tracing, stack traces, and
per-module log levels, written to a rotating file plus the console.

Level is controlled by the LOG_LEVEL env var (default INFO). Set
LOG_LEVEL=DEBUG for verbose tracing during local development.
"""

import os
import logging
from logging.handlers import RotatingFileHandler

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
DEBUG_LOG_FILE = os.path.join(LOG_DIR, "debug.log")

_LOG_FORMAT = "%(asctime)s %(levelname)-8s [%(name)s] %(message)s"


def configure_logging() -> None:
    """Set up root logger handlers. Idempotent — safe to call more than once
    (e.g. under uvicorn's --reload, which re-imports main.py)."""
    root = logging.getLogger()
    level = getattr(logging, os.getenv("LOG_LEVEL", "INFO").strip().upper(), logging.INFO)
    root.setLevel(level)

    if any(getattr(h, "_qubitguard_debug_handler", False) for h in root.handlers):
        return

    formatter = logging.Formatter(_LOG_FORMAT)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler._qubitguard_debug_handler = True
    root.addHandler(console_handler)

    # 5 MB per file, keep 5 rotations — enough local history without
    # growing unbounded on a long-running dev/staging process.
    file_handler = RotatingFileHandler(DEBUG_LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler._qubitguard_debug_handler = True
    root.addHandler(file_handler)

    # uvicorn's own loggers otherwise bypass this format/handler set.
    for noisy in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(noisy).handlers = []
        logging.getLogger(noisy).propagate = True

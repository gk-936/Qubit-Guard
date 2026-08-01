"""
SQLAlchemy engine and session factory for QuantumShield SQLite database.
"""

import logging
import os
import sqlite3
import time

from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import OperationalError as SAOperationalError
from sqlalchemy.orm import sessionmaker, declarative_base

log = logging.getLogger(__name__)

DB_DIR = os.path.join(os.path.dirname(__file__), "database")
os.makedirs(DB_DIR, exist_ok=True)

DATABASE_URL = f"sqlite:///{os.path.join(DB_DIR, 'quantumshield.db')}"

# `timeout` is the Python sqlite3 driver's own connect-time setting (seconds).
# Under the hood, the stdlib sqlite3 module implements it by calling SQLite's
# sqlite3_busy_timeout() C API at connection time, so it establishes a busy
# handler as soon as the DBAPI connection is created — before our "connect"
# event listener below runs its PRAGMA statements. It's kept here mainly as a
# defensive baseline for that brief window and for any connection made
# outside the event hook. The PRAGMA busy_timeout set in the listener is the
# one that actually governs behavior for the lifetime of each pooled
# connection: it is set explicitly (independent of driver defaults/version
# quirks), re-applied on every new connection, and is what SQLite itself
# consults when a writer hits a lock. So: driver `timeout` = safety net,
# `PRAGMA busy_timeout` = source of truth.
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 5},
    echo=False,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


@event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):
    """Apply SQLite concurrency-hardening PRAGMAs to every new DBAPI
    connection. Guarded to only run for SQLite so this engine module keeps
    working unmodified if DATABASE_URL is ever pointed at another database.
    """
    if engine.dialect.name != "sqlite":
        return

    cursor = dbapi_connection.cursor()
    try:
        # WAL mode lets readers proceed concurrently with a single writer
        # instead of blocking on SQLite's default rollback-journal exclusive
        # lock. This is the single biggest fix for the "dashboard read while
        # a scan writes" contention described in the problem statement.
        cursor.execute("PRAGMA journal_mode=WAL")

        # Without this, a connection that finds the DB locked raises
        # sqlite3.OperationalError immediately. With it, SQLite internally
        # retries/waits for up to this many milliseconds before giving up.
        # 5000ms is the commonly recommended default for busy_timeout: long
        # enough to ride out a typical scan write (or another request's
        # transaction) without the caller ever seeing "database is locked",
        # short enough that a genuinely stuck/deadlocked connection still
        # fails within a bounded, human-noticeable time rather than hanging
        # a request indefinitely.
        cursor.execute("PRAGMA busy_timeout=5000")

        # synchronous=NORMAL is the standard companion to WAL: in WAL mode,
        # NORMAL still guarantees the database can never be corrupted by an
        # application/OS crash (SQLite docs), it just means the most recent
        # transaction(s) could theoretically be lost on a power loss/OS
        # crash at the exact moment of a checkpoint. That's an acceptable
        # trade for a locally-hosted scan-results DB in exchange for
        # meaningfully faster writes (avoids an fsync on every commit,
        # which is the other major source of write latency/lock contention
        # here). FULL (the default outside WAL) is unnecessary durability
        # for this workload and just makes the lock-contention problem worse.
        cursor.execute("PRAGMA synchronous=NORMAL")

        # Not previously set — enforce referential integrity on every
        # connection now that we're already touching per-connection PRAGMAs.
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


def get_db():
    """FastAPI dependency that yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def with_retry(fn, attempts=3, base_delay=0.1):
    """Retry helper for the residual case where a write still fails even
    after PRAGMA busy_timeout has been waiting — e.g. very hot contention
    where multiple writers keep re-acquiring the lock faster than one of
    them can get in, or a single writer holding the lock longer than the
    busy_timeout window.

    Not wired into any call site in this module or elsewhere — callers
    (services, routers) own the decision of which individual write needs
    this protection and should wrap just that operation, e.g.:

        from db import with_retry

        def save_scan_result(db, ...):
            with_retry(lambda: (db.add(result), db.commit()))

    Behavior:
      - Retries only sqlite3.OperationalError / sqlalchemy.exc.OperationalError
        whose message contains "locked" or "busy" (case-insensitive) — i.e.
        exactly the "database is locked" / "database is busy" family.
      - Any other exception (including other OperationalErrors, e.g. a bad
        column name) is re-raised immediately, unretried.
      - Uses exponential backoff between attempts: base_delay * 2**(n-1).
      - After the final attempt still fails, re-raises the original
        exception — the failure is never swallowed.
    """
    last_exc = None
    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except (sqlite3.OperationalError, SAOperationalError) as exc:
            message = str(exc).lower()
            if "locked" not in message and "busy" not in message:
                # Not a lock-contention error — don't retry, surface it now.
                raise

            last_exc = exc
            if attempt >= attempts:
                log.error(
                    "with_retry: giving up after %d attempt(s), last error: %s",
                    attempt,
                    exc,
                )
                raise

            delay = base_delay * (2 ** (attempt - 1))
            log.warning(
                "with_retry: attempt %d/%d failed (%s), retrying in %.3fs",
                attempt,
                attempts,
                exc,
                delay,
            )
            time.sleep(delay)

    # Unreachable in practice (the loop always returns or raises above),
    # but kept as a defensive final re-raise so a failure can never be
    # silently swallowed.
    if last_exc is not None:
        raise last_exc


# Tables that carry the "source" provenance column (seed / scan / manual).
_PROVENANCE_TABLES = [
    "dashboard_summary",
    "inventory_stats",
    "posture_stats",
    "cbom_vulnerability_summary",
    "cbom_items",
]


def ensure_schema():
    """Idempotent migration for databases whose on-disk schema has drifted
    behind models.py. Base.metadata.create_all() only creates brand-new
    tables — it never adds columns to tables that already exist — so any
    pre-existing quantumshield.db file keeps whatever columns existed the
    day it was first created, forever, unless something migrates it.

    Two passes:
      1. Provenance columns ('source' on the five seed/scan/manual tables,
         see #18) — handled first since it also backfills existing rows.
      2. Generic column drift — for every other model column missing from
         its table on disk, ADD COLUMN it. Only columns the model declares
         nullable are auto-added (existing rows get NULL, which is always a
         legal value for them); a NOT NULL column that's missing needs a
         real default decided by a human, so it's logged and skipped rather
         than guessed at.

    This exists because 'schedules' silently drifted five columns behind
    its model (scheduled_time, email, report_type, is_active, last_run_at)
    with nothing to catch it — the very first read of that table at startup
    (the scheduler reloading active jobs) raised OperationalError and the
    app failed to boot. Pass 2 makes that class of failure impossible to
    reintroduce for any table.
    """
    with engine.begin() as conn:
        for table in _PROVENANCE_TABLES:
            cols = [row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))]
            if not cols:
                # Table doesn't exist yet (fresh DB) — create_all() will make
                # it with the column already present.
                continue
            if "source" not in cols:
                conn.execute(text(
                    f"ALTER TABLE {table} ADD COLUMN source VARCHAR(20) NOT NULL DEFAULT 'scan'"
                ))
                # Every row that existed the instant before this ALTER ran
                # predates provenance tracking entirely, so it was seeded.
                conn.execute(text(f"UPDATE {table} SET source='seed'"))
                print(f"[MIGRATION] Added 'source' column to '{table}' and backfilled existing rows as 'seed'.")

        for table_name, table in Base.metadata.tables.items():
            db_cols = [row[1] for row in conn.execute(text(f"PRAGMA table_info({table_name})"))]
            if not db_cols:
                continue  # fresh table — create_all() already made it correctly
            db_cols = set(db_cols)
            for column in table.columns:
                if column.name in db_cols:
                    continue
                if not column.nullable:
                    log.warning(
                        "ensure_schema: '%s.%s' is missing from the database but is "
                        "NOT NULL in the model — skipping auto-migration; add it manually "
                        "with an explicit default.",
                        table_name, column.name,
                    )
                    continue
                col_type = column.type.compile(dialect=engine.dialect)
                conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column.name} {col_type}"))
                print(f"[MIGRATION] Added missing column '{table_name}.{column.name}' ({col_type}).")

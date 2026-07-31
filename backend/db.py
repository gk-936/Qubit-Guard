"""
SQLAlchemy engine and session factory for QuantumShield SQLite database.
"""

import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base

DB_DIR = os.path.join(os.path.dirname(__file__), "database")
os.makedirs(DB_DIR, exist_ok=True)

DATABASE_URL = f"sqlite:///{os.path.join(DB_DIR, 'quantumshield.db')}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False}, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency that yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Tables that carry the "source" provenance column (seed / scan / manual).
_PROVENANCE_TABLES = [
    "dashboard_summary",
    "inventory_stats",
    "posture_stats",
    "cbom_vulnerability_summary",
    "cbom_items",
]


def ensure_schema():
    """Idempotent migration for databases created before the 'source'
    provenance column existed. Base.metadata.create_all() only creates
    brand-new tables — it never adds columns to tables that already exist —
    so pre-existing quantumshield.db files need this to pick up 'source'.

    For each provenance table: if the 'source' column is missing, add it
    (defaulting new/future rows to 'scan'), then immediately mark every row
    that already exists at that moment as 'seed', since every row present
    before this migration ran was inserted by the old seed script.
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

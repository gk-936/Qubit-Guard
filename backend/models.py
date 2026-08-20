"""
SQLAlchemy ORM models for QuantumShield.
"""

from sqlalchemy import Column, Integer, String, Float, Text, Boolean, DateTime
from sqlalchemy.sql import func
from db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False)
    password = Column(String(255), nullable=False)  # bcrypt hash
    role = Column(String(50), default="admin")
    email = Column(String(255), default="")


class DashboardSummary(Base):
    __tablename__ = "dashboard_summary"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, nullable=False)
    value = Column(String(255), nullable=False)
    label = Column(String(255), default="")
    subtext = Column(String(255), default="")
    # Provenance of this row: "seed" (shipped demo data), "scan" (derived from
    # a real scan), or "manual" (user-entered). Lets consumers tell fabricated
    # demo numbers apart from measured results.
    source = Column(String(20), default="scan", nullable=False, index=True)


class InventoryStat(Base):
    __tablename__ = "inventory_stats"

    id = Column(Integer, primary_key=True, index=True)
    category = Column(String(100), unique=True, nullable=False)  # ssl, software, iot, logins
    count = Column(Integer, default=0)
    source = Column(String(20), default="scan", nullable=False, index=True)


class PostureStat(Base):
    __tablename__ = "posture_stats"

    id = Column(Integer, primary_key=True, index=True)
    metric = Column(String(100), unique=True, nullable=False)
    value = Column(Integer, default=0)
    source = Column(String(20), default="scan", nullable=False, index=True)


class CbomVulnerabilitySummary(Base):
    __tablename__ = "cbom_vulnerability_summary"

    id = Column(Integer, primary_key=True, index=True)
    severity = Column(String(50), unique=True, nullable=False)
    count = Column(Integer, default=0)
    source = Column(String(20), default="scan", nullable=False, index=True)


class CbomItem(Base):
    __tablename__ = "cbom_items"

    id = Column(Integer, primary_key=True, index=True)
    component = Column(String(255), nullable=False)
    version = Column(String(100), default="")
    algorithm = Column(String(100), default="")
    quantum_safe = Column(Boolean, default=False)
    risk = Column(String(50), default="High")
    category = Column(String(100), default="")  # TLS, JWT, VPN, etc.
    purl = Column(String(500), default="")
    key_size = Column(String(50), default="")
    mode = Column(String(50), default="")
    source = Column(String(20), default="scan", nullable=False, index=True)


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(100), unique=True, nullable=False)
    timestamp = Column(DateTime, server_default=func.now())
    web_url = Column(String(500), default="")
    vpn_url = Column(String(500), default="")
    api_url = Column(String(500), default="")
    findings_json = Column(Text, default="{}")   # Full JSON findings
    risk_scores_json = Column(Text, default="{}") # Per-pillar QVS
    cbom_json = Column(Text, default="{}")        # Generated CBOM
    api_metrics_json = Column(Text, default="{}") # Persisted API metrics
    asset_details_json = Column(Text, default="{}") # Per-asset classification/algorithms/certs/DNS/library versions
    overall_qvs = Column(Float, default=0.0)


class Schedule(Base):
    __tablename__ = "schedules"

    id = Column(Integer, primary_key=True, index=True)
    frequency = Column(String(50), nullable=False)
    targets_json = Column(Text, default="{}")
    scheduled_time = Column(String(10), nullable=True)  # Format: "HH:MM"
    email = Column(String(255), nullable=True)
    report_type = Column(String(50), default="executive")
    is_active = Column(Boolean, default=True)
    last_run_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

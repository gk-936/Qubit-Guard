"""
Report Service — single canonical report builder, rendered into PDF/XML/JSON/CSV.

Every format exported by this app (manual download, the unified export
endpoint, and scheduled-scan emails) is built from `build_canonical_report()`.
No format has its own separate data-gathering path — that was the source of
the earlier drift between what the UI showed and what a downloaded/emailed
report said. If a value was never measured, it is carried through as None /
"N/A" here and every renderer below must show it that way too — never a
fabricated default.
"""

import csv
import io
import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime

from sqlalchemy.orm import Session

from models import ScanResult
from services.remediation_service import generate_triad_remediation

log = logging.getLogger(__name__)

# The five Triad pillars, in the fixed order every report renders them.
PILLARS = ["web", "vpn", "api", "firmware", "archival"]

NA = "N/A"


def _na(v):
    if v is None:
        return NA
    if isinstance(v, (list, tuple, dict)) and len(v) == 0:
        return NA
    if isinstance(v, str) and not v.strip():
        return NA
    return v


def _load_scan(db: Session, scan_id: str = None) -> ScanResult:
    """Fetch the scan this report is for — a specific scan_id, or the most
    recent one. Never silently substitutes a different scan than the one
    asked for: a bad scan_id returns None, not the latest scan instead."""
    if scan_id:
        return db.query(ScanResult).filter(ScanResult.scan_id == scan_id).first()
    return db.query(ScanResult).order_by(ScanResult.timestamp.desc()).first()


def build_canonical_report(db: Session, scan_id: str = None) -> dict:
    """Build the single canonical report dict every export format renders
    from. Returns None if the requested scan (or any scan, if none was
    requested) does not exist — callers must not fabricate a report for a
    scan that was never run.
    """
    scan = _load_scan(db, scan_id)
    if not scan:
        return None

    findings = json.loads(scan.findings_json or "{}")
    risk_scores = json.loads(scan.risk_scores_json or "{}")
    cbom = json.loads(scan.cbom_json or "{}")
    asset_details = json.loads(scan.asset_details_json or "{}")

    # Real per-pillar remediation, generated from this scan's own findings —
    # the same function the Triad Scanner UI's remediation cards use. Not
    # regenerated per format: computed once here so PDF/XML/JSON/CSV agree.
    remediation = generate_triad_remediation(findings, scan.web_url, scan.vpn_url, scan.api_url)
    remediation_by_pillar = {}
    for r in remediation:
        remediation_by_pillar.setdefault(r["pillar"], []).append(r)

    overall_qvs = risk_scores.get("overall")
    from services.scanner_engine import _tag_from_qvs
    overall_tag = _tag_from_qvs(overall_qvs)

    assets = []
    engine_libraries = None
    for pillar in PILLARS:
        detail = asset_details.get(pillar)
        pillar_findings = findings.get(pillar, [])
        if detail is None:
            # This pillar's asset_details weren't persisted (older scan row,
            # pre-dating that column) — fall back to N/A fields rather than
            # omitting the pillar, so every report always lists all 5 pillars.
            detail = {}
        if engine_libraries is None and detail.get("libraries"):
            engine_libraries = detail.get("libraries")

        cert = detail.get("certificate") or {}
        dns = detail.get("dns") or {}
        recs = remediation_by_pillar.get(pillar, [])

        assets.append({
            "pillar": pillar,
            "host": _na(detail.get("host")),
            "port": _na(detail.get("port")),
            "classification": _na(detail.get("classification")),
            "tag": _na(detail.get("tag")),
            "qvs_score": risk_scores.get(pillar),
            "tls_version": _na(detail.get("tls_version")),
            "tls_protocol_id": _na(detail.get("tls_protocol_id")),
            "hash_algorithm": _na(detail.get("hash_algorithm")),
            "encryption_algorithm": _na(detail.get("encryption_algorithm")),
            "cipher_hash_algorithm": _na(detail.get("cipher_hash_algorithm")),
            "authentication_algorithm": _na(detail.get("authentication_algorithm")),
            "key_exchange_algorithm": _na(detail.get("key_exchange_algorithm")),
            "key_exchange_group": _na(detail.get("key_exchange_group")),
            "key_length_bits": _na(detail.get("key_length_bits")),
            "signature_algorithm_oid": _na(detail.get("signature_algorithm_oid")),
            "signature_algorithm_name": _na(detail.get("signature_algorithm_name")),
            "certificate": {
                "serial_number": _na(cert.get("serial_number")),
                "issuer": _na(cert.get("issuer")),
                "subject": _na(cert.get("subject")),
                "not_before": _na(cert.get("not_before")),
                "not_after": _na(cert.get("not_after")),
                "san_dns": _na(cert.get("san_dns")),
                "san_ip": _na(cert.get("san_ip")),
            },
            "dns": {
                "ipv4": _na(dns.get("ipv4")),
                "ipv6": _na(dns.get("ipv6")),
            },
            "findings_count": len(pillar_findings),
            "findings": pillar_findings,
            "recommendations": [
                {"title": r["title"], "summary": r["summary"], "priority": (
                    "critical" if detail.get("classification", "").startswith("QUANTUM-VULNERABLE (CRITICAL")
                    else "high" if "QUANTUM-VULNERABLE" in (detail.get("classification") or "")
                    else "medium" if "HYBRID" in (detail.get("classification") or "")
                    else "info"
                )}
                for r in recs
            ] if recs else [],
        })

    return {
        "scan_id": scan.scan_id,
        "timestamp": scan.timestamp.isoformat() if scan.timestamp else None,
        "generated_at": datetime.utcnow().isoformat(),
        "web_url": scan.web_url,
        "vpn_url": scan.vpn_url,
        "api_url": scan.api_url,
        "overall_qvs": overall_qvs,
        "overall_tag": overall_tag,
        "risk_scores": risk_scores,
        "assets": assets,
        "cbom_summary": {
            "component_count": len(cbom.get("components", [])),
            "spec_version": cbom.get("specVersion"),
            "serial_number": cbom.get("serialNumber"),
        },
        # The actual OpenSSL/cryptography/dnspython versions this scan's TLS
        # probes ran with — read from whichever pillar captured them (they're
        # process-wide, so any successfully-probed pillar's value applies to
        # the whole scan). None if no pillar ever completed a probe.
        "scan_engine_libraries": engine_libraries or {
            "python_ssl_module": NA, "openssl": NA, "cryptography": NA, "dnspython": NA,
        },
    }


# ── Format renderers — all consume the exact same canonical dict above ──────

def to_json_bytes(report: dict) -> bytes:
    return json.dumps(report, indent=2, default=str).encode("utf-8")


def to_csv_bytes(report: dict) -> bytes:
    """One row per scanned asset (pillar). Every column here has a matching
    field in the PDF/XML/JSON output — same names, same values."""
    fieldnames = [
        "scan_id", "pillar", "host", "port", "tag", "classification", "qvs_score",
        "tls_version", "tls_protocol_id", "hash_algorithm", "encryption_algorithm",
        "cipher_hash_algorithm", "authentication_algorithm", "key_exchange_algorithm",
        "key_exchange_group", "key_length_bits", "signature_algorithm_oid",
        "signature_algorithm_name", "cert_serial_number", "cert_issuer", "cert_subject",
        "cert_not_before", "cert_not_after", "cert_san_dns", "cert_san_ip",
        "dns_ipv4", "dns_ipv6", "findings_count", "top_recommendation",
    ]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for a in report["assets"]:
        cert = a["certificate"]
        dns = a["dns"]
        top_rec = a["recommendations"][0]["summary"] if a["recommendations"] else NA
        writer.writerow({
            "scan_id": report["scan_id"], "pillar": a["pillar"], "host": a["host"],
            "port": a["port"], "tag": a["tag"], "classification": a["classification"],
            "qvs_score": a["qvs_score"] if a["qvs_score"] is not None else NA,
            "tls_version": a["tls_version"], "tls_protocol_id": a["tls_protocol_id"],
            "hash_algorithm": a["hash_algorithm"], "encryption_algorithm": a["encryption_algorithm"],
            "cipher_hash_algorithm": a["cipher_hash_algorithm"],
            "authentication_algorithm": a["authentication_algorithm"],
            "key_exchange_algorithm": a["key_exchange_algorithm"],
            "key_exchange_group": a["key_exchange_group"], "key_length_bits": a["key_length_bits"],
            "signature_algorithm_oid": a["signature_algorithm_oid"],
            "signature_algorithm_name": a["signature_algorithm_name"],
            "cert_serial_number": cert["serial_number"], "cert_issuer": cert["issuer"],
            "cert_subject": cert["subject"], "cert_not_before": cert["not_before"],
            "cert_not_after": cert["not_after"],
            "cert_san_dns": ";".join(cert["san_dns"]) if isinstance(cert["san_dns"], list) else cert["san_dns"],
            "cert_san_ip": ";".join(cert["san_ip"]) if isinstance(cert["san_ip"], list) else cert["san_ip"],
            "dns_ipv4": ";".join(dns["ipv4"]) if isinstance(dns["ipv4"], list) else dns["ipv4"],
            "dns_ipv6": ";".join(dns["ipv6"]) if isinstance(dns["ipv6"], list) else dns["ipv6"],
            "findings_count": a["findings_count"], "top_recommendation": top_rec,
        })
    # Library-versions footer row block — same values the JSON/XML/PDF report.
    buf.write("\n")
    buf.write("scan_engine_library,version\n")
    for k, v in report["scan_engine_libraries"].items():
        buf.write(f"{k},{v}\n")
    return buf.getvalue().encode("utf-8")


def _xml_text(parent, tag, value):
    el = ET.SubElement(parent, tag)
    if isinstance(value, list):
        el.text = ";".join(str(v) for v in value) if value else NA
    else:
        el.text = str(value) if value is not None else NA
    return el


def to_xml_bytes(report: dict) -> bytes:
    root = ET.Element("QubitGuardReport", {"scanId": str(report["scan_id"])})
    meta = ET.SubElement(root, "Meta")
    _xml_text(meta, "Timestamp", report["timestamp"])
    _xml_text(meta, "GeneratedAt", report["generated_at"])
    _xml_text(meta, "WebUrl", report["web_url"])
    _xml_text(meta, "VpnUrl", report["vpn_url"])
    _xml_text(meta, "ApiUrl", report["api_url"])
    _xml_text(meta, "OverallQvs", report["overall_qvs"])
    _xml_text(meta, "OverallTag", report["overall_tag"])

    libs = ET.SubElement(root, "ScanEngineLibraries")
    for k, v in report["scan_engine_libraries"].items():
        _xml_text(libs, k, v)

    assets_el = ET.SubElement(root, "Assets")
    for a in report["assets"]:
        asset_el = ET.SubElement(assets_el, "Asset", {"pillar": a["pillar"]})
        for field in ["host", "port", "tag", "classification", "qvs_score", "tls_version",
                      "tls_protocol_id", "hash_algorithm", "encryption_algorithm",
                      "cipher_hash_algorithm", "authentication_algorithm",
                      "key_exchange_algorithm", "key_exchange_group", "key_length_bits",
                      "signature_algorithm_oid", "signature_algorithm_name", "findings_count"]:
            _xml_text(asset_el, field, a[field])
        cert_el = ET.SubElement(asset_el, "Certificate")
        for k, v in a["certificate"].items():
            _xml_text(cert_el, k, v)
        dns_el = ET.SubElement(asset_el, "Dns")
        for k, v in a["dns"].items():
            _xml_text(dns_el, k, v)
        recs_el = ET.SubElement(asset_el, "Recommendations")
        for r in a["recommendations"]:
            rec_el = ET.SubElement(recs_el, "Recommendation", {"priority": r["priority"]})
            _xml_text(rec_el, "Title", r["title"])
            _xml_text(rec_el, "Summary", r["summary"])

    buf = io.BytesIO()
    ET.ElementTree(root).write(buf, encoding="utf-8", xml_declaration=True)
    return buf.getvalue()


def _pdf_text(report: dict) -> str:
    """Render the canonical report as the section-per-line text format the
    existing reportlab canvas renderer (mail_service._build_pdf_binary)
    already knows how to lay out — reused as-is rather than duplicating a
    second PDF drawing engine."""
    lines = [
        "QUBIT-GUARD CANONICAL SCAN REPORT",
        f"Scan ID: {report['scan_id']}",
        f"Scan Timestamp: {report['timestamp']}",
        f"Report Generated: {report['generated_at']}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "OVERALL SUMMARY:",
        f"├─ Web Target: {report['web_url'] or NA}",
        f"├─ VPN Target: {report['vpn_url'] or NA}",
        f"├─ API Target: {report['api_url'] or NA}",
        f"├─ Overall QVS: {report['overall_qvs'] if report['overall_qvs'] is not None else NA}",
        f"└─ Overall Tag: {report['overall_tag']}",
        "",
        "SCAN ENGINE LIBRARIES (actually used for this scan):",
    ]
    for k, v in report["scan_engine_libraries"].items():
        lines.append(f"├─ {k}: {v}")
    lines.append("")

    for a in report["assets"]:
        lines.append(f"PILLAR: {a['pillar'].upper()} — {a['host']}")
        lines.append("────────────────────────────────────────")
        lines.append(f"Tag: {a['tag']} | Classification: {a['classification']} | QVS: {a['qvs_score'] if a['qvs_score'] is not None else NA}")
        lines.append(f"TLS Version: {a['tls_version']} (Protocol ID {a['tls_protocol_id']})")
        lines.append(f"Hash Algorithm: {a['hash_algorithm']}")
        lines.append(f"Encryption Algorithm: {a['encryption_algorithm']} | Cipher Hash: {a['cipher_hash_algorithm']}")
        lines.append(f"Authentication Algorithm: {a['authentication_algorithm']}")
        lines.append(f"Key Exchange: {a['key_exchange_algorithm']} (group: {a['key_exchange_group']}, {a['key_length_bits']} bits)")
        lines.append(f"Signature Algorithm: {a['signature_algorithm_name']} (OID {a['signature_algorithm_oid']})")
        cert = a["certificate"]
        lines.append(f"Certificate Serial: {cert['serial_number']} | Issuer: {cert['issuer']}")
        lines.append(f"Certificate Valid: {cert['not_before']} to {cert['not_after']}")
        lines.append(f"SAN DNS: {cert['san_dns']} | SAN IP: {cert['san_ip']}")
        dns = a["dns"]
        lines.append(f"DNS IPv4: {dns['ipv4']} | DNS IPv6: {dns['ipv6']}")
        lines.append(f"Findings: {a['findings_count']}")
        if a["recommendations"]:
            lines.append("Recommendations:")
            for r in a["recommendations"]:
                lines.append(f"  [{r['priority'].upper()}] {r['title']}: {r['summary']}")
        else:
            lines.append("Recommendations: none generated for this pillar")
        lines.append("")

    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    lines.append("Qubit-Guard — Post-Quantum Cryptography Assessment")
    return "\n".join(lines)


def to_pdf_bytes(report: dict, bank_name: str = "Organization") -> bytes:
    from services.mail_service import _build_pdf_binary
    return _build_pdf_binary(_pdf_text(report), bank_name)


EXPORTERS = {
    "json": (to_json_bytes, "application/json"),
    "csv": (to_csv_bytes, "text/csv"),
    "xml": (to_xml_bytes, "application/xml"),
}

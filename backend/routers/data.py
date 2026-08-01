"""
Data router — dashboard, inventory, cbom queries from SQLite.
"""

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from db import get_db, with_retry
from models import DashboardSummary, InventoryStat, PostureStat, CbomVulnerabilitySummary, CbomItem, ScanResult
from services.cbom_generator import generate_cyclonedx
from services.mail_service import send_scan_report, send_scan_report_async, generate_professional_pdf, _extract_bank_name
from services.audit_service import log_audit_event
from pydantic import BaseModel

class EmailRequest(BaseModel):
    email: str
    reportType: str
    formats: list[str] = []

class InventoryItemRequest(BaseModel):
    component: str
    version: str = ""
    algorithm: str = ""
    category: str = ""
    quantum_safe: bool = False
    risk: str = "High"
    purl: str = ""

router = APIRouter()


def _provenance(db: Session, *models) -> dict:
    """Build the dataProvenance block for a response by counting real rows
    across whichever provenance-tracked tables that endpoint actually reads.
    'seedRows' is rows with source == 'seed' (shipped demo data); 'scanRows'
    is everything else (scan-derived or manually entered — i.e. not fabricated
    demo data). isDemoData is True the instant any seed row is in the mix."""
    seed_rows = 0
    total_rows = 0
    for model in models:
        seed_rows += db.query(model).filter(model.source == "seed").count()
        total_rows += db.query(model).count()
    scan_rows = total_rows - seed_rows
    return {
        "isDemoData": seed_rows > 0,
        "seedRows": seed_rows,
        "scanRows": scan_rows,
    }


def _cyber_rating(overall) -> dict:
    """Build the Cyber Rating card. A null QVS means no pillar was assessed —
    it must not be graded as a tier, since that would read as a real result."""
    if overall is None:
        return {"value": "Not Assessed", "label": "Cyber Rating",
                "subtext": "No pillar could be probed"}
    tier = "Tier 1" if overall < 20 else "Tier 2" if overall < 50 else "Tier 4"
    return {"value": tier, "label": "Cyber Rating", "subtext": f"QVS: {overall}"}


@router.get("/dashboard")
def get_dashboard(request: Request, db: Session = Depends(get_db)):
    import json
    scan_id = request.headers.get("X-Scan-Id")
    
    if scan_id:
        scan = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).first()
        if scan:
            risk_scores = json.loads(scan.risk_scores_json or '{}')
            cbom = json.loads(scan.cbom_json or '{}')
            findings = json.loads(scan.findings_json or '{}')
            # Derive dashboard stats directly from structural scan results (no fakes)
            comp_count = len(cbom.get("components", []))
            
            # Count the severities from actual real findings (which were populated organically)
            # Find the total vulnerabilities across all scanners
            all_findings = []
            for pillar_findings in findings.values():
                all_findings.extend(pillar_findings)
                
            critical_count = sum(1 for f in all_findings if f.get("severity") == "critical")
            high_count = sum(1 for f in all_findings if f.get("severity") == "high")
            medium_count = sum(1 for f in all_findings if f.get("severity") == "medium")
            low_count = sum(1 for f in all_findings if f.get("severity") == "info" or f.get("severity") == "low")
            
            summary = {
                "assetsDiscovery": {"value": str(comp_count), "label": "Assets Discovered", "subtext": f"Target: {scan.web_url}"},
                "cyberRating": _cyber_rating(risk_scores.get("overall")),
                "sslCerts": {"value": str(len(findings.get("web", []))), "label": "SSL Certs Engine", "subtext": "Web Target Findings"},
                "cbomVulnerabilities": {"value": str(critical_count + high_count), "label": "Severe Vulnerabilities", "subtext": "Critical and High"},
            }
            
            inventory = {
                "ssl": len(findings.get("web", [])),
                "software": comp_count,
                "iot": len(findings.get("firmware", [])), # Mapping IoT/hardware to firmware findings
                "logins": len(findings.get("api", [])),   # Mapping logins to API findings
            }
            
            def _pct_or_none(qvs):
                # qvs is None when that pillar wasn't assessed (unreachable target,
                # no JWT supplied, etc.) — a documented, expected outcome, not an
                # edge case. `risk_scores.get(key, 100)` used to crash here: the
                # key is always present (just set to None), so the default never
                # applied and `100 - None` raised a TypeError, 500-ing the whole
                # dashboard for any scan with an unassessed pillar.
                return max(0, 100 - qvs) if qvs is not None else None

            posture = {
                "mlKemAdoption": _pct_or_none(risk_scores.get("web")),
                "mlDsaTransition": _pct_or_none(risk_scores.get("api")),
                "legacyRemoval": _pct_or_none(risk_scores.get("overall")),
            }
            
            cbom_summary = {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
            }
            
            return {
                "success": True,
                "data": {
                    "summary": summary,
                    "inventory": inventory,
                    "posture": posture,
                    "cbomSummary": cbom_summary,
                },
                # Everything above came from the live ScanResult JSON, not the
                # seeded demo tables — never demo data.
                "dataProvenance": {"isDemoData": False, "seedRows": 0, "scanRows": comp_count},
            }

    # --- DYNAMIC DASHBOARD (No active scan) ---
    # We calculate real counts from our persistence layer
    cbom_count = db.query(CbomItem).count()
    vuln_count = db.query(CbomItem).filter(CbomItem.quantum_safe == False).count()
    
    # Base summary with real counts
    rows = db.query(DashboardSummary).all()
    summary = {}
    for r in rows:
        val = r.value
        if r.key == "assetsDiscovery":
            val = f"{cbom_count:,}"
        elif r.key == "cbomVulnerabilities":
            val = f"{vuln_count:,}"
        summary[r.key] = {"value": val, "label": r.label, "subtext": r.subtext}

    # Inventory distribution
    ssl_cnt = db.query(CbomItem).filter(CbomItem.category == "TLS").count()
    soft_cnt = db.query(CbomItem).filter(CbomItem.category == "Software").count()
    api_cnt = db.query(CbomItem).filter(CbomItem.category == "API").count()
    vpn_cnt = db.query(CbomItem).filter(CbomItem.category == "VPN").count()
    iot_cnt = db.query(CbomItem).filter(CbomItem.category == "IoT").count()
    
    inventory = {
        "ssl": ssl_cnt,
        "software": soft_cnt,
        "iot": iot_cnt,
        "logins": api_cnt
    }

    posture_rows = db.query(PostureStat).all()
    posture = {r.metric: r.value for r in posture_rows}

    # CBOM Vulnerability Breakdown
    cbom_summary = {
        "critical": db.query(CbomItem).filter(CbomItem.risk == "Critical").count(),
        "high": db.query(CbomItem).filter(CbomItem.risk == "High").count(),
        "medium": db.query(CbomItem).filter(CbomItem.risk == "Medium").count(),
        "low": db.query(CbomItem).filter(CbomItem.risk == "Safe").count(),
    }

    return {
        "success": True,
        "data": {
            "summary": summary,
            "inventory": inventory,
            "posture": posture,
            "cbomSummary": cbom_summary,
        },
        "dataProvenance": _provenance(db, DashboardSummary, CbomItem, PostureStat),
    }


@router.get("/inventory")
def get_inventory(request: Request, db: Session = Depends(get_db)):
    import json
    scan_id = request.headers.get("X-Scan-Id")
    if scan_id:
        scan = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).first()
        if scan:
            cbom = json.loads(scan.cbom_json or '{}')
            data = [
                {
                    "component": c["name"],
                    "version": c.get("version", ""),
                    "algorithm": c.get("crypto", "Unknown"),
                    "quantumSafe": c.get("quantumSafe", False),
                    "risk": "Critical" if not c.get("quantumSafe") else "Safe",
                    "category": c.get("type", "TLS"),
                    "purl": f"pkg:triad/{c['name']}@{c.get('version', '0.0.0')}",
                    "details": c.get("details", {}),
                    "server_banner": c.get("details", {}).get("server_banner", "Unknown"),
                    "security_audit": c.get("details", {}).get("security_audit", {}),
                    "source": "scan",
                }
                for c in cbom.get("components", [])
            ]
            return {
                "success": True,
                "data": data,
                "dataProvenance": {"isDemoData": False, "seedRows": 0, "scanRows": len(data)},
            }

    items = db.query(CbomItem).all()
    data = [
        {
            "component": i.component,
            "version": i.version,
            "algorithm": i.algorithm,
            "quantumSafe": i.quantum_safe,
            "risk": i.risk,
            "category": i.category,
            "purl": i.purl,
            "server_banner": getattr(i, 'server_banner', 'N/A'),
            "security_audit": getattr(i, 'security_audit', {}),
            "source": i.source,
        }
        for i in items
    ]
    return {
        "success": True,
        "data": data,
        "dataProvenance": _provenance(db, CbomItem),
    }


@router.delete("/inventory/{purl:path}")
def delete_asset(purl: str, db: Session = Depends(get_db)):
    from urllib.parse import unquote

    # The frontend may send the purl percent-encoded (slashes/@ survive transit)
    # or raw. Try the raw value first, then fall back to the decoded form so
    # either works.
    item = db.query(CbomItem).filter(CbomItem.purl == purl).first()
    decoded_purl = purl
    if item is None:
        decoded_purl = unquote(purl)
        if decoded_purl != purl:
            item = db.query(CbomItem).filter(CbomItem.purl == decoded_purl).first()

    if item:
        deleted_purl = item.purl
        db.delete(item)
        with_retry(lambda: db.commit())
        log_audit_event({"action": "INVENTORY_DELETE", "purl": deleted_purl})
        return {"success": True, "message": f"Asset {deleted_purl} removed successfully."}

    return JSONResponse(
        status_code=404,
        content={"success": False, "message": f"Asset not found: {decoded_purl}"},
    )


@router.get("/cbom")
def get_cbom(request: Request, db: Session = Depends(get_db)):
    import json
    scan_id = request.headers.get("X-Scan-Id")
    if scan_id:
        scan = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).first()
        if scan:
            cbom = json.loads(scan.cbom_json or '{}')
            cbom_items = [
                {
                    "component": c["name"],
                    "version": c.get("version", ""),
                    "algorithm": c.get("crypto", "Unknown"),
                    "quantumSafe": c.get("quantumSafe", False),
                    "risk": "Critical" if not c.get("quantumSafe") else "Safe",
                    "category": c.get("type", "TLS"),
                    "purl": f"pkg:triad/{c['name']}@{c.get('version', '0.0.0')}",
                    "source": "scan",
                }
                for c in cbom.get("components", [])
            ]
            return {
                "success": True,
                "data": {"cbomItems": cbom_items},
                "dataProvenance": {"isDemoData": False, "seedRows": 0, "scanRows": len(cbom_items)},
            }

    items = db.query(CbomItem).all()
    cbom_items = [
        {
            "component": i.component,
            "version": i.version,
            "algorithm": i.algorithm,
            "quantumSafe": i.quantum_safe,
            "risk": i.risk,
            "category": i.category,
            "purl": i.purl,
            "source": i.source,
        }
        for i in items
    ]
    return {
        "success": True,
        "data": {"cbomItems": cbom_items},
        "dataProvenance": _provenance(db, CbomItem),
    }


@router.get("/cbom/export/{fmt}")
def export_cbom(fmt: str, db: Session = Depends(get_db)):
    items = db.query(CbomItem).all()
    item_dicts = [
        {
            "component": i.component,
            "version": i.version,
            "algorithm": i.algorithm,
            "key_size": i.key_size,
            "mode": i.mode,
            "quantum_safe": i.quantum_safe,
            "risk": i.risk,
            "category": i.category,
            "purl": i.purl,
        }
        for i in items
    ]

    if fmt == "csv":
        import io, csv
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=item_dicts[0].keys() if item_dicts else [])
        writer.writeheader()
        writer.writerows(item_dicts)
        return JSONResponse(
            content=output.getvalue(),
            headers={"Content-Disposition": "attachment; filename=cbom.csv", "Content-Type": "text/csv"},
        )
    elif fmt == "xml":
        import xml.etree.ElementTree as ET
        root = ET.Element("bom", {"xmlns": "http://cyclonedx.org/schema/bom/1.5"})
        components = ET.SubElement(root, "components")
        for item in item_dicts:
            c = ET.SubElement(components, "component", {"type": "library"})
            ET.SubElement(c, "name").text = item["component"]
            ET.SubElement(c, "version").text = item["version"]
            # Add crypto properties as per CycloneDX
            props = ET.SubElement(c, "properties")
            ET.SubElement(props, "property", {"name": "crypto:algorithm"}).text = item["algorithm"]
            ET.SubElement(props, "property", {"name": "crypto:quantum-safe"}).text = str(item["quantum_safe"])
        
        import io
        output = io.BytesIO()
        tree = ET.ElementTree(root)
        tree.write(output, encoding='utf-8', xml_declaration=True)
        return JSONResponse(
            content=output.getvalue().decode('utf-8'),
            headers={"Content-Disposition": "attachment; filename=cbom.xml", "Content-Type": "application/xml"},
        )
    
    # Default JSON
    cbom = generate_cyclonedx(item_dicts)
    return JSONResponse(
        content=cbom,
        headers={"Content-Disposition": f"attachment; filename=cbom.{fmt}"},
    )
@router.get("/remediation")
def get_remediation(request: Request, db: Session = Depends(get_db)):
    import json
    from services.remediation_service import generate_triad_remediation
    scan_id = request.headers.get("X-Scan-Id")
    if scan_id:
        scan = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).first()
        if scan:
            findings = json.loads(scan.findings_json or '{}')
            return {"success": True, "data": generate_triad_remediation(findings, scan.web_url, scan.vpn_url, scan.api_url)}
    
    return {"success": True, "data": []}


@router.post("/report/send")
async def send_report(req: EmailRequest, db: Session = Depends(get_db)):
    import asyncio
    
    # Fetch latest scan result for URLs and detailed findings
    latest_scan = db.query(ScanResult).order_by(ScanResult.timestamp.desc()).first()
    
    web_url = latest_scan.web_url if latest_scan else ""
    vpn_url = latest_scan.vpn_url if latest_scan else ""
    api_url = latest_scan.api_url if latest_scan else ""
    
    # Fetch CBOM data for this report
    cbom_rows = db.query(CbomItem).all()
    cbom_data = {
        "components": [
            {
                "component": row.component,
                "version": row.version,
                "algorithm": row.algorithm,
                "quantumSafe": row.quantum_safe,
                "risk": row.risk,
                "category": row.category,
                "purl": row.purl,
            } for row in cbom_rows
        ]
    }
    
    # Fetch risk scores from posture stats
    posture_rows = db.query(PostureStat).all()
    risk_scores = {
        row.metric: row.value for row in posture_rows
    }
    
    # A missing score stays missing — never fabricate a QVS. Downstream,
    # _cyber_rating() (this file) and services/mail_service.py's report
    # generators both treat a missing/None "overall" as "Not Assessed"
    # rather than substituting a default number.

    # Fetch findings
    cbom_vuln_rows = db.query(CbomVulnerabilitySummary).all()
    findings = {
        row.severity: row.count for row in cbom_vuln_rows
    }
    
    # Parse scan findings and scores by category
    scan_findings = {}
    scan_data_from_json = {}
    if latest_scan:
        try:
            import json
            scan_findings = json.loads(latest_scan.findings_json or '{}')
            risk_scores = json.loads(latest_scan.risk_scores_json or '{}')
            cbom_data = json.loads(latest_scan.cbom_json or '{}')
            
            # Map simplified findings for the summary counts
            # findings is used for the summary table counts in some reports
            all_findings = []
            for pillar in scan_findings.values():
                all_findings.extend(pillar)
            
            summary_findings = {
                "critical": sum(1 for f in all_findings if f.get("severity") == "critical" or f.get("risk") == "Critical"),
                "high": sum(1 for f in all_findings if f.get("severity") == "high" or f.get("risk") == "High"),
                "medium": sum(1 for f in all_findings if f.get("severity") == "medium" or f.get("risk") == "Medium"),
                "low": sum(1 for f in all_findings if f.get("severity") == "info" or f.get("severity") == "low" or f.get("risk") == "Low"),
            }
            findings = summary_findings
            
        except Exception as e:
            print(f"[REPORTS] Error parsing scan JSON: {e}")
    
    # Categorize findings for the detailed section
    web_findings = scan_findings.get("web", [])
    api_findings = scan_findings.get("api", [])
    vpn_findings = scan_findings.get("vpn", [])
    mobile_findings = scan_findings.get("mobile", [])
    iot_findings = scan_findings.get("iot", [])
    
    # Build complete scan data payload
    scan_data = {
        "reportType": req.reportType,
        "formats": req.formats,
        "riskScores": risk_scores,
        "cbom": cbom_data,
        "findings": findings,
        "url": web_url,
        "web_url": web_url,
        "vpn_url": vpn_url,
        "api_url": api_url,
        "web_findings": web_findings,
        "api_findings": api_findings,
        "vpn_findings": vpn_findings,
        "mobile_findings": mobile_findings,
        "iot_findings": iot_findings,
    }
    
    try:
        # 10-second hard timeout so the button never hangs forever
        success, detail = await asyncio.wait_for(
            send_scan_report_async(req.email, scan_data),
            timeout=10.0
        )
    except asyncio.TimeoutError:
        print(f"[MAIL] Timed out after 10s. NO EMAIL SENT.")
        success, detail = False, "SMTP_TIMEOUT"

    if success:
        log_audit_event({"action": "REPORT_SEND", "email": req.email, "report_type": req.reportType, "delivered": True})
        return {
            "success": True,
            "delivered": True,
            "message": f"PQC audit report generated and sent to {req.email}",
            "reportType": req.reportType,
        }

    # The report was generated; delivery did not happen. Say so plainly — never
    # report a send that did not occur.
    reasons = {
        "NOT_CONFIGURED": "SMTP credentials are not configured on the server (SMTP_USER / SMTP_PASS).",
        "SMTP_BLOCKED":   "the SMTP ports (587/465) are blocked on this network.",
        "SMTP_TIMEOUT":   "the SMTP server did not respond within 10 seconds.",
    }
    reason = reasons.get(str(detail), f"SMTP error: {detail}")
    log_audit_event({"action": "REPORT_SEND", "email": req.email, "report_type": req.reportType, "delivered": False, "reason_code": str(detail)})
    return {
        "success": False,
        "delivered": False,
        "message": f"Report generated but NOT sent to {req.email} — {reason} Use Download PDF to retrieve it.",
        "reason_code": str(detail),
        "reportType": req.reportType,
    }


@router.post("/inventory/add")
def add_inventory_item(body: InventoryItemRequest, db: Session = Depends(get_db)):
    from models import CbomItem
    new_item = CbomItem(
        component=body.component,
        version=body.version,
        algorithm=body.algorithm,
        category=body.category,
        quantum_safe=body.quantum_safe,
        risk=body.risk,
        purl=body.purl or f"pkg:triad/{body.component}@{body.version or '0.0.0'}",
        source="manual"
    )
    db.add(new_item)
    with_retry(lambda: db.commit())
    db.refresh(new_item)
    log_audit_event({"action": "INVENTORY_ADD", "purl": new_item.purl, "component": new_item.component})
    return {"success": True, "message": "Asset added successfully."}


@router.get("/report/download-pdf")
def download_pdf_report(type: str = "executive", db: Session = Depends(get_db)):
    import json
    
    # Fetch latest scan result for data
    latest_scan = db.query(ScanResult).order_by(ScanResult.timestamp.desc()).first()
    
    # Prepare scan_data payload for generator
    scan_data = {
        "reportType": type.upper(),
        "url": latest_scan.web_url if latest_scan else "Internal Infrastructure",
        "web_url": latest_scan.web_url if latest_scan else "",
        "vpn_url": latest_scan.vpn_url if latest_scan else "",
        "api_url": latest_scan.api_url if latest_scan else "",
    }
    
    if latest_scan:
        try:
            scan_data["findings"] = json.loads(latest_scan.findings_json or '{}')
            scan_data["riskScores"] = json.loads(latest_scan.risk_scores_json or '{}')
            scan_data["cbom"] = json.loads(latest_scan.cbom_json or '{}')
            
            # Map simplified findings for the PDF generator internal logic
            scan_data["web_findings"] = scan_data["findings"].get("web", [])
            scan_data["api_findings"] = scan_data["findings"].get("api", [])
            scan_data["vpn_findings"] = scan_data["findings"].get("vpn", [])
            scan_data["mobile_findings"] = scan_data["findings"].get("mobile", [])
        except Exception as e:
            print(f"[REPORTS] Error parsing scan JSON for download: {e}")

    # Generate PDF binary
    pdf_bytes = generate_professional_pdf(type, scan_data, db)
    
    # Prepare dynamic filename
    bank_name = _extract_bank_name(latest_scan.web_url if latest_scan else "")
    bank_id = bank_name.replace(" ", "_").replace("Bank", "").strip("_") if bank_name else "QVS"
    if not bank_id: bank_id = "QVS"
    filename = f"{bank_id}_QVS_Audit_{type.title()}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )


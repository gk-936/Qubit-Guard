"""
SMTP email report service — Gmail.
Uses asyncio executor to prevent blocking the FastAPI event loop.
Professional PDF Report Generation with Database Integration.
"""

import os
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
import json
import asyncio
from concurrent.futures import ThreadPoolExecutor
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

log = logging.getLogger(__name__)


def _qvs_text(score, suffix: str = "/100") -> str:
    """Render a QVS for the report. A missing score means the pillar was never
    assessed — it must not be substituted with an invented number."""
    return "Not Assessed" if score is None else f"{score}{suffix}"


def _inverse_pct_text(score) -> str:
    """Render `100 - QVS` (the 'readiness'/'compliant' side) safely."""
    return "Not Assessed" if score is None else f"{100 - score}%"


def _risk_level(score) -> str:
    """Classify overall risk from a QVS.

    QVS is a severity scale: 100 = fully quantum-vulnerable (RSA), 0 = fully PQC.
    Higher therefore means worse. Thresholds match the dashboard so the emailed
    report and the UI cannot disagree.
    """
    if score is None:
        return "NOT ASSESSED"
    if score >= 80:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"

_smtp_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="smtp")


def generate_professional_pdf(report_type: str, scan_data: dict, db: Session = None) -> bytes:
    """
    Generate professional PDF reports based on report type with real database data.
    
    Report Types:
    - EXECUTIVE: High-level risk posture, KPIs, recommendations
    - TECHNICAL: Detailed CBOM, cryptographic inventory, OID analysis  
    - COMPLIANCE: Gap analysis, standards mapping (NIST SP 800-215, FIPS 203/204)
    """
    
    report_type = (report_type or "EXECUTIVE").upper()
    timestamp = datetime.utcnow()
    
    # Extract bank name from URL
    bank_name = _extract_bank_name(scan_data.get("url", ""))
    
    # Fetch real data from database if available
    cbom_items = []
    # An empty dict, not a fabricated one: risk_scores.get("overall") must return
    # None (not a plausible-looking fake 75) when riskScores is genuinely absent,
    # so the "Not Assessed" rendering below (_qvs_text) actually applies. This
    # exact fallback used to inject {"overall": 75, "web": 80, "api": 70, "iot": 85}
    # — real numbers, not None — which silently bypassed that honesty check.
    risk_scores = scan_data.get("riskScores") or {}
    findings = scan_data.get("findings", {})
    
    if db:
        try:
            from models import CbomItem
            cbom_items = db.query(CbomItem).all()
        except (ImportError, SQLAlchemyError) as e:
            log.warning("Failed to load CBOM items from database: %s", e, exc_info=True)
            cbom_items = []
    
    # Extract CBOM from scan_data if available
    if "cbom" in scan_data:
        cbom_items = scan_data["cbom"].get("components", [])
    
    # Normalize items (handle both DB objects and JSON dicts)
    normalized_items = []
    for c in cbom_items:
        item_dict = {}
        if not isinstance(c, dict):
            # ORM object conversion
            item_dict = {
                "component": getattr(c, "component", getattr(c, "name", "Unknown")),
                "version": getattr(c, "version", "N/A"),
                "algorithm": getattr(c, "algorithm", getattr(c, "crypto", "Unknown")),
                "quantumSafe": getattr(c, "quantum_safe", getattr(c, "quantumSafe", False)),
                "risk": getattr(c, "risk", "Medium"),
                "purl": getattr(c, "purl", "N/A"),
            }
        else:
            # Handle dictionary sourcing
            item_dict = {
                "component": c.get("component", c.get("name", "Unknown")),
                "version": c.get("version", "N/A"),
                "algorithm": c.get("algorithm", c.get("crypto", "Unknown")),
                "quantumSafe": c.get("quantumSafe", c.get("quantum_safe", False)),
                "risk": c.get("risk", "Medium"),
                "purl": c.get("purl", "N/A"),
            }
        
        normalized_items.append(item_dict)
    
    cbom_items = normalized_items

    # Separate quantum-safe and vulnerable components
    vulnerable_components = [c for c in cbom_items if not c.get("quantumSafe", False)]
    safe_components = [c for c in cbom_items if c.get("quantumSafe", True)]
    
    # Filter scan_data for unpacking to avoid argument conflicts
    # 'findings' is the primary conflict, but we filter others to be safe.
    # risk_scores, findings, vulnerable_components, etc. are passed positionally.
    report_kwargs = {k: v for k, v in scan_data.items() if k not in ["findings", "riskScores", "cbom"]}
    
    if report_type == "EXECUTIVE":
        content = _generate_executive_report(risk_scores, findings, cbom_items, timestamp, bank_name, **report_kwargs)
    elif report_type == "TECHNICAL":
        content = _generate_technical_cbom_report(vulnerable_components, safe_components, risk_scores, timestamp, bank_name, **report_kwargs)
    elif report_type == "COMPLIANCE":
        content = _generate_compliance_audit_report(vulnerable_components, risk_scores, timestamp, bank_name, **report_kwargs)
    else:
        content = _generate_executive_report(risk_scores, findings, cbom_items, timestamp, bank_name, **report_kwargs)
    
    return _build_pdf_binary(content, bank_name)


def _extract_bank_name(url: str) -> str:
    """Extract bank name from URL, ignoring test/staging subdomains."""
    if not url:
        return "Organization"

    # Common bank domain patterns. Matched against the DOMAIN only (see below),
    # never the raw URL string — matching the full URL let query strings and
    # paths trigger false positives (e.g. "?ref=yesbank-promo" on an unrelated
    # site). "yes" was also narrowed to "yesbank": as a bare 3-letter pattern
    # it matched inside ordinary English substrings — confirmed false positives
    # on "eyestest.com" and "myeservices.co.in", both reported as "YES Bank".
    bank_patterns = {
        "pnb": "Punjab National Bank",
        "manipur": "Manipur Bank",
        "manipurbank": "Manipur Bank",
        "bankofindia": "Bank of India",
        "bankofbaroda": "Bank of Baroda",
        "sbi": "State Bank of India",
        "hdfc": "HDFC Bank",
        "icici": "ICICI Bank",
        "axis": "Axis Bank",
        "kotak": "Kotak Mahindra Bank",
        "yesbank": "YES Bank",
    }

    # Subdomains to skip (test, staging, dev, etc.)
    skip_subdomains = ["test", "staging", "dev", "demo", "sandbox", "qa", "uat"]

    # Extract the domain first — every match below is checked against this,
    # never the full URL (scheme/path/query), which is where the false
    # positives above came from.
    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc or url
        domain = domain.replace("www.", "")
        parts = domain.split(".")
    except (IndexError, AttributeError, ValueError) as e:
        log.warning("Failed to derive bank name from URL %r: %s", url, e, exc_info=True)
        return "Organization"

    domain_lower = domain.lower()
    # Longest pattern first so a more specific match always wins over a
    # shorter one that happens to be its prefix/substring.
    for pattern in sorted(bank_patterns, key=len, reverse=True):
        if pattern in domain_lower:
            return bank_patterns[pattern]

    # No known bank matched — fall back to the domain's own label, ignoring
    # test/staging prefix subdomains.
    for i, part in enumerate(parts[:-2]):  # Check all parts except TLD and main domain
        if part in skip_subdomains and i + 1 < len(parts):
            # Use the next part as the domain name
            return parts[i + 1].title() + " Bank"

    return parts[0].title() + " Bank" if parts and parts[0] else "Organization"


def _generate_executive_report(risk_scores: dict, findings: dict, components: list, timestamp: datetime, bank_name: str = "Organization", **kwargs) -> str:
    """Executive Summary: High-level risk posture and recommendations."""
    
    # The real pillars this app scans are web/vpn/api/firmware/archival — there is
    # no "iot" pillar anywhere in the scan engine, so risk_scores.get("iot") always
    # returned None and this section permanently showed "IoT/Embedded Systems QVS:
    # Not Assessed" on every single report, while the VPN pillar — a real,
    # genuinely-scanned pillar — was silently missing from this summary entirely.
    overall_qvs = risk_scores.get("overall")
    web_qvs = risk_scores.get("web")
    api_qvs = risk_scores.get("api")
    vpn_qvs = risk_scores.get("vpn")

    overall_txt = _qvs_text(overall_qvs)
    web_txt = _qvs_text(web_qvs)
    api_txt = _qvs_text(api_qvs)
    vpn_txt = _qvs_text(vpn_qvs)
    readiness_txt = _inverse_pct_text(overall_qvs)
    gap_txt = _qvs_text(overall_qvs, "%")

    # Extract URLs and findings
    web_url = kwargs.get("web_url", "")
    vpn_url = kwargs.get("vpn_url", "")
    api_url = kwargs.get("api_url", "")
    web_findings = kwargs.get("web_findings", [])
    api_findings = kwargs.get("api_findings", [])
    vpn_findings = kwargs.get("vpn_findings", [])
    mobile_findings = kwargs.get("mobile_findings", [])
    
    risk_level = _risk_level(overall_qvs)
    
    # CALCULATE INTEGRATED COUNTS (Findings + CBOM Risks)
    critical_count = 0
    high_count = 0
    medium_count = 0
    
    # 1. Count from findings (scanner results)
    all_findings_list = []
    if isinstance(findings, dict):
        for pillar_findings in findings.values():
            if isinstance(pillar_findings, list):
                all_findings_list.extend(pillar_findings)
    elif isinstance(findings, list):
        all_findings_list = findings

    for f in all_findings_list:
        sev = str(f.get("severity") or f.get("risk") or "").lower()
        if sev == "critical": critical_count += 1
        elif sev == "high": high_count += 1
        elif sev == "medium": medium_count += 1
    
    # 2. Count from components (CBOM inventory)
    for c in components:
        # If the component specifically lists a risk level, count it
        risk = str(c.get("risk") or "").lower()
        if risk == "critical": critical_count += 1
        elif risk == "high": high_count += 1
        elif risk == "medium": medium_count += 1
        # Fallback if risk key is missing but it's not quantum safe
        elif not c.get("quantumSafe", True) and not risk:
            # Default to High if it's vulnerable and no specific risk level set
            high_count += 1
            
    quantum_safe_count = len([c for c in components if c.get("quantumSafe")])
    
    content = f"""
OVERALL QUANTUM VULNERABILITY SCORE (QVS): {overall_txt}

EXECUTIVE SUMMARY: QUANTUM READINESS AUDIT
{bank_name} — Post-Quantum Cryptography Initiative
{timestamp.strftime('%B %d, %Y at %H:%M UTC')}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

OVERALL QUANTUM VULNERABILITY SCORE (QVS): {overall_txt}
RISK CLASSIFICATION: {risk_level}

KEY METRICS:
├─ Web/TLS Infrastructure QVS:    {web_txt}
├─ API Gateway Infrastructure QVS: {api_txt}
├─ VPN Gateway Infrastructure QVS: {vpn_txt}
└─ FIPS 203/204 Readiness:        {readiness_txt} TRANSITION REQUIRED

SCANNED ENDPOINTS:
├─ Web Portal: {web_url if web_url else 'N/A'}
├─ VPN Gateway: {vpn_url if vpn_url else 'N/A'}
├─ API Gateway: {api_url if api_url else 'N/A'}
└─ Mobile Apps: Included in scan

SCAN RESULTS SUMMARY:
├─ Web/TLS Vulnerabilities: {len(web_findings)} findings
├─ API Endpoint Issues: {len(api_findings)} findings
├─ VPN Security: {len(vpn_findings)} findings
└─ Mobile App Risks: {len(mobile_findings)} findings

VULNERABILITY SUMMARY:
├─ CRITICAL Issues:  {critical_count}
├─ HIGH Severity:    {high_count}
├─ MEDIUM Severity:  {medium_count}
└─ QUANTUM-SAFE Components: {quantum_safe_count} Active

COMPLIANCE STATUS:
├─ NIST SP 800-215:           {readiness_txt} Compliant (Gap: {gap_txt})
├─ FIPS 203 Migration:        Recommended
├─ FIPS 204 Migration:        Recommended
└─ CERT-In Guidelines:        {readiness_txt} Aligned

REMEDIATION TIMELINE:
├─ Phase 1 (0-30 days):  Audit and Inventory Complete
├─ Phase 2 (30-90 days): Hybrid Implementation
└─ Phase 3 (90-180 days): Full Post-Quantum Migration

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{bank_name} | Qubit-Guard v2.0 — Post-Quantum Cryptography Assessment
Classification: CONFIDENTIAL - RESTRICTED DISTRIBUTION
"""
    
    return content


def _generate_technical_cbom_report(vulnerable: list, safe: list, risk_scores: dict, timestamp: datetime, bank_name: str = "Organization", **kwargs) -> str:
    """Technical CBOM: Detailed cryptographic inventory and analysis with scan results."""
    
    web_url = kwargs.get("web_url", "")
    vpn_url = kwargs.get("vpn_url", "")
    api_url = kwargs.get("api_url", "")
    web_findings = kwargs.get("web_findings", [])
    api_findings = kwargs.get("api_findings", [])
    vpn_findings = kwargs.get("vpn_findings", [])
    mobile_findings = kwargs.get("mobile_findings", [])
    
    content = f"""
{bank_name} CBOM REPORT: CRYPTOGRAPHIC INVENTORY ANALYSIS
Post-Quantum Cryptography Initiative
{timestamp.strftime('%B %d, %Y at %H:%M UTC')}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WEB/TLS SCAN RESULTS
URL: {web_url if web_url else 'N/A'}
────────────────────────────────────────
Findings: {len(web_findings)} issues detected
"""
    
    if web_findings:
        for i, finding in enumerate(web_findings[:5], 1):
            if isinstance(finding, dict):
                issue = finding.get("issue", finding.get("name", str(finding)))
                risk = finding.get("risk", "Medium")
            else:
                issue = str(finding)
                risk = "Medium"
            content += f"\n{i}. {issue} [{risk}]"
    else:
        # An empty findings list is not the same as "confirmed secure" — it can
        # also mean the pillar was never reached or never assessed. Neutral
        # wording, not an affirmative clean bill of health that wasn't earned.
        content += "\n• No findings recorded for this pillar"

    content += f"""

API GATEWAY SCAN RESULTS
URL: {api_url if api_url else 'N/A'}
────────────────────────────────────────
Findings: {len(api_findings)} issues detected
"""
    
    if api_findings:
        for i, finding in enumerate(api_findings[:5], 1):
            if isinstance(finding, dict):
                endpoint = finding.get("endpoint", finding.get("path", str(finding)))
                issue = finding.get("issue", "Unknown")
            else:
                endpoint = str(finding)
                issue = "Requires review"
            content += f"\n{i}. {endpoint}: {issue}"
    else:
        # Confirmed reachable live: the API pillar produces zero findings when no
        # JWT token is supplied (it's optional) and mTLS isn't strictly enforced —
        # "not tested", not "tested and clean". This previously claimed the latter.
        content += "\n• No findings recorded — the API pillar may not have been assessed (e.g. no JWT token was supplied)"
    
    content += f"""

VPN GATEWAY SCAN RESULTS
URL: {vpn_url if vpn_url else 'N/A'}
────────────────────────────────────────
Findings: {len(vpn_findings)} issues detected
"""
    
    if vpn_findings:
        for i, finding in enumerate(vpn_findings[:5], 1):
            if isinstance(finding, dict):
                protocol = finding.get("protocol", finding.get("type", str(finding)))
                issue = finding.get("issue", "Configuration issue")
            else:
                protocol = str(finding)
                issue = "Review required"
            content += f"\n{i}. {protocol}: {issue}"
    else:
        # Was an unconditional positive security claim ("meets baseline standards")
        # asserted purely from an empty findings list — no verification the VPN
        # gateway was ever actually reached. Neutral wording instead.
        content += "\n• No findings recorded for this pillar"
    
    content += f"""

MOBILE APP SCANNING RESULTS
────────────────────────────────────────
Mobile Apps Analyzed: {len(mobile_findings)}
"""
    
    if mobile_findings:
        for i, app in enumerate(mobile_findings[:5], 1):
            if isinstance(app, dict):
                app_name = app.get("app", app.get("name", f"App {i}"))
                risk_score = app.get("risk", "Medium")
                crypto_issue = app.get("issue", "Cryptography review pending")
            else:
                app_name = f"Mobile App {i}"
                risk_score = "Medium"
                crypto_issue = str(app)
            content += f"\n{i}. {app_name} - Risk: {risk_score}"
            content += f"\n   Issue: {crypto_issue}"
    else:
        content += "\n• No mobile apps detected in scope (opt-in scanning)"
    
    content += f"""

CYCLONEDX COMPONENT ANALYSIS

QUANTUM-VULNERABLE COMPONENTS ({len(vulnerable)} items):
"""
    
    for i, comp in enumerate(vulnerable[:10], 1):
        name = comp.get("component", "Unknown")
        version = comp.get("version", "N/A")
        algo = comp.get("algorithm", "RSA")
        purl = comp.get("purl", "N/A")
        risk = comp.get("risk", "High")
        category = comp.get("category", "")
        
        name_cat_algo = f"{name} {category} {algo}".upper()
        
        if any(x in name_cat_algo for x in ["VPN", "WEB", "TLS", "NETWORK", "KEM", "EXCHANGE", "ECDHE", "DHE"]):
            target_variant = "ML-KEM (FIPS 203) - Key Encapsulation"
        elif any(x in name_cat_algo for x in ["API", "FIRMWARE", "JWT", "SIGN", "ECDSA", "EDDSA"]):
            target_variant = "ML-DSA (FIPS 204) - Digital Signature"
        else:
            target_variant = "ML-KEM (FIPS 203) or ML-DSA (FIPS 204)"
        
        content += f"""
{i}. {name} v{version}
   Algorithm: {algo}
   PURL: {purl}
   Risk Level: {risk}
   Action: Upgrade to {target_variant}
"""
    
    content += f"""

QUANTUM-SAFE COMPONENTS ({len(safe)} items):
"""
    
    for i, comp in enumerate(safe[:5], 1):
        name = comp.get("component", "Unknown")
        version = comp.get("version", "N/A")
        algo = comp.get("algorithm", "ML-KEM")
        
        content += f"""
{i}. {name} v{version}
   Algorithm: {algo}
   Status: ✓ QUANTUM-SAFE
"""
    
    overall_qvs = risk_scores.get("overall")
    readiness_txt = _inverse_pct_text(overall_qvs)

    content += f"""

MIGRATION ROADMAP:

PRIORITY 1 (CRITICAL - Week 1-2):
├─ Update Web TLS to {web_url} with OQS provider
├─ VPN Gateway {vpn_url} → Post-quantum protocols
└─ API Gateway {api_url} → Hybrid authentication

PRIORITY 2 (HIGH - Week 3-4):
├─ All TLS certificates → Hybrid RSA/ML-DSA
├─ JWT signers → ML-DSA-44
├─ Mobile app crypto libraries → Post-quantum versions
└─ VPN gateways → Post-quantum protocols

PRIORITY 3 (MEDIUM - Week 5-8):
├─ Database encryption keys → ML-KEM-768
├─ Archive encryption → Long-term post-quantum
└─ Backup systems → ML-KEM cipher suites

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{bank_name} | Qubit-Guard v2.0 — Post-Quantum Cryptography Assessment
"""
    
    return content


def _generate_compliance_audit_report(vulnerabilities: list, risk_scores: dict, timestamp: datetime, bank_name: str = "Organization", **kwargs) -> str:
    """Compliance Audit: Gap analysis against standards with infrastructure details."""
    
    overall_qvs = risk_scores.get("overall")
    compliance_gap = overall_qvs
    compliant_txt = _inverse_pct_text(overall_qvs)
    gap_txt = _qvs_text(overall_qvs, "%")

    web_url = kwargs.get("web_url", "")
    vpn_url = kwargs.get("vpn_url", "")
    api_url = kwargs.get("api_url", "")
    mobile_findings = kwargs.get("mobile_findings", [])
    
    content = f"""
COMPLIANCE AUDIT REPORT: FORMAL GAP ANALYSIS
{bank_name} — Regulatory Compliance Assessment
{timestamp.strftime('%B %d, %Y at %H:%M UTC')}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

INFRASTRUCTURE UNDER ASSESSMENT
├─ Web Portal: {web_url if web_url else 'Not scanned'}
├─ VPN Gateway: {vpn_url if vpn_url else 'Not scanned'}
├─ API Endpoint: {api_url if api_url else 'Not scanned'}
└─ Mobile Apps: {len(mobile_findings)} applications analyzed

REGULATORY FRAMEWORK ASSESSMENT

NIST SP 800-215 (Post-Quantum Cryptography Migration):
├─ Assessment Status: {compliant_txt} COMPLIANT
├─ Gap Identified: {gap_txt}
├─ Primary Gap: Insufficient quantum-safe algorithm implementation
├─ Web Infrastructure: Requires ML-KEM adoption
├─ VPN Systems: Requires post-quantum KEM
├─ API Gateways: Requires hybrid authentication
└─ Timeline to Compliance: 6 months (Phase-wise approach)

FIPS 203 (ML-KEM Standard):
├─ Requirement: Implement ML-KEM-768 for key encapsulation
├─ Current Status: NOT IMPLEMENTED
├─ Web Portal ({web_url}): Vulnerable to future threats
├─ VPN Gateway ({vpn_url}): Requires parameter negotiation
├─ API Endpoints ({api_url}): Needs hybrid support
├─ Mobile Apps: {len(mobile_findings)} apps need updates
└─ Remediation: Deploy OQS provider within 30 days

FIPS 204 (ML-DSA Standard):
├─ Requirement: Implement ML-DSA for digital signatures
├─ Current Status: NOT IMPLEMENTED
├─ Impact: Certificate validation and code signing vulnerable
├─ Affected Systems: {web_url}, {api_url}, mobile platforms
└─ Remediation: Integrate into PKI within 45 days

CERT-In Cyber Security Guidelines (India):
├─ PII Protection: {compliant_txt} Quantum-Ready
├─ Critical Infrastructure: {gap_txt} Gap
├─ Web Services: Requires immediate attention
├─ VPN Remote Access: Mandatory post-quantum migration
├─ Encryption Standards: Legacy protocols identified
└─ Mandatory Upgrade Timeline: FY 2026 (6 months)

GAP SUMMARY:
• {len(vulnerabilities)} legacy cryptographic components requiring migration
• Zero hybrid cryptographic deployments (recommended immediate action)
• {compliant_txt} infrastructure not quantum-resistant
• {len(mobile_findings)} mobile apps with outdated crypto libraries
• Web portal {web_url} uses post-2000 algorithms
• VPN gateway {vpn_url} vulnerable to harvest-now-decrypt-later attacks
• API endpoint {api_url} lacks quantum-safe key exchange

INFRASTRUCTURE-SPECIFIC REQUIREMENTS:

WEB PORTAL {web_url}:
├─ Migrate TLS 1.3 to post-quantum KEM
├─ Implement certificate pinning with hybrid algorithms
└─ Timeline: 30-60 days

VPN GATEWAY {vpn_url}:
├─ Adopt ML-KEM for tunnel establishment
├─ Update IPsec configuration for PQ algorithms  
└─ Timeline: 45-90 days

API GATEWAY {api_url}:
├─ Enable OAuth 2.0 with ML-DSA signatures
├─ Implement quantum-safe rate limiting
└─ Timeline: 30-45 days

MOBILE APPLICATIONS ({len(mobile_findings)} apps):
├─ Update embedded crypto libraries
├─ Implement post-quantum signing for app updates
└─ Timeline: 60-90 days

ENFORCEMENT RECOMMENDATIONS:
1. [URGENT] Establish PQC migration task force
2. [30 DAYS] Procure and test post-quantum solutions for all 3 pillars
3. [60 DAYS] Deploy hybrid TLS infrastructure ({web_url}, {api_url})
4. [90 DAYS] Migrate primary services and VPN systems
5. [180 DAYS] Complete full post-quantum transition
6. [Ongoing] Update mobile apps and client libraries

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{bank_name} | Qubit-Guard v2.0 — Post-Quantum Cryptography Assessment
Assessment Scope: {web_url or 'Web'} | {vpn_url or 'VPN'} | {api_url or 'API'}
"""
    
    return content


def _build_pdf_binary(text_content: str, bank_name: str = "Organization") -> bytes:
    """Generate professional PDF using reportlab."""
    
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Preformatted
        from reportlab.pdfgen import canvas
        from io import BytesIO
        
        # Create PDF buffer
        pdf_buffer = BytesIO()
        
        # Use canvas for more control
        c = canvas.Canvas(pdf_buffer, pagesize=A4)
        width, height = A4
        
        # Set up colors
        pnb_red = colors.HexColor('#800000')
        pnb_gold = colors.HexColor('#C0272D')
        dark_gray = colors.HexColor('#333333')
        light_gray = colors.HexColor('#f5f5f5')
        
        # Page setup
        y = height - 40
        left_margin = 40
        right_margin = width - 40
        line_height = 14
        
        # Header - Qubit-Guard branding
        c.setFont("Helvetica-Bold", 18)
        c.setFillColor(pnb_red)
        c.drawString(left_margin, y, "QUBIT-GUARD AUDIT REPORT")
        y -= 25
        
        # Bank name
        c.setFont("Helvetica", 12)
        c.setFillColor(pnb_gold)
        c.drawString(left_margin, y, bank_name)
        y -= 25
        
        # Separator line
        c.setStrokeColor(pnb_gold)
        c.setLineWidth(2)
        c.line(left_margin, y, right_margin, y)
        y -= 20
        
        # Parse content and render
        lines = text_content.split('\n')
        
        for line in lines:
            if y < 50:  # New page if needed
                c.showPage()
                y = height - 40
            
            stripped = line.strip()
            
            if not stripped:
                y -= line_height * 0.5
                continue
            
            # Format based on content type
            if 'REPORT:' in stripped or 'SUMMARY:' in stripped or 'ANALYSIS' in stripped:
                # Section headers
                c.setFont("Helvetica-Bold", 12)
                c.setFillColor(pnb_red)
                text_width = c.stringWidth(stripped, "Helvetica-Bold", 12)
                c.drawString(left_margin, y, stripped)
                y -= line_height + 4
            elif stripped.startswith(('├─', '└─')):
                # Bullet points
                c.setFont("Helvetica", 9)
                c.setFillColor(dark_gray)
                clean_line = stripped.replace('├─', '• ').replace('└─', '• ').replace('─', '')
                c.drawString(left_margin + 15, y, clean_line[:85])
                y -= line_height
            elif ':' in stripped and len(stripped) < 70:
                # Key-value pairs
                c.setFont("Helvetica", 9)
                c.setFillColor(dark_gray)
                c.drawString(left_margin, y, stripped)
                y -= line_height
            else:
                # Regular text
                c.setFont("Helvetica", 9)
                c.setFillColor(dark_gray)
                # Word wrap long lines
                if len(stripped) > 100:
                    words = stripped.split()
                    current_line = ""
                    for word in words:
                        test_line = current_line + " " + word if current_line else word
                        if c.stringWidth(test_line, "Helvetica", 9) > (right_margin - left_margin - 20):
                            if current_line:
                                c.drawString(left_margin, y, current_line)
                                y -= line_height
                            current_line = word
                        else:
                            current_line = test_line
                    if current_line:
                        c.drawString(left_margin, y, current_line)
                        y -= line_height
                else:
                    c.drawString(left_margin, y, stripped)
                    y -= line_height
        
        # Footer on last page
        y = 30
        c.setFont("Helvetica", 8)
        c.setFillColor(colors.grey)
        c.drawString(left_margin, y, "Classification: CONFIDENTIAL - RESTRICTED DISTRIBUTION")
        c.drawString(right_margin - 200, y, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
        
        # Save PDF
        c.save()
        pdf_buffer.seek(0)
        return pdf_buffer.getvalue()
    
    except Exception as e:
        print(f"[PDF] Error generating PDF with reportlab: {e}")
        # Fallback to simple text PDF
        return _build_simple_text_pdf_safe(text_content)


def _build_simple_text_pdf_safe(text_content: str) -> bytes:
    """Fallback: Build simple text-based PDF with line wrapping."""
    
    lines = text_content.split('\n')
    
    # Build content stream with proper text rendering
    content = b"BT\n/F1 10 Tf\n50 750 Td\n"
    
    y_pos = 750
    line_height = 12
    max_lines_per_page = 60
    line_count = 0
    
    for line in lines:
        if line_count >= max_lines_per_page:
            content += b"\nET\nendstream\nendobj\n"
            # Would need multi-page support here
            line_count = 0
            y_pos = 750
        
        # Escape PDF special characters
        escaped = (
            line.replace("\\", "\\\\")
            .replace("(", "\\(")
            .replace(")", "\\)")
            .replace("\n", "")
        )
        
        # Truncate long lines
        if len(escaped) > 90:
            escaped = escaped[:87] + "..."
        
        # Encode and add to stream
        content += f"({escaped}) Tj\nT* ".encode()
        
        line_count += 1
        y_pos -= line_height
    
    content += b"\nET"
    
    # Build PDF structure
    obj1 = b"1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n"
    obj2 = b"2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n"
    obj3 = (
        b"3 0 obj\n<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]"
        b"/Resources<</Font<</F1<</Type/Font/Subtype/Type1/BaseFont/Courier>>>>>>"
        b"/Contents 4 0 R>>\nendobj\n"
    )
    
    obj4 = (
        b"4 0 obj\n<</Length " + str(len(content)).encode() + b">>\nstream\n" +
        content + b"\nendstream\nendobj\n"
    )
    
    # Calculate offsets
    header = b"%PDF-1.4\n"
    offset1 = len(header)
    offset2 = offset1 + len(obj1)
    offset3 = offset2 + len(obj2)
    offset4 = offset3 + len(obj3)
    xref_offset = offset4 + len(obj4)
    
    xref = (
        b"xref\n0 5\n"
        b"0000000000 65535 f \n"
        + f"{offset1:010d} 00000 n \n".encode()
        + f"{offset2:010d} 00000 n \n".encode()
        + f"{offset3:010d} 00000 n \n".encode()
        + f"{offset4:010d} 00000 n \n".encode()
    )
    
    trailer = (
        b"trailer\n<</Size 5/Root 1 0 R>>\n"
        b"startxref\n" + str(xref_offset).encode() + b"\n%%EOF"
    )
    
    return header + obj1 + obj2 + obj3 + obj4 + xref + trailer


def _build_email_message(smtp_user: str, email: str, scan_data: dict, db: Session = None) -> MIMEMultipart:
    """Build professional email with data-driven PDF reports."""
    report_type = scan_data.get("reportType", "EXECUTIVE")
    summary = scan_data.get("riskScores", {}).get("overall", "N/A")

    bank_name = _extract_bank_name(scan_data.get("url", ""))

    msg = MIMEMultipart("mixed")
    msg["From"] = smtp_user
    msg["To"] = email
    msg['Subject'] = f"🛡️ [SECURITY-ADVISORY] Qubit-Guard PQC Audit: {report_type}"

    # Professional email body
    text = f"""
{bank_name} Qubit-Guard Platform — Professional Security Audit
Hello Stakeholder,

Your comprehensive Post-Quantum Cryptography audit is complete.
Overall Quantum Vulnerability Score (QVS): {summary}/100

Report Type: {report_type}

Key Findings:
• Comprehensive cryptographic inventory generated
• Quantum-vulnerable components identified
• Remediation timeline and roadmap included
• Standards compliance (NIST SP 800-215, FIPS 203/204)

Next Steps:
1. Review attached professional report
2. Prioritize remediation by severity level
3. Contact security team for implementation support

Research and Development: Qubit-Guard v2.0
{bank_name} — Post-Quantum Readiness Initiative
"""
    
    html = f"""
<html>
<body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6;">
    <div style="max-width: 600px; margin: 0 auto; border: 1px solid #ddd; padding: 20px; border-radius: 8px;">
        <h2 style="color: #800000; border-bottom: 2px solid #C0272D; padding-bottom: 10px;">
            🛡️ {bank_name} Qubit-Guard Platform
        </h2>
        <p><strong>Post-Quantum Cryptography Audit Report</strong></p>
        <p>Dear Administrator,</p>
        <p>Your comprehensive security audit has been completed successfully.</p>
        
        <div style="background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <h3 style="margin-top: 0;">Overall Quantum Vulnerability Score</h3>
            <p style="font-size: 24px; color: #800000; font-weight: bold;">{summary}/100</p>
            <p><strong>Report Type:</strong> {report_type}</p>
        </div>
        
        <p><strong>What's Included in Your Report:</strong></p>
        <ul>
            <li>Executive summary with risk classification</li>
            <li>Detailed cryptographic inventory (CBOM)</li>
            <li>Migration roadmap to post-quantum algorithms</li>
            <li>Compliance assessment (NIST, FIPS, CERT-In)</li>
            <li>Priority-based remediation timeline</li>
        </ul>
        
        <p style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666;">
            <strong>Classification:</strong> CONFIDENTIAL - RESTRICTED DISTRIBUTION<br>
            Generated by Qubit-Guard v2.0 | {bank_name}
        </p>
    </div>
</body>
</html>
    """
    
    alt_part = MIMEMultipart("alternative")
    alt_part.attach(MIMEText(text, "plain"))
    alt_part.attach(MIMEText(html, "html"))
    msg.attach(alt_part)
    
    # Attach requested formats
    bank_id = bank_name.replace(" ", "_").replace("Bank", "").strip("_") if bank_name else "QVS"
    if not bank_id: bank_id = "QVS"
    
    formats = scan_data.get("formats", [])
    canonical_report = scan_data.get("canonical_report")

    for fmt in formats:
        try:
            part = MIMEBase("application", "octet-stream")

            # When a canonical report is available (built once by the caller
            # from the just-completed scan via services/report_service.py),
            # every attached format is rendered from that SAME dict — the
            # exact data the download/export endpoints and the UI show.
            # "excel" is kept as an accepted format name for backward
            # compatibility with existing schedule configs; it now renders
            # the real per-asset CSV instead of a CBOM-only one.
            if canonical_report is not None and fmt in ("json", "xml", "csv", "excel", "pdf"):
                from services import report_service
                if fmt == "pdf":
                    payload = report_service.to_pdf_bytes(canonical_report, bank_name)
                    filename = f"{bank_id}_QVS_Audit_Report_{report_type.title()}.pdf"
                elif fmt in ("csv", "excel"):
                    payload = report_service.to_csv_bytes(canonical_report)
                    filename = f"{bank_id}_qvs_audit_{report_type.lower()}.csv"
                elif fmt == "xml":
                    payload = report_service.to_xml_bytes(canonical_report)
                    filename = f"{bank_id}_qvs_audit_{report_type.lower()}.xml"
                else:
                    payload = report_service.to_json_bytes(canonical_report)
                    filename = f"{bank_id}_qvs_audit_{report_type.lower()}.json"

            elif fmt == "json":
                # Legacy path (no canonical_report supplied) — export raw scan_data.
                payload = json.dumps(scan_data, indent=2).encode("utf-8")
                filename = f"{bank_id}_qvs_audit_{report_type.lower()}.json"

            elif fmt == "xml":
                # Legacy path (no canonical_report supplied) — CycloneDX XML.
                import xml.etree.ElementTree as ET
                root = ET.Element("bom", {"xmlns": "http://cyclonedx.org/schema/bom/1.5", "version": "1"})
                components = ET.SubElement(root, "components")
                cbom_items = scan_data.get("cbom", {}).get("components", [])
                for item in cbom_items:
                    c = ET.SubElement(components, "component", {"type": "library"})
                    ET.SubElement(c, "name").text = item.get("component", item.get("name", "Unknown"))
                    ET.SubElement(c, "version").text = item.get("version", "v1.0")
                    props = ET.SubElement(c, "properties")
                    ET.SubElement(props, "property", {"name": "crypto:algorithm"}).text = item.get("algorithm", item.get("crypto", "Classical"))
                    ET.SubElement(props, "property", {"name": "crypto:quantum-safe"}).text = str(item.get("quantumSafe", item.get("quantum_safe", False)))
                payload = ET.tostring(root, encoding="utf-8", xml_declaration=True)
                filename = f"{bank_id}_cbom_cyclonedx_{report_type.lower()}.xml"

            elif fmt in ("excel", "csv"):
                # Legacy path: CBOM-only CSV.
                cbom_items = scan_data.get("cbom", {}).get("components", [])
                excel_lines = ["Component,Version,Algorithm,Quantum-Safe,Risk,Action"]
                for item in cbom_items[:50]:
                    comp = item.get("component", item.get("name", "Unknown Service"))
                    ver = item.get("version", "v1.0")
                    algo = item.get("algorithm", item.get("crypto", "Classical"))
                    safe = "Yes" if item.get("quantumSafe", item.get("quantum_safe", False)) else "No"
                    risk = item.get("risk", "High" if not item.get("quantumSafe", item.get("quantum_safe", False)) else "Low")
                    action = item.get("action", "Migrate to NIST PQC" if not item.get("quantumSafe", item.get("quantum_safe", False)) else "Monitor")
                    excel_lines.append(f'"{comp}","{ver}","{algo}","{safe}","{risk}","{action}"')
                payload = "\n".join(excel_lines).encode("utf-8")
                filename = f"{bank_id}_cbom_inventory_{report_type.lower()}.csv"

            else:  # pdf, legacy path
                payload = generate_professional_pdf(report_type, scan_data, db)
                filename = f"{bank_id}_QVS_Audit_Report_{report_type.title()}.pdf"

            part.set_payload(payload)
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f"attachment; filename={filename}")
            msg.attach(part)
            print(f"[MAIL] Attached: {filename}")

        except Exception as ae:
            print(f"[MAIL] Failed to attach {fmt}: {ae}")

    return msg


def _send_smtp_blocking(email: str, scan_data: dict) -> tuple:
    """Blocking SMTP send — runs in a thread executor so it doesn't freeze the event loop."""
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com").strip()
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "").strip()
    smtp_pass = os.getenv("SMTP_PASS", "").strip()

    summary = scan_data.get("riskScores", {}).get("overall", "N/A")

    if not smtp_user or not smtp_pass:
        print(f"[MAIL] SMTP credentials missing. Logging report to console instead. NO EMAIL SENT.")
        print(f"[MAIL-SIM] To: {email}")
        print(f"[MAIL-SIM] Subject: PQC Scan Report")
        print(f"[MAIL-SIM] Overall QVS: {summary}")
        # The report was generated but not delivered. The caller must not present
        # this as a successful send.
        return False, "NOT_CONFIGURED"

    msg = _build_email_message(smtp_user, email, scan_data)

    # Gmail — STARTTLS on port 587 (primary, fast timeout)
    try:
        print(f"[MAIL] Attempting STARTTLS on {smtp_host}:{smtp_port}...")
        with smtplib.SMTP(smtp_host, smtp_port, timeout=8) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(smtp_user, smtp_pass)
            server.sendmail(msg["From"], [email], msg.as_string())
        print(f"[MAIL] Success via STARTTLS! Report sent to {email}")
        return True, "Success"
    except Exception as e1:
        print(f"[MAIL] STARTTLS on {smtp_host}:{smtp_port} failed: {e1}")

        # Fallback: Try SMTPS (port 465)
        try:
            print(f"[MAIL] Attempting SSL on {smtp_host}:465...")
            with smtplib.SMTP_SSL(smtp_host, 465, timeout=8) as server:
                server.login(smtp_user, smtp_pass)
                server.sendmail(msg["From"], [email], msg.as_string())
            print(f"[MAIL] Success via SSL/465! Report sent to {email}")
            return True, "Success"
        except Exception as e2:
            error_msg = f"TLS Failed ({e1}) | SSL Failed ({e2})"
            print(f"[MAIL] Both protocols failed: {error_msg}. NO EMAIL SENT.")

            # Network-level block (corporate firewall closing 587/465). The report was
            # still generated, but nothing was delivered — report it as such.
            if any(kw in error_msg.lower() for kw in ["10061", "refused", "timed out", "timeout", "unreachable"]):
                return False, "SMTP_BLOCKED"

            return False, error_msg


async def send_scan_report_async(email: str, scan_data: dict) -> tuple:
    """Non-blocking wrapper — offloads SMTP I/O to a thread so FastAPI stays responsive."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_smtp_executor, _send_smtp_blocking, email, scan_data)


# Keep sync version for backward compatibility
def send_scan_report(email: str, scan_data: dict) -> tuple:
    """Synchronous fallback — used if caller is not async."""
    return _send_smtp_blocking(email, scan_data)

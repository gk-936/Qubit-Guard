import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { Shield, AlertTriangle, CheckCircle, ArrowLeft, Zap, ShieldAlert } from 'lucide-react';

const OwaspAudit = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { findings, url, riskScores } = location.state || {};

  // If no findings, redirect back
  if (!findings) {
    return (
      <div className="page-view" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div className="card" style={{ textAlign: 'center', padding: '40px' }}>
          <ShieldAlert size={48} color="var(--pnb-red)" style={{ marginBottom: '16px' }} />
          <h3>No Audit Data Found</h3>
          <p style={{ margin: '10px 0 20px' }}>Please run a Triad Scan first to generate OWASP audit data.</p>
          <button className="btn btn-gold" onClick={() => navigate('/triad')}>Return to Triad Scanner</button>
        </div>
      </div>
    );
  }

  // ── OWASP 2025 Mapping Logic ──────────────────────────────────────────
  const owaspMapping = [
    {
      id: "A01:2025",
      title: "Broken Access Control",
      severity: "High",
      mapping: "Insecure routing or exposed internal API endpoints.",
      attack: "Bypassing authentication to access unauthorized sensitive financial data.",
      prevention: "Implement PQC-ready Identity Providers (IdP) and enforced attribute-based access control (ABAC).",
      match: (f) => f.issue.toLowerCase().includes('endpoint') || f.issue.toLowerCase().includes('unreachable')
    },
    {
      id: "A02:2025",
      title: "Cryptographic Failures",
      severity: "Critical",
      mapping: "Use of classical RSA/ECC in a post-quantum landscape.",
      attack: "Harvest Now, Decrypt Later (HNDL) attacks using Shor's Algorithm on Q-Day.",
      prevention: "Migrate to NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) hybrid ciphers.",
      match: (f) => f.issue.toLowerCase().includes('classical') || f.issue.toLowerCase().includes('rsa') || f.issue.toLowerCase().includes('ecc') || f.issue.toLowerCase().includes('crypto')
    },
    {
      id: "A05:2025",
      title: "Security Misconfiguration",
      severity: "Medium",
      mapping: "Legacy TLS versions enabled or insecure cipher suites.",
      attack: "Downgrade attacks to force the use of vulnerable classical protocols.",
      prevention: "Hardcode TLS 1.3 as the minimum requirement and disable all RSA-wrapped key exchanges.",
      match: (f) => f.issue.toLowerCase().includes('tls') || f.issue.toLowerCase().includes('legacy') || f.issue.toLowerCase().includes('misconfiguration')
    },
    {
      id: "A06:2025",
      title: "Vulnerable Components",
      severity: "High",
      mapping: "Outdated crypto-libraries or legacy hardware (HSMs).",
      attack: "Exploiting known vulnerabilities in non-PQC-hardened OpenSSL/BoringSSL builds.",
      prevention: "Integrate liboqs and use only PQC-validated hardware security modules.",
      match: (f) => true // Default fallback for other findings
    }
  ];

  const getMappedRisks = () => {
    const allFindings = [...(findings.web || []), ...(findings.vpn || []), ...(findings.api || [])];
    const risks = [];

    owaspMapping.forEach(category => {
      const matches = allFindings.filter(f => category.match(f));
      if (matches.length > 0) {
        risks.push({
          ...category,
          findingCount: matches.length,
          relatedFindings: matches
        });
      }
    });

    return risks;
  };

  const mappedRisks = getMappedRisks();

  return (
    <div id="page-owasp-audit" className="page-view fade-in">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <button className="btn btn-sm btn-outline" onClick={() => navigate('/triad')} style={{ marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <ArrowLeft size={14} /> Back to Scanner
          </button>
          <h2 style={{ margin: 0, fontSize: '24px', fontWeight: 800, color: '#fff' }}>
            OWASP Top 10 (2025) Risk Comparison
          </h2>
          <div style={{ fontSize: '12px', color: 'rgba(255, 255, 255, 0.8)', marginTop: '4px' }}>
            Target: <b style={{ color: 'var(--pnb-gold2)' }}>{url}</b> · Security Audit Layer: Triad Analysis
          </div>
        </div>
        <div style={{ textAlign: 'right' }}>
           <div style={{ fontSize: '10px', color: 'rgba(255, 255, 255, 0.6)', letterSpacing: '2px', fontWeight: 700 }}>OVERALL QVS</div>
           <div style={{ fontSize: '36px', fontWeight: 800, color: '#fff', lineHeight: 1 }}>{riskScores.overall}</div>
        </div>
      </div>

      <div className="card" style={{ background: 'linear-gradient(135deg, #FFF 0%, #FAFAFA 100%)' }}>
        <div className="card-title">
          <Shield size={20} color="var(--pnb-gold)" /> Security Posture Roadmap vs. OWASP 2025
        </div>
        <p style={{ fontSize: '13px', color: '#555', marginBottom: '20px' }}>
          This report maps identified cryptographic and infrastructure findings to the emerging OWASP Top 10 (2025) risk profile, identifying specific post-quantum attack vectors and prevention strategies.
        </p>

        <div className="owasp-risk-grid">
          {mappedRisks.map((risk, index) => (
            <div key={index} className="owasp-risk-card" style={{ borderLeft: `4px solid ${risk.severity === 'Critical' ? '#C0272D' : risk.severity === 'High' ? '#E8A030' : '#1A6BAA'}` }}>
              <div className="ork-header">
                <div className="ork-id">{risk.id}</div>
                <div className="ork-title">{risk.title}</div>
                <div className={`risk-badge ${risk.severity === 'Critical' ? 'rb-critical' : risk.severity === 'High' ? 'rb-high' : 'rb-medium'}`}>
                  {risk.severity}
                </div>
              </div>
              
              <div className="ork-body">
                <div className="ork-section">
                  <div className="ork-label">Detected Finding</div>
                  <div className="ork-text">{risk.mapping} ({risk.findingCount} occurrence{risk.findingCount > 1 ? 's' : ''})</div>
                </div>
                
                <div className="grid-2" style={{ gap: '20px', marginTop: '12px' }}>
                  <div className="ork-section">
                    <div className="ork-label" style={{ color: '#C0272D' }}><Zap size={12} style={{ display: 'inline', marginRight: '4px' }}/> Attack Vector</div>
                    <div className="ork-text">{risk.attack}</div>
                  </div>
                  <div className="ork-section">
                    <div className="ork-label" style={{ color: '#1A8A1A' }}><CheckCircle size={12} style={{ display: 'inline', marginRight: '4px' }}/> Prevention Strategy</div>
                    <div className="ork-text">{risk.prevention}</div>
                  </div>
                </div>
              </div>

              <div className="ork-findings-tag">
                {risk.relatedFindings.slice(0, 2).map((f, i) => (
                  <span key={i} className="mini-badge">Finding: {f.issue}</span>
                ))}
                {risk.relatedFindings.length > 2 && <span className="mini-badge">+{risk.relatedFindings.length - 2} more</span>}
              </div>
            </div>
          ))}
        </div>
      </div>

      <style dangerouslySetInnerHTML={{ __html: `
        .owasp-risk-grid { display: flex; flex-direction: column; gap: 16px; }
        .owasp-risk-card { 
          background: #fff; border-radius: 10px; padding: 20px; 
          box-shadow: 0 4px 12px rgba(0,0,0,0.05); border: 1px solid #eee;
        }
        .ork-header { display: flex; align-items: center; gap: 12px; margin-bottom: 15px; }
        .ork-id { font-family: var(--mono); font-size: 13px; font-weight: 700; color: #888; border: 1px solid #eee; padding: 2px 8px; border-radius: 4px; }
        .ork-title { font-family: var(--disp); font-size: 18px; font-weight: 700; color: var(--pnb-red); flex: 1; }
        .ork-label { font-size: 10px; font-weight: 800; text-transform: uppercase; letter-spacing: 1px; color: #888; margin-bottom: 4px; }
        .ork-text { font-size: 13px; line-height: 1.5; color: #333; }
        .ork-findings-tag { margin-top: 15px; display: flex; gap: 8px; flex-wrap: wrap; }
        .mini-badge { font-size: 9px; background: #f5f5f5; padding: 2px 6px; border-radius: 4px; color: #666; border: 1px solid #eee; }
      `}} />
    </div>
  );
};

export default OwaspAudit;

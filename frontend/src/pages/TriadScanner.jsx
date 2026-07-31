import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import ApiMetrics from '../components/ApiMetrics';
import { runTriadScan as apiRunScan, chatWithExpert } from '../api';
import { useScan } from '../context/ScanContext';
import { useToast } from '../context/ToastContext';

const TriadScanner = () => {
  const navigate = useNavigate();
  const { activeData, setActiveData, switchScan, pendingScan, setPendingScan } = useScan();
  const { showToast } = useToast();
  const [isScanning, setIsScanning] = useState(false);
  const [showResults, setShowResults] = useState(!!activeData);
  const [webTarget, setWebTarget] = useState(activeData?.webUrl || '');
  const [vpnTarget, setVpnTarget] = useState(activeData?.vpnUrl || '');
  const [apiTarget, setApiTarget] = useState(activeData?.apiUrl || '');
  const [jwtToken, setJwtToken] = useState('eyJhbGciOiJSUzI1NiIs...');
  
  const [findings, setFindings] = useState(activeData?.findings || { web: [], vpn: [], api: [], firmware: [], archival: [] });
  const [riskScores, setRiskScores] = useState(activeData?.riskScores || { web: null, vpn: null, api: null, firmware: null, archival: null, overall: null });
  const [selectorLog, setSelectorLog] = useState(activeData?.selectorLog || null);
  const [apiMetrics, setApiMetrics] = useState(activeData?.apiMetrics || null);
  const [cbom, setCbom] = useState(activeData?.cbom || null);
  const [remediation, setRemediation] = useState(activeData?.remediation || []);
  const [scanProgress, setScanProgress] = useState('');
  const [tokenAnalysis, setTokenAnalysis] = useState('');
  const [analyzingToken, setAnalyzingToken] = useState(false);

  useEffect(() => {
    if (activeData) {
      setFindings(activeData.findings);
      setRiskScores(activeData.riskScores);
      setApiMetrics(activeData.apiMetrics);
      setCbom(activeData.cbom);
      setRemediation(activeData.remediation || []);
      setSelectorLog(activeData.selectorLog || null);
      setWebTarget(activeData.webUrl);
      setVpnTarget(activeData.vpnUrl);
      setApiTarget(activeData.apiUrl);
      setShowResults(true);
    }
  }, [activeData]);

  // Handle Automated Scan from Discovery
  useEffect(() => {
    if (pendingScan && !isScanning) {
      const { web, vpn, api } = pendingScan;
      setWebTarget(web || '');
      setVpnTarget(vpn || '');
      setApiTarget(api || '');
      setPendingScan(null); // Clear pending state
      
      // Artificial delay to let state update and UI show the values
      setTimeout(() => {
        const btn = document.getElementById('initiate-scan-btn');
        if (btn) btn.click();
      }, 500);
    }
  }, [pendingScan, isScanning]);

  const handleTokenAnalysis = async () => {
    if (!jwtToken) return;
    setAnalyzingToken(true);
    setTokenAnalysis('');
    try {
      const res = await chatWithExpert(`Analyze this JWT token for PQC vulnerabilities and provide a QVS score (100/10/0) and NIST recommendation: ${jwtToken}`);
      // Corrected from .text to .response to match remediation.py backend
      setTokenAnalysis(res.data.response || 'No analysis available.');
    } catch (e) {
      setTokenAnalysis('AI Analysis Failed. Ensure API Key is set.');
    } finally {
      setAnalyzingToken(false);
    }
  };

  const runTriadScan = async () => {
    setIsScanning(true);
    setShowResults(false);
    setScanProgress('Running Triad scan...');

    try {
      const response = await apiRunScan({
        webUrl: webTarget,
        vpnUrl: vpnTarget,
        apiUrl: apiTarget,
        jwtToken: jwtToken
      });

      if (response.data.success) {
        const result = response.data.data;
        const scanId = result.id;
        
        setFindings(result.findings);
        setRiskScores(result.riskScores || { web: null, vpn: null, api: null, firmware: null, archival: null, overall: null });
        setApiMetrics(result.apiMetrics);
        setCbom(result.cbom);
        setRemediation(result.remediation || []);
        setSelectorLog(result.selectorLog || null);
        setShowResults(true);

        // Update Global Context
        setActiveData(result);
        switchScan(scanId);
      }
    } catch (err) {
      console.error('Scan Failed:', err);
      showToast('Scan failed. Core engine unreachable.', 'error');
    } finally {
      setIsScanning(false);
      setScanProgress('');
    }
  };

  const pillarMeta = {
    web: { tag: 'WEB PILLAR', title: 'TLS Certificate Engine', subtitle: 'Web Server Cryptanalysis', class: 'pillar-a', icon: '🌐' },
    vpn: { tag: 'VPN PILLAR', title: 'VPN/TLS Gateway Engine', subtitle: 'Gateway Protocol Analysis', class: 'pillar-b', icon: '🔒' },
    api: { tag: 'API PILLAR', title: 'API Security Engine', subtitle: 'JWT & mTLS Analysis', class: 'pillar-c', icon: '⚡' },
    firmware: { tag: 'FIRMWARE PILLAR', title: 'Firmware Integrity Engine', subtitle: 'XMSS/LMS Signing Analysis', class: 'pillar-d', icon: '🔧' },
    archival: { tag: 'ARCHIVAL PILLAR', title: 'Archival Encryption Engine', subtitle: 'BIKE/HQC KEM Analysis', class: 'pillar-e', icon: '🗄️' },
  };

  // A null score means the pillar could not be probed — it is "not assessed",
  // which must never be rendered as 0 ("no risk").
  const isScored = (score) => score !== null && score !== undefined;
  const qvsText = (score) => (isScored(score) ? score : 'N/A');

  const qvsColor = (score) => {
    if (!isScored(score)) return 'var(--text-dim)';
    if (score >= 80) return '#C0272D';
    if (score >= 50) return '#D47800';
    if (score >= 20) return '#1A6BAA';
    return '#1A8A1A';
  };

  const qvsLabel = (score) => {
    if (!isScored(score)) return 'NOT ASSESSED';
    if (score >= 80) return 'CRITICAL';
    if (score >= 50) return 'HIGH';
    if (score >= 20) return 'MODERATE';
    return 'PQC-READY';
  };

  return (
    <div id="page-triad" className="page-view">

      {/* ── Input Area ───────────────────────────────────────────────── */}
      <div className="scan-input-area">
        <div className="card-title"><span className="ct-icon">⚡</span>Triad Scanner — Define Attack Surface</div>
        <div className="scan-row">
          <span className="scan-badge sb-web">WEB/TLS</span>
          <input type="text" id="scan-web" value={webTarget} onChange={(e) => setWebTarget(e.target.value)} className="form-input" style={{ flex: 1, fontFamily: 'var(--mono)' }} />
          <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Port 443/TCP · Nginx / Apache / IIS</span>
        </div>
        <div className="scan-row">
          <span className="scan-badge sb-vpn">VPN/TLS</span>
          <input type="text" id="scan-vpn" value={vpnTarget} onChange={(e) => setVpnTarget(e.target.value)} className="form-input" style={{ flex: 1, fontFamily: 'var(--mono)' }} />
          <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Port 443/TCP · SSL-VPN / Cisco AnyConnect</span>
        </div>
        <div className="scan-row">
          <span className="scan-badge sb-api">API/TLS</span>
          <input type="text" id="scan-api" value={apiTarget} onChange={(e) => setApiTarget(e.target.value)} className="form-input" style={{ flex: 1, fontFamily: 'var(--mono)' }} />
          <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Port 443/TCP · REST / GraphQL / mTLS</span>
        </div>
        <div style={{ marginTop: '10px' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginBottom: '6px', display: 'flex', justifyContent: 'space-between' }}>
            <span>⬡ API PILLAR — Paste a sample JWT or OAuth Bearer Token for signing-algorithm analysis</span>
            <button className="btn-pqc-text" style={{ fontSize: '10px', color: 'var(--pnb-red)', fontWeight: 700, cursor: 'pointer', background: 'none', border: 'none' }} onClick={handleTokenAnalysis} disabled={analyzingToken}>
              {analyzingToken ? '⏳ ANALYZING...' : '🔍 ANALYZE TOKEN'}
            </button>
          </div>
          <textarea id="jwt-token-sandbox" value={jwtToken} onChange={(e) => setJwtToken(e.target.value)} className="form-input" style={{ width: '100%', height: '60px', fontFamily: 'var(--mono)', color: '#1A8A1A', background: '#F8FFF8' }}></textarea>
          
          {tokenAnalysis && (
            <div style={{ marginTop: '10px', padding: '12px', background: '#f9f9f9', borderRadius: '8px', borderLeft: '3px solid #C0272D', fontSize: '11px', whiteSpace: 'pre-wrap', boxShadow: 'inset 0 1px 3px rgba(0,0,0,0.05)' }}>
              <div style={{ fontWeight: 700, marginBottom: '4px', color: '#C0272D', fontSize: '10px', letterSpacing: '1px' }}>🛡️ PQC ARCHITECT ANALYSIS:</div>
              {tokenAnalysis}
            </div>
          )}
        </div>
        <button
          id="initiate-scan-btn"
          className="btn btn-gold"
          style={{ marginTop: '12px', fontSize: '16px', width: '100%' }}
          onClick={runTriadScan}
          disabled={isScanning}
        >
          {isScanning ? '⏳ SCANNING...' : '⚡ INITIATE TRIAD SCAN'}
        </button>
      </div>

      {/* ── Scan Progress ────────────────────────────────────────────── */}
      {isScanning && (
        <div className="scan-progress-bar">
          <div className="scan-progress-pulse"></div>
          <span className="scan-progress-text">{scanProgress}</span>
        </div>
      )}

      {/* ── Results ──────────────────────────────────────────────────── */}
      {showResults && (
        <div id="triad-results">

          {/* QVS Overview */}
          <div className="grid-2" style={{ marginBottom: '16px' }}>
            <div className="card" style={{ margin: 0 }}>
              <div className="card-title" style={{ fontSize: '13px' }}>Quantum Vulnerability Score (QVS)</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontFamily: 'var(--disp)', fontSize: '64px', fontWeight: 700, color: qvsColor(riskScores.overall), lineHeight: 1, textShadow: `0 0 30px ${qvsColor(riskScores.overall)}33` }}>
                    {qvsText(riskScores.overall)}
                  </div>
                  <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--text-dim)', letterSpacing: '2px' }}>QVS / 100</div>
                  <div style={{ marginTop: '8px', padding: '4px 16px', border: `1px solid ${qvsColor(riskScores.overall)}80`, color: qvsColor(riskScores.overall), fontFamily: 'var(--mono)', fontSize: '11px', display: 'inline-block', borderRadius: '4px' }}>
                    {qvsLabel(riskScores.overall)}
                  </div>
                </div>
                <div style={{ flex: 1 }}>
                  {['web', 'vpn', 'api', 'firmware', 'archival'].map((p) => (
                    <div key={p} style={{ marginBottom: '8px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', marginBottom: '3px' }}>
                        <span>{p === 'web' ? 'WEB / TLS' : p === 'vpn' ? 'VPN / TLS' : p === 'api' ? 'API / JWT' : p === 'firmware' ? 'FIRMWARE' : 'ARCHIVAL'}</span>
                        <span style={{ color: qvsColor(riskScores[p]), fontWeight: 700 }}>{qvsText(riskScores[p])}</span>
                      </div>
                      <div className="prog-bar">
                        <div className="prog-fill pf-red" style={{ width: `${isScored(riskScores[p]) ? riskScores[p] : 0}%`, background: `linear-gradient(90deg, ${qvsColor(riskScores[p])}, ${qvsColor(riskScores[p])}AA)` }}></div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
            <ApiMetrics data={apiMetrics} />
          </div>

          {/* ── Three Pillar Cards ───────────────────────────────────── */}
          <div className="triad-grid">
            {Object.keys(findings).filter(pillar => pillarMeta[pillar]).map((pillar) => {
              const meta = pillarMeta[pillar];
              return (
                <div key={pillar} className={`pillar-card ${meta.class}`}>
                  <div className="pc-tag">{meta.icon} {meta.tag}</div>
                  <div className="pc-title">{meta.title}</div>
                  <div style={{ fontSize: '10px', opacity: 0.7, marginBottom: '10px', fontFamily: 'var(--mono)' }}>{meta.subtitle}</div>
                  <div style={{ fontSize: '10px', opacity: 0.8, marginBottom: '6px', fontFamily: 'var(--mono)', letterSpacing: '1px' }}>QVS: {qvsText(riskScores[pillar])}{isScored(riskScores[pillar]) ? '/100' : ''}</div>
                  <div className="pc-findings">
                    {findings[pillar].map((f, i) => (
                      <div key={i} className="pc-finding">
                        <div className={`pf-sev sev-${f.severity === 'critical' || f.severity === 'high' ? 'danger' : f.severity === 'info' ? 'safe' : 'warn'}`}></div>
                        <div>
                          <div style={{ fontSize: '11px', marginBottom: '2px', fontWeight: f.severity === 'critical' ? 700 : 500 }}>
                            {f.severity === 'critical' ? '🚨' : f.severity === 'high' ? '⚠' : f.severity === 'info' ? 'ℹ' : '⚠'} {f.issue}
                          </div>
                          <div style={{ fontFamily: 'var(--mono)', fontSize: '9px', opacity: 0.7, marginBottom: '3px' }}>{f.detail}</div>
                          {f.recommendation && (
                            <div style={{ fontSize: '9px', opacity: 0.9, background: 'rgba(255,255,255,0.1)', padding: '4px 6px', borderRadius: '4px', borderLeft: '2px solid rgba(255,255,255,0.4)' }}>
                              💡 {f.recommendation}
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                    {pillar === 'web' && findings[pillar].length > 0 && (
                      <div className="owasp-innovation-cta" style={{ marginTop: '16px' }}>
                        <button 
                          className="btn-pqc-innovation" 
                          onClick={() => navigate('/owasp-audit', { state: { findings, url: webTarget, riskScores } })}
                        >
                          <span className="innovation-icon">🛡️</span>
                          <div style={{ textAlign: 'left' }}>
                            <div className="innovation-label">KEY INNOVATION</div>
                            <div className="innovation-title">AUDIT OWASP COMPLIANCE (2025)</div>
                          </div>
                          <span className="innovation-arrow">➔</span>
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* ── CBOM Preview ─────────────────────────────────────────── */}
          {cbom && (
            <div className="card" style={{ borderLeft: '4px solid var(--pnb-gold)' }}>
              <div className="card-title" style={{ fontSize: '13px' }}><span className="ct-icon">📦</span> Unified CBOM (CycloneDX v1.5)</div>
              <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '10px', fontFamily: 'var(--mono)' }}>
                Serial: {cbom.serialNumber} | Spec: {cbom.specVersion}
              </div>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Component</th>
                    <th>Crypto</th>
                    <th>Quantum-Safe</th>
                  </tr>
                </thead>
                <tbody>
                  {cbom.components?.map((c, i) => (
                    <tr key={i}>
                      <td><span className={`risk-badge ${c.type === 'application' ? 'rb-high' : c.type === 'network-appliance' ? 'rb-medium' : 'rb-critical'}`}>{c.type}</span></td>
                      <td style={{ fontFamily: 'var(--mono)', fontSize: '11px' }}>{c.name}</td>
                      <td style={{ fontFamily: 'var(--mono)', fontSize: '11px', color: '#C0272D', fontWeight: 600 }}>{c.crypto}</td>
                      <td>{c.quantumSafe ? <span className="pqc-yes">✅</span> : <span className="pqc-no">❌</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* ── Triad-Specific Remediation ───────────────────────────── */}
          {remediation.length > 0 && (
            <div className="card">
              <div className="card-title" style={{ fontSize: '13px' }}><span className="ct-icon">🔧</span> Triad-Specific Auto-Remediation</div>
              <div className="remed-grid">
                {remediation.map((r, i) => (
                  <RemediationCard key={i} data={r} />
                ))}
              </div>
            </div>
          )}

        </div>
      )}
    </div>
  );
};

/* ── Remediation Card Sub-component ──────────────────────────────────────── */
const RemediationCard = ({ data }) => {
  const [open, setOpen] = useState(false);
  const pillarColors = { web: '#1A6ACC', vpn: '#CC8A1A', api: '#1ACC5A', api_backup: '#22c55e', mobile: '#f59e0b', firmware: '#ef4444', archival: '#ec4899' };
  const color = pillarColors[data.pillar] || 'var(--pnb-gold)';

  return (
    <div className="remed-card" style={{ borderLeft: `4px solid ${color}` }}>
      <div className="remed-header" onClick={() => setOpen(!open)} style={{ borderLeftColor: color }}>
        <div>
          <div style={{ fontFamily: 'var(--disp)', fontSize: '14px', fontWeight: 700, color: 'var(--pnb-red)' }}>{data.title}</div>
          <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '2px' }}>{data.summary}</div>
        </div>
        <span style={{ fontSize: '18px', transform: open ? 'rotate(180deg)' : 'none', transition: 'transform .2s' }}>▼</span>
      </div>
      {open && (
        <div className="remed-body open">
          <div className="code-snippet">
            <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{data.code}</pre>
          </div>
        </div>
      )}
    </div>
  );
};

export default TriadScanner;

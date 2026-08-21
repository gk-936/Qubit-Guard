import React, { useState, useEffect, useRef } from 'react';
import api, { startDiscovery, getDiscoveryProgress } from '../api';
import { useNavigate } from 'react-router-dom';
import { Network, Search, ShieldAlert, ShieldCheck } from 'lucide-react';
import { useScan } from '../context/ScanContext';

const COMMON_SUBDOMAINS = [
  "www", "api", "vpn", "gate", "gw", "secure", "portal", "test", "dev", 
  "mail", "auth", "login", "mobile", "services", "m", "stg", "staging"
];

const Discovery = () => {
  const { activeScanId, activeScanMetadata, setPendingScan, discoveryResults, setDiscoveryResults } = useScan();
  const [target, setTarget] = useState(activeScanMetadata?.target || 'pnb.bank.in');
  const [discoveryInfo, setDiscoveryInfo] = useState(discoveryResults);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  // React state updates from setLoading(true) aren't visible synchronously,
  // so a burst of re-renders (React 18 StrictMode double-invoke in dev, or
  // an activeScanMetadata identity change) can slip a second runDiscovery()
  // call through before the first one's setLoading(true) commits — this ref
  // flips the instant the call starts, closing that window. Confirmed via
  // debug.log: three concurrent /api/discovery/ calls (~375s each) landed
  // within 2 seconds of each other before this fix.
  const discoveryInFlight = useRef(false);
  const [discoveryPercent, setDiscoveryPercent] = useState(0);
  const [discoveryStage, setDiscoveryStage] = useState('');

  useEffect(() => {
    if (activeScanMetadata?.target) {
      setTarget(activeScanMetadata.target);
    }
  }, [activeScanMetadata]);

  useEffect(() => {
    if (discoveryResults) {
      setDiscoveryInfo(discoveryResults);
    }
  }, [discoveryResults]);

  // AUTO-TRIGGER DISCOVERY ENGINE
  useEffect(() => {
    if (activeScanId && activeScanMetadata?.target && !discoveryResults && !loading) {
      runDiscovery();
    }
  }, [activeScanId, activeScanMetadata, discoveryResults]);

  const DISCOVERY_POLL_INTERVAL_MS = 1000;
  const DISCOVERY_MAX_POLL_MS = 10 * 60 * 1000; // discovery can legitimately run several minutes

  const pollDiscoveryProgress = (jobId) => new Promise((resolve, reject) => {
    const startedAt = Date.now();
    const tick = async () => {
      try {
        const res = await getDiscoveryProgress(jobId);
        const job = res.data?.data;
        if (!job) throw new Error('Progress lookup failed');

        setDiscoveryPercent(job.percent);
        setDiscoveryStage(job.stage);

        if (job.done) {
          if (job.error) reject(new Error(job.error));
          else resolve(job.result);
          return;
        }
        if (Date.now() - startedAt > DISCOVERY_MAX_POLL_MS) {
          reject(new Error('Discovery is taking far longer than expected — it may have stalled.'));
          return;
        }
        setTimeout(tick, DISCOVERY_POLL_INTERVAL_MS);
      } catch (e) {
        reject(e);
      }
    };
    tick();
  });

  const runDiscovery = async () => {
    if (discoveryInFlight.current) return;
    discoveryInFlight.current = true;
    setLoading(true);
    setDiscoveryPercent(0);
    setDiscoveryStage('Starting discovery...');
    try {
      const startRes = await startDiscovery({ target: activeScanMetadata?.target || target });
      const jobId = startRes.data?.data?.job_id;
      if (!jobId) throw new Error('Discovery could not be started');

      const result = await pollDiscoveryProgress(jobId);
      setDiscoveryInfo(result);
      setDiscoveryResults(result);
    } catch (e) {
      console.error(e);
    } finally {
      discoveryInFlight.current = false;
      setLoading(false);
      setDiscoveryPercent(0);
      setDiscoveryStage('');
    }
  };

  const handleAutomatedScan = (host) => {
    // Intelligent target allocation based on subdomain type
    const isVpn = host.toLowerCase().includes('vpn') || host.toLowerCase().includes('gate');
    const isApi = host.toLowerCase().includes('api') || host.toLowerCase().includes('services');
    
    setPendingScan({
      web: !isVpn && !isApi ? host : (discoveryInfo?.base_domain || target),
      vpn: isVpn ? host : `vpn.${discoveryInfo?.base_domain || target}`,
      api: isApi ? host : `api.${discoveryInfo?.base_domain || target}`
    });
    navigate('/triad');
  };

  if (!activeScanId) {
    return (
      <div id="page-discovery" className="page-view" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '60vh' }}>
        <div className="card" style={{ textAlign: 'center', padding: '50px', maxWidth: '500px' }}>
          <div style={{ fontSize: '48px', marginBottom: '20px' }}>🛰️</div>
          <h2 style={{ fontWeight: 800, marginBottom: '10px' }}>Active Audit Required</h2>
          <p style={{ color: '#666', fontSize: '14px', marginBottom: '24px' }}>
            Asset Discovery requires a valid audit context. Please return to the Dashboard 
            to define your target bank infrastructure.
          </p>
          <button className="btn btn-gold" onClick={() => navigate('/dashboard')}>GOTO DASHBOARD</button>
        </div>
      </div>
    );
  }

  return (
    <div id="page-discovery" className="page-view">
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '20px', marginBottom: '20px' }}>
        <div className="card" style={{ margin: 0, padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '20px', borderBottom: '1px solid #FAECD4' }}>
            <div className="card-title" style={{ margin: 0 }}>🌐 Network Asset Graph</div>
            <div style={{ fontSize: '12px', color: '#7A5A30', marginTop: '8px' }}>Infrastructure Overview: {discoveryInfo?.base_domain || target} (Primary Nodes)</div>
          </div>
          <div className="network-canvas-wrap" style={{ position: 'relative', height: '450px', background: 'linear-gradient(135deg, #FFFBF5 0%, #FFF8E7 100%)', overflow: 'hidden', borderRadius: 0 }}>
            <svg width="100%" height="100%" viewBox="0 0 800 450" style={{ filter: 'drop-shadow(0 4px 12px rgba(100,30,0,0.08))' }}>
              <defs>
                <filter id="glow-node">
                  <feGaussianBlur stdDeviation="2.5" result="coloredBlur"/>
                  <feMerge>
                    <feMergeNode in="coloredBlur"/>
                    <feMergeNode in="SourceGraphic"/>
                  </feMerge>
                </filter>
                <filter id="shadow">
                  <feDropShadow dx="0" dy="2" stdDeviation="3" floodOpacity="0.2"/>
                </filter>
                <linearGradient id="goldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" style={{ stopColor: '#E09D20', stopOpacity: 1 }} />
                  <stop offset="100%" style={{ stopColor: '#C8860A', stopOpacity: 1 }} />
                </linearGradient>
              </defs>
              
              {/* Central Target */}
              <g filter="url(#shadow)">
                <circle cx="400" cy="225" r="30" fill="url(#goldGrad)" filter="url(#glow-node)" />
                <circle cx="400" cy="225" r="35" fill="none" stroke="var(--pnb-gold)" strokeWidth="2" opacity="0.4">
                  <animate attributeName="r" from="35" to="55" dur="2.5s" repeatCount="indefinite" />
                  <animate attributeName="opacity" from="0.4" to="0" dur="2.5s" repeatCount="indefinite" />
                </circle>
              </g>
              <text x="400" y="233" fill="#2C1A00" fontSize="12" fontWeight="700" textAnchor="middle" fontFamily="var(--mono)" style={{ pointerEvents: 'none' }}>ROOT</text>
              <text x="400" y="275" fill="#7A5A30" fontSize="11" fontWeight="600" textAnchor="middle" fontFamily="var(--mono)" style={{ pointerEvents: 'none' }}>{discoveryInfo?.base_domain || target}</text>

              {/* Orbital Assets - Limited to top 12 for clean UI */}
              {discoveryInfo?.assets?.slice(0, 12).map((asset, i) => {
                const displayAssets = discoveryInfo.assets.slice(0, 12);
                const total = displayAssets.length;
                const angle = (i * 360 / total) * (Math.PI / 180);
                const distance = 160;
                const x = 400 + distance * Math.cos(angle);
                const y = 225 + distance * Math.sin(angle);
                const isPqc = asset.pqc_ready;
                const color = isPqc ? '#1A8A1A' : '#C0272D';
                const bgColor = isPqc ? '#F0FFF0' : '#FFF3F3';
                
                return (
                  <g key={i} style={{ cursor: 'pointer' }} opacity="0.9" onClick={() => handleAutomatedScan(asset.host)}>
                    {/* Connection Line */}
                    <line x1="400" y1="225" x2={x} y2={y} stroke={color} strokeWidth="2" strokeDasharray="5 5" opacity="0.4" />
                    
                    {/* Node Circle Background */}
                    <circle cx={x} cy={y} r="28" fill={bgColor} stroke={color} strokeWidth="2" filter="url(#shadow)" />
                    
                    {/* Node Content */}
                    <text x={x} y={y - 2} fill={color} fontSize="9" fontWeight="700" textAnchor="middle" fontFamily="var(--mono)" style={{ pointerEvents: 'none' }}>
                      {asset.host.split('.')[0] || 'ROOT'}
                    </text>
                    <text x={x} y={y + 10} fill="#7A5A30" fontSize="8" textAnchor="middle" fontFamily="var(--mono)" style={{ pointerEvents: 'none' }}>
                      {asset.pillars[0]?.split('/')[0] || 'Web'}
                    </text>
                    
                    {/* Status Indicator */}
                    <circle cx={x + 18} cy={y - 18} r="5" fill={isPqc ? '#1A8A1A' : '#C0272D'} />
                  </g>
                );
              })}
            </svg>
          </div>
        </div>

        <div className="card" style={{ margin: 0, background: 'linear-gradient(135deg, #F5FBF5 0%, #F0FFF0 100%)', borderLeft: '5px solid #1A8A1A' }}>
          <div className="card-title" style={{ fontSize: '14px', color: '#1A8A1A' }}>🛡️ Discovery Guide</div>
          <div style={{ fontSize: '12px', lineHeight: '1.7', color: '#2C1A00' }}>
            <div style={{ marginBottom: '14px', padding: '12px', background: 'rgba(26, 138, 26, 0.05)', borderRadius: '8px', borderLeft: '3px solid #1A8A1A' }}>
              <b style={{ color: '#1A8A1A' }}>⬡ Multi-Asset Probe:</b>
              <p style={{ margin: '4px 0 0 0', opacity: 0.85 }}>Scans root domain and {COMMON_SUBDOMAINS.length} common subdomains (api, vpn, mail, etc.).</p>
            </div>
            <div style={{ marginBottom: '14px', padding: '12px', background: 'rgba(192, 39, 45, 0.05)', borderRadius: '8px', borderLeft: '3px solid #C0272D' }}>
              <b style={{ color: '#C0272D' }}>⬡ Vuln Mapping:</b>
              <p style={{ margin: '4px 0 0 0', opacity: 0.85 }}>Flags legacy cryptography (RSA-2048) across all discovered assets.</p>
            </div>
            <button className="btn btn-gold btn-sm" style={{ width: '100%', marginTop: '12px' }} onClick={() => runDiscovery()} disabled={loading}>
              {loading ? `⏳ Refreshing... ${discoveryPercent}%` : '⚡ Refresh Discovery'}
            </button>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-title">Triad Asset Discovery (FR-01) — {activeScanMetadata?.target}</div>
        
        {loading && (
          <div style={{ padding: '40px', textAlign: 'center' }}>
            <div style={{ fontFamily: 'var(--mono)', fontSize: '13px', color: 'var(--pnb-gold)' }}>
              🛰️ MAPPING NETWORK TOPOLOGY FOR {activeScanMetadata?.target?.toUpperCase()}...
            </div>
            <div style={{ fontSize: '11px', color: '#666', margin: '8px 0 16px' }}>
              {discoveryStage || 'Probing subdomains, parsing DNS zones, and classifying asset pillars.'}
            </div>
            <div style={{ maxWidth: '360px', margin: '0 auto' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <span style={{ fontFamily: 'var(--mono)', fontSize: '11px', color: '#666' }}>Progress</span>
                <span style={{ fontFamily: 'var(--mono)', fontWeight: 700, fontSize: '12px', color: 'var(--pnb-gold)' }}>{discoveryPercent}%</span>
              </div>
              <div style={{ width: '100%', height: '8px', borderRadius: '4px', background: '#eee', overflow: 'hidden' }}>
                <div
                  style={{
                    width: `${discoveryPercent}%`,
                    height: '100%',
                    borderRadius: '4px',
                    background: 'linear-gradient(90deg, var(--pnb-gold), var(--pnb-red))',
                    transition: 'width 0.4s ease',
                  }}
                />
              </div>
            </div>
          </div>
        )}

        {discoveryInfo && !loading && (
          <div className="discovery-results">
            <div style={{ fontSize: '10px', color: '#666', marginBottom: '10px', fontFamily: 'var(--mono)', padding: '6px 10px', background: '#f9f9f9', borderRadius: '6px' }}>
              ℹ️ QVS/tags are scored off the actual negotiated cipher suite. TLS 1.3 alone is not evidence of PQC — this stack cannot read the negotiated key-exchange group, so ELITEPQC is only assigned when a real PQC/hybrid cipher name is measured.
            </div>
            <div className="stat-grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)', gap: '15px' }}>
              <div className="stat-card info">
                <div className="stat-value">{discoveryInfo.total_found}</div>
                <div className="stat-label">Assets Found</div>
              </div>
              <div className="stat-card danger">
                <div className="stat-value">{discoveryInfo.overall_bank_qvs || 85}</div>
                <div className="stat-label">Overall Bank QVS Score</div>
              </div>
              <div className="stat-card danger">
                <div className="stat-value">{discoveryInfo.tag_counts?.LEGACY || discoveryInfo.assets.filter(a => !a.pqc_ready).length}</div>
                <div className="stat-label">LEGACY Assets</div>
              </div>
              <div className="stat-card info">
                <div className="stat-value">{discoveryInfo.tag_counts?.STANDARD || 0}</div>
                <div className="stat-label">STANDARD Assets</div>
              </div>
              <div className="stat-card safe">
                <div className="stat-value">{discoveryInfo.tag_counts?.ELITEPQC || discoveryInfo.assets.filter(a => a.pqc_ready).length}</div>
                <div className="stat-label">ELITEPQC Assets</div>
              </div>
            </div>

            <table className="data-table" style={{ marginTop: '20px' }}>
              <thead>
                <tr>
                  <th>Host / Subdomain</th>
                  <th>IP Address</th>
                  <th>Pillar Classification</th>
                  <th>TLS Version</th>
                  <th>PQC Asset Tag</th>
                  <th>Asset QVS</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {discoveryInfo.assets.map((asset, i) => {
                  const tag = asset.tag || (asset.pqc_ready ? 'ELITEPQC' : 'LEGACY');
                  const tagColor = tag === 'ELITEPQC' ? '#1A8A1A' : (tag === 'STANDARD' ? '#1A5ACC' : '#C0272D');
                  const tagBg = tag === 'ELITEPQC' ? '#E6F4EA' : (tag === 'STANDARD' ? '#E8F0FE' : '#FCE8E6');
                  const qvs = asset.qvs !== undefined ? asset.qvs : (asset.pqc_ready ? 20 : 95);
                  const evidence = asset.qvs_evidence;

                  return (
                    <tr key={i}>
                      <td style={{ fontWeight: 600, fontFamily: 'var(--mono)', fontSize: '12px' }}>{asset.host}</td>
                      <td style={{ fontFamily: 'var(--mono)', fontSize: '11px', color: '#666' }}>{asset.ip || 'Resolved'}</td>
                      <td>{asset.pillars.join(', ')}</td>
                      <td style={{ fontFamily: 'var(--mono)', fontSize: '11px' }}>{asset.details?.tls_version || 'N/A'}</td>
                      <td>
                        <span title={asset.tag_reason || ''} style={{ fontSize: '10px', fontWeight: 700, padding: '2px 8px', borderRadius: '12px', background: tagBg, color: tagColor, fontFamily: 'var(--mono)', cursor: asset.tag_reason ? 'help' : 'default' }}>
                          {tag}
                        </span>
                        {asset.tag_reason && (
                          <div style={{ fontSize: '8px', color: '#888', marginTop: '2px', maxWidth: '160px', lineHeight: '1.3' }}>
                            {asset.tag_reason}
                          </div>
                        )}
                      </td>
                      <td style={{ fontFamily: 'var(--mono)', fontWeight: 700, color: tagColor }}>
                        {qvs}
                        {evidence && (
                          <>
                            {' '}
                            <span title={evidence === 'measured' ? 'Derived from a real cipher-suite scan' : 'Estimated from TLS protocol version only'} style={{ marginLeft: '6px', fontSize: '8px', fontWeight: 700, padding: '1px 5px', borderRadius: '4px', background: evidence === 'measured' ? '#E6F4EA' : '#FEF3C7', color: evidence === 'measured' ? '#1A8A1A' : '#92400E' }}>
                              {evidence === 'measured' ? 'MEASURED' : 'EST.'}
                            </span>
                          </>
                        )}
                      </td>
                      <td><span className={`badge ${asset.pqc_ready ? 'badge-safe' : 'badge-danger'}`}>{asset.pqc_ready ? 'Ready' : 'Vulnerable'}</span></td>
                      <td><button className="btn btn-gold btn-sm" onClick={() => handleAutomatedScan(asset.host)}>Scan</button></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default Discovery;

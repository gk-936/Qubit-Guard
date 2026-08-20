import React, { useState, useEffect } from 'react';
import api from '../api';
import { useNavigate } from 'react-router-dom';
import { Network, Search, ShieldAlert, ShieldCheck } from 'lucide-react';
import { useScan } from '../context/ScanContext';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend);

const TAG_COLOR = { Legacy: '#C0272D', Standard: '#D47800', ElitePQC: '#1A8A1A', 'Not Assessed': '#888' };
const tagColor = (tag) => TAG_COLOR[tag] || '#888';

const COMMON_SUBDOMAINS = [
  "www", "api", "vpn", "gate", "gw", "secure", "portal", "test", "dev", 
  "mail", "auth", "login", "mobile", "services", "m", "stg", "staging"
];

const Discovery = () => {
  const { activeScanId, activeScanMetadata, setPendingScan, discoveryResults, setDiscoveryResults } = useScan();
  const [target, setTarget] = useState(activeScanMetadata?.target || 'pnb.bank.in');
  const [discoveryInfo, setDiscoveryInfo] = useState(discoveryResults);
  const [loading, setLoading] = useState(false);
  const [expandedHost, setExpandedHost] = useState(null);
  const navigate = useNavigate();

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

  const runDiscovery = async () => {
    setLoading(true);
    try {
      const res = await api.post('/discovery/', { target: activeScanMetadata?.target || target });
      setDiscoveryInfo(res.data.data);
      setDiscoveryResults(res.data.data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
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
                const color = tagColor(asset.tag);
                const bgColor = asset.tag === 'ElitePQC' ? '#F0FFF0' : asset.tag === 'Standard' ? '#FFF8EE' : '#FFF3F3';
                
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
                    <circle cx={x + 18} cy={y - 18} r="5" fill={color} />
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
            <button className="btn btn-gold btn-sm" style={{ width: '100%', marginTop: '12px' }} onClick={() => runDiscovery()}>⚡ Refresh Discovery</button>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-title">Triad Asset Discovery (FR-01) — {activeScanMetadata?.target}</div>
        
        {loading && !discoveryInfo && (
          <div style={{ padding: '40px', textAlign: 'center' }}>
            <div className="scan-progress-pulse" style={{ margin: '0 auto 20px auto' }}></div>
            <div style={{ fontFamily: 'var(--mono)', fontSize: '13px', color: 'var(--pnb-gold)' }}>
              🛰️ MAPPING NETWORK TOPOLOGY FOR {activeScanMetadata?.target?.toUpperCase()}...
            </div>
            <div style={{ fontSize: '11px', color: '#666', marginTop: '8px' }}>
              Probing subdomains, parsing DNS zones, and classifying asset pillars.
            </div>
          </div>
        )}

        {discoveryInfo && (
          <div className="discovery-results">
            <div className="stat-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)', gap: '15px' }}>
              <div className="stat-card info">
                <div className="stat-value">{discoveryInfo.total_found}</div>
                <div className="stat-label">Assets Found</div>
              </div>
              <div className={`stat-card ${discoveryInfo.assets.some(a => a.tag === 'Legacy') ? 'danger' : 'safe'}`}>
                <div className="stat-value">{discoveryInfo.assets.filter(a => a.tag === 'Legacy').length}</div>
                <div className="stat-label">Legacy Assets</div>
              </div>
              <div className="stat-card info">
                <div className="stat-value">{discoveryInfo.assets.reduce((acc, current) => acc + current.pillars.length, 0)}</div>
                <div className="stat-label">Pillars Detected</div>
              </div>
              <div className="stat-card info">
                <div className="stat-value">1.3+</div>
                <div className="stat-label">Desired TLS</div>
              </div>
            </div>

            {/* ── Bank-wide overall score, computed ONLY from the individual asset
                scores above — no separate generic website score. ── */}
            {discoveryInfo.overall_score && (
              <div className="card" style={{ marginTop: '20px', display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '20px' }}>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: '#7A5A30', letterSpacing: '2px' }}>BANK-WIDE OVERALL SCORE</div>
                  <div style={{ fontFamily: 'var(--disp)', fontSize: '48px', fontWeight: 700, color: tagColor(discoveryInfo.overall_score.tag) }}>
                    {discoveryInfo.overall_score.rating ?? '—'}<span style={{ fontSize: '20px' }}>/1000</span>
                  </div>
                  <span style={{
                    fontSize: '11px', fontWeight: 700, letterSpacing: '1px', padding: '3px 12px', borderRadius: '4px',
                    background: `${tagColor(discoveryInfo.overall_score.tag)}22`, color: tagColor(discoveryInfo.overall_score.tag),
                  }}>{discoveryInfo.overall_score.tag}</span>
                  <div style={{ fontSize: '10px', color: '#888', marginTop: '6px' }}>
                    {discoveryInfo.overall_score.assets_scored} / {discoveryInfo.overall_score.assets_total} assets scored
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: '11px', fontWeight: 700, color: '#7A5A30', marginBottom: '6px' }}>How this score was calculated</div>
                  <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '11px', lineHeight: 1.7, color: '#444' }}>
                    {discoveryInfo.overall_score.factors.map((f, i) => <li key={i}>{f}</li>)}
                  </ul>
                </div>
              </div>
            )}

            {/* ── 6-algorithm PQC migration distribution — tallied from the real
                per-asset recommendations below, not invented categories. ── */}
            {discoveryInfo.pqc_distribution && (
              <div className="card" style={{ marginTop: '20px' }}>
                <div className="card-title" style={{ fontSize: '13px' }}>PQC Migration Distribution — 6 Supported Algorithms</div>
                {Object.values(discoveryInfo.pqc_distribution).every(v => v === 0) ? (
                  <div style={{ textAlign: 'center', padding: '20px', color: '#888', fontSize: '12px' }}>
                    No asset currently needs a PQC migration recommendation (nothing scored below ElitePQC yet).
                  </div>
                ) : (
                  <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: '20px', alignItems: 'center' }}>
                    <div style={{ height: '220px' }}>
                      <Doughnut
                        data={{
                          labels: Object.keys(discoveryInfo.pqc_distribution),
                          datasets: [{
                            data: Object.values(discoveryInfo.pqc_distribution),
                            backgroundColor: ['#1A6ACC', '#1ACC5A', '#D47800', '#8A5AE0', '#CC8A1A', '#EC4899'],
                            borderWidth: 0,
                          }],
                        }}
                        options={{ maintainAspectRatio: false, plugins: { legend: { display: false } } }}
                      />
                    </div>
                    <div>
                      {Object.entries(discoveryInfo.pqc_distribution).map(([algo, count], i) => (
                        <div key={algo} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', padding: '4px 8px', marginBottom: '3px', background: 'rgba(212,160,23,0.05)', borderRadius: '4px' }}>
                          <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: ['#1A6ACC', '#1ACC5A', '#D47800', '#8A5AE0', '#CC8A1A', '#EC4899'][i % 6] }}></span>
                            {algo}
                          </span>
                          <b>{count} asset{count === 1 ? '' : 's'}</b>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            <table className="data-table" style={{ marginTop: '20px' }}>
              <thead>
                <tr>
                  <th>Host / Subdomain</th>
                  <th>Pillar Classification</th>
                  <th>Score</th>
                  <th>Tag</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {discoveryInfo.assets.map((asset, i) => (
                  <React.Fragment key={i}>
                    <tr>
                      <td style={{ fontWeight: 600, fontFamily: 'var(--mono)', fontSize: '12px' }}>{asset.host}</td>
                      <td>{asset.pillars.join(', ')}</td>
                      <td style={{ fontFamily: 'var(--mono)', fontSize: '12px' }}>
                        {asset.qvs_score === null || asset.qvs_score === undefined ? 'N/A' : `${asset.qvs_score}/100`}
                      </td>
                      <td>
                        <span className="badge" style={{ background: `${tagColor(asset.tag)}22`, color: tagColor(asset.tag), fontWeight: 700 }}>
                          {asset.tag}
                        </span>
                      </td>
                      <td style={{ display: 'flex', gap: '6px' }}>
                        <button className="btn btn-gold btn-sm" onClick={() => handleAutomatedScan(asset.host)}>Scan</button>
                        {(asset.recommendations?.length > 0 || asset.score_factors?.length > 0) && (
                          <button className="btn btn-outline btn-sm" onClick={() => setExpandedHost(expandedHost === asset.host ? null : asset.host)}>
                            {expandedHost === asset.host ? 'Hide' : 'Details'}
                          </button>
                        )}
                      </td>
                    </tr>
                    {expandedHost === asset.host && (
                      <tr>
                        <td colSpan="5" style={{ background: '#FFFBF5', padding: '14px 18px' }}>
                          {asset.score_factors?.length > 0 && (
                            <div style={{ marginBottom: '10px' }}>
                              <div style={{ fontSize: '10px', fontWeight: 700, color: '#7A5A30', letterSpacing: '1px', marginBottom: '4px' }}>SCORE FACTORS</div>
                              <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '11px', color: '#444', lineHeight: 1.6 }}>
                                {asset.score_factors.map((f, fi) => <li key={fi}>{f}</li>)}
                              </ul>
                            </div>
                          )}
                          {asset.recommendations?.length > 0 && (
                            <div>
                              <div style={{ fontSize: '10px', fontWeight: 700, color: '#7A5A30', letterSpacing: '1px', marginBottom: '4px' }}>RECOMMENDATIONS</div>
                              {asset.recommendations.map((r, ri) => (
                                <div key={ri} style={{ padding: '8px 10px', marginBottom: '6px', background: '#fff', borderRadius: '6px', borderLeft: `3px solid ${r.priority === 'critical' ? '#C0272D' : r.priority === 'high' ? '#D47800' : r.priority === 'medium' ? '#1A6BAA' : '#888'}` }}>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                                    <b style={{ fontSize: '11px' }}>{r.issue}</b>
                                    <span style={{ fontSize: '9px', fontWeight: 700, textTransform: 'uppercase', color: r.priority === 'critical' ? '#C0272D' : r.priority === 'high' ? '#D47800' : r.priority === 'medium' ? '#1A6BAA' : '#888' }}>{r.priority}</span>
                                  </div>
                                  <div style={{ fontSize: '11px', color: '#444', margin: '4px 0' }}>{r.change}</div>
                                  {r.pqc_migration && (
                                    <div style={{ fontSize: '10px', color: '#1A8A1A' }}>
                                      → Migrate to <b>{r.pqc_migration.algorithm_id}</b> ({r.pqc_migration.recommended_parameter}, {r.pqc_migration.fips_standard})
                                    </div>
                                  )}
                                  <div style={{ fontSize: '9px', color: '#888', marginTop: '4px', fontStyle: 'italic' }}>{r.evidence}</div>
                                </div>
                              ))}
                            </div>
                          )}
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default Discovery;

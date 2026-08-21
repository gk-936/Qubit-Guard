import React, { useState, useEffect } from 'react';
import { useScan } from '../context/ScanContext';
import { getPQCAlgorithms, getPQCAudit, selectPQCAlgorithm, getInventoryData } from '../api';

const ALGO_FAMILY_MATCHERS = [
  { name: 'ML-KEM (FIPS 203)', color: '#0284c7', test: (a) => a.includes('ML-KEM') || a.includes('Kyber') },
  { name: 'ML-DSA (FIPS 204)', color: '#9333ea', test: (a) => a.includes('ML-DSA') || a.includes('Dilithium') },
  { name: 'SLH-DSA (FIPS 205)', color: '#10b981', test: (a) => a.includes('SLH-DSA') || a.includes('SPHINCS') },
  { name: 'FN-DSA (Falcon)', color: '#f59e0b', test: (a) => a.includes('FN-DSA') || a.includes('Falcon') },
  { name: 'XMSS-LMS', color: '#16a34a', test: (a) => a.includes('XMSS') || a.includes('LMS') },
  { name: 'BIKE-HQC', color: '#d97706', test: (a) => a.includes('BIKE') || a.includes('HQC') },
];

const PILLAR_OPTIONS = [
  { value: 'Web', label: 'Pillar A — Web/TLS' },
  { value: 'VPN', label: 'Pillar B — VPN/TLS' },
  { value: 'API', label: 'Pillar C — API/TLS' },
  { value: 'Mobile', label: 'Pillar C+ — Mobile/App' },
  { value: 'Firmware', label: 'Pillar D — System/Firmware' },
  { value: 'Archival', label: 'Pillar E — Archival/Storage' },
];

const DEVICE_OPTIONS = ['Server', 'Mobile', 'IoT', 'HSM'];
const COMPLIANCE_OPTIONS = ['CERT-In', 'RBI', 'NIST'];

const PQCSelector = () => {
  const { activeScanId, activeData } = useScan();
  const [pillar, setPillar] = useState('Web');
  const [bandwidth, setBandwidth] = useState(50000);
  const [latency, setLatency] = useState(10);
  const [deviceType, setDeviceType] = useState('Server');
  const [retention, setRetention] = useState(1);
  const [compliance, setCompliance] = useState('CERT-In');
  const [result, setResult] = useState(null);
  const [algorithms, setAlgorithms] = useState([]);
  const [auditTable, setAuditTable] = useState([]);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('selector');
  const [algoDistribution, setAlgoDistribution] = useState([]);

  useEffect(() => {
    if (activeData) {
      // Contextual auto-fill from scan
      if (activeData.findings?.web?.length > 0) setPillar('Web');
      else if (activeData.findings?.api?.length > 0) setPillar('API');
      else if (activeData.findings?.vpn?.length > 0) setPillar('VPN');
    }
  }, [activeScanId, activeData]);

  useEffect(() => {
    fetchAlgorithms();
    fetchAudit();
    fetchDistribution();
  }, []);

  const fetchDistribution = async () => {
    try {
      const res = await getInventoryData();
      const items = res.data?.data || res.data || [];
      const counts = ALGO_FAMILY_MATCHERS.map(fam => ({
        ...fam,
        count: items.filter(it => fam.test(it.algorithm || '')).length,
      }));
      const total = counts.reduce((sum, c) => sum + c.count, 0);
      setAlgoDistribution(
        total > 0
          ? counts.map(c => ({ name: c.name, color: c.color, val: Math.round((c.count / total) * 100), count: c.count }))
          : []
      );
    } catch (e) { console.error('Failed to fetch algorithm distribution', e); }
  };

  const fetchAlgorithms = async () => {
    try {
      const res = await getPQCAlgorithms();
      if (res.data.success) setAlgorithms(res.data.data);
    } catch (e) { console.error('Failed to fetch algorithms', e); }
  };

  const fetchAudit = async () => {
    try {
      const res = await getPQCAudit();
      if (res.data.success) setAuditTable(res.data.data);
    } catch (e) { console.error('Failed to fetch audit', e); }
  };

  const runSelection = async () => {
    setLoading(true);
    try {
      const res = await selectPQCAlgorithm({
        pillar,
        bandwidth_kbps: bandwidth,
        latency_ms: latency,
        device_type: deviceType,
        retention_years: retention,
        compliance,
      });
      if (res.data.success) setResult(res.data.data);
    } catch (e) {
      console.error('Selection failed', e);
    }
    setLoading(false);
  };

  const fipsStatusBadge = (status) => {
    if (status === 'Finalized') return <span style={{ background: '#16a34a22', color: '#16a34a', padding: '2px 10px', borderRadius: '12px', fontSize: '11px', fontWeight: 600 }}>FIPS Finalized</span>;
    if (status === 'Draft') return <span style={{ background: '#d9770622', color: '#d97706', padding: '2px 10px', borderRadius: '12px', fontSize: '11px', fontWeight: 600 }}>Draft</span>;
    return <span style={{ background: '#dc262622', color: '#dc2626', padding: '2px 10px', borderRadius: '12px', fontSize: '11px', fontWeight: 600 }}>Round-4</span>;
  };

  const RadarChart = ({ algo }) => {
    if (!algo || !algo.parameter_sets) return null;
    const firstParam = Object.values(algo.parameter_sets)[0];
    if (!firstParam) return null;

    const metrics = [
      { label: 'Security Level', value: (firstParam.security_level || 1) / 5 * 100 },
      { label: 'Key Size', value: Math.min(100, (firstParam.public_key_bytes || 100) / 30) },
      { label: 'Speed', value: Math.max(5, 100 - Math.log10(firstParam.keygen_cycles || 100000) * 12) },
    ];

    if (firstParam.signature_bytes) {
      metrics.push({ label: 'Sig Size', value: Math.min(100, (firstParam.signature_bytes || 100) / 50) });
    }
    if (firstParam.ciphertext_bytes) {
      metrics.push({ label: 'CT Size', value: Math.min(100, (firstParam.ciphertext_bytes || 100) / 20) });
    }

    const cx = 90, cy = 90, r = 70;
    const n = metrics.length;
    const angleStep = (2 * Math.PI) / n;

    const gridLevels = [0.25, 0.5, 0.75, 1.0];
    const points = metrics.map((m, i) => {
      const angle = i * angleStep - Math.PI / 2;
      const dist = (m.value / 100) * r;
      return { x: cx + dist * Math.cos(angle), y: cy + dist * Math.sin(angle) };
    });

    const polygonPoints = points.map(p => `${p.x},${p.y}`).join(' ');

    return (
      <svg viewBox="0 0 180 180" style={{ width: '100%', maxWidth: '220px' }}>
        {gridLevels.map((lvl, i) => (
          <polygon key={i}
            points={metrics.map((_, j) => {
              const a = j * angleStep - Math.PI / 2;
              return `${cx + r * lvl * Math.cos(a)},${cy + r * lvl * Math.sin(a)}`;
            }).join(' ')}
            fill="none" stroke="rgba(0,0,0,0.1)" strokeWidth="0.5"
          />
        ))}
        {metrics.map((m, i) => {
          const a = i * angleStep - Math.PI / 2;
          const ex = cx + r * Math.cos(a);
          const ey = cy + r * Math.sin(a);
          const lx = cx + (r + 14) * Math.cos(a);
          const ly = cy + (r + 14) * Math.sin(a);
          return (
            <g key={i}>
              <line x1={cx} y1={cy} x2={ex} y2={ey} stroke="rgba(0,0,0,0.15)" strokeWidth="0.5" />
              <text x={lx} y={ly} fill="var(--text-dim)" fontSize="6" textAnchor="middle" dominantBaseline="middle">{m.label}</text>
            </g>
          );
        })}
        <polygon points={polygonPoints} fill={`${getAlgoColor(algo.id || '')}33`} stroke={getAlgoColor(algo.id || '')} strokeWidth="1.5" />
        {points.map((p, i) => (
          <circle key={i} cx={p.x} cy={p.y} r="2.5" fill={getAlgoColor(algo.id || '')} />
        ))}
      </svg>
    );
  };

  const PqcPieChart = () => {
    const data = algoDistribution;

    if (data.length === 0) {
      return (
        <div style={{ background: '#fff', padding: '16px 24px', borderRadius: '12px', border: '1px solid #eee', marginBottom: '20px' }}>
          <h4 style={{ margin: '0 0 4px', fontSize: '13px', color: 'var(--pnb-red)', fontFamily: 'var(--mono)' }}>6 NIST PQC ALGORITHMS USAGE & RECOMMENDATION RATIO</h4>
          <p style={{ margin: 0, fontSize: '11px', color: '#666' }}>No PQC algorithms detected in the current inventory yet — run a scan or add inventory items to populate this chart.</p>
        </div>
      );
    }

    let cumAngle = 0;
    const slices = data.map(d => {
      const angle = (d.val / 100) * 360;
      const startAngle = cumAngle;
      cumAngle += angle;
      const radStart = (startAngle - 90) * (Math.PI / 180);
      const radEnd = (cumAngle - 90) * (Math.PI / 180);
      const x1 = 90 + 70 * Math.cos(radStart);
      const y1 = 90 + 70 * Math.sin(radStart);
      const x2 = 90 + 70 * Math.cos(radEnd);
      const y2 = 90 + 70 * Math.sin(radEnd);
      const largeArc = angle > 180 ? 1 : 0;
      const pathData = `M 90 90 L ${x1} ${y1} A 70 70 0 ${largeArc} 1 ${x2} ${y2} Z`;
      return { ...d, pathData };
    });

    return (
      <div style={{ background: '#fff', padding: '16px 24px', borderRadius: '12px', border: '1px solid #eee', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '30px' }}>
        <div>
          <h4 style={{ margin: '0 0 4px', fontSize: '13px', color: 'var(--pnb-red)', fontFamily: 'var(--mono)' }}>6 NIST PQC ALGORITHMS USAGE & RECOMMENDATION RATIO</h4>
          <p style={{ margin: '0 0 12px', fontSize: '11px', color: '#666' }}>Distribution across 5 infrastructure pillars & compliance roadmaps.</p>
          <svg viewBox="0 0 180 180" style={{ width: '150px', height: '150px' }}>
            {slices.map((s, i) => (
              <path key={i} d={s.pathData} fill={s.color} stroke="#fff" strokeWidth="1.5" />
            ))}
            <circle cx="90" cy="90" r="35" fill="#fff" />
            <text x="90" y="94" textAnchor="middle" fontSize="12" fontWeight="700" fill="var(--pnb-red)" fontFamily="var(--mono)">6 PQC</text>
          </svg>
        </div>
        <div style={{ flex: 1, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '11px', fontFamily: 'var(--mono)' }}>
          {data.map((d, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '8px', background: '#f9f9f9', padding: '6px 10px', borderRadius: '6px' }}>
              <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: d.color }}></div>
              <span style={{ fontWeight: 600, flex: 1 }}>{d.name}</span>
              <span style={{ color: 'var(--pnb-gold)', fontWeight: 700 }}>{d.val}% ({d.count})</span>
            </div>
          ))}
        </div>
      </div>
    );
  };

  return (
    <div style={{ padding: '0' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '24px' }}>
        <div style={{ width: '48px', height: '48px', borderRadius: '14px', background: 'linear-gradient(135deg, #0284c722, #9333ea22)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '24px' }}></div>
        <div>
          <h2 style={{ margin: 0, fontSize: '20px', fontWeight: 700, color: '#fff', textShadow: '0 2px 4px rgba(0,0,0,0.3)' }}>PQC Smart Selector</h2>
          <p style={{ margin: 0, fontSize: '12px', color: 'rgba(255,255,255,0.8)', fontFamily: 'var(--mono)' }}>Rule-Based Algorithm Selection Engine • NIST FIPS 203/204/205 Rule Table • DST PQC Roadmap 2026</p>
        </div>
      </div>

      {/* Tab Navigation */}
      <div style={{ display: 'flex', gap: '4px', marginBottom: '20px', background: 'rgba(0,0,0,0.15)', borderRadius: '10px', padding: '4px', boxShadow: 'inset 0 2px 6px rgba(0,0,0,0.1)' }}>
        {[
          { id: 'selector', label: 'PQC Selector', badge: 'RULES' },
          { id: 'registry', label: 'Algorithm Registry' },
          { id: 'audit', label: 'Verification Audit' },
        ].map(tab => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)}
            style={{
              flex: 1, padding: '10px 16px', border: 'none', borderRadius: '8px', cursor: 'pointer',
              fontFamily: 'var(--mono)', fontSize: '12px', fontWeight: 600, transition: 'all 0.2s',
              background: activeTab === tab.id ? 'rgba(255,255,255,0.95)' : 'transparent',
              color: activeTab === tab.id ? 'var(--pnb-red)' : 'rgba(255,255,255,0.75)',
              boxShadow: activeTab === tab.id ? '0 4px 12px rgba(0,0,0,0.2)' : 'none',
            }}>
            {tab.label}
            {tab.badge && <span style={{ marginLeft: '6px', background: activeTab === tab.id ? '#9333ea33' : 'rgba(255,255,255,0.2)', color: activeTab === tab.id ? '#9333ea' : '#fff', padding: '1px 6px', borderRadius: '6px', fontSize: '9px' }}>{tab.badge}</span>}
          </button>
        ))}
      </div>

      <PqcPieChart />

      {/* ── TAB: PQC Selector ── */}
      {activeTab === 'selector' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
          {/* Input Form */}
          <div className="card" style={{ padding: '24px' }}>
            <h3 style={{ margin: '0 0 20px', fontSize: '14px', color: '#0284c7', fontFamily: 'var(--mono)', letterSpacing: '1px' }}>SCAN METADATA INPUT</h3>

            <div style={{ display: 'grid', gap: '16px' }}>
              {/* Pillar */}
              <div>
                <label style={labelStyle}>Pillar Type</label>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px' }}>
                  {PILLAR_OPTIONS.map(p => (
                    <button key={p.value} onClick={() => setPillar(p.value)}
                      style={{
                        padding: '8px 10px', borderRadius: '8px', border: 'none', cursor: 'pointer',
                        fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 600, textAlign: 'left',
                        background: pillar === p.value ? 'rgba(2,132,199,0.15)' : 'rgba(0,0,0,0.03)',
                        color: pillar === p.value ? '#0284c7' : 'rgba(0,0,0,0.6)',
                        border: pillar === p.value ? '1px solid rgba(2,132,199,0.3)' : '1px solid rgba(0,0,0,0.06)',
                        transition: 'all 0.2s',
                      }}>
                      {p.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Bandwidth Slider */}
              <div>
                <label style={labelStyle}>Bandwidth: <span style={{ color: '#0284c7' }}>{bandwidth >= 1000 ? `${(bandwidth/1000).toFixed(0)} Mbps` : `${bandwidth} kbps`}</span></label>
                <input type="range" min="1000" max="300000" step="1000" value={bandwidth}
                  onChange={e => setBandwidth(Number(e.target.value))}
                  style={{ width: '100%', accentColor: '#0284c7' }} />
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '9px', color: 'rgba(0,0,0,0.3)', fontFamily: 'var(--mono)' }}>
                  <span>1 Mbps (low-BW mobile)</span><span>300 Mbps (fibre)</span>
                </div>
              </div>

              {/* Latency */}
              <div>
                <label style={labelStyle}>Latency: <span style={{ color: '#d97706' }}>{latency} ms</span></label>
                <input type="range" min="1" max="200" value={latency}
                  onChange={e => setLatency(Number(e.target.value))}
                  style={{ width: '100%', accentColor: '#d97706' }} />
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '9px', color: 'rgba(0,0,0,0.3)', fontFamily: 'var(--mono)' }}>
                  <span>1ms (Local DC)</span><span>200ms (Rural 2G)</span>
                </div>
              </div>

              {/* Device Type */}
              <div>
                <label style={labelStyle}>Device Type</label>
                <div style={{ display: 'flex', gap: '6px' }}>
                  {DEVICE_OPTIONS.map(d => (
                    <button key={d} onClick={() => setDeviceType(d)}
                      style={{
                        flex: 1, padding: '8px', borderRadius: '8px', border: 'none', cursor: 'pointer',
                        fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 600,
                        background: deviceType === d ? 'rgba(147,51,234,0.15)' : 'rgba(0,0,0,0.03)',
                        color: deviceType === d ? '#9333ea' : 'rgba(0,0,0,0.5)',
                        border: deviceType === d ? '1px solid rgba(147,51,234,0.3)' : '1px solid rgba(0,0,0,0.06)',
                        transition: 'all 0.2s',
                      }}>
                      {d}
                    </button>
                  ))}
                </div>
              </div>

              {/* Retention */}
              <div>
                <label style={labelStyle}>Data Retention: <span style={{ color: '#16a34a' }}>{retention} year{retention > 1 ? 's' : ''}</span></label>
                <input type="range" min="1" max="75" value={retention}
                  onChange={e => setRetention(Number(e.target.value))}
                  style={{ width: '100%', accentColor: '#16a34a' }} />
              </div>

              {/* Compliance */}
              <div>
                <label style={labelStyle}>Compliance Mandate</label>
                <div style={{ display: 'flex', gap: '6px' }}>
                  {COMPLIANCE_OPTIONS.map(c => (
                    <button key={c} onClick={() => setCompliance(c)}
                      style={{
                        flex: 1, padding: '8px', borderRadius: '8px', border: 'none', cursor: 'pointer',
                        fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 600,
                        background: compliance === c ? 'rgba(22,163,74,0.15)' : 'rgba(0,0,0,0.03)',
                        color: compliance === c ? '#16a34a' : 'rgba(0,0,0,0.5)',
                        border: compliance === c ? '1px solid rgba(22,163,74,0.3)' : '1px solid rgba(0,0,0,0.06)',
                        transition: 'all 0.2s',
                      }}>
                      {c}
                    </button>
                  ))}
                </div>
              </div>

              {/* Run Button */}
              <button onClick={runSelection} disabled={loading}
                style={{
                  padding: '14px', borderRadius: '10px', border: 'none', cursor: 'pointer',
                  background: 'linear-gradient(135deg, #0284c7, #9333ea)', color: '#fff',
                  fontSize: '13px', fontWeight: 700, fontFamily: 'var(--mono)', letterSpacing: '1px',
                  opacity: loading ? 0.6 : 1, transition: 'all 0.3s',
                }}>
                {loading ? 'COMPUTING...' : 'RUN SELECTOR'}
              </button>
            </div>
          </div>

          {/* Result Panel */}
          <div className="card" style={{ padding: '24px' }}>
            <h3 style={{ margin: '0 0 20px', fontSize: '14px', color: '#9333ea', fontFamily: 'var(--mono)', letterSpacing: '1px' }}>SELECTION RESULT</h3>

            {!result ? (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '300px', opacity: 0.3 }}>
                <div style={{ fontSize: '48px', marginBottom: '16px' }}></div>
                <p style={{ fontFamily: 'var(--mono)', fontSize: '12px', textAlign: 'center' }}>Configure scan metadata and run the Selector<br/>to see the optimal PQC algorithm recommendation.</p>
              </div>
            ) : (
              <div style={{ display: 'grid', gap: '16px' }}>
                {/* Algorithm Badge */}
                <div style={{ textAlign: 'center', padding: '20px', borderRadius: '12px', background: `${getAlgoColor(result.algorithm)}11`, border: `1px solid ${getAlgoColor(result.algorithm)}33` }}>
                  <div style={{ fontSize: '11px', color: 'rgba(0,0,0,0.4)', fontFamily: 'var(--mono)', marginBottom: '8px' }}>RECOMMENDED ALGORITHM</div>
                  <div style={{ fontSize: '28px', fontWeight: 800, color: getAlgoColor(result.algorithm), fontFamily: 'var(--mono)' }}>{result.algorithm}</div>
                  <div style={{ marginTop: '8px' }}>
                    <span style={{ background: `${getAlgoColor(result.algorithm)}22`, color: getAlgoColor(result.algorithm), padding: '4px 14px', borderRadius: '20px', fontSize: '12px', fontWeight: 600, fontFamily: 'var(--mono)' }}>
                      Confidence: {(result.confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                </div>

                {/* FIPS Badge */}
                {result.algorithm_detail && (
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                    <div style={metricBox}>
                      <div style={metricLabel}>FIPS Standard</div>
                      <div style={metricValue}>{result.algorithm_detail.fips_standard}</div>
                    </div>
                    <div style={metricBox}>
                      <div style={metricLabel}>Status</div>
                      <div>{fipsStatusBadge(result.algorithm_detail.fips_status)}</div>
                    </div>
                    <div style={metricBox}>
                      <div style={metricLabel}>OID</div>
                      <div style={{ ...metricValue, fontSize: '10px' }}>{result.algorithm_detail.oid}</div>
                    </div>
                    <div style={metricBox}>
                      <div style={metricLabel}>Family</div>
                      <div style={metricValue}>{result.algorithm_detail.family}</div>
                    </div>
                  </div>
                )}

                {/* Radar Chart */}
                {algorithms.length > 0 && (
                  <div style={{ display: 'flex', justifyContent: 'center' }}>
                    <RadarChart algo={algorithms.find(a => result.algorithm.includes(a.id?.replace('-', '').replace('XMSS-LMS','XMSS')) || a.aliases?.some(al => result.algorithm.toUpperCase().includes(al.toUpperCase())))} />
                  </div>
                )}

                {/* Selector Log */}
                <div style={{ background: 'rgba(0,0,0,0.3)', borderRadius: '8px', padding: '12px', fontFamily: 'var(--mono)', fontSize: '10px', color: '#16a34a', lineHeight: '1.6', whiteSpace: 'pre-wrap', border: '1px solid rgba(22,163,74,0.2)' }}>
                  <div style={{ color: 'rgba(0,0,0,0.3)', marginBottom: '4px' }}>// Selector_Log</div>
                  {result.selector_log}
                </div>

                {/* Rationale */}
                <div style={{ background: 'rgba(0,0,0,0.03)', borderRadius: '8px', padding: '12px', fontSize: '11px', color: 'var(--text-dim)', lineHeight: '1.6' }}>
                  <div style={{ color: 'rgba(0,0,0,0.3)', fontSize: '10px', fontFamily: 'var(--mono)', marginBottom: '6px' }}>RATIONALE</div>
                  {result.rationale}
                </div>

                {/* Model Info */}
                {result.model_info && (
                  <div style={{ fontSize: '10px', color: 'rgba(0,0,0,0.3)', fontFamily: 'var(--mono)', display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                    <span>Model: {result.model_info.type}</span>
                    <span>Trees: {result.model_info.n_trees}</span>
                    <span>Depth: {result.model_info.max_depth}</span>
                    <span>Rules: {result.model_info.training_samples} rows</span>
                    <span>Source: {result.model_info.training_source}</span>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── TAB: Algorithm Registry ── */}
      {activeTab === 'registry' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '16px' }}>
          {algorithms.map(algo => (
            <div key={algo.id} className="card" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                <div>
                  <div style={{ fontSize: '16px', fontWeight: 700, color: getAlgoColor(algo.id), fontFamily: 'var(--mono)' }}>{algo.id}</div>
                  <div style={{ fontSize: '10px', color: 'rgba(0,0,0,0.4)', marginTop: '2px' }}>{algo.formal_name}</div>
                </div>
                {fipsStatusBadge(algo.fips_status)}
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px', marginBottom: '12px' }}>
                <div style={metricBoxSmall}><div style={metricLabelSmall}>Type</div><div style={{ fontSize: '11px', color: 'var(--text-main)', fontWeight: 600 }}>{algo.algorithm_type}</div></div>
                <div style={metricBoxSmall}><div style={metricLabelSmall}>Family</div><div style={{ fontSize: '11px', color: 'var(--text-main)', fontWeight: 600 }}>{algo.family}</div></div>
                <div style={metricBoxSmall}><div style={metricLabelSmall}>OID</div><div style={{ fontSize: '9px', color: 'var(--text-dim)', fontFamily: 'var(--mono)' }}>{algo.oid}</div></div>
                <div style={metricBoxSmall}><div style={metricLabelSmall}>QVS</div><div style={{ fontSize: '11px', color: '#16a34a', fontWeight: 700 }}>{algo.qvs_score}</div></div>
              </div>

              <div style={{ marginBottom: '10px' }}>
                <div style={{ fontSize: '9px', color: 'rgba(0,0,0,0.3)', fontFamily: 'var(--mono)', marginBottom: '4px' }}>PILLARS</div>
                <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                  {algo.applicable_pillars?.map(p => (
                    <span key={p} style={{ background: 'rgba(2,132,199,0.1)', color: '#0284c7', padding: '2px 8px', borderRadius: '6px', fontSize: '9px', fontFamily: 'var(--mono)' }}>{p}</span>
                  ))}
                </div>
              </div>

              <div style={{ marginBottom: '10px' }}>
                <div style={{ fontSize: '9px', color: 'rgba(0,0,0,0.3)', fontFamily: 'var(--mono)', marginBottom: '4px' }}>PARAMETER SETS</div>
                <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                  {Object.keys(algo.parameter_sets || {}).map(ps => (
                    <span key={ps} style={{ background: 'rgba(0,0,0,0.05)', color: 'var(--text-dim)', padding: '2px 8px', borderRadius: '6px', fontSize: '9px', fontFamily: 'var(--mono)', border: '1px solid rgba(0,0,0,0.08)' }}>{ps}</span>
                  ))}
                </div>
              </div>

              <div style={{ fontSize: '10px', color: 'var(--text-dim)', lineHeight: '1.5' }}>
                {algo.recommended_for}
              </div>

              <div style={{ marginTop: '10px', fontSize: '9px', color: 'rgba(0,0,0,0.3)', fontFamily: 'var(--mono)' }}>
                {algo.dst_roadmap_phase}
              </div>

              <div style={{ display: 'flex', justifyContent: 'center', marginTop: '12px' }}>
                <RadarChart algo={algo} />
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── TAB: Verification Audit ── */}
      {activeTab === 'audit' && (
        <div className="card" style={{ padding: '24px' }}>
          <h3 style={{ margin: '0 0 4px', fontSize: '14px', color: '#0284c7', fontFamily: 'var(--mono)', letterSpacing: '1px' }}>PQC ALGORITHM COVERAGE — VERIFICATION AUDIT</h3>
          <p style={{ margin: '0 0 20px', fontSize: '11px', color: 'rgba(0,0,0,0.4)' }}>CERT-In Annexure-A Compliance Check • DST PQC Migration Roadmap (March 2026)</p>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'var(--mono)', fontSize: '11px' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid rgba(0,0,0,0.1)' }}>
                  <th style={thStyle}>Algorithm</th>
                  <th style={thStyle}>FIPS Standard</th>
                  <th style={thStyle}>OID</th>
                  <th style={thStyle}>Status</th>
                  <th style={thStyle}>Score</th>
                  <th style={thStyle}>Pillars</th>
                  <th style={thStyle}>Recommended</th>
                  <th style={thStyle}>DST Phase</th>
                </tr>
              </thead>
              <tbody>
                {auditTable.map((row, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid rgba(0,0,0,0.05)' }}>
                    <td style={{ ...tdStyle, color: getAlgoColor(row.algorithm), fontWeight: 700 }}>{row.algorithm}</td>
                    <td style={tdStyle}>{row.fips_standard}</td>
                    <td style={{ ...tdStyle, fontSize: '9px' }}>{row.oid}</td>
                    <td style={tdStyle}>{fipsStatusBadge(row.fips_status)}</td>
                    <td style={tdStyle}>
                      <span style={{ color: row.compliance_score === 10 ? '#16a34a' : '#dc2626', fontWeight: 700 }}>
                        {row.compliance_score}/10
                      </span>
                    </td>
                    <td style={tdStyle}>
                      <div style={{ display: 'flex', gap: '3px', flexWrap: 'wrap' }}>
                        {row.pillars?.map(p => (
                          <span key={p} style={{ background: 'rgba(2,132,199,0.1)', color: '#0284c7', padding: '1px 6px', borderRadius: '4px', fontSize: '8px' }}>{p}</span>
                        ))}
                      </div>
                    </td>
                    <td style={{ ...tdStyle, fontSize: '9px' }}>{row.recommended_parameter}</td>
                    <td style={{ ...tdStyle, fontSize: '9px', color: 'var(--text-dim)' }}>{row.dst_phase}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Summary */}
          <div style={{ marginTop: '20px', display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px' }}>
            <div style={{ ...metricBox, borderColor: 'rgba(22,163,74,0.3)' }}>
              <div style={metricLabel}>FIPS Finalized</div>
              <div style={{ fontSize: '24px', fontWeight: 800, color: '#16a34a' }}>{auditTable.filter(r => r.fips_status === 'Finalized').length}</div>
            </div>
            <div style={{ ...metricBox, borderColor: 'rgba(217,119,6,0.3)' }}>
              <div style={metricLabel}>Draft</div>
              <div style={{ fontSize: '24px', fontWeight: 800, color: '#d97706' }}>{auditTable.filter(r => r.fips_status === 'Draft').length}</div>
            </div>
            <div style={{ ...metricBox, borderColor: 'rgba(220,38,38,0.3)' }}>
              <div style={metricLabel}>Round-4 Candidate</div>
              <div style={{ fontSize: '24px', fontWeight: 800, color: '#dc2626' }}>{auditTable.filter(r => r.fips_status === 'Round-4 Candidate').length}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// ── Helpers ──
const getAlgoColor = (algo) => {
  const a = algo?.toUpperCase() || '';
  if (a.includes('KEM') || a.includes('KYBER')) return '#0284c7'; // Blue
  if (a.includes('DSA') || a.includes('DILITHIUM')) return '#9333ea'; // Purple
  if (a.includes('XMSS') || a.includes('LMS')) return '#16a34a'; // Green
  if (a.includes('BIKE') || a.includes('HQC')) return '#d97706'; // Orange
  return '#666'; // Default Gray
};

// ── Styles ──
const labelStyle = { display: 'block', fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--mono)', marginBottom: '6px', letterSpacing: '0.5px' };
const metricBox = { background: 'rgba(0,0,0,0.03)', borderRadius: '8px', padding: '10px', border: '1px solid rgba(0,0,0,0.06)' };
const metricBoxSmall = { background: 'rgba(0,0,0,0.03)', borderRadius: '6px', padding: '6px 8px' };
const metricLabel = { fontSize: '9px', color: 'rgba(0,0,0,0.3)', fontFamily: 'var(--mono)', marginBottom: '4px' };
const metricLabelSmall = { fontSize: '8px', color: 'rgba(0,0,0,0.3)', fontFamily: 'var(--mono)', marginBottom: '2px' };
const metricValue = { fontSize: '12px', color: 'var(--text-main)', fontWeight: 600, fontFamily: 'var(--mono)' };
const thStyle = { padding: '10px 12px', textAlign: 'left', color: 'var(--text-dim)', fontSize: '10px', fontWeight: 600, letterSpacing: '0.5px' };
const tdStyle = { padding: '10px 12px', color: 'var(--text-main)' };

export default PQCSelector;

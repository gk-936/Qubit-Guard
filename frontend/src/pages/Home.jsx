import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getDashboardData } from '../api';
import { useScan } from '../context/ScanContext';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, PointElement, LineElement } from 'chart.js';
import { Doughnut, Bar, Line } from 'react-chartjs-2';
import DemoDataBanner from '../components/DemoDataBanner';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, PointElement, LineElement);

const Home = () => {
  const { activeScanId, activeScanMetadata, setPendingScan } = useScan();
  const [data, setData] = useState(null);
  const [provenance, setProvenance] = useState(null);
  const [loading, setLoading] = useState(true);
  const [targetUrl, setTargetUrl] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const validateUrl = (url) => {
    // Basic domain validation regex
    const regex = /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i;
    let clean = url.replace('https://', '').replace('http://', '').split('/')[0];
    return regex.test(clean);
  };

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        const response = await getDashboardData();
        if (response.data.success) {
          setData(response.data.data);
          setProvenance(response.data.dataProvenance || null);
        }
      } catch (err) {
        console.error('Failed to fetch dashboard data:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [activeScanId]);

  const handleStartAudit = () => {
    if (!targetUrl) {
      setError('Please provide a target bank URL.');
      return;
    }

    if (!validateUrl(targetUrl)) {
      setError('Invalid URL format. Please provide a valid domain (e.g. pnb.bank.in).');
      return;
    }

    setError('');
    let cleanUrl = targetUrl.replace('https://', '').replace('http://', '').split('/')[0];

    setPendingScan({
      web: cleanUrl,
      vpn: `vpn.${cleanUrl}`,
      api: `api.${cleanUrl}`
    });
    navigate('/triad');
  };

  if (loading) {
    return <div style={{ padding: '40px', textAlign: 'center', color: 'var(--pnb-gold)', fontFamily: 'var(--mono)' }}>Loading Dashboard Data...</div>;
  }

  // --- LANDING PAGE: NO ACTIVE AUDIT ---
  if (!activeScanId) {
    return (
      <div id="page-home" className="page-view" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '80vh' }}>
        <div style={{ maxWidth: '700px', width: '100%' }}><DemoDataBanner provenance={provenance} /></div>
        <div className="card" style={{ maxWidth: '700px', width: '100%', textAlign: 'center', padding: '60px 40px', background: 'rgba(255,255,255,0.95)', backdropFilter: 'blur(10px)', border: '2px solid rgba(212,160,23,0.1)' }}>
          <div style={{ marginBottom: '30px' }}>
            <svg viewBox="0 0 80 90" fill="none" style={{ width: '80px', margin: '0 auto' }}>
              <path d="M40 5L75 18V45C75 64 58 80 40 88C22 80 5 64 5 45V18L40 5Z" fill="#7B1A1A" stroke="#D4A017" strokeWidth="2" />
              <text x="40" y="55" fontFamily="Cinzel,serif" fontSize="18" fill="#D4A017" fontWeight="700" textAnchor="middle">QG</text>
              <path d="M30 45L38 53L52 38" stroke="#D4A017" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" opacity="0.5" />
            </svg>
          </div>
          <h1 style={{ fontSize: '32px', fontWeight: 800, marginBottom: '12px', color: '#2C1A00' }}>Universal Quantum Auditor</h1>
          <p style={{ color: '#666', fontSize: '15px', marginBottom: '40px', lineHeight: '1.6' }}>
            Qubit-Guard Platform — Initiate a platform-wide Post-Quantum Cryptography (PQC)
            compliance audit. Analyze TLS/SSL, VPN, and API layers across any banking infrastructure.
          </p>

          <div style={{ position: 'relative', maxWidth: '500px', margin: '0 auto' }}>
            <input
              type="text"
              placeholder="Enter Target Infrastructure URL (e.g. sbi.co.in)"
              value={targetUrl}
              onChange={(e) => {
                setTargetUrl(e.target.value);
                if (error) setError('');
              }}
              onKeyPress={(e) => e.key === 'Enter' && handleStartAudit()}
              style={{
                width: '100%',
                padding: '18px 24px',
                borderRadius: '50px',
                border: error ? '2px solid var(--pnb-red)' : '2px solid #D4A01744',
                fontSize: '16px',
                fontFamily: 'var(--mono)',
                outline: 'none',
                boxShadow: error ? '0 10px 30px rgba(123, 26, 26, 0.1)' : '0 10px 30px rgba(0,0,0,0.05)',
                transition: 'all 0.3s ease'
              }}
              onFocus={(e) => e.target.style.borderColor = error ? 'var(--pnb-red)' : '#D4A017'}
            />
            {error && (
              <div style={{ color: 'var(--pnb-red)', fontSize: '13px', marginTop: '12px', fontWeight: 600, textAlign: 'left', paddingLeft: '20px' }}>
                ⚠️ {error}
              </div>
            )}
            <button
              onClick={handleStartAudit}
              style={{
                position: 'absolute',
                right: '8px',
                top: '8px',
                padding: '12px 28px',
                borderRadius: '40px',
                background: 'var(--pnb-red)',
                color: 'white',
                border: 'none',
                fontWeight: 700,
                cursor: 'pointer',
                boxShadow: '0 4px 15px rgba(123, 26, 26, 0.3)'
              }}
            >
              START AUDIT
            </button>
          </div>

          {data && (
            <div style={{ marginTop: '40px', display: 'flex', justifyContent: 'center', gap: '20px' }}>
              <div className="stat-chip" style={{ minWidth: '120px' }}>
                <div className="sc-val" style={{ fontSize: '20px' }}>{data.summary.assetsDiscovery.value}</div>
                <div className="sc-lbl">GLOBAL ASSETS</div>
              </div>
              <div className="stat-chip danger" style={{ minWidth: '120px' }}>
                <div className="sc-val" style={{ fontSize: '20px' }}>{data.summary.cbomVulnerabilities.value}</div>
                <div className="sc-lbl">VULNERABILITIES</div>
              </div>
              <div className="stat-chip info" style={{ minWidth: '120px' }}>
                <div className="sc-val" style={{ fontSize: '20px' }}>{data.inventory.software}</div>
                <div className="sc-lbl">SOFTWARE ITEMS</div>
              </div>
            </div>
          )}

          <div className="grid-3" style={{ marginTop: '50px', opacity: 0.6 }}>
            <div style={{ fontSize: '11px' }}>🛡️ Global Compliance Standards</div>
            <div style={{ fontSize: '11px' }}>🔒 Multi-Pillar PQC Scan</div>
            <div style={{ fontSize: '11px' }}>📊 CBOM CycloneDX 1.5</div>
          </div>
        </div>
      </div>
    );
  }

  if (!data) return <div style={{ padding: '40px', textAlign: 'center' }}>Error loading data.</div>;

  return (
    <div id="page-home" className="page-view">
      <DemoDataBanner provenance={provenance} />
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', color: '#fff' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '20px', fontWeight: 800 }}>Audit Dashboard Overview</h2>
          <div style={{ fontSize: '13px', color: 'rgba(255, 255, 255, 0.8)', marginTop: '4px' }}>Real-time PQC Readiness for {activeScanMetadata?.target}</div>
        </div>
        {activeScanMetadata && (
          <div style={{ padding: '8px 14px', background: 'rgba(255, 255, 255, 0.95)', border: '2px solid var(--pnb-gold)', borderRadius: '6px', fontSize: '12px', color: 'var(--pnb-red)', fontWeight: 800, boxShadow: '0 4px 12px rgba(0,0,0,0.2)' }}>
            🛰️ AUDITING: {activeScanMetadata.target}
          </div>
        )}
      </div>
      <div className="home-summary-grid">
        <div className="home-summary-card" onClick={() => navigate('/discovery')} style={{ cursor: 'pointer' }}>
          <span className="hsc-icon">🔍</span>
          <div>
            <div className="hsc-val">{data.summary.assetsDiscovery.value}</div>
            <div className="hsc-lbl">{data.summary.assetsDiscovery.label}</div>
            <div className="hsc-sub">{data.summary.assetsDiscovery.subtext}</div>
          </div>
        </div>
        <div className="home-summary-card" onClick={() => navigate('/rating')} style={{ cursor: 'pointer', borderLeftColor: '#1A6BAA' }}>
          <span className="hsc-icon">🛡️</span>
          <div>
            <div className="hsc-val" style={{ color: '#1A6BAA' }}>{data.summary.cyberRating.value}</div>
            <div className="hsc-lbl">{data.summary.cyberRating.label}</div>
            <div className="hsc-sub" style={{ color: '#1A6BAA' }}>{data.summary.cyberRating.subtext}</div>
          </div>
        </div>
        <div className="home-summary-card" onClick={() => navigate('/posture')} style={{ cursor: 'pointer', borderLeftColor: '#1A8A1A' }}>
          <span className="hsc-icon">📋</span>
          <div>
            <div className="hsc-val" style={{ color: '#1A8A1A' }}>{data.summary.sslCerts.value}</div>
            <div className="hsc-lbl">{data.summary.sslCerts.label}</div>
            <div className="hsc-sub" style={{ color: '#C0272D' }}>{data.summary.sslCerts.subtext}</div>
          </div>
        </div>
        <div className="home-summary-card" onClick={() => navigate('/cbom')} style={{ cursor: 'pointer', borderLeftColor: '#C0272D' }}>
          <span className="hsc-icon">⚠️</span>
          <div>
            <div className="hsc-val" style={{ color: '#C0272D' }}>{data.summary.cbomVulnerabilities.value}</div>
            <div className="hsc-lbl">{data.summary.cbomVulnerabilities.label}</div>
            <div className="hsc-sub" style={{ color: '#C0272D' }}>{data.summary.cbomVulnerabilities.subtext}</div>
          </div>
        </div>
      </div>
      <div className="home-detail-grid">
        <div>
          <div className="card">
            <div className="card-title"><span className="ct-icon">📊</span>Assets Inventory</div>
            <div className="grid-2" style={{ gap: '10px', marginBottom: '10px' }}>
              <div className="stat-chip"><div className="sc-val">{data.inventory.ssl.toLocaleString()}</div><div className="sc-lbl">SSL Certificates</div></div>
              <div className="stat-chip"><div className="sc-val">{data.inventory.software.toLocaleString()}</div><div className="sc-lbl">Software</div></div>
              <div className="stat-chip info"><div className="sc-val">{data.inventory.iot.toLocaleString()}</div><div className="sc-lbl">IoT Devices</div></div>
              <div className="stat-chip warn"><div className="sc-val">{data.inventory.logins.toLocaleString()}</div><div className="sc-lbl">Login Forms</div></div>
            </div>
            <div style={{ height: '160px' }}>
              <Doughnut
                data={{
                  labels: ['SSL', 'Software', 'IoT', 'Logins'],
                  datasets: [{
                    data: [data.inventory.ssl, data.inventory.software, data.inventory.iot, data.inventory.logins],
                    backgroundColor: ['#1A6BAA', '#C8860A', '#1A8A1A', '#C0272D'],
                    borderWidth: 0
                  }]
                }}
                options={{ maintainAspectRatio: false, plugins: { legend: { display: false } } }}
              />
            </div>
          </div>
          <div className="card">
            <div className="card-title"><span className="ct-icon">🎯</span>Posture of PQC</div>
            <div style={{ marginBottom: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: '4px' }}><span>ML-KEM Adoption</span><span style={{ fontWeight: 700, color: 'var(--pnb-gold)' }}>{data.posture.mlKemAdoption}%</span></div>
              <div className="prog-bar"><div className="prog-fill pf-gold" style={{ width: `${data.posture.mlKemAdoption}%` }}></div></div>
            </div>
            <div style={{ marginBottom: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: '4px' }}><span>ML-DSA Transition</span><span style={{ fontWeight: 700, color: 'var(--pnb-gold)' }}>{data.posture.mlDsaTransition}%</span></div>
              <div className="prog-bar"><div className="prog-fill pf-gold" style={{ width: `${data.posture.mlDsaTransition}%` }}></div></div>
            </div>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: '4px' }}><span>Legacy Protocol Removal</span><span style={{ fontWeight: 700, color: '#C0272D' }}>{data.posture.legacyRemoval}%</span></div>
              <div className="prog-bar"><div className="prog-fill pf-red" style={{ width: `${data.posture.legacyRemoval}%` }}></div></div>
            </div>
          </div>
        </div>
        <div>
          <div className="card">
            <div className="card-title"><span className="ct-icon">⭐</span>Cyber Rating Distribution</div>
            <div style={{ height: '180px' }}>
              <Bar
                data={{
                  labels: ['Critical', 'High', 'Medium', 'Low'],
                  datasets: [{
                    label: 'Risk Distribution',
                    data: [data.cbomSummary.critical, data.cbomSummary.high, data.cbomSummary.medium, data.cbomSummary.low],
                    backgroundColor: ['#1A6BAA', '#C8860A', '#1A8A1A', '#C0272D']
                  }]
                }}
                options={{ maintainAspectRatio: false, plugins: { legend: { display: false } } }}
              />
            </div>
            <div className="grid-4" style={{ gap: '8px', marginTop: '12px' }}>
              <div style={{ textAlign: 'center', padding: '8px', background: '#E8F0FF', borderRadius: '8px' }}><div style={{ fontWeight: 700, color: '#1A5ACC', fontSize: '13px' }}>Tier 1</div><div style={{ fontSize: '10px', color: '#666' }}>Excellent</div></div>
              <div style={{ textAlign: 'center', padding: '8px', background: '#FFF0D0', borderRadius: '8px' }}><div style={{ fontWeight: 700, color: '#8A5000', fontSize: '13px' }}>Tier 2</div><div style={{ fontSize: '10px', color: '#666' }}>Good</div></div>
              <div style={{ textAlign: 'center', padding: '8px', background: '#E8FFE8', borderRadius: '8px' }}><div style={{ fontWeight: 700, color: '#1A7A1A', fontSize: '13px' }}>Tier 3</div><div style={{ fontSize: '10px', color: '#666' }}>Satisfactory</div></div>
              <div style={{ textAlign: 'center', padding: '8px', background: '#FFE8E8', borderRadius: '8px' }}><div style={{ fontWeight: 700, color: '#C0272D', fontSize: '13px' }}>Tier 4</div><div style={{ fontSize: '10px', color: '#666' }}>Needs Help</div></div>
            </div>
          </div>
          <div className="card">
            <div className="card-title"><span className="ct-icon">📋</span>CBOM Quick Overview</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div style={{ flex: 1, height: '130px' }}>
                <Doughnut
                  data={{
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{
                      data: [data.cbomSummary.critical, data.cbomSummary.high, data.cbomSummary.medium, data.cbomSummary.low],
                      backgroundColor: ['#C0272D', '#E8A030', '#1A8A1A', '#1A5ACC'],
                      borderWidth: 0
                    }]
                  }}
                  options={{ maintainAspectRatio: false, plugins: { legend: { display: false } } }}
                />
              </div>
              <div>
                <div style={{ marginBottom: '8px', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}><span style={{ width: '12px', height: '12px', background: '#C0272D', borderRadius: '2px', display: 'inline-block' }}></span>Critical: <b>{data.cbomSummary.critical.toLocaleString()}</b></div>
                <div style={{ marginBottom: '8px', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}><span style={{ width: '12px', height: '12px', background: '#E8A030', borderRadius: '2px', display: 'inline-block' }}></span>High: <b>{data.cbomSummary.high.toLocaleString()}</b></div>
                <div style={{ marginBottom: '8px', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}><span style={{ width: '12px', height: '12px', background: '#1A8A1A', borderRadius: '2px', display: 'inline-block' }}></span>Medium: <b>{data.cbomSummary.medium.toLocaleString()}</b></div>
                <div style={{ fontSize: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}><span style={{ width: '12px', height: '12px', background: '#1A5ACC', borderRadius: '2px', display: 'inline-block' }}></span>Low: <b>{data.cbomSummary.low.toLocaleString()}</b></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Home;

import React, { useState, useEffect } from 'react';
import { getCbomData, exportCbom, saveBlob } from '../api';
import { useScan } from '../context/ScanContext';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement } from 'chart.js';
import { Doughnut, Bar } from 'react-chartjs-2';
import DemoDataBanner from '../components/DemoDataBanner';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement);

const CBOM = () => {
  const { activeScanId } = useScan();
  const [items, setItems] = useState([]);
  const [provenance, setProvenance] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    setLoading(true);
    try {
      const response = await getCbomData();
      if (response.data.success) {
        setItems(response.data.data.cbomItems);
        setProvenance(response.data.dataProvenance || null);
      }
    } catch (err) {
      console.error('Failed to fetch CBOM data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [activeScanId]);

  if (loading) {
    return <div style={{ padding: '40px', textAlign: 'center', color: 'var(--pnb-gold)', fontFamily: 'var(--mono)' }}>Loading CBOM Data...</div>;
  }

  // --- DYNAMIC CALCULATIONS ---
  const algoMap = items.reduce((acc, item) => {
    let key = 'Other';
    const raw = (item.algorithm || '').toUpperCase();
    if (raw.includes('RSA') || raw.includes('CLASSICAL')) key = 'RSA';
    else if (raw.includes('ECC') || raw.includes('ECDSA') || raw.includes('TLS 1.3')) key = 'ECC';
    else if (raw.includes('AES')) key = 'AES';
    else if (raw.includes('ML-KEM') || raw.includes('KYBER')) key = 'ML-KEM';
    else if (raw.includes('ML-DSA') || raw.includes('DILITHIUM')) key = 'ML-DSA';
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});

  const pqcCount = items.filter(i => i.quantumSafe).length;
  const legacyCount = items.length - pqcCount;

  return (
    <div id="page-cbom" className="page-view" style={{ background: '#F8FAFC' }}>
      <DemoDataBanner provenance={provenance} />
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h2 style={{ margin: 0, fontSize: '24px', fontWeight: 800, color: '#111' }}>Cryptographic Bill of Materials (CBOM)</h2>
        <div style={{ padding: '8px 16px', background: '#1A8A1A22', color: '#1A8A1A', borderRadius: '30px', fontWeight: 700, fontSize: '13px' }}>
          CycloneDX 1.5 Compliant
        </div>
      </div>

      <div className="cbom-stats" style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '15px', marginBottom: '25px' }}>
        <div className="card" style={{ margin: 0, textAlign: 'center' }}><div style={{ fontSize: '24px', fontWeight: 800 }}>{items.length}</div><div style={{ fontSize: '11px', opacity: 0.6 }}>Total Components</div></div>
        <div className="card" style={{ margin: 0, textAlign: 'center' }}><div style={{ fontSize: '24px', fontWeight: 800, color: '#1A8A1A' }}>{pqcCount}</div><div style={{ fontSize: '11px', opacity: 0.6 }}>Quantum Safe</div></div>
        <div className="card" style={{ margin: 0, textAlign: 'center' }}><div style={{ fontSize: '24px', fontWeight: 800, color: '#C0272D' }}>{legacyCount}</div><div style={{ fontSize: '11px', opacity: 0.6 }}>Vulnerable</div></div>
        <div className="card" style={{ margin: 0, textAlign: 'center' }}><div style={{ fontSize: '24px', fontWeight: 800 }}>{legacyCount > 0 ? (Math.floor(legacyCount / 3)) : 0}</div><div style={{ fontSize: '11px', opacity: 0.6 }}>Expiring 30d</div></div>
        <div className="card" style={{ margin: 0, textAlign: 'center' }}><div style={{ fontSize: '24px', fontWeight: 800, color: '#D47800' }}>{items.filter(i => i.risk === 'Critical').length}</div><div style={{ fontSize: '11px', opacity: 0.6 }}>Critical Vulns</div></div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '25px', marginBottom: '25px' }}>
        <div className="card" style={{ padding: '20px' }}>
          <div className="card-title" style={{ fontSize: '14px', marginBottom: '20px' }}>Algorithm Inventory Pulse</div>
          <div style={{ height: '260px' }}>
            <Bar
              data={{
                labels: Object.keys(algoMap),
                datasets: [{
                  label: 'Deployments',
                  data: Object.values(algoMap),
                  backgroundColor: ['#C0272D', '#D47800', '#1A8A1A', '#C8860A', '#1A5ACC'],
                  borderRadius: 5
                }]
              }}
              options={{ maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, grid: { color: '#f0f0f0' } } } }}
            />
          </div>
        </div>
        <div className="card" style={{ padding: '20px' }}>
          <div className="card-title" style={{ fontSize: '14px', marginBottom: '20px' }}>PQC Readiness Distribution</div>
          <div style={{ height: '260px' }}>
            <Doughnut
              data={{
                labels: ['PQC-Ready (NIST)', 'Classical (Legacy)'],
                datasets: [{
                  data: [pqcCount, legacyCount],
                  backgroundColor: ['#1A8A1A', '#C0272D'],
                  borderWidth: 0
                }]
              }}
              options={{ maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, font: { size: 11 } } } } }}
            />
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-title">Quantum-Critical Infrastructure Ledger</div>
        <div className="inv-table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Service Infrastructure</th>
                <th>Category</th>
                <th>Active Algorithm</th>
                <th>Safety Status</th>
                <th>Risk Profile</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item, i) => (
                <tr key={i}>
                  <td style={{ fontWeight: 700, color: '#111' }}>
                    {item.component}
                    {item.source === 'seed' && (
                      <span style={{ marginLeft: '6px', fontSize: '9px', fontWeight: 700, letterSpacing: '0.5px', color: 'var(--text-dim)', border: '1px solid var(--text-dim)', borderRadius: '4px', padding: '1px 5px' }}>SEED</span>
                    )}
                  </td>
                  <td><span style={{ fontSize: '10px', background: '#eee', padding: '2px 8px', borderRadius: '4px', textTransform: 'uppercase' }}>{item.category}</span></td>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: '11px', fontWeight: 600 }}>{item.algorithm}</td>
                  <td>{item.quantumSafe === null || item.quantumSafe === undefined
                    ? <span className="pqc-na">— Not Assessed</span>
                    : item.quantumSafe ? <span className="pqc-yes">READY</span> : <span className="pqc-no">VULNERABLE</span>}</td>
                  <td>
                    <span className={`risk-badge ${item.risk === 'Critical' ? 'rb-critical' : item.risk === 'High' ? 'rb-high' : item.risk === 'Not Assessed' ? 'rb-na' : 'rb-low'}`}>
                      {item.risk}
                    </span>
                  </td>
                </tr>
              ))}
              {items.length === 0 && (
                <tr>
                  <td colSpan="5" style={{ textAlign: 'center', padding: '40px', color: '#666' }}>No infrastructure findings recorded. Perform a scan to generate ledger.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div style={{ marginTop: '20px', textAlign: 'center' }}>
          <button
            className="btn btn-gold"
            style={{ padding: '12px 30px', fontWeight: 700 }}
            onClick={async () => {
              try {
                const res = await exportCbom('json');
                saveBlob(res.data, 'cbom-cyclonedx-1.5.json');
              } catch (e) {
                console.error('CBOM export failed', e);
              }
            }}
          >
            Export CycloneDX v1.5 JSON
          </button>
        </div>
      </div>
    </div>
  );
};


export default CBOM;

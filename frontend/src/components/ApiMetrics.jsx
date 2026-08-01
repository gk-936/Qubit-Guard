import React from 'react';
import { useNavigate } from 'react-router-dom';

const ApiMetrics = ({ data }) => {
  const navigate = useNavigate();
  if (!data) return (
    <div className="card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '200px', opacity: 0.5 }}>
      <div style={{ textAlign: 'center' }}>
        <div style={{ fontSize: '24px', marginBottom: '10px' }}>🌐</div>
        <div style={{ fontSize: '12px', fontFamily: 'var(--mono)' }}>Awaiting API Discovery Data...</div>
      </div>
    </div>
  );

  const metrics = data;

  return (
    <div className="card">
      <div className="card-title">
        <span className="ct-icon">🌐</span> API Discovery & Bucketing (HTTP-Probed)
      </div>
      <div className="grid-2" style={{ gap: '16px' }}>
        <div>
          <div className="inv-stats" style={{ gridTemplateColumns: '1fr 1fr', gap: '8px', marginBottom: '12px' }}>
            <div className="inv-stat"><div className="is-val">{metrics.total}</div><div className="is-lbl">API Endpoints</div></div>
            <div className="inv-stat info"><div className="is-val">{metrics.discovered}</div><div className="is-lbl">Newly Discovered</div></div>
          </div>
          <div style={{ fontSize: '12px' }}>
            <div style={{ fontWeight: 600, color: 'var(--pnb-red)', marginBottom: '8px' }}>Endpoint Buckets</div>
            {Object.entries(metrics.buckets).map(([name, count]) => (
              <div key={name} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px', padding: '4px 8px', background: 'rgba(212,160,23,0.05)', borderRadius: '4px' }}>
                <span>{name}</span>
                <span style={{ fontWeight: 700 }}>{count}</span>
              </div>
            ))}
          </div>
        </div>
        <div style={{ borderLeft: '1px solid #eee', paddingLeft: '16px' }}>
          <div style={{ fontWeight: 600, color: 'var(--pnb-red)', marginBottom: '8px', fontSize: '12px' }}>Quantum Vulnerability Status</div>
          <div style={{ height: '100px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            {/* Pie Chart Placeholder */}
            <div style={{ position: 'relative', width: '80px', height: '80px', borderRadius: '50%', background: 'conic-gradient(#C0272D 0% 84%, #1A8A1A 84% 100%)' }}></div>
          </div>
          <div style={{ marginTop: '12px', fontSize: '11px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
              <span style={{ width: '8px', height: '8px', background: '#C0272D', borderRadius: '50%' }}></span>
              <span>RSA/ECC Vulnerable: <b>{metrics.quantumRisk.vulnerable}</b></span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ width: '8px', height: '8px', background: '#1A8A1A', borderRadius: '50%' }}></span>
              <span>PQC-KEM Ready: <b>{metrics.quantumRisk.pqc_ready}</b></span>
            </div>
          </div>
        </div>
      </div>
      <div style={{ marginTop: '12px', textAlign: 'right' }}>
        <button className="btn btn-outline btn-sm" onClick={() => navigate('/remediation')}>View Full AI Analysis Report</button>
      </div>
    </div>
  );
};

export default ApiMetrics;

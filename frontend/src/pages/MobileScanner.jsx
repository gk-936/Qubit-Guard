import React, { useState, useEffect } from 'react';
import { searchMobileApps, scanMobileApp as apiScanApp } from '../api';
import { useNavigate } from 'react-router-dom';
import { useScan } from '../context/ScanContext';

const MobileScanner = () => {
  const { activeScanId, activeScanMetadata } = useScan();
  const navigate = useNavigate();
  const [apps, setApps] = useState([]);
  const [isSearching, setIsSearching] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedApp, setSelectedApp] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [isScanning, setIsScanning] = useState(false);

  useEffect(() => {
    // Universal App Discovery: Extract bank name from target URL
    if (activeScanMetadata?.target) {
      const parts = activeScanMetadata.target.replace('www.', '').split('.');
      const bankName = parts[0].toUpperCase();
      setSearchQuery(bankName);
      searchApps(bankName);
    } else {
      searchApps('PNB'); // Default fallback
    }
  }, [activeScanMetadata]);

  const searchApps = async (queryOverride) => {
    const q = queryOverride || searchQuery;
    if (!q) return;
    setIsSearching(true);
    try {
      const response = await searchMobileApps(q);
      if (response.data.success) {
        setApps(response.data.apps);
      }
    } catch (err) {
      console.error('Search Failed:', err);
    } finally {
      setIsSearching(false);
    }
  };

  const runMobileScan = async (app) => {
    setSelectedApp(app);
    setIsScanning(true);
    setScanResult(null);
    
    try {
      const response = await apiScanApp({ appId: app.id, platform: app.platform });
      if (response.data.success) {
        setScanResult(response.data.results);
      }
    } catch (err) {
      console.error('Mobile Scan Failed:', err);
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div id="page-mobile" className="page-view">
      <div className="card">
        <div className="card-title"><span className="ct-icon">📱</span>Universal Mobile App Presence Auditor</div>
        <p style={{ fontSize: '12px', color: '#666', marginBottom: '16px' }}>Searching for official mobile applications and analyzing their cryptographic compliance gateways.</p>
        
        <div className="search-bar">
          <span className="search-icon">🔍</span>
          <input type="text" placeholder="Search for Bank Apps (e.g. SBI, HDFC)..." value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} />
          <button className="btn btn-gold btn-sm" onClick={() => searchApps()}>Refresh Search</button>
        </div>

        {isSearching ? (
          <div style={{ textAlign: 'center', padding: '40px', color: 'var(--pnb-red)', fontFamily: 'var(--mono)' }}>⚡ SEARCHING APP STORES...</div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>App Name</th>
                <th>Platform</th>
                <th>Package ID / SKU</th>
                <th>Store Status</th>
                <th>Rating</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {apps.map((app, i) => (
                <tr key={i}>
                  <td style={{ fontWeight: 700 }}>
                    {app.name}
                    {app.source === 'derived-from-ios' && (
                      <div style={{ fontSize: '10px', fontWeight: 500, color: '#a66a00' }} title={app.note}>
                        ⚠ inferred from iOS listing — not independently verified
                      </div>
                    )}
                  </td>
                  <td style={{ color: app.platform === 'Android' ? '#A4C639' : '#555' }}>
                    {app.platform === 'Android' ? '🤖 Android' : '🍏 iOS'}
                  </td>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: '11px' }}>{app.id}</td>
                  <td><span className="risk-badge rb-low">{app.status}</span></td>
                  <td>⭐ {app.rating}</td>
                  <td>
                    <button className="btn btn-gold btn-sm" onClick={() => runMobileScan(app)}>⚡ Scan App</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {selectedApp && (
        <div className="card" style={{ marginTop: '20px', borderTop: '4px solid var(--pnb-red)' }}>
          <div className="card-title">
            Scan Analysis: {selectedApp.name} ({selectedApp.platform})
          </div>
          
          {isScanning ? (
            <div style={{ textAlign: 'center', padding: '30px' }}>
              <div style={{ fontSize: '13px', color: 'var(--pnb-red)', marginBottom: '10px' }}>⏳ PERFORMING CRYPTOGRAPHIC ANALYSIS ON ENDPOINTS...</div>
              <div className="prog-bar"><div className="prog-fill pf-gold" style={{ width: '60%', transition: 'width 2s' }}></div></div>
            </div>
          ) : scanResult && (
            <div className="grid-2">
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                  <div style={{ fontWeight: 600, color: 'var(--pnb-red)', fontSize: '13px' }}>Vulnerabilities Identified</div>
                  <div style={{ fontSize: '11px', color: '#888' }}>v{scanResult.version} • {scanResult.packageSize}</div>
                </div>
                {scanResult.findings.map((f, i) => (
                  <div key={i} className="pc-finding" style={{ borderBottom: '1px solid #eee', paddingBottom: '8px', marginBottom: '8px', color: '#333' }}>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <div className={`pf-sev sev-${f.severity === 'high' || f.severity === 'critical' ? 'danger' : f.severity === 'info' ? 'safe' : 'warn'}`}></div>
                      <div>
                        <div style={{ fontWeight: 700, fontSize: '12px' }}>{f.severity === 'info' ? 'ℹ' : '⚠'} {f.issue}</div>
                        <div style={{ fontSize: '11px', color: '#444', fontWeight: 500, margin: '2px 0' }}>{f.detail}</div>
                        {f.recommendation && (
                          <div style={{ fontSize: '10px', color: '#666', fontStyle: 'italic', background: '#f9f9f9', padding: '4px', borderRadius: '4px', borderLeft: '2px solid #ccc', marginTop: '4px' }}>
                             <b>Remediation:</b> {f.recommendation}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
              <div style={{ textAlign: 'center', borderLeft: '1px solid #eee', paddingLeft: '20px' }}>
                <div style={{ fontFamily: 'var(--mono)', fontSize: '11px', color: '#888', letterSpacing: '2px' }}>MOBILE PQC SCORE</div>
                {scanResult.pqc_score === null || scanResult.pqc_score === undefined ? (
                  <>
                    <div style={{ fontSize: '40px', fontWeight: 700, color: '#888' }}>N/A</div>
                    <div className="risk-badge rb-medium" style={{ fontSize: '14px', padding: '6px 20px' }}>NOT ASSESSED</div>
                  </>
                ) : (
                  <>
                    <div style={{ fontSize: '64px', fontWeight: 700, color: scanResult.pqc_score > 70 ? '#1A8A1A' : '#C0272D' }}>{scanResult.pqc_score}</div>
                    <div className="risk-badge rb-medium" style={{ fontSize: '14px', padding: '6px 20px' }}>NEEDS TRANSITION</div>
                  </>
                )}
                <button className="btn btn-outline btn-sm" onClick={() => navigate('/remediation')} style={{ marginTop: '20px', display: 'block', width: '100%' }}>View Remediation Code</button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default MobileScanner;

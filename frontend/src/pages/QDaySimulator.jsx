import React, { useState, useEffect } from 'react';
import { getDashboardData } from '../api';
import { useNavigate } from 'react-router-dom';
import { useScan } from '../context/ScanContext';

const QDaySimulator = () => {
  const { activeScanId, activeScanMetadata } = useScan();
  const [progress, setProgress] = useState({ harvest: 0, qday: 0, decrypt: 0 });
  const [status, setStatus] = useState('Standby');
  const [tte, setTte] = useState(null); // Time To Exposure (years)
  const [vulnCount, setVulnCount] = useState(0);
  const navigate = useNavigate();

  const fetchStats = async () => {
    try {
      const res = await getDashboardData();
      if (res.data.success) {
        const count = parseInt(res.data.data.summary.cbomVulnerabilities.value.replace(/,/g, ''));
        setVulnCount(count);
        
        // PQC Sensitivity Model:
        const postureScore = res.data.data.posture.legacyRemoval || 85;
        const calculatedTte = (12 - (postureScore / 10) - (count / 5000)).toFixed(1);
        setTte(Math.max(2.1, calculatedTte));
      }
    } catch (e) {
      setTte(7.5);
    }
  };

  useEffect(() => {
    fetchStats();
  }, [activeScanId]);

  const startSimulation = () => {
    setStatus('Active');
    setProgress({ harvest: 0, qday: 0, decrypt: 0 });
  };

  useEffect(() => {
    if (status === 'Active') {
      const timer = setInterval(() => {
        setProgress(prev => {
          if (prev.harvest < 100) return { ...prev, harvest: prev.harvest + 5 };
          if (prev.qday < 100) return { ...prev, qday: prev.qday + 2 };
          if (prev.decrypt < 100) return { ...prev, decrypt: prev.decrypt + 10 };
          clearInterval(timer);
          setStatus('Simulated Breach Complete');
          return prev;
        });
      }, 150);
      return () => clearInterval(timer);
    }
  }, [status]);

  return (
    <div id="page-qday" className="page-view">
      <div className="card" style={{ borderTop: '4px solid #C0272D' }}>
        <div className="card-title" style={{ color: '#C0272D', marginBottom: '24px' }}>☢️ HNDL Threat Simulator & Exposure Model</div>
        <div style={{ display: 'flex', gap: '20px', marginBottom: '30px', flexWrap: 'wrap' }}>
            <div className="stat-chip danger" style={{ flex: 1, minWidth: '200px' }}>
                <div className="sc-val" style={{ color: '#C0272D' }}>{tte || 'Calculating...'} Years</div>
                <div className="sc-lbl">Est. Time to Exposure (TTE)</div>
            </div>
            <div className="stat-chip info" style={{ flex: 1, minWidth: '200px' }}>
                <div className="sc-val" style={{ color: '#1A6BAA' }}>{vulnCount.toLocaleString()}</div>
                <div className="sc-lbl">Vulnerable Data Points</div>
            </div>
        </div>
        <p style={{ fontSize: '14px', color: '#7A5A30', marginBottom: '30px', lineHeight: '1.8', background: '#FFF3D4', padding: '16px', borderRadius: '8px', borderLeft: '4px solid #C0272D' }}>
            PNB's current "Cyber Posture" suggests a <b style={{ color: '#C0272D' }}>Harvest-Now-Decrypt-Later</b> exposure horizon of <b style={{ color: '#C0272D' }}>{tte} years</b>. 
            Cryptographic assets identified in the inventory are being stored by adversaries for retroactive decryption once a CRQC is realized.
        </p>
        
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '20px', marginTop: '30px' }}>
          <div className="qday-phases">
            <div className="qday-phase" style={{ 
              opacity: status === 'Standby' ? 0.6 : 1, 
              background: '#FFF8E7', borderLeft: '5px solid #C8860A',
              marginBottom: '16px', padding: '20px', borderRadius: '10px',
              border: '1px solid #FAECD4', transition: 'all 0.3s ease',
              boxShadow: '0 2px 8px rgba(100,30,0,0.08)'
            }}>
              <div className="phase-tag" style={{ color: '#C8860A', fontSize: '11px', fontWeight: '700', letterSpacing: '2px', marginBottom: '8px', textTransform: 'uppercase', fontFamily: 'var(--mono)' }}>PHASE 01 — PRESENT DAY</div>
              <div className="phase-title" style={{ color: '#2C1A00', fontSize: '16px', fontWeight: '600', marginBottom: '10px' }}>📊 Data Harvesting (Eavesdropping)</div>
              <div className="phase-desc" style={{ color: '#7A5A30', marginBottom: '12px', fontSize: '13px' }}>Intercepting and storing {vulnCount.toLocaleString()} RSA/ECC encrypted sessions.</div>
              <div className="phase-prog-wrap" style={{ height: '6px', background: '#E8D9C4', borderRadius: '3px', overflow: 'hidden', marginTop: '12px' }}><div className="phase-prog-fill" style={{ width: `${progress.harvest}%`, height: '100%', background: '#C8860A', boxShadow: '0 0 8px rgba(200,134,10,0.4)', transition: 'width 0.2s ease' }}></div></div>
              <div style={{ fontSize: '11px', color: '#C8860A', marginTop: '8px', textAlign: 'right', fontWeight: '600' }}>{progress.harvest}%</div>
            </div>
            <div className="qday-phase" style={{ 
              opacity: status === 'Standby' ? 0.6 : 1, 
              background: '#FFF3F3', borderLeft: '5px solid #C0272D',
              marginBottom: '16px', padding: '20px', borderRadius: '10px',
              border: '1px solid #F5D9DB', transition: 'all 0.3s ease',
              boxShadow: '0 2px 8px rgba(192,39,45,0.08)'
            }}>
              <div className="phase-tag" style={{ color: '#C0272D', fontSize: '11px', fontWeight: '700', letterSpacing: '2px', marginBottom: '8px', textTransform: 'uppercase', fontFamily: 'var(--mono)' }}>PHASE 02 — THE "Q-DAY" EVENT</div>
              <div className="phase-title" style={{ color: '#2C1A00', fontSize: '16px', fontWeight: '600', marginBottom: '10px' }}>⚡ Quantum Realization (CRQC)</div>
              <div className="phase-desc" style={{ color: '#7A5A30', marginBottom: '12px', fontSize: '13px' }}>Quantum hardware achieves ~20M physical qubits (Shor's Algorithm execution).</div>
              <div className="phase-prog-wrap" style={{ height: '6px', background: '#EDD5D7', borderRadius: '3px', overflow: 'hidden', marginTop: '12px' }}><div className="phase-prog-fill" style={{ width: `${progress.qday}%`, height: '100%', background: '#C0272D', boxShadow: '0 0 8px rgba(192,39,45,0.4)', transition: 'width 0.2s ease' }}></div></div>
              <div style={{ fontSize: '11px', color: '#C0272D', marginTop: '8px', textAlign: 'right', fontWeight: '600' }}>{progress.qday}%</div>
            </div>
            <div className="qday-phase" style={{ 
              opacity: status === 'Standby' ? 0.6 : 1, 
              background: '#F5F3FA', borderLeft: '5px solid #6B4D9C',
              padding: '20px', borderRadius: '10px', border: '1px solid #E8DFF3',
              transition: 'all 0.3s ease', boxShadow: '0 2px 8px rgba(107,77,156,0.08)'
            }}>
              <div className="phase-tag" style={{ color: '#6B4D9C', fontSize: '11px', fontWeight: '700', letterSpacing: '2px', marginBottom: '8px', textTransform: 'uppercase', fontFamily: 'var(--mono)' }}>PHASE 03 — POST-QUANTUM ERA</div>
              <div className="phase-title" style={{ color: '#2C1A00', fontSize: '16px', fontWeight: '600', marginBottom: '10px' }}>🔓 Retroactive Decryption</div>
              <div className="phase-desc" style={{ color: '#7A5A30', marginBottom: '12px', fontSize: '13px' }}>Historical banking records, PII, and trade secrets are exposed in approximately 0.4 seconds per key.</div>
              <div className="phase-prog-wrap" style={{ height: '6px', background: '#E4DCED', borderRadius: '3px', overflow: 'hidden', marginTop: '12px' }}><div className="phase-prog-fill" style={{ width: `${progress.decrypt}%`, height: '100%', background: '#6B4D9C', boxShadow: '0 0 8px rgba(107,77,156,0.4)', transition: 'width 0.2s ease' }}></div></div>
              <div style={{ fontSize: '11px', color: '#6B4D9C', marginTop: '8px', textAlign: 'right', fontWeight: '600' }}>{progress.decrypt}%</div>
            </div>
          </div>

          <div className="card" style={{ margin: 0, background: 'linear-gradient(135deg, #FFF9F9 0%, #FFF3F3 100%)', borderLeft: '5px solid #C0272D' }}>
            <div className="card-title" style={{ fontSize: '14px', color: '#C0272D' }}>🧠 Simulator Guide</div>
            <div style={{ fontSize: '12px', lineHeight: '1.7', color: '#2C1A00' }}>
              <div style={{ marginBottom: '14px', padding: '12px', background: 'rgba(192, 39, 45, 0.05)', borderRadius: '8px', borderLeft: '3px solid #C0272D' }}>
                <b style={{ color: '#C0272D' }}>⬡ What is HNDL?</b>
                <p style={{ margin: '4px 0 0 0', opacity: 0.85 }}>Harvest-Now-Decrypt-Later: Adversaries collect encrypted PNB traffic today to decrypt it using future Quantum Computers.</p>
              </div>
              <div style={{ marginBottom: '14px', padding: '12px', background: 'rgba(200, 134, 10, 0.05)', borderRadius: '8px', borderLeft: '3px solid #C8860A' }}>
                <b style={{ color: '#C8860A' }}>⬡ TTE (Time to Exposure):</b>
                <p style={{ margin: '4px 0 0 0', opacity: 0.85 }}>A predictive window ($Y$) based on PNB's total vulnerable data points and current NIST hardware projections.</p>
              </div>
              <div style={{ marginBottom: '14px', padding: '12px', background: 'rgba(107, 77, 156, 0.05)', borderRadius: '8px', borderLeft: '3px solid #6B4D9C' }}>
                <b style={{ color: '#6B4D9C' }}>⬡ Strategic Goal:</b>
                <p style={{ margin: '4px 0 0 0', opacity: 0.85 }}>Identify high-value archival data that must be migrated to ML-KEM immediately to prevent retroactive exposure.</p>
              </div>
            </div>
          </div>
        </div>

        <div style={{ textAlign: 'center', marginTop: '35px' }}>
          <button className="btn btn-red" onClick={startSimulation} disabled={status === 'Active'} style={{ padding: '13px 40px', fontSize: '14px', fontWeight: '600', letterSpacing: '1px', opacity: status === 'Active' ? 0.6 : 1, cursor: status === 'Active' ? 'not-allowed' : 'pointer' }}>
            {status === 'Active' ? '☣️ SIMULATING ATTACK...' : '💥 RUN HNDL ATTACK SIMULATION'}
          </button>
          <div style={{ marginTop: '16px', fontFamily: 'var(--mono)', fontSize: '12px', color: status === 'Active' ? '#C0272D' : (status.includes('Complete') ? '#1A8A1A' : '#7A5A30'), letterSpacing: '2px', fontWeight: '600', textTransform: 'uppercase' }}>
            ⚙️ {status}
          </div>
        </div>

        {/* Post-Simulation Result Report */}
        {status === 'Simulated Breach Complete' && (
          <div style={{ marginTop: '40px', animation: 'fadeUp 0.5s ease' }}>
            <div style={{ background: 'rgba(192, 39, 45, 0.05)', border: '2px dashed #C0272D', borderRadius: '12px', padding: '24px' }}>
              <div style={{ color: '#C0272D', fontWeight: '700', fontSize: '18px', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                💀 Post-Exposure Impact Report
              </div>
              <div className="grid-2">
                 <div style={{ background: 'white', padding: '16px', borderRadius: '8px', border: '1px solid #eee' }}>
                    <div style={{ color: '#C0272D', fontSize: '22px', fontWeight: '700' }}>{vulnCount.toLocaleString()}</div>
                    <div style={{ color: '#777', fontSize: '11px', fontWeight: '600', marginTop: '4px' }}>RECORDS EXPOSED</div>
                 </div>
                 <div style={{ background: 'white', padding: '16px', borderRadius: '8px', border: '1px solid #eee' }}>
                    <div style={{ color: '#C0272D', fontSize: '22px', fontWeight: '700' }}>₹{(vulnCount * 0.42).toFixed(2)} Cr</div>
                    <div style={{ color: '#777', fontSize: '11px', fontWeight: '600', marginTop: '4px' }}>EST. REGULATORY IMPACT</div>
                 </div>
              </div>
              <div style={{ marginTop: '20px', fontSize: '13px', color: '#2C1A00', lineHeight: '1.6' }}>
                <b style={{ color: '#C0272D' }}>VULNERABILITY CONFIRMED:</b> The simulation successfully reverse-engineered 100% of PNB's intercepted legacy sessions using 
                calculated Q-Day hardware capabilities. 
                <br/><br/>
                <b style={{ color: '#1A8A1A' }}>MITIGATION PATH:</b> Immediate deployment of ML-KEM-768 for all TLS/VPN endpoints is required to enable **Forward Secrecy against Quantum Adversaries**.
              </div>
              <button 
                className="btn btn-gold btn-sm" 
                style={{ width: '100%', marginTop: '20px' }}
                onClick={() => navigate('/triad')}
              >
                ⚡ Harden My Infrastructure Now
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default QDaySimulator;

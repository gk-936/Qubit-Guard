import React from 'react';
import { useScan } from '../context/ScanContext';

const History = () => {
    const { history, switchScan, activeScanId, fetchHistory } = useScan();

    const formatDate = (iso) => {
        const d = new Date(iso);
        return d.toLocaleString();
    };

    return (
        <div className="page-view animate-fade-in">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <h2 style={{ margin: 0, fontSize: '20px', fontWeight: 800, color: '#fff', fontFamily: 'var(--disp)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className="ct-icon">📜</span> 
                    Scan Execution History
                </h2>
                <button 
                  onClick={fetchHistory} 
                  className="btn btn-sm" 
                  style={{ fontSize: '11px', background: 'rgba(255,255,255,0.1)', color: '#fff', border: '1px solid rgba(255,255,255,0.3)' }}
                >
                  🔄 Refresh
                </button>
            </div>

            <div className="card" style={{ padding: 0 }}>
                <table className="data-table">
                    <thead>
                        <tr>
                            <th>Scan ID</th>
                            <th>Target Domain</th>
                            <th>QVS Score</th>
                            <th>Timestamp</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {history.length > 0 ? (
                            history.map((s) => (
                                <tr key={s.id} className={activeScanId === s.id ? 'active-row' : ''}>
                                    <td style={{ fontFamily: 'var(--mono)', fontSize: '11px' }}>{s.id}</td>
                                    <td><strong>{s.target}</strong></td>
                                    <td>
                                        <span className={`risk-badge ${s.qvs > 80 ? 'rb-critical' : s.qvs > 50 ? 'rb-high' : 'rb-low'}`}>
                                            {s.qvs} QVS
                                        </span>
                                    </td>
                                    <td>{formatDate(s.timestamp)}</td>
                                    <td>
                                        {activeScanId === s.id ? (
                                            <button className="btn btn-sm btn-red" onClick={() => switchScan('')}>
                                                Clear Active
                                            </button>
                                        ) : (
                                            <button className="btn btn-sm btn-gold" onClick={() => {
                                                switchScan(s.id);
                                            }}>
                                                Activate Context
                                            </button>
                                        )}
                                    </td>
                                </tr>
                            ))
                        ) : (
                            <tr>
                                <td colSpan="5" style={{ textAlign: 'center', padding: '40px', color: 'var(--text-dim)' }}>
                                    No scans found in persistence layer.
                                </td>
                            </tr>
                        )}
                    </tbody>
                </table>
            </div>

            <style>{`
                .active-row {
                    background: rgba(212, 160, 23, 0.05);
                }
                .active-row td {
                    border-bottom: 2px solid var(--pnb-gold);
                }
            `}</style>
        </div>
    );
};

export default History;

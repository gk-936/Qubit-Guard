import React from 'react';
import { useScan } from '../context/ScanContext';

const Header = ({ title, onLogout }) => {
  const { activeScanMetadata, isHistoryMode, switchScan } = useScan();
  return (
    <div id="topbar">
      <div className="tb-page-title">{title}</div>
      <div className="tb-logo">
        <svg className="tb-logo-shield" viewBox="0 0 60 70" fill="none">
          <path d="M30 4L56 14V36C56 52 44 63 30 68C16 63 4 52 4 36V14L30 4Z" fill="url(#ts)" stroke="#D4A017" strokeWidth="1.5" />
          <defs><linearGradient id="ts" x1="0" y1="0" x2="60" y2="70" gradientUnits="userSpaceOnUse"><stop stopColor="#8B1A1A" /><stop offset="1" stopColor="#4B0A0A" /></linearGradient></defs>
          <text x="30" y="40" fontFamily="Cinzel,serif" fontSize="13" fill="#D4A017" fontWeight="700" textAnchor="middle">QG</text>
          <text x="30" y="52" fontFamily="sans-serif" fontSize="5" fill="rgba(255,255,255,0.7)" textAnchor="middle">PQC-Ready</text>
        </svg>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
        {isHistoryMode && activeScanMetadata && (
          <div className="history-banner" onClick={() => switchScan('')}>
            <span style={{ fontSize: '12px' }}>📅 VIEWING SCAN: <strong>{new Date(activeScanMetadata.timestamp).toLocaleDateString()}</strong></span>
            <span style={{ opacity: 0.7 }}>By {activeScanMetadata.user}</span>
            <span className="close-banner">✖</span>
          </div>
        )}
        <div className="tb-welcome">User: <span>admin</span></div>
        <button onClick={onLogout} className="btn btn-outline btn-sm" style={{ borderColor: 'rgba(255,255,255,0.3)', color: 'white', padding: '4px 8px' }}>Logout</button>
      </div>

      <style>{`
        .history-banner {
          background: rgba(192, 39, 45, 0.9);
          padding: 4px 12px;
          border-radius: 4px;
          color: white;
          font-family: var(--mono);
          display: flex;
          align-items: center;
          gap: 10px;
          cursor: pointer;
          border: 1px solid #C0272D;
          transition: all 0.2s;
        }
        .history-banner:hover {
          background: #C0272D;
          transform: scale(1.02);
        }
        .close-banner {
          font-size: 10px;
          background: rgba(0,0,0,0.2);
          width: 16px;
          height: 16px;
          display: flex;
          align-items: center;
          justify-content: center;
          border-radius: 50%;
        }
      `}</style>
    </div>
  );
};

export default Header;

import React, { useEffect, useState } from 'react';
import { useScan } from '../context/ScanContext';

const Header = ({ title, sidebarOpen, onToggleSidebar, showLastScan }) => {
  const { activeScanMetadata, isHistoryMode, switchScan } = useScan();
  const [now, setNow] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 30000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div id="topbar">
      <div className={`tb-left ${sidebarOpen ? 'shifted' : ''}`}>
        <button
          type="button"
          className={`sidebar-toggle ${sidebarOpen ? 'open' : ''}`}
          aria-label={sidebarOpen ? 'Close menu' : 'Open menu'}
          aria-expanded={sidebarOpen}
          onClick={onToggleSidebar}
        >
          <span></span>
          <span></span>
          <span></span>
        </button>
        <div className="tb-page-title">{title}</div>
      </div>

      <div className="tb-logo">
        <svg className="tb-logo-shield" viewBox="0 0 60 70" fill="none">
          <path d="M30 4L56 14V36C56 52 44 63 30 68C16 63 4 52 4 36V14L30 4Z" fill="url(#ts)" stroke="#D4A017" strokeWidth="1.5" />
          <defs><linearGradient id="ts" x1="0" y1="0" x2="60" y2="70" gradientUnits="userSpaceOnUse"><stop stopColor="#8B1A1A" /><stop offset="1" stopColor="#4B0A0A" /></linearGradient></defs>
          <text x="30" y="40" fontFamily="Cinzel,serif" fontSize="13" fill="#D4A017" fontWeight="700" textAnchor="middle">QG</text>
          <text x="30" y="52" fontFamily="sans-serif" fontSize="5" fill="rgba(255,255,255,0.7)" textAnchor="middle">PQC-Ready</text>
        </svg>
      </div>

      <div className="tb-right">
        {showLastScan && isHistoryMode && activeScanMetadata && (
          <div className="history-banner" onClick={() => switchScan('')}>
            <span style={{ fontSize: '12px' }}>Last Scan: <strong>{new Date(activeScanMetadata.timestamp).toLocaleDateString()}</strong></span>
            <span className="close-banner">&times;</span>
          </div>
        )}
        <div className="tb-datetime">
          {now.toLocaleDateString('en-GB')} &middot; {now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
        </div>
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

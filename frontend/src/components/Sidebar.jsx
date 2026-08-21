import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { useScan } from '../context/ScanContext';

const Sidebar = ({ isOpen, onNavigate, onLogout }) => {
  const { resetAudit, activeScanMetadata } = useScan();
  const navigate = useNavigate();

  const handleNewAudit = () => {
    resetAudit();
    navigate('/dashboard');
    onNavigate?.();
  };
  const menuItems = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'inventory', label: 'Asset Inventory' },
    { id: 'discovery', label: 'Asset Discovery' },
    { id: 'cbom', label: 'CBOM' },
    { id: 'posture', label: 'Posture of PQC' },
    { id: 'rating', label: 'Cyber Rating' },
    { id: 'reporting', label: 'Reporting' },
    { id: 'triad', label: 'Triad Scanner', badge: 'NEW' },
    { id: 'history', label: 'Scan History' },
    { id: 'mobile', label: 'Mobile App Scanning' },
    { id: 'remediation', label: 'Auto-Remediation' },
    { id: 'qday', label: 'Q-Day Simulator' },
    { id: 'pqc-selector', label: 'PQC Selector', badge: 'RULES' },
  ];

  return (
    <div id="sidebar" className={isOpen ? 'open' : ''}>
      <div className="sb-logo-area" style={{ padding: '12px', gap: '8px' }}>
        <svg className="sb-shield" viewBox="0 0 60 70" fill="none" style={{ width: '32px', height: '32px' }}>
          <path d="M30 4L56 14V36C56 52 44 63 30 68C16 63 4 52 4 36V14L30 4Z" fill="url(#ss)" stroke="#D4A017" strokeWidth="1.5" />
          <defs><linearGradient id="ss" x1="0" y1="0" x2="60" y2="70" gradientUnits="userSpaceOnUse"><stop stopColor="#7B1A1A" /><stop offset="1" stopColor="#5B0A0A" /></linearGradient></defs>
          <text x="30" y="40" fontFamily="Cinzel,serif" fontSize="13" fill="#D4A017" fontWeight="700" textAnchor="middle">QG</text>
          <text x="30" y="52" fontFamily="sans-serif" fontSize="5" fill="rgba(255,255,255,0.7)" textAnchor="middle">PQC-Ready</text>
        </svg>
        <div className="sb-brand">Qubit-Guard Platform</div>
      </div>

      <div style={{ padding: '0 12px 12px 12px' }}>
        <button
          onClick={handleNewAudit}
          style={{
            width: '100%',
            padding: '10px',
            background: 'linear-gradient(90deg, #D4A017 0%, #B8860B 100%)',
            border: 'none',
            borderRadius: '6px',
            color: 'white',
            fontWeight: '700',
            fontSize: '12px',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '8px',
            boxShadow: '0 4px 10px rgba(212, 160, 23, 0.3)',
            transition: 'all 0.2s ease'
          }}
          onMouseOver={(e) => e.target.style.transform = 'translateY(-1px)'}
          onMouseOut={(e) => e.target.style.transform = 'none'}
        >
          AUDIT NEW BANK
        </button>
      </div>

      <div className="sb-nav">
        {menuItems.map((item) => (
          <NavLink
            key={item.id}
            to={`/${item.id}`}
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            onClick={onNavigate}
          >
            <span className="ni-label">{item.label}</span>
            {item.badge && <span className="ni-badge">{item.badge}</span>}
          </NavLink>
        ))}
      </div>
      <div className="sb-footer">
        <div className="sb-user">auditor@qubitguard.ai</div>
        <div className="sb-user" style={{ marginTop: '4px' }}>Role: Security Admin</div>
        <button onClick={onLogout} className="sb-logout-btn">Logout</button>
      </div>
    </div>
  );
};

export default Sidebar;

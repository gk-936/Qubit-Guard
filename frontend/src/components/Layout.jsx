import { useEffect, useState } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import Sidebar from './Sidebar';
import Header from './Header';

const Layout = ({ onLogout }) => {
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  useEffect(() => {
    setSidebarOpen(false);
  }, [location.pathname]);

  const pageTitles = {
    '/dashboard': 'Home Dashboard',
    '/inventory': 'Asset Inventory',
    '/discovery': 'Asset Discovery',
    '/cbom': 'CBOM (Crypto Bill of Materials)',
    '/posture': 'Posture of PQC',
    '/rating': 'Cyber Rating',
    '/reporting': 'Reporting & Automation',
    '/triad': 'Triad PQC Scanner',
    '/remediation': 'AI Auto-Remediation',
    '/qday': 'Q-Day HNDL Simulator',
    '/mobile': 'Mobile App Scanning'
  };

  const currentTitle = pageTitles[location.pathname] || 'Qubit-Guard Platform';

  return (
    <div id="app">
      <div className="hk-bg"></div>
      <Sidebar isOpen={sidebarOpen} onNavigate={() => setSidebarOpen(false)} onLogout={onLogout} />
      {sidebarOpen && <div className="sidebar-backdrop" onClick={() => setSidebarOpen(false)}></div>}
      <div id="main">
        <Header
          title={currentTitle}
          onLogout={onLogout}
          sidebarOpen={sidebarOpen}
          onToggleSidebar={() => setSidebarOpen((open) => !open)}
          showLastScan={location.pathname === '/triad'}
        />
        <div id="content">
          <Outlet />
        </div>
      </div>
    </div>
  );
};

export default Layout;

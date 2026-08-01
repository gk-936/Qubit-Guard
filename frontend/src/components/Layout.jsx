import { Outlet, useLocation } from 'react-router-dom';
import Sidebar from './Sidebar';
import Header from './Header';

const Layout = ({ onLogout }) => {
  const location = useLocation();
  
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
      <Sidebar />
      <div id="main">
        <Header title={currentTitle} onLogout={onLogout} />
        <div id="content">
          <Outlet />
        </div>
        <div id="footer-bar">
          <span>{new Date().toLocaleDateString('en-GB')}</span>
          <span>Qubit-Guard Platform</span>
          <span>v1.0</span>
        </div>
      </div>
    </div>
  );
};

export default Layout;

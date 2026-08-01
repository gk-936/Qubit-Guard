import React, { useState, useEffect } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Layout from './components/Layout';
import ProtectedRoute from './components/ProtectedRoute';
import Home from './pages/Home';
import Inventory from './pages/Inventory';
import Discovery from './pages/Discovery';
import CBOM from './pages/CBOM';
import Posture from './pages/Posture';
import Rating from './pages/Rating';
import Reporting from './pages/Reporting';
import TriadScanner from './pages/TriadScanner';
import Remediation from './pages/Remediation';
import QDaySimulator from './pages/QDaySimulator';
import MobileScanner from './pages/MobileScanner';
import PQCSelector from './pages/PQCSelector';
import History from './pages/History';
import OwaspAudit from './pages/OwaspAudit';
import { ScanProvider } from './context/ScanContext';
import { ToastProvider } from './context/ToastContext';
import { login, verifyToken } from './api';
import './index.css';

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(!!localStorage.getItem('pnc_token'));
  const [user, setUser] = useState(null);
  const [verifying, setVerifying] = useState(true);

  useEffect(() => {
    document.title = "Qubit-Guard Platform";
  }, []);

  useEffect(() => {
    const checkAuth = async () => {
      const token = localStorage.getItem('pnc_token');
      if (token) {
        try {
          const res = await verifyToken();
          if (res.data.success) {
            setUser(res.data.user);
            setIsLoggedIn(true);
          } else {
            handleLogout();
          }
        } catch (err) {
          console.error("Auth verification failed:", err);
          handleLogout();
        }
      }
      setVerifying(false);
    };
    
    // Add small delay to avoid UI flicker
    const timeout = setTimeout(() => {
      if (verifying) setVerifying(false);
    }, 4000); 

    checkAuth();
    return () => clearTimeout(timeout);
  }, []);

  const handleLogin = async (username, password) => {
    try {
      const res = await login({ username, password });
      if (res.data.success) {
        localStorage.setItem('pnc_token', res.data.token);
        setUser(res.data.user);
        setIsLoggedIn(true);
      }
    } catch (err) {
      alert('Login Failed: ' + (err.response?.data?.message || 'Invalid credentials'));
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('pnc_token');
    setUser(null);
    setIsLoggedIn(false);
  };

  const Login = () => {
    const [u, setU] = useState('admin');
    const [p, setP] = useState('pnb_password_2026');
    const [showP, setShowP] = useState(false);

    return (
      <div id="login-page">
        <div className="hk-bg"></div>
        <div className="login-box">
          <div className="login-logo">
            <div className="shield-logo">
              <svg className="shield-svg" viewBox="0 0 80 90" fill="none">
                <path d="M40 5L75 18V45C75 64 58 80 40 88C22 80 5 64 5 45V18L40 5Z" fill="url(#sg)" stroke="#D4A017" strokeWidth="2"/>
                <defs><linearGradient id="sg" x1="0" y1="0" x2="80" y2="90" gradientUnits="userSpaceOnUse"><stop stopColor="#8B1A1A"/><stop offset="1" stopColor="#6B0F0F"/></linearGradient></defs>
                <text x="40" y="52" fontFamily="Cinzel,serif" fontSize="18" fill="#D4A017" fontWeight="700" textAnchor="middle">QG</text>
                <text x="40" y="66" fontFamily="Exo 2,sans-serif" fontSize="7" fill="rgba(255,255,255,0.8)" textAnchor="middle" letterSpacing="1">PQC-Ready</text>
                <circle cx="40" cy="30" r="10" fill="none" stroke="#D4A017" strokeWidth="1.5" strokeDasharray="3 2"/>
                <path d="M34 30L38 34L47 25" stroke="#D4A017" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
            <div className="login-title">Qubit-Guard Platform</div>
          </div>
          <label className="login-label">Username</label>
          <input className="login-input" type="text" value={u} onChange={(e) => setU(e.target.value)} />
          <label className="login-label">Password</label>
          <div style={{ position: 'relative' }}>
            <input className="login-input" type={showP ? "text" : "password"} value={p} onChange={(e) => setP(e.target.value)} />
            <span 
              onClick={() => setShowP(!showP)} 
              style={{ position: 'absolute', right: '10px', top: '10px', cursor: 'pointer', fontSize: '14px', color: '#D4A017' }}
            >
              {showP ? '👁️' : '🔒'}
            </span>
          </div>
          <span className="login-forgot">Forgot Password?</span>
          <button className="login-btn" onClick={() => handleLogin(u, p)}>Sign In</button>
        </div>
        <div className="login-right">
          <div style={{ fontSize: '16px', opacity: 0.8, marginBottom: '6px' }}>Advanced Quantum Cryptographic Audit</div>
          <h1>Universal Unified<br/>Security Auditor</h1>
          <h2 style={{ marginTop: '12px' }}>Next-Gen PQC Protection</h2>
        </div>
      </div>
    );
  };

  if (verifying) return <div className="hk-bg" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', color: 'white', fontFamily: 'var(--mono)' }}>Authenticating...</div>;

  return (
    <ToastProvider>
      <ScanProvider>
        <Routes>
          <Route path="/login" element={isLoggedIn ? <Navigate to="/" replace /> : <Login />} />
          <Route path="/" element={<ProtectedRoute isLoggedIn={isLoggedIn}><Layout onLogout={handleLogout} /></ProtectedRoute>}>
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="dashboard" element={<Home />} />
            <Route path="inventory" element={<Inventory />} />
            <Route path="discovery" element={<Discovery />} />
            <Route path="cbom" element={<CBOM />} />
            <Route path="posture" element={<Posture />} />
            <Route path="rating" element={<Rating />} />
            <Route path="reporting" element={<Reporting />} />
            <Route path="triad" element={<TriadScanner />} />
            <Route path="remediation" element={<Remediation />} />
            <Route path="qday" element={<QDaySimulator />} />
            <Route path="mobile" element={<MobileScanner />} />
            <Route path="pqc-selector" element={<PQCSelector />} />
            <Route path="history" element={<History />} />
            <Route path="owasp-audit" element={<OwaspAudit />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </ScanProvider>
    </ToastProvider>
  );
}

export default App;

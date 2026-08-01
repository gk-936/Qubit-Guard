import React, { createContext, useContext, useState, useEffect } from 'react';
import { getScanHistory, getScanById } from '../api';

const ScanContext = createContext();

export const ScanProvider = ({ children, isLoggedIn }) => {
  const [activeScanId, setActiveScanId] = useState(localStorage.getItem('active_scan_id') || '');
  const [activeScanMetadata, setActiveScanMetadata] = useState(null);
  const [activeData, setActiveData] = useState(null);
  const [history, setHistory] = useState([]);
  const [pendingScan, setPendingScan] = useState(null);
  const [discoveryResults, setDiscoveryResults] = useState(null);

  // Fetch history on load
  const fetchHistory = async () => {
    try {
      const res = await getScanHistory();
      if (res.data.success) {
        setHistory(res.data.data);
      }
    } catch (err) {
      console.error('Failed to fetch history:', err);
    }
  };

  const fetchScanDetail = async (id) => {
    if (!id) return;
    try {
      const res = await getScanById(id);
      if (res.data.success) {
        setActiveData(res.data.data);
        setActiveScanMetadata({
          id: res.data.data.id,
          target: res.data.data.webUrl,
          timestamp: res.data.data.timestamp,
        });
      }
    } catch (err) {
      console.error('Failed to fetch scan detail:', err);
    }
  };

  useEffect(() => {
    // Skip entirely when logged out — these are authenticated endpoints, and
    // firing them anyway just produces a guaranteed 401 on every mount
    // (including the login page itself) for no benefit.
    //
    // `isLoggedIn` must be in the dependency array, not just checked inline:
    // ScanProvider mounts once at the top of the app (wrapping both the
    // login route and the main routes), before any login has happened, so
    // on a fresh login (no page reload) this effect would otherwise never
    // re-run and history/activeData would silently stay empty until the
    // user manually hit "Refresh" on the History page.
    if (!isLoggedIn || !localStorage.getItem('pnc_token')) return;
    fetchHistory();
    if (activeScanId) {
      fetchScanDetail(activeScanId);
    }
  }, [activeScanId, isLoggedIn]);

  const switchScan = (id) => {
    setActiveScanId(id);
    if (id) {
      localStorage.setItem('active_scan_id', id);
    } else {
      localStorage.removeItem('active_scan_id');
      setActiveScanMetadata(null);
      setActiveData(null);
      setDiscoveryResults(null); 
      setPendingScan(null);
    }
  };

  const resetAudit = () => {
    switchScan(null);
  };

  return (
    <ScanContext.Provider value={{
      activeScanId,
      activeScanMetadata,
      activeData,
      setActiveData,
      history,
      switchScan,
      resetAudit,
      fetchHistory,
      pendingScan,
      setPendingScan,
      discoveryResults,
      setDiscoveryResults,
      isHistoryMode: !!activeScanId
    }}>
      {children}
    </ScanContext.Provider>
  );
};

export const useScan = () => useContext(ScanContext);

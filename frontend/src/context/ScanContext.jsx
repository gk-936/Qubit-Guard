import React, { createContext, useContext, useState, useEffect } from 'react';
import { getScanHistory, getScanById } from '../api';

const ScanContext = createContext();

export const ScanProvider = ({ children }) => {
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
    fetchHistory();
    if (activeScanId) {
      fetchScanDetail(activeScanId);
    }
  }, [activeScanId]);

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

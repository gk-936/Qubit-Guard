import axios from 'axios';

const API_BASE_URL = '/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 60000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add scan ID context
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('pnc_token');
  if (token) {
    config.headers.Authorization = token;
  }
  const activeScanId = localStorage.getItem('active_scan_id');
  if (activeScanId) {
    config.headers['X-Scan-Id'] = activeScanId;
  }
  return config;
}, (error) => {
  return Promise.reject(error);
});

// The backend now rejects unauthenticated requests, so an expired session must send
// the user back to login rather than failing silently on every page. Two cases must
// NOT trigger a reload, or every page that fetches data before login (e.g. ScanContext
// loading scan history on mount) would 401, reload, remount, re-fetch, 401 again — an
// infinite reload loop:
//   1. Login itself — a 401 there is a wrong password, not an expired session.
//   2. Any request that never carried a token in the first place — that's just an
//      anonymous call made before the user is logged in, not a session that expired.
// Only a request that DID send a token and got rejected anyway means the session is
// genuinely dead and the user needs to be sent back to login.
api.interceptors.response.use(
  (response) => response,
  (error) => {
    const isLoginCall = (error.config?.url || '').includes('/auth/login');
    const hadToken = !!error.config?.headers?.Authorization;
    if (error.response?.status === 401 && !isLoginCall && hadToken) {
      localStorage.removeItem('pnc_token');
      localStorage.removeItem('active_scan_id');
      window.location.reload();
    }
    return Promise.reject(error);
  }
);

export const checkHealth = () => api.get('/health');

// A Triad scan runs several real, sequential network probes per pillar (TLS
// handshakes, IKE port checks, HTTP HEAD requests) — on a target with a closed
// or filtered VPN/firmware/archival surface, each probe can legitimately run
// its full multi-second timeout rather than fail fast, so total scan time
// varies a lot by target and can exceed the 60s default used elsewhere.
// Only this call gets the longer timeout so a genuinely broken/hanging
// endpoint elsewhere still fails fast for the user.
export const runTriadScan = (data) => api.post('/scan/triad', data, { timeout: 180000 });
export const getScanHistory = () => api.get('/scan/history');
export const getScanById = (id) => api.get(`/scan/${id}`);

export const analyzeVulnerabilities = (data) => api.post('/analyze', { data });

export const createSchedule = (data) => api.post('/scheduler/create', data);

export const listSchedules = () => api.get('/scheduler/list');

export const searchMobileApps = (query) => api.get('/mobile/search', { params: { query } });

export const scanMobileApp = (data) => api.post('/mobile/scan', data);

export const getDashboardData = () => api.get('/data/dashboard');
export const getInventoryData = () => api.get('/data/inventory');
export const deleteInventoryItem = (purl) => api.delete(`/data/inventory/${encodeURIComponent(purl)}`);
export const getCbomData = () => api.get('/data/cbom');
export const getRemediationData = () => api.get('/data/remediation');

export const login = (credentials) => api.post('/auth/login', credentials);
export const verifyToken = () => api.get('/auth/verify');

export const generateRemediation = (findings) => api.post('/remediation/generate', { findings });

export const chatWithExpert = (message, history) => api.post('/remediation/chat', { message, history });
export const sendEmailReport = (data) => api.post('/data/report/send', data);
export const addInventoryItem = (data) => api.post('/inventory/add', data);

// File downloads must go through the authenticated axios instance — a plain
// window.open() cannot attach the Authorization header, so it would 401.
export const exportCbom = (fmt) => api.get(`/data/cbom/export/${fmt}`, { responseType: 'blob' });
export const downloadReportPdf = (type) =>
  api.get('/data/report/download-pdf', { params: { type }, responseType: 'blob' });

export const saveBlob = (blob, filename) => {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
};

export const selectPQCAlgorithm = (metadata) => api.post('/pqc/select', metadata);
export const getPQCAlgorithms = () => api.get('/pqc/algorithms');
export const getPQCAudit = () => api.get('/pqc/audit');

export default api;

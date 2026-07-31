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

// The backend now rejects unauthenticated requests, so an expired token must send
// the user back to login rather than failing silently on every page. Login itself
// is excluded — a 401 there is a wrong password, not an expired session.
api.interceptors.response.use(
  (response) => response,
  (error) => {
    const isLoginCall = (error.config?.url || '').includes('/auth/login');
    if (error.response?.status === 401 && !isLoginCall) {
      localStorage.removeItem('pnc_token');
      localStorage.removeItem('active_scan_id');
      window.location.reload();
    }
    return Promise.reject(error);
  }
);

export const checkHealth = () => api.get('/health');

export const runTriadScan = (data) => api.post('/scan/triad', data);

export const analyzeVulnerabilities = (data) => api.post('/analyze', { data });

export const createSchedule = (data) => api.post('/scheduler/create', data);

export const listSchedules = () => api.get('/scheduler/list');

export const searchMobileApps = (query) => api.get('/mobile/search', { params: { query } });

export const scanMobileApp = (data) => api.post('/mobile/scan', data);

export const getDashboardData = () => api.get('/data/dashboard');
export const getInventoryData = () => api.get('/data/inventory');
export const deleteInventoryItem = (purl) => api.delete(`/data/inventory/${encodeURIComponent(purl)}`);
export const getCbomData = () => api.get('/data/cbom');

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

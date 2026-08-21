import React, { useState } from 'react';
import { sendEmailReport, createSchedule, downloadReportPdf, exportCanonicalReport, saveBlob } from '../api';
import { useScan } from '../context/ScanContext';
import { useToast } from '../context/ToastContext';

const Reporting = () => {
  const { activeScanId, activeScanMetadata } = useScan();
  const { showToast } = useToast();
  const [reportType, setReportType] = useState('executive');
  const [isScheduled, setIsScheduled] = useState(false);
  const [email, setEmail] = useState('');
  const [scheduledTime, setScheduledTime] = useState('09:00');
  const [scheduledEmail, setScheduledEmail] = useState('');
  const [frequency, setFrequency] = useState('daily');
  const [sending, setSending] = useState(false);
  const [formats, setFormats] = useState({ pdf: true, excel: false, json: false, xml: false });
  const [exporting, setExporting] = useState(null);

  const handleExportCanonical = async (fmt) => {
    setExporting(fmt);
    try {
      const res = await exportCanonicalReport(fmt, activeScanId || undefined);
      saveBlob(res.data, `qubit-guard-report-${activeScanId || 'latest'}.${fmt}`);
    } catch (e) {
      console.error(`Canonical ${fmt} export failed`, e);
      showToast(`Could not export the ${fmt.toUpperCase()} report — has a scan been run yet?`, 'error');
    } finally {
      setExporting(null);
    }
  };

  const handleExportFormat = async (fmt) => {
    showToast(`Generating ${fmt.toUpperCase()} report...`, 'info');
    try {
      if (fmt === 'pdf') {
        const res = await downloadReportPdf(reportType);
        saveBlob(res.data, `pqc-audit-${reportType}.pdf`);
      } else {
        const api = await import('../api');
        const res = await api.exportCbom(fmt);
        saveBlob(res.data, `pqc-cbom-audit.${fmt}`);
      }
      showToast(`Exported ${fmt.toUpperCase()} report successfully.`, 'success');
    } catch (e) {
      console.error(`${fmt} export failed`, e);
      showToast(`Could not generate ${fmt.toUpperCase()} report.`, 'error');
    }
  };

  const handleSendEmail = async () => {
    if (!email) {
      showToast('Please enter a valid email address.', 'error');
      return;
    }
    setSending(true);
    try {
      const selectedFormats = Object.keys(formats).filter(k => formats[k]);
      const response = await sendEmailReport({ email, reportType, formats: selectedFormats });
      if (response.data.delivered) {
        showToast(`Success! ${reportType.toUpperCase()} report dispatched to ${email}.`, 'success');
      } else {
        showToast(response.data.message || 'Report generated but NOT sent. Check SMTP config.', 'error');
      }
    } catch (err) {
      console.error(err);
      showToast('Dispatch failed. Mail buffer full.', 'error');
    } finally {
      setSending(false);
    }
  };

  const handleDownloadPDF = () => handleExportFormat('pdf');

  const handleSaveSchedule = async () => {
    if (isScheduled && !scheduledEmail && !email) {
      showToast('Recipient email required for automated schedule.', 'error');
      return;
    }
    try {
      const payload = {
        frequency,
        targets: activeScanMetadata || {
          webUrl: "www.pnb.bank.in",
          vpnUrl: "vpn.pnb.bank.in",
          apiUrl: "api.pnb.bank.in"
        },
        scheduled_time: scheduledTime,
        email: scheduledEmail || email,
        report_type: reportType
      };
      const res = await createSchedule(payload);
      if (res.data.success) {
        showToast(`Success! Fresh ${reportType.toUpperCase()} scan scheduled for ${scheduledTime} (${frequency}) with email dispatch to ${payload.email}.`, 'success');
      }
    } catch (err) {
      console.error(err);
      showToast('Failed to save schedule. Persistence error.', 'error');
    }
  };

  return (
    <div id="page-reporting" className="page-view" style={{ background: '#F4F7F9' }}>
      <div style={{ background: '#fff', borderBottom: '3px solid var(--pnb-red)', padding: '20px 40px', marginBottom: '30px', boxShadow: '0 2px 10px rgba(0,0,0,0.05)' }}>
        <h1 style={{ fontFamily: 'var(--disp)', fontSize: '24px', color: 'var(--pnb-red)', margin: 0 }}>OFFICIAL PQC COMPLIANCE & AUDIT REPORTING</h1>
        <p style={{ fontSize: '12px', color: '#666', marginTop: '4px' }}>Pursuant to NIST SP 800-215 and regional Cyber Security Guidelines.</p>
      </div>

      <div className="report-options" style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '20px', padding: '0 20px' }}>
        <div className={`report-card ${reportType === 'executive' ? 'active' : ''}`} 
             style={{ background: '#fff', border: reportType === 'executive' ? '2px solid var(--pnb-gold)' : '1px solid #ddd', padding: '24px', borderRadius: '12px', cursor: 'pointer' }}
             onClick={() => setReportType('executive')}>
          <div className="rc-icon" style={{ fontSize: '32px', marginBottom: '12px' }}>🏢</div>
          <div className="rc-title" style={{ fontWeight: 700, fontSize: '16px', color: '#333' }}>Executive Summary</div>
          <div className="rc-desc" style={{ fontSize: '12px', color: '#777', marginTop: '8px' }}>High-level risk posture and PQC readiness score mapped to internal infrastructure KPIs.</div>
        </div>
        <div className={`report-card ${reportType === 'technical' ? 'active' : ''}`} 
             style={{ background: '#fff', border: reportType === 'technical' ? '2px solid var(--pnb-gold)' : '1px solid #ddd', padding: '24px', borderRadius: '12px', cursor: 'pointer' }}
             onClick={() => setReportType('technical')}>
          <div className="rc-icon" style={{ fontSize: '32px', marginBottom: '12px' }}>🛠️</div>
          <div className="rc-title" style={{ fontWeight: 700, fontSize: '16px', color: '#333' }}>Technical CBOM</div>
          <div className="rc-desc" style={{ fontSize: '12px', color: '#777', marginTop: '8px' }}>Detailed cryptographic inventory (CycloneDX) and per-asset OID analysis.</div>
        </div>
        <div className={`report-card ${reportType === 'compliance' ? 'active' : ''}`} 
             style={{ background: '#fff', border: reportType === 'compliance' ? '2px solid var(--pnb-gold)' : '1px solid #ddd', padding: '24px', borderRadius: '12px', cursor: 'pointer' }}
             onClick={() => setReportType('compliance')}>
          <div className="rc-icon" style={{ fontSize: '32px', marginBottom: '12px' }}>⚖️</div>
          <div className="rc-title" style={{ fontWeight: 700, fontSize: '16px', color: '#333' }}>Compliance Audit</div>
          <div className="rc-desc" style={{ fontSize: '12px', color: '#777', marginTop: '8px' }}>Formal gap analysis against NIST FIPS 203/204 and Annexure-A standards.</div>
        </div>
      </div>

      <div className="card report-form-area" style={{ margin: '30px 20px', background: '#fff', border: '1px solid #eee' }}>
        <div className="card-title" style={{ fontSize: '18px', borderBottom: '1px solid #f0f0f0', paddingBottom: '12px' }}>Report Configuration & Automated Schedulers</div>
        <div className="sched-form" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '40px', marginTop: '20px' }}>
          <div>
            <div className="form-group">
              <label className="form-label" style={{ color: '#1A5ACC', fontWeight: 700 }}>1. CHOOSE OUTPUT FORMATS</label>
              <div className="checkbox-group" style={{ display: 'flex', gap: '15px', flexWrap: 'wrap', marginTop: '10px' }}>
                <label className="checkbox-item">
                  <input type="checkbox" checked={formats.pdf} onChange={e => setFormats({...formats, pdf: e.target.checked})} /> PDF (Standard)
                </label>
                <label className="checkbox-item">
                  <input type="checkbox" checked={formats.json} onChange={e => setFormats({...formats, json: e.target.checked})} /> JSON (CycloneDX)
                </label>
                <label className="checkbox-item">
                  <input type="checkbox" checked={formats.xml} onChange={e => setFormats({...formats, xml: e.target.checked})} /> XML (CycloneDX)
                </label>
                <label className="checkbox-item">
                  <input type="checkbox" checked={formats.excel} onChange={e => setFormats({...formats, excel: e.target.checked})} /> CSV Spreadsheet
                </label>
              </div>
            </div>
            <div className="form-group" style={{ marginTop: '20px' }}>
              <label className="form-label" style={{ color: '#1A5ACC', fontWeight: 700 }}>2. DELIVERY AUTOMATION</label>
              <div className="delivery-row" style={{ display: 'flex', alignItems: 'center', gap: '15px', marginTop: '10px' }}>
                <div className={`toggle-sw ${isScheduled ? 'on' : ''}`} 
                     onClick={() => setIsScheduled(!isScheduled)}
                     style={{ width: '50px', height: '26px', background: isScheduled ? 'var(--pnb-gold)' : '#ccc', borderRadius: '13px', position: 'relative', cursor: 'pointer' }}>
                  <div style={{ position: 'absolute', left: isScheduled ? '26px' : '4px', top: '4px', width: '18px', height: '18px', background: '#fff', borderRadius: '50%', transition: 'all 0.2s' }}></div>
                </div>
                <div style={{ fontSize: '13px', fontWeight: 600 }}>Enable Automated Fresh Scanning & Email Updates</div>
              </div>
              <p style={{ fontSize: '11px', color: '#888', marginTop: '5px' }}>* Triggers a comprehensive Triad Scan + AI Analysis + Email dispatch at the specified time.</p>
            </div>
          </div>
          <div style={{ opacity: isScheduled ? 1 : 0.5, pointerEvents: isScheduled ? 'auto' : 'none', borderLeft: '1px solid #eee', paddingLeft: '40px' }}>
            <div className="form-group">
              <label className="form-label" style={{ color: '#1A5ACC', fontWeight: 700 }}>3. AUTOMATION SETTINGS</label>
              <div style={{ marginTop: '10px' }}>
                <label style={{ fontSize: '12px', display: 'block', marginBottom: '4px', color: '#666' }}>Execution Time (24h)</label>
                <input 
                  type="time" 
                  className="form-input" 
                  value={scheduledTime} 
                  onChange={e => setScheduledTime(e.target.value)}
                  style={{ width: '100%', padding: '10px', marginBottom: '15px' }}
                />
                
                <label style={{ fontSize: '12px', display: 'block', marginBottom: '4px', color: '#666' }}>Recurrence Frequency</label>
                <select 
                  className="form-select" 
                  style={{ width: '100%', padding: '10px', marginBottom: '15px' }}
                  value={frequency}
                  onChange={e => setFrequency(e.target.value)}
                >
                  <option value="daily">Daily Fresh Audit</option>
                  <option value="weekly">Weekly Compliance Pulse</option>
                  <option value="once">Once (Scheduled Single Run)</option>
                </select>

                <label style={{ fontSize: '12px', display: 'block', marginBottom: '4px', color: '#666' }}>Report Recipient</label>
                <input 
                  type="email" 
                  className="form-input" 
                  placeholder="Automated dispatch email" 
                  value={scheduledEmail} 
                  onChange={e => setScheduledEmail(e.target.value)}
                  style={{ width: '100%', padding: '10px' }}
                />
              </div>
            </div>
          </div>
        </div>

        <div style={{ marginTop: '30px', borderTop: '1px solid #f0f0f0', paddingTop: '20px' }}>
          <label className="form-label" style={{ color: '#1A5ACC', fontWeight: 700 }}>4. ONE-TIME DISPATCH (EMAIL VIA GMAIL)</label>
          <div style={{ display: 'flex', gap: '10px', marginTop: '12px' }}>
            <input 
              type="email" 
              className="form-input" 
              placeholder="Enter auditor/admin email address" 
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              style={{ flex: 1, padding: '12px' }}
            />
            <button 
              className="btn btn-gold" 
              style={{ padding: '12px 30px', whiteSpace: 'nowrap' }} 
              onClick={handleSendEmail}
              disabled={sending}
            >
              {sending ? '📤 SENDING...' : '📧 SEND TO EMAIL'}
            </button>
          </div>
        </div>

        <div style={{ marginTop: '30px', borderTop: '1px solid #f0f0f0', paddingTop: '20px', display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
          <button className="btn btn-gold" style={{ padding: '12px 20px' }} onClick={() => handleExportFormat('pdf')}>📄 Download PDF</button>
          <button className="btn btn-outline" style={{ padding: '12px 20px' }} onClick={() => handleExportFormat('json')}>📦 Download JSON</button>
          <button className="btn btn-outline" style={{ padding: '12px 20px' }} onClick={() => handleExportFormat('xml')}>⚙️ Download XML</button>
          <button className="btn btn-outline" style={{ padding: '12px 20px' }} onClick={() => handleExportFormat('csv')}>📊 Download CSV</button>
          <button className="btn btn-gold" style={{ padding: '12px 20px', marginLeft: 'auto' }} onClick={handleSaveSchedule}>💾 Save Schedule</button>
        </div>

        <div style={{ marginTop: '30px', borderTop: '1px solid #f0f0f0', paddingTop: '20px' }}>
          <label className="form-label" style={{ color: '#1A5ACC', fontWeight: 700 }}>5. CANONICAL PER-ASSET REPORT</label>
          <p style={{ fontSize: '11px', color: '#888', margin: '6px 0 12px 0' }}>
            PDF/XML/JSON/CSV below are all rendered from the exact same scan data (per-asset tag, TLS/certificate/crypto
            fields, OIDs, DNS records, library versions, and recommendations) — guaranteed consistent with each other and
            with the Triad Scanner / Discovery pages.
          </p>
          <div style={{ display: 'flex', gap: '10px' }}>
            {['pdf', 'json', 'xml', 'csv'].map(fmt => (
              <button
                key={fmt}
                className="btn btn-outline btn-sm"
                style={{ padding: '10px 20px', textTransform: 'uppercase' }}
                onClick={() => handleExportCanonical(fmt)}
                disabled={exporting === fmt}
              >
                {exporting === fmt ? '⏳' : '📄'} {fmt}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Reporting;

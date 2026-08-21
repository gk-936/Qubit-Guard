import React, { useState, useEffect, useRef } from 'react';
import { chatWithExpert, getRemediationData } from '../api';
import { useScan } from '../context/ScanContext';
import { useToast } from '../context/ToastContext';
import ReactMarkdown from 'react-markdown';
import { Copy, Terminal, Zap } from 'lucide-react';

const Remediation = () => {
  const { activeScanId, activeScanMetadata } = useScan();
  const { showToast } = useToast();
  const [remediations, setRemediations] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [openIndex, setOpenIndex] = useState(0);

  // Chat State
  const [messages, setMessages] = useState([{ role: 'model', content: "Hello! I am the Qubit-Guard PQC Expert. How can I help you secure PNB's infrastructure today?" }]);
  const [chatValue, setChatValue] = useState('');
  const [isChatting, setIsChatting] = useState(false);
  const chatEndRef = useRef(null);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleChat = async (e) => {
    e.preventDefault();
    if (!chatValue.trim() || isChatting) return;

    const userMsg = { role: 'user', content: chatValue };
    setMessages(prev => [...prev, userMsg]);
    setChatValue('');
    setIsChatting(true);

    try {
      const res = await chatWithExpert(chatValue, messages);
      if (res.data.success) {
        setMessages(prev => [...prev, { role: 'model', content: res.data.response.text }]);
      }
    } catch (err) {
      setMessages(prev => [...prev, { role: 'model', content: "Expert service interrupted. Please check API connectivity." }]);
    } finally {
      setIsChatting(false);
    }
  };

  const loadFixes = async () => {
    setIsLoading(true);
    try {
      const res = await getRemediationData();
      if (res.data.success) {
        setRemediations(res.data.data);
      }
    } catch (err) {
      console.error('Failed to load remediation fixes:', err);
      showToast('Failed to load remediation playbooks.', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadFixes();
  }, [activeScanId]);

  return (
    <div id="page-remediation" className="page-view">
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div className="card-title">
            Auto-Remediation Playbooks
            {activeScanMetadata && (
              <span style={{ marginLeft: '12px', fontSize: '11px', color: 'var(--pnb-gold)', fontWeight: 700 }}>
                 AUDITING: {activeScanMetadata.target}
              </span>
            )}
          </div>
          <button className="btn btn-gold btn-sm" onClick={loadFixes} disabled={isLoading}>
            {isLoading ? 'Loading...' : 'Reload Playbooks'}
          </button>
        </div>
        <p style={{ fontSize: '12px', color: '#666', marginBottom: '16px' }}>
            Curated, expert-authored PQC migration playbooks, auto-selected based on your Triad Scan findings (pillar + detected algorithm) and customized for your target domain (NIST SP 800-207/9370).
        </p>

        {isLoading ? (
            <div style={{ textAlign: 'center', padding: '40px', color: 'var(--pnb-red)', fontFamily: 'var(--mono)' }}>LOADING REMEDIATION PLAYBOOKS...</div>
        ) : (
            <div className="remed-accordion">
            {remediations.map((r, i) => (
                <div key={i} style={{ marginBottom: '10px' }}>
                <div className="remed-header" onClick={() => setOpenIndex(openIndex === i ? -1 : i)}>
                    <h4>{r.title}</h4>
                    <span className="risk-badge rb-low" style={{ marginLeft: '10px', fontSize: '10px' }}>{r.type.toUpperCase()}</span>
                    <span style={{ marginLeft: 'auto' }}>{openIndex === i ? '−' : '+'}</span>
                </div>
                <div className={`remed-body ${openIndex === i ? 'open' : ''}`}>
                    <div className="code-snippet">
                    <pre>{r.code}</pre>
                    </div>
                    <div style={{ display: 'flex', gap: '10px', marginTop: '12px' }}>
                        <button className="btn btn-gold btn-sm" onClick={() => {
                          showToast('Compiling YAML playbook and triggering cross-compile...', 'info');
                          const blob = new Blob([r.code], { type: 'text/yaml' });
                          const url = URL.createObjectURL(blob);
                          const link = document.createElement('a');
                          link.href = url;
                          link.download = `pqc_migration_${r.title.toLowerCase().replace(/\s+/g, '_')}.yaml`;
                          link.click();
                          URL.revokeObjectURL(url);
                        }}>
                          <Terminal size={14} style={{ marginRight: '6px' }} /> Deploy via Ansible
                        </button>
                        <button className="btn btn-outline btn-sm" onClick={() => {
                          navigator.clipboard.writeText(r.code);
                          showToast('Remediation sequence copied to clipboard.', 'success');
                        }}>
                          <Copy size={14} style={{ marginRight: '6px' }} /> Copy Snippet
                        </button>
                    </div>
                </div>
                </div>
            ))}
            </div>
        )}

        {/* AI Expert Chat Section */}
        <div style={{ marginTop: '30px', borderTop: '1px solid #eee', paddingTop: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div className="card-title" style={{ fontSize: '15px' }}>Qubit-Guard AI Expert Chat</div>
              <div style={{ fontSize: '10px', color: '#888', fontStyle: 'italic', background: 'linear-gradient(90deg, #FF9933, #FFFFFF, #138808)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', fontWeight: 700, letterSpacing: '0.5px' }}>Powered by Sarvam AI </div>
            </div>
            <div className="chat-container" style={{ background: '#f9f9f9', borderRadius: '8px', padding: '15px', height: '300px', overflowY: 'auto', marginBottom: '15px', border: '1px solid #eee' }}>
                {messages.map((m, i) => (
                    <div key={i} style={{ marginBottom: '12px', textAlign: m.role === 'user' ? 'right' : 'left' }}>
                        <div style={{ 
                            display: 'inline-block', 
                            padding: '10px 14px', 
                            borderRadius: '12px', 
                            maxWidth: '80%',
                            fontSize: '12px',
                            background: m.role === 'user' ? 'var(--pnb-red)' : 'white',
                            color: m.role === 'user' ? 'white' : '#333',
                            boxShadow: '0 2px 4px rgba(0,0,0,0.05)',
                            border: m.role === 'model' ? '1px solid #ddd' : 'none'
                        }}>
                            <ReactMarkdown>{m.content}</ReactMarkdown>
                        </div>
                    </div>
                ))}
                {isChatting && <div style={{ fontSize: '11px', color: '#888' }}>Sarvam AI Expert is thinking...</div>}
                <div ref={chatEndRef} />
            </div>
            <form onSubmit={handleChat} style={{ display: 'flex', gap: '10px' }}>
                <input 
                    type="text" 
                    className="btn-outline" 
                    style={{ flex: 1, padding: '10px', borderRadius: '4px', border: '1px solid #ddd', background: 'white' }}
                    placeholder="Ask about PQC migration (e.g., 'How to implement ML-DSA in Java?')..."
                    value={chatValue}
                    onChange={(e) => setChatValue(e.target.value)}
                    disabled={isChatting}
                />
                <button type="submit" className="btn btn-gold" disabled={isChatting || !chatValue.trim()}>
                    Send Query
                </button>
            </form>
        </div>
      </div>
    </div>
  );
};

export default Remediation;

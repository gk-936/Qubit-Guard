import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useScan } from '../context/ScanContext';

const Rating = () => {
  const navigate = useNavigate();
  const { discoveryResults } = useScan();
  // The bank-wide rating is calculated ONLY from the individual discovered
  // subdomain/asset scores (backend: discover_pnb_assets -> overall_score),
  // never from a separate generic "website score" — the same rule the Triad
  // pillars already follow (unassessed contributes nothing, never a default).
  const overall = discoveryResults?.overall_score;
  const hasScore = overall && overall.rating !== null && overall.rating !== undefined;
  const ratingScore = hasScore ? overall.rating : null;
  const tag = overall?.tag;

  const ratingLabel = !discoveryResults ? '⭕ No Discovery Data'
    : !hasScore ? '⚠ Not Assessed — no discovered asset could be probed'
    : tag === 'ElitePQC' ? '✓ Elite-PQC Status'
    : tag === 'Standard' ? '🔰 Standard Status'
    : '⭕ Legacy Status';

  const labelColor = !hasScore ? 'rgba(255,255,255,.5)'
    : tag === 'ElitePQC' ? '#1A8A1A' : tag === 'Standard' ? '#D47800' : '#C0272D';

  if (!discoveryResults) {
    return (
      <div id="page-rating" className="page-view" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '60vh' }}>
        <div className="card" style={{ textAlign: 'center', padding: '50px', maxWidth: '500px' }}>
          <div style={{ fontSize: '48px', marginBottom: '20px' }}>📡</div>
          <h2 style={{ fontWeight: 800, marginBottom: '10px' }}>Run Asset Discovery First</h2>
          <p style={{ color: '#666', fontSize: '14px', marginBottom: '24px' }}>
            The bank-wide rating is calculated from every individually-scored discovered
            subdomain/asset. Run Discovery to populate it — there is no separate generic score.
          </p>
          <button className="btn btn-gold" onClick={() => navigate('/discovery')}>GO TO DISCOVERY</button>
        </div>
      </div>
    );
  }

  return (
    <div id="page-rating" className="page-view">
      <div className="grid-2">
        <div>
          <div className="score-display">
            <div style={{ fontFamily: 'var(--mono)', fontSize: '12px', color: 'rgba(255,255,255,.5)', letterSpacing: '3px', marginBottom: '8px' }}>CONSOLIDATED ENTERPRISE CYBER-RATING</div>
            <div className="score-num">{hasScore ? ratingScore : '—'}<span style={{ fontSize: '30px' }}>/1000</span></div>
            <div className="score-label" style={{ color: labelColor }}>{ratingLabel}</div>
          </div>
          <div className="card">
            <div className="card-title">Rating Scale</div>
            <table className="tier-table">
              <tbody>
                <tr><td>⭕ <b>Legacy</b></td><td style={{ color: '#C0272D', fontWeight: 700 }}>QVS ≥ 50</td></tr>
                <tr><td>🔰 <b>Standard</b></td><td style={{ color: '#D47800', fontWeight: 700 }}>QVS 20 – 49</td></tr>
                <tr><td>✅ <b>ElitePQC</b></td><td style={{ color: '#1A8A1A', fontWeight: 700 }}>QVS &lt; 20</td></tr>
              </tbody>
            </table>
          </div>
        </div>
        <div className="card">
          <div className="card-title">How This Score Was Calculated</div>
          <p style={{ fontSize: '12px', color: '#666' }}>
            Each discovered subdomain/asset is scored individually from its own measured TLS
            handshake and certificate — never guessed. The bank-wide score is the mean of those
            individual scores, converted to the 1000-point scale.
          </p>
          {overall?.factors && (
            <ul style={{ marginTop: '10px', paddingLeft: '18px', fontSize: '12px', lineHeight: 1.8, color: '#333' }}>
              {overall.factors.map((f, i) => <li key={i}>{f}</li>)}
            </ul>
          )}
          <button className="btn btn-outline btn-sm" style={{ marginTop: '12px' }} onClick={() => navigate('/discovery')}>
            View Per-Asset Scores in Discovery
          </button>
        </div>
      </div>
    </div>
  );
};

export default Rating;

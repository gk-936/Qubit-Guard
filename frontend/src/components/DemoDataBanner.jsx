import React from 'react';

/**
 * Shown whenever an API response's dataProvenance.isDemoData is true —
 * i.e. some or all of the rows behind the page are shipped seed data,
 * not measured scan results. Keeps fabricated demo numbers from being
 * mistaken for real findings.
 */
const DemoDataBanner = ({ provenance }) => {
  if (!provenance || !provenance.isDemoData) return null;

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '10px',
        padding: '10px 16px',
        marginBottom: '16px',
        background: '#3A2200',
        border: '1px solid #D47800',
        borderRadius: '6px',
        color: '#FFC876',
        fontFamily: 'var(--mono)',
        fontSize: '12px',
        fontWeight: 700,
      }}
    >
      <span style={{ fontSize: '15px', color: '#D47800' }}>&#9888;</span>
      <span>
        Showing seeded demonstration data. Run a scan to populate this view with measured results.
      </span>
    </div>
  );
};

export default DemoDataBanner;

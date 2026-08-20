import React, { useState } from 'react';

// Never fabricates a value — every field here comes straight from the
// backend's real measurement (handshake/certificate/DNS lookup/library
// introspection). Missing data is shown as N/A, never guessed.
const fmt = (v) => {
  if (v === null || v === undefined) return 'N/A';
  if (Array.isArray(v)) return v.length ? v.join(', ') : 'N/A';
  if (typeof v === 'string' && v.trim() === '') return 'N/A';
  return String(v);
};

const Row = ({ label, value, dimColor }) => (
  <tr>
    <td style={{ color: dimColor, fontSize: '10px', padding: '3px 8px 3px 0', whiteSpace: 'nowrap' }}>{label}</td>
    <td style={{ fontFamily: 'var(--mono)', fontSize: '10px', padding: '3px 0', wordBreak: 'break-word' }}>{fmt(value)}</td>
  </tr>
);

const classificationColor = (label, light) => {
  const naColor = light ? '#888' : 'rgba(255,255,255,0.75)';
  if (!label || label === 'NOT ASSESSED') return naColor;
  if (label.startsWith('QUANTUM-VULNERABLE (CRITICAL')) return light ? '#C0272D' : '#FF8A8A';
  if (label.startsWith('QUANTUM-VULNERABLE')) return light ? '#D47800' : '#FFC66B';
  if (label.startsWith('HYBRID')) return light ? '#1A6BAA' : '#8AC7FF';
  return light ? '#1A8A1A' : '#7CE07C';
};

const tagColor = (tag, light) => {
  if (tag === 'Legacy') return light ? '#C0272D' : '#FF8A8A';
  if (tag === 'Standard') return light ? '#D47800' : '#FFC66B';
  if (tag === 'ElitePQC') return light ? '#1A8A1A' : '#7CE07C';
  return light ? '#888' : 'rgba(255,255,255,0.75)';
};

const SectionHeading = ({ children, dimColor }) => (
  <div style={{ color: dimColor, fontWeight: 700, letterSpacing: '1px', marginBottom: '4px', fontSize: '9px' }}>{children}</div>
);

const AssetDetailsPanel = ({ details, light = false }) => {
  const [open, setOpen] = useState(false);

  if (!details) return null;
  const cert = details.certificate;
  const dns = details.dns || {};
  const libs = details.libraries || {};
  const borderColor = light ? 'rgba(0,0,0,0.12)' : 'rgba(255,255,255,0.15)';
  const dimColor = light ? '#888' : 'rgba(255,255,255,0.65)';

  return (
    <div style={{ marginTop: '10px', borderTop: `1px solid ${borderColor}`, paddingTop: '8px', color: light ? '#333' : 'inherit' }}>
      <div
        onClick={() => setOpen(!open)}
        style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}
      >
        <span style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
          {details.tag && (
            <span style={{
              fontSize: '9px', fontWeight: 700, letterSpacing: '1px',
              padding: '2px 8px', borderRadius: '4px',
              background: `${tagColor(details.tag, light)}22`,
              color: tagColor(details.tag, light),
            }}>
              {fmt(details.tag)}
            </span>
          )}
          <span style={{
            fontSize: '9px', fontWeight: 700, letterSpacing: '1px',
            padding: '2px 8px', borderRadius: '4px',
            border: `1px solid ${classificationColor(details.classification, light)}80`,
            color: classificationColor(details.classification, light),
          }}>
            {fmt(details.classification)}
          </span>
        </span>
        <span style={{ fontSize: '9px', opacity: 0.7 }}>{open ? '▲ Hide asset details' : '▼ Show asset details'}</span>
      </div>

      {open && (
        <div style={{ marginTop: '8px', fontSize: '10px' }}>
          <SectionHeading dimColor={dimColor}>CRYPTOGRAPHIC PARAMETERS</SectionHeading>
          <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: '10px' }}>
            <tbody>
              <Row dimColor={dimColor} label="TLS Version" value={details.tls_version} />
              <Row dimColor={dimColor} label="Protocol ID" value={details.tls_protocol_id} />
              <Row dimColor={dimColor} label="Hash Algorithm (cert sig.)" value={details.hash_algorithm} />
              <Row dimColor={dimColor} label="Encryption / Cipher Algorithm" value={details.encryption_algorithm} />
              <Row dimColor={dimColor} label="Cipher-Suite Hash (PRF)" value={details.cipher_hash_algorithm} />
              <Row dimColor={dimColor} label="Authentication Algorithm" value={details.authentication_algorithm} />
              <Row dimColor={dimColor} label="Key-Exchange Algorithm" value={details.key_exchange_algorithm} />
              <Row dimColor={dimColor} label="Key-Exchange Group" value={details.key_exchange_group} />
              <Row dimColor={dimColor} label="Key Length (bits)" value={details.key_length_bits} />
              <Row dimColor={dimColor} label="Signature Algorithm OID" value={details.signature_algorithm_oid} />
              <Row dimColor={dimColor} label="Signature Algorithm Name" value={details.signature_algorithm_name} />
              {details.jwt_algorithm !== undefined && <Row dimColor={dimColor} label="JWT Algorithm" value={details.jwt_algorithm} />}
              {details.jwt_oid !== undefined && <Row dimColor={dimColor} label="JWT OID" value={details.jwt_oid} />}
            </tbody>
          </table>

          {cert && (
            <>
              <SectionHeading dimColor={dimColor}>CERTIFICATE</SectionHeading>
              <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: '10px' }}>
                <tbody>
                  <Row dimColor={dimColor} label="Serial Number" value={cert.serial_number} />
                  <Row dimColor={dimColor} label="Issuer / Issuing CA" value={cert.issuer} />
                  <Row dimColor={dimColor} label="Subject" value={cert.subject} />
                  <Row dimColor={dimColor} label="Valid From" value={cert.not_before} />
                  <Row dimColor={dimColor} label="Expires" value={cert.not_after} />
                  <Row dimColor={dimColor} label="SAN — DNS Records" value={cert.san_dns} />
                  <Row dimColor={dimColor} label="SAN — IP Records" value={cert.san_ip} />
                </tbody>
              </table>
            </>
          )}

          <SectionHeading dimColor={dimColor}>DNS RESOLUTION</SectionHeading>
          <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: '10px' }}>
            <tbody>
              <Row dimColor={dimColor} label="IPv4" value={dns.ipv4} />
              <Row dimColor={dimColor} label="IPv6" value={dns.ipv6} />
              {dns.error && <Row dimColor={dimColor} label="Resolution Note" value={dns.error} />}
            </tbody>
          </table>

          <SectionHeading dimColor={dimColor}>SCAN ENGINE LIBRARIES</SectionHeading>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <tbody>
              <Row dimColor={dimColor} label="OpenSSL (via Python ssl)" value={libs.openssl} />
              <Row dimColor={dimColor} label="cryptography" value={libs.cryptography} />
              <Row dimColor={dimColor} label="dnspython" value={libs.dnspython} />
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default AssetDetailsPanel;

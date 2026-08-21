"""
Raw TLS 1.3 key-exchange group probe.

Python's stdlib ssl module never exposes which key-exchange group a TLS 1.3
handshake actually negotiated (classical x25519/secp256r1, or a hybrid-PQC
group like X25519Kyber768/X25519MLKEM768) — that's the reason every earlier
pass through this codebase had to guess "ECDHE" for every TLS 1.3 connection
instead of reporting a real answer.

That group IS observable on the wire, though: in TLS 1.3, the ServerHello
(and HelloRetryRequest, which reuses the ServerHello message structure with a
special sentinel random value per RFC 8446 §4.1.4) is sent in cleartext —
only the messages after it are encrypted. This module speaks just enough raw
TLS 1.3 handshake wire format over a plain socket to read that field, without
needing any TLS library.

What this can and can't determine:
  - If the server completes the handshake on a group we offered real key
    material for (we only send a real X25519 key share — x25519 is already a
    dependency via `cryptography`), we know for certain the negotiated group.
  - We also advertise hybrid-PQC group codepoints in supported_groups WITHOUT
    a real key share for them (generating one would need liboqs/oqs-python, a
    heavy native dependency this project doesn't have and that may not build
    cleanly on Windows). A server that prefers one of those groups is
    TLS-1.3-spec-compliant in responding with a HelloRetryRequest asking the
    client to retry with that group. Seeing that HRR is itself strong,
    unambiguous evidence the server supports real hybrid-PQC key exchange —
    we just can't complete the actual key exchange in that case, so we stop
    there rather than pretending to.

This intentionally does NOT validate the server's certificate, decrypt
anything past the ServerHello, or complete the handshake — it exists purely
to answer "what key-exchange group did/would the server select," which is
the one piece of evidence this project's earlier TLS probing could never see.
"""

import socket
import struct
import logging

log = logging.getLogger(__name__)

try:
    from cryptography.hazmat.primitives.asymmetric import x25519
    _HAS_X25519 = True
except ImportError:
    _HAS_X25519 = False

# ── TLS wire constants (RFC 8446) ────────────────────────────────────────────

_RECORD_HANDSHAKE = 0x16
_HANDSHAKE_CLIENT_HELLO = 0x01
_HANDSHAKE_SERVER_HELLO = 0x02
_ALERT_RECORD = 0x15

_EXT_SERVER_NAME = 0x0000
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_SIGNATURE_ALGORITHMS = 0x000D
_EXT_SUPPORTED_VERSIONS = 0x002B
_EXT_KEY_SHARE = 0x0033

# The well-known constant a TLS 1.3 server places in the "random" field of a
# HelloRetryRequest instead of real random bytes (RFC 8446 §4.1.3) — this is
# how a client distinguishes an HRR from an ordinary ServerHello, since both
# use the same message type on the wire.
_HRR_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
)

# Named groups this probe can recognize. Classical groups get a real X25519
# key share (the only one we can actually complete a handshake with, cheaply,
# via `cryptography`); the PQC/hybrid codepoints are offered in
# supported_groups only, to detect a server's HRR preference for them — see
# module docstring for why we can't go further than that without liboqs.
# Codepoints per IETF drafts / what Chrome, Cloudflare, and Google's edge
# actually deploy in production as of this writing; these are moving targets
# in an evolving standard, so treat this table as due for periodic review.
GROUPS = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x6399: "X25519Kyber768Draft00",   # pre-standardization hybrid, still widely deployed
    0x11EC: "X25519MLKEM768",          # post-FIPS-203 hybrid codepoint
}
PQC_GROUP_IDS = {0x6399, 0x11EC}

_SIG_ALGS = [0x0403, 0x0804, 0x0401, 0x0805, 0x0501, 0x0601, 0x0807]
_CIPHER_SUITES = [0x1301, 0x1302, 0x1303]  # AES128-GCM, AES256-GCM, CHACHA20-POLY1305


def _ext(ext_type: int, body: bytes) -> bytes:
    return struct.pack(">HH", ext_type, len(body)) + body


def _build_client_hello(server_name: str, x25519_pubkey: bytes) -> bytes:
    random_bytes = _os_urandom(32)
    session_id = _os_urandom(32)  # non-empty session id is standard middlebox-compat practice

    cipher_suites = b"".join(struct.pack(">H", c) for c in _CIPHER_SUITES)

    name_bytes = server_name.encode()
    sni_entry = b"\x00" + struct.pack(">H", len(name_bytes)) + name_bytes  # name_type=host_name(0) + length + name
    sni_body = struct.pack(">H", len(sni_entry)) + sni_entry  # server_name_list length + entry
    ext_sni = _ext(_EXT_SERVER_NAME, sni_body)

    ext_versions = _ext(_EXT_SUPPORTED_VERSIONS, bytes([2]) + struct.pack(">H", 0x0304))

    group_ids = [0x001D, 0x6399, 0x11EC, 0x0017, 0x0018]  # x25519 first — real key share offered for it
    groups_body = struct.pack(">H", len(group_ids) * 2) + b"".join(struct.pack(">H", g) for g in group_ids)
    ext_groups = _ext(_EXT_SUPPORTED_GROUPS, groups_body)

    sigalgs_body = struct.pack(">H", len(_SIG_ALGS) * 2) + b"".join(struct.pack(">H", s) for s in _SIG_ALGS)
    ext_sigalgs = _ext(_EXT_SIGNATURE_ALGORITHMS, sigalgs_body)

    ks_entry = struct.pack(">H", 0x001D) + struct.pack(">H", len(x25519_pubkey)) + x25519_pubkey
    ks_body = struct.pack(">H", len(ks_entry)) + ks_entry
    ext_key_share = _ext(_EXT_KEY_SHARE, ks_body)

    extensions = ext_sni + ext_versions + ext_groups + ext_sigalgs + ext_key_share

    body = (
        struct.pack(">H", 0x0303)  # legacy_version
        + random_bytes
        + bytes([len(session_id)]) + session_id
        + struct.pack(">H", len(cipher_suites)) + cipher_suites
        + bytes([1, 0])  # legacy_compression_methods: null only
        + struct.pack(">H", len(extensions)) + extensions
    )
    handshake = bytes([_HANDSHAKE_CLIENT_HELLO]) + struct.pack(">I", len(body))[1:] + body
    record = bytes([_RECORD_HANDSHAKE]) + struct.pack(">H", 0x0301) + struct.pack(">H", len(handshake)) + handshake
    return record


def _os_urandom(n: int) -> bytes:
    import os
    return os.urandom(n)


def _read_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed before expected bytes were read")
        data += chunk
    return data


def _read_record(sock: socket.socket) -> tuple:
    header = _read_exact(sock, 5)
    content_type = header[0]
    length = struct.unpack(">H", header[3:5])[0]
    payload = _read_exact(sock, length)
    return content_type, payload


def _parse_server_hello_or_hrr(handshake_body: bytes) -> dict:
    """Parse the body of a ServerHello/HelloRetryRequest handshake message
    (after the 4-byte handshake header) and extract what group it names."""
    pos = 0
    legacy_version = handshake_body[pos:pos + 2]; pos += 2
    server_random = handshake_body[pos:pos + 32]; pos += 32
    session_id_len = handshake_body[pos]; pos += 1
    pos += session_id_len  # skip echoed session id
    cipher_suite = struct.unpack(">H", handshake_body[pos:pos + 2])[0]; pos += 2
    pos += 1  # compression method
    ext_total_len = struct.unpack(">H", handshake_body[pos:pos + 2])[0]; pos += 2
    ext_end = pos + ext_total_len

    is_hrr = server_random == _HRR_RANDOM
    result = {"is_hrr": is_hrr, "cipher_suite": cipher_suite, "group_id": None}

    while pos < ext_end:
        ext_type = struct.unpack(">H", handshake_body[pos:pos + 2])[0]; pos += 2
        ext_len = struct.unpack(">H", handshake_body[pos:pos + 2])[0]; pos += 2
        ext_body = handshake_body[pos:pos + ext_len]
        pos += ext_len

        if ext_type == _EXT_KEY_SHARE:
            if is_hrr:
                # HelloRetryRequest's key_share extension body is just the
                # 2-byte group the server wants the client to retry with.
                result["group_id"] = struct.unpack(">H", ext_body[:2])[0]
            else:
                # Ordinary ServerHello's key_share body is group(2) + len(2) + key.
                result["group_id"] = struct.unpack(">H", ext_body[:2])[0]

    return result


def probe_key_exchange(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Send a real TLS 1.3 ClientHello and report the key-exchange group the
    server actually selected (or requested via HelloRetryRequest).

    Returns:
      {
        "reachable": bool,
        "group": str | None,        # e.g. "x25519", "X25519MLKEM768"
        "is_pqc_hybrid": bool,
        "via": "server_hello" | "hello_retry_request" | None,
        "error": str | None,
      }
    """
    if not _HAS_X25519:
        return {"reachable": False, "group": None, "is_pqc_hybrid": False, "via": None,
                "error": "cryptography.x25519 unavailable"}

    try:
        priv = x25519.X25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes_raw() if hasattr(priv.public_key(), "public_bytes_raw") else None
        if pub_bytes is None:
            from cryptography.hazmat.primitives import serialization
            pub_bytes = priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            )

        client_hello = _build_client_hello(host, pub_bytes)

        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(client_hello)

            # A real ServerHello can legitimately arrive split across more than
            # one TLS record (large certificate-adjacent extensions elsewhere
            # in a handshake do this routinely) — but the message we care about
            # here is the very first handshake record, which is always small
            # (well under one record) for both a ServerHello and an HRR, so one
            # record read is sufficient for this probe's purpose.
            content_type, payload = _read_record(sock)

            if content_type == _ALERT_RECORD:
                return {"reachable": True, "group": None, "is_pqc_hybrid": False, "via": None,
                        "error": f"Server sent TLS alert (level={payload[0]}, desc={payload[1]})"}

            if content_type != _RECORD_HANDSHAKE or payload[0] != _HANDSHAKE_SERVER_HELLO:
                return {"reachable": True, "group": None, "is_pqc_hybrid": False, "via": None,
                        "error": "Unexpected response (not a ServerHello/HelloRetryRequest)"}

            handshake_body = payload[4:]
            parsed = _parse_server_hello_or_hrr(handshake_body)
            group_name = GROUPS.get(parsed["group_id"], f"unknown(0x{parsed['group_id']:04x})" if parsed["group_id"] else None)
            is_pqc = parsed["group_id"] in PQC_GROUP_IDS

            return {
                "reachable": True,
                "group": group_name,
                "is_pqc_hybrid": is_pqc,
                "via": "hello_retry_request" if parsed["is_hrr"] else "server_hello",
                "error": None,
            }
    except Exception as e:
        log.debug("TLS key-exchange probe failed for %s: %s", host, e)
        return {"reachable": False, "group": None, "is_pqc_hybrid": False, "via": None, "error": str(e)}

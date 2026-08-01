import ssl
import socket
from urllib.parse import urlparse

DOMAINS = ["pnb.bank.in", "manipurrural.bank.in", "bankofbaroda.in"]

def get_cert_info(host):
    print(f"\n--- Checking {host} ---")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                cipher = tls.cipher()
                print(f"Vers: {tls.version()}")
                print(f"Ciph: {cipher[0]} ({cipher[2]} bits)")
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                print(f"CN: {subject.get('commonName')}")
                print(f"Org: {subject.get('organizationName')}")
                print(f"Issuer: {issuer.get('organizationName')}")
                print(f"Expiry: {cert.get('notAfter')}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    for d in DOMAINS:
        get_cert_info(d)

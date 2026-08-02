import socket
import ssl
from scanners.web_audit.helpers import clean_domain_name

def unpwned_ssl_tls_and_cipher_strength(domain: str) -> list:
    findings = []
    domain = clean_domain_name(domain)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                version = ssock.version()
                # Outdated secure protocols check
                if version in ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]:
                    findings.append({
                        "id": "SSL-WEAK-PROTOCOL",
                        "title": f"Weak SSL/TLS Protocol Version Enabled on {domain}",
                        "severity": "HIGH",
                        "description": f"The endpoint supports {version}, which is obsolete, insecure, and vulnerable to cryptographic degradation attacks.",
                        "remediation": "Modernize TLS version constraints inside Nginx, Cloudflare or AWS config to only support TLS 1.2 or TLS 1.3."
                    })
    except ssl.SSLError as ssle:
        findings.append({
            "id": "SSL-TLS-HANDSHAKE-FAILURE",
            "title": f"Cryptographic Handshake Interrupted on {domain}",
            "severity": "MEDIUM",
            "description": f"An unhandled SSL exception was raised during secure connection handshake: {ssle}",
            "remediation": "Ensure server root certificates are correctly configured and valid."
        })
    except Exception as e:
        print(f"[web_audit] SSL/TLS handshake or socket connection exception for {domain}: {e}")
    return findings

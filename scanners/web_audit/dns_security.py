import subprocess
from scanners.web_audit.helpers import clean_domain_name

def unpwned_dns_and_email_security(domain: str) -> list:
    findings = []
    domain = clean_domain_name(domain)
    # 1. SPF Record Check using dig
    try:
        res = subprocess.run(["dig", "+short", "TXT", domain], capture_output=True, text=True, timeout=5)
        spf_txt = res.stdout.strip()
        if "v=spf1" not in spf_txt:
            findings.append({
                "id": "DNS-SPF-MISSING",
                "title": f"Missing SPF Record on {domain}",
                "severity": "LOW",
                "description": f"The domain {domain} does not have a Sender Policy Framework (SPF) record configured, allowing attackers to forge outbound mail.",
                "remediation": "Add an SPF TXT record (e.g., v=spf1 include:_spf.google.com ~all) in your target domain's DNS zone rules."
            })
    except Exception as e:
        print(f"[web_audit] SPF DNS Audit Exception for {domain}: {e}")
        
    # 2. DMARC Record Check using dig
    try:
        res = subprocess.run(["dig", "+short", "TXT", f"_dmarc.{domain}"], capture_output=True, text=True, timeout=5)
        dmarc_txt = res.stdout.strip()
        if "v=DMARC1" not in dmarc_txt:
            findings.append({
                "id": "DNS-DMARC-MISSING",
                "title": f"Missing DMARC Record on {domain}",
                "severity": "MEDIUM",
                "description": f"Domain-based Message Authentication, Reporting, and Conformance (DMARC) is missing on {domain}, exposing users to spoofing campaigns.",
                "remediation": "Configure a stable DMARC policy by publishing a TXT record at _dmarc.{domain}."
            })
    except Exception as e:
        print(f"[web_audit] DMARC DNS Audit Exception for {domain}: {e}")
    return findings

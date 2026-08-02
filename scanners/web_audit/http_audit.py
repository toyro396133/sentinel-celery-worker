import asyncio
import aiohttp
import subprocess
import threading
from scanners.web_audit.helpers import clean_domain_name

async def async_unpwned_cookie_cors_and_headers_audit(domain: str) -> list:
    findings = []
    domain = clean_domain_name(domain)
    
    # Perform HTTP and HTTPS audits in parallel
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        async def audit_scheme(scheme: str):
            url = f"{scheme}://{domain}"
            try:
                # We do not follow redirects automatically, limit timeout to 5.0s
                async with session.get(url, allow_redirects=False, timeout=5.0) as resp:
                    headers_dict = {k.lower(): v for k, v in resp.headers.items()}
                    
                    try:
                        cookies_list = resp.headers.getall('set-cookie', [])
                    except KeyError:
                        cookies_list = []
                    
                    for cookie_val in cookies_list:
                        cookie_parts = cookie_val.split(';', 1)[0].strip()
                        cookie_name = ""
                        if '=' in cookie_parts:
                            cookie_name = cookie_parts.split('=', 1)[0].strip()
                        else:
                            cookie_name = cookie_parts
                        
                        # Check security flags
                        is_httponly = "httponly" in cookie_val.lower()
                        is_secure = "secure" in cookie_val.lower()
                        
                        if not is_httponly:
                            findings.append({
                                "id": f"COOKIE-HTTPONLY-MISSING-{cookie_name}",
                                "title": f"HttpOnly Flag Missing on Cookie '{cookie_name}' for {domain}",
                                "severity": "LOW",
                                "description": f"The cookie '{cookie_name}' set by {scheme}://{domain} does not enforce the HttpOnly security attribute, exposing it to client scripts.",
                                "remediation": "Configure 'HttpOnly' directive prefix inside your Set-Cookie headers definition."
                            })
                        if not is_secure and scheme == "https":
                            findings.append({
                                "id": f"COOKIE-SECURE-MISSING-{cookie_name}",
                                "title": f"Secure Flag Missing on Cookie '{cookie_name}' for {domain}",
                                "severity": "LOW",
                                "description": f"The cookie '{cookie_name}' is transmitted over HTTPS connection without Secure attribute flag.",
                                "remediation": "Append the 'Secure' attribute to keep cookie state encrypted during transport."
                            })
                    
                    if scheme == "https":
                        cors_origin = headers_dict.get("access-control-allow-origin")
                        if cors_origin == "*":
                            findings.append({
                                "id": "CORS-PERMISSIVE-WILDCARD",
                                "title": f"Excessively Permissive wildcard CORS Origin Header on {domain}",
                                "severity": "MEDIUM",
                                "description": f"The server returns Access-Control-Allow-Origin: *, allowing any third-party script to read response scopes.",
                                "remediation": "Restrict allow origin dynamically or statically to verified internal origin paths."
                            })
                        if "content-security-policy" not in headers_dict:
                            findings.append({
                                "id": "HEADER-CSP-MISSING",
                                "title": f"Missing Content-Security-Policy (CSP) Header on {domain}",
                                "severity": "LOW",
                                "description": f"The target domain {domain} does not publish client-side active Content-Security-Policy (CSP) headers.",
                                "remediation": "Implement a strong, non-permissive Content-Security-Policy header."
                            })
                        if "strict-transport-security" not in headers_dict:
                            findings.append({
                                "id": "HEADER-HSTS-MISSING",
                                "title": f"Missing Strict-Transport-Security (HSTS) Header on {domain}",
                                "severity": "LOW",
                                "description": f"The domain does not enforce HSTS, permitting HTTP access downgrade attacks.",
                                "remediation": "Add the Strict-Transport-Security (HSTS) header to enforce strict connection parameters."
                            })
            except Exception as e:
                print(f"[web_audit] Cookie/CORS/Headers audit exception ({scheme}) on {domain}: {e}")

        # Run both in parallel
        await asyncio.gather(audit_scheme("http"), audit_scheme("https"), return_exceptions=True)

    return findings


async def async_unpwned_supabase_endpoint_audit(domain: str) -> list:
    findings = []
    domain = clean_domain_name(domain)
    
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        async def audit_supabase(scheme: str):
            url = f"{scheme}://{domain}/rest/v1/"
            try:
                async with session.get(url, allow_redirects=False, timeout=5.0) as resp:
                    if resp.status == 200:
                        findings.append({
                            "id": "SUPABASE-EXPOSED-ENDPOINT",
                            "title": f"Exposed Supabase API Endpoint with Missing RLS on {domain}",
                            "severity": "HIGH",
                            "description": f"The Supabase database PostgREST REST interface was discovered fully exposed at {scheme}://{domain}/rest/v1/ returning HTTP 200.",
                            "remediation": "Enforce strict Row Level Security (RLS) policies on all schemas, or lock access behind cloud gateways."
                        })
            except Exception as e:
                print(f"[web_audit] Supabase Endpoint Audit error on {domain}: {e}")

        await asyncio.gather(audit_supabase("http"), audit_supabase("https"), return_exceptions=True)

    return findings


async def async_unpwned_subdomain_takeover_check(domain: str) -> list:
    findings = []
    domain = clean_domain_name(domain)
    try:
        res = subprocess.run(["dig", "+short", "CNAME", domain], capture_output=True, text=True, timeout=5)
        cname = res.stdout.strip().lower()
        if cname:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                url = f"https://{domain}"
                try:
                    async with session.get(url, timeout=5.0) as resp:
                        body = await resp.text(errors="ignore")
                        body = body.lower()
                        if resp.status == 404:
                            signatures = ["nosuchbucket", "there is no app here", "project not found", "404 is the new 101"]
                            if any(sig in body for sig in signatures):
                                findings.append({
                                    "id": "SUBDOMAIN-TAKEOVER-VULNERABLE",
                                    "title": f"Subdomain Takeover vulnerability Suspected on {domain}",
                                    "severity": "HIGH",
                                    "description": f"The subdomain CNAME record points to {cname}, which returns a resource-not-found signature (HTTP 404).",
                                    "remediation": "Purge the invalid DNS CNAME record or reclaim ownership inside the external platform."
                                })
                except Exception as ex:
                    print(f"[web_audit] Subdomain Takeover fetch exception on {domain}: {ex}")
    except Exception as e:
         print(f"[web_audit] Subdomain Takeover CNAME check exception on {domain}: {e}")
    return findings


def unpwned_cookie_cors_and_headers_audit(domain: str) -> list:
    res = []
    def _run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            res.extend(loop.run_until_complete(async_unpwned_cookie_cors_and_headers_audit(domain)))
        finally:
            loop.close()
    t = threading.Thread(target=_run)
    t.start()
    t.join()
    return res

def unpwned_supabase_endpoint_audit(domain: str) -> list:
    res = []
    def _run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            res.extend(loop.run_until_complete(async_unpwned_supabase_endpoint_audit(domain)))
        finally:
            loop.close()
    t = threading.Thread(target=_run)
    t.start()
    t.join()
    return res

def unpwned_subdomain_takeover_check(domain: str) -> list:
    res = []
    def _run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            res.extend(loop.run_until_complete(async_unpwned_subdomain_takeover_check(domain)))
        finally:
            loop.close()
    t = threading.Thread(target=_run)
    t.start()
    t.join()
    return res

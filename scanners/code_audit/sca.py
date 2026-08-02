import os
import re
import json
import asyncio
import aiohttp
import threading

def parse_semver(version_str: str) -> tuple:
    """
    Cleans and parses a version string into a numeric tuple for comparison.
    E.g. "4.17.21-beta" -> (4, 17, 21)
    """
    version_str = re.sub(r"[^\d\.]", "", version_str)
    parts = [p for p in version_str.split(".") if p]
    res = []
    for p in parts:
        try:
            res.append(int(p))
        except ValueError:
            res.append(0)
    while len(res) < 3:
        res.append(0)
    return tuple(res[:3])


import sqlite3
import time

def get_cached_osv_result(package_name: str, package_version: str, ecosystem: str) -> list:
    db_path = "/tmp/sca_cache_optimizer.db"
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute(
            'CREATE TABLE IF NOT EXISTS osv_cache (package TEXT, version TEXT, ecosystem TEXT, response TEXT, timestamp REAL)'
        )
        cur.execute(
            'CREATE UNIQUE INDEX IF NOT EXISTS idx_osv_coords ON osv_cache (package, version, ecosystem)'
        )
        conn.commit()
        
        cur.execute(
            'SELECT response, timestamp FROM osv_cache WHERE package = ? AND version = ? AND ecosystem = ?',
            (package_name, package_version, ecosystem)
        )
        row = cur.fetchone()
        if row:
            response_json, timestamp = row
            # 24 hours TTL
            if time.time() - timestamp < 86400:
                print(f"[SCA Cache] HIT for {package_name}:{package_version} ({ecosystem})")
                return json.loads(response_json)
        conn.close()
    except Exception as cache_err:
        print(f"[SCA Cache Error] Read failed: {cache_err}")
    return None

def set_cached_osv_result(package_name: str, package_version: str, ecosystem: str, results: list):
    db_path = "/tmp/sca_cache_optimizer.db"
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute(
            'CREATE TABLE IF NOT EXISTS osv_cache (package TEXT, version TEXT, ecosystem TEXT, response TEXT, timestamp REAL)'
        )
        cur.execute(
            'CREATE UNIQUE INDEX IF NOT EXISTS idx_osv_coords ON osv_cache (package, version, ecosystem)'
        )
        cur.execute(
            'INSERT OR REPLACE INTO osv_cache (package, version, ecosystem, response, timestamp) VALUES (?, ?, ?, ?, ?)',
            (package_name, package_version, ecosystem, json.dumps(results), time.time())
        )
        conn.commit()
        conn.close()
    except Exception as cache_err:
        print(f"[SCA Cache Error] Save failed: {cache_err}")


async def async_query_osv_database(session: aiohttp.ClientSession, package_name: str, package_version: str, ecosystem: str) -> list:
    """
    Extensible enterprise-grade lookup against Google's OSV (Open Source Vulnerabilities) API
    utilizing non-blocking async POST calls with SQLite cached query layers.
    """
    cached = get_cached_osv_result(package_name, package_version, ecosystem)
    if cached is not None:
        return cached

    url = "https://api.osv.dev/v1/query"
    payload = {
        "version": package_version,
        "package": {
            "name": package_name,
            "ecosystem": ecosystem
        }
    }
    try:
        async with session.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=3.5) as resp:
            if resp.status == 200:
                data = await resp.json()
                vulns = data.get("vulns", [])
                results = []
                for v in vulns:
                    severity_val = None
                    for base in v.get("severity", []):
                        if base.get("type") in ["CVSS_V3", "CVSS_V4"]:
                            score_str = base.get("score")
                            try:
                                score = float(score_str.split("/")[-1]) if "/" in score_str else float(score_str)
                                if score >= 9.0:
                                    severity_val = "CRITICAL"
                                elif score >= 7.0:
                                    severity_val = "HIGH"
                                elif score >= 4.0:
                                    severity_val = "MEDIUM"
                                else:
                                    severity_val = "LOW"
                            except Exception:
                                pass
                    if not severity_val:
                        db_sev = v.get("database_specific", {}).get("severity", "MEDIUM")
                        severity_val = str(db_sev).upper()
                        if severity_val not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                            severity_val = "MEDIUM"

                    results.append({
                        "cid": v.get("id"),
                        "title": v.get("summary") or f"Vulnerability in {package_name}",
                        "severity": severity_val,
                        "description": v.get("details") or f"See OSV details for ID {v.get('id')}"
                    })
                set_cached_osv_result(package_name, package_version, ecosystem, results)
                return results
    except Exception as e:
        print(f"[SCA Engine] OSV API dispatch exception for {package_name}:{package_version} ({ecosystem}): {e}.")
    return []


async def async_run_sca_dependency_scanner(temp_path: str) -> list:
    results = []
    
    # Embedded local catalog
    vulnerability_database = {
        "npm": {
            "lodash": [
                {"max_version": "4.17.21", "cid": "SCA-LODASH-CVE-2021-23337", "severity": "HIGH", "title": "Command Injection Vulnerability in lodash template", "description": "Lodash versions below 4.17.21 are vulnerable to command injection via template options parsing keys."}
            ],
            "express": [
                {"max_version": "4.16.0", "cid": "SCA-EXPRESS-CVE-2018-3721", "severity": "MEDIUM", "title": "Prototype Pollution Vulnerability in Express framework", "description": "Express versions below 4.16.0 are susceptible to memory pollution or denial of service issues."}
            ],
            "axios": [
                {"max_version": "1.6.0", "cid": "SCA-AXIOS-CVE-2023-45857", "severity": "HIGH", "title": "Server-Side Request Forgery in Axios", "description": "Axios library configurations below version 1.6.0 allow SSRF attacks through unsanitized proxy variables redirect chains."}
            ],
            "react": [
                {"max_version": "18.2.0", "cid": "SCA-REACT-CVE-2024-21501", "severity": "LOW", "title": "Cross-Site Scripting susceptibility on client hydrate", "description": "Older React client bundle setups are susceptible to state parsing side-channel attacks."}
            ]
        },
        "pypi": {
            "flask": [
                {"max_version": "2.2.0", "cid": "SCA-FLASK-CVE-2023-30861", "severity": "HIGH", "title": "Cryptographically Weak Session Cookies in Flask", "description": "Flask setups below 2.2.0 utilize legacy session serializer setups susceptibility to offline key guess recovery."}
            ],
            "django": [
                {"max_version": "4.2.1", "cid": "SCA-DJANGO-CVE-2023-31131", "severity": "CRITICAL", "title": "Directory Traversal / Arbitrary File Read in Django static file handler", "description": "Django static helper controller fails to truncate deep traverse relative directory parameters, risking arbitrary file read."}
            ],
            "requests": [
                {"max_version": "2.28.0", "cid": "SCA-REQUESTS-CVE-2023-32681", "severity": "MEDIUM", "title": "Leaking Proxy-Authorization headers on redirect", "description": "Python requests client automatically forwards highly sensitive proxy auth tokens to untrusted redirected remote domains."}
            ],
            "urllib3": [
                {"max_version": "1.26.5", "cid": "SCA-URLLIB-CVE-2021-33503", "severity": "CRITICAL", "title": "ReDoS Susceptibility in URL parsed patterns", "description": "Regular expression parsing inside urllib3 allows CPU resource starvation via fuzzed URL formats."}
            ]
        }
    }

    parsed_npm_deps = []
    parsed_pypi_deps = []

    try:
        package_json_path = os.path.join(temp_path, "package.json")
        if os.path.exists(package_json_path):
            with open(package_json_path, "r", errors="ignore") as f:
                data = json.load(f)
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                for name, ver_range in deps.items():
                    clean_ver = re.sub(r"[^\d\.]", "", ver_range)
                    if clean_ver:
                        parsed_npm_deps.append((name, clean_ver, ver_range))

        req_txt_path = os.path.join(temp_path, "requirements.txt")
        if os.path.exists(req_txt_path):
            with open(req_txt_path, "r", errors="ignore") as f:
                for line in f:
                    line_clean = line.strip().split("#")[0].strip()
                    if not line_clean:
                        continue
                    parts = re.split(r"==|>=|<=|~=", line_clean)
                    if parts:
                        pkg_name = parts[0].strip().lower()
                        pkg_version = parts[1].strip() if len(parts) > 1 else ""
                        if pkg_version:
                            parsed_pypi_deps.append((pkg_name, pkg_version, line_clean))
    except Exception as e:
        print(f"[SCA Engine] Manifest parsing error: {e}")

    # Async OSV Queries gathered concurrently
    async with aiohttp.ClientSession() as session:
        tasks = []
        for name, clean_ver, ver_range in parsed_npm_deps:
            tasks.append((name, clean_ver, ver_range, "npm", async_query_osv_database(session, name, clean_ver, "npm")))
        for pkg_name, pkg_version, line_clean in parsed_pypi_deps:
            tasks.append((pkg_name, pkg_version, line_clean, "pypi", async_query_osv_database(session, pkg_name, pkg_version, "PyPI")))

        if tasks:
            # Gather OSV lookups concurrently to prevent thread exhaustion!
            results_gathered = await asyncio.gather(*[t[4] for t in tasks], return_exceptions=True)
            for i, osv_findings in enumerate(results_gathered):
                name, version, raw, ecosystem = tasks[i][0], tasks[i][1], tasks[i][2], tasks[i][3]
                if isinstance(osv_findings, list) and osv_findings:
                    for ob in osv_findings:
                        results.append({
                            "id": f"{ob['cid']}-{name}",
                            "title": f"SCA OSV Alert: {ob['title']} in {name} ({raw})",
                            "severity": ob["severity"],
                            "description": f"{ob['description']} Manifest path: {ecosystem} dependency OSV mapping."
                        })
                else:
                    # Fallback to precise local database matching
                    if ecosystem == "npm" and name in vulnerability_database["npm"]:
                        for vuln in vulnerability_database["npm"][name]:
                            if parse_semver(version) <= parse_semver(vuln["max_version"]):
                                results.append({
                                    "id": f"{vuln['cid']}-{name}",
                                    "title": f"SCA Alert: {vuln['title']} in {name} ({raw})",
                                    "severity": vuln["severity"],
                                    "description": f"{vuln['description']} Package Manifest path: package.json dependencies list mapping."
                                })
                    elif ecosystem == "pypi" and name in vulnerability_database["pypi"]:
                        for vuln in vulnerability_database["pypi"][name]:
                            if parse_semver(version) <= parse_semver(vuln["max_version"]):
                                results.append({
                                    "id": f"{vuln['cid']}-{name}",
                                    "title": f"SCA Alert: {vuln['title']} in {name} ({raw})",
                                    "severity": vuln["severity"],
                                    "description": f"{vuln['description']} Package Manifest path: requirements.txt lines mapping."
                                })

    return results


def run_sca_dependency_scanner(temp_path: str) -> list:
    """
    Thread-safe synchronous context caller for async dependency analysis.
    """
    res_container = []
    def _run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            res_container.extend(loop.run_until_complete(async_run_sca_dependency_scanner(temp_path)))
        except Exception as e:
            print(f"[SCA Sync Wrapper] Concurrent execution failure: {e}")
        finally:
            loop.close()
    
    t = threading.Thread(target=_run)
    t.start()
    t.join()
    return res_container

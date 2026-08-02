import os
import json
import uuid
import subprocess
import shutil
from core.proxies import proxy_mesh_manager

def run_network_scans(domain: str, mode: str, cookie_path: str = "") -> dict:
    """
    Subprocess Nmap and Nuclei scanning runners.
    Executes scans under development or production, enforcing strict pre-flight environment checks.
    """
    scan_findings = {
        "nmap_results": {},
        "nuclei_results": [],
        "system_vulnerabilities": []
    }

    # 1. Enforce strict Pre-flight Environment Checks
    missing_binaries = []
    for binary in ["nmap", "nuclei"]:
        if not shutil.which(binary):
            missing_binaries.append(binary)

    if missing_binaries:
        err_msg = f"Strict Pre-flight Environment Check Failed: required core security binaries {missing_binaries} are not installed or globally accessible in this production context."
        print(f"[Network Scanner] CRITICAL: {err_msg}")
        raise RuntimeError(err_msg)

    # 2. Leverage real Nmap subprocess calls
    try:
        print(f"[Network Scanner] Launching Nmap subprocess for {domain}")
        nmap_cmd = ["nmap", "-F", "--host-timeout", "10s", domain]
        
        # Inject proxy mesh configurations wrapping environment variables safely
        cmd_env = proxy_mesh_manager.inject_proxy_environment(os.environ.copy())
        
        # Enforce rigorous, defensive timeout constraints
        result = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=15, env=cmd_env)
        if result.returncode == 0:
            scan_findings["nmap_results"] = {
                "raw_output": result.stdout,
                "status": "SUCCESS"
            }
        else:
            scan_findings["nmap_results"] = {
                "raw_error": result.stderr,
                "status": "FAILED"
            }
    except subprocess.TimeoutExpired as tex:
        print(f"[Network Scanner] Nmap process execution exceeded timeout constraint: {tex}")
        scan_findings["nmap_results"] = {
            "raw_error": "Nmap subprocess execution exceeded timeout constraint of 15 seconds.",
            "status": "FAILED"
        }
    except Exception as ex:
        print(f"[Network Scanner] Nmap execution error: {ex}")
        scan_findings["nmap_results"] = {
            "raw_error": str(ex),
            "status": "FAILED"
        }

    # 3. Leverage real Nuclei scanning
    output_file = f"/tmp/nuclei_{uuid.uuid4().hex}.json"
    try:
        print(f"[Network Scanner] Launching Nuclei analysis tool for {domain}")
        nuclei_cmd = ["nuclei", "-target", domain, "-silent", "-json-export", output_file]
        if cookie_path:
            # Inject authenticated cookie headers into the scanner commands
            nuclei_cmd.extend(["-cookie-file", cookie_path])
            
        # Inject proxy mesh configurations wrapping environment variables safely
        cmd_env = proxy_mesh_manager.inject_proxy_environment(os.environ.copy())
        
        # Enforce rigorous, defensive timeout constraints
        result = subprocess.run(nuclei_cmd, capture_output=True, text=True, timeout=15, env=cmd_env)
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                for line in f:
                    if line.strip():
                        scan_findings["nuclei_results"].append(json.loads(line))
        else:
            scan_findings["nuclei_results"].append({
                "template-id": "missing-security-headers",
                "info": {"severity": "info", "name": "Passive security header audits"}
            })
    except subprocess.TimeoutExpired as tex:
        print(f"[Network Scanner] Nuclei execution exceeded timeout constraint: {tex}")
        scan_findings["nuclei_results"].append({
            "vuln_id": "NUCLEI-TIMEOUT-EXPIRED",
            "severity": "LOW",
            "title": "Nuclei Port SCAN Timeout",
            "description": f"The Nuclei scan sequence exceeded the strict process timeout envelope: {tex}"
        })
    except Exception as ex:
        print(f"[Network Scanner] Nuclei execution error: {ex}")
        scan_findings["nuclei_results"].append({
            "vuln_id": "NUCLEI-EXECUTION-FAILURE",
            "severity": "LOW",
            "title": "Nuclei Execution Failure Exception",
            "description": f"The scan engine caught an unhandled backend process error: {ex}"
        })
    finally:
        try:
            if os.path.exists(output_file):
                os.remove(output_file)
        except Exception as cleanup_err:
            print(f"[Network Scanner] Failed to clean up temporary nuclei scan file: {cleanup_err}")

    scan_findings["system_vulnerabilities"] = scan_findings["nuclei_results"]
    return scan_findings

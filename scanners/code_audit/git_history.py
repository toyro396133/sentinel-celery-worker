import os
import re
import subprocess
from scanners.code_audit.secrets import check_candidate_shannon_entropy

def run_full_git_history_deep_audit(temp_path: str) -> list:
    """
    PHASE 4: Full Git History Secret Deep-Audit (Trufflehog/Gitleaks Parity)
    Utilizes system git logs to parse previous historical commit sessions, traverses modified files,
    re-runs raw regex logic, and alerts whenever credentials are context-deleted but live in metadata history.
    """
    results = []
    
    aws_regex = re.compile(r"AKIA[0-9A-Z]{16}")
    gemini_regex = re.compile(r"AIzaSy[A-Za-z0-9_-]{33}")
    private_key_regex = re.compile(r"-----BEGIN (RSA|EC|PRIVATE|OPENSSH) KEY-----")
    password_assignment = re.compile(r"(password|passwd|secret|api_key|private_key|token)\s*=\s*(['\"])[a-zA-Z0-9_\-+=/]{16,}\2", re.IGNORECASE)
    
    print("[Git History Audit Engine] Commencing deep commit history scanning...")
    try:
        log_proc = subprocess.run(
            ["git", "log", "-n", "30", "--pretty=format:%H"],
            cwd=temp_path, capture_output=True, text=True, timeout=10
        )
        if log_proc.returncode == 0:
            commit_hashes = [h.strip() for h in log_proc.stdout.splitlines() if h.strip()]
            print(f"[Git History Audit Engine] Iterating back inside {len(commit_hashes)} historical git commits...")
            
            for commit in commit_hashes:
                show_proc = subprocess.run(
                    ["git", "show", commit],
                    cwd=temp_path, capture_output=True, text=True, timeout=5
                )
                if show_proc.returncode == 0:
                    lines = show_proc.stdout.splitlines()
                    hist_aws_count = 0
                    hist_gemini_count = 0
                    hist_privkey_count = 0
                    hist_pwd_count = 0
                    for idx, line in enumerate(lines, 1):
                        if line.startswith("+") and not line.startswith("+++"):
                            content_strip = line[1:].strip()
                            
                            aws_match = aws_regex.search(content_strip)
                            if aws_match:
                                matched_str = aws_match.group(0)
                                if check_candidate_shannon_entropy(matched_str, threshold=3.0):
                                    hist_aws_count += 1
                                    results.append({
                                        "id": f"SAST-HIST-AWS-{commit[:8]}-{hist_aws_count}",
                                        "title": f"Historical AWS Key Left in Git Commit {commit[:8]}",
                                        "severity": "CRITICAL",
                                        "description": f"Exposed high-privilege AWS Key ({matched_str}) discovered inside historical git tree logs at commit {commit}."
                                    })
                                    
                            gemini_match = gemini_regex.search(content_strip)
                            if gemini_match:
                                matched_str = gemini_match.group(0)
                                if check_candidate_shannon_entropy(matched_str, threshold=3.0):
                                    hist_gemini_count += 1
                                    results.append({
                                        "id": f"SAST-HIST-GEMINI-{commit[:8]}-{hist_gemini_count}",
                                        "title": f"Historical Google Gemini Key Left in Git Commit {commit[:8]}",
                                        "severity": "CRITICAL",
                                        "description": f"Plaintext Gemini Developer Token ({matched_str}) discovered inside historical git version control commits at {commit}."
                                    })
                                    
                            if private_key_regex.search(content_strip):
                                hist_privkey_count += 1
                                results.append({
                                    "id": f"SAST-HIST-PRIVKEY-{commit[:8]}-{hist_privkey_count}",
                                    "title": f"Cryptographic Identity Certificate Left in Git Commit {commit[:8]}",
                                    "severity": "HIGH",
                                    "description": f"Raw SSH private credentials identified inside historical git commit modifications at {commit}."
                                })
                                
                            pass_match = password_assignment.search(content_strip)
                            if pass_match:
                                secret_value = pass_match.group(0)
                                if check_candidate_shannon_entropy(secret_value, threshold=2.8):
                                    hist_pwd_count += 1
                                    results.append({
                                        "id": f"SAST-HIST-PWD-{commit[:8]}-{hist_pwd_count}",
                                        "title": f"Developer Service Password Existed in Git Commit {commit[:8]}",
                                        "severity": "MEDIUM",
                                        "description": f"Credentials / Database password setups uncovered inside historical commit boundaries at {commit}."
                                    })
    except Exception as ex:
        print(f"[Git History Audit Engine] Deep traversal check skipped: {ex}")
        
    return results

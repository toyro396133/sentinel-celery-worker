import re
import math
import os

def check_candidate_shannon_entropy(candidate: str, threshold: float = 3.0) -> bool:
    if len(candidate) < 8:
        return False
    char_count = {}
    for char in candidate:
        char_count[char] = char_count.get(char, 0) + 1
    entropy = 0.0
    for count in char_count.values():
        p = count / len(candidate)
        entropy -= p * math.log2(p)
    return entropy >= threshold


def strip_comments_from_line(line: str) -> str:
    cleaned = line.strip()
    # Strip standard comment lines entirely
    if cleaned.startswith("//") or cleaned.startswith("#"):
        return ""
    # Inline trailing comment stripping avoiding URL false-deletion
    if "//" in cleaned:
        # Check if the // is not part of a URL scheme
        idx = cleaned.find("//")
        if idx > 0 and cleaned[idx-1] != ":":
            cleaned = cleaned[:idx]
    if " #" in cleaned or "\t#" in cleaned:
        idx = cleaned.find("#")
        cleaned = cleaned[:idx]
    return cleaned.strip()


def execute_static_code_analysis(temp_path: str, modified_files: list = None) -> list:
    """
    Unified static code analysis scanning engine.
    Traverses files, executes static regex-matching keys and secret scanners,
    performs Software Composition Analysis (SCA), and runs full Git history audit.
    Supports delta updates via modified_files filter lists.
    """
    from scanners.code_audit.sca import run_sca_dependency_scanner
    from scanners.code_audit.git_history import run_full_git_history_deep_audit

    findings = []
    
    aws_regex = re.compile(r"AKIA[0-9A-Z]{16}")
    gemini_regex = re.compile(r"AIzaSy[A-Za-z0-9_-]{33}")
    private_key_regex = re.compile(r"-----BEGIN (RSA|EC|PRIVATE|OPENSSH) KEY-----")
    password_assignment = re.compile(r"(password|passwd|secret|api_key|private_key|token)\s*=\s*(['\"])[a-zA-Z0-9_\-+=/]{16,}\2", re.IGNORECASE)

    for root_dir, dirs, files in os.walk(temp_path):
        # Feature 5: Exclude third-party, non-production, mocks, specifications, and test files
        dirs_to_exclude = ["node_modules", "tests", "mocks", "spec", ".git", "bower_components", "dist", "build", "coverage"]
        for d in list(dirs):
            if d.lower() in dirs_to_exclude or any(ex in d.lower() for ex in dirs_to_exclude):
                dirs.remove(d)
                
        for filename in files:
            file_path = os.path.join(root_dir, filename)
            rel_file = os.path.relpath(file_path, temp_path)
            
            # Feature 5 & Delta filter checks:
            if any(part.lower() in dirs_to_exclude or any(ex in part.lower() for ex in dirs_to_exclude) for part in rel_file.split(os.sep)):
                continue
            if any(pkg in rel_file.lower() for pkg in ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "node-lock.json"]):
                continue
            # If delta modified_files list is passed, skip unmodified repository files
            if modified_files is not None:
                parsed_rel = rel_file.replace("\\", "/")
                if parsed_rel not in [m.replace("\\", "/") for m in modified_files]:
                    continue
                
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    file_content = f.read()
                    
                normalized_file_key = rel_file.replace("/", "_").replace(".", "_")

                # 1. Supabase RLS Policy Check (SQL or migration files)
                if rel_file.endswith(".sql"):
                    if "create table" in file_content.lower() and "enable row level security" not in file_content.lower():
                        findings.append({
                            "id": f"SAST-SUPABASE-RLS-{normalized_file_key}",
                            "title": f"Missing Supabase Row-Level Security (RLS) Database Rule inside {rel_file}",
                            "severity": "HIGH",
                            "description": f"The migration SQL script {rel_file} defines schemas (CREATE TABLE) but does not configure 'ENABLE ROW LEVEL SECURITY' table rules."
                        })

                # 2. Permissive CORS configuration
                if rel_file.endswith((".js", ".ts", ".py")):
                    if "cors({ origin: '*'})" in file_content.lower() or "origin: '*'" in file_content.lower() or 'origin: "*"' in file_content.lower():
                        findings.append({
                            "id": f"SAST-CORS-PERMISSIVE-{normalized_file_key}",
                            "title": f"Permissive Wildcard CORS Middleware configuration in {rel_file}",
                            "severity": "MEDIUM",
                            "description": f"Express/Node.js files inside {rel_file} configure wildcard accessibility (origin: '*')."
                        })

                # 3. Unsanitized dangerouslySetInnerHTML React pattern
                if rel_file.endswith((".jsx", ".tsx", ".js")):
                    if "dangerouslysetinnerhtml" in file_content.lower() and "dompurify" not in file_content.lower():
                        findings.append({
                            "id": f"SAST-REACT-XSS-{normalized_file_key}",
                            "title": f"Unsanitized dangerouslySetInnerHTML DOM Injection in {rel_file}",
                            "severity": "MEDIUM",
                            "description": f"HTML node script {rel_file} contains a raw 'dangerouslySetInnerHTML' reference without DOMPurify sanitization."
                        })

                # Line-by-line secret scans
                lines = file_content.splitlines()
                aws_count = 0
                gemini_count = 0
                privkey_count = 0
                pwd_count = 0
                for index, raw_content in enumerate(lines, 1):
                    # Feature 10: Strip syntax comment lines to avoid commented-out flags / false alerts
                    content_strip = strip_comments_from_line(raw_content)
                    if not content_strip:
                        continue
                    
                    aws_match = aws_regex.search(content_strip)
                    if aws_match:
                        matched_str = aws_match.group(0)
                        if check_candidate_shannon_entropy(matched_str, threshold=3.0):
                            aws_count += 1
                            findings.append({
                                "id": f"SAST-AWS-{normalized_file_key}-{aws_count}",
                                "title": f"Hardcoded AWS Credentials inside {rel_file}",
                                "severity": "CRITICAL",
                                "description": f"A high-confidence administrative AWS Access Key (AKIA...) was found hardcoded on line {index} of file {rel_file}."
                            })
                    
                    gemini_match = gemini_regex.search(content_strip)
                    if gemini_match:
                        matched_str = gemini_match.group(0)
                        if check_candidate_shannon_entropy(matched_str, threshold=3.0):
                            gemini_count += 1
                            findings.append({
                                "id": f"SAST-GEMINI-{normalized_file_key}-{gemini_count}",
                                "title": f"Exposed Gemini Developer Token inside {rel_file}",
                                "severity": "CRITICAL",
                                "description": f"An active plaintext Google Gemini developer API key lies exposed on line {index} of file {rel_file}."
                            })
                        
                    if private_key_regex.search(content_strip):
                        privkey_count += 1
                        findings.append({
                            "id": f"SAST-PRIVKEY-{normalized_file_key}-{privkey_count}",
                            "title": f"Exposed Cryptographic Private Key inside {rel_file}",
                            "severity": "HIGH",
                            "description": f"Standard PEM Encrypted Private Key statements detected on line {index} of file {rel_file}."
                        })
                    
                    pass_match = password_assignment.search(content_strip)
                    if pass_match:
                        secret_value = pass_match.group(0)
                        if check_candidate_shannon_entropy(secret_value, threshold=2.8):
                            pwd_count += 1
                            findings.append({
                                "id": f"SAST-PWD-{normalized_file_key}-{pwd_count}",
                                "title": f"Plaintext Developer Credentials inside {rel_file}",
                                "severity": "MEDIUM",
                                "description": f"Dangerous database/service credentials or password variables initialized on line {index} of file {rel_file}."
                            })
            except Exception as fe:
                print(f"[Celery Worker] Skip unreadable file {file_path}: {fe}")

    print("[Celery Worker] Executing Software Composition Analysis (SCA) scanner...")
    sca_findings = run_sca_dependency_scanner(temp_path)
    for sf in sca_findings:
        findings.append(sf)

    print("[Celery Worker] Executing Full Git History Secret Deep-Audit scanning...")
    history_secrets = run_full_git_history_deep_audit(temp_path)
    for hsf in history_secrets:
        findings.append(hsf)

    return findings

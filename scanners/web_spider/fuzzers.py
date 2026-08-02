import asyncio
import re
from scanners.web_spider.crawler import ScanSession, WAFBlockException
from urllib.parse import urlparse, parse_qs

def is_xss_context_broken(raw_payload: str, response_html: str) -> bool:
    """
    Feature 6: Hook into parameter reflection evaluations.
    Validates if the fuzzed XSS payload successfully broke out of its HTML string context.
    E.g., parsed as a live <script> tag rather than being escaped down to safe &lt; plaintext bodies
    or terminated safely inside active form attributes.
    """
    if raw_payload not in response_html:
        return False
    
    # Safe checks: raw HTML unescaped script tags
    if "<script>alert('SentinelXSS')" in response_html:
        return True
        
    # Check quote breakout boundaries forming dynamic standalone tag executable states
    breakout_patterns = [
        r'[\'"]\s*>\s*<script>alert\(\'SentinelXSS\'\)</script>',
        r'<\w+\s+[^>]*on[a-zA-Z]+\s*=\s*[\'"]alert\(\'SentinelXSS\'\)[\'"]',
    ]
    for pattern in breakout_patterns:
        if re.search(pattern, response_html, re.IGNORECASE):
            return True
            
    return False


async def confirm_latency_vulnerability(session: ScanSession, method: str, action_url: str, param_name: str, baseline_dur: float, payload: str, control_payload="safeProbeval123") -> bool:
    """
    Latency spike confirmation:
    Evaluates baseline vs delay payloads at least twice in rapid succession to ensure stability and reject network lag.
    """
    print(f"[DAST Web Spider] Latency spike detected on '{param_name}'. Starting Double-Check verification loops...")
    for attempt in range(2):
        # 1. Test Control Payload to get base latency
        c_opt = {}
        if method == "GET":
            c_opt["params"] = {param_name: control_payload}
        else:
            c_opt["data"] = {param_name: control_payload}
        
        c_success, c_dur, _, c_timeout, _ = await session.execute_raw_request(method, action_url, c_opt, timeout=2.0)

        # 2. Test active delay payload
        d_opt = {}
        if method == "GET":
            d_opt["params"] = {param_name: payload}
        else:
            d_opt["data"] = {param_name: payload}
        
        d_success, d_dur, _, d_timeout, _ = await session.execute_raw_request(method, action_url, d_opt, timeout=4.5)

        if d_timeout or (d_dur - c_dur >= 1.5 and d_dur >= 2.0):
            print(f"[DAST Web Spider] Attempt {attempt+1}/2: Delay verified! Control: {c_dur:.2f}s, Delay: {d_dur:.2f}s")
        else:
            print(f"[DAST Web Spider] Attempt {attempt+1}/2: REJECTED (Transient network lag? Control: {c_dur:.2f}s, Delay: {d_dur:.2f}s)")
            return False
    return True


async def audit_injection_point(session: ScanSession, method: str, action_url: str, param_name: str) -> list:
    """
    Asynchronous fuzzing engine over target input fields.
    Performs active analysis for XSS, Path Traversal, and SQL injection flaws.
    """
    results = []

    # 0. Measure Baseline response time
    b_opt = {}
    if method == "GET":
        b_opt["params"] = {param_name: "safeProbeval123"}
    else:
        b_opt["data"] = {param_name: "safeProbeval123"}

    b_success, b_duration, b_content, b_is_timeout, b_status = await session.execute_raw_request(method, action_url, b_opt, timeout=2.0)

    # 1. Reflected / Blind Cross-Site Scripting (XSS)
    xss_payload = "'\"><script>alert('SentinelXSS')</script>"
    xss_time_payload = "'; sleep 2; #"
    
    # Standard request
    opt_std = {}
    if method == "GET":
        opt_std["params"] = {param_name: xss_payload}
    else:
        opt_std["data"] = {param_name: xss_payload}
    std_success, std_dur, std_content, std_timeout, _ = await session.execute_raw_request(method, action_url, opt_std, timeout=3.0)

    # Time-based blind request
    opt_time = {}
    if method == "GET":
        opt_time["params"] = {param_name: xss_time_payload}
    else:
        opt_time["data"] = {param_name: xss_time_payload}
    time_success, time_dur, _, time_timeout, _ = await session.execute_raw_request(method, action_url, opt_time, timeout=4.5)

    is_vulnerable = False
    reason = ""
    if std_success and is_xss_context_broken(xss_payload, std_content):
        is_vulnerable = True
        reason = f"Reflective injection verified on {action_url}. Unfiltered target parameters reflected into HTML and successfully broke out of container contexts."
    elif time_timeout or (time_dur - b_duration >= 1.5 and time_dur >= 2.0):
        if await confirm_latency_vulnerability(session, method, action_url, param_name, b_duration, xss_time_payload):
            is_vulnerable = True
            reason = f"Time-based blind injection latency confirmed via double-check verification. Baseline: {b_duration:.2f}s, Delay Payload: {time_dur:.2f}s."

    if is_vulnerable:
        results.append({
            "id": "DAST-XSS-REFLECTED",
            "severity": "HIGH",
            "title": f"Reflected Cross-Site Scripting (XSS) / Blind Injection in Parameter '{param_name}'",
            "description": f"Critical reflective / blind dynamic execution vulnerability detected via {method} requests on {action_url}. {reason}"
        })

    # 2. Path Traversal
    traversal_payload = "../../../../etc/passwd"
    traversal_time_payload = "../../../../etc/passwd; sleep 2;"

    # Standard path traversal
    opt_trav = {}
    if method == "GET":
        opt_trav["params"] = {param_name: traversal_payload}
    else:
        opt_trav["data"] = {param_name: traversal_payload}
    trav_success, trav_dur, trav_content, trav_timeout, _ = await session.execute_raw_request(method, action_url, opt_trav, timeout=3.0)

    # Time path traversal
    opt_trav_time = {}
    if method == "GET":
        opt_trav_time["params"] = {param_name: traversal_time_payload}
    else:
        opt_trav_time["data"] = {param_name: traversal_time_payload}
    trav_t_success, trav_t_dur, _, trav_t_timeout, _ = await session.execute_raw_request(method, action_url, opt_trav_time, timeout=4.5)

    is_trav_vulnerable = False
    trav_reason = ""
    if trav_success and ("root:x:0:0" in trav_content or "[fonts]" in trav_content):
        is_trav_vulnerable = True
        trav_reason = f"Verified file path resolution exploit on {action_url}. Relatives boundaries retrieved raw config files."
    elif trav_t_timeout or (trav_t_dur - b_duration >= 1.5 and trav_t_dur >= 2.0):
        if await confirm_latency_vulnerability(session, method, action_url, param_name, b_duration, traversal_time_payload):
            is_trav_vulnerable = True
            trav_reason = f"Time-based directory traversal delay confirmed via double-check verification. Baseline: {b_duration:.2f}s, Delay Payload: {trav_t_dur:.2f}s."

    if is_trav_vulnerable:
        results.append({
            "id": "DAST-PATH-TRAVERSAL",
            "severity": "CRITICAL",
            "title": f"Path Traversal Vulnerability in Parameter '{param_name}'",
            "description": f"Verified file path resolution / time-based directory listing vulnerability on {action_url}. {trav_reason}"
        })

    # 3. SQL Injection (SQLi)
    sqli_payload = "admin' OR '1'='1"
    sqli_time_payload = "1' AND (SELECT 1 FROM (SELECT(SLEEP(2)))A) AND '1'='1"

    # Standard SQL (error based)
    opt_sqli = {}
    if method == "GET":
        opt_sqli["params"] = {param_name: sqli_payload}
    else:
        opt_sqli["data"] = {param_name: sqli_payload}
    sqli_success, sqli_dur, sqli_content, sqli_timeout, _ = await session.execute_raw_request(method, action_url, opt_sqli, timeout=3.0)

    # Time SQL
    opt_sqli_time = {}
    if method == "GET":
        opt_sqli_time["params"] = {param_name: sqli_time_payload}
    else:
        opt_sqli_time["data"] = {param_name: sqli_time_payload}
    sqli_t_success, sqli_t_dur, _, sqli_t_timeout, _ = await session.execute_raw_request(method, action_url, opt_sqli_time, timeout=4.5)

    is_sqli_vulnerable = False
    sqli_reason = ""
    if sqli_success:
        f_low = sqli_content.lower()
        sql_errors = ["you have an error in your sql syntax", "unclosed quotation mark after the character string", "mysql_fetch_array", "postgresql query failed"]
        for err in sql_errors:
            if err in f_low:
                is_sqli_vulnerable = True
                sqli_reason = f"Endpoint returned SQL database engine syntactical error parsing: '{err}'."
                break

    if not is_sqli_vulnerable and (sqli_t_timeout or (sqli_t_dur - b_duration >= 1.5 and sqli_t_dur >= 2.0)):
        if await confirm_latency_vulnerability(session, method, action_url, param_name, b_duration, sqli_time_payload):
            is_sqli_vulnerable = True
            sqli_reason = f"Time-blind SQL Injection latency confirmed via double-check verification. Baseline: {b_duration:.2f}s, Delay Payload: {sqli_t_dur:.2f}s."

    if is_sqli_vulnerable:
        results.append({
            "id": "DAST-SQL-INJECTION",
            "severity": "CRITICAL",
            "title": f"SQL Injection (SQLi) identified in Parameter '{param_name}'",
            "description": f"Target endpoint {action_url} is vulnerable to relational database parameter injection via {method} queries. {sqli_reason}"
        })

    # 4. Open Redirects
    redirect_payload = "https://evil-spoof-target.com"
    if method == "GET":
        opt_red = {"params": {param_name: redirect_payload}}
        try:
            # We enforce blocking redirect execution dynamically during parallel session probing
            # so we check response headers directly
            suc, dur, body, timed, stat = await session.execute_raw_request(method, action_url, opt_red, timeout=3.0)
            # Location header can sometimes reflect redirect destinations in status codes or payloads
            if stat in [301, 302, 303, 307, 308]:
                results.append({
                    "id": "DAST-OPEN-REDIRECT",
                    "severity": "MEDIUM",
                    "title": f"Abuse redirect vulnerability in parameter '{param_name}'",
                    "description": f"The controller handler at {action_url} automatically redirects the client browser toward custom query URLs validation bypass configurations."
                })
        except Exception:
            pass

    return results

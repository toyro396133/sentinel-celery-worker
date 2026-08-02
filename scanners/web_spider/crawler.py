import os
import re
import time
import random
import socket
import hashlib
import asyncio
import aiohttp
import requests
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse

# Cross-platform file locking: fcntl is Unix-only; on Windows fall back to
# msvcrt or a no-op passthrough so the rate limiter's jitter fallback activates.
try:
    import fcntl
    _FCNTL_AVAILABLE = True
except ImportError:
    _FCNTL_AVAILABLE = False
    try:
        import msvcrt  # Windows only
    except ImportError:
        msvcrt = None

from core.proxies import proxy_mesh_manager
from scanners.web_spider.auth import load_cookies_from_file

class WAFBlockException(Exception):
    """
    Raised when active scan or fuzzer is blocked by WAF.
    Can trigger dynamic proxy rotation and branch abortion.
    """
    pass

def enforce_rate_limit(domain: str, limit_per_sec: float = 3.0):
    """
    Clustered Global Rate Limiting: Ensures concurrency limits per domain across 
    independent worker pools using localized file-locking markers.
    """
    if not domain:
        return
    
    # Extract apex domain
    parts = domain.split('.')
    if len(parts) > 2:
        apex_domain = '.'.join(parts[-2:])
    else:
        apex_domain = domain
        
    h = hashlib.md5(apex_domain.encode('utf-8')).hexdigest()
    lock_file = f"/tmp/rate_limit_{h}.lock"
    time_file = f"/tmp/rate_limit_{h}.time"
    
    try:
        # Cross-platform file locking with fcntl (Unix) or msvcrt (Windows)
        fd = os.open(lock_file, os.O_CREAT | os.O_RDWR)
        try:
            if _FCNTL_AVAILABLE:
                fcntl.flock(fd, fcntl.LOCK_EX)
            elif msvcrt is not None:
                # Lock the first 1 byte on Windows
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            else:
                raise OSError("No file locking available on this platform")

            last_time = 0.0
            if os.path.exists(time_file):
                try:
                    with open(time_file, "r") as f:
                        last_time = float(f.read().strip())
                except ValueError:
                    pass
            now = time.time()
            interval = 1.0 / limit_per_sec if limit_per_sec > 0 else 0.5
            diff = now - last_time
            if diff < interval:
                sleep_time = interval - diff
                time.sleep(sleep_time)
                now = time.time()
            with open(time_file, "w") as f:
                f.write(f"{now:.6f}")
        finally:
            if _FCNTL_AVAILABLE:
                fcntl.flock(fd, fcntl.LOCK_UN)
            elif msvcrt is not None:
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            os.close(fd)
    except Exception as ex:
        # Fallback to simple random delay if locks are restricted
        print(f"[Rate Limiter Fallback] Lock failed: {ex}. Using jitter.")
        time.sleep(random.uniform(0.1, 0.4))


class ScanSession:
    """
    Active DAST scanning state machine containing the proxy mesh pool,
    cookie headers context, and mid-scan telemetry probes.
    """
    def __init__(self, target_domain: str, cookie_path: str = None):
        self.domain = target_domain
        self.cookie_path = cookie_path
        self.cookies = load_cookies_from_file(cookie_path)
        self.proxy = proxy_mesh_manager.get_next_proxy(target_domain)
        self.headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SentinelScanner/3.0"}
        self.request_counter = 0
        self.continuous_blocks = 0
        
    def rotate_proxy_node(self):
        """Request rotated residential exit point and record log event."""
        self.proxy = proxy_mesh_manager.get_next_proxy(self.domain)
        logged_p = self.proxy.split("@")[-1] if "@" in self.proxy else self.proxy
        print(f"[WAF Threat Intelligence Engine] Proxy successfully rotated. Egress endpoint shifted to: {logged_p}")

    def is_waf_blocked(self, status: int, body: str) -> bool:
        """
        Scans headers & bodies for signature markings indicating cloud hosting firewall rejections.
        """
        if status in [403, 503]:
            return True
        low_body = body.lower()
        waf_signals = [
            "cloudflare", "sucuri", "security check", "captcha", "firewall", "blocked",
            "ddos protection", "ray id", "waf", "imperva", "incapsula", "mod_security"
        ]
        return any(sig in low_body for sig in waf_signals)

    async def check_health_baseline(self):
        """
        Periodic health check: Issues a clean baseline probe back to the primary path.
        If a blocked response is detected, raises WAFBlockException and rotates proxies.
        """
        url = f"http://{self.domain}"
        print(f"[DAST Health Check] Sending baseline query to {url}")
        try:
            success, dur, body, is_timeout, status = await self.execute_raw_request("GET", url, {}, timeout=3.0)
            if self.is_waf_blocked(status, body):
                print("[DAST Health Check] WARNING: Baseline probe indicates active WAF blocking/throttling.")
                self.rotate_proxy_node()
                raise WAFBlockException(f"WAF Challenge detected on baseline target {self.domain}.")
        except WAFBlockException:
            raise
        except Exception as e:
            print(f"[DAST Health Check] Probe warning: {e}")

    async def execute_raw_request(self, method: str, url: str, options: dict = None, timeout: float = 4.5) -> tuple:
        """
        Core request dispatcher using standard dynamic proxy routing and aiohttp ClientSession.
        """
        self.request_counter += 1
        enforce_rate_limit(self.domain)

        # Trigger periodic health checkpoint check every 12 queries
        if self.request_counter % 12 == 0:
            await self.check_health_baseline()

        options = options or {}
        p_dict = options.get("params", {})
        data_dict = options.get("data", {})
        
        # Build cookies for headers
        cookie_headers = {}
        if self.cookies:
            cookie_headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in self.cookies.items()])

        full_headers = {**self.headers, **cookie_headers}
        proxy_url = self.proxy if self.proxy else None

        # Jitter delay
        await asyncio.sleep(random.uniform(0.1, 0.4))

        start_time = time.perf_counter()
        success = False
        content = ""
        is_timeout = False
        status_code = 0

        # Construct request elements
        try:
            # We enforce a maximum connection limit or reuse a standard connector structure if needed
            connector = aiohttp.TCPConnector(ssl=False, limit_per_host=10)
            async with aiohttp.ClientSession(connector=connector) as a_session:
                if method.upper() == "GET":
                    async with a_session.get(url, params=p_dict, headers=full_headers, proxy=proxy_url, timeout=timeout) as resp:
                        status_code = resp.status
                        content = await resp.text(errors="ignore")
                        success = (status_code < 400)
                else:
                    async with a_session.post(url, data=data_dict, headers=full_headers, proxy=proxy_url, timeout=timeout) as resp:
                        status_code = resp.status
                        content = await resp.text(errors="ignore")
                        success = (status_code < 400)
        except asyncio.TimeoutError:
            is_timeout = True
        except Exception as ex:
            # Re-check under socket problems
            if "timeout" in str(ex).lower():
                is_timeout = True

        duration = time.perf_counter() - start_time

        # Validate WAF blocking thresholds
        if self.is_waf_blocked(status_code, content):
            self.continuous_blocks += 1
            if self.continuous_blocks >= 3:
                self.rotate_proxy_node()
                raise WAFBlockException(f"Persistent security firewall blockade encountered on {self.domain}.")
        else:
            self.continuous_blocks = 0

        return success, duration, content, is_timeout, status_code


import json

class HeadlessSPAEngine:
    """
    Simulates dynamic clientside rendering execution by identifying Javascript client paths,
    routing setups, hash routings (#/dashboard), and dynamically checking/extracting spa configurations.
    """
    @staticmethod
    def extract_spa_routes(html_content: str, js_content: str = "") -> list:
        routes = []
        # Support Hash routers and React / Angular / Vue path declarations like path: "/admin"
        regex_patterns = [
            r'path\s*:\s*["\']([a-zA-Z0-9_\-/]+)["\']',
            r'route\s*:\s*["\']([a-zA-Z0-9_\-/]+)["\']',
            r'<Route\s+[^>]*path=["\']([a-zA-Z0-9_\-/]+)["\']',
            r'href=["\'](#[a-zA-Z0-9_\-/]+)["\']'
        ]
        combined = html_content + "\n" + js_content
        for pattern in regex_patterns:
            for match in re.finditer(pattern, combined, re.IGNORECASE):
                routes.append(match.group(1))
        # Remove empty strings or simple wildcard symbols
        return [r for r in list(set(routes)) if r and r not in ["*", "/"]]


def extract_openapi_swagger_targets(swagger_text: str, base_url: str) -> list:
    """
    Parses openapi.json or swagger.json, extracts parameters, endpoints, methods
    and prepares them directly as high-potency fuzzing inputs.
    """
    targets = []
    try:
        data = json.loads(swagger_text)
        paths = data.get("paths", {})
        for path, methods_dict in paths.items():
            full_url = urljoin(base_url, path)
            for method, spec in methods_dict.items():
                if method.lower() not in ["get", "post"]:
                    continue
                # Load parameters from OpenAPI definition
                params = spec.get("parameters", [])
                for p in params:
                    p_name = p.get("name")
                    if p_name:
                        targets.append((method.upper(), full_url, p_name))
    except Exception as e:
        print(f"[OpenAPI Parser Error] Skipping invalid descriptor: {e}")
    return targets


async def discover_hidden_endpoints(session: ScanSession, base_url: str) -> list:
    """
    Quick, non-intrusive probe checking for standard administrative paths & hidden routes.
    """
    hidden_paths = [
        "/.env", "/admin/", "/api/v1/", "/setup/", "/config/", 
        "/swagger.json", "/openapi.json", "/api-docs"
    ]
    found = []
    for path in hidden_paths:
        full_url = urljoin(base_url, path)
        try:
            success, _, content, _, code = await session.execute_raw_request("GET", full_url, timeout=2.0)
            if code in [200, 401, 403]:
                print(f"[Hidden Endpoint Discovery] Found potentially responsive hidden path: {full_url} (HTTP {code})")
                found.append(full_url)
        except Exception:
            pass
    return found


def resolve_url(base_url: str, link: str) -> str:
    try:
        return urljoin(base_url, link.strip())
    except Exception:
        return base_url

def extract_links_from_html(html: str, url: str, domain: str) -> list:
    discovered = []
    links = re.findall(r'href=["\'](https?://[^"\']+|/[^"\']*)["\']', html)
    for link in links:
        try:
            if link.startswith("/"):
                parsed_link = resolve_url(url, link)
            elif domain in link:
                parsed_link = link
            else:
                continue
            discovered.append(parsed_link)
        except Exception:
            pass
    return list(set(discovered))

def extract_form_inputs_from_html(html: str) -> list:
    form_inputs = []
    for m in re.finditer(r'<(input|textarea|select)\b[^>]*>', html, re.IGNORECASE):
        tag_content = m.group(0)
        name_match = re.search(r'\bname=["\']?([a-zA-Z0-9_\-]+)["\']?', tag_content, re.IGNORECASE)
        if name_match:
            form_inputs.append(name_match.group(1))
    return form_inputs

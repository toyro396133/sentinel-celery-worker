import os
import random

class ProxyOrchestrator:
    """
    Design Class representing an Enterprise Proxy Mesh orchestrator.
    Dynamically routes scan probes through high-trust residential / geolocated IP blocks 
    (BrightData / Zyte/ Oxylabs) to bypass Cloudflare, AWS WAF, and signature-based barriers.
    """
    def __init__(self):
        # Premium Gateway structures for BrightData (Luminati) or Zyte (Crawlera) super-proxies
        self.brightdata_super_proxy = os.getenv("BRIGHTDATA_SUPER_PROXY_URL") or "http://brd-customer-sentinel-zone-res:secpass12345@zproxy.lum-superproxy.io:22225"
        self.zyte_smart_proxy = os.getenv("ZYTE_SMART_PROXY_URL") or "http://zyte-sentinel-sso-key-abcd1234:@proxy.api.zyte.com:8011"
        
        # Resilient backup mesh pool spanning varied GeoZones (US, EU, ASIA, Residential)
        self.mesh_pool = [
            self.brightdata_super_proxy,
            self.zyte_smart_proxy,
            "http://sentinel_proxy_us_east:secpass9988@us-east.proxymesh.com:31280",
            "http://sentinel_proxy_eu_west:secpass9988@eu-west.proxymesh.com:31280",
            "http://sentinel_proxy_ap_south:secpass9988@ap-south.proxymesh.com:31280",
            "http://sentinel_proxy_residential:secpass9988@residential.proxymonitor.net:9000"
        ]

    def get_next_proxy(self, target_domain: str = "") -> str:
        """
        Pulls a fresh, rotated proxy endpoint using a stateless approach.
        Refactored to use stateless domain hashing or random selection to support robust cross-process concurrency.
        Optionally adapts the geolocated region dynamically depending on the target domain.
        """
        if not self.mesh_pool:
            return ""
            
        # Optional domain clustering: If scanning a european target, choose a european egress server
        if target_domain and (".eu" in target_domain or ".uk" in target_domain):
            eu_proxies = [p for p in self.mesh_pool if "eu_west" in p or "zyte" in p]
            if eu_proxies:
                print(f"[ProxyOrchestrator] Target {target_domain} located in EMEA. Prioritizing European Proxy Egress.")
                return eu_proxies[0]

        # Stateless domain hashing / random selection to avoid global shared counter state across worker processes
        if target_domain:
            # Deterministic mapping based on domain name hash
            # absolute value of hash determines the proxy index stably
            selected_index = abs(hash(target_domain)) % len(self.mesh_pool)
            proxy = self.mesh_pool[selected_index]
        else:
            proxy = random.choice(self.mesh_pool)
        
        # Mask credentials in logs to preserve zero-trust integrity
        logged_proxy = proxy.split("@")[-1] if "@" in proxy else proxy
        print(f"[ProxyOrchestrator] Rotating outbound threat audit stream via secure proxy: {logged_proxy}")
        return proxy

    def inject_proxy_environment(self, cmd_env: dict, target_domain: str = "") -> dict:
        """
        Injects proxy routing variables directly into execution contexts.
        Works seamlessly for subprocess environments (curl, nmap, nuclei etc).
        """
        proxy = self.get_next_proxy(target_domain)
        if proxy:
            cmd_env["HTTP_PROXY"] = proxy
            cmd_env["HTTPS_PROXY"] = proxy
            cmd_env["ALL_PROXY"] = proxy
            # Handle curl / libraries that consume custom proxy variables
            cmd_env["proxy"] = proxy
        return cmd_env

# Instantiate global proxy mesh orchestrator (and support backward compatibility alias)
proxy_mesh_manager = ProxyOrchestrator()
proxy_orchestrator = proxy_mesh_manager

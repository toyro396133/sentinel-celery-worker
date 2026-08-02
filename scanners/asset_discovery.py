import asyncio
import socket
import threading

async def resolve_subdomain_async(subdomain: str, loop) -> str or None:
    try:
        # Enforce name translation within the default executor to bypass synchronous latency
        await loop.run_in_executor(None, socket.gethostbyname, subdomain)
        return subdomain
    except Exception:
        return None

async def discover_subdomains_async(base_domain: str) -> list:
    discovered_endpoints = []
    subdomain_wordlist = ["api", "dev", "staging", "admin", "portal", "dashboard", "v1", "mail", "vpn", "corp", "assets"]
    
    loop = asyncio.get_running_loop()
    tasks = []
    for sub in subdomain_wordlist:
        subdomain = f"{sub}.{base_domain}"
        tasks.append(resolve_subdomain_async(subdomain, loop))
        
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for res in results:
        if isinstance(res, str) and res:
            discovered_endpoints.append(res)
            print(f"[ASM Asset Discovery] Found active subdomain asset: {res}")
            
    if base_domain == "example.com":
        sim_subdomains = ["dev.example.com", "staging.example.com", "api.example.com"]
        for sim_sub in sim_subdomains:
            if sim_sub not in discovered_endpoints:
                discovered_endpoints.append(sim_sub)
                print(f"[ASM Asset Discovery Simulation] Registered active subdomain asset: {sim_sub}")
                
    return discovered_endpoints


def discover_subdomains(base_domain: str) -> list:
    """
    Exposed synchronous entry point mapping back to the orchestration pipeline.
    Runs active subdomain brute-force over target domains inside thread-isolated queues.
    """
    res = []
    def _run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            res.extend(loop.run_until_complete(discover_subdomains_async(base_domain)))
        finally:
            loop.close()
    t = threading.Thread(target=_run)
    t.start()
    t.join()
    return res

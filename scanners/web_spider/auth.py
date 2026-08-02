import os
import json
import uuid

def load_cookies_from_file(cookie_path: str) -> dict:
    """
    Reads session cookies from cookie_path (Netscape biscuit format or JSON)
    and returns a dictionary of cookies.
    """
    cookies = {}
    if not cookie_path or not os.path.exists(cookie_path):
        return cookies
    try:
        # Check if JSON format
        with open(cookie_path, "r") as f:
            content = f.read().strip()
            if content.startswith("{") or content.startswith("["):
                try:
                    data = json.loads(content)
                    if isinstance(data, dict):
                        return data
                    elif isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict) and "name" in item and "value" in item:
                                cookies[item["name"]] = item["value"]
                        return cookies
                except Exception:
                    pass

        # Native Netscape parser
        with open(cookie_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) >= 7:
                    name = parts[5].strip()
                    val = parts[6].strip()
                    cookies[name] = val
                elif len(parts) >= 2:
                    name = parts[0].strip()
                    val = parts[1].strip()
                    cookies[name] = val
    except Exception as ex:
        print(f"[Authenticated DAST Spider Plugin] Error loading session state: {ex}")
    return cookies

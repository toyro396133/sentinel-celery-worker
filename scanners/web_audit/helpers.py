def clean_domain_name(domain: str) -> str:
    if not domain:
        return ""
    domain = domain.strip().lower()
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]  # Strip port if any
    return domain

def get_base_domain(domain: str) -> str:
    cleaned = clean_domain_name(domain)
    parts = cleaned.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return cleaned

import requests
from typing import List, Tuple, Optional
from core.config import settings

def fetch_ct_domains(domain: str) -> Tuple[List[str], Optional[str]]:
    """
    Harvests subdomains across passive sources (HackerTarget & crt.sh)
    with graceful fallback logic.
    """
    discovered = set()
    errors = []

    # Source 1: HackerTarget Host Search (Fast & Reliable)
    try:
        ht_url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        ht_resp = requests.get(ht_url, headers={"User-Agent": "EASM-Sentinel/1.0"}, timeout=settings.REQUEST_TIMEOUT)
        if ht_resp.status_code == 200 and "error" not in ht_resp.text.lower():
            lines = ht_resp.text.strip().split("\n")
            for line in lines:
                parts = line.split(",")
                if parts:
                    sub = parts[0].strip().lower()
                    if sub.endswith(domain) and not sub.startswith("*"):
                        discovered.add(sub)
    except Exception as e:
        errors.append(f"HackerTarget query failed: {str(e)}")

    # Source 2: crt.sh Fallback
    try:
        crt_url = f"https://crt.sh/?q=%.{domain}&output=json"
        crt_resp = requests.get(crt_url, headers={"User-Agent": "EASM-Sentinel/1.0"}, timeout=10)
        if crt_resp.status_code == 200:
            entries = crt_resp.json()
            for entry in entries:
                name_val = entry.get("name_value", "")
                for sub in name_val.split("\n"):
                    sub_clean = sub.strip().lower()
                    if sub_clean.endswith(domain) and not sub_clean.startswith("*"):
                        discovered.add(sub_clean)
        else:
            errors.append(f"crt.sh returned HTTP {crt_resp.status_code}")
    except Exception as e:
        errors.append(f"crt.sh query failed: {str(e)}")

    error_msg = " | ".join(errors) if (not discovered and errors) else None
    return sorted(list(discovered))[:30], error_msg

import requests
from typing import List, Tuple, Optional
from core.models import ShodanResult

def query_shodan_passive(domain: str, api_key: str) -> Tuple[List[ShodanResult], Optional[str]]:
    """Passively retrieves host open ports and service banners via Shodan API."""
    if not api_key:
        return [], "Shodan API Key missing. Passive port fingerprinting skipped."

    url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=hostname:{domain}"
    
    try:
        resp = requests.get(url, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            hosts = []
            for match in data.get("matches", []):
                raw_port = match.get("port")
                # Wrap integer port into a list to match the dataclass schema
                ports_list = [raw_port] if isinstance(raw_port, int) else (raw_port if isinstance(raw_port, list) else [])
                
                hosts.append(ShodanResult(
                    ip=match.get("ip_str", ""),
                    ports=ports_list,
                    hostnames=match.get("hostnames", []),
                    org=match.get("org", "N/A")
                ))
            return hosts[:5], None
        elif resp.status_code == 401:
            return [], "Invalid Shodan API Key."
        return [], f"Shodan API error: {resp.status_code}"
    except Exception as e:
        return [], f"Shodan fetch failed: {str(e)}"

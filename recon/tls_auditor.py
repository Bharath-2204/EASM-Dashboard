import ssl
import socket
from datetime import datetime, timezone
from typing import Tuple, Optional
from core.models import TLSAuditResult
from core.config import settings

def audit_tls_endpoint(domain: str) -> Tuple[Optional[TLSAuditResult], Optional[str]]:
    """Performs native SSL/TLS inspection on target domain on port 443."""
    context = ssl.create_default_context()
    
    try:
        with socket.create_connection((domain, 443), timeout=settings.REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                issuer = issuer_dict.get("organizationName", issuer_dict.get("commonName", "Unknown Issuer"))
                
                not_after_str = cert.get("notAfter", "")
                exp_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                
                days_left = (exp_date - now).days
                is_expired = days_left < 0
                
                sans = [item[1] for item in cert.get("subjectAltName", []) if item[0] == "DNS"]
                cipher_version = f"{cipher[0]} ({cipher[1]})" if cipher else "Unknown Protocol"
                
                result = TLSAuditResult(
                    issuer=issuer,
                    expiration_date=exp_date.strftime("%Y-%m-%d"),
                    days_left=days_left,
                    cipher_version=cipher_version,
                    is_expired=is_expired,
                    sans=sans
                )
                return result, None

    except socket.timeout:
        return None, f"Connection to {domain}:443 timed out."
    except ssl.SSLError as e:
        return None, f"SSL Handshake failed for {domain}: {e.reason}"
    except Exception as e:
        return None, f"TLS inspection error for {domain}: {str(e)}"

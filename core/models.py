from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class TLSAuditResult:
    issuer: str
    expiration_date: str
    days_left: int
    cipher_version: str
    is_expired: bool
    sans: List[str] = field(default_factory=list)

@dataclass
class ShodanResult:
    ip: str
    ports: List[int] = field(default_factory=list)
    hostnames: List[str] = field(default_factory=list)
    org: str = "N/A"

@dataclass
class ExtendedOSINTResult:
    domain: str
    ct_subdomains: List[str] = field(default_factory=list)
    tls_audit: Optional[TLSAuditResult] = None
    shodan_hosts: List[ShodanResult] = field(default_factory=list)
    github_leaks: List[dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

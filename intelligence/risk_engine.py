from dataclasses import dataclass, field
from typing import List
from core.models import ExtendedOSINTResult

@dataclass
class RiskAssessment:
    score: int
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    factors: List[str] = field(default_factory=list)

def calculate_risk_score(data: ExtendedOSINTResult) -> RiskAssessment:
    """
    Calculates a weighted attack surface risk score based on discovered telemetry.
    
    Scoring Weights:
    - GitHub Credential Leaks: +30 points per leak (Max: 60)
    - Expired TLS Certificate: +25 points
    - High-Risk Open Ports (RDP, DBs, Management Interfaces): +15 points per host (Max: 30)
    - Broad Subdomain Surface (>15 endpoints): +10 points
    """
    raw_score = 0
    factors = []

    # 1. GitHub Secrets / Configuration Leaks (Highest Severity)
    if data.github_leaks:
        leak_count = len(data.github_leaks)
        points = min(leak_count * 30, 60)
        raw_score += points
        factors.append(f"CRITICAL: Identified {leak_count} exposed sensitive configuration/credential file(s) on GitHub (+{points} pts)")

    # 2. TLS/SSL Security Posture
    if data.tls_audit:
        if data.tls_audit.is_expired:
            raw_score += 25
            factors.append("HIGH: Endpoint TLS/SSL certificate is expired (+25 pts)")
        elif data.tls_audit.days_left < 14 and data.tls_audit.days_left >= 0:
            raw_score += 10
            factors.append(f"MEDIUM: Endpoint TLS certificate expiring soon ({data.tls_audit.days_left} days left) (+10 pts)")

    # 3. Exposed Services & High-Risk Ports (Shodan)
    high_risk_ports = {22, 3389, 1433, 3306, 5432, 6379, 27017, 9200, 11211}  # SSH, RDP, DBs, Redis, Mongo, ES
    for host in data.shodan_hosts:
        # Guarantee host.ports is an iterable list/tuple/set
        ports_iterable = host.ports if isinstance(host.ports, (list, tuple, set)) else [host.ports]
        exposed_dangerous = set(ports_iterable).intersection(high_risk_ports)
        if exposed_dangerous:
            raw_score += 15
            factors.append(f"HIGH: Host {host.ip} exposes high-risk management/database port(s) {list(exposed_dangerous)} (+15 pts)")
            break

    # 4. Attack Surface Breadth (Certificate Transparency)
    if len(data.ct_subdomains) > 15:
        raw_score += 10
        factors.append(f"LOW: Large external attack surface area detected ({len(data.ct_subdomains)} subdomains) (+10 pts)")

    # Normalize score ceiling
    final_score = min(raw_score, 100)

    # Severity Tiering
    if final_score >= 75:
        severity = "CRITICAL"
    elif final_score >= 50:
        severity = "HIGH"
    elif final_score >= 25:
        severity = "MEDIUM"
    elif final_score > 0:
        severity = "LOW"
    else:
        severity = "INFORMATIONAL"

    return RiskAssessment(
        score=final_score,
        severity=severity,
        factors=factors if factors else ["No immediate high-severity risk vectors identified."]
    )

import json
import uuid
from datetime import datetime, timezone
from core.models import ExtendedOSINTResult

def generate_stix_bundle(data: ExtendedOSINTResult) -> str:
    """Serializes ExtendedOSINTResult telemetry into a STIX 2.1 JSON Bundle."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    bundle_id = f"bundle--{uuid.uuid4()}"
    objects = []

    # 1. Target Domain Observable (SCO)
    target_domain_id = f"domain-name--{uuid.uuid4()}"
    objects.append({
        "type": "domain-name",
        "spec_version": "2.1",
        "id": target_domain_id,
        "value": data.domain
    })

    # 2. Subdomain Observables
    for sub in data.ct_subdomains:
        objects.append({
            "type": "domain-name",
            "spec_version": "2.1",
            "id": f"domain-name--{uuid.uuid4()}",
            "value": sub
        })

    # 3. Shodan Exposed Infrastructure (IPv4 & Infrastructure SDOs)
    for host in data.shodan_hosts:
        ip_id = f"ipv4-addr--{uuid.uuid4()}"
        objects.append({
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": ip_id,
            "value": host.ip
        })

        infra_id = f"infrastructure--{uuid.uuid4()}"
        objects.append({
            "type": "infrastructure",
            "spec_version": "2.1",
            "id": infra_id,
            "created": now,
            "modified": now,
            "name": f"Exposed Infrastructure: {host.ip}",
            "description": f"Organization: {host.org} | Open Ports: {host.ports} | Hostnames: {', '.join(host.hostnames)}",
            "infrastructure_types": ["hosting-target"]
        })

    # 4. Indicator SDOs for GitHub Leaks (if any)
    for leak in data.github_leaks:
        indicator_id = f"indicator--{uuid.uuid4()}"
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now,
            "modified": now,
            "name": f"Exposed Credential/Config File: {leak.get('file')}",
            "description": f"Public repo leak detected at {leak.get('url')}",
            "pattern": f"[file:name = '{leak.get('file')}']",
            "pattern_type": "stix",
            "valid_from": now
        })

    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects
    }

    return json.dumps(bundle, indent=2)

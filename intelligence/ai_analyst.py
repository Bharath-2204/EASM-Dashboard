import json
import boto3
from core.models import ExtendedOSINTResult
from core.config import settings

def _build_strict_prompt(data: ExtendedOSINTResult) -> str:
    shodan_hosts_summary = []
    shodan_subdomains = []
    for h in data.shodan_hosts:
        shodan_hosts_summary.append(f"IP: {h.ip} (Ports: {h.ports}, Org: {h.org})")
        shodan_subdomains.extend(h.hostnames)

    all_discovered_subs = sorted(list(set(data.ct_subdomains + shodan_subdomains)))
    tls_sans = data.tls_audit.sans if data.tls_audit else []

    telemetry_json = {
        "target_domain": data.domain,
        "discovered_subdomains_count": len(all_discovered_subs),
        "sample_subdomains": all_discovered_subs[:10],
        "tls_status": {
            "issuer": data.tls_audit.issuer if data.tls_audit else "Unknown",
            "days_remaining": data.tls_audit.days_left if data.tls_audit else -1,
            "is_expired": data.tls_audit.is_expired if data.tls_audit else False,
            "sans_sample": tls_sans[:5]
        },
        "shodan_exposure": shodan_hosts_summary,
        "github_leak_count": len(data.github_leaks)
    }

    return f"""
Synthesize raw OSINT telemetry into an executive threat intelligence briefing.

OSINT Telemetry JSON:
{json.dumps(telemetry_json, indent=2)}

Output Requirements:
1. Two concise paragraphs evaluating infrastructure attack surface, TLS certificate health, and credential leakage risks for domain '{data.domain}'.
2. A 'MITRE ATT&CK Mapping' section formatted as:
   - [Technique ID] - [Technique Name]: [Risk Explanation]
"""

def generate_mitre_briefing(data: ExtendedOSINTResult):
    """Streams executive security report via Bedrock Converse Stream API."""
    user_prompt = _build_strict_prompt(data)
    system_prompt = (
        "You are an Enterprise Cyber Threat Intelligence Lead. "
        "Base analysis ONLY on the target domain and provided JSON telemetry. "
        "NEVER invent fictional entities, training datasets, or placeholder text. "
        "If telemetry is clean or missing, explicitly report low risk exposure."
    )

    try:
        session_kwargs = {"region_name": settings.AWS_REGION}
        if settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
            session_kwargs["aws_access_key_id"] = settings.AWS_ACCESS_KEY_ID
            session_kwargs["aws_secret_access_key"] = settings.AWS_SECRET_ACCESS_KEY

        bedrock = boto3.client(service_name="bedrock-runtime", **session_kwargs)

        # Unified Converse API supported across Meta Llama 3/3.1, Claude, and Mistral
        response = bedrock.converse_stream(
            modelId=settings.BEDROCK_MODEL_ID,
            system=[{"text": system_prompt}],
            messages=[
                {
                    "role": "user",
                    "content": [{"text": user_prompt}]
                }
            ],
            inferenceConfig={
                "temperature": 0.2,
                "maxTokens": 1000
            }
        )

        for event in response.get("stream", []):
            if "contentBlockDelta" in event:
                delta = event["contentBlockDelta"].get("delta", {})
                if "text" in delta:
                    yield delta["text"]

    except Exception as e:
        yield f"⚠️ AWS Bedrock Connection Error: {str(e)}\n\nPlease ensure 'Meta Llama 3.1 8B Instruct' model access is granted under AWS Bedrock > Model access."

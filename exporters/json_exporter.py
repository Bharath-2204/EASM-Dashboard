import json
from dataclasses import asdict
from core.models import ExtendedOSINTResult

def generate_json_export(data: ExtendedOSINTResult) -> str:
    """Converts dataclass OSINT result into clean, formatted JSON."""
    return json.dumps(asdict(data), indent=2)

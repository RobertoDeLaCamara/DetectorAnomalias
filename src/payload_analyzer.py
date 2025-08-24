import re
from .config import MALICIOUS_PATTERNS

def detect_malicious_payload(payload):
    """Analyzes the payload content to detect suspicious patterns."""
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, payload):
            return True, pattern.decode('utf-8', errors='ignore')
    return False, None

import ipaddress
import re
from typing import Optional, Tuple

from app.models.indicator import IndicatorType

SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")
MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")

def defang_or_clean(raw_val: str) -> str:
    """Cleans defanged indicators like hxxp://, 1[.]1[.]1[.]1, etc."""
    cleaned = raw_val.strip()
    cleaned = cleaned.replace("[.]", ".").replace("(.)", ".").replace("hxxp", "http")
    return cleaned

def detect_indicator_type(val: str) -> Tuple[Optional[IndicatorType], str]:
    """
    Detects indicator type and returns (IndicatorType, cleaned_value).
    """
    cleaned = defang_or_clean(val)

    # 1. IP check
    try:
        ipaddress.ip_address(cleaned)
        return IndicatorType.IP, cleaned
    except ValueError:
        pass

    # 2. Hash SHA-256
    if SHA256_REGEX.match(cleaned):
        return IndicatorType.HASH_SHA256, cleaned.lower()

    # 3. Hash MD5
    if MD5_REGEX.match(cleaned):
        return IndicatorType.HASH_MD5, cleaned.lower()

    # 4. CVE
    if CVE_REGEX.match(cleaned):
        return IndicatorType.CVE, cleaned.upper()

    # 5. Email
    if EMAIL_REGEX.match(cleaned):
        return IndicatorType.EMAIL, cleaned.lower()

    # 6. URL
    if cleaned.startswith("http://") or cleaned.startswith("https://") or "/" in cleaned:
        return IndicatorType.URL, cleaned

    # 7. Domain
    if DOMAIN_REGEX.match(cleaned):
        return IndicatorType.DOMAIN, cleaned.lower()

    return None, cleaned

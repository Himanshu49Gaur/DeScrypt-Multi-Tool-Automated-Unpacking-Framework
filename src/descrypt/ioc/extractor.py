"""Indicator of Compromise (IoC) extraction, defanging, and noise filtering.

Paper References:
- Section 3.4: DeScrypt recovered an indicator for 7.0% of samples
- Section 3.4 & 3.7: _is_noise_url filters out benign domains such as 'w3.org' SVG namespaces
- Appendix E: Extracted defanged URL and IP
"""

from __future__ import annotations

import re
from typing import Dict, List, Set

# Regex patterns for URL and IPv4 addresses
_URL_REGEX = re.compile(r"""https?://[a-zA-Z0-9_\-\.:]+(?:/[^\s'"\)<>]*[^\s'"\)<>\.,])?""")
_IP_REGEX = re.compile(r"""\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b""")

# Known benign domains and XML namespaces filtered by _is_noise_url (Section 3.4, 3.7)
_NOISE_DOMAINS = {
    "w3.org",
    "schemas.microsoft.com",
    "schema.org",
    "xmlsoap.org",
    "openxmlformats.org",
    "adobe.com",
    "apple.com",
}


def is_noise_url(url: str) -> bool:
    """Checks whether a URL matches known benign noise schemas/namespaces."""
    lower = url.lower()
    for domain in _NOISE_DOMAINS:
        if domain in lower:
            return True
    return False


def defang_url(url: str) -> str:
    """Defangs a URL by replacing http with hxxp and period with [.]."""
    defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    # Defang dots in the host/path appropriately
    # Replace dots with [.]
    parts = defanged.split("://", 1)
    if len(parts) == 2:
        scheme, rest = parts
        # If rest has a path, defang host and filename extension
        defanged_rest = rest.replace(".", "[.]")
        return f"{scheme}://{defanged_rest}"
    return defanged.replace(".", "[.]")


def defang_ip(ip: str) -> str:
    """Defangs an IPv4 address by replacing dots with [.]."""
    return ip.replace(".", "[.]")


def extract_iocs(text: str) -> List[Dict[str, str]]:
    """Extracts, defangs, and filters IoCs from text."""
    if not text:
        return []

    iocs: List[Dict[str, str]] = []
    seen: Set[str] = set()

    # Extract URLs
    for raw_url in _URL_REGEX.findall(text):
        if is_noise_url(raw_url):
            continue
        defanged = defang_url(raw_url)
        if defanged not in seen:
            seen.add(defanged)
            iocs.append({"kind": "url", "value": defanged})

    # Extract IPs
    for raw_ip in _IP_REGEX.findall(text):
        # Ignore localhost or standard masks
        if raw_ip.startswith("127.") or raw_ip == "0.0.0.0" or raw_ip == "255.255.255.255":
            continue
        defanged = defang_ip(raw_ip)
        if defanged not in seen:
            seen.add(defanged)
            iocs.append({"kind": "ip", "value": defanged})

    return iocs

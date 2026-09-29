"""Content type and Shannon entropy detection.

Paper References:
- Section 2.1: Detect layer (YARA/Python)
- Section 3.2: Clean terminal state requirement, entropy levels (H3.0, H5.7, H7.8)
- Appendix E: Logged entropy and script detection
"""

from __future__ import annotations

import math
import re
from collections import Counter


def calculate_shannon_entropy(data: bytes | str) -> float:
    """Computes byte-level Shannon entropy in bits per byte (range 0.0 to 8.0).

    Formula: H(X) = - sum(p_i * log2(p_i))
    """
    if not data:
        return 0.0
    if isinstance(data, str):
        byte_data = data.encode("utf-8", errors="ignore")
    else:
        byte_data = data

    n = len(byte_data)
    if n == 0:
        return 0.0

    counts = Counter(byte_data)
    entropy = 0.0
    for count in counts.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)

    return round(entropy, 1)


# Compiled regular expressions for language detection
_PE_MAGIC = b"MZ"
_PS_INDICATORS = re.compile(
    r"(\$[a-zA-Z0-9_]+\s*=|\[System\.|\[ScriptBlock\]|Start-Process|New-Object|"
    r"Invoke-Expression|IEX\b|Get-Random|-join\b|-replace\b|WriteAllBytes|SecurityProtocol|"
    r"WinHTTP\.WinHTTPRequest|DownloadString|powershell)",
    re.IGNORECASE,
)
_JS_INDICATORS = re.compile(
    r"(\bfunction\b|\bvar\s+[a-zA-Z0-9_]+\b|\blet\s+[a-zA-Z0-9_]+\b|"
    r"\bconst\s+[a-zA-Z0-9_]+\b|\beval\s*\(|\bString\.fromCharCode\b|"
    r"document\.|window\.|console\.log|\.charCodeAt\b)",
    re.IGNORECASE,
)
_VBS_INDICATORS = re.compile(
    r"(\bdim\s+[a-zA-Z0-9_]+\b|\bWScript\.\b|\bCreateObject\s*\(|"
    r"\bSub\s+[a-zA-Z0-9_]+\b|\bEnd\s+Sub\b|\bOn\s+Error\s+Resume\s+Next\b)",
    re.IGNORECASE,
)


def detect_content_type(data: bytes | str) -> str:
    """Detects content type of a layer payload.

    Returns one of: 'powershell', 'javascript', 'vbscript', 'pe', 'binary', 'unknown'.
    """
    if not data:
        return "unknown"

    byte_data = data.encode("utf-8", errors="ignore") if isinstance(data, str) else data

    if byte_data.startswith(_PE_MAGIC):
        return "pe"

    # Check non-printable ratio for binary detection
    non_printable = sum(1 for b in byte_data if b < 9 or (13 < b < 32) or b > 126)
    if len(byte_data) > 32 and (non_printable / len(byte_data)) > 0.35:
        return "binary"

    text = ""
    try:
        text = byte_data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = byte_data.decode("latin-1")
        except Exception:
            return "binary"

    ps_matches = len(_PS_INDICATORS.findall(text))
    js_matches = len(_JS_INDICATORS.findall(text))
    vbs_matches = len(_VBS_INDICATORS.findall(text))

    if ps_matches > js_matches and ps_matches > vbs_matches and ps_matches > 0:
        return "powershell"
    if js_matches > ps_matches and js_matches > vbs_matches and js_matches > 0:
        return "javascript"
    if vbs_matches > 0 and vbs_matches >= js_matches and vbs_matches >= ps_matches:
        return "vbscript"

    if ps_matches > 0:
        return "powershell"
    if js_matches > 0:
        return "javascript"

    return "unknown"


def is_clean_terminal(
    content: bytes | str,
    content_type: str,
    entropy: float,
    entropy_threshold: float = 6.5,
) -> bool:
    """Determines whether a layer represents a clean terminal payload.

    Paper Section 3.1 & 3.2: Confirmed to be readable script or PE,
    with no remaining base64 encoding or high-entropy sections.
    """
    if content_type not in ("powershell", "javascript", "vbscript", "pe"):
        return False

    if entropy >= entropy_threshold:
        return False

    text = content.decode("utf-8", errors="ignore") if isinstance(content, bytes) else content

    # Check for prominent remaining base64 blobs (>64 chars unbroken alnum+/=)
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{64,}={0,2}")
    if b64_pattern.search(text):
        return False

    # Check for obvious nested eval/packer wrappers
    if re.search(r"(\beval\s*\(|\[ScriptBlock\]::Create)", text):
        return False

    return True

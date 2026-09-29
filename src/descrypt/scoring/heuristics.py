"""Detection heuristics and behavioral rules for DeScrypt.

Paper References:
- Section 2.1: Detection layer combining YARA and behavioral heuristics
- Section 3.4: Suspicious API calls (WinHTTP, DownloadString, WriteAllBytes, Start-Process)
- Section 3.7: Tuned weights (js_eval_packer reduced to 0.1 to avoid FP on lodash)
- Appendix E: Signals and scoring on recovered payload
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from descrypt.core.tree import Layer


@dataclass
class HeuristicMatch:
    id: str
    canonical_class: str
    weight: float
    description: str
    matched_text: Optional[str] = None


# Heuristic rule definitions: (id, canonical_class, weight, regex, description)
HEURISTIC_RULES = [
    # Cradle & Download behaviors (High risk)
    (
        "ps_winhttp_download",
        "cradle_download",
        0.70,
        r'New-Object\s+-ComObject\s+["\']WinHTTP\.WinHTTPRequest',
        "WinHTTP COM object instantiation for payload download",
    ),
    (
        "ps_download_string",
        "cradle_download",
        0.70,
        r'\.Download(?:String|File|Data)\s*\(',
        "WebClient or HttpClient download method",
    ),
    (
        "ps_write_all_bytes",
        "executable_dropper",
        0.65,
        r'\[(?:System\.)?IO\.File\]::WriteAllBytes\b',
        "Direct binary write to filesystem via IO.File",
    ),
    (
        "ps_start_hidden_process",
        "process_execution",
        0.60,
        r'Start-Process\s+.*-WindowStyle\s+Hidden',
        "Process execution with hidden window style",
    ),
    (
        "ps_security_protocol_tls",
        "c2_setup",
        0.30,
        r'\[(?:System\.)?Net\.ServicePointManager\]::SecurityProtocol\s*=\s*[\'"]Tls12[\'"]',
        "TLS 1.2 protocol force for network connection",
    ),
    (
        "ps_iex_execution",
        "script_eval",
        0.60,
        r'(?:\bIEX\b|\bInvoke-Expression\b|\[ScriptBlock\]::Create\b)',
        "PowerShell dynamic script evaluation cradle",
    ),
    # JavaScript Unpacking & Obfuscation
    (
        "js_eval_packer",
        "eval_packer",
        0.10,  # Tuned down from 0.30 (Section 3.7) to avoid lodash false positives
        r'\b(?:eval|Function)\s*\(',
        "JavaScript dynamic eval or Function constructor packer",
    ),
    (
        "js_from_char_code",
        "char_obfuscation",
        0.25,
        r'String\.fromCharCode\s*\(',
        "Character code array reconstruction",
    ),
    (
        "ps_encoded_command",
        "encoded_command",
        0.40,
        r'-(?:enc(?:odedcommand)?|e)\s+[A-Za-z0-9+/=]{16,}',
        "Base64 encoded command execution argument",
    ),
    (
        "generic_high_entropy_blob",
        "packed_payload",
        0.30,
        r'[A-Za-z0-9+/]{128,}={0,2}',
        "Extensive unbroken Base64 blob in script",
    ),
    (
        "ps_c2_url_embedded",
        "c2_communication",
        0.50,
        r'https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d+)?/[^\s\'"\)]+',
        "Direct IP-based HTTP URL found in script",
    ),
    (
        "ps_from_char_code",
        "char_obfuscation",
        0.25,
        r'\[char\]\s*\d+\s*(?:\+\s*\[char\]\s*\d+)+',
        "PowerShell [char] integer addition chain",
    ),
    (
        "ps_reflection_load",
        "process_execution",
        0.65,
        r'\[(?:System\.)?Reflection\.Assembly\]::Load\b',
        ".NET dynamic reflective assembly loader",
    ),
    (
        "vbs_wscript_shell",
        "script_eval",
        0.35,
        r'CreateObject\s*\(\s*["\']WScript\.Shell["\']',
        "VBScript WScript.Shell object creation",
    ),
    (
        "js_document_write",
        "dom_manipulation",
        0.20,
        r'(?:document\.write\s*\(|window\[[\'"]location[\'"]\])',
        "JavaScript dynamic DOM injection or redirection",
    ),
    (
        "ps_string_manipulation",
        "string_manipulation",
        0.30,
        r'\.Replace\s*\([^)]+\)\.Replace\s*\(',
        "Chained string replacement obfuscation",
    ),
    (
        "generic_hex_payload",
        "packed_payload",
        0.40,
        r'(?:\\x[0-9a-fA-F]{2}){16,}',
        "Long raw byte / shellcode hex stream",
    ),
]


def evaluate_heuristics(layer: Layer) -> List[HeuristicMatch]:
    """Runs behavioral heuristics and detectors against a layer."""
    text = layer.text
    if not text:
        return []

    matches: List[HeuristicMatch] = []
    for hid, c_class, weight, pattern, desc in HEURISTIC_RULES:
        found = re.search(pattern, text, re.IGNORECASE)
        if found:
            matches.append(
                HeuristicMatch(
                    id=hid,
                    canonical_class=c_class,
                    weight=weight,
                    description=desc,
                    matched_text=found.group(0),
                )
            )

    return matches

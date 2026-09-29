"""ROT13 substitution cipher decoding tool for DeScrypt.

Paper References:
- Section 3.3, Figure 5: generic.rot13 (5 invocations across malicious corpus)
"""

from __future__ import annotations

import codecs
import re
from descrypt.core.tree import Layer
from descrypt.tools.base import Tool, ToolResult

# Indicators that content might be ROT13 (e.g. 'cbjrefuryy' -> 'powershell', 'jvaubfg' -> 'winhost')
_ROT13_INDICATORS = re.compile(
    r"""\b(?:cbjrefuryy|vachg|inyhr|hfre|fpevcg|ybpny|cebprff|uggc|uggcf)\b""",
    re.IGNORECASE,
)


class Rot13Tool(Tool):
    """Decodes ROT-13 caesar cipher substitutions."""

    @property
    def name(self) -> str:
        return "generic.rot13"

    def can_handle(self, layer: Layer) -> float:
        text = layer.text
        if not text:
            return 0.0

        matches = len(_ROT13_INDICATORS.findall(text))
        if matches >= 2:
            return 0.85
        elif matches == 1:
            return 0.50
        return 0.0

    def execute(self, layer: Layer) -> ToolResult:
        text = layer.text
        if not text:
            return ToolResult(success=False, error="Empty text")

        decoded = codecs.decode(text, "rot_13")
        return ToolResult(
            success=True,
            output=decoded.encode("utf-8"),
            metadata={"cipher": "rot13"},
        )

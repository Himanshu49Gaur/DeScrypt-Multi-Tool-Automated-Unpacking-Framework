"""Character code decoding tool for DeScrypt.

Paper References:
- Section 3.3, Figure 5: generic.charcode_decode (25 invocations across malicious corpus)
- Section 3.3: 41 samples that attempted to restructure a sample using fromCharCode
"""

from __future__ import annotations

import re
from descrypt.core.tree import Layer
from descrypt.tools.base import Tool, ToolResult

# Match JavaScript String.fromCharCode(72, 101, ...)
_JS_FROM_CHARCODE = re.compile(
    r"""String\.fromCharCode\s*\(\s*([0-9\s,]+)\s*\)""",
    re.IGNORECASE,
)
# Match PowerShell [char[]](72, 101, ...) or [char[]]@(72, 101, ...)
_PS_CHAR_ARRAY = re.compile(
    r"""\[char\[\]\]\s*(?:@\()?\s*([0-9\s,]+)\s*\)?""",
    re.IGNORECASE,
)


class CharCodeDecodeTool(Tool):
    """Decodes integer character arrays generated via fromCharCode or [char[]]."""

    @property
    def name(self) -> str:
        return "generic.charcode_decode"

    def can_handle(self, layer: Layer) -> float:
        text = layer.text
        if not text:
            return 0.0

        if _JS_FROM_CHARCODE.search(text) or _PS_CHAR_ARRAY.search(text):
            return 0.90
        return 0.0

    def execute(self, layer: Layer) -> ToolResult:
        text = layer.text
        if not text:
            return ToolResult(success=False, error="Empty text")

        original = text

        def _resolve_js_charcode(m: re.Match) -> str:
            nums_str = m.group(1)
            chars = []
            for n in nums_str.split(","):
                n = n.strip()
                if n.isdigit():
                    chars.append(chr(int(n)))
            decoded = "".join(chars)
            return f'"{decoded}"'

        text = _JS_FROM_CHARCODE.sub(_resolve_js_charcode, text)

        def _resolve_ps_charcode(m: re.Match) -> str:
            nums_str = m.group(1)
            chars = []
            for n in nums_str.split(","):
                n = n.strip()
                if n.isdigit():
                    chars.append(chr(int(n)))
            decoded = "".join(chars)
            return f'"{decoded}"'

        text = _PS_CHAR_ARRAY.sub(_resolve_ps_charcode, text)

        if text == original:
            return ToolResult(success=False, error="No character code sequences resolved")

        return ToolResult(
            success=True,
            output=text.encode("utf-8"),
            metadata={"resolved": True},
        )

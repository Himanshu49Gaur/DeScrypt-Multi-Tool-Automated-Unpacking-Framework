"""Escape decoding tool (URL, hex, and unicode unescaping) for DeScrypt.

Paper References:
- Section 3.3: 215 invocations across malicious corpus
- Section 3.6, Figure 10: S1 d0 -> generic.escape_decode
"""

from __future__ import annotations

import re
import urllib.parse

from descrypt.core.tree import Layer
from descrypt.tools.base import Tool, ToolResult

_HEX_ESCAPE_REGEX = re.compile(r"\\x([0-9a-fA-F]{2})")
_URL_ESCAPE_REGEX = re.compile(r"%([0-9a-fA-F]{2})")
_UNICODE_ESCAPE_REGEX = re.compile(r"\\u([0-9a-fA-F]{4})")


class EscapeDecodeTool(Tool):
    """Decodes URL percent-encoding and \\xHH / \\uHHHH character escapes."""

    @property
    def name(self) -> str:
        return "generic.escape_decode"

    def can_handle(self, layer: Layer) -> float:
        text = layer.text
        if not text:
            return 0.0

        url_escapes = len(_URL_ESCAPE_REGEX.findall(text))
        hex_escapes = len(_HEX_ESCAPE_REGEX.findall(text))
        uni_escapes = len(_UNICODE_ESCAPE_REGEX.findall(text))

        total = url_escapes + hex_escapes + uni_escapes
        if total > 10:
            return 0.90
        elif total > 0:
            return 0.60
        return 0.0

    def execute(self, layer: Layer) -> ToolResult:
        text = layer.text
        if not text:
            return ToolResult(success=False, error="Empty text")

        # Unescape URL percent encoding
        decoded = urllib.parse.unquote(text)

        # Unescape \xHH
        def _replace_hex(m: re.Match) -> str:
            try:
                return chr(int(m.group(1), 16))
            except Exception:
                return m.group(0)

        decoded = _HEX_ESCAPE_REGEX.sub(_replace_hex, decoded)

        # Unescape \uHHHH
        def _replace_uni(m: re.Match) -> str:
            try:
                return chr(int(m.group(1), 16))
            except Exception:
                return m.group(0)

        decoded = _UNICODE_ESCAPE_REGEX.sub(_replace_uni, decoded)

        if decoded == text:
            return ToolResult(success=False, error="No escape sequences decoded")

        return ToolResult(
            success=True,
            output=decoded.encode("utf-8"),
            metadata={"original_len": len(text), "decoded_len": len(decoded)},
        )

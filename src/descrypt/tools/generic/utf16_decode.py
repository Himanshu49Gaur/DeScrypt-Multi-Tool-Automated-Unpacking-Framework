"""UTF-16 decoding tool for DeScrypt.

Paper References:
- Section 3.3: 136 invocations across malicious corpus
- Appendix E: Chained immediately after base64_decode (utf-16-le, 5029 chars and 1741 chars)
"""

from __future__ import annotations

from descrypt.core.tree import Layer
from descrypt.tools.base import Tool, ToolResult


class Utf16DecodeTool(Tool):
    """Detects and decodes UTF-16 Little Endian (common in PowerShell payloads)."""

    @property
    def name(self) -> str:
        return "generic.utf16_decode"

    def _is_utf16_le(self, content: bytes) -> bool:
        if len(content) < 4:
            return False
        # Check BOM
        if content.startswith(b"\xff\xfe"):
            return True
        # Check null byte interleaving in even positions (ASCII text in UTF-16LE)
        # In UTF-16LE ASCII chars 'A' is 0x41 0x00
        null_count = sum(1 for i in range(1, min(len(content), 200), 2) if content[i] == 0)
        ratio = null_count / (min(len(content), 200) // 2)
        return ratio > 0.65

    def can_handle(self, layer: Layer) -> float:
        if self._is_utf16_le(layer.content):
            return 0.95
        return 0.0

    def execute(self, layer: Layer) -> ToolResult:
        content = layer.content
        if not self._is_utf16_le(content):
            return ToolResult(success=False, error="Content does not appear to be UTF-16LE")

        try:
            # Strip BOM if present
            raw = content
            if raw.startswith(b"\xff\xfe"):
                raw = raw[2:]
            decoded_text = raw.decode("utf-16-le")
            # Filter null characters if any trailing
            decoded_text = decoded_text.replace("\x00", "")

            output_bytes = decoded_text.encode("utf-8")
            return ToolResult(
                success=True,
                output=output_bytes,
                metadata={
                    "encoding": "utf-16-le",
                    "decoded_chars": len(decoded_text),
                },
            )
        except Exception as e:
            return ToolResult(success=False, error=f"UTF-16 decode failed: {e}")

"""XOR key search and decoding tool for DeScrypt.

Paper References:
- Section 2.1 & Section 3.3: xorsearch tool invocation attempts (54 invocations in Section 3.3)
"""

from __future__ import annotations

from descrypt.core.tree import Layer
from descrypt.tools.base import Tool, ToolResult

_MARKERS = [b"powershell", b"http://", b"https://", b"function", b"WScript", b"This program"]


class XorSearchTool(Tool):
    """Brute forces 1-byte XOR keys looking for known script and protocol signatures."""

    @property
    def name(self) -> str:
        return "generic.xorsearch"

    def _find_xor_key(self, data: bytes) -> tuple[int, bytes] | None:
        if len(data) < 16:
            return None
        # Try all 255 non-zero single-byte XOR keys
        for key in range(1, 256):
            # Check markers on sample
            for marker in _MARKERS:
                xored_marker = bytes(b ^ key for b in marker)
                if xored_marker in data:
                    # Found key
                    full_decrypted = bytes(b ^ key for b in data)
                    return key, full_decrypted
        return None

    def can_handle(self, layer: Layer) -> float:
        # Check if binary, unknown, or elevated entropy
        if layer.content_type in ("binary", "unknown") or layer.entropy > 4.0:
            key_match = self._find_xor_key(layer.content[:1024])
            if key_match:
                return 0.85
        return 0.0

    def execute(self, layer: Layer) -> ToolResult:
        res = self._find_xor_key(layer.content)
        if not res:
            return ToolResult(success=False, error="No 1-byte XOR key matching known signatures found")

        key, decrypted = res
        return ToolResult(
            success=True,
            output=decrypted,
            metadata={"xor_key": hex(key)},
        )

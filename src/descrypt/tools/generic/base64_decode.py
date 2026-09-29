"""Base64 decoding tool for DeScrypt.

Paper References:
- Section 3.3: Most frequent decoder (350 invocations)
- Section 3.7: Enforces minimum length (32+ chars) to prevent false positives
- Appendix E: Logs blob_offset and decoded_bytes
"""

from __future__ import annotations

import base64
import re
from typing import Optional, Tuple

from descrypt.core.tree import Layer
from descrypt.tools.base import Tool, ToolResult

# Match continuous base64 candidates: at least 32 characters of [A-Za-z0-9+/], optional = padding
_B64_REGEX = re.compile(r"([A-Za-z0-9+/]{32,}={0,2})")


class Base64DecodeTool(Tool):
    """Detects and extracts embedded or whole-buffer Base64 blobs."""

    @property
    def name(self) -> str:
        return "generic.base64_decode"

    def _find_candidate(self, text: str) -> Optional[Tuple[int, str]]:
        """Finds the most prominent Base64 candidate in text."""
        matches = list(_B64_REGEX.finditer(text))
        if not matches:
            return None
        # Prioritize largest candidate
        best_match = max(matches, key=lambda m: len(m.group(1)))
        return best_match.start(), best_match.group(1)

    def can_handle(self, layer: Layer) -> float:
        # Check if layer contains valid Base64 string of sufficient length
        text = layer.text
        if not text:
            # Also check if raw bytes look like ASCII base64
            try:
                text = layer.content.decode("ascii")
            except Exception:
                return 0.0

        candidate = self._find_candidate(text)
        if candidate:
            _, b64_str = candidate
            # Higher confidence for larger base64 payloads
            length = len(b64_str)
            if length > 500:
                return 0.95
            elif length > 100:
                return 0.85
            return 0.70
        return 0.0

    def execute(self, layer: Layer) -> ToolResult:
        text = layer.text
        candidate = self._find_candidate(text)
        if not candidate:
            return ToolResult(success=False, error="No base64 candidate found")

        offset, b64_str = candidate
        # Standardize padding
        rem = len(b64_str) % 4
        if rem > 0:
            b64_str += "=" * (4 - rem)

        try:
            decoded = base64.b64decode(b64_str)
            if len(decoded) < 8:
                return ToolResult(success=False, error="Decoded content too short")

            return ToolResult(
                success=True,
                output=decoded,
                metadata={
                    "blob_offset": offset,
                    "decoded_bytes": len(decoded),
                },
            )
        except Exception as e:
            return ToolResult(success=False, error=f"Base64 decode failed: {e}")

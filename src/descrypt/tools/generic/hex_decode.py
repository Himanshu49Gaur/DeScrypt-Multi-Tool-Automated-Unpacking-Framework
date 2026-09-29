"""Hexadecimal decoding tool for DeScrypt.

Paper References:
- Section 3.3, Figure 5: generic.hex_decode (85 invocations across malicious corpus)
"""

from __future__ import annotations

import re
from descrypt.core.tree import Layer
from descrypt.tools.base import Tool, ToolResult

# Match sequences of hex: 0x41, 0x42, ... or continuous hex sequences
_HEX_ARRAY_REGEX = re.compile(
    r"""(?:0x[0-9a-fA-F]{2}\s*,\s*){3,}0x[0-9a-fA-F]{2}""",
    re.IGNORECASE,
)
_HEX_STR_REGEX = re.compile(r"""(?:[0-9a-fA-F]{2}){16,}""")


class HexDecodeTool(Tool):
    """Detects and decodes hexadecimal character arrays or strings."""

    @property
    def name(self) -> str:
        return "generic.hex_decode"

    def can_handle(self, layer: Layer) -> float:
        text = layer.text
        if not text:
            return 0.0

        if _HEX_ARRAY_REGEX.search(text):
            return 0.90

        matches = _HEX_STR_REGEX.findall(text)
        if matches and max(len(m) for m in matches) >= 32:
            return 0.70

        return 0.0

    def execute(self, layer: Layer) -> ToolResult:
        text = layer.text
        if not text:
            return ToolResult(success=False, error="Empty text")

        # 1. Check array format 0x41, 0x42...
        arr_match = _HEX_ARRAY_REGEX.search(text)
        if arr_match:
            hex_chunk = arr_match.group(0)
            byte_vals = [int(h.strip(), 16) for h in hex_chunk.split(",") if h.strip()]
            decoded_bytes = bytes(byte_vals)
            try:
                decoded_str = decoded_bytes.decode("utf-8")
            except Exception:
                decoded_str = decoded_bytes.decode("latin-1", errors="replace")

            new_text = text[: arr_match.start()] + f'"{decoded_str}"' + text[arr_match.end() :]
            return ToolResult(
                success=True,
                output=new_text.encode("utf-8"),
                metadata={"format": "hex_array", "decoded_bytes": len(decoded_bytes)},
            )

        # 2. Check continuous hex string
        str_matches = list(_HEX_STR_REGEX.finditer(text))
        if str_matches:
            best = max(str_matches, key=lambda m: len(m.group(0)))
            raw_hex = best.group(0)
            try:
                decoded_bytes = bytes.fromhex(raw_hex)
                try:
                    decoded_str = decoded_bytes.decode("utf-8")
                except Exception:
                    decoded_str = decoded_bytes.decode("latin-1", errors="replace")

                new_text = text[: best.start()] + f'"{decoded_str}"' + text[best.end() :]
                return ToolResult(
                    success=True,
                    output=new_text.encode("utf-8"),
                    metadata={"format": "hex_string", "decoded_bytes": len(decoded_bytes)},
                )
            except Exception as e:
                return ToolResult(success=False, error=f"Hex decode failed: {e}")

        return ToolResult(success=False, error="No hex sequences found")

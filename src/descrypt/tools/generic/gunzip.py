"""Gzip decompression tool for DeScrypt.

Paper References:
- Section 3.3, Figure 5, Figure 10, Figure 13 (gunzip on binary payload)
"""

from __future__ import annotations

import gzip
import zlib

from descrypt.core.tree import Layer
from descrypt.tools.base import Tool, ToolResult

_GZIP_MAGIC = b"\x1f\x8b"


class GunzipTool(Tool):
    """Decompresses gzip or raw deflate compressed binary blobs."""

    @property
    def name(self) -> str:
        return "generic.gunzip"

    def can_handle(self, layer: Layer) -> float:
        content = layer.content
        if content.startswith(_GZIP_MAGIC):
            return 0.98
        # Check if gzip magic appears inside first 64 bytes
        idx = content.find(_GZIP_MAGIC)
        if 0 <= idx < 64:
            return 0.90
        # Check raw zlib
        if content.startswith(b"\x78\x9c") or content.startswith(b"\x78\x01") or content.startswith(b"\x78\xda"):
            return 0.80
        return 0.0

    def execute(self, layer: Layer) -> ToolResult:
        content = layer.content
        idx = content.find(_GZIP_MAGIC)
        if idx >= 0:
            data = content[idx:]
            try:
                decompressed = gzip.decompress(data)
                return ToolResult(
                    success=True,
                    output=decompressed,
                    metadata={"method": "gzip", "offset": idx, "size": len(decompressed)},
                )
            except Exception:
                pass

        try:
            decompressed = zlib.decompress(content)
            return ToolResult(
                success=True,
                output=decompressed,
                metadata={"method": "zlib", "size": len(decompressed)},
            )
        except Exception as e:
            return ToolResult(success=False, error=f"Gunzip decompression failed: {e}")

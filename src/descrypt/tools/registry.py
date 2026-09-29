"""Tool registry and ranking engine for DeScrypt.

Paper References:
- Section 2.1: Tool Ranking (Confidence)
- Section 3.1: Static vs Dynamic mode exclusions (e.g. excluded_tools=['js.box_js'])
- Section 3.3: Invocations across malicious corpus
"""

from __future__ import annotations

from typing import List, Tuple
from descrypt.core.tree import Layer
from descrypt.tools.base import Tool
from descrypt.tools.generic.base64_decode import Base64DecodeTool
from descrypt.tools.generic.charcode_decode import CharCodeDecodeTool
from descrypt.tools.generic.concat_reassemble import ConcatReassembleTool
from descrypt.tools.generic.dejunk import DejunkTool
from descrypt.tools.generic.escape_decode import EscapeDecodeTool
from descrypt.tools.generic.fold_concat import FoldConcatTool
from descrypt.tools.generic.gunzip import GunzipTool
from descrypt.tools.generic.hex_decode import HexDecodeTool
from descrypt.tools.generic.rot13 import Rot13Tool
from descrypt.tools.generic.utf16_decode import Utf16DecodeTool
from descrypt.tools.generic.xorsearch import XorSearchTool
from descrypt.tools.js.beautify import JsBeautifyTool
from descrypt.tools.powershell.encodedcommand import PowerShellEncodedCommandTool


class ToolRegistry:
    """Maintains available tools and ranks viable candidates for unpacking a layer."""

    def __init__(self, mode: str = "static"):
        self.mode = mode
        self.tools: list[Tool] = [
            Base64DecodeTool(),
            Utf16DecodeTool(),
            DejunkTool(),
            GunzipTool(),
            EscapeDecodeTool(),
            FoldConcatTool(),
            PowerShellEncodedCommandTool(),
            HexDecodeTool(),
            CharCodeDecodeTool(),
            ConcatReassembleTool(),
            Rot13Tool(),
            JsBeautifyTool(),
            XorSearchTool(),
        ]

    def register_tool(self, tool: Tool) -> None:
        self.tools.append(tool)

    def rank_candidates(self, layer: Layer) -> List[Tuple[Tool, float]]:
        """Ranks viable tools for the current layer by confidence score.

        Returns:
            List of (tool, confidence) tuples sorted from highest to lowest confidence.
        """
        candidates: List[Tuple[Tool, float]] = []
        for tool in self.tools:
            if self.mode == "static" and tool.is_dynamic:
                continue
            conf = tool.can_handle(layer)
            if conf > 0.0:
                candidates.append((tool, conf))

        # Sort descending by confidence
        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates

"""Array join and string concatenation reassembly tool for DeScrypt.

Paper References:
- Section 3.3, Figure 5: generic.concat_reassemble (14 invocations across malicious corpus)
"""

from __future__ import annotations

import re
from descrypt.core.tree import Layer
from descrypt.tools.base import Tool, ToolResult

# Match JavaScript array join: ['foo', 'bar'].join('') or ["foo", "bar"].join("")
_JS_ARRAY_JOIN = re.compile(
    r"""\[((?:['"][^'"]*['"]\s*,\s*)*['"][^'"]*['"])\]\.join\s*\(\s*['"]\s*['"]\s*\)"""
)


class ConcatReassembleTool(Tool):
    """Reassembles fragmented array joins in scripts."""

    @property
    def name(self) -> str:
        return "generic.concat_reassemble"

    def can_handle(self, layer: Layer) -> float:
        text = layer.text
        if not text:
            return 0.0

        matches = len(_JS_ARRAY_JOIN.findall(text))
        if matches >= 2:
            return 0.90
        elif matches == 1:
            return 0.65
        return 0.0

    def execute(self, layer: Layer) -> ToolResult:
        text = layer.text
        original = text

        def _resolve_array_join(m: re.Match) -> str:
            items_str = m.group(1)
            parts = re.findall(r"""['"]([^'"]*)['"]""", items_str)
            joined = "".join(parts)
            return f'"{joined}"'

        text = _JS_ARRAY_JOIN.sub(_resolve_array_join, text)

        if text == original:
            return ToolResult(success=False, error="No array joins reassembled")

        return ToolResult(
            success=True,
            output=text.encode("utf-8"),
            metadata={"reassembled_count": len(_JS_ARRAY_JOIN.findall(original))},
        )

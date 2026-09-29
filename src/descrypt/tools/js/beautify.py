"""JavaScript code formatting and beautification tool for DeScrypt.

Paper References:
- Section 3.3, Figure 5: js.beautify (120 invocations across malicious corpus)
"""

from __future__ import annotations

import re
from descrypt.core.tree import Layer
from descrypt.tools.base import Tool, ToolResult


class JsBeautifyTool(Tool):
    """Beautifies and formats dense or minified JavaScript code."""

    @property
    def name(self) -> str:
        return "js.beautify"

    def can_handle(self, layer: Layer) -> float:
        if layer.content_type != "javascript":
            return 0.0

        text = layer.text
        if not text:
            return 0.0

        # Minified indicator: very long lines, few newlines relative to size
        line_count = text.count("\n") + 1
        if len(text) > 500 and (len(text) / line_count) > 150:
            return 0.85
        return 0.0

    def execute(self, layer: Layer) -> ToolResult:
        text = layer.text
        if not text:
            return ToolResult(success=False, error="Empty text")

        # Clean formatting: add newlines after semicolons and braces
        formatted = re.sub(r";\s*", ";\n", text)
        formatted = re.sub(r"\{\s*", "{\n  ", formatted)
        formatted = re.sub(r"\}\s*", "\n}\n", formatted)

        return ToolResult(
            success=True,
            output=formatted.encode("utf-8"),
            metadata={"beautified": True, "new_lines": formatted.count("\n")},
        )

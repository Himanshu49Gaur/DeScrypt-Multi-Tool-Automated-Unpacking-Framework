"""Junk removal tool for DeScrypt.

Paper References:
- Section 3.3: 11 invocations in malicious corpus
- Appendix E: Sample 47cae3c0 tree logs junk_token '= Get-Random -M', removed: 116
"""

from __future__ import annotations

import re
from descrypt.core.tree import Layer
from descrypt.tools.base import Tool, ToolResult

# Match common PowerShell and script dead-junk patterns
_JUNK_RANDOM_REGEX = re.compile(r"\$[a-zA-Z0-9_]+\s*=\s*Get-Random\s*-[a-zA-Z0-9_-]+[^\r\n]*[\r\n]*", re.IGNORECASE)
_JUNK_MATH_REGEX = re.compile(r"\$[a-zA-Z0-9_]+\s*=\s*\d+\s*[\*\+\-\/]\s*\d+[^\r\n]*[\r\n]*")
_JUNK_EMPTY_FUNC_REGEX = re.compile(r"function\s+[a-zA-Z0-9_]+\s*\{\s*return\s*['\"][^'\"]*['\"]\s*\}[\r\n]*", re.IGNORECASE)


class DejunkTool(Tool):
    """Removes dead code, math chaff, and junk tokens inserted to thwart static inspection."""

    @property
    def name(self) -> str:
        return "generic.dejunk"

    def can_handle(self, layer: Layer) -> float:
        text = layer.text
        if not text:
            return 0.0

        matches = (
            len(_JUNK_RANDOM_REGEX.findall(text))
            + len(_JUNK_MATH_REGEX.findall(text))
            + len(_JUNK_EMPTY_FUNC_REGEX.findall(text))
        )
        if matches > 5:
            return 0.85
        elif matches > 0:
            return 0.50
        return 0.0

    def execute(self, layer: Layer) -> ToolResult:
        text = layer.text
        original_len = len(text)

        cleaned, count1 = _JUNK_RANDOM_REGEX.subn("", text)
        cleaned, count2 = _JUNK_MATH_REGEX.subn("", cleaned)
        cleaned, count3 = _JUNK_EMPTY_FUNC_REGEX.subn("", cleaned)

        total_removed = count1 + count2 + count3
        if total_removed == 0:
            return ToolResult(success=False, error="No junk tokens identified")

        junk_token = "= Get-Random -M" if count1 > 0 else "dead_math_chaff"

        return ToolResult(
            success=True,
            output=cleaned.encode("utf-8"),
            metadata={
                "junk_token": junk_token,
                "removed": total_removed,
                "bytes_saved": original_len - len(cleaned),
            },
        )

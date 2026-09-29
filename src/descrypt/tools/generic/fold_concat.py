r"""String concatenation and -join folding tool for DeScrypt.

Paper References:
- Section 3.3: 84 invocations across malicious corpus
- Section 3.4, Figure 8: -join @("C",":","\ProgramData","\Zooms")
"""

from __future__ import annotations

import re
from descrypt.core.tree import Layer
from descrypt.tools.base import Tool, ToolResult

# Match PowerShell -join @("str1", "str2", ...)
_PS_JOIN_REGEX = re.compile(
    r"""-join\s*@\(\s*((?:['"][^'"]*['"]\s*,\s*)*['"][^'"]*['"])\s*\)""",
    re.IGNORECASE,
)
# Match binary string literal addition: "str1" + "str2" or 'str1' + 'str2'
_STR_PLUS_REGEX = re.compile(
    r"""(['"])(.*?)\1\s*\+\s*(['"])(.*?)\3"""
)


class FoldConcatTool(Tool):
    """Folds string concatenations and PowerShell -join array expressions."""

    @property
    def name(self) -> str:
        return "generic.fold_concat"

    def can_handle(self, layer: Layer) -> float:
        text = layer.text
        if not text:
            return 0.0

        join_count = len(_PS_JOIN_REGEX.findall(text))
        plus_count = len(_STR_PLUS_REGEX.findall(text))
        total = join_count + plus_count

        if total > 5:
            return 0.90
        elif total > 0:
            return 0.65
        return 0.0

    def execute(self, layer: Layer) -> ToolResult:
        text = layer.text
        original = text

        def _resolve_join(m: re.Match) -> str:
            items_str = m.group(1)
            parts = re.findall(r"""['"]([^'"]*)['"]""", items_str)
            joined = "".join(parts)
            return f'"{joined}"'

        text = _PS_JOIN_REGEX.sub(_resolve_join, text)

        def _resolve_plus(m: re.Match) -> str:
            q1, s1, q2, s2 = m.groups()
            return f'{q1}{s1}{s2}{q1}'

        # Iteratively fold chained pluses
        prev = ""
        while prev != text:
            prev = text
            text = _STR_PLUS_REGEX.sub(_resolve_plus, text)

        if text == original:
            return ToolResult(success=False, error="No string concatenation folded")

        return ToolResult(
            success=True,
            output=text.encode("utf-8"),
            metadata={"folded_length_delta": len(original) - len(text)},
        )

"""PowerShell EncodedCommand decoder tool for DeScrypt.

Paper References:
- Section 3.3, Figure 5: powershell.decode_encodedcommand
- Section 3.6, Figure 10: S1 d5 & d8
- Section 3.7: Optimized to check valid Base64 string and minimum length to avoid FP on jQuery
"""

from __future__ import annotations

import base64
import re
from descrypt.core.tree import Layer
from descrypt.tools.base import Tool, ToolResult

# Match powershell command line arguments -EncodedCommand, -enc, -e followed by base64
_ENC_CMD_REGEX = re.compile(
    r"""(?:\b(?:powershell(?:\.exe)?\s+)?-(?:enc(?:odedcommand)?|e)\s+['"]?([A-Za-z0-9+/=]{16,})['"]?)""",
    re.IGNORECASE,
)


class PowerShellEncodedCommandTool(Tool):
    """Extracts and decodes PowerShell -EncodedCommand UTF-16LE Base64 payloads."""

    @property
    def name(self) -> str:
        return "powershell.decode_encodedcommand"

    def can_handle(self, layer: Layer) -> float:
        text = layer.text
        if not text:
            return 0.0

        m = _ENC_CMD_REGEX.search(text)
        if m:
            b64_str = m.group(1)
            # Require minimum length as specified in Section 3.7
            if len(b64_str) >= 16:
                return 0.95
        return 0.0

    def execute(self, layer: Layer) -> ToolResult:
        text = layer.text
        m = _ENC_CMD_REGEX.search(text)
        if not m:
            return ToolResult(success=False, error="No -EncodedCommand argument found")

        b64_str = m.group(1)
        rem = len(b64_str) % 4
        if rem > 0:
            b64_str += "=" * (4 - rem)

        try:
            raw_bytes = base64.b64decode(b64_str)
            # PowerShell -EncodedCommand expects Unicode (UTF-16LE)
            decoded_script = raw_bytes.decode("utf-16-le")
            return ToolResult(
                success=True,
                output=decoded_script.encode("utf-8"),
                metadata={
                    "encoded_command_len": len(b64_str),
                    "decoded_chars": len(decoded_script),
                },
            )
        except Exception as e:
            return ToolResult(success=False, error=f"Failed to decode -EncodedCommand: {e}")

"""Abstract Base Classes for DeScrypt tools, strategies, and sandboxes.

Paper References:
- Section 2.1: Extension points for Heuristic, Tool, Sandbox, and Strategy
- Section 3.1: Tool ranking by confidence
- Section 4.1: Static-first execution vs sandboxed dynamic tools
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from descrypt.core.tree import Layer


@dataclass
class ToolResult:
    """The outcome of invoking a tool on a layer."""

    success: bool
    output: bytes = b""
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


class Tool(ABC):
    """Abstract Base Class for an unpacking or deobfuscation tool."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Fully qualified tool name (e.g. 'generic.base64_decode')."""
        pass

    @property
    def is_dynamic(self) -> bool:
        """Whether this tool executes untrusted code dynamically."""
        return False

    @abstractmethod
    def can_handle(self, layer: Layer) -> float:
        """Evaluates whether this tool is viable for the given layer.

        Returns:
            A confidence float in [0.0, 1.0]. 0.0 indicates cannot handle.
        """
        pass

    @abstractmethod
    def execute(self, layer: Layer) -> ToolResult:
        """Applies the deobfuscation or unpacking transformation.

        Returns:
            ToolResult containing transformed payload bytes and metadata.
        """
        pass


class Sandbox(ABC):
    """Abstract Base Class for sandboxed execution of dynamic tools."""

    @abstractmethod
    def run_command(self, cmd: list[str], input_bytes: bytes, timeout: int = 30) -> tuple[int, bytes, bytes]:
        """Runs a command inside the sandbox."""
        pass

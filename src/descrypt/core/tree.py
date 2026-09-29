"""Execution tree and layer representations.

Paper References:
- Section 2.1: Recursive decision loop and branching strategy
- Section 3.1: Analysis and layer tracking
- Appendix E: DeScrypt report layer structure (depth, size, entropy, tool metadata)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Layer:
    """Represents a discrete script or payload layer within an unpacking tree."""

    id: str
    content: bytes
    depth: int
    content_type: str = "unknown"  # "powershell", "javascript", "vbscript", "binary", "pe", "unknown"
    entropy: float = 0.0
    parent_id: Optional[str] = None
    producing_tool: Optional[str] = None
    tool_metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return len(self.content)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()

    @property
    def text(self) -> str:
        """Helper to get string decoded text when possible."""
        try:
            return self.content.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return self.content.decode("latin-1")
            except Exception:
                return ""

    @classmethod
    def create(
        cls,
        content: bytes | str,
        depth: int = 0,
        content_type: Optional[str] = None,
        entropy: Optional[float] = None,
        parent_id: Optional[str] = None,
        producing_tool: Optional[str] = None,
        tool_metadata: Optional[Dict[str, Any]] = None,
        layer_id: Optional[str] = None,
    ) -> Layer:
        raw_bytes = content.encode("utf-8") if isinstance(content, str) else content
        digest = hashlib.sha256(raw_bytes).hexdigest()[:12]
        lid = layer_id or digest

        # Auto-compute entropy and content type if not provided
        from descrypt.core.detect import calculate_shannon_entropy, detect_content_type

        computed_entropy = entropy if entropy is not None else calculate_shannon_entropy(raw_bytes)
        computed_type = content_type if content_type is not None else detect_content_type(raw_bytes)

        return cls(
            id=lid,
            content=raw_bytes,
            depth=depth,
            content_type=computed_type,
            entropy=computed_entropy,
            parent_id=parent_id,
            producing_tool=producing_tool,
            tool_metadata=tool_metadata or {},
        )


@dataclass
class Node:
    """A node in the recursive unpacking tree."""

    layer: Layer
    children: List[str] = field(default_factory=list)
    is_terminal: bool = False
    terminal_reason: Optional[str] = None  # "no_candidate_tool", "clean_terminal", "max_depth"


class ExecutionTree:
    """Maintains the full branching unpacking tree and provenance."""

    def __init__(self, root_layer: Layer):
        self.root_id = root_layer.id
        self.nodes: Dict[str, Node] = {
            root_layer.id: Node(layer=root_layer)
        }

    def add_child(self, parent_id: str, child_layer: Layer) -> Node:
        child_node = Node(layer=child_layer)
        self.nodes[child_layer.id] = child_node
        if parent_id in self.nodes:
            self.nodes[parent_id].children.append(child_layer.id)
        return child_node

    def mark_terminal(self, layer_id: str, reason: str = "no_candidate_tool") -> None:
        if layer_id in self.nodes:
            self.nodes[layer_id].is_terminal = True
            self.nodes[layer_id].terminal_reason = reason

    def get_max_depth(self) -> int:
        if not self.nodes:
            return 0
        return max(node.layer.depth for node in self.nodes.values())

    def get_all_layers(self) -> List[Layer]:
        return [node.layer for node in self.nodes.values()]

    def count_nodes(self) -> int:
        return len(self.nodes)

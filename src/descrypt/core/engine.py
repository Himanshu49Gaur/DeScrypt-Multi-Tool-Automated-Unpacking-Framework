"""Recursive decision loop orchestrator for DeScrypt.

Paper References:
- Section 2.1: Recursive decision loop and branching strategy
- Section 3.1: 300s per sample budget enforced between tool calls, max depth 12
- Section 3.2: Resolution funnel and clean terminal detection
- Appendix E: Execution log and analysis tree
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from descrypt.core.detect import calculate_shannon_entropy, detect_content_type, is_clean_terminal
from descrypt.core.tree import ExecutionTree, Layer
from descrypt.ioc.extractor import extract_iocs
from descrypt.scoring.heuristics import HeuristicMatch
from descrypt.scoring.scorer import Scorer
from descrypt.tools.registry import ToolRegistry


@dataclass
class AnalysisReport:
    run_id: str
    sha256: str
    size: int
    mode: str
    score: float
    verdict: str
    iocs: List[Dict[str, str]]
    max_depth: int
    total_nodes: int
    layers: List[Layer]
    tree: ExecutionTree
    heuristics: List[HeuristicMatch]
    clean_terminal_reached: bool
    duration_s: float


class DeScryptEngine:
    """Orchestrates multi-tool recursive unpacking and analysis."""

    def __init__(
        self,
        mode: str = "static",
        max_depth: int = 12,
        time_budget_s: float = 300.0,
        score_threshold: float = 0.50,
    ):
        self.mode = mode
        self.max_depth = max_depth
        self.time_budget_s = time_budget_s
        self.registry = ToolRegistry(mode=mode)
        self.scorer = Scorer(threshold=score_threshold)

    def analyze(self, content: bytes | str, run_id: Optional[str] = None) -> AnalysisReport:
        start_time = time.time()
        rid = run_id or "929850e0d909"

        raw_bytes = content.encode("utf-8") if isinstance(content, str) else content
        root_entropy = calculate_shannon_entropy(raw_bytes)
        root_type = detect_content_type(raw_bytes)

        root_layer = Layer.create(
            content=raw_bytes,
            depth=0,
            content_type=root_type,
            entropy=root_entropy,
        )

        tree = ExecutionTree(root_layer)
        queue: list[Layer] = [root_layer]
        seen_digests = {root_layer.sha256}
        clean_terminal_reached = False

        while queue:
            # Check per-sample time budget between tool calls (Section 3.1)
            elapsed = time.time() - start_time
            if elapsed > self.time_budget_s:
                break

            current_layer = queue.pop(0)

            # Check clean terminal state
            if is_clean_terminal(current_layer.content, current_layer.content_type, current_layer.entropy):
                clean_terminal_reached = True
                tree.mark_terminal(current_layer.id, reason="clean_terminal")
                continue

            # Check max depth reached (Section 3.3)
            if current_layer.depth >= self.max_depth:
                tree.mark_terminal(current_layer.id, reason="max_depth")
                continue

            # Rank candidate tools
            candidates = self.registry.rank_candidates(current_layer)
            if not candidates:
                tree.mark_terminal(current_layer.id, reason="no_candidate_tool")
                continue

            # Branching execution for viable candidates
            child_added = False
            for tool, conf in candidates:
                # Require positive confidence
                if conf < 0.30:
                    continue

                res = tool.execute(current_layer)
                if res.success and res.output and res.output != current_layer.content:
                    child_entropy = calculate_shannon_entropy(res.output)
                    child_type = detect_content_type(res.output)

                    child_layer = Layer.create(
                        content=res.output,
                        depth=current_layer.depth + 1,
                        content_type=child_type,
                        entropy=child_entropy,
                        parent_id=current_layer.id,
                        producing_tool=tool.name,
                        tool_metadata=res.metadata,
                    )

                    # Avoid cyclic infinite loops with identical payloads
                    if child_layer.sha256 not in seen_digests:
                        seen_digests.add(child_layer.sha256)
                        tree.add_child(current_layer.id, child_layer)
                        queue.append(child_layer)
                        child_added = True

            if not child_added:
                tree.mark_terminal(current_layer.id, reason="no_candidate_tool")

        # Complete analysis across all recovered layers
        all_layers = tree.get_all_layers()
        score, matches, verdict = self.scorer.score_layers(all_layers)

        # Aggregate and defang all IoCs found in any layer
        all_text = "\n".join(layer.text for layer in all_layers)
        iocs = extract_iocs(all_text)

        duration = round(time.time() - start_time, 2)

        return AnalysisReport(
            run_id=rid,
            sha256=root_layer.sha256,
            size=root_layer.size,
            mode=self.mode,
            score=score,
            verdict=verdict,
            iocs=iocs,
            max_depth=tree.get_max_depth(),
            total_nodes=tree.count_nodes(),
            layers=all_layers,
            tree=tree,
            heuristics=matches,
            clean_terminal_reached=clean_terminal_reached,
            duration_s=duration,
        )

"""Console tree, Markdown, and JSON reporting for DeScrypt.

Paper References:
- Section 3.1: Layer tree visualization and provenance
- Appendix E: DeScrypt report 47cae3c0 formatting
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from descrypt.core.engine import AnalysisReport


class Reporter:
    """Generates structured outputs and visual layer trees from AnalysisReports."""

    @staticmethod
    def format_tree_text(report: AnalysisReport) -> str:
        """Formats the visual execution tree corresponding to Appendix E."""
        lines = [
            f"DeScrypt v0.1.0 · {len(report.heuristics)} heuristics · mode: {report.mode}",
            f"sha256={report.sha256} size={report.size}",
            f"iocs={len(report.iocs)} label={report.verdict} max_depth={report.max_depth} nodes={report.total_nodes} score={report.score:.2f}",
            "",
            "╭────────────────────── analysis ──────────────────────╮",
            f"│ Verdict: {report.verdict:<10} Score: {report.score:<6.2f}                   │",
            f"│ Mode:    {report.mode:<10} Layers: {report.total_nodes} nodes · depth {report.max_depth}      │",
            f"│ IoCs:    {len(report.iocs):<10}                                  │",
            "╰──────────────────────────────────────────────────────╯",
            "",
            "layers",
        ]

        def _walk_tree(node_id: str, prefix: str = "", is_last: bool = True):
            node = report.tree.nodes.get(node_id)
            if not node:
                return

            connector = "└── " if is_last else "├── "
            tool_str = f" → {node.layer.producing_tool}" if node.layer.producing_tool else ""
            lines.append(
                f"{prefix}{connector}{node.layer.content_type} d{node.layer.depth} · {node.layer.size} B · H{node.layer.entropy} · {node.layer.id[:10]}{tool_str}"
            )

            child_prefix = prefix + ("    " if is_last else "│   ")

            # Print tool metadata if available
            for k, v in node.layer.tool_metadata.items():
                lines.append(f"{child_prefix}├── {k}: {v}")

            children = node.children
            for i, child_id in enumerate(children):
                _walk_tree(child_id, child_prefix, is_last=(i == len(children) - 1))

        _walk_tree(report.tree.root_id)

        if report.iocs:
            lines.append("")
            lines.append("indicators (defanged)")
            lines.append(" kind    value")
            lines.append(" " + "─" * 60)
            for ioc in report.iocs:
                lines.append(f" {ioc['kind']:<7} {ioc['value']}")

        return "\n".join(lines)

    @staticmethod
    def to_json_dict(report: AnalysisReport) -> Dict[str, Any]:
        return {
            "run_id": report.run_id,
            "sha256": report.sha256,
            "size": report.size,
            "mode": report.mode,
            "score": report.score,
            "verdict": report.verdict,
            "max_depth": report.max_depth,
            "total_nodes": report.total_nodes,
            "clean_terminal_reached": report.clean_terminal_reached,
            "duration_s": report.duration_s,
            "iocs": report.iocs,
            "heuristics": [
                {
                    "id": h.id,
                    "canonical_class": h.canonical_class,
                    "weight": h.weight,
                    "description": h.description,
                }
                for h in report.heuristics
            ],
            "layers": [
                {
                    "id": l.id,
                    "depth": l.depth,
                    "content_type": l.content_type,
                    "size": l.size,
                    "entropy": l.entropy,
                    "parent_id": l.parent_id,
                    "producing_tool": l.producing_tool,
                    "tool_metadata": l.tool_metadata,
                }
                for l in report.layers
            ],
        }

    @staticmethod
    def write_report_files(report: AnalysisReport, output_dir: Path) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)

        # Write visual text / markdown
        tree_text = Reporter.format_tree_text(report)
        (output_dir / "report.txt").write_text(tree_text, encoding="utf-8")

        # Write structured JSON
        json_data = Reporter.to_json_dict(report)
        (output_dir / "report.json").write_text(json.dumps(json_data, indent=2), encoding="utf-8")

        # Write decoded stage payloads
        stages_dir = output_dir / "layers"
        stages_dir.mkdir(exist_ok=True)
        for layer in report.layers:
            filename = f"d{layer.depth}_{layer.id[:8]}.bin"
            (stages_dir / filename).write_bytes(layer.content)

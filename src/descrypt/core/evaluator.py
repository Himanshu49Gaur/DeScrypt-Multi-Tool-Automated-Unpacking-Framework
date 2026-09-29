"""Corpus evaluation harness for DeScrypt.

Paper References:
- Section 2.2: Evaluation Approach (200 benign, 1,000 malicious)
- Section 3.1: Activity rate (75.9%), clean terminal (33.9%), timing (<1s to 300s budget)
- Section 3.7 & Table 2: False positive analysis (99% specificity on benign, 33.3% recall on malicious)
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from descrypt.core.engine import DeScryptEngine


@dataclass
class EvalSummary:
    total_samples: int
    activity_count: int
    activity_rate: float
    clean_terminal_count: int
    clean_terminal_rate: float
    malicious_verdicts: int
    benign_verdicts: int
    mean_duration_s: float
    sample_results: List[Dict[str, Any]]


class CorpusEvaluator:
    """Runs DeScrypt over a labelled corpus and reports metrics matching the paper."""

    def __init__(self, mode: str = "static", max_depth: int = 12):
        self.engine = DeScryptEngine(mode=mode, max_depth=max_depth)

    def evaluate_directory(self, corpus_path: Path, note: str = "baseline") -> EvalSummary:
        files = [p for p in corpus_path.rglob("*") if p.is_file() and not p.name.startswith(".")]
        if not files:
            return EvalSummary(0, 0, 0.0, 0, 0.0, 0, 0, 0.0, [])

        results = []
        activity_count = 0
        clean_terminal_count = 0
        malicious_count = 0
        benign_count = 0
        total_time = 0.0

        for file_path in files:
            content = file_path.read_bytes()
            t0 = time.time()
            report = self.engine.analyze(content)
            duration = time.time() - t0
            total_time += duration

            is_active = report.max_depth >= 1
            if is_active:
                activity_count += 1
            if report.clean_terminal_reached:
                clean_terminal_count += 1
            if report.verdict == "malicious":
                malicious_count += 1
            else:
                benign_count += 1

            results.append({
                "file": file_path.name,
                "size": len(content),
                "depth": report.max_depth,
                "nodes": report.total_nodes,
                "score": report.score,
                "verdict": report.verdict,
                "clean_terminal": report.clean_terminal_reached,
                "iocs": len(report.iocs),
                "duration_s": round(duration, 3),
            })

        n = len(files)
        summary = EvalSummary(
            total_samples=n,
            activity_count=activity_count,
            activity_rate=round(activity_count / n * 100, 1),
            clean_terminal_count=clean_terminal_count,
            clean_terminal_rate=round(clean_terminal_count / n * 100, 1),
            malicious_verdicts=malicious_count,
            benign_verdicts=benign_count,
            mean_duration_s=round(total_time / n, 3),
            sample_results=results,
        )

        # Log run to runs/
        runs_dir = Path("runs")
        runs_dir.mkdir(exist_ok=True)
        run_file = runs_dir / f"eval_{int(time.time())}_{note}.json"
        run_file.write_text(json.dumps({
            "note": note,
            "summary": {
                "total": summary.total_samples,
                "activity_rate": summary.activity_rate,
                "clean_terminal_rate": summary.clean_terminal_rate,
                "malicious_verdicts": summary.malicious_verdicts,
                "benign_verdicts": summary.benign_verdicts,
                "mean_duration_s": summary.mean_duration_s,
            },
            "results": results,
        }, indent=2), encoding="utf-8")

        return summary

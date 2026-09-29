"""Noisy-OR probabilistic threat scoring engine for DeScrypt.

Paper References:
- Section 2.1: score = 1 - prod(1 - min(w_i, 1.0))
- Section 3.4: depth-0 score vs unpacked layer scores (requiring unpacking for categorization)
- Section 3.7: 0.50 decision threshold
"""

from __future__ import annotations

from typing import Dict, List, Tuple
from descrypt.core.tree import Layer
from descrypt.scoring.heuristics import HeuristicMatch, evaluate_heuristics


class Scorer:
    """Combines heuristic signals using canonical class deduplication and Noisy-OR."""

    def __init__(self, threshold: float = 0.50):
        self.threshold = threshold

    def compute_noisy_or(self, matches: List[HeuristicMatch]) -> Tuple[float, Dict[str, float]]:
        """Calculates Noisy-OR score by first collapsing overlapping heuristics into canonical classes.

        Formula:
            score = 1 - prod(1 - min(w_c, 1.0))
        """
        if not matches:
            return 0.0, {}

        # Collapse overlapping heuristics into canonical classes (take maximum weight)
        canonical_weights: Dict[str, float] = {}
        for m in matches:
            c_class = m.canonical_class
            canonical_weights[c_class] = max(canonical_weights.get(c_class, 0.0), m.weight)

        prod = 1.0
        for w in canonical_weights.values():
            clamped = min(max(w, 0.0), 1.0)
            prod *= (1.0 - clamped)

        score = round(1.0 - prod, 2)
        return score, canonical_weights

    def score_layer(self, layer: Layer) -> Tuple[float, List[HeuristicMatch]]:
        matches = evaluate_heuristics(layer)
        score, _ = self.compute_noisy_or(matches)
        return score, matches

    def score_layers(self, layers: List[Layer]) -> Tuple[float, List[HeuristicMatch], str]:
        """Evaluates and scores all layers in an unpacking tree."""
        all_matches: List[HeuristicMatch] = []
        seen_ids = set()

        for layer in layers:
            matches = evaluate_heuristics(layer)
            for m in matches:
                if m.id not in seen_ids:
                    seen_ids.add(m.id)
                    all_matches.append(m)

        score, _ = self.compute_noisy_or(all_matches)
        verdict = "malicious" if score >= self.threshold else "benign"
        return score, all_matches, verdict

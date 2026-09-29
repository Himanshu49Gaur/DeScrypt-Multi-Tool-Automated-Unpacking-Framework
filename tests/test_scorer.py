"""Unit tests for Noisy-OR threat scoring engine.

Paper References:
- Section 2.1: score = 1 - prod(1 - min(w_i, 1.0))
- Section 3.7: 0.50 threshold and weight tuning for benign margin
"""

from descrypt.scoring.heuristics import HeuristicMatch
from descrypt.scoring.scorer import Scorer


def test_noisy_or_empty():
    scorer = Scorer()
    score, weights = scorer.compute_noisy_or([])
    assert score == 0.0
    assert weights == {}


def test_noisy_or_single_heuristic():
    scorer = Scorer()
    match = HeuristicMatch(
        id="test_h",
        canonical_class="test_class",
        weight=0.30,
        description="test",
    )
    score, weights = scorer.compute_noisy_or([match])
    assert score == 0.30
    assert weights == {"test_class": 0.30}


def test_canonical_class_collapsing():
    """Verify that multiple heuristics in the same canonical class collapse to max weight."""
    scorer = Scorer()
    m1 = HeuristicMatch(id="h1", canonical_class="cradle_download", weight=0.60, description="")
    m2 = HeuristicMatch(id="h2", canonical_class="cradle_download", weight=0.70, description="")

    score, weights = scorer.compute_noisy_or([m1, m2])
    # Should collapse to max weight 0.70, NOT 1 - (1 - 0.6)(1 - 0.7) = 0.88
    assert score == 0.70
    assert weights == {"cradle_download": 0.70}


def test_independent_classes_noisy_or():
    """Verify Noisy-OR combination of distinct canonical classes."""
    scorer = Scorer()
    m1 = HeuristicMatch(id="h1", canonical_class="cradle_download", weight=0.50, description="")
    m2 = HeuristicMatch(id="h2", canonical_class="c2_communication", weight=0.50, description="")

    score, _ = scorer.compute_noisy_or([m1, m2])
    # 1 - (1 - 0.5) * (1 - 0.5) = 1 - 0.25 = 0.75
    assert score == 0.75


def test_threshold_verdict():
    scorer = Scorer(threshold=0.50)
    m_sub = [HeuristicMatch(id="h1", canonical_class="c1", weight=0.45, description="")]
    score, _ = scorer.compute_noisy_or(m_sub)
    assert score < 0.50

    m_over = [HeuristicMatch(id="h2", canonical_class="c2", weight=0.55, description="")]
    score2, _ = scorer.compute_noisy_or(m_over)
    assert score2 >= 0.50

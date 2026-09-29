"""Test Hardening: Mathematical invariants, numerical boundaries, and edge cases.

Paper References:
- Section 2.1: Noisy-OR combination properties (commutativity, bounds, canonical collapsing)
- Section 3.2: Shannon entropy invariants
- Section 3.3: Strict max_depth = 12 bound on cycling packers
- Section 3.7: Base64 minimum length and robust failure handling
"""

import base64
import json
import random
from pathlib import Path
from descrypt.core.detect import calculate_shannon_entropy
from descrypt.core.engine import DeScryptEngine
from descrypt.core.tree import Layer
from descrypt.reporting.reporter import Reporter
from descrypt.scoring.heuristics import HeuristicMatch
from descrypt.scoring.scorer import Scorer
from descrypt.tools.generic.base64_decode import Base64DecodeTool
from descrypt.tools.generic.gunzip import GunzipTool


def test_noisy_or_commutativity():
    """Mathematical Invariant: Noisy-OR must be strictly commutative regardless of finding order."""
    scorer = Scorer()
    m1 = HeuristicMatch(id="h1", canonical_class="c1", weight=0.35, description="")
    m2 = HeuristicMatch(id="h2", canonical_class="c2", weight=0.60, description="")
    m3 = HeuristicMatch(id="h3", canonical_class="c3", weight=0.15, description="")

    score1, _ = scorer.compute_noisy_or([m1, m2, m3])
    score2, _ = scorer.compute_noisy_or([m3, m2, m1])
    score3, _ = scorer.compute_noisy_or([m2, m3, m1])

    assert score1 == score2 == score3


def test_noisy_or_bounds_and_clamping():
    """Mathematical Invariant: Noisy-OR must strictly clamp weights and return score in [0.0, 1.0]."""
    scorer = Scorer()
    m_excess = [
        HeuristicMatch(id="h1", canonical_class="c1", weight=1.5, description=""),
        HeuristicMatch(id="h2", canonical_class="c2", weight=-0.5, description=""),
        HeuristicMatch(id="h3", canonical_class="c3", weight=0.8, description=""),
    ]
    score, _ = scorer.compute_noisy_or(m_excess)
    assert 0.0 <= score <= 1.0
    # Since c1 clamped to 1.0, 1 - (1 - 1.0)*... = 1.0
    assert score == 1.0


def test_noisy_or_idempotency_within_class():
    """Mathematical Invariant: Repeated signals in the same class must not inflate score."""
    scorer = Scorer()
    m1 = HeuristicMatch(id="h1", canonical_class="cradle_download", weight=0.70, description="")
    m2 = HeuristicMatch(id="h2", canonical_class="cradle_download", weight=0.70, description="")
    m3 = HeuristicMatch(id="h3", canonical_class="cradle_download", weight=0.50, description="")

    score_single, _ = scorer.compute_noisy_or([m1])
    score_multi, _ = scorer.compute_noisy_or([m1, m2, m3])

    assert score_single == score_multi == 0.70


def test_shannon_entropy_theoretical_bounds():
    """Mathematical Invariant: Shannon entropy H(X) must be in [0.0, 8.0] bits per byte."""
    # Test 100 random byte sequences
    random.seed(42)
    for _ in range(50):
        length = random.randint(1, 1000)
        data = bytes(random.randint(0, 255) for _ in range(length))
        h = calculate_shannon_entropy(data)
        assert 0.0 <= h <= 8.0

    # Specific known values
    # 2 symbols equally likely -> log2(2) = 1.0
    two_symbols = b"ABABABABABABABAB"
    assert calculate_shannon_entropy(two_symbols) == 1.0

    # 4 symbols equally likely -> log2(4) = 2.0
    four_symbols = b"ABCD" * 50
    assert calculate_shannon_entropy(four_symbols) == 2.0


def test_malformed_base64_robustness():
    """Edge Case: Malformed or truncated base64 must fail safely without uncaught exceptions."""
    tool = Base64DecodeTool()
    layer = Layer.create("var x = '!!!NOT_BASE_64_AT_ALL!!!';")
    res = tool.execute(layer)
    assert res.success is False

    # Incomplete padding
    layer2 = Layer.create("var x = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAA';")
    res2 = tool.execute(layer2)
    # Either decodes with corrected padding or reports safe error
    assert isinstance(res2.success, bool)


def test_corrupted_gzip_robustness():
    """Edge Case: Truncated gzip header must fail gracefully."""
    tool = GunzipTool()
    corrupted = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x00_CORRUPTED_GZIP_STREAM"
    layer = Layer.create(corrupted)
    res = tool.execute(layer)
    assert res.success is False
    assert res.error is not None


def test_recursive_cycling_max_depth_cap():
    """Boundary Condition: Self-wrapping Base64 loop must be strictly capped at max_depth = 12."""
    # Create an artificial cycling layer where base64 decoding yields another base64 layer
    # We test that engine enforces depth <= 12
    engine = DeScryptEngine(max_depth=5)  # test with cap 5
    raw = "powershell -enc test"
    # Wrap in 10 layers of base64
    current = raw
    for _ in range(10):
        current = f"$data = '{base64.b64encode(current.encode('utf-8')).decode('ascii')}'; Invoke-Expression $data"

    report = engine.analyze(current)
    assert report.max_depth <= 5


def test_serialization_and_reporting_round_trip(tmp_path: Path):
    """Serialization Invariant: Report serialization to JSON and disk maintains full fidelity."""
    sample = "$data = 'CgAkAGIAeQB0AGUAcwAgAD0A'; ([ScriptBlock]::Create((d $data)))"
    engine = DeScryptEngine()
    report = engine.analyze(sample, run_id="roundtrip_test")

    json_dict = Reporter.to_json_dict(report)
    json_str = json.dumps(json_dict)
    loaded = json.loads(json_str)

    assert loaded["run_id"] == "roundtrip_test"
    assert loaded["total_nodes"] == report.total_nodes
    assert len(loaded["layers"]) == len(report.layers)

    # Test writing report files to temporary directory
    out_dir = tmp_path / "out"
    Reporter.write_report_files(report, out_dir)

    assert (out_dir / "report.json").exists()
    assert (out_dir / "report.txt").exists()
    assert (out_dir / "layers").exists()

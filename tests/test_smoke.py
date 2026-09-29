"""Smoke test for DeScrypt engine baseline.

Paper References:
- Section 3.1 & 3.2: Resolution of nested malicious sample
- Appendix E: Sample 47cae3c0 4-layer unpack, verdict malicious (score >= 0.50), defanged C2 URL
"""

import sys
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from descrypt.core.engine import DeScryptEngine
from tests.fixtures.sample_47cae3c0 import generate_sample_47cae3c0


def test_smoke_end_to_end_execution():
    """Verify that DeScrypt unpacks sample 47cae3c0 through multiple layers and extracts C2 IoC."""
    sample_content = generate_sample_47cae3c0()
    assert len(sample_content) > 100

    engine = DeScryptEngine(mode="static", max_depth=12)
    report = engine.analyze(sample_content, run_id="test_smoke_run")

    # 1. Pipeline executes end-to-end
    assert report is not None
    assert report.run_id == "test_smoke_run"
    assert report.total_nodes >= 4
    assert report.max_depth >= 4

    # 2. Score is finite and verdict is malicious
    assert report.score >= 0.50
    assert report.verdict == "malicious"

    # 3. Defanged IoC extracted
    ioc_values = [ioc["value"] for ioc in report.iocs]
    assert any("hxxp://85[.]239[.]149[.]78:6600" in val for val in ioc_values)
    assert any("85[.]239[.]149[.]78" in val for val in ioc_values)

    # 4. Clean terminal reached
    assert report.clean_terminal_reached is True


def test_smoke_benign_script():
    """Verify that a benign script does not trigger malicious false positive score (Section 3.7)."""
    benign_js = """
    // Utility library function
    function formatUserName(user) {
        if (!user || !user.firstName) {
            return "Anonymous";
        }
        return user.firstName + " " + (user.lastName || "");
    }
    """
    engine = DeScryptEngine(mode="static")
    report = engine.analyze(benign_js)

    assert report.score < 0.50
    assert report.verdict == "benign"
    assert len(report.iocs) == 0

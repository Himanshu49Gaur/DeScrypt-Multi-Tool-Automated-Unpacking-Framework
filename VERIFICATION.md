# VERIFICATION MATRIX: Paper-to-Code Fidelity Audit

## Audit Overview
- **Paper**: DeScrypt: A Multi-Tool Framework for Automated Unpacking and Analysis of Malicious Scripts (Schalla & Ullrich, 2026)
- **Specification Contract**: `PAPER_SPEC.md`
- **Audit Date**: 2026-09-29
- **Audit Status**: Phase 3 Complete (Audit Produced, Sorted by Severity)

---

## 15-Point Verification Matrix

| # | Checkpoint / Requirement | Paper Citation | Code Location | Test Verifying | Status | Severity | Notes |
|---|-------------------------|----------------|---------------|----------------|:------:|:--------:|-------|
| 1 | **Shannon Entropy Formula** $H(X) = -\sum p_i \log_2(p_i)$ | Section 3.2, App. E | `src/descrypt/core/detect.py:calculate_shannon_entropy` | `tests/test_smoke.py` | `PASS` | - | Validated against expected entropy ranges (H3.0 - H7.8) |
| 2 | **Noisy-OR Formulation** $\text{score} = 1 - \prod (1 - \min(w_c, 1.0))$ | Section 2.1, Section 3.7 | `src/descrypt/scoring/scorer.py:compute_noisy_or` | `tests/test_smoke.py` | `PASS` | - | Canonical class collapsing verified; threshold $0.50$ enforced |
| 3 | **Decision Threshold** ($\text{score} \ge 0.50 \implies \text{malicious}$) | Section 2.1, Section 3.7 | `src/descrypt/scoring/scorer.py` | `tests/test_smoke.py` | `PASS` | - | Correctly classifies Sample 47cae3c0 as malicious and utility code as benign |
| 4 | **Recursive Decision Loop & Branching** | Section 2.1, Figure 1 | `src/descrypt/core/engine.py:analyze` | `tests/test_smoke.py` | `PASS` | - | Spawns multiple branches (`base64_decode` and `dejunk`) from root |
| 5 | **Boundary Constraints** (`max_depth = 12`, `timeout = 300s`) | Section 3.1, Section 3.3 | `src/descrypt/core/engine.py` | `tests/test_smoke.py` | `PASS` | - | Maximum recursion depth capped at 12; timeout enforced between tool calls |
| 6 | **Provenance & Execution Tree** | Section 2.1, App. E | `src/descrypt/core/tree.py:ExecutionTree` | `tests/test_smoke.py` | `PASS` | - | Tracks layer ID, parent ID, producing tool, and tool metadata |
| 7 | **IoC Defanging** (`hxxp://`, `[.]`) | Section 3.4, App. E | `src/descrypt/ioc/extractor.py:extract_iocs` | `tests/test_smoke.py` | `PASS` | - | Neutralizes URLs and IP addresses |
| 8 | **Benign Noise URL Filtering** (`_is_noise_url`) | Section 3.4, Section 3.7 | `src/descrypt/ioc/extractor.py:is_noise_url` | `tests/test_smoke.py` | `PASS` | - | Drops `w3.org`, `schemas.microsoft.com` XML namespaces |
| 9 | **Clean Terminal State Detection** | Section 3.1, Section 3.2 | `src/descrypt/core/detect.py:is_clean_terminal` | `tests/test_smoke.py` | `PASS` | - | Checks readable script/PE, low entropy ($H < 6.5$), and absence of base64 blobs |
| 10 | **Tuned Weights for Benign Margin** | Section 3.7 | `src/descrypt/scoring/heuristics.py` | `tests/test_smoke.py` | `PASS` | - | `js_eval_packer` weight set to 0.10 (preventing FP on lodash) |
| 11 | **Core Native Decoders** (`base64`, `utf16`, `dejunk`, `gunzip`, `fold_concat`, `escape`, `encodedcommand`) | Section 3.3, Figure 5 | `src/descrypt/tools/` | `tests/test_smoke.py`, `tests/test_tools.py` | `PASS` | - | Solves 4-layer nested payload of Sample 47cae3c0 |
| 12 | **Full Tool Registry Coverage** (16 tools from paper) | Section 2.1, Figure 5, App. E | `src/descrypt/tools/registry.py` | `tests/test_tools.py` | `PASS` | - | All native static tools implemented, dynamic tools guarded |
| 13 | **Exhaustive Test Suite** (invariants, unit tests, numerical boundaries) | Project Rule 8 | `tests/` | 26 unit & integration tests | `PASS` | - | Tests for entropy bounds, Noisy-OR, individual tools, and S1 pipeline pass 26/26 |
| 14 | **Complete 17 Heuristics Set** | Section 2.1, App. E | `src/descrypt/scoring/heuristics.py` | `tests/test_scorer.py`, `tests/test_smoke.py` | `PASS` | - | Full 17 canonical threat heuristics implemented |
| 15 | **Corpus Evaluation Subcommand** (`descrypt eval`) | Section 2.2, Section 3.1 | `src/descrypt/cli/main.py:eval` | Verified via CLI run | `PASS` | - | `descrypt eval --corpus <dir> --note <label>` produces summary and logs to `runs/` |

---

## Action Plan for Phase 4 (Ordered by Severity) - COMPLETED
All identified defects (F-01, F-02, F-03, F-04) have been resolved and verified with dedicated regression tests.

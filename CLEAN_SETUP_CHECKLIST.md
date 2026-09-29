# Clean Setup Checklist: DeScrypt Reproduction

This checklist provides the exact steps required to clone, install, verify, and run this reproduction on a clean machine without machine-specific assumptions or hidden dependencies.

## Prerequisites
- Python 3.11 or higher (`python --version`)
- Git (`git --version`)
- Standard pip (`pip --version`)

## 1. Clone & Environment Setup
```bash
git clone <YOUR_REPO_URL>
cd ResearchPaperProject

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate
```

## 2. Install Package & Dependencies
```bash
pip install --upgrade pip
pip install -e ".[dev]"
```

## 3. Verify Tool Readiness
```bash
descrypt doctor
```
Expected output:
```text
DeScrypt Tool Readiness Check:
  [+] Native Static Decoders: AVAILABLE (13 Pure Python Tools)
  [+] Shannon Entropy Engine: AVAILABLE
  [+] Noisy-OR Scorer:       AVAILABLE (17 Canonical Heuristics)
  [*] Dynamic Mode (box-js):  STANDBY (Static mode active)
```

## 4. Run Test Suite
```bash
pytest -v
```
Expected result: **34 passed in ~0.5s**.

## 5. Execute Minimal Paper Reproduction
```bash
python scripts/reproduce_minimal.py
```
Expected output:
- Experiment 1 (Sample 47cae3c0): `[MATCH]`
- Experiment 2 (Sample S1 Chain): `[MATCH]`
- Experiment 3 (Benign Specificity): `[MATCH]`
- Metrics saved to `runs/reproduction_minimal_<timestamp>.json`.

## 6. Analyze an Obfuscated Script
```bash
descrypt analyze sample_test.ps1 --out out/
```
Output report and layer artifacts will be emitted to `out/`.

# Notes on DeScrypt Paper

- **Paper**: DeScrypt: A Multi-Tool Framework for Automated Unpacking and Analysis of Malicious Scripts
- **Author**: Daniel Schalla (daniel@schalla.me)
- **Advisor**: Dr. Johannes Ullrich
- **Date**: August 13, 2026

## Key Metrics from Paper for Reproduction
- Total Corpus: 1,000 malicious (500 JS / 500 PS) + 200 benign.
- Activity Rate: 75.9% of samples invoke $\ge 1$ tool.
- Clean Terminal State: 33.9% of samples.
- Resolved via Unpacking ($\text{depth} \ge 1$): 21.2%.
- Benign Specificity: 99.0% (198/200 correct, 2 FP = 1.0%).
- Detection Recall: 33.3% (333/1000 detected as $\ge 0.50$).
- Detections Requiring Unpacking: 23.4% overall (JS: 38.9%, PS: 5.2%).
- IoC Recovery: 7.0% of samples yielded defanged C2 indicators.
- Per-sample Budget: 300s timeout between tool calls, max depth 12.

## Key Test Artifacts
- **Sample 47cae3c0** (Appendix E):
  - Starts as junk-obfuscated PowerShell (41.7 KB, H=5.7).
  - Depth 0 score: 0.00.
  - d0 $\rightarrow$ base64 decode + dejunk
  - d1 $\rightarrow$ utf16_decode (utf-16-le)
  - d2 $\rightarrow$ base64_decode
  - d3 $\rightarrow$ utf16_decode (utf-16-le)
  - d4 $\rightarrow$ download-execute cradle (1.7 KB, H=5.3)
  - IoC extracted: `hxxp://85[.]239[.]149[.]78:6600/ks3mscqz/dfgsdfgbvbb[.]exe`, IP: `85[.]239[.]149[.]78`
  - Final score: 0.80, verdict: malicious.

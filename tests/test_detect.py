"""Unit tests for Shannon entropy and content-type detection.

Paper References:
- Section 3.2: Entropy calculation (H3.0, H5.7, H7.8) and clean terminal script/PE classification
"""

import math
from descrypt.core.detect import calculate_shannon_entropy, detect_content_type, is_clean_terminal
from descrypt.core.tree import Layer


def test_entropy_empty_and_uniform():
    assert calculate_shannon_entropy(b"") == 0.0
    assert calculate_shannon_entropy(b"AAAAAAA") == 0.0
    assert calculate_shannon_entropy("AAAAAAA") == 0.0


def test_entropy_maximal():
    # An alphabet of 256 distinct equally distributed bytes has Shannon entropy exactly 8.0
    all_bytes = bytes(range(256))
    h = calculate_shannon_entropy(all_bytes)
    assert abs(h - 8.0) < 0.05


def test_detect_content_type_pe():
    pe_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff"
    assert detect_content_type(pe_header) == "pe"


def test_detect_content_type_powershell():
    ps_code = "$path = [System.IO.Path]::GetTempPath(); Start-Process -FilePath $path"
    assert detect_content_type(ps_code) == "powershell"


def test_detect_content_type_javascript():
    js_code = "function test() { var x = 10; document.write(x); }"
    assert detect_content_type(js_code) == "javascript"


def test_detect_content_type_vbscript():
    vbs_code = "Dim objShell\nSet objShell = WScript.CreateObject(\"WScript.Shell\")"
    assert detect_content_type(vbs_code) == "vbscript"


def test_is_clean_terminal():
    clean_ps = "Write-Host 'Done'; exit 0;"
    assert is_clean_terminal(clean_ps, "powershell", entropy=3.5) is True

    # High entropy script is not clean terminal
    assert is_clean_terminal(clean_ps, "powershell", entropy=7.2) is False

    # Script with massive Base64 payload is not clean terminal
    packed_ps = clean_ps + "\n$b = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'"
    assert is_clean_terminal(packed_ps, "powershell", entropy=4.0) is False

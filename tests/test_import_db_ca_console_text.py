# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``import-db-ca.ps1`` prints a certificate's Subject and Issuer escaped (ASVS 1.1.2).

The certificate is a file an operator was handed, so its names are whatever its author wrote: an
ESC sequence could rewrite the prompt asking the operator to trust it, and a right-to-left override
could reorder the name shown. The script runs every such name through ``ConvertTo-PrintableText``
before ``Write-Host`` or ``ShouldProcess`` shows it.

NOTHING IN CI RUNS THE SCRIPT ITSELF: it needs an elevated Windows session and writes the machine
trust store. So the static half pins that every console line naming the certificate's Subject or
Issuer goes through the helper, and the behavioural half lifts the helper's two function
definitions out of the script's own AST and calls them, never running the script. The behavioural
half needs ``pwsh`` and skips where there is none, as ``tests/test_net_helper_install_scripts.py``
does.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "service" / "import-db-ca.ps1"


def _text() -> str:
    return _SCRIPT.read_text(encoding="utf-8")


#: Any spelling that reads a certificate's names: the two properties, the X500DistinguishedName
#: ones, GetNameInfo, ToString, or the whole object piped to a formatter.
_CERT_NAME = re.compile(
    r"\$cert\.(Subject|Issuer|SubjectName|IssuerName|GetNameInfo|ToString)\b|\$cert\s*\|"
)
_ESCAPED_NAME = re.compile(r"\$\(ConvertTo-PrintableText \$cert\.(Subject|Issuer)\)")


def test_every_line_naming_the_certificates_names_goes_through_the_helper() -> None:
    code = [ln for ln in _text().splitlines() if not ln.lstrip().startswith("#")]
    lines = [ln for ln in code if _CERT_NAME.search(ln)]
    assert len(lines) >= 3, "the scan found fewer cert-name lines than the script has; it is blind"
    for line in lines:
        assert not _CERT_NAME.search(_ESCAPED_NAME.sub("", line)), f"raw cert name: {line.strip()}"
    assert any("Write-Host" in ln and "Subject" in ln for ln in lines)
    assert any("Write-Host" in ln and "Issuer" in ln for ln in lines)
    assert any("ShouldProcess" in ln for ln in lines)


def test_the_scan_sees_a_raw_name_in_each_spelling() -> None:
    # The positive control: each spelling a later edit might use is caught by the scan above.
    for raw in (
        'Write-Host "$($cert.Subject)"',
        'Write-Host "$($cert.SubjectName.Name)"',
        'Write-Host "$($cert.IssuerName.Name)"',
        "Write-Host $cert.GetNameInfo('SimpleName', $false)",
        "Write-Host $cert.ToString()",
        "$cert | Format-List",
    ):
        assert _CERT_NAME.search(_ESCAPED_NAME.sub("", raw)), raw


def test_the_helper_names_both_control_and_format_categories() -> None:
    text = _text()
    assert "function ConvertTo-PrintableText" in text
    assert "function Test-EscapedForConsole" in text
    assert "[char]::IsControl(" in text
    assert "UnicodeCategory]::Format" in text


def _psq(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def test_the_helper_escapes_control_and_bidi_characters_and_keeps_the_rest(tmp_path: Path) -> None:
    if shutil.which("pwsh") is None:
        pytest.skip("SKIP (nothing run): pwsh not on PATH")
    cases = {
        "esc": "CN=a\x1b[2Jb",
        "rlo": "CN=evil\u202egpj.exe",
        "c1": "CN=a\u009bb",
        "lrm": "O=\u200eX",
        "nl": "CN=a\nCN=forged",
        "plain": "CN=Caf\u00e9 \u2014 Root, O=Acme",
        "spelled": "CN=\\u202e",
        "slash": "CN=a\\b",
        "unc": "CN=\\\\fileserver\\share",
        "slash_before_escape": "CN=\\\x1b",
        "pair": "CN=\U0001f600",
        "private": "CN=\ue000",
    }
    # The inputs travel as JSON so no control character crosses the command line raw.
    payload = json.dumps(cases)
    script = f"""
$ErrorActionPreference = 'Stop'
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    {_psq(str(_SCRIPT))}, [ref]$null, [ref]$null)
foreach ($name in @('Test-EscapedForConsole', 'ConvertTo-PrintableText')) {{
  $def = $ast.Find({{ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
      $args[0].Name -eq $name }}, $true)
  if (-not $def) {{ throw "missing function $name" }}
  . ([scriptblock]::Create($def.Extent.Text))
}}
$cases = {_psq(payload)} | ConvertFrom-Json -AsHashtable
$out = @{{}}
foreach ($k in $cases.Keys) {{ $out[$k] = ConvertTo-PrintableText $cases[$k] }}
# ASCII on the wire whatever the console code page: a Windows pipe is not UTF-8.
$out | ConvertTo-Json -Compress -EscapeHandling EscapeNonAscii
"""
    f = tmp_path / f"dbca-{uuid.uuid4().hex}.ps1"
    f.write_text(script, encoding="utf-8")
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(f)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    assert proc.returncode == 0, f"harness failed: {proc.stdout}\n{proc.stderr}"
    shown = json.loads(proc.stdout.strip().splitlines()[-1])
    assert shown["esc"] == "CN=a\\u001b[2Jb"
    assert shown["rlo"] == "CN=evil\\u202egpj.exe"
    assert shown["c1"] == "CN=a\\u009bb"
    assert shown["lrm"] == "O=\\u200eX"
    assert shown["nl"] == "CN=a\\u000aCN=forged"
    assert shown["plain"] == cases["plain"]
    assert shown["spelled"] == "CN=\\\\u202e"
    assert shown["slash"] == "CN=a\\b"
    assert shown["unc"] == cases["unc"]
    assert shown["slash_before_escape"] == "CN=\\\\\\u001b"
    assert shown["pair"] == "CN=\\ud83d\\ude00"
    assert shown["private"] == "CN=\\ue000"

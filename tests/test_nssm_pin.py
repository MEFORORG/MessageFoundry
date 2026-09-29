# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""No service script runs an nssm.exe it has not checked, from a folder the engine can write (#2364).

``install-service.ps1`` used to check NSSM's hash only when it downloaded the archive, and cached the
binary in ``<DataDir>\\bin``, where the engine's own account has modify rights. A copy from
``-NssmPath``, ``PATH`` or that cache ran unchecked, as administrator. A hash check alone would not
have been enough there: from that folder the engine could also plant a DLL beside the binary, or turn
the folder into a junction after the check. The helper installer checked neither ``nssm.exe`` nor
``mefor-net-helper.exe`` before starting the helper as LocalSystem.

What the scripts do now, and what this file pins:

1. **One pin, two identical copies.** ``install-service.ps1`` and ``install-net-helper.ps1`` share a
   byte-identical block: ``$NssmExeSha256`` (the win64 ``nssm.exe`` inside the pinned archive, which
   is NOT the archive's own ``$NssmSha256``), ``Get-FilePinProblem``, ``Lock-PinnedFile`` and
   ``Get-BroadWriteHolders``.
2. **The engine installer keeps nssm.exe in an administrator-only folder,** ``-NssmDir``, checks every
   source against the pin before copying it in, and refuses a folder anyone else can write. The
   resolver is lifted out by PowerShell AST and run against stand-in files, with the folder reading
   stubbed, because a test's temp folder is never administrator-only. Every refusal has a positive
   control beside it.
3. **The lock holds**: a locked file cannot be written through another handle, and a refused lock
   leaves nothing open.
4. **The registration is read back.** ``Get-ServiceImageProblem`` is run against stubbed service
   records, and a reinstall refuses a service registered to start any other nssm.exe.
5. **Each top level uses these in order**, read from the AST: check before stop, lock before the
   first nssm call and released after the last, a trap that releases it on failure.
6. **The uninstallers run no nssm.exe at all.** The SCM stops the service and ``sc.exe`` removes it.

Everything runs in ONE pwsh process, because this file imports the engine and so runs on every
engine leg, where each spawn costs about a second.

WHAT THIS DOES NOT TEST: that ``$NssmExeSha256`` is the hash of the real binary, and that the SCM
starts a service registered from ``-NssmDir``. The download path checks the extracted binary against
the pin, so a wrong pin fails closed on the first download. The ``windows-service-smoke`` leg runs
that download and that start.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import stat
import subprocess
import sys
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.service as svc

_INSTALL_SERVICE = svc.install_script_path()
_DIR = _INSTALL_SERVICE.parent if _INSTALL_SERVICE is not None else None

pytestmark = pytest.mark.skipif(
    _DIR is None,
    reason="scripts/service not locatable (off-repo / non-editable install)",
)

_WITH_BLOCK = ("install-service.ps1", "install-net-helper.ps1")
_WITHOUT_NSSM = ("uninstall-service.ps1", "uninstall-net-helper.ps1")
_BEGIN = "# BEGIN pinned-hash check"
_END = "# END pinned-hash check"
_PIN_RE = re.compile(r'^\$NssmExeSha256\s*=\s*"([^"]*)"', re.M)
_ARCHIVE_RE = re.compile(r'\$NssmSha256\s*=\s*"([^"]*)"')

# Stand-ins for nssm.exe. Never executed: every function under test only hashes or copies them.
_GOOD = b"stand-in for the pinned nssm.exe\n"
_BAD = b"stand-in for a planted nssm.exe\n"


def _path(name: str) -> Path:
    assert _DIR is not None  # narrowed by the module-level skipif
    return _DIR / name


def _text(name: str) -> str:
    return _path(name).read_text(encoding="utf-8").replace("\r\n", "\n")


def _block(name: str) -> str:
    text = _text(name)
    assert text.count(_BEGIN) == 1 and text.count(_END) == 1, (
        f"{name} must hold exactly one pinned-hash block, between '{_BEGIN}' and '{_END}'"
    )
    return text[text.index(_BEGIN) : text.index(_END) + len(_END)]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def _psq(value: str) -> str:
    """One PowerShell single-quoted literal. Backslashes are literal inside single quotes."""
    return "'" + value.replace("'", "''") + "'"


# ------------------------------------------------------------------------------ the shared pin


def test_the_two_copies_of_the_block_are_identical() -> None:
    first, second = (_block(name) for name in _WITH_BLOCK)
    assert first == second, (
        "the pinned-hash block in install-net-helper.ps1 differs from install-service.ps1's. The two "
        "copies are one definition kept in two places; change both in the same commit."
    )


def test_the_pin_is_well_formed_and_is_not_the_archive_pin() -> None:
    found = _PIN_RE.findall(_block("install-service.ps1"))
    assert len(found) == 1, "CONTROL FAILED: the block holds no $NssmExeSha256 assignment"
    pin = found[0]
    assert re.fullmatch(r"[0-9A-F]{64}", pin), (
        f"$NssmExeSha256 must be 64 uppercase hex characters; got {pin!r}"
    )
    archive = _ARCHIVE_RE.search(_text("install-service.ps1"))
    assert archive is not None, "CONTROL FAILED: install-service.ps1 no longer pins the archive"
    assert pin != archive.group(1), (
        "$NssmExeSha256 equals $NssmSha256, the hash of the ZIP. A binary is never equal to its "
        "archive, so every copy of nssm.exe would be refused."
    )


def test_no_script_restates_the_pin_outside_the_block() -> None:
    pin = _PIN_RE.findall(_block("install-service.ps1"))[0].lower()
    for name in _WITH_BLOCK + _WITHOUT_NSSM:
        text = _text(name)
        outside = text.replace(_block(name), "") if name in _WITH_BLOCK else text
        assert pin not in outside.lower(), (
            f"{name} states the nssm.exe pin outside the shared block. A second spelling is not "
            "guarded by the drift test and goes stale quietly."
        )


# ------------------------------------------------------------------- one pwsh run for all of it

# Functions lifted out of each script. The block's functions are identical in both installers,
# which the drift test above pins, so taking them from one is taking them from both.
_FUNCTIONS = {
    "install-service.ps1": [
        "Get-FilePinProblem",
        "Lock-PinnedFile",
        "Resolve-Nssm",
        "Save-PinnedNssm",
        "Get-ServiceImageProblem",
    ],
    "install-net-helper.ps1": ["Resolve-AbsolutePath", "Resolve-HelperNssm"],
}

# Stubs, defined AFTER the lifted functions so they win. A test's temp folder is never
# administrator-only, so the folder reading is set per case; the download must never be reached;
# the service records are whatever a case says they are.
_STUBS = """
  $broadHolders = @()
  function Get-BroadWriteHolders { param($Path) $broadHolders }
  function Invoke-WebRequest { throw 'NETWORK TOUCHED' }
  function icacls { }
  $services = @()
  function Get-CimInstance { $services }
"""

_CASES = """
  # --- Get-FilePinProblem
  Invoke-Case 'pin-good' 'path-none' { Get-FilePinProblem -Path $good -Expected $NssmExeSha256 }
  Invoke-Case 'pin-good-lower' 'path-none' {
    Get-FilePinProblem -Path $good -Expected $NssmExeSha256.ToLowerInvariant() }
  Invoke-Case 'pin-bad' 'path-none' { Get-FilePinProblem -Path $bad -Expected $NssmExeSha256 }
  Invoke-Case 'pin-missing' 'path-none' {
    Get-FilePinProblem -Path (Join-Path $root 'nope.exe') -Expected $NssmExeSha256 }
  # --- install-service.ps1 Resolve-Nssm, each case with a folder of its own
  Invoke-Case 'install-provided-good' 'path-bad' {
    Resolve-Nssm -Provided $good -NssmDir (Join-Path $root 'home-provided-good') }
  Invoke-Case 'install-provided-bad' 'path-good' {
    Resolve-Nssm -Provided $bad -NssmDir (Join-Path $root 'home-provided-bad') }
  Invoke-Case 'install-path-good' 'path-good' {
    Resolve-Nssm -NssmDir (Join-Path $root 'home-path-good') }
  Invoke-Case 'install-path-bad' 'path-bad' {
    Resolve-Nssm -NssmDir (Join-Path $root 'home-path-bad') }
  Invoke-Case 'install-home-good' 'path-bad' {
    Resolve-Nssm -NssmDir (Join-Path $root 'home-good') }
  Invoke-Case 'install-home-bad' 'path-good' {
    Resolve-Nssm -NssmDir (Join-Path $root 'home-bad') }
  Invoke-Case 'install-home-good-provided-bad' 'path-good' {
    Resolve-Nssm -Provided $bad -NssmDir (Join-Path $root 'home-good') }
  $broadHolders = @('BUILTIN\\Users (Write)')
  Invoke-Case 'install-broad-folder' 'path-good' {
    Resolve-Nssm -NssmDir (Join-Path $root 'home-broad') }
  $broadHolders = @()
  # --- install-net-helper.ps1 Resolve-HelperNssm
  Invoke-Case 'helper-provided-good' 'path-bad' { Resolve-HelperNssm -Provided $good }
  Invoke-Case 'helper-provided-bad' 'path-good' { Resolve-HelperNssm -Provided $bad }
  Invoke-Case 'helper-path-good' 'path-good' { Resolve-HelperNssm }
  Invoke-Case 'helper-path-bad' 'path-bad' { Resolve-HelperNssm }
  Invoke-Case 'helper-none' 'path-none' { Resolve-HelperNssm }
  # --- Get-ServiceImageProblem, over stubbed service records
  $img = 'C:\\Program Files\\MessageFoundry\\nssm\\nssm.exe'
  foreach ($row in @(
      @{ key = 'image-quoted'; line = ('"' + $img + '"') },
      @{ key = 'image-unquoted'; line = $img },
      @{ key = 'image-quoted-args'; line = ('"' + $img + '" -x') },
      @{ key = 'image-other'; line = '"C:\\ProgramData\\MessageFoundry\\bin\\nssm.exe"' },
      @{ key = 'image-longer-name'; line = ($img + '.evil.exe') })) {
    $services = @([pscustomobject]@{ Name = 'Svc'; PathName = $row.line },
                  [pscustomobject]@{ Name = 'Other'; PathName = ('"' + $img + '"') })
    $line = $row.line
    Invoke-Case $row.key 'path-none' { Get-ServiceImageProblem -ServiceName 'Svc' -Path $img }
  }
  $services = @([pscustomobject]@{ Name = 'Other'; PathName = ('"' + $img + '"') })
  Invoke-Case 'image-missing' 'path-none' { Get-ServiceImageProblem -ServiceName 'Svc' -Path $img }
  # --- Lock-PinnedFile. LAST, because the write probes change the files they reach.
  Invoke-Case 'lock-good' 'path-none' {
    $h = Lock-PinnedFile -Path $lockGood -Expected $NssmExeSha256
    try {
      try { [IO.File]::WriteAllBytes($lockGood, [byte[]](1, 2, 3)); 'write allowed' }
      catch { 'write refused' }
    } finally { $h.Dispose() }
  }
  Invoke-Case 'lock-bad' 'path-none' { Lock-PinnedFile -Path $lockBad -Expected $NssmExeSha256 }
  Invoke-Case 'lock-bad-released' 'path-none' {
    try { $null = Lock-PinnedFile -Path $lockBad -Expected $NssmExeSha256 } catch { }
    [IO.File]::WriteAllBytes($lockBad, [byte[]](1, 2, 3)); 'released'
  }
  # Where each resolver case left nssm.exe, and what it holds.
  $res['homes'] = @{}
  foreach ($d in @(Get-ChildItem -LiteralPath $root -Directory -Filter 'home-*')) {
    $f = Join-Path $d.FullName 'nssm.exe'
    $res['homes'][$d.Name] = $(if (Test-Path -LiteralPath $f) {
      (Get-FileHash -Algorithm SHA256 -LiteralPath $f).Hash } else { '' })
  }
"""

_AST_PROBES = """
  $ast = @{}
  foreach ($name in @('install-service.ps1', 'uninstall-service.ps1', 'install-net-helper.ps1',
                      'uninstall-net-helper.ps1')) {
    $tree = [System.Management.Automation.Language.Parser]::ParseFile(
      (Join-Path $scripts $name), [ref]$null, [ref]$null)
    $ast[$name] = @{
      commands = @($tree.FindAll({
          $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) |
        Where-Object { $_.CommandElements.Count -gt 0 } |
        ForEach-Object { @{ name = $_.GetCommandName(); first = $_.CommandElements[0].Extent.Text;
          text = $_.Extent.Text; offset = $_.Extent.StartOffset } })
      calls = @($tree.FindAll({
          $args[0] -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true) |
        ForEach-Object { @{ text = $_.Extent.Text; offset = $_.Extent.StartOffset } })
      functions = @($tree.FindAll({
          $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
        ForEach-Object { @{ name = $_.Name; start = $_.Extent.StartOffset; end = $_.Extent.EndOffset } })
      traps = @($tree.EndBlock.Traps | ForEach-Object { $_.Extent.Text })
      params = @($tree.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    }
  }
  $tree = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $scripts 'install-net-helper.ps1'), [ref]$null, [ref]$null)
  $p = $tree.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'HelperSha256' }
  $row = @{ declared = [bool]$p }
  if ($p) {
    $row['mandatory'] = [bool]($p.Attributes | Where-Object {
      $_.TypeName.Name -eq 'Parameter' -and $_.NamedArguments.ArgumentName -contains 'Mandatory' })
    foreach ($probe in @(
        @{ key = 'hex'; value = ('ab' * 32) },
        @{ key = 'short'; value = 'abc' },
        @{ key = 'nonhex'; value = ('zz' * 32) })) {
      $sb = [scriptblock]::Create("param($($p.Extent.Text))`n`$HelperSha256")
      $splat = @{ HelperSha256 = $probe.value }
      try { $null = & $sb @splat; $row[$probe.key] = $true } catch { $row[$probe.key] = $false }
    }
  }
  $ast['helper-param'] = $row
  $res['ast'] = $ast
"""


def _stand_in(directory: Path, data: bytes) -> None:
    """An nssm on a PATH directory: nssm.exe for Windows, an executable `nssm` elsewhere."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "nssm.exe").write_bytes(data)
    plain = directory / "nssm"
    plain.write_bytes(data)
    plain.chmod(plain.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


@pytest.fixture(scope="module")
def report(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Run every case, and read every top level, in ONE pwsh process."""
    if shutil.which("pwsh") is None:
        pytest.skip("SKIP (nothing run): pwsh not on PATH")
    root = tmp_path_factory.mktemp("nssmpin")
    for name, data in (
        ("good", _GOOD),
        ("bad", _BAD),
        ("lock-good", _GOOD),
        ("lock-bad", _BAD),
        ("home-good", _GOOD),
        ("home-bad", _BAD),
    ):
        (root / name).mkdir()
        (root / name / "nssm.exe").write_bytes(data)
    _stand_in(root / "path-good", _GOOD)
    _stand_in(root / "path-bad", _BAD)
    (root / "path-none").mkdir()

    lines = ["& {", "  $ErrorActionPreference = 'Stop'"]
    for script, names in _FUNCTIONS.items():
        lines += [
            f"  $tree = [System.Management.Automation.Language.Parser]::ParseFile("
            f"{_psq(str(_path(script)))}, [ref]$null, [ref]$null)",
            "  foreach ($n in @(" + ", ".join(_psq(n) for n in names) + ")) {",
            "    $fn = $tree.Find({ $args[0] -is "
            "[System.Management.Automation.Language.FunctionDefinitionAst] -and "
            "$args[0].Name -eq $n }, $true)",
            f'    if (-not $fn) {{ throw "not defined in {script}: $n" }}',
            "    . ([scriptblock]::Create($fn.Extent.Text))",
            "  }",
        ]
    lines += [
        _STUBS,
        # The pin is the stand-in's hash, so the positive controls have something to match.
        f"  $NssmExeSha256 = {_psq(_sha(_GOOD))}",
        f"  $root = {_psq(str(root))}",
        f"  $scripts = {_psq(str(_DIR))}",
        "  $res = @{}",
        "  function Invoke-Case([string]$Key, [string]$PathDir, [scriptblock]$Body) {",
        "    $env:PATH = Join-Path $root $PathDir",
        # The throw is turned into output INSIDE the redirection, so a case that warns and then
        # throws keeps its warnings.
        "    $out = @(& { try { & $Body } catch { [pscustomobject]@{ Threw = $_.Exception.Message } } } 3>&1)",
        "    $isWarn = { $_ -is [System.Management.Automation.WarningRecord] }",
        "    $thrown = @($out | Where-Object { $_.PSObject.Properties['Threw'] })",
        "    $warn = @($out | Where-Object $isWarn | ForEach-Object { $_.Message })",
        "    $val = @($out | Where-Object { -not (& $isWarn) -and -not $_.PSObject.Properties['Threw'] } |",
        '      ForEach-Object { "$_" })',
        "    $res[$Key] = @{ threw = [bool]$thrown.Count; value = ($val -join '|'); warnings = $warn;",
        "      error = $(if ($thrown.Count) { $thrown[0].Threw } else { '' }) }",
        "  }",
        "  $good = Join-Path $root 'good/nssm.exe'",
        "  $bad = Join-Path $root 'bad/nssm.exe'",
        "  $lockGood = Join-Path $root 'lock-good/nssm.exe'",
        "  $lockBad = Join-Path $root 'lock-bad/nssm.exe'",
        _CASES,
        _AST_PROBES,
        "  $res | ConvertTo-Json -Depth 8 -Compress",
        "}",
    ]
    harness = root / f"harness-{uuid.uuid4().hex}.ps1"
    harness.write_text("\n".join(lines), encoding="utf-8")
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(harness)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, f"harness failed:\n{(proc.stderr + proc.stdout)[:3000]}"
    parsed = json.loads(proc.stdout.strip().splitlines()[-1])
    assert isinstance(parsed, dict)
    return parsed


def _case(report: dict[str, Any], key: str) -> dict[str, Any]:
    assert key in report, f"CONTROL FAILED: the harness did not run case {key!r}"
    case = report[key]
    assert isinstance(case, dict)
    return case


def _names_both_hashes(message: str) -> None:
    assert _sha(_BAD) in message.upper(), f"the message does not name the actual hash: {message}"
    assert _sha(_GOOD) in message.upper(), f"the message does not name the pinned hash: {message}"


def _from(value: object, directory: str) -> bool:
    """Whether a resolved path is the nssm in ``directory`` (``good``, ``path-good``, ``home-x``)."""
    parent = Path(str(value)).parent
    return parent.parts[-len(Path(directory).parts) :] == Path(directory).parts


# ---------------------------------------------------------------------- the check and the lock


def test_the_check_passes_a_match_and_names_both_hashes_on_a_mismatch(
    report: dict[str, Any],
) -> None:
    assert _case(report, "pin-good")["value"] == "", "a matching file must pass (positive control)"
    assert _case(report, "pin-good-lower")["value"] == "", (
        "a lower-case expected hash must still match: -HelperSha256 accepts either case"
    )
    _names_both_hashes(str(_case(report, "pin-bad")["value"]))
    missing = str(_case(report, "pin-missing")["value"])
    assert "could not be hashed" in missing, f"an unreadable file must be a mismatch: {missing!r}"


def test_the_lock_holds_a_matching_file_and_releases_a_refused_one(
    report: dict[str, Any],
) -> None:
    locked = _case(report, "lock-good")
    assert locked["threw"] is False, f"positive control: a matching file must lock: {locked}"
    if sys.platform == "win32":
        # Share modes are the Windows kernel's; .NET only emulates them, advisorily, elsewhere.
        assert locked["value"] == "write refused", (
            "a write through another handle succeeded while the lock was held, so a checked copy "
            "could still be swapped before it runs"
        )
    refused = _case(report, "lock-bad")
    assert refused["threw"] is True, "a copy that fails the check must not come back locked"
    _names_both_hashes(str(refused["error"]))
    released = _case(report, "lock-bad-released")
    assert released["threw"] is False and released["value"] == "released", (
        f"a refused lock left the file held open: {released}"
    )


# ------------------------------------------------------------- the engine installer's resolver


def test_the_installer_copies_a_matching_source_into_its_own_folder(report: dict[str, Any]) -> None:
    homes = report["homes"]
    for key, home in (
        ("install-provided-good", "home-provided-good"),
        ("install-path-good", "home-path-good"),
        ("install-home-good", "home-good"),
    ):
        case = _case(report, key)
        assert case["threw"] is False, f"{key} threw: {case['error']}"
        assert _from(case["value"], home), (
            f"{key} returned {case['value']!r}, not the copy in {home}"
        )
        assert homes[home] == _sha(_GOOD), f"{key}: the copy in {home} is not the checked bytes"


def test_the_installer_refuses_a_named_or_installed_copy_that_does_not_match(
    report: dict[str, Any],
) -> None:
    homes = report["homes"]
    for key, needle in (
        ("install-provided-bad", "-NssmPath"),
        ("install-home-bad", "installed"),
        ("install-home-good-provided-bad", "-NssmPath"),
    ):
        case = _case(report, key)
        assert case["threw"] is True, f"{key}: a copy that fails the check must be refused"
        assert needle in str(case["error"]), f"{key}: {case['error']}"
        _names_both_hashes(str(case["error"]))
    assert homes["home-provided-bad"] == "", "a refused -NssmPath copy was still copied in"
    assert homes["home-bad"] == _sha(_BAD), "CONTROL FAILED: the tampered installed copy is gone"


def test_the_installer_skips_a_path_copy_that_does_not_match(report: dict[str, Any]) -> None:
    case = _case(report, "install-path-bad")
    # It went on to the download, which the stub refuses: proof the PATH copy was not used.
    assert case["threw"] is True and "NETWORK TOUCHED" in str(case["error"]), case
    warnings = case["warnings"]
    assert isinstance(warnings, list) and len(warnings) == 1, warnings
    assert "PATH" in warnings[0] and "-NssmPath" in warnings[0], warnings[0]
    _names_both_hashes(warnings[0])
    assert report["homes"]["home-path-bad"] == "", "the mismatched PATH copy was copied in"


def test_the_installer_refuses_a_folder_others_can_write(report: dict[str, Any]) -> None:
    case = _case(report, "install-broad-folder")
    assert case["threw"] is True and "not administrator-only" in str(case["error"]), case
    assert "BUILTIN\\Users" in str(case["error"]), "the refusal must name who can write there"
    assert report["homes"]["home-broad"] == "", "nssm.exe was copied into a folder others can write"


def test_the_registration_must_start_the_checked_copy(report: dict[str, Any]) -> None:
    for key in ("image-quoted", "image-unquoted", "image-quoted-args"):
        assert _case(report, key)["value"] == "", f"positive control {key}: {_case(report, key)}"
    for key in ("image-other", "image-longer-name", "image-missing"):
        problem = str(_case(report, key)["value"])
        assert "is registered to start" in problem, f"{key} was accepted: {problem!r}"


def test_the_helper_installer_refuses_every_copy_that_does_not_match(
    report: dict[str, Any],
) -> None:
    assert _from(_case(report, "helper-provided-good")["value"], "good"), "positive control"
    assert _from(_case(report, "helper-path-good")["value"], "path-good"), "positive control"
    for key in ("helper-provided-bad", "helper-path-bad"):
        case = _case(report, key)
        assert case["threw"] is True, f"{key}: a copy that fails the check must be refused"
        _names_both_hashes(str(case["error"]))
    none = _case(report, "helper-none")
    assert none["threw"] is True and "not found" in str(none["error"])


# ------------------------------------------------------------------ the top levels, in order


def _script(report: dict[str, Any], script: str) -> dict[str, Any]:
    facts = report["ast"][script]
    assert isinstance(facts, dict) and facts["commands"], (
        f"CONTROL FAILED: nothing read from {script}"
    )
    return facts


def _at(entries: list[dict[str, Any]], predicate: Callable[[dict[str, Any]], bool]) -> list[int]:
    hits = [int(e["offset"]) for e in entries if predicate(e)]
    assert hits, "CONTROL FAILED: the command this ordering check is aimed at is gone"
    return hits


def _named(name: str, *needles: str) -> Callable[[dict[str, Any]], bool]:
    return lambda c: c.get("name") == name and all(n in str(c["text"]) for n in needles)


def _top_level(facts: dict[str, Any]) -> Callable[[dict[str, Any]], bool]:
    """Outside every function body: the script's own statements."""
    spans = [(int(f["start"]), int(f["end"])) for f in facts["functions"]]
    return lambda c: not any(s <= int(c["offset"]) < e for s, e in spans)


def test_helper_sha256_is_required_and_must_be_a_sha256(report: dict[str, Any]) -> None:
    row = report["ast"]["helper-param"]
    assert row["declared"], "install-net-helper.ps1 no longer declares -HelperSha256"
    assert row["mandatory"], (
        "-HelperSha256 is not mandatory. A default or an optional check would start an unchecked "
        "binary as LocalSystem whenever the operator left it out."
    )
    assert row["hex"] is True, "positive control: a 64-hex value must bind"
    assert row["short"] is False and row["nonhex"] is False, (
        "-HelperSha256 accepts a value that is not a SHA-256, so a typo would reach the compare"
    )


def test_the_helper_binary_is_checked_before_anything_is_stopped(report: dict[str, Any]) -> None:
    commands = _script(report, "install-net-helper.ps1")["commands"]
    check = min(_at(commands, _named("Get-FilePinProblem", "$SourceExe", "$HelperSha256")))
    assert check < min(_at(commands, _named("Stop-Service"))), (
        "mefor-net-helper.exe is checked against -HelperSha256 only after the running helper is "
        "stopped. A wrong binary should cost a message, not a stopped helper."
    )
    assert check < min(_at(commands, _named("Copy-Item"))), "the check comes after the copy"


def test_the_helper_installer_holds_both_installed_copies(report: dict[str, Any]) -> None:
    facts = _script(report, "install-net-helper.ps1")
    commands = facts["commands"]
    last_copy = max(_at(commands, _named("Copy-Item")))
    nssm_runs = _at(commands, _named("Invoke-HelperNssm"))
    for needles in (("$TargetExe", "$HelperSha256"), ("$TargetNssm", "$NssmExeSha256")):
        for at in _at(commands, _named("Lock-PinnedFile", *needles)):
            assert last_copy < at < min(nssm_runs), (
                f"the installed copy {needles} is not held between the last copy and the first nssm "
                "call, so the file the SCM starts as SYSTEM is not the file checked"
            )
    # A rejected copy is deleted, both binaries, so the registration cannot start it at boot.
    assert _at(commands, _named("Remove-Item", "$TargetExe", "$TargetNssm"))
    released = _at(facts["calls"], lambda c: c["text"] == "$held.Dispose()")
    assert max(released) > max(nssm_runs), "the copies are released before the last nssm call"
    assert any("$held.Dispose()" in trap for trap in facts["traps"]), (
        "no trap releases the held copies when the install fails part-way"
    )


def test_the_engine_installer_holds_its_copy_from_check_to_last_use(report: dict[str, Any]) -> None:
    facts = _script(report, "install-service.ps1")
    commands = facts["commands"]
    resolved = min(_at(commands, _named("Resolve-Nssm")))
    lock = min(_at(commands, _named("Lock-PinnedFile", "$NssmPath", "$NssmExeSha256")))
    top = _top_level(facts)
    uses = _at(
        commands,
        lambda c: top(c) and c.get("name") in ("Invoke-Nssm", "Stop-ServiceAndConfirm"),
    )
    assert resolved < lock < min(uses), "the copy is not held from its check to its first use"
    dispose = _at(facts["calls"], lambda c: c["text"] == "$NssmLock.Dispose()")
    # The trap's own Dispose() sits above the lock; the release on the success path comes after it.
    top_dispose = [d for d in dispose if top({"offset": d}) and d > lock]
    assert len(top_dispose) == 1 and top_dispose[0] > max(uses), (
        "the copy is released before the last nssm call, or more than once"
    )
    assert any("$NssmLock.Dispose()" in trap for trap in facts["traps"]), (
        "no trap releases the copy when the install fails part-way"
    )


def test_the_engine_installer_reads_the_registration_back(report: dict[str, Any]) -> None:
    facts = _script(report, "install-service.ps1")
    commands = facts["commands"]
    top = _top_level(facts)
    checks = _at(commands, lambda c: top(c) and c.get("name") == "Get-ServiceImageProblem")
    stop = min(_at(commands, lambda c: top(c) and c.get("name") == "Stop-ServiceAndConfirm"))
    install = min(_at(commands, _named("Invoke-Nssm", "install $ServiceName")))
    assert any(at < stop for at in checks), (
        "a reinstall stops and reconfigures the service before checking which nssm.exe it starts"
    )
    assert any(at > install for at in checks), "a fresh registration is not read back"


@pytest.mark.parametrize("script", _WITHOUT_NSSM)
def test_the_uninstallers_run_no_nssm(report: dict[str, Any], script: str) -> None:
    facts = _script(report, script)
    assert "NssmPath" not in facts["params"], f"{script} still takes an nssm.exe to run"
    top = _top_level(facts)
    for c in facts["commands"]:
        first = str(c["first"])
        assert not (top(c) and first.startswith("$") and "nssm" in first.lower()), (
            f"{script} runs {first} at its top level: {c['text']!r}"
        )
    assert _at(facts["commands"], _named("sc.exe", "delete $ServiceName")), (
        f"CONTROL FAILED: {script} no longer removes the service with sc.exe"
    )
    if script == "uninstall-service.ps1":
        assert _at(facts["commands"], _named("Stop-ServiceAndConfirm", '-NssmPath ""')), (
            "uninstall-service.ps1 no longer stops the service through the SCM"
        )

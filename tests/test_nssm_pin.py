# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every service script checks the nssm.exe it runs, whatever its source (BACKLOG #2364).

``install-service.ps1`` used to check NSSM's hash only when it downloaded the archive. A copy it
found through ``-NssmPath``, on ``PATH`` or cached under ``<DataDir>\\bin`` ran unchecked, as
administrator, and the cache sits where the engine's own account can write. The helper installer
checked neither ``nssm.exe`` nor ``mefor-net-helper.exe`` before starting the helper as LocalSystem.

Four scripts now carry one byte-identical block holding ``$NssmExeSha256``, the SHA-256 of the win64
``nssm.exe`` inside the pinned archive; ``Get-FilePinProblem``, which each script calls before it
runs a copy; and ``Lock-PinnedFile``, which holds a copy open against change from its check until
its last use. This file pins four things:

1. **The four copies of the block are identical**, so the four scripts check against one pin. The
   pin is also not the ARCHIVE pin, which is the easy mistake: ``$NssmSha256`` hashes the zip, and a
   binary compared against it would be refused every time.
2. **Each resolver refuses a wrong copy and takes a right one.** The functions are lifted out of the
   scripts by PowerShell AST and run, the pattern ``tests/test_service_install_manifest.py`` uses.
   Every refusal has a positive control beside it: a check that refuses everything would pass a
   refusal-only test. The pin is swapped for the hash of a stand-in file, because the real
   ``nssm.exe`` is not in this repository; the swap is what makes the positive control possible.
3. **The lock holds.** A locked file cannot be written by another handle, and a failed lock leaves
   nothing open.
4. **Each script's top level uses these in the right order.** The top levels need elevation and a
   service, so the order is read from the AST: the check before anything is stopped or run, the
   lock before the first nssm call and released after the last one.

Everything runs in ONE pwsh process, because this file imports the engine and so runs on every
engine leg, where each spawn costs about a second.

WHAT THIS DOES NOT TEST: that ``$NssmExeSha256`` is the hash of the real binary. That value was read
from a copy ``install-service.ps1`` had cached after a checked download; the download path checks the
extracted binary against it, so a wrong pin fails closed on the first download. The
``windows-service-smoke`` leg is where that download runs.
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

_SCRIPTS = (
    "install-service.ps1",
    "uninstall-service.ps1",
    "install-net-helper.ps1",
    "uninstall-net-helper.ps1",
)
_BEGIN = "# BEGIN pinned-hash check"
_END = "# END pinned-hash check"
_PIN_RE = re.compile(r'^\$NssmExeSha256\s*=\s*"([^"]*)"', re.M)
_ARCHIVE_RE = re.compile(r'\$NssmSha256\s*=\s*"([^"]*)"')

# Stand-ins for nssm.exe. Never executed: every function under test only hashes them.
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


def test_the_four_copies_of_the_block_are_identical() -> None:
    blocks = {name: _block(name) for name in _SCRIPTS}
    reference = blocks["install-service.ps1"]
    drifted = sorted(name for name, block in blocks.items() if block != reference)
    assert not drifted, (
        f"the pinned-hash block in {drifted} differs from install-service.ps1's. The four copies "
        "are one definition kept in four places; change all four in the same commit."
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


def test_no_script_outside_the_block_restates_the_pin() -> None:
    pin = _PIN_RE.findall(_block("install-service.ps1"))[0]
    for name in _SCRIPTS:
        outside = _text(name).replace(_block(name), "")
        assert pin.lower() not in outside.lower(), (
            f"{name} states the nssm.exe pin outside the shared block. A second spelling is not "
            "guarded by the drift test and goes stale quietly."
        )


# ------------------------------------------------------------------- one pwsh run for all of it

# Functions lifted out of each script. The block's functions are identical in all four scripts,
# which the drift test above pins, so taking them from one is taking them from all.
_FUNCTIONS = {
    "install-service.ps1": ["Get-FilePinProblem", "Lock-PinnedFile", "Resolve-Nssm"],
    "uninstall-service.ps1": ["Resolve-UninstallNssm"],
    "install-net-helper.ps1": ["Resolve-AbsolutePath", "Resolve-HelperNssm"],
}

# Top levels whose command order is read back, for the ordering tests.
_ORDERED = ("install-service.ps1", "uninstall-service.ps1", "install-net-helper.ps1")

_CASES = """
  # --- Get-FilePinProblem
  Invoke-Case 'pin-good' 'path-none' { Get-FilePinProblem -Path $good -Expected $NssmExeSha256 }
  Invoke-Case 'pin-good-lower' 'path-none' {
    Get-FilePinProblem -Path $good -Expected $NssmExeSha256.ToLowerInvariant() }
  Invoke-Case 'pin-bad' 'path-none' { Get-FilePinProblem -Path $bad -Expected $NssmExeSha256 }
  Invoke-Case 'pin-missing' 'path-none' {
    Get-FilePinProblem -Path (Join-Path $root 'nope.exe') -Expected $NssmExeSha256 }
  # --- install-service.ps1 Resolve-Nssm
  Invoke-Case 'install-provided-good' 'path-none' {
    Resolve-Nssm -Provided $good -DataDir (Join-Path $root 'data-none') }
  Invoke-Case 'install-provided-bad' 'path-good' {
    Resolve-Nssm -Provided $bad -DataDir (Join-Path $root 'data-good') }
  Invoke-Case 'install-path-good' 'path-good' { Resolve-Nssm -DataDir (Join-Path $root 'data-bad') }
  Invoke-Case 'install-path-bad-cache-good' 'path-bad' {
    Resolve-Nssm -DataDir (Join-Path $root 'data-good') }
  Invoke-Case 'install-cache-good' 'path-none' { Resolve-Nssm -DataDir (Join-Path $root 'data-good') }
  Invoke-Case 'install-cache-bad' 'path-none' { Resolve-Nssm -DataDir (Join-Path $root 'data-bad') }
  Invoke-Case 'install-path-bad-cache-bad' 'path-bad' {
    Resolve-Nssm -DataDir (Join-Path $root 'data-bad') }
  # --- uninstall-service.ps1 Resolve-UninstallNssm
  Invoke-Case 'uninstall-provided-good' 'path-none' {
    Resolve-UninstallNssm -Provided $good -Cached (Join-Path $root 'data-none/bin/nssm.exe') }
  Invoke-Case 'uninstall-provided-bad' 'path-good' {
    Resolve-UninstallNssm -Provided $bad -Cached (Join-Path $root 'data-good/bin/nssm.exe') }
  Invoke-Case 'uninstall-path-bad-cache-good' 'path-bad' {
    Resolve-UninstallNssm -Cached (Join-Path $root 'data-good/bin/nssm.exe') }
  Invoke-Case 'uninstall-path-good' 'path-good' {
    Resolve-UninstallNssm -Cached (Join-Path $root 'data-bad/bin/nssm.exe') }
  Invoke-Case 'uninstall-cache-bad' 'path-none' {
    Resolve-UninstallNssm -Cached (Join-Path $root 'data-bad/bin/nssm.exe') }
  # --- install-net-helper.ps1 Resolve-HelperNssm
  Invoke-Case 'helper-provided-good' 'path-bad' { Resolve-HelperNssm -Provided $good }
  Invoke-Case 'helper-provided-bad' 'path-good' { Resolve-HelperNssm -Provided $bad }
  Invoke-Case 'helper-path-good' 'path-good' { Resolve-HelperNssm }
  Invoke-Case 'helper-path-bad' 'path-bad' { Resolve-HelperNssm }
  Invoke-Case 'helper-none' 'path-none' { Resolve-HelperNssm }
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
"""

_AST_PROBES = """
  $ast = @{}
  foreach ($name in @(__ORDERED__)) {
    $tree = [System.Management.Automation.Language.Parser]::ParseFile(
      (Join-Path $scripts $name), [ref]$null, [ref]$null)
    $ast[$name] = @($tree.FindAll({
        $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) |
      Where-Object { $_.CommandElements.Count -gt 0 } |
      ForEach-Object { @{ name = $_.GetCommandName(); text = $_.Extent.Text;
        offset = $_.Extent.StartOffset } })
    # Method calls, for the Dispose() of the lock.
    $ast["$name::calls"] = @($tree.FindAll({
        $args[0] -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true) |
      ForEach-Object { @{ text = $_.Extent.Text; offset = $_.Extent.StartOffset } })
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
    for name, data in (("good", _GOOD), ("bad", _BAD), ("lock-good", _GOOD), ("lock-bad", _BAD)):
        (root / name).mkdir()
        (root / name / "nssm.exe").write_bytes(data)
    _stand_in(root / "path-good", _GOOD)
    _stand_in(root / "path-bad", _BAD)
    (root / "path-none").mkdir()
    for name, data in (("data-good", _GOOD), ("data-bad", _BAD)):
        (root / name / "bin").mkdir(parents=True)
        (root / name / "bin" / "nssm.exe").write_bytes(data)
    (root / "data-none").mkdir()

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
        # The pin is the stand-in's hash, so the positive controls have something to match.
        f"  $NssmExeSha256 = {_psq(_sha(_GOOD))}",
        # A resolver that reached the download would be a test that touches the network.
        "  function Invoke-WebRequest { throw 'NETWORK TOUCHED' }",
        f"  $root = {_psq(str(root))}",
        f"  $scripts = {_psq(str(_DIR))}",
        "  $res = @{}",
        "  function Invoke-Case([string]$Key, [string]$PathDir, [scriptblock]$Body) {",
        "    $env:PATH = Join-Path $root $PathDir",
        "    try {",
        "      $out = @(& $Body 3>&1)",
        "      $isWarn = { $_ -is [System.Management.Automation.WarningRecord] }",
        "      $warn = @($out | Where-Object $isWarn | ForEach-Object { $_.Message })",
        '      $val = @($out | Where-Object { -not (& $isWarn) } | ForEach-Object { "$_" })',
        "      $res[$Key] = @{ threw = $false; value = ($val -join '|'); warnings = $warn; error = '' }",
        "    } catch {",
        "      $res[$Key] = @{ threw = $true; value = ''; warnings = @(); error = $_.Exception.Message }",
        "    }",
        "  }",
        "  $good = Join-Path $root 'good/nssm.exe'",
        "  $bad = Join-Path $root 'bad/nssm.exe'",
        "  $lockGood = Join-Path $root 'lock-good/nssm.exe'",
        "  $lockBad = Join-Path $root 'lock-bad/nssm.exe'",
        _CASES,
        _AST_PROBES.replace("__ORDERED__", ", ".join(_psq(n) for n in _ORDERED)),
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
    """Whether a resolved path is the stand-in in ``directory`` (``path-good``, ``data-good/bin``)."""
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


# ------------------------------------------------------------------------------- the resolvers


def test_the_installer_takes_a_matching_copy_from_every_source(report: dict[str, Any]) -> None:
    for key, directory in (
        ("install-provided-good", "good"),
        ("install-path-good", "path-good"),
        ("install-cache-good", "data-good/bin"),
        ("install-path-bad-cache-good", "data-good/bin"),
    ):
        case = _case(report, key)
        assert case["threw"] is False, f"{key} threw: {case['error']}"
        assert _from(case["value"], directory), f"{key} resolved {case['value']!r}, not {directory}"


def test_the_installer_refuses_a_named_or_cached_copy_that_does_not_match(
    report: dict[str, Any],
) -> None:
    provided = _case(report, "install-provided-bad")
    assert provided["threw"] is True, "a wrong -NssmPath copy must be refused, not run"
    assert "-NssmPath" in str(provided["error"])
    _names_both_hashes(str(provided["error"]))
    for key in ("install-cache-bad", "install-path-bad-cache-bad"):
        cached = _case(report, key)
        assert cached["threw"] is True, f"{key}: a changed cached copy must be refused"
        assert "cached" in str(cached["error"])
        assert "NETWORK TOUCHED" not in str(cached["error"]), f"{key} reached the download"
        _names_both_hashes(str(cached["error"]))


def test_the_installer_skips_a_path_copy_that_does_not_match(report: dict[str, Any]) -> None:
    warnings = _case(report, "install-path-bad-cache-good")["warnings"]
    assert isinstance(warnings, list) and len(warnings) == 1, (
        f"a mismatched PATH copy must be named in exactly one warning; got {warnings!r}"
    )
    assert "PATH" in warnings[0]
    _names_both_hashes(warnings[0])


def test_the_uninstaller_never_runs_a_copy_that_does_not_match(report: dict[str, Any]) -> None:
    for key, directory in (
        ("uninstall-provided-good", "good"),
        ("uninstall-path-good", "path-good"),
        ("uninstall-path-bad-cache-good", "data-good/bin"),
    ):
        assert _from(_case(report, key)["value"], directory), f"positive control: {key}"

    for key in ("uninstall-provided-bad", "uninstall-cache-bad"):
        case = _case(report, key)
        # "" means: stop through the SCM and remove with sc.exe. Never fatal here.
        assert case["threw"] is False, f"{key} threw: {case['error']}"
        assert case["value"] == "", f"{key} returned a copy that failed the check: {case['value']}"
        assert case["warnings"], f"{key} refused silently"
        _names_both_hashes(" ".join(case["warnings"]))
    assert "Only the installer writes" in " ".join(_case(report, "uninstall-cache-bad")["warnings"])


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


def _commands(report: dict[str, Any], script: str) -> list[dict[str, Any]]:
    commands = report["ast"][script]
    assert isinstance(commands, list) and commands, (
        f"CONTROL FAILED: no commands read from {script}"
    )
    return commands


def _at(entries: list[dict[str, Any]], predicate: Callable[[dict[str, Any]], bool]) -> list[int]:
    hits = [int(e["offset"]) for e in entries if predicate(e)]
    assert hits, "CONTROL FAILED: the command this ordering check is aimed at is gone"
    return hits


def _named(name: str, *needles: str) -> Callable[[dict[str, Any]], bool]:
    return lambda c: c.get("name") == name and all(n in str(c["text"]) for n in needles)


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
    commands = _commands(report, "install-net-helper.ps1")
    check = min(_at(commands, _named("Get-FilePinProblem", "$SourceExe", "$HelperSha256")))
    assert check < min(_at(commands, _named("Stop-Service"))), (
        "mefor-net-helper.exe is checked against -HelperSha256 only after the running helper is "
        "stopped. A wrong binary should cost a message, not a stopped helper."
    )
    assert check < min(_at(commands, _named("Copy-Item"))), "the check comes after the copy"


def test_both_installed_copies_are_checked_before_anything_runs(report: dict[str, Any]) -> None:
    commands = _commands(report, "install-net-helper.ps1")
    last_copy = max(_at(commands, _named("Copy-Item")))
    first_nssm = min(_at(commands, _named("Invoke-HelperNssm")))
    for needles in (("$TargetExe", "$HelperSha256"), ("$TargetNssm", "$NssmExeSha256")):
        for at in _at(commands, _named("Get-FilePinProblem", *needles)):
            assert last_copy < at < first_nssm, (
                f"the installed copy check {needles} does not sit between the last copy and the "
                "first nssm call, so the file the SCM starts as SYSTEM is not the file checked"
            )


@pytest.mark.parametrize(
    ("script", "resolver", "first_use", "last_use"),
    [
        ("install-service.ps1", "Resolve-Nssm", "Stop-ServiceAndConfirm", "Invoke-Nssm"),
        ("uninstall-service.ps1", "Resolve-UninstallNssm", "Stop-ServiceAndConfirm", None),
    ],
)
def test_the_nssm_copy_is_held_from_its_check_to_its_last_use(
    report: dict[str, Any], script: str, resolver: str, first_use: str, last_use: str | None
) -> None:
    commands = _commands(report, script)
    resolved = min(_at(commands, _named(resolver)))
    lock = min(_at(commands, _named("Lock-PinnedFile", "$NssmPath", "$NssmExeSha256")))
    first = min(_at(commands, _named(first_use)))
    assert resolved < lock < first, (
        f"{script}: the lock is not taken between {resolver} and the first nssm use, so the copy "
        "that runs is not held against change from its check"
    )
    uses = _at(commands, _named(last_use)) if last_use else []
    # uninstall-service.ps1 runs `& $NssmPath remove` directly, a command with no name.
    uses += _at(commands, lambda c: str(c["text"]).startswith("& $NssmPath"))
    dispose = _at(report["ast"][f"{script}::calls"], lambda c: "$NssmLock.Dispose()" in c["text"])
    assert len(dispose) == 1 and dispose[0] > max(uses), (
        f"{script}: the lock is released before the last nssm call, or more than once"
    )


def test_the_helper_uninstaller_gates_nssm_on_the_check() -> None:
    helper = _text("uninstall-net-helper.ps1")
    # Starts false, and the passing branch is the ONE place that sets it true.
    assert helper.count("$useNssm = $true") == 1, "only a passed check may set $useNssm"
    m = re.search(
        r"\$useNssm = \$false\s*if \(Test-Path -LiteralPath \$nssmForRemoval\) \{\s*"
        r"\$problem = Get-FilePinProblem -Path \$nssmForRemoval -Expected \$NssmExeSha256\s*"
        r"if \(\$problem\) \{(?P<refuse>.*?)\} else \{\s*\$useNssm = \$true\s*\}",
        helper,
        re.S,
    )
    assert m is not None, "uninstall-net-helper.ps1 no longer gates its nssm on the pinned hash"
    assert "$useNssm = $true" not in m.group("refuse")
    assert re.search(r"if \(\$useNssm\) \{\s*& \$nssmForRemoval remove", helper), (
        "the nssm removal no longer sits under `if ($useNssm)`"
    )

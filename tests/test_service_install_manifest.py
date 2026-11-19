# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Static-manifest policy guards for the NSSM integrity-verify path (DEPLOY-7).

``install-service.ps1`` auto-downloads a pinned NSSM release when no checked copy is available,
then verifies it against a hard-coded SHA-256 before trusting the binary. That download + hash +
extract runs only on Windows, so it can't execute under pytest here (the windows-service-smoke job
runs it, since the runner's PATH nssm does not match the binary pin). ``Resolve-Nssm``'s choice of
source is exercised in ``tests/test_nssm_pin.py`` (BACKLOG #2364). What IS unit-testable off-Windows is the *static shape* of the
integrity policy, which is the load-bearing part: a blanked/malformed pin or a mismatch branch
downgraded from ``throw`` to ``Write-Warning`` is a silent fail-open of supply-chain verification.

These guards read the script source (located via ``service.install_script_path()``) and assert:
  1. the pinned ``$NssmSha256`` is present and a well-formed SHA-256 (64 uppercase hex chars);
  2. the mismatch branch is fail-closed — ``Get-FileHash -Algorithm SHA256`` compared to the pin,
     which ``throw``s (not merely warns) and removes the downloaded zip on mismatch;
  3. the download is TLS-hardened (Tls12) and extraction selects ``win64\\nssm.exe``.

The basis is CWE-494 (download of code without integrity check) / SLSA-style artifact pinning.

BEHAVIOURAL GUARDS WERE ADDED LATER, AND THEY ARE NOT STATIC (BACKLOG #1573, #1558, #1699, #1553).
Some of what these scripts must get right cannot be witnessed by reading them: whether a failure
message still carries a password, whether a stop is confirmed, what DACL ``icacls`` actually leaves on
a directory. Those guards EXTRACT the named function from the .ps1 by PowerShell AST, dot-source that
one function into an isolated scope, and RUN it -- the pattern
``tests/test_install_gate_allowlist_merge.py`` established for ``install-gate.ps1``, skipping when
``pwsh`` is absent the way ``tests/test_collision_gate.py`` does. Extracting one function runs no other
line of the installer, so nothing here installs, downloads, or touches a service.

The static guards are kept alongside, because an executed FUNCTION says nothing about whether the
script still CALLS it -- which is exactly the #1699 complaint about this file.
"""

from __future__ import annotations

import functools
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.service as svc

_SCRIPT = svc.install_script_path()
_UNINSTALL = svc.uninstall_script_path()

pytestmark = pytest.mark.skipif(
    _SCRIPT is None,
    reason="install-service.ps1 not locatable (off-repo / non-editable install)",
)


def _script_text() -> str:
    assert _SCRIPT is not None  # narrowed by the module-level skipif
    return _SCRIPT.read_text(encoding="utf-8")


# --------------------------------------------------------------- the AST extract-and-run harness


def _psq(value: str) -> str:
    """One PowerShell single-quoted literal. Backslashes are literal inside single quotes."""
    return "'" + value.replace("'", "''") + "'"


def _extract(path: Path, names: list[str], body: str) -> str:
    """A script that dot-sources ``names`` out of ``path`` by AST, then runs ``body`` against them.

    ``ParseFile`` parses; it never runs the file. Only the named function definitions are then
    executed, so no preflight, download, ACL call or service registration in the source script runs.

    A file that does not parse throws, naming the parser's errors. ``ParseFile`` still returns a
    partial tree for it, and a guard reading that tree can miss a call the parser dropped and pass.
    """
    lines = [
        "& {",
        "  $ErrorActionPreference = 'Stop'",
        f"  $src = {_psq(str(path))}",
        "  $parseErrors = $null",
        "  $ast = [System.Management.Automation.Language.Parser]::ParseFile("
        "$src, [ref]$null, [ref]$parseErrors)",
        "  if ($parseErrors) {",
        '    throw "$(Split-Path -Leaf $src) does not parse: $(@($parseErrors |'
        ' ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" }) -join \'; \')"',
        "  }",
        "  foreach ($n in @(" + ", ".join(_psq(n) for n in names) + ")) {",
        "    $fn = $ast.Find({ $args[0] -is "
        "[System.Management.Automation.Language.FunctionDefinitionAst] -and "
        "$args[0].Name -eq $n }, $true)",
        '    if (-not $fn) { throw "not defined in $(Split-Path -Leaf $src): $n" }',
        "    . ([scriptblock]::Create($fn.Extent.Text))",
        "  }",
        body,
        "}",
    ]
    return "\n".join(lines)


def _run(script: str, tmp_path: Path, host: str = "pwsh") -> subprocess.CompletedProcess[str]:
    """Run ``script`` on PowerShell 7, or on ``host="powershell"``, Windows PowerShell 5.1, the host
    CI runs the installer on."""
    if shutil.which(host) is None:
        pytest.skip(f"SKIP (nothing run): {host} not on PATH")
    f = tmp_path / f"harness-{uuid.uuid4().hex}.ps1"
    env = None
    if host == "powershell":
        # 5.1 reads a BOM-less file as the ANSI code page. A PSModulePath inherited from PowerShell 7
        # points 5.1 at 7's modules, and Get-Acl then fails to load; 5.1 rebuilds its own path when
        # the variable is absent.
        f.write_text(script, encoding="utf-8-sig")
        env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
        cmd = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"]
    else:
        f.write_text(script, encoding="utf-8")
        cmd = ["pwsh", "-NoProfile", "-NonInteractive"]
    return subprocess.run(
        [*cmd, "-File", str(f)],
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )


def _ok(script: str, tmp_path: Path, host: str = "pwsh") -> str:
    r = _run(script, tmp_path, host)
    assert r.returncode == 0, f"harness failed:\n{(r.stderr + r.stdout)[:2000]}"
    return r.stdout


def _pinned_sha() -> str:
    """Extract the RHS of ``$NssmSha256 = "..."`` from the script."""
    m = re.search(r'\$NssmSha256\s*=\s*"([^"]*)"', _script_text())
    assert m is not None, "the $NssmSha256 pin assignment is missing from install-service.ps1"
    return m.group(1)


def test_nssm_sha_pin_is_present_and_well_formed() -> None:
    """The pin exists and is a 64-char uppercase-hex SHA-256 — not blanked or malformed.

    A blanked ("") or truncated pin would let any downloaded artifact pass the compare and be
    trusted: the exact supply-chain fail-open this guard exists to catch.
    """
    sha = _pinned_sha()
    assert sha != "", "$NssmSha256 is blank — integrity check would accept any download"
    assert re.fullmatch(r"[0-9A-F]{64}", sha), (
        f"$NssmSha256 must be 64 uppercase hex chars (SHA-256 shape); got {sha!r}"
    )


def test_integrity_branch_is_fail_closed() -> None:
    """A download that fails the pin is never opened, and no matching download means a throw.

    Since BACKLOG #2504 there is more than one source, so a mismatch skips to the next source rather
    than throwing on the spot. What must hold is that the mismatch branch deletes the file and moves
    on without marking it verified, and that nothing is extracted until a download has matched.
    ``tests/test_nssm_pin.py`` runs this function against stand-in sources; this reads its shape.
    """
    text = _script_text()
    # The comparison is against the pin, computed with SHA256.
    assert "Get-FileHash -Algorithm SHA256" in text, (
        "the download must be hashed with Get-FileHash -Algorithm SHA256"
    )
    assert re.search(r"\$hash\s*-ne\s*\$NssmSha256", text), (
        "the computed hash must be compared against the pinned $NssmSha256"
    )

    # Isolate the mismatch block and prove it leaves the download unused: skip it, or throw.
    m = re.search(
        r"if\s*\(\s*\$hash\s*-ne\s*\$NssmSha256\s*\)\s*\{(?P<body>.*?)\}",
        text,
        re.DOTALL,
    )
    assert m is not None, "the '$hash -ne $NssmSha256' mismatch block is missing"
    body = m.group("body")
    assert re.search(r"^\s*(continue|throw)\b", body, re.MULTILINE), (
        "an integrity mismatch must skip the source or throw; it must not fall through to use it"
    )
    assert "$verified" not in body, "an integrity mismatch must never mark the download verified"
    # The rejected artifact is deleted so a stale bad zip can't be reused.
    assert "Remove-Item" in body, "the mismatched download must be removed on failure"
    # Only a matching download is extracted: the no-match branch throws before Expand-Archive.
    unverified = re.search(r"if\s*\(\s*-not\s+\$verified\s*\)\s*\{(?P<body>.*?)\}", text, re.DOTALL)
    assert unverified is not None, "there is no refusal for when no download matched"
    assert "throw" in unverified.group("body"), "no matching download must THROW (fail closed)"
    assert unverified.start() > m.start(), "the no-match refusal must follow the per-source check"
    assert unverified.end() < text.index("Expand-Archive"), (
        "the archive is extracted before the no-match refusal, so an unverified archive is opened"
    )


def test_download_is_tls_hardened_and_extracts_win64() -> None:
    """The download negotiates TLS 1.2 and extraction selects the win64 nssm.exe."""
    text = _script_text()
    assert "Tls12" in text, "the download must enable TLS 1.2 (Tls12) for the NSSM fetch"
    assert re.search(r'\$_\.Directory\.Name\s*-eq\s*"win64"', text), (
        "extraction must select the win64\\nssm.exe from the archive"
    )
    # A missing win64 binary is itself fail-closed.
    assert re.search(r"if\s*\(\s*-not\s+\$exe\s*\)\s*\{[^}]*throw", text, re.DOTALL), (
        "a missing win64\\nssm.exe must throw, not proceed"
    )


# --- least-privilege run-as default (BACKLOG #224; #99(b)) ----------------------------------------
# The installer defaults the service run-as to the per-service VIRTUAL account
# ``NT SERVICE\<ServiceName>`` (no password); LocalSystem is reachable only via an explicit
# ``-AllowLocalSystem`` opt-out. That flip is exercised end-to-end by the mirror-gated
# ``windows-service-smoke`` leg, which cannot run in this pytest loop — so the *static shape* of the
# default is guarded here. Without these, a refactor could silently restore LocalSystem-by-default
# (a privilege regression that no PR-blocking leg would catch, since the smoke is mirror-only).


def test_default_run_as_is_the_least_privilege_virtual_account() -> None:
    r"""No -ServiceAccount and no -AllowLocalSystem must default to NT SERVICE\<ServiceName>."""
    text = _script_text()
    m = re.search(
        r"if\s*\(\s*-not\s+\$ServiceAccount\s+-and\s+-not\s+\$AllowLocalSystem\s*\)\s*\{"
        r"(?P<body>.*?)\n\}",
        text,
        re.DOTALL,
    )
    assert m is not None, (
        "the least-privilege default branch "
        "'if (-not $ServiceAccount -and -not $AllowLocalSystem)' is missing — the run-as default "
        "may have regressed to LocalSystem (BACKLOG #224)"
    )
    # Literal substring, not a regex: the assigned value contains both '\' and '$', which are
    # regex-significant and were silently mis-escaped when this was a pattern.
    assert r'$ServiceAccount = "NT SERVICE\$ServiceName"' in m.group("body"), (
        r"the default branch must assign the per-service virtual account NT SERVICE\$ServiceName"
    )


def test_localsystem_requires_the_explicit_opt_out() -> None:
    """LocalSystem must be reachable ONLY by passing -AllowLocalSystem."""
    text = _script_text()
    assert re.search(r"\[switch\]\$AllowLocalSystem", text), (
        "the -AllowLocalSystem opt-out switch is missing"
    )
    # ObjectName is left unset (=> NSSM runs as LocalSystem) only on the empty-$ServiceAccount
    # branch, which the default above can now reach only when -AllowLocalSystem was passed.
    assert re.search(r"Write-Warning\s*\(\s*[\"']Service will run as LocalSystem", text), (
        "the LocalSystem opt-out must still warn that it is the most-privileged account"
    )


def test_gmsa_preflight_and_logon_right_are_wired(monkeypatch: pytest.MonkeyPatch) -> None:
    """A (g)MSA -ServiceAccount gets Test-ADServiceAccount + SeServiceLogonRight before registration.

    Both degrade gracefully off-domain (skip-with-message, never abort), which is what lets the
    non-domain CI leg and a dev box keep working — assert the calls exist, not that they succeed.
    """
    text = _script_text()
    assert "Test-ADServiceAccount" in text, "the gMSA preflight (Test-ADServiceAccount) is missing"
    assert "SeServiceLogonRight" in text, (
        "the 'Log on as a service' (SeServiceLogonRight) grant is missing — a gMSA/virtual account "
        "otherwise fails to start with error 1069"
    )
    assert re.search(r"\[switch\]\$SkipGmsaPreflight", text), (
        "the -SkipGmsaPreflight opt-out is missing"
    )


# --- the nssm failure message must not carry the service-account password (BACKLOG #1573) ---------
# ``Invoke-Nssm`` throws "nssm <args> failed (exit N)" on a non-zero exit. One of its 18 call sites
# passes the service-account password, so a joined message there puts cleartext into the throw, the
# host's error rendering, and the $Error record it leaves behind.
#
# THE NAIVE FIX IS THE ONE TO GUARD AGAINST: stripping the arguments from every message would pass a
# test that only checks "the password is absent", and would also destroy the 18 messages an operator
# actually needs. So the ordinary-call arm below is a POSITIVE CONTROL, not a bonus assertion -- it is
# what distinguishes a redaction from an erasure.

_SECRET = "hunter2-DO-NOT-LEAK-THIS"


def _nssm_stub(path_stem: Path, *, message: str, exit_code: int, chatter: str = "") -> Path:
    """Write a stub nssm that prints ``message`` to stderr and exits ``exit_code``.

    ``chatter``, when given, is printed to STDOUT as well -- nssm is not silent, and stdout is the
    stream that lands in a PowerShell function's return value.

    THE STUB MUST BE A REAL NATIVE COMMAND ON THE HOST RUNNING THE TEST, and a ``.cmd`` is not one
    off Windows. These arms exist to read a genuine ``$LASTEXITCODE`` back from a genuine child
    process, so a stub that cannot launch does not weaken the test -- it silently replaces it.

    Measured 2026-09-18 on the ubuntu-latest CI leg, where a ``.cmd`` stub produced exactly that:
    PowerShell resolved the path (the file exists), failed to start it, wrote a NON-terminating
    error, and carried on to the exit-code check with $LASTEXITCODE never set. Every message under
    test then rendered the code as an empty string -- ``failed (exit )``, ``exited  (its message is
    above)`` -- and the two arms that assert a code is present failed while the two that assert
    silence saw a warning. The scripts were right; the stub was not a command.

    So: a batch file on Windows, a shebanged shell script with the execute bit everywhere else.
    NEVER an extension a desktop has an association for -- see ``_stub_control``, which records what
    a ``.txt`` did here.
    """
    if sys.platform.startswith("win"):
        stub = path_stem.with_suffix(".cmd")
        out = f"echo {chatter}\r\n" if chatter else ""
        stub.write_text(
            f"@echo off\r\n{out}echo {message} 1>&2\r\nexit /b {exit_code}\r\n", "ascii"
        )
        return stub
    stub = path_stem.with_suffix(".sh")
    out = f"echo '{chatter}'\n" if chatter else ""
    stub.write_text(f"#!/bin/sh\n{out}echo '{message}' >&2\nexit {exit_code}\n", "ascii")
    stub.chmod(0o755)
    return stub


def _stub_control(stub: Path, exit_code: int) -> str:
    """Harness that proves the stub is a runnable native command BEFORE any arm relies on it.

    A stub that cannot launch reads as a script defect, not as a harness defect, and that is how a
    whole afternoon goes. This makes the instrument say so in its own words: an execute bit that did
    not take, a noexec temp filesystem, a host with no shell.

    It leaves $LASTEXITCODE at a real 0, deliberately. A STALE value is what the code under test must
    not read, and 0 is the one value that would let a stale read look like success -- so if the clear
    inside the function under test is ever dropped, the arms below fail rather than pass on this.
    """
    return (
        f"  & {_psq(str(stub))}\n"
        f"  if ($LASTEXITCODE -ne {exit_code}) {{ throw ("
        f"'CONTROL FAILED: the nssm stub is not a runnable command on this host (expected exit "
        f"{exit_code}, got [' + \"$LASTEXITCODE\" + ']). The arms below would then measure a failed "
        f"LAUNCH rather than the exit code the script reads.') }}\n"
        "  $global:LASTEXITCODE = 0\n"
    )


def _invoke_nssm_arms(tmp_path: Path) -> dict[str, str]:
    """Run Invoke-Nssm against a stub that always exits 3, once with a secret and once without.

    Everything a leaked password could reach is collected per arm: the exception message, the error
    record as the host renders it, the record's full property dump, and the $Error entry.
    """
    assert _SCRIPT is not None
    stub = _nssm_stub(
        tmp_path / "nssm-stub", message="nssm: the service could not be configured", exit_code=3
    )
    body = (
        _stub_control(stub, 3)
        + rf"""
  $NssmPath = {_psq(str(stub))}
  $out = [ordered]@{{}}
  foreach ($arm in 'sensitive', 'ordinary') {{
    $Error.Clear()
    $text = ''
    try {{
      if ($arm -eq 'sensitive') {{
        Invoke-Nssm -Secret {_psq(_SECRET)} set MessageFoundry ObjectName 'DOMAIN\svc'
      }} else {{
        Invoke-Nssm set MessageFoundry AppStdout 'C:\ProgramData\MessageFoundry\logs\service.out.log'
      }}
    }} catch {{
      $text = @(
        $_.Exception.Message
        ($_ | Out-String)
        ($_ | Format-List * -Force | Out-String)
        ($Error | Out-String)
      ) -join "`n"
    }}
    $out[$arm] = $text
  }}
  $out | ConvertTo-Json -Depth 4 -Compress
"""
    )
    raw = _ok(
        _extract(
            _SCRIPT,
            ["Invoke-Nssm", "Test-LegacyNativeArgumentPassing", "ConvertTo-NativeArgument"],
            body,
        ),
        tmp_path,
    )
    parsed: dict[str, str] = json.loads(raw.strip().splitlines()[-1])
    return parsed


def test_nssm_failure_message_redacts_the_service_account_password(tmp_path: Path) -> None:
    """The password never reaches the throw, the rendered record, or the $Error entry."""
    arms = _invoke_nssm_arms(tmp_path)
    sensitive = arms["sensitive"]
    assert sensitive, "the sensitive arm did not throw -- the stub's exit 3 was not detected"
    assert _SECRET not in sensitive, (
        "the service-account password reached the nssm failure message / $Error record "
        f"(BACKLOG #1573):\n{sensitive[:1500]}"
    )
    assert "<redacted>" in sensitive, (
        "the redaction placeholder is missing -- the secret must be replaced in the message, not "
        "silently dropped, so an operator can see an argument was withheld"
    )
    assert "ObjectName" in sensitive, (
        "even the redacted message must still name the failing subcommand, or the fix has traded a "
        "leak for an unusable message"
    )


def test_ordinary_nssm_failures_still_name_their_arguments(tmp_path: Path) -> None:
    """POSITIVE CONTROL. Without this, emptying every message passes the test above.

    17 of the 18 call sites carry no secret and their joined arguments are the whole diagnostic
    value of the throw.
    """
    arms = _invoke_nssm_arms(tmp_path)
    ordinary = arms["ordinary"]
    assert ordinary, "the ordinary arm did not throw -- the stub's exit 3 was not detected"
    assert "AppStdout" in ordinary, "an ordinary nssm failure must still name its subcommand"
    assert "service.out.log" in ordinary, (
        "an ordinary nssm failure must still name its arguments -- a fix that strips every "
        "argument would satisfy the redaction test while destroying 17 useful messages"
    )
    assert "exit 3" in ordinary, "the failure message must carry nssm's exit code"


def test_the_password_reaches_the_scm_only_as_a_securestring(tmp_path: Path) -> None:
    """CALL-SITE guard for the run-as password (BACKLOG #1573, #2364).

    The account is set through Set-ServiceAccount, not `nssm set ObjectName`: NSSM 2.24 refuses a
    virtual account ("Setting ObjectName requires both a username and password", exit 6, CI run
    36590581708). The password must reach that function as the -ServiceAccountPassword SecureString,
    by name, and be turned into plaintext nowhere at the script's top level. Located by AST.
    """
    assert _SCRIPT is not None
    body = """
  $cmds = @($ast.FindAll({ $args[0] -is
      [System.Management.Automation.Language.CommandAst] }, $true) | Where-Object {
      $_.GetCommandName() -in @('Invoke-Nssm', 'Set-ServiceAccount') })
  $fn = $ast.Find({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
      $args[0].Name -eq 'Set-ServiceAccount' }, $true)
  $bstr = @($ast.FindAll({ $args[0] -is
      [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
      $args[0].Member.Extent.Text -eq 'PtrToStringBSTR' }, $true))
  [pscustomobject]@{
    calls = @($cmds | ForEach-Object {
      [pscustomobject]@{ name = $_.GetCommandName(); text = $_.Extent.Text
                         elements = @($_.CommandElements | ForEach-Object { $_.Extent.Text }) } })
    fnStart = $(if ($fn) { $fn.Extent.StartOffset } else { -1 })
    fnEnd = $(if ($fn) { $fn.Extent.EndOffset } else { -1 })
    plaintext = @($bstr | ForEach-Object { $_.Extent.StartOffset })
  } | ConvertTo-Json -Depth 5 -Compress
"""
    facts = json.loads(_ok(_extract(_SCRIPT, [], body), tmp_path).strip().splitlines()[-1])
    calls = facts["calls"]
    assert not [c for c in calls if c["name"] == "Invoke-Nssm" and "ObjectName" in c["elements"]], (
        "an Invoke-Nssm call still sets ObjectName, which NSSM 2.24 refuses for a virtual account"
    )
    with_password = [
        c for c in calls if c["name"] == "Set-ServiceAccount" and "-Password" in c["elements"]
    ]
    assert len(with_password) == 1, (
        f"exactly one Set-ServiceAccount call passes the password; found {len(with_password)}"
    )
    elements = with_password[0]["elements"]
    assert elements[elements.index("-Password") + 1] == "$ServiceAccountPassword", (
        "the password must be passed as the SecureString parameter, not a plaintext local: "
        + with_password[0]["text"]
    )
    assert facts["fnStart"] >= 0, "CONTROL FAILED: Set-ServiceAccount is not defined"
    outside = [o for o in facts["plaintext"] if not (facts["fnStart"] <= o < facts["fnEnd"])]
    assert facts["plaintext"] and not outside, (
        "the SecureString is turned into plaintext outside Set-ServiceAccount, where a message or "
        "an $Error record could carry it"
    )


# --- a stop must be checked AND confirmed before the next step runs (BACKLOG #1558) ---------------
# Three stop sites existed, all unchecked: the reconfigure branch of install-service.ps1, and BOTH
# branches of uninstall-service.ps1 (nssm, and the SCM fallback when nssm is absent).
#
# THE ROW BLAMED THE EMPTY ``catch { }`` AND THAT IS NOT WHERE THE SWALLOW WAS. Measured on both
# hosts against a stub that writes to stderr and exits 3:
#   * PowerShell 7.6.6              -- nothing raised, catch never fired, $LASTEXITCODE == 3.
#   * Windows PowerShell 5.1.26100  -- the ``2>&1`` MERGE raised a terminating RemoteException that
#     the empty catch swallowed, and $LASTEXITCODE came back -1 because the pipeline aborted before
#     nssm's real exit code was recorded.
# 5.1 is the host CI runs these scripts on (``shell: powershell``), so an exit-code check written
# after a merged capture would have been UNREACHABLE there. The fix calls nssm bare.
#
# And an exit code alone is still not the question: ``nssm stop`` can exit 0 while the process is
# still draining, which is why the status is polled back. The arms below separate those two.

_STOP_FN = "Stop-ServiceAndConfirm"


def _stop_arms(
    tmp_path: Path,
    *,
    nssm_exit: int | None,
    states: list[str],
    timeout: int = 1,
    chatter: str = "",
    service: str = "MessageFoundry",
    found_name: str | None = None,
    lookup_error: str | None = None,
) -> dict:
    """Run Stop-ServiceAndConfirm with Get-Service and Stop-Service shadowed.

    ``states`` is what the shadowed Get-Service reports on successive calls (the last value repeats);
    an empty list means the service is absent. ``nssm_exit`` of None runs the no-nssm branch, which
    is uninstall-service.ps1's third stop site. ``chatter`` makes the stub print to STDOUT.

    ``service`` is the -ServiceName passed. ``found_name`` is the Name the shadowed Get-Service
    reports for it, ``service`` itself when None: a different one is how the real cmdlet answers a
    DISPLAY name (BACKLOG #5402). ``lookup_error`` makes it throw an error with that
    FullyQualifiedErrorId instead, and ``threw`` then holds what the helper threw, if anything.

    ``outputs`` counts the non-warning objects the helper emitted. It is reported rather than
    collapsed because the COUNT is the defect: the callers test one boolean.
    """
    assert _SCRIPT is not None
    stub = _nssm_stub(
        tmp_path / f"nssm-stop-{uuid.uuid4().hex}",
        message="nssm: stop reported a problem",
        exit_code=nssm_exit if nssm_exit is not None else 0,
        chatter=chatter,
    )
    prelude = _stub_control(stub, nssm_exit) if nssm_exit is not None else ""
    nssm_arg = _psq(str(stub)) if nssm_exit is not None else "''"
    states_ps = "@(" + ", ".join(_psq(s) for s in states) + ")"
    found_ps = _psq(found_name) if found_name is not None else "$null"
    error_ps = _psq(lookup_error) if lookup_error is not None else "$null"
    body = (
        prelude
        + rf"""
  $script:StopServiceCalls = 0
  $script:GetServiceCalls = 0
  $script:States = {states_ps}
  $script:FoundName = {found_ps}
  $script:LookupError = {error_ps}
  $script:StopTargets = @()
  function Get-Service {{
    param([string]$Name, $ErrorAction)
    $script:GetServiceCalls++
    if ($null -ne $script:LookupError) {{
      throw [System.Management.Automation.ErrorRecord]::new(
        [Exception]::new('synthetic lookup failure'), $script:LookupError, 'NotSpecified', $Name)
    }}
    if ($script:States.Count -eq 0) {{ return $null }}
    $i = [Math]::Min($script:GetServiceCalls - 1, $script:States.Count - 1)
    $found = if ($null -ne $script:FoundName) {{ $script:FoundName }} else {{ $Name }}
    return [pscustomobject]@{{ Name = $found; Status = $script:States[$i] }}
  }}
  function Stop-Service {{
    param([string]$Name, $InputObject, [switch]$Force, $ErrorAction)
    $script:StopServiceCalls++
    $script:StopTargets += $(if ($Name) {{ "name:$Name" }} else {{ "object:$($InputObject.Name)" }})
  }}
  $warnings = @()
  $result = $null
  $threw = ''
  $emitted = @()
  try {{
    $emitted = & {{
      {_STOP_FN} -ServiceName {_psq(service)} -NssmPath {nssm_arg} -TimeoutSeconds {timeout}
    }} 3>&1
  }} catch {{ $threw = "$_" }}
  $outputs = 0
  foreach ($o in @($emitted)) {{
    if ($o -is [System.Management.Automation.WarningRecord]) {{ $warnings += "$o" }}
    else {{ $result = $o; $outputs++ }}
  }}
  [pscustomobject]@{{
    result           = [bool]$result
    outputs          = $outputs
    warnings         = @($warnings)
    stopServiceCalls = $script:StopServiceCalls
    getServiceCalls  = $script:GetServiceCalls
    stopTargets      = @($script:StopTargets)
    threw            = $threw
  }} | ConvertTo-Json -Depth 4 -Compress
"""
    )
    raw = _ok(_extract(_SCRIPT, [_STOP_FN], body), tmp_path)
    parsed: dict = json.loads(raw.strip().splitlines()[-1])
    parsed["warnings"] = [w for w in (parsed.get("warnings") or []) if w]
    return parsed


def test_a_clean_stop_is_reported_clean(tmp_path: Path) -> None:
    """POSITIVE CONTROL. nssm exits 0 and the service reads Stopped: True, and no warning.

    Without this, a helper that warned unconditionally, or always returned False, would satisfy
    every failure arm below.
    """
    arms = _stop_arms(tmp_path, nssm_exit=0, states=["Stopped"])
    assert arms["result"] is True, "a clean stop must report success"
    assert arms["warnings"] == [], f"a clean stop must warn about nothing; got {arms['warnings']}"


@pytest.mark.parametrize("nssm_exit", [0, None])
def test_an_scm_read_that_fails_is_not_taken_as_gone(tmp_path: Path, nssm_exit: int | None) -> None:
    """Only "no such service" means gone (BACKLOG #5402). Any other failed read says nothing about
    whether the service still runs, so the helper throws rather than report it stopped, and stops
    nothing it could not identify."""
    failed = _stop_arms(
        tmp_path, nssm_exit=nssm_exit, states=["Running"], lookup_error="RpcServerUnavailable"
    )
    assert "Could not read 'MessageFoundry' from the SCM" in failed["threw"], failed
    assert failed["stopServiceCalls"] == 0, failed
    # The control: the cmdlet's own "no such service" error is an absent service, as before.
    gone = _stop_arms(
        tmp_path,
        nssm_exit=nssm_exit,
        states=["Running"],
        lookup_error="NoServiceFoundForGivenName,Microsoft.PowerShell.Commands.GetServiceCommand",
    )
    assert gone["threw"] == "" and gone["result"] is True, gone
    assert gone["stopServiceCalls"] == 0, gone


def test_a_nonzero_nssm_exit_is_no_longer_swallowed(tmp_path: Path) -> None:
    """The exit code is TESTED. The old call discarded it (and nssm's message) into Out-Null."""
    arms = _stop_arms(tmp_path, nssm_exit=3, states=["Stopped"])
    joined = " ".join(arms["warnings"])
    assert "3" in joined and "nssm stop" in joined, (
        f"a non-zero `nssm stop` exit must be surfaced, not swallowed; warnings were {arms['warnings']}"
    )


def test_nssm_chatter_does_not_become_part_of_the_return_value(tmp_path: Path) -> None:
    """THE HELPER RETURNS ONE BOOLEAN, and nssm is not silent.

    The call is bare on purpose - a redirection is what broke the previous version - but bare also
    means nssm's STDOUT joins the function's output stream, ahead of the boolean. Both callers then
    hold an ARRAY, and `if (-not $stopped)` on a multi-element array is $false no matter how the stop
    went: install-service.ps1 reconfigures, and uninstall-service.ps1 removes the registration, both
    without the "still running" warning, and precisely when nssm had something to report.

    Measured 2026-09-18 on PowerShell 7.6.6 and Windows PowerShell 5.1.26100 against a stub printing
    one stdout line: a bare call returned 2 objects, `| Out-Host` returned 1 and left $LASTEXITCODE
    intact. The arms around this one cannot see it -- they keep the LAST non-warning object and drop
    the rest, which is exactly the extra output that breaks the real callers.
    """
    arms = _stop_arms(
        tmp_path, nssm_exit=0, states=["Running"], chatter="nssm: MessageFoundry: STOP: 0"
    )
    assert arms["outputs"] == 1, (
        "Stop-ServiceAndConfirm emitted nssm's stdout into its own output stream, so the caller "
        "gets an array instead of a boolean and `-not $stopped` is always false (got "
        f"{arms['outputs']} objects)"
    )
    assert arms["result"] is False, (
        "a service still Running must report False; a True here means the boolean was read off the "
        "wrong object"
    )


def test_a_lingering_service_is_caught_by_the_status_reread(tmp_path: Path) -> None:
    """THE ARM THE EXIT CODE CANNOT REACH. nssm exits 0 while the service stays Running.

    This is the case BACKLOG #1558 asks for by name: the next step (reconfigure, or remove) must not
    run believing the service stopped.
    """
    arms = _stop_arms(tmp_path, nssm_exit=0, states=["Running"])
    assert arms["result"] is False, (
        "a service still Running after a clean `nssm stop` must be reported as NOT stopped -- an "
        "exit-code check alone returns True here"
    )
    assert arms["getServiceCalls"] >= 2, (
        "the status must be POLLED, not read once; a single read cannot distinguish a slow drain "
        f"from a stuck service (got {arms['getServiceCalls']} reads)"
    )
    assert any("Running" in w for w in arms["warnings"]), (
        f"the warning must name the state the service is actually in; got {arms['warnings']}"
    )


def test_a_slow_drain_is_waited_out_rather_than_failed(tmp_path: Path) -> None:
    """Still Running on the first reads, Stopped later: True. A drain is not a failure."""
    arms = _stop_arms(tmp_path, nssm_exit=0, states=["Running", "Running", "Stopped"], timeout=10)
    assert arms["result"] is True, "a service that stops within the timeout must report success"
    assert arms["warnings"] == [], f"a normal drain must not warn; got {arms['warnings']}"


def test_the_scm_fallback_stop_is_confirmed_too(tmp_path: Path) -> None:
    """THE THIRD STOP SITE. uninstall-service.ps1 falls back to Stop-Service when nssm is absent,
    and that branch was as unchecked as the other two."""
    arms = _stop_arms(tmp_path, nssm_exit=None, states=["Running"])
    assert arms["stopServiceCalls"] == 1, (
        f"the no-nssm branch must still stop the service via the SCM (got {arms['stopServiceCalls']})"
    )
    assert arms["result"] is False, "the SCM fallback must confirm the stop, not assume it"
    assert arms["stopTargets"] == ["object:MessageFoundry"], (
        "the SCM stop must take the service object the exact-name lookup found, never a name "
        f"Stop-Service resolves again (BACKLOG #5402); got {arms['stopTargets']}"
    )


@pytest.mark.parametrize("nssm_exit", [3, None], ids=["nssm", "scm"])
def test_a_display_name_never_stops_the_service_it_names(
    tmp_path: Path, nssm_exit: int | None
) -> None:
    """``-ServiceName 'Windows Time'`` passes the name pattern, and Get-Service -Name answers it
    with W32Time, the service whose DISPLAY name it is (BACKLOG #5402). Nothing may be stopped:
    not through the SCM, and not through nssm, which would warn about its exit 3 if it ran.

    The positive control is the SCM-fallback arm above, which stops a service the lookup found
    under its own name.
    """
    arms = _stop_arms(
        tmp_path,
        nssm_exit=nssm_exit,
        states=["Running"],
        service="Windows Time",
        found_name="W32Time",
    )
    assert arms["stopServiceCalls"] == 0, (
        f"a display name stopped the service it names: {arms['stopTargets']}"
    )
    assert arms["warnings"] == [], (
        f"nssm was asked to stop a display name, or a warning fired: {arms['warnings']}"
    )
    assert arms["result"] is True, "no service by that exact name means nothing is left running"


def test_no_unchecked_stop_site_survives_in_either_script(tmp_path: Path) -> None:
    """CALL-SITE guard. A correct helper is worth nothing if a raw stop is still there.

    Read from the TOKEN stream with comments removed, not from the file text. The helper's own
    docstring quotes the defective line verbatim, so a text scan matches the explanation of the
    defect and reports the defect -- the sentence and its own negation are the same string.
    """
    assert _UNINSTALL is not None
    for path in (_SCRIPT, _UNINSTALL):
        assert path is not None
        body = """
  $tokens = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($src, [ref]$tokens, [ref]$null)
  # $ast above was parsed from the same file and threw on any parse error, so none is dropped here.
  (@($tokens | Where-Object { $_.Kind -ne 'Comment' } |
      ForEach-Object { $_.Text }) -join ' ')
"""
        code = _ok(_extract(path, [], body), tmp_path)
        assert "2>&1" not in code, (
            f"{path.name} still merges a native command's stderr into the success stream -- on "
            "Windows PowerShell 5.1 that turns nssm's stderr into a terminating error and loses "
            "its exit code (BACKLOG #1558)"
        )
        assert _STOP_FN in code, f"{path.name} must route its stop through {_STOP_FN}"


def test_every_stop_service_call_lives_inside_the_helper(tmp_path: Path) -> None:
    """``Stop-Service`` must not be called anywhere but inside the confirming helper, in either
    script -- that is what makes 'every stop is confirmed' true rather than merely typical."""
    assert _UNINSTALL is not None
    for path in (_SCRIPT, _UNINSTALL):
        assert path is not None
        body = f"""
  $fn = $ast.Find({{ $args[0] -is
      [System.Management.Automation.Language.FunctionDefinitionAst] -and
      $args[0].Name -eq {_psq(_STOP_FN)} }}, $true)
  $calls = @($ast.FindAll({{ $args[0] -is
      [System.Management.Automation.Language.CommandAst] }}, $true) | Where-Object {{
      $_.GetCommandName() -eq 'Stop-Service' }})
  [pscustomobject]@{{
    hasFn   = [bool]$fn
    fnStart = $(if ($fn) {{ $fn.Extent.StartOffset }} else {{ -1 }})
    fnEnd   = $(if ($fn) {{ $fn.Extent.EndOffset }} else {{ -1 }})
    calls   = @($calls | ForEach-Object {{
      [pscustomobject]@{{ start = $_.Extent.StartOffset; line = $_.Extent.StartLineNumber }} }})
  }} | ConvertTo-Json -Depth 4 -Compress
"""
        facts = json.loads(_ok(_extract(path, [], body), tmp_path).strip().splitlines()[-1])
        assert facts["hasFn"], f"{path.name} does not define {_STOP_FN}"
        stray = [c for c in facts["calls"] if not (facts["fnStart"] <= c["start"] < facts["fnEnd"])]
        assert not stray, (
            f"{path.name} calls Stop-Service outside {_STOP_FN} at line(s) "
            f"{[c['line'] for c in stray]} -- that stop is neither checked nor confirmed"
        )


def test_every_nssm_exit_code_is_read_from_a_cleared_variable(tmp_path: Path) -> None:
    """$LASTEXITCODE must be cleared before each nssm call, and a $null one treated as a failure.

    A STATIC guard, and the reason it is static is worth writing down, because the behavioural
    version of it was built first and had to be withdrawn.

    $LASTEXITCODE is session-wide and a failed LAUNCH never writes it, so an exit-code check reads
    whatever the previous native command left. Witnessing that needs a launch to fail while
    execution CARRIES ON, and whether it does is host-dependent:

      * Windows -- MEASURED 2026-09-18 on PowerShell 7.6.6 and Windows PowerShell 5.1.26100, with a
        file carrying a PATHEXT extension whose content is not a PE image: the launch raises a
        TERMINATING ApplicationFailedException. It never reaches the check, so the shape cannot be
        built here at all.
      * Linux -- OBSERVED on the ubuntu-latest CI leg of this branch: PowerShell resolved a
        non-executable file, failed to start it, wrote a NON-terminating error, and ran straight on
        to the exit-code check with $LASTEXITCODE never set. Every message rendered the code as an
        empty string.

    A FIRST ATTEMPT AT THE BEHAVIOURAL ARM MEASURED SOMETHING ELSE ENTIRELY. Its unrunnable file was
    a ``.txt``; PowerShell handed a non-PATHEXT extension to the shell, which consulted the file
    association and SUCCESSFULLY opened the registered editor. "Threw nothing, left $LASTEXITCODE
    alone" was a successful ShellExecute wearing the costume of a failed launch -- and it would have
    made the arm pass on a host where the guard does nothing. Hence: never give a stub or a dud an
    extension that a desktop can open.

    So the property is asserted where it is host-independent -- in the source. The drift test below
    pins the two copies of the stop helper together, so checking the install copy covers both.
    """
    assert _SCRIPT is not None
    # READ THE AST, NOT THE TEXT. Both helpers QUOTE the defective call in their own docstrings, so a
    # string scan finds the explanation of the defect and reports the defect -- the same trap
    # test_no_unchecked_stop_site_survives_in_either_script sidesteps by dropping comment tokens.
    body = """
  $fns = @($ast.FindAll({ $args[0] -is
      [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | Where-Object {
      $_.Name -in @('Invoke-Nssm', 'Stop-ServiceAndConfirm') })
  @($fns | ForEach-Object {
    $fn = $_
    $calls = @($fn.FindAll({ $args[0] -is
        [System.Management.Automation.Language.CommandAst] }, $true) | Where-Object {
        $_.CommandElements.Count -gt 0 -and $_.CommandElements[0].Extent.Text -eq '$NssmPath' })
    $clears = @($fn.FindAll({ $args[0] -is
        [System.Management.Automation.Language.AssignmentStatementAst] }, $true) | Where-Object {
        $_.Left.Extent.Text -eq '$global:LASTEXITCODE' -and $_.Right.Extent.Text -eq '$null' })
    $nulls = @($fn.FindAll({ $args[0] -is
        [System.Management.Automation.Language.BinaryExpressionAst] }, $true) | Where-Object {
        $_.Left.Extent.Text -eq '$null' -and "$($_.Operator)" -eq 'Ieq' })
    [pscustomobject]@{
      name      = $fn.Name
      callAt    = $(if ($calls.Count) { ($calls | ForEach-Object { $_.Extent.StartOffset } |
                    Measure-Object -Minimum).Minimum } else { -1 })
      clearsAt  = $(if ($clears.Count) { ($clears | ForEach-Object { $_.Extent.StartOffset } |
                    Measure-Object -Minimum).Minimum } else { -1 })
      testsNull = [bool]$nulls.Count
    }
  }) | ConvertTo-Json -Depth 4 -Compress
"""
    raw = _ok(_extract(_SCRIPT, [], body), tmp_path)
    fns = json.loads(raw.strip().splitlines()[-1])
    if isinstance(fns, dict):
        fns = [fns]
    seen = {f["name"] for f in fns}
    assert seen == {"Invoke-Nssm", "Stop-ServiceAndConfirm"}, (
        f"CONTROL FAILED: the search did not find both nssm callers, so a clean result here would "
        f"mean nothing; found {sorted(seen)}"
    )
    for f in fns:
        assert f["callAt"] >= 0, f"{f['name']} no longer invokes & $NssmPath -- re-aim this guard"
        assert f["clearsAt"] >= 0, (
            f"{f['name']} reads $LASTEXITCODE without clearing it first, so a failed launch is read "
            "as the PREVIOUS command's exit code (BACKLOG #1558)"
        )
        assert f["clearsAt"] < f["callAt"], (
            f"{f['name']} clears $LASTEXITCODE AFTER invoking nssm, which discards the code it was "
            "about to check"
        )
        assert f["testsNull"], (
            f"{f['name']} does not test for a $null exit code, so an absent one renders as a blank "
            "-- 'failed (exit )' is what the ubuntu leg printed"
        )


def test_the_two_copies_of_the_helper_have_not_drifted(tmp_path: Path) -> None:
    """The scripts are standalone (an operator runs either one directly), so the helper is
    duplicated rather than imported. Duplication is only safe while the copies agree."""
    assert _UNINSTALL is not None
    body = f"""
  $fn = $ast.Find({{ $args[0] -is
      [System.Management.Automation.Language.FunctionDefinitionAst] -and
      $args[0].Name -eq {_psq(_STOP_FN)} }}, $true)
  if (-not $fn) {{ throw "not defined" }}
  $fn.Extent.Text
"""
    texts = []
    for path in (_SCRIPT, _UNINSTALL):
        assert path is not None
        texts.append(_ok(_extract(path, [], body), tmp_path).replace("\r\n", "\n").strip())
    assert texts[0] == texts[1], (
        f"the two copies of {_STOP_FN} have drifted; the behavioural arms above only ever run the "
        "install-service.ps1 copy, so a divergent uninstall copy would be untested"
    )


# --- the smoke leg's last stop is judged by the SCM, not by nssm's exit code (BACKLOG #2747) ------
# "Stop the service (graceful)" in windows-service-smoke was `nssm stop` alone, so nssm's exit code
# was the step's result. The comment at that step in ci.yml says what that cost; it is not restated
# here. The step's run script is read out of ci.yml and RUN, the way a hosted runner runs it, with
# three stand-ins: a stub for the checked nssm.exe, a Get-Service that reports a scripted sequence
# of states, and a Start-Sleep that prints instead of sleeping.
#
# WHAT THIS DOES NOT TEST: a real service, a real Service Control Manager, or the real nssm.exe.
# No test here stops a service. Only the windows-service-smoke leg does, and a pull_request event
# skips that job, so its result has to be read after a merge-queue, nightly or dispatched run.

_SMOKE_STOP_STEP = "Stop the service (graceful)"
_SMOKE_NSSM = '"$env:SMOKE_NSSM_DIR\\nssm.exe"'
_SMOKE_STOP_CALL = f"& {_SMOKE_NSSM} stop MessageFoundry"
# What nssm 2.24 printed, with exit 1, in the job the ci.yml comment names.
_NSSM_UNEXPECTED = "MessageFoundry: Unexpected status SERVICE_RUNNING in response to STOP control."
_NOTHING_TO_STOP = "no MessageFoundry service is registered, so there is nothing to stop"
# The unit closes the token: without it "500" would also count a sleep of 5000.
_SLEPT = "STAND-IN SLEEP 500 ms"


@functools.cache
def _smoke_step(name_starts: str) -> str:
    """A windows-service-smoke step's run script, without its comment lines. Cached: every arm
    reads the same script, and each read parses the whole of ci.yml.

    Imported here: without PyYAML that module skips whoever imports it.
    """
    from tests._workflow_contexts import step_script

    return step_script("ci.yml", "windows-service-smoke", name_starts)[1]


def _smoke_stop_script() -> str:
    return _smoke_step(_SMOKE_STOP_STEP)


def _run_smoke_stop(
    tmp_path: Path, *, nssm_exit: int, states: list[str] | None
) -> subprocess.CompletedProcess[str]:
    """Run the step's script as the runner does, and return the process: its exit code is the
    step's result.

    ``states`` is what the stand-in Get-Service reports for MessageFoundry on successive reads (the
    last value repeats). An empty list means no such service. None is a read that can see no
    service at all: no MessageFoundry and no EventLog either.

    NOTHING HERE MAY REACH A REAL SERVICE, and a developer's machine can have a real MessageFoundry
    service. The script's one nssm call is pointed at the stub, Get-Service is a stand-in, and the
    other commands that change a service are stand-ins that throw. So an edit that adds one of
    those to the step fails here and does not run it.

    THE WRAPPER IS THE RUNNER'S. GitHub runs a pwsh step as ``pwsh -command ". '{0}'"``, puts
    ``$ErrorActionPreference = 'stop'`` first, and ends the script by exiting with $LASTEXITCODE
    when one is set. That last line is why a stop command's non-zero code fails a step that ran to
    its end. ``$PSNativeCommandUseErrorActionPreference`` is set to $true ahead of the script, the
    setting under which a non-zero native exit is an error at once, so the step is shown not to
    depend on the runner's default for it.
    """
    if shutil.which("pwsh") is None:
        pytest.skip("SKIP (nothing run): pwsh not on PATH")
    script = _smoke_stop_script()
    # The stub takes any arguments, so what is sent, and to which service, is read from the text:
    # one whole line, so a longer service name or an extra argument does not match. How many
    # times it is sent is counted from the stub's own message, in the arms below.
    calls = [line.strip() for line in script.splitlines() if _SMOKE_NSSM in line]
    assert calls == [_SMOKE_STOP_CALL] and script.count(_SMOKE_NSSM) == 1, (
        f"expected the step to name the checked nssm.exe once, as {_SMOKE_STOP_CALL!r}: {calls}"
    )
    stub = _nssm_stub(
        tmp_path / f"nssm-smoke-stop-{uuid.uuid4().hex}",
        message=_NSSM_UNEXPECTED,
        exit_code=nssm_exit,
    )
    states_ps = "@(" + ", ".join(_psq(s) for s in states or []) + ")"
    stand_ins = f"""$ErrorActionPreference = 'stop'
$PSNativeCommandUseErrorActionPreference = $true
$global:States = {states_ps}
$global:Reads = 0
foreach ($changes in 'Stop-Service', 'Start-Service', 'Restart-Service', 'Set-Service', 'sc.exe') {{
  Set-Item -Path "function:global:$changes" -Value {{
    throw "the step ran $($MyInvocation.MyCommand.Name), which this harness does not stand in for"
  }}
}}
function Get-Service {{
  param([string]$Name, $ErrorAction)
  $status = $null
  if ($Name -eq 'EventLog') {{
    if ({"$false" if states is None else "$true"}) {{ $status = 'Running' }}
  }} elseif ($Name -ne 'MessageFoundry') {{
    throw "the stand-in was asked for an unexpected service: $Name"
  }} elseif ($global:States.Count -gt 0) {{
    $status = $global:States[[Math]::Min($global:Reads, $global:States.Count - 1)]
    $global:Reads++
  }}
  if ($null -ne $status) {{ return [pscustomobject]@{{ Status = $status }} }}
  # The real cmdlet fails on a service it cannot find unless it is told not to, and under the
  # runner's 'stop' preference that failure ends the step. The message is the real one.
  if ("$ErrorAction" -ne 'SilentlyContinue') {{
    throw "Cannot find any service with service name '$Name'."
  }}
}}
function Start-Sleep {{ param($Milliseconds) "STAND-IN SLEEP $Milliseconds ms" }}
"""
    f = tmp_path / f"smoke-stop-{uuid.uuid4().hex}.ps1"
    f.write_text(
        stand_ins
        + script.replace(_SMOKE_NSSM, _psq(str(stub)))
        + "\nif ((Test-Path -LiteralPath variable:\\LASTEXITCODE)) { exit $LASTEXITCODE }\n",
        encoding="utf-8",
    )
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", f". {_psq(str(f))}"],
        capture_output=True,
        text=True,
        timeout=180,
    )


def test_the_smoke_stop_passes_when_the_scm_confirms_a_stop_nssm_called_failed(
    tmp_path: Path,
) -> None:
    """THE CASE THAT FAILED THE MERGE GROUP. nssm prints its message and exits 1, and the service
    then stops. The step passes, and it says what nssm's code was.

    The stub's message on stderr is the control: it shows the stub ran and exited through the
    path the step reads, so the pass is not a pass over a command that never launched.

    Every scripted state but the two StopPending reads is different, so each printed reading can
    only have come from its own read.
    """
    r = _run_smoke_stop(
        tmp_path,
        nssm_exit=1,
        states=["StartPending", "Running", "StopPending", "StopPending", "Stopped"],
    )
    said = r.stdout + r.stderr
    assert said.count(_NSSM_UNEXPECTED) == 1, (
        f"the stop was sent {said.count(_NSSM_UNEXPECTED)} times, not once. Zero is CONTROL "
        f"FAILED, the nssm stub did not run:\n{said[:2000]}"
    )
    assert r.returncode == 0, (
        "the step failed on a stop the Service Control Manager confirmed, so nssm's exit code "
        f"still decides it (exit {r.returncode}):\n{said[:2000]}"
    )
    # The first two states answer "is it registered" and "what did it read as nssm returned".
    # The wait then read StopPending twice, slept twice, and ended on Stopped.
    printed = [line for line in r.stdout.splitlines() if line.startswith("the service read ")]
    assert printed == [
        "the service read StartPending before the stop; the stop command exited 1; "
        "the service read Running as it returned",
        "the service read Stopped after the wait",
    ], (
        "the step no longer prints the state before the stop, nssm's exit code and the state as "
        f"it returned, each from its own read, BEFORE the wait:\n{said[:2000]}"
    )
    assert r.stdout.index(printed[0]) < r.stdout.index(_SLEPT) < r.stdout.index(printed[1])
    assert r.stdout.count(_SLEPT) == 2, f"the wait did not end when the service stopped:\n{said}"


def test_the_smoke_stop_still_fails_on_a_service_that_never_stops(tmp_path: Path) -> None:
    """THE REAL FAILURE STAYS RED, and nssm's exit code cannot make it green. nssm exits 0 and the
    service stays Running: the step fails, names the state, and gave up after its bound.

    A service that hangs in its drain reads StopPending for the whole wait, and that is not
    Stopped either. Both states run under both exit codes, so neither code decides the step:
    exit 1 over a service still Running is the incident's own output with a stop that was lost.
    StartPending and Paused are there so that only Stopped counts as stopped.

    The state is read from the line the step prints. The failure's own text says the same, but
    pwsh wraps an error at the width of the console it inherits, and a phrase can be split there.
    """
    arms = [(code, state) for state in ("Running", "StopPending") for code in (0, 1)]
    for nssm_exit, stuck in [*arms, (0, "StartPending"), (0, "Paused")]:
        r = _run_smoke_stop(tmp_path, nssm_exit=nssm_exit, states=["Running", "Running", stuck])
        said = r.stdout + r.stderr
        assert said.count(_NSSM_UNEXPECTED) == 1, (
            f"the stop was sent {said.count(_NSSM_UNEXPECTED)} times, not once. Zero is CONTROL "
            f"FAILED, the nssm stub did not run:\n{said[:2000]}"
        )
        assert r.returncode != 0, (
            f"a service still {stuck} passed the step under an nssm that exited {nssm_exit}:\n"
            f"{said[:2000]}"
        )
        assert f"the service read {stuck} after the wait" in r.stdout.splitlines(), said[:2000]
        # 60 waits of 500 ms: the bound the failure message states, and a bound at all.
        assert r.stdout.count(_SLEPT) == 60, (
            f"the wait is not 60 reads of 500 ms ({r.stdout.count(_SLEPT)} sleeps), so 'within 30 "
            "seconds' in the failure is no longer what the step did"
        )


def test_the_smoke_stop_says_so_and_passes_when_no_service_is_registered(tmp_path: Path) -> None:
    """The step is ``if: always()``, so it also runs after an install that registered nothing. It
    says there is nothing to stop and passes: the red is the earlier step's. nssm is not run, so
    its error about a missing service is not printed as a second fault.

    The arms above are the control for "nssm is not run": there the same stub's message is in the
    output.
    """
    r = _run_smoke_stop(tmp_path, nssm_exit=1, states=[])
    said = r.stdout + r.stderr
    assert r.returncode == 0, f"a missing service failed the stop step:\n{said[:2000]}"
    assert _NOTHING_TO_STOP in r.stdout, said[:2000]
    assert _NSSM_UNEXPECTED not in said, (
        f"nssm was run against a service that is not there:\n{said}"
    )


def test_the_smoke_stop_does_not_read_a_blind_scm_as_nothing_to_stop(tmp_path: Path) -> None:
    """A read that can see no service at all must not pass as "not installed" over an engine that
    is still running. The stand-in reports no EventLog service and no MessageFoundry service, which
    is what such a read returns. The step fails on its control and does not say nothing to stop."""
    r = _run_smoke_stop(tmp_path, nssm_exit=0, states=None)
    said = r.stdout + r.stderr
    assert r.returncode != 0 and "CONTROL FAILED" in said, said[:2000]
    assert _NOTHING_TO_STOP not in said, said[:2000]


def test_the_smoke_stop_runs_after_a_failed_step_and_before_the_uninstall() -> None:
    """The step keeps ``if: always()`` and its place: after the token step, whose probe it stops,
    and before the uninstall, which removes the service it asks about."""
    from tests._workflow_contexts import jobs_of

    steps = jobs_of("ci.yml")["windows-service-smoke"]["steps"]

    def at(name_starts: str) -> int:
        found = [i for i, s in enumerate(steps) if str(s.get("name", "")).startswith(name_starts)]
        assert len(found) == 1, f"expected one step named {name_starts!r}, found {len(found)}"
        return found[0]

    stop = at(_SMOKE_STOP_STEP)
    assert steps[stop].get("if") == "always()", steps[stop].get("if")
    assert at("Verify the service token is restricted") < stop < at("Uninstall the service")


# --- every path baked into the registration is absolute, and made so IN TIME (BACKLOG #1554) ------
# A service resolves a relative path against its own working directory. Only -Config was normalized,
# and it was normalized after Resolve-Nssm had already joined a possibly-relative -DataDir and after
# Test-Path had validated a relative -DbPath against the operator's shell location rather than the
# AppDirectory the service would use.
#
# ORDER IS THE DEFECT, so the guards below are about WHERE the normalization happens, not merely that
# it happens. Three assertions of shape and one of behaviour.

_PATH_PARAMS = [
    "DataDir",
    "AppExe",
    "PythonExe",
    "Config",
    "ServiceConfig",
    "ProjectRoot",
    "DbPath",
    "SecretsDir",
    # -EngineWheel's inputs (vault BACKLOG #2626), read before the build acts.
    "EngineWheel",
    "RequirementsLock",
    "BasePython",
]


_FACTS_BODY = """
  $assigns = @(foreach ($a in $ast.FindAll({ $args[0] -is
      [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
    $lhs = $null
    if ($a.Left -is [System.Management.Automation.Language.VariableExpressionAst]) {
      $lhs = $a.Left.VariablePath.UserPath
    }
    $cmd = $null
    $firstCmd = $a.Right.Find({ $args[0] -is
        [System.Management.Automation.Language.CommandAst] }, $true)
    if ($firstCmd) { $cmd = $firstCmd.GetCommandName() }
    [pscustomobject]@{
      lhs     = $lhs
      start   = $a.Extent.StartOffset
      line    = $a.Extent.StartLineNumber
      rhsCmd  = $cmd
      rhsText = $a.Right.Extent.Text
    }
  })
  $cmds = @(foreach ($c in $ast.FindAll({ $args[0] -is
      [System.Management.Automation.Language.CommandAst] }, $true)) {
    # One walk up: whether the call is in a function, and where the outermost if statement around
    # it ends, or the call itself when no if statement is around it.
    $inFunction = $false
    $outerIfEnd = $c.Extent.EndOffset
    for ($q = $c.Parent; $q; $q = $q.Parent) {
      if ($q -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $inFunction = $true }
      if ($q -is [System.Management.Automation.Language.IfStatementAst]) { $outerIfEnd = $q.Extent.EndOffset }
    }
    [pscustomobject]@{
      name       = $c.GetCommandName()
      start      = $c.Extent.StartOffset
      line       = $c.Extent.StartLineNumber
      text       = $c.Extent.Text
      inFunction = $inFunction
      outerIfEnd = $outerIfEnd
    }
  })
  [pscustomobject]@{ assignments = @($assigns); commands = @($cmds) } |
      ConvertTo-Json -Depth 6 -Compress
"""
_FACTS_MARK = "@@FACTS "


def _preflight_facts_many(tmp_path: Path, scripts: list[Path]) -> list[dict]:
    """``_preflight_facts`` for each of ``scripts``, in ONE PowerShell process.

    Each process costs seconds to start, and a guard's control arms read one changed copy each. A
    copy whose read throws, one that does not parse for instance, yields ``{"error": ...}`` in its
    place rather than failing the copies beside it.
    """
    blocks = [
        "try {\n"
        f"  $out = {_extract(path, [], _FACTS_BODY)}\n"
        f'  "{_FACTS_MARK}" + @($out)[-1]\n'
        "} catch {\n"
        f'  "{_FACTS_MARK}" + ([pscustomobject]@{{ error = "$_" }} | ConvertTo-Json -Compress)\n'
        "}"
        for path in scripts
    ]
    out = _ok("\n".join(blocks), tmp_path).splitlines()
    facts = [json.loads(line[len(_FACTS_MARK) :]) for line in out if line.startswith(_FACTS_MARK)]
    assert len(facts) == len(scripts), f"expected {len(scripts)} fact sets, read {len(facts)}"
    return facts


def _preflight_facts(tmp_path: Path, script: Path | None = None) -> dict:
    """Assignments and command calls of install-service.ps1, with source offsets, by AST.

    ``script`` reads another file the same way: the uninstaller, or a changed copy of the installer
    that a guard must fail on.
    """
    path = script if script is not None else _SCRIPT
    assert path is not None
    [facts] = _preflight_facts_many(tmp_path, [path])
    assert "error" not in facts, f"harness failed: {facts['error']}"
    return facts


def _sole_call(facts: dict, name: str) -> dict:
    hits = [c for c in facts["commands"] if c["name"] == name]
    assert len(hits) == 1, f"expected exactly one {name} call, found {len(hits)}"
    return hits[0]


def test_every_path_parameter_is_absolute_before_anything_consumes_it(tmp_path: Path) -> None:
    """Each of -DataDir, -AppExe, -Config, -DbPath is finalised BEFORE the Resolve-Nssm call.

    Resolve-Nssm is the first consumer of a normalized path (-NssmDir); every later consumer
    (Test-Path, the ACL grants, AppParameters) inherits whatever these hold. A normalization that
    runs after any of them is the #1554 defect in a new position.
    """
    facts = _preflight_facts(tmp_path)
    # Two call sites, one per path: an install that builds its root (vault BACKLOG #2626)
    # resolves NSSM before the build, any other after the install check. The first is the bound.
    calls = [c for c in facts["commands"] if c["name"] == "Resolve-Nssm"]
    assert len(calls) == 2, f"expected two Resolve-Nssm calls, found {len(calls)}"
    first = min(calls, key=lambda c: c["start"])
    nssm_at = first["start"]
    for var in _PATH_PARAMS:
        writes = [a for a in facts["assignments"] if a["lhs"] == var]
        assert writes, f"nothing assigns ${var} in the preflight"
        late = [a for a in writes if a["start"] > nssm_at]
        assert not late, (
            f"${var} is still being written at line(s) {[a['line'] for a in late]}, AFTER "
            f"Resolve-Nssm (line {first['line']}) has already consumed "
            "the preflight values -- BACKLOG #1554 is about exactly this ordering"
        )


def test_the_repo_root_is_computed_before_the_defaults_that_need_it(tmp_path: Path) -> None:
    """Each default is built from a root that has to exist first: $AppExe and $AppDirectory from
    $DefaultInstallRoot, and $AppDirectory from $RepoRoot for a checkout (vault BACKLOG #2626).

    This is the second half of the reorder: moving the normalization up is wrong if it lands above
    the value a default is built from.
    """
    facts = _preflight_facts(tmp_path)
    for root_var, dependents in (
        ("RepoRoot", ("AppDirectory",)),
        ("DefaultInstallRoot", ("AppExe", "AppDirectory")),
    ):
        root = [a for a in facts["assignments"] if a["lhs"] == root_var]
        assert len(root) == 1, f"expected one ${root_var} assignment, found {len(root)}"
        for var in dependents:
            first = min(a["start"] for a in facts["assignments"] if a["lhs"] == var)
            assert root[0]["start"] < first, (
                f"${root_var} (line {root[0]['line']}) is computed after the first write to "
                f"${var}, whose default is built from it"
            )


def test_no_path_parameter_is_normalized_with_resolve_path(tmp_path: Path) -> None:
    """Resolve-Path THROWS on a path that does not exist, and a first install has no database file.

    This is the trap the obvious fix falls into: Resolve-Path looks like the normalizer and turns a
    fresh install into a hard failure on -DbPath.
    """
    facts = _preflight_facts(tmp_path)
    for var in _PATH_PARAMS:
        bad = [
            a
            for a in facts["assignments"]
            if a["lhs"] == var and "Resolve-Path" in (a["rhsText"] or "")
        ]
        assert not bad, (
            f"${var} is normalized with Resolve-Path at line(s) {[a['line'] for a in bad]}; it "
            "throws when the path does not exist yet -- use "
            "GetUnresolvedProviderPathFromPSPath instead"
        )


def test_resolve_absolutepath_anchors_to_the_invocation_directory(tmp_path: Path) -> None:
    """BEHAVIOUR. A relative path resolves against where the OPERATOR stood, not the script's home,
    and a path that does not exist is normalized rather than refused."""
    assert _SCRIPT is not None
    anchor = tmp_path / "anchor"
    (anchor / "sub").mkdir(parents=True)
    body = rf"""
  Set-Location {_psq(str(anchor))}
  [pscustomobject]@{{
    relative   = (Resolve-AbsolutePath 'sub\mefor.db')
    missing    = (Resolve-AbsolutePath 'no-such-dir\not-created-yet.db')
    absolute   = (Resolve-AbsolutePath {_psq(str(anchor / "sub"))})
    dotdot     = (Resolve-AbsolutePath 'sub\..\other.db')
  }} | ConvertTo-Json -Depth 3 -Compress
"""
    got = json.loads(
        _ok(_extract(_SCRIPT, ["Resolve-AbsolutePath"], body), tmp_path).strip().splitlines()[-1]
    )
    assert got["relative"] == str(anchor / "sub" / "mefor.db"), (
        "a relative path must resolve against the directory the installer was RUN from; anchoring "
        f"it to $PSScriptRoot or $RepoRoot silently relocates it (got {got['relative']!r})"
    )
    assert got["missing"] == str(anchor / "no-such-dir" / "not-created-yet.db"), (
        "a path that does not exist yet must still normalize -- a first install has no database "
        f"file (got {got['missing']!r})"
    )
    assert got["absolute"] == str(anchor / "sub"), "an absolute path must come back unchanged"
    assert got["dotdot"] == str(anchor / "other.db"), "'..' segments must be collapsed"


def test_the_troubleshooting_step_no_longer_promises_what_the_script_cannot_do() -> None:
    """docs/SERVICE.md told an operator whose service will not start to re-run the installer
    "which resolves all paths to absolute". It did not; only -Config was normalized. A repair step
    resting on a false premise is what CLAUDE.md section 11 (SDS-3.7) forbids.

    The sentence WRAPPED, so the phrase is matched with whitespace collapsed -- a one-line grep for
    it returns zero and reads as already fixed.
    """
    root = Path(__file__).resolve().parents[1]
    doc = (root / "docs" / "SERVICE.md").read_text(encoding="utf-8")
    flat = " ".join(doc.split())
    assert "resolves all paths to absolute" not in flat, (
        "docs/SERVICE.md still tells an operator that re-running the install script resolves ALL "
        "paths to absolute"
    )
    assert "re-run the install script" not in flat.lower() or "anchored to the directory" in flat, (
        "the troubleshooting step must say what the installer actually anchors relative paths to"
    )


# --- the H-13 log-directory ACL is READ BACK, not assumed (BACKLOG #1699) --------------------------
# Nothing witnessed Set-SecureDataDirAcl. Re-measured repo-wide on origin/main before writing these:
# `git grep -n 'Set-SecureDataDirAcl'` returns six hits and NOT ONE is a test -- the definition and
# call site in install-service.ps1, a comment in .github/workflows/ci.yml, and two docs. The
# instrument returned six, so the zero-tests result is a real zero and not a broken search.
#
# NOT BUILT ON ``owner_only_from_icacls`` (messagefoundry/auth/trust_anchors.py), which looks exactly
# right and is not. It flags only WRITE-shaped access -- its own test asserts that BUILTIN\Users:(RX)
# returns True -- and Users:(RX) on the log directory is the precise ACE this row exists to catch. A
# witness built on it passes with the defect fully live.
#
# BOTH SPELLINGS ARE CHECKED. On an English host icacls prints ``BUILTIN\Users``, not
# ``S-1-5-32-545``, so a SID-only search returns a false clean.

_BROAD = {
    "S-1-1-0": "Everyone",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-32-546": "Guests",
}

_ACL_FNS = ["Set-SecureDataDirAcl", "Get-WellKnownBroadSids", "Get-BroadAclResidue"]

_windows_only = pytest.mark.skipif(
    not sys.platform.startswith("win"), reason="icacls / Windows DACLs"
)


def _lockdown(
    tmp_path: Path, *, broad_ace: str | None, inherited: bool, rights: str = "RX"
) -> dict:
    """Apply Set-SecureDataDirAcl to a real directory and read the resulting DACL back.

    ``broad_ace`` is a well-known SID granted before the lockdown. ``inherited`` puts it on the
    PARENT (the ProgramData shape, which /inheritance:r removes) instead of on the data dir itself
    (the shape that survived, which is why this is measured both ways).

    The control read is taken BEFORE the lockdown: an "absent afterwards" assertion means nothing
    unless the search can be shown to find the thing when it IS there.
    """
    assert _SCRIPT is not None
    parent = tmp_path / f"dd-{uuid.uuid4().hex[:8]}"
    data = parent / "MessageFoundry"
    (data / "logs").mkdir(parents=True)
    grant_target = str(parent) if inherited else str(data)
    pre = (
        f"  & icacls {_psq(grant_target)} /grant '{broad_ace}:(OI)(CI){rights}' | Out-Null\n"
        if broad_ace
        else ""
    )
    # THE RESTORE IS IN A `finally`, and that is not tidiness. Set-SecureDataDirAcl strips
    # inheritance and replaces the DACL partway through; _extract sets $ErrorActionPreference =
    # 'Stop', so any throw from icacls, Get-Acl or the function itself would abandon the tree
    # locked. pytest's tmp_path reaper then hits a directory it cannot delete, and the PermissionError
    # surfaces on some LATER run with nothing tying it back to here.
    body = rf"""
  $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  $data = {_psq(str(data))}
  try {{
{pre}
  $before = (& icacls $data | Out-String)
  $beforeSids = @((Get-Acl $data).Access | ForEach-Object {{
    try {{ $_.IdentityReference.Translate(
      [Security.Principal.SecurityIdentifier]).Value }} catch {{ "$($_.IdentityReference)" }} }})
  $warnings = @()
  $emitted = & {{ Set-SecureDataDirAcl -Path $data -Account $me }} 3>&1
  foreach ($o in @($emitted)) {{
    if ($o -is [System.Management.Automation.WarningRecord]) {{ $warnings += "$o" }}
  }}
  $after = (& icacls $data | Out-String)
  $afterLogs = (& icacls (Join-Path $data 'logs') | Out-String)
  $sids = @((Get-Acl $data).Access | ForEach-Object {{
    try {{ $_.IdentityReference.Translate(
      [Security.Principal.SecurityIdentifier]).Value }} catch {{ "$($_.IdentityReference)" }} }})
  $logSids = @((Get-Acl (Join-Path $data 'logs')).Access | ForEach-Object {{
    try {{ $_.IdentityReference.Translate(
      [Security.Principal.SecurityIdentifier]).Value }} catch {{ "$($_.IdentityReference)" }} }})
  [pscustomobject]@{{
    before = $before; after = $after; afterLogs = $afterLogs
    beforeSids = @($beforeSids); sids = @($sids); logSids = @($logSids)
    warnings = @($warnings); account = $me
  }} | ConvertTo-Json -Depth 4 -Compress
  }} finally {{
    # Put the tree back in reach so pytest can clean it up, however the block above ended.
    & icacls {_psq(str(parent))} /inheritance:e /grant "${{me}}:(OI)(CI)F" | Out-Null
    & icacls $data /inheritance:e /grant "${{me}}:(OI)(CI)F" | Out-Null
  }}
"""
    out: dict = json.loads(
        _ok(_extract(_SCRIPT, _ACL_FNS, body), tmp_path).strip().splitlines()[-1]
    )
    out["warnings"] = [w for w in (out.get("warnings") or []) if w]
    return out


@_windows_only
@pytest.mark.parametrize("sid", sorted(_BROAD))
def test_a_broad_inherited_ace_is_stripped_from_the_data_dir_and_its_logs(
    tmp_path: Path, sid: str
) -> None:
    """THE PROGRAMDATA SHAPE. ProgramData grants BUILTIN\\Users (RX) and the data dir inherits it;
    the engine's stdout/stderr logs live beneath, so that ACE makes a PHI sink world-readable."""
    got = _lockdown(tmp_path, broad_ace=f"*{sid}", inherited=True)
    name = _BROAD[sid]
    assert sid in got["beforeSids"], (
        f"CONTROL FAILED: {name} ({sid}) was not on the directory BEFORE the lockdown ran, so its "
        f"absence afterwards proves nothing about the lockdown:\n{got['before']}"
    )
    assert sid not in got["sids"], (
        f"{name} ({sid}) still holds access to the data dir after Set-SecureDataDirAcl "
        f"(BACKLOG #1699):\n{got['after']}"
    )
    assert sid not in got["logSids"], (
        f"{name} ({sid}) still reaches the LOG directory, which is the PHI sink review finding "
        f"H-13 is about:\n{got['afterLogs']}"
    )
    assert name.lower() not in got["after"].lower(), (
        f"the NAME spelling of {name} survives in the icacls output; on an English host icacls "
        "prints the name, not the SID, so a SID-only check would read this as clean"
    )


@_windows_only
@pytest.mark.parametrize("sid", sorted(_BROAD))
def test_a_broad_explicit_ace_is_stripped_too(tmp_path: Path, sid: str) -> None:
    """THE SHAPE THAT SURVIVED. ``/inheritance:r`` removes INHERITED ACEs and ``/grant:r`` replaces
    only the principals it NAMES, so an EXPLICIT broad ACE came through the old lockdown untouched,
    propagated to the logs beneath it, and icacls exited 0.

    Reached whenever the data dir is not a fresh ProgramData child: an operator pointing -DataDir at
    an existing directory or share, a dir created by another tool, or a reinstall after somebody
    granted access by hand.
    """
    got = _lockdown(tmp_path, broad_ace=f"*{sid}", inherited=False)
    name = _BROAD[sid]
    assert sid in got["beforeSids"], (
        f"CONTROL FAILED: the explicit {name} ({sid}) ACE was not on the directory before the "
        f"lockdown ran:\n{got['before']}"
    )
    assert sid not in got["sids"], (
        f"an EXPLICIT {name} ({sid}) ACE survived Set-SecureDataDirAcl:\n{got['after']}"
    )
    assert sid not in got["logSids"], (
        f"an EXPLICIT {name} ({sid}) ACE reached the log directory:\n{got['afterLogs']}"
    )


@_windows_only
def test_an_explicit_owner_rights_ace_is_stripped_too(tmp_path: Path) -> None:
    """OWNER RIGHTS (S-1-3-4), which removing CREATOR OWNER (S-1-3-0) does NOT cover.

    CREATOR OWNER materializes into an ACE for the creating principal at creation time. OWNER RIGHTS
    stays S-1-3-4 in the DACL and is evaluated against whoever owns the object at ACCESS time -- and
    the owner moves: any Administrator can take ownership, and the service account owns every log
    file it writes. So it is a standing grant to a moving target over a PHI sink.

    THIS IS THE ACE THAT FAILED CI RATHER THAN A HYPOTHETICAL. Measured 2026-09-18 on windows-2022
    and windows-2025: an explicit OWNER RIGHTS ACE survived ``/inheritance:r /grant:r`` with icacls
    exiting 0, reached the logs directory beneath, and the read-back named it -- which is how the
    residue warning, not this assertion, was the thing that went red.

    (OI)(CI)F rather than the RX the arms above plant, and deliberately: an OWNER RIGHTS ACE REPLACES
    the owner's implicit READ_CONTROL + WRITE_DAC with exactly what it grants, so an RX one takes
    away the right to rewrite the DACL and the lockdown's own second icacls call then fails with
    "Access is denied" (exit 5) on any host where the Administrators ACE is not in the running token.
    F is strictly broader than RX, so it tests removal at least as hard without making the arm depend
    on whether the test process happens to be elevated.
    """
    got = _lockdown(tmp_path, broad_ace="*S-1-3-4", inherited=False, rights="F")
    assert "S-1-3-4" in got["beforeSids"], (
        "CONTROL FAILED: the explicit OWNER RIGHTS (S-1-3-4) ACE was not on the directory before "
        f"the lockdown ran:\n{got['before']}"
    )
    assert "S-1-3-4" not in got["sids"], (
        f"an EXPLICIT OWNER RIGHTS (S-1-3-4) ACE survived Set-SecureDataDirAcl:\n{got['after']}"
    )
    assert "S-1-3-4" not in got["logSids"], (
        f"OWNER RIGHTS reached the LOG directory, which is the PHI sink:\n{got['afterLogs']}"
    )
    assert "owner rights" not in got["after"].lower(), (
        f"the NAME spelling of OWNER RIGHTS survives in the icacls output:\n{got['after']}"
    )
    assert got["warnings"] == [], (
        f"OWNER RIGHTS must be REMOVED, not merely reported as residue; got {got['warnings']}"
    )


@_windows_only
def test_the_lockdown_keeps_what_the_service_actually_needs(tmp_path: Path) -> None:
    """POSITIVE CONTROL. A lockdown that removed everything would pass every assertion above and
    leave a service that cannot start: SYSTEM, Administrators and the run-as account must remain."""
    got = _lockdown(tmp_path, broad_ace=None, inherited=False)
    assert "S-1-5-18" in got["sids"], f"SYSTEM lost access to the data dir:\n{got['after']}"
    assert "S-1-5-32-544" in got["sids"], (
        f"Administrators lost access to the data dir:\n{got['after']}"
    )
    assert got["account"].split("\\")[-1].lower() in got["after"].lower(), (
        f"the run-as account lost read/write on its own data dir:\n{got['after']}"
    )
    assert "S-1-5-18" in got["logSids"] and "S-1-5-32-544" in got["logSids"], (
        f"the grants did not inherit down to the log directory:\n{got['afterLogs']}"
    )
    assert got["warnings"] == [], f"a clean lockdown must report no residue; got {got['warnings']}"


@_windows_only
def test_residue_outside_the_well_known_set_is_reported_not_hidden(tmp_path: Path) -> None:
    """The named removals cover the well-known broad principals. Anything else -- a local group, a
    stale SID -- is READ BACK and named, so the caller is never told a lockdown happened that did
    not. Uses a well-known SID outside the removal list to stand in for that case."""
    # S-1-5-32-547 = BUILTIN\Power Users: a real, resolvable group that is NOT in the removal set.
    got = _lockdown(tmp_path, broad_ace="*S-1-5-32-547", inherited=False)
    assert got["warnings"], (
        "a principal outside the removal set survived and nothing said so -- the caller would "
        f"believe the directory was locked down:\n{got['after']}"
    )
    assert any("Power Users" in w or "S-1-5-32-547" in w for w in got["warnings"]), (
        f"the warning must NAME the principal that still has access; got {got['warnings']}"
    )


# --- the -LockConfigDir lockdown is READ BACK too (BACKLOG #5562) ----------------------------------
# Set-SecureConfigAcl had the shape Set-SecureDataDirAcl had before #1699: `/inheritance:r /grant:r`
# on the directory alone. An EXPLICIT broad ACE on the directory survived it, and so did every child
# file or folder whose own DACL carried an explicit grant or had inheritance turned off -- while the
# installer printed "Config : locked to ...". The runtime guard (SEC-003) vets the directory and each
# *.py, so the likely outcome is a service that refuses to start under a line saying it was locked.
#
# Only an elevated token may make Administrators an owner, so an unelevated run reads back an owner
# problem for every item; _config_lockdown keeps those apart for the owner arm.

_CONFIG_ACL_FNS = [
    "Set-SecureConfigAcl",
    "Get-WellKnownBroadSids",
    "Get-BroadAclResidue",
    "Get-ReparsePointAncestor",
    "Reset-ConfigTreeAcl",
]


def _config_lockdown(tmp_path: Path, prepare: str = "", account: str = "$me") -> dict:
    """Run Set-SecureConfigAcl on a real config tree and read every DACL in it back.

    The tree is ``config\\mod.py`` and ``config\\sub\\inner.py``, with a folder ``outside`` beside
    it that a junction planted in the tree may point at. ``prepare`` runs first, with ``$cfg``,
    ``$outside`` and ``$me`` set. The before-reads are the controls.
    """
    assert _SCRIPT is not None
    parent = tmp_path / f"cfg-{uuid.uuid4().hex[:8]}"
    cfg = parent / "config"
    outside = parent / "outside"
    (cfg / "sub").mkdir(parents=True)
    outside.mkdir()
    (cfg / "mod.py").write_text("X = 1\n", encoding="utf-8")
    (cfg / "sub" / "inner.py").write_text("Y = 2\n", encoding="utf-8")
    (outside / "target.py").write_text("Z = 3\n", encoding="utf-8")
    (outside / "shared.py").write_text("W = 4\n", encoding="utf-8")
    body = rf"""
  $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  $parent = {_psq(str(parent))}
  $cfg = {_psq(str(cfg))}
  $outside = {_psq(str(outside))}
  $paths = [ordered]@{{
    cfg = $cfg; mod = (Join-Path $cfg 'mod.py'); sub = (Join-Path $cfg 'sub')
    inner = (Join-Path $cfg 'sub\inner.py'); target = (Join-Path $outside 'target.py')
    shared = (Join-Path $outside 'shared.py')
  }}
  function Read-Sids([string]$p) {{
    @((Get-Acl -LiteralPath $p).Access | ForEach-Object {{
      try {{ $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }}
      catch {{ "$($_.IdentityReference)" }} }})
  }}
  function Read-Tree {{
    $o = [ordered]@{{}}
    foreach ($k in $paths.Keys) {{ $o[$k] = @(Read-Sids $paths[$k]) }}
    $o['modProtected'] = (Get-Acl -LiteralPath $paths.mod).AreAccessRulesProtected
    $o['cfgProtected'] = (Get-Acl -LiteralPath $cfg).AreAccessRulesProtected
    $o['targetOwner'] = (Get-Acl -LiteralPath $paths.target).GetOwner(
      [Security.Principal.SecurityIdentifier]).Value
    $o
  }}
  try {{
{prepare}
    $before = Read-Tree
    $warnings = @()
    $problems = @()
    $emitted = & {{ Set-SecureConfigAcl -Path $cfg -Account {account} }} 3>&1
    foreach ($o in @($emitted)) {{
      if ($o -is [System.Management.Automation.WarningRecord]) {{ $warnings += "$o" }}
      else {{ $problems += "$o" }}
    }}
    $after = Read-Tree
    [pscustomobject]@{{
      before = $before; after = $after; problems = @($problems); warnings = @($warnings)
      listing = (& icacls $cfg /T | Out-String); meSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
      elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    }} | ConvertTo-Json -Depth 5 -Compress
  }} finally {{
    # Put the tree back in reach so pytest can delete it, however the block above ended. The
    # junction is deleted as a link once the folder holding it is writable again, and before any
    # child is touched: nothing below may walk through it.
    foreach ($p in @($parent, $cfg, $outside)) {{
      & icacls $p /inheritance:e /grant "${{me}}:(OI)(CI)F" | Out-Null
    }}
    $link = Join-Path $cfg 'linked'
    if (Test-Path -LiteralPath $link) {{ (Get-Item -LiteralPath $link -Force).Delete() }}
    foreach ($p in @($paths.mod, $paths.sub, $paths.inner, $paths.target)) {{
      & icacls $p /inheritance:e /grant "${{me}}:F" | Out-Null
    }}
  }}
"""
    out: dict = json.loads(
        _ok(_extract(_SCRIPT, _CONFIG_ACL_FNS, body), tmp_path).strip().splitlines()[-1]
    )
    problems = [p for p in (out.get("problems") or []) if p]
    # Only an elevated token may make Administrators the owner, so an unelevated run reads back an
    # owner problem for every item. Those are kept apart, and the owner arm below judges them.
    out["ownerProblems"] = [p for p in problems if "is owned by" in p]
    out["problems"] = [p for p in problems if "is owned by" not in p]
    out["warnings"] = [w for w in (out.get("warnings") or []) if w]
    return out


@_windows_only
def test_an_explicit_broad_ace_on_the_config_dir_is_stripped(tmp_path: Path) -> None:
    """The #1699 shape on the config dir: an EXPLICIT BUILTIN\\Users Modify survives
    ``/inheritance:r /grant:r`` and reaches every module below it."""
    got = _config_lockdown(
        tmp_path, "    & icacls $cfg /grant '*S-1-5-32-545:(OI)(CI)M' | Out-Null"
    )
    assert "S-1-5-32-545" in got["before"]["cfg"], (
        f"CONTROL FAILED: the explicit Users ACE was not planted:\n{got['listing']}"
    )
    assert "S-1-5-32-545" in got["before"]["mod"], "CONTROL FAILED: mod.py did not inherit it"
    for key in ("cfg", "mod", "sub", "inner"):
        assert "S-1-5-32-545" not in got["after"][key], (
            f"BUILTIN\\Users still holds access to {key} after Set-SecureConfigAcl:\n{got['listing']}"
        )
    assert got["problems"] == [], (
        f"a removed ACE must not be reported as residue: {got['problems']}"
    )


@_windows_only
def test_a_child_with_its_own_dacl_is_reset_to_inherit_the_lockdown(tmp_path: Path) -> None:
    """A module with inheritance turned off and its own grant, and a folder with an explicit grant
    its files inherit. ``/inheritance:r`` on the directory touches neither, and the guard vets each
    *.py, so the service would refuse to start under a line saying the config was locked."""
    prepare = r"""
    & icacls $paths.mod /inheritance:r /grant:r "${me}:F" '*S-1-5-11:M' | Out-Null
    & icacls $paths.sub /grant '*S-1-5-11:(OI)(CI)M' | Out-Null
"""
    got = _config_lockdown(tmp_path, prepare)
    assert got["before"]["modProtected"] is True, "CONTROL FAILED: mod.py still inherits"
    assert "S-1-5-11" in got["before"]["mod"], "CONTROL FAILED: mod.py has no own grant"
    assert "S-1-5-11" in got["before"]["inner"], "CONTROL FAILED: inner.py did not inherit"
    for key in ("mod", "sub", "inner"):
        assert "S-1-5-11" not in got["after"][key], (
            f"Authenticated Users still holds access to {key}:\n{got['listing']}"
        )
    assert got["after"]["modProtected"] is False, (
        f"mod.py still has inheritance turned off, so the lockdown never reaches it:\n{got['listing']}"
    )
    assert "S-1-5-32-544" in got["after"]["mod"] and "S-1-5-18" in got["after"]["mod"], (
        f"mod.py did not inherit the lockdown's grants:\n{got['listing']}"
    )
    assert got["problems"] == [], (
        f"a reset child must not be reported as residue: {got['problems']}"
    )


@_windows_only
def test_config_residue_outside_the_removal_set_is_returned(tmp_path: Path) -> None:
    """What the named removals miss is READ BACK and returned, so the installer does not print the
    lockdown line over it. Power Users stands in for any account outside the well-known set."""
    got = _config_lockdown(
        tmp_path, "    & icacls $cfg /grant '*S-1-5-32-547:(OI)(CI)RX' | Out-Null"
    )
    assert "S-1-5-32-547" in got["before"]["cfg"], "CONTROL FAILED: Power Users was not planted"
    assert any("Power Users" in p or "S-1-5-32-547" in p for p in got["problems"]), (
        "a principal outside the removal set survived and nothing returned it -- the installer "
        f"would print the lockdown line over it: {got['problems']}\n{got['listing']}"
    )


@_windows_only
def test_a_junction_in_the_config_dir_is_not_followed_and_is_named(tmp_path: Path) -> None:
    """icacls /T walks through a junction (measured: ``icacls <dir>\\* /reset /T`` reset a file in
    the junction's target, with /L or without), so the reset walks the tree itself and stops at a
    link. A link it did not reset is named, because the lockdown did not reach what it points at.

    The owner step walks the same way: ``/setowner /T`` follows a junction too. Unelevated, no
    owner can be set either way, so only an elevated run (CI) witnesses the owner arm.

    A HARD LINK shares one DACL among all its names, so resetting ``config\\shared.py`` would
    rewrite ``outside\\shared.py`` too. It is named and left alone."""
    prepare = r"""
    & icacls $paths.target /grant '*S-1-5-32-547:R' | Out-Null
    & icacls $paths.shared /grant '*S-1-5-32-547:R' | Out-Null
    cmd /c mklink /J (Join-Path $cfg 'linked') $outside | Out-Null
    cmd /c mklink /H (Join-Path $cfg 'shared.py') $paths.shared | Out-Null
"""
    got = _config_lockdown(tmp_path, prepare)
    assert "S-1-5-32-547" in got["before"]["target"], "CONTROL FAILED: the target has no grant"
    assert "S-1-5-32-547" in got["before"]["shared"], "CONTROL FAILED: the shared file has no grant"
    assert "S-1-5-32-547" in got["after"]["target"], (
        "the reset followed the junction and rewrote a file OUTSIDE the config dir"
    )
    assert got["after"]["targetOwner"] == got["before"]["targetOwner"], (
        "the owner step followed the junction and re-owned a file OUTSIDE the config dir"
    )
    assert "S-1-5-32-547" in got["after"]["shared"], (
        "the reset went through a hard link and rewrote the DACL of a file OUTSIDE the config dir"
    )
    assert any("linked" in p for p in got["problems"]), (
        f"the junction must be named as not reset: {got['problems']}"
    )
    assert any("shared.py" in p and "hard link" in p for p in got["problems"]), (
        f"the hard link must be named as not reset: {got['problems']}"
    )


def test_the_walk_changes_a_link_itself_never_its_target() -> None:
    """Without ``/L`` icacls follows a link and re-owns and resets its target, which may lie
    outside the config dir. A link the checks before the per-item calls miss would reach them, so
    every icacls call in the per-item loop must carry ``/L``, wherever in its arguments; on a file
    that is not a link, ``/L`` changes nothing (measured)."""
    m = re.search(r"(?ms)^function Reset-ConfigTreeAcl \{.*?^\}", _script_text())
    assert m is not None, "Reset-ConfigTreeAcl is missing from install-service.ps1"
    loop = re.search(r"(?ms)foreach \(\$child in \$children\) \{.*?^        \}", m.group(0))
    assert loop is not None, "the per-item loop of Reset-ConfigTreeAcl was not found"
    # An invocation starts a statement; a message that only mentions icacls does not.
    call = re.compile(r"""(?i)^\s*(?:&\s*)?["']?icacls(?:\.exe)?["']?\s""")
    calls = [ln for ln in loop.group(0).splitlines() if call.search(ln)]
    verbs = {v for c in calls for v in ("/setowner", "/reset") if v in c.split()}
    assert verbs == {"/setowner", "/reset"}, (
        f"CONTROL FAILED: the per-item /setowner and /reset calls were not found: {calls}"
    )
    for c in calls:
        assert "/L" in c.split(), (
            f"a per-item icacls call lacks /L, so it acts on a link's target: {c}"
        )


@_windows_only
def test_a_file_link_whose_type_is_hidden_does_not_reach_its_target(tmp_path: Path) -> None:
    """A file link whose own DACL hides its link type passes ``$isLink``, so the walk fails closed on
    any file reparse point whose type reads empty: it skips the item and names it. A named problem
    withholds the installer's "Config : locked" line. Creating a symbolic link needs the privilege
    an unelevated account has only in Developer Mode, so the test skips without it.

    THE HARNESS STARTS WITH THE BACKUP AND RESTORE PRIVILEGES OFF. Either one lets reading LinkType
    pass the deny entry; ``_privileges_disabled`` says why. Both hosted Windows legs failed the
    control while the restore privilege was on (run 43668208722). A control that still fails fails
    the test, and its message names what whoami reads in the harness."""
    from tests.test_worktree_remove_in_use import _privileges_disabled

    probe = tmp_path / "symlink-probe"
    try:
        probe.symlink_to(tmp_path)
    except OSError as e:
        pytest.skip(f"SKIP (nothing run): this account cannot create a symbolic link ({e})")
    probe.unlink()
    prepare = r"""
    & icacls $paths.target /grant '*S-1-5-32-547:R' | Out-Null
    $hidden = Join-Path $cfg 'hidden.py'
    New-Item -ItemType SymbolicLink -Path $hidden -Target $paths.target | Out-Null
    # Denying SYNCHRONIZE empties LinkType (measured on pwsh 7.6).
    & icacls $hidden /L /deny "${me}:(S)" | Out-Null
    if ("$((Get-Item -LiteralPath $hidden -Force).LinkType)") {
      # By full path: under Git Bash, as on the CI legs, a bare whoami is MSYS's, which has no /priv.
      $whoami = Join-Path $env:SystemRoot 'System32\whoami.exe'
      $held = @(& $whoami /priv | Select-String 'SeBackupPrivilege|SeRestorePrivilege') -join '; '
      if (-not $held) { $held = 'neither listed' }
      throw ("CONTROL FAILED: the deny entry did not hide the link's type (privileges this " +
        "test switched off: $wereOn; whoami /priv here: $held)")
    }
"""
    with _privileges_disabled() as were_on:
        got = _config_lockdown(tmp_path, f"    $wereOn = {were_on}\n" + prepare)
    assert "S-1-5-32-547" in got["before"]["target"], "CONTROL FAILED: the target has no grant"
    assert "S-1-5-32-547" in got["after"]["target"], (
        "the reset followed a link whose type it could not read and rewrote a file OUTSIDE the "
        "config dir"
    )
    assert got["after"]["targetOwner"] == got["before"]["targetOwner"], (
        "the owner step followed a link whose type it could not read and re-owned a file OUTSIDE "
        "the config dir"
    )
    assert any("hidden.py" in p and "link type could not be read" in p for p in got["problems"]), (
        "a link whose type could not be read was not named, so the installer would print the "
        f"locked line over it: {got['problems']}"
    )
    decided = re.search(
        r"(?s)if \(\$ConfigLockProblems\) \{.*?Write-Warning.*?\} else \{.*?Config : locked",
        _script_text(),
    )
    assert decided is not None, (
        "the installer no longer withholds the 'Config : locked' line when the lockdown returns a "
        "problem"
    )


@_windows_only
def test_every_owner_in_the_config_tree_is_read_back(tmp_path: Path) -> None:
    """The guard refuses a dir or *.py whose owner it cannot trust, so an owner the lockdown could
    not set is returned, not left under the lockdown line. Unelevated, nothing can be made
    Administrators-owned, so every item must come back; elevated, none."""
    got = _config_lockdown(tmp_path)
    named = " ".join(got["ownerProblems"])
    if got["elevated"]:
        assert got["ownerProblems"] == [], got["ownerProblems"]
    else:
        for part in ("config'", "mod.py", "sub'", "inner.py"):
            assert part in named, f"an owner left unset was not returned for {part}: {named}"


@_windows_only
def test_a_root_that_could_not_be_locked_leaves_the_tree_alone(tmp_path: Path) -> None:
    """The walk resets each child to inherit from the root, so after a failed root lock it would
    WIDEN a child that was tighter than the root. An account icacls cannot resolve fails the
    root grant; the owner-only module below must keep its own DACL."""
    prepare = r"""
    & icacls $cfg /grant '*S-1-5-32-547:(OI)(CI)M' | Out-Null
    & icacls $paths.mod /inheritance:r /grant:r "${me}:F" | Out-Null
"""
    got = _config_lockdown(tmp_path, prepare, account="'NoSuchAccount-b234x'")
    assert got["before"]["modProtected"] is True, "CONTROL FAILED: mod.py still inherits"
    assert any("could not be locked" in p for p in got["problems"]), got["problems"]
    assert got["after"]["modProtected"] is True, (
        f"the walk ran over a root that was not locked and widened mod.py:\n{got['listing']}"
    )
    assert "S-1-5-32-547" not in got["after"]["mod"], got["listing"]


@_windows_only
def test_a_root_still_granting_another_account_leaves_the_tree_alone(tmp_path: Path) -> None:
    """The root grant succeeded, but an entry outside the removal set survived on it. Resetting a
    child to inherit would then pass that entry to a child that was tighter than the root."""
    prepare = r"""
    & icacls $cfg /grant '*S-1-5-32-547:(OI)(CI)M' | Out-Null
    & icacls $paths.mod /inheritance:r /grant:r "${me}:F" | Out-Null
"""
    got = _config_lockdown(tmp_path, prepare)
    assert got["before"]["modProtected"] is True, "CONTROL FAILED: mod.py still inherits"
    assert any("S-1-5-32-547" in p or "Power Users" in p for p in got["problems"]), got["problems"]
    assert any("nothing below" in p for p in got["problems"]), got["problems"]
    assert got["after"]["modProtected"] is True, (
        f"the walk reset mod.py under a root that still grants Power Users:\n{got['listing']}"
    )
    assert "S-1-5-32-547" not in got["after"]["mod"], got["listing"]


@_windows_only
def test_a_dot_backslash_account_locks_like_its_full_name(tmp_path: Path) -> None:
    """icacls does not take '.\\name', which Set-ServiceAccount accepts, so the account is spelled
    with this host's name first; otherwise -LockConfigDir could never finish for it."""
    got = _config_lockdown(tmp_path, account="('.\\' + $me.Split('\\')[-1])")
    assert got["problems"] == [], got["problems"]
    assert got["meSid"] in got["after"]["cfg"], f"the account got no grant:\n{got['listing']}"


@_windows_only
def test_a_deny_entry_on_the_config_dir_is_returned(tmp_path: Path) -> None:
    """A deny entry survives /remove:g, which removes grants only, and is passed down by the reset;
    one against the run-as account stops the service reading its config under a clean line."""
    got = _config_lockdown(
        tmp_path, "    & icacls $cfg /deny '*S-1-5-32-547:(OI)(CI)(W)' | Out-Null"
    )
    assert any("deny" in p for p in got["problems"]), got["problems"]


@_windows_only
def test_a_write_grant_for_the_run_as_account_below_the_config_is_named(tmp_path: Path) -> None:
    """The reset drops the run-as account's own explicit Modify on a child folder to the read it
    inherits. The read-back allows that account, so without a warning a File connection writing
    there would fail at run time with nothing said at install."""
    got = _config_lockdown(tmp_path, '    & icacls $paths.sub /grant "${me}:(OI)(CI)M" | Out-Null')
    assert any("write away" in w and "sub'" in w for w in got["warnings"]), got["warnings"]
    assert got["problems"] == [], got["problems"]


@_windows_only
def test_a_clean_config_lockdown_returns_nothing_and_keeps_what_the_service_needs(
    tmp_path: Path,
) -> None:
    """POSITIVE CONTROL. Every arm above passes on a function that strips everything, or that
    returns a problem for every tree."""
    got = _config_lockdown(tmp_path)
    assert got["problems"] == [], f"a clean tree must read back clean: {got['problems']}"
    assert got["warnings"] == [], f"a clean tree must warn of nothing: {got['warnings']}"
    assert got["after"]["cfgProtected"] is True, "the config dir must not inherit from its parent"
    for key in ("cfg", "mod", "sub", "inner"):
        sids = got["after"][key]
        assert "S-1-5-18" in sids and "S-1-5-32-544" in sids, (
            f"SYSTEM or Administrators lost access to {key}:\n{got['listing']}"
        )
        assert got["meSid"] in sids, f"the run-as account lost read on {key}:\n{got['listing']}"


def test_the_config_lockdown_line_is_printed_only_after_a_clean_read_back() -> None:
    """CALL-SITE guard. The function's read-back says nothing if the installer still prints
    "Config : locked to ..." whatever it returned."""
    text = _script_text()
    collect = text.index(
        "$ConfigLockProblems += @(Set-SecureConfigAcl -Path $LockPath -Account $ServiceAccount)"
    )
    gate = text.index("if ($ConfigLockProblems) {", collect)
    clean = text.index("} else {", gate)
    line = text.index('Write-Host "  Config : locked to $cfgGrantees', clean)
    refused = text[gate:clean]
    assert "Write-Warning" in refused and "$ConfigLockProblems" in refused, (
        "the residue branch must warn and name what it found"
    )
    assert "locked to" not in refused, "the residue branch must not claim the lockdown"
    assert collect < gate < clean < line


def test_the_installer_still_calls_the_lockdown_on_the_data_dir(tmp_path: Path) -> None:
    """CALL-SITE guard, and the literal complaint of BACKLOG #1699: deleting the call left every
    test green. The behavioural arms above run the FUNCTION and say nothing about whether the
    script invokes it."""
    facts = _preflight_facts(tmp_path)
    calls = [c for c in facts["commands"] if _named(c, "Set-SecureDataDirAcl")]
    assert len(calls) == 1, (
        f"expected exactly one Set-SecureDataDirAcl call in install-service.ps1, found {len(calls)}"
    )
    assert "-Path $DataDir" in calls[0]["text"], (
        f"the lockdown must be applied to the data dir (the logs inherit from it): {calls[0]['text']}"
    )


def test_the_smoke_leg_reads_the_dacl_it_produced() -> None:
    """The other half of #1699: windows-service-smoke installs the service and never looked at the
    ACL the installer left behind.

    THIS CANNOT BE DEMONSTRATED FROM A PULL REQUEST. That job is
    ``if: schedule || workflow_dispatch || merge_group``, so a pull_request event SKIPS it. This
    asserts the step EXISTS and checks both spellings; somebody has to read the leg's own result
    after a nightly or a merge-queue run.
    """
    root = Path(__file__).resolve().parents[1]
    ci = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "Verify the data-directory DACL" in ci, (
        "windows-service-smoke has no step reading back the DACL the installer produced "
        "(BACKLOG #1699)"
    )
    for needle in ("S-1-5-32-545", "BUILTIN", "icacls"):
        assert needle in ci, (
            f"the smoke DACL check must look for {needle!r}: on an English runner icacls prints "
            "the NAME and a SID-only grep returns a false clean"
        )


# --- the smoke step also requires the RUN-AS grant, and is RUN here (BACKLOG #1699) ---------------
# What the step requires, and why, is in the step's own comment in ci.yml. Its leg cannot run on a
# pull request, so the arms below run the step's own script, read from the parsed workflow, against
# stand-in icacls output: a wrong matcher fails here rather than first in the merge queue.

_DACL_STEP = "Verify the data-directory DACL"
_DATA = r"C:\ProgramData\MessageFoundry"
_LOGS = r"C:\ProgramData\MessageFoundry\logs"
_VIRTUAL = r"NT SERVICE\MessageFoundry"
_LOCKED = [r"NT AUTHORITY\SYSTEM:(OI)(CI)(F)", r"BUILTIN\Administrators:(OI)(CI)(F)"]
_GRANTED = [f"{_VIRTUAL}:(OI)(CI)(M)", *_LOCKED]


def _icacls(path: str, entries: list[str]) -> str:
    """What icacls prints for ``path``: the path on the first entry's line, the rest aligned under
    it. The path is what makes a bare-name match on "MessageFoundry" pass with the entry gone."""
    pad = " " * (len(path) + 1)
    lines = [f"{path} {entries[0]}"] + [pad + e for e in entries[1:]]
    return "\n".join(lines + ["", "Successfully processed 1 files; Failed processing 0 files"])


def _inherited(entries: list[str]) -> list[str]:
    return [e.replace(":(", ":(I)(", 1) for e in entries]


# A whole line that only prints or throws one double-quoted string, with no subexpression in it.
_MESSAGE_LINE = re.compile(r'(?i)^(?:(?:throw|write-\w+)\s+)?"[^"$]*(?:\$(?!\()[^"$]*)*"$')
_DACL_TOOL = re.compile(r"(?i)cacls|set-acl|takeown|system32")


def _dacl_tool_lines(script: str) -> list[str]:
    """The lines of ``script`` that name a DACL tool, each stripped. Comment lines are skipped.

    A line is read as a message, and skipped, only when the WHOLE line is ``throw``, a ``Write-``
    cmdlet or nothing, followed by one double-quoted string with no ``$(`` in it. Any other line
    stays in the census whole, quotes included, because a quoted string there can be the call
    itself: ``& "C:\\Windows\\System32\\icacls.exe" ...``, ``cmd /c "icacls ..."``, or a call after
    a ``;`` or in a pipeline. The stand-ins below would not intercept those. This reds in the safe
    direction: a message that is not alone on its line, ``if (...) { throw "icacls ..." }`` for
    one, is counted as a tool line, and the census then refuses to run the step.
    """
    lines = []
    for raw in script.splitlines():
        line = raw.strip()
        if line.startswith("#") or _MESSAGE_LINE.match(line):
            continue
        if _DACL_TOOL.search(line):
            lines.append(line)
    return lines


@pytest.mark.parametrize(
    "extra",
    [
        r'& "C:\Windows\System32\icacls.exe" $d /grant "x:(OI)(CI)F"',
        'cmd /c "icacls $d /grant x:F"',
        "& 'icacls.exe' $d /reset",
        r'Start-Process -FilePath "$env:SystemRoot\System32\icacls.exe" -ArgumentList $d',
    ],
    ids=["quoted-full-path", "cmd-c", "single-quoted", "start-process"],
)
def test_the_dacl_tool_census_sees_a_quoted_call(extra: str) -> None:
    """The census in front of the stand-ins must not read a quoted call as message text."""
    _census_sees(extra)


@pytest.mark.parametrize(
    "extra",
    [
        r'Write-Host "locking"; & "C:\Windows\System32\icacls.exe" $d /reset',
        r'"$d" | ForEach-Object { & "C:\Windows\System32\icacls.exe" $_ /reset }',
        r'Write-Host (& "C:\Windows\System32\icacls.exe" $d /reset)',
        r'throw "failed: $(& "C:\Windows\System32\icacls.exe" $d /reset)"',
    ],
    ids=["after-a-message", "pipeline", "message-argument", "subexpression-in-a-message"],
)
def test_the_dacl_tool_census_sees_a_call_beside_a_message(extra: str) -> None:
    """A line that starts like a message but runs a call is not skipped as one."""
    _census_sees(extra)


def _census_sees(extra: str) -> None:
    script = _smoke_step(_DACL_STEP)
    assert _dacl_tool_lines(script) == ["$acl = (& icacls $d | Out-String)"], (
        "CONTROL FAILED: the step's own census changed"
    )
    assert extra in _dacl_tool_lines(f"{script}\n{extra}\n"), "the census missed a quoted call"


def test_the_dacl_tool_census_ignores_message_text() -> None:
    """A message naming icacls is not a call, so it does not trip the census."""
    messages = [
        'throw "icacls on $d failed"',
        'Write-Host "icacls says:"',
        '"===== icacls $d ====="',
        "# icacls is read here, never written",
    ]
    assert _dacl_tool_lines("\n".join(messages)) == []
    assert _dacl_tool_lines("\n".join([*messages, "& icacls $d"])) == ["& icacls $d"], (
        "CONTROL: a bare call beside the messages is still read"
    )


def _run_dacl_step(
    tmp_path: Path, *, account: str, data: list[str], logs: list[str]
) -> subprocess.CompletedProcess[str]:
    """Run the step's script with icacls and Test-Path stood in, under ``SMOKE_ACCOUNT=account``.

    A function shadows the bare name ``icacls`` and nothing else: a path to the executable would
    run the real one. So the script's DACL-tool lines are read first, and the bare call must be the
    only one. A few other spellings are stand-ins that throw as well. Wrapped as the runner wraps
    a powershell step, as _run_smoke_stop says: 'stop' first, $LASTEXITCODE last. The runner
    dot-sources a script FILE; this dot-sources the same text as a script block, so nothing here
    may rest on $PSScriptRoot or a file position. The step is ``shell: powershell``, so Windows
    PowerShell 5.1 runs it where it is on PATH; pwsh elsewhere.
    """
    shell = shutil.which("powershell") or shutil.which("pwsh")
    if shell is None:
        pytest.skip("SKIP (nothing run): neither powershell nor pwsh on PATH")
    script = _smoke_step(_DACL_STEP)
    tools = _dacl_tool_lines(script)
    assert tools == ["$acl = (& icacls $d | Out-String)"], (
        f"expected the step's one DACL-tool line to be the bare, read-only icacls call: {tools}"
    )
    acls = {_DATA: _icacls(_DATA, data), _LOGS: _icacls(_LOGS, logs)}
    table = "; ".join(f"{_psq(k)} = {_psq(v)}" for k, v in acls.items())
    stand_ins = f"""$ErrorActionPreference = 'stop'
$global:Acls = @{{ {table} }}
foreach ($changes in 'icacls.exe', 'cacls', 'cacls.exe', 'Set-Acl', 'takeown', 'takeown.exe') {{
  Set-Item -Path "function:global:$changes" -Value {{
    throw "the step ran $($MyInvocation.MyCommand.Name), which this harness does not stand in for"
  }}
}}
function Test-Path {{
  param($Path, $LiteralPath)
  if ($LiteralPath) {{ return Microsoft.PowerShell.Management\\Test-Path -LiteralPath $LiteralPath }}
  $global:Acls.ContainsKey($Path)
}}
function icacls {{ param($Path) if ($args.Count) {{ throw "the step changed a DACL: $args" }}; $global:Acls[$Path] -split "`n" }}
"""
    f = tmp_path / f"smoke-dacl-{uuid.uuid4().hex}.ps1"
    f.write_text(
        stand_ins
        + script
        + "\nif ((Test-Path -LiteralPath variable:\\LASTEXITCODE)) { exit $LASTEXITCODE }\n",
        encoding="utf-8",
    )
    # Read the file and dot-source it as a script block rather than as a script file. Execution
    # policy governs script FILES, so this runs where a machine or user policy set by Group Policy
    # would overrule a process-scope -ExecutionPolicy Bypass and refuse the file.
    run = f". ([scriptblock]::Create([IO.File]::ReadAllText({_psq(str(f))})))"
    return subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-Command", run],
        capture_output=True,
        text=True,
        timeout=180,
        env={
            **os.environ,
            "SMOKE_ACCOUNT": account,
            "SMOKE_LOCAL_USER": "mefor-svc",
            "COMPUTERNAME": "RIG-01",
        },
    )


def test_the_smoke_dacl_step_passes_a_lockdown_that_kept_the_run_as_grant(tmp_path: Path) -> None:
    """THE CONTROL for the arms that follow: the DACL the installer leaves passes. Explicit on the
    data directory, inherited onto logs."""
    r = _run_dacl_step(tmp_path, account="virtual", data=_GRANTED, logs=_inherited(_GRANTED))
    assert r.returncode == 0, r.stderr + r.stdout
    assert f"{_VIRTUAL} holds (OI)(CI)(M) on the data directory and (I)(OI)(CI)(M)" in r.stdout


_DENY = f"{_VIRTUAL}:(OI)(CI)(DENY)(W)"


@pytest.mark.parametrize(
    ("broken", "data", "logs"),
    [
        # The entry is gone from logs, and only the path still says MessageFoundry.
        (_LOGS, _GRANTED, _inherited(_LOCKED)),
        (_LOGS, _GRANTED, [*_inherited(_LOCKED), f"{_VIRTUAL}:(I)(OI)(CI)(RX)"]),
        # Not inherited by what the service creates beneath logs.
        (_LOGS, _GRANTED, [*_inherited(_LOCKED), f"{_VIRTUAL}:(I)(M)"]),
        (_LOGS, _GRANTED, [*_inherited(_LOCKED), r"NT SERVICE\MessageFoundryX:(I)(OI)(CI)(M)"]),
        # Explicit on logs: logs no longer inherits the data directory's lockdown.
        (_LOGS, _GRANTED, _GRANTED),
        (_LOGS, _GRANTED, [*_inherited(_GRANTED), _DENY.replace(":(", ":(I)(", 1)]),
        (_DATA, _LOCKED, _inherited(_GRANTED)),
        # Inherited on the data directory: the lockdown's /inheritance:r did not take there.
        (_DATA, _inherited(_GRANTED), _inherited(_GRANTED)),
        (_DATA, [*_GRANTED, _DENY], _inherited(_GRANTED)),
    ],
    ids=[
        "logs-gone",
        "logs-read-only",
        "logs-not-inherited-onward",
        "logs-other-account",
        "logs-explicit",
        "logs-deny",
        "data-gone",
        "data-inherited",
        "data-deny",
    ],
)
def test_the_smoke_dacl_step_fails_when_the_run_as_grant_is_wrong(
    tmp_path: Path, broken: str, data: list[str], logs: list[str]
) -> None:
    """Each wrong entry is refused and named by its directory. The other directory keeps the right
    one, so the failure is that directory's line alone."""
    r = _run_dacl_step(tmp_path, account="virtual", data=data, logs=logs)
    assert r.returncode != 0, r.stdout
    out = r.stdout + r.stderr
    fine = _DATA if broken == _LOGS else _LOGS
    assert f"NO RUN-AS GRANT: {broken} " in out, out
    assert f"NO RUN-AS GRANT: {fine} " not in out, out


def test_the_smoke_dacl_step_requires_systems_entry_on_the_localsystem_leg(tmp_path: Path) -> None:
    """The installer writes no named grant for LocalSystem, which writes through SYSTEM's entry, so
    that is the entry this leg requires. A SYSTEM entry that cannot write is refused."""
    r = _run_dacl_step(tmp_path, account="localsystem", data=_LOCKED, logs=_inherited(_LOCKED))
    assert r.returncode == 0, r.stderr + r.stdout
    assert r"NT AUTHORITY\SYSTEM holds (OI)(CI)(F) on the data directory" in r.stdout, r.stdout
    read_only = [r"NT AUTHORITY\SYSTEM:(OI)(CI)(RX)", r"BUILTIN\Administrators:(OI)(CI)(F)"]
    weak = _run_dacl_step(
        tmp_path, account="localsystem", data=read_only, logs=_inherited(read_only)
    )
    assert weak.returncode != 0, weak.stdout
    assert f"NO RUN-AS GRANT: {_DATA} shows no" in weak.stdout + weak.stderr


def test_the_smoke_dacl_step_names_the_local_user_on_that_leg(tmp_path: Path) -> None:
    """The localuser leg requires its own account, matched without regard to case, and the virtual
    account's entry does not stand in for it."""
    user = [r"rig-01\mefor-svc:(OI)(CI)(M)", *_LOCKED]
    ok = _run_dacl_step(tmp_path, account="localuser", data=user, logs=_inherited(user))
    assert ok.returncode == 0, ok.stderr + ok.stdout
    wrong = _run_dacl_step(tmp_path, account="localuser", data=_GRANTED, logs=_inherited(_GRANTED))
    assert wrong.returncode != 0, wrong.stdout
    assert r"shows no 'RIG-01\mefor-svc:(OI)(CI)(M)' entry" in wrong.stdout + wrong.stderr


def test_the_smoke_dacl_step_still_refuses_a_broad_principal(tmp_path: Path) -> None:
    logs = [*_inherited(_GRANTED), r"BUILTIN\Users:(I)(OI)(CI)(RX)"]
    r = _run_dacl_step(tmp_path, account="virtual", data=_GRANTED, logs=logs)
    assert r.returncode != 0, r.stdout
    assert rf"BROAD ACCESS: {_LOGS} grants BUILTIN\Users" in r.stdout + r.stderr


def test_the_smoke_dacl_step_refuses_an_account_leg_it_does_not_know(tmp_path: Path) -> None:
    r = _run_dacl_step(tmp_path, account="gmsa", data=_LOCKED, logs=_inherited(_LOCKED))
    assert r.returncode != 0, r.stdout
    assert "unknown SMOKE_ACCOUNT 'gmsa'" in r.stdout + r.stderr


# --- the run-as account and the ACLs must agree on EVERY path (BACKLOG #1553) ---------------------
# -AllowLocalSystem on a RERUN left the previous account configured (ObjectName was written only on the
# non-LocalSystem branch) and then stripped that still-running account's access to the data dir. The
# config dir goes the same way, and losing READ there makes SEC-003 source-trust refuse to load config
# at all -- three ACL sites, not the one the row names.
#
# The fix is an ORDERING-FREE one: write ObjectName unconditionally, so the assumption about what NSSM
# defaults to at create time stops mattering. The guards are therefore about which branches write it.

_ACL_CALLS = [
    "Set-SecureDataDirAcl",
    "Set-SecureConfigAcl",
    "Set-ConfigReadAcl",
    "Set-SecretsDirAcl",
]


def _objectname_calls(facts: dict) -> list[dict]:
    """The calls that set the run-as account. Set-ServiceAccount, through the SCM, since NSSM 2.24
    refuses `set ObjectName` for a virtual account (BACKLOG #2364)."""
    return [c for c in facts["commands"] if _named(c, "Set-ServiceAccount")]


def _named(call: dict, name: str) -> bool:
    """PowerShell resolves a command name without regard to case, so a guard must too."""
    return str(call["name"] or "").lower() == name.lower()


def test_objectname_is_written_on_every_run_as_branch(tmp_path: Path) -> None:
    """Three branches set the run-as account -- password, password-less, and the LocalSystem opt-out
    -- and all three must set the account (Set-ServiceAccount).

    The opt-out used to write nothing, on the reasoning that NSSM defaults to LocalSystem. That is
    true of a FRESH install only; on a rerun it leaves whatever account is already registered.
    """
    facts = _preflight_facts(tmp_path)
    calls = _objectname_calls(facts)
    assert len(calls) == 3, (
        "expected ObjectName to be set on all three run-as branches (password, password-less, "
        f"LocalSystem opt-out); found {len(calls)}:\n"
        + "\n".join(f"  line {c['line']}: {c['text']}" for c in calls)
    )


def test_the_localsystem_optout_writes_objectname_rather_than_leaving_it(tmp_path: Path) -> None:
    """Locate the opt-out branch, then prove a real ObjectName CALL sits inside its offsets.

    A call counted anywhere in the file is not the question; the question is whether the branch a
    rerun with -AllowLocalSystem actually takes writes it.

    MATCHED ON COMMANDS, NOT ON THE BRANCH TEXT. An extent includes its comments, and the comment
    explaining why ObjectName is written here contains the word "ObjectName" -- so a substring test
    over the branch text passes on a branch whose call has been deleted. Measured: it did.
    """
    assert _SCRIPT is not None
    body = """
  $ifs = @(foreach ($i in $ast.FindAll({ $args[0] -is
      [System.Management.Automation.Language.IfStatementAst] }, $true)) {
    $else = $i.ElseClause
    [pscustomobject]@{
      cond      = $i.Clauses[0].Item1.Extent.Text
      elseStart = $(if ($else) { $else.Extent.StartOffset } else { -1 })
      elseEnd   = $(if ($else) { $else.Extent.EndOffset } else { -1 })
      elseText  = $(if ($else) { $else.Extent.Text } else { '' })
    }
  })
  @($ifs) | ConvertTo-Json -Depth 4 -Compress
"""
    blocks = json.loads(_ok(_extract(_SCRIPT, [], body), tmp_path).strip().splitlines()[-1])
    if isinstance(blocks, dict):
        blocks = [blocks]
    optout = [b for b in blocks if "Service will run as LocalSystem" in (b["elseText"] or "")]
    assert len(optout) == 1, (
        "could not locate the -AllowLocalSystem opt-out branch by its warning text; found "
        f"{len(optout)} candidates"
    )
    facts = _preflight_facts(tmp_path)
    inside = [
        c
        for c in _objectname_calls(facts)
        if optout[0]["elseStart"] <= c["start"] < optout[0]["elseEnd"]
    ]
    assert inside, (
        "the -AllowLocalSystem branch does not CALL Set-ServiceAccount, so a rerun over a "
        "service already registered with another account leaves THAT account configured while the "
        "ACL block below strips its access (BACKLOG #1553)"
    )
    assert any("$RunAsObjectName" in c["text"] for c in inside), (
        "the opt-out branch must write the derived run-as value, not a literal: "
        f"{[c['text'] for c in inside]}"
    )


def test_the_acl_calls_never_receive_the_literal_localsystem(tmp_path: Path) -> None:
    """The nssm ObjectName value and the account needing an explicit ACL grant are DIFFERENT values.

    Set-SecureDataDirAcl already grants ``*S-1-5-18``, which IS LocalSystem; adding a named
    "LocalSystem" grant is redundant and can make icacls exit non-zero. Passing $RunAsObjectName to
    an ACL call is the collapse this guards against.
    """
    facts = _preflight_facts(tmp_path)
    for fn in _ACL_CALLS:
        for call in [c for c in facts["commands"] if _named(c, fn)]:
            assert "LocalSystem" not in call["text"], (
                f"{fn} is being handed a literal LocalSystem at line {call['line']}: {call['text']}"
            )
            assert "$RunAsObjectName" not in call["text"], (
                f"{fn} at line {call['line']} takes the nssm ObjectName value rather than the "
                f"ACL-grant account; the two must stay separate: {call['text']}"
            )
            assert "$ServiceAccount" in call["text"], (
                f"{fn} at line {call['line']} must take $ServiceAccount, which is EMPTY for the "
                f"LocalSystem opt-out: {call['text']}"
            )


def test_the_run_as_value_and_the_acl_account_are_separate_variables(tmp_path: Path) -> None:
    """$RunAsObjectName exists, is derived from $ServiceAccount, and does not overwrite it.

    Assigning "LocalSystem" back into $ServiceAccount would satisfy the ObjectName guards above and
    then feed the literal straight into all three ACL calls -- one variable answering two questions,
    which is the shape #1553 is made of.
    """
    facts = _preflight_facts(tmp_path)
    runas = [a for a in facts["assignments"] if a["lhs"] == "RunAsObjectName"]
    assert len(runas) == 1, f"expected exactly one $RunAsObjectName assignment, found {len(runas)}"
    assert "LocalSystem" in runas[0]["rhsText"], (
        "the run-as value must fall back to LocalSystem for the opt-out: " + runas[0]["rhsText"]
    )
    bad = [
        a
        for a in facts["assignments"]
        if a["lhs"] == "ServiceAccount" and "LocalSystem" in (a["rhsText"] or "")
    ]
    assert not bad, (
        f"$ServiceAccount is assigned LocalSystem at line(s) {[a['line'] for a in bad]}; it must "
        "stay EMPTY for the opt-out so the ACL calls add no redundant named grant"
    )


def test_all_three_acl_sites_are_still_wired(tmp_path: Path) -> None:
    """The row names the data dir. There are THREE: the data dir, and both config-dir paths.

    Repairing only the data dir leaves the still-configured account without READ on the config dir,
    and SEC-003 source-trust then stops the engine loading config at all.
    """
    facts = _preflight_facts(tmp_path)
    for fn in _ACL_CALLS:
        calls = [c for c in facts["commands"] if _named(c, fn)]
        assert len(calls) == 1, f"expected exactly one {fn} call, found {len(calls)}"


# --- the ACLs are written AFTER the run-as account is set (BACKLOG #1699, S4 ordering, #224) ---------
# The grants are written for $ServiceAccount, and they are right only while the service runs as that
# account (BACKLOG #1553), so they follow the call that makes it run as that account. The row says
# "after ObjectName"; the account is now set by Set-ServiceAccount through the SCM (BACKLOG #2364), so
# that is the call the order is pinned to. The virtual account NT SERVICE\<ServiceName> also resolves
# for icacls only once the service exists, and the service is registered before that call. The
# installer's own comment says the SID needs ObjectName too; that part is not what this guard rests on.
#
# THE RULE. Take the outermost if statement around each Set-ServiceAccount call, or the call itself
# where no if statement is around it. Every Set-SecureDataDirAcl, Set-SecureConfigAcl and
# Set-ConfigReadAcl call must start after the end of the last of those, and none of these calls may
# sit inside a function, whose body runs when it is called rather than where it is written. There must
# be at least one Set-ServiceAccount call and at least one call of each ACL function. Names match
# without regard to case, as PowerShell resolves them.
#
# The rule pins the installer's real shape: it sets the account in three places, all inside one run-as
# if/else, and locks down once, after that whole if/else. So a lockdown placed inside a run-as branch
# reads red BY DESIGN, even after that branch's own Set-ServiceAccount. So does one in any order
# inside an if statement that also wraps the run-as if, and that one is a FALSE red: a -WhatIf gate
# around the whole install body, account call first and lockdown after it, is in the right order and
# still reads red. The installer has no such gate today. Whoever adds one changes this rule in the
# same change, rather than reading the red as a wrong order. An ACL call nested in a
# Set-ServiceAccount argument sits inside that call, and reads red too. Only the ifs around a
# Set-ServiceAccount call are read. An if statement around no Set-ServiceAccount call changes
# nothing: the real Set-SecureConfigAcl sits in one after the run-as if, and a lockdown in one before
# it is simply earlier.
#
# It does NOT check, at least:
#   * code that runs more than once around both, such as a loop, a switch over several values or a
#     ForEach-Object block, where an earlier pass runs an ACL call written after a Set-ServiceAccount
#     that only a later pass runs. Inside such a loop, an ACL call in the same if as the account call,
#     or written before that if, reads red; one written after that if, still inside the loop, reads
#     green;
#   * a branch that is not an if statement. Only an if statement's extent is read, so an account call
#     in a try or catch block, a switch clause, either side of && or ||, a ternary operand, or the
#     right side of -and or -or counts as the call alone, and an ACL call written after it in the
#     same construct reads green;
#   * an exit, return or throw between the run-as if and the lockdown, which leaves the account set
#     and nothing locked;
#   * whether each run-as branch actually sets the account.
#     test_objectname_is_written_on_every_run_as_branch counts three calls, and
#     test_the_localsystem_optout_writes_objectname_rather_than_leaving_it places one in the opt-out
#     branch; neither places one in each named-account branch;
#   * a call that runs elsewhere than it is written: a stored scriptblock, a trap body,
#     Invoke-Expression, a computed command name.

_RUN_AS_ASSIGNMENT = "$RunAsObjectName = if ("
_NOT_AFTER = "is not after the whole run-as block"


def _acl_order_problems(facts: dict) -> list[str]:
    """Why the ACL calls in install-service.ps1 break the rule above."""
    accounts = _objectname_calls(facts)
    if not accounts:
        return ["no Set-ServiceAccount call sets the run-as account the ACLs name"]
    problems = [
        f"{c['name']} at line {c['line']} is inside a function, so its offset is not its run order"
        for c in facts["commands"]
        if c["inFunction"] and any(_named(c, n) for n in (*_ACL_CALLS, "Set-ServiceAccount"))
    ]
    last = max(accounts, key=lambda a: a["outerIfEnd"])
    for fn in _ACL_CALLS:
        calls = [c for c in facts["commands"] if _named(c, fn)]
        if not calls:
            problems.append(f"{fn} is not called")
        problems += [
            f"{fn} at line {c['line']} {_NOT_AFTER}: it starts before the end of the"
            f" Set-ServiceAccount at line {last['line']}, or of the outermost if statement around it"
            for c in calls
            if c["start"] < last["outerIfEnd"]
        ]
    return problems


def test_the_acls_are_written_after_the_run_as_account_is_set(tmp_path: Path) -> None:
    assert _acl_order_problems(_preflight_facts(tmp_path)) == []


def _rewrite(*edits: tuple[str, str]) -> Callable[[str], str]:
    """Replace each ``old`` with its ``new``, in order. Each ``old`` must be in the script once."""

    def mutate(source: str) -> str:
        for old, new in edits:
            assert source.count(old) == 1, f"CONTROL FAILED: {old!r} is not in the script once"
            source = source.replace(old, new)
        return source

    return mutate


def _hoist(call: str, wrap: str = "{call}") -> Callable[[str], str]:
    """Move ``call`` from where it stands to just above the run-as block, written as ``wrap``
    (with ``{call}`` in it)."""
    above = f"{wrap.format(call=call)}\n{_RUN_AS_ASSIGNMENT}"
    return _rewrite((call, ""), (_RUN_AS_ASSIGNMENT, above))


def _replace(call: str, template: str) -> Callable[[str], str]:
    """Rewrite ``call`` in place as ``template`` (with ``{call}`` in it)."""
    return _rewrite((call, template.format(call=call)))


_LOCKDOWN = "Set-SecureDataDirAcl -Path $DataDir -Account $ServiceAccount"
_CONFIG_LOCK = "Set-SecureConfigAcl -Path $LockPath -Account $ServiceAccount"
_CONFIG_READ = "Set-ConfigReadAcl -Path $Config -Account $ServiceAccount"
# The three run-as calls, each anchored so that it is in the script once.
_ACCOUNT_CALL = "Set-ServiceAccount -ServiceName $ServiceName -Account $RunAsObjectName"
_PASSWORD_CALL = f"{_ACCOUNT_CALL} -Password $ServiceAccountPassword"
_NO_PASSWORD_CALL = f"        {_ACCOUNT_CALL}\n    }}\n"
_LOCALSYSTEM_CALL = f"\n    {_ACCOUNT_CALL}\n"
_NAMED_BRANCH_END = '    Write-Host "  Account: $RunAsObjectName" -ForegroundColor Green\n'


def _after(anchor: str, line: str) -> tuple[str, str]:
    return anchor, f"{anchor}{line}\n"


def _then(mutate: Callable[[str], str], line: str) -> Callable[[str], str]:
    """``mutate``, then ``line`` appended as the script's last top-level statement."""
    return lambda source: f"{mutate(source)}\n{line}\n"


def _commented(call: str) -> tuple[str, str]:
    return call, call.replace(_ACCOUNT_CALL, f"# {_ACCOUNT_CALL}")


_ORDER_MUTATIONS = [
    pytest.param(
        _hoist(_LOCKDOWN), ("Set-SecureDataDirAcl at line", _NOT_AFTER), id="lockdown-hoisted"
    ),
    pytest.param(
        _hoist(_CONFIG_LOCK),
        ("Set-SecureConfigAcl at line", _NOT_AFTER),
        id="config-lock-hoisted",
    ),
    pytest.param(
        _hoist(_CONFIG_READ),
        ("Set-ConfigReadAcl at line", _NOT_AFTER),
        id="config-read-hoisted",
    ),
    # $null, not a comment: the read call shares its line with the closing brace of its if.
    pytest.param(
        _replace(_LOCKDOWN, "$null"),
        ("Set-SecureDataDirAcl is not called",),
        id="lockdown-deleted",
    ),
    pytest.param(
        _replace(_CONFIG_LOCK, "$null"),
        ("Set-SecureConfigAcl is not called",),
        id="config-lock-deleted",
    ),
    pytest.param(
        _replace(_CONFIG_READ, "$null"),
        ("Set-ConfigReadAcl is not called",),
        id="config-read-deleted",
    ),
    pytest.param(
        _replace(_LOCKDOWN, "function Invoke-Lockdown {{ {call} }}"),
        ("Set-SecureDataDirAcl at line", "is inside a function"),
        id="lockdown-in-a-function",
    ),
    # The in-function check reads the account calls as well as the ACL calls.
    pytest.param(
        _replace(_PASSWORD_CALL, "function Invoke-RunAs {{ {call} }}"),
        ("Set-ServiceAccount at line", "is inside a function"),
        id="account-call-in-a-function",
    ),
    # Red BY DESIGN: after its own branch's account, yet inside the run-as if/else.
    pytest.param(
        _rewrite((_LOCKDOWN, "$null"), _after(_NAMED_BRANCH_END, f"    {_LOCKDOWN}")),
        ("Set-SecureDataDirAcl at line", _NOT_AFTER),
        id="lockdown-moved-into-a-run-as-branch",
    ),
    # With no account call in the else, only the OUTERMOST if puts this lockdown inside: the
    # innermost if around each remaining call ends above it.
    pytest.param(
        _rewrite(
            _commented(_LOCALSYSTEM_CALL),
            (_LOCKDOWN, "$null"),
            _after(_NAMED_BRANCH_END, f"    {_LOCKDOWN}"),
        ),
        ("Set-SecureDataDirAcl at line", _NOT_AFTER),
        id="lockdown-in-the-named-branch-with-no-account-in-the-else",
    ),
    pytest.param(
        _rewrite(
            (_LOCKDOWN, "$null"),
            _after(_NAMED_BRANCH_END, f"    {_LOCKDOWN}"),
            _after(_LOCALSYSTEM_CALL, f"    {_LOCKDOWN}"),
        ),
        ("Set-SecureDataDirAcl at line", _NOT_AFTER),
        id="lockdown-moved-into-each-run-as-branch",
    ),
    # Red BY DESIGN: in order, but inside an if that also wraps the run-as if.
    pytest.param(
        _rewrite(
            (_RUN_AS_ASSIGNMENT, f"if ($true) {{\n{_RUN_AS_ASSIGNMENT}"),
            (_LOCKDOWN, f"{_LOCKDOWN}\n}}"),
        ),
        ("Set-SecureDataDirAcl at line", _NOT_AFTER),
        id="lockdown-and-run-as-if-in-one-wrapping-if",
    ),
    pytest.param(
        _hoist(_LOCKDOWN, "if ($LockConfigDir) {{ {call} }}"),
        ("Set-SecureDataDirAcl at line", _NOT_AFTER),
        id="lockdown-in-an-unrelated-if-before-the-run-as-if",
    ),
    # At top level, so only the account call's own END puts the lockdown inside it.
    pytest.param(
        _then(
            _replace(_LOCKDOWN, "$null"),
            _ACCOUNT_CALL.replace("$RunAsObjectName", f"({_LOCKDOWN})"),
        ),
        ("Set-SecureDataDirAcl at line", _NOT_AFTER),
        id="lockdown-in-a-run-as-argument",
    ),
    pytest.param(
        _replace(
            _LOCKDOWN,
            "foreach ($step in 'acl', 'account') {{ if ($step -eq 'acl') {{ {call} }}"
            f" else {{{{ {_ACCOUNT_CALL} }}}} }}}}",
        ),
        ("Set-SecureDataDirAcl at line", _NOT_AFTER),
        id="lockdown-and-account-in-one-loop",
    ),
    pytest.param(
        _rewrite(*map(_commented, (_PASSWORD_CALL, _NO_PASSWORD_CALL, _LOCALSYSTEM_CALL))),
        ("no Set-ServiceAccount call sets the run-as account the ACLs name",),
        id="no-set-serviceaccount",
    ),
    # A second lockdown, spelled in lower case, above the run-as block. PowerShell runs it.
    pytest.param(
        _rewrite((_RUN_AS_ASSIGNMENT, f"{_LOCKDOWN.lower()}\n{_RUN_AS_ASSIGNMENT}")),
        ("Set-SecureDataDirAcl at line", _NOT_AFTER),
        id="early-call-in-lower-case",
    ),
    # A further account call after every ACL call: the order swapped from the other side.
    pytest.param(_then(_rewrite(), _ACCOUNT_CALL), (_NOT_AFTER,), id="account-set-last"),
]


@pytest.fixture(scope="module")
def order_guard_facts(tmp_path_factory: pytest.TempPathFactory) -> dict[object, dict]:
    """The facts of every changed copy in ``_ORDER_MUTATIONS``, keyed by its mutation, read in one
    process.

    A mutation that raises, its CONTROL assertion or any other error, yields ``{"error": ...}``
    for its own arm alone.
    """
    assert _SCRIPT is not None
    source = _SCRIPT.read_text(encoding="utf-8")
    tmp = tmp_path_factory.mktemp("order-guard")
    facts: dict[object, dict] = {}
    copies: dict[object, Path] = {}
    for n, arm in enumerate(_ORDER_MUTATIONS):
        mutate = arm.values[0]
        assert callable(mutate)
        try:
            text = mutate(source)
        except Exception as exc:  # noqa: BLE001 - reported on its own arm, below
            facts[mutate] = {"error": f"{type(exc).__name__}: {exc}"}
            continue
        copies[mutate] = tmp / f"install-service-{n}.ps1"
        copies[mutate].write_text(text, encoding="utf-8")
    facts.update(zip(copies, _preflight_facts_many(tmp, list(copies.values())), strict=True))
    return facts


# One process reads every arm's copy, and its time is charged to the first arm's setup.
@pytest.mark.timeout(240)
@pytest.mark.parametrize(("mutate", "expect"), _ORDER_MUTATIONS)
def test_the_acl_order_guard_fails_when_the_order_is_broken(
    order_guard_facts: dict[object, dict],
    mutate: Callable[[str], str],
    expect: tuple[str, ...],
) -> None:
    """THE CONTROL. Each mutation (``mutate``, applied by the fixture) breaks the order, or the
    call, in a copy of the script, and the guard must then name it, in one problem carrying every
    part of ``expect``. A guard that cannot fail would pass on a script that locks nothing."""
    facts = order_guard_facts[mutate]
    assert "error" not in facts, facts["error"]
    problems = _acl_order_problems(facts)
    assert any(all(part in p for part in expect) for p in problems), problems


def test_a_script_that_does_not_parse_is_refused_not_read(tmp_path: Path) -> None:
    """``ParseFile`` returns a partial tree for a file it cannot parse, and a guard reading that
    tree passes on whatever calls survived. The harness throws instead, naming the error."""
    broken = tmp_path / "install-service.ps1"
    broken.write_text(_script_text() + "\nif ($true) {\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="does not parse"):
        _preflight_facts(tmp_path, script=broken)
    assert _preflight_facts(tmp_path)["commands"], "CONTROL: the real installer parses and is read"


# --- the uninstaller's inventory of what it leaves (BACKLOG #1704) --------------------------------
# It printed one line: "Logs and the message store were left in place." That is a COMPLETENESS
# CLAIM, and the host disagrees with it in at least six places -- the SeServiceLogonRight grant, the
# run-as account's entry on the DATA dir, the same account's entry on the CONFIG dir, the
# inheritance strip on the data dir (and on the config dir under -LockConfigDir, with its owner
# moved to Administrators), the cached bin\nssm.exe, and the machine-wide WER keys that
# -SuppressCrashDumps writes. docs/SERVICE.md and docs/USER-GUIDE.md repeated the same claim.
#
# THE ROW NAMES FOUR. The data-directory entry and the WER keys are the two it does not, and the
# arms below cover all six -- an enumeration in a row is not a specification (SDS-3.6).
#
# THE NOTICE RETURNS LINES RATHER THAN PRINTING THEM, which is what makes these behavioural. A scan
# over the script's TEXT cannot tell a message from the comment that explains it: the function's own
# docstring quotes the sentence it replaced.
#
# EVERY ARM CARRIES ITS OWN NEGATIVE. A notice that hard-coded all six lines would satisfy any "does
# it mention X" test, so each fact is dropped in turn and the matching line must DISAPPEAR while the
# others stay. The unconditional data-directory line has no fact to drop, so it gets the literal
# control instead: its emitting statement is deleted from a copy of the script and the guard must go
# red.

_UNINSTALL_FNS = [
    "Get-ConfigDirFromAppParameters",
    # Get-AccountResidueSpec holds the ONE rule for "does this account carry a residue, and how is it
    # spelled for icacls", shared by the notice and by -RemoveAccountAces. The notice calls it, so it
    # has to be dot-sourced alongside.
    "Get-AccountResidueSpec",
    "Get-UninstallResidueNotice",
]

_FULL_FACTS: dict[str, object] = {
    "ServiceName": "MessageFoundry",
    "DataDir": r"C:\ProgramData\MessageFoundry",
    "ServiceAccount": r"NT SERVICE\MessageFoundry",
    "ServiceAccountSid": "S-1-5-80-4001",
    "ConfigDir": r"D:\mefor\config",
    "SecretsDir": r"C:\ProgramData\MessageFoundry-secrets",
    "ConfigInheritanceStripped": True,
    "CachedNssm": r"C:\ProgramData\MessageFoundry\bin\nssm.exe",
    "WerImages": ["messagefoundry.exe", "python.exe"],
}

# One needle per residue, each chosen to appear on that residue's line and nowhere else -- which is
# what lets the drop-the-fact arms distinguish "this line went" from "the notice emptied".
_NEEDLE = {
    "data_dir": "Data directory",
    "cached_nssm": r"bin\nssm.exe",
    "data_ace": "Data dir entry",
    "config_ace": "Config dir entry",
    "secrets_dir": "Secrets dir ",
    "secrets_ace": "Secrets entry",
    "logon_right": "Log on as a service",
    "config_inheritance": "/inheritance:e",
    "wer": "Windows Error Reporting",
}


def _ps_arg(name: str, value: object) -> str:
    """One PowerShell named argument.

    A [switch] takes the COLON form. Written ``-Name $true`` the value binds positionally instead
    and the switch stays off, so every boolean arm would silently test the same fact set.
    """
    if isinstance(value, bool):
        return f"-{name}:" + ("$true" if value else "$false")
    if isinstance(value, (list, tuple)):
        return f"-{name} @(" + ", ".join(_psq(str(v)) for v in value) + ")"
    return f"-{name} {_psq(str(value))}"


def _notice(tmp_path: Path, facts: dict[str, object], *, script: Path | None = None) -> str:
    """Run Get-UninstallResidueNotice over one fact set and return its lines as one string.

    ``Out-String -Width`` rather than bare output: the host wraps at the console width when stdout
    is redirected, and a wrapped icacls command would fail an assertion for a reason that has
    nothing to do with the notice.
    """
    path = script if script is not None else _UNINSTALL
    assert path is not None
    args = " ".join(_ps_arg(k, v) for k, v in facts.items())
    body = f"  @(Get-UninstallResidueNotice {args}) | Out-String -Width 500\n"
    return _ok(_extract(path, _UNINSTALL_FNS, body), tmp_path)


def test_the_notice_names_every_residue_the_installer_leaves(tmp_path: Path) -> None:
    """All six, with the command an operator can act on -- not "logs and the store"."""
    text = _notice(tmp_path, _FULL_FACTS)
    for residue, needle in _NEEDLE.items():
        assert needle in text, (
            f"the uninstall notice does not name the {residue} residue ({needle!r}); an operator "
            f"would believe the host was back to its pre-install state:\n{text}"
        )
    # Naming a leftover without a way to clear it is half an inventory.
    assert 'icacls "C:\\ProgramData\\MessageFoundry" /remove:g' in text, (
        f"the notice must give the command that removes the data-dir entry:\n{text}"
    )
    assert 'icacls "D:\\mefor\\config" /remove:g' in text, (
        f"the notice must give the command that removes the config-dir entry:\n{text}"
    )
    assert "-RemoveLogonRight" in text, (
        f"the notice must point at the switch that clears the logon right:\n{text}"
    )
    assert "left in place" not in text.lower(), (
        f"the completeness claim this row is about is back in the notice:\n{text}"
    )


@pytest.mark.parametrize(
    ("dropped", "gone", "kept"),
    [
        # Drop the cached binary: only the NSSM line goes.
        ({"CachedNssm": ""}, ["cached_nssm"], ["data_dir", "data_ace", "logon_right", "wer"]),
        # A LocalSystem install was never given a named grant or the logon right, so all three
        # account residues go -- and nothing else may go with them.
        (
            {"ServiceAccount": "LocalSystem", "ServiceAccountSid": ""},
            ["data_ace", "config_ace", "secrets_ace", "logon_right"],
            ["data_dir", "cached_nssm", "config_inheritance", "wer", "secrets_dir"],
        ),
        # No config dir could be read off the registration: its two lines go, the data dir's stay.
        (
            {"ConfigDir": ""},
            ["config_ace", "config_inheritance"],
            ["data_dir", "data_ace", "logon_right", "wer"],
        ),
        # Inheritance measured intact: the -LockConfigDir line goes, the config ENTRY line stays.
        (
            {"ConfigInheritanceStripped": False},
            ["config_inheritance"],
            ["config_ace", "data_ace", "logon_right"],
        ),
        # No secrets directory was registered: its two lines go, the rest stay.
        (
            {"SecretsDir": ""},
            ["secrets_dir", "secrets_ace"],
            ["data_dir", "data_ace", "config_ace"],
        ),
        # No image is excluded, so this host never ran -SuppressCrashDumps.
        ({"WerImages": []}, ["wer"], ["data_dir", "data_ace", "config_ace"]),
    ],
)
def test_each_line_is_driven_by_a_measured_fact(
    tmp_path: Path, dropped: dict[str, object], gone: list[str], kept: list[str]
) -> None:
    """THE NEGATIVE CONTROL FOR THE ARM ABOVE.

    A notice that printed all six lines unconditionally would pass every "does it name X" check and
    would send an operator after an entry that is not there. So each fact is dropped in turn: its
    line must disappear, and the ``kept`` set must survive -- which is what stops a "fix" that
    simply empties the notice from passing.
    """
    facts = dict(_FULL_FACTS)
    facts.update(dropped)
    text = _notice(tmp_path, facts)
    for residue in gone:
        assert _NEEDLE[residue] not in text, (
            f"dropping {sorted(dropped)} left the {residue} line in place ({_NEEDLE[residue]!r}), "
            f"so the notice reports a residue nobody measured:\n{text}"
        )
    for residue in kept:
        assert _NEEDLE[residue] in text, (
            f"dropping {sorted(dropped)} also removed the {residue} line, which it has nothing to "
            f"do with:\n{text}"
        )


def test_the_residue_guard_reddens_when_a_line_is_deleted(tmp_path: Path) -> None:
    """THE LITERAL FALSIFIABILITY CONTROL, for the one line no fact can switch off.

    The data-directory residue is unconditional -- the installer always locks that directory -- so
    the drop-a-fact arms cannot reach it. Delete its emitting statement from a COPY of the script
    and the guard must go red. A guard over a list of strings is exactly the kind that passes
    because some other line happens to carry the same words.
    """
    assert _UNINSTALL is not None
    source = _UNINSTALL.read_text(encoding="utf-8")
    emit = '    $lines += "  Data directory   $DataDir"'
    assert source.count(emit) == 1, (
        "the data-directory line is no longer emitted by exactly one statement, so this control "
        "cannot aim at it -- re-point it before trusting the arms above"
    )
    mutated = tmp_path / "uninstall-mutated.ps1"
    mutated.write_text(source.replace(emit, ""), encoding="utf-8")

    text = _notice(tmp_path, _FULL_FACTS, script=mutated)
    assert _NEEDLE["data_dir"] not in text, (
        "deleting the data-directory statement did NOT change the notice, so the assertion that "
        f"the notice names it is satisfied by some other line:\n{text}"
    )
    # The mutation must be surgical, or the control proves only that a broken function prints less.
    assert _NEEDLE["logon_right"] in text, (
        f"the mutated copy stopped rendering the rest of the notice too:\n{text}"
    )


def test_a_cleared_residue_is_reported_as_cleared_not_as_remaining(tmp_path: Path) -> None:
    """-RemoveLogonRight / -RemoveAccountAces change the HOST, so they must change the report.

    A notice that still told an operator to run the icacls command after this script had already
    run it is the same defect pointing the other way.
    """
    facts = dict(_FULL_FACTS)
    facts.update(
        {
            "LogonRightRemoved": True,
            "DataAceRemoved": True,
            "ConfigAceRemoved": True,
            "SecretsAceRemoved": True,
        }
    )
    text = _notice(tmp_path, facts)
    assert text.count("REMOVED") >= 4, (
        f"the notice must report what this run actually took back:\n{text}"
    )
    assert "/remove:g" not in text, (
        f"the notice still tells the operator to remove entries this run already removed:\n{text}"
    )
    assert "-RemoveLogonRight" not in text, (
        f"the notice still offers the switch that has just run:\n{text}"
    )
    # The residues the switches do NOT touch must survive, or "cleared" has become "silent".
    assert _NEEDLE["config_inheritance"] in text and _NEEDLE["wer"] in text, (
        f"clearing the two reversible residues hid the ones that remain:\n{text}"
    )


def test_the_commands_name_the_sid_when_one_was_resolved(tmp_path: Path) -> None:
    """A deleted service's virtual account no longer translates, so icacls refuses its NAME.

    The SID was resolved before the registration went; the printed command has to use it. Falling
    back to the name is right only when nothing resolved, and it is still the best available.
    """
    with_sid = _notice(tmp_path, _FULL_FACTS)
    assert '/remove:g "*S-1-5-80-4001"' in with_sid, (
        f"the removal command must use the SID spelling that still resolves:\n{with_sid}"
    )
    facts = dict(_FULL_FACTS)
    facts["ServiceAccountSid"] = ""
    without = _notice(tmp_path, facts)
    assert '/remove:g "NT SERVICE\\MessageFoundry"' in without, (
        f"with no SID the command must still name the account, not an empty principal:\n{without}"
    )
    assert '/remove:g ""' not in without, (
        f"an unresolved SID produced a command with no principal at all:\n{without}"
    )


def test_a_read_that_failed_is_named_rather_than_silently_shortening_the_list(
    tmp_path: Path,
) -> None:
    """SDS-3.6. The defect being fixed is a completeness claim, so its replacement must not make
    one: a notice built from reads that failed is SHORTER, and a shorter list looks exactly like a
    cleaner host."""
    facts = dict(_FULL_FACTS)
    facts["Unreadable"] = ["the run-as account of 'MessageFoundry' (access denied)"]
    text = _notice(tmp_path, facts)
    assert "could NOT read" in text, (
        f"a failed read must be declared, not absorbed into a shorter list:\n{text}"
    )
    assert "the run-as account of 'MessageFoundry' (access denied)" in text, (
        f"the notice must name WHAT it could not read:\n{text}"
    )
    clean = _notice(tmp_path, _FULL_FACTS)
    assert "could NOT read" not in clean, (
        f"the caution block fires when nothing failed, so it carries no information:\n{clean}"
    )


@pytest.mark.parametrize(
    ("parameters", "expected"),
    [
        (
            r'serve --config "C:\repo\samples\config" --db "C:\d\m.db" --env prod',
            r"C:\repo\samples\config",
        ),
        (r'serve --config "D:\path with spaces\cfg" --port 8765', r"D:\path with spaces\cfg"),
        (r"serve --config C:\bare\cfg --env dev", r"C:\bare\cfg"),
        (r'serve --db "C:\d\m.db" --env prod', ""),
        ("", ""),
    ],
)
def test_the_config_dir_is_read_back_off_the_registration(
    tmp_path: Path, parameters: str, expected: str
) -> None:
    """The uninstaller takes no -Config, so the only way to NAME the directory holding an orphaned
    entry is the command line NSSM stored -- and only before the registration is deleted.

    An absent --config yields an empty string rather than a guessed default: naming a directory
    that may have nothing to do with this install is worse than saying nothing.
    """
    assert _UNINSTALL is not None
    body = f"  Get-ConfigDirFromAppParameters -AppParameters {_psq(parameters)}\n"
    got = _ok(_extract(_UNINSTALL, _UNINSTALL_FNS, body), tmp_path).strip()
    assert got == expected, f"parsed {got!r} from {parameters!r}, expected {expected!r}"


def test_the_facts_are_read_before_the_registration_is_removed(tmp_path: Path) -> None:
    """ORDER IS THE DEFECT HERE, the way it was in #1554.

    Every fact the notice needs dies with the registration: the run-as account and the command line
    live in the service's registry key, which ``nssm remove`` deletes. A read moved below the
    removal returns nothing and renders an EMPTY inventory -- indistinguishable from a clean host.
    """
    assert _UNINSTALL is not None
    body = """
  $cmds = @(foreach ($c in $ast.FindAll({ $args[0] -is
      [System.Management.Automation.Language.CommandAst] }, $true)) {
    [pscustomobject]@{ name = $c.GetCommandName(); start = $c.Extent.StartOffset
                       line = $c.Extent.StartLineNumber; text = $c.Extent.Text }
  })
  @($cmds) | ConvertTo-Json -Depth 4 -Compress
"""
    cmds = json.loads(_ok(_extract(_UNINSTALL, [], body), tmp_path).strip().splitlines()[-1])
    if isinstance(cmds, dict):
        cmds = [cmds]
    removals = [
        c
        for c in cmds
        if (c["name"] or "").endswith("sc.exe") or "remove $ServiceName confirm" in c["text"]
    ]
    assert removals, (
        "CONTROL FAILED: neither the nssm removal nor the sc.exe fallback was located, so an "
        "ordering result here would mean nothing"
    )
    first_removal = min(c["start"] for c in removals)
    reads = [c for c in cmds if c["name"] in ("Get-ItemProperty", "Get-ConfigDirFromAppParameters")]
    assert reads, "nothing reads the registration before it is removed"
    late = [c for c in reads if c["start"] > first_removal]
    assert not late, (
        f"the registration is read at line(s) {[c['line'] for c in late]}, AFTER it has been "
        "removed -- those reads return nothing and the notice renders empty"
    )


# --- the two switches issue the reverse operations (BACKLOG #1704) --------------------------------
# WHAT THESE PROVE AND WHAT THEY DO NOT. secedit and icacls are SHADOWED, so these arms witness the
# command the script ISSUES and the policy file it writes. They say nothing about whether Windows
# accepts either: both need elevation, and the uninstaller's own Administrator guard means no
# unelevated runner can reach the real thing. Read them as "the reverse operation is correctly
# formed", never as "the right was removed". The end-to-end half belongs to windows-service-smoke.

_SECEDIT_FN = "Remove-ServiceLogonRight"
_ACE_FN = "Remove-AccountAce"

_OTHER_SID = "S-1-5-80-400"  # a STRING PREFIX of S-1-5-80-4001, deliberately


_WORKDIR_FN = "New-SeceditWorkDirectory"


def _workdir_seam(parent: Path) -> str:
    """Point New-SeceditWorkDirectory at ``parent``, owned by the test's own account.

    On Windows the REAL helper runs, wrapped so it makes the folder under ``parent`` and owns it
    as this unelevated account rather than as Administrators, which only an elevated token may
    name as an owner. Elsewhere there are no Windows ACLs to set, so a plain folder stands in.
    """
    if sys.platform.startswith("win"):
        return rf"""
  $script:RealWorkDir = ${{function:{_WORKDIR_FN}}}
  $script:WorkOwner = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  function {_WORKDIR_FN} {{ & $script:RealWorkDir -Parent {_psq(str(parent))} -OwnerSid $script:WorkOwner `
    -CheckedUpTo {_psq(str(parent.parent))} }}
"""
    return rf"""
  function {_WORKDIR_FN} {{
    $d = Join-Path {_psq(str(parent))} ([guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $d | Out-Null
    $d
  }}
"""


def _logon_right_arms(
    tmp_path: Path, *, holders: list[str], sid: str, workdir: str | None = None
) -> dict:
    """Run Remove-ServiceLogonRight against a stubbed secedit whose policy holds ``holders``.

    ``workdir`` replaces the New-SeceditWorkDirectory seam; by default it is the real helper on
    Windows. At the configure call the stub reads the folder the policy file sits in, so the
    arms can say who could have changed that file before secedit imported it.
    """
    assert _UNINSTALL is not None
    parent = tmp_path / "secedit-parent"
    parent.mkdir(exist_ok=True)
    inf = ["[Unicode]", "Unicode=yes", "[Privilege Rights]"]
    if holders:
        inf.append("SeServiceLogonRight = " + ",".join(holders))
    inf.append("[Version]")
    inf_ps = "@(" + ", ".join(_psq(line) for line in inf) + ")"
    body = rf"""
  # The old code wrote its export here; set so a regression to it lands in the test's own folder.
  $env:TEMP = {_psq(str(tmp_path))}
{_workdir_seam(parent) if workdir is None else workdir}
  $script:Configured = ''
  $script:ConfigureCalls = 0
  $script:ExportCalls = 0
  $script:Cfg = ''
  $script:Db = ''
  $script:Folder = $null
  function secedit {{
    $a = @($args)
    $i = [array]::IndexOf($a, '/cfg')
    $script:Cfg = $a[$i + 1]
    if ($a -contains '/export') {{
      $script:ExportCalls++
      Set-Content -LiteralPath $script:Cfg -Value {inf_ps} -Encoding Unicode
    }} elseif ($a -contains '/configure') {{
      $script:ConfigureCalls++
      $script:Configured = ((Get-Content -LiteralPath $script:Cfg) -join ' | ')
      $script:Db = $a[[array]::IndexOf($a, '/db') + 1]
      $dir = Split-Path -Parent $script:Cfg
      if ($IsWindows -or $env:OS -eq 'Windows_NT') {{
        $acl = Get-Acl -LiteralPath $dir
        $script:Folder = [ordered]@{{
          path = $dir
          owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
          protected = $acl.AreAccessRulesProtected
          reparse = [bool]((Get-Item -LiteralPath $dir -Force).Attributes -band
            [System.IO.FileAttributes]::ReparsePoint)
          sids = @($acl.Access | Where-Object {{ $_.AccessControlType -eq 'Allow' }} |
            ForEach-Object {{ $_.IdentityReference.Translate(
              [Security.Principal.SecurityIdentifier]).Value }})
        }}
      }}
    }}
    $global:LASTEXITCODE = 0
  }}
  $warnings = @()
  $said = @()
  $result = $null
  $outputs = 0
  $emitted = & {{ {_SECEDIT_FN} -Account 'NT SERVICE\MessageFoundry' -Sid {_psq(sid)} }} 3>&1 6>&1
  foreach ($o in @($emitted)) {{
    if ($o -is [System.Management.Automation.WarningRecord]) {{ $warnings += "$o" }}
    elseif ($o -is [System.Management.Automation.InformationRecord]) {{ $said += "$o" }}
    else {{ $result = $o; $outputs++ }}
  }}
  [pscustomobject]@{{
    result = [bool]$result; outputs = $outputs; warnings = @($warnings); said = @($said)
    unproven = [bool]$script:LogonRightUnproven
    exportCalls = $script:ExportCalls; configureCalls = $script:ConfigureCalls
    configured = $script:Configured; cfg = $script:Cfg; db = $script:Db; folder = $script:Folder
    left = @(Get-ChildItem -LiteralPath {_psq(str(parent))} -Force | ForEach-Object {{ $_.Name }})
    me = $(if ($IsWindows -or $env:OS -eq 'Windows_NT') {{
      [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }} else {{ '' }})
  }} | ConvertTo-Json -Depth 4 -Compress
"""
    parsed: dict = json.loads(
        _ok(_extract(_UNINSTALL, [_SECEDIT_FN, _WORKDIR_FN], body), tmp_path)
        .strip()
        .splitlines()[-1]
    )
    parsed["warnings"] = [w for w in (parsed.get("warnings") or []) if w]
    parsed["said"] = [s for s in (parsed.get("said") or []) if s]
    return parsed


def test_the_logon_right_switch_rewrites_the_policy_without_the_accounts_sid(
    tmp_path: Path,
) -> None:
    """The reverse of install-service.ps1's grant: the SID leaves the row, the other holders stay."""
    got = _logon_right_arms(
        tmp_path,
        holders=["*S-1-5-80-4001", "*S-1-5-32-544", f"*{_OTHER_SID}"],
        sid="S-1-5-80-4001",
    )
    assert got["exportCalls"] == 1, "the current policy must be exported before it is rewritten"
    assert got["configureCalls"] == 1, (
        "the rewritten policy must be re-imported with secedit /configure; got "
        f"{got['configureCalls']} calls"
    )
    assert got["result"] is True, (
        f"a successful removal must report True; warnings were {got['warnings']}"
    )
    assert got["outputs"] == 1, (
        f"the helper must return ONE boolean; {got['outputs']} objects means a caller assigning it "
        "holds an array, and `if (-not $x)` on an array is false however the call went"
    )
    assert "*S-1-5-80-4001" not in got["configured"], (
        f"the account's SID survived the rewrite:\n{got['configured']}"
    )
    # POSITIVE CONTROL: emptying the row would satisfy the assertion above and strip the right from
    # every service on the host.
    assert "*S-1-5-32-544" in got["configured"], (
        f"another holder was dropped along with the account:\n{got['configured']}"
    )
    assert f"*{_OTHER_SID}" in got["configured"], (
        "a SID that is a STRING PREFIX of the removed one was dropped too -- the row must be "
        f"matched by exact token, not by substring:\n{got['configured']}"
    )


def test_the_logon_right_switch_refuses_to_empty_the_right_for_everyone(tmp_path: Path) -> None:
    """The sole-holder case. Writing back an empty SeServiceLogonRight takes the right from every
    account the row covers, which is a far larger change than the one asked for."""
    got = _logon_right_arms(tmp_path, holders=["*S-1-5-80-4001"], sid="S-1-5-80-4001")
    assert got["result"] is False, "the sole-holder case must not report a successful removal"
    assert got["configureCalls"] == 0, (
        "the policy was re-imported with an EMPTY SeServiceLogonRight, which takes the right away "
        "from every service on the host"
    )
    assert any("ONLY account" in w for w in got["warnings"]), (
        f"the refusal must say why, or it reads as a silent failure; got {got['warnings']}"
    )


def test_the_logon_right_switch_removes_the_account_written_by_its_name(tmp_path: Path) -> None:
    """The installer counts a holder written as the account's name as held (BACKLOG #5401), so
    the removal must take that name out too, or it reports 'does not hold' and leaves the right."""
    got = _logon_right_arms(
        tmp_path, holders=["*S-1-5-32-545", "NT SERVICE\\MessageFoundry"], sid="S-1-5-80-4001"
    )
    assert got["result"] is True, got
    assert "SeServiceLogonRight = *S-1-5-32-545 |" in got["configured"], got["configured"]


@_windows_only
def test_the_logon_right_switch_removes_a_name_that_resolves_to_the_sid(tmp_path: Path) -> None:
    # BUILTIN\Administrators resolves to S-1-5-32-544 on an English-language Windows host (a
    # localized host names the group differently); BUILTIN\Users does not, and must stay.
    got = _logon_right_arms(
        tmp_path, holders=["BUILTIN\\Users", "BUILTIN\\Administrators"], sid="S-1-5-32-544"
    )
    assert got["result"] is True, got
    assert "SeServiceLogonRight = BUILTIN\\Users |" in got["configured"], got["configured"]


def test_a_right_the_account_does_not_hold_is_a_no_op(tmp_path: Path) -> None:
    """POSITIVE CONTROL the other way: nothing is rewritten when there is nothing to remove, so a
    re-run cannot disturb a host it already cleaned."""
    got = _logon_right_arms(tmp_path, holders=["*S-1-5-32-544"], sid="S-1-5-80-4001")
    assert got["result"] is False, "reporting a removal that did not happen is the #1704 shape"
    assert got["configureCalls"] == 0, "the policy must not be rewritten when nothing changes"


def _grant_configured(
    tmp_path: Path, row: str | None, *, configure_runs: bool = True, section: bool = True
) -> str:
    """The policy install-service.ps1's Set-ServiceLogonRight hands ``secedit /configure`` when the
    export holds ``row`` (``None``: no SeServiceLogonRight row at all), granting the right to
    BUILTIN\\Administrators (S-1-5-32-544). secedit is a stub; nothing is configured.

    With ``configure_runs=False`` the configure call sets no exit code, as a command that never
    ran, and what the function said is returned instead of the policy."""
    runs = "$true" if configure_runs else "$false"
    assert _SCRIPT is not None
    parent = tmp_path / "grant-parent"
    parent.mkdir(exist_ok=True)
    inf = ["[Unicode]", "Unicode=yes", *(["[Privilege Rights]"] if section else [])]
    if row is not None:
        inf.append(row)
    inf.append("[Version]")
    inf_ps = "@(" + ", ".join(_psq(line) for line in inf) + ")"
    body = rf"""
{_workdir_seam(parent)}
  $script:Configured = ''
  function secedit {{
    $a = @($args)
    $cfg = $a[[array]::IndexOf($a, '/cfg') + 1]
    if ($a -contains '/export') {{ Set-Content -LiteralPath $cfg -Value {inf_ps} -Encoding Unicode }}
    elseif ($a -contains '/configure') {{
      $script:Configured = ((Get-Content -LiteralPath $cfg) -join ' | ')
      if (-not {runs}) {{ return }}
    }}
    $global:LASTEXITCODE = 0
  }}
  $said = @(Set-ServiceLogonRight -Account 'BUILTIN\Administrators' 3>&1 6>&1 |
    ForEach-Object {{ "$_" }})
  if ({runs}) {{ 'OUT=' + $script:Configured }} else {{ 'OUT=' + ($said -join ' / ') }}
"""
    out = _ok(_extract(_SCRIPT, ["Set-ServiceLogonRight", _WORKDIR_FN], body), tmp_path)
    return out.strip().splitlines()[-1].removeprefix("OUT=")


@_windows_only
@pytest.mark.parametrize(
    "row", ["SeServiceLogonRight =", "SeServiceLogonRight =   ", "SeServiceLogonRight = ,"]
)
def test_the_grant_to_an_empty_exported_row_has_no_leading_comma(tmp_path: Path, row: str) -> None:
    """BACKLOG #5401: an exported SeServiceLogonRight row can be present and empty. Appending
    ``,*SID`` to it wrote a value that starts with a comma."""
    configured = _grant_configured(tmp_path, row)
    assert "SeServiceLogonRight = *S-1-5-32-544 |" in configured, configured
    assert "=," not in configured.replace(" ", ""), configured


@_windows_only
def test_the_grant_keeps_every_holder_and_a_dollar_in_a_held_name(tmp_path: Path) -> None:
    """POSITIVE CONTROL for the row above: a row with holders keeps them, in order, with the SID
    appended, and a ``$`` in a held account name is written as itself. ``$0`` and ``$&`` are
    what a regex replacement would expand into the whole matched row."""
    configured = _grant_configured(
        tmp_path, "SeServiceLogonRight = *S-1-5-80-4001,CONTOSO\\svc$0,CONTOSO\\svc$&"
    )
    want = "SeServiceLogonRight = *S-1-5-80-4001,CONTOSO\\svc$0,CONTOSO\\svc$&,*S-1-5-32-544 |"
    assert want in configured, configured


@_windows_only
@pytest.mark.parametrize("holder", ["BUILTIN\\Administrators", "Administrators"])
def test_a_holder_written_as_a_name_is_already_granted(tmp_path: Path, holder: str) -> None:
    """BACKLOG #5401 item 1: an exported row can name a holder rather than give its ``*SID``.
    Compared by SID alone, the account written as a name read as missing, and the grant
    re-imported the policy with the account added a second time. Nothing may be configured."""
    configured = _grant_configured(tmp_path, f"SeServiceLogonRight = *S-1-5-80-4001,{holder}")
    assert configured == "", f"the policy was re-imported for a held account: {configured}"


@_windows_only
def test_a_name_that_resolves_to_another_account_still_grants(tmp_path: Path) -> None:
    """POSITIVE CONTROL for the name case: a name resolving to some other SID, and one that does
    not resolve, are not this account, so the grant still writes it."""
    configured = _grant_configured(
        tmp_path, "SeServiceLogonRight = BUILTIN\\Users,NO-SUCH-DOMAIN-b532r\\nobody"
    )
    want = "SeServiceLogonRight = BUILTIN\\Users,NO-SUCH-DOMAIN-b532r\\nobody,*S-1-5-32-544 |"
    assert want in configured, configured


@_windows_only
def test_the_grant_after_a_trailing_comma_writes_no_empty_holder(tmp_path: Path) -> None:
    configured = _grant_configured(tmp_path, "SeServiceLogonRight = *S-1-5-80-4001,")
    assert "SeServiceLogonRight = *S-1-5-80-4001,*S-1-5-32-544 |" in configured, configured


@_windows_only
def test_a_configure_that_never_ran_is_not_reported_as_a_grant(tmp_path: Path) -> None:
    """The stub's export left ``$LASTEXITCODE`` at 0 and its configure sets none. Read uncleared,
    that stale 0 reports a grant that never happened."""
    said = _grant_configured(tmp_path, "SeServiceLogonRight = *S-1-5-80-4001", configure_runs=False)
    assert "granted SeServiceLogonRight" not in said, said
    assert "secedit configure did not run" in said, said


@_windows_only
def test_the_grant_with_no_privilege_rights_section_adds_one(tmp_path: Path) -> None:
    """An export with no ``[Privilege Rights]`` line left the policy unchanged, and the re-import
    of it was still reported as a grant."""
    configured = _grant_configured(tmp_path, None, section=False)
    assert "[Privilege Rights] | SeServiceLogonRight = *S-1-5-32-544" in configured, configured


@_windows_only
def test_the_grant_with_no_exported_row_adds_one(tmp_path: Path) -> None:
    configured = _grant_configured(tmp_path, None)
    assert "[Privilege Rights] | SeServiceLogonRight = *S-1-5-32-544 |" in configured, configured


# --- the secedit files live in a folder only administrators can change (BACKLOG #5563) -------------
# The export and the database sat at $env:TEMP\mefor-secedit-remove-<PID>.inf/.sdb. The uninstaller
# runs elevated, but the user's TEMP belongs to the user, so a same-user process at medium integrity
# could plant or rewrite the .inf between the export and `secedit /configure` and so change a
# machine-wide user right. A folder of its own in that TEMP is not enough either: holding
# FILE_DELETE_CHILD on the TEMP, that process can rename the folder away and put its own in its place.


@_windows_only
def test_the_secedit_files_sit_in_a_fresh_folder_only_administrators_can_change(
    tmp_path: Path,
) -> None:
    got = _logon_right_arms(
        tmp_path, holders=["*S-1-5-80-4001", "*S-1-5-32-544"], sid="S-1-5-80-4001"
    )
    assert got["configureCalls"] == 1 and got["result"] is True, got["warnings"]
    folder = got["folder"]
    temp = str(tmp_path)
    assert folder["path"].rstrip("\\").lower() != temp.lower(), (
        f"the policy file is written straight into the user's TEMP: {got['cfg']}"
    )
    assert re.search(r"[0-9a-f]{32}", Path(folder["path"]).name), (
        f"the work folder's name is predictable: {folder['path']}"
    )
    assert Path(got["db"]).parent == Path(got["cfg"]).parent, (
        f"the database must sit in the same private folder: {got['db']}"
    )
    assert folder["protected"] is True, "the work folder inherits entries from the folder above"
    assert folder["reparse"] is False, "the work folder is a junction or a link"
    # The test's own account stands in for Administrators as the owner (see _workdir_seam).
    assert folder["owner"] == got["me"], f"the work folder has another owner: {folder['owner']}"
    extra = set(folder["sids"]) - {"S-1-5-18", "S-1-5-32-544", got["me"]}
    assert not extra, f"the work folder grants access to {sorted(extra)}"
    assert got["left"] == [], f"the work folder was not removed afterwards: {got['left']}"


@_windows_only
@pytest.mark.parametrize(
    ("where", "grant"),
    [
        # A parent that lets another account delete its children lets that account rename the
        # private folder away and substitute its own. Delete-child alone, so this case still fails
        # if the check stops judging FILE_DELETE_CHILD.
        ("parent-children", "*S-1-5-32-545:(DC)"),
        # Modify holds DELETE on the parent itself but no FILE_DELETE_CHILD, so the parent, with
        # the private folder inside, can be renamed away and a planted one put at its name.
        ("parent", "*S-1-5-32-545:M"),
        # Delete-child alone on the folder ABOVE the parent, on that folder only: it renames the
        # parent away, though the parent's own DACL grants nothing.
        ("above", "*S-1-5-32-545:(DC)"),
        # An entry that applies to the parent and is also inherited still applies to the parent.
        ("parent-inheritable", "*S-1-5-32-545:(OI)(CI)F"),
    ],
)
def test_the_work_folder_is_refused_when_the_parent_or_a_folder_above_can_be_renamed(
    tmp_path: Path, where: str, grant: str
) -> None:
    """The helper refuses a parent whose children, or which itself, or any folder above which,
    another account can rename. BACKLOG #8239 item 13 added the last two."""
    assert _UNINSTALL is not None
    above = tmp_path / "above"
    parent = above / "parent"
    parent.mkdir(parents=True)
    target = above if where == "above" else parent
    body = rf"""
  $parent = {_psq(str(parent))}
  $top = {_psq(str(tmp_path))}
  $target = {_psq(str(target))}
  $me = [Security.Principal.WindowsIdentity]::GetCurrent()
  & icacls $target /grant {_psq(grant)} | Out-Null
  $made = $null
  $refusal = ''
  try {{ $made = {_WORKDIR_FN} -Parent $parent -OwnerSid $me.User.Value -CheckedUpTo $top }}
  catch {{ $refusal = $_.Exception.Message }}
  $clean = $null
  & icacls $target /remove:g '*S-1-5-32-545' | Out-Null
  try {{ $clean = {_WORKDIR_FN} -Parent $parent -OwnerSid $me.User.Value -CheckedUpTo $top }} catch {{ $clean = "ERR $_" }}
  [pscustomobject]@{{ made = $made; refusal = $refusal; clean = $clean
    left = @(Get-ChildItem -LiteralPath $parent -Force | ForEach-Object {{ $_.Name }}) }} |
    ConvertTo-Json -Compress
"""
    got = json.loads(
        _ok(_extract(_UNINSTALL, [_WORKDIR_FN], body), tmp_path).strip().splitlines()[-1]
    )
    assert got["made"] is None, f"a folder was made though {where} can be renamed: {got['made']}"
    assert "S-1-5-32-545" in got["refusal"] or "Users" in got["refusal"], got["refusal"]
    assert f"'{target}' S-1-5-32-545" in got["refusal"], (
        f"the refusal does not name {target} as the open folder: {got['refusal']}"
    )
    # POSITIVE CONTROL: the same chain without the grant is accepted.
    assert got["clean"] and not str(got["clean"]).startswith("ERR"), got["clean"]
    assert got["left"] == [Path(got["clean"]).name], (
        f"the refused attempt left a folder behind: {got['left']}"
    )


def test_a_work_folder_that_cannot_be_made_runs_no_secedit(tmp_path: Path) -> None:
    """When the private folder cannot be made, nothing is exported or imported, and the operator is
    told the right was not removed rather than left believing it was."""
    seam = f"""
  function {_WORKDIR_FN} {{ throw 'planted refusal' }}
"""
    got = _logon_right_arms(
        tmp_path, holders=["*S-1-5-80-4001", "*S-1-5-32-544"], sid="S-1-5-80-4001", workdir=seam
    )
    assert got["exportCalls"] == 0 and got["configureCalls"] == 0
    assert got["result"] is False
    assert any("planted refusal" in w and "NOT removed" in w for w in got["warnings"]), got[
        "warnings"
    ]


def test_the_secedit_folder_defaults_to_the_windows_temp_not_the_users(tmp_path: Path) -> None:
    """STATIC. The default parent is %SystemRoot%\\Temp, where a user may make a folder but may not
    delete or rename one an administrator made; the user's TEMP lets its owner do both. Unelevated,
    the tests cannot make a folder there, so this reads the source."""
    assert _UNINSTALL is not None
    body = f"""
  $out = [ordered]@{{}}
  foreach ($n in @('{_SECEDIT_FN}', '{_WORKDIR_FN}')) {{
    $fn = $ast.Find({{ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
      $args[0].Name -eq $n }}, $true)
    $out[$n] = $fn.Body.Extent.Text
  }}
  [pscustomobject]$out | ConvertTo-Json -Compress
"""
    got = json.loads(_ok(_extract(_UNINSTALL, [], body), tmp_path).strip().splitlines()[-1])
    remove = got[_SECEDIT_FN]
    helper = got[_WORKDIR_FN]
    code = "\n".join(
        line
        for line in re.sub(r"<#.*?#>", "", remove, flags=re.S).splitlines()
        if not line.lstrip().startswith("#")
    )
    assert "$env:TEMP" not in code and "GetTempPath" not in code, (
        "Remove-ServiceLogonRight still builds a path in the user's TEMP"
    )
    assert re.search(rf"\b{_WORKDIR_FN}\b", code), (
        "Remove-ServiceLogonRight does not call the helper"
    )
    assert re.search(r'Join-Path \(\[Environment\]::GetFolderPath\("Windows"\)\) "Temp"', helper), (
        "the helper's default parent must be the Windows folder's Temp, asked of the system"
    )
    helper_code = "\n".join(
        line
        for line in re.sub(r"<#.*?#>", "", helper, flags=re.S).splitlines()
        if not line.lstrip().startswith("#")
    )
    assert "$env:SystemRoot" not in helper_code and "$env:windir" not in helper_code.lower(), (
        "the user can set SystemRoot and windir for their own processes, so neither may name the "
        "trusted parent"
    )


def test_no_caller_cuts_the_secedit_folder_walk_short() -> None:
    """STATIC. The walk to the root is the production check; -CheckedUpTo, which ends it early, is
    a test seam, so neither script names it outside the helper's own definition."""
    assert _SCRIPT is not None and _UNINSTALL is not None
    for script in (_SCRIPT, _UNINSTALL):
        text = script.read_text(encoding="utf-8-sig")
        start = text.index(f"function {_WORKDIR_FN} {{")
        end = text.index("\nfunction ", start)
        rest = text[:start] + text[end:]
        assert "CheckedUpTo" not in rest, f"{script.name} cuts the ancestor walk short"


@_windows_only
def test_the_work_folder_is_refused_under_a_reparse_point_above_the_parent(tmp_path: Path) -> None:
    """A junction above the parent makes the walk read the junction's own ACL, not the folders that
    hold the parent, so the helper refuses it."""
    assert _UNINSTALL is not None
    real = tmp_path / "real"
    (real / "parent").mkdir(parents=True)
    link = tmp_path / "link"
    made = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(real)], capture_output=True, text=True
    )
    assert made.returncode == 0, made.stdout + made.stderr
    body = rf"""
  $me = [Security.Principal.WindowsIdentity]::GetCurrent()
  $out = [ordered]@{{}}
  foreach ($p in @({_psq(str(link / "parent"))}, {_psq(str(real / "parent"))})) {{
    try {{ $out[$p] = {_WORKDIR_FN} -Parent $p -OwnerSid $me.User.Value -CheckedUpTo {_psq(str(tmp_path))} }}
    catch {{ $out[$p] = "ERR $($_.Exception.Message)" }}
  }}
  [pscustomobject]$out | ConvertTo-Json -Compress
"""
    got = json.loads(
        _ok(_extract(_UNINSTALL, [_WORKDIR_FN], body), tmp_path).strip().splitlines()[-1]
    )
    through_link = got[str(link / "parent")]
    assert str(through_link).startswith("ERR") and "reparse point" in through_link, through_link
    # POSITIVE CONTROL: the same parent reached by its real path is accepted.
    direct = got[str(real / "parent")]
    assert direct and not str(direct).startswith("ERR"), direct


def test_both_scripts_carry_the_same_secedit_folder_helper(tmp_path: Path) -> None:
    """The installer and the uninstaller share no file, so each carries New-SeceditWorkDirectory.
    A fix to one copy that never reaches the other would reopen #5563 on one side, silently."""
    assert _SCRIPT is not None and _UNINSTALL is not None
    body = f"""
  $out = @()
  foreach ($src in @({_psq(str(_SCRIPT))}, {_psq(str(_UNINSTALL))})) {{
    $tree = [System.Management.Automation.Language.Parser]::ParseFile($src, [ref]$null, [ref]$null)
    $fns = @($tree.FindAll({{ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
      $args[0].Name -eq '{_WORKDIR_FN}' }}, $true))
    $out += ,@($fns | ForEach-Object {{ $_.Extent.Text }})
  }}
  ConvertTo-Json -InputObject $out -Depth 3 -Compress
"""
    got = json.loads(_ok(_extract(_SCRIPT, [], body), tmp_path).strip().splitlines()[-1])
    install, uninstall = got
    assert len(install) == 1 and len(uninstall) == 1, (
        f"each script must define {_WORKDIR_FN} once: {len(install)}, {len(uninstall)}"
    )

    def norm(text: str) -> str:
        return text.replace("\r\n", "\n")

    assert norm(install[0]) == norm(uninstall[0]), (
        f"the two copies of {_WORKDIR_FN} differ; change both, byte for byte"
    )


_GRANT_FN = "Set-ServiceLogonRight"


def _grant_arms(tmp_path: Path, *, workdir: str | None = None) -> dict:
    """Run install-service.ps1's Set-ServiceLogonRight against a stubbed secedit, the account
    being this test's own, and read the folder the policy file sits in at the configure call."""
    assert _SCRIPT is not None
    parent = tmp_path / "secedit-parent"
    parent.mkdir(exist_ok=True)
    inf = ["[Unicode]", "Unicode=yes", "[Privilege Rights]", "SeServiceLogonRight = *S-1-5-32-544"]
    inf_ps = "@(" + ", ".join(_psq(line) for line in inf) + ")"
    body = rf"""
  $env:TEMP = {_psq(str(tmp_path))}
{_workdir_seam(parent) if workdir is None else workdir}
  $script:Calls = 0
  $script:Cfg = ''
  $script:Configured = ''
  $script:Folder = $null
  function secedit {{
    $a = @($args)
    $script:Calls++
    $script:Cfg = $a[[array]::IndexOf($a, '/cfg') + 1]
    if ($a -contains '/export') {{
      Set-Content -LiteralPath $script:Cfg -Value {inf_ps} -Encoding Unicode
    }} else {{
      $script:Configured = ((Get-Content -LiteralPath $script:Cfg) -join ' | ')
      $dir = Split-Path -Parent $script:Cfg
      $acl = Get-Acl -LiteralPath $dir
      $script:Folder = [ordered]@{{
        path = $dir
        owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        protected = $acl.AreAccessRulesProtected
        sids = @($acl.Access | Where-Object {{ $_.AccessControlType -eq 'Allow' }} |
          ForEach-Object {{ $_.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]).Value }})
      }}
    }}
    $global:LASTEXITCODE = 0
  }}
  $me = [Security.Principal.WindowsIdentity]::GetCurrent()
  $warnings = @()
  $emitted = & {{ {_GRANT_FN} -Account $me.Name }} 3>&1 6>$null
  foreach ($o in @($emitted)) {{
    if ($o -is [System.Management.Automation.WarningRecord]) {{ $warnings += "$o" }}
  }}
  [pscustomobject]@{{
    calls = $script:Calls; cfg = $script:Cfg; configured = $script:Configured
    folder = $script:Folder; warnings = @($warnings); me = $me.User.Value
    left = @(Get-ChildItem -LiteralPath {_psq(str(parent))} -Force | ForEach-Object {{ $_.Name }})
  }} | ConvertTo-Json -Depth 4 -Compress
"""
    parsed: dict = json.loads(
        _ok(_extract(_SCRIPT, [_GRANT_FN, _WORKDIR_FN], body), tmp_path).strip().splitlines()[-1]
    )
    parsed["warnings"] = [w for w in (parsed.get("warnings") or []) if w]
    return parsed


@_windows_only
def test_the_installer_grants_the_logon_right_from_a_private_folder(tmp_path: Path) -> None:
    """The grant direction of #5563, and the larger one: `secedit /configure` applies every user
    right in the file, so a rewritten .inf could hand any right to any account."""
    got = _grant_arms(tmp_path)
    assert got["calls"] == 2, got["warnings"]
    assert f"*{got['me']}" in got["configured"], "the account's SID was not added to the policy"
    folder = got["folder"]
    assert Path(folder["path"]).parent == tmp_path / "secedit-parent", (
        f"the policy file is not in a folder of its own under the trusted parent: {got['cfg']}"
    )
    assert re.search(r"[0-9a-f]{32}", Path(folder["path"]).name), folder["path"]
    assert folder["protected"] is True, "the work folder inherits entries from the folder above"
    assert folder["owner"] == got["me"], f"the work folder has another owner: {folder['owner']}"
    extra = set(folder["sids"]) - {"S-1-5-18", "S-1-5-32-544", got["me"]}
    assert not extra, f"the work folder grants access to {sorted(extra)}"
    assert got["left"] == [], f"the work folder was not removed afterwards: {got['left']}"


@_windows_only
def test_the_installer_runs_no_secedit_without_a_private_folder(tmp_path: Path) -> None:
    seam = f"""
  function {_WORKDIR_FN} {{ throw 'planted refusal' }}
"""
    got = _grant_arms(tmp_path, workdir=seam)
    assert got["calls"] == 0, "secedit ran although the private folder could not be made"
    assert any("planted refusal" in w and "NOT granted" in w for w in got["warnings"]), got[
        "warnings"
    ]


def test_the_ace_switch_issues_the_reverse_icacls_call(tmp_path: Path) -> None:
    """``icacls <dir> /remove:g <principal>`` -- the reverse of the installer's grant.

    /remove:g removes ALLOW entries only, so the worst case is that nothing matched. A /deny or a
    /grant here would be a different operation wearing this switch's name.
    """
    assert _UNINSTALL is not None
    target = tmp_path / "datadir"
    target.mkdir()
    body = rf"""
  $script:Calls = @()
  function icacls {{
    $script:Calls += ,@($args | ForEach-Object {{ "$_" }})
    $global:LASTEXITCODE = 0
  }}
  $result = & {{ {_ACE_FN} -Path {_psq(str(target))} -Principal '*S-1-5-80-4001' `
      -What 'data directory' }} 6>$null
  [pscustomobject]@{{ result = [bool]$result; calls = @($script:Calls) }} |
      ConvertTo-Json -Depth 4 -Compress
"""
    got = json.loads(_ok(_extract(_UNINSTALL, [_ACE_FN], body), tmp_path).strip().splitlines()[-1])
    calls = got["calls"]
    if calls and isinstance(calls[0], str):
        calls = [calls]
    assert len(calls) == 1, f"expected exactly one icacls call, got {calls}"
    args = calls[0]
    assert args[0] == str(target), f"the call must target the directory it was given: {args}"
    assert "/remove:g" in args, (
        f"the reverse operation must be /remove:g -- a grant or a deny is a different change: {args}"
    )
    assert "*S-1-5-80-4001" in args, f"the principal must be named on the call: {args}"
    assert not any(a in ("/grant", "/grant:r", "/deny", "/inheritance:r") for a in args), (
        f"the removal issued a permission change beyond dropping the entry: {args}"
    )
    assert got["result"] is True, "a clean icacls exit must be reported as a removal"


def test_a_missing_directory_is_not_reported_as_a_removal(tmp_path: Path) -> None:
    """POSITIVE CONTROL. A directory the operator already deleted must not make the notice claim an
    entry was cleared -- that is the false-completeness shape again, one level down."""
    assert _UNINSTALL is not None
    body = rf"""
  $script:Calls = 0
  function icacls {{ $script:Calls++; $global:LASTEXITCODE = 0 }}
  $result = & {{ {_ACE_FN} -Path {_psq(str(tmp_path / "gone"))} -Principal '*S-1-5-80-4001' `
      -What 'config directory' }} 6>$null
  [pscustomobject]@{{ result = [bool]$result; calls = $script:Calls }} |
      ConvertTo-Json -Depth 4 -Compress
"""
    got = json.loads(_ok(_extract(_UNINSTALL, [_ACE_FN], body), tmp_path).strip().splitlines()[-1])
    assert got["result"] is False, "a directory that is not there cannot have had an entry removed"
    assert got["calls"] == 0, "icacls must not be run against a path that does not exist"


def test_both_switches_are_declared_and_wired(tmp_path: Path) -> None:
    """CALL-SITE guard, the complaint #1699 made about this file: a correct helper proves nothing if
    the script never calls it."""
    assert _UNINSTALL is not None
    text = _UNINSTALL.read_text(encoding="utf-8")
    for switch in ("RemoveLogonRight", "RemoveAccountAces"):
        assert re.search(rf"\[switch\]\${switch}\b", text), f"-{switch} is not declared"
    body = """
  $cmds = @(foreach ($c in $ast.FindAll({ $args[0] -is
      [System.Management.Automation.Language.CommandAst] }, $true)) {
    [pscustomobject]@{ name = $c.GetCommandName(); text = $c.Extent.Text }
  })
  @($cmds) | ConvertTo-Json -Depth 4 -Compress
"""
    cmds = json.loads(_ok(_extract(_UNINSTALL, [], body), tmp_path).strip().splitlines()[-1])
    if isinstance(cmds, dict):
        cmds = [cmds]
    names = [c["name"] for c in cmds]
    assert names.count(_SECEDIT_FN) == 1, (
        f"expected one {_SECEDIT_FN} call, found {names.count(_SECEDIT_FN)}"
    )
    assert names.count(_ACE_FN) == 3, (
        "the account's entry is written on the data dir, the config dir and the secrets dir, so "
        f"each must be removable; found {names.count(_ACE_FN)} {_ACE_FN} calls"
    )
    notice = [c for c in cmds if c["name"] == "Get-UninstallResidueNotice"]
    assert len(notice) == 1, f"expected one Get-UninstallResidueNotice call, found {len(notice)}"
    for fact in (
        "-DataDir",
        "-ServiceAccount",
        "-ConfigDir",
        "-SecretsDir",
        "-CachedNssm",
        "-WerImages",
    ):
        assert fact in notice[0]["text"], (
            f"the notice is called without {fact}, so that residue can never be reported: "
            f"{notice[0]['text']}"
        )


def test_no_document_still_claims_only_the_logs_and_the_store_remain() -> None:
    """The false claim was in three places, and fixing the script alone leaves two standing.

    Matched with whitespace COLLAPSED: both sentences wrap in their source, so a one-line grep for
    either returns zero and reads as already fixed.
    """
    root = Path(__file__).resolve().parents[1]
    for rel in ("docs/SERVICE.md", "docs/USER-GUIDE.md"):
        flat = " ".join((root / rel).read_text(encoding="utf-8").split())
        assert "message store under `DataDir` are left in place" not in flat, (
            f"{rel} still tells an operator that the logs and the store are all that remains"
        )
        assert "leaves logs + store in place" not in flat, (
            f"{rel} still summarises the uninstall as leaving only the logs and the store"
        )
    service = " ".join((root / "docs" / "SERVICE.md").read_text(encoding="utf-8").split())
    assert "SeServiceLogonRight" in service, (
        "docs/SERVICE.md's uninstall section must name the user right that survives an uninstall"
    )
    assert "-RemoveLogonRight" in service and "-RemoveAccountAces" in service, (
        "docs/SERVICE.md must document the two switches that take the reversible residues back"
    )


@pytest.mark.parametrize(
    ("account", "sid", "has_account", "principal"),
    [
        # The installer's default: a per-service virtual account, named grants written.
        (r"NT SERVICE\MessageFoundry", "S-1-5-80-4001", True, "*S-1-5-80-4001"),
        # The -AllowLocalSystem opt-out, in its usual spelling.
        ("LocalSystem", "", False, "LocalSystem"),
        # THE ARM THAT MATTERS. Same account, different spelling. A NAME test says "this is an
        # account with a named grant", and -RemoveAccountAces then issues
        # `icacls <DataDir> /remove:g *S-1-5-18` -- stripping the SYSTEM entry the installer writes
        # on EVERY install off the directory holding the logs and the message store.
        (r"NT AUTHORITY\SYSTEM", "S-1-5-18", False, "*S-1-5-18"),
        # A SID that did not resolve still counts as an account: over-reporting costs one icacls
        # read, under-reporting is the defect this file exists to fix.
        (r"DOMAIN\svc$", "", True, r"DOMAIN\svc$"),
    ],
)
def test_the_account_residue_rule_is_decided_on_the_sid_not_the_spelling(
    tmp_path: Path, account: str, sid: str, has_account: bool, principal: str
) -> None:
    """ONE rule, shared by the notice that PRINTS a removal command and the switch that RUNS one."""
    assert _UNINSTALL is not None
    body = (
        f"  Get-AccountResidueSpec -ServiceAccount {_psq(account)} "
        f"-ServiceAccountSid {_psq(sid)} | ConvertTo-Json -Compress\n"
    )
    got = json.loads(
        _ok(_extract(_UNINSTALL, ["Get-AccountResidueSpec"], body), tmp_path)
        .strip()
        .splitlines()[-1]
    )
    assert got["HasAccount"] is has_account, (
        f"{account!r} (SID {sid!r}) was classified HasAccount={got['HasAccount']}, expected "
        f"{has_account}; a wrong answer here either hides a residue or removes SYSTEM's own entry"
    )
    assert got["Principal"] == principal, (
        f"the icacls spelling for {account!r} was {got['Principal']!r}, expected {principal!r}"
    )


def test_the_notice_and_the_removal_agree_on_the_principal(tmp_path: Path) -> None:
    """The rule above has two callers, and the whole point is that they cannot disagree.

    A script that prints one ``icacls ... /remove:g X`` and runs another with a different X is the
    #1704 shape wearing a fix: the operator's transcript and the host's state stop matching.
    """
    assert _UNINSTALL is not None
    text = _UNINSTALL.read_text(encoding="utf-8")
    assert text.count("Get-AccountResidueSpec -ServiceAccount") >= 2, (
        "the residue rule is called from fewer than two sites, so one of the notice and the "
        "removal switch is deriving the principal on its own again"
    )
    # The removal must pass the SAME variable the notice was handed, not rebuild it.
    assert re.search(r"Remove-AccountAce -Path \$DataDir -Principal \$acePrincipal", text), (
        "-RemoveAccountAces no longer runs the principal the notice prints"
    )
    assert not re.search(r'\$acePrincipal = if \(\$accountSid\) \{ "\*\$accountSid" \}', text), (
        "the principal is being rebuilt at the removal site instead of shared"
    )


def test_a_holder_with_a_dollar_sign_survives_the_policy_rewrite(tmp_path: Path) -> None:
    """secedit can export a holder by NAME, and a gMSA or computer account name ends in '$'.

    The name is looked up. Off Windows that lookup throws, which reads as a holder that may be this
    account (BACKLOG #5401), so the row is still rewritten but the result is not a removal there.

    '$' is a .NET substitution metacharacter in a -replace REPLACEMENT operand, so building the
    rewritten row that way re-reads a holder as $&, $+ or $$ and feeds a mangled machine-wide
    user-right row straight into `secedit /configure`.
    """
    got = _logon_right_arms(
        tmp_path,
        holders=["*S-1-5-80-4001", r"DOMAIN\ws-host$", "*S-1-5-32-544"],
        sid="S-1-5-80-4001",
    )
    assert got["configureCalls"] == 1, f"the removal did not run; warnings {got['warnings']}"
    if sys.platform.startswith("win"):
        assert got["result"] is True, f"the removal was not reported; warnings {got['warnings']}"
    assert r"DOMAIN\ws-host$" in got["configured"], (
        "a holder whose name ends in '$' was mangled or dropped by the rewrite -- the replacement "
        f"operand is being read as substitution syntax:\n{got['configured']}"
    )
    assert "*S-1-5-80-4001" not in got["configured"], (
        f"the account's own SID survived the rewrite:\n{got['configured']}"
    )


def test_the_notice_names_localdumps_separately_from_the_exclusion_list(tmp_path: Path) -> None:
    """TWO independent WER surfaces. Windows evaluates LocalDumps separately from the exclusion
    list, so an operator who clears ExcludedApplications alone still has per-image dump overrides in
    force -- and a notice that named only one would have told them the host was back to normal."""
    facts = dict(_FULL_FACTS)
    facts["WerLocalDumps"] = ["python.exe"]
    text = _notice(tmp_path, facts)
    assert "ExcludedApplications" in text and "LocalDumps" in text, (
        f"both WER surfaces must be named, not merged into one line:\n{text}"
    )
    # NEGATIVE: a host with no LocalDumps configuration must not be told it has one.
    plain = _notice(tmp_path, _FULL_FACTS)
    assert "LocalDumps" not in plain, (
        f"LocalDumps is reported on a host where nothing measured it:\n{plain}"
    )
    # And the exclusion-list line must still fire on its own.
    assert "ExcludedApplications" in plain, (
        f"the exclusion-list surface stopped being named:\n{plain}"
    )


# --------------------------------------------- the secrets directory (vault BACKLOG #2595 slice C)


def test_the_environment_merge_replaces_only_the_secrets_directory(tmp_path: Path) -> None:
    """`nssm set AppEnvironmentExtra` replaces the whole list, so the installer merges instead: a
    rerun keeps every entry an operator set and leaves exactly one MEFOR_SECRETS_DIRECTORY, whatever
    case the old entry was spelled in. The control: the old value is in the input."""
    assert _SCRIPT is not None
    body = r"""
  $old = @('MEFOR_LOG_LEVEL=INFO', 'mefor_secrets_directory=C:\old', 'MEFOR_X=a=b')
  $merged = Get-MergedEnvironmentList -Existing $old -Name 'MEFOR_SECRETS_DIRECTORY' -Value 'C:\new'
  $fresh = Get-MergedEnvironmentList -Existing $null -Name 'MEFOR_SECRETS_DIRECTORY' -Value 'C:\new'
  [pscustomobject]@{ old = $old; merged = @($merged); fresh = @($fresh) } | ConvertTo-Json -Compress
"""
    got = json.loads(
        _ok(
            _extract(_SCRIPT, ["Get-MergedEnvironmentList", "Test-EnvironmentEntryNames"], body),
            tmp_path,
        )
        .strip()
        .splitlines()[-1]
    )
    assert r"mefor_secrets_directory=C:\old" in got["old"]  # the control
    assert got["merged"] == [
        "MEFOR_LOG_LEVEL=INFO",
        "MEFOR_X=a=b",
        r"MEFOR_SECRETS_DIRECTORY=C:\new",
    ]
    assert got["fresh"] == [r"MEFOR_SECRETS_DIRECTORY=C:\new"]


@_windows_only
def test_the_secrets_directory_lockdown_passes_the_engines_own_check(tmp_path: Path) -> None:
    """Set-SecretsDirAcl on a directory that inherits Users read and the account's Modify, the shape
    a fresh secrets directory would have under an unlocked parent. Measured with the engine's own
    check, broad_access_problem(directory=True): it refuses the directory before and accepts it
    after. The account keeps read and loses the inherited Modify. Unelevated, the owner change is
    refused, and the function refuses for that alone: the read-back finds no other problem."""
    from messagefoundry.restricted_file import broad_access_problem

    assert _SCRIPT is not None
    parent = tmp_path / f"sd-{uuid.uuid4().hex[:8]}"
    secrets = parent / "secrets"
    secrets.mkdir(parents=True)
    # Two phases, so the engine's check reads the directory in the state the lockdown starts from.
    pre = rf"""
  $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  & icacls {_psq(str(parent))} /grant '*S-1-5-32-545:(OI)(CI)RX' "${{me}}:(OI)(CI)M" | Out-Null
"""
    _ok(_extract(_SCRIPT, [], pre), tmp_path)
    before = broad_access_problem(secrets, directory=True)
    assert before is not None, (
        "CONTROL FAILED: the engine accepted the directory before the lockdown"
    )
    lock = rf"""
  $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  $mySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $dir = {_psq(str(secrets))}
  $refusal = ''
  try {{ Set-SecretsDirAcl -Path $dir -Account $me }} catch {{ $refusal = $_.Exception.Message }}
  $acl = Get-Acl $dir
  $mine = @($acl.Access | Where-Object {{
    try {{ $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $mySid }}
    catch {{ $false }} }})
  [pscustomobject]@{{
    refusal = $refusal
    inherited = @($acl.Access | Where-Object {{ $_.IsInherited }}).Count
    protected = $acl.AreAccessRulesProtected
    mine = @($mine | ForEach-Object {{ "$($_.FileSystemRights)" }})
    text = (& icacls $dir | Out-String)
  }} | ConvertTo-Json -Depth 4 -Compress
"""
    try:
        got = json.loads(
            _ok(
                _extract(
                    _SCRIPT,
                    [
                        "Set-SecretsDirAcl",
                        "Get-WellKnownBroadSids",
                        "Get-BroadAclResidue",
                        "Get-ReparsePointAncestor",
                    ],
                    lock,
                ),
                tmp_path,
            )
            .strip()
            .splitlines()[-1]
        )
        after = broad_access_problem(secrets, directory=True)
    finally:
        restore = rf"""
  $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  & icacls {_psq(str(secrets))} /inheritance:e /grant "${{me}}:(OI)(CI)F" | Out-Null
"""
        _run(_extract(_SCRIPT, [], restore), tmp_path)
    assert after is None, f"the engine still refuses the locked directory: {after}\n{got['text']}"
    assert got["protected"] and got["inherited"] == 0, got["text"]
    assert got["mine"], f"the service account lost its read:\n{got['text']}"
    assert all("Modify" not in r and "Write" not in r for r in got["mine"]), (
        f"the account kept the Modify it inherited:\n{got['text']}"
    )
    # Elevated, nothing is refused. Unelevated, the owner change is, and only that.
    refusal = got["refusal"]
    assert not refusal or (
        "owner" in refusal and "grants access" not in refusal and "inherits" not in refusal
    ), f"a clean lockdown must find no residue; got {refusal}"


def test_the_installer_creates_and_names_the_secrets_directory(tmp_path: Path) -> None:
    """CALL-SITE guard: the functions above prove nothing if the script stops calling them. The
    directory is restricted after the data directory, whose inheritable grants would reach it, and
    is named to the service through the merging writer, never `nssm set AppEnvironmentExtra`."""
    facts = _preflight_facts(tmp_path)
    data = _sole_call(facts, "Set-SecureDataDirAcl")
    locks = [c for c in facts["commands"] if c["name"] == "Set-SecretsDirAcl"]
    assert all("-Path $SecretsDir" in c["text"] for c in locks), locks
    lock = _sole_call(facts, "Set-SecretsDirAcl")
    assert "-Account $ServiceAccount" in lock["text"], lock["text"]
    assert lock["start"] > data["start"], "the secrets directory is restricted before the data dir"
    named = _sole_call(facts, "Set-ServiceEnvironmentValue")
    assert "MEFOR_SECRETS_DIRECTORY" in named["text"] and "$SecretsDir" in named["text"]
    assert "AppEnvironmentExtra" not in " ".join(
        c["text"] for c in facts["commands"] if c["name"] == "Invoke-Nssm"
    ), "an `nssm set AppEnvironmentExtra` would replace the operator's whole list"
    # The lockdown replaces the directory's list, so -SecretsDir is judged by the -LockConfigDir
    # rule, and the directory is made, before anything acts on the service.
    check = next(
        c
        for c in facts["commands"]
        if c["name"] == "Get-LockPathProblem" and "-Path $SecretsDir" in c["text"]
    )
    assert "-AllowMissing" in check["text"] and "-OnlyFolders @()" in check["text"], check["text"]
    # Made in one step with its owner and list (New-RestrictedDirectory), never New-Item then icacls,
    # which leaves a window where the folder inherits Users' create right.
    creates = _sole_call(facts, "New-RestrictedDirectory")
    assert "-Path $SecretsDir" in creates["text"], creates["text"]
    assert not [
        c
        for c in facts["commands"]
        if c["name"] in ("New-AdminOnlyFolder", "New-Item") and "-Path $SecretsDir" in c["text"]
    ], "the secrets directory itself must not be made by New-Item"
    junction = next(
        c
        for c in facts["commands"]
        if c["name"] == "Get-ReparsePointAncestor" and "-Path $SecretsDir" in c["text"]
    )
    sharers = _sole_call(facts, "Get-OtherServiceNamingPath")
    empty = _sole_call(facts, "Get-SecretsDirHeldProblem")
    registered = min(
        c["start"]
        for c in facts["commands"]
        if c["name"] == "Invoke-Nssm" and "install" in c["text"]
    )
    assert check["start"] < junction["start"] < sharers["start"] < creates["start"] < registered, (
        "the secrets directory must be judged and made before the service registration changes"
    )
    # The empty check follows the restricted create, both before the registration.
    assert creates["start"] < empty["start"] < registered, (
        "the made directory must be found empty before the registration changes"
    )
    # An existing directory the service does not name is refused, never adopted: the preflight
    # says so, and no lockdown runs before the account's.
    assert "it already exists and the service does not name it" in _script_text()
    holds = next(a for a in facts["assignments"] if a["lhs"] == "SecretsHolds")["rhsText"]
    for other in ("$DataDir", "$LogDir", "$DbPath", "$Config", "$NssmDir", "$AppDirectory"):
        assert other in holds, other
    assert "environments" in holds and "$ServiceConfig" in holds, holds


@_windows_only
def test_the_secrets_directory_path_rule(tmp_path: Path) -> None:
    """Get-LockPathProblem with -AllowMissing, as the installer calls it for -SecretsDir: a path
    that does not exist yet passes; a volume root, a folder holding a folder, and a path inside a
    refused folder do not. The control: the same call without -AllowMissing refuses the absent
    path, so the switch is what lets it through."""
    assert _SCRIPT is not None
    existing = tmp_path / "sec"
    (existing / "sub").mkdir(parents=True)
    absent = tmp_path / "absent"
    body = rf"""
  $absent = {_psq(str(absent))}
  $existing = {_psq(str(existing))}
  $outer = {_psq(str(tmp_path))}
  [pscustomobject]@{{
    absent = (Get-LockPathProblem -Path $absent -OnlyFolders @() -AllowMissing)
    absentStrict = (Get-LockPathProblem -Path $absent -OnlyFolders @())
    root = (Get-LockPathProblem -Path ([System.IO.Path]::GetPathRoot($outer)) -OnlyFolders @() -AllowMissing)
    folder = (Get-LockPathProblem -Path $existing -OnlyFolders @() -AllowMissing)
    within = (Get-LockPathProblem -Path $absent -NotWithin @($outer) -OnlyFolders @() -AllowMissing)
    holds = (Get-LockPathProblem -Path $absent -Holds @((Join-Path $absent 'x')) -OnlyFolders @() -AllowMissing)
  }} | ConvertTo-Json -Compress
"""
    got = json.loads(
        _ok(_extract(_SCRIPT, ["Get-LockPathProblem"], body), tmp_path).strip().splitlines()[-1]
    )
    assert got["absent"] == "", got
    assert got["absentStrict"], "CONTROL FAILED: without -AllowMissing an absent path passed"
    assert "root of a volume" in got["root"], got
    assert "other folders" in got["folder"], got
    assert "inside" in got["within"], got
    assert "holds" in got["holds"], got


@_windows_only
@pytest.mark.parametrize("host", ["pwsh", "powershell"])
def test_the_secrets_directory_is_made_restricted_in_one_step(tmp_path: Path, host: str) -> None:
    """New-RestrictedDirectory makes the folder with its owner and protected list at once, so it
    never inherits the parent's grants, and the engine's own check accepts it as made. Run on both
    hosts: 5.1 takes the CreateDirectory overload, 7 the extension method. The test owns the folder
    (-OwnerSid of its own SID), since an unelevated process cannot name Administrators.

    The control: a folder that was already there, made by mkdir under the same open parent, is
    refused, because CreateDirectory would otherwise hand it back as if it had made it."""
    from messagefoundry.restricted_file import broad_access_problem

    assert _SCRIPT is not None
    parent = tmp_path / f"rd-{uuid.uuid4().hex[:8]}"
    parent.mkdir()
    made = parent / "secrets"
    squatted = parent / "squatted"
    squatted.mkdir()
    body = rf"""
  $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  & icacls {_psq(str(parent))} /grant '*S-1-5-32-545:(OI)(CI)M' | Out-Null
  New-RestrictedDirectory -Path {_psq(str(made))} -OwnerSid $me
  $acl = Get-Acl -LiteralPath {_psq(str(made))}
  $squat = ''
  try {{ New-RestrictedDirectory -Path {_psq(str(squatted))} -OwnerSid $me }}
  catch {{ $squat = $_.Exception.Message }}
  [pscustomobject]@{{
    owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    me = $me
    protected = $acl.AreAccessRulesProtected
    inherited = @($acl.Access | Where-Object {{ $_.IsInherited }}).Count
    sids = @($acl.Access | ForEach-Object {{
      $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }})
    squat = $squat
  }} | ConvertTo-Json -Compress
"""
    script = _extract(_SCRIPT, ["New-RestrictedDirectory", "Get-ReparsePointAncestor"], body)
    got = json.loads(_ok(script, tmp_path, host).strip().splitlines()[-1])
    assert got["owner"] == got["me"] and got["protected"] and got["inherited"] == 0, got
    assert sorted(set(got["sids"])) == ["S-1-5-18", "S-1-5-32-544"], got
    # The parent grants Users Modify; none of it reached the folder.
    assert broad_access_problem(made, directory=True) is None
    assert "was there before" in got["squat"], f"CONTROL FAILED: the squatted folder passed: {got}"


@_windows_only
def test_a_junction_above_the_secrets_directory_is_named(tmp_path: Path) -> None:
    """Get-ReparsePointAncestor names a junction anywhere above the path, skips folders not made
    yet, and finds nothing above a plain path. The control: the same tail below a plain folder."""
    assert _SCRIPT is not None
    target = tmp_path / "target"
    target.mkdir()
    plain = tmp_path / "plain"
    plain.mkdir()
    link = tmp_path / "link"
    made = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True
    )
    assert made.returncode == 0, made.stderr
    body = rf"""
  [pscustomobject]@{{
    under = (Get-ReparsePointAncestor -Path {_psq(str(link / "absent" / "secrets"))})
    plain = (Get-ReparsePointAncestor -Path {_psq(str(plain / "absent" / "secrets"))})
  }} | ConvertTo-Json -Compress
"""
    got = json.loads(
        _ok(_extract(_SCRIPT, ["Get-ReparsePointAncestor"], body), tmp_path)
        .strip()
        .splitlines()[-1]
    )
    assert "junction" in got["under"] and str(link) in got["under"], got
    assert got["plain"] == "", f"CONTROL FAILED: a plain path was named: {got}"


_SHARER_FUNCTIONS = [
    "Get-OtherServiceNamingPath",
    "ConvertTo-EngineStripped",
    "ConvertTo-NormalPath",
    "Get-EnvironmentListValue",
    "Test-EnvironmentEntryNames",
]


def _sharer_hits(
    tmp_path: Path, services: list[tuple[str, str]], host: str = "pwsh", extra: str = ""
) -> dict[str, Any]:
    """Get-OtherServiceNamingPath for 'Mine' at C:\\PD\\MF-secrets, against a services key built
    under HKCU holding ``services`` as (name, MEFOR_SECRETS_DIRECTORY value) pairs, plus a service
    with no Parameters key. ``extra`` is PowerShell whose value is returned as ``extra``."""
    assert _SCRIPT is not None
    root = f"HKCU:\\Software\\MeforTest-{uuid.uuid4().hex[:8]}"
    # One row per line, each with a unary comma, so a single row stays one pair rather than
    # flattening into its two strings.
    rows = "\n".join(
        f"      ,@({_psq(name)}, {_psq('MEFOR_SECRETS_DIRECTORY=' + value)})"
        for name, value in services
    )
    body = rf"""
  $root = {_psq(root)}
  try {{
    $services = @(
{rows}
    )
    foreach ($s in $services) {{
      $k = New-Item -Path (Join-Path $root "$($s[0])\Parameters") -Force
      Set-ItemProperty -LiteralPath $k.PSPath -Name AppEnvironmentExtra -Type MultiString `
        -Value @('MEFOR_X=1', $s[1])
    }}
    New-Item -Path (Join-Path $root 'NoParams') -Force | Out-Null
    $hits = @(Get-OtherServiceNamingPath -ServiceName 'Mine' -Name 'MEFOR_SECRETS_DIRECTORY' `
      -Path 'C:\PD\MF-secrets' -ServicesKey $root)
    [pscustomobject]@{{ hits = $hits; extra = $({extra or "$null"}) }} | ConvertTo-Json -Compress
  }} finally {{ Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }}
"""
    out = _ok(_extract(_SCRIPT, _SHARER_FUNCTIONS, body), tmp_path, host)
    got: dict[str, Any] = json.loads(out.strip().splitlines()[-1])
    return got


@_windows_only
def test_a_secrets_directory_another_service_names_is_found(tmp_path: Path) -> None:
    """Get-OtherServiceNamingPath, against a services key built under HKCU: a second service whose
    NSSM environment names the same directory (another case, a trailing backslash), the same one
    through '..' and forward slashes, a folder inside it, or a folder around it is returned; the
    installing service itself, a sibling whose name only starts the same, and a service naming
    another directory are not."""
    got = _sharer_hits(
        tmp_path,
        [
            ("First", "C:\\PD\\MF-SECRETS\\"),
            ("Mine", "C:\\PD\\MF-secrets"),
            ("Dots", "C:/PD/x/../MF-secrets"),
            ("Inside", "C:\\PD\\MF-secrets\\sub"),
            ("Around", "C:\\PD"),
            ("Sibling", "C:\\PD\\MF-secrets-two"),
            ("Other", "C:\\PD\\elsewhere"),
        ],
    )
    assert sorted(got["hits"]) == ["Around", "Dots", "First", "Inside"], got


@_windows_only
def test_a_secrets_directory_value_that_cannot_be_compared_counts_as_a_sharer(
    tmp_path: Path,
) -> None:
    """An absolute value ConvertTo-NormalPath cannot read is returned, not skipped: on Windows
    PowerShell 5.1 a path over 260 characters, which the engine may still read. It names no folder
    that overlaps C:\\PD\\MF-secrets as written, so only the fail-closed rule reports it. A host
    that can read it measures nothing here, so it skips. The control: a readable value naming
    another directory is still not returned."""
    long_value = "C:\\PD\\other\\" + "a" * 300
    got = _sharer_hits(
        tmp_path,
        [("Long", long_value), ("Other", "C:\\PD\\elsewhere")],
        host="powershell",
        extra=f"$null -eq (ConvertTo-NormalPath {_psq(long_value)})",
    )
    if got["extra"] is not True:
        pytest.skip(f"SKIP (nothing measured): this host reads the long path: {got}")
    assert sorted(got["hits"]) == ["Long"], got


@_windows_only
def test_a_secrets_directory_value_with_a_leading_space_is_a_sharer(tmp_path: Path) -> None:
    """The engine strips MEFOR_SECRETS_DIRECTORY with str.strip() before reading it, so a value
    with a leading space, or a leading U+001C that String.Trim() would keep, names the same
    directory and is returned. A run with one service checks a single row is not flattened. The
    control: a leading-space value naming another directory is not returned."""
    got = _sharer_hits(
        tmp_path,
        [
            ("Spaced", " C:\\PD\\MF-secrets"),
            ("Sep", "\x1cC:\\PD\\MF-secrets"),
            ("Other", " C:\\PD\\elsewhere"),
        ],
    )
    assert sorted(got["hits"]) == ["Sep", "Spaced"], got
    single = _sharer_hits(tmp_path, [("Only", " C:\\PD\\MF-secrets")])
    assert single["hits"] == ["Only"], single


@_windows_only
def test_the_secrets_directory_refuses_residue_and_held_files(tmp_path: Path) -> None:
    """Refusals where a warning used to be. Set-SecretsDirAcl throws when an entry for another
    account is left after the removals: icacls is shadowed so /remove:g does nothing, the way a
    removal that fails would. It throws too when the account's read is missing at the end: the
    shadow drops the account's /grant. Get-SecretsDirHeldProblem names a file the directory holds.
    The controls: the same directory with nothing in it reads clean, and the
    residue named is the one the setup granted."""
    assert _SCRIPT is not None
    held = tmp_path / "held"
    held.mkdir()
    (held / "MEFOR_PLANTED").write_text("x", encoding="utf-8")
    empty = tmp_path / "empty"
    empty.mkdir()
    residue = tmp_path / "residue"
    residue.mkdir()
    noread = tmp_path / "noread"
    noread.mkdir()
    body = rf"""
  & icacls.exe {_psq(str(residue))} /grant '*S-1-5-32-551:(OI)RX' | Out-Null
  function icacls {{
    if ($global:dropRemove -and $args -contains '/remove:g') {{ $global:LASTEXITCODE = 0; return }}
    if ($global:dropGrant -and $args -contains '/grant') {{ $global:LASTEXITCODE = 0; return }}
    & icacls.exe @args
  }}
  $global:dropRemove = $true
  $res = ''
  try {{ Set-SecretsDirAcl -Path {_psq(str(residue))} }} catch {{ $res = $_.Exception.Message }}
  $global:dropRemove = $false
  $global:dropGrant = $true
  $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  $noread = ''
  try {{ Set-SecretsDirAcl -Path {_psq(str(noread))} -Account $me }} catch {{ $noread = $_.Exception.Message }}
  $heldMsg = Get-SecretsDirHeldProblem -Path {_psq(str(held))}
  $emptyMsg = Get-SecretsDirHeldProblem -Path {_psq(str(empty))}
  [pscustomobject]@{{ res = $res; noread = $noread; held = $heldMsg; empty = $emptyMsg }} |
    ConvertTo-Json -Compress
"""
    try:
        got = json.loads(
            _ok(
                _extract(
                    _SCRIPT,
                    [
                        "Set-SecretsDirAcl",
                        "Get-WellKnownBroadSids",
                        "Get-BroadAclResidue",
                        "Get-ReparsePointAncestor",
                        "Get-SecretsDirHeldProblem",
                    ],
                    body,
                ),
                tmp_path,
            )
            .strip()
            .splitlines()[-1]
        )
    finally:
        me = subprocess.run(["whoami"], capture_output=True, text=True).stdout.strip()
        for locked in (residue, noread):
            subprocess.run(
                ["icacls", str(locked), "/inheritance:e", "/grant", f"{me}:(OI)(CI)F"],
                capture_output=True,
            )
    assert "still grants access" in got["res"] and "Backup Operators" in got["res"], got
    assert "holds no read" in got["noread"], got
    assert "holds no read" not in got["res"], (
        f"CONTROL FAILED: no -Account, yet a read check: {got}"
    )
    assert "MEFOR_PLANTED" in got["held"], got
    assert got["empty"] == "", f"CONTROL FAILED: an empty directory was refused: {got}"


@pytest.mark.parametrize("leaf", ["data[1]", "data[a-z]"])
def test_the_uninstall_ace_removal_reads_a_bracketed_data_dir_literally(
    tmp_path: Path, leaf: str
) -> None:
    """BACKLOG #5402 item 2: ``Remove-AccountAce`` tested ``-DataDir`` with a plain ``Test-Path``,
    which expands ``[...]`` as a wildcard, so an existing ``data[1]`` read as gone and its ACE
    stayed. icacls is a stub here; no ACL is touched."""
    assert _UNINSTALL is not None
    target = tmp_path / leaf
    target.mkdir()
    body = rf"""
  $script:Calls = @()
  function icacls {{ $script:Calls += ,@($args); $global:LASTEXITCODE = 0 }}
  $r = Remove-AccountAce -Path {_psq(str(target))} -Principal '*S-1-5-80-4001' -What 'data directory'
  'OUT=' + $r + '|' + $script:Calls.Count + '|' + ($script:Calls[0] -join ' ')
"""
    out = _ok(_extract(_UNINSTALL, ["Remove-AccountAce"], body), tmp_path).strip()
    result, count, call = out.splitlines()[-1].removeprefix("OUT=").split("|", 2)
    assert (result, count) == ("True", "1"), f"the existing directory read as gone: {out}"
    assert call.startswith(str(target)), call


# --- a holder-name lookup that could not be made is not "not this account" (BACKLOG #5401) --------
# Both scripts used `catch { $true }` / `catch { $false }` around Translate, so ANY lookup failure
# read as "this holder is some other account", and the uninstaller then printed "does not hold" for
# an account that may hold the right. Only IdentityNotMappedException means "no such account" now.
# The tests below that use `_UNREADABLE` cover a lookup that throws something other than "not
# mapped". They stand in for that failure with a 1000-character holder name: on Windows the
# NTAccount cast throws for a name over 512 characters (measured 2026-11-19: 513 throws, 512 does
# not). Off Windows the cast may throw for any name (unmeasured). They do not model an
# unreachable domain controller. Whether LSA reports a domain it cannot reach as "not mapped",
# which this fix would still read as "no such account", is unmeasured.

_UNREADABLE = "x" * 1000


def test_an_unread_holder_name_is_not_reported_as_does_not_hold(tmp_path: Path) -> None:
    got = _logon_right_arms(tmp_path, holders=["*S-1-5-32-545", _UNREADABLE], sid="S-1-5-80-4001")
    assert got["result"] is False, got
    assert got["unproven"] is True, "the residue notice is not told the right is unproven"
    assert got["configureCalls"] == 0, "the policy was rewritten although nothing was proven held"
    assert not any("does not hold" in s for s in got["said"]), got["said"]
    assert any("Could not look up" in w and "may still hold" in w for w in got["warnings"]), got[
        "warnings"
    ]


@_windows_only
def test_a_holder_name_that_maps_to_no_account_still_reads_as_does_not_hold(
    tmp_path: Path,
) -> None:
    """POSITIVE CONTROL: a well-formed name in a domain that does not exist maps to no account,
    which is still "not this account"."""
    got = _logon_right_arms(
        tmp_path, holders=["*S-1-5-32-545", "NOSUCHDOMAINB532R\\nobody"], sid="S-1-5-80-4001"
    )
    assert got["result"] is False, got
    assert any("does not hold" in s for s in got["said"]), got["said"]
    assert not got["warnings"], got["warnings"]
    assert got["unproven"] is False, got


def test_a_removal_beside_an_unread_holder_is_not_reported_as_removed(tmp_path: Path) -> None:
    """The SID token goes, but a name left in the row may still be the account, so the residue
    notice must not be told the account no longer holds the right."""
    got = _logon_right_arms(
        tmp_path,
        holders=["*S-1-5-80-4001", "*S-1-5-32-545", _UNREADABLE],
        sid="S-1-5-80-4001",
    )
    assert got["configureCalls"] == 1, got
    assert f"SeServiceLogonRight = *S-1-5-32-545,{_UNREADABLE} |" in got["configured"], got[
        "configured"
    ]
    assert got["result"] is False, "a removal with an unproven holder left was reported as complete"
    assert got["unproven"] is True, "the residue notice is not told the right is unproven"
    assert not any("removed SeServiceLogonRight" in s for s in got["said"]), got["said"]
    assert any("may still hold" in w for w in got["warnings"]), got["warnings"]


@_windows_only
def test_the_grant_adds_the_sid_beside_an_unread_holder_and_says_so(tmp_path: Path) -> None:
    """Install's safe direction: an unread holder is not counted as held, since a missed grant
    fails the service with error 1069, so the SID is added and the grant it reports is real."""
    assert _SCRIPT is not None
    parent = tmp_path / "grant-parent"
    parent.mkdir()
    row = f"SeServiceLogonRight = {_UNREADABLE}"
    inf = ["[Unicode]", "Unicode=yes", "[Privilege Rights]", row, "[Version]"]
    inf_ps = "@(" + ", ".join(_psq(line) for line in inf) + ")"
    body = rf"""
  # A regression to the old TEMP-based secedit files lands in the test's own folder.
  $env:TEMP = {_psq(str(tmp_path))}
{_workdir_seam(parent)}
  $script:Configured = ''
  function secedit {{
    $a = @($args)
    $cfg = $a[[array]::IndexOf($a, '/cfg') + 1]
    if ($a -contains '/export') {{ Set-Content -LiteralPath $cfg -Value {inf_ps} -Encoding Unicode }}
    elseif ($a -contains '/configure') {{
      $script:Configured = ((Get-Content -LiteralPath $cfg) -join ' | ')
    }}
    $global:LASTEXITCODE = 0
  }}
  $me = [Security.Principal.WindowsIdentity]::GetCurrent()
  $said = @({_GRANT_FN} -Account $me.Name 3>&1 6>&1 | ForEach-Object {{ "$_" }})
  [pscustomobject]@{{ configured = $script:Configured; said = @($said); me = $me.User.Value }} |
    ConvertTo-Json -Compress
"""
    got = json.loads(
        _ok(_extract(_SCRIPT, [_GRANT_FN, _WORKDIR_FN], body), tmp_path).strip().splitlines()[-1]
    )
    said = " / ".join(got["said"] or [])
    assert "already holds" not in said, said
    assert "Could not look up" in said, said
    assert "granted SeServiceLogonRight" in said, said
    assert f"{row},*{got['me']} |" in got["configured"], got["configured"]


def test_an_unproven_logon_right_is_reported_as_unknown(tmp_path: Path) -> None:
    """Neither "REMOVED" nor "still holds ... Next time, pass -RemoveLogonRight" is true when the
    switch ran and a holder name could not be looked up (BACKLOG #5401)."""
    facts = dict(_FULL_FACTS)
    facts["LogonRightUnproven"] = True
    text = _notice(tmp_path, facts)
    assert "UNPROVEN" in text and "may still hold" in text, text
    assert "-RemoveLogonRight" not in text and "still holds the" not in text, text
    # POSITIVE CONTROL: without the flag the notice still offers the switch.
    assert "-RemoveLogonRight" in _notice(tmp_path, _FULL_FACTS)


def test_the_uninstaller_hands_the_unproven_state_to_the_notice() -> None:
    """The helper and the notice are tested apart, so the call site is pinned here: a correct
    helper proves nothing if the script never passes its outcome on (#1699)."""
    assert _UNINSTALL is not None
    text = _UNINSTALL.read_text(encoding="utf-8")
    assert "\n$script:LogonRightUnproven = $false" in text.replace("\r\n", "\n")
    assert "-LogonRightUnproven:$script:LogonRightUnproven `" in text

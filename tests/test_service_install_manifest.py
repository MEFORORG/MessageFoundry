# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Static-manifest policy guards for the NSSM integrity-verify path (DEPLOY-7).

``install-service.ps1`` auto-downloads a pinned NSSM release when nssm is absent from PATH, then
verifies it against a hard-coded SHA-256 before trusting the binary. That download + hash + extract
runs only on Windows when nssm is missing, so it can't execute under pytest here (it's a
ci-leg-to-add: exercise ``Resolve-Nssm`` on a runner with nssm stripped from PATH — a Pester test or
the windows-service-smoke job). What IS unit-testable off-Windows is the *static shape* of the
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

import json
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

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
    """
    lines = [
        "& {",
        "  $ErrorActionPreference = 'Stop'",
        f"  $src = {_psq(str(path))}",
        "  $ast = [System.Management.Automation.Language.Parser]::ParseFile("
        "$src, [ref]$null, [ref]$null)",
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


def _run(script: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    if shutil.which("pwsh") is None:
        pytest.skip("SKIP (nothing run): pwsh not on PATH")
    f = tmp_path / f"harness-{uuid.uuid4().hex}.ps1"
    f.write_text(script, encoding="utf-8")
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(f)],
        capture_output=True,
        text=True,
        timeout=180,
    )


def _ok(script: str, tmp_path: Path) -> str:
    r = _run(script, tmp_path)
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


def test_integrity_branch_is_fail_closed_throw_not_warn() -> None:
    """The hash-mismatch branch REFUSES: it compares against the pin and ``throw``s, and does not
    downgrade to ``Write-Warning`` (which would trust an unverified binary)."""
    text = _script_text()
    # The comparison is against the pin, computed with SHA256.
    assert "Get-FileHash -Algorithm SHA256" in text, (
        "the download must be hashed with Get-FileHash -Algorithm SHA256"
    )
    assert re.search(r"\$hash\s*-ne\s*\$NssmSha256", text), (
        "the computed hash must be compared against the pinned $NssmSha256"
    )

    # Isolate the mismatch block and prove it is a hard throw, not a warn.
    m = re.search(
        r"if\s*\(\s*\$hash\s*-ne\s*\$NssmSha256\s*\)\s*\{(?P<body>.*?)\}",
        text,
        re.DOTALL,
    )
    assert m is not None, "the '$hash -ne $NssmSha256' mismatch block is missing"
    body = m.group("body")
    assert "throw" in body, "integrity mismatch must THROW (fail closed), not continue"
    assert "Write-Warning" not in body, (
        "integrity mismatch must not be downgraded to Write-Warning (that fails OPEN)"
    )
    # The rejected artifact is deleted so a stale bad zip can't be reused.
    assert "Remove-Item" in body, "the mismatched download must be removed on failure"


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
    raw = _ok(_extract(_SCRIPT, ["Invoke-Nssm"], body), tmp_path)
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


def test_the_password_call_site_passes_the_secret_by_name(tmp_path: Path) -> None:
    """CALL-SITE guard: a correct Invoke-Nssm is no use if ObjectName still passes the password
    positionally. Located by AST, so a reordering or a rename of the local does not walk past it."""
    assert _SCRIPT is not None
    body = """
  $cmds = @($ast.FindAll({ $args[0] -is
      [System.Management.Automation.Language.CommandAst] }, $true) | Where-Object {
      $_.GetCommandName() -eq 'Invoke-Nssm' })
  @($cmds | ForEach-Object {
    $els = @($_.CommandElements | ForEach-Object { $_.Extent.Text })
    [pscustomobject]@{ text = $_.Extent.Text; elements = $els }
  }) | ConvertTo-Json -Depth 4 -Compress
"""
    raw = _ok(_extract(_SCRIPT, [], body), tmp_path)
    calls = json.loads(raw.strip().splitlines()[-1])
    if isinstance(calls, dict):
        calls = [calls]
    objectname = [c for c in calls if "ObjectName" in c["elements"]]
    assert objectname, "no Invoke-Nssm call sets ObjectName -- the run-as account is not configured"
    secret_calls = [c for c in objectname if "-Secret" in c["elements"]]
    assert len(secret_calls) == 1, (
        "exactly one ObjectName call passes the password, and it must pass it as -Secret "
        f"(BACKLOG #1573); found {len(secret_calls)} of {len(objectname)} ObjectName calls:\n"
        + "\n".join(c["text"] for c in objectname)
    )
    # The password local must appear EXACTLY ONCE on that call, and only as -Secret's argument. A
    # second occurrence would be a positional argument, which lands in $NssmArgs and is joined into
    # the message -- the leak, restored beside a fix that looks applied.
    elements = secret_calls[0]["elements"]
    secret_at = elements.index("-Secret")
    password_at = [i for i, e in enumerate(elements) if e == "$plain"]
    assert password_at == [secret_at + 1], (
        "the password local must appear exactly once on the ObjectName call, as the argument to "
        f"-Secret; a second (positional) occurrence is joined into the failure message:\n"
        f"{secret_calls[0]['text']}"
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
) -> dict:
    """Run Stop-ServiceAndConfirm with Get-Service and Stop-Service shadowed.

    ``states`` is what the shadowed Get-Service reports on successive calls (the last value repeats);
    an empty list means the service is absent. ``nssm_exit`` of None runs the no-nssm branch, which
    is uninstall-service.ps1's third stop site. ``chatter`` makes the stub print to STDOUT.

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
    body = (
        prelude
        + rf"""
  $script:StopServiceCalls = 0
  $script:GetServiceCalls = 0
  $script:States = {states_ps}
  function Get-Service {{
    param([string]$Name, $ErrorAction)
    $script:GetServiceCalls++
    if ($script:States.Count -eq 0) {{ return $null }}
    $i = [Math]::Min($script:GetServiceCalls - 1, $script:States.Count - 1)
    return [pscustomobject]@{{ Status = $script:States[$i] }}
  }}
  function Stop-Service {{
    param([string]$Name, [switch]$Force, $ErrorAction)
    $script:StopServiceCalls++
  }}
  $warnings = @()
  $result = $null
  $emitted = & {{
    {_STOP_FN} -ServiceName 'MessageFoundry' -NssmPath {nssm_arg} -TimeoutSeconds {timeout}
  }} 3>&1
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


# --- every path baked into the registration is absolute, and made so IN TIME (BACKLOG #1554) ------
# A service resolves a relative path against its own working directory. Only -Config was normalized,
# and it was normalized after Resolve-Nssm had already joined a possibly-relative -DataDir and after
# Test-Path had validated a relative -DbPath against the operator's shell location rather than the
# AppDirectory the service would use.
#
# ORDER IS THE DEFECT, so the guards below are about WHERE the normalization happens, not merely that
# it happens. Three assertions of shape and one of behaviour.

_PATH_PARAMS = ["DataDir", "AppExe", "Config", "DbPath"]


def _preflight_facts(tmp_path: Path) -> dict:
    """Assignments and command calls of install-service.ps1, with source offsets, by AST."""
    assert _SCRIPT is not None
    body = """
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
    [pscustomobject]@{
      name  = $c.GetCommandName()
      start = $c.Extent.StartOffset
      line  = $c.Extent.StartLineNumber
      text  = $c.Extent.Text
    }
  })
  [pscustomobject]@{ assignments = @($assigns); commands = @($cmds) } |
      ConvertTo-Json -Depth 6 -Compress
"""
    parsed: dict = json.loads(_ok(_extract(_SCRIPT, [], body), tmp_path).strip().splitlines()[-1])
    return parsed


def _sole_call(facts: dict, name: str) -> dict:
    hits = [c for c in facts["commands"] if c["name"] == name]
    assert len(hits) == 1, f"expected exactly one {name} call, found {len(hits)}"
    return hits[0]


def test_every_path_parameter_is_absolute_before_anything_consumes_it(tmp_path: Path) -> None:
    """Each of -DataDir, -AppExe, -Config, -DbPath is finalised BEFORE the Resolve-Nssm call.

    Resolve-Nssm joins ``bin`` onto -DataDir and caches nssm.exe there; every later consumer
    (Test-Path, the ACL grants, AppParameters) inherits whatever these hold. A normalization that
    runs after any of them is the #1554 defect in a new position.
    """
    facts = _preflight_facts(tmp_path)
    nssm_at = _sole_call(facts, "Resolve-Nssm")["start"]
    for var in _PATH_PARAMS:
        writes = [a for a in facts["assignments"] if a["lhs"] == var]
        assert writes, f"nothing assigns ${var} in the preflight"
        late = [a for a in writes if a["start"] > nssm_at]
        assert not late, (
            f"${var} is still being written at line(s) {[a['line'] for a in late]}, AFTER "
            f"Resolve-Nssm (line {_sole_call(facts, 'Resolve-Nssm')['line']}) has already consumed "
            "the preflight values -- BACKLOG #1554 is about exactly this ordering"
        )


def test_the_repo_root_is_computed_before_the_defaults_that_need_it(tmp_path: Path) -> None:
    """$AppExe and $Config default from $RepoRoot, so $RepoRoot has to exist first.

    This is the second half of the reorder: moving the normalization up is wrong if it lands above
    the value two of the four defaults are built from.
    """
    facts = _preflight_facts(tmp_path)
    root = [a for a in facts["assignments"] if a["lhs"] == "RepoRoot"]
    assert len(root) == 1, f"expected one $RepoRoot assignment, found {len(root)}"
    for var in ("AppExe", "Config"):
        first = min(a["start"] for a in facts["assignments"] if a["lhs"] == var)
        assert root[0]["start"] < first, (
            f"$RepoRoot (line {root[0]['line']}) is computed after the first write to ${var}, "
            "whose default is built from it"
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

_ACL_FNS = ["Set-SecureDataDirAcl", "Get-BroadAclResidue"]

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


def test_the_installer_still_calls_the_lockdown_on_the_data_dir(tmp_path: Path) -> None:
    """CALL-SITE guard, and the literal complaint of BACKLOG #1699: deleting the call left every
    test green. The behavioural arms above run the FUNCTION and say nothing about whether the
    script invokes it."""
    facts = _preflight_facts(tmp_path)
    calls = [c for c in facts["commands"] if c["name"] == "Set-SecureDataDirAcl"]
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


# --- the run-as account and the ACLs must agree on EVERY path (BACKLOG #1553) ---------------------
# -AllowLocalSystem on a RERUN left the previous account configured (ObjectName was written only on the
# non-LocalSystem branch) and then stripped that still-running account's access to the data dir. The
# config dir goes the same way, and losing READ there makes SEC-003 source-trust refuse to load config
# at all -- three ACL sites, not the one the row names.
#
# The fix is an ORDERING-FREE one: write ObjectName unconditionally, so the assumption about what NSSM
# defaults to at create time stops mattering. The guards are therefore about which branches write it.

_ACL_CALLS = ["Set-SecureDataDirAcl", "Set-SecureConfigAcl", "Set-ConfigReadAcl"]


def _objectname_calls(facts: dict) -> list[dict]:
    return [
        c for c in facts["commands"] if c["name"] == "Invoke-Nssm" and "ObjectName" in c["text"]
    ]


def test_objectname_is_written_on_every_run_as_branch(tmp_path: Path) -> None:
    """Three branches set the run-as account -- password, password-less, and the LocalSystem opt-out
    -- and all three must write ObjectName.

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
        "the -AllowLocalSystem branch does not CALL nssm to set ObjectName, so a rerun over a "
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
        for call in [c for c in facts["commands"] if c["name"] == fn]:
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
        calls = [c for c in facts["commands"] if c["name"] == fn]
        assert len(calls) == 1, f"expected exactly one {fn} call, found {len(calls)}"


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
            ["data_ace", "config_ace", "logon_right"],
            ["data_dir", "cached_nssm", "config_inheritance", "wer"],
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
    facts.update({"LogonRightRemoved": True, "DataAceRemoved": True, "ConfigAceRemoved": True})
    text = _notice(tmp_path, facts)
    assert text.count("REMOVED") >= 3, (
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


def _logon_right_arms(tmp_path: Path, *, holders: list[str], sid: str) -> dict:
    """Run Remove-ServiceLogonRight against a stubbed secedit whose policy holds ``holders``."""
    assert _UNINSTALL is not None
    inf = ["[Unicode]", "Unicode=yes", "[Privilege Rights]"]
    if holders:
        inf.append("SeServiceLogonRight = " + ",".join(holders))
    inf.append("[Version]")
    inf_ps = "@(" + ", ".join(_psq(line) for line in inf) + ")"
    body = rf"""
  # $env:TEMP is where the function writes its policy export; on a Linux runner it is unset and
  # Join-Path would throw before a single assertion ran.
  $env:TEMP = {_psq(str(tmp_path))}
  $script:Configured = ''
  $script:ConfigureCalls = 0
  $script:ExportCalls = 0
  function secedit {{
    $a = @($args)
    if ($a -contains '/export') {{
      $script:ExportCalls++
      $i = [array]::IndexOf($a, '/cfg')
      Set-Content -Path $a[$i + 1] -Value {inf_ps} -Encoding Unicode
    }} elseif ($a -contains '/configure') {{
      $script:ConfigureCalls++
      $i = [array]::IndexOf($a, '/cfg')
      $script:Configured = ((Get-Content $a[$i + 1]) -join ' | ')
    }}
    $global:LASTEXITCODE = 0
  }}
  $warnings = @()
  $result = $null
  $outputs = 0
  $emitted = & {{ {_SECEDIT_FN} -Account 'NT SERVICE\MessageFoundry' -Sid {_psq(sid)} }} 3>&1 6>$null
  foreach ($o in @($emitted)) {{
    if ($o -is [System.Management.Automation.WarningRecord]) {{ $warnings += "$o" }}
    else {{ $result = $o; $outputs++ }}
  }}
  [pscustomobject]@{{
    result = [bool]$result; outputs = $outputs; warnings = @($warnings)
    exportCalls = $script:ExportCalls; configureCalls = $script:ConfigureCalls
    configured = $script:Configured
  }} | ConvertTo-Json -Depth 4 -Compress
"""
    parsed: dict = json.loads(
        _ok(_extract(_UNINSTALL, [_SECEDIT_FN], body), tmp_path).strip().splitlines()[-1]
    )
    parsed["warnings"] = [w for w in (parsed.get("warnings") or []) if w]
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


def test_a_right_the_account_does_not_hold_is_a_no_op(tmp_path: Path) -> None:
    """POSITIVE CONTROL the other way: nothing is rewritten when there is nothing to remove, so a
    re-run cannot disturb a host it already cleaned."""
    got = _logon_right_arms(tmp_path, holders=["*S-1-5-32-544"], sid="S-1-5-80-4001")
    assert got["result"] is False, "reporting a removal that did not happen is the #1704 shape"
    assert got["configureCalls"] == 0, "the policy must not be rewritten when nothing changes"


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
    assert names.count(_ACE_FN) == 2, (
        "the account's entry is written on BOTH the data dir and the config dir, so both must be "
        f"removable; found {names.count(_ACE_FN)} {_ACE_FN} calls"
    )
    notice = [c for c in cmds if c["name"] == "Get-UninstallResidueNotice"]
    assert len(notice) == 1, f"expected one Get-UninstallResidueNotice call, found {len(notice)}"
    for fact in ("-DataDir", "-ServiceAccount", "-ConfigDir", "-CachedNssm", "-WerImages"):
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

    '$' is a .NET substitution metacharacter in a -replace REPLACEMENT operand, so building the
    rewritten row that way re-reads a holder as $&, $+ or $$ and feeds a mangled machine-wide
    user-right row straight into `secedit /configure`.
    """
    got = _logon_right_arms(
        tmp_path,
        holders=["*S-1-5-80-4001", r"DOMAIN\ws-host$", "*S-1-5-32-544"],
        sid="S-1-5-80-4001",
    )
    assert got["result"] is True, f"the removal did not run; warnings {got['warnings']}"
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

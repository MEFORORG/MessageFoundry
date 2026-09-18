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


def _uninstall_text() -> str:
    assert _UNINSTALL is not None
    return _UNINSTALL.read_text(encoding="utf-8")


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
# ``Invoke-Nssm`` throws "nssm <args> failed (exit N)" on a non-zero exit. One of its 19 call sites
# passes the service-account password, so a joined message there puts cleartext into the throw, the
# host's error rendering, and the $Error record it leaves behind.
#
# THE NAIVE FIX IS THE ONE TO GUARD AGAINST: stripping the arguments from every message would pass a
# test that only checks "the password is absent", and would also destroy the 18 messages an operator
# actually needs. So the ordinary-call arm below is a POSITIVE CONTROL, not a bonus assertion -- it is
# what distinguishes a redaction from an erasure.

_SECRET = "hunter2-DO-NOT-LEAK-THIS"

_NSSM_STUB = "@echo off\r\necho nssm: the service could not be configured 1>&2\r\nexit /b 3\r\n"


def _invoke_nssm_arms(tmp_path: Path) -> dict[str, str]:
    """Run Invoke-Nssm against a stub that always exits 3, once with a secret and once without.

    Everything a leaked password could reach is collected per arm: the exception message, the error
    record as the host renders it, the record's full property dump, and the $Error entry.
    """
    assert _SCRIPT is not None
    stub = tmp_path / "nssm-stub.cmd"
    stub.write_text(_NSSM_STUB, encoding="ascii")
    body = rf"""
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

    18 of the 19 call sites carry no secret and their joined arguments are the whole diagnostic
    value of the throw.
    """
    arms = _invoke_nssm_arms(tmp_path)
    ordinary = arms["ordinary"]
    assert ordinary, "the ordinary arm did not throw -- the stub's exit 3 was not detected"
    assert "AppStdout" in ordinary, "an ordinary nssm failure must still name its subcommand"
    assert "service.out.log" in ordinary, (
        "an ordinary nssm failure must still name its arguments -- a fix that strips every "
        "argument would satisfy the redaction test while destroying 18 useful messages"
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
    tmp_path: Path, *, nssm_exit: int | None, states: list[str], timeout: int = 1
) -> dict:
    """Run Stop-ServiceAndConfirm with Get-Service and Stop-Service shadowed.

    ``states`` is what the shadowed Get-Service reports on successive calls (the last value repeats);
    an empty list means the service is absent. ``nssm_exit`` of None runs the no-nssm branch, which
    is uninstall-service.ps1's third stop site.
    """
    assert _SCRIPT is not None
    stub = tmp_path / f"nssm-stop-{uuid.uuid4().hex}.cmd"
    stub.write_text(
        "@echo off\r\necho nssm: stop reported a problem 1>&2\r\n"
        f"exit /b {nssm_exit if nssm_exit is not None else 0}\r\n",
        encoding="ascii",
    )
    nssm_arg = _psq(str(stub)) if nssm_exit is not None else "''"
    states_ps = "@(" + ", ".join(_psq(s) for s in states) + ")"
    body = rf"""
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
  foreach ($o in @($emitted)) {{
    if ($o -is [System.Management.Automation.WarningRecord]) {{ $warnings += "$o" }}
    else {{ $result = $o }}
  }}
  [pscustomobject]@{{
    result           = [bool]$result
    warnings         = @($warnings)
    stopServiceCalls = $script:StopServiceCalls
    getServiceCalls  = $script:GetServiceCalls
  }} | ConvertTo-Json -Depth 4 -Compress
"""
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


def _lockdown(tmp_path: Path, *, broad_ace: str | None, inherited: bool) -> dict:
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
        f"  & icacls {_psq(grant_target)} /grant '{broad_ace}:(OI)(CI)RX' | Out-Null\n"
        if broad_ace
        else ""
    )
    body = rf"""
{pre}
  $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  $data = {_psq(str(data))}
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
  # Put the tree back in reach so pytest can clean it up.
  & icacls {_psq(str(parent))} /inheritance:e /grant "${{me}}:(OI)(CI)F" | Out-Null
  & icacls $data /inheritance:e /grant "${{me}}:(OI)(CI)F" | Out-Null
  [pscustomobject]@{{
    before = $before; after = $after; afterLogs = $afterLogs
    beforeSids = @($beforeSids); sids = @($sids); logSids = @($logSids)
    warnings = @($warnings); account = $me
  }} | ConvertTo-Json -Depth 4 -Compress
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

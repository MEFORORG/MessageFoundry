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

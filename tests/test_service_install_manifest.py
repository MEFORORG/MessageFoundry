# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
"""

from __future__ import annotations

import re

import pytest

import messagefoundry.service as svc

_SCRIPT = svc.install_script_path()

pytestmark = pytest.mark.skipif(
    _SCRIPT is None,
    reason="install-service.ps1 not locatable (off-repo / non-editable install)",
)


def _script_text() -> str:
    assert _SCRIPT is not None  # narrowed by the module-level skipif
    return _SCRIPT.read_text(encoding="utf-8")


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

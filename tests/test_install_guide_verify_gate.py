# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1566: the INSTALL-GUIDE.md verify-before-install blocks must actually GATE the install.

``docs/INSTALL-GUIDE.md``'s "Verify the release before you install (supply-chain integrity)" section
prints two copy-pasteable PowerShell blocks whose whole point is: run ``gh attestation verify`` (and
``sigstore``), and only install the wheel if that check passed. As shipped, neither block checked
``$LASTEXITCODE`` after any external command. PowerShell does **not** raise a terminating error when a
native command like ``gh`` or ``python`` returns a nonzero exit code -- it falls straight through to
the next line -- so a failed verification did not stop the script from reaching ``pip install``. The
gate the section exists to provide simply did not gate anything.

The second block had an independent second defect: it resolved the downloaded wheel with an
unconstrained ``Get-ChildItem`` glob (no handling for zero or several matches) and then re-installed
via ``pip install --no-index --find-links .\\verify "messagefoundry==$V"`` -- a re-resolution of the
*package name* against the whole folder, not an install of the *file* that was actually verified. A
stale second file in that folder could make ``pip`` install something other than what ``gh attestation
verify`` had just checked.

This module extracts both fenced ``powershell`` blocks from the doc and runs each one for real, with
``gh``, ``python`` (``-m sigstore``), and ``pip`` replaced by recording fakes on ``PATH`` that return a
controlled exit code and touch no network. It asserts:

* a **positive control** -- every fake returns 0 -- reaches ``pip install`` (block 1) or ``pip install
  <the exact resolved file>`` (block 2). Without this, the negative assertions below would pass
  vacuously if the extraction or the fake harness were simply broken and nothing ran at all.
* a **negative case** for every verifying step -- ``gh release download``, ``gh attestation verify``,
  ``python -m sigstore verify identity`` (block 1); ``pip download``, ``gh attestation verify`` (block
  2) -- returning nonzero stops the script before ``pip install`` ever runs.
* block 2's zero-match and multiple-match ``Get-ChildItem`` cases stop the script with a clear error,
  never falling through to verify or install anything.
* block 2's ``pip install`` argument is the exact file path that was passed to ``gh attestation
  verify`` -- not a ``--find-links``/bare-package-name re-resolution.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_DOC = _ROOT / "docs" / "INSTALL-GUIDE.md"
_HEADING = "### Verify the release before you install (supply-chain integrity)"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)

# A column-0 ```powershell fence: ```powershell\n ... \n```. Mirrors the ```toml fence pattern in
# tests/test_off_loopback_runbook.py's `_FENCE_RE` / test_runbook_proxy_tls_floor.py's `_fences`.
_FENCE_RE = re.compile(r"^```powershell[ \t]*$\n(.*?)^```[ \t]*$", re.DOTALL | re.MULTILINE)

# Recording fakes. Each logs "<cmd>|<arg1>|<arg2>|..." to $env:FAKE_LOG (pipe-delimited so a Python
# reader can split reliably even though real arguments contain spaces, colons and slashes) and exits
# with a controlled code so a test can force any one step to fail without touching the network.
_GH_SHIM = """\
Add-Content -LiteralPath $env:FAKE_LOG -Value ("gh|" + ($args -join "|"))
if ($args[0] -eq "release" -and $args[1] -eq "download") {
    exit ([int]($env:FAKE_GH_RELEASE_EXIT ?? 0))
}
if ($args[0] -eq "attestation" -and $args[1] -eq "verify") {
    exit ([int]($env:FAKE_GH_ATTEST_EXIT ?? 0))
}
exit 0   # any other `gh` call the doc might add later succeeds rather than hanging the test
"""

_PYTHON_SHIM = """\
Add-Content -LiteralPath $env:FAKE_LOG -Value ("python|" + ($args -join "|"))
exit ([int]($env:FAKE_SIGSTORE_EXIT ?? 0))
"""

# `pip download` actually materializes N fake wheels under the `-d` target so the doc's own
# Get-ChildItem resolution step has something real to resolve (or fail to resolve) against.
_PIP_SHIM = """\
Add-Content -LiteralPath $env:FAKE_LOG -Value ("pip|" + ($args -join "|"))
if ($args[0] -eq "download") {
    $dIndex = [array]::IndexOf($args, "-d")
    $dest = $args[$dIndex + 1]
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    $count = [int]($env:FAKE_PIP_DOWNLOAD_COUNT ?? 1)
    for ($i = 0; $i -lt $count; $i++) {
        $name = "messagefoundry-0.1.0-py3-none-any$i.whl"
        Set-Content -LiteralPath (Join-Path $dest $name) -Value "fake wheel $i"
    }
    exit ([int]($env:FAKE_PIP_DOWNLOAD_EXIT ?? 0))
}
if ($args[0] -eq "install") {
    exit ([int]($env:FAKE_PIP_INSTALL_EXIT ?? 0))
}
exit 0   # any other `pip` call the doc might add later succeeds rather than hanging the test
"""


def _verify_section() -> str:
    text = _DOC.read_text(encoding="utf-8")
    start = text.find(_HEADING)
    assert start != -1, f"{_HEADING!r} missing from {_DOC.name}"
    nxt = text.find("\n## ", start + len(_HEADING))
    return text[start:] if nxt == -1 else text[start:nxt]


def _powershell_blocks() -> list[str]:
    return _FENCE_RE.findall(_verify_section())


def _run_block(
    block: str, tmp_path: Path, env: dict[str, str]
) -> tuple[subprocess.CompletedProcess[str], list[tuple[str, list[str]]]]:
    """Run one extracted PowerShell block under the recording fakes and return
    ``(process, invocations)``, where each invocation is ``(command, args)``."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "gh.ps1").write_text(_GH_SHIM, encoding="utf-8")
    (bin_dir / "python.ps1").write_text(_PYTHON_SHIM, encoding="utf-8")
    (bin_dir / "pip.ps1").write_text(_PIP_SHIM, encoding="utf-8")

    log = tmp_path / "log.txt"
    log.write_text("", encoding="utf-8")

    script = tmp_path / "block.ps1"
    script.write_text(block, encoding="utf-8")

    # Start every run from a clean slate: strip whatever FAKE_* the caller's own shell carries, so a
    # var this function does not explicitly set (below, or via `env`) can never leak in from outside.
    run_env = {k: v for k, v in os.environ.items() if not k.startswith("FAKE_")}
    run_env["FAKE_LOG"] = str(log)
    run_env["PATH"] = str(bin_dir) + os.pathsep + run_env.get("PATH", "")
    run_env.update(env)

    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=run_env,
        timeout=60,
    )
    invocations = [
        (parts[0], parts[1:])
        for line in log.read_text(encoding="utf-8").splitlines()
        if line.strip()
        for parts in [line.split("|")]
    ]
    return proc, invocations


def _pip_installs(invocations: list[tuple[str, list[str]]]) -> list[list[str]]:
    return [args for cmd, args in invocations if cmd == "pip" and args[:1] == ["install"]]


def test_the_verify_section_has_exactly_two_powershell_blocks() -> None:
    """Liveness / anti-narrowing receipt. Every test below indexes into this list -- if the doc's
    structure changes and the extraction silently finds zero or a different count, every test that
    follows would be exercising nothing rather than failing."""
    blocks = _powershell_blocks()
    assert len(blocks) == 2, (
        f"expected 2 fenced powershell blocks under {_HEADING!r} in {_DOC.name}, found "
        f"{len(blocks)} -- the extraction regex or the doc's own structure changed"
    )


# ── Block 1: gh release download -> gh attestation verify -> sigstore verify identity -> pip install


def test_block_one_installs_once_every_check_passes(tmp_path: Path) -> None:
    """POSITIVE CONTROL. Without this, every negative test below could pass because nothing ever
    reaches `pip install` in the first place -- a broken extraction or a broken fake harness looks
    identical to a correctly-gated script unless something proves the happy path still installs."""
    block = _powershell_blocks()[0]
    proc, invocations = _run_block(block, tmp_path, {})
    assert proc.returncode == 0, f"expected success:\n{proc.stdout}\n{proc.stderr}"
    assert _pip_installs(invocations), (
        f"every fake returned 0, so `pip install` must run. Invocations: {invocations}"
    )


@pytest.mark.parametrize(
    "env",
    [
        pytest.param({"FAKE_GH_RELEASE_EXIT": "1"}, id="gh-release-download-fails"),
        pytest.param({"FAKE_GH_ATTEST_EXIT": "1"}, id="gh-attestation-verify-fails"),
        pytest.param({"FAKE_SIGSTORE_EXIT": "1"}, id="sigstore-verify-identity-fails"),
    ],
)
def test_block_one_never_installs_after_a_failed_check(tmp_path: Path, env: dict[str, str]) -> None:
    """The #1566 defect: PowerShell does not stop on a nonzero exit code by itself. This is the
    negative case for each of the three verifying steps in turn."""
    block = _powershell_blocks()[0]
    proc, invocations = _run_block(block, tmp_path, env)
    assert proc.returncode != 0, (
        f"a failed check ({env}) must stop the script with a nonzero exit, got 0 -- the "
        f"$LASTEXITCODE gate is missing or broken:\n{proc.stdout}\n{proc.stderr}"
    )
    assert not _pip_installs(invocations), (
        f"`pip install` ran after a failed check ({env}). Invocations: {invocations}"
    )


# ── Block 2: pip download -> resolve to one file -> gh attestation verify -> pip install <that file>


def test_block_two_installs_the_exact_file_it_verified(tmp_path: Path) -> None:
    """POSITIVE CONTROL, and the fix for the second #1566 defect: the file passed to `pip install`
    must be the SAME path that was passed to `gh attestation verify`, not a --find-links
    re-resolution of the bare package name against the whole folder."""
    block = _powershell_blocks()[1]
    proc, invocations = _run_block(block, tmp_path, {"FAKE_PIP_DOWNLOAD_COUNT": "1"})
    assert proc.returncode == 0, f"expected success:\n{proc.stdout}\n{proc.stderr}"

    verifies = [
        args for cmd, args in invocations if cmd == "gh" and args[:2] == ["attestation", "verify"]
    ]
    installs = _pip_installs(invocations)
    assert verifies, f"gh attestation verify never ran. Invocations: {invocations}"
    assert installs, f"pip install never ran (positive control). Invocations: {invocations}"

    verified_path = verifies[0][2]
    installed_path = installs[0][1]
    assert installed_path == verified_path, (
        f"pip install used {installed_path!r} but gh attestation verify checked "
        f"{verified_path!r} -- these must be the exact same file"
    )
    # And it must not be the OLD, broken shape: a bare package name resolved via --find-links.
    assert "--find-links" not in " ".join(installs[0]), (
        f"block 2 still installs via --find-links (a package-name re-resolution) instead of the "
        f"exact verified file path: {installs[0]}"
    )


def test_block_two_never_installs_after_a_failed_verify(tmp_path: Path) -> None:
    block = _powershell_blocks()[1]
    proc, invocations = _run_block(
        block, tmp_path, {"FAKE_PIP_DOWNLOAD_COUNT": "1", "FAKE_GH_ATTEST_EXIT": "1"}
    )
    assert proc.returncode != 0, (
        f"a failed gh attestation verify must stop the script, got 0:\n{proc.stdout}\n{proc.stderr}"
    )
    assert not _pip_installs(invocations), (
        f"`pip install` ran after a failed attestation check. Invocations: {invocations}"
    )


def test_block_two_never_installs_after_a_failed_download(tmp_path: Path) -> None:
    block = _powershell_blocks()[1]
    proc, invocations = _run_block(
        block, tmp_path, {"FAKE_PIP_DOWNLOAD_COUNT": "1", "FAKE_PIP_DOWNLOAD_EXIT": "1"}
    )
    assert proc.returncode != 0, (
        f"a failed pip download must stop the script, got 0:\n{proc.stdout}\n{proc.stderr}"
    )
    assert not _pip_installs(invocations), (
        f"`pip install` ran after a failed pip download. Invocations: {invocations}"
    )
    assert not any(cmd == "gh" for cmd, _ in invocations), (
        f"gh attestation verify ran against a download that failed. Invocations: {invocations}"
    )


@pytest.mark.parametrize(
    "count",
    [
        pytest.param(0, id="zero-matches"),
        pytest.param(2, id="two-matches"),
    ],
)
def test_block_two_refuses_to_guess_which_file_to_verify(tmp_path: Path, count: int) -> None:
    """The unconstrained `Get-ChildItem` glob: at zero matches `.FullName` on nothing silently
    produces `$null`, and at several matches the old code had no explicit rule and could pick either
    one or error ambiguously. The fixed block must stop with a clear error in both cases, before ever
    calling `gh attestation verify` or `pip install`."""
    block = _powershell_blocks()[1]
    proc, invocations = _run_block(block, tmp_path, {"FAKE_PIP_DOWNLOAD_COUNT": str(count)})
    assert proc.returncode != 0, (
        f"{count} downloaded file(s) matching the glob must stop the script with a clear error, "
        f"got success:\n{proc.stdout}\n{proc.stderr}"
    )
    assert not any(cmd == "gh" for cmd, _ in invocations), (
        f"gh attestation verify ran despite {count} matching file(s). Invocations: {invocations}"
    )
    assert not _pip_installs(invocations), (
        f"pip install ran despite {count} matching file(s). Invocations: {invocations}"
    )

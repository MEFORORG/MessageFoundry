# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The installer must grade the gate against origin/main, not only against itself (BACKLOG #1878).

install-gate.ps1 took the bytes it installs AND the yardstick ``-Status`` grades them against from
one place: the checkout it was invoked in. So an install from a stale tree shipped a stale gate to
every config dir on the box, and ``-Status`` run from that same tree printed ``IN SYNC``. Measured
2026-09-21: a primary 66 commits behind origin/main read ``IN SYNC`` while a worktree at origin/main
read ``STALE`` against the same installed file.

Every test here builds its own two-repository fixture -- an "upstream" and a clone of it whose
origin/main can be moved ahead of HEAD with a fetch -- and drives the REAL installer file against
it. ``-Status`` runs as a whole script, copied into the fixture clone so that its ``$RepoRoot``
resolves there, with ``USERPROFILE`` pointed at a fixture home. The install path refuses inside
Claude Code by design, so its refusal is tested the way tests/test_install_gate_records_the_install.py
tests its region: the real functions and the real region are cut out of the real file and run.

No test here reads or writes this machine's real config dirs or its installed gate.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
INSTALLER = REPO / "scripts" / "worktree" / "install-gate.ps1"
GATE_REL = Path("scripts") / "hooks" / "worktree_gate.ps1"

GATE_V1 = '$GateVersion = "2026.01.01.1"\n# rule set ONE\n'
GATE_V2 = '$GateVersion = "2026.01.01.1"\n# rule set TWO -- same label, different rules\n'

# The install-path region under test: the stale-source check, and nothing after it.
_REGION_START = "$sourceGate = Join-Path $RepoRoot"
_REGION_END = "New-Item -ItemType Directory -Force -Path $HooksDir"


def _need_tools() -> None:
    if shutil.which("pwsh") is None:
        pytest.skip("SKIP (nothing run): pwsh not on PATH")
    if shutil.which("git") is None:
        pytest.skip("SKIP (nothing run): git not on PATH")


def _clean_env(**extra: str) -> dict[str, str]:
    """This process's environment minus any GIT_* that could point git at the real repository."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(extra)
    return env


def _psq(value: str) -> str:
    """A PowerShell single-quoted literal. An apostrophe in a temp path must not end the string."""
    return "'" + value.replace("'", "''") + "'"


def _git(cwd: Path, *args: str) -> str:
    # A hooks path that does not exist: git then finds no hooks at all, so neither this machine's
    # global hooks nor a stray file anywhere shared can run inside the fixture.
    nohooks = cwd / ".fixture-no-hooks"
    r = subprocess.run(
        [
            "git",
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            f"core.hooksPath={nohooks.as_posix()}",
            "-c",
            "core.autocrlf=false",
            *args,
        ],
        cwd=cwd,
        capture_output=True,
        text=True,
        env=_clean_env(),
    )
    assert r.returncode == 0, f"git {' '.join(args)} failed in {cwd}:\n{r.stdout}\n{r.stderr}"
    return r.stdout


def _write_gate(root: Path, text: str) -> None:
    p = root / GATE_REL
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(text.encode("utf-8"))


def _fixture(tmp_path: Path, *, behind: bool) -> Path:
    """An upstream carrying the gate, and a clone of it. Returns the clone.

    With ``behind``, upstream moves on to GATE_V2 after the clone and the clone FETCHES, so its
    origin/main is one commit ahead of its HEAD -- the stale-primary shape the row measured.
    """
    up = tmp_path / "upstream"
    up.mkdir()
    _git(up, "init", "-q", "-b", "main")
    _write_gate(up, GATE_V1)
    _git(up, "add", ".")
    _git(up, "commit", "-q", "-m", "gate v1")

    checkout = tmp_path / "checkout"
    _git(tmp_path, "clone", "-q", str(up), str(checkout))
    if behind:
        _write_gate(up, GATE_V2)
        _git(up, "commit", "-q", "-am", "gate v2")
        _git(checkout, "fetch", "-q", "origin")
    return checkout


def _plant(home: Path, text: str, *, crlf: bool = False) -> None:
    """The INSTALLED gate, under a fixture home."""
    dst = home / ".claude" / "hooks" / "worktree_gate.ps1"
    dst.parent.mkdir(parents=True, exist_ok=True)
    body = text.replace("\n", "\r\n") if crlf else text
    dst.write_bytes(body.encode("utf-8"))


def _status(checkout: Path, home: Path) -> str:
    """Run the REAL installer's -Status from inside the fixture checkout."""
    installer = checkout / "scripts" / "worktree" / "install-gate.ps1"
    installer.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(INSTALLER, installer)
    r = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(installer), "-Status"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        env=_clean_env(USERPROFILE=str(home), CLAUDECODE="1"),
    )
    assert r.returncode == 0, f"-Status must never fail:\n{(r.stderr + r.stdout)[:1500]}"
    print(r.stdout)
    return r.stdout


def _parity(out: str) -> str:
    """The parity verdict and its continuation lines."""
    lines = out.splitlines()
    for i, ln in enumerate(lines):
        if ln.startswith("parity      :"):
            block = [ln]
            for nxt in lines[i + 1 :]:
                if not nxt.startswith("              "):
                    break
                block.append(nxt)
            return "\n".join(block)
    raise AssertionError(f"-Status printed no parity verdict:\n{out}")


def _short_hashes(out: str) -> dict[str, str]:
    """The 12-hex digest -Status prints on each of the installed, source and upstream lines."""
    found: dict[str, str] = {}
    for ln in out.splitlines():
        for label in ("installed", "source", "upstream"):
            if ln.startswith(f"{label}"):
                tail = ln.split(" sha ", 1)
                if len(tail) == 2:
                    found[label] = tail[1][:12]
    return found


# ------------------------------------------------------------------------------------ -Status


def test_a_stale_install_run_from_a_stale_tree_does_not_read_in_sync(tmp_path: Path) -> None:
    """The defect itself. Installed and checkout agree with each other, and both are behind."""
    _need_tools()
    checkout = _fixture(tmp_path, behind=True)
    home = tmp_path / "home"
    _plant(home, GATE_V1)

    out = _status(checkout, home)
    verdict = _parity(out)
    hashes = _short_hashes(out)

    # CONTROL: the fixture really is stale-against-stale, so the verdict below is a reading of that
    # shape and not of a fixture that forgot to move origin/main.
    assert hashes.get("installed") == hashes.get("source"), out
    assert hashes.get("upstream") and hashes["upstream"] != hashes["installed"], out

    assert "IN SYNC" not in verdict, (
        f"a stale install graded against its own stale tree read green:\n{verdict}"
    )
    assert "NOT CURRENT" in verdict, verdict
    assert hashes["installed"] in verdict and hashes["upstream"] in verdict, (
        f"the verdict must name both digests, not only assert that they differ:\n{verdict}"
    )
    assert "1 commit(s) behind origin/main" in verdict, verdict


def test_the_same_fixture_reads_in_sync_once_everything_is_current(tmp_path: Path) -> None:
    """Positive control for the test above: the instrument CAN say green, so its red is a reading."""
    _need_tools()
    checkout = _fixture(tmp_path, behind=True)
    _git(checkout, "merge", "-q", "--ff-only", "origin/main")
    home = tmp_path / "home"
    _plant(home, GATE_V2)

    out = _status(checkout, home)
    verdict = _parity(out)
    assert "IN SYNC" in verdict and "AND to origin/main" in verdict, verdict
    # At zero behind with IDENTICAL content, the "carries a gate change" note would be false.
    assert "carries a gate change" not in out, out


def test_a_local_branch_named_origin_main_does_not_replace_the_remote_ref(tmp_path: Path) -> None:
    """A short ref resolves to refs/heads/origin/main before refs/remotes/origin/main.

    Such a branch at the stale HEAD would make the yardstick the stale tree itself, and the verdict
    IN SYNC again -- the defect through a different door.
    """
    _need_tools()
    checkout = _fixture(tmp_path, behind=True)
    _git(checkout, "branch", "origin/main", "HEAD")  # refs/heads/origin/main, at the STALE commit
    home = tmp_path / "home"
    _plant(home, GATE_V1)

    verdict = _parity(_status(checkout, home))
    assert "IN SYNC" not in verdict and "NOT CURRENT" in verdict, verdict


def test_line_endings_alone_do_not_make_the_installed_gate_differ_from_origin_main(
    tmp_path: Path,
) -> None:
    """The upstream digest must use Get-GateHash's fold, or every Windows install reads NOT CURRENT.

    The blob is stored LF; an installed copy laid down from a core.autocrlf checkout carries CRLF.
    """
    _need_tools()
    checkout = _fixture(tmp_path, behind=False)
    _write_gate(checkout, GATE_V1.replace("\n", "\r\n"))  # the autocrlf working-tree form
    home = tmp_path / "home"
    _plant(home, GATE_V1, crlf=True)

    verdict = _parity(_status(checkout, home))
    assert "IN SYNC" in verdict, (
        f"CRLF against an LF blob was graded as a content difference:\n{verdict}"
    )


def _lonely(tmp_path: Path) -> Path:
    """A checkout with no remote at all, so origin/main cannot resolve."""
    checkout = tmp_path / "lonely"
    checkout.mkdir()
    _git(checkout, "init", "-q", "-b", "main")
    _write_gate(checkout, GATE_V1)
    _git(checkout, "add", ".")
    _git(checkout, "commit", "-q", "-m", "no remote at all")
    return checkout


def test_an_unreadable_origin_main_is_unverified_and_never_green(tmp_path: Path) -> None:
    _need_tools()
    checkout = _lonely(tmp_path)
    home = tmp_path / "home"
    _plant(home, GATE_V1)

    out = _status(checkout, home)
    verdict = _parity(out)
    assert "upstream    : origin/main UNREADABLE" in out, out
    assert "IN SYNC" not in verdict and "UNVERIFIED" in verdict, verdict


def test_a_current_install_read_from_a_stale_tree_is_current_not_stale(tmp_path: Path) -> None:
    """The false RED of the same defect: graded against this checkout alone, a current gate read STALE."""
    _need_tools()
    checkout = _fixture(tmp_path, behind=True)
    home = tmp_path / "home"
    _plant(home, GATE_V2)  # installed from a CURRENT tree; this checkout is the stale one

    verdict = _parity(_status(checkout, home))
    assert "*** STALE ***" not in verdict and "CURRENT" in verdict, verdict
    assert "do NOT install from it" in verdict, verdict


def test_stale_says_which_copy_origin_main_agrees_with(tmp_path: Path) -> None:
    """The STALE warning asks the reader to work out which copy is older. The ref answers it."""
    _need_tools()
    checkout = _fixture(tmp_path, behind=True)
    _git(checkout, "merge", "-q", "--ff-only", "origin/main")
    home = tmp_path / "home"
    _plant(home, GATE_V1)  # the installed gate is the old one; this checkout is current

    verdict = _parity(_status(checkout, home))
    assert "*** STALE ***" in verdict, verdict
    assert "matches THIS CHECKOUT, so the INSTALLED gate is the copy that differs" in verdict, (
        verdict
    )


def test_an_upstream_ref_that_looks_like_an_option_is_rejected(tmp_path: Path) -> None:
    """The ref is handed to git as an argument; a leading '-' would be read as a git option."""
    _need_tools()
    r = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(INSTALLER),
            "-Status",
            "-UpstreamRef",
            "--output=x",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        env=_clean_env(USERPROFILE=str(tmp_path / "home"), CLAUDECODE="1"),
    )
    both = r.stdout + r.stderr
    # The validation message specifically, so a binding failure for another reason cannot pass this.
    assert r.returncode != 0 and "Cannot validate argument on parameter 'UpstreamRef'" in both, both


# ------------------------------------------------------------------------------ install refusal


def _run_region(
    checkout: Path, tmp_path: Path, *, allow: bool, ref: str = "origin/main"
) -> subprocess.CompletedProcess[str]:
    """Run the real stale-source region, with the real functions it calls, against a fixture."""
    text = INSTALLER.read_text(encoding="utf-8")
    region = text[text.index(_REGION_START) : text.index(_REGION_END)]
    script = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            "Set-StrictMode -Version Latest",
            "$ast = [System.Management.Automation.Language.Parser]::ParseFile("
            f"{_psq(INSTALLER.as_posix())}, [ref]$null, [ref]$null)",
            "foreach ($n in @('Get-GateHash', 'Get-UpstreamGate', 'Format-UpstreamPosition', 'Get-StaleSourceRefusal')) {",
            "  $f = @($ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq $n }, $true))",
            '  if ($f.Count -ne 1) { throw "expected one function $n, found $($f.Count)" }',
            "  . ([scriptblock]::Create($f[0].Extent.Text))",
            "}",
            f"$RepoRoot = {_psq(checkout.as_posix())}",
            f"$UpstreamRef = {_psq(ref)}",
            f"$AllowStaleSource = ${'true' if allow else 'false'}",
            region,
            "Write-Host 'PROCEEDED PAST THE CHECK'",
        ]
    )
    runner = tmp_path / "region.ps1"
    runner.write_text(script, encoding="utf-8")
    r = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(runner)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        env=_clean_env(),
    )
    print(r.stdout, r.stderr)
    return r


def test_an_install_from_a_checkout_behind_origin_main_refuses(tmp_path: Path) -> None:
    _need_tools()
    r = _run_region(_fixture(tmp_path, behind=True), tmp_path, allow=False)
    both = r.stdout + r.stderr
    assert r.returncode != 0 and "PROCEEDED" not in both, both
    assert "Refusing to install" in both and "1 commit(s) behind origin/main" in both, both
    assert "-AllowStaleSource" in both and "rollback" in both, (
        "the refusal must name the override and the deliberate case it is for"
    )


def test_the_override_installs_a_stale_source_with_a_warning(tmp_path: Path) -> None:
    _need_tools()
    r = _run_region(_fixture(tmp_path, behind=True), tmp_path, allow=True)
    assert r.returncode == 0 and "PROCEEDED PAST THE CHECK" in r.stdout, r.stdout + r.stderr
    assert "WARNING" in r.stdout and "-AllowStaleSource" in r.stdout, r.stdout


def test_a_current_checkout_installs_without_the_override(tmp_path: Path) -> None:
    """Control: the refusal is conditional, so its firing above is a reading of the fixture."""
    _need_tools()
    r = _run_region(_fixture(tmp_path, behind=False), tmp_path, allow=False)
    assert r.returncode == 0 and "PROCEEDED PAST THE CHECK" in r.stdout, r.stdout + r.stderr
    assert "WARNING" not in r.stdout, r.stdout


def test_an_install_refuses_when_origin_main_cannot_be_read(tmp_path: Path) -> None:
    _need_tools()
    r = _run_region(_lonely(tmp_path), tmp_path, allow=False)
    both = r.stdout + r.stderr
    assert r.returncode != 0 and "could not be read" in both, both


def test_the_override_on_an_unreadable_ref_does_not_promise_a_verdict_it_cannot_give(
    tmp_path: Path,
) -> None:
    _need_tools()
    r = _run_region(_lonely(tmp_path), tmp_path, allow=True)
    assert r.returncode == 0 and "PROCEEDED PAST THE CHECK" in r.stdout, r.stdout + r.stderr
    assert "WARNING" in r.stdout and "origin/main is unreadable" in r.stdout, r.stdout
    assert "NOT CURRENT" not in r.stdout, r.stdout


def test_a_non_default_yardstick_is_named_when_the_check_passes(tmp_path: Path) -> None:
    """`-UpstreamRef HEAD` passes any committed tree, so a pass against it must say what it was."""
    _need_tools()
    r = _run_region(_fixture(tmp_path, behind=True), tmp_path, allow=False, ref="HEAD")
    assert r.returncode == 0 and "PROCEEDED PAST THE CHECK" in r.stdout, r.stdout + r.stderr
    assert "NOTE" in r.stdout and "-UpstreamRef HEAD" in r.stdout, r.stdout


def test_a_missing_source_is_refused_even_with_the_override(tmp_path: Path) -> None:
    """Left to the Copy-Item, a missing gate failed only after the allowlist write had changed the box."""
    _need_tools()
    checkout = _fixture(tmp_path, behind=False)
    (checkout / GATE_REL).unlink()
    r = _run_region(checkout, tmp_path, allow=True)
    both = r.stdout + r.stderr
    assert r.returncode != 0 and "PROCEEDED" not in both, both
    assert "has no gate at" in both, both


def test_the_check_runs_before_anything_on_the_box_changes() -> None:
    """A refusal says nothing was changed, so the check must precede every install-path write."""
    text = INSTALLER.read_text(encoding="utf-8")
    # The install section's own banner. Everything the check is compared against is searched for
    # FROM here, so the -Uninstall block's own `$bak = Write-GovernedRoots` cannot stand in for the
    # install path's, and a check moved up into -Uninstall fails the first assertion.
    install = text.index("# " + "-" * 89 + " install\n")
    assert text.count(_REGION_START) == 1, "the stale-source region must appear exactly once"
    check = text.index(_REGION_START)
    assert install < check, "the stale-source check is not on the install path"
    for write in (
        _REGION_END,
        "$bak = Write-GovernedRoots -Path $ReposFile",
        "Copy-Item -LiteralPath $GateSrc -Destination $GateDst",
    ):
        assert check < text.index(write, install), f"the stale-source check runs after {write!r}"

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Guard the leak-gate's own machinery (scripts/publish/publish.ps1 + install-mirror-hook.ps1).

publish.ps1 is a fail-closed gate that keeps customer/PHI-adjacent data off the public mirror. Nothing
executes it in CI (it needs a live remote + a public clone), so without THESE tests a refactor could
silently delete the harness self-check, revert gitleaks to warn-only, or drift the Gate-Provenance trailer
out of sync with the hook that enforces it — and every other test would still pass. Each test here fails
LOUDLY if a load-bearing guard disappears. They are pure text/`re` checks (no pwsh needed) so they run
everywhere the suite runs.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
PUBLISH = _REPO / "scripts" / "publish" / "publish.ps1"
INSTALLER = _REPO / "scripts" / "publish" / "install-mirror-hook.ps1"


def _pub() -> str:
    return PUBLISH.read_text(encoding="utf-8")


def _installer() -> str:
    return INSTALLER.read_text(encoding="utf-8")


def _hook_regex() -> str:
    """The exact regex the pre-push hook greps commit messages for (extracted, not hardcoded, so drift on
    either side of the contract is caught)."""
    m = re.search(r"grep -qE '([^']+)'", _installer())
    assert m, "could not find the hook's `grep -qE '...'` trailer regex in install-mirror-hook.ps1"
    return m.group(1)


# --- the trailer <-> hook contract (the single highest-value check) ----------------------------------


def test_publish_trailer_matches_hook_regex() -> None:
    # publish.ps1 stamps the mirror commit; the hook enforces the stamp. If either drifts, EITHER every
    # legitimate publish is rejected (hard outage) OR ungated commits sail through. Pin them together.
    sha = "a" * 40
    rendered = f"Gate-Provenance: origin/main@{sha} gate-tree={sha}"
    assert re.search(_hook_regex(), rendered, re.M), (
        f"the trailer publish.ps1 emits does not match the hook regex.\n"
        f"  regex: {_hook_regex()}\n  trailer: {rendered}"
    )
    # and publish.ps1 really emits that shape (AuthBranch pinned to main is the only pushable case)
    assert "Gate-Provenance: origin/$AuthBranch@$authSha gate-tree=" in _pub(), (
        "publish.ps1 no longer emits the expected Gate-Provenance trailer template"
    )


def test_hook_regex_rejects_ungated_and_weakened_trailers() -> None:
    rx = _hook_regex()
    sha = "a" * 40
    bad = {
        "empty / no trailer": "",
        "prose only": "Publish snapshot 2026-07-13 (from deadbeef)",
        "short sha": f"Gate-Provenance: origin/main@{'a' * 7} gate-tree={sha}",
        "uppercase sha": f"Gate-Provenance: origin/main@{'A' * 40} gate-tree={sha}",
        "non-main branch (weaker gate)": f"Gate-Provenance: origin/dev@{sha} gate-tree={sha}",
        "trailing text after trailer": f"Gate-Provenance: origin/main@{sha} gate-tree={sha} oops",
        "missing gate-tree": f"Gate-Provenance: origin/main@{sha}",
    }
    for why, msg in bad.items():
        assert not re.search(rx, msg, re.M), f"hook regex WRONGLY accepts: {why!r} -> {msg!r}"


# --- the hook body must be executable by git's sh ----------------------------------------------------


def test_hook_body_is_posix_sh_and_lf() -> None:
    src = _installer()
    assert "#!/bin/sh" in src, "hook lost its shebang"
    # installer must strip CRLF and write UTF-8 without BOM, or git's sh refuses ('bad interpreter').
    assert '-replace "`r`n", "`n"' in src, "installer no longer forces LF line endings on the hook"
    assert "UTF8Encoding" in src, "installer no longer writes the hook UTF-8 (no BOM)"


def test_hook_checks_all_introduced_commits_not_just_tip() -> None:
    # A new-branch / re-created-ref push must verify every introduced commit, or an ungated parent rides in
    # under a gated tip — precisely the mirror re-bootstrap path.
    assert "--not --remotes=origin" in _installer(), (
        "the hook's new-branch path must rev-list all introduced commits (`--not --remotes=origin`), not the tip"
    )


def test_installer_resolves_core_hookspath() -> None:
    # A hardcoded <pub>/.git/hooks is dead when core.hooksPath is set (common in worktrees). The installer
    # must resolve the real hook path and VERIFY after writing.
    src = _installer()
    assert "core.hooksPath" in src, (
        "installer ignores core.hooksPath (hook may be written where git never looks)"
    )
    assert "--git-common-dir" in src, "installer must resolve the common git dir"
    assert "Post-install verification" in src, (
        "installer must verify the hook is where git will run it"
    )


# --- guard-presence canaries on publish.ps1 (silent-removal tripwires) --------------------------------


def test_publish_guard_canaries_present() -> None:
    pub = _pub()
    required = {
        "self-check verifies the RUNNING file": "hash-object -- $PSCommandPath",
        "EOL-safe self-check (forced normalization)": "core.autocrlf=true hash-object",
        "live-remote authority via FETCH_HEAD": "FETCH_HEAD",
        "fetch can never hang": "GIT_TERMINAL_PROMPT",
        "-GateRef can never push": "-GateRef verifies against an UNAUTHORITATIVE gate",
        "-AuthBranch can never push (case-sensitive)": "-not $isMain -and $Push",
        "gitleaks mandatory for -Push": "-not $gitleaks -and -not $DryRun",
        "vacuous-tree floor": "-lt 200",
        "-Push requires the mirror hook": "Resolve-HookFile",
        "anchored origin host + repo (no fork/mirror gate)": "github\\.com",
        "provenance trailer is written": "Gate-Provenance: origin/$AuthBranch@$authSha",
        # gate is MATERIALIZED from the authoritative commit, never read from the on-disk checkout
        "gate materialized from authSha": "archive --format=zip -o $GateZip $authSha",
        "scanner run from the materialized gate": "$GateScanner = Join-Path $GateDir",
        # a real publish is unreachable with a non-authoritative gate (backstop for the force-DryRun)
        "non-authoritative-gate backstop before mirror": "a real publish was reached with a non-authoritative gate",
    }
    missing = [name for name, tok in required.items() if tok not in pub]
    assert not missing, f"publish.ps1 lost these guards: {missing}"


def test_gateref_and_nonmain_authbranch_force_dryrun() -> None:
    # The documented invariant is "-GateRef / a non-main -AuthBranch can VERIFY but never PUBLISH". Each
    # relies on forcing -DryRun; if a refactor drops the `$DryRun = $true`, a -GateRef run (no -Push) could
    # proceed to commit a snapshot gated by an arbitrary ref, carrying a hook-valid origin/main@ trailer.
    # Pin that BOTH escape branches force DryRun, and that the pre-mirror backstop exists as a second line.
    pub = _pub()
    # -GateRef block forces DryRun
    gateref_block = re.search(r"if \(\$GateRef\)\s*\{(.*?)\}", pub, re.S)
    assert gateref_block and "$DryRun = $true" in gateref_block.group(1), (
        "the -GateRef branch no longer forces -DryRun (it could then publish an arbitrary-ref gate)"
    )
    # non-main -AuthBranch forces DryRun
    assert re.search(r"if \(-not \$isMain\)\s*\{[^}]*\$DryRun = \$true", pub, re.S), (
        "a non-main -AuthBranch no longer forces -DryRun"
    )
    # the belt-and-suspenders backstop guards the mirror step even if a force-DryRun is removed
    assert '$GateRef -or -not $AuthBranch.Equals("main"' in pub, (
        "the pre-mirror non-authoritative-gate backstop is gone"
    )


def test_publish_has_no_stale_gate_escape_hatch() -> None:
    # The ONLY hatch is -GateRef (which forces -DryRun). There must never be a way to publish through an
    # unverified/stale gate.
    pub = _pub()
    # Check the VARIABLE form ($Name), which appears only if it is a real parameter -- the docs deliberately
    # mention "-AllowStaleGate" (dash form) to say it does NOT exist, so a naive substring check false-trips.
    for var in ("$AllowStaleGate", "$SkipGate", "$AllowUnverified", "$NoGate", "$Insecure"):
        assert var not in pub, f"a gate-bypass parameter {var} was reintroduced"


# --- end-to-end: the hook actually blocks an ungated push --------------------------------------------


@pytest.mark.skipif(shutil.which("git") is None, reason="git not on PATH")
@pytest.mark.skipif(
    shutil.which("sh") is None and shutil.which("bash") is None, reason="no POSIX sh for git hooks"
)
def test_hook_blocks_ungated_push_end_to_end(tmp_path: Path) -> None:
    # Drive the REAL hook body against a real bare remote: an ungated commit must be refused, a properly
    # trailered one accepted. This is the only check that catches "git reflowed/stripped the trailer".
    hook_body = re.search(r"\$hook = @'\r?\n(.*?)\r?\n'@", _installer(), re.S)
    assert hook_body, "could not extract the hook body from the installer"
    body = hook_body.group(1).replace("\r\n", "\n")

    def git(*args: str, cwd: Path, **kw: object) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, **kw)  # type: ignore[return-value]

    bare = tmp_path / "mirror.git"
    git("init", "--bare", "-b", "main", str(bare), cwd=tmp_path, check=True)
    work = tmp_path / "work"
    git("clone", str(bare), str(work), cwd=tmp_path, check=True)
    git("config", "user.email", "t@t", cwd=work, check=True)
    git("config", "user.name", "t", cwd=work, check=True)

    hook_path = work / ".git" / "hooks" / "pre-push"
    hook_path.write_text(body, encoding="utf-8", newline="\n")
    hook_path.chmod(0o755)

    sha = "0" * 40
    trailer = f"Publish snapshot\n\nGate-Provenance: origin/main@{sha} gate-tree={sha}"

    # 1) ungated commit -> push REFUSED, remote ref must not move
    (work / "a.txt").write_text("1", encoding="utf-8")
    git("add", "-A", cwd=work, check=True)
    git("commit", "-m", "ungated snapshot", cwd=work, check=True)
    r = git("push", "origin", "main", cwd=work)
    assert r.returncode != 0, "hook allowed an UNGATED push"
    assert git("rev-parse", "main", cwd=bare).returncode != 0, (
        "ungated commit reached the bare remote"
    )

    # 2) make the (only) commit gated -> push ACCEPTED. Amend so the branch history is a single, gated
    #    commit; a new gated commit ON TOP of the ungated one would (correctly) still be refused, because
    #    the new-branch path checks EVERY introduced commit, not just the tip (finding #9).
    git("commit", "--amend", "-m", trailer, cwd=work, check=True)
    r = git("push", "origin", "main", cwd=work)
    assert r.returncode == 0, f"hook rejected a properly gated push:\n{r.stderr}"

    # 3) a new UNGATED commit on top of a gated history -> REFUSED (the tip-only bug would miss this)
    (work / "c.txt").write_text("3", encoding="utf-8")
    git("add", "-A", cwd=work, check=True)
    git("commit", "-m", "sneaky ungated followup", cwd=work, check=True)
    r = git("push", "origin", "main", cwd=work)
    assert r.returncode != 0, "hook allowed an ungated commit pushed on top of a gated history"

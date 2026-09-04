# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""An install must ADD to the machine-wide gate allowlist, not replace it (BACKLOG #1375).

THE DEFECT. `install-gate.ps1` wrote `worktree-gate.repos.txt` with a bare `Set-Content` of the roots
one run had been given, and `-Repo` defaults to exactly ONE root. So a bare install run from either of
two governed checkouts un-governed the other, with no backup and no line printed.

WHY NOTHING REPORTED IT, stated because the obvious explanation is the wrong one. It is NOT the gate's
zero-root kill switch: that fires only when the allowlist holds no roots at all, and a bare run writes
one. The dropped root is simply absent from the gate's `$roots` list, so it matches no rule, and the
gate exits 0 on every tool call into that tree without printing anything. The gate is ON and just no
longer looking at the checkout you care about -- which reads exactly like the gate working.

WHAT THESE TESTS PIN, AND THE ARM THAT MAKES THEM WORTH RUNNING. Every case here seeds an allowlist
with a root the run does NOT name. A merge keeps it; the replace this item removes loses it.

The revert was RUN, not reasoned about: putting `$govern = @($resolved)` back in the merge branch and
running this file gives 4 failed, 3 passed --

    test_an_install_adds_its_roots_to_the_ones_the_allowlist_already_governs
    test_narrowing_scope_needs_the_explicit_switch
    test_reinstalling_the_same_root_neither_duplicates_it_nor_regrows_the_header
    test_a_root_already_governed_is_not_re_added_under_a_different_spelling

-- and the source was then restored. Recorded as the measured set rather than the predicted one: the
prediction named test_a_narrowing_run_names_every_root_it_is_about_to_stop_governing and was wrong.
That test drives the narrowing branch explicitly, so it stays green under a replace and is NOT an
anti-vacuity arm; it pins the announcement, and its own control is the quiet arm at the end of it.

WHY THESE EXECUTE THE REGION RATHER THAN ASSERT ITS SHAPE -- the seam
tests/test_install_gate_records_the_install.py establishes, and the reasoning is stated in full there.
The short form: the install path refuses to run inside Claude Code, so a whole-script run is
unavailable, and a static test that pins call-site SHAPE gets escaped by the next rename. These cut
the real region out of the real file and RUN it against a temp allowlist, then read the file back.

NOTHING HERE TOUCHES THE MACHINE ALLOWLIST. Every case drives a fresh file under tmp_path. The real
one at ~/.claude/hooks/worktree-gate.repos.txt governs live checkouts, and a test that rewrote it
would be the #1375 defect wearing a test's clothes.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

# The brace-matching lift, imported rather than re-typed. A second copy of the extractor is a second
# definition of "where does this region start", and the copy that drifts is the one that decides
# whether these tests are still reading the code that ships.
from test_install_gate_records_the_install import _function

REPO = Path(__file__).resolve().parents[1]
INSTALLER = REPO / "scripts" / "worktree" / "install-gate.ps1"

# The region under test: from the read of the existing allowlist through the write of the new one.
_START = "$existing = Read-GovernedRoots $ReposFile"
_END = ") | Set-Content -LiteralPath $ReposFile -Encoding utf8"

# Two checkouts on one box, which is the precondition the item is about. VAULT is the root a bare run
# never names, so it is the one a replace loses.
VAULT = r"C:\Users\me\Code\MessageFoundry-vault"
ENGINE = r"C:\Users\me\Code\MessageFoundry"


def _region() -> str:
    text = INSTALLER.read_text(encoding="utf-8")
    i = text.index(_START)
    j = text.index(_END) + len(_END)
    return text[i:j]


def _roots(path: Path) -> list[str]:
    """The governed roots as the gate would read them: non-blank, non-comment lines."""
    if not path.exists():
        return []
    lines = (ln.strip() for ln in path.read_text(encoding="utf-8").splitlines())
    return [ln for ln in lines if ln and not ln.startswith("#")]


def _comments(path: Path) -> list[str]:
    lines = (ln.strip() for ln in path.read_text(encoding="utf-8").splitlines())
    return [ln for ln in lines if ln.startswith("#")]


def _run(
    repos: Path,
    *,
    resolved: list[str],
    replace: bool = False,
    existing: list[str] | None = None,
) -> str:
    """Run the real region against a temp allowlist and return what it printed.

    `existing` seeds the file the way a previous install left it, header included, so the region reads
    a realistic input rather than a bare list of paths.
    """
    if shutil.which("pwsh") is None:
        pytest.skip("SKIP (nothing run): pwsh not on PATH")

    if existing is not None:
        repos.write_text(
            "\n".join(["# Primary checkouts governed by the worktree gate.", *existing]) + "\n",
            encoding="utf-8",
        )

    quoted = ", ".join(f"'{r}'" for r in resolved)
    script = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f"$ReposFile = '{repos}'",
            f"$resolved = @({quoted})",
            f"$ReplaceAllowlist = ${'true' if replace else 'false'}",
            _function("Read-GovernedRoots"),
            _function("Get-PathKey"),
            _region(),
        ]
    )
    runner = repos.parent / "run.ps1"
    runner.write_text(script, encoding="utf-8")
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(runner)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert proc.returncode == 0, f"the region failed to run:\n{proc.stdout}\n{proc.stderr}"
    return proc.stdout


def test_an_install_adds_its_roots_to_the_ones_the_allowlist_already_governs(
    tmp_path: Path,
) -> None:
    """The #1375 defect itself. This reddens the moment the merge degrades back to a replace."""
    repos = tmp_path / "worktree-gate.repos.txt"

    # CONTROL FIRST: the run must not name VAULT, or a replace would keep it and the assertion below
    # would be satisfied by the defect. This is the whole basis of the test.
    resolved = [ENGINE]
    assert VAULT not in resolved, (
        "fixture named the root it is testing for; the test proves nothing"
    )

    _run(repos, existing=[VAULT], resolved=resolved)

    assert _roots(repos) == [VAULT, ENGINE], (
        "an install that names one root must UNION it with the roots already governed. Dropping "
        f"{VAULT} here is the #1375 defect: nothing downstream reports the loss."
    )


def test_the_previous_allowlist_is_backed_up_beside_it_before_the_write(tmp_path: Path) -> None:
    repos = tmp_path / "worktree-gate.repos.txt"
    bak = Path(f"{repos}.bak")

    _run(repos, existing=[VAULT], resolved=[ENGINE])

    assert bak.exists(), (
        "the allowlist was overwritten with no backup, which is half the #1375 defect"
    )
    assert _roots(bak) == [VAULT], (
        "the .bak does not hold the PREVIOUS list, so it is not a recovery point"
    )
    assert ENGINE not in _roots(bak), (
        "the .bak carries the root this run added, so it is a copy of the NEW file rather than the old "
        "one -- it would restore the state you are trying to undo"
    )


def test_a_first_install_writes_the_allowlist_and_leaves_no_backup(tmp_path: Path) -> None:
    """No previous file means no recovery point to keep, and a stale .bak would be worse than none."""
    repos = tmp_path / "worktree-gate.repos.txt"

    _run(repos, existing=None, resolved=[ENGINE])

    assert _roots(repos) == [ENGINE]
    assert not Path(f"{repos}.bak").exists(), "backed up a file that did not exist"


def test_narrowing_scope_needs_the_explicit_switch(tmp_path: Path) -> None:
    """Both arms in one test: narrowing must stay possible, and must not be reachable by default."""
    merged = tmp_path / "merged" / "worktree-gate.repos.txt"
    merged.parent.mkdir()
    _run(merged, existing=[VAULT, ENGINE], resolved=[ENGINE], replace=False)
    assert _roots(merged) == [VAULT, ENGINE], "the default run narrowed the governed set"

    narrowed = tmp_path / "narrowed" / "worktree-gate.repos.txt"
    narrowed.parent.mkdir()
    _run(narrowed, existing=[VAULT, ENGINE], resolved=[ENGINE], replace=True)
    assert _roots(narrowed) == [ENGINE], (
        "-ReplaceAllowlist did not narrow the set. Narrowing has to remain available, or the only way "
        "to drop a root is to hand-edit the file the installer will merge back into next run."
    )


def test_a_narrowing_run_names_every_root_it_is_about_to_stop_governing(tmp_path: Path) -> None:
    """A warning printed on every run is not information, so the quiet arm is asserted too."""
    narrowed = tmp_path / "narrowed" / "worktree-gate.repos.txt"
    narrowed.parent.mkdir()
    loud = _run(narrowed, existing=[VAULT, ENGINE], resolved=[ENGINE], replace=True)

    assert VAULT in loud, (
        "the run dropped a root without naming it. The governed list being printable by -Status is not "
        "the same announcement: what nothing printed was the TRANSITION."
    )
    assert "no longer governed" in loud, f"the narrowing is not announced as a loss:\n{loud}"

    merged = tmp_path / "merged" / "worktree-gate.repos.txt"
    merged.parent.mkdir()
    quiet = _run(merged, existing=[VAULT, ENGINE], resolved=[ENGINE], replace=False)
    assert "no longer governed" not in quiet, (
        "a merging run warns about a narrowing that did not happen; a reader learns to skip that line, "
        "which is how a real one goes unnoticed"
    )


def test_reinstalling_the_same_root_neither_duplicates_it_nor_regrows_the_header(
    tmp_path: Path,
) -> None:
    repos = tmp_path / "worktree-gate.repos.txt"
    _run(repos, existing=[VAULT], resolved=[ENGINE])
    after_first = _comments(repos)

    _run(repos, resolved=[ENGINE])

    assert _roots(repos) == [VAULT, ENGINE], "a re-install duplicated a root it already governed"
    assert _comments(repos) == after_first, (
        "the header grew on the second run, so the reader is feeding comment lines back in as roots"
    )


def test_a_root_already_governed_is_not_re_added_under_a_different_spelling(tmp_path: Path) -> None:
    """Windows paths are case-insensitive and a hand-edited line can carry a trailing separator."""
    repos = tmp_path / "worktree-gate.repos.txt"
    already = ENGINE.lower() + "\\"

    _run(repos, existing=[already], resolved=[ENGINE])

    assert _roots(repos) == [already], (
        "the same checkout is now listed twice under two spellings. The gate compares paths "
        "case-insensitively, so the duplicate governs nothing new and only misreports the scope."
    )

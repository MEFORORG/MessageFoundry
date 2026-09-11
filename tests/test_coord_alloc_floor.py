# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``Get-Floor`` must read EVERY ref without spawning a git process PER ref (BACKLOG #1534).

The defect, its measurement and the one batching shape that was rejected are recorded ONCE, beside
the code, in ``Get-Floor``'s adr branch in ``scripts/coord/alloc.ps1``. Read that comment first --
restating its numbers here is how two copies of one measurement start to drift.

**The speed fix is where a correctness hole gets introduced, which is why this file exists.**

**The process-count case covers BOTH kinds, deliberately.** Only the adr branch was slow, but both
are batched now for the same reason, and a guard aimed at the branch that happened to break leaves
the other free to regress in silence. The invariant belongs to ``Get-Floor``, not to one of its arms.

``-ShowFloor`` is used throughout: allocation is a one-way door and a test that allocated would leave
permanent holes in a shared registry.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_ALLOC = _ROOT / "scripts" / "coord" / "alloc.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)


def _git(*args: str, cwd: Path) -> str:
    proc = subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True)
    return proc.stdout


def _checkout(path: Path, adrs: dict[str, str]) -> Path:
    """A minimal checkout carrying alloc.ps1 and the numbers the floor is supposed to see.

    Only ``scripts/coord/alloc.ps1`` is copied. The script anchors every git call on ``$PSScriptRoot``
    (BACKLOG #1060), so the copy -- not this repository -- is the tree whose floor gets computed.

    ``scripts/hooks/ledger_check.py`` is deliberately absent even though the backlog kind reads
    PUBLIC_BACKLOG_FLOOR out of it. ``-ShowFloor`` returns before the refusal that needs it, so the
    floor is still computed and printed; adding a stub would test a file this module is not about.
    """
    (path / "scripts" / "coord").mkdir(parents=True)
    (path / "docs" / "adr").mkdir(parents=True)
    shutil.copy2(_ALLOC, path / "scripts" / "coord" / "alloc.ps1")
    for name, body in adrs.items():
        (path / "docs" / "adr" / name).write_text(body, encoding="utf-8")
    (path / "docs" / "BACKLOG.md").write_text(
        "# Backlog\n\n## 77. An item, so the backlog arm has a floor to find\n", encoding="utf-8"
    )
    _git("init", "-b", "main", ".", cwd=path)
    _git("config", "user.email", "t@e.com", cwd=path)
    _git("config", "user.name", "t", cwd=path)
    _git("add", "-A", cwd=path)
    _git("commit", "-m", "fixture", "--no-verify", cwd=path)
    return path


def _floor(repo: Path, kind: str = "adr", env: dict[str, str] | None = None) -> int:
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(repo / "scripts" / "coord" / "alloc.ps1"),
            "-ShowFloor",
            "-Kind",
            kind,
        ],
        cwd=str(repo),
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    match = re.search(r"^floor\s*:\s*(\d+)$", proc.stdout, re.MULTILINE)
    assert match, f"no floor line in:\n{proc.stdout}"
    return int(match.group(1))


def test_a_number_is_seen_even_when_its_file_shares_a_blob_with_another(
    tmp_path: Path,
) -> None:
    """The dedup trap, and the reason it is asserted on the MAXIMUM.

    Batching means reading each DISTINCT object once, and the tempting one-process spelling of that
    -- ``git rev-list --objects`` over the trees -- dedupes by OBJECT rather than by name. Measured
    directly while the implementation was being chosen: a tree holding ``0150-alpha.md`` and
    ``0151-beta.md`` with byte-identical content printed ONE of the two names.

    The floor is a maximum, so a hidden number only changes the answer when it IS the maximum. 0150
    sorts first in the tree, so the deduping sweep keeps 0150 and drops 0151 -- the higher one, the
    one that moves the floor. Give 0151 a distinct body and this test passes with the bug in.
    """
    stub = "# Superseded\n"
    repo = _checkout(
        tmp_path / "dup",
        {
            "0001-first.md": "# First\n",
            "0150-alpha.md": stub,
            "0151-beta.md": stub,
        },
    )
    blobs = {
        line.split()[2]
        for line in _git("ls-tree", "HEAD:docs/adr", cwd=repo).splitlines()
        if "-alpha.md" in line or "-beta.md" in line
    }
    assert len(blobs) == 1, f"fixture is not exercising the trap; blobs={blobs}"

    assert _floor(repo) == 151


def test_the_floor_reads_a_side_branch_not_just_the_checked_out_tip(
    tmp_path: Path,
) -> None:
    """The all-refs term, asserted by the DIVERGENCE -- the high number is not on main.

    A number that exists only on an unpushed branch is taken. Put the maximum on main and this case
    passes against a sweep that reads one ref.
    """
    repo = _checkout(tmp_path / "branch", {"0001-first.md": "# First\n"})
    _git("checkout", "-q", "-b", "side", cwd=repo)
    (repo / "docs" / "adr" / "0090-only-on-a-branch.md").write_text("# Side\n", encoding="utf-8")
    _git("add", "-A", cwd=repo)
    _git("commit", "-m", "side adr", "--no-verify", cwd=repo)
    _git("checkout", "-q", "main", cwd=repo)
    assert not (repo / "docs" / "adr" / "0090-only-on-a-branch.md").exists()

    assert _floor(repo) == 90


@pytest.mark.parametrize(("kind", "expected"), [("adr", 1), ("backlog", 77)])
def test_the_sweep_does_not_spawn_a_git_process_per_ref(
    tmp_path: Path, kind: str, expected: int
) -> None:
    """BACKLOG #1534, measured rather than timed.

    A wall-clock assertion would be flaky and -- worse -- would pass on any clone small enough to run
    the suite, which is every CI runner. The defect is proportionality, so count the git processes
    instead: ``GIT_TRACE`` writes one ``trace: built-in: git ...`` line per invocation, appended by
    every process to the one file it names.

    Both arms were run on this fixture before the bound was chosen, which is the only way to know it
    discriminates: the pre-fix script made **206** invocations (202 of them ``ls-tree``) for 200 refs,
    and the batched one made **6**, none of them ``ls-tree``. Six is what BOTH kinds cost, and the
    count is fixed whatever the ref count, so the bound below is a constant and the 200 refs are
    there only to make a per-ref sweep unmistakable.

    The cat-file assertion is the POSITIVE CONTROL. An empty or unwritten trace file would satisfy
    the bound while measuring nothing at all, and a guard that cannot fail is worse than no guard.
    """
    repo = _checkout(tmp_path / f"refs-{kind}", {"0001-first.md": "# First\n"})
    head = _git("rev-parse", "HEAD", cwd=repo).strip()
    # BYTES, not text. Text-mode stdin translates "\n" to "\r\n" on Windows and git rejects the
    # command line it then reads -- `fatal: create refs/heads/b0: extra input`. One process creates
    # all 200 refs; 200 `git branch` calls would be the very cost this test exists to measure.
    subprocess.run(
        ["git", "update-ref", "--stdin"],
        cwd=str(repo),
        check=True,
        capture_output=True,
        input="".join(f"create refs/heads/b{i} {head}\n" for i in range(200)).encode(),
    )
    assert len(_git("for-each-ref", "--format=%(refname)", cwd=repo).splitlines()) >= 200

    trace = tmp_path / f"git-trace-{kind}.log"
    env = {**os.environ, "GIT_TRACE": str(trace)}
    assert _floor(repo, kind=kind, env=env) == expected

    invocations = [
        line
        for line in trace.read_text(encoding="utf-8", errors="replace").splitlines()
        if "built-in: git " in line
    ]
    assert any("cat-file" in line for line in invocations), (
        "GIT_TRACE captured no cat-file invocation, so it is not measuring the sweep:\n"
        + "\n".join(invocations[:20])
    )
    assert len(invocations) <= 15, (
        f"{len(invocations)} git invocations for 200 refs -- the sweep scales with the ref count:\n"
        + "\n".join(invocations[:20])
    )

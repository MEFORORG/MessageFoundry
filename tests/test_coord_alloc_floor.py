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
    and the batched one made **6**, none of them ``ls-tree``. The 200 refs are there only to make a
    per-ref sweep unmistakable.

    **WHAT THIS CASE CANNOT SEE, stated because the bound looks more general than it is.** All 200
    refs here point at ONE commit, so the fixture holds exactly ONE distinct ledger blob. Since
    BACKLOG #1535 the backlog sweep runs one ``git grep`` per 128 distinct BLOBS, so on this fixture
    it is one grep whatever the chunk size -- and an implementation that never chunked at all, and
    therefore dies on a real clone's 1,500 blobs against the Windows argv limit, would stay green
    right here. The count is fixed against the REF count, which is what this case pins; it is not
    fixed against the blob count. ``test_the_backlog_sweep_chunks_over_distinct_blobs`` is the case
    that sees the other axis.

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


# Chunk size in alloc.ps1's backlog branch. 200 distinct blobs is deliberately more than one chunk
# and less than two full ones, so a sweep that silently stops after the first chunk loses the planted
# maximum instead of merely running slower.
_GREP_CHUNK = 128
_BLOBS = 200


def _many_distinct_ledger_blobs(repo: Path, count: int) -> int:
    """Give the repo ``count`` DISTINCT docs/BACKLOG.md blobs, one per ref, and return the maximum.

    ``git fast-import`` because the alternative is ``count`` commits at roughly 40ms of process
    startup each. One process builds the whole object graph.

    Every blob differs in content, which is what makes them distinct objects -- 200 refs pointing at
    one commit is one blob, and that is precisely the shape the sibling case above cannot see past.
    The maximum is planted in the LAST blob alone, so it falls in the final chunk: an implementation
    that processes only the first chunk still finds 199 numbers and the wrong answer.
    """
    lines = []
    for i in range(count):
        number = 100 + i
        body = f"# Backlog\n\n## {number}. item on ref {i}\n"
        payload = body.encode()
        lines.append(f"blob\nmark :{i + 1}\ndata {len(payload)}\n{body}")
        lines.append(
            f"commit refs/heads/blob{i}\n"
            f"author t <t@e.com> 0 +0000\n"
            f"committer t <t@e.com> 0 +0000\n"
            "data 0\n"
            f"M 100644 :{i + 1} docs/BACKLOG.md\n"
        )
    subprocess.run(
        ["git", "fast-import", "--quiet", "--force"],
        cwd=str(repo),
        check=True,
        capture_output=True,
        input="".join(lines).encode(),
    )
    return 100 + count - 1


def test_the_backlog_sweep_chunks_over_distinct_blobs(tmp_path: Path) -> None:
    """BACKLOG #1535. The axis the ref-count case is blind to.

    The backlog sweep does not read blob bodies any more -- ``git grep`` filters them in C and emits
    only the headings. That trades a byte-volume problem for an ARGUMENT-LENGTH one: every distinct
    blob oid goes on a command line, and Windows' CreateProcess refuses past 32,767 characters. On
    this clone, 795 oids pass and 796 fail. So the sweep must chunk, and this case is what proves it
    does.

    **The planted maximum is the instrument.** It lives on a ref and NOWHERE else -- not in the
    working tree, not in the registry -- so it can only be found by the term under test. Every way
    this stage fails silently produces the same observable, a floor that is merely lower: a dropped
    chunk, an over-long argv, ``\\d`` in a POSIX ERE that has no ``\\d``, a missing ``-h``, a binary
    blob suppressed, a hostile ``grep.lineNumber``. All of them miss 299 and this assertion catches
    all of them.

    Asserting the floor is only safe here BECAUSE the fixture is built so the floor cannot come from
    anywhere else. On the real clone it would prove nothing: there, the registry term carries the
    maximum, so the whole stage can return nothing without moving the printed floor.
    """
    repo = _checkout(tmp_path / "blobs", {"0001-first.md": "# First\n"})
    planted = _many_distinct_ledger_blobs(repo, _BLOBS)

    blobs = {
        _git("rev-parse", f"refs/heads/blob{i}:docs/BACKLOG.md", cwd=repo).strip()
        for i in range(_BLOBS)
    }
    assert len(blobs) == _BLOBS, (
        f"fixture is not exercising chunking: {len(blobs)} distinct blobs, expected {_BLOBS}"
    )
    assert planted > 77, "the planted maximum must beat the working-tree term's 77"
    assert f"## {planted}." not in (repo / "docs" / "BACKLOG.md").read_text(encoding="utf-8")

    trace = tmp_path / "git-trace-chunk.log"
    env = {**os.environ, "GIT_TRACE": str(trace)}
    assert _floor(repo, kind="backlog", env=env) == planted

    invocations = [
        line
        for line in trace.read_text(encoding="utf-8", errors="replace").splitlines()
        if "built-in: git " in line
    ]
    greps = [line for line in invocations if "built-in: git grep" in line]
    expected_greps = -(-_BLOBS // _GREP_CHUNK)  # ceil
    assert len(greps) == expected_greps, (
        f"{len(greps)} git grep invocations for {_BLOBS} distinct blobs; expected "
        f"{expected_greps} at a chunk size of {_GREP_CHUNK}. Either the chunk size moved (update "
        f"_GREP_CHUNK here in the same commit) or the sweep stopped chunking."
    )
    # The count must track BLOBS, not refs, and must stay far below one-process-per-blob.
    assert len(invocations) <= 15, (
        f"{len(invocations)} git invocations for {_BLOBS} distinct blobs:\n"
        + "\n".join(invocations[:20])
    )


def test_the_backlog_sweep_survives_a_hostile_grep_config(tmp_path: Path) -> None:
    """BACKLOG #1535. The sweep reads git config that the old one never did.

    Moving stage 2 to ``git grep`` gave three ordinary config settings the power to silently zero the
    all-refs term. ``grep.lineNumber`` prefixes ``1302:``, ``grep.column`` prefixes ``1:``, and
    ``color.ui=always`` injects ANSI escapes -- and each one makes the anchored extraction match
    nothing at all, with a zero exit code and no error. ``git cat-file`` read none of them, so this is
    a failure mode the rewrite INTRODUCED, which is why it gets its own case rather than a comment.

    ``--no-line-number``, ``--no-column`` and ``--no-color`` neutralise all three. None of them is set
    on any machine here today, which is exactly why nobody would notice the day one is: this fixture
    sets all three deliberately so the flags are exercised rather than merely present.

    The assertion is again the planted maximum, which lives only on a ref. If any flag is dropped the
    sweep either finds nothing (floor falls to the working tree's 77) or throws on the malformed line.
    Both are failures here; both are silent on a fixture that does not set the config.

    **WHAT THESE CASES DO NOT REACH, measured rather than guessed.** Nine mutations of the shipped
    sweep were run against this file; seven are refused -- the ``\\d`` dialect, a missing ``-h``, no
    chunking, a dropped chunk, and each of ``--no-line-number`` / ``--no-color`` / ``-E``. Two are
    NOT caught, and both are defence-in-depth for a state no fixture here can produce:

    * removing ``-a`` -- no ledger blob in any fixture (or on the real clone) trips git's binary
      detection, so nothing exercises it. It stays in because the day one does, the lines vanish
      silently and a live number gets re-issued;
    * replacing the non-conforming-line ``throw`` with a skip -- with every neutralising flag present,
      no non-conforming line is ever emitted. It only fires once another guard has already failed,
      and its job is to make that failure loud instead of a silent zero.

    Neither gap is a reason to drop the flag or the throw. Both are a reason not to read a green run
    here as proof that every guard is live.
    """
    repo = _checkout(tmp_path / "hostile", {"0001-first.md": "# First\n"})
    planted = _many_distinct_ledger_blobs(repo, _BLOBS)

    _git("config", "grep.lineNumber", "true", cwd=repo)
    _git("config", "grep.column", "true", cwd=repo)
    _git("config", "color.ui", "always", cwd=repo)
    _git("config", "grep.patternType", "fixed", cwd=repo)
    # Prove the config is live, so a silently-ignored setting cannot make this pass vacuously.
    noisy = _git("grep", "-h", "-e", "## 100.", "refs/heads/blob0", cwd=repo)
    assert not noisy.startswith("## 100."), (
        f"fixture config is not reaching git grep; got a clean line: {noisy!r}"
    )

    assert _floor(repo, kind="backlog") == planted

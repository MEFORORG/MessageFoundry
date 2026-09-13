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

**A SECOND INVARIANT LIVES HERE TOO, and it is the opposite failure.** The sweep must also read refs
this clone does NOT yet have, which means a pre-flight ``git fetch origin`` -- see the pre-flight
block at ``alloc.ps1``'s single ``Get-Floor`` call site for why, where and how it fails closed. The
cases at the end of this file pin that fetch in both directions, pin the no-origin skip, pin the
refusal on a fetch that cannot succeed, and pin ``-List`` staying offline. They are the ones that
break if the fetch is deleted as dead weight.

``-ShowFloor`` is used throughout: allocation is a one-way door and a test that allocated would leave
permanent holes in a shared registry.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
from collections.abc import Sequence
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


def _invocations(trace: Path) -> list[str]:
    """Every git process the traced run started. ``GIT_TRACE`` writes one such line per invocation."""
    return [
        line
        for line in trace.read_text(encoding="utf-8", errors="replace").splitlines()
        if "built-in: git " in line
    ]


def _fetches(trace: Path) -> list[str]:
    """Just the fetch invocations, which is a count the retry cases assert on."""
    return [line for line in _invocations(trace) if "built-in: git fetch" in line]


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


def _run(
    repo: Path, *args: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Run the fixture's OWN copy of alloc.ps1, from inside the fixture.

    One copy of the invocation, because the cases below drive it three ways -- ``-ShowFloor``, a real
    allocation, and ``-List`` -- and a second spelling is a second thing to keep in step.
    """
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(repo / "scripts" / "coord" / "alloc.ps1"),
            *args,
        ],
        cwd=str(repo),
        capture_output=True,
        text=True,
        env=env,
    )


def _floor(
    repo: Path,
    kind: str = "adr",
    env: dict[str, str] | None = None,
    extra: Sequence[str] = (),
) -> int:
    proc = _run(repo, "-ShowFloor", "-Kind", kind, *extra, env=env)
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

    Re-measured 2026-09-12, when the pre-flight fetch landed: **8** on both arms. This fixture has no
    remote, so the block adds one ``config --get remote.origin.url`` probe and, on that skip path, one
    ``git remote`` to decide whether to warn about an upstream under another name -- and no fetch. The
    bound is deliberately not tightened to 8: it exists to catch proportionality to the REF count, and
    a bound one process above the current total reds on any unrelated single-process addition.

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

    invocations = _invocations(trace)
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
    this stage fails silently produces the same observable, a floor that is merely lower: an
    over-long argv, ``\\d`` in a POSIX ERE that has no ``\\d``, a missing ``-h``, a binary blob
    suppressed, a hostile ``grep.lineNumber``. All of them miss 299 and the floor assertion catches
    all of them.

    **A DROPPED CHUNK IS CAUGHT BY THE GREP COUNT, NOT BY THE FLOOR, and an earlier version of this
    docstring had that wrong.** It reasoned that the maximum lands in the last chunk because it is
    written to the last ref created. Processing order is not creation order: stage 1 walks
    ``for-each-ref``, which sorts refnames LEXICOGRAPHICALLY, so ``blob199`` is the 112th ref and the
    maximum falls in chunk 0. Keeping only the first chunk therefore still finds 299, and it is the
    ``expected_greps`` assertion below that refuses it. Both assertions are load-bearing and they
    catch disjoint failures; do not drop either as redundant.

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

    invocations = _invocations(trace)
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


def _body_whose_blob_id_ends_in_a_lead_byte(repo: Path) -> tuple[str, str]:
    """Find an ADR body whose blob id's final byte is a DBCS lead byte (0x81-0xFE).

    Cheap: git hashes a short string in well under a millisecond and roughly half of all ids qualify,
    so this lands in a handful of tries. Raises rather than degrading, because a fixture that quietly
    settles for a non-lead byte is a test that cannot see the defect it was written for.
    """
    for i in range(2000):
        body = f"# Primer\n\nvariant {i}\n"
        oid = (
            subprocess.run(
                ["git", "hash-object", "--stdin"],
                cwd=str(repo),
                input=body.encode(),
                capture_output=True,
                check=True,
            )
            .stdout.decode()
            .strip()
        )
        if int(oid[-2:], 16) >= 0x81:
            return body, oid
    raise AssertionError("no body found whose blob id ends in a lead byte")


@pytest.mark.skipif(os.name != "nt", reason="console code pages are a Windows concept")
@pytest.mark.parametrize("codepage", [437, 932, 936, 950])
def test_the_adr_sweep_is_invariant_under_the_console_code_page(
    tmp_path: Path, codepage: int
) -> None:
    """The defect this case exists for SHIPPED, and nothing here could see it.

    An earlier adr stage 2 piped RAW tree objects through the pipeline and scanned them for
    ``(?:100644|100755) NNNN-``. A tree entry carries 20 raw bytes of object id, and PowerShell
    decodes native output with ``[Console]::OutputEncoding`` -- the OEM console code page on Windows.
    Under a DBCS page (932 Japanese, 936 Simplified Chinese, 949 Korean, 950 Traditional, all locale
    DEFAULTS) a lead byte ending one entry's id consumes the ``1`` that starts the next entry's
    ``100644``, and that ADR vanishes. Measured on the real clone: 181 numbers under utf-8, cp437 and
    cp1252; **174 under cp932 and 164 under cp936/950**.

    The comment that shipped it argued no multi-byte decode could swallow an ASCII byte. That is true
    of UTF-8 and false of DBCS, and no test disagreed because every runner here is cp437 or UTF-8.

    ``chcp`` runs BEFORE pwsh starts, so the shell initialises its own encoding rather than having a
    test mutate it mid-session -- otherwise this would measure the mutation, not the environment.

    **THE FIXTURE IS SEARCHED, NOT WRITTEN, AND THAT IS WHAT MAKES IT DISCRIMINATE.** The damage
    needs a DBCS lead byte immediately before the next entry's ``100644``, and a tree entry ends with
    20 RAW bytes of the preceding file's blob id. An arbitrary body gives that a ~50% chance, so the
    first version of this case passed under cp932 with the defect fully present -- it was measured
    doing exactly that. So 0100's body is varied until its blob id ENDS in a lead byte (0x81-0xFE),
    which puts the hazard next to 0999's entry by construction rather than by luck.
    """
    repo = _checkout(tmp_path / f"cp{codepage}", {"0100-primer.md": "# Primer\n"})

    body, oid = _body_whose_blob_id_ends_in_a_lead_byte(repo)
    (repo / "docs" / "adr" / "0100-primer.md").write_text(body, encoding="utf-8")
    (repo / "docs" / "adr" / "0999-highest.md").write_text("# Highest\n", encoding="utf-8")
    _git("add", "-A", cwd=repo)
    _git("commit", "-m", "two adrs", "--no-verify", cwd=repo)
    assert _git("rev-parse", "HEAD:docs/adr/0100-primer.md", cwd=repo).strip() == oid
    assert int(oid[-2:], 16) >= 0x81, f"fixture blob id {oid} does not end in a DBCS lead byte"

    script = repo / "scripts" / "coord" / "alloc.ps1"
    # shell=True, NOT ["cmd", "/c", ...]. The list form makes Python quote the whole command as one
    # argument and cmd.exe then hands pwsh the quotes as part of the filename -- measured, it fails
    # identically under EVERY code page, which would have read as "the sweep is broken everywhere"
    # rather than as a quoting bug in the test.
    proc = subprocess.run(
        f'chcp {codepage} >nul && pwsh -NoProfile -NonInteractive -File "{script}" '
        "-ShowFloor -Kind adr",
        shell=True,
        cwd=str(repo),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    match = re.search(r"^floor\s*:\s*(\d+)$", proc.stdout, re.MULTILINE)
    assert match, f"no floor line under code page {codepage}:\n{proc.stdout}\n{proc.stderr}"
    assert int(match.group(1)) == 999, (
        f"code page {codepage} changed the ADR floor to {match.group(1)}. The sweep is reading "
        "bytes the console decoder can damage; it must read text git has already decoded."
    )


def test_an_adr_kept_as_a_directory_still_holds_its_number(tmp_path: Path) -> None:
    """Also shipped, also invisible here: a mode filter that ``ls-tree`` never had.

    The reverted byte scan anchored on ``100644|100755``, which admits regular files ONLY. Every
    other entry shape became invisible: an ADR kept as a folder with its diagrams
    (``docs/adr/0199-with-assets/``, mode 040000) or a superseded ADR left as a symlink to its
    replacement (120000). ``git ls-tree --name-only`` reports every mode, which is why the sweep was
    reverted to it.

    The number here lives ONLY in the directory entry and only on a ref, so nothing else can supply
    it. A mode-filtered sweep returns 100 and the next allocation lands on a live 0199.
    """
    repo = _checkout(tmp_path / "moded", {"0100-plain.md": "# Plain\n"})
    assets = repo / "docs" / "adr" / "0199-with-assets"
    assets.mkdir()
    (assets / "README.md").write_text("# With assets\n", encoding="utf-8")
    _git("add", "-A", cwd=repo)
    _git("commit", "-m", "adr as a directory", "--no-verify", cwd=repo)

    modes = {
        line.split()[0]
        for line in _git("ls-tree", "HEAD:docs/adr", cwd=repo).splitlines()
        if "0199-with-assets" in line
    }
    assert modes == {"040000"}, f"fixture is not exercising a non-blob entry; modes={modes}"

    assert _floor(repo) == 199


def test_a_ledger_with_no_numbered_heading_can_still_be_swept(tmp_path: Path) -> None:
    """``git grep`` exits 1 for "no match", and an earlier guard threw on it.

    ``$?`` is False after ANY non-zero native exit, so ``if (-not $?) { throw }`` fired on exit 1 --
    the documented no-match code -- and the accurate exit-code check below it became dead code that
    could never print. A repository whose ledger blobs carry no ``## N.`` heading yet could not
    allocate a backlog number AT ALL, which is the state of a fresh clone of this tooling.

    Measured while fixing it: a blob with no heading gives ``LASTEXITCODE=1`` with ``$?`` False.

    The floor here comes from the registry seed alone, so the assertion is that the sweep RETURNS
    rather than that it finds anything.
    """
    repo = _checkout(tmp_path / "noheadings", {"0001-first.md": "# First\n"})
    (repo / "docs" / "BACKLOG.md").write_text(
        "# Backlog\n\nProse only. No numbered headings anywhere in this file.\n", encoding="utf-8"
    )
    _git("add", "-A", cwd=repo)
    _git("commit", "-m", "ledger with no numbered heading", "--no-verify", cwd=repo)
    assert "## " not in (repo / "docs" / "BACKLOG.md").read_text(encoding="utf-8")

    assert _floor(repo, kind="backlog") == 0


def test_a_number_living_only_in_the_archive_is_taken(tmp_path: Path) -> None:
    """Retiring an item MOVES its heading into the archive, and the sweep must read both paths.

    No fixture covered the archive at all, so deleting it from ``$backlogPaths`` -- which drops it
    from the ref sweep AND the working-tree term together -- left the suite green. The comment beside
    that line calls the loss "the #240-#247 shape again, just sourced from a different blind spot",
    and nothing was checking.
    """
    repo = _checkout(tmp_path / "archive", {"0001-first.md": "# First\n"})
    archive = repo / "docs" / "archive" / "backlog"
    archive.mkdir(parents=True)
    (archive / "BACKLOG-CLOSED.md").write_text(
        "# Closed\n\n## 555. A retired item, living only here\n", encoding="utf-8"
    )
    _git("add", "-A", cwd=repo)
    _git("commit", "-m", "archive", "--no-verify", cwd=repo)
    assert "555" not in (repo / "docs" / "BACKLOG.md").read_text(encoding="utf-8")

    assert _floor(repo, kind="backlog") == 555


def test_a_number_written_but_committed_nowhere_is_taken(tmp_path: Path) -> None:
    """The working-tree term, which no fixture reached.

    Every fixture writes ``docs/BACKLOG.md`` and then COMMITS it, so its numbers are always reachable
    from a ref and the committed sweep supplies them. Nothing exercised the one thing this term
    exists for -- a number written to a file and committed NOWHERE -- so dropping the Multiline flag
    left the suite green, and that flag's absence is the exact silent hole its comment records.

    Here 888 is UNCOMMITTED, so only the working-tree term can find it. ``^`` in .NET anchors at the
    start of the STRING unless Multiline is set, and this term feeds ``Get-Content -Raw``: without
    the flag the count goes to zero.
    """
    repo = _checkout(tmp_path / "wip", {"0001-first.md": "# First\n"})
    committed = (repo / "docs" / "BACKLOG.md").read_text(encoding="utf-8")
    (repo / "docs" / "BACKLOG.md").write_text(
        committed + "\n## 888. Drafted here and committed nowhere\n", encoding="utf-8"
    )
    assert _git("status", "--porcelain", cwd=repo).strip(), (
        "fixture must leave the edit uncommitted"
    )
    assert "888" not in _git("show", "HEAD:docs/BACKLOG.md", cwd=repo)

    assert _floor(repo, kind="backlog") == 888


# ---------------------------------------------------------------------------------------------
# The pre-flight fetch (BACKLOG #1616). The invariant these cases hold is the MIRROR of the one
# above: the sweep must read refs this clone does not yet have.
#
# Until 2026-09-12 the script executed zero fetches, so the floor came from whatever refs happened
# to be on disk. Clone B that had not fetched since clone A pushed read A's number as FREE, took it,
# and B's ledger gate then passed CORRECTLY -- the number genuinely was allocated in B's own
# registry. Two machines, one number, every gate green on both sides. It happened on 2026-09-11:
# PR 1061 wrote "## 1546." over a number claimed to PR 1060.
#
# NOTHING HERE TOUCHES A NETWORK. Where a case needs a remote it is a LOCAL PATH; one case has no
# remote at all, and one points at a path where no repository exists. (That is a property of every
# case, not of "all three": an earlier version of this line said all three fixtures used a local
# path as the remote while the no-origin case asserted, 30 lines down, that it had none.)
# ---------------------------------------------------------------------------------------------

_PLANTED_ON_THE_REMOTE = 1234
_UPSTREAM_BRANCH = "upstream-item"


def _upstream_with_a_high_number_on_a_branch(tmp_path: Path) -> Path:
    """An upstream repo whose high ledger number lives on a BRANCH, not on main.

    A branch rather than main because ``origin/main`` is one of the sweep's two named specs, so a
    number on main could be argued to arrive by a different route. On a branch it can only reach the
    floor through the configured ``+refs/heads/*:refs/remotes/origin/*`` refspec that a bare
    ``git fetch origin`` uses -- which is the exact path both #1546 items travelled.
    """
    upstream = _checkout(tmp_path / "upstream", {"0001-first.md": "# First\n"})
    _git("checkout", "-q", "-b", _UPSTREAM_BRANCH, cwd=upstream)
    (upstream / "docs" / "BACKLOG.md").write_text(
        f"# Backlog\n\n## {_PLANTED_ON_THE_REMOTE}. allocated in the other clone\n",
        encoding="utf-8",
    )
    _git("add", "-A", cwd=upstream)
    _git("commit", "-m", "the other clone's item", "--no-verify", cwd=upstream)
    _git("checkout", "-q", "main", cwd=upstream)
    return upstream


def _downstream_pointing_at(upstream: Path, path: Path) -> Path:
    """A fresh clone-shaped fixture with ``origin`` set and DELIBERATELY never fetched.

    ``protocol.file.allow=always`` is set LOCALLY, on the fixture, because the fetch under test runs
    inside ``alloc.ps1`` and no ``-c`` from here could reach it. Git's default already allows the
    file transport for a plain fetch -- measured -- but a hardened runner or a developer with
    ``protocol.file.allow=never`` in ``~/.gitconfig`` would otherwise see the allocator's own
    refusal and read it as a network problem. ``tests/test_worktree_gate_control_plane.py`` sets the
    same knob for the same reason.
    """
    downstream = _checkout(path, {"0001-first.md": "# First\n"})
    _git("config", "protocol.file.allow", "always", cwd=downstream)
    _git("remote", "add", "origin", upstream.as_posix(), cwd=downstream)
    return downstream


def _assert_the_planted_number_is_not_here(repo: Path) -> None:
    """The POSITIVE CONTROL. Without it the case could pass on a fixture that was already fetched.

    Two independent checks, because either one alone leaves a way to pass vacuously: the
    remote-tracking ref must be ABSENT, and the number must appear in no local ref's ledger and not
    in the working tree.
    """
    missing = subprocess.run(
        ["git", "rev-parse", "--verify", f"refs/remotes/origin/{_UPSTREAM_BRANCH}"],
        cwd=str(repo),
        capture_output=True,
        text=True,
    )
    assert missing.returncode != 0, (
        f"fixture has already fetched refs/remotes/origin/{_UPSTREAM_BRANCH}, so the fetch under "
        "test is not what supplies the number"
    )
    heading = f"## {_PLANTED_ON_THE_REMOTE}."
    for ref in _git("for-each-ref", "--format=%(refname)", cwd=repo).split():
        blob = subprocess.run(
            ["git", "show", f"{ref}:docs/BACKLOG.md"], cwd=str(repo), capture_output=True, text=True
        )
        assert heading not in blob.stdout, (
            f"{_PLANTED_ON_THE_REMOTE} is already reachable from {ref}"
        )
    assert heading not in (repo / "docs" / "BACKLOG.md").read_text(encoding="utf-8")


def test_the_floor_sees_a_number_that_only_the_remote_carries(tmp_path: Path) -> None:
    """THE CASE THAT FAILS IF THE PRE-FLIGHT FETCH IS REMOVED.

    Every other case in this file is satisfied by a sweep that reads local refs only, which is
    exactly why the missing fetch survived a whole release: nothing here could see it. Here the
    planted number exists ONLY on the upstream's branch, so the floor can reach it by one route and
    no other.

    Delete the fetch and this returns 77, the fixture's own seed -- the same silent, merely-lower
    floor every other failure mode in this sweep produces.
    """
    upstream = _upstream_with_a_high_number_on_a_branch(tmp_path)
    downstream = _downstream_pointing_at(upstream, tmp_path / "downstream")
    _assert_the_planted_number_is_not_here(downstream)

    trace = tmp_path / "git-trace-fetch.log"
    env = {**os.environ, "GIT_TRACE": str(trace)}
    assert _floor(downstream, kind="backlog", env=env) == _PLANTED_ON_THE_REMOTE

    invocations = _invocations(trace)
    assert _fetches(trace), (
        "the floor was right but no fetch was traced, so something else supplied the number:\n"
        + "\n".join(invocations)
    )
    # ITS OWN BOUND, LOOSER THAN THE SIBLING CASES', because a fetch is not one process: measured 12
    # here 2026-09-12, git spawning upload-pack, pack-objects, unpack-objects and rev-list beneath
    # it. Those are git's children over a local remote and their number is not this script's to fix,
    # so the bound only has to stay far below one-process-per-ref. It was 13 until the fetch started
    # passing `-c maintenance.auto=false`, which is why the number moved DOWN when a fix landed.
    assert len(invocations) <= 30, (
        f"{len(invocations)} git invocations for a four-ref fetch:\n" + "\n".join(invocations)
    )


def test_nofetch_really_does_not_fetch(tmp_path: Path) -> None:
    """-NoFetch pinned in BOTH directions, so the sibling case cannot be satisfied by a no-op flag.

    The cheapest way to make the case above pass is to fetch unconditionally and let ``-NoFetch``
    mean nothing. Then a genuinely offline box has no way out and the switch is a lie in the
    parameter block. So this asserts the STALE floor -- proving the flag reaches the branch -- and
    that GIT_TRACE carries no fetch.

    The ``config --get`` assertion is the other half: with ``-NoFetch`` the whole pre-flight block is
    skipped, so the guard does not run either. An implementation that still probed the remote and
    merely skipped the fetch would leave that line in the trace.
    """
    upstream = _upstream_with_a_high_number_on_a_branch(tmp_path)
    downstream = _downstream_pointing_at(upstream, tmp_path / "downstream-nofetch")
    _assert_the_planted_number_is_not_here(downstream)

    trace = tmp_path / "git-trace-nofetch.log"
    env = {**os.environ, "GIT_TRACE": str(trace)}
    assert _floor(downstream, kind="backlog", env=env, extra=("-NoFetch",)) == 77

    invocations = _invocations(trace)
    assert invocations, "GIT_TRACE captured nothing, so this case is measuring nothing"
    assert not _fetches(trace), "-NoFetch still fetched:\n" + "\n".join(invocations)
    assert not [line for line in invocations if "remote.origin.url" in line], (
        "-NoFetch still probed the remote, so the whole pre-flight block was not skipped:\n"
        + "\n".join(invocations)
    )


def test_a_repo_with_no_origin_still_returns_a_floor(tmp_path: Path) -> None:
    """No origin is not a failure, stated explicitly so nobody makes the fetch unconditional.

    Every other fixture here is also originless, so this property is already load-bearing across the
    whole module -- and that is the problem: it holds by accident, as a side effect of how the
    fixtures happen to be built, and an unguarded ``git fetch origin`` exits 128 and would red the
    entire file at once. A reader seeing a dozen reds does not conclude "the guard was dropped".

    So the guard gets a case that names it. The floor is the fixture's own seed, and the trace must
    show the ``config --get`` probe running and no fetch following it: that pair is what proves the
    block was entered and chose to skip, rather than being skipped wholesale.
    """
    repo = _checkout(tmp_path / "no-origin", {"0001-first.md": "# First\n"})
    assert _git("remote", cwd=repo).strip() == "", "fixture must have no remote at all"

    trace = tmp_path / "git-trace-no-origin.log"
    env = {**os.environ, "GIT_TRACE": str(trace)}
    assert _floor(repo, kind="backlog", env=env) == 77

    invocations = _invocations(trace)
    assert [line for line in invocations if "remote.origin.url" in line], (
        "the no-origin guard did not run, so this case is not exercising it:\n"
        + "\n".join(invocations)
    )
    assert not _fetches(trace), "a repo with no origin still tried to fetch:\n" + "\n".join(
        invocations
    )


def test_a_fetch_that_cannot_succeed_refuses_and_allocates_nothing(tmp_path: Path) -> None:
    """THE CONTROL THE WHOLE DESIGN ARGUMENT RESTS ON, and nothing was asserting it.

    The three cases above all cover a fetch that WORKS. An editor who decides the refusal is too
    aggressive -- and there is a real reason to think so, since a concurrent git process in any
    worktree of one clone can fail a fetch on a ref lock -- can convert this back to
    allocate-and-shout with every one of them staying green. Allocate-and-shout is the control that
    was already in the script when #1546 collided, so restoring it would reinstall a control that
    cannot reach the case. That is worth a case of its own.

    This one really ALLOCATES, unlike every other case in the file, because "there is no partial
    state" is half the claim and only a real allocation can leave any. It is safe here: the registry
    lives under the throwaway fixture's own ``.git``.

    THE POSITIVE CONTROL IS THE SECOND RUN. The same fixture with ``-NoFetch`` allocates fine, so the
    refusal is caused by the fetch and not by anything else about a fixture with no real remote.
    """
    repo = _checkout(tmp_path / "dead-origin", {"0001-first.md": "# First\n"})
    _git("remote", "add", "origin", (tmp_path / "no-repository-here").as_posix(), cwd=repo)
    registry = repo / ".git" / "mefor-coord" / "alloc"

    refused = _run(repo, "-Kind", "adr", "-Title", "refusal probe")
    combined = refused.stdout + refused.stderr
    assert refused.returncode != 0, f"a fetch that cannot succeed allocated anyway:\n{combined}"
    assert "REFUSING TO ALLOCATE" in combined, (
        "the refusal must say which operation it refused, in its first words:\n" + combined
    )
    assert "-NoFetch" in combined, (
        "the refusal must name the escape, or an offline operator has no way past it:\n" + combined
    )
    assert sorted(p.name for p in registry.rglob("*.json")) == [], (
        "the refusal left a claimed number behind, so it does not fail closed"
    )

    allowed = _run(repo, "-Kind", "adr", "-Title", "control probe", "-NoFetch")
    assert allowed.returncode == 0, allowed.stdout + allowed.stderr
    assert [p.name for p in registry.rglob("*.json")], (
        "the control run allocated nothing either, so the case above proves nothing about the fetch"
    )


def test_list_reaches_no_network(tmp_path: Path) -> None:
    """``-List`` must stay offline, and the placement that keeps it offline is one line's distance.

    The pre-flight block sits AFTER the ``-List`` early return, which is the only thing making this
    true -- move it four hundred lines up and ``-List`` becomes a network call. Nothing in the
    repository pinned that, and the no-origin case exists on exactly this argument: name the property
    so nobody later makes the fetch unconditional.
    """
    upstream = _upstream_with_a_high_number_on_a_branch(tmp_path)
    downstream = _downstream_pointing_at(upstream, tmp_path / "downstream-list")

    trace = tmp_path / "git-trace-list.log"
    env = {**os.environ, "GIT_TRACE": str(trace)}
    listed = _run(downstream, "-List", env=env)
    assert listed.returncode == 0, listed.stdout + listed.stderr

    invocations = _invocations(trace)
    assert invocations, "GIT_TRACE captured nothing, so this case is measuring nothing"
    assert not _fetches(trace), "-List fetched:\n" + "\n".join(invocations)
    assert not [line for line in invocations if "remote.origin.url" in line], (
        "-List probed the remote, so the pre-flight block now runs before the early return:\n"
        + "\n".join(invocations)
    )


def test_the_fetch_cannot_be_turned_into_a_prune_by_config(tmp_path: Path) -> None:
    """``fetch.prune`` in config makes a bare ``git fetch`` prune, so ``--no-prune`` is not optional.

    Leaving ``--prune`` off the command line does not leave pruning off: ``fetch.prune`` and
    ``remote.<name>.prune`` turn it on from any config scope. The allocator would then DELETE the
    remote-tracking ref carrying a number as part of computing the floor -- destroying its own
    evidence mid-run, in the one direction the block argues can never happen ("an added ref can only
    RAISE the floor").

    Measured before the flag was passed explicitly: this fixture's floor fell from 9999 to 77 and
    the witness was gone. The ratchet cannot cover it, because the witness dies before any high-water
    for it exists.
    """
    doomed = 9999
    upstream = _checkout(tmp_path / "upstream-prune", {"0001-first.md": "# First\n"})
    _git("checkout", "-q", "-b", "doomed", cwd=upstream)
    (upstream / "docs" / "BACKLOG.md").write_text(
        f"# Backlog\n\n## {doomed}. allocated, then its branch was deleted\n", encoding="utf-8"
    )
    _git("add", "-A", cwd=upstream)
    _git("commit", "-m", "the doomed item", "--no-verify", cwd=upstream)
    _git("checkout", "-q", "main", cwd=upstream)

    downstream = _downstream_pointing_at(upstream, tmp_path / "downstream-prune")
    _git("fetch", "origin", cwd=downstream)
    assert _floor(downstream, kind="backlog") == doomed, "fixture did not see the doomed number"
    _git("branch", "-D", "doomed", cwd=upstream)  # gone upstream; the NUMBER is still spent
    _git("config", "fetch.prune", "true", cwd=downstream)

    assert _floor(downstream, kind="backlog") == doomed, (
        "the pre-flight fetch pruned the ref carrying the number it was run to find"
    )
    assert (
        subprocess.run(
            ["git", "rev-parse", "--verify", "refs/remotes/origin/doomed"],
            cwd=str(downstream),
            capture_output=True,
            text=True,
        ).returncode
        == 0
    ), "the witness ref was deleted by the allocator's own fetch"


def test_a_narrowed_refspec_cannot_hide_a_number(tmp_path: Path) -> None:
    """The wide refspec is the DEFAULT VALUE of ``remote.origin.fetch``, not a property of the verb.

    ``git clone --single-branch`` (which ``--depth`` implies) and ``actions/checkout`` both narrow it
    to main alone. A bare ``git fetch origin`` in such a clone runs, exits 0, updates one ref, prints
    nothing unusual -- and leaves the floor exactly as stale as no fetch at all. That is the ``fetch
    origin main`` behaviour the block rejects by argument, reached by config instead, and it is worse
    than the no-origin skip because the operator can see a fetch happen and conclude it worked.

    Measured before the refspec was passed explicitly: floor 77, the remote carrying 1234, exit 0, no
    warning. So the command line names the refspec and this case holds it there.
    """
    upstream = _upstream_with_a_high_number_on_a_branch(tmp_path)
    downstream = _downstream_pointing_at(upstream, tmp_path / "downstream-narrow")
    _git(
        "config", "remote.origin.fetch", "+refs/heads/main:refs/remotes/origin/main", cwd=downstream
    )
    _assert_the_planted_number_is_not_here(downstream)

    assert _floor(downstream, kind="backlog") == _PLANTED_ON_THE_REMOTE, (
        "a clone whose refspec is narrowed to main got the pre-fix behaviour: the fetch ran, "
        "succeeded, and the number on the other branch stayed invisible"
    )


def test_a_transient_fetch_failure_is_retried_rather_than_refused(tmp_path: Path) -> None:
    """A failed fetch is not evidence of a broken remote, and refusing on the first one costs a turn.

    ``git fetch`` takes a per-ref lock, and worktrees of one clone share one ref store. So two
    allocations overlapping in the same clone -- the ordinary case on this fleet, measured at one
    allocation about every 36s against a ~38s sweep -- make the loser exit 1 with "cannot lock ref"
    while the WINNER brings the refs in. Measured 2026-09-12 before the retry existed: four
    concurrent ``-ShowFloor`` runs, two of them refused. A Builder gets one turn, so a spurious
    refusal is a turn spent with nothing pushed -- and the escape from it is ``-NoFetch``, which
    trades a transient lock for exactly the staleness this whole block exists to prevent.

    THE FIXTURE HOLDS A REAL REF LOCK and releases it only once the trace shows a SECOND fetch
    starting, so the first attempt fails for the real reason rather than a timed one. The run must
    still end at the planted number, and the trace must carry at least two fetches -- an outcome
    assertion alone would pass against a single lucky attempt.

    IF THIS EVER REDS ON A DIFFERENT GIT, read here first: it assumes creating
    ``<gitdir>/refs/remotes/origin/<branch>.lock`` makes a fetch that must update that ref exit
    non-zero. That is git's own lockfile protocol and it held on git 2.x here, but a build that
    ignored the lock would let attempt one succeed and leave one fetch in the trace. That is a
    fixture that stopped reproducing the hazard, not the retry regressing.
    """
    upstream = _upstream_with_a_high_number_on_a_branch(tmp_path)
    downstream = _downstream_pointing_at(upstream, tmp_path / "downstream-locked")
    locks = [
        downstream / ".git" / "refs" / "remotes" / "origin" / name
        for name in ("main.lock", f"{_UPSTREAM_BRANCH}.lock")
    ]
    for lock in locks:
        lock.parent.mkdir(parents=True, exist_ok=True)
        lock.write_text("", encoding="utf-8")

    trace = tmp_path / "git-trace-locked.log"
    done = threading.Event()

    def release_once_a_retry_is_under_way() -> None:
        while not done.wait(0.05):
            if trace.exists() and len(_fetches(trace)) >= 2:
                break
        for lock in locks:
            lock.unlink(missing_ok=True)

    releaser = threading.Thread(target=release_once_a_retry_is_under_way)
    releaser.start()
    try:
        floor = _floor(downstream, kind="backlog", env={**os.environ, "GIT_TRACE": str(trace)})
    finally:
        done.set()
        releaser.join(timeout=10)
        for lock in locks:
            lock.unlink(missing_ok=True)

    assert floor == _PLANTED_ON_THE_REMOTE, (
        "a held ref lock made the allocator refuse instead of retrying, so a concurrent git process "
        "in any worktree of this clone can cost a session its allocation"
    )
    assert len(_fetches(trace)) >= 2, (
        "only one fetch was traced, so the retry did not run and this case proved nothing:\n"
        + "\n".join(_invocations(trace))
    )

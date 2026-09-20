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


# ONE ARM NOW. The `backlog` arm went with the kind itself (BACKLOG #1250, #1754) -- alloc.ps1
# refuses `-Kind backlog` at parameter binding, so the case could only ever measure the refusal.
@pytest.mark.parametrize(("kind", "expected"), [("adr", 1)])
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
    refs here point at ONE commit, so the ADR sweep resolves them to ONE distinct tree. The bound is
    fixed against the REF count, which is what this case pins; it says nothing about how the sweep
    scales with the number of distinct TREES, and an implementation that read every tree separately
    would stay green right here.

    The companion case that watched the other axis was the backlog sweep's blob-chunking test. It
    retired with that sweep (BACKLOG #1250), so **the tree axis is now unwatched** -- recorded here
    rather than left for someone to assume it is covered.

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


# --- BACKLOG #1768: the allocator must not speak the work-claim register -----------------------


def test_the_allocator_does_not_speak_the_work_claim_register() -> None:
    """An ALLOCATION reserves a NUMBER; a CLAIM reserves the WORK. Two registers, two scripts.

    `alloc.ps1` used to end every successful allocation with `claimed by: <worktree>`, which is
    `claim.ps1`'s word for the other thing. A reader who saw it concluded the row was claimed and
    did not run `claim.ps1 -Take` -- a collision the allocator cannot prevent and does not report.

    AN ABSENCE ASSERTION, DELIBERATELY. Pinning the exact replacement label would red the day
    somebody legitimately rewords it, which is the tripwire shape this repo has been removing
    elsewhere. Pinning the absence of the wrong register reds only on the regression it guards.

    Non-vacuity is carried by the second assertion, and it pins the DATA rather than the label:
    deleting the line outright would otherwise pass this test silently. The wording stays free.

    Reads the source. It does not allocate -- see this module's docstring for why nothing here may.
    """
    src = (_ROOT / "scripts" / "coord" / "alloc.ps1").read_text(encoding="utf-8")

    assert "claimed by:" not in src, (
        "alloc.ps1 labels an allocation with claim.ps1's register again (BACKLOG #1768). An "
        "allocation reserves the NUMBER; the work claim is a separate register and a separate "
        "script, and conflating them means a row nobody claimed reads as claimed."
    )
    assert '$ownerRepo [$ownerBranch]"' in src, (
        "the success output no longer names the worktree the number is recorded against, so the "
        "absence check above would pass on a line that had simply been deleted"
    )

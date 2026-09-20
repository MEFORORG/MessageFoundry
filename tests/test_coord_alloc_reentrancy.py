# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A re-run of ``alloc.ps1`` for one owner and one title must not mint a second number (BACKLOG #1703).

The reasoning -- why the key is the recorded ``worktree``, why the branch is deliberately ignored,
and why the check sits before the pre-flight fetch -- lives ONCE, beside the code, in the
re-entrancy block in ``scripts/coord/alloc.ps1``. Read that first; restating its argument here is
how two copies of it start to drift.

**THESE CASES REALLY ALLOCATE, unlike ``tests/test_coord_alloc_floor.py``, which cannot.** A
re-entrancy check is a property of the allocating path, so ``-ShowFloor`` cannot reach it. It is
safe here for the reason that file's one allocating case is safe: the registry lives under the
throwaway fixture's own ``.git``, never under this repository's.

**EVERY CASE IS PAIRED WITH ITS OPPOSITE, because the dangerous failure is the silent one.** "Never
allocates again" satisfies the headline case perfectly and destroys the allocator, so each reuse
assertion is answered by a case that must still issue a fresh number: a different title, a sibling
worktree of the same clone, and -- for the placement claim -- a fetch that still refuses when a
number is genuinely being issued.
"""

from __future__ import annotations

import json
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


def _checkout(path: Path) -> Path:
    """A throwaway checkout carrying its own copy of the allocator.

    Only ``scripts/coord/alloc.ps1`` is copied, and the copy is what runs: the script anchors every
    git call on ``$PSScriptRoot`` (BACKLOG #1060), so the fixture -- not this repository -- is the
    tree whose floor is computed and whose registry is written.
    """
    (path / "scripts" / "coord").mkdir(parents=True)
    (path / "docs" / "adr").mkdir(parents=True)
    shutil.copy2(_ALLOC, path / "scripts" / "coord" / "alloc.ps1")
    (path / "docs" / "adr" / "0001-first.md").write_text("# First\n", encoding="utf-8")
    _git("init", "-b", "main", ".", cwd=path)
    _git("config", "user.email", "t@e.com", cwd=path)
    _git("config", "user.name", "t", cwd=path)
    _git("add", "-A", cwd=path)
    _git("commit", "-m", "fixture", "--no-verify", cwd=path)
    return path


def _run(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run the fixture's OWN copy, from inside the fixture."""
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
        timeout=300,
    )


def _registry(repo: Path) -> Path:
    """Where the fixture's claims land. ``--git-common-dir``, so a linked worktree shares it."""
    common = _git("rev-parse", "--path-format=absolute", "--git-common-dir", cwd=repo).strip()
    return Path(common) / "mefor-coord" / "alloc" / "adr"


def _numbers(repo: Path) -> list[str]:
    return sorted(p.stem for p in _registry(repo).glob("*.json"))


def _key(path: str) -> str:
    """The comparison alloc.ps1 makes at the CALL SITE, which is ``Get-PathKey`` plus its ``-ieq``.

    Separators first, then the trailing slash, matching ``Get-PathKey``'s order: reversed, a path
    recorded with a trailing backslash keeps it and the comparison fails for a reason that has
    nothing to do with re-entrancy.

    **It is deliberately LOOSER than ``Get-PathKey`` alone, and these cases are not a parity check
    on it.** ``.casefold()`` stands in for the ``-ieq`` the script compares with, and ``.strip()``
    is this file's own, because the value on one side comes from ``git rev-parse`` with its newline
    attached. What these assertions pin is WHICH TREE a record names, never how the script spells a
    key -- read them as that, or this helper becomes the restated predicate its own subject warns
    about.
    """
    return path.strip().replace("\\", "/").rstrip("/").casefold()


def _out(proc: subprocess.CompletedProcess[str]) -> str:
    """Both streams. The allocator writes its warnings to stdout and its refusals to stderr."""
    return proc.stdout + proc.stderr


def _allocated(proc: subprocess.CompletedProcess[str]) -> str:
    """The number a run reports, whichever of the two verbs it used."""
    combined = _out(proc)
    assert proc.returncode == 0, combined
    match = re.search(r"^(?:ALLOCATED|REUSING) ADR (\d+)", combined, re.MULTILINE)
    assert match, f"no number in:\n{combined}"
    return match.group(1)


def test_a_rerun_for_one_owner_and_title_hands_back_the_same_number(tmp_path: Path) -> None:
    """The headline case, and the registry -- not the printed text -- is what proves it.

    A run that printed the first number while still writing a second record would satisfy any
    output assertion and leave the hole intact, so the count of records is the real measurement.
    """
    repo = _checkout(tmp_path / "rerun")

    first = _run(repo, "-Kind", "adr", "-Title", "Re-entrancy probe", "-NoFetch")
    assert "ALLOCATED ADR" in first.stdout, first.stdout + first.stderr
    issued = _allocated(first)

    second = _run(repo, "-Kind", "adr", "-Title", "Re-entrancy probe", "-NoFetch")
    assert _allocated(second) == issued, (
        "the re-run reported a different number:\n" + second.stdout + second.stderr
    )
    assert "REUSING ADR" in second.stdout, (
        "the re-run must say it reused rather than allocated, or the caller cannot tell:\n"
        + second.stdout
        + second.stderr
    )
    assert _numbers(repo) == [issued], (
        f"the re-run minted a second record: {_numbers(repo)}. Numbers are never reclaimed, so "
        "every extra one is a permanent hole that names nothing."
    )


def test_a_different_title_in_the_same_worktree_still_allocates(tmp_path: Path) -> None:
    """THE NON-VACUITY CONTROL. An allocator that stopped allocating would pass the case above."""
    repo = _checkout(tmp_path / "different-title")

    first = _allocated(_run(repo, "-Kind", "adr", "-Title", "The first ADR", "-NoFetch"))
    second = _allocated(_run(repo, "-Kind", "adr", "-Title", "A different ADR", "-NoFetch"))

    assert first != second, "two different titles were handed one number, which is a COLLISION"
    assert _numbers(repo) == sorted([first, second]), (
        f"expected two records, one per title; got {_numbers(repo)}"
    )


@pytest.mark.parametrize(
    "retyped",
    ["  worktree gate  ", "Worktree  Gate", "Worktree-gate", "worktree gate."],
    ids=["space", "double-space", "hyphen", "trailing-dot"],
)
def test_a_title_that_slugs_the_same_is_the_same_re_run(tmp_path: Path, retyped: str) -> None:
    """THE KEY IS THE SLUG, because the slug is what the ADR filename is built from.

    All four spellings name ``worktree-gate``. A trimmed case-insensitive compare would call the
    last three DIFFERENT titles and mint a number for each, which is this defect reached by a stray
    keystroke rather than by a deliberate re-run.

    Parametrized rather than written four times because the four differ only in the input: the
    argument, the assertions and what they would mean are identical, which is the one shape where
    a table is clearer than four bodies.
    """
    repo = _checkout(tmp_path / f"loose-{retyped.strip().replace(' ', '_')}")

    issued = _allocated(_run(repo, "-Kind", "adr", "-Title", "Worktree Gate", "-NoFetch"))
    again = _run(repo, "-Kind", "adr", "-Title", retyped, "-NoFetch")

    assert _allocated(again) == issued, _out(again)
    assert _numbers(repo) == [issued], (
        f"{retyped!r} slugs to the same ADR filename as the recorded title but spent a second "
        f"number: {_numbers(repo)}"
    )
    assert f"docs/adr/{issued}-worktree-gate.md" in again.stdout, (
        "the filename must be slugged from the RECORDED title, not from what this run was given -- "
        "otherwise a re-run names a second file for one number:\n" + again.stdout
    )


def test_a_sibling_worktree_of_the_same_clone_gets_its_own_number(tmp_path: Path) -> None:
    """THE KEY IS THE OWNER, and a linked worktree is the case that proves it is not the registry.

    Both trees share one ``--git-common-dir``, so both read the SAME allocation records. If the
    reuse check keyed on the title alone, the sibling would be handed the first tree's number and
    the ledger gate would then refuse its commit -- a number issued to a tree that cannot use it.
    """
    repo = _checkout(tmp_path / "primary")
    sibling = tmp_path / "sibling"
    _git("worktree", "add", "-b", "sibling", str(sibling), cwd=repo)
    assert (sibling / "scripts" / "coord" / "alloc.ps1").exists(), (
        "the linked worktree has no allocator to run, so this case measures nothing"
    )

    mine = _allocated(_run(repo, "-Kind", "adr", "-Title", "Shared title", "-NoFetch"))
    theirs = _allocated(_run(sibling, "-Kind", "adr", "-Title", "Shared title", "-NoFetch"))

    assert mine != theirs, (
        "a sibling worktree was handed another tree's number. ledger_check.py::owns keys on the "
        "recorded worktree, so that number is uncommittable from the tree that asked for it."
    )
    records = {
        p.stem: json.loads(p.read_text(encoding="utf-8")) for p in _registry(repo).glob("*.json")
    }
    assert _key(records[theirs]["worktree"]) == _key(
        _git("rev-parse", "--path-format=absolute", "--show-toplevel", cwd=sibling)
    ), f"the sibling's record names the wrong tree: {records[theirs]}"


def test_an_allocation_made_with_for_reuses_against_the_named_tree(tmp_path: Path) -> None:
    """``-For`` moves the recorded owner, so it must move the reuse key with it.

    The check reads ``$ownerRepo``, which ``-For`` repoints -- so a Manager re-running one brief's
    allocation gets the Builder's number back rather than a second one. The third limb is the
    control: the SAME title without ``-For`` has a different owner and must still allocate, or the
    check has collapsed into a title-only match and ``-For`` has stopped meaning anything.
    """
    repo = _checkout(tmp_path / "for-primary")
    target = tmp_path / "for-target"
    _git("worktree", "add", "-b", "target", str(target), cwd=repo)

    issued = _allocated(
        _run(repo, "-Kind", "adr", "-Title", "Peer ADR", "-For", str(target), "-NoFetch")
    )
    again = _run(repo, "-Kind", "adr", "-Title", "Peer ADR", "-For", str(target), "-NoFetch")
    assert _allocated(again) == issued, (
        "a re-run with the same -For minted a second number for the named tree:\n" + _out(again)
    )

    own = _run(repo, "-Kind", "adr", "-Title", "Peer ADR", "-NoFetch")
    assert _allocated(own) != issued, (
        "the same title from a DIFFERENT owner was handed the -For tree's number, so the reuse "
        "check is matching on title alone:\n" + _out(own)
    )
    records = {
        p.stem: json.loads(p.read_text(encoding="utf-8")) for p in _registry(repo).glob("*.json")
    }
    assert _key(records[issued]["worktree"]) == _key(
        _git("rev-parse", "--path-format=absolute", "--show-toplevel", cwd=target)
    ), f"-For did not record the named tree: {records[issued]}"


def test_show_floor_is_not_short_circuited_by_an_existing_allocation(tmp_path: Path) -> None:
    """``-ShowFloor`` answers "what is free", never "what do I already hold".

    It does not even require ``-Title``, so a reuse check that ran for it would either match an
    empty title or report a number in place of the floor. Both make the inspector answer a
    different question than the one asked.
    """
    repo = _checkout(tmp_path / "showfloor")
    issued = _allocated(_run(repo, "-Kind", "adr", "-Title", "Held title", "-NoFetch"))

    shown = _run(repo, "-ShowFloor", "-Kind", "adr", "-Title", "Held title", "-NoFetch")
    assert shown.returncode == 0, shown.stdout + shown.stderr
    assert "REUSING ADR" not in shown.stdout, (
        "-ShowFloor short-circuited into the reuse path:\n" + shown.stdout
    )
    assert re.search(r"^floor\s*:\s*\d+$", shown.stdout, re.MULTILINE), (
        "-ShowFloor stopped printing a floor:\n" + shown.stdout
    )
    assert "Read-only: nothing was allocated." in shown.stdout, shown.stdout
    assert _numbers(repo) == [issued], f"-ShowFloor allocated: {_numbers(repo)}"


def test_a_reuse_needs_no_remote_but_a_fresh_number_still_does(tmp_path: Path) -> None:
    """THE PLACEMENT CLAIM, PINNED IN BOTH DIRECTIONS -- the reuse check runs BEFORE the fetch.

    A reuse issues no number, so it needs no floor and no remote. Move the check below the
    pre-flight block and this fixture's dead origin makes it REFUSE a caller that was only asking
    which number it already holds -- and the refusal's own advice then steers that caller into
    allocating a second one, which is BACKLOG #1703 reinstalled by the control meant to prevent
    #1546.

    THE SECOND HALF IS WHY THIS IS NOT AN ARGUMENT FOR MOVING THE FETCH. A genuinely NEW title on
    the same fixture must still refuse, so the fetch is still guarding every number this script
    actually issues. Without that half, deleting the pre-flight block outright would pass.
    """
    repo = _checkout(tmp_path / "dead-origin")
    _git("remote", "add", "origin", (tmp_path / "no-repository-here").as_posix(), cwd=repo)

    issued = _allocated(_run(repo, "-Kind", "adr", "-Title", "Offline reuse", "-NoFetch"))

    reused = _run(repo, "-Kind", "adr", "-Title", "Offline reuse")
    assert _allocated(reused) == issued, (
        "the reuse path went through the pre-flight fetch and was refused by it:\n"
        + reused.stdout
        + reused.stderr
    )

    fresh = _run(repo, "-Kind", "adr", "-Title", "A number nobody holds yet")
    combined = fresh.stdout + fresh.stderr
    assert fresh.returncode != 0, (
        "a NEW number was issued without a successful fetch, so the reuse check has been placed "
        "in front of a guard it was never meant to bypass:\n" + combined
    )
    assert "REFUSING TO ALLOCATE" in combined, combined
    assert _numbers(repo) == [issued], f"the refusal left a number behind: {_numbers(repo)}"


def test_a_title_that_already_holds_two_numbers_reports_both_and_picks_the_lowest(
    tmp_path: Path,
) -> None:
    """THE BRANCH THAT SERVES THE POPULATION THE WHOLE CHANGE IS JUSTIFIED BY, and it is unreachable.

    Once the check is in place the allocator can never create a second record for one owner and
    title, so ``$ordered.Count -gt 1`` fires only on duplicates that PREDATE it -- the 19 titles
    docs/LEDGER-GATE.md measures. Nothing else here can plant that state, so this case writes the
    second record straight into the registry, the way the unreadable case writes its empty one.

    It also pins the choice: the LOWEST number is the one handed back, because it is the one any
    citation already written is most likely to name.
    """
    repo = _checkout(tmp_path / "already-duplicated")
    issued = _allocated(_run(repo, "-Kind", "adr", "-Title", "Twice numbered", "-NoFetch"))
    recorded = json.loads((_registry(repo) / f"{issued}.json").read_text(encoding="utf-8"))
    higher = f"{int(issued) + 7:04d}"
    (_registry(repo) / f"{higher}.json").write_text(
        json.dumps({**recorded, "number": higher}), encoding="utf-8"
    )

    proc = _run(repo, "-Kind", "adr", "-Title", "Twice numbered", "-NoFetch")
    assert _allocated(proc) == issued, (
        f"the lower number {issued} must win over {higher}:\n" + _out(proc)
    )
    combined = _out(proc)
    assert higher in combined, (
        "the note must list every number this title already holds, or the operator cannot see the "
        "holes they are leaving behind:\n" + combined
    )
    assert _numbers(repo) == sorted([issued, higher]), (
        f"a third number was minted on top of the duplicate pair: {_numbers(repo)}"
    )


def test_the_number_comes_from_the_filename_not_the_record_body(tmp_path: Path) -> None:
    """THE FILENAME IS THE KEY, and a record whose body disagrees must not be believed.

    Get-Floor parses ``$f.BaseName`` and ledger_check.py::owns opens ``<number>.json``, so both key
    on the name. A body carrying a different number is what a hand-repair during a LEDGER-GATE
    recovery leaves behind. Believing the body would hand back a number with NO registry file, which
    the floor sweep still counts free -- the clean-merging collision this script exists to prevent.
    """
    repo = _checkout(tmp_path / "body-disagrees")
    issued = _allocated(_run(repo, "-Kind", "adr", "-Title", "Mislabelled", "-NoFetch"))
    path = _registry(repo) / f"{issued}.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    path.write_text(json.dumps({**record, "number": "0999"}), encoding="utf-8")

    proc = _run(repo, "-Kind", "adr", "-Title", "Mislabelled", "-NoFetch")
    assert _allocated(proc) == issued, (
        "the reuse path believed the record body over its filename, so it named a number with no "
        "registry file behind it:\n" + _out(proc)
    )
    assert "0999" not in _out(proc), "the body's number reached the operator:\n" + _out(proc)


def test_a_title_that_slugs_to_nothing_never_matches(tmp_path: Path) -> None:
    """An empty key would pair every punctuation-only title with every untitled record.

    ``-Title "   "`` passes the -Title guard, because a whitespace string is truthy in PowerShell,
    and slugs to "". So does ``"---"``. If an empty key were allowed to match, the second would be
    handed the first's number for work that has nothing to do with it.
    """
    repo = _checkout(tmp_path / "empty-slug")
    first = _allocated(_run(repo, "-Kind", "adr", "-Title", "   ", "-NoFetch"))
    second = _allocated(_run(repo, "-Kind", "adr", "-Title", "---", "-NoFetch"))

    assert first != second, (
        "two unrelated titles that both slug to the empty string were treated as one re-run"
    )
    assert _numbers(repo) == sorted([first, second]), _numbers(repo)


def test_a_record_the_check_cannot_read_says_so(tmp_path: Path) -> None:
    """An unreadable record must WARN, because "no match" is what mints the duplicate.

    A zero-byte record is the shape to expect: the atomic ``CreateNew`` makes the file before
    anything is written into it, so a process killed in between leaves exactly one. Skipping it
    silently would be a silent narrowing of the very check that decides whether a number is
    re-issued.
    """
    repo = _checkout(tmp_path / "unreadable")
    issued = _allocated(_run(repo, "-Kind", "adr", "-Title", "Readable", "-NoFetch"))
    (_registry(repo) / "9998.json").write_text("", encoding="utf-8")

    proc = _run(repo, "-Kind", "adr", "-Title", "Readable", "-NoFetch")
    assert _allocated(proc) == issued, proc.stdout + proc.stderr
    combined = proc.stdout + proc.stderr
    assert "could not be read" in combined, (
        "an unreadable record was skipped without a word, so a false 'no match' is invisible:\n"
        + combined
    )
    assert "9998.json" in combined, "the warning must name the file, or it is not actionable"

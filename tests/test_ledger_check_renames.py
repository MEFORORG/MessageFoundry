# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An ADR that arrives by RENAME or COPY is an added ADR to the ledger gate (BACKLOG #5453).

`git diff --diff-filter=A` asks git for added paths, and git detects renames by default
(diff.renames), so a `git mv` onto `docs/adr/NNNN-x.md` reports as `R`, not `A`, and was filtered
out. A `diff.renames=copies` config does the same to a copy, as `C`. Either way the file never
reached check_adrs, so the collision, ownership and index-row rules were all skipped for it.

THE CONTROL IS A LEGITIMATE SLUG RENAME WHOSE ROW FOLLOWS IT. It passes before and after the fix, so
the fix is shown not to refuse a rename the index still covers.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

CHECK = Path(__file__).resolve().parents[1] / "scripts" / "hooks" / "ledger_check.py"

ROW = "| [{n}]({n}-{slug}.md) | {title} | Accepted |"
README_HEAD = "# Architecture Decision Records\n\n| ADR | Decision | Status |\n|---|---|---|\n"
BODY = "# A synthetic decision record\n\n" + "Line of body text that stays the same.\n" * 20


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def run_check(repo: Path, *args: str, env: dict[str, str] | None = None) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(CHECK), *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, **env} if env else None,
    )
    return proc.returncode, proc.stdout + proc.stderr


def write(repo: Path, rel: str, text: str) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A base holding ADR 0001 and a non-ADR note whose body could be moved onto an ADR path."""
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    git(r, "config", "user.email", "t@t")
    git(r, "config", "user.name", "t")
    git(r, "config", "commit.gpgsign", "false")
    # Pinned, not inherited: rename detection is git's default, but a runner's global config could
    # turn it off and let the unfixed gate pass this suite for the wrong reason.
    git(r, "config", "diff.renames", "true")
    write(r, "docs/adr/0001-first.md", BODY)
    write(r, "docs/notes/draft.md", BODY.replace("synthetic", "drafted"))
    write(
        r,
        "docs/adr/README.md",
        README_HEAD + ROW.format(n="0001", slug="first", title="First") + "\n",
    )
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")
    git(r, "update-ref", "refs/remotes/origin/main", "HEAD")
    return r


def _staged_status(repo: Path) -> str:
    return git(repo, "diff", "--cached", "--name-status")


def _ci_status(repo: Path) -> str:
    """What the CI mode's two-dot diff reports, with git's default rename detection on."""
    return git(repo, "diff", "--name-status", "origin/main", "HEAD")


def test_a_rename_onto_a_base_adr_number_is_blocked(repo: Path) -> None:
    git(repo, "mv", "docs/notes/draft.md", "docs/adr/0001-moved.md")
    # The premise: git itself reports this as a rename, which is what the filter used to drop.
    assert _staged_status(repo).startswith("R"), _staged_status(repo)

    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0001 already exists" in out


def test_a_rename_onto_a_base_adr_number_is_blocked_in_CI_mode(repo: Path) -> None:
    git(repo, "mv", "docs/notes/draft.md", "docs/adr/0001-moved.md")
    git(repo, "commit", "-qm", "move a note onto ADR 0001")
    assert _ci_status(repo).startswith("R"), _ci_status(repo)

    code, out = run_check(repo, "--ci")
    assert code == 1, out
    assert "ADR 0001 already exists" in out


def test_a_rename_onto_a_new_number_with_no_index_row_is_blocked(repo: Path) -> None:
    git(repo, "mv", "docs/notes/draft.md", "docs/adr/0002-moved.md")
    git(repo, "commit", "-qm", "move a note onto ADR 0002")
    assert _ci_status(repo).startswith("R"), _ci_status(repo)

    code, out = run_check(repo, "--ci")
    assert code == 1, out
    assert "ADR 0002" in out and "has no row in docs/adr/README.md" in out


def test_a_copy_onto_a_base_adr_number_is_blocked(repo: Path) -> None:
    # With copy detection on, a copy from a file the same change modifies reports as `C`.
    git(repo, "config", "diff.renames", "copies")
    write(repo, "docs/adr/0001-copy.md", BODY)
    write(repo, "docs/adr/0001-first.md", BODY + "One added line.\n")
    git(repo, "add", "-A")
    assert any(line.startswith("C") for line in _staged_status(repo).splitlines()), _staged_status(
        repo
    )

    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0001 already exists" in out


def test_CONTROL_a_slug_rename_whose_row_follows_it_passes(repo: Path) -> None:
    git(repo, "mv", "docs/adr/0001-first.md", "docs/adr/0001-renamed.md")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD + ROW.format(n="0001", slug="renamed", title="First") + "\n",
    )
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 0, out


def test_a_slug_rename_whose_row_still_links_the_old_name_is_refused_as_a_rename(
    repo: Path,
) -> None:
    """Refused, because the row would link a file that is gone, but NOT as a reuse: the remedy is to
    relink the row, never to allocate a new number for an ADR that already has one."""
    git(repo, "mv", "docs/adr/0001-first.md", "docs/adr/0001-renamed.md")
    assert _staged_status(repo).startswith("R"), _staged_status(repo)

    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0001 was renamed from 0001-first.md" in out
    assert "already exists" not in out
    assert "alloc.ps1" not in out


def test_the_rename_wording_holds_in_CI_mode(repo: Path) -> None:
    git(repo, "mv", "docs/adr/0001-first.md", "docs/adr/0001-renamed.md")
    git(repo, "commit", "-qm", "rename ADR 0001 without relinking its row")

    code, out = run_check(repo, "--ci")
    assert code == 1, out
    assert "ADR 0001 was renamed from 0001-first.md" in out


def test_a_rename_that_also_drops_the_row_reports_the_missing_row_too(repo: Path) -> None:
    git(repo, "mv", "docs/adr/0001-first.md", "docs/adr/0001-renamed.md")
    write(repo, "docs/adr/README.md", README_HEAD)
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0001 (0001-renamed.md) has no row in docs/adr/README.md" in out
    # There is no row left to keep linking the old name, so the rename refusal must not claim one,
    # and the change is still not a reuse.
    assert "points away" not in out
    assert "already exists" not in out


def test_a_renamed_COMPANION_gets_the_rename_wording(repo: Path) -> None:
    write(repo, "docs/adr/0001-second.md", BODY.replace("synthetic", "companion"))
    row = "| [0001](0001-first.md) and [companion](0001-second.md) | First | Accepted |"
    write(repo, "docs/adr/README.md", README_HEAD + row + "\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "declare a companion")
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")

    git(repo, "mv", "docs/adr/0001-second.md", "docs/adr/0001-third.md")
    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0001 was renamed from 0001-second.md" in out
    assert "already exists" not in out


def test_a_STALE_BASE_collision_is_still_a_reuse_not_a_rename(repo: Path) -> None:
    """The number arrived on the base after this branch was cut. Nothing here removed a file, so
    nothing is renamed, and the remedy stays: allocate a fresh number."""
    git(repo, "switch", "-q", "-c", "stale")
    git(repo, "switch", "-q", "main")
    write(repo, "docs/adr/0002-alpha.md", "# Alpha\n")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD
        + ROW.format(n="0001", slug="first", title="First")
        + "\n"
        + ROW.format(n="0002", slug="alpha", title="Alpha")
        + "\n",
    )
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "another session takes 0002")
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    git(repo, "switch", "-q", "stale")

    write(repo, "docs/adr/0002-beta.md", "# Beta\n")
    git(repo, "add", "-A")
    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0002 already exists" in out
    assert "alloc.ps1" in out
    assert "renamed" not in out


def test_an_UNRELATED_file_replacing_a_deleted_adr_is_still_a_reuse(repo: Path) -> None:
    git(repo, "rm", "-q", "docs/adr/0001-first.md")
    write(repo, "docs/adr/0001-unrelated.md", "# A different decision\n\nNothing in common.\n")
    git(repo, "add", "-A")
    assert "R" not in [line[:1] for line in _staged_status(repo).splitlines()], _staged_status(repo)

    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0001 already exists" in out
    assert "renamed" not in out


def test_a_same_number_rename_of_a_BRANCH_adr_needs_no_allocation(repo: Path) -> None:
    """The number is on this branch, not the base, and this tree did not allocate it. Renaming the
    file allocates nothing, which the gate before BACKLOG #5453 let through by not seeing it."""
    write(repo, "docs/adr/0002-x.md", BODY.replace("synthetic", "branch"))
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD
        + ROW.format(n="0001", slug="first", title="First")
        + "\n"
        + ROW.format(n="0002", slug="x", title="X")
        + "\n",
    )
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "the branch carries 0002")

    git(repo, "mv", "docs/adr/0002-x.md", "docs/adr/0002-y.md")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD
        + ROW.format(n="0001", slug="first", title="First")
        + "\n"
        + ROW.format(n="0002", slug="y", title="X")
        + "\n",
    )
    git(repo, "add", "-A")
    code, out = run_check(repo)
    assert code == 0, out


def test_a_renumber_by_rename_still_needs_an_allocation(repo: Path) -> None:
    """A `git mv` onto a DIFFERENT number is not a same-number rename: the new number is a fresh
    one, so it owes an allocation like any other new ADR, and the refusal must not call it a
    rename."""
    git(repo, "mv", "docs/adr/0001-first.md", "docs/adr/0002-first.md")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD + ROW.format(n="0002", slug="first", title="First") + "\n",
    )
    git(repo, "add", "-A")
    assert _staged_status(repo).startswith("R"), _staged_status(repo)

    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0002" in out
    assert "renamed" not in out
    assert "already exists" not in out


# PAST diff.renameLimit, git gives up pairing anything but exact renames. The renames elsewhere in
# the change must not cost an ADR rename its pairing, so the rename probe only looks at docs/adr/.
# Each file below is edited as it moves: an EXACT rename is paired whatever the limit, so an
# unedited move would pass this test for the wrong reason.
OTHER = "# Unrelated note {name}\n\n" + "Unrelated filler line about {name}.\n" * 20


def _many_renames_elsewhere(repo: Path) -> None:
    """Base two non-ADR notes, then set a limit their renames alone exceed."""
    for name in ("a", "b"):
        write(repo, f"docs/other/{name}.md", OTHER.format(name=name))
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "two unrelated notes")
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    git(repo, "config", "diff.renameLimit", "1")


def _rename_the_others(repo: Path) -> None:
    for name in ("a", "b"):
        git(repo, "mv", f"docs/other/{name}.md", f"docs/other/{name}-moved.md")
        write(repo, f"docs/other/{name}-moved.md", OTHER.format(name=name) + "Edited.\n")


def test_a_branch_adr_rename_past_the_rename_limit_needs_no_allocation(repo: Path) -> None:
    _many_renames_elsewhere(repo)
    write(repo, "docs/adr/0002-x.md", BODY.replace("synthetic", "branch"))
    rows = README_HEAD + ROW.format(n="0001", slug="first", title="First") + "\n"
    write(repo, "docs/adr/README.md", rows + ROW.format(n="0002", slug="x", title="X") + "\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "the branch carries 0002")

    _rename_the_others(repo)
    git(repo, "mv", "docs/adr/0002-x.md", "docs/adr/0002-y.md")
    write(repo, "docs/adr/0002-y.md", BODY.replace("synthetic", "branch") + "Edited.\n")
    write(repo, "docs/adr/README.md", rows + ROW.format(n="0002", slug="y", title="X") + "\n")
    git(repo, "add", "-A")
    # The premise: with the limit in force, git pairs NOTHING in the whole change.
    assert not any(line.startswith("R") for line in _staged_status(repo).splitlines()), (
        _staged_status(repo)
    )

    code, out = run_check(repo)
    assert code == 0, out


def test_a_base_adr_rename_past_the_rename_limit_keeps_the_rename_wording(repo: Path) -> None:
    _many_renames_elsewhere(repo)
    _rename_the_others(repo)
    git(repo, "mv", "docs/adr/0001-first.md", "docs/adr/0001-renamed.md")
    write(repo, "docs/adr/0001-renamed.md", BODY + "Edited.\n")
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0001 was renamed from 0001-first.md" in out
    assert "already exists" not in out
    assert "alloc.ps1" not in out


def test_a_base_adr_rename_past_the_rename_limit_keeps_the_rename_wording_in_CI_mode(
    repo: Path,
) -> None:
    _many_renames_elsewhere(repo)
    _rename_the_others(repo)
    git(repo, "mv", "docs/adr/0001-first.md", "docs/adr/0001-renamed.md")
    write(repo, "docs/adr/0001-renamed.md", BODY + "Edited.\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "rename ADR 0001 among other renames")

    code, out = run_check(repo, "--ci")
    assert code == 1, out
    assert "ADR 0001 was renamed from 0001-first.md" in out
    assert "already exists" not in out


def test_CONTROL_an_unrelated_replacement_whose_row_links_it_passes(repo: Path) -> None:
    """The declared-companion rule covers it: the row links the new file, so nothing is unindexed
    and nothing is a second session's reuse. docs/LEDGER-GATE.md says so; this pins it."""
    git(repo, "rm", "-q", "docs/adr/0001-first.md")
    write(repo, "docs/adr/0001-unrelated.md", "# A different decision\n\nNothing in common.\n")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD + ROW.format(n="0001", slug="unrelated", title="First") + "\n",
    )
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 0, out


def test_a_rename_that_revives_a_number_the_base_LOST_is_a_restore_not_a_rename(
    repo: Path,
) -> None:
    """The branch was cut while the base still held ADR 0002; the base then deleted it. Renaming the
    branch's copy brings the number back with new bytes, which rule 2 refuses: only the lost bytes
    may come back. The rename exemption must not skip that."""
    second = _base_takes_then_drops_0002(repo, branch_before_drop="stale")
    git(repo, "switch", "-q", "stale")
    _rename_0002_second_to_revived(repo, second)

    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0002 is a RESTORE" in out
    # The remedy says why an exact restore will not let this rename through, so it cannot loop.
    assert "a rename is refused even after an exact restore" in out


def test_a_revival_by_rename_in_a_SHALLOW_clone_is_refused(repo: Path, tmp_path: Path) -> None:
    """A shallow clone cannot show that the base never held the number, so the grant refuses
    whether or not the fork point is in reach; the next test pins the in-reach case. The refusal
    names the truncated history, and, because this is a rename, how to make it checkable."""
    rows = README_HEAD + ROW.format(n="0001", slug="first", title="First") + "\n"
    second = BODY.replace("synthetic", "second")
    write(repo, "docs/adr/0002-second.md", second)
    write(repo, "docs/adr/README.md", rows + ROW.format(n="0002", slug="second", title="S") + "\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "the base takes 0002")
    git(repo, "switch", "-q", "-c", "stale")
    write(repo, "docs/notes/branch.md", "A branch-only note.\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "the branch moves on")
    git(repo, "switch", "-q", "main")
    git(repo, "rm", "-q", "docs/adr/0002-second.md")
    write(repo, "docs/adr/README.md", rows)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "the base drops 0002")

    clone = tmp_path / "shallow"
    clone_args = ["clone", "-q", "--depth", "1", "--no-single-branch", "--branch", "stale"]
    subprocess.run(["git", *clone_args, repo.as_uri(), str(clone)], capture_output=True, check=True)
    for key, value in (("user.email", "t@t"), ("user.name", "t"), ("diff.renames", "true")):
        git(clone, "config", key, value)
    assert git(clone, "rev-parse", "--is-shallow-repository").strip() == "true"

    git(clone, "mv", "docs/adr/0002-second.md", "docs/adr/0002-revived.md")
    write(clone, "docs/adr/0002-revived.md", second + "Edited.\n")
    write(
        clone, "docs/adr/README.md", rows + ROW.format(n="0002", slug="revived", title="S") + "\n"
    )
    git(clone, "add", "-A")
    assert _staged_status(clone).startswith("R"), _staged_status(clone)

    code, out = run_check(clone)
    assert code == 1, out
    assert "ADR 0002 cannot be checked against origin/main -- the history is TRUNCATED" in out
    assert "git fetch --unshallow origin" in out


def test_several_adr_renames_past_the_rename_limit_still_pair(repo: Path) -> None:
    """Two edited ADR renames against a limit of one: the docs/adr/ pathspec alone does not bring
    the pair count under it, so this pins -l0."""
    git(repo, "config", "diff.renameLimit", "1")
    rows = README_HEAD + ROW.format(n="0001", slug="first", title="First") + "\n"
    # Bodies with no line in common, so git cannot pair 0002's old path with 0003's new one.
    bodies = {
        n: f"# Decision {n}\n\n" + f"A line only decision {n} has.\n" * 20 for n in ("0002", "0003")
    }
    before = "".join(ROW.format(n=n, slug="x", title=n) + "\n" for n in bodies)
    for n, body in bodies.items():
        write(repo, f"docs/adr/{n}-x.md", body)
    write(repo, "docs/adr/README.md", rows + before)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "the branch carries 0002 and 0003")

    for n, body in bodies.items():
        git(repo, "mv", f"docs/adr/{n}-x.md", f"docs/adr/{n}-y.md")
        write(repo, f"docs/adr/{n}-y.md", body + "Edited.\n")
    after = "".join(ROW.format(n=n, slug="y", title=n) + "\n" for n in bodies)
    write(repo, "docs/adr/README.md", rows + after)
    git(repo, "add", "-A")
    assert not any(line.startswith("R") for line in _staged_status(repo).splitlines()), (
        _staged_status(repo)
    )

    code, out = run_check(repo)
    assert code == 0, out


def _base_takes_then_drops_0002(repo: Path, *, branch_before_drop: str | None = None) -> str:
    """The base takes ADR 0002, then deletes it and its row. Returns the deleted bytes. A branch
    named ``branch_before_drop`` is cut between the two, while the base still holds the number."""
    rows = README_HEAD + ROW.format(n="0001", slug="first", title="First") + "\n"
    second = BODY.replace("synthetic", "second")
    write(repo, "docs/adr/0002-second.md", second)
    write(repo, "docs/adr/README.md", rows + ROW.format(n="0002", slug="second", title="S") + "\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "the base takes 0002")
    if branch_before_drop:
        git(repo, "branch", branch_before_drop)
    git(repo, "rm", "-q", "docs/adr/0002-second.md")
    write(repo, "docs/adr/README.md", rows)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "the base drops 0002")
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    return second


def _rename_0002_second_to_revived(repo: Path, second: str) -> None:
    rows = README_HEAD + ROW.format(n="0001", slug="first", title="First") + "\n"
    git(repo, "mv", "docs/adr/0002-second.md", "docs/adr/0002-revived.md")
    write(repo, "docs/adr/0002-revived.md", second + "Edited.\n")
    write(repo, "docs/adr/README.md", rows + ROW.format(n="0002", slug="revived", title="S") + "\n")
    git(repo, "add", "-A")
    assert _staged_status(repo).startswith("R"), _staged_status(repo)


def test_a_revival_by_rename_after_MERGING_the_base_is_still_a_restore(repo: Path) -> None:
    """The branch was cut while the base held ADR 0002, then merged the base after the base dropped
    it, keeping its copy. The fork point is now the base tip, which holds no 0002, so a fork-point
    test alone would grant the rename. The base's history still spent the number."""
    second = _base_takes_then_drops_0002(repo, branch_before_drop="stale")
    git(repo, "switch", "-q", "stale")
    git(repo, "merge", "-q", "-s", "ours", "main", "-m", "merge the base, keeping 0002")
    assert (
        git(repo, "merge-base", "origin/main", "HEAD").strip()
        == git(repo, "rev-parse", "origin/main").strip()
    )

    _rename_0002_second_to_revived(repo, second)
    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0002 is a RESTORE" in out


def test_an_exact_restore_then_a_rename_in_a_second_commit_is_still_a_restore(
    repo: Path,
) -> None:
    """Restoring the lost bytes exactly passes, as docs/LEDGER-GATE.md says. Renaming the restored
    file in a later commit brings the number back under a name and bytes the base never held, so it
    is refused the same way a revival under a new name in one commit is."""
    second = _base_takes_then_drops_0002(repo)
    git(repo, "switch", "-q", "-c", "restorer")
    rows = README_HEAD + ROW.format(n="0001", slug="first", title="First") + "\n"
    write(repo, "docs/adr/0002-second.md", second)
    write(repo, "docs/adr/README.md", rows + ROW.format(n="0002", slug="second", title="S") + "\n")
    git(repo, "add", "-A")
    code, out = run_check(repo)
    assert code == 0, out  # the premise: an exact restore passes
    git(repo, "commit", "-qm", "restore ADR 0002 exactly")

    _rename_0002_second_to_revived(repo, second)
    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0002 is a RESTORE" in out


def test_a_rename_of_a_branch_adr_whose_number_the_base_has_since_SPENT_is_a_reuse(
    repo: Path,
) -> None:
    """The branch carries its own ADR 0002, and another session lands a different 0002 on the base.
    Renaming the branch's file is paired by git, but the source is not the base's ADR, so keeping
    the number is wrong advice: the number is spent, and the refusal must say allocate."""
    git(repo, "switch", "-q", "-c", "stale")
    rows = README_HEAD + ROW.format(n="0001", slug="first", title="First") + "\n"
    write(repo, "docs/adr/0002-x.md", BODY.replace("synthetic", "branch"))
    write(repo, "docs/adr/README.md", rows + ROW.format(n="0002", slug="x", title="X") + "\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "the branch carries 0002")
    git(repo, "switch", "-q", "main")
    write(repo, "docs/adr/0002-alpha.md", "# Alpha\n")
    write(repo, "docs/adr/README.md", rows + ROW.format(n="0002", slug="alpha", title="A") + "\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "another session takes 0002")
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    git(repo, "switch", "-q", "stale")

    git(repo, "mv", "docs/adr/0002-x.md", "docs/adr/0002-y.md")
    assert _staged_status(repo).startswith("R"), _staged_status(repo)
    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0002 already exists on origin/main as 0002-alpha.md" in out
    assert "alloc.ps1" in out
    assert "renamed" not in out


def test_a_branch_adr_rename_in_a_SHALLOW_clone_is_refused_even_with_the_fork_point_in_reach(
    repo: Path, tmp_path: Path
) -> None:
    """The fork point is inside the clone, so the fork-point test alone would grant this. But past
    the graft the base's history cannot show the number was never spent, and a doubt refuses."""
    for name in ("one", "two"):
        write(repo, f"docs/notes/{name}.md", f"Base note {name}.\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", f"the base adds note {name}")
    git(repo, "switch", "-q", "-c", "stale")
    rows = README_HEAD + ROW.format(n="0001", slug="first", title="First") + "\n"
    write(repo, "docs/adr/0002-x.md", BODY.replace("synthetic", "branch"))
    write(repo, "docs/adr/README.md", rows + ROW.format(n="0002", slug="x", title="X") + "\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "the branch carries 0002")

    clone = tmp_path / "shallow-reach"
    clone_args = ["clone", "-q", "--depth", "2", "--no-single-branch", "--branch", "stale"]
    subprocess.run(["git", *clone_args, repo.as_uri(), str(clone)], capture_output=True, check=True)
    for key, value in (("user.email", "t@t"), ("user.name", "t"), ("diff.renames", "true")):
        git(clone, "config", key, value)
    assert git(clone, "rev-parse", "--is-shallow-repository").strip() == "true"
    # The premise: the fork point IS reachable, so only the history test can refuse.
    assert git(clone, "merge-base", "origin/main", "HEAD").strip()

    git(clone, "mv", "docs/adr/0002-x.md", "docs/adr/0002-y.md")
    write(clone, "docs/adr/README.md", rows + ROW.format(n="0002", slug="y", title="X") + "\n")
    git(clone, "add", "-A")
    assert _staged_status(clone).startswith("R"), _staged_status(clone)

    code, out = run_check(clone)
    assert code == 1, out
    assert "ADR 0002 cannot be checked against origin/main -- the history is TRUNCATED" in out


def test_CONTROL_an_unallocated_plain_add_in_a_SHALLOW_clone_is_not_told_to_unshallow(
    repo: Path, tmp_path: Path
) -> None:
    """The unshallow line belongs to a rename only: for a plain unallocated add, unshallowing changes
    the refusal and lets nothing through."""
    write(repo, "docs/notes/two.md", "Base note two.\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "the base adds a note")
    clone = tmp_path / "shallow-plain"
    clone_args = ["clone", "-q", "--depth", "1", "--no-single-branch"]
    subprocess.run(["git", *clone_args, repo.as_uri(), str(clone)], capture_output=True, check=True)
    for key, value in (("user.email", "t@t"), ("user.name", "t")):
        git(clone, "config", key, value)
    assert git(clone, "rev-parse", "--is-shallow-repository").strip() == "true"

    rows = README_HEAD + ROW.format(n="0001", slug="first", title="First") + "\n"
    write(clone, "docs/adr/0002-new.md", "# New\n")
    write(clone, "docs/adr/README.md", rows + ROW.format(n="0002", slug="new", title="N") + "\n")
    git(clone, "add", "-A")

    code, out = run_check(clone)
    assert code == 1, out
    assert "the history is TRUNCATED" in out
    assert "--unshallow" not in out


def test_a_revival_by_rename_through_a_MERGED_SIDE_BRANCH_is_still_a_restore(repo: Path) -> None:
    """A side branch takes ADR 0002 and drops it, then merges into the base with --no-ff. Default
    history simplification follows the merge's first parent, which never held 0002, so a plain walk
    reads the number as never spent. --full-history sees the side branch."""
    git(repo, "switch", "-q", "-c", "side")
    second = BODY.replace("synthetic", "second")
    rows = README_HEAD + ROW.format(n="0001", slug="first", title="First") + "\n"
    write(repo, "docs/adr/0002-second.md", second)
    write(repo, "docs/adr/README.md", rows + ROW.format(n="0002", slug="second", title="S") + "\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "the side branch takes 0002")
    git(repo, "branch", "stale")
    git(repo, "rm", "-q", "docs/adr/0002-second.md")
    write(repo, "docs/adr/README.md", rows)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "the side branch drops 0002")
    git(repo, "switch", "-q", "main")
    git(repo, "merge", "-q", "--no-ff", "side", "-m", "merge the side branch")
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    # The premise: a simplified walk misses the number entirely.
    assert git(repo, "rev-list", "origin/main", "--", "docs/adr/0002-*.md").strip() == ""

    git(repo, "switch", "-q", "stale")
    git(repo, "merge", "-q", "-s", "ours", "main", "-m", "merge the base, keeping 0002")
    _rename_0002_second_to_revived(repo, second)
    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0002 is a RESTORE" in out


def test_a_revival_by_rename_is_refused_under_GIT_LITERAL_PATHSPECS(repo: Path) -> None:
    """GIT_LITERAL_PATHSPECS makes `*` literal and disables `:(glob)`, so the walk would come back
    empty and grant the rename. The gate drops the variable for its own git calls."""
    second = _base_takes_then_drops_0002(repo, branch_before_drop="stale")
    git(repo, "switch", "-q", "stale")
    git(repo, "merge", "-q", "-s", "ours", "main", "-m", "merge the base, keeping 0002")
    _rename_0002_second_to_revived(repo, second)

    code, out = run_check(repo, env={"GIT_LITERAL_PATHSPECS": "1"})
    assert code == 1, out
    assert "ADR 0002 is a RESTORE" in out


def test_a_base_adr_renamed_over_TWO_commits_keeps_the_rename_wording(repo: Path) -> None:
    """The first rename relinks its row and passes. The second does not relink, and is paired with
    the base's name, as CI pairs it, so the advice is to relink the row and keep the number."""
    git(repo, "mv", "docs/adr/0001-first.md", "docs/adr/0001-mid.md")
    write(
        repo, "docs/adr/README.md", README_HEAD + ROW.format(n="0001", slug="mid", title="F") + "\n"
    )
    git(repo, "add", "-A")
    code, out = run_check(repo)
    assert code == 0, out
    git(repo, "commit", "-qm", "rename ADR 0001 once")

    git(repo, "mv", "docs/adr/0001-mid.md", "docs/adr/0001-final.md")
    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0001 was renamed from 0001-first.md" in out
    assert "already exists" not in out
    assert "alloc.ps1" not in out


def test_a_merge_carrying_the_bases_own_renamed_adr_is_told_to_relink_the_row(repo: Path) -> None:
    """The base renamed ADR 0001 and relinked its row. A merge of the base whose README keeps the
    old link adds the base's own file: nothing is reused, so the advice is to fix the row."""
    git(repo, "switch", "-q", "-c", "old")
    git(repo, "switch", "-q", "main")
    git(repo, "mv", "docs/adr/0001-first.md", "docs/adr/0001-renamed.md")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD + ROW.format(n="0001", slug="renamed", title="First") + "\n",
    )
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "the base renames ADR 0001")
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    git(repo, "switch", "-q", "old")

    git(repo, "merge", "-q", "--no-commit", "--no-ff", "main")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD + ROW.format(n="0001", slug="first", title="First") + "\n",
    )
    git(repo, "add", "docs/adr/README.md")
    code, out = run_check(repo)
    assert code == 1, out
    assert "does not link a file origin/main carries under that number" in out
    assert "already exists" not in out
    assert "alloc.ps1" not in out


def _base_lands_0002_after_the_branch(repo: Path, slug: str, body: str) -> None:
    """Cut branch ``stale``, then land ``docs/adr/0002-<slug>.md`` on the base, and return to stale."""
    git(repo, "switch", "-q", "-c", "stale")
    git(repo, "switch", "-q", "main")
    rows = README_HEAD + ROW.format(n="0001", slug="first", title="First") + "\n"
    write(repo, f"docs/adr/0002-{slug}.md", body)
    write(repo, "docs/adr/README.md", rows + ROW.format(n="0002", slug=slug, title="A") + "\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "another session takes 0002")
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    git(repo, "switch", "-q", "stale")


def test_a_STALE_BASE_collision_with_a_SIMILAR_body_is_still_a_reuse(repo: Path) -> None:
    """Diffed against the base, the base's later 0002 reads as removed by this branch, and a
    similar body pairs with it. The branch never had that file, so it is no rename of it."""
    _base_lands_0002_after_the_branch(repo, "alpha", BODY.replace("synthetic", "alpha"))
    write(repo, "docs/adr/0002-beta.md", BODY.replace("synthetic", "beta"))
    git(repo, "add", "-A")
    base_status = git(
        repo, "diff", "--cached", "-M", "--name-status", "origin/main", "--", "docs/adr/"
    )
    assert any(line.startswith("R") for line in base_status.splitlines()), base_status

    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0002 already exists on origin/main as 0002-alpha.md" in out
    assert "alloc.ps1" in out
    assert "renamed" not in out


def test_a_STALE_BASE_collision_on_the_SAME_PATH_with_other_bytes_is_still_a_reuse(
    repo: Path,
) -> None:
    _base_lands_0002_after_the_branch(repo, "ledger", "# The base session's decision\n")
    write(repo, "docs/adr/0002-ledger.md", "# This branch's own, different decision\n")
    git(repo, "add", "-A")

    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0002 already exists on origin/main as 0002-ledger.md" in out
    assert "alloc.ps1" in out


@pytest.mark.parametrize("var", ["GIT_GLOB_PATHSPECS", "GIT_ICASE_PATHSPECS"])
def test_CONTROL_a_pathspec_switch_in_the_environment_does_not_crash_the_gate(
    repo: Path, var: str
) -> None:
    git(repo, "mv", "docs/adr/0001-first.md", "docs/adr/0001-renamed.md")
    write(
        repo,
        "docs/adr/README.md",
        README_HEAD + ROW.format(n="0001", slug="renamed", title="First") + "\n",
    )
    git(repo, "add", "-A")

    code, out = run_check(repo, env={var: "1"})
    assert code == 0, out


def _merge_base_fails(repo: Path) -> bool:
    """True only for git's own "no common ancestor" answer: exit 1 and no output. A missing ref or a
    bad object exits 128, and must not pass for the shape a test claims."""
    probe = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "origin/main", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return probe.returncode == 1 and not probe.stdout.strip()


def test_the_rename_wording_holds_in_the_REAL_CI_checkout_shape(repo: Path, tmp_path: Path) -> None:
    """CI checks out the PR merge commit at depth 1, then fetches main shallow. That pair has no merge
    base, so a rename probe that asked git for the fork point read every rename of a base ADR as a
    reuse and told the author to allocate a new number. In CI the source is in the base by
    construction, so the rename wording must hold here too."""
    for name in ("one", "two"):
        write(repo, f"docs/notes/{name}.md", f"Base note {name}.\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", f"the base adds note {name}")
    git(repo, "switch", "-q", "-c", "pr")
    git(repo, "mv", "docs/adr/0001-first.md", "docs/adr/0001-renamed.md")
    git(repo, "commit", "-qm", "rename ADR 0001 without relinking its row")
    git(repo, "switch", "-q", "main")
    write(repo, "docs/notes/three.md", "Base note three.\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "the base moves on")
    git(repo, "switch", "-q", "-c", "pr-merge")
    git(repo, "merge", "-q", "--no-ff", "-m", "Merge pr into main", "pr")
    git(repo, "switch", "-q", "main")

    clone = tmp_path / "ci"
    clone_args = ["clone", "-q", "--depth", "1", "--branch", "pr-merge"]
    subprocess.run(["git", *clone_args, repo.as_uri(), str(clone)], capture_output=True, check=True)
    git(clone, "fetch", "-q", "--no-tags", "--depth=200", "origin", "main:refs/remotes/origin/main")
    git(clone, "config", "diff.renames", "true")
    # The premise: git finds no merge base in this shape, so only a CI answer that skips the fork
    # point can keep the rename wording.
    assert _merge_base_fails(clone)
    assert _ci_status(clone).startswith("R"), _ci_status(clone)

    code, out = run_check(clone, "--ci")
    assert code == 1, out
    assert "ADR 0001 was renamed from 0001-first.md" in out
    assert "already exists" not in out
    assert "alloc.ps1" not in out


# The gate's restore check reads one blob per walked commit, so a capped walk is 200 git spawns,
# and a spawn here costs tens to hundreds of milliseconds: well past the suite's 60s default.
@pytest.mark.timeout(600)
def test_a_branch_adr_rename_past_the_history_CAP_does_not_call_the_clone_shallow(
    repo: Path,
) -> None:
    """The base touched 0002 more times than the walk's cap, then dropped it. The walk is truncated
    by its cap, not by a graft, so the rename line must not say the clone is shallow."""
    parts = []
    for i in range(201):
        content = f"Version {i} of a busy decision record.\n"
        parts.append(
            "commit refs/heads/main\n"
            f"committer t <t@t> {1700000000 + i} +0000\n"
            "data 4\nbusy\n"
            + ("from refs/heads/main^0\n" if i == 0 else "")
            + f"M 100644 inline docs/adr/0002-old.md\ndata {len(content)}\n{content}\n"
        )
    parts.append(
        "commit refs/heads/main\ncommitter t <t@t> 1700001000 +0000\ndata 4\ndrop\n"
        "D docs/adr/0002-old.md\n\n"
    )
    # One fast-import stream, not 200 commits: a git spawn costs tens of milliseconds here.
    subprocess.run(
        ["git", "-C", str(repo), "fast-import", "--quiet", "--force"],
        input="".join(parts).encode("utf-8"),
        capture_output=True,
        check=True,
    )
    git(repo, "reset", "-q", "--hard", "main")
    git(repo, "update-ref", "refs/remotes/origin/main", "main")
    assert git(repo, "rev-parse", "--is-shallow-repository").strip() == "false"

    git(repo, "switch", "-q", "-c", "stale")
    rows = README_HEAD + ROW.format(n="0001", slug="first", title="First") + "\n"
    write(repo, "docs/adr/0002-x.md", BODY.replace("synthetic", "branch"))
    write(repo, "docs/adr/README.md", rows + ROW.format(n="0002", slug="x", title="X") + "\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "the branch carries 0002")
    git(repo, "mv", "docs/adr/0002-x.md", "docs/adr/0002-y.md")
    write(repo, "docs/adr/README.md", rows + ROW.format(n="0002", slug="y", title="X") + "\n")
    git(repo, "add", "-A")
    assert _staged_status(repo).startswith("R"), _staged_status(repo)

    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0002 cannot be checked against origin/main -- the history is TRUNCATED" in out
    assert "This file is a RENAME, and the base's history already touched this" in out
    assert "shallow" not in out


def test_a_branch_adr_rename_with_NO_FORK_POINT_is_not_sent_to_the_allocator(repo: Path) -> None:
    """The base never held 0002 and the clone is not shallow; the grant declines only because git
    finds no merge base. The number may well be allocated, so the refusal must name the fork point,
    not tell the author to allocate."""
    git(repo, "switch", "-q", "--orphan", "side")
    rows = README_HEAD + ROW.format(n="0001", slug="first", title="First") + "\n"
    write(repo, "docs/adr/0002-x.md", BODY.replace("synthetic", "branch"))
    write(repo, "docs/adr/README.md", rows + ROW.format(n="0002", slug="x", title="X") + "\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "an unrelated history carries 0002")
    git(repo, "mv", "docs/adr/0002-x.md", "docs/adr/0002-y.md")
    write(repo, "docs/adr/README.md", rows + ROW.format(n="0002", slug="y", title="X") + "\n")
    git(repo, "add", "-A")
    assert _staged_status(repo).startswith("R"), _staged_status(repo)
    assert _merge_base_fails(repo)

    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0002 is a rename, but git found no fork point with origin/main" in out
    assert "was not allocated to this worktree" not in out
    # The allocator stays reachable, for a number nobody allocated, but only as the last resort.
    assert "Otherwise:" in out
    assert out.index("Otherwise:") < out.index("alloc.ps1")

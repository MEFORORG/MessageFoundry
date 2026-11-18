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


def run_check(repo: Path, *args: str) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(CHECK), *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
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
    rows = README_HEAD + ROW.format(n="0001", slug="first", title="First") + "\n"
    second = BODY.replace("synthetic", "second")
    write(repo, "docs/adr/0002-second.md", second)
    write(repo, "docs/adr/README.md", rows + ROW.format(n="0002", slug="second", title="S") + "\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "the base takes 0002")
    git(repo, "switch", "-q", "-c", "stale")
    git(repo, "switch", "-q", "main")
    git(repo, "rm", "-q", "docs/adr/0002-second.md")
    write(repo, "docs/adr/README.md", rows)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "the base drops 0002")
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    git(repo, "switch", "-q", "stale")

    git(repo, "mv", "docs/adr/0002-second.md", "docs/adr/0002-revived.md")
    write(repo, "docs/adr/0002-revived.md", second + "Edited.\n")
    write(repo, "docs/adr/README.md", rows + ROW.format(n="0002", slug="revived", title="S") + "\n")
    git(repo, "add", "-A")
    assert _staged_status(repo).startswith("R"), _staged_status(repo)

    code, out = run_check(repo)
    assert code == 1, out
    assert "ADR 0002 is a RESTORE" in out

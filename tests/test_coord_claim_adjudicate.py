# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A stranded claim is released only when something DURABLE on origin/main has replaced it.

``claim-reconcile.ps1`` asks whether the BRANCH a claim names has landed. Measured 2026-08-18 on the
live registry, that question could not clear a single one of 20 stranded claims -- because they sat
on six branches, one of them carrying nine keys, and a seat branch accumulates commits from every
item the seat ever touched. Branch containment can only clear a whole seat at once, so a long-lived
seat branch never clears and every key on it stays stuck.

``claim-adjudicate.ps1`` asks the per-key question instead, and the criterion is the project's own.
Item #1010's banner on origin/main states it: the claim registry is *machine-local and unversioned*,
so "this banner is the protection that travels; the claim is not". A claim is therefore worth
keeping only until origin/main protects the item better -- and the tests below pin BOTH directions
of that, because the failure that matters is not a missed release but a granted one.

Every releasing test here is paired with the case that would ALSO pass if the tool released whatever
it could not see: an item reading OPEN, a key with no item at all, a commit that merely CITES the
item in prose. Those must come back untouched, and the tool must write nothing on any path -- it has
no ``-Apply`` and the suite asserts that the registry is byte-identical afterwards.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLAIM = ROOT / "scripts" / "coord" / "claim.ps1"
ADJUDICATE = ROOT / "scripts" / "coord" / "claim-adjudicate.ps1"
# Deliberately below pytest's own bound, for the reason spelled out in
# test_coord_claim_reconcile.py: a backstop is only worth having if it fires FIRST, so the failure
# reads "a pwsh spawn hung" rather than pytest's generic timeout.
TIMEOUT = 45

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="claim-adjudicate.ps1 needs pwsh on Windows",
)

# The status vocabulary is backlog_status_check.py's. Written as escapes so this file stays legible
# on a console that cannot render the glyphs -- and so a cp1252 round-trip cannot mangle a fixture
# into one that tests nothing.
SHIPPED = "\N{WHITE HEAVY CHECK MARK}"
DECLINED = "\N{NO ENTRY}"
RETIRED = "\N{HEADSTONE}"
PRIORITIZED = "\N{INPUT SYMBOL FOR NUMBERS}"
IN_PROGRESS = "\N{CONSTRUCTION SIGN}"


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout


def backlog(repo: Path, body: str) -> None:
    """Write docs/BACKLOG.md and publish it to origin/main.

    Publishing matters: the tool reads ``origin/main`` and falls back to local main only when there
    is no origin. A fixture that never pushed would exercise the fallback while claiming to test the
    primary path.
    """
    p = repo / "docs" / "BACKLOG.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("# Backlog\n\n" + body, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "backlog")
    git(repo, "push", "-q", "origin", "main")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A sandbox carrying its OWN copies -- both scripts anchor on where they live (BACKLOG #1060)."""
    r = tmp_path / "repo"
    (r / "scripts" / "coord").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    shutil.copy2(CLAIM, r / "scripts" / "coord" / "claim.ps1")
    shutil.copy2(ADJUDICATE, r / "scripts" / "coord" / "claim-adjudicate.ps1")
    (r / "f.txt").write_text("x", encoding="utf-8")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")

    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(origin)], check=True, capture_output=True)
    git(r, "remote", "add", "origin", str(origin))
    git(r, "push", "-q", "-u", "origin", "main")
    return r


def claims_dir(repo: Path) -> Path:
    d = repo / ".git" / "mefor-coord" / "claims"
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_claim(repo: Path, key: str, holder: Path | str, branch: str, note: str = "n") -> Path:
    """Write a claim file the way claim.ps1 writes one: UTF-8, no BOM, compact JSON."""
    p = claims_dir(repo) / f"{key}.json"
    p.write_bytes(
        json.dumps(
            {
                "key": key,
                "note": note,
                "branch": branch,
                "worktree": str(holder).replace("\\", "/"),
                "claimed": "2026-08-01T00:00:00.0000000-05:00",
            }
        ).encode("utf-8")
    )
    return p


def adjudicate(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(repo / "scripts" / "coord" / "claim-adjudicate.ps1"),
            *args,
        ],
        cwd=str(repo),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=TIMEOUT,
    )


def rows(repo: Path, *args: str) -> dict[str, dict]:
    proc = adjudicate(repo, "-Json", *args)
    assert proc.returncode == 0, proc.stderr
    return {c["key"]: c for c in json.loads(proc.stdout)["claims"]}


def verdicts(repo: Path, *args: str) -> dict[str, str]:
    return {k: v["verdict"] for k, v in rows(repo, *args).items()}


def unmerged_branch(repo: Path, name: str) -> None:
    """A branch carrying a commit of its own -- the shape whose keys must never be released."""
    git(repo, "branch", name, "main")
    wt = repo.parent / f"wt-{name.replace('/', '-')}"
    git(repo, "worktree", "add", "-q", str(wt), name)
    (wt / "work.txt").write_text("real work", encoding="utf-8")
    git(wt, "add", "-A")
    git(wt, "commit", "-qm", "work that exists nowhere else")
    git(repo, "worktree", "remove", "--force", str(wt))


# ---------------------------------------------------------------------------------------------
# THE RELEASING DIRECTION
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "glyph,expected",
    [(SHIPPED, "CLOSED/shipped"), (DECLINED, "CLOSED/declined"), (RETIRED, "CLOSED/retired")],
)
def test_a_closed_banner_supersedes_the_claim(
    repo: Path, tmp_path: Path, glyph: str, expected: str
) -> None:
    """All three CLOSED states release, and for one reason: none of them can be rebuilt into.

    Shipped, declined and retired are different dispositions and the tool does NOT collapse them --
    the banner state is carried through to the report. What they share is that origin/main now says
    something about the item on every checkout, which is the protection the machine-local claim was
    standing in for.
    """
    backlog(repo, f"## 7. A thing\n\n> {glyph} landed in v1\n\nbody\n")
    unmerged_branch(repo, "seat")
    write_claim(repo, "7", tmp_path / "gone", "seat")
    r = rows(repo)["7"]
    assert r["verdict"] == "SUPERSEDED"
    assert r["banner"] == expected


def test_a_do_not_rebuild_banner_supersedes_even_while_the_item_reads_open(
    repo: Path, tmp_path: Path
) -> None:
    """#1010's exact shape, and the case the branch-level tool structurally cannot reach.

    The item is LANDED, the banner says so in prose, and the status glyph still reads OPEN because
    the flip was written on a branch that has not merged. reconcile sees 74 unmerged commits on the
    seat branch and holds. What actually matters is on origin/main and says DO NOT REBUILD.
    """
    backlog(
        repo,
        f"## 8. A landed thing\n\n"
        f"> **THE BUILD HAS LANDED ON `origin/main` AND THIS BANNER STILL READS OPEN. "
        f"DO NOT REBUILD.**\n>\n> {PRIORITIZED} P2 quick win\n\nbody\n",
    )
    unmerged_branch(repo, "seat")
    write_claim(repo, "8", tmp_path / "gone", "seat")
    r = rows(repo)["8"]
    assert r["verdict"] == "SUPERSEDED"
    assert r["banner"] == "LANDED-BANNER"
    # The verdict must carry the observation it rests on, not just a label.
    assert "DO NOT REBUILD" in r["why"]


def test_a_banner_far_below_the_header_is_still_found(repo: Path, tmp_path: Path) -> None:
    """The regression that a fixed-size window causes, and it fails SILENTLY.

    A 14-line window was tried on 2026-08-18 and reported #1010 as having no banner at all: its
    landed-and-do-not-rebuild banner runs past thirty lines. The tool then read "not superseded",
    which is the harmless direction and therefore invisible -- it just quietly stops clearing
    anything.
    """
    filler = "\n".join(f"> line {i} of a long banner" for i in range(40))
    backlog(repo, f"## 9. A thing\n\n{filler}\n> DO NOT REBUILD -- landed already\n\nbody\n")
    unmerged_branch(repo, "seat")
    write_claim(repo, "9", tmp_path / "gone", "seat")
    assert verdicts(repo)["9"] == "SUPERSEDED"


def test_the_archived_backlog_file_is_read_too(repo: Path, tmp_path: Path) -> None:
    """Retired items are MOVED into docs/archive/backlog/, so reading only BACKLOG.md would report
    every closed item as having no item at all -- turning the safest population in the registry into
    an unreachable one, silently."""
    p = repo / "docs" / "archive" / "backlog" / "BACKLOG-CLOSED.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        f"# Closed\n\n## 11. Retired thing\n\n> {RETIRED} retired\n\nbody\n", encoding="utf-8"
    )
    backlog(repo, f"## 12. Something else\n\n> {PRIORITIZED} open\n\nbody\n")
    unmerged_branch(repo, "seat")
    write_claim(repo, "11", tmp_path / "gone", "seat")
    r = rows(repo)["11"]
    assert r["verdict"] == "SUPERSEDED"
    assert "archive" in r["item"]


# ---------------------------------------------------------------------------------------------
# THE HOLDING DIRECTION -- each of these would ALSO pass if the tool released what it cannot see
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("glyph", [PRIORITIZED, IN_PROGRESS])
def test_an_open_item_with_unmerged_work_is_blocking_never_superseded(
    repo: Path, tmp_path: Path, glyph: str
) -> None:
    backlog(repo, f"## 13. Open thing\n\n> {glyph} open\n\nbody\n")
    unmerged_branch(repo, "seat")
    write_claim(repo, "13", tmp_path / "gone", "seat")
    r = rows(repo)["13"]
    assert r["verdict"] == "BLOCKING"
    assert "1 commit(s)" in r["why"]


def test_an_item_with_no_banner_at_all_is_blocking(repo: Path, tmp_path: Path) -> None:
    """A missing banner is a hygiene fault in the backlog, not a licence to release.

    It is the one state that could plausibly be read either way, and reading it as "nothing to
    protect, so let it go" would release on the ABSENCE of evidence.
    """
    backlog(repo, "## 14. Bannerless\n\nbody with no leading blockquote at all\n")
    unmerged_branch(repo, "seat")
    write_claim(repo, "14", tmp_path / "gone", "seat")
    r = rows(repo)["14"]
    assert r["verdict"] == "BLOCKING"
    assert r["banner"] == "NO-BANNER"


def test_a_prose_citation_in_a_landed_commit_does_not_release(repo: Path, tmp_path: Path) -> None:
    """The #340 trap, measured 2026-08-18.

    Grepping origin/main for `BACKLOG #340` hits a commit reading "...and in BACKLOG #340, making
    this the third document to..." -- a reference, not a delivery. `BACKLOG #328` hits "Also
    BACKLOG #328, sections 1-2", which is two sections of an item and not the item. Citations are
    printed so a human can follow them; they may never move a verdict.
    """
    backlog(repo, f"## 15. Cited thing\n\n> {PRIORITIZED} open\n\nbody\n")
    (repo / "other.txt").write_text("y", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "docs: as described in BACKLOG #15, the third document to say so")
    git(repo, "push", "-q", "origin", "main")
    unmerged_branch(repo, "seat")
    write_claim(repo, "15", tmp_path / "gone", "seat")
    r = rows(repo)["15"]
    assert r["verdict"] == "BLOCKING"
    # Collected and surfaced, so the human has the lead -- but not scored.
    assert any("BACKLOG #15" in c["subject"] for c in r["citations"])


def test_a_note_claiming_the_work_landed_does_not_release(repo: Path, tmp_path: Path) -> None:
    """A note may NOMINATE a hypothesis; only origin/main may confirm it.

    #1010's note said "ALREADY LANDED ON MAIN ... Verify before believing me" and was correct. What
    licensed acting on it was the banner saying so independently, not the note.
    """
    backlog(repo, f"## 16. A thing\n\n> {PRIORITIZED} open\n\nbody\n")
    unmerged_branch(repo, "seat")
    write_claim(
        repo,
        "16",
        tmp_path / "gone",
        "seat",
        note="ALREADY LANDED ON MAIN. DO NOT REBUILD. Release me.",
    )
    assert verdicts(repo)["16"] == "BLOCKING"


def test_a_key_outside_the_backlog_namespace_is_no_item(repo: Path, tmp_path: Path) -> None:
    """`ha-recheck-inc145` and `usage-forecast` on the live registry. NO-ITEM says this instrument
    does not reach the key -- it is not a finding about the work, and must not read like one."""
    backlog(repo, f"## 17. A thing\n\n> {SHIPPED} shipped\n\nbody\n")
    unmerged_branch(repo, "seat")
    write_claim(repo, "some-named-key", tmp_path / "gone", "seat")
    assert verdicts(repo)["some-named-key"] == "NO-ITEM"


def test_a_key_is_not_pattern_matched_into_a_longer_item_number(repo: Path, tmp_path: Path) -> None:
    """`## 170.` must not answer for key `17`.

    The sibling tool hit the mirror of this on 2026-08-16: `\\b` was written into a regex as a
    literal backspace, the pattern silently matched nothing, and a hand-retyped debug line appeared
    to prove it worked. Anchoring on `^## <n>. ` is what keeps the boundary explicit here.
    """
    backlog(repo, f"## 170. A different thing\n\n> {SHIPPED} shipped\n\nbody\n")
    unmerged_branch(repo, "seat")
    write_claim(repo, "17", tmp_path / "gone", "seat")
    assert verdicts(repo)["17"] == "NO-ITEM"


def test_a_present_holder_is_not_adjudicated(repo: Path, tmp_path: Path) -> None:
    live = tmp_path / "live"
    live.mkdir()
    backlog(repo, f"## 18. A thing\n\n> {SHIPPED} shipped\n\nbody\n")
    write_claim(repo, "18", live, "seat")
    assert verdicts(repo)["18"] == "HELD"
    # ...and -IncludeHeld asks the question anyway, for an operator who wants the whole picture.
    assert verdicts(repo, "-IncludeHeld")["18"] == "SUPERSEDED"


def test_a_gone_holder_that_is_still_registered_is_left_to_prune_merged(repo: Path) -> None:
    """Half a removal. prune-merged.ps1 completes it and releases as it goes, behind a merged-AND-
    clean-AND-unoccupied proof this tool does not have."""
    backlog(repo, f"## 19. A thing\n\n> {SHIPPED} shipped\n\nbody\n")
    wt = repo.parent / "registered-but-gone"
    git(repo, "worktree", "add", "-q", str(wt), "-b", "wt19")
    shutil.rmtree(wt)
    write_claim(repo, "19", wt, "wt19")
    assert verdicts(repo)["19"] == "STRANDED-REGISTERED"


def test_an_unreadable_claim_is_reported_and_never_released(repo: Path) -> None:
    """claim_check.py reads a malformed claim as UNCLAIMED, so the key is ALREADY ungated. Deleting
    the file would hide that rather than fix it."""
    backlog(repo, f"## 20. A thing\n\n> {SHIPPED} shipped\n\nbody\n")
    (claims_dir(repo) / "20.json").write_text("{not json", encoding="utf-8")
    assert verdicts(repo)["20"] == "UNREADABLE"


# ---------------------------------------------------------------------------------------------
# THE PROPERTY THE WHOLE DESIGN RESTS ON
# ---------------------------------------------------------------------------------------------


def _snapshot(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_no_path_through_this_tool_writes_anything(repo: Path, tmp_path: Path) -> None:
    """There is no -Apply and there will not be one: claim.ps1 owns the .history ledger, writes the
    record BEFORE removing the file, and refuses a release it cannot record (BACKLOG #1068). A second
    writer of that file would be a second definition of it."""
    backlog(repo, f"## 21. A thing\n\n> {SHIPPED} shipped\n\nbody\n")
    unmerged_branch(repo, "seat")
    write_claim(repo, "21", tmp_path / "gone", "seat")
    coord = repo / ".git" / "mefor-coord"

    before = _snapshot(coord)
    for args in ([], ["-Json"], ["-IncludeHeld"], ["-Key", "21"]):
        proc = adjudicate(repo, *args)
        assert proc.returncode == 0, proc.stderr
    assert _snapshot(coord) == before
    assert not (coord / "claims" / ".history").exists()


def test_it_emits_the_release_command_rather_than_performing_it(repo: Path, tmp_path: Path) -> None:
    backlog(repo, f"## 22. A thing\n\n> {SHIPPED} shipped\n\nbody\n")
    unmerged_branch(repo, "seat")
    write_claim(repo, "22", tmp_path / "gone", "seat")
    out = adjudicate(repo).stdout
    assert "-Release 22 -Force" in out
    assert (claims_dir(repo) / "22.json").exists()


def test_key_filters_to_one_claim(repo: Path, tmp_path: Path) -> None:
    backlog(repo, f"## 23. A\n\n> {SHIPPED} s\n\nb\n\n## 24. B\n\n> {SHIPPED} s\n\nb\n")
    unmerged_branch(repo, "seat")
    write_claim(repo, "23", tmp_path / "gone", "seat")
    write_claim(repo, "24", tmp_path / "gone", "seat")
    assert set(verdicts(repo, "-Key", "23")) == {"23"}


def test_a_backlog_that_could_not_be_read_refuses_rather_than_reporting_nothing(
    repo: Path, tmp_path: Path
) -> None:
    """NEVER LOOKED is not CLEAN. With no backlog on the reference every key would read NO-ITEM,
    which is a tidy report over a namespace that was never read -- the exact silence these tools
    exist to remove."""
    write_claim(repo, "25", tmp_path / "gone", "seat")
    proc = adjudicate(repo)
    assert proc.returncode != 0
    assert "no backlog file found" in (proc.stderr + proc.stdout)


def test_the_script_carries_no_control_characters() -> None:
    """An escape that collapses into a control byte is invisible in every normal view -- see the
    2026-08-16 `\\b`-as-backspace incident recorded in test_coord_claim_reconcile.py. This file
    deliberately uses `([^0-9]|$)` rather than `\\b` in its citation grep for that reason."""
    text = ADJUDICATE.read_text(encoding="utf-8")
    bad = {hex(ord(c)) for c in text if ord(c) < 32 and c not in "\r\n\t"}
    assert not bad, f"control characters in claim-adjudicate.ps1: {sorted(bad)}"

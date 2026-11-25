# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
import re
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


def _publish(repo: Path, rel: str, text: str) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", f"write {rel}")
    git(repo, "push", "-q", "origin", "main")


def backlog(repo: Path, body: str) -> None:
    """Write docs/BACKLOG.md and publish it to origin/main.

    Publishing matters: the tool reads ``origin/main`` and falls back to local main only when there
    is no origin. A fixture that never pushed would exercise the fallback while claiming to test the
    primary path.
    """
    _publish(repo, "docs/BACKLOG.md", "# Backlog\n\n" + body)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A sandbox carrying its OWN copies -- both scripts anchor on where they live (BACKLOG #1060)."""
    r = tmp_path / "repo"
    (r / "scripts" / "coord").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    shutil.copy2(CLAIM, r / "scripts" / "coord" / "claim.ps1")
    shutil.copy2(CLAIM.parent / "coord-root.ps1", r / "scripts" / "coord" / "coord-root.ps1")
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


def test_a_backlog_named_file_with_no_item_refuses_rather_than_reporting_no_item(
    repo: Path, tmp_path: Path
) -> None:
    """BACKLOG #5480. The ledger left this repository and docs/BACKLOG.md became a stub with no item
    heading, while other docs carry BACKLOG in their names. A file-name match then passed the check
    above and every numeric key read NO-ITEM over a namespace that holds nothing.

    THE CONTROL is the same claim against a ledger holding one item: it is adjudicated, so the
    refusal is caused by the missing item heading and not by the fixture.
    """
    write_claim(repo, "26", tmp_path / "gone", "seat")
    stub = (
        "Planning and the backlog for this project are maintained privately.\n\n"
        "## How to contribute\n\nOpen a pull request.\n\n"
        "## Why `BACKLOG #N` does not resolve here\n\nThose numbers index the private ledger.\n"
    )
    proposals = repo / "docs" / "backlog-proposals" / "packet.md"
    proposals.parent.mkdir(parents=True)
    proposals.write_text("# Proposal\n\n## Item 26 would be this\n", encoding="utf-8")
    backlog(repo, stub)

    proc = adjudicate(repo)
    combined = proc.stderr + proc.stdout
    assert proc.returncode != 0, f"a ledger with no item still produced a report:\n{combined}"
    assert "no backlog item heading found" in combined, combined
    assert "vault" in combined, combined
    # The refusal names the remedy (BACKLOG #5480 follow-up).
    assert "-LedgerRepo" in _flat(combined), combined
    assert "NO-ITEM" not in proc.stdout, combined

    backlog(repo, f"## 26. A real item\n\n> {SHIPPED} SHIPPED\n")
    proc = adjudicate(repo, "-Json")
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    assert {c["key"] for c in report["claims"]} == {"26"}
    # The proposals file is outside docs/BACKLOG.md and docs/archive/backlog/, so it is not a source.
    assert report["sources"]["backlog"] == ["docs/BACKLOG.md"], report["sources"]


def _failing_git_env(tmp_path: Path, subcommand: str, said: str) -> dict[str, str]:
    """PATH with a ``git.cmd`` shim first that fails ONE git subcommand, writing ``said`` to stderr.

    The script spells every namespace read ``git -C <repo> <subcommand> ...``, so the subcommand is
    ``%3``; every other call passes through to the real git. pwsh finds a ``.cmd`` first on PATH.
    """
    real_git = shutil.which("git")
    assert real_git is not None
    shim = tmp_path / f"shim-{subcommand}"
    shim.mkdir()
    (shim / "git.cmd").write_text(
        "@echo off\r\n"
        f'if "%3"=="{subcommand}" (\r\n'
        f"  echo {said} 1>&2\r\n"
        "  exit /b 128\r\n"
        ")\r\n"
        f'"{real_git}" %*\r\n',
        encoding="ascii",
        newline="",
    )
    return dict(os.environ, PATH=f"{shim}{os.pathsep}{os.environ['PATH']}")


def _with_quoting_forced(env: dict[str, str]) -> dict[str, str]:
    """``env`` with git's path quoting forced ON, appended after any inherited GIT_CONFIG_* entries.

    A machine with ``core.quotePath=false`` never quotes a non-ASCII name, so the pre-``-z`` code
    would pass the non-ASCII case there and it would no longer pin the regression. Appended at the
    inherited count rather than overwriting index 0, so config a runner injects the same way stays.
    """
    out = dict(env)
    n = int(out.get("GIT_CONFIG_COUNT", "0") or "0")
    out[f"GIT_CONFIG_KEY_{n}"] = "core.quotePath"
    out[f"GIT_CONFIG_VALUE_{n}"] = "true"
    out["GIT_CONFIG_COUNT"] = str(n + 1)
    return out


def _flat(text: str) -> str:
    """pwsh's error view colours a thrown message and word-wraps it at the console width with a
    ``|`` gutter, so a phrase can straddle a line. Strip both before matching a phrase."""
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    return re.sub(r"\s*\n\s*\|?\s*", " ", text)


def _adjudicate_env(
    repo: Path, env: dict[str, str], *args: str
) -> subprocess.CompletedProcess[str]:
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
        env=env,
    )


def test_the_failing_git_shim_passes_every_other_call_through(repo: Path, tmp_path: Path) -> None:
    """THE CONTROL for the refusals below: a shim failing a subcommand the script never runs still
    lets the claim be adjudicated, so a refusal there is the failing call and not the shim."""
    write_claim(repo, "27", tmp_path / "gone", "seat")
    backlog(repo, f"## 27. A real item\n\n> {SHIPPED} SHIPPED\n")
    proc = _adjudicate_env(repo, _failing_git_env(tmp_path, "never-run", "fatal: unused"), "-Json")
    assert proc.returncode == 0, proc.stderr
    assert {c["key"] for c in json.loads(proc.stdout)["claims"]} == {"27"}


@pytest.mark.parametrize(
    "subcommand,phrase",
    [("show", "only partly read"), ("ls-tree", "not read")],
)
def test_a_failed_namespace_read_refuses_and_carries_gits_own_words(
    repo: Path, tmp_path: Path, subcommand: str, phrase: str
) -> None:
    """MUST TRIP. A git show or ls-tree that fails must refuse the whole run rather than drop a file
    (its items would read NO-ITEM) or read an empty tree, and the refusal must carry git's own stderr
    so the operator sees why. The control is the pass-through case above.
    """
    write_claim(repo, "27", tmp_path / "gone", "seat")
    backlog(repo, f"## 27. A real item\n\n> {SHIPPED} SHIPPED\n")
    said = f"fatal: synthetic {subcommand} failure"
    proc = _adjudicate_env(repo, _failing_git_env(tmp_path, subcommand, said))
    combined = _flat(proc.stderr + proc.stdout)
    assert proc.returncode != 0, f"a failed {subcommand} still produced a report:\n{combined}"
    assert f"git {subcommand} exited 128" in combined, combined
    assert phrase in combined, combined
    assert said in combined, f"the refusal dropped git's stderr:\n{combined}"
    assert "NO-ITEM" not in proc.stdout, combined


def test_a_non_ascii_backlog_file_name_is_read_not_quoted_away(repo: Path, tmp_path: Path) -> None:
    """MUST TRIP on ``ls-tree`` without ``-z``: git quotes a path holding a non-ASCII byte, and the
    quoted spelling is not a path git show can read. The control is
    ``test_the_archived_backlog_file_is_read_too``, the same shape with an ASCII name.
    """
    name = "BACKLOG-CLOS\N{LATIN CAPITAL LETTER E WITH ACUTE}.md"
    p = repo / "docs" / "archive" / "backlog" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        f"# Closed\n\n## 11. Retired thing\n\n> {RETIRED} retired\n\nbody\n", encoding="utf-8"
    )
    backlog(repo, f"## 12. Something else\n\n> {PRIORITIZED} open\n\nbody\n")
    unmerged_branch(repo, "seat")
    write_claim(repo, "11", tmp_path / "gone", "seat")
    # Quoting forced ON, so a developer's core.quotePath=false cannot hide the regression.
    env = _with_quoting_forced(dict(os.environ))
    proc = _adjudicate_env(repo, env, "-Json")
    assert proc.returncode == 0, proc.stderr
    r = {c["key"]: c for c in json.loads(proc.stdout)["claims"]}["11"]
    assert r["verdict"] == "SUPERSEDED", r


def test_the_script_carries_no_control_characters() -> None:
    """An escape that collapses into a control byte is invisible in every normal view -- see the
    2026-08-16 `\\b`-as-backspace incident recorded in test_coord_claim_reconcile.py. This file
    deliberately uses `([^0-9]|$)` rather than `\\b` in its citation grep for that reason."""
    text = ADJUDICATE.read_text(encoding="utf-8")
    bad = {hex(ord(c)) for c in text if ord(c) < 32 and c not in "\r\n\t"}
    assert not bad, f"control characters in claim-adjudicate.ps1: {sorted(bad)}"


# ===================================================================================================
# SIBLING CITATIONS -- three items of four were invisible here (BACKLOG #1347).
# ===================================================================================================


def test_a_sibling_citation_is_collected_not_just_the_item_carrying_the_prefix(
    repo: Path, tmp_path: Path
) -> None:
    """The house form writes `BACKLOG` ONCE and the siblings after it.

    `--grep="BACKLOG #<item>"` matched only the item carrying the prefix, so a commit reading
    `(BACKLOG #1319, #1322, #1323, #1331)` surfaced for #1319 and for nothing else. The failure
    direction is the expensive one: work that landed reads as never delivered, and a dispatcher
    hands a builder a finished item. The live control is `df8acc95`, the commit that misled two
    seats into holding three claims for landed work.
    """
    backlog(repo, f"## 22. Sibling thing\n\n> {PRIORITIZED} open\n\nbody\n")
    (repo / "other.txt").write_text("y", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "four gates that could not fail (BACKLOG #19, #22, #23, #31)")
    git(repo, "push", "-q", "origin", "main")
    unmerged_branch(repo, "seat")
    write_claim(repo, "22", tmp_path / "gone", "seat")
    r = rows(repo)["22"]
    assert any("#22" in c["subject"] for c in r["citations"]), (
        "a sibling citation was not collected. #22 carries no BACKLOG prefix of its own -- it sits "
        "after the one prefix the house form writes -- and that is exactly the shape that was "
        f"invisible. citations={r['citations']}"
    )


def test_a_squash_merge_suffix_is_not_collected_as_a_citation(repo: Path, tmp_path: Path) -> None:
    """The negative that bounds the widening, and it is the reason for scoping to the parenthetical.

    Closing the sibling gap by taking every `#N` after the BACKLOG token would collect the
    pull-request number a squash-merge appends: `(BACKLOG #1040) (#547)` would report a delivery of
    item 547. Measured over `git log --all` on 2026-08-25, unscoped calls 641 subjects multi-item
    against 38 of 1070 for the scoped rule -- so the unscoped form is wrong about roughly 17 times
    as many commits as it is right about.
    """
    backlog(repo, f"## 47. Not delivered by a PR number\n\n> {PRIORITIZED} open\n\nbody\n")
    (repo / "other.txt").write_text("y", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "fix(hooks): the deny text (BACKLOG #40) (#47)")
    git(repo, "push", "-q", "origin", "main")
    unmerged_branch(repo, "seat")
    write_claim(repo, "47", tmp_path / "gone", "seat")
    r = rows(repo)["47"]
    assert not r["citations"], (
        "the squash-merge pull-request suffix was collected as a delivery citation for item 47. "
        f"citations={r['citations']}"
    )


@pytest.mark.parametrize(
    "subject",
    [
        # A labelled pull request inside the group is not an item.
        "fix(hooks): the deny text (BACKLOG #40, PR #47)",
        # A conventional-commit scope is the WORD, not the `BACKLOG #` token.
        "docs(backlog): file #47 and #48",
        # A closed group ends what its token governs.
        "fix(hooks): the deny text (BACKLOG #40) closes #47",
    ],
)
def test_a_number_the_claim_gate_does_not_count_is_not_collected_either(
    repo: Path, tmp_path: Path, subject: str
) -> None:
    """PARITY WITH scripts/hooks/claim_check.py (BACKLOG #1347). The gate counts a subject's items by
    this tool's rule and refuses every other `#N`. Where the gate reads a number as NOT an item, this
    tool must not collect it as a delivery of one, or the two disagree about the same subject."""
    backlog(repo, f"## 47. Not delivered here\n\n> {PRIORITIZED} open\n\nbody\n")
    (repo / "other.txt").write_text("y", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", subject)
    git(repo, "push", "-q", "origin", "main")
    unmerged_branch(repo, "seat")
    write_claim(repo, "47", tmp_path / "gone", "seat")
    r = rows(repo)["47"]
    assert not r["citations"], f"{subject!r} was collected for item 47: {r['citations']}"


def test_a_sibling_after_a_bare_token_is_still_collected(repo: Path, tmp_path: Path) -> None:
    """The positive arm for the negatives above: narrowing the token must not lose the bare-token
    form, which the gate counts as an item and therefore accepts."""
    backlog(repo, f"## 47. Delivered as a sibling\n\n> {PRIORITIZED} open\n\nbody\n")
    (repo / "other.txt").write_text("y", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "fix(hooks): BACKLOG #40, #47 deny text")
    git(repo, "push", "-q", "origin", "main")
    unmerged_branch(repo, "seat")
    write_claim(repo, "47", tmp_path / "gone", "seat")
    r = rows(repo)["47"]
    assert any("#47" in c["subject"] for c in r["citations"]), r["citations"]


# ===================================================================================================
# THE LEDGER LIVES IN ANOTHER REPOSITORY -- -LedgerRepo (BACKLOG #5480).
# ===================================================================================================

STUB = (
    "Planning and the backlog for this project are maintained privately.\n\n"
    "## Why `BACKLOG #N` does not resolve here\n\nThose numbers index the private ledger.\n"
)


def _names_path(text: str, path: Path) -> bool:
    """Whether ``text`` names ``path`` as git prints it (forward slashes). Whitespace is dropped from
    both, because pwsh's error view word-wraps a thrown message at the console width."""
    want = re.sub(r"\s+", "", str(path.resolve()).replace("\\", "/")).lower()
    return want in re.sub(r"\s+", "", _flat(text)).replace("|", "").lower()


@pytest.fixture
def vault(tmp_path: Path) -> Path:
    """A ledger repository of its own, with an origin/main the tool must read rather than local main.

    It carries a CLOSED item, an item with a do-not-rebuild banner, an OPEN item, and an archived
    CLOSED item: the shape of the real vault.
    """
    v = tmp_path / "vault"
    subprocess.run(["git", "init", "-q", "-b", "main", str(v)], check=True, capture_output=True)
    git(v, "config", "user.email", "t@example.invalid")
    git(v, "config", "user.name", "t")
    origin = tmp_path / "vault-origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(origin)], check=True, capture_output=True)
    git(v, "remote", "add", "origin", str(origin))
    archived = v / "docs" / "archive" / "backlog" / "BACKLOG-CLOSED.md"
    archived.parent.mkdir(parents=True)
    archived.write_text(
        f"# Closed\n\n## 61. Archived thing\n\n> {RETIRED} retired\n\nbody\n", encoding="utf-8"
    )
    _publish(
        v,
        "docs/BACKLOG.md",
        f"# Backlog\n\n## 60. Shipped thing\n\n> {SHIPPED} SHIPPED\n\nbody\n\n"
        "## 62. Landed thing\n\n> **DO NOT REBUILD.** landed already\n\nbody\n\n"
        f"## 63. Open thing\n\n> {PRIORITIZED} open\n\nbody\n",
    )
    return v


def test_ledger_repo_verdicts_come_from_the_ledger_repository(
    repo: Path, vault: Path, tmp_path: Path
) -> None:
    """MUST TRIP on origin/main, which has no -LedgerRepo. The engine fixture holds only the stub, so
    every verdict below can only have come from the ledger repository. The report names the ledger
    checkout and the SHA it pinned, which is the vault's origin/main."""
    backlog(repo, STUB)
    unmerged_branch(repo, "seat")
    for k in ("60", "61", "62", "63"):
        write_claim(repo, k, tmp_path / "gone", "seat")

    proc = adjudicate(repo, "-Json", "-LedgerRepo", str(vault))
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    got = {c["key"]: c for c in report["claims"]}
    assert {k: v["verdict"] for k, v in got.items()} == {
        "60": "SUPERSEDED",
        "61": "SUPERSEDED",
        "62": "SUPERSEDED",
        "63": "BLOCKING",
    }
    assert got["61"]["banner"] == "CLOSED/retired"
    assert got["62"]["banner"] == "LANDED-BANNER"
    # The ahead count is still the ENGINE branch's: the branches live here, not in the ledger.
    assert "1 commit(s)" in got["63"]["why"], got["63"]
    assert sorted(report["sources"]["backlog"]) == [
        "docs/BACKLOG.md",
        "docs/archive/backlog/BACKLOG-CLOSED.md",
    ]
    ledger = report["sources"]["ledger"]
    assert Path(ledger["repo"]).resolve() == vault.resolve()
    assert ledger["reference"] == "origin/main"
    assert ledger["sha"] == git(vault, "rev-parse", "origin/main").strip()


def test_ledger_repo_text_report_names_the_checkout_and_the_pinned_sha(
    repo: Path, vault: Path, tmp_path: Path
) -> None:
    """MUST TRIP on origin/main, which has no -LedgerRepo. The human report, not only -Json, says
    which ledger it read. A test of its own, so each stays inside the per-test watchdog."""
    backlog(repo, STUB)
    write_claim(repo, "60", tmp_path / "gone", "seat")
    proc = adjudicate(repo, "-LedgerRepo", str(vault))
    assert proc.returncode == 0, proc.stderr
    assert git(vault, "rev-parse", "origin/main").strip() in proc.stdout, proc.stdout
    assert _names_path(proc.stdout, vault), proc.stdout


def test_ledger_repo_is_pinned_to_origin_main_not_local_main(
    repo: Path, vault: Path, tmp_path: Path
) -> None:
    """A banner on an unpushed local commit in the ledger checkout must not count: origin/main is the
    protection that travels. The control is the pushed case above."""
    backlog(repo, STUB)
    unmerged_branch(repo, "seat")
    write_claim(repo, "63", tmp_path / "gone", "seat")
    (vault / "docs" / "BACKLOG.md").write_text(
        f"# Backlog\n\n## 63. Open thing\n\n> {SHIPPED} SHIPPED locally only\n\nbody\n",
        encoding="utf-8",
    )
    git(vault, "commit", "-qam", "local only")
    assert verdicts(repo, "-LedgerRepo", str(vault))["63"] == "BLOCKING"


def test_a_ledger_repo_that_is_not_a_git_repository_refuses(repo: Path, tmp_path: Path) -> None:
    """MUST TRIP on origin/main, where the unknown parameter fails for another reason entirely --
    so the assertion is on git's own words, which only the -LedgerRepo read can carry."""
    backlog(repo, STUB)
    write_claim(repo, "60", tmp_path / "gone", "seat")
    plain = tmp_path / "not-a-repo"
    plain.mkdir()
    # A ceiling, so an ancestor of the temp directory that is itself a repository cannot answer.
    env = dict(os.environ, GIT_CEILING_DIRECTORIES=str(tmp_path))
    proc = _adjudicate_env(repo, env, "-Json", "-LedgerRepo", str(plain))
    combined = _flat(proc.stderr + proc.stdout)
    assert proc.returncode != 0, combined
    assert "git rev-parse exited" in combined, combined
    assert "not a git repository" in combined, combined
    assert '"claims"' not in proc.stdout, combined


def test_a_ledger_checkout_without_origin_main_refuses_rather_than_read_local_main(
    repo: Path, tmp_path: Path
) -> None:
    """MUST TRIP on origin/main. The checkout's LOCAL main carries a CLOSED banner nobody published.
    Reading it would release the claim on protection that does not travel -- the costly direction --
    so the ledger gets no local-main fallback and the refusal carries git's own words."""
    backlog(repo, STUB)
    unmerged_branch(repo, "seat")
    write_claim(repo, "60", tmp_path / "gone", "seat")
    local = tmp_path / "local-only-vault"
    subprocess.run(["git", "init", "-q", "-b", "main", str(local)], check=True, capture_output=True)
    git(local, "config", "user.email", "t@example.invalid")
    git(local, "config", "user.name", "t")
    (local / "docs").mkdir()
    (local / "docs" / "BACKLOG.md").write_text(
        f"# Backlog\n\n## 60. Shipped thing\n\n> {SHIPPED} SHIPPED\n\nbody\n", encoding="utf-8"
    )
    git(local, "add", "-A")
    git(local, "commit", "-qm", "local only")
    proc = adjudicate(repo, "-Json", "-LedgerRepo", str(local))
    combined = _flat(proc.stderr + proc.stdout)
    assert proc.returncode != 0, combined
    assert "git rev-parse exited" in combined, combined
    assert "origin/main in" in combined, combined
    assert "SUPERSEDED" not in proc.stdout, combined


def test_the_blocking_roll_up_strips_a_banner_state_holding_a_space(
    repo: Path, tmp_path: Path
) -> None:
    """MUST TRIP on origin/main: `OPEN/in progress` holds a space, so the roll-up's strip of the
    "item reads <state> on <ref> and" lead never matched and the whole sentence printed."""
    backlog(repo, f"## 67. In progress\n\n> {IN_PROGRESS} in progress\n\nbody\n")
    unmerged_branch(repo, "seat")
    write_claim(repo, "67", tmp_path / "gone", "seat")
    proc = adjudicate(repo)
    assert proc.returncode == 0, proc.stderr
    assert "'seat' carries 1 commit(s)" in proc.stdout, proc.stdout
    assert "item reads" not in proc.stdout, proc.stdout


def test_an_archive_file_not_named_backlog_does_not_shadow_the_ledger(
    repo: Path, tmp_path: Path
) -> None:
    """MUST TRIP on origin/main, which read every docs/ file whose path held the word. The archive
    sorts before docs/BACKLOG.md, so a README there numbering its own sections would shadow live
    items. Only BACKLOG*.md, the vault checker's own glob, is a ledger file; the archived
    BACKLOG-CLOSED.md is still read (test_the_archived_backlog_file_is_read_too)."""
    _publish(
        repo,
        "docs/archive/backlog/README.md",
        f"# How to archive\n\n## 68. Archive procedure\n\n> {SHIPPED} done\n",
    )
    backlog(repo, f"## 68. Live open item\n\n> {PRIORITIZED} open\n\nbody\n")
    unmerged_branch(repo, "seat")
    write_claim(repo, "68", tmp_path / "gone", "seat")
    assert verdicts(repo)["68"] == "BLOCKING"


@pytest.mark.parametrize(
    "lead",
    [
        # The declined glyph as decoration mid-line inside an item whose status line reads OPEN.
        f"> {IN_PROGRESS} in progress\n> **Filed -- not started. {DECLINED} OPEN ON EVERY GATE.**",
        # "do not rebuild" as SCOPE, in lower case, inside an open item.
        f"> {PRIORITIZED} open\n> Build the pane; do not rebuild the endpoint.",
    ],
)
def test_vault_banner_shapes_that_are_not_a_closure_stay_blocking(
    repo: Path, tmp_path: Path, lead: str
) -> None:
    """MUST TRIP on origin/main, which matched a CLOSED glyph anywhere in the banner run and the
    landing phrases in any case. Both shapes stand in the vault ledger inside open items (measured
    2026-11-19), and each read SUPERSEDED there: a printed release line for open, unbuilt work."""
    backlog(repo, f"## 69. Open thing\n\n{lead}\n\nbody\n")
    unmerged_branch(repo, "seat")
    write_claim(repo, "69", tmp_path / "gone", "seat")
    assert verdicts(repo)["69"] == "BLOCKING"


def test_a_ledger_repo_with_no_item_heading_refuses(
    repo: Path, vault: Path, tmp_path: Path
) -> None:
    """MUST TRIP on origin/main. A ledger checkout whose backlog files hold no `## N.` heading is the
    stub again, wherever it sits; the control is the populated vault above."""
    backlog(repo, STUB)
    write_claim(repo, "60", tmp_path / "gone", "seat")
    git(vault, "rm", "-q", "docs/archive/backlog/BACKLOG-CLOSED.md")
    _publish(vault, "docs/BACKLOG.md", STUB)
    proc = adjudicate(repo, "-Json", "-LedgerRepo", str(vault))
    combined = _flat(proc.stderr + proc.stdout)
    assert proc.returncode != 0, combined
    assert "no backlog item heading found" in combined, combined
    assert _names_path(proc.stderr + proc.stdout, vault), combined
    assert '"claims"' not in proc.stdout, combined


def test_a_plan_file_named_backlog_is_not_part_of_the_namespace(repo: Path, tmp_path: Path) -> None:
    """MUST TRIP on origin/main, which took any docs/ file with BACKLOG in its name. The vault carries
    plan and handoff files of that name with `## N.` step headings; a key the ledger lacks must read
    NO-ITEM, not take a plan step's text as its banner. This uses origin/main's own arguments, so it
    trips there only because the plan file joined the namespace."""
    _publish(repo, "docs/releases/BACKLOG-PLAN.md", f"# Plan\n\n## 64. Step\n\n> {SHIPPED} done\n")
    backlog(repo, f"## 65. A real item\n\n> {PRIORITIZED} open\n\nbody\n")
    unmerged_branch(repo, "seat")
    write_claim(repo, "64", tmp_path / "gone", "seat")
    assert verdicts(repo)["64"] == "NO-ITEM"


# ===================================================================================================
# CITATION RECALL AND THE REPORT'S OWN WORDS (BACKLOG #7562, #7563).
# ===================================================================================================


def test_the_citation_cap_is_applied_after_filtering_not_before(repo: Path, tmp_path: Path) -> None:
    """MUST TRIP on origin/main (BACKLOG #7562). git's `--grep` reads the whole message, so every
    commit whose squash suffix or body names the number is a candidate, and `--max-count=40` kept
    only the 40 newest candidates before the subject filter ran. Forty newer non-citations then
    hid the real delivery commit behind them."""
    backlog(repo, f"## 47. Delivered long ago\n\n> {PRIORITIZED} open\n\nbody\n")
    git(repo, "commit", "-q", "--allow-empty", "-m", "the real delivery (BACKLOG #47)")
    for i in range(41):
        git(repo, "commit", "-q", "--allow-empty", "-m", f"unrelated change {i} (#47)")
    git(repo, "push", "-q", "origin", "main")
    unmerged_branch(repo, "seat")
    write_claim(repo, "47", tmp_path / "gone", "seat")
    cites = rows(repo)["47"]["citations"]
    assert [c["subject"] for c in cites] == ["the real delivery (BACKLOG #47)"], cites


def test_an_unreadable_claim_for_another_key_stays_out_of_a_single_key_query(
    repo: Path, tmp_path: Path
) -> None:
    """MUST TRIP on origin/main (BACKLOG #7563 part 2): the UNREADABLE row was appended before the
    -Key filter ran, so `-Key 23` reported an unrelated corrupt claim as well."""
    backlog(repo, f"## 23. A\n\n> {SHIPPED} s\n\nb\n")
    write_claim(repo, "23", tmp_path / "gone", "seat")
    (claims_dir(repo) / "99.json").write_text("{not json", encoding="utf-8")
    assert verdicts(repo, "-Key", "23") == {"23": "SUPERSEDED"}
    # ...and the key's own unreadable file is still reported.
    assert verdicts(repo, "-Key", "99") == {"99": "UNREADABLE"}


def test_a_stale_local_branch_does_not_hide_unmerged_commits_on_origin(
    repo: Path, tmp_path: Path
) -> None:
    """MUST TRIP on origin/main (BACKLOG #7563 part 1): the local branch was probed first and alone,
    so a local copy left at main read "carries no commit" while origin held the unmerged work."""
    backlog(repo, f"## 68. Open\n\n> {PRIORITIZED} open\n\nbody\n")
    unmerged_branch(repo, "seat")
    git(repo, "push", "-q", "origin", "seat")
    git(repo, "branch", "-f", "seat", "main")
    write_claim(repo, "68", tmp_path / "gone", "seat")
    why = rows(repo)["68"]["why"]
    assert "'seat' carries 1 commit(s)" in why, why


def test_claims_with_no_branch_are_not_rolled_up_as_one_branch_decision(
    repo: Path, tmp_path: Path
) -> None:
    """MUST TRIP on origin/main (BACKLOG #7563 part 3): Group-Object put every claim with an empty
    branch into one group and offered "release all 2" as one branch decision for unrelated keys."""
    backlog(
        repo, f"## 69. A\n\n> {PRIORITIZED} open\n\nb\n\n## 70. B\n\n> {PRIORITIZED} open\n\nb\n"
    )
    write_claim(repo, "69", tmp_path / "gone", "")
    write_claim(repo, "70", tmp_path / "gone", "")
    proc = adjudicate(repo)
    assert proc.returncode == 0, proc.stderr
    assert "release all 2" not in proc.stdout, proc.stdout
    assert "records no branch" in proc.stdout, proc.stdout


def test_the_release_command_quotes_the_script_path(repo: Path, tmp_path: Path) -> None:
    """MUST TRIP on origin/main (BACKLOG #7563 part 4): the path was printed bare, so a checkout
    under a directory holding a space printed a command that does not run as pasted."""
    backlog(repo, f"## 22. A thing\n\n> {SHIPPED} shipped\n\nbody\n")
    write_claim(repo, "22", tmp_path / "gone", "seat")
    out = adjudicate(repo).stdout
    assert re.search(r"-File '[^']+claim\.ps1' -Release 22 -Force", out), out

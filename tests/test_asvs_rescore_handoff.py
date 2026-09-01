# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Does the re-score handoff check find a missing banner flip without inventing ones?

BACKLOG #1328, remaining limb. The screen compares a cell's re-score date against the date its item's
banner was last touched. Two failure directions matter and they are not symmetric: a missed flip is a
ledger that misreports finished work, while a manufactured hit costs a human read of an entry that was
fine. The item's own first run produced two apparent hits that dissolved on reading, so over-firing is
the tolerable direction -- but only if it is bounded and stated.

**THE TWO DEFECTS THESE ROWS EXIST TO PIN WERE BOTH FOUND BY RUNNING THE TOOL, NOT BY READING IT.**
Reading only the live ledger reported every CLOSED item as absent -- and a closed item is exactly the
case where the flip happened. A truncated walk floored every date at the window boundary and
manufactured hits at the floor. Both produced confident, wrong, plausible output.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "asvs"))

from rescore_handoff_check import (  # noqa: E402
    Flag,
    Pair,
    banner_last_touched,
    evaluate,
    main,
    read_pairs,
)

LIVE = "docs/BACKLOG.md"
ARCHIVE = "docs/archive/backlog/BACKLOG-CLOSED.md"


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True
    ).stdout.strip()


@pytest.fixture
def shallow_ledger(ledger: Path, tmp_path: Path) -> Path:
    """A depth-1 clone of the ledger fixture, so the walk's oldest revision IS the graft boundary.

    Cloned over file:// with --no-local, because a local clone hardlinks the object store and is not
    actually shallow.
    """
    dest = tmp_path / "shallow"
    git(
        "clone",
        "--depth",
        "1",
        "--no-local",
        ledger.as_uri(),
        str(dest),
        cwd=tmp_path,
    )
    # A CLONE INHERITS NO IDENTITY. user.email and user.name are per-repo, live in .git/config, and
    # clone copies none of them -- so a fixture that COMMITS into this clone succeeds on a developer
    # box off the GLOBAL identity and exits 128 on a runner that has none. That is exactly how this
    # reached CI: green locally, `git commit` 128 there. The two fixtures that `git init` set identity
    # explicitly; this one had nothing to inherit and nobody noticed, because the machine that ran it
    # supplied the missing value invisibly.
    git("config", "user.email", "t@example.com", cwd=dest)
    git("config", "user.name", "t", cwd=dest)
    return dest


def item_block(num: int, banner: str) -> str:
    return f"## {num}. a row\n\n> {banner} **Filed.** body\n\nCluster: x\n\n"


@pytest.fixture
def ledger(tmp_path: Path) -> Path:
    """A ledger history where one item is flipped IN PLACE and another is MOVED to the archive.

    The move is the case a live-only walk gets backwards, so it is built rather than described.
    """
    repo = tmp_path / "engine"
    git("init", "-b", "main", str(repo), cwd=tmp_path)
    git("config", "user.email", "t@example.com", cwd=repo)
    git("config", "user.name", "t", cwd=repo)
    (repo / "docs" / "archive" / "backlog").mkdir(parents=True)
    live = repo / LIVE
    archive = repo / ARCHIVE

    def commit(message: str, when: str) -> None:
        git("add", "-A", cwd=repo)
        env_date = f"{when}T12:00:00"
        subprocess.run(
            ["git", "commit", "-m", message],
            cwd=str(repo),
            check=True,
            capture_output=True,
            text=True,
            env={
                **dict(__import__("os").environ),
                "GIT_AUTHOR_DATE": env_date,
                "GIT_COMMITTER_DATE": env_date,
            },
        )

    live.write_text(item_block(10, "\U0001f522") + item_block(20, "\U0001f522"), encoding="utf-8")
    archive.write_text("", encoding="utf-8")
    commit("both open", "2026-01-01")

    # #10 is flipped IN PLACE and stays live.
    live.write_text(item_block(10, "✅") + item_block(20, "\U0001f522"), encoding="utf-8")
    commit("flip 10 in place", "2026-02-01")

    # #20 MOVES to the archive, closed. A live-only walk sees it vanish and calls it absent.
    live.write_text(item_block(10, "✅"), encoding="utf-8")
    archive.write_text(item_block(20, "✅"), encoding="utf-8")
    commit("archive 20", "2026-03-01")
    return repo


# --------------------------------------------------------------------- reading the pairs


def test_only_the_literal_BACKLOG_form_is_resolved() -> None:
    """A bare ``#N`` also spells a PR number, and the namespaces are indistinguishable by shape.

    Resolving one would produce a cross-reference that reads as a working link forever.
    """
    text = (
        '[[cell]]\nlast_verified = "2026-05-05"\nresidual = "closes BACKLOG #77, see also #156"\n'
    )
    pairs, ambiguous = read_pairs(text)
    assert pairs == [Pair(item=77, last_verified="2026-05-05")]
    assert ambiguous == 1


def test_a_pair_is_scoped_to_its_own_cell() -> None:
    """An item named in one cell must not inherit another cell's date -- that would fabricate exactly
    the linkage this check exists to make reliable."""
    text = (
        '[[cell]]\nlast_verified = "2026-01-01"\nresidual = "BACKLOG #1"\n'
        '[[cell]]\nlast_verified = "2026-09-09"\nresidual = "BACKLOG #2"\n'
    )
    pairs, _ = read_pairs(text)
    assert sorted((p.item, p.last_verified) for p in pairs) == [
        (1, "2026-01-01"),
        (2, "2026-09-09"),
    ]


def test_an_empty_scorecard_returns_nothing_rather_than_raising() -> None:
    """``strict=True`` on the span zip caught this loudly: with no cells the end offset still made a
    second sequence, so the tool crashed. A crash is better than a silent empty, but neither is the
    right answer -- the caller refuses on the empty result instead."""
    assert read_pairs("") == ([], 0)


# --------------------------------------------------------------------- the comparison itself


def test_equal_dates_are_not_a_hit() -> None:
    """A re-score and a flip landing the same day is the IN-SYNC case. Treating it as a hit would fire
    on every correctly handled item, which is how a screen gets switched off."""
    flags, _ = evaluate([Pair(1, "2026-05-05")], {1: "2026-05-05"})
    assert flags == []


def test_a_rescore_after_the_flip_is_a_hit() -> None:
    flags, _ = evaluate([Pair(1, "2026-05-06")], {1: "2026-05-05"})
    assert flags == [Flag(1, "2026-05-06", "2026-05-05")]


def test_an_item_with_no_banner_history_is_reported_not_dropped() -> None:
    """Dropping it would shrink the denominator invisibly, which is how a coverage figure stops
    meaning what it says."""
    flags, unknown = evaluate([Pair(999, "2026-05-06")], {})
    assert flags == []
    assert unknown == [999]


# --------------------------------------------------------------------- the ledger walk


def test_the_archive_is_walked_so_a_CLOSED_item_is_not_reported_absent(ledger: Path) -> None:
    """The defect that reading one file produced, pinned.

    #20 was flipped and moved. A live-only walk records its last touch as the day it VANISHED from the
    live ledger, which is older than the flip -- so a later re-score reads as a missing flip when the
    flip is exactly what happened.
    """
    live_only = banner_last_touched(ledger, [LIVE], None).touched
    both = banner_last_touched(ledger, [LIVE, ARCHIVE], None).touched

    assert live_only[20] == "2026-01-01"
    assert both[20] == "2026-03-01"

    # And the consequence, stated as the verdict rather than as the date: a re-score between the two
    # is a false hit on the live-only walk and correctly silent once the archive is read.
    assert evaluate([Pair(20, "2026-02-15")], live_only)[0] != []
    assert evaluate([Pair(20, "2026-02-15")], both)[0] == []


def test_an_in_place_flip_is_dated_at_the_flip(ledger: Path) -> None:
    """The control for the row above: #10 never moved, so both walks must agree about it. Without this
    the archive fix could have shifted every date and still passed."""
    live_only = banner_last_touched(ledger, [LIVE], None).touched
    both = banner_last_touched(ledger, [LIVE, ARCHIVE], None).touched
    assert live_only[10] == both[10] == "2026-02-01"


# --------------------------------------------------------------------- refusals


def test_limit_suppresses_the_flag_list(ledger: Path, tmp_path: Path, capsys) -> None:
    """A truncated walk FLOORS every date at the window boundary, so every later re-score reports as a
    missing flip. Measured on the real record with a 40-revision window: 16 hits, all at the floor.
    The option stays because it is useful for a fast smoke run, but it may not print a verdict.
    """
    card = tmp_path / "card.toml"
    card.write_text(
        '[[cell]]\nlast_verified = "2026-12-01"\nresidual = "BACKLOG #10"\n', encoding="utf-8"
    )
    assert main(["--scorecard", str(card), "--root", str(ledger), "--limit", "1"]) == 0
    out = capsys.readouterr().out
    assert "SUPPRESSED" in out
    assert "RE-SCORED AFTER" not in out


def test_a_scorecard_with_no_pairs_is_refused_not_reported_clean(
    ledger: Path, tmp_path: Path
) -> None:
    """An empty result here is indistinguishable from a scorecard the tool could not read, and
    reporting it as 'no missing flips' is the most reassuring possible wrong answer."""
    card = tmp_path / "empty.toml"
    card.write_text("", encoding="utf-8")
    assert main(["--scorecard", str(card), "--root", str(ledger)]) == 3


def test_a_missing_scorecard_is_refused(ledger: Path, tmp_path: Path) -> None:
    assert main(["--scorecard", str(tmp_path / "nope.toml"), "--root", str(ledger)]) == 2


def test_a_root_that_is_not_a_checkout_is_refused(tmp_path: Path) -> None:
    card = tmp_path / "card.toml"
    card.write_text('[[cell]]\nlast_verified = "2026-01-01"\n', encoding="utf-8")
    assert main(["--scorecard", str(card), "--root", str(tmp_path)]) == 2


# ------------------------------------------------- the instrument reporting its own failed read
#
# EVERY ROW BELOW PINS A GUARD THAT DOES NOT EXIST YET, AND EACH PINS A DIFFERENT ONE. The shared
# defect is an all-clear printed over a read that never happened -- the most reassuring possible
# wrong answer, and the one this file's own docstring says both original defects wore.


def test_a_root_whose_HEAD_cannot_be_resolved_is_refused_not_stamped_HEAD(
    tmp_path: Path, capsys
) -> None:
    """``git rev-parse HEAD`` on a commitless repo exits 128 AND ECHOES THE LITERAL ``HEAD`` ON
    STDOUT, so the header renders ``engine=HEAD``.

    That is worse than an empty value and it is the whole point: ``engine=`` invites a second look,
    ``engine=HEAD`` reads as a deliberate measurement and passes review forever. This file declares
    the ref pair part of the measurement, so an unresolvable HEAD is a refusal, not a footnote.
    """
    repo = tmp_path / "commitless"
    git("init", "-b", "main", str(repo), cwd=tmp_path)
    card = tmp_path / "card.toml"
    card.write_text(
        '[[cell]]\nlast_verified = "2026-01-01"\nresidual = "BACKLOG #10"\n', encoding="utf-8"
    )
    assert main(["--scorecard", str(card), "--root", str(repo)]) == 3
    captured = capsys.readouterr()
    # NOT a bare ``"HEAD" in err``. That assertion passed with this guard REMOVED, because pytest
    # names ``tmp_path`` after the test and this test's name contains HEAD -- so the directory path
    # echoed in a DIFFERENT refusal satisfied it. Caught by mutation, not by re-reading. The phrase
    # below is emitted by the rev-parse guard and by nothing else in either tool.
    assert "cannot resolve HEAD" in captured.err
    assert "engine=HEAD" not in captured.out


def test_a_failed_ledger_walk_raises_rather_than_reading_as_no_history(tmp_path: Path) -> None:
    """A ``git log`` that fails yields no lines, and no lines is indistinguishable from a ledger
    whose banners were never touched.

    Pinned at the unit rather than through ``main`` deliberately: the walk is also the half that can
    fail on ONE of the two ledgers while the other succeeds, and a partial walk is non-empty, so the
    emptiness guard below cannot see it.
    """
    repo = tmp_path / "commitless"
    git("init", "-b", "main", str(repo), cwd=tmp_path)
    with pytest.raises(RuntimeError):
        banner_last_touched(repo, [LIVE], None)


def test_a_walk_that_found_no_banner_history_is_refused_not_reported_clean(
    tmp_path: Path, capsys
) -> None:
    """A ledger path absent from a real history makes ``git log`` exit ZERO with no output.

    So the walk succeeds, returns nothing, every pair falls to ``unknown``, and the tool prints the
    all-clear. The correct guard was already written thirty lines earlier for the OTHER input --
    ``if not pairs`` -- and the same reasoning transfers verbatim.
    """
    repo = tmp_path / "engine"
    git("init", "-b", "main", str(repo), cwd=tmp_path)
    git("config", "user.email", "t@example.com", cwd=repo)
    git("config", "user.name", "t", cwd=repo)
    (repo / "unrelated.txt").write_text("x\n", encoding="utf-8")
    git("add", "-A", cwd=repo)
    git("commit", "-m", "one", cwd=repo)

    card = tmp_path / "card.toml"
    card.write_text(
        '[[cell]]\nlast_verified = "2026-01-01"\nresidual = "BACKLOG #10"\n', encoding="utf-8"
    )
    assert main(["--scorecard", str(card), "--root", str(repo)]) == 3
    captured = capsys.readouterr()
    assert "REFUSING" in captured.err
    assert "no item was re-scored" not in captured.out


# ----------------------------------------------- round two: the guards covered entrances, not the class
#
# EVERY ROW HERE PINS SOMETHING ROUND ONE CLAIMED AND DID NOT DELIVER. Round one's commit message said
# "four guards, each with a test that fails when only that guard is removed". THREE WERE. Guard 2 was
# executed by no test at all -- deleting it outright left 31 of 31 green. Found by an adversarial pass
# and confirmed by hand, not by re-reading.


def test_a_walk_that_fails_on_a_repo_WITH_commits_is_refused_at_the_call_site(
    ledger: Path, tmp_path: Path, capsys
) -> None:
    """Guard 2, the call-site catch, reached through main() for the first time.

    Round one made it unreachable by construction: the only input that made the walk raise was a
    commitless repo, and the rev-parse guard returns 3 before the walk ever runs. So the guard that
    turns a raised walk into a refusal was pinned by nothing, and deleting it changed no test.

    A ledger path git refuses to walk -- one outside the repository -- fails the walk while HEAD still
    resolves, which is the only way through to this guard.
    """
    card = tmp_path / "card.toml"
    card.write_text(
        '[[cell]]\nlast_verified = "2026-01-01"\nresidual = "BACKLOG #10"\n', encoding="utf-8"
    )
    rc = main(["--scorecard", str(card), "--root", str(ledger), "--backlog", "../outside.md"])
    assert rc == 3
    captured = capsys.readouterr()
    # A phrase only guard 1's raise produces, arriving through guard 2's catch.
    assert "git log failed over" in captured.err
    assert "no item was re-scored" not in captured.out


def test_a_PARTIAL_walk_is_refused_even_though_the_result_is_not_empty(
    ledger: Path, tmp_path: Path, capsys
) -> None:
    """Guard 1's whole stated reason to exist, which round one asserted in capitals and never tested.

    The guard's comment argues the emptiness guard is not a substitute because "a walk that fails over
    ONE of the two ledgers while the other succeeds leaves a PARTIAL result, which is non-empty and
    reads as complete". That sentence describes exactly this test, and round one's only guard-1 test
    used a single ledger on a commitless repo -- so the failure always happened while touched was
    still empty, and `if walk.returncode != 0 and not touched` would have kept every test green while
    making the guard inert for the case it was written for.

    Here the first ledger walks fine and fills touched; the second fails. The refusal must still fire.
    """
    card = tmp_path / "card.toml"
    card.write_text(
        '[[cell]]\nlast_verified = "2026-01-01"\nresidual = "BACKLOG #10"\n', encoding="utf-8"
    )
    rc = main(
        [
            "--scorecard",
            str(card),
            "--root",
            str(ledger),
            # --backlog is action="append", so the two ledgers are two flags, not one list.
            "--backlog",
            LIVE,
            "--backlog",
            "../outside.md",
        ]
    )
    assert rc == 3
    captured = capsys.readouterr()
    assert "git log failed over" in captured.err
    assert "no item was re-scored" not in captured.out


def test_a_truncated_history_is_refused_rather_than_answered_from_the_visible_window(
    shallow_ledger: Path, tmp_path: Path, capsys
) -> None:
    """A shallow clone makes git log exit ZERO over a truncated window, so no guard round one added
    can see it -- the walk does not raise and touched is full.

    The distortion runs in the under-fire direction: every banner date floors at the clone boundary,
    which makes the last touch look LATER than it was, and evaluate() only fires when the re-score is
    strictly later. So real hits are SUPPRESSED and the tool prints the all-clear.

    The tool already refuses to print a verdict under --limit for exactly this reason. The same
    truncation arriving through a shallow clone got a full unsuppressed verdict.
    """
    card = tmp_path / "card.toml"
    card.write_text(
        '[[cell]]\nlast_verified = "2026-12-01"\nresidual = "BACKLOG #10"\n', encoding="utf-8"
    )
    rc = main(["--scorecard", str(card), "--root", str(shallow_ledger)])
    assert rc == 3
    captured = capsys.readouterr()
    assert "TRUNCATED" in captured.err
    assert "RE-SCORED AFTER" not in captured.out


def test_a_shallow_clone_whose_ledger_history_is_COMPLETE_is_answered_normally(
    ledger: Path, tmp_path: Path, capsys
) -> None:
    """THE CONTROL THAT KEEPS THE ROW ABOVE FROM BEING A FALSE REFUSAL, and it is not hypothetical:
    THIS REPOSITORY IS ITSELF A SHALLOW CLONE.

    Measured 2026-08-29: `git rev-parse --is-shallow-repository` returns true in the primary and in
    every worktree, over 856 commits with 3 graft points. But docs/BACKLOG.md was CREATED after the
    graft boundary, so the oldest revision touching it HAS a parent and the walk sees the file's whole
    history. Refusing on shallowness alone would therefore refuse every real run on this machine.

    So the discriminator is not "is the repo shallow" but "did this path's walk reach past its own
    beginning": a walk is truncated only when its oldest revision has no parent AND the repo is
    shallow. Here the ledger fixture is a normal clone, so nothing is truncated and nothing refuses.
    """
    card = tmp_path / "card.toml"
    card.write_text(
        '[[cell]]\nlast_verified = "2026-12-01"\nresidual = "BACKLOG #10"\n', encoding="utf-8"
    )
    assert main(["--scorecard", str(card), "--root", str(ledger)]) == 0
    assert "TRUNCATED" not in capsys.readouterr().err


def test_revisions_the_walk_could_not_read_are_counted_and_reported(
    ledger: Path, tmp_path: Path, capsys
) -> None:
    """`git show` inside the walk still swallows its returncode with a bare `continue`.

    Round one guarded `git log` and `git rev-parse` and left the third git call in the same loop
    unreported, which is the same partial-walk hazard the new comment claims to have closed. Neither
    skip updates `previous` either, so the next readable revision is diffed against a stale
    fingerprint and the change is attributed to a LATER commit -- suppressing the flag.

    Refusing here would be wrong: a revision that DELETED the path makes `git show` fail legitimately.
    So the count is reported instead, and a zero is stated rather than left to be assumed.
    """
    card = tmp_path / "card.toml"
    card.write_text(
        '[[cell]]\nlast_verified = "2026-01-01"\nresidual = "BACKLOG #10"\n', encoding="utf-8"
    )
    assert main(["--scorecard", str(card), "--root", str(ledger)]) == 0
    assert "revisions the walk could not read" in capsys.readouterr().out


@pytest.fixture
def shallow_with_a_true_root(shallow_ledger: Path) -> Path:
    """A SHALLOW repo containing a parentless commit that is NOT a graft boundary.

    That combination is not exotic -- it is this repository. Measured 2026-08-29: the engine is
    shallow with three graft points, and the one parentless commit reachable from HEAD is
    ``5fa6db9f4``, a deliberate 2026-07-06 history reset that appears in NONE of them. Every file
    present in that commit has a parentless oldest revision and a COMPLETE history.

    Built here by adding an orphan-rooted ledger inside an already-shallow clone.
    """
    git("checkout", "--orphan", "orphaned", cwd=shallow_ledger)
    git("rm", "-rf", "--cached", ".", cwd=shallow_ledger)
    (shallow_ledger / "docs").mkdir(parents=True, exist_ok=True)
    (shallow_ledger / LIVE).write_text(item_block(10, "\U0001f6a7"), encoding="utf-8")
    git("add", LIVE, cwd=shallow_ledger)
    git("commit", "-m", "an orphan root, parentless and not a graft", cwd=shallow_ledger)
    return shallow_ledger


def test_a_parentless_revision_that_is_NOT_a_graft_boundary_is_not_a_truncation(
    shallow_with_a_true_root: Path, tmp_path: Path, capsys
) -> None:
    """THE FALSE REFUSAL MY OWN TRUNCATION GUARD SHIPPED, and it fires on this very repository.

    The first version asked "is the repo shallow AND does the oldest revision lack a parent". A TRUE
    ROOT also lacks a parent, so any path whose history reaches the beginning of the project was
    reported as truncated. Measured against the real engine checkout: every file present in the
    2026-07-06 history-reset root -- .gitattributes, .gitignore, .github and the rest -- refused, on
    a history that is complete, with remediation advice (``git fetch --unshallow``) that cannot help
    because those commits are not on the remote either.

    The right question is not "does it have a parent" but "is it one of the graft points git itself
    recorded", which ``.git/shallow`` answers exactly.
    """
    card = tmp_path / "card.toml"
    card.write_text(
        '[[cell]]\nlast_verified = "2026-01-01"\nresidual = "BACKLOG #10"\n', encoding="utf-8"
    )
    rc = main(["--scorecard", str(card), "--root", str(shallow_with_a_true_root)])
    assert rc == 0
    assert "TRUNCATED" not in capsys.readouterr().err

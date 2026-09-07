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

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "asvs"))

from rescore_handoff_check import (  # noqa: E402
    GRADE_MOVED,
    GRADE_MOVED_DOWN,
    GRADE_UNCHANGED,
    GRADE_UNKNOWN,
    Flag,
    Pair,
    banner_last_touched,
    classify,
    evaluate,
    grade_history,
    main,
    read_pairs,
    split_by_boundary,
)

LIVE = "docs/BACKLOG.md"
ARCHIVE = "docs/archive/backlog/BACKLOG-CLOSED.md"


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True
    ).stdout.strip()


def commit_at(repo: Path, message: str, when: str) -> None:
    """Stage everything and commit it with a FIXED committer date.

    The date is not decoration: the graft boundary this file tests is identified BY its committer
    date, and a fixture committed at wall-clock time would put every revision on the same day and
    make the boundary comparison unfalsifiable.
    """
    git("add", "-A", cwd=repo)
    stamp = f"{when}T12:00:00"
    subprocess.run(
        ["git", "commit", "-m", message],
        cwd=str(repo),
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_AUTHOR_DATE": stamp, "GIT_COMMITTER_DATE": stamp},
    )


def clone_shallow(source: Path, dest: Path, depth: int) -> Path:
    """Clone ``source`` to ``dest`` truncated to ``depth`` revisions.

    Cloned over file:// with --no-local, because a local clone hardlinks the object store and is not
    actually shallow.
    """
    git("clone", "--depth", str(depth), "--no-local", source.as_uri(), str(dest), cwd=dest.parent)
    # A CLONE INHERITS NO IDENTITY. user.email and user.name are per-repo, live in .git/config, and
    # clone copies none of them -- so a fixture that COMMITS into this clone succeeds on a developer
    # box off the GLOBAL identity and exits 128 on a runner that has none. That is exactly how this
    # reached CI: green locally, `git commit` 128 there. The two fixtures that `git init` set identity
    # explicitly; this one had nothing to inherit and nobody noticed, because the machine that ran it
    # supplied the missing value invisibly.
    git("config", "user.email", "t@example.com", cwd=dest)
    git("config", "user.name", "t", cwd=dest)
    return dest


@pytest.fixture
def shallow_ledger(ledger: Path, tmp_path: Path) -> Path:
    """A depth-1 clone of the ledger fixture, so the walk's oldest revision IS the graft boundary.

    One visible revision means every item's last touch floors to that single date, so a DECIDABLE
    pair here is necessarily a hit. The fixture below exists because the clean-verdict case needs a
    window wide enough for a real touch to sit above the boundary.
    """
    return clone_shallow(ledger, tmp_path / "shallow", 1)


@pytest.fixture
def shallow_ledger_two_deep(ledger: Path, tmp_path: Path) -> Path:
    """A depth-2 clone, where the graft is dated 2026-02-01 and a real touch lands after it.

    #10's banner is fingerprinted at the graft and never moves again, so it floors to 2026-02-01.
    #20 moves to the archive at 2026-03-01, which the window can see, so its touch is TRUE. That
    split is what makes a decidable-and-clean pair possible at all.
    """
    return clone_shallow(ledger, tmp_path / "shallow2", 2)


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

    live.write_text(item_block(10, "\U0001f522") + item_block(20, "\U0001f522"), encoding="utf-8")
    archive.write_text("", encoding="utf-8")
    commit_at(repo, "both open", "2026-01-01")

    # #10 is flipped IN PLACE and stays live.
    live.write_text(item_block(10, "✅") + item_block(20, "\U0001f522"), encoding="utf-8")
    commit_at(repo, "flip 10 in place", "2026-02-01")

    # #20 MOVES to the archive, closed. A live-only walk sees it vanish and calls it absent.
    live.write_text(item_block(10, "✅"), encoding="utf-8")
    archive.write_text(item_block(20, "✅"), encoding="utf-8")
    commit_at(repo, "archive 20", "2026-03-01")
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

    THE DATE HERE IS LOAD-BEARING AND WAS NOT, ROUND TWO. The clone's only visible revision is dated
    2026-03-01, so a re-score on 2026-02-01 sits BELOW the boundary -- squarely inside the window the
    floor can suppress -- and the refusal must still fire. Round two's version of this row used
    2026-12-01, which the floor provably cannot reach, so it pinned the refusal on an input that did
    not need refusing. That is what made the tool refuse the only environment it ships into.
    """
    card = tmp_path / "card.toml"
    card.write_text(
        '[[cell]]\nlast_verified = "2026-02-01"\nresidual = "BACKLOG #10"\n', encoding="utf-8"
    )
    rc = main(["--scorecard", str(card), "--root", str(shallow_ledger)])
    assert rc == 3
    captured = capsys.readouterr()
    assert "TRUNCATED" in captured.err
    assert "RE-SCORED AFTER" not in captured.out
    assert "no item was re-scored" not in captured.out


def test_a_truncation_the_floor_cannot_reach_is_answered_rather_than_refused(
    shallow_ledger: Path, tmp_path: Path, capsys
) -> None:
    """THE OTHER ARM, AND THE DEFECT THIS PAIR EXISTS TO FIX. Truncation alone is not an unanswerable
    run.

    The floor sets an affected item's last touch to the boundary date, and the floor is always later
    than or equal to the truth. So a re-score STRICTLY AFTER the boundary is decided identically
    either way -- ``re-score > floored >= true`` -- and refusing it discards a sound answer.

    Here #10's banner truly last moved 2026-02-01 and floors to 2026-03-01. A re-score on 2026-12-01
    clears both, so the hit is real on the visible history and on the hidden history alike.

    Without the arm above this test would pass on a tool that reported "proceed" for every input,
    which is why neither is allowed to stand alone.
    """
    card = tmp_path / "card.toml"
    card.write_text(
        '[[cell]]\nlast_verified = "2026-12-01"\nresidual = "BACKLOG #10"\n', encoding="utf-8"
    )
    rc = main(["--scorecard", str(card), "--root", str(shallow_ledger)])
    assert rc == 0
    captured = capsys.readouterr()
    assert "REFUSING" not in captured.err
    assert "RE-SCORED AFTER THE BANNER WAS LAST TOUCHED: 1" in captured.out
    # The branch is NAMED, so a reader can tell a bounded run from an unbounded one.
    assert "truncation branch: BOUNDED at 2026-03-01" in captured.out
    # AND THE TOUCH DATE IS MARKED AS A FLOOR. #10's banner truly moved on 2026-02-01, which this
    # window cannot see, so printing a bare "2026-03-01" would hand the reader a flip date that
    # never happened. The flag is sound; the date under it is a bound, and it has to say so.
    assert "at or before 2026-03-01 (FLOORED at the graft, not measured)" in captured.out


def test_a_measured_touch_date_is_printed_bare_even_on_a_truncated_run(
    shallow_ledger_two_deep: Path, tmp_path: Path, capsys
) -> None:
    """THE CONTROL FOR THE FLOOR MARKER, without which "mark everything as floored" would pass.

    On this two-deep window #20's move to the archive is VISIBLE, so its 2026-03-01 touch is a real
    measurement sitting above the 2026-02-01 boundary. It must print as a date, not as a bound --
    otherwise the marker stops distinguishing anything and a reader learns to ignore it.
    """
    card = tmp_path / "card.toml"
    card.write_text(
        '[[cell]]\nlast_verified = "2026-04-01"\nresidual = "BACKLOG #20"\n', encoding="utf-8"
    )
    assert main(["--scorecard", str(card), "--root", str(shallow_ledger_two_deep)]) == 0
    out = capsys.readouterr().out
    assert "BACKLOG #20: re-scored 2026-04-01, banner last touched 2026-03-01" in out
    assert "FLOORED" not in out


def test_a_mixed_run_answers_what_it_can_and_names_what_it_cannot(
    shallow_ledger: Path, tmp_path: Path, capsys
) -> None:
    """The verdict is per PAIR, so a run holding both kinds must not collapse to either one.

    #10's re-score clears the boundary and is decided; #20's does not and is undecidable. The
    dangerous output is an all-clear that quietly covers #20, which is the same
    reassuring-answer-to-an-unasked-question the two REFUSING guards above exist to prevent, arriving
    one step later. So the clean line has to state its own scope.
    """
    card = tmp_path / "card.toml"
    card.write_text(
        '[[cell]]\nlast_verified = "2026-12-01"\nresidual = "BACKLOG #10"\n'
        '[[cell]]\nlast_verified = "2026-01-15"\nresidual = "BACKLOG #20"\n',
        encoding="utf-8",
    )
    rc = main(["--scorecard", str(card), "--root", str(shallow_ledger)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "1 pairs are decided exactly and 1 are UNDECIDABLE" in out
    assert "items NOT covered by the verdict below" in out
    assert "[20]" in out
    # #10 still gets its real verdict rather than being dragged down by its neighbour.
    assert "BACKLOG #10" in out


def test_a_clean_verdict_over_undecidable_pairs_states_its_own_scope(
    shallow_ledger_two_deep: Path, tmp_path: Path, capsys
) -> None:
    """The all-clear path of the row above, which is the one a reader actually acts on.

    An unqualified "no item was re-scored after its banner was last touched" over a run that could
    not decide some of its pairs is a false completeness claim, and this file's own docstring says
    over-firing is tolerable only because it is BOUNDED AND STATED.

    #20's re-score on 2026-03-01 clears the 2026-02-01 boundary AND equals its true banner touch, so
    it is decidable and in sync -- a clean decidable pair, which a depth-1 window cannot produce.
    #10's re-score sits below the boundary and stays undecidable.
    """
    card = tmp_path / "card.toml"
    card.write_text(
        '[[cell]]\nlast_verified = "2026-03-01"\nresidual = "BACKLOG #20"\n'
        '[[cell]]\nlast_verified = "2026-01-15"\nresidual = "BACKLOG #10"\n',
        encoding="utf-8",
    )
    assert main(["--scorecard", str(card), "--root", str(shallow_ledger_two_deep)]) == 0
    out = capsys.readouterr().out
    assert "no DECIDABLE item was re-scored" in out
    assert "are NOT covered by this line" in out
    # The unqualified sentence must not appear, because it would claim the undecidable pairs too.
    assert "no item was re-scored after its banner was last touched" not in out


def test_a_shallow_clone_whose_ledger_history_is_COMPLETE_is_answered_normally(
    ledger: Path, tmp_path: Path, capsys
) -> None:
    """THE CONTROL THAT KEEPS THE ROW ABOVE FROM BEING A FALSE REFUSAL, and it is not hypothetical:
    THIS REPOSITORY IS ITSELF A SHALLOW CLONE.

    Measured 2026-08-29: `git rev-parse --is-shallow-repository` returns true in the primary and in
    every worktree, over 856 commits with 3 graft points.

    ***THE SECOND HALF OF THAT MEASUREMENT WAS WRONG, AND IT IS CORRECTED HERE RATHER THAN QUIETLY
    DROPPED, BECAUSE BELIEVING IT COST A DIAGNOSIS.*** This docstring said docs/BACKLOG.md was
    CREATED after the graft boundary, so its oldest revision had a parent and the walk saw the whole
    file. **Re-measured 2026-09-03: it does not.** The clone now holds 719 commits over 20 graft
    points, the only parentless commit reachable from HEAD IS a graft (`ca8a7488`, 2026-08-04), and
    docs/BACKLOG.md exists in it -- so the ledger's own history really is cut, and the refusal that
    followed was correct rather than false. What was wrong was treating it as fatal to the whole run.

    So the discriminator is not "is the repo shallow" but "did this path's walk begin at a graft
    point git itself recorded". Here the ledger fixture is a normal clone, so nothing is truncated
    and nothing refuses.
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

    That combination WAS this repository. Measured 2026-08-29: the engine was shallow with three
    graft points, and the one parentless commit reachable from HEAD was ``5fa6db9f4``, a deliberate
    2026-07-06 history reset appearing in NONE of them, so every file present in it had a parentless
    oldest revision and a COMPLETE history.

    **Re-measured 2026-09-03: that commit is no longer reachable at all.** A re-fetch left 719
    commits over 20 graft points, and the only parentless commit reachable from HEAD is now itself a
    graft. **The fixture stays, and it stays SYNTHETIC on purpose** -- the distinction it pins is
    real whether or not today's clone happens to exhibit it, and a row that silently stopped
    exercising anything the day a fetch changed shape would be worse than one built by hand.

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


# ------------------------------------------- round three: a graft that predates the ledger itself
#
# THE TOOL REFUSED THE ONLY ENVIRONMENT IT SHIPS INTO. Driving it against the real record exited 3
# with the truncation refusal, so the date comparison BACKLOG #1328 calls "the open work" had never
# produced an answer at all. The engine checkout is shallow, its whole visible history begins at a
# graft, and both ledger files exist at that boundary -- a genuine truncation, correctly detected and
# wrongly treated as fatal to the entire run.


@pytest.fixture
def shallow_graft_older_than_the_ledger(tmp_path: Path) -> Path:
    """A SHALLOW repo whose graft boundary is OLDER than the ledger's own first revision.

    Four commits, of which the ledger appears only in the last two, cloned to depth 3. The graft
    therefore lands on a commit with no ledger in it, so nothing about the ledger's banner history is
    hidden and the walk saw every revision of it there is.

    This arm holds BY CONSTRUCTION rather than by a separate test in the tool: ``git log -- <path>``
    lists only revisions where the path CHANGED, so a graft older than the path's creation is never
    the oldest line. Pinning it matters anyway -- it is the half a future "just refuse whenever the
    repo is shallow" simplification would silently break, and this repository is always shallow.
    """
    repo = tmp_path / "late-ledger"
    git("init", "-b", "main", str(repo), cwd=tmp_path)
    git("config", "user.email", "t@example.com", cwd=repo)
    git("config", "user.name", "t", cwd=repo)

    (repo / "unrelated.txt").write_text("one\n", encoding="utf-8")
    commit_at(repo, "before the ledger existed", "2026-01-01")
    (repo / "unrelated.txt").write_text("two\n", encoding="utf-8")
    commit_at(repo, "still before the ledger existed", "2026-01-15")

    (repo / "docs" / "archive" / "backlog").mkdir(parents=True)
    (repo / LIVE).write_text(item_block(10, "\U0001f522"), encoding="utf-8")
    (repo / ARCHIVE).write_text("", encoding="utf-8")
    commit_at(repo, "the ledger is created here", "2026-02-01")

    (repo / LIVE).write_text(item_block(10, "✅"), encoding="utf-8")
    commit_at(repo, "flip 10", "2026-03-01")

    # Depth 3 leaves the graft on "still before the ledger existed", which holds no ledger at all.
    return clone_shallow(repo, tmp_path / "shallow-late", 3)


def test_a_graft_older_than_the_ledgers_first_revision_is_not_a_truncation(
    shallow_graft_older_than_the_ledger: Path, tmp_path: Path, capsys
) -> None:
    """The tool must PROCEED here, and the re-score date is chosen so that a wrong answer cannot hide.

    2026-01-10 sits BELOW the graft commit's own date, so a tool that wrongly called this walk
    truncated would find the single pair undecidable, refuse the whole run, and fail this row. A late
    date would have passed either way and proved nothing.
    """
    card = tmp_path / "card.toml"
    card.write_text(
        '[[cell]]\nlast_verified = "2026-01-10"\nresidual = "BACKLOG #10"\n', encoding="utf-8"
    )
    rc = main(["--scorecard", str(card), "--root", str(shallow_graft_older_than_the_ledger)])
    assert rc == 0
    captured = capsys.readouterr()
    assert "REFUSING" not in captured.err
    assert "truncation branch: NONE" in captured.out
    # The graft IS present and IS read -- the walk simply did not begin at it. Asserting the count
    # keeps this from passing on a repo that turned out not to be shallow at all.
    assert "graft points git recorded in .git/shallow: 1" in captured.out
    assert "not at a graft" in captured.out


# ------------------------------------------------------------------ the per-pair boundary decision


def test_a_pair_after_the_boundary_is_decidable_and_one_at_or_before_it_is_not() -> None:
    """The inequality the whole fix rests on, pinned at the unit.

    A floored date is later than or equal to the truth, so ``re-score > floored`` implies
    ``re-score > true`` and the verdict is the same on both. At or before the boundary that argument
    is unavailable, and the answer is unknown rather than clean.
    """
    pairs = [Pair(1, "2026-05-06"), Pair(2, "2026-05-05"), Pair(3, "2026-05-04")]
    decidable, undecidable = split_by_boundary(pairs, "2026-05-05", {})
    assert [p.item for p in decidable] == [1]
    assert [p.item for p in undecidable] == [2, 3]


def test_with_no_boundary_every_pair_is_decidable() -> None:
    """The unbounded branch. An empty boundary means no walk began at a graft, so nothing is floored
    and holding anything back would be a refusal with no cause."""
    pairs = [Pair(1, "2026-05-06"), Pair(2, "2026-01-01")]
    decidable, undecidable = split_by_boundary(pairs, "", {})
    assert decidable == pairs
    assert undecidable == []


def test_the_run_reports_what_it_actually_scanned(ledger: Path, tmp_path: Path, capsys) -> None:
    """An empty scan and a clean scan must not render alike, and this tool already shipped one
    failure of exactly that shape.

    A locale-decoded blob destroyed every banner glyph, so the walk found no change anywhere and
    reported it in perfectly plausible output. A per-path revision count is the cheapest thing that
    would have caught it, and a stated zero for the graft count is checkable where an absent line is
    not.
    """
    card = tmp_path / "card.toml"
    card.write_text(
        '[[cell]]\nlast_verified = "2026-01-01"\nresidual = "BACKLOG #10"\n', encoding="utf-8"
    )
    assert main(["--scorecard", str(card), "--root", str(ledger)]) == 0
    out = capsys.readouterr().out
    assert "graft points git recorded in .git/shallow: 0" in out
    assert f"walked {LIVE}: 3 of 3 revisions" in out
    assert f"walked {ARCHIVE}: 2 of 2 revisions" in out
    assert "truncation branch: NONE" in out


# ------------------------------------------- a measured touch is decidable whatever the graft says


def test_an_item_whose_touch_was_MEASURED_is_decidable_below_the_boundary() -> None:
    """The half of the inequality the first fix read only one way.

    Hidden revisions all sit at or before the boundary, so a true last touch is
    ``max(visible, something <= boundary)``. When the visible touch already clears the boundary, that
    max IS the visible date -- the graft cannot raise it. Item 2's own re-score date sits below the
    boundary, and it is still decided exactly, because its BANNER date was measured rather than
    floored.
    """
    pairs = [Pair(1, "2026-05-04"), Pair(2, "2026-05-04")]
    touched = {1: "2026-05-05", 2: "2026-05-09"}
    decidable, undecidable = split_by_boundary(pairs, "2026-05-05", touched)
    assert [p.item for p in decidable] == [2]
    assert [p.item for p in undecidable] == [1]


def test_the_per_item_rule_never_narrows_the_old_one() -> None:
    """A widening must not turn a previously decided pair undecidable. Pinned because the two rules
    are OR-ed, and an OR written as an AND would silently shrink the answer instead of growing it."""
    pairs = [Pair(1, "2026-05-06"), Pair(2, "2026-05-04")]
    old, _ = split_by_boundary(pairs, "2026-05-05", {})
    new, _ = split_by_boundary(pairs, "2026-05-05", {2: "2026-05-01"})
    assert {p.item for p in old} <= {p.item for p in new}
    assert [p.item for p in new] == [1]


def test_a_FLOORED_banner_date_cannot_produce_a_clean_GRADE_UNCHANGED(tmp_path: Path) -> None:
    """THE INEQUALITY RUNS THE OPPOSITE WAY HERE, AND REUSING IT UNEXAMINED INVERTED THE ANSWER.

    ``evaluate`` is safe against a floored banner date because a later date can only suppress a hit.
    ``classify`` asks what survives ABOVE that date, so pushing it later DELETES change points and
    turns a real move into a confident confirmation. Same history, same cell: on the true date the
    grade moved; on the floored one the walk can see nothing above it and must say so.
    """
    repo = scorecard_repo(tmp_path, [("2026-01-01", "partial"), ("2026-05-01", "pass")])
    history = grade_history(repo / "card.toml")
    true_date = Flag(10, "2026-05-01", "2026-02-01", "C1")
    assert classify(true_date, history) == GRADE_MOVED
    floored = Flag(10, "2026-05-01", "2026-08-31", "C1")
    assert classify(floored, history, "2026-08-31") == GRADE_UNKNOWN
    # A change ABOVE the floor is still a true change, so it is answered rather than withheld.
    low_floor = Flag(10, "2026-05-01", "2026-02-01", "C1")
    assert classify(low_floor, history, "2026-02-01") == GRADE_MOVED


def test_an_UNKNOWN_verdict_is_not_counted_as_a_grade_that_MOVED(
    ledger: Path, tmp_path: Path, capsys
) -> None:
    """FAILURE-TO-LOOK MUST NOT RENDER AS THE STRONGEST SIGNAL IN THE ONE LINE A READER ACTS ON.

    The first cut counted every verdict that was not UNCHANGED as "moved", so a hit whose grade
    history could not be read was summarised as a grade that moved. Here the scorecard's committed
    history carries a different cell id than the working tree, which is what an uncommitted re-score
    looks like, so the join misses and the verdict is UNKNOWN.
    """
    repo = scorecard_repo(tmp_path, [("2026-01-01", "partial")])
    card = repo / "card.toml"
    card.write_text(
        '[[cell]]\nid = "UNCOMMITTED"\nverdict = "partial"\n'
        'last_verified = "2026-05-01"\nresidual = "BACKLOG #10"\n',
        encoding="utf-8",
    )
    assert main(["--scorecard", str(card), "--root", str(ledger)]) == 0
    out = capsys.readouterr().out
    assert "0 sit on a cell whose GRADE moved after the banner" in out
    assert "1 could not be decided" in out
    assert GRADE_UNKNOWN in out
    # The steer to read the moved lines first must not appear when there are none.
    assert "READ THE 'GRADE MOVED' LINES FIRST" not in out


def test_the_ranked_verdicts_cannot_drift_from_the_lines_printed(
    ledger: Path, tmp_path: Path, capsys
) -> None:
    """The summary counts and the detail lines come from one structure, so they cannot disagree.

    Keying the verdicts on the Flag dataclass collapsed two flags equal in every field into one
    entry, which would have described fewer hits than it went on to print.
    """
    repo = scorecard_repo(tmp_path, [("2026-01-01", "partial"), ("2026-05-01", "pass")])
    assert main(["--scorecard", str(repo / "card.toml"), "--root", str(ledger)]) == 0
    out = capsys.readouterr().out
    printed = [line for line in out.splitlines() if line.strip().startswith("BACKLOG #")]
    assert "RE-SCORED AFTER THE BANNER WAS LAST TOUCHED: 1" in out
    assert len(printed) == 1
    assert "1 sit on a cell whose GRADE moved after the banner" in out


# --------------------------------------------- a date move is not a re-score: the grade classifier


def scorecard_repo(tmp_path: Path, revisions: list[tuple[str, str]]) -> Path:
    """A scorecard repo whose single cell takes each ``(date, verdict)`` in turn."""
    repo = tmp_path / "vault"
    repo.mkdir()
    git("init", "-b", "main", str(repo), cwd=tmp_path)
    git("config", "user.email", "t@example.com", cwd=repo)
    git("config", "user.name", "t", cwd=repo)
    card = repo / "card.toml"
    for when, verdict in revisions:
        card.write_text(
            f'[[cell]]\nid = "C1"\nverdict = "{verdict}"\n'
            f'last_verified = "{when}"\nresidual = "BACKLOG #10"\n',
            encoding="utf-8",
        )
        commit_at(repo, f"{verdict} at {when}", when)
    return repo


def test_a_cell_only_RE_VERIFIED_after_the_banner_is_not_a_re_score(tmp_path: Path) -> None:
    """THE DEFECT THIS CLASSIFIER EXISTS FOR. ``last_verified`` bumps on a confirming re-check just as
    it does on a real re-score, so the date comparison alone fires on both.

    Measured 2026-09-04 against the vault record: 22 of 28 flagged items were this case.
    """
    repo = scorecard_repo(tmp_path, [("2026-01-01", "partial"), ("2026-05-01", "partial")])
    history = grade_history(repo / "card.toml")
    assert classify(Flag(10, "2026-05-01", "2026-03-01", "C1"), history) == GRADE_UNCHANGED


def test_a_cell_whose_grade_moved_after_the_banner_is_the_real_signal(tmp_path: Path) -> None:
    repo = scorecard_repo(tmp_path, [("2026-01-01", "partial"), ("2026-05-01", "pass")])
    history = grade_history(repo / "card.toml")
    assert classify(Flag(10, "2026-05-01", "2026-03-01", "C1"), history) == GRADE_MOVED


def test_a_grade_that_moved_DOWN_after_a_banner_is_called_out_separately(tmp_path: Path) -> None:
    """The reverting direction, which is the one #1328's amendment warns about: a CLOSED banner
    resting on a pass that a later re-score withdrew is a compensating control on a false premise
    (SDS-3.7). It must not render the same as a strengthening."""
    repo = scorecard_repo(tmp_path, [("2026-01-01", "pass"), ("2026-05-01", "partial")])
    history = grade_history(repo / "card.toml")
    assert classify(Flag(10, "2026-05-01", "2026-03-01", "C1"), history) == GRADE_MOVED_DOWN


def test_a_move_into_na_is_a_scope_change_not_a_weakening(tmp_path: Path) -> None:
    """``na`` means the requirement does not apply. Ranking it at either end of the scale would
    report every scope change as a strengthening or a weakening, which is a grade claim the record
    never made."""
    repo = scorecard_repo(tmp_path, [("2026-01-01", "pass"), ("2026-05-01", "na")])
    history = grade_history(repo / "card.toml")
    assert classify(Flag(10, "2026-05-01", "2026-03-01", "C1"), history) == GRADE_MOVED


def test_an_unreadable_grade_history_is_UNKNOWN_and_never_silently_UNCHANGED(
    tmp_path: Path,
) -> None:
    """THE WHOLE POINT OF RETURNING None. An empty history would classify every hit as UNCHANGED --
    the most reassuring possible answer, produced by having failed to look. That is the same shape as
    the two refusals this tool already carries."""
    loose = tmp_path / "loose"
    loose.mkdir()
    card = loose / "card.toml"
    card.write_text('[[cell]]\nid = "C1"\nlast_verified = "2026-05-01"\n', encoding="utf-8")
    assert grade_history(card) is None
    assert classify(Flag(10, "2026-05-01", "2026-03-01", "C1"), None) == GRADE_UNKNOWN


def test_a_cell_absent_from_the_grade_history_is_UNKNOWN_rather_than_confirmed(
    tmp_path: Path,
) -> None:
    """A cell the history never saw is not a cell whose grade held steady."""
    repo = scorecard_repo(tmp_path, [("2026-01-01", "partial")])
    history = grade_history(repo / "card.toml")
    assert classify(Flag(10, "2026-05-01", "2026-03-01", "MISSING"), history) == GRADE_UNKNOWN


def test_read_pairs_carries_the_cell_so_the_grade_can_be_joined() -> None:
    """The join key. It is READ but never PRINTED -- cell ids stay vaulted."""
    pairs, _ = read_pairs(
        '[[cell]]\nid = "C1"\nlast_verified = "2026-01-01"\nresidual = "BACKLOG #10"\n'
    )
    assert [(p.item, p.cell) for p in pairs] == [(10, "C1")]


def test_the_run_splits_confirmations_from_real_grade_moves(
    ledger: Path, tmp_path: Path, capsys
) -> None:
    """End to end: the hit list states how much of itself is noise, so a reader knows where to start.

    #10's banner is flipped 2026-02-01 and the cell is re-verified 2026-05-01 WITHOUT moving, which
    is the in-sync state and the dominant real-world case -- 22 of 28 items when this ran against the
    vault record.
    """
    repo = scorecard_repo(tmp_path, [("2026-01-01", "partial"), ("2026-05-01", "partial")])
    assert main(["--scorecard", str(repo / "card.toml"), "--root", str(ledger)]) == 0
    out = capsys.readouterr().out
    assert "RE-SCORED AFTER THE BANNER WAS LAST TOUCHED: 1" in out
    assert "0 sit on a cell whose GRADE moved after the banner" in out
    assert "1 on a cell that was only re-verified" in out
    assert "0 could not be decided" in out
    assert GRADE_UNCHANGED in out


def test_the_refusal_names_the_route_that_needs_no_owner_decision(
    shallow_ledger: Path, tmp_path: Path, capsys
) -> None:
    """A refusal whose only remedy is 'ask the owner' is why this tool sat unrun for twelve days.

    A throwaway clone shares no object store, so the shared-store objection that makes --unshallow
    the owner's call does not reach it, and --root already takes a separate history source.
    """
    card = tmp_path / "card.toml"
    card.write_text(
        '[[cell]]\nid = "C1"\nlast_verified = "2020-01-01"\nresidual = "BACKLOG #10"\n',
        encoding="utf-8",
    )
    assert main(["--scorecard", str(card), "--root", str(shallow_ledger)]) == 3
    err = capsys.readouterr().err
    assert "git clone --single-branch" in err
    assert "shares no object store" in err
    assert "2020-01-01" in err
    assert "--filter=blob:none" in err

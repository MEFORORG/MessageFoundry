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
    live_only = banner_last_touched(ledger, [LIVE], None)
    both = banner_last_touched(ledger, [LIVE, ARCHIVE], None)

    assert live_only[20] == "2026-01-01"
    assert both[20] == "2026-03-01"

    # And the consequence, stated as the verdict rather than as the date: a re-score between the two
    # is a false hit on the live-only walk and correctly silent once the archive is read.
    assert evaluate([Pair(20, "2026-02-15")], live_only)[0] != []
    assert evaluate([Pair(20, "2026-02-15")], both)[0] == []


def test_an_in_place_flip_is_dated_at_the_flip(ledger: Path) -> None:
    """The control for the row above: #10 never moved, so both walks must agree about it. Without this
    the archive fix could have shifted every date and still passed."""
    live_only = banner_last_touched(ledger, [LIVE], None)
    both = banner_last_touched(ledger, [LIVE, ARCHIVE], None)
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

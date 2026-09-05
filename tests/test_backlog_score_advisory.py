#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The unscored-row advisory in ``backlog_status_check.py`` (BACKLOG #1455).

**What it guards.** An OPEN row with no value/difficulty is absent from the ranked table while
present in the ledger, so the instrument that answers *"what next"* reads complete while being
incomplete. Measured across three days: 73 rows carried no score on 2026-09-03, 5 on 2026-09-04 and
1 on 2026-09-05. Each pass closed the gap; ordinary filing re-opened it; none of the three was found
by a gate.

**ADVISORY, BY OWNER RULING 2026-09-05.** The check must WARN and must never fail the gate, because
this module runs in the required ``test`` leg and an error would red the pull request of anyone who
FILES an unscored row. ``test_the_advisory_never_fails_the_gate`` is the arm that pins the ruling,
and it is the one to read before anyone promotes this to an error.

**The arms that matter are the must-NOT-warn ones.** A gate keyed on the sentence that usually
introduces a score, rather than on the score itself, reports a correctly-scored row as unscored --
measured on #1435, whose numbers sit inline in a filing banner with no ``Scored`` phrase at all, and
on #1312, hand-written with ``--`` separators and different emphasis. Both shapes are pinned below
so a future tightening of the pattern has to break a test rather than a filer's pull request.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "scripts" / "docs"))

from backlog_status_check import main, parse_items, scan  # noqa: E402

_ADVISORY = "carries no value/difficulty score"

# Every shape is a COMPLETE minimal ledger, so a case can be pasted into a file and run by hand.
_OPEN = "\U0001f522"
_WIP = "\U0001f6a7"
_SHIPPED = "✅"
_DOT = "·"


def _warned(text: str) -> bool:
    errors, warnings = scan([("t.md", text)])
    assert not errors, f"fixture is not supposed to carry errors: {errors}"
    return any(_ADVISORY in w for w in warnings)


def test_an_open_row_with_no_score_warns() -> None:
    """The must-trip arm. Without this the whole check could be a no-op and read as success."""
    assert _warned(f"## 1. unscored\n\n> {_OPEN} **Filed.** no numbers here\n")


def test_the_house_style_score_does_not_warn() -> None:
    assert not _warned(
        f"## 2. scored\n\n> {_OPEN} **Scored 2026-09-05 -> P3.** "
        f"Value **4/10** {_DOT} Difficulty **2/10** {_DOT} _fill-in_. why\n"
    )


def test_a_hand_written_score_does_not_warn() -> None:
    """#1312's real shape: ``--`` separators, filed by hand outside the mechanical pass."""
    assert not _warned(
        f"## 3. hand written\n\n> {_OPEN} **Filed.** "
        "Value **6/10** -- Difficulty **3/10** -- _fill-in_. why\n"
    )


def test_a_score_inline_in_a_filing_banner_does_not_warn() -> None:
    """#1435's real shape, and the reason this keys on the SCORE and not on a ``Scored`` phrase.

    Measured 2026-09-05: a phrase-keyed census called #1435 unscored while a score-keyed one called
    it scored. The second is right. A phrase-keyed gate would have red-flagged a correctly-scored
    row and taught filers to write a magic string.
    """
    assert not _warned(
        f"## 4. inline\n\n> {_WIP} **Filed. The marker is built.** "
        "Value **5/10** · Difficulty **2/10** for what shipped, **6/10** for what is left.\n"
    )


def test_a_closed_row_with_no_score_does_not_warn() -> None:
    """Exempt by design: a score prices the REMAINDER, and a shipped row has none."""
    assert not _warned(f"## 5. shipped\n\n> {_SHIPPED} **SHIPPED.** no numbers\n")


def test_a_score_below_the_banner_block_still_warns() -> None:
    """The KNOWN LIMIT, pinned so it is a decision rather than a surprise.

    ``parse_items`` reads the banner block only, so a score below it is invisible here. Measured
    2026-09-05 over all 277 open rows: zero are shaped this way, so the limit costs nothing today.
    If this test ever has to change, the fix is the block boundary, not the score pattern.
    """
    assert _warned(
        f"## 6. below\n\n> {_OPEN} **Filed.** no numbers\n\n"
        f"**Cluster:** x. Value **7/10** {_DOT} Difficulty **1/10**\n"
    )


def test_the_parser_exposes_the_value_it_read() -> None:
    items = parse_items(
        f"## 7. scored\n\n> {_OPEN} **Scored.** Value **6/10** {_DOT} Difficulty **3/10**\n"
    )
    assert items[0].score == 6


def test_the_newest_score_wins_when_a_superseded_one_is_kept_below_it() -> None:
    """A re-score is prepended ABOVE the superseded line, which rows often keep and label.

    Taking the last match would read the retired number, which is how a row that was re-scored
    DOWN would keep sorting on its old, higher value.
    """
    items = parse_items(
        f"## 8. rescored\n\n> {_OPEN} **Re-scored 2026-09-05 -> P3.** Value **2/10** "
        f"{_DOT} Difficulty **1/10**. _(was 6/10.)_\n"
        f"> **Scored 2026-08-20, SUPERSEDED.** Value **6/10** {_DOT} Difficulty **4/10**\n"
    )
    assert items[0].score == 2


def test_the_advisory_never_fails_the_gate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """THE ARM THAT PINS THE OWNER RULING. Advisory means exit 0, not exit 0 today.

    Read this before promoting the check to an error: the ruling of 2026-09-05 chose advisory over
    a fatal gate precisely so that filing an unranked row stays cheap.
    """
    ledger = tmp_path / "BACKLOG.md"
    ledger.write_text(f"## 9. unscored\n\n> {_OPEN} **Filed.** no numbers\n", encoding="utf-8")
    rc = main(["--backlog", str(ledger)])
    captured = capsys.readouterr()
    assert rc == 0, "the unscored advisory must never fail the gate (owner ruling, BACKLOG #1455)"
    # STDERR, not stdout: main() routes every WARN and ERROR there. Asserting on stdout passes
    # vacuously for a check that emits nothing at all, which is the failure this arm exists to
    # catch -- it did exactly that on the first run.
    assert _ADVISORY in captured.err, "the advisory must be surfaced on stderr, not merely counted"
    assert captured.err.isascii(), (
        "the advisory must stay ASCII: stderr is not hardened to UTF-8 the way stdout is "
        "(#1030), so a non-ASCII character here can raise UnicodeEncodeError on a cp1252 "
        "console and turn an advisory into a crash"
    )

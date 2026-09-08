# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""docs/SECURITY.md's "Attributes not consumed at this release" list must stay honest.

BACKLOG #1153 (ASVS 8.2.4). The verb asks for adaptive controls based on a consumer's environmental
and contextual attributes -- time of day, location, IP address, device -- applied at session start
AND during an existing session, "as defined in the application's documentation".

That last clause is the whole reason this guard exists. It makes the documentation the measure, which
makes NARROWING the documentation the cheapest way to appear to pass: shorten the not-consumed list
and the shipped controls suddenly match what the application "defines". The item names that move as
its first disqualified one. Nothing prevented it, so this is the mechanical defence -- the paragraph
is pinned, and dropping a class from it reds.

**The second half is the part that was measured wrong before, and it is the reason this file is not
just a string comparison.** An absence check is only worth the instrument behind it. The engine
SHIPS a complete timezone-aware time-of-day and day-of-week window evaluator -- ``ActiveWindow`` and
``Schedule`` in ``config/models.py``, used to start and stop connections on a calendar and to pace
alert rules. A "no time-of-day logic here" pattern that cannot match THAT returns a zero which means
"my pattern is wrong", not "the engine has no clock", and the two are indistinguishable from the
result alone. So the positive control below asserts the evaluator exists and is findable BEFORE the
absence is asserted, and the absence is asserted where it actually bears on the requirement: no
authorization decision reads one.
"""

from __future__ import annotations

import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_SECURITY_MD = _ROOT / "docs" / "SECURITY.md"
_AUTH_PKG = _ROOT / "messagefoundry" / "auth"

_HEADING = "**Attributes not consumed at this release**"

#: Every attribute class the paragraph disclaims. Dropping one from the doc reds; the point is that
#: the list may only ever GROW SHORTER by a class actually being built, never by an edit.
_DISCLAIMED = (
    "time-of-day",
    "geolocation",
    "device security posture",
    "user-agent",
    "behavioural baselines",
    "address history",
)

#: Symbols that make up the engine's own time-of-day / day-of-week evaluator. These are the
#: spellings an absence pattern must be able to match, or it is not measuring anything.
_WINDOW_SYMBOLS = ("ActiveWindow", "Schedule", "is_active", "weekday")


def _disclaimer_paragraph() -> str:
    text = _SECURITY_MD.read_text(encoding="utf-8")
    start = text.find(_HEADING)
    assert start != -1, (
        f"docs/SECURITY.md no longer contains {_HEADING!r}. If the paragraph was renamed, retarget "
        f"this guard in the same commit. Do NOT delete it: an unpinned disclaimer is the exact "
        f"surface BACKLOG #1153 names as the cheapest way to buy this cell."
    )
    rest = text[start:]
    end = rest.find("\n\n")
    return rest[:end] if end != -1 else rest


@pytest.mark.parametrize("attribute", _DISCLAIMED)
def test_the_not_consumed_list_still_names_every_disclaimed_attribute(attribute: str) -> None:
    """Narrowing the disclaimer reds. Widening it does not, which is the right asymmetry.

    A class leaves this list honestly only when the control is BUILT, and that commit changes this
    tuple with the code beside it. A class leaving it any other way is the documentation being tuned
    to fit the product, which is what the requirement's "as defined in the application's
    documentation" clause invites and what this test refuses.
    """
    assert attribute in _disclaimer_paragraph(), (
        f"docs/SECURITY.md's not-consumed list no longer names {attribute!r}. If the control was "
        f"actually built, remove it from _DISCLAIMED in the SAME commit as the code that consumes "
        f"it. If it was not, this is the disqualified move: restore the sentence."
    )


def test_the_engine_ships_a_time_of_day_evaluator_this_pattern_can_see() -> None:
    """Positive control, and it must run before the absence below means anything.

    BACKLOG #1153 measured that the recorded time-of-day absence pattern matched NONE of this
    evaluator's spellings. An absence check whose pattern cannot match the thing where the thing
    demonstrably exists reports a zero that is indistinguishable from a broken pattern.
    """
    models = (_ROOT / "messagefoundry" / "config" / "models.py").read_text(encoding="utf-8")
    for symbol in _WINDOW_SYMBOLS:
        assert symbol in models, (
            f"{symbol!r} is not in config/models.py, so the absence assertion below is being made "
            f"with a pattern that has not been shown to match anything. Either the evaluator moved "
            f"-- retarget both halves -- or the spelling changed."
        )
    assert "def contains" in models and "def is_active" in models, (
        "the window evaluator's entry points are gone; re-derive this guard rather than trusting it"
    )


@pytest.mark.parametrize("symbol", _WINDOW_SYMBOLS)
def test_no_authorization_decision_reads_a_time_window(symbol: str) -> None:
    """The absence that actually bears on the verb, asserted where it bears.

    "Time of day is not consumed" does not mean the engine has no clock -- it plainly has one, and
    the control above proves this pattern can find it. It means no AUTHORIZATION decision reads one.
    The engine's windows start and stop connections and pace alert rules; none of that is a consumer
    environmental attribute changing an allow or a deny.

    If this ever reds, do not delete the disclaimer to match. A time-window read inside ``auth/``
    would be a real adaptive control, and the honest response is to grade it -- and to keep the
    product-purpose objection in view, since there is no defensible default window for the operator
    console of a twenty-four-hour clinical service.
    """
    hits = [
        f"{path.relative_to(_ROOT)}"
        for path in sorted(_AUTH_PKG.rglob("*.py"))
        if symbol in path.read_text(encoding="utf-8")
    ]
    assert not hits, (
        f"{symbol!r} appears inside messagefoundry/auth/ ({hits}), so an authorization path may now "
        f"read a time window. docs/SECURITY.md still disclaims time-of-day as not consumed. Grade "
        f"the new control and correct the disclaimer together -- do not silence this."
    )

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``docs/SECURITY.md`` says once whose rows ``GET /me/security-events`` shows (vault BACKLOG
#1151, #4776 item 3).

The rule is the feed's bullet under *Single-route data rules*, which
``tests/test_single_route_data_rules_doc_drift.py`` executes against a live app. Two other
passages restated it, and one said the feed shows "the caller's own audited" events, while the
store selects the rows recorded under the caller's username at or after the account's
``created_at``, which can include rows the caller did not write. This keeps each passage outside
the rule pointing at it rather than restating it. A planted copy of the old wording is the
positive control. It is a text check.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.store.store import _security_events_where

_DOC = Path(__file__).resolve().parent.parent / "docs" / "SECURITY.md"
_RULE = (
    "> - `GET /me/security-events` returns the `auth.*` rows recorded under the caller's username"
)
_POINTER = "Whose rows it shows is stated once, in the `GET /me/security-events` bullet"
#: Restatements of the selection outside the rule, as the two passages once worded them.
_FORBIDDEN = (
    "caller's own audited",
    "selects rows by the caller's own username",
)


def _flat(text: str) -> str:
    return " ".join(text.split())


def _problems(text: str) -> list[str]:
    found: list[str] = []
    if text.count(_RULE) != 1:
        found.append(f"the rule bullet appears {text.count(_RULE)} times")
    flat = _flat(text)
    for phrase in _FORBIDDEN:
        if phrase in flat:
            found.append(f"restated: {phrase!r}")
    pointers = flat.count(_flat(_POINTER))
    if pointers != 2:
        found.append(f"{pointers} pointers to the rule, expected 2")
    return found


def test_the_doc_states_the_feed_rule_once() -> None:
    assert _problems(_DOC.read_text(encoding="utf-8")) == []


def test_the_rule_matches_the_store_selection() -> None:
    # The rule says "recorded under the caller's username" and "at or after created_at": the
    # store's clause keys on the actor column and the account's own created_at.
    clause, params = _security_events_where("someone", None)
    assert "actor = ?" in clause and "created_at" in clause and params == ["someone", "someone"]


@pytest.mark.parametrize("phrase", _FORBIDDEN)
def test_guard_detects_a_planted_restatement(phrase: str) -> None:
    text = _DOC.read_text(encoding="utf-8")
    planted = text.replace(_POINTER, f"{_POINTER} It shows the {phrase} rows.", 1)
    assert planted != text
    assert f"restated: {phrase!r}" in _problems(planted)


def test_guard_detects_a_dropped_pointer() -> None:
    text = _DOC.read_text(encoding="utf-8")
    planted = text.replace(_POINTER, "It shows rows.", 1)
    assert planted != text
    assert any("pointers to the rule" in p for p in _problems(planted))

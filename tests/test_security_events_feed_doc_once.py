# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``docs/SECURITY.md`` no longer contradicts itself on whose rows ``GET /me/security-events``
shows (vault BACKLOG #1151, #4776 item 3).

The rule is the feed's bullet under *Single-route data rules*, which
``tests/test_single_route_data_rules_doc_drift.py`` executes against a live app: the ``auth.*``
rows recorded under the caller's username at or after the account's ``created_at``. At least two
other passages restated it, and one said the feed shows "the caller's own audited" events, which
reads as rows of the caller's own acts. Those two now point at the rule and at the store-side
residuals instead. This checks the two pointers and refuses the two old wordings; planted copies
are the positive controls. It is a text check and does not read every passage that names the feed.
"""

from __future__ import annotations

import functools
from pathlib import Path

import pytest

_DOC = Path(__file__).resolve().parent.parent / "docs" / "SECURITY.md"
_RULE = (
    "> - `GET /me/security-events` returns the `auth.*` rows recorded under the caller's username"
)
_POINTER = (
    "Whose rows it shows is the `GET /me/security-events` bullet under *Single-route data rules*,"
    " in [The `/ui` console plane](#the-ui-console-plane-serve_uitrue)"
)
#: The heading the pointer's link resolves to, by GitHub's slug of it.
_HEADING = "#### The `/ui` console plane (`serve_ui=True`)"
_RESIDUALS = "the store-side name-compare residuals that `_security_events_where`"
#: The two old wordings of the selection outside the rule.
_FORBIDDEN = (
    "caller's own audited",
    "selects rows by the caller's own username",
)


@functools.cache
def _doc() -> str:
    return _DOC.read_text(encoding="utf-8")


def _flat(text: str) -> str:
    return " ".join(text.split())


def _problems(text: str) -> list[str]:
    found: list[str] = []
    if _HEADING not in text:
        found.append("the pointer's link target heading is gone")
    if text.count(_RULE) != 1:
        found.append(f"the rule bullet appears {text.count(_RULE)} times")
    flat = _flat(text)
    for phrase in _FORBIDDEN:
        if phrase in flat:
            found.append(f"restated: {phrase!r}")
    for name, needle in (("pointer", _POINTER), ("residuals", _RESIDUALS)):
        count = flat.count(_flat(needle))
        if count != 2:
            found.append(f"{count} {name} sentences, expected 2")
    return found


def test_the_two_passages_point_at_the_feed_rule() -> None:
    assert _problems(_doc()) == []


@pytest.mark.parametrize("phrase", _FORBIDDEN)
def test_guard_detects_a_planted_restatement(phrase: str) -> None:
    flat = _flat(_doc())
    planted = flat.replace(_POINTER, f"It shows the {phrase} rows. {_POINTER}", 1)
    assert planted != flat
    assert f"restated: {phrase!r}" in _problems(planted)


@pytest.mark.parametrize("needle", [_POINTER, _RESIDUALS])
def test_guard_detects_a_dropped_sentence(needle: str) -> None:
    flat = _flat(_doc())
    planted = flat.replace(needle, "It shows rows.", 1)
    assert planted != flat
    assert any("sentences, expected 2" in p for p in _problems(planted))


def test_guard_detects_a_dropped_rule() -> None:
    text = _doc()
    planted = text.replace(_RULE, "> - The feed returns rows", 1)
    assert planted != text
    assert "the rule bullet appears 0 times" in _problems(planted)


def test_guard_detects_a_renamed_link_target() -> None:
    text = _doc()
    planted = text.replace(_HEADING, "#### The console plane", 1)
    assert planted != text
    assert "the pointer's link target heading is gone" in _problems(planted)

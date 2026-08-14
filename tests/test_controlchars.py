# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The shared C0/DEL predicate (BACKLOG #1253).

#1239 asked for a test that "the two predicates agree across a shared character corpus, so a future
widening of one without the other fails". There is now ONE predicate, so that obligation becomes a
CHARACTERISATION test: pin the exact code-point set, over the whole of Latin-1 plus the neighbours
that tempt a widener, so a change to the shared definition has to be deliberate and cannot ride in
as a tidy-up. Seven call sites move together now -- that is the leverage and also the risk.
"""

from __future__ import annotations

import pytest

from messagefoundry.controlchars import has_control_char, strip_control_chars

#: The set the predicate is defined to catch. Written independently of the implementation, so this
#: is a second opinion rather than a restatement of the same expression.
_CONTROL = frozenset(chr(c) for c in range(0x00, 0x20)) | {chr(0x7F)}


@pytest.mark.parametrize("code", sorted(ord(c) for c in _CONTROL))
def test_every_c0_control_and_del_is_caught(code: int) -> None:
    assert has_control_char(f"a{chr(code)}b") is True


def test_the_predicate_matches_its_definition_across_all_of_latin1_and_beyond() -> None:
    """The characterisation. Any divergence here is a deliberate widening or a mistake, and either
    way it must not pass silently -- seven call sites share this now."""
    caught = {chr(c) for c in range(0x0000, 0x0300) if has_control_char(chr(c))}
    assert caught == set(_CONTROL)


def test_ordinary_text_is_not_flagged() -> None:
    assert has_control_char("") is False
    assert has_control_char("a normal value") is False
    assert has_control_char("punctuation!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~") is False


def test_the_boundaries_are_where_they_are_documented() -> None:
    """0x1F in, 0x20 out; 0x7E out, 0x7F in, 0x80 out. The off-by-one at each edge."""
    assert has_control_char(chr(0x1F)) is True
    assert has_control_char(chr(0x20)) is False  # space
    assert has_control_char(chr(0x7E)) is False  # tilde
    assert has_control_char(chr(0x7F)) is True  # DEL
    assert has_control_char(chr(0x80)) is False  # C1 starts here and is NOT covered


@pytest.mark.parametrize("code", [0x85, 0x9B, 0x2028, 0x2029, 0x200B, 0xFEFF])
def test_c1_and_unicode_separators_are_deliberately_NOT_caught(code: int) -> None:
    """Documented as deliberate, and pinned so nobody "fixes" it by accident. Every call site
    screens values bound for byte-oriented sinks where C0 and DEL are the injection alphabet.
    Widening this is a behaviour change at seven sites at once and must be made on purpose."""
    assert has_control_char(chr(code)) is False


# --- the two actions stay two actions ---------------------------------------------------------


def test_strip_removes_exactly_what_the_predicate_catches() -> None:
    noisy = "".join(sorted(_CONTROL)) + "keep me"
    assert strip_control_chars(noisy) == "keep me"
    assert has_control_char(strip_control_chars(noisy)) is False


def test_strip_is_a_no_op_on_clean_text() -> None:
    assert strip_control_chars("nothing to remove") == "nothing to remove"


def test_strip_preserves_order_and_the_rest_of_the_value() -> None:
    assert strip_control_chars("a\rb\nc\td") == "abcd"


def test_the_two_actions_disagree_on_purpose() -> None:
    """A regression that turned the strip into a reject (or vice versa) would show up here. #1253
    requires both arms to survive: six sites refuse, rest.py's header-VALUE path neutralises."""
    hostile = "value\r\nX-Injected: 1"
    assert has_control_char(hostile) is True
    assert strip_control_chars(hostile) == "valueX-Injected: 1"
    assert has_control_char(strip_control_chars(hostile)) is False


def test_the_strip_defeats_header_injection_which_is_why_it_exists() -> None:
    """CRLF is the whole point: a stripped value can no longer split a request line."""
    assert "\r" not in strip_control_chars("a\rb")
    assert "\n" not in strip_control_chars("a\nb")

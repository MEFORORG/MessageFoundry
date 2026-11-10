# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The three terminal-text callers agree on the dangerous categories (BACKLOG #2891).

The toolkit report line and the ``check-privileges`` text print each character of
``CONTROL_CATEGORIES`` as a visible escape through the shared ``terminal_text`` rule, and the root
comparison in ``privilege_check.printable`` strips it. Each control below makes the check go red
when one caller diverges. These lived in ``tests/test_adr_analyze.py`` until PR 2390 note 7.
"""

from __future__ import annotations

import contextlib
import io
import unicodedata

import pytest

from messagefoundry import privilege_check, terminal_text
from messagefoundry.controlchars import CONTROL_CATEGORIES
from messagefoundry.privilege_probes import VaultTokenReading
from messagefoundry_toolkit import __main__ as toolkit

#: One code point for each category in ``CONTROL_CATEGORIES``, built from integers so no editor
#: can show or rewrite them. The test below checks the sample covers the set exactly, so a widened
#: set cannot pass with the sample left behind.
_ONE_PER_CATEGORY = {
    "Cc": 0x9B,
    "Cf": 0x200B,
    "Zl": 0x2028,
    "Zp": 0x2029,
    "Cs": 0xD800,
    "Co": 0xE000,
    "Cn": 0xFFFF,
}


def _disagreements() -> list[str]:
    """Every place one of the three terminal-text callers fails to treat a code point of
    ``CONTROL_CATEGORIES`` as dangerous (BACKLOG #2891): the toolkit report line and the
    ``check-privileges`` text must print it as its visible escape, and the root comparison
    in ``privilege_check.printable`` must strip it. The escape is looked for, not the raw
    character's absence, because ``_safe_print`` turns an unencodable one into ``?``."""
    consumer = privilege_check.VaultConsumer("vault.store", "kek", "store key", "read the KEK")
    found = []
    for category, code in _ONE_PER_CATEGORY.items():
        char, escape = chr(code), f"\\u{code:04x}"
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            toolkit._print_record_line(f"item a{char}b")
        if escape not in printed.getvalue():
            found.append(f"the toolkit line does not escape {category}")
        reading = VaultTokenReading(looked_up=True, policies=(f"p{char}q",))
        hop = privilege_check.vault_hop(consumer, reading)
        if escape not in "\n".join(privilege_check.render_text([hop])):
            found.append(f"the check-privileges text does not escape {category}")
        if privilege_check.printable(f"ro{char}ot") != "root":
            found.append(f"the root comparison does not strip {category}")
    return found


def test_the_three_terminal_text_callers_agree_on_the_dangerous_categories() -> None:
    assert set(_ONE_PER_CATEGORY) == CONTROL_CATEGORIES
    assert all(unicodedata.category(chr(c)) == k for k, c in _ONE_PER_CATEGORY.items())
    assert vars(privilege_check)["CONTROL_CATEGORIES"] is CONTROL_CATEGORIES, (
        "a copy, not the engine's set"
    )
    assert _disagreements() == []


def test_the_agreement_check_fails_when_the_root_comparison_diverges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Control: the comparison's rule before BACKLOG #2891, category ``C*``, which left the line
    and paragraph separators in."""
    old = frozenset(c for c in CONTROL_CATEGORIES if c.startswith("C"))
    monkeypatch.setattr(privilege_check, "CONTROL_CATEGORIES", old)
    assert _disagreements() == [
        "the root comparison does not strip Zl",
        "the root comparison does not strip Zp",
    ]


def test_the_agreement_check_fails_when_the_shared_terminal_rule_diverges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Control: a shared rule that stopped escaping the line separator reaches the toolkit line,
    and the check-privileges text, which both keep printable Unicode, and the check names both."""
    monkeypatch.setattr(terminal_text, "CONTROL_CATEGORIES", CONTROL_CATEGORIES - {"Zl"})
    assert _disagreements() == [
        "the toolkit line does not escape Zl",
        "the check-privileges text does not escape Zl",
    ]

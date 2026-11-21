# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A hit in a mapped field is told apart by one anchored reading of its label, not by a
substring test (vault BACKLOG #5533 items 4 and 27).

``has_other_cause``, ``mapped_field_advice``, ``refusal_advice``, ``retarget_residue_hits`` and
``kept_component_hits`` each asked whether a label's words appeared anywhere in a hit. A token
hit names the token's description from the token source, so a description holding those words
read as a hit in a mapped field: ``has_other_cause`` then said the report had no other cause, and
the run dropped the general advice the token needed. They now share ``mapped_field_label``, which
reads the label only where ``past_first_component_hits`` writes it, at the end before the
address, and a token hit never counts as one.

The token description here is made up.
"""

from __future__ import annotations

import re
from types import ModuleType

import pytest

from messagefoundry_toolkit.anon import leak as engine_leak
from tee.anon import leak as tee_leak

_LEAKS = pytest.mark.parametrize("leak", [engine_leak, tee_leak], ids=["engine", "tee"])


def _report(leak: ModuleType, *, tokens: list[str], structural: list[str]) -> object:
    return leak.LeakReport(
        hits=[*tokens, *structural],
        unmapped_fields=(),
        structural_hits=structural,
        token_tables_live=True,
        token_floor_reason=None,
    )


@_LEAKS
def test_a_token_hit_holding_a_label_is_another_cause(leak: ModuleType) -> None:
    token = f"synthetic partner {leak.RETARGET_RESIDUE} in PID-3"
    residue = f"dashed SSN {leak.KEPT_COMPONENT} in PID-3"
    report = _report(leak, tokens=[token], structural=[residue])
    assert leak.has_other_cause(report)
    assert leak.mapped_field_advice(report) == [leak.KEPT_COMPONENT_ADVICE]
    assert "Extend the rule map" in leak.refusal_advice(report)


@_LEAKS
def test_a_label_not_at_the_end_is_not_a_mapped_field_hit(leak: ModuleType) -> None:
    hit = f"note {leak.KEPT_COMPONENT} in PID-3 and more"
    assert leak.mapped_field_label(hit) is None
    report = _report(leak, tokens=[], structural=[hit])
    assert leak.mapped_field_advice(report) == []
    assert leak.has_other_cause(report)


@_LEAKS
def test_each_label_is_read_where_the_walk_writes_it(leak: ModuleType) -> None:
    """The control: the hits ``past_first_component_hits`` writes read as their own label."""
    assert leak.mapped_field_label(f"dashed SSN {leak.RETARGET_RESIDUE} in PID-11") == (
        leak.RETARGET_RESIDUE
    )
    assert leak.mapped_field_label(f"punctuated phone {leak.KEPT_COMPONENT} in GT1-2") == (
        leak.KEPT_COMPONENT
    )
    report = _report(leak, tokens=[], structural=[f"dashed SSN {leak.KEPT_COMPONENT} in GT1-2"])
    assert not leak.has_other_cause(report)
    assert "Extend the rule map" not in leak.refusal_advice(report)


@_LEAKS
def test_a_token_hit_with_a_structural_hits_exact_text_is_another_cause(leak: ModuleType) -> None:
    """A token hit is told apart by where it sits in ``hits``, not by its text, so one that reads
    exactly like a mapped-field hit still needs the general advice."""
    same = f"dashed SSN {leak.KEPT_COMPONENT} in PID-3"
    report = _report(leak, tokens=[same], structural=[same])
    assert leak.has_other_cause(report)


@_LEAKS
def test_the_pattern_names_the_label_constants(leak: ModuleType) -> None:
    """The pattern is written out for the ReDoS scanner; this keeps it on the constants."""
    # Each label is plain words, so it stands in the pattern unescaped.
    assert all(re.escape(label).replace("\\ ", " ") == label for label in leak._MAPPED_FIELD_LABELS)
    alternation = "|".join(leak._MAPPED_FIELD_LABELS)
    assert leak._MAPPED_FIELD_TAIL.pattern == f" ({alternation}) in [^ ]+$"
    assert leak._MAPPED_FIELD_LABELS == (leak.RETARGET_RESIDUE, leak.KEPT_COMPONENT)

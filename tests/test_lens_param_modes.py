# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The per-argument value classifier of ADR 0076 Amendment E (BACKLOG #237).

Amendment E makes `templated` mode WRITABLE, and that is the whole reason it needed an ADR: E.5
admits one new argument shape into a grammar that previously took only "literal args or bounded
Message-read expressions". Writing a shape means the rewriter must be able to read it back to the
SAME mode with the SAME parts -- round-trip totality, which E.6.3 makes a build gate.

THAT IS WHY THE ADMITTED SET IS CLOSED AND THESE TESTS ENUMERATE ITS COMPLEMENT. AC-M3 requires one
case per excluded shape precisely so that widening the set FAILS A TEST rather than passing
silently. An open predicate -- "anything that looks safe" -- would be a second grammar drifting from
the first, which is the failure `scripts/quality/lens_coverage.py` already refuses by driving the
shipped parser instead of reimplementing it.

The asymmetry worth holding while reading: a shape wrongly called `dynamic` renders read-only,
exactly as it does today, and E.5 says that is "not a degradation and not an error". A shape wrongly
called `templated` licenses the rewriter to emit something it cannot round-trip. The tests below are
therefore much harder on false `templated` than on false `dynamic`.
"""

from __future__ import annotations

import ast

import pytest

from messagefoundry.lens import (
    MODE_DYNAMIC,
    MODE_STATIC,
    MODE_TEMPLATED,
    _is_bounded_message_read,
    _param_mode,
)


def _expr(src: str) -> ast.expr:
    """The single expression `src` parses to."""
    parsed = ast.parse(src, mode="eval").body
    return parsed


# --- the admitted set (E.5) ---------------------------------------------------

ADMITTED = [
    pytest.param("f\"{msg['PID-5.1']}\"", id="single-subscript-read"),
    pytest.param("f\"{msg['PID-5.1']} {msg['PID-5.2']}\"", id="two-reads-and-literal-text"),
    pytest.param("f\"MRN: {msg['PID-3.1']}\"", id="leading-literal-text"),
    pytest.param("f\"{msg['PID-5.1']} trailing\"", id="trailing-literal-text"),
    pytest.param("f\"{msg.field('PID-5.1')}\"", id="field-call-read"),
    pytest.param("f\"{msg.field('OBX-5', 2)}\"", id="field-call-multiple-constant-args"),
    pytest.param('f"no placeholders at all"', id="fstring-with-no-placeholders"),
]


@pytest.mark.parametrize("src", ADMITTED)
def test_the_admitted_interpolations_classify_templated(src: str) -> None:
    assert _param_mode(_expr(src)) == MODE_TEMPLATED


# --- the exclusion list (E.5), one case per named shape -----------------------
#
# E.5 names these explicitly. Each must be `dynamic`, and each is a separate parametrized case so a
# future widening reports WHICH shape it admitted rather than a single opaque failure.

EXCLUDED = [
    pytest.param('msg["PID-5.1"] + " " + msg["PID-5.2"]', id="plus-concatenation"),
    pytest.param('"%s" % msg["PID-5.1"]', id="percent-formatting"),
    pytest.param('"{}".format(msg["PID-5.1"])', id="str-format"),
    pytest.param('" ".join([msg["PID-5.1"]])', id="str-join"),
    pytest.param("f\"{helper(msg['PID-5.1'])}\"", id="nested-call"),
    pytest.param("f\"{msg['PID-5.1']:>10}\"", id="format-spec"),
    pytest.param("f\"{msg['PID-5.1']!r}\"", id="conversion-repr"),
    pytest.param("f\"{msg['PID-5.1']!s}\"", id="conversion-str"),
    pytest.param('f"{[x for x in msg.segments()]}"', id="comprehension"),
    pytest.param("f\"{(y := msg['PID-5.1'])}\"", id="walrus"),
    pytest.param("f\"{msg['PID-5.1'] if flag else ''}\"", id="conditional-expression"),
    pytest.param("f\"{msg['PID-5.1'] + msg['PID-5.2']}\"", id="fstring-containing-concatenation"),
]


@pytest.mark.parametrize("src", EXCLUDED)
def test_every_shape_e5_excludes_classifies_dynamic(src: str) -> None:
    """AC-M3's negative half. This is the half that keeps the set closed."""
    assert _param_mode(_expr(src)) == MODE_DYNAMIC


def test_the_exclusion_list_covers_every_shape_e5_names() -> None:
    """POSITIVE CONTROL ON THE TEST DATA ITSELF, not on the classifier.

    A parametrized suite silently shrinks when a case is deleted, and a shrunken suite still passes.
    E.5 names eleven excluded shapes; this pins the count so removing a case fails here rather than
    quietly narrowing what AC-M3 checks.
    """
    ids = {p.id for p in EXCLUDED}
    assert len(ids) == len(EXCLUDED), "duplicate ids would hide a missing shape"
    for required in (
        "plus-concatenation",
        "percent-formatting",
        "str-format",
        "str-join",
        "nested-call",
        "format-spec",
        "conversion-repr",
        "comprehension",
        "walrus",
        "conditional-expression",
    ):
        assert required in ids, f"E.5 names {required} and no case covers it"


# --- static, and its tie to literal_params (AC-M2) ----------------------------


@pytest.mark.parametrize(
    "src", ['"PID-5.1"', "42", "True", "None", "3.5"], ids=["str", "int", "bool", "none", "float"]
)
def test_a_literal_classifies_static(src: str) -> None:
    assert _param_mode(_expr(src)) == MODE_STATIC


def test_static_is_exactly_ast_constant_and_nothing_looser() -> None:
    """AC-M2 requires `static` and `literal_params` to agree in BOTH directions, and
    `literal_params` is literally `isinstance(node, ast.Constant)`. So anything that is not an
    `ast.Constant` must not be `static`, however literal it looks.

    A list of literals is the case that tempts a looser rule: `dests=["A", "B"]` reads as data, but
    `_literal_param_names` excludes it because the rewriter refuses to write a list from a scalar.
    """
    assert _param_mode(_expr('["A", "B"]')) != MODE_STATIC
    assert _param_mode(_expr('("A", "B")')) != MODE_STATIC
    assert _param_mode(_expr('f"already central"')) != MODE_STATIC


# --- the bounded-read predicate, tested directly -------------------------------


@pytest.mark.parametrize(
    "src",
    ['msg["PID-5.1"]', 'msg.field("PID-5.1")', 'msg.field("OBX-5", 2)'],
    ids=["subscript", "field-one-arg", "field-two-args"],
)
def test_bounded_reads_are_recognized(src: str) -> None:
    assert _is_bounded_message_read(_expr(src))


@pytest.mark.parametrize(
    "src",
    [
        pytest.param("msg[path]", id="non-literal-subscript"),
        pytest.param("other['PID-5.1']", id="not-the-msg-name"),
        pytest.param("msg.get('PID-5.1')", id="not-the-field-method"),
        pytest.param("msg.field(path)", id="field-with-non-literal-arg"),
        pytest.param("msg.field('OBX-5', occurrence=i)", id="field-with-keyword"),
        pytest.param("msg.field()", id="field-with-no-args"),
        pytest.param("msg.segments()", id="an-iteration-not-a-read"),
    ],
)
def test_reads_outside_the_closed_set_are_rejected(src: str) -> None:
    """Each of these renders `dynamic`, which is read-only and therefore SAFE. The predicate errs
    strict on purpose -- see its docstring for why the two error directions are not symmetric."""
    assert not _is_bounded_message_read(_expr(src))


def test_a_rejected_read_makes_the_whole_interpolation_dynamic() -> None:
    """One bad part is enough. E.5 quantifies over EVERY FormattedValue, so a single unbounded read
    disqualifies the string rather than degrading just that placeholder."""
    assert _param_mode(_expr("f\"{msg['PID-5.1']} {msg[other]}\"")) == MODE_DYNAMIC

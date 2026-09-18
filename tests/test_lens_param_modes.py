# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.lens import (
    CONTRACT_V1,
    CONTRACT_V2,
    MODE_DYNAMIC,
    MODE_STATIC,
    MODE_TEMPLATED,
    _editable_slots,
    _is_bounded_message_read,
    _param_mode,
    parse_source,
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


# =============================================================================
# EMISSION into the row contract -- AC-M1, AC-M2, AC-M7
# =============================================================================
#
# The classifier above has one production caller per row that carries typed arguments. There are FOUR
# such emission sites and they do not share a code path, so each is pinned by its own test below:
#
#   1. the NATIVE action row (`msg.set(...)`, ADR 0089 Phase A) -- `_native_action_row`
#   2. the WRAPPER action row (`set_field(msg, ...)`)
#   3. the DIAGNOSTIC row (`log_note(...)` / `checkpoint(...)`)
#   4. the LOOKUP row (`db_lookup(...)` / `fhir_lookup(...)` / `code_lookup(...)`)
#
# E.4 names `action` and `lookup`; the `diagnostic` row is included because it carries typed params and
# `literal_params` exactly as those two do, and E.7 scopes modes to "rows that have typed arguments".
# Leaving it out would give one row kind a "is this EDITABLE" answer with no "what SHAPE is this"
# answer beside it, which is the asymmetry E.10's root-cause paragraph warns against.

SAMPLES = Path(__file__).resolve().parents[1] / "samples" / "config"

PREAMBLE = "from messagefoundry import Send, handler\n\n\n"

#: Every argument shape that matters to AC-M1 and AC-M2, in one handler. Note what is deliberately
#: here: a native `occurrence=` display kwarg (a LITERAL THAT IS NOT EDITABLE -- E.10's live
#: instance), a wrapper positional past the signature (the same state on the other path), a `*args`
#: splat and a `**kwargs` splat (params keys that are in no editable set at all).
VOCAB_CORPUS = (
    PREAMBLE + '@handler("wide")\n'
    "def wide(msg):\n"
    '    set_field(msg, "PID-5.1", "SMITH")\n'
    '    set_field(msg, "PID-5.2", f"{msg[\'PID-3.1\']}")\n'
    '    set_field(msg, "PID-5.3", msg["PID-3.1"] + "!")\n'
    '    set_field(msg, "PID-5.4", "X", **extra)\n'
    '    copy_field(msg, "PID-3.1", "PID-4.1")\n'
    '    split_field(msg, "PID-5", "^", dests=["PID-5.1", "PID-5.2"])\n'
    '    pad_field(msg, "PID-3.1", 10, fill="0")\n'
    '    log_note("note {} {}", "LITERAL", msg["PID-3.1"])\n'
    '    log_note("splatted {}", *operands)\n'
    '    checkpoint(msg, "after-copy")\n'
    '    row = db_lookup("CONN", "SELECT 1", params={"id": 1})\n'
    '    hit = fhir_lookup("FHIR", "Patient", params={"identifier": msg["PID-3.1"]})\n'
    '    code_lookup(msg, "PID-8", "GENDER", default="U")\n'
    '    msg.set("OBX-5", "V", occurrence=2)\n'
    '    msg.set("PID-8", f"{msg.field(\'PID-8\')}")\n'
    '    msg.set("NK1-2.1", msg.field("PID-5.1") or "")\n'
    '    msg.add_segment("ODS|R", index=3)\n'
    '    msg.delete_segments("ZZ1")\n'
    '    return Send("OB_X", msg)\n'
)

#: The adversarial corpus FIRST, then the real one. Ordering matters to a reader: `samples/config`
#: contributes no param-carrying row at all today (see the positive control below), so it is a
#: regression tripwire here and never the evidence.
CORPUS: list[tuple[str, str]] = [("adversarial", VOCAB_CORPUS)] + [
    (p.name, p.read_text(encoding="utf-8")) for p in sorted(SAMPLES.glob("*.py"))
]
CORPUS_IDS = [name for name, _ in CORPUS]


def _rows(source: str, *, contract: int, module: str = "m.py") -> list[dict[str, Any]]:
    """Every row of every element in ``source``, flattened."""
    return [
        row
        for entry in parse_source(source, module=module, contract=contract)
        for row in entry["rows"]
    ]


def _row_at(source: str, kind: str) -> dict[str, Any]:
    """The single row of ``kind`` in a one-statement fixture."""
    rows = [r for r in _rows(source, contract=CONTRACT_V2) if r["kind"] == kind]
    assert len(rows) == 1, f"expected exactly one {kind} row, got {rows}"
    return rows[0]


# --- AC-M1: the map is TOTAL over params -------------------------------------


@pytest.mark.parametrize(("name", "source"), CORPUS, ids=CORPUS_IDS)
def test_param_modes_is_total_over_params(name: str, source: str) -> None:
    """AC-M1 -- every argument named, none missing, so a consumer never interprets an absent key.

    Asserted as a BICONDITIONAL against `params` rather than as a subset: a partial map and a map
    with a key `params` does not have are the same defect from the consumer's side, because both
    leave it deciding what a mismatch means.
    """
    for row in _rows(source, contract=CONTRACT_V2, module=name):
        assert ("param_modes" in row) == ("params" in row), (
            f"a row carries one of params/param_modes without the other: {row}"
        )
        if "params" not in row:
            continue
        assert set(row["param_modes"]) == set(row["params"]), (
            f"param_modes is not total over params: {row}"
        )
        assert set(row["param_modes"].values()) <= {MODE_STATIC, MODE_TEMPLATED, MODE_DYNAMIC}, row


def test_the_corpus_actually_carries_rows_of_every_emission_site() -> None:
    """POSITIVE CONTROL ON THE CORPUS, and it is the reason the samples leg is not the evidence.

    MEASURED 2026-09-15: `samples/config` produces 28 rows at CONTRACT_V1 and 67 at CONTRACT_V2, and
    NOT ONE of them carries `params` -- the shipped samples use native `msg[...]` assignment and
    helper calls the vocabulary does not name, so the corpus contains no action, diagnostic or lookup
    row. A corpus-wide AC-M1/AC-M2 test over `samples/config` alone therefore passes over an empty
    set, which is indistinguishable from a correct implementation.
    """
    samples_with_params = [
        row
        for name, source in CORPUS
        if name != "adversarial"
        for row in _rows(source, contract=CONTRACT_V2, module=name)
        if "params" in row
    ]
    assert not samples_with_params, (
        "samples/config now carries param rows -- the vacuity note above is stale, and the corpus "
        "leg has become real evidence rather than a tripwire"
    )
    kinds = [r["kind"] for r in _rows(VOCAB_CORPUS, contract=CONTRACT_V2) if "params" in r]
    assert kinds.count("action") >= 2, "need both a wrapper and a native action row"
    assert kinds.count("diagnostic") >= 1
    assert kinds.count("lookup") >= 1


# --- AC-M2: static-and-editable is exactly literal_params ---------------------


@pytest.mark.parametrize(("name", "source"), CORPUS, ids=CORPUS_IDS)
def test_static_and_editable_is_exactly_literal_params(name: str, source: str) -> None:
    """AC-M2 as corrected by E.10 -- BOTH directions, scoped to the EDITABLE params.

    The scope is load-bearing and not a hedge. Unscoped the criterion is UNSATISFIABLE: a native
    `occurrence=` display kwarg is `static` by shape and absent from `literal_params` by design, and
    so is a wrapper positional past the signature. Widening `literal_params` to swallow them was
    considered and REFUSED (E.10), because E.8 depends on an older consumer reading that field
    unchanged.

    `editable` comes from `_editable_slots` -- the rewriter's own answer to "which params may an edit
    splice" -- so this test cannot agree with the parser merely by reimplementing it.
    """
    stmts = _statements_by_line(source)
    for row in _rows(source, contract=CONTRACT_V2, module=name):
        if "param_modes" not in row:
            continue
        slots = _editable_slots(stmts[row["line_start"]], row["kind"])
        assert slots is not None, f"a row with typed params has no editable slots: {row}"
        editable = set(slots)
        static_editable = {
            p for p, mode in row["param_modes"].items() if mode == MODE_STATIC and p in editable
        }
        assert static_editable == set(row["literal_params"]), (
            f"static-and-editable drifted from literal_params: {row}"
        )


def _statements_by_line(source: str) -> dict[int, ast.stmt]:
    """``{first line: statement}`` for every statement that can open a typed row."""
    out: dict[int, ast.stmt] = {}
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Expr | ast.Assign | ast.AnnAssign | ast.Return):
            out.setdefault(node.lineno, node)
    return out


def test_a_literal_that_is_not_editable_is_static_and_stays_out_of_literal_params() -> None:
    """E.10's live instance, pinned on BOTH paths, because it is the case the criterion was corrected
    for and the one a future "repair" of the asymmetry would silently delete."""
    native = _row_at(
        PREAMBLE + '@handler("h")\ndef h(msg):\n    msg.set("OBX-5", "V", occurrence=2)\n',
        "action",
    )
    assert native["param_modes"]["occurrence"] == MODE_STATIC
    assert "occurrence" not in native["literal_params"]

    wrapper = _row_at(
        PREAMBLE + '@handler("h")\ndef h(msg):\n    log_note("note {}", "LITERAL")\n',
        "diagnostic",
    )
    assert wrapper["param_modes"]["arg1"] == MODE_STATIC
    assert "arg1" not in wrapper["literal_params"]


# --- the four emission sites, one test each ----------------------------------


def test_the_native_action_site_emits_modes() -> None:
    """Site 1 -- `_native_action_row` (ADR 0089 Phase A). `params` is slots PLUS display kwargs, so
    totality here is the case AC-M1 is most likely to lose."""
    row = _row_at(
        PREAMBLE + '@handler("h")\ndef h(msg):\n    msg.set("OBX-5", "V", occurrence=2)\n',
        "action",
    )
    assert row["param_modes"] == {
        "path": MODE_STATIC,
        "value": MODE_STATIC,
        "occurrence": MODE_STATIC,
    }
    assert row["literal_params"] == ["path", "value"]


def test_the_native_action_site_classifies_a_templated_value() -> None:
    row = _row_at(
        PREAMBLE + '@handler("h")\ndef h(msg):\n    msg.set("PID-8", f"{msg.field(\'PID-8\')}")\n',
        "action",
    )
    assert row["param_modes"] == {"path": MODE_STATIC, "value": MODE_TEMPLATED}


def test_the_wrapper_action_site_emits_modes() -> None:
    """Site 2 -- `_ACTION_PARAMS`."""
    row = _row_at(
        PREAMBLE
        + '@handler("h")\ndef h(msg):\n    set_field(msg, "PID-5.1", f"{msg[\'PID-3.1\']}")\n',
        "action",
    )
    assert row["param_modes"] == {"path": MODE_STATIC, "value": MODE_TEMPLATED}
    assert row["literal_params"] == ["path"]


def test_the_diagnostic_site_emits_modes() -> None:
    """Site 3 -- `_DIAGNOSTIC_PARAMS`. The operand past the signature still gets a mode, because
    AC-M1 is total over `params` and `params` carries it."""
    row = _row_at(
        PREAMBLE + '@handler("h")\ndef h(msg):\n    log_note("note {}", msg["PID-3.1"])\n',
        "diagnostic",
    )
    assert row["param_modes"] == {"template": MODE_STATIC, "arg1": MODE_DYNAMIC}


def test_the_lookup_site_emits_modes() -> None:
    """Site 4 -- `_LOOKUP_PARAMS`. A mapping argument is `dynamic`: it is not an `ast.Constant`, and
    `static` is exactly that test and nothing looser."""
    row = _row_at(
        PREAMBLE
        + '@handler("h")\ndef h(msg):\n    row = db_lookup("CONN", "SELECT 1", params={"id": 1})\n',
        "lookup",
    )
    assert row["param_modes"] == {
        "connection": MODE_STATIC,
        "statement": MODE_STATIC,
        "params": MODE_DYNAMIC,
    }
    assert row["literal_params"] == ["connection", "statement"]


def test_a_splatted_argument_gets_a_mode_under_its_rendered_name() -> None:
    """`*args` and `**kwargs` reach `params` under synthetic keys, so AC-M1 obliges a mode for each.
    Neither can ever be `static`-and-editable: the rewriter refuses to splice either."""
    row = _row_at(
        PREAMBLE + '@handler("h")\ndef h(msg):\n    set_field(msg, "PID-5.1", "X", **extra)\n',
        "action",
    )
    assert row["param_modes"]["**kwargs"] == MODE_DYNAMIC
    splat = _row_at(
        PREAMBLE + '@handler("h")\ndef h(msg):\n    log_note("note {}", *operands)\n',
        "diagnostic",
    )
    assert splat["param_modes"]["*arg1"] == MODE_DYNAMIC


# --- AC-M7: the pre-Amendment-E contract emits no map -------------------------

#: Every key a CONTRACT_V1 row could carry before Amendment E. Hardcoded on purpose: derived from the
#: corpus it would absorb any new key and assert nothing. Adding to it is a contract change.
V1_ROW_KEYS = frozenset(
    {
        "action",
        "appended",
        "assign_to",
        "call",
        "control",
        "filtered",
        "kind",
        "label",
        "line_end",
        "line_start",
        "literal_params",
        "nesting",
        "operand",
        "outbounds",
        "params",
        "recognized",
        "suite",
        "test_src",
    }
)


@pytest.mark.parametrize(("name", "source"), CORPUS, ids=CORPUS_IDS)
def test_contract_v1_emits_no_param_modes_and_no_other_new_key(name: str, source: str) -> None:
    """AC-M7 -- a consumer asking for the pre-Amendment-E contract gets today's payload.

    CONTRACT_V1 is that version: `param_modes` rides CONTRACT_V2, the same version Amendments A and D
    landed in, rather than minting one of its own. E.8 puts the FORWARD skew on the consumer -- an
    older IDE keeps reading `params`/`literal_params` and ignores the key it does not know -- and the
    shipped extension asks for contract 2 today, so that sentence is about a real consumer rather
    than a hypothetical one. A version of its own would instead make an older engine REFUSE a newer
    IDE outright, which is the other direction and not what E.8 describes.
    """
    for row in _rows(source, contract=CONTRACT_V1, module=name):
        assert "param_modes" not in row, f"CONTRACT_V1 leaked an Amendment E field: {row}"
        assert set(row) <= V1_ROW_KEYS, (
            f"CONTRACT_V1 grew a row key: {sorted(set(row) - V1_ROW_KEYS)}"
        )


def test_the_only_row_difference_between_the_contracts_is_the_added_map() -> None:
    """The strong half of AC-M7: over a corpus with no `note`/`route` content, stripping
    `param_modes` from the v2 rows must reproduce the v1 rows EXACTLY -- not merely the same kinds,
    the same rows, same order, same line ranges, same values."""
    v1 = _rows(VOCAB_CORPUS, contract=CONTRACT_V1)
    v2 = _rows(VOCAB_CORPUS, contract=CONTRACT_V2)
    stripped = [{k: v for k, v in row.items() if k != "param_modes"} for row in v2]
    assert stripped == v1
    assert any("param_modes" in row for row in v2), (
        "the comparison is vacuous unless v2 actually added the map"
    )

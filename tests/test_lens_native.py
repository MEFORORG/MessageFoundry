# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Recognition-first lens (ADR 0089 Phase A) — native ``Message``-API write idioms render as the SAME
editable ``action`` rows as ADR 0076's wrapper vocabulary, WITHOUT the module being rewritten.

Two properties, mirroring the ADR 0076 lens tests:

* **Recognition** — each native form (``msg.set(path, lit)``, ``msg.set(dst, msg.field(src)[ or ""])``,
  ``msg.set(path, expr)``, ``msg.delete_segments(id)``) becomes the expected action row + params +
  literal_params; ``occurrence=`` is captured read-only; false positives (``msg.setState``, wrong
  arity, non-``msg`` receiver, ``msg.set`` nested in a bigger expression) fall to ``code`` rows; the
  wrapper forms still classify unchanged; the coverage partition holds on a mixed body.
* **Rewrite / byte-stability (gate 2)** — editing ``path``/``value`` of a native ``msg.set`` splices only
  those bytes; every other byte (``occurrence=``, comments, trailing, the multi-byte non-ASCII path)
  is preserved, the result re-parses and round-trips.
"""

from __future__ import annotations

import ast
from typing import Any

import pytest

from messagefoundry.lens import LensRewriteError, parse_source, rewrite_source


def _handler_def_ranges(source: str) -> dict[str, tuple[int, int]]:
    """Independently (of the lens) derive each ``@handler`` def body's ``(first_stmt_line, end_line)``."""
    tree = ast.parse(source)
    out: dict[str, tuple[int, int]] = {}
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and getattr(dec.func, "id", None) == "handler":
                name = (
                    dec.args[0].value
                    if dec.args and isinstance(dec.args[0], ast.Constant)
                    else node.name
                )
                assert node.end_lineno is not None
                out[name] = (node.body[0].lineno, node.end_lineno)
    return out


def _assert_partition(rows: list[dict[str, Any]], body_start: int, body_end: int) -> None:
    """The rows exactly partition ``[body_start, body_end]`` — ordered, contiguous, non-overlapping."""
    assert rows, "expected at least one row for a non-empty def body"
    assert rows == sorted(rows, key=lambda r: r["line_start"]), "rows must be in source order"
    assert rows[0]["line_start"] == body_start
    assert rows[-1]["line_end"] == body_end
    for prev, nxt in zip(rows, rows[1:], strict=False):
        assert prev["line_end"] + 1 == nxt["line_start"], f"gap/overlap between {prev} and {nxt}"


def _rows(source: str, handler: str) -> list[dict[str, Any]]:
    """Parse ``source``, assert the coverage partition for ``handler``, and return its rows."""
    contract = next(c for c in parse_source(source, module="native.py") if c["handler"] == handler)
    body_start, body_end = _handler_def_ranges(source)[handler]
    _assert_partition(contract["rows"], body_start, body_end)
    return contract["rows"]


def _one_row(body: str, handler: str = "h") -> dict[str, Any]:
    """A single-statement handler wrapping ``body`` (the statement under test) + a trailing send; the
    body's row (index 0)."""
    src = (
        "from messagefoundry import handler, Send\n\n\n"
        f'@handler("{handler}")\n'
        f"def {handler}(msg):\n"
        f"    {body}\n"
        '    return Send("OB", msg)\n'
    )
    return _rows(src, handler)[0]


# --- recognition: the four native forms --------------------------------------


def test_native_set_field_literal_both_editable() -> None:
    # Form (1): msg.set("PATH", <literal>) -> set_field, path + value BOTH literal (editable).
    row = _one_row('msg.set("MSH-11.1", "T")')
    assert row["kind"] == "action"
    assert row["action"] == "set_field"
    assert row["params"] == {"path": "MSH-11.1", "value": "T"}
    assert row["literal_params"] == ["path", "value"]


def test_native_set_field_expression_value_path_only_editable() -> None:
    # Form (2): value is not a literal -> set_field, params carry the verbatim value source, but only
    # `path` is a literal_param (value is an expression, read-only for now).
    row = _one_row('msg.set("PV1-2", simplified)')
    assert row["action"] == "set_field"
    assert row["params"] == {"path": "PV1-2", "value": "simplified"}
    assert row["literal_params"] == ["path"]


def test_native_set_field_nonliteral_path_is_read_only() -> None:
    # If the path itself is a non-literal expression, path is read-only too (no literal_params).
    row = _one_row("msg.set(path_var, value_var)")
    assert row["action"] == "set_field"
    assert row["params"] == {"path": "path_var", "value": "value_var"}
    assert row["literal_params"] == []


def test_native_copy_field_or_default_idiom() -> None:
    # Form (3): msg.set(dst, msg.field(src) or "") -> copy_field with src/dst.
    row = _one_row('msg.set("NK1-2.1", msg.field("PID-5.1") or "")')
    assert row["action"] == "copy_field"
    assert row["params"] == {"src": "PID-5.1", "dst": "NK1-2.1"}
    assert row["literal_params"] == ["src", "dst"]


def test_native_copy_field_bare_field() -> None:
    # Form (3) without the `or ""`: msg.set(dst, msg.field(src)) is still a copy_field.
    row = _one_row('msg.set("OBR-3", msg.field("ORC-3"))')
    assert row["action"] == "copy_field"
    assert row["params"] == {"src": "ORC-3", "dst": "OBR-3"}
    assert row["literal_params"] == ["src", "dst"]


def test_native_copy_field_nonliteral_src_dst() -> None:
    # A copy whose src/dst are expressions: still copy_field, but neither is a literal_param.
    row = _one_row("msg.set(dst_path, msg.field(src_path))")
    assert row["action"] == "copy_field"
    assert row["params"] == {"src": "src_path", "dst": "dst_path"}
    assert row["literal_params"] == []


def test_native_delete_segment() -> None:
    # Form (4): msg.delete_segments("SEG") -> delete_segment.
    row = _one_row('msg.delete_segments("ZZZ")')
    assert row["action"] == "delete_segment"
    assert row["params"] == {"segment_id": "ZZZ"}
    assert row["literal_params"] == ["segment_id"]


def test_native_delete_segment_singular_name() -> None:
    # The singular `delete_segment` alias is recognized too (ADR 0089 §2 "or delete_segment").
    row = _one_row('msg.delete_segment("ODS")')
    assert row["action"] == "delete_segment"
    assert row["params"] == {"segment_id": "ODS"}


def test_native_occurrence_kwarg_captured_read_only() -> None:
    # occurrence= (and any other kwarg) is captured as a bound/read-only param — present in params, but
    # NOT in literal_params (never editable in Phase A).
    row = _one_row('msg.set("OBX-5", "V", occurrence=i)')
    assert row["action"] == "set_field"
    assert row["params"] == {"path": "OBX-5", "value": "V", "occurrence": "i"}
    assert row["literal_params"] == ["path", "value"]  # occurrence excluded

    # A literal occurrence is likewise read-only (never promoted to an editable literal_param).
    row2 = _one_row('msg.set("OBX-5", "V", occurrence=2)')
    assert row2["params"] == {"path": "OBX-5", "value": "V", "occurrence": 2}
    assert "occurrence" not in row2["literal_params"]


# --- recognition: no false positives -----------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        'msg.setState("x")',  # msg.setXxx — attr is not exactly "set"
        'other.set("A", "B")',  # non-msg receiver
        'msg.set("A", "B", "C")',  # 3 positional args (not 2)
        'msg.set("A")',  # 1 positional arg (not 2)
        'msg.delete_segments("A", "B")',  # delete with wrong arity
        'wrapper_result = foo(msg.set("A", "B"))',  # msg.set nested in a bigger expression
        "msg.set(*args)",  # a *args splat defeats static arity
    ],
)
def test_native_false_positives_fall_to_code(body: str) -> None:
    row = _one_row(body)
    assert row["kind"] == "code", f"{body!r} should be a code row, got {row}"
    assert "action" not in row


def test_msg_set_in_boolop_statement_is_code() -> None:
    # `msg.set(...) or fallback()` as a statement is NOT a bare set — the whole expr is opaque.
    row = _one_row('msg.set("A", "B") or fallback()')
    assert row["kind"] == "code"


# --- recognition: wrapper forms unchanged + mixed-body partition -------------


def test_wrapper_forms_still_recognized() -> None:
    src = """\
from messagefoundry import handler, Send, set_field, copy_field, delete_segment


@handler("wrap")
def wrap(msg):
    set_field(msg, "PID-3.1", "NEW")
    copy_field(msg, "PID-5.1", "NK1-2.1")
    delete_segment(msg, "ZZZ")
    return Send("OB", msg)
"""
    rows = _rows(src, "wrap")
    assert [(r["kind"], r.get("action")) for r in rows] == [
        ("action", "set_field"),
        ("action", "copy_field"),
        ("action", "delete_segment"),
        ("send", None),
    ]
    assert rows[0]["params"] == {"path": "PID-3.1", "value": "NEW"}  # msg dropped
    assert rows[1]["params"] == {"src": "PID-5.1", "dst": "NK1-2.1"}


MIXED_NATIVE = """\
from messagefoundry import handler, Send


@handler("mixed")
def mixed(msg):
    msg.set("MSH-11.1", "T")
    x = compute_something(msg)
    if msg["MSH-9.1"] == "ADT":
        msg.set("EVN-1", msg.field("MSH-9.2") or "")
        msg.delete_segments("Z01")
    msg.set("PV1-2", local, occurrence=n)
    # a hand-written comment
    msg.set("PID-3.1", derive(msg))
    return Send("OB", msg)
"""


def test_mixed_native_body_partitions_and_classifies() -> None:
    rows = _rows(MIXED_NATIVE, "mixed")
    summary = [(r["kind"], r.get("control") or r.get("action"), r["nesting"]) for r in rows]
    assert summary == [
        ("action", "set_field", 0),
        ("code", None, 0),  # x = compute_something(msg)
        ("control", "if", 0),
        ("action", "copy_field", 1),
        ("action", "delete_segment", 1),
        ("action", "set_field", 0),  # occurrence kwarg
        ("code", None, 0),  # the standalone comment
        ("action", "set_field", 0),  # value = derive(msg) — expression value
        ("send", None, 0),
    ]
    # the occurrence-carrying set is path/value with occurrence bound read-only
    occ = rows[5]
    assert occ["params"] == {"path": "PV1-2", "value": "local", "occurrence": "n"}
    assert occ["literal_params"] == ["path"]
    # the expression-valued set exposes only path as editable
    assert rows[7]["literal_params"] == ["path"]


def test_semicolon_compound_native_coalesces_to_one_code_row() -> None:
    # Two native sets sharing one physical line must degrade to a SINGLE code row (coverage-partition
    # invariant — otherwise the rows double-count the shared line).
    src = """\
from messagefoundry import handler, Send


@handler("semi")
def semi(msg):
    msg.set("A", "1"); msg.set("B", "2")
    return Send("OB", msg)
"""
    rows = _rows(src, "semi")
    assert [r["kind"] for r in rows] == ["code", "send"]
    covered: set[int] = set()
    for row in rows:
        span = set(range(row["line_start"], row["line_end"] + 1))
        assert not (covered & span), "rows share a physical line"
        covered |= span


# --- rewrite / byte-stability (gate 2) ---------------------------------------


def _assert_only_line_changed(before: str, after: str, lineno: int, expected: str) -> None:
    bl, al = before.splitlines(), after.splitlines()
    assert len(bl) == len(al), "line count changed"
    for i in range(len(bl)):
        if i + 1 == lineno:
            assert al[i] == expected, f"line {lineno}: {al[i]!r} != {expected!r}"
        else:
            assert al[i] == bl[i], f"line {i + 1} changed unexpectedly: {bl[i]!r} -> {al[i]!r}"


NATIVE_SET = """\
from messagefoundry import handler, Send


@handler("h")
def h(msg):
    msg.set("PID-3.1", "OLD")
    return Send("OB", msg)
"""


def test_native_set_edit_path_and_value_touches_only_its_line() -> None:
    out = rewrite_source(
        NATIVE_SET,
        {
            "line_start": 6,
            "line_end": 6,
            "op": "set_params",
            "params": {"path": "PID-5.1", "value": "NEW"},
        },
    )
    _assert_only_line_changed(NATIVE_SET, out, 6, '    msg.set("PID-5.1", "NEW")')
    # Re-parses and a follow-up no-op is byte-stable.
    assert parse_source(out)[0]["rows"][0]["params"] == {"path": "PID-5.1", "value": "NEW"}
    assert (
        rewrite_source(out, {"line_start": 6, "line_end": 6, "op": "set_params", "params": {}})
        == out
    )


def test_native_set_edit_only_value() -> None:
    out = rewrite_source(
        NATIVE_SET,
        {"line_start": 6, "line_end": 6, "op": "set_params", "params": {"value": "T"}},
    )
    _assert_only_line_changed(NATIVE_SET, out, 6, '    msg.set("PID-3.1", "T")')


def test_native_noop_is_byte_identical() -> None:
    out = rewrite_source(
        NATIVE_SET, {"line_start": 6, "line_end": 6, "op": "set_params", "params": {}}
    )
    assert out == NATIVE_SET


def test_native_occurrence_kwarg_preserved_on_edit() -> None:
    # Editing path/value must splice ONLY those args — the occurrence=i kwarg and the trailing comment
    # survive byte-for-byte (the hard ADR 0089 invariant).
    src = (
        "from messagefoundry import handler, Send\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    msg.set("PID-3.1", "OLD", occurrence=i)  # in the loop\n'
        '    return Send("OB", msg)\n'
    )
    out = rewrite_source(
        src,
        {
            "line_start": 6,
            "line_end": 6,
            "op": "set_params",
            "params": {"path": "PID-5.1", "value": "NEW"},
        },
    )
    _assert_only_line_changed(
        src, out, 6, '    msg.set("PID-5.1", "NEW", occurrence=i)  # in the loop'
    )
    parse_source(out)  # re-parses (gate 3)


def test_native_occurrence_is_not_editable() -> None:
    src = (
        "from messagefoundry import handler, Send\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    msg.set("PID-3.1", "OLD", occurrence=i)\n'
        '    return Send("OB", msg)\n'
    )
    with pytest.raises(LensRewriteError, match="unknown or absent"):
        rewrite_source(
            src,
            {"line_start": 6, "line_end": 6, "op": "set_params", "params": {"occurrence": 2}},
        )


def test_native_set_non_ascii_value_edit() -> None:
    # A non-ASCII value + trailing comment: editing only the value must byte-preserve the multi-byte
    # path arg and the comment (byte-space splice, F1).
    src = (
        "from messagefoundry import handler, Send\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    msg.set("PID-5.1", "Frank")  # patient name\n'
        '    return Send("OB", msg)\n'
    )
    out = rewrite_source(
        src,
        {"line_start": 6, "line_end": 6, "op": "set_params", "params": {"value": "François"}},
    )
    _assert_only_line_changed(src, out, 6, '    msg.set("PID-5.1", "François")  # patient name')
    parse_source(out)


def test_native_expression_value_refuses_scalar_but_edits_path() -> None:
    # Form (2): value is an expression. A bare-scalar value edit is refused (would drop the expression);
    # the path edit still applies, and the value expression is byte-preserved.
    src = (
        "from messagefoundry import handler, Send\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    msg.set("PV1-2", simplified)\n'
        '    return Send("OB", msg)\n'
    )
    with pytest.raises(LensRewriteError, match="expression"):
        rewrite_source(
            src,
            {"line_start": 6, "line_end": 6, "op": "set_params", "params": {"value": "X"}},
        )
    out = rewrite_source(
        src, {"line_start": 6, "line_end": 6, "op": "set_params", "params": {"path": "PV1-3"}}
    )
    _assert_only_line_changed(src, out, 6, '    msg.set("PV1-3", simplified)')


def test_native_copy_field_edit_src_and_dst() -> None:
    # The copy form's src lives INSIDE the inner msg.field(...) arg; dst is the outer set's arg0. Editing
    # both must splice each in place and preserve the `or ""` idiom byte-for-byte.
    src = (
        "from messagefoundry import handler, Send\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    msg.set("NK1-2.1", msg.field("PID-5.1") or "")\n'
        '    return Send("OB", msg)\n'
    )
    out = rewrite_source(
        src,
        {
            "line_start": 6,
            "line_end": 6,
            "op": "set_params",
            "params": {"src": "PID-6.1", "dst": "NK1-3.1"},
        },
    )
    _assert_only_line_changed(src, out, 6, '    msg.set("NK1-3.1", msg.field("PID-6.1") or "")')
    parse_source(out)
    # A no-op round-trips byte-identically.
    assert (
        rewrite_source(src, {"line_start": 6, "line_end": 6, "op": "set_params", "params": {}})
        == src
    )


def test_native_delete_segment_edit() -> None:
    src = (
        "from messagefoundry import handler, Send\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    msg.delete_segments("Z01")\n'
        '    return Send("OB", msg)\n'
    )
    out = rewrite_source(
        src,
        {"line_start": 6, "line_end": 6, "op": "set_params", "params": {"segment_id": "Z02"}},
    )
    _assert_only_line_changed(src, out, 6, '    msg.delete_segments("Z02")')


def test_native_multiline_call_single_line_arg_edit() -> None:
    # A native msg.set spanning several lines: a single-line value arg is editable and only its line moves.
    src = """\
from messagefoundry import handler, Send


@handler("h")
def h(msg):
    msg.set(
        "PID-3.1",
        "OLD",
        occurrence=i,
    )
    return Send("OB", msg)
"""
    out = rewrite_source(
        src, {"line_start": 6, "line_end": 10, "op": "set_params", "params": {"value": "NEW"}}
    )
    bl, al = src.splitlines(), out.splitlines()
    assert [i + 1 for i in range(len(bl)) if bl[i] != al[i]] == [8]
    assert al[7] == '        "NEW",'
    parse_source(out)


def test_native_crlf_terminators_preserved_on_edit() -> None:
    src = (
        "from messagefoundry import handler, Send\r\n\r\n\r\n"
        '@handler("h")\r\n'
        "def h(msg):\r\n"
        '    msg.set("A", "1")\r\n'
        '    return Send("OB", msg)\r\n'
    )
    out = rewrite_source(
        src, {"line_start": 6, "line_end": 6, "op": "set_params", "params": {"value": "2"}}
    )
    # The \r\n terminators survive; only the value bytes changed.
    assert out == src.replace('msg.set("A", "1")', 'msg.set("A", "2")')

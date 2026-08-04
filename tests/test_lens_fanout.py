# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Steps-view accumulator Send fan-out (ADR 0104 copy-on-Send authoring).

The lens recognizes ``sends.append(Send(dest, msg))`` as an editable ``send`` action row (positioned AT
the append, not inside a ``return``), tags the ``sends = []`` init + bare ``return sends`` footer as
read-only scaffold, and authors the idiom via the ``insert_send`` / ``add_destination`` byte-stable ops —
while ``return Send(...)`` / ``return [Send, ...]`` / ``return []`` stay byte-identical for the estate.

Gates mirror ``test_lens_rewrite_v2``: (2) byte-preservation outside the edited span via an independent
oracle, (3) re-parse + ruff-format-clean, (4) coverage-partition holds, plus honest degradation and the
runtime equivalence (a NAME-built accumulator delivers identically to a returned list). Static-only for
parse/rewrite; the runtime tests use ``transform_one``."""

from __future__ import annotations

import ast
import subprocess
import sys

import pytest

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.wiring import (
    ConnectionSpec,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.lens import LensRewriteError, parse_source, rewrite_source
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.dryrun import transform_one

# --- helpers -----------------------------------------------------------------


def _wrap(body: str, *, imports: str = "handler, Send") -> str:
    """A minimal ``@handler`` module whose body is ``body`` (already 4-space indented)."""
    return f'from messagefoundry import {imports}\n\n\n@handler("H")\ndef H(msg):\n{body}'


def _rows(src: str) -> list[dict]:
    return parse_source(src)[0]["rows"]


def _shape(rows: list[dict]) -> list[tuple]:
    """(kind, scaffold-or-outbounds) per row — the recognition fingerprint."""
    return [(r["kind"], r.get("scaffold") or r.get("outbounds")) for r in rows]


def _keepends(src: str) -> list[str]:
    return src.splitlines(keepends=True)


def _assert_partition(source: str) -> None:
    """Every handler's rows still exactly tile its def body (gate 4)."""
    tree = ast.parse(source)
    ranges: dict[str, tuple[int, int]] = {}
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
                ranges[name] = (node.body[0].lineno, node.end_lineno)
    for contract in parse_source(source):
        rows = contract["rows"]
        body_start, body_end = ranges[contract["handler"]]
        assert rows
        assert rows == sorted(rows, key=lambda r: r["line_start"])
        assert rows[0]["line_start"] == body_start
        assert rows[-1]["line_end"] == body_end
        for prev, nxt in zip(rows, rows[1:], strict=False):
            assert prev["line_end"] + 1 == nxt["line_start"], f"gap/overlap: {prev} {nxt}"


def _ruff_format_clean(source: str) -> bool:
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "ruff", "format", "--check", "-"],
            input=source.encode("utf-8"),
            capture_output=True,
        )
    except (OSError, ValueError) as exc:  # pragma: no cover - env guard
        pytest.skip(f"ruff not runnable: {exc}")
    return proc.returncode == 0


def _assert_first_class(source: str) -> None:
    """Re-parses and stays ruff-format-clean (gate 3)."""
    ast.parse(source)
    assert _ruff_format_clean(source), "not ruff-format-clean"


def _send_row(src: str, dest: str) -> dict:
    return next(r for r in _rows(src) if r["kind"] == "send" and r.get("outbounds") == [dest])


# =============================================================================
# recognizer
# =============================================================================


def test_append_send_literal_dest_is_send_row() -> None:
    src = _wrap('    sends = []\n    sends.append(Send("OB_A", msg))\n    return sends\n')
    assert _shape(_rows(src)) == [
        ("code", "collector_init"),
        ("send", ["OB_A"]),
        ("code", "return_collector"),
    ]
    send = _rows(src)[1]
    assert send["appended"] is True  # discriminates a mid-body append from a terminal return-send
    assert "filtered" not in send  # an append is a real delivery, never the filter


def test_append_send_dynamic_dest_has_empty_outbounds() -> None:
    src = _wrap(
        "    sends = []\n    ob = pick(msg)\n    sends.append(Send(ob, msg))\n    return sends\n",
        imports="handler, Send, pick",
    )
    send = next(r for r in _rows(src) if r["kind"] == "send")
    assert send["outbounds"] == []  # dynamic destination — never fabricated
    assert "filtered" not in send


def test_scaffold_init_and_footer_tagged() -> None:
    src = _wrap('    sends = []\n    sends.append(Send("OB", msg))\n    return sends\n')
    rows = _rows(src)
    assert rows[0]["kind"] == "code" and rows[0]["scaffold"] == "collector_init"
    assert rows[-1]["kind"] == "code" and rows[-1]["scaffold"] == "return_collector"


def test_scaffold_init_tagged_even_with_a_preceding_statement() -> None:
    # A `sends = []` preceded by another statement still renders as its own muted scaffold row (tagged
    # before merge + kept standalone), not blended into a code block with the preceding line.
    src = _wrap(
        "    dest = pick(msg)\n    sends = []\n    sends.append(Send(dest, msg))\n    return sends\n",
        imports="handler, Send, pick",
    )
    assert _shape(_rows(src)) == [
        ("code", None),  # dest = pick(msg)
        ("code", "collector_init"),  # sends = []  — muted, standalone
        ("send", []),  # sends.append(Send(dest, msg))  — dynamic dest
        ("code", "return_collector"),  # return sends
    ]
    _assert_partition(src)


def test_full_accumulator_partitions_with_interleaved_transform() -> None:
    src = _wrap(
        "    sends = []\n"
        '    sends.append(Send("OB_A", msg))\n'
        '    msg.set("PID-3", "X")\n'
        '    sends.append(Send("OB_B", msg))\n'
        "    return sends\n"
    )
    assert _shape(_rows(src)) == [
        ("code", "collector_init"),
        ("send", ["OB_A"]),
        ("action", None),
        ("send", ["OB_B"]),
        ("code", "return_collector"),
    ]
    _assert_partition(src)


def test_nested_append_inside_for_is_send_row() -> None:
    src = _wrap(
        "    sends = []\n"
        '    for i in range(1, msg.count_segments("NK1") + 1):\n'
        '        sends.append(Send("OB", msg))\n'
        "    return sends\n"
    )
    sends = [r for r in _rows(src) if r["kind"] == "send"]
    assert len(sends) == 1 and sends[0]["outbounds"] == ["OB"] and sends[0]["nesting"] == 1
    _assert_partition(src)


# =============================================================================
# recognize-legacy (estate byte-identity)
# =============================================================================


@pytest.mark.parametrize(
    "body,expect",
    [
        ('    return Send("OB", msg)\n', ("send", ["OB"])),
        ('    return [Send("A", msg), Send("B", msg)]\n', ("send", ["A", "B"])),
        ("    return []\n", ("send", [])),
        # ADR 0108 §6 SHALLs `return ()` alongside `return []`, and lens.py recognizes both, but only
        # `return []` was pinned — the tuple half had no regression coverage at all (BACKLOG #341).
        ("    return ()\n", ("send", [])),
    ],
)
def test_legacy_return_forms_recognized_and_byte_identical(body: str, expect: tuple) -> None:
    src = _wrap(body)
    rows = _rows(src)
    assert len(rows) == 1 and (rows[0]["kind"], rows[0]["outbounds"]) == expect
    assert "appended" not in rows[0]  # a returned send is never flagged as an append
    # a no-op set_params round-trips byte-identically
    noop = rewrite_source(
        src,
        {
            "op": "set_params",
            "line_start": rows[0]["line_start"],
            "line_end": rows[0]["line_end"],
            "params": {},
        },
    )
    assert noop == src


def test_return_empty_is_filtered_not_scaffold() -> None:
    src = _wrap("    return []\n")
    row = _rows(src)[0]
    assert row["kind"] == "send" and row["filtered"] is True and "scaffold" not in row


# =============================================================================
# ops — insert_send / add_destination / set_params / delete / move
# =============================================================================


def test_insert_send_into_fresh_handler_lays_scaffolding() -> None:
    src = _wrap('    set_field(msg, "PID-3", "X")\n', imports="handler, set_field")
    action = next(r for r in _rows(src) if r["kind"] == "action")
    out = rewrite_source(
        src,
        {
            "op": "insert_send",
            "line_start": action["line_start"],
            "line_end": action["line_end"],
            "position": "after",
            "destination": "OB_A",
        },
    )
    assert "from messagefoundry import Send\n" in out  # import injected
    assert _shape(_rows(out)) == [
        ("code", "collector_init"),
        ("action", None),
        ("send", ["OB_A"]),
        ("code", "return_collector"),
    ]
    _assert_first_class(out)
    _assert_partition(out)


def test_insert_send_subsequent_is_append_only() -> None:
    src = _wrap('    sends = []\n    sends.append(Send("OB_A", msg))\n    return sends\n')
    send = _send_row(src, "OB_A")
    out = rewrite_source(
        src,
        {
            "op": "insert_send",
            "line_start": send["line_start"],
            "line_end": send["line_end"],
            "position": "after",
            "destination": "OB_B",
        },
    )
    # exactly one new append; no duplicate init/footer
    assert out.count("sends = []") == 1
    assert out.count("return sends") == 1
    assert out.count("sends.append(") == 2
    _assert_first_class(out)
    _assert_partition(out)


def test_insert_send_requires_a_destination() -> None:
    src = _wrap("    return []\n")
    with pytest.raises(LensRewriteError, match="destination"):
        rewrite_source(
            src, {"op": "insert_send", "line_start": 6, "line_end": 6, "destination": ""}
        )


def test_insert_send_refuses_preexisting_non_accumulator_local() -> None:
    src = _wrap("    sends = compute(msg)\n", imports="handler, Send, compute")
    row = _rows(src)[0]
    with pytest.raises(LensRewriteError, match="already binds a local"):
        rewrite_source(
            src,
            {
                "op": "insert_send",
                "line_start": row["line_start"],
                "line_end": row["line_end"],
                "destination": "OB",
            },
        )


def test_set_params_edits_append_destination_only() -> None:
    src = _wrap('    sends = []\n    sends.append(Send("OB_A", msg))\n    return sends\n')
    send = _send_row(src, "OB_A")
    out = rewrite_source(
        src,
        {
            "op": "set_params",
            "line_start": send["line_start"],
            "line_end": send["line_end"],
            "params": {"to": "OB_NEW"},
        },
    )
    assert 'sends.append(Send("OB_NEW", msg))' in out
    # only the destination literal changed; the rest of the file is byte-preserved
    assert out == src.replace('Send("OB_A", msg)', 'Send("OB_NEW", msg)')
    _assert_first_class(out)


def test_add_destination_converts_returned_single_send() -> None:
    src = _wrap('    return Send("OB_A", msg)\n')
    send = _send_row(src, "OB_A")
    out = rewrite_source(
        src,
        {
            "op": "add_destination",
            "line_start": send["line_start"],
            "line_end": send["line_end"],
            "destination": "OB_B",
        },
    )
    assert _shape(_rows(out)) == [
        ("code", "collector_init"),
        ("send", ["OB_A"]),
        ("send", ["OB_B"]),
        ("code", "return_collector"),
    ]
    _assert_first_class(out)
    _assert_partition(out)


def test_add_destination_converts_inline_return_list_verbatim() -> None:
    src = _wrap('    return [Send("A", msg, occurrence=2), Send("B", msg)]\n')
    send = next(r for r in _rows(src) if r["kind"] == "send")
    out = rewrite_source(
        src,
        {
            "op": "add_destination",
            "line_start": send["line_start"],
            "line_end": send["line_end"],
            "destination": "C",
        },
    )
    # each existing Send preserved byte-exact (incl. the occurrence= kwarg)
    assert 'sends.append(Send("A", msg, occurrence=2))' in out
    assert 'sends.append(Send("B", msg))' in out
    assert 'sends.append(Send("C", msg))' in out
    _assert_first_class(out)
    _assert_partition(out)


def test_add_destination_refuses_list_with_non_send() -> None:
    src = _wrap(
        '    return [Send("A", msg), SetState("k", 1)]\n', imports="handler, Send, SetState"
    )
    send = next(r for r in _rows(src) if r["kind"] == "send")
    with pytest.raises(LensRewriteError, match="non-Send"):
        rewrite_source(
            src,
            {
                "op": "add_destination",
                "line_start": send["line_start"],
                "line_end": send["line_end"],
                "destination": "C",
            },
        )


def test_add_destination_refuses_over_column_limit() -> None:
    # a return already near the limit overflows once wrapped as `sends.append(...)` (+ ~14 cols)
    long_dest = "OB_" + "X" * 82
    src = _wrap(f'    return Send("{long_dest}", msg)\n')
    send = next(r for r in _rows(src) if r["kind"] == "send")
    with pytest.raises(LensRewriteError, match="column"):
        rewrite_source(
            src,
            {
                "op": "add_destination",
                "line_start": send["line_start"],
                "line_end": send["line_end"],
                "destination": "OB_C",
            },
        )


def test_delete_append_preserves_siblings_and_scaffold() -> None:
    src = _wrap(
        "    sends = []\n"
        '    sends.append(Send("OB_A", msg))\n'
        '    sends.append(Send("OB_B", msg))\n'
        "    return sends\n"
    )
    send = _send_row(src, "OB_A")
    out = rewrite_source(
        src, {"op": "delete_row", "line_start": send["line_start"], "line_end": send["line_end"]}
    )
    assert 'Send("OB_A", msg)' not in out
    assert 'sends.append(Send("OB_B", msg))' in out
    assert "sends = []" in out and "return sends" in out
    _assert_first_class(out)
    _assert_partition(out)


def test_delete_last_append_leaves_empty_accumulator() -> None:
    src = _wrap('    sends = []\n    sends.append(Send("OB_A", msg))\n    return sends\n')
    send = _send_row(src, "OB_A")
    out = rewrite_source(
        src, {"op": "delete_row", "line_start": send["line_start"], "line_end": send["line_end"]}
    )
    # no coupled name-scrub: sends = []; return sends remain (→ an empty accumulator, FILTERED at
    # runtime). With no append left, the two lines coalesce into one opaque (read-only) code row —
    # honest, and Add→Send still recognizes the accumulator by AST and appends into it.
    assert "sends.append(" not in out
    assert "    sends = []\n" in out and "    return sends\n" in out
    _assert_first_class(out)
    # a subsequent insert_send re-recognizes the empty accumulator and appends (does not re-lay it)
    code_row = next(r for r in _rows(out) if r["kind"] == "code")
    out2 = rewrite_source(
        out,
        {
            "op": "insert_send",
            "line_start": code_row["line_start"],
            "line_end": code_row["line_end"],
            "position": "after",
            "destination": "OB_Z",
        },
    )
    assert out2.count("sends = []") == 1 and out2.count("return sends") == 1


def test_move_append_reorders_within_accumulator() -> None:
    src = _wrap(
        "    sends = []\n"
        '    sends.append(Send("OB_A", msg))\n'
        '    sends.append(Send("OB_B", msg))\n'
        "    return sends\n"
    )
    b = _send_row(src, "OB_B")
    out = rewrite_source(
        src,
        {
            "op": "move_row",
            "line_start": b["line_start"],
            "line_end": b["line_end"],
            "direction": "up",
        },
    )
    a_line = next(i for i, ln in enumerate(out.splitlines()) if "OB_A" in ln)
    b_line = next(i for i, ln in enumerate(out.splitlines()) if "OB_B" in ln)
    assert b_line < a_line  # B moved above A
    _assert_first_class(out)
    _assert_partition(out)


def test_scaffold_rows_are_read_only() -> None:
    src = _wrap('    sends = []\n    sends.append(Send("OB", msg))\n    return sends\n')
    rows = _rows(src)
    init, footer = rows[0], rows[-1]
    for row in (init, footer):
        with pytest.raises(LensRewriteError, match="read-only|'code' row"):
            rewrite_source(
                src,
                {
                    "op": "set_params",
                    "line_start": row["line_start"],
                    "line_end": row["line_end"],
                    "params": {"to": "X"},
                },
            )
        with pytest.raises(LensRewriteError, match="read-only|'code' row"):
            rewrite_source(
                src,
                {
                    "op": "delete_row",
                    "line_start": row["line_start"],
                    "line_end": row["line_end"],
                },
            )


def test_add_send_to_filter_return_converts_it() -> None:
    src = _wrap("    return []\n")
    row = _rows(src)[0]
    out = rewrite_source(
        src,
        {
            "op": "insert_send",
            "line_start": row["line_start"],
            "line_end": row["line_end"],
            "destination": "OB_A",
        },
    )
    assert _shape(_rows(out)) == [
        ("code", "collector_init"),
        ("send", ["OB_A"]),
        ("code", "return_collector"),
    ]
    _assert_first_class(out)


def test_add_send_refuses_non_send_return() -> None:
    src = _wrap("    return None\n", imports="handler, Send")
    row = _rows(src)[0]
    with pytest.raises(LensRewriteError, match="can't be extended"):
        rewrite_source(
            src,
            {
                "op": "insert_send",
                "line_start": row["line_start"],
                "line_end": row["line_end"],
                "destination": "OB",
            },
        )


# =============================================================================
# degradation ladder (ADR 0089 §4 — honest, read-only code rows)
# =============================================================================


@pytest.mark.parametrize(
    "stmt",
    [
        'sends.append(Send("A", msg), extra)',  # extra positional
        "sends.append(foo(msg))",  # not a Send
        "sends.append(SetState(1))",  # not a Send
        'self.sends.append(Send("A", msg))',  # attribute receiver
        'box[0].append(Send("A", msg))',  # subscript receiver
        'sends.append(Send("A", msg), key=1)',  # keyword arg
        "sends.append(*items)",  # splat
    ],
)
def test_out_of_grammar_append_degrades_to_code(stmt: str) -> None:
    src = _wrap(
        f"    sends = []\n    {stmt}\n    return sends\n",
        imports="handler, Send, foo, SetState, items",
    )
    # nothing is a recognized send: the out-of-grammar append, the init, and the bare return all stay
    # read-only code rows (which coalesce), so no send row is emitted and no scaffold is tagged.
    rows = _rows(src)
    assert all(r["kind"] == "code" for r in rows)
    assert not any("scaffold" in r for r in rows)


@pytest.mark.parametrize(
    "init",
    ["sends = [x]", "sends = f()", "sends = ()"],
)
def test_non_empty_or_wrong_init_is_untagged(init: str) -> None:
    src = _wrap(
        f'    {init}\n    sends.append(Send("A", msg))\n    return sends\n',
        imports="handler, Send, x, f",
    )
    init_row = _rows(src)[0]
    assert init_row["kind"] == "code" and "scaffold" not in init_row


def test_stray_empty_list_without_append_is_untagged() -> None:
    src = _wrap("    buf = []\n    return []\n")
    buf_row = _rows(src)[0]
    assert buf_row["kind"] == "code" and "scaffold" not in buf_row


def test_return_name_without_recognized_append_is_untagged() -> None:
    src = _wrap("    other = build(msg)\n    return other\n", imports="handler, build")
    footer = _rows(src)[-1]
    assert footer["kind"] == "code" and "scaffold" not in footer


# =============================================================================
# round-trip / byte-stability
# =============================================================================


def test_insert_send_reparses_to_editable_send_row() -> None:
    src = _wrap('    set_field(msg, "PID-3", "X")\n', imports="handler, set_field")
    action = next(r for r in _rows(src) if r["kind"] == "action")
    out = rewrite_source(
        src,
        {
            "op": "insert_send",
            "line_start": action["line_start"],
            "line_end": action["line_end"],
            "position": "after",
            "destination": "OB_A",
        },
    )
    send = _send_row(out, "OB_A")
    # editing the inserted append's destination round-trips (proves it is first-class editable)
    out2 = rewrite_source(
        out,
        {
            "op": "set_params",
            "line_start": send["line_start"],
            "line_end": send["line_end"],
            "params": {"to": "OB_Z"},
        },
    )
    assert 'sends.append(Send("OB_Z", msg))' in out2


def test_ops_byte_stable_outside_edited_range() -> None:
    src = _wrap(
        "    sends = []\n"
        '    sends.append(Send("OB_A", msg))\n'
        '    sends.append(Send("OB_B", msg))\n'
        "    return sends\n"
    )
    # deleting the OB_A append must leave every other physical line byte-identical
    a = _send_row(src, "OB_A")
    out = rewrite_source(
        src, {"op": "delete_row", "line_start": a["line_start"], "line_end": a["line_end"]}
    )
    src_lines = _keepends(src)
    expected = "".join(src_lines[: a["line_start"] - 1] + src_lines[a["line_end"] :])
    assert out == expected


def test_accumulator_ops_preserve_crlf() -> None:
    src = _wrap('    return Send("OB_A", msg)\r\n').replace("\n", "\r\n")
    send = next(r for r in _rows(src) if r["kind"] == "send")
    out = rewrite_source(
        src,
        {
            "op": "add_destination",
            "line_start": send["line_start"],
            "line_end": send["line_end"],
            "destination": "OB_B",
        },
    )
    assert "\r\n" in out and "\n\n" not in out.replace("\r\n", "")  # terminators preserved
    ast.parse(out)


# =============================================================================
# runtime equivalence (the load-bearing claim: accumulator == returned list)
# =============================================================================

_ADT = (
    "MSH|^~\\&|SENDA|SENDF|RECV|RFAC|20200101||ADT^A01^ADT_A01|MSG1|P|2.5\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


def _two_ob_registry(handler) -> Registry:  # type: ignore[no-untyped-def]
    reg = Registry()
    for name in ("OB_A", "OB_B"):
        reg.add_outbound(
            OutboundConnection(
                name,
                ConnectionSpec(ConnectorType.FILE, {"directory": ".", "filename": "{MSH-10}.hl7"}),
            )
        )
    reg.add_handler("H", handler)
    return reg


def test_accumulator_delivers_identically_to_returned_list() -> None:
    """An append-built accumulator delivers the SAME destinations/order as the equivalent returned list —
    ``_partition`` materialises whatever container it is handed and never inspects the collector name."""

    def _accumulator(msg):  # type: ignore[no-untyped-def]
        sends = []
        sends.append(Send("OB_A", msg))
        sends.append(Send("OB_B", msg))
        return sends

    def _returned_list(msg):  # type: ignore[no-untyped-def]
        return [Send("OB_A", msg), Send("OB_B", msg)]

    acc, _, _, _ = transform_one(_two_ob_registry(_accumulator), "H", _ADT, "hl7v2")
    lst, _, _, _ = transform_one(_two_ob_registry(_returned_list), "H", _ADT, "hl7v2")
    assert [d.to for d in acc] == [d.to for d in lst] == ["OB_A", "OB_B"]
    assert [Message.parse(d.payload).field("MSH-10") for d in acc] == [
        Message.parse(d.payload).field("MSH-10") for d in lst
    ]


def test_empty_accumulator_delivers_nothing() -> None:
    """``sends = []; return sends`` (the terminal state after deleting every append) delivers nothing —
    the honest FILTERED disposition, no coupled name-scrub needed."""

    def _empty(msg):  # type: ignore[no-untyped-def]
        sends = []
        return sends

    deliveries, _, _, _ = transform_one(_two_ob_registry(_empty), "H", _ADT, "hl7v2")
    assert deliveries == []


# =============================================================================
# adversarial-review regressions (accumulator must actually DELIVER; safe codegen)
# =============================================================================


def _ruff_clean(source: str) -> bool:
    return _ruff_format_clean(source)


def test_send_import_injected_above_handlers_with_trailing_top_level_import() -> None:
    """FANOUT-1: a stray top-level import BELOW the edited handler must not make the injected `Send` import
    land mid-file after the body splice — it goes at the top, ruff-format-clean (gate 3)."""
    src = (
        "from messagefoundry import handler\n\n\n"
        '@handler("A")\ndef A(msg):\n    set_field(msg, "PID-3", "x")\n\n\n'
        "import datetime\n\n\n"
        '@handler("B")\ndef B(msg):\n    return datetime.date.today()\n'
    )
    out = rewrite_source(
        src,
        {"op": "insert_send", "line_start": 6, "line_end": 6, "destination": "OB", "handler": "A"},
    )
    assert out.index("import Send") < out.index("def A")  # above every handler body
    assert _ruff_clean(out)
    ast.parse(out)


def test_convert_refuses_nested_guard_return() -> None:
    """A send/filter return that is a NESTED guard (`if bad: return []`), not a top-level terminal, is
    refused — converting it in place would move the fan-out into that branch."""
    src = _wrap(
        '    if bad(msg):\n        return []\n    set_field(msg, "A", "B")\n',
        imports="handler, Send, bad, set_field",
    )
    with pytest.raises(LensRewriteError, match="can't be extended"):
        rewrite_source(
            src, {"op": "insert_send", "line_start": 7, "line_end": 7, "destination": "OB"}
        )


def test_add_send_refuses_rebound_accumulator() -> None:
    """A `sends` that is REBOUND (assigned twice) is not a clean delivering accumulator, so the op refuses
    rather than splice an append into a non-list `sends` (a runtime AttributeError)."""
    src = _wrap(
        "    sends = []\n    sends = other(msg)\n    return sends\n", imports="handler, Send, other"
    )
    row = _rows(src)[0]  # the whole body coalesces into one read-only code row
    with pytest.raises(LensRewriteError):
        rewrite_source(
            src,
            {
                "op": "insert_send",
                "line_start": row["line_start"],
                "line_end": row["line_end"],
                "destination": "OB",
            },
        )


def test_orphan_append_not_returned_degrades_to_code() -> None:
    """An `append(Send(...))` into a list the handler never returns does not deliver, so it is a read-only
    code row (not a send) and its `NAME = []` is not tagged scaffold."""
    src = _wrap('    junk = []\n    junk.append(Send("A", msg))\n    return []\n')
    rows = _rows(src)
    assert not any(
        r["kind"] == "send" and r.get("appended") for r in rows
    )  # no visible append-send
    assert not any("scaffold" in r for r in rows)
    # the real `return []` filter is still recognized
    assert any(r["kind"] == "send" and r.get("filtered") for r in rows)


def test_convert_refuses_nonempty_tuple_return() -> None:
    """A non-empty tuple return DELIVERS at runtime since BACKLOG #341, so converting it up would be
    delivery-neutral rather than the 0→N flip ADR 0108 §7 refused it for. The refusal stands on
    conservative scope — the palette never authors this form, and enabling the rewrite carries its own
    byte-stability obligations — so this pins the refusal, not the superseded reason."""
    src = _wrap('    return (Send("A", msg), Send("B", msg))\n')
    row = next(r for r in _rows(src) if r["kind"] == "send")
    with pytest.raises(LensRewriteError, match="can't be extended"):
        rewrite_source(
            src,
            {
                "op": "add_destination",
                "line_start": row["line_start"],
                "line_end": row["line_end"],
                "destination": "C",
            },
        )


def test_append_from_nested_anchor_lands_top_level() -> None:
    """Adding a send while a NESTED (in-loop) row is the anchor lands the append at the accumulator's own
    top-level indent, before the footer — one delivery per message, valid + ruff-clean (F2)."""
    src = _wrap(
        "    sends = []\n    for i in range(3):\n        transform(msg, i)\n    return sends\n",
        imports="handler, Send, transform",
    )
    out = rewrite_source(
        src,
        {
            "op": "insert_send",
            "line_start": 8,
            "line_end": 8,
            "position": "after",
            "destination": "OB",
        },
    )
    assert '    sends.append(Send("OB", msg))\n' in out  # top-level (4-space) indent, not 8-space
    assert _ruff_clean(out)
    # re-parses to a top-level (nesting 0) send row
    send = _send_row(out, "OB")
    assert send["nesting"] == 0


def test_destination_with_double_quote_stays_ruff_clean() -> None:
    """FANOUT-2: a destination containing a `"` renders via ruff's escape-avoidance (single quotes), so the
    op output stays ruff-format-clean (gate 3)."""
    src = _wrap('    return Send("OB_A", msg)\n')
    row = next(r for r in _rows(src) if r["kind"] == "send")
    out = rewrite_source(
        src,
        {
            "op": "add_destination",
            "line_start": row["line_start"],
            "line_end": row["line_end"],
            "destination": 'A"B',
        },
    )
    assert _ruff_clean(out)
    ast.parse(out)


def test_closure_only_append_is_not_tagged_scaffold() -> None:
    """An append that lives only in a nested closure is not a visible send row, so the outer `sends = []` /
    `return sends` are not tagged scaffold (F2 nested-closure)."""
    src = _wrap(
        '    sends = []\n\n    def cb():\n        sends.append(Send("A", msg))\n\n    return sends\n'
    )
    rows = _rows(src)
    assert not any("scaffold" in r for r in rows)

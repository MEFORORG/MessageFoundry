# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0089 Phase A row 4 (BACKLOG #1505): ``name = msg.field(path)`` renders as a Read Field row.

Three properties:

* **Recognition.** A single-name assignment from ``msg.field(<path>)`` becomes a ``read_field``
  ``action`` row. ``path`` is its one slot, editable while it is a literal. The bound name rides
  read-only as ``assign_to``, the field ``lookup`` rows already use. Keyword args (``occurrence=``,
  ``repetition=``) are display-only.
* **No false positives.** Every other shape stays a ``code`` row: tuple, attribute, subscript and
  chained targets, an annotated or augmented assignment, the ``or ""`` default, a wrong arity, a splat,
  a non-``msg`` receiver, a bare ``msg.field(...)`` statement, and any read inside a ``@router``.
* **Byte-stable rewrite (gate 2).** A ``path`` edit splices only the path bytes. The target name,
  the kwargs, a trailing comment and the line terminators survive, and the bound name and the kwargs
  cannot be edited at all.
"""

from __future__ import annotations

from typing import Any

import pytest

from messagefoundry.lens import (
    CONTRACT_V2,
    LensRewriteError,
    parse_source,
    rewrite_source,
)


def _src(body: str, *, nl: str = "\n") -> str:
    """A one-statement handler: ``body`` on line 6, then a send on line 7."""
    return nl.join(
        [
            "from messagefoundry import handler, Send",
            "",
            "",
            '@handler("h")',
            "def h(msg):",
            f"    {body}",
            '    return Send("OB", msg)',
            "",
        ]
    )


def _row(body: str, *, contract: int = 1) -> dict[str, Any]:
    rows = parse_source(_src(body), contract=contract)[0]["rows"]
    assert rows[0]["line_start"] == rows[0]["line_end"] == 6, rows
    return rows[0]


def _edit(src: str, params: dict[str, Any]) -> str:
    return rewrite_source(
        src, {"line_start": 6, "line_end": 6, "op": "set_params", "params": params}
    )


# --- recognition -------------------------------------------------------------


def test_read_field_literal_path_is_an_editable_action_row() -> None:
    row = _row('name = msg.field("PID-5.1")')
    assert row["kind"] == "action"
    assert row["action"] == "read_field"
    assert row["params"] == {"path": "PID-5.1"}
    assert row["literal_params"] == ["path"]
    assert row["assign_to"] == "name"


def test_read_field_kwargs_are_display_only() -> None:
    row = _row('value = msg.field("OBX-5", occurrence=i, repetition=2)')
    assert row["action"] == "read_field"
    assert row["params"] == {"path": "OBX-5", "occurrence": "i", "repetition": 2}
    assert row["literal_params"] == ["path"]  # neither kwarg, even the literal one
    assert row["assign_to"] == "value"


def test_read_field_nonliteral_path_is_a_row_with_a_read_only_path() -> None:
    # The same rule as a native ``msg.set(path_var, ...)``: the row renders, the slot is not offered.
    row = _row('name = msg.field(f"OBX-{i}")')
    assert row["action"] == "read_field"
    assert row["literal_params"] == []
    assert row["assign_to"] == "name"


def test_read_field_param_modes_ride_contract_v2() -> None:
    row = _row('name = msg.field("PID-5.1", occurrence=i)', contract=CONTRACT_V2)
    assert set(row["param_modes"]) == set(row["params"]) == {"path", "occurrence"}
    assert row["param_modes"]["path"] == "static"


@pytest.mark.parametrize(
    "body",
    [
        'msg.field("PID-5.1")',  # a bare read binds nothing
        'a, b = msg.field("PID-5.1")',  # tuple target
        'obj.attr = msg.field("PID-5.1")',  # attribute target
        'cache["k"] = msg.field("PID-5.1")',  # subscript target
        'a = b = msg.field("PID-5.1")',  # chained targets
        'name: str | None = msg.field("PID-5.1")',  # annotated assignment
        'name += msg.field("PID-5.1")',  # augmented assignment
        'name = msg.field("PID-5.1") or ""',  # the default idiom changes the value
        'name = msg.field("PID-5.1").strip()',  # a read inside a bigger expression
        "name = msg.field()",  # no path
        'name = msg.field("PID-5.1", "extra")',  # two positionals
        "name = msg.field(*args)",  # positional splat
        'name = msg.field("PID-5.1", **kw)',  # keyword splat
        'name = other.field("PID-5.1")',  # not the msg receiver
        'name = msg.fields("PID-5.1")',  # a lookalike method
        'msg = msg.field("PID-5.1")',  # rebinding the receiver would shadow the message
    ],
)
def test_other_shapes_stay_code(body: str) -> None:
    row = _row(body)
    assert row["kind"] == "code", f"{body!r} should stay a code row, got {row}"


def test_a_read_in_a_router_stays_code() -> None:
    # Routers project at CONTRACT_V2 only. A router's only recognized simple statement is its
    # routing return (ADR 0076 §D.6), so a read there stays code.
    src = (
        "from messagefoundry import router" + "\n\n\n"
        '@router("r")\n'
        "def r(msg):\n"
        '    kind = msg.field("MSH-9.2")\n'
        '    return ["H"]\n'
    )
    rows = parse_source(src, contract=CONTRACT_V2)[0]["rows"]
    assert rows[0]["kind"] == "code"


# --- rewrite / byte-stability -------------------------------------------------


def test_path_edit_touches_only_the_path_bytes() -> None:
    src = _src('name = msg.field("PID-5.1", occurrence=i)  # family name')
    out = _edit(src, {"path": "PID-5.2"})
    assert out == src.replace('"PID-5.1"', '"PID-5.2"')
    row = parse_source(out)[0]["rows"][0]
    assert row["params"] == {"path": "PID-5.2", "occurrence": "i"}
    assert row["assign_to"] == "name"


def test_noop_is_byte_identical() -> None:
    src = _src('name = msg.field("PID-5.1")')
    assert _edit(src, {}) == src


def test_crlf_terminators_survive_a_path_edit() -> None:
    src = _src('name = msg.field("PID-5.1")', nl="\r\n")
    out = _edit(src, {"path": "PID-3.1"})
    assert out == src.replace('"PID-5.1"', '"PID-3.1"')


def test_non_ascii_before_the_path_splices_in_byte_space() -> None:
    src = _src('nómbre = msg.field("PID-5.1")')
    out = _edit(src, {"path": "PID-5.2"})
    assert out == src.replace('"PID-5.1"', '"PID-5.2"')


@pytest.mark.parametrize("param", ["assign_to", "name", "var", "occurrence"])
def test_the_bound_name_and_the_kwargs_are_not_editable(param: str) -> None:
    src = _src('name = msg.field("PID-5.1", occurrence=2)')
    with pytest.raises(LensRewriteError, match="unknown or absent"):
        _edit(src, {param: "x"})


# --- structure stays read-only: the row binds a name later statements use ----------

#: A read on line 6, its use on line 7, a guard block on lines 8-9, then the send.
BOUND = (
    "from messagefoundry import handler, Send\n\n\n"
    '@handler("h")\n'
    "def h(msg):\n"
    '    name = msg.field("PID-5.1")\n'
    '    msg.set("NK1-2.1", name)\n'
    "    if flag:\n"
    '        msg.set("PID-8", "U")\n'
    '    return Send("OB", msg)\n'
)


def test_delete_row_on_a_read_field_is_refused() -> None:
    # Deleting line 6 would leave ``name`` on line 7 unbound (a NameError at run time). A Steps cut is
    # this same op, so the refusal covers cut too.
    with pytest.raises(LensRewriteError, match="Read Field row binding 'name'"):
        rewrite_source(BOUND, {"line_start": 6, "line_end": 6, "op": "delete_row"})


@pytest.mark.parametrize(
    "move",
    [
        {"direction": "down"},  # below its use: UnboundLocalError
        {"direction": "up"},
        {"to_line_start": 7, "to_line_end": 7, "to_position": "after"},  # a drag below the use
        {"to_line_start": 9, "to_line_end": 9, "to_position": "after"},  # a drag into the if body
    ],
    ids=["down", "up", "drag-below-use", "drag-into-block"],
)
def test_move_row_on_a_read_field_is_refused(move: dict[str, Any]) -> None:
    with pytest.raises(LensRewriteError, match="Read Field row binding 'name'"):
        rewrite_source(BOUND, {"line_start": 6, "line_end": 6, "op": "move_row", **move})


def test_the_path_stays_editable_where_structure_is_refused() -> None:
    out = _edit(BOUND, {"path": "PID-5.2"})
    assert out == BOUND.replace('"PID-5.1"', '"PID-5.2"')


def test_insert_row_of_a_read_field_is_out_of_scope_and_refused() -> None:
    # Inserting a Read Field is not built (BACKLOG #1505 scope). The IDE offers no such item; a
    # hand-built spec is refused rather than guessed.
    with pytest.raises(LensRewriteError):
        rewrite_source(
            BOUND,
            {
                "line_start": 7,
                "line_end": 7,
                "op": "insert_row",
                "action": "read_field",
                "params": {"path": "PID-3.1"},
                "assign_to": "mrn",
            },
        )


def test_a_nonliteral_path_refuses_a_scalar_but_takes_an_expr() -> None:
    src = _src("name = msg.field(path_var)")
    with pytest.raises(LensRewriteError, match="currently an expression"):
        _edit(src, {"path": "PID-5.1"})
    out = _edit(src, {"path": {"expr": "other_var"}})
    assert out == src.replace("msg.field(path_var)", "msg.field(other_var)")

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The Lander's review of PR 2155 (Theia review finding R1), one test per finding.

Each finding is reproduced against the ``lens rewrite`` surface and paired with a control the lens
must still accept, so a refusal is attributable to the payload and not to a broken edit spec. The
findings are numbered as the review numbers them; S-4 is spike S-4's review of the same code.
"""

from __future__ import annotations

import ast
from typing import Any

import pytest

from messagefoundry.lens import LensRewriteError, rewrite_source

TYPED_ONLY = "typed-only mode"
REFUSED = "not a value a Steps edit may write"


def _edit(op: str, line: int, **extra: Any) -> dict[str, Any]:
    return {"op": op, "line_start": line, "line_end": line, **extra}


def _refused(src: str, edit: dict[str, Any], match: str = TYPED_ONLY, **kw: Any) -> None:
    with pytest.raises(LensRewriteError, match=match) as info:
        rewrite_source(src, edit, **kw)
    assert info.value.code == "refused"


# --- finding 1: a drop past code ---------------------------------------------------------------

_DROP = """\
@handler("H")
def h(msg):
    msg.set("A", "1")
    x = compute(msg)
    msg.set("B", "2")
    if msg.field("C"):
        msg.set("D", "3")
    return Send("OB", msg)
"""


@pytest.mark.parametrize(
    "edit",
    [
        # Down past the code row, by a drop and not a swap.
        _edit("move_row", 3, to_line_start=5, to_position="after"),
        # Up past it, into a typed block below it.
        _edit("move_row", 3, to_line_start=7, to_position="after"),
        # A typed row dropped from below the code row to above it.
        _edit("move_row", 5, to_line_start=3, to_position="before"),
    ],
    ids=["down", "into-block", "up"],
)
def test_finding_1_typed_only_refuses_a_drop_past_code(edit: dict[str, Any]) -> None:
    assert rewrite_source(_DROP, edit) != _DROP
    _refused(_DROP, edit, typed_only=True)


def test_decision_3_a_dynamic_row_is_not_dragged_across_code_to_a_typed_anchor() -> None:
    # Manager decision 2026-10-07 (G.6): code rows and dynamic rows keep their order and suite path.
    src = _DROP.replace('msg.set("A", "1")', 'msg.set("A", pick(msg))')
    edit = _edit("move_row", 3, to_line_start=5, to_position="after")
    assert rewrite_source(src, edit) != src
    _refused(src, edit, typed_only=True)


def test_finding_1_control_a_drop_that_crosses_no_code_is_accepted() -> None:
    edit = _edit("move_row", 5, to_line_start=7, to_position="after")
    out = rewrite_source(_DROP, edit, typed_only=True)
    assert '        msg.set("B", "2")\n' in out


# --- finding 2 and S-4: a row whose arguments or callee are code ------------------------------

_DYN = """\
@handler("H")
def h(msg):
    if msg.field("PID-3"):
        msg.set("PID-5", os.system("x"))
        msg.set("PID-6", "y")
    msg.set("A", "1")
    os.set_field(msg, "B", "2")
    set_field(other, "C", "3")
    set_field(msg, "D", "4")
    return Send(pick(msg), msg)
"""


@pytest.mark.parametrize(
    "edit",
    [
        _edit("move_row", 4, to_line_start=6, to_position="after"),  # out of its guard
        _edit("delete_row", 4),
        _edit("delete_row", 3),  # the guard holding it
        _edit("delete_row", 10),  # a send whose destination is computed
        _edit("move_row", 10, direction="up"),
        _edit("delete_row", 7),  # an attribute callee
        _edit("move_row", 7, direction="down"),
        _edit("delete_row", 8),  # a message argument that is not msg
        _edit("move_row", 8, direction="up"),
    ],
)
def test_finding_2_typed_only_refuses_a_row_with_code_in_its_arguments(
    edit: dict[str, Any],
) -> None:
    assert rewrite_source(_DYN, edit) != _DYN
    _refused(_DYN, edit, typed_only=True)


def test_finding_2_control_a_typed_row_still_deletes() -> None:
    assert 'msg.set("A", "1")' not in rewrite_source(_DYN, _edit("delete_row", 6), typed_only=True)
    assert 'set_field(msg, "D", "4")' not in rewrite_source(
        _DYN, _edit("delete_row", 9), typed_only=True
    )


@pytest.mark.parametrize("typed_only", [False, True])
def test_s4_set_params_refuses_a_message_argument_that_is_not_msg(typed_only: bool) -> None:
    edit = _edit("set_params", 8, params={"value": "Z"})
    _refused(_DYN, edit, match="message argument", typed_only=typed_only)
    ok = rewrite_source(_DYN, _edit("set_params", 9, params={"value": "Z"}), typed_only=typed_only)
    assert 'set_field(msg, "D", "Z")' in ok


# --- finding 3: a top-level binding a later row reads ------------------------------------------

_BIND = """\
@handler("H")
def h(msg):
    row = db_lookup("C", "select 1", {"a": 1})
    unused = db_lookup("C", "select 2", {"a": 1})
    msg.set("A", row)
    return Send("OB", msg)
"""


@pytest.mark.parametrize(
    "edit",
    [
        _edit("delete_row", 3),
        _edit("move_row", 3, to_line_start=5, to_position="after"),
        _edit("move_row", 5, to_line_start=3, to_position="before"),
    ],
    ids=["delete", "binding-below-use", "use-above-binding"],
)
def test_finding_3_typed_only_refuses_leaving_a_read_unbound(edit: dict[str, Any]) -> None:
    assert rewrite_source(_BIND, edit) != _BIND
    _refused(_BIND, edit, typed_only=True)


def test_finding_3_control_an_unread_binding_still_deletes() -> None:
    out = rewrite_source(_BIND, _edit("delete_row", 4), typed_only=True)
    assert "unused" not in out


# --- finding 4: a name imported only for the type checker --------------------------------------

_TC = """\
from typing import TYPE_CHECKING

from messagefoundry import Send, handler

if TYPE_CHECKING:
    from messagefoundry import db_lookup


@handler("H")
def h(msg):
    msg.set("A", "1")
    return Send("OB", msg)
"""


def _runtime_imports(src: str) -> set[str]:
    return {
        al.asname or al.name
        for node in ast.parse(src).body
        if isinstance(node, ast.ImportFrom)
        for al in node.names
    }


def test_finding_4_a_type_checking_import_does_not_count_as_in_scope() -> None:
    edit = _edit(
        "insert_row",
        12,
        position="before",
        action="db_lookup",
        params={"connection": "C", "statement": "select 1", "params": {"expr": "{}"}},
        assign_to="row",
    )
    assert "db_lookup" not in _runtime_imports(_TC)
    assert "db_lookup" in _runtime_imports(rewrite_source(_TC, edit))
    # Control: a runtime import is still found, so nothing is injected beside it.
    runtime = _TC.replace("import Send, handler", "import Send, db_lookup, handler")
    assert rewrite_source(runtime, edit).count("import db_lookup") == 1


# --- finding 5: a destination held in a local --------------------------------------------------

_DEST = """\
OB_DEST = "OB_X"


@handler("H")
def h(msg):
    dest = msg.field("MSH-5")
    if msg.field("A"):
        return Send(dest, msg)
    return Send(OB_DEST, msg)
"""


def test_finding_5_set_params_refuses_to_overwrite_a_destination_held_in_a_local() -> None:
    to = {"to": {"expr": '"OB"'}}
    _refused(_DEST, _edit("set_params", 8, params=to), match="computed by code")
    assert 'return Send("OB", msg)' in rewrite_source(_DEST, _edit("set_params", 9, params=to))


# --- finding 6: an unhashable lookup params key ------------------------------------------------


@pytest.mark.parametrize(
    ("expr", "ok"), [("{[1]: 1}", False), ("{(1, [2]): 1}", False), ('{"a": 1}', True)]
)
def test_finding_6_lookup_params_keys_must_be_hashable(expr: str, ok: bool) -> None:
    edit = _edit(
        "insert_row",
        6,
        position="before",
        action="db_lookup",
        params={"connection": "C", "statement": "select 1", "params": {"expr": expr}},
        assign_to="fresh",
    )
    if ok:
        assert expr in rewrite_source(_BIND, edit)
    else:
        _refused(_BIND, edit, match=REFUSED)


# --- finding 7: a module-level name that is not an inert literal -------------------------------

_MOD = """\
import os

SEEN = []
TAGS = ("a", "b")
LIMIT = 3
NEG = -1
SHOUT = "x"
FROZEN = frozenset({"a", "b"})
RAW = b"x"
CS = code_set("gender")
TOTAL = 0
TOTAL += 1
BOX = {"k": 1}


def keep(msg):  # type: ignore[no-untyped-def]
    SHOUT.upper()


@handler("H")
def h(msg):
    SEEN.append(msg.field("PID-3"))
    BOX["k"] = msg.field("PID-3")
    return Send("OB", msg)
"""
_MOD_SEND = 24


@pytest.mark.parametrize(
    ("name", "ok"),
    [
        ("SEEN", False),  # a list, filled from the message
        ("BOX", False),  # a dict, stored into
        ("TOTAL", False),  # augmented
        ("SHOUT", False),  # an attribute call on it
        ("RAW", False),  # bytes are excluded
        ("os", False),  # an import
        ("Send", False),  # an import that is not even bound here
        ("len", False),  # a builtin
        ("TAGS", True),
        ("LIMIT", True),
        ("NEG", True),
        ("FROZEN", True),
        ("CS", False),  # a code_set capture: only code_lookup's table takes one
    ],
)
def test_finding_7_only_an_unmutated_immutable_module_literal_is_inert(name: str, ok: bool) -> None:
    edit = _edit("set_params", _MOD_SEND, params={"to": {"expr": name}})
    if ok:
        assert f"return Send({name}, msg)" in rewrite_source(_MOD, edit)
    else:
        _refused(_MOD, edit, match=REFUSED)


# --- Manager decision 2026-10-07: a code_set capture is inert only as code_lookup's table ------

_CS = """\
GENDER = code_set("gender")


@handler("H")
def h(msg):
    msg.set("A", "1")
    code_lookup(msg, "PID-8", GENDER)
    return Send("OB", msg)
"""


@pytest.mark.parametrize(
    ("action", "params"),
    [
        ("checkpoint", {"label": {"expr": "GENDER"}}),
        ("log_note", {"template": {"expr": "GENDER"}}),
        ("set_field", {"path": "PID-3.1", "value": {"expr": "GENDER"}}),
    ],
)
def test_a_code_set_name_is_refused_outside_the_code_lookup_table(
    action: str, params: dict[str, Any]
) -> None:
    edit = _edit("insert_row", 8, position="before", action=action, params=params)
    _refused(_CS, edit, match=REFUSED)


def test_a_code_set_name_is_still_a_code_lookup_table() -> None:
    edit = _edit(
        "insert_row",
        8,
        position="before",
        action="code_lookup",
        params={"path": "PID-9", "table": {"expr": "GENDER"}},
    )
    assert 'code_lookup(msg, "PID-9", GENDER)' in rewrite_source(_CS, edit)
    # A typed code_lookup row stays typed, so typed-only still moves and deletes it.
    assert "code_lookup" not in rewrite_source(_CS, _edit("delete_row", 7), typed_only=True)
    moved = rewrite_source(_CS, _edit("move_row", 7, direction="up"), typed_only=True)
    assert moved.index("code_lookup") < moved.index('msg.set("A"')


# --- finding 8: a note row ---------------------------------------------------------------------


def test_finding_8_typed_only_still_deletes_a_note() -> None:
    src = '@handler("H")\ndef h(msg):\n    msg.set("A", "1")\n    # a note\n    return Send("OB", msg)\n'
    assert "# a note" not in rewrite_source(
        src, _edit("delete_row", 4), contract=2, typed_only=True
    )


# --- finding 9: the fan-out scaffold the lens writes itself ------------------------------------

_FAN = """\
@handler("H")
def h(msg):
    sends = []
    msg.set("A", "1")
    sends.append(Send("OB", msg))
    return sends
"""


@pytest.mark.parametrize(
    "edit",
    [
        _edit("move_row", 4, direction="up"),  # past the init: harmless
        _edit("move_row", 5, direction="up"),  # an append above a typed row
    ],
)
def test_finding_9_typed_only_moves_rows_around_the_scaffold(edit: dict[str, Any]) -> None:
    assert rewrite_source(_FAN, edit, typed_only=True) != _FAN


@pytest.mark.parametrize(
    "edit",
    [
        _edit("move_row", 5, to_line_start=3, to_position="before"),  # an append above its init
        _edit("move_row", 5, direction="down"),  # below the return
        _edit("move_row", 3, direction="down"),  # the scaffold itself
        _edit("delete_row", 6),
    ],
)
def test_finding_9_the_scaffold_itself_still_holds(edit: dict[str, Any]) -> None:
    with pytest.raises(LensRewriteError):
        rewrite_source(_FAN, edit, typed_only=True)


# --- finding 10: the FHIR import step ----------------------------------------------------------


def test_finding_10_an_assignment_target_is_not_an_import() -> None:
    edit = _edit(
        "insert_row",
        6,
        position="before",
        action="fhir_lookup",
        params={"connection": "EPIC", "query": "Patient", "params": {"expr": "{}"}},
        assign_to="FhirRaw",
    )
    assert "import FhirRaw" not in rewrite_source(_BIND, edit)


# --- finding 11: arithmetic on a name that may hold text ---------------------------------------

_ARITH = """\
LIMIT = 3
SHOUT = "x"


@handler("H")
def h(msg):
    pid5 = msg.field("PID-5")
    for i in range(1, msg.count_segments("OBX") + 1):
        pass
    return Send("OB", msg)
"""


@pytest.mark.parametrize(
    ("expr", "ok"),
    [
        ("-pid5", False),
        ("+pid5", False),
        ("pid5 + 1", False),
        ("SHOUT - 1", False),
        ("i + 1", True),
        ("LIMIT - 1", True),
        ("-LIMIT", True),
        ("pid5", True),
    ],
)
def test_finding_11_arithmetic_takes_numeric_names_only(expr: str, ok: bool) -> None:
    edit = _edit(
        "insert_row",
        10,
        position="before",
        action="set_field",
        params={"path": "PID-3.1", "value": {"expr": expr}},
    )
    if ok:
        assert expr in rewrite_source(_ARITH, edit)
    else:
        _refused(_ARITH, edit, match=REFUSED)

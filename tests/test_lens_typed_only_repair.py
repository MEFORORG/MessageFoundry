# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The Lander's review of PR 2155 (Theia review finding R1), one test per finding.

Each finding is reproduced against the ``lens rewrite`` surface and paired with a control the lens
must still accept, so a refusal is attributable to the payload and not to a broken edit spec. The
findings are numbered as the review numbers them; S-4 is spike S-4's review of the same code.
"""

from __future__ import annotations

import ast
import itertools
from typing import Any

import pytest

from messagefoundry import lens
from messagefoundry.lens import LensRewriteError, rewrite_source

TYPED_ONLY = "typed-only mode"
REFUSED = "not a value a Steps edit may write"
NEVER_RUNS = "never runs"


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
    if edit["op"] == "delete_row":
        assert rewrite_source(_BIND, edit) != _BIND
        _refused(_BIND, edit, typed_only=True)
    else:
        # A move that strands a read is refused in every mode (Manager decision 2026-10-07).
        for typed_only in (False, True):
            _refused(_BIND, edit, match="before anything binds", typed_only=typed_only)


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

from messagefoundry import code_set

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
_MOD_SEND = 26


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
from messagefoundry import code_set

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
    edit = _edit("insert_row", 10, position="before", action=action, params=params)
    _refused(_CS, edit, match=REFUSED)


def test_a_code_set_name_is_still_a_code_lookup_table() -> None:
    edit = _edit(
        "insert_row",
        10,
        position="before",
        action="code_lookup",
        params={"path": "PID-9", "table": {"expr": "GENDER"}},
    )
    assert 'code_lookup(msg, "PID-9", GENDER)' in rewrite_source(_CS, edit)
    # A typed code_lookup row stays typed, so typed-only still moves and deletes it.
    assert "code_lookup" not in rewrite_source(_CS, _edit("delete_row", 9), typed_only=True)
    moved = rewrite_source(_CS, _edit("move_row", 9, direction="up"), typed_only=True)
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


@pytest.mark.parametrize("expr", ["-pid5", "+pid5", "pid5 + 1", "SHOUT - 1"])
def test_finding_11_arithmetic_refuses_a_name_that_may_hold_text(expr: str) -> None:
    edit = _edit(
        "insert_row",
        10,
        position="before",
        action="set_field",
        params={"path": "PID-3.1", "value": {"expr": expr}},
    )
    _refused(_ARITH, edit, match=REFUSED)


@pytest.mark.parametrize("expr", ["i + 1", "i", "2 * 3"])
def test_finding_11_control_arithmetic_on_a_numeric_name_in_a_number_slot(expr: str) -> None:
    edit = _edit(
        "insert_row",
        9,
        position="before",
        action="set_field",
        params={"path": "OBX-3", "value": "x", "occurrence": {"expr": expr}},
    )
    assert f"occurrence={expr}" in rewrite_source(_ARITH, edit)


# --- review of head 513797260a ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("expr", "ok"),
    [("1 + 2", False), ("0", False), ("None", False), ('[{"a": 1}]', False), ("pid5", True)],
)
def test_r2_finding_5_a_field_value_must_be_text(expr: str, ok: bool) -> None:
    edit = _edit(
        "insert_row",
        10,
        position="before",
        action="set_field",
        params={"path": "PID-3.1", "value": {"expr": expr}},
    )
    if ok:
        assert f'msg.set("PID-3.1", {expr})' in rewrite_source(_ARITH, edit)
    else:
        with pytest.raises(LensRewriteError):
            rewrite_source(_ARITH, edit)


_GUARD = """\
@handler("H")
def h(msg):
    msg.set("A", "1")
    if msg.field("C"):
        msg.set("B", "2")
        raise ValueError("bad")
    if msg.field("D"):
        x = compute(msg)
    msg.set("E", "5")
    y = other(msg)
    return Send("OB", msg)
"""


@pytest.mark.parametrize(
    "edit",
    [
        # A guarded raise lifted out of its guard runs on every message.
        _edit("move_row", 6, to_line_start=3, to_position="before"),
        # A typed row dropped into a typed block that holds code.
        _edit("move_row", 9, to_line_start=8, to_position="before"),
    ],
    ids=["raise-out-of-guard", "into-block-with-code"],
)
def test_r2_findings_1_and_6_typed_only_keeps_guards_and_code_blocks(edit: dict[str, Any]) -> None:
    assert rewrite_source(_GUARD, edit) != _GUARD
    _refused(_GUARD, edit, typed_only=True)


def test_r2_finding_1_a_raise_reordered_up_its_guard_strands_the_row_it_passes() -> None:
    # Once a control; G.6 rule 8 now refuses it in typed-only mode (Manager decision 2026-10-08).
    edit = _edit("move_row", 6, direction="up")
    assert rewrite_source(_GUARD, edit) != _GUARD
    _refused(_GUARD, edit, match=NEVER_RUNS, typed_only=True)


def test_r2_finding_1_control_a_row_still_moves_in_above_a_guarded_raise() -> None:
    edit = _edit("move_row", 3, to_line_start=6, to_position="before")
    out = rewrite_source(_GUARD, edit, typed_only=True)
    assert '        msg.set("A", "1")\n        raise ValueError("bad")\n' in out


_COMP = """\
@handler("H")
def h(msg):
    codes = [r for r in msg.segments("OBX")]
    key = lambda r: r
    r = db_lookup("C", "select 1", {"a": 1})
    msg.set("A", r)
    return Send("OB", msg)
"""


@pytest.mark.parametrize(
    "edit",
    [_edit("delete_row", 5), _edit("move_row", 5, to_line_start=6, to_position="after")],
)
def test_r2_finding_2_a_comprehension_or_lambda_does_not_bind_for_the_handler(
    edit: dict[str, Any],
) -> None:
    _refused(_COMP, edit, match="typed-only mode|before anything binds", typed_only=True)


@pytest.mark.parametrize(
    "params",
    [
        {"path": "PID-3.1", "value": {"expr": "pid5"}},  # above its binding
        {"path": "PID-3.1", "value": {"expr": "nosuchname"}},  # bound nowhere
        {"path": "PID-3.1", "value": "x", "occurrence": {"expr": "i"}},  # outside its loop
    ],
)
@pytest.mark.parametrize("typed_only", [False, True])
def test_r2_finding_3_an_insert_reads_no_name_before_it_is_bound(
    params: dict[str, Any], typed_only: bool
) -> None:
    edit = _edit("insert_row", 7, position="before", action="set_field", params=params)
    with pytest.raises(LensRewriteError):
        rewrite_source(_ARITH, edit, typed_only=typed_only)
    below = _edit("insert_row", 10, position="before", action="set_field", params=params)
    if params["path"] == "PID-3.1" and params.get("value") == {"expr": "pid5"}:
        assert "pid5)" in rewrite_source(_ARITH, below, typed_only=typed_only)


_SHADOW = """\
import os

from messagefoundry import Send, handler


def set_field(msg, path, value):  # type: ignore[no-untyped-def]
    os.system(value)


class FhirToken:
    pass


@handler("H")
def h(msg):
    msg.set("A", "1")
    set_field(msg, "B", "2")
    return Send("OB", msg)
"""


def test_r2_finding_4_a_module_level_shadow_of_a_vocabulary_name_is_not_typed() -> None:
    _refused(_SHADOW, _edit("delete_row", 17), typed_only=True)
    _refused(_SHADOW, _edit("move_row", 17, direction="up"), typed_only=True)
    edit = _edit(
        "insert_row",
        18,
        position="before",
        action="fhir_lookup",
        params={
            "connection": "EPIC",
            "query": "Patient",
            "params": {"expr": '{"identifier": FhirToken("sys", msg["PID-3"] or "")}'},
        },
    )
    _refused(_SHADOW, edit, match=REFUSED)


def test_r2_finding_7_setattr_voids_every_inert_name() -> None:
    src = _DEST.replace(
        "    dest = msg.field",
        "    setattr(sys.modules[__name__], 'OB_DEST', 1)\n    dest = msg.field",
    )
    _refused(
        src,
        _edit("set_params", 10, params={"to": {"expr": "OB_DEST"}}),
        match=f"{REFUSED}|computed by code",
    )


def test_r2_finding_8_an_existing_compile_error_is_named_as_such() -> None:
    src = "def helper():  # type: ignore[no-untyped-def]\n    await thing()\n\n\n" + _DROP.replace(
        "    x = compute(msg)\n", ""
    )
    with pytest.raises(LensRewriteError, match="does not compile as it stands"):
        rewrite_source(src, _edit("delete_row", 7))


# --- review of PR 2154: the reads_ok path takes inert names and locals only ----------------------


@pytest.mark.parametrize(
    ("action", "params"),
    [
        ("db_lookup", {"connection": "C", "statement": "s", "params": {"expr": '{"a": SEEN}'}}),
        ("db_lookup", {"connection": "C", "statement": "s", "params": {"expr": '{"a": CS}'}}),
        ("set_field", {"path": "PID-3.1", "value": {"expr": "CS"}}),
        ("set_field", {"path": "PID-3.1", "value": {"expr": "SEEN"}}),
    ],
)
def test_the_reads_ok_path_refuses_mutable_and_code_set_names(
    action: str, params: dict[str, Any]
) -> None:
    edit = _edit("insert_row", _MOD_SEND, position="before", action=action, params=params)
    if action == "db_lookup":
        edit["assign_to"] = "fresh"
    _refused(_MOD, edit, match=REFUSED)


# --- Manager decisions 2026-10-07, third set ------------------------------------------------------

_ONCE = """\
from messagefoundry import code_set

TWICE = "a"
TWICE = "b"
ONCE = ("a", "b")
GENDER: CodeSet = code_set("gender")


@handler("H")
def h(msg):
    msg.set("A", "1")
    return Send("OB", msg)
"""


@pytest.mark.parametrize(("name", "ok"), [("TWICE", False), ("ONCE", True)])
def test_decision_a_module_name_bound_more_than_once_is_refused(name: str, ok: bool) -> None:
    edit = _edit("set_params", 12, params={"to": {"expr": name}})
    if ok:
        assert f"return Send({name}, msg)" in rewrite_source(_ONCE, edit)
    else:
        _refused(_ONCE, edit, match=REFUSED)


def _table(src: str, line: int) -> dict[str, Any]:
    return _edit(
        "insert_row",
        line,
        position="before",
        action="code_lookup",
        params={"path": "PID-8", "table": {"expr": "GENDER"}},
    )


def test_decision_an_annotated_code_set_capture_is_a_table() -> None:
    assert 'code_lookup(msg, "PID-8", GENDER)' in rewrite_source(_ONCE, _table(_ONCE, 12))


@pytest.mark.parametrize(
    "change",
    [
        # code_set is a local helper, not the vocabulary's
        (
            "from messagefoundry import code_set\n",
            "def code_set(name):  # type: ignore\n    return {}\n",
        ),
        # code_set comes from another module
        ("from messagefoundry import code_set\n", "from helpers import code_set\n"),
        # the capture is bound twice
        (
            'GENDER: CodeSet = code_set("gender")\n',
            'GENDER = code_set("a")\nGENDER = code_set("b")\n',
        ),
    ],
    ids=["local-def", "helper-import", "bound-twice"],
)
def test_decision_a_code_set_table_needs_one_binding_from_messagefoundry(
    change: tuple[str, str],
) -> None:
    src = _ONCE.replace(*change)
    line = src.splitlines().index('    return Send("OB", msg)') + 1
    _refused(src, _table(src, line), match=REFUSED)


_LOOP = """\
@handler("H")
def h(msg):
    for i in range(1, msg.count_segments("OBX") + 1):
        msg.set("OBX-11", "F", occurrence=i)
        msg.set("OBX-12", "G")
    msg.set("A", "1")
    return Send("OB", msg)
"""


@pytest.mark.parametrize("typed_only", [False, True])
@pytest.mark.parametrize(
    "edit",
    [
        _edit("move_row", 4, to_line_start=6, to_position="after"),
        _edit(
            "insert_row",
            7,
            position="before",
            action="set_field",
            params={"path": "OBX-3", "value": "x", "occurrence": {"expr": "i"}},
        ),
    ],
    ids=["move", "insert"],
)
def test_decision_a_loop_index_is_read_only_inside_its_loop(
    edit: dict[str, Any], typed_only: bool
) -> None:
    with pytest.raises(LensRewriteError):
        rewrite_source(_LOOP, edit, typed_only=typed_only)


def test_decision_control_a_loop_index_row_still_moves_inside_its_loop() -> None:
    out = rewrite_source(_LOOP, _edit("move_row", 4, direction="down"), typed_only=True)
    assert out.index('"OBX-12"') < out.index('"OBX-11"')


# --- review of head c172beda9c ------------------------------------------------------------------


@pytest.mark.parametrize("expr", ["i", "LIMIT"])
def test_r3_finding_1_a_numeric_name_is_not_a_field_value(expr: str) -> None:
    edit = _edit(
        "insert_row",
        9,
        position="before",
        action="set_field",
        params={"path": "OBX-3", "value": {"expr": expr}},
    )
    with pytest.raises(LensRewriteError, match="not text"):
        rewrite_source(_ARITH, edit)


@pytest.mark.parametrize("value", ["x", {"expr": "0"}, {"expr": "'x'"}, {"expr": "1/2"}])
def test_r3_finding_2_an_occurrence_is_a_whole_number(value: Any) -> None:
    edit = _edit(
        "insert_row",
        9,
        position="before",
        action="set_field",
        params={"path": "OBX-3", "value": "x", "occurrence": value},
    )
    with pytest.raises(LensRewriteError, match="not a whole number"):
        rewrite_source(_ARITH, edit)


_BRANCH = """\
@handler("H")
def h(msg):
    if msg.field("A"):
        x = msg.field("B")
    else:
        x = "none"
    with open("f") as fh:
        y = "z"
    return Send("OB", msg)
"""


@pytest.mark.parametrize("name", ["x"])
def test_r3_finding_3_a_name_every_branch_binds_is_bound_after_the_block(name: str) -> None:
    edit = _edit(
        "insert_row",
        9,
        position="before",
        action="set_field",
        params={"path": "PID-3.1", "value": {"expr": name}},
    )
    assert f'msg.set("PID-3.1", {name})' in rewrite_source(_BRANCH, edit)


def test_r3_finding_4_a_globals_dict_write_voids_every_inert_name() -> None:
    src = _DEST.replace(
        "    dest = msg.field", '    h.__globals__["OB_DEST"] = 1\n    dest = msg.field'
    )
    _refused(
        src,
        _edit("set_params", 10, params={"to": {"expr": "OB_DEST"}}),
        match=f"{REFUSED}|computed by code",
    )


def test_r3_finding_8_set_params_takes_the_handler_s_own_message_name() -> None:
    src = '@handler("H")\ndef h(message):\n    set_field(message, "A", "B")\n    return []\n'
    out = rewrite_source(src, _edit("set_params", 3, params={"value": "Z"}))
    assert 'set_field(message, "A", "Z")' in out


# --- ADR 0076 Amendment G, G.6 and G.7 as read on PR 2154 ---------------------------------------

_GLOBAL = """\
from messagefoundry import code_set

LAB = code_set("lab")
SEEN = []


def keep(msg):  # type: ignore[no-untyped-def]
    global LAB, SEEN


@handler("H")
def h(msg):
    LAB = 1
    SEEN = 2
    msg.set("A", "1")
    return Send("OB", msg)
"""


@pytest.mark.parametrize("name", ["LAB", "SEEN"])
def test_g7_a_global_declared_name_is_not_a_handler_local(name: str) -> None:
    edit = _edit(
        "insert_row",
        16,
        position="before",
        action="set_field",
        params={"path": "PID-3.1", "value": {"expr": name}},
    )
    _refused(_GLOBAL, edit, match=REFUSED)


@pytest.mark.parametrize(
    ("literal", "ok"),
    [
        ("frozenset()", False),
        ('("a", frozenset({"b"}))', False),
        ('("a", ("b", "c"))', False),
        ('frozenset({"a", "b"})', True),
        ('("a", -1, None)', True),
    ],
)
def test_g7_the_immutable_literal_ceiling(literal: str, ok: bool) -> None:
    src = f'NAME = {literal}\n\n\n@handler("H")\ndef h(msg):\n    return Send("OB", msg)\n'
    edit = _edit("set_params", 6, params={"to": {"expr": "NAME"}})
    if ok:
        assert "return Send(NAME, msg)" in rewrite_source(src, edit)
    else:
        _refused(src, edit, match=REFUSED)


_ELSE = """\
@handler("H")
def h(msg):
    if msg.field("C"):
        row = db_lookup("C", "s", {"a": 1})
    else:
        row = db_lookup("C", "t", {"a": 1})
        msg.set("Z", "z")
    msg.set("A", row)
    return Send("OB", msg)
"""


@pytest.mark.parametrize("typed_only", [False, True])
def test_g6_rule_6_an_else_binding_does_not_move_below_its_use(typed_only: bool) -> None:
    edit = _edit("move_row", 6, to_line_start=8, to_position="after")
    with pytest.raises(LensRewriteError):
        rewrite_source(_ELSE, edit, typed_only=typed_only)
    if not typed_only:
        _refused(_ELSE, edit, match="before anything binds")


# --- review of head 6259fb97a2 ------------------------------------------------------------------


def test_r4_finding_3_a_with_body_binding_is_not_sure_after_the_block() -> None:
    edit = _edit(
        "insert_row",
        9,
        position="before",
        action="set_field",
        params={"path": "PID-3.1", "value": {"expr": "y"}},
    )
    with pytest.raises(LensRewriteError, match="before anything binds"):
        rewrite_source(_BRANCH, edit)


_LAST = """\
@handler("H")
def h(msg):
    msg.set("Z", "z")
    for seg in msg.segments("OBX"):
        last = seg
    for i in range(1, msg.count_segments("OBX") + 1):
        pass
    msg.set("A", last)
    msg.set("B", "b", occurrence=i)
    return Send("OB", msg)
"""


@pytest.mark.parametrize("line", [8, 9])
def test_r4_finding_1_a_read_does_not_move_above_every_binding(line: int) -> None:
    edit = _edit("move_row", line, to_line_start=3, to_position="before")
    with pytest.raises(LensRewriteError, match="before anything binds"):
        rewrite_source(_LAST, edit)


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ({"expr": "-1"}, False),
        ({"expr": "0+0"}, False),
        ({"expr": "1-1"}, False),
        ({"expr": "i - 1"}, False),
        ({"expr": "LIMIT"}, False),
        ({"expr": "i + 0"}, True),
        ({"expr": "2 * 3"}, True),
    ],
)
def test_r4_finding_2_an_occurrence_is_1_or_more_on_every_message(value: Any, ok: bool) -> None:
    edit = _edit(
        "insert_row",
        9,
        position="before",
        action="set_field",
        params={"path": "OBX-3", "value": "x", "occurrence": value},
    )
    if ok:
        assert "occurrence=" in rewrite_source(_ARITH, edit)
    else:
        with pytest.raises(LensRewriteError, match="not a whole number"):
            rewrite_source(_ARITH, edit)


def test_r4_finding_2_a_zero_based_loop_index_is_not_an_occurrence() -> None:
    src = _ARITH.replace("range(1, ", "range(0, ")
    edit = _edit(
        "insert_row",
        9,
        position="before",
        action="set_field",
        params={"path": "OBX-3", "value": "x", "occurrence": {"expr": "i"}},
    )
    with pytest.raises(LensRewriteError, match="not a whole number"):
        rewrite_source(src, edit)


def test_r4_finding_6_an_eval_method_does_not_void_inert_names() -> None:
    src = (
        'OB_DEST = "OB_X"\n\n\ndef helper(df):  # type: ignore[no-untyped-def]\n'
        '    return df.eval("a + b")\n\n\n'
        '@handler("H")\ndef h(msg):\n    return Send("OB", msg)\n'
    )
    edit = _edit("set_params", 10, params={"to": {"expr": "OB_DEST"}})
    assert "return Send(OB_DEST, msg)" in rewrite_source(src, edit)


def test_r4_finding_8_repetition_may_be_none() -> None:
    edit = _edit(
        "insert_row",
        9,
        position="before",
        action="set_field",
        params={"path": "OBX-3", "value": "x", "repetition": None},
    )
    assert "repetition=None" in rewrite_source(_ARITH, edit)


# --- review of head bd5843dbd4 ------------------------------------------------------------------


@pytest.mark.parametrize(
    "loops",
    [
        # One loop is 1-based, the other binding the same name is not.
        '    for i in range(1, 3):\n        pass\n    for i in range(0, msg.count_segments("OBX")):\n',
        # A negative step reaches 0.
        "    for i in range(3, -1, -1):\n",
    ],
    ids=["any-loop", "negative-step"],
)
def test_r5_findings_1_2_every_loop_binding_an_index_is_1_based(loops: str) -> None:
    src = f'@handler("H")\ndef h(msg):\n{loops}        pass\n    return Send("OB", msg)\n'
    line = len(src.splitlines()) - 1
    edit = _edit(
        "insert_row",
        line,
        position="before",
        action="set_field",
        params={"path": "OBX-3", "value": "x", "occurrence": {"expr": "i"}},
    )
    with pytest.raises(LensRewriteError, match="not a whole number"):
        rewrite_source(src, edit)


def test_r5_finding_3_a_guarded_raise_does_not_move_into_another_same_header_guard() -> None:
    src = """\
@handler("H")
def h(msg):
    if msg.field("PID-3"):
        msg.set("B", "2")
        raise ValueError("bad")
    msg.set("PID-3", "X")
    if msg.field("PID-3"):
        msg.set("C", "3")
    return Send("OB", msg)
"""
    edit = _edit("move_row", 5, to_line_start=8, to_position="after")
    assert rewrite_source(src, edit) != src
    _refused(src, edit, typed_only=True)


@pytest.mark.parametrize(
    "write", ['builtins.globals()["OB_DEST"] = 1', 'builtins.exec("OB_DEST = 1")']
)
def test_r5_finding_4_a_builtins_attribute_voids_inert_names(write: str) -> None:
    src = (
        'import builtins\n\nOB_DEST = "OB_X"\n\n\n'
        f"def poke():  # type: ignore[no-untyped-def]\n    {write}\n\n\n"
        '@handler("H")\ndef h(msg):\n    return Send("OB", msg)\n'
    )
    edit = _edit("set_params", 12, params={"to": {"expr": "OB_DEST"}})
    _refused(src, edit, match=REFUSED)


def test_r5_finding_5_a_comprehension_target_is_not_a_handler_read() -> None:
    src = """\
@handler("H")
def h(msg):
    msg.set("Z", "z")
    for seg in msg.segments("OBX"):
        pass
    ids = [seg for seg in msg.segments("PID")]
    return Send("OB", msg)
"""
    edit = _edit("move_row", 6, to_line_start=3, to_position="before")
    assert rewrite_source(src, edit).index("ids = ") < rewrite_source(src, edit).index("for seg")


# --- Lander review of bd5843dbd4..71fe1207f4 ----------------------------------------------------

_SCOPE = """\
@handler("H")
def h(msg):
    d = {}
    xs = []
    msg.set("Z", "z")
    col = msg.field("C")
    {row}
    return Send("OB", msg)
"""


@pytest.mark.parametrize(
    "row",
    [
        # A default runs in the handler's scope when the lambda is made.
        "key = lambda s, col=col: s[col]",
        # A comprehension's first iterable runs in the handler's scope.
        "out = [col.upper() for col in col]",
        # A subscript target's index is a read, not a binding.
        "vals = [1 for d[col] in xs]",
        # A nested lambda's parameter does not bind the outer lambda's body.
        "key = lambda s, f=lambda col: 0: s[col]",
    ],
    ids=["lambda-default", "first-iterable", "subscript-target", "nested-lambda-default"],
)
def test_r6_a_read_in_the_enclosing_scope_still_counts(row: str) -> None:
    src = _SCOPE.replace("{row}", row)
    edit = _edit("move_row", 7, to_line_start=5, to_position="before")
    with pytest.raises(LensRewriteError, match="before anything binds"):
        rewrite_source(src, edit)


@pytest.mark.parametrize(
    "row",
    [
        "key = lambda s, col=1: s[col]",
        "out = [col.upper() for col in xs]",
        "out = [c for col in xs for c in col]",
    ],
    ids=["lambda-param", "comprehension-target", "second-generator"],
)
def test_r6_control_a_name_the_inner_scope_binds_is_not_a_handler_read(row: str) -> None:
    src = _SCOPE.replace("{row}", row)
    edit = _edit("move_row", 7, to_line_start=5, to_position="before")
    out = rewrite_source(src, edit)
    assert out.index(row) < out.index('msg.set("Z", "z")')


@pytest.mark.parametrize(
    "write",
    [
        "import builtins as b\n\n\ndef poke():  # type: ignore[no-untyped-def]\n"
        '    b.globals()["OB_DEST"] = 1\n',
        "from builtins import globals as g\n\n\ndef poke():  # type: ignore[no-untyped-def]\n"
        '    g()["OB_DEST"] = 1\n',
        "import builtins\n\n\ndef poke():  # type: ignore[no-untyped-def]\n"
        '    getattr(builtins, "globals")()["OB_DEST"] = 1\n',
        'def poke():  # type: ignore[no-untyped-def]\n    __builtins__["exec"]("OB_DEST = 1")\n',
        "import importlib\n\n\ndef poke():  # type: ignore[no-untyped-def]\n"
        '    importlib.import_module("builtins").exec("OB_DEST = 1")\n',
        "def poke(name):  # type: ignore[no-untyped-def]\n    return getattr(poke, name)\n",
    ],
    ids=[
        "import-as",
        "from-import-as",
        "getattr-literal",
        "dunder-builtins",
        "importlib",
        "getattr-var",
    ],
)
def test_r6_finding_4_every_route_to_builtins_voids_inert_names(write: str) -> None:
    src = (
        f'OB_DEST = "OB_X"\n\n\n{write}\n\n@handler("H")\ndef h(msg):\n    return Send("OB", msg)\n'
    )
    line = len(src.splitlines())
    _refused(src, _edit("set_params", line, params={"to": {"expr": "OB_DEST"}}), match=REFUSED)


def test_r6_finding_4_control_an_ordinary_helper_keeps_inert_names() -> None:
    src = (
        'import os\n\nOB_DEST = "OB_X"\n\n\ndef helper(x):  # type: ignore[no-untyped-def]\n'
        '    return getattr(x, "name"), os.sep\n\n\n'
        '@handler("H")\ndef h(msg):\n    return Send("OB", msg)\n'
    )
    line = len(src.splitlines())
    edit = _edit("set_params", line, params={"to": {"expr": "OB_DEST"}})
    assert "return Send(OB_DEST, msg)" in rewrite_source(src, edit)


@pytest.mark.parametrize(
    ("header", "ok"),
    [
        ("for i in range(1, *rest):", False),
        ("for i in range(1, n, *steps):", False),
        ("for i in range(1, 10, 2):", True),
        ('for i in range(1, msg.count_segments("OBX") + 1):', True),
    ],
)
def test_r6_finding_2_a_starred_range_is_not_1_based(header: str, ok: bool) -> None:
    src = (
        '@handler("H")\ndef h(msg):\n    rest = [5]\n    n = 5\n    steps = [1]\n'
        f'    {header}\n        pass\n    return Send("OB", msg)\n'
    )
    edit = _edit(
        "insert_row",
        7,
        position="before",
        action="set_field",
        params={"path": "OBX-3", "value": "x", "occurrence": {"expr": "i"}},
    )
    if ok:
        assert "occurrence=i" in rewrite_source(src, edit)
    else:
        with pytest.raises(LensRewriteError, match="not a whole number"):
            rewrite_source(src, edit)


# --- review of 71fe1207f4..11f5ddd5c4 -----------------------------------------------------------


@pytest.mark.parametrize(
    "write",
    [
        "import sys\n\n\ndef poke():  # type: ignore[no-untyped-def]\n"
        '    sys._getframe().f_globals["OB_DEST"] = 1\n',
        "def poke(h):  # type: ignore[no-untyped-def]\n"
        "    ga = getattr\n"
        '    ga(h, "x")["OB_DEST"] = 1\n',
        "def poke(h, n):  # type: ignore[no-untyped-def]\n"
        '    object.__getattribute__(h, n)["OB_DEST"] = 1\n',
        "import operator\n\n\ndef poke(h):  # type: ignore[no-untyped-def]\n"
        '    operator.attrgetter("x")(h)["OB_DEST"] = 1\n',
    ],
    ids=["f_globals", "getattr-alias", "getattribute", "attrgetter"],
)
def test_r7_more_routes_to_module_globals_void_inert_names(write: str) -> None:
    src = (
        f'OB_DEST = "OB_X"\n\n\n{write}\n\n@handler("H")\ndef h(msg):\n    return Send("OB", msg)\n'
    )
    line = len(src.splitlines())
    _refused(src, _edit("set_params", line, params={"to": {"expr": "OB_DEST"}}), match=REFUSED)


def test_r7_control_a_relative_builtins_module_keeps_inert_names() -> None:
    src = (
        'from .builtins import helper\n\nOB_DEST = "OB_X"\n\n\n'
        '@handler("H")\ndef h(msg):\n    return Send("OB", msg)\n'
    )
    line = len(src.splitlines())
    edit = _edit("set_params", line, params={"to": {"expr": "OB_DEST"}})
    assert "return Send(OB_DEST, msg)" in rewrite_source(src, edit)


# --- review of 11f5ddd5c4..b0beb2f930 -----------------------------------------------------------


@pytest.mark.parametrize(
    "write",
    [
        "import sys\n\n\ndef poke():  # type: ignore[no-untyped-def]\n"
        '    getattr(sys._getframe(), "f_globals")["OB_DEST"] = 1\n',
        "import sys\n\n\ndef poke():  # type: ignore[no-untyped-def]\n"
        '    getattr(sys, "modules")[__name__].OB_DEST = 1\n',
        "import sys\nfrom operator import attrgetter\n\n\ndef poke():  # type: ignore[no-untyped-def]\n"
        '    attrgetter("modules")(sys)[__name__].OB_DEST = 1\n',
        "from sys import modules\n\n\ndef poke():  # type: ignore[no-untyped-def]\n"
        "    modules[__name__].OB_DEST = 1\n",
        'locals()["OB_DEST"] = 1\n',
        "import sys\n\n\ndef poke():  # type: ignore[no-untyped-def]\n"
        '    sys._getframe().f_builtins["globals"]()["OB_DEST"] = 1\n',
    ],
    ids=[
        "getattr-f_globals",
        "getattr-modules",
        "from-attrgetter",
        "from-modules",
        "locals",
        "f_builtins",
    ],
)
def test_r8_routes_to_module_globals_void_inert_names(write: str) -> None:
    src = (
        f'OB_DEST = "OB_X"\n\n\n{write}\n\n@handler("H")\ndef h(msg):\n    return Send("OB", msg)\n'
    )
    line = len(src.splitlines())
    _refused(src, _edit("set_params", line, params={"to": {"expr": "OB_DEST"}}), match=REFUSED)


# --- Lander review of PR 2154: indexes inside a field read --------------------------------------

_OCC = """\
OCC = 2


@handler("H")
def h(msg):
    for i in range(1, msg.count_segments("OBX") + 1):
        pass
    return Send("OB", msg)
"""


@pytest.mark.parametrize(
    ("read", "ok"),
    [
        ('msg.field("OBX-5", occurrence=0)', False),
        ('msg.field("OBX-5", occurrence=OCC)', False),
        ('msg.field("OBX-5", repetition=0)', False),
        ('msg.field("OBX-5", occurrence=2)', True),
        ('msg.field("OBX-5", occurrence=i + 1)', True),
        ('msg.field("OBX-5", repetition=None)', True),
    ],
)
def test_r9_an_index_inside_a_field_read_is_1_or_more(read: str, ok: bool) -> None:
    edit = _edit(
        "insert_row",
        7,
        position="before",
        action="set_field",
        params={"path": "OBX-3", "value": {"expr": read}},
    )
    if ok:
        assert read in rewrite_source(_OCC, edit)
    else:
        _refused(_OCC, edit, match=REFUSED)


# --- Lander review of 21159e57d6: the two cheap closes -------------------------------------------


@pytest.mark.parametrize(
    "write",
    [
        "import inspect\n\n\ndef poke():  # type: ignore[no-untyped-def]\n"
        '    getattr(inspect, "builtins").globals()["OB_DEST"] = 1\n',
        'import os\n\n\ndef poke():  # type: ignore[no-untyped-def]\n    getattr(os, "globals")\n',
        "from inspect import builtins as b\n\n\ndef poke():  # type: ignore[no-untyped-def]\n"
        '    b.globals()["OB_DEST"] = 1\n',
        "import os\n\n\ndef poke():  # type: ignore[no-untyped-def]\n"
        '    getattr(os, "importlib")\n',
        "from somewhere import importlib\n",
    ],
    ids=[
        "getattr-builtins-literal",
        "getattr-writer-literal",
        "from-import-builtins",
        "getattr-importlib-literal",
        "from-import-importlib",
    ],
)
def test_r10_a_literal_route_name_voids_inert_names(write: str) -> None:
    src = (
        f'OB_DEST = "OB_X"\n\n\n{write}\n\n@handler("H")\ndef h(msg):\n    return Send("OB", msg)\n'
    )
    line = len(src.splitlines())
    _refused(src, _edit("set_params", line, params={"to": {"expr": "OB_DEST"}}), match=REFUSED)


# --- Lander review of PR 2154: a field value must be text ---------------------------------------

_TEXT = """\
TAGS = ("a", "b")
FROZ = frozenset({"a"})
NONE = None
LIMIT = 3
TXT = "t"


@handler("H")
def h(msg):
    pid5 = msg.field("PID-5")
    row = db_lookup("C", "s", {"a": 1})
    msg.set("A", "1")
    msg.add_repetition("B", "x")
    code_lookup(msg, "PID-8", GENDER, default="U")
    return Send("OB", msg)
"""
_TEXT_ANCHOR = 12


@pytest.mark.parametrize("action", ["set_field", "add_repetition"])
@pytest.mark.parametrize(
    ("expr", "ok"),
    [
        ("TAGS", False),
        ("FROZ", False),
        ("NONE", False),
        ("LIMIT", False),
        ("row", False),  # a lookup result is not known to be text
        ("TXT", True),
        ("pid5", True),
        ('"x"', True),
        ('f"{msg["PID-3"]}-x"', True),
        ('msg["PID-3"] or ""', True),
    ],
)
def test_r11_an_inserted_field_value_must_be_text(action: str, expr: str, ok: bool) -> None:
    edit = _edit(
        "insert_row",
        _TEXT_ANCHOR,
        position="before",
        action=action,
        params={"path": "PID-3", "value": {"expr": expr}},
    )
    if ok:
        assert expr in rewrite_source(_TEXT, edit)
    else:
        with pytest.raises(LensRewriteError, match="not text"):
            rewrite_source(_TEXT, edit)


@pytest.mark.parametrize(("line", "pname"), [(12, "value"), (13, "value"), (14, "default")])
@pytest.mark.parametrize("value", [5, None, True, {"expr": "1"}, {"expr": "TAGS"}])
def test_r11_set_params_writes_only_text_into_a_field_value(
    line: int, pname: str, value: Any
) -> None:
    edit = _edit("set_params", line, params={pname: value})
    with pytest.raises(LensRewriteError):
        rewrite_source(_TEXT, edit, contract=2)


@pytest.mark.parametrize(("line", "pname"), [(12, "value"), (13, "value"), (14, "default")])
def test_r11_control_set_params_still_writes_a_string(line: int, pname: str) -> None:
    out = rewrite_source(_TEXT, _edit("set_params", line, params={pname: "ok"}), contract=2)
    assert '"ok"' in out.splitlines()[line - 1]


@pytest.mark.parametrize(
    ("default", "ok"),
    [({"expr": '("a", "b")'}, False), ({"expr": "TAGS"}, False), (1, False), ("U", True)],
)
def test_r11_a_code_lookup_default_must_be_text(default: Any, ok: bool) -> None:
    edit = _edit(
        "insert_code_lookup",
        _TEXT_ANCHOR,
        position="before",
        code_set="gender",
        path="PID-9",
        default=default,
    )
    if ok:
        assert 'default="U"' in rewrite_source(_TEXT, edit)
    else:
        with pytest.raises(LensRewriteError, match="not text"):
            rewrite_source(_TEXT, edit)


# --- review of 2558f17928..1d7340b2d6 -----------------------------------------------------------


def _text_insert(body: str, expr: str) -> tuple[str, dict[str, Any]]:
    src = f'@handler("H")\ndef h(msg):\n{body}    msg.set("A", "1")\n    return Send("OB", msg)\n'
    line = len(src.splitlines()) - 1
    edit = _edit(
        "insert_row",
        line,
        position="before",
        action="add_repetition",
        params={"path": "PID-3", "value": {"expr": expr}},
    )
    return src, edit


@pytest.mark.parametrize(
    "body",
    [
        '    v = "a"\n    import json as v\n',
        '    v = "a"\n    from os import sep as v\n',
        '    v = "a"\n\n    def v():  # type: ignore[no-untyped-def]\n        pass\n\n',
    ],
    ids=["import-as", "from-import", "nested-def"],
)
def test_r12_finding_1_any_other_binding_drops_a_text_local(body: str) -> None:
    src, edit = _text_insert(body, "v")
    with pytest.raises(LensRewriteError, match="not text"):
        rewrite_source(src, edit)


@pytest.mark.parametrize(
    "body",
    [
        '    v = msg.field("PID-5") or ""\n',
        '    v = msg.field("OBX-5", occurrence=2)\n',
    ],
    ids=["field-or-empty", "field-occurrence"],
)
def test_r12_finding_2_an_admitted_field_read_binds_a_text_local(body: str) -> None:
    src, edit = _text_insert(body, "v")
    assert 'msg.add_repetition("PID-3", v)' in rewrite_source(src, edit)


def test_r12_finding_2_a_for_each_read_binds_a_text_local() -> None:
    src = (
        '@handler("H")\ndef h(msg):\n'
        '    for i in range(1, msg.count_segments("OBX") + 1):\n'
        '        v = msg.field("OBX-5", occurrence=i)\n'
        '        msg.set("A", "1")\n'
        '    return Send("OB", msg)\n'
    )
    edit = _edit(
        "insert_row",
        5,
        position="before",
        action="add_repetition",
        params={"path": "PID-3", "value": {"expr": "v"}},
    )
    assert 'msg.add_repetition("PID-3", v)' in rewrite_source(src, edit)


# --- Lander review of 2558f17928: findings A and B ---------------------------------------------

_GLOBAL_I = """\
i = ""


def stash(msg):  # type: ignore[no-untyped-def]
    global i
    i = msg.field("PID-5")


@handler("H")
def h(msg):
    global i
    for i in range(1, 3):
        pass
    return Send("OB", msg)
"""

_GLOBAL_RANGE = """\
def rebind(msg):  # type: ignore[no-untyped-def]
    global range
    range = lambda *a: [msg.field("PID-5")]


@handler("H")
def h(msg):
    for i in range(1, 3):
        pass
    return Send("OB", msg)
"""


@pytest.mark.parametrize("src", [_GLOBAL_I, _GLOBAL_RANGE], ids=["global-index", "global-range"])
def test_r13_a_loop_index_that_may_carry_text_is_not_a_destination(src: str) -> None:
    line = len(src.splitlines())
    _refused(src, _edit("set_params", line, params={"to": {"expr": "i"}}), match=REFUSED)


# --- review of 2558f17928..784abde3d4 -----------------------------------------------------------


def test_r14_finding_2_another_function_s_global_does_not_touch_the_handler_s_index() -> None:
    src = _GLOBAL_I.replace("    global i\n    for i", "    for i")
    edit = _edit(
        "insert_row",
        12,
        position="before",
        action="set_field",
        params={"path": "OBX-3", "value": "x", "occurrence": {"expr": "i"}},
    )
    assert "occurrence=i" in rewrite_source(src, edit)


@pytest.mark.parametrize(
    "rebind",
    [
        "import builtins\n\n\ndef rebind(msg):  # type: ignore[no-untyped-def]\n"
        '    builtins.range = lambda *a: [msg.field("PID-5")]\n',
        "def rebind(msg):  # type: ignore[no-untyped-def]\n"
        '    globals()["range"] = lambda *a: [msg.field("PID-5")]\n',
    ],
    ids=["builtins-attr", "globals-dict"],
)
def test_r14_finding_1_a_globals_route_voids_the_loop_index(rebind: str) -> None:
    src = (
        f'{rebind}\n\n@handler("H")\ndef h(msg):\n'
        '    for i in range(1, 3):\n        pass\n    return Send("OB", msg)\n'
    )
    line = len(src.splitlines())
    _refused(src, _edit("set_params", line, params={"to": {"expr": "i"}}), match=REFUSED)


# --- Lander review of 784abde3d4..034e441eea: a loop in a NESTED scope is not the handler's index ---

_NESTED_LOOP = """\
i = ""


def stash(msg):  # type: ignore[no-untyped-def]
    global i
    i = msg.field("PID-5")


@handler("H")
def h(msg):
{nested}
    return Send("OB", msg)
"""


@pytest.mark.parametrize(
    "nested",
    [
        "    def inner():\n        for i in range(1, 3):\n            pass",
        "    async def inner():\n        for i in range(1, 3):\n            pass",
        "    class Inner:\n        for i in range(1, 3):\n            pass",
        # The handler's own loop does not count when a nested def also binds ``i``: either a
        # ``nonlocal`` writer that sets it from the message, or an unrelated loop of its own.
        "    for i in range(1, 3):\n        pass\n"
        '    def inner():\n        nonlocal i\n        i = msg.field("PID-5")',
        "    for i in range(1, 3):\n        pass\n"
        "    def inner():\n        for i in range(1, 3):\n            pass",
    ],
    ids=["def", "async-def", "class", "nonlocal-writer", "both-scopes"],
)
def test_r15_a_nested_scope_s_loop_does_not_make_the_handler_s_free_name_an_index(
    nested: str,
) -> None:
    src = _NESTED_LOOP.format(nested=nested)
    line = len(src.splitlines())
    _refused(src, _edit("set_params", line, params={"to": {"expr": "i"}}), match=REFUSED)


def test_r15_the_handler_s_own_loop_index_is_admitted_as_a_destination() -> None:
    # The same op and payload as the refusals above, so they are attributable to the nested scope.
    src = _NESTED_LOOP.format(nested="    for i in range(1, 3):\n        pass")
    line = len(src.splitlines())
    assert "Send(i, msg)" in rewrite_source(
        src, _edit("set_params", line, params={"to": {"expr": "i"}})
    )


def test_r15_the_handler_s_own_one_based_loop_still_admits_its_index() -> None:
    src = _NESTED_LOOP.format(nested="    for i in range(1, 3):\n        pass")
    # Before the loop body's ``pass``, so the inserted read sits inside the loop that binds ``i``.
    line = len(src.splitlines()) - 1
    edit = _edit(
        "insert_row",
        line,
        position="before",
        action="set_field",
        params={"path": "OBX-3", "value": "x", "occurrence": {"expr": "i"}},
    )
    assert "occurrence=i" in rewrite_source(src, edit)


# --- G.6 rule 8: a row that never runs (Lander review of PR 2201) ------------------------------

_TERMINAL = """\
@handler("H")
def h(msg):
    if msg.field("PID-3"):
        msg.set("A", "1")
        return Send("OB", msg)
    msg.set("B", "2")
    return Send("OB2", msg)
"""

_RAISE = """\
@handler("H")
def h(msg):
    msg.set("B", "2")
    raise ValueError("x")
"""

_EITHER = """\
@handler("H")
def h(msg):
    msg.set("B", "2")
    if msg.field("PID-3"):
        return Send("OB", msg)
    else:
        raise ValueError("x")
"""

_SET_PID8 = {"action": "set_field", "params": {"path": "PID-8", "value": "M"}}


@pytest.mark.parametrize(
    ("src", "edit"),
    [
        (_TERMINAL, _edit("move_row", 6, direction="down")),  # swapped below the last return
        (
            _TERMINAL,
            _edit("move_row", 6, to_line_start=5, to_position="after"),
        ),  # after the guard's
        (_TERMINAL, _edit("move_row", 4, to_line_start=7, to_position="after")),  # after the last
        (_TERMINAL, _edit("move_row", 7, direction="up")),  # the return lifted above a row
        (_RAISE, _edit("move_row", 3, direction="down")),  # swapped below a raise
        (_EITHER, _edit("move_row", 3, to_line_start=7, to_position="after")),  # finding 1
        # Finding 2: an insert or template that strands a row, or lands where it never runs.
        (_TERMINAL, _edit("insert_row", 7, position="after", **_SET_PID8)),
        (_TERMINAL, _edit("template", 6, position="before", template="filter")),
        (_TERMINAL, _edit("template", 6, position="before", template="raise", message="x")),
        (_TERMINAL, _edit("template", 6, position="before", template="send", destination="OB3")),
    ],
    ids=[
        "swap-return",
        "drop-guard-return",
        "drop-last-return",
        "return-up",
        "swap-raise",
        "below-if-else",
        "insert-after-return",
        "filter",
        "raise",
        "send",
    ],
)
def test_rule_8_typed_only_refuses_a_row_that_never_runs(src: str, edit: dict[str, Any]) -> None:
    # G.6 scopes the rule to typed-only mode, so the default mode accepts the edit (decision D1).
    assert rewrite_source(src, edit) != src
    _refused(src, edit, match=NEVER_RUNS, typed_only=True)


_GUARD_ONLY = _TERMINAL.replace('        return Send("OB", msg)\n', "        pass\n")


@pytest.mark.parametrize(
    ("src", "edit", "expect"),
    [
        # A guarded return's block moves past a row; nothing lands below a terminal.
        (_TERMINAL, _edit("move_row", 3, direction="down"), '    msg.set("B", "2")\n    if msg'),
        # Into the guard, above its return.
        (
            _TERMINAL,
            _edit("move_row", 6, to_line_start=5, to_position="before"),
            '        msg.set("B", "2")\n        return Send("OB", msg)\n',
        ),
        # An insert above the last return.
        (
            _TERMINAL,
            _edit("insert_row", 7, position="before", **_SET_PID8),
            '    msg.set("PID-8", "M")\n    return Send("OB2", msg)\n',
        ),
        # A filter above the generator's ``pass`` seed: a dead ``pass`` strands no row.
        (
            _GUARD_ONLY,
            _edit("template", 5, position="before", template="filter"),
            "        return []\n        pass\n",
        ),
    ],
    ids=["guard-block-down", "into-guard", "insert-above-return", "filter-above-pass"],
)
def test_rule_8_control_typed_only_accepts_an_edit_that_strands_nothing(
    src: str, edit: dict[str, Any], expect: str
) -> None:
    assert expect in rewrite_source(src, edit, typed_only=True)


_DEAD_BLOCK = (
    _TERMINAL + '    if msg.field("PID-9"):\n        msg.set("C", "3")\n        msg.set("D", "4")\n'
)


def test_rule_8_a_row_moved_out_of_a_dead_block_is_accepted() -> None:
    # Finding 4: the row starts inside a block below the last return, and moves where it runs.
    edit = _edit("move_row", 9, to_line_start=6, to_position="before")
    out = rewrite_source(_DEAD_BLOCK, edit, typed_only=True)
    assert out.index('msg.set("C", "3")') < out.index('msg.set("B", "2")')


def test_rule_8_code_already_dead_does_not_block_another_edit() -> None:
    edit = _edit("move_row", 6, to_line_start=5, to_position="before")
    out = rewrite_source(_DEAD_BLOCK, edit, typed_only=True)
    assert '        msg.set("B", "2")\n        return Send("OB", msg)\n' in out


def _handler(body: str) -> Any:
    return ast.parse(f"def h(msg):\n{body}").body[0]


def _never_run(before: Any, after: Any, same: dict[int, int], refusal: LensRewriteError) -> None:
    lens._refuse_rows_that_never_run(
        lens._reachability(before), lens._reachability(after), same, refusal
    )


def _level(body: str) -> int:
    """How surely the ``f()`` row of ``body`` never runs, as ``lens._reachability`` sees it."""
    key = ast.dump(ast.parse("f()").body[0])
    (level,) = (lvl for stmt, lvl in lens._reachability(_handler(body)) if ast.dump(stmt) == key)
    return level


def test_rule_8_a_dead_copy_cannot_stand_in_for_a_live_row() -> None:
    # Review 2 finding 3, at the function level: the same text is dead once before and once after,
    # but the row that ran is the one now dead. ``same`` names each row, so text cannot stand in.
    before = _handler(
        '    if msg.field("A"):\n        msg.set("X", "1")\n    return Send("OB", msg)\n'
        '    msg.set("X", "1")\n'
    )
    after = _handler(
        '    if msg.field("A"):\n        return Send("OB", msg)\n        msg.set("X", "1")\n'
        '    msg.set("X", "1")\n'
    )
    # Statements in source order. Before: if, X, return, X. After: if, return, X, X.
    same = {0: 0, 1: 2, 2: 1, 3: 3}
    with pytest.raises(LensRewriteError, match="stranded"):
        _never_run(before, after, same, LensRewriteError("stranded"))
    # Control: every row is itself and nothing moved, so the dead row below the return is no bar.
    _never_run(before, before, {i: i for i in range(4)}, LensRewriteError("stranded"))


@pytest.mark.parametrize(
    ("body", "dead"),
    [
        ("    for x in y:\n        continue\n        f()\n", True),
        ("    for x in y:\n        break\n        f()\n", True),
        ("    while True:\n        g()\n    f()\n", True),
        ("    while True:\n        if g():\n            break\n    f()\n", False),
        ("    while True:\n        for x in y:\n            break\n    f()\n", True),
        ("    for x in y:\n        return 1\n    f()\n", False),  # the loop may not run
        ("    for x in y:\n        g()\n    else:\n        return 1\n    f()\n", True),
        ("    for x in y:\n        break\n    else:\n        return 1\n    f()\n", False),
        ("    while g():\n        h()\n    else:\n        raise E\n    f()\n", True),
        ("    with c:\n        return 1\n    f()\n", True),  # a context manager cannot swallow it
        ("    with c:\n        raise E\n    f()\n", False),  # but it may swallow an exception
        ("    try:\n        return 1\n    except E:\n        raise\n    f()\n", True),
        ("    try:\n        return 1\n    except E:\n        g()\n    f()\n", False),
        (
            "    try:\n        g()\n    except E:\n        return 2\n    else:\n        return 1\n    f()\n",
            True,
        ),
        ("    try:\n        g()\n    finally:\n        return 1\n    f()\n", True),
        (
            "    match x:\n        case 1:\n            return 1\n        case _:\n            return 2\n    f()\n",
            True,
        ),
        (
            "    match x:\n        case 1:\n            return 1\n        case 2:\n            return 2\n    f()\n",
            False,
        ),
        (
            "    match x:\n        case 1:\n            return 1\n        case y:\n            g()\n    f()\n",
            False,
        ),
        ("    if a:\n        return 1\n    f()\n", False),  # no else
        (
            "    if a:\n        return 1\n    elif b:\n        raise E\n    else:\n        return 2\n    f()\n",
            True,
        ),
    ],
    ids=[
        "continue",
        "break",
        "while-true",
        "while-true-break",
        "inner-break",
        "for",
        "for-else",
        "for-else-break",
        "while-else",
        "with-return",
        "with-raise",
        "try",
        "try-handler-falls",
        "try-else",
        "try-finally",
        "match-wildcard",
        "match-refutable",
        "match-arm-falls",
        "if-no-else",
        "if-elif-else",
    ],
)
def test_rule_8_never_falls_through(body: str, dead: bool) -> None:
    # Findings 1 and 5, decisions D3 and D7: ``f()`` is dead exactly when control cannot reach it.
    assert _level(body) == (lens._DEAD if dead else lens._LIVE)


@pytest.mark.parametrize(
    ("body", "level"),
    [
        # Review 4: an earlier body statement may raise and the manager may swallow it.
        ("    with c:\n        g()\n        return 1\n    f()\n", lens._MAYBE_DEAD),
        (
            "    with c:\n        if a:\n            return 1\n        else:\n            return 2\n    f()\n",
            lens._MAYBE_DEAD,
        ),
        # Review of 19e20ebbd6: these could still raise inside the ``with``, so they only count.
        ("    with c:\n        with d:\n            return 1\n    f()\n", lens._COUNTED_DEAD),
        ("    with c, d:\n        return 1\n    f()\n", lens._COUNTED_DEAD),
        ("    with c:\n        return g()\n    f()\n", lens._COUNTED_DEAD),
        ("    with c:\n        return x\n    f()\n", lens._DEAD),
        ("    with c:\n        g()\n        return 1\n    return 2\n    f()\n", lens._DEAD),
        # A suite can be deader than its block: a ``try``'s ``else``, and a ``while True``'s.
        (
            "    try:\n        return 1\n    except E:\n        g()\n    else:\n        f()\n",
            lens._DEAD,
        ),
        ("    try:\n        return 1\n    except E:\n        f()\n", lens._LIVE),
        ("    try:\n        return 1\n    finally:\n        f()\n", lens._LIVE),
        (
            "    try:\n        g()\n    except E:\n        return 1\n    else:\n        f()\n",
            lens._LIVE,
        ),
        ("    while True:\n        g()\n    else:\n        f()\n", lens._DEAD),
        ("    while g():\n        h()\n    else:\n        f()\n", lens._LIVE),
        ("    if a:\n        return 1\n    else:\n        f()\n", lens._LIVE),
    ],
    ids=[
        "with-statement-then-return",
        "with-if-else",
        "with-with-return",
        "with-two-managers",
        "with-return-call",
        "with-return-name",
        "return-below-with",
        "try-else-below-return",
        "try-handler",
        "try-finally",
        "try-else-live",
        "while-true-else",
        "while-else",
        "if-else",
    ],
)
def test_rule_8_levels_of_a_with_and_of_a_suite(body: str, level: int) -> None:
    assert _level(body) == level


_LIVE_TWIN = """\
@handler("H")
def h(msg):
    msg.set("A", "1")
    msg.set("B", "2")
    return Send("OB", msg)
    msg.set("A", "1")
"""


@pytest.mark.parametrize(
    "edit",
    [
        # Decision D8: an edit to a dead row strands nothing, so it is accepted.
        _edit("set_params", 6, params={"value": "9"}),
        # An edit, delete or move of a live row with a dead twin of the same text.
        _edit("set_params", 3, params={"value": "9"}),
        _edit("delete_row", 3),
        _edit("move_row", 3, direction="down"),
    ],
    ids=["set-dead-row", "set-live-twin", "delete-live-twin", "move-live-twin"],
)
def test_rule_8_an_edit_that_strands_nothing_new_is_accepted(edit: dict[str, Any]) -> None:
    assert rewrite_source(_LIVE_TWIN, edit, typed_only=True) != _LIVE_TWIN


def test_rule_8_a_row_moved_into_the_dead_twin_s_place_is_refused() -> None:
    # The live twin dropped after the return lands dead, even though the same text was dead before.
    edit = _edit("move_row", 3, to_line_start=6, to_position="after")
    _refused(_LIVE_TWIN, edit, match=NEVER_RUNS, typed_only=True)


_WITH = """@handler("H")
def h(msg):
    with lock:
        return Send("OB", msg)
    msg.set("C", "3")
"""


@pytest.mark.parametrize(
    "body", ['return Send("OB", msg)', "pass"], ids=["returns", "falls-through"]
)
def test_rule_8_an_insert_after_a_with_follows_its_body(body: str) -> None:
    # D7: a ``with`` whose body returns never falls through, so a row inserted after it never
    # runs; one whose body falls through is the control.
    src = _WITH.replace('return Send("OB", msg)', body)
    edit = _edit("insert_row", 5, position="before", **_SET_PID8)
    if body == "pass":
        assert '    msg.set("PID-8", "M")\n' in rewrite_source(src, edit, typed_only=True)
    else:
        _refused(src, edit, match=NEVER_RUNS, typed_only=True)


# --- Lander review 4 of PR 2201: row identity, and a ``with`` that may swallow -----------------

_SWALLOW = """@handler("H")
def h(msg):
    with suppress(KeyError):
        msg.set("A", "1")
        return Send("OB", msg)
    if msg.field("PID-3"):
        return []
    msg.set("B", "2")
"""


def test_rule_8_a_row_below_a_swallowing_with_cannot_move_below_a_return() -> None:
    # Blocking finding 1. The row may run, when the ``with`` swallows a KeyError; below the
    # guard's ``return []`` it never does. Head 94ac5aab36 judged it already dead and accepted.
    edit = _edit("move_row", 8, to_line_start=7, to_position="after")
    assert rewrite_source(_SWALLOW, edit) != _SWALLOW  # the default mode applies no rule 8
    _refused(_SWALLOW, edit, match=NEVER_RUNS, typed_only=True)


@pytest.mark.parametrize(
    "body",
    [
        '        return Send(ROUTES[msg.field("MSH-4")], msg)\n',
        "        with lookup(msg) as dest:\n            return Send(dest, msg)\n",
    ],
    ids=["return-of-a-lookup", "inner-with"],
)
def test_rule_8_a_row_below_a_with_that_returns_at_once_is_not_exempt(body: str) -> None:
    # Review of 19e20ebbd6: working out the returned value, or entering the inner manager, may
    # raise KeyError, and ``suppress`` swallows it. So the rows below may run, and are not exempt:
    # one may not move below the guard's return. A row may still not be written there (D7).
    src = _SWALLOW.replace('        msg.set("A", "1")\n        return Send("OB", msg)\n', body)
    last = len(src.splitlines())
    move = _edit("move_row", last, to_line_start=last - 1, to_position="after")
    assert rewrite_source(src, move) != src
    _refused(src, move, match=NEVER_RUNS, typed_only=True)
    _refused(src, _edit("insert_row", last, **_SET_PID8), match=NEVER_RUNS, typed_only=True)


@pytest.mark.parametrize("position", ["before", "after"])
def test_rule_8_an_insert_below_a_swallowing_with_is_accepted(position: str) -> None:
    # Blocking finding 2, case 3: the tail may run, so a row written there is as live as its
    # neighbours. Head 94ac5aab36 refused it.
    edit = _edit("insert_row", 8, position=position, **_SET_PID8)
    out = rewrite_source(_SWALLOW, edit, typed_only=True)
    assert out == rewrite_source(_SWALLOW, edit)
    assert '    msg.set("PID-8", "M")\n' in out


def test_rule_8_a_kept_row_may_not_run_less_surely_than_it_did() -> None:
    # The four levels, at the function level. ``f()`` is the last statement of each body and the
    # only row whose level differs, so each verdict below is about ``f()`` alone.
    bodies = [
        "    g()\n    f()\n",  # runs
        "    with c:\n        g()\n        return 1\n    f()\n",  # might not run
        "    with c:\n        return g()\n    f()\n",  # counted as never running
        "    return 1\n    f()\n",  # surely never runs
    ]
    funcs = [_handler(body) for body in bodies]
    last = [len(lens._reachability(func)) - 1 for func in funcs]
    assert [_level(body) for body in bodies] == [0, 1, 2, 3]
    stranded = LensRewriteError("stranded")
    for was, now in itertools.product(range(4), repeat=2):
        # A kept row: refused exactly when its level got worse, by any step.
        kept = {last[now]: last[was]}
        if now > was:
            with pytest.raises(LensRewriteError, match="stranded"):
                _never_run(funcs[was], funcs[now], kept, stranded)
        else:
            _never_run(funcs[was], funcs[now], kept, stranded)
    for now in range(4):
        # A row the edit wrote: refused where it never runs, accepted where it might.
        if now >= lens._COUNTED_DEAD:
            with pytest.raises(LensRewriteError, match="stranded"):
                _never_run(funcs[0], funcs[now], {}, stranded)
        else:
            _never_run(funcs[0], funcs[now], {}, stranded)


_DEAD_ABOVE = """@handler("H")
def h(msg):
    if msg.field("PID-3"):
        return []
        msg.set("PID-8", "M")
    msg.set("B", "2")
    if msg.field("PID-5"):
        return []
"""

_TWO_DEAD = """@handler("H")
def h(msg):
    return Send("OB", msg)
    msg.set("A", "1")
    return Send("OB", msg)
    msg.set("A", "1")
"""

_DEAD_PAIR = """@handler("H")
def h(msg):
    return Send("OB", msg)
    msg.set("A", "1")
    msg.set("A", "9")
"""


@pytest.mark.parametrize(
    ("src", "edit", "expect"),
    [
        # Case 1: a live row written below a dead row of the same text.
        (
            _DEAD_ABOVE,
            _edit("insert_row", 6, position="before", **_SET_PID8),
            '        msg.set("PID-8", "M")\n    msg.set("PID-8", "M")\n    msg.set("B", "2")\n',
        ),
        # Case 2: the first of two dead rows of the same text is deleted.
        (
            _TWO_DEAD,
            _edit("delete_row", 4),
            '    return Send("OB", msg)\n    return Send("OB", msg)\n    msg.set("A", "1")\n',
        ),
        # Case 4: a dead row is edited to the text of the dead row below it.
        (
            _DEAD_PAIR,
            _edit("set_params", 4, params={"value": "9"}),
            '    msg.set("A", "9")\n    msg.set("A", "9")\n',
        ),
    ],
    ids=["insert-below-dead-twin", "delete-first-dead-twin", "set-dead-row-to-its-twin"],
)
def test_rule_8_a_twin_that_is_not_the_row_does_not_refuse_the_edit(
    src: str, edit: dict[str, Any], expect: str
) -> None:
    # Blocking finding 2: each row is compared with itself, wherever a row of the same text sits.
    # Head 94ac5aab36 aligned rows by text and refused all three.
    out = rewrite_source(src, edit, typed_only=True)
    assert expect in out
    assert out == rewrite_source(src, edit)  # and it is the edit the default mode makes


def test_rule_8_a_return_dropped_below_its_twin_is_refused_as_itself() -> None:
    # Exact identity cuts both ways: the first ``return`` ran and would not, so the move is
    # refused, although moving the row between them up instead gives the same text (G.7 limit).
    src = _TWO_DEAD.replace("def h(msg):\n", 'def h(msg):\n    msg.set("B", "2")\n')
    _refused(
        src, _edit("move_row", 4, to_line_start=6, to_position="after"), NEVER_RUNS, typed_only=True
    )


def test_rule_8_identity_of_a_move_and_of_a_rewritten_row() -> None:
    # What ``_refuse_rows_that_never_run`` is given, read directly: which row each statement was.
    # Every row of ``twins`` has the same text, so text could not tell them apart.
    def identity(src: str, edit: dict[str, Any]) -> dict[int, int]:
        out = rewrite_source(src, edit)
        before, after = (
            next(n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef))
            for text in (src, out)
        )
        carried = lens._carried_lines(src, out, before, after, edit)
        return lens._row_identity(
            carried,
            lens._reachability(before),
            lens._reachability(after),
            pair_rest=edit["op"] in ("set_params", "move_row"),
        )

    twins = '@handler("H")\ndef h(msg):\n' + '    msg.set("A", "1")\n' * 4
    # Row 1 dropped after row 3, and row 3 moved to before row 1: each is itself where it lands.
    drop = _edit("move_row", 4, to_line_start=6, to_position="after")
    assert identity(twins, drop) == {0: 0, 1: 2, 2: 3, 3: 1}
    lift = _edit("move_row", 6, to_line_start=4, to_position="before")
    assert identity(twins, lift) == {0: 0, 1: 3, 2: 1, 3: 2}
    assert identity(twins, _edit("move_row", 5, direction="up")) == {0: 0, 1: 2, 2: 1, 3: 3}
    # An insert before row 2, then after it: the new statement has no entry.
    insert = _edit(
        "insert_row", 5, position="before", action="set_field", params={"path": "A", "value": "1"}
    )
    assert identity(twins, insert) == {0: 0, 1: 1, 3: 2, 4: 3}
    assert identity(twins, {**insert, "position": "after"}) == {0: 0, 1: 1, 2: 2, 4: 3}
    assert identity(twins, _edit("delete_row", 4)) == {0: 0, 1: 2, 2: 3}
    rewritten = _edit("set_params", 4, params={"value": "9"})
    assert identity(twins, rewritten) == {i: i for i in range(4)}
    # A row moved to another depth is re-indented, and is still itself.
    out_of_guard = _edit("move_row", 4, to_line_start=3, to_position="before")
    assert identity(_TERMINAL, out_of_guard) == {0: 1, 1: 0, 2: 2, 3: 3, 4: 4}
    # A moved block takes its rows with it.
    block_down = _edit("move_row", 3, direction="down")
    assert identity(_TERMINAL, block_down) == {0: 3, 1: 0, 2: 1, 3: 2, 4: 4}
    # The last row moved up past a blank line: the handler then ends one line sooner (review of
    # 19e20ebbd6, which paired these rows by their text).
    row = '    msg.set("A", "1")\n'
    gap = '@handler("H")\ndef h(msg):\n' + row * 2 + "\n" + row
    assert identity(gap, _edit("move_row", 6, direction="up")) == {0: 0, 1: 2, 2: 1}
    assert identity(gap.rstrip("\n"), _edit("move_row", 6, direction="up")) == {0: 0, 1: 2, 2: 1}
    # A fresh fan-out writes at three places, and injects an import above the handler.
    send = _edit("insert_send", 3, destination="OB", position="after")
    assert identity(gap, send) == {1: 0, 3: 1, 4: 2}
    assert rewrite_source(gap, send, typed_only=True) == rewrite_source(gap, send)


def test_rule_8_a_row_that_never_ran_may_move_where_it_never_runs() -> None:
    # Only a row that certainly never ran is exempt: it moves within the dead code below the last
    # return, and a block moves with a dead row inside it. Nothing is stranded that ran.
    dead_move = _edit("move_row", 9, direction="down")
    out = rewrite_source(_DEAD_BLOCK, dead_move, typed_only=True)
    assert out == rewrite_source(_DEAD_BLOCK, dead_move) != _DEAD_BLOCK
    inner_dead = _TERMINAL.replace(
        '        return Send("OB", msg)\n',
        '        return Send("OB", msg)\n        msg.set("D", "4")\n',
    )
    out = rewrite_source(inner_dead, _edit("move_row", 3, direction="down"), typed_only=True)
    assert out.index('msg.set("B", "2")') < out.index('msg.set("D", "4")')

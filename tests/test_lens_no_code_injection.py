# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What ``lens rewrite`` refuses to write from a Steps edit (Theia review finding R1).

Closed here, at least:

* an ``{"expr": ...}`` on ``insert_row`` (its params, occurrence kwargs and the code-lookup default)
  or on a send row's destination that calls, walks an attribute or applies an operator;
* message content (a read, a template, or a local that may hold one) in a parameter that is not a
  value parameter, and a lookup ``params`` that is not a dict with literal keys;
* an ``insert_row`` ``assign_to`` that rebinds ``msg`` or any name the handler or module binds;
* a raw ``if``/``elif`` ``test`` that spans lines, is not one condition, yields, or awaits in a sync
  handler;
* under ``typed_only``, every ``paste_block`` and every raw ``test``.

Each refused case is paired with a control the lens must still accept, so a refusal is attributable to
the payload and not to a broken edit spec. Without ``typed_only``, ``paste_block`` and a one-line raw
``test`` still take arbitrary source: they are the escape hatches ADR 0076 section 5 and ADR 0106
license for a developer.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
import warnings
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.lens import LensRewriteError, parse_source, rewrite_source

SOURCE = """\
OB_DEST = "OB_X"


@handler("H")
def h(msg):
    pid5 = msg.field("PID-5")
    for i in range(1, msg.count_segments("OBX") + 1):
        pass
    if msg.field("PID-3.1"):
        pass
    return Send("OB_ACME_ADT", msg)
"""
_FOR, _IF, _SEND = 7, 9, 11

REFUSED = "not a value a Steps edit may write"

EVIL_CALL = '__import__("os").system("x")'
_ACTIVE = [
    EVIL_CALL,
    "msg.__class__.__init__.__globals__",
    'msg.field("PID-3").upper()',
    '"a" + "b"',
    "(lambda: 0)",
    "__builtins__",
    "[*x]",
    "{**x}",
    '{"k": [__import__("os")]}',
    'f"{x()}"',
    "(x := 1)",
    "msg",
    # Message.field takes occurrence/repetition keyword-only, so a positional extra raises TypeError.
    'msg.field("PID-5", 2)',
]


def _insert(params: dict[str, Any], action: str = "set_field", **extra: Any) -> str:
    edit = {
        "line_start": _SEND,
        "line_end": _SEND,
        "op": "insert_row",
        "position": "before",
        "action": action,
        "params": params,
        **extra,
    }
    return rewrite_source(SOURCE, edit)


def _clause(test: str, source: str = SOURCE, line: int = _IF, **kw: Any) -> str:
    edit = {"line_start": line, "line_end": line, "op": "insert_clause", "clause": "elif"}
    return rewrite_source(source, {**edit, "test": test}, **kw)


@pytest.mark.parametrize("expr", _ACTIVE)
def test_insert_row_refuses_an_expr_that_is_not_an_inert_value(expr: str) -> None:
    with pytest.raises(LensRewriteError, match=REFUSED):
        _insert({"path": "PID-3.1", "value": {"expr": expr}})


@pytest.mark.parametrize(
    ("params", "action", "spliced"),
    [
        # A field value must be text; a number goes in a number slot (review of PR 2155).
        ({"path": "PID-3.1", "value": {"expr": '"0"'}}, "set_field", '"0"'),
        (
            {"path": "PID-3.1", "value": "x", "occurrence": {"expr": "2"}},
            "set_field",
            "occurrence=2",
        ),
        ({"path": "PID-3.1", "value": {"expr": 'msg["PID-5"]'}}, "set_field", 'msg["PID-5"]'),
        (
            {"path": "PID-3.1", "value": {"expr": 'msg["PID-5"] or ""'}},
            "set_field",
            'msg["PID-5"] or ""',
        ),
        (
            {"path": "PID-3.1", "value": {"expr": 'msg.field("PID-5", occurrence=2)'}},
            "set_field",
            'msg.field("PID-5", occurrence=2)',
        ),
        # A value parameter may carry message content, so a local holding some is fine there.
        ({"path": "PID-3.1", "value": {"expr": "pid5"}}, "set_field", "pid5"),
        ({"path": {"expr": "OB_DEST"}, "value": "x"}, "set_field", "OB_DEST"),
        (
            {"src": "PID-5", "sep": "^", "dests": {"expr": '["PID-5.1", "PID-5.2"]'}},
            "split_field",
            '["PID-5.1", "PID-5.2"]',
        ),
        (
            {"connection": "MPI", "statement": "select 1", "params": {"expr": "{}"}},
            "db_lookup",
            "{}",
        ),
        (
            {
                "connection": "MPI",
                "statement": "select 1",
                "params": {"expr": '{"m": msg["PID-3"]}'},
            },
            "db_lookup",
            '{"m": msg["PID-3"]}',
        ),
        (
            {
                "connection": "EPIC",
                "query": "Patient",
                "params": {"expr": '{"identifier": FhirToken("MRN", msg["PID-3.1"] or "")}'},
            },
            "fhir_lookup",
            'FhirToken("MRN", msg["PID-3.1"] or "")',
        ),
    ],
)
def test_insert_row_still_accepts_inert_values(
    params: dict[str, Any], action: str, spliced: str
) -> None:
    out = _insert(params, action)
    assert spliced in out
    ast.parse(out)


@pytest.mark.parametrize(
    ("action", "params"),
    [
        # A statement or query built from message content is the SQL/FHIR injection path.
        (
            "db_lookup",
            {
                "connection": "MPI",
                "statement": {"expr": "f\"select {msg['PID-3'] or ''}\""},
                "params": {"expr": "{}"},
            },
        ),
        (
            "db_lookup",
            {"connection": "MPI", "statement": {"expr": "pid5"}, "params": {"expr": "{}"}},
        ),
        (
            "fhir_lookup",
            {"connection": {"expr": 'msg["MSH-3"]'}, "query": "Patient", "params": {"expr": "{}"}},
        ),
        # A diagnostic template is logged unredacted, whether it is a read or a local holding one.
        ("log_note", {"template": {"expr": 'msg["PID-5"]'}}),
        ("log_note", {"template": {"expr": "pid5"}}),
        ("log_note", {"template": {"expr": "msg"}}),
        # A path chosen by message content picks which field is overwritten.
        ("set_field", {"path": {"expr": 'msg["ZZZ-1"]'}, "value": "x"}),
        ("set_field", {"path": {"expr": "pid5"}, "value": "x"}),
        # A lookup params value must be a dict with literal keys; the two lookups take a Mapping.
        ("db_lookup", {"connection": "MPI", "statement": "s", "params": {"expr": '[msg["A"]]'}}),
        ("db_lookup", {"connection": "MPI", "statement": "s", "params": {"expr": '{msg["A"]: 1}'}}),
        ("db_lookup", {"connection": "MPI", "statement": "s", "params": {"expr": "pid5"}}),
        (
            "fhir_lookup",
            {
                "connection": "EPIC",
                "query": "Patient",
                "params": {"expr": '{"identifier": FhirToken(msg["A"], "c")}'},
            },
        ),
        (
            "db_lookup",
            {
                "connection": "MPI",
                "statement": "s",
                "params": {"expr": '{"identifier": FhirToken("MRN", "c")}'},
            },
        ),
    ],
)
def test_insert_row_keeps_message_content_out_of_non_value_params(
    action: str, params: dict[str, Any]
) -> None:
    with pytest.raises(LensRewriteError, match=REFUSED):
        _insert(params, action)


def test_occurrence_takes_a_loop_index_but_not_message_content_or_a_call() -> None:
    edit = {
        "line_start": _FOR + 1,
        "line_end": _FOR + 1,
        "op": "insert_row",
        "position": "before",
        "action": "set_field",
        "params": {"path": "OBX-11", "value": "F", "occurrence": {"expr": "i"}},
    }
    assert "occurrence=i" in rewrite_source(SOURCE, edit)
    for bad in (EVIL_CALL, 'msg["PID-9"]', "pid5"):
        edit["params"] = {"path": "OBX-11", "value": "F", "occurrence": {"expr": bad}}
        with pytest.raises(LensRewriteError, match=REFUSED):
            rewrite_source(SOURCE, edit)


def test_code_lookup_default_is_gated_and_a_reserved_variable_names_the_code_set() -> None:
    edit: dict[str, Any] = {
        "line_start": _SEND,
        "line_end": _SEND,
        "op": "insert_code_lookup",
        "position": "before",
        "code_set": "gender",
        "path": "PID-8",
        "default": {"expr": EVIL_CALL},
    }
    with pytest.raises(LensRewriteError, match=REFUSED):
        rewrite_source(SOURCE, edit)
    edit["default"] = "U"
    assert 'code_lookup(msg, "PID-8", GENDER, default="U")' in rewrite_source(SOURCE, edit)
    edit["code_set"] = "__init__"
    with pytest.raises(LensRewriteError, match="code set '__init__' is a reserved name"):
        rewrite_source(SOURCE, edit)


def _set_send(expr: str, source: str = SOURCE, line: int = _SEND) -> str:
    edit = {
        "line_start": line,
        "line_end": line,
        "op": "set_params",
        "params": {"to": {"expr": expr}},
    }
    return rewrite_source(source, edit)


@pytest.mark.parametrize("expr", [EVIL_CALL, "msg.__class__", '"a" + "b"', "pid5", 'msg["MSH-5"]'])
def test_send_destination_refuses_code_and_message_content(expr: str) -> None:
    with pytest.raises(LensRewriteError, match=REFUSED):
        _set_send(expr)


@pytest.mark.parametrize("expr", ['"OB_NEW"', "OB_DEST"])
def test_send_destination_still_accepts_a_literal_or_a_module_name(expr: str) -> None:
    assert f"return Send({expr}, msg)" in _set_send(expr)


_APPEND_SOURCE = """\
@handler("H")
def h(msg):
    sends = []
    sends.append(Send("OB_ACME_ADT", msg))
    return sends
"""


@pytest.mark.parametrize(
    ("expr", "ok"), [(EVIL_CALL, False), ("__builtins__", False), ('"OB_N"', True)]
)
def test_appended_send_destination_is_gated_too(expr: str, ok: bool) -> None:
    if ok:
        assert f"sends.append(Send({expr}, msg))" in _set_send(expr, _APPEND_SOURCE, 4)
    else:
        with pytest.raises(LensRewriteError, match=REFUSED):
            _set_send(expr, _APPEND_SOURCE, 4)


def test_route_list_edit_is_unaffected() -> None:
    src = '@router("R")\ndef r(msg):\n    return ["a"]\n'
    edit = {"line_start": 3, "line_end": 3, "op": "set_params", "params": {"handlers": ["b", "c"]}}
    assert 'return ["b", "c"]' in rewrite_source(src, edit, contract=2)


@pytest.mark.parametrize("name", ["msg", "__x__", "class", "pid5", "i", "OB_DEST"])
def test_insert_row_assign_to_cannot_rebind_a_bound_or_reserved_name(name: str) -> None:
    params = {"connection": "MPI", "statement": "select 1", "params": {"expr": "{}"}}
    with pytest.raises(LensRewriteError, match="assign_to"):
        _insert(params, "db_lookup", assign_to=name)
    assert 'row = db_lookup("MPI", "select 1", {})' in _insert(params, "db_lookup", assign_to="row")


_SMUGGLE = "True:\n        " + EVIL_CALL + "\n    elif True"


@pytest.mark.parametrize(
    "test",
    [_SMUGGLE, "True\r\nx = 1", "True:", "a) or (b", "(yield)", "(yield from x)", "(await x)"],
)
def test_elif_raw_test_must_be_one_condition_on_one_line(test: str) -> None:
    with pytest.raises(LensRewriteError, match="raw 'test'"):
        _clause(test)


def test_if_template_raw_test_must_be_one_line() -> None:
    edit = {
        "line_start": _SEND,
        "line_end": _SEND,
        "op": "template",
        "template": "if",
        "position": "before",
        "test": _SMUGGLE,
    }
    with pytest.raises(LensRewriteError, match="raw 'test'"):
        rewrite_source(SOURCE, edit)


@pytest.mark.parametrize(
    ("test", "header"),
    [
        ('re.match("^A", msg["PID-3.1"] or "")', 'elif re.match("^A", msg["PID-3.1"] or ""):'),
        # An unparenthesized walrus is valid in an if header, so the escape hatch takes it.
        ('x := msg.field("PID-3.1")', 'elif x := msg.field("PID-3.1"):'),
        ("   True  ", "elif True:"),
        # A yield inside a lambda belongs to the lambda, not to the handler.
        ("(lambda: (yield))", "elif (lambda: (yield)):"),
    ],
)
def test_a_single_line_raw_test_is_still_accepted(test: str, header: str) -> None:
    out = _clause(test)
    assert header in out
    assert len(parse_source(out)[0]["rows"]) == len(parse_source(SOURCE)[0]["rows"]) + 2


def test_await_in_a_raw_test_is_accepted_only_in_an_async_handler() -> None:
    async_src = SOURCE.replace("def h(msg):", "async def h(msg):")
    assert "elif await x:" in _clause("await x", async_src)
    with pytest.raises(LensRewriteError, match="raw 'test'"):
        _clause("await x")


# --- typed-only mode (owner ruling 2026-10-07) ---------------------------------------------------

_PASTE = {
    "line_start": _SEND,
    "line_end": _SEND,
    "op": "paste_block",
    "position": "before",
    "block": '    msg["MSH-4"] = "X"',
}
_IF_RAW = {
    "line_start": _SEND,
    "line_end": _SEND,
    "op": "template",
    "template": "if",
    "position": "before",
    "test": "True",
}
_ELIF_RAW = {
    "line_start": _IF,
    "line_end": _IF,
    "op": "insert_clause",
    "clause": "elif",
    "test": "True",
}


@pytest.mark.parametrize("edit", [_PASTE, _IF_RAW, _ELIF_RAW], ids=["paste", "if-raw", "elif-raw"])
def test_typed_only_refuses_raw_source_that_the_default_mode_accepts(edit: dict[str, Any]) -> None:
    assert rewrite_source(SOURCE, edit) != SOURCE
    with pytest.raises(LensRewriteError, match="typed-only mode") as info:
        rewrite_source(SOURCE, edit, typed_only=True)
    assert info.value.code == "refused"


def test_typed_only_still_accepts_typed_edits() -> None:
    typed_if = {k: v for k, v in _IF_RAW.items() if k != "test"} | {"field": "PID-3.1"}
    assert "if msg.field(" in rewrite_source(SOURCE, typed_if, typed_only=True)
    typed_elif = {k: v for k, v in _ELIF_RAW.items() if k != "test"} | {"field": "PID-3.1"}
    assert "elif msg.field(" in rewrite_source(SOURCE, typed_elif, typed_only=True)
    insert = {
        "line_start": _SEND,
        "line_end": _SEND,
        "op": "insert_row",
        "position": "before",
        "action": "set_field",
        "params": {"path": "PID-3.1", "value": "B"},
    }
    assert 'msg.set("PID-3.1", "B")' in rewrite_source(SOURCE, insert, typed_only=True)


def _cli(module: Path, edit: dict[str, Any], *flags: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "messagefoundry",
            "lens",
            "rewrite",
            str(module),
            "--edit",
            json.dumps(edit),
            *flags,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def test_the_cli_refuses_an_injected_insert_value(tmp_path: Path) -> None:
    module = tmp_path / "h.py"
    module.write_text(SOURCE, encoding="utf-8")
    edit = {
        "line_start": _SEND,
        "line_end": _SEND,
        "op": "insert_row",
        "position": "before",
        "action": "set_field",
        "params": {"path": "PID-3.1", "value": {"expr": EVIL_CALL}},
    }
    proc = _cli(module, edit)
    assert proc.returncode != 0
    assert json.loads(proc.stdout)["code"] == "refused"
    assert REFUSED in json.loads(proc.stdout)["error"]
    assert "__import__" not in proc.stdout  # nothing rewritten was emitted


def test_the_cli_typed_only_flag_refuses_paste_block(tmp_path: Path) -> None:
    module = tmp_path / "h.py"
    module.write_text(SOURCE, encoding="utf-8")
    ok = _cli(module, _PASTE)
    assert ok.returncode == 0
    assert 'msg["MSH-4"] = "X"' in ok.stdout
    proc = _cli(module, _PASTE, "--typed-only")
    assert proc.returncode != 0
    assert json.loads(proc.stdout)["code"] == "refused"
    assert "typed-only mode" in proc.stdout
    assert 'msg["MSH-4"]' not in proc.stdout


@pytest.mark.parametrize(
    ("binding", "name"),
    [
        ("    try:\n        pass\n    except ValueError as err:\n        pass\n", "err"),
        ('    match msg["PID-8"]:\n        case sex:\n            pass\n', "sex"),
        ('    match msg["PID-8"]:\n        case [*rest]:\n            pass\n', "rest"),
        ('    match msg["PID-8"]:\n        case {"a": 1, **more}:\n            pass\n', "more"),
        ("    import os as osmod\n", "osmod"),
        ("    with open('x') as fh:\n        pass\n", "fh"),
        ("    total = 0\n    total += 1\n", "total"),
    ],
)
def test_every_kind_of_handler_binding_is_blocked_from_a_literal_param(
    binding: str, name: str
) -> None:
    src = SOURCE.replace('    pid5 = msg.field("PID-5")\n', binding)
    send = len(src.splitlines())
    with pytest.raises(LensRewriteError, match=REFUSED):
        _set_send(name, src, send)


def test_a_name_any_function_declares_global_is_blocked() -> None:
    src = (
        'LAST = ""\n\n\ndef note(msg):  # type: ignore[no-untyped-def]\n    global LAST\n'
        '    LAST = msg["PID-5"]\n\n\n' + SOURCE
    )
    send = len(src.splitlines())
    with pytest.raises(LensRewriteError, match=REFUSED):
        _set_send("LAST", src, send)
    assert "return Send(OB_DEST, msg)" in _set_send("OB_DEST", src, send)


def test_a_loop_index_reused_by_two_for_each_loops_is_still_admitted() -> None:
    loop = '    for i in range(1, msg.count_segments("OBX") + 1):\n        pass\n'
    src = SOURCE.replace(loop, loop + loop)
    edit = {
        "line_start": _FOR + 3,
        "line_end": _FOR + 3,
        "op": "insert_row",
        "position": "before",
        "action": "set_field",
        "params": {"path": "OBX-11", "value": "F", "occurrence": {"expr": "i"}},
    }
    assert "occurrence=i" in rewrite_source(src, edit)
    # The same name bound once more by something other than a range loop is no longer an index.
    rebound = src.replace('    pid5 = msg.field("PID-5")\n', '    i = msg.field("PID-5")\n')
    with pytest.raises(LensRewriteError, match=REFUSED):
        rewrite_source(rebound, edit)


@pytest.mark.parametrize("name", ["range", "len", "print"])
def test_assign_to_and_code_set_var_cannot_shadow_a_builtin(name: str) -> None:
    params = {"connection": "MPI", "statement": "select 1", "params": {"expr": "{}"}}
    with pytest.raises(LensRewriteError, match="assign_to"):
        _insert(params, "db_lookup", assign_to=name)
    edit = {
        "line_start": _SEND,
        "line_end": _SEND,
        "op": "insert_code_lookup",
        "position": "before",
        "code_set": "gender",
        "path": "PID-8",
        "var": name,
    }
    with pytest.raises(LensRewriteError, match="reserved name"):
        rewrite_source(SOURCE, edit)


@pytest.mark.parametrize(
    "token",
    ['FhirToken("MRN", msg["A"], "x")', 'FhirToken("MRN", code=msg["A"])', "FhirToken(*x)"],
)
def test_fhir_token_admits_only_the_two_positional_form(token: str) -> None:
    params = {"connection": "EPIC", "query": "Patient", "params": {"expr": f'{{"id": {token}}}'}}
    with pytest.raises(LensRewriteError, match=REFUSED):
        _insert(params, "fhir_lookup")


# An occurrence is a whole number: ``1/3`` is a float (review of PR 2155).
@pytest.mark.parametrize(("expr", "ok"), [("i + 1", True), ("1/3", False), ("2 ** 99", False)])
def test_plain_arithmetic_in_a_numeric_field_is_admitted(expr: str, ok: bool) -> None:
    edit = {
        "line_start": _FOR + 1,
        "line_end": _FOR + 1,
        "op": "insert_row",
        "position": "before",
        "action": "set_field",
        "params": {"path": "OBX-11", "value": "F", "occurrence": {"expr": expr}},
    }
    if ok:
        assert f"occurrence={expr}" in rewrite_source(SOURCE, edit)
    else:
        with pytest.raises(LensRewriteError, match=f"{REFUSED}|not a whole number"):
            rewrite_source(SOURCE, edit)


def test_the_reported_send_destination_payload_is_refused() -> None:
    # The exact payload an independent review spliced through set_params on a send row at origin/main.
    with pytest.raises(LensRewriteError, match=REFUSED):
        _set_send("__import__('os').getenv('X') or 'OB_A'")


@pytest.mark.parametrize(
    "edit",
    [
        {"line_start": _IF, "line_end": _IF, "op": "insert_clause", "clause": "else", "test": "x"},
        {**_ELIF_RAW, "test": ""},
        {**_IF_RAW, "template": "filter"},
    ],
    ids=["else-ignores-test", "empty-test", "non-if-template"],
)
def test_typed_only_refuses_only_a_test_that_would_be_rendered(edit: dict[str, Any]) -> None:
    if edit.get("test") == "":
        edit = {**edit, "field": "PID-3.1"}
    assert rewrite_source(SOURCE, edit, typed_only=True) != SOURCE


_DB = {"connection": "MPI", "statement": "select 1", "params": {"expr": "{}"}}


@pytest.mark.parametrize(
    ("prefix", "binding", "name"),
    [
        # A try-guarded module import the handler reads would turn local and raise UnboundLocalError.
        (
            "try:\n    from zoneinfo import ZoneInfo\nexcept ImportError:\n    pass\n",
            "    ZoneInfo\n",
            "ZoneInfo",
        ),
        # Under a star import, a name the handler reads may come from it.
        ("from messagefoundry import *\n", "", "Send"),
        ("", "    try:\n        pass\n    except ValueError as err:\n        pass\n", "err"),
        ("", "    import os as osmod\n", "osmod"),
        # Pinned behaviour change: a second lookup into an existing local needs a new name.
        ("", "    row = 1\n", "row"),
    ],
)
def test_assign_to_refuses_any_name_the_handler_or_module_binds_or_reads(
    prefix: str, binding: str, name: str
) -> None:
    src = prefix + SOURCE.replace('    pid5 = msg.field("PID-5")\n', binding)
    send = len(src.splitlines())
    edit = {
        "line_start": send,
        "line_end": send,
        "op": "insert_row",
        "position": "before",
        "action": "db_lookup",
        "assign_to": name,
        "params": _DB,
    }
    with pytest.raises(LensRewriteError, match="assign_to"):
        rewrite_source(src, edit)
    # A name bound only inside ANOTHER function is not this handler's, so it is free here.
    other = "def other(msg):  # type: ignore[no-untyped-def]\n    fresh = 1\n\n\n" + SOURCE
    edit_other = {**edit, "assign_to": "fresh", "line_start": _SEND + 4, "line_end": _SEND + 4}
    assert "fresh = db_lookup(" in rewrite_source(other, edit_other)


@pytest.mark.parametrize(
    ("expr", "ok"),
    [
        ("pid5 * 2000000000", False),
        ("OB_DEST * 2000000000", False),
        ("OB_DEST % 3", False),
        # An occurrence is 1 or more on every message (review of PR 2155).
        ("i - 1", False),
        ("-i", False),
        ("2 * 3", True),
    ],
)
def test_multiplication_and_modulo_take_numbers_only(expr: str, ok: bool) -> None:
    edit = {
        "line_start": _FOR + 1,
        "line_end": _FOR + 1,
        "op": "insert_row",
        "position": "before",
        "action": "set_field",
        # A number slot: a field value must be text (review of PR 2155).
        "params": {"path": "OBX-11", "value": "F", "occurrence": {"expr": expr}},
    }
    if ok:
        assert expr in rewrite_source(SOURCE, edit)
    else:
        with pytest.raises(LensRewriteError, match=f"{REFUSED}|not a whole number"):
            rewrite_source(SOURCE, edit)


def test_a_fhir_repeated_parameter_list_of_tokens_is_admitted() -> None:
    value = '{"id": [FhirToken("MRN", msg["A"] or ""), "x"]}'
    params = {"connection": "EPIC", "query": "Patient", "params": {"expr": value}}
    assert value in _insert(params, "fhir_lookup")
    bad = '{"id": [FhirToken("MRN", msg["A"]), __import__("os")]}'
    with pytest.raises(LensRewriteError, match=REFUSED):
        _insert({**params, "params": {"expr": bad}}, "fhir_lookup")


def test_a_rebound_range_voids_the_loop_index_exemption() -> None:
    src = "range = lambda *a: [1]\n" + SOURCE
    edit = {
        "line_start": _FOR + 2,
        "line_end": _FOR + 2,
        "op": "insert_row",
        "position": "before",
        "action": "set_field",
        "params": {"path": "OBX-11", "value": "F", "occurrence": {"expr": "i"}},
    }
    with pytest.raises(LensRewriteError, match=REFUSED):
        rewrite_source(src, edit)


# --- round 3 (Theia review finding R1) -----------------------------------------------------------


@pytest.mark.parametrize(
    "test",
    [
        "(lambda x=(yield): x)",  # a lambda's default runs in the handler
        "(lambda: (await x))",  # parses, does not compile
        "[x async for x in y]",  # parses, does not compile in a sync handler
        "[i := 0 for i in w]",  # parses, does not compile
    ],
)
def test_raw_test_that_does_not_compile_or_yields_through_a_default_is_refused(test: str) -> None:
    with pytest.raises(LensRewriteError, match="raw 'test'|invalid Python"):
        _clause(test)


@pytest.mark.parametrize(
    ("action", "params", "name"),
    [
        ("db_lookup", _DB, "db_lookup"),
        (
            "fhir_lookup",
            {
                "connection": "EPIC",
                "query": "Patient",
                "params": {"expr": '{"id": FhirToken("MRN", msg["A"] or "")}'},
            },
            "FhirToken",
        ),
        ("db_lookup", _DB, "exit"),
    ],
)
def test_assign_to_cannot_shadow_what_the_inserted_line_reads(
    action: str, params: dict[str, Any], name: str
) -> None:
    with pytest.raises(LensRewriteError, match="assign_to"):
        _insert(params, action, assign_to=name)


def test_a_thousand_term_sum_is_a_clean_refusal() -> None:
    with pytest.raises(LensRewriteError, match="nested too deeply"):
        _insert({"path": "PID-3.1", "value": {"expr": "+".join(["1"] * 1000)}})


def test_inert_reads_with_a_loop_index_and_the_copy_fallback_are_admitted() -> None:
    edit = {
        "line_start": _FOR + 1,
        "line_end": _FOR + 1,
        "op": "insert_row",
        "position": "before",
        "action": "set_field",
        "params": {"path": "OBX-11", "value": {"expr": 'msg.field("OBX-5", occurrence=i)'}},
    }
    assert 'msg.field("OBX-5", occurrence=i)' in rewrite_source(SOURCE, edit)
    assert 'msg.field("PID-5") or ""' in _insert(
        {"path": "PID-3.1", "value": {"expr": 'msg.field("PID-5") or ""'}}
    )
    with pytest.raises(LensRewriteError, match=REFUSED):
        _insert({"path": "PID-3.1", "value": {"expr": 'msg.field("OBX-5", occurrence=pid5)'}})


@pytest.mark.parametrize(
    ("value", "ok"),
    [('FhirRaw("status,-date")', True), ('FhirRaw(msg["A"])', False), ("FhirRaw(x, y)", False)],
)
def test_fhir_raw_takes_a_literal_only(value: str, ok: bool) -> None:
    params = {"connection": "EPIC", "query": "Patient", "params": {"expr": f'{{"_sort": {value}}}'}}
    if ok:
        assert value in _insert(params, "fhir_lookup")
    else:
        with pytest.raises(LensRewriteError, match=REFUSED):
            _insert(params, "fhir_lookup")


def test_code_lookup_var_bound_by_except_as_is_refused() -> None:
    binding = "    try:\n        pass\n    except ValueError as GENDER:\n        pass\n"
    src = SOURCE.replace('    pid5 = msg.field("PID-5")\n', binding)
    send = len(src.splitlines())
    edit = {
        "line_start": send,
        "line_end": send,
        "op": "insert_code_lookup",
        "position": "before",
        "code_set": "gender",
        "path": "PID-8",
    }
    with pytest.raises(LensRewriteError, match="local variable"):
        rewrite_source(src, edit)


def test_a_star_import_voids_the_loop_index_exemption() -> None:
    src = "from somewhere import *\n" + SOURCE
    edit = {
        "line_start": _FOR + 2,
        "line_end": _FOR + 2,
        "op": "insert_row",
        "position": "before",
        "action": "set_field",
        "params": {"path": "OBX-11", "value": "F", "occurrence": {"expr": "i"}},
    }
    with pytest.raises(LensRewriteError, match=REFUSED):
        rewrite_source(src, edit)


@pytest.mark.parametrize("expr", ["1//0", "1/0", "1%3", 'b"x"', "1j", "...", "i / 2", "i // n"])
def test_division_by_zero_modulo_and_odd_constants_are_refused(expr: str) -> None:
    edit = {
        "line_start": _FOR + 1,
        "line_end": _FOR + 1,
        "op": "insert_row",
        "position": "before",
        "action": "set_field",
        "params": {"path": "OBX-11", "value": "F", "occurrence": {"expr": expr}},
    }
    with pytest.raises(LensRewriteError, match=REFUSED):
        rewrite_source(SOURCE, edit)


@pytest.mark.parametrize(
    ("action", "params"),
    [
        # Measured, item 3: an f-string reading the message is refused in a statement and in a
        # log_note template or operand, because none of those is a value parameter.
        (
            "db_lookup",
            {"connection": "M", "statement": {"expr": "f\"s {msg['PID-3']}\""}, "params": None},
        ),
        ("log_note", {"template": {"expr": "f\"MRN {msg['PID-3']}\""}}),
        ("log_note", {"template": "MRN {}", "operand": {"expr": "f\"{msg['PID-3']}\""}}),
    ],
)
def test_an_f_string_read_is_refused_outside_a_value_param(
    action: str, params: dict[str, Any]
) -> None:
    with pytest.raises(LensRewriteError, match=REFUSED):
        _insert(params, action)


# --- dynamic overwrite, every mode ---------------------------------------------------------------


def test_route_set_params_refuses_to_overwrite_a_computed_list() -> None:
    src = '@router("R")\ndef r(msg):\n    return [pick(msg)]\n'
    edit = {"line_start": 3, "line_end": 3, "op": "set_params", "params": {"handlers": ["H1"]}}
    with pytest.raises(LensRewriteError, match="computed by code") as info:
        rewrite_source(src, edit, contract=2)
    assert info.value.code == "refused"
    literal = src.replace("[pick(msg)]", '["H0"]')
    assert 'return ["H1"]' in rewrite_source(literal, edit, contract=2)


def test_send_set_params_refuses_to_overwrite_a_computed_destination() -> None:
    src = '@handler("H")\ndef h(msg):\n    return Send(pick(msg), msg)\n'
    edit = {"line_start": 3, "line_end": 3, "op": "set_params", "params": {"to": {"expr": '"OB"'}}}
    with pytest.raises(LensRewriteError, match="computed by code"):
        rewrite_source(src, edit)
    # A module-level literal is inert, so it may be overwritten (Manager decision 2026-10-07).
    named = 'OB_DEST = "OB_X"\n\n\n' + src.replace("pick(msg)", "OB_DEST")
    edit = {**edit, "line_start": 6, "line_end": 6}
    assert 'return Send("OB", msg)' in rewrite_source(named, edit)


# --- typed-only structure limits (Manager decision 2026-10-07) -----------------------------------

_STRUCT = """\
@handler("H")
def h(msg):
    x = compute(msg)
    if msg.field("PID-3.1") == "A":
        pass
    if msg.field("PID-3.1"):
        y = compute(msg)
    if re.match("A", msg["PID-3"] or ""):
        pass
    for i in range(1, msg.count_segments("OBX") + 1):
        msg.set("OBX-11", "F", occurrence=i)
    return Send("OB", msg)
"""


def _struct(op: str, line: int, *, typed_only: bool) -> str:
    edit: dict[str, Any] = {"line_start": line, "line_end": line, "op": op}
    if op == "move_row":
        edit["direction"] = "down" if line == 3 else "up"
    return rewrite_source(_STRUCT, edit, typed_only=typed_only)


@pytest.mark.parametrize(
    ("op", "line"),
    [
        ("move_row", 3),  # a lone code row
        ("move_row", 6),  # an if whose body holds a code row
        ("delete_row", 6),
        ("move_row", 8),  # an if whose test no typed input renders
        ("delete_row", 8),
    ],
)
def test_typed_only_refuses_moving_or_deleting_untyped_code(op: str, line: int) -> None:
    assert _struct(op, line, typed_only=False) != _STRUCT
    with pytest.raises(LensRewriteError, match="typed-only mode") as info:
        _struct(op, line, typed_only=True)
    assert info.value.code == "refused"


@pytest.mark.parametrize(("op", "line"), [("delete_row", 4), ("delete_row", 10)])
def test_typed_only_still_moves_and_deletes_typed_blocks(op: str, line: int) -> None:
    assert _struct(op, line, typed_only=True) != _STRUCT


# --- round 3 repair -------------------------------------------------------------------------------


def test_route_set_params_still_edits_an_unrouted_return_none() -> None:
    src = '@router("R")\ndef r(msg):\n    return None\n'
    edit = {"line_start": 3, "line_end": 3, "op": "set_params", "params": {"handlers": ["H1"]}}
    assert 'return ["H1"]' in rewrite_source(src, edit, contract=2)


def test_a_for_header_with_an_unrenderable_segment_is_a_clean_refusal() -> None:
    src = _STRUCT.replace('count_segments("OBX")', 'count_segments("O\\nX")')
    with pytest.raises(LensRewriteError, match="typed-only mode"):
        rewrite_source(src, {"line_start": 10, "line_end": 10, "op": "delete_row"}, typed_only=True)


@pytest.mark.parametrize(
    "edit",
    [
        # Swapping a typed row with an untyped neighbour moves the untyped one too.
        {"line_start": 4, "line_end": 4, "op": "move_row", "direction": "up"},
        # Dropping a typed row into an untyped block.
        {
            "line_start": 12,
            "line_end": 12,
            "op": "move_row",
            "to_line_start": 9,
            "to_position": "after",
        },
    ],
    ids=["swap-with-code", "drop-into-untyped-if"],
)
def test_typed_only_refuses_a_move_that_shifts_untyped_code(edit: dict[str, Any]) -> None:
    assert rewrite_source(_STRUCT, edit) != _STRUCT
    with pytest.raises(LensRewriteError, match="typed-only mode"):
        rewrite_source(_STRUCT, edit, typed_only=True)


_CHAINS = """\
@handler("H")
def h(msg):
    if msg.field("A") == "1":
        pass
    elif msg.field("B"):
        pass
    else:
        msg.set("C", "x")
    if msg.field("A"):
        pass
    elif re.match("x", msg["A"] or ""):
        pass
    if msg.field("A"):
        pass
    else:
        z = compute(msg)
    if msg.field("A"):
        while True:
            break
    if msg.field("A"):
        x = msg.field("B")
    if msg.field("A"):
        raise ValueError("stop")
    raise ValueError("end")
"""


@pytest.mark.parametrize(
    ("line", "ok"),
    [
        (3, True),  # a typed if/elif/else chain
        (9, False),  # an untyped elif
        (13, False),  # a code row in the else
        (17, False),  # a while nested in a typed if
        (20, False),  # a Read Field binding inside the block
        (22, True),  # a typed raise inside a typed if
    ],
)
def test_typed_only_delete_walks_the_whole_chain(line: int, ok: bool) -> None:
    edit = {"line_start": line, "line_end": line, "op": "delete_row"}
    if ok:
        assert rewrite_source(_CHAINS, edit, typed_only=True) != _CHAINS
    else:
        with pytest.raises(LensRewriteError, match="typed-only mode"):
            rewrite_source(_CHAINS, edit, typed_only=True)


@pytest.mark.parametrize("typed_only", [False, True])
def test_a_typed_raise_row_never_moves_above_a_row(typed_only: bool) -> None:
    # A raise moved up its suite strands what it passes (ADR 0076 G.6 rule 8), in both modes.
    rows = parse_source(_CHAINS)[0]["rows"]
    last = next(r for r in rows if r["line_start"] == 24)
    edit = {"line_start": 24, "line_end": last["line_end"], "op": "move_row", "direction": "up"}
    with pytest.raises(LensRewriteError, match="below a return or raise"):
        rewrite_source(_CHAINS, edit, typed_only=typed_only)


def test_the_cli_typed_only_flag_refuses_moving_a_code_row(tmp_path: Path) -> None:
    module = tmp_path / "h.py"
    module.write_text(_STRUCT, encoding="utf-8")
    edit = {"line_start": 3, "line_end": 3, "op": "move_row", "direction": "down"}
    assert _cli(module, edit).returncode == 0
    proc = _cli(module, edit, "--typed-only")
    assert proc.returncode != 0
    assert json.loads(proc.stdout)["code"] == "refused"


def test_a_syntax_warning_in_existing_code_does_not_block_an_edit() -> None:
    src = SOURCE.replace('    pid5 = msg.field("PID-5")\n', '    flag = pid5 is "x"\n')
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        out = rewrite_source(
            src,
            {
                "line_start": _SEND,
                "line_end": _SEND,
                "op": "insert_row",
                "position": "before",
                "action": "set_field",
                "params": {"path": "PID-3.1", "value": "B"},
            },
        )
    assert 'msg.set("PID-3.1", "B")' in out


def test_a_fhir_value_object_gets_its_import_and_cannot_be_shadowed() -> None:
    params = {
        "connection": "EPIC",
        "query": "Patient",
        "params": {"expr": '{"id": FhirToken("MRN", msg["A"] or "")}'},
    }
    assert "from messagefoundry import FhirToken" in _insert(params, "fhir_lookup")
    shadowed = SOURCE.replace('    pid5 = msg.field("PID-5")\n', "    FhirToken = 1\n")
    edit = {
        "line_start": _SEND,
        "line_end": _SEND,
        "op": "insert_row",
        "position": "before",
        "action": "fhir_lookup",
        "params": params,
    }
    with pytest.raises(LensRewriteError, match=REFUSED):
        rewrite_source(shadowed, edit)


@pytest.mark.parametrize("expr", ["{[1]}", "{(1, [2]): 1}", '{{"a": 1}: 2}'])
def test_an_unhashable_set_member_or_dict_key_is_refused(expr: str) -> None:
    with pytest.raises(LensRewriteError, match=REFUSED):
        _insert({"src": "PID-5", "sep": "^", "dests": {"expr": expr}}, "split_field")

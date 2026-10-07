# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A typed Steps edit cannot write code that runs (Theia review finding R1).

``lens rewrite`` used to splice an ``{"expr": ...}`` verbatim on ``insert_row`` and on a send row's
destination, and the raw ``if``/``elif`` ``test`` could carry line breaks that add statements. Each
refused case below is paired with a control the lens must still accept, so a refusal is attributable to
the payload and not to a broken edit spec.

``paste_block`` and a single-line raw ``test`` still take arbitrary source: both are the escape hatches
ADR 0076 section 5 and ADR 0106 license, and restricting them is an owner question, not this fix.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.lens import LensRewriteError, parse_source, rewrite_source

SOURCE = """\
@handler("H")
def h(msg):
    for i in range(1, msg.count_segments("OBX") + 1):
        pass
    if msg.field("PID-3.1"):
        pass
    return Send("OB_ACME_ADT", msg)
"""
_FOR, _IF, _SEND = 3, 5, 7

EVIL_CALL = '__import__("os").system("x")'
EVIL_ATTR = "msg.__class__.__init__.__globals__"
EVIL_METHOD = 'msg.field("PID-3").upper()'
EVIL_OP = '"a" + "b"'
EVIL_LAMBDA = "(lambda: 0)"
EVIL_DUNDER_NAME = "__builtins__"
EVIL_SPLAT = "[*x]"
EVIL_DICT_SPLAT = "{**x}"
EVIL_NESTED = '{"k": [__import__("os")]}'
EVIL_FSTRING_CALL = 'f"{x()}"'
EVIL_WALRUS = "(x := 1)"

_ACTIVE = [
    EVIL_FSTRING_CALL,
    EVIL_WALRUS,
    EVIL_CALL,
    EVIL_ATTR,
    EVIL_METHOD,
    EVIL_OP,
    EVIL_LAMBDA,
    EVIL_DUNDER_NAME,
    EVIL_SPLAT,
    EVIL_DICT_SPLAT,
    EVIL_NESTED,
]


def _insert(params: dict[str, Any], action: str = "set_field") -> str:
    return rewrite_source(
        SOURCE,
        {
            "line_start": _SEND,
            "line_end": _SEND,
            "op": "insert_row",
            "position": "before",
            "action": action,
            "params": params,
        },
    )


@pytest.mark.parametrize("expr", _ACTIVE)
def test_insert_row_refuses_an_expr_that_runs_code(expr: str) -> None:
    with pytest.raises(LensRewriteError, match="would run code"):
        _insert({"path": "PID-3.1", "value": {"expr": expr}})


@pytest.mark.parametrize(
    ("params", "action", "spliced"),
    [
        ({"path": "PID-3.1", "value": {"expr": "0"}}, "set_field", "0"),
        ({"path": "PID-3.1", "value": {"expr": "-1"}}, "set_field", "-1"),
        ({"path": "PID-3.1", "value": {"expr": 'msg["PID-5"]'}}, "set_field", 'msg["PID-5"]'),
        (
            {"path": "PID-3.1", "value": {"expr": 'msg["PID-5"] or ""'}},
            "set_field",
            'msg["PID-5"] or ""',
        ),
        ({"path": "PID-3.1", "value": {"expr": "other_var"}}, "set_field", "other_var"),
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
                "params": {"expr": '{"mrn": msg["PID-3.1"]}'},
            },
            "db_lookup",
            '{"mrn": msg["PID-3.1"]}',
        ),
    ],
)
def test_insert_row_still_accepts_inert_values(
    params: dict[str, Any], action: str, spliced: str
) -> None:
    out = _insert(params, action)
    assert spliced in out
    ast.parse(out)


def test_occurrence_loop_index_is_still_accepted_and_a_call_is_not() -> None:
    edit = {
        "line_start": _FOR + 1,
        "line_end": _FOR + 1,
        "op": "insert_row",
        "position": "before",
        "action": "set_field",
        "params": {"path": "OBX-11", "value": "F", "occurrence": {"expr": "i"}},
    }
    assert "occurrence=i" in rewrite_source(SOURCE, edit)
    edit["params"] = {"path": "OBX-11", "value": "F", "occurrence": {"expr": EVIL_CALL}}
    with pytest.raises(LensRewriteError, match="would run code"):
        rewrite_source(SOURCE, edit)


def test_code_lookup_default_refuses_an_expr_that_runs_code() -> None:
    edit: dict[str, Any] = {
        "line_start": _SEND,
        "line_end": _SEND,
        "op": "insert_code_lookup",
        "position": "before",
        "code_set": "gender",
        "path": "PID-8",
        "default": {"expr": EVIL_CALL},
    }
    with pytest.raises(LensRewriteError, match="would run code"):
        rewrite_source(SOURCE, edit)
    edit["default"] = "U"
    assert 'code_lookup(msg, "PID-8", GENDER, default="U")' in rewrite_source(SOURCE, edit)


@pytest.mark.parametrize("expr", [EVIL_CALL, EVIL_ATTR, EVIL_OP])
def test_send_destination_refuses_an_expr_that_runs_code(expr: str) -> None:
    with pytest.raises(LensRewriteError, match="would run code"):
        rewrite_source(
            SOURCE,
            {
                "line_start": _SEND,
                "line_end": _SEND,
                "op": "set_params",
                "params": {"to": {"expr": expr}},
            },
        )


@pytest.mark.parametrize(("expr", "spliced"), [('"OB_NEW"', '"OB_NEW"'), ("OB_DEST", "OB_DEST")])
def test_send_destination_still_accepts_a_literal_or_a_name(expr: str, spliced: str) -> None:
    out = rewrite_source(
        SOURCE,
        {
            "line_start": _SEND,
            "line_end": _SEND,
            "op": "set_params",
            "params": {"to": {"expr": expr}},
        },
    )
    assert f"return Send({spliced}, msg)" in out


def test_route_list_edit_is_unaffected() -> None:
    src = '@router("R")\ndef r(msg):\n    return ["a"]\n'
    out = rewrite_source(
        src,
        {"line_start": 3, "line_end": 3, "op": "set_params", "params": {"handlers": ["b", "c"]}},
        contract=2,
    )
    assert 'return ["b", "c"]' in out


_SMUGGLE = "True:\n        " + EVIL_CALL + "\n    elif True"


@pytest.mark.parametrize("test", [_SMUGGLE, "True\r\nx = 1", "True:"])
def test_elif_raw_test_must_be_one_line_and_one_expression(test: str) -> None:
    with pytest.raises(LensRewriteError, match="raw 'test'"):
        rewrite_source(
            SOURCE,
            {
                "line_start": _IF,
                "line_end": _IF,
                "op": "insert_clause",
                "clause": "elif",
                "test": test,
            },
        )


def test_if_template_raw_test_must_be_one_line() -> None:
    with pytest.raises(LensRewriteError, match="raw 'test'"):
        rewrite_source(
            SOURCE,
            {
                "line_start": _SEND,
                "line_end": _SEND,
                "op": "template",
                "template": "if",
                "position": "before",
                "test": _SMUGGLE,
            },
        )


def test_typed_if_and_a_single_line_raw_test_are_still_accepted() -> None:
    typed = rewrite_source(
        SOURCE,
        {
            "line_start": _IF,
            "line_end": _IF,
            "op": "insert_clause",
            "clause": "elif",
            "field": "PID-3.1",
            "operator": "equals",
            "value": "A",
        },
    )
    assert 'elif msg.field("PID-3.1") == "A":' in typed
    raw = rewrite_source(
        SOURCE,
        {
            "line_start": _IF,
            "line_end": _IF,
            "op": "insert_clause",
            "clause": "elif",
            "test": 're.match("^A", msg["PID-3.1"] or "")',
        },
    )
    assert 'elif re.match("^A", msg["PID-3.1"] or ""):' in raw
    # The smuggled form would have added a statement; the accepted one adds exactly the clause.
    assert len(parse_source(raw)[0]["rows"]) == len(parse_source(SOURCE)[0]["rows"]) + 2


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
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "messagefoundry",
            "lens",
            "rewrite",
            str(module),
            "--edit",
            json.dumps(edit),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "would run code" in proc.stdout + proc.stderr
    assert module.read_text(encoding="utf-8") == SOURCE


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
            "fhir_lookup",
            {"connection": {"expr": 'msg["MSH-3"]'}, "query": "Patient", "params": {"expr": "{}"}},
        ),
        # A diagnostic template is logged unredacted.
        ("log_note", {"template": {"expr": 'msg["PID-5"]'}}),
        # A path chosen by message content picks which field is overwritten.
        ("set_field", {"path": {"expr": 'msg["ZZZ-1"]'}, "value": "x"}),
    ],
)
def test_insert_row_keeps_message_content_out_of_non_value_params(
    action: str, params: dict[str, Any]
) -> None:
    with pytest.raises(LensRewriteError, match="not a value a Steps edit may write"):
        _insert(params, action)


def test_occurrence_cannot_be_message_content() -> None:
    edit = {
        "line_start": _FOR + 1,
        "line_end": _FOR + 1,
        "op": "insert_row",
        "position": "before",
        "action": "set_field",
        "params": {"path": "OBX-11", "value": "F", "occurrence": {"expr": 'msg["PID-9"]'}},
    }
    with pytest.raises(LensRewriteError, match="not a value a Steps edit may write"):
        rewrite_source(SOURCE, edit)


@pytest.mark.parametrize("name", ["msg", "__x__", "class"])
def test_insert_row_assign_to_cannot_rebind_msg_or_take_a_reserved_name(name: str) -> None:
    edit = {
        "line_start": _SEND,
        "line_end": _SEND,
        "op": "insert_row",
        "position": "before",
        "action": "db_lookup",
        "assign_to": name,
        "params": {"connection": "MPI", "statement": "select 1", "params": {"expr": "{}"}},
    }
    with pytest.raises(LensRewriteError, match="assign_to"):
        rewrite_source(SOURCE, edit)
    edit["assign_to"] = "row"
    assert 'row = db_lookup("MPI", "select 1", {})' in rewrite_source(SOURCE, edit)


@pytest.mark.parametrize("test", ["(yield)", "(yield from x)", "(await x)"])
def test_raw_test_cannot_yield_or_await(test: str) -> None:
    with pytest.raises(LensRewriteError, match="raw 'test'"):
        rewrite_source(
            SOURCE,
            {
                "line_start": _IF,
                "line_end": _IF,
                "op": "insert_clause",
                "clause": "elif",
                "test": test,
            },
        )


_APPEND_SOURCE = """\
@handler("H")
def h(msg):
    sends = []
    sends.append(Send("OB_ACME_ADT", msg))
    return sends
"""


@pytest.mark.parametrize(
    ("expr", "ok"), [(EVIL_CALL, False), ("__builtins__", False), ('"OB_NEW"', True)]
)
def test_appended_send_destination_is_gated_too(expr: str, ok: bool) -> None:
    edit = {"line_start": 4, "line_end": 4, "op": "set_params", "params": {"to": {"expr": expr}}}
    if ok:
        assert f"sends.append(Send({expr}, msg))" in rewrite_source(_APPEND_SOURCE, edit)
    else:
        with pytest.raises(LensRewriteError, match="not a value a Steps edit may write"):
            rewrite_source(_APPEND_SOURCE, edit)

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Peer text is escaped before a command-line tool prints it to a terminal (ASVS 1.1.2).

The rule is :func:`messagefoundry.terminal_text.escape_for_terminal`. ``samples/send_mllp.py``
prints an ACK by it (``tests/test_send_mllp_frame_bytes.py``); this file covers the rule itself and
the other places that now print by it: ``rigadmin get``, the harness scenario and load command
lines, and the reconcile text report.
"""

from __future__ import annotations

import argparse
import json
from typing import Any

import pytest

from harness.load import rigadmin
from messagefoundry.apiclient import ApiError
from messagefoundry.terminal_text import escape_for_terminal, escape_json_for_terminal

#: A sender's bytes that would drive a terminal: clear screen (ESC CSI), retitle the window (OSC
#: ending in BEL), DEL, an 8-bit CSI (U+009B) and a right-to-left override (U+202E).
_HOSTILE = "A\x1b[2J\x1b]0;owned\x07\x7f\u009b1m\u202eB"
_HOSTILE_SHOWN = "A\\x1b[2J\\x1b]0;owned\\x07\\x7f\\u009b1m\\u202eB"


# --- the rule ------------------------------------------------------------------


def test_printable_ascii_newline_and_tab_print_as_themselves() -> None:
    shown = "".join(chr(c) for c in range(0x20, 0x7F) if chr(c) != "\\") + "\n\t"
    assert escape_for_terminal(shown) == shown


@pytest.mark.parametrize("code", [c for c in range(0x20) if c not in (0x09, 0x0A)] + [0x7F])
def test_every_other_ascii_control_prints_as_a_hex_escape(code: int) -> None:
    assert escape_for_terminal(f"a{chr(code)}b") == f"a\\x{code:02x}b"


@pytest.mark.parametrize(
    ("char", "shown"),
    [
        ("\u0080", "\\u0080"),  # first C1 control
        ("\u009b", "\\u009b"),  # the 8-bit CSI
        ("\u009f", "\\u009f"),  # last C1 control
        ("\u00e9", "\\u00e9"),  # an accented letter is escaped too, so a cp1252 console can print
        ("\u200f", "\\u200f"),  # right-to-left mark
        ("\u202e", "\\u202e"),  # right-to-left override
        ("\u2066", "\\u2066"),  # left-to-right isolate
        ("\u2028", "\\u2028"),  # line separator
        ("\ufffd", "\\ufffd"),
        ("\U0001f600", "\\U0001f600"),
    ],
)
def test_every_code_point_past_ascii_prints_as_a_unicode_escape(char: str, shown: str) -> None:
    assert escape_for_terminal(char) == shown


def test_a_backslash_is_doubled_only_where_it_would_read_as_an_escape() -> None:
    # Ordinary text keeps its backslashes: an HL7 delimiter set and escape, a Windows path.
    assert escape_for_terminal("MSH|^~\\&|X\\F\\Y") == "MSH|^~\\&|X\\F\\Y"
    assert escape_for_terminal("C:\\Program Files\\app") == "C:\\Program Files\\app"
    # Text spelling an escape cannot pass for one, and stays apart from a real ESC.
    assert escape_for_terminal("\\x1b") == "\\\\x1b"
    assert escape_for_terminal("\x1b") == "\\x1b"
    assert escape_for_terminal("\\u202e") == "\\\\u202e"
    assert escape_for_terminal("\\U0001f600") == "\\\\U0001f600"
    assert escape_for_terminal("\\\x1b") == "\\\\\\x1b"  # a backslash before an escaped byte
    # A run is doubled whole before an escape-lookalike, and left alone elsewhere, so the parity
    # of the run before an escape tells a real one (odd) from text (even).
    assert escape_for_terminal("\\\\x1b") == "\\\\\\\\x1b"
    assert escape_for_terminal("\\\\") == "\\\\"


def test_the_output_is_ascii_so_any_console_codec_encodes_it() -> None:
    every = "".join(chr(c) for c in range(0x300)) + "\u202e\U0001f600"
    shown = escape_for_terminal(every)
    assert shown.isascii()
    assert shown.encode("ascii").decode("cp1252") == shown
    assert not any((ch < " " and ch not in "\n\t") or ch == "\x7f" for ch in shown)


# --- rigadmin get ----------------------------------------------------------------


def _engine(monkeypatch: pytest.MonkeyPatch, body: bytes) -> None:
    """A signed-in engine that answers every GET with ``body``: 401 without a session, 200 with."""

    def fake_call(method: str, url: str, **kw: Any) -> tuple[int, bytes]:
        return (200, body) if kw.get("bearer") else (401, b"")

    monkeypatch.setattr(rigadmin, "_call", fake_call)
    monkeypatch.setattr(rigadmin, "sign_in", lambda base, admin=None, *, cacert=None: "session")


def _get(path: str, capsys: pytest.CaptureFixture[str]) -> str:
    assert rigadmin.main(["get", "--engine", "http://127.0.0.1:9", path]) == 0
    return capsys.readouterr().out


def test_get_escapes_a_body_that_would_drive_the_terminal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The attachment route answers with a sender's own bytes.
    _engine(monkeypatch, _HOSTILE.encode("utf-8") + b"\xff\r\n")
    assert _get("/messages/m1/attachments/a1", capsys) == _HOSTILE_SHOWN + "\\ufffd\\x0d\n"


def test_get_prints_a_clean_json_body_unchanged(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    body = b'{"total":3,"messages":[{"id":"m1","status":"processed"}]}'
    _engine(monkeypatch, body)
    assert _get("/messages", capsys) == body.decode("ascii")


def test_get_keeps_a_json_body_meaning_the_same_value(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A Windows path is a JSON escape the text rule would double, so it must print as it came.
    path_body = json.dumps({"interpreter": {"executable": "C:\\Python\\python.exe"}}).encode()
    _engine(monkeypatch, path_body)
    assert _get("/security/posture", capsys) == path_body.decode("ascii")

    # Non-ASCII in a string value is valid JSON. It prints as JSON's own \u escape, with a
    # surrogate pair past the BMP, and a CR between tokens as a newline. Nothing is decoded and
    # written again, so a number, a duplicate key and the layout all survive.
    body = (
        '{"detail":"\u009b1m\u202eB\u00e9\U0001f600",\r\n"big":1e400,"big":12345678901234567890.5}'
    )
    _engine(monkeypatch, body.encode("utf-8"))
    assert _get("/security/posture", capsys) == (
        '{"detail":"\\u009b1m\\u202eB\\u00e9\\ud83d\\ude00",\n\n"big":1e400,'
        '"big":12345678901234567890.5}'
    )


def test_get_prints_a_body_too_deep_for_json_rather_than_crashing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _engine(monkeypatch, b"[" * 200_000)
    assert _get("/messages/m1/attachments/a1", capsys) == "[" * 200_000
    # The integer reader refuses it the same way, with nothing on stdout.
    code = rigadmin.main(["get", "--engine", "http://127.0.0.1:9", "--field", "total", "/x"])
    assert code == 1
    assert capsys.readouterr().out == ""


def test_get_reads_json_past_pythons_integer_digit_limit_as_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Valid JSON Python will not convert must still keep its value: a backslash is not doubled.
    body = '{"n":' + "9" * 5000 + ',"path":"C:\\\\x\u00e9"}'
    _engine(monkeypatch, body.encode("utf-8"))
    assert _get("/security/posture", capsys) == body.replace("\u00e9", "\\u00e9")


def test_the_json_escape_changes_no_value_and_leaves_plain_json_alone() -> None:
    plain = '{"a":"C:\\\\x","b":"\\u001b","c":[1e400,1,1]}'
    assert escape_json_for_terminal(plain) == plain
    assert escape_json_for_terminal('{"a":"\x7f\u0085\u2028"}') == '{"a":"\\u007f\\u0085\\u2028"}'
    assert escape_json_for_terminal('{"a":"\U00010000"}') == '{"a":"\\ud800\\udc00"}'
    assert escape_json_for_terminal('{"a":"\U0010ffff"}') == '{"a":"\\udbff\\udfff"}'
    assert escape_json_for_terminal("[1,\r\n2]") == "[1,\n\n2]"


# --- harness command line ----------------------------------------------------------


class _Client:
    def __init__(self, url: str, cacert: str | None = None) -> None:
        pass

    def __enter__(self) -> _Client:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def _scenario(monkeypatch: pytest.MonkeyPatch, outcome: Any) -> None:
    import harness.scenarios
    import messagefoundry.apiclient

    def run(scenario: object, client: object, **kw: object) -> object:
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(harness.scenarios, "SCENARIOS", {"probe": object()})
    monkeypatch.setattr(harness.scenarios, "run_scenario", run)
    monkeypatch.setattr(messagefoundry.apiclient, "EngineClient", _Client)


@pytest.mark.parametrize(
    ("ok", "skipped", "verdict", "code"),
    [(True, False, "PASS", 0), (False, False, "FAIL", 1), (False, True, "SKIP", 2)],
)
def test_a_scenario_verdict_prints_its_detail_escaped(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    ok: bool,
    skipped: bool,
    verdict: str,
    code: int,
) -> None:
    from harness.__main__ import _run_scenario
    from harness.scenarios import ScenarioResult

    _scenario(monkeypatch, ScenarioResult(object(), ok, f"ACK said {_HOSTILE}", skipped))  # type: ignore[arg-type]
    assert _run_scenario("probe", "https://127.0.0.1:9", None, 1.0, None) == code
    assert capsys.readouterr().out == f"{verdict}  probe: ACK said {_HOSTILE_SHOWN}\n"


def test_a_scenario_api_error_prints_the_engines_text_escaped(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from harness.__main__ import _run_scenario

    _scenario(monkeypatch, ApiError(f"HTTP 422: {_HOSTILE}", status=422))
    assert _run_scenario("probe", "https://127.0.0.1:9", None, 1.0, None) == 1
    assert capsys.readouterr().err == f"FAIL  probe: HTTP 422: {_HOSTILE_SHOWN}\n"


def test_a_load_runs_engine_setup_error_prints_escaped(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import harness.load.profile
    import harness.load.runner
    from harness.__main__ import _run_load

    async def refused(*args: object, **kw: object) -> object:
        raise ApiError(f"HTTP 401: {_HOSTILE}", status=401)

    monkeypatch.setattr(harness.load.profile, "get_profile", lambda name: object())
    monkeypatch.setattr(harness.load.runner, "run_load", refused)
    args = argparse.Namespace(
        load="any",
        engine="https://127.0.0.1:9",
        token=None,
        sink_port=None,
        sink_ports=None,
        db_backend=None,
        skip_preflight=True,
        shard_engine=None,
        cacert=None,
    )
    assert _run_load(args) == 2
    assert capsys.readouterr().err == f"engine setup failed: HTTP 401: {_HOSTILE_SHOWN}\n"


# --- harness reconcile -----------------------------------------------------------------


def test_the_reconcile_report_prints_message_keys_and_differences_escaped() -> None:
    from harness.reconcile.compare import MessagePair, ReconcileResult
    from harness.reconcile.normalize import Difference
    from harness.reconcile.report import render_text

    # A segment id is whatever a captured line holds before its first field separator.
    diff = Difference(_HOSTILE, 1, None, "x", None, "left-only-segment")
    result = ReconcileResult(
        "IB_DEMO",
        pairs=[MessagePair(f"K1{_HOSTILE}", [diff])],
        mefor_only=[f"K2{_HOSTILE}"],
        corepoint_only=[f"K3{_HOSTILE}"],
    )
    text = render_text(result)
    assert f"K1{_HOSTILE_SHOWN}:" in text
    assert f"left-only-segment @ {_HOSTILE_SHOWN}[1]: left='x' right=None" in text
    assert f"MEFOR-only keys: K2{_HOSTILE_SHOWN}" in text
    assert f"Corepoint-only keys: K3{_HOSTILE_SHOWN}" in text
    assert not any(ch in text for ch in "\x1b\x07\x7f\u009b\u202e")


def test_the_shared_rule_imports_only_the_standard_library() -> None:
    # harness/load/rigadmin.py imports it from a file that promises the standard library only.
    import ast
    import sys
    from pathlib import Path

    import messagefoundry.terminal_text as module

    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert imported, "the walk found no import at all, so it proves nothing"
    assert {name.split(".")[0] for name in imported} <= set(sys.stdlib_module_names)

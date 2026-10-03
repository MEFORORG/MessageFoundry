# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The remaining console sinks print peer text through the shared rule (ASVS 1.1.2).

``tests/test_terminal_text.py`` covers the strict rule and the sinks that first adopted it. This
file covers the two options added after it -- ``single_line`` and ``keep_printable_unicode`` --
and the sinks that use them: the ``messagefoundry verify`` console summary (a JWKS key id is
peer-supplied), the harness ``shardcert`` two-box ``ApiError`` lines, the ``--fuzz`` setup and
failure lines, and the one-line scenario and load verdicts, where a newline in peer text could
start a forged ``PASS`` line.
"""

from __future__ import annotations

import base64
import functools
import json
import unicodedata
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from messagefoundry.apiclient import ApiError
from messagefoundry.terminal_text import CONTROL_CATEGORIES, escape_for_terminal
from messagefoundry.verify.model import CheckResult, Status
from messagefoundry.verify.report import render_console, render_json, render_markdown

#: ESC CSI, an 8-bit CSI (U+009B), a right-to-left override (U+202E), a left-to-right isolate.
_HOSTILE = "k\x1b[2J\u009b1m\u202eevil\u2066"
_HOSTILE_SHOWN = "k\\x1b[2J\\u009b1m\\u202eevil\\u2066"


def _keep(text: str, *, single_line: bool = False) -> str:
    return escape_for_terminal(text, keep_printable_unicode=True, single_line=single_line)


# --- keep_printable_unicode: the alphabet ---------------------------------------------------


@pytest.mark.parametrize(
    "char",
    [
        "\u00e9",  # an accented letter
        "\u2014",  # the em dash the engine's own verify details use
        "\u2192",  # an arrow
        "\u00a0",  # a no-break space (Zs) prints as a space would
        "\u4e2d",  # a CJK letter
        "\U0001f600",  # past the BMP
    ],
)
def test_keeping_unicode_prints_a_printable_character_as_itself(char: str) -> None:
    assert _keep(f"a{char}b") == f"a{char}b"


@pytest.mark.parametrize(
    ("char", "shown"),
    [
        ("\x1b", "\\x1b"),  # ESC (Cc, C0)
        ("\x7f", "\\x7f"),  # DEL
        ("\u0085", "\\u0085"),  # NEL (Cc, C1)
        ("\u009b", "\\u009b"),  # the 8-bit CSI
        ("\u00ad", "\\u00ad"),  # soft hyphen (Cf)
        ("\u200b", "\\u200b"),  # zero-width space (Cf)
        ("\u200e", "\\u200e"),  # left-to-right mark
        ("\u200f", "\\u200f"),  # right-to-left mark
        ("\u202a", "\\u202a"),  # left-to-right embedding
        ("\u202e", "\\u202e"),  # right-to-left override
        ("\u2066", "\\u2066"),  # left-to-right isolate
        ("\u2069", "\\u2069"),  # pop directional isolate
        ("\ufeff", "\\ufeff"),  # zero-width no-break space / BOM (Cf)
        ("\u2028", "\\u2028"),  # line separator (Zl)
        ("\u2029", "\\u2029"),  # paragraph separator (Zp)
        ("\ud800", "\\ud800"),  # a lone surrogate (Cs)
        ("\ue000", "\\ue000"),  # private use (Co)
        ("\U000e0001", "\\U000e0001"),  # language tag (Cf), past the BMP
    ],
)
def test_keeping_unicode_still_escapes_every_control_and_format_character(
    char: str, shown: str
) -> None:
    assert _keep(f"a{char}b") == f"a{shown}b"


def test_keeping_unicode_escapes_exactly_the_named_categories_over_the_whole_bmp() -> None:
    # The alphabet is stated once, as CONTROL_CATEGORIES; this walks every BMP code point past
    # ASCII and holds the function to it, so the two cannot drift apart.
    for code in range(0x80, 0x10000):
        char = chr(code)
        expected_escaped = unicodedata.category(char) in CONTROL_CATEGORIES
        assert (_keep(char) != char) is expected_escaped, f"U+{code:04X}"


def test_keeping_unicode_keeps_newline_and_tab_unless_single_line() -> None:
    assert _keep("a\nb\tc") == "a\nb\tc"
    assert _keep("a\nb\tc", single_line=True) == "a\\x0ab\\x09c"


def test_keeping_unicode_disambiguates_a_backslash_as_the_strict_rule_does() -> None:
    assert _keep("\\x1b") == "\\\\x1b"  # text spelling an escape
    assert _keep("\\u202e") == "\\\\u202e"
    assert _keep("\\\u202e") == "\\\\\\u202e"  # a backslash before an escaped character
    assert _keep("\\\\x1b") == "\\\\\\\\x1b"  # a run before a lookalike is doubled whole
    assert _keep("\\\\") == "\\\\"
    # A backslash before ASCII that prints as itself stays single, as before plain text. Before a
    # non-ASCII character it is doubled, because a kept character can pass for an escape letter.
    assert _keep("C:\\caf\u00e9\\\u00e9") == "C:\\caf\u00e9\\\\\u00e9"
    assert _keep("MSH|^~\\&|") == "MSH|^~\\&|"


@pytest.mark.parametrize("keep", [False, True])
def test_a_windows_or_unc_path_prints_as_typed(keep: bool) -> None:
    for path in ("C:\\Users\\svc\\mf", "\\\\fileserver\\share\\mf", "C:\\x\\unit\\Up"):
        assert escape_for_terminal(path, keep_printable_unicode=keep) == path
        assert escape_for_terminal(path, keep_printable_unicode=keep, single_line=True) == path


def test_a_long_backslash_run_is_one_linear_pass() -> None:
    import time

    started = time.perf_counter()
    assert escape_for_terminal("\\" * 200_000 + "!") == "\\" * 200_000 + "!"
    assert escape_for_terminal("\\" * 200_000 + "\x1b") == "\\" * 400_000 + "\\x1b"
    # A per-backslash lookahead over the run would be quadratic: minutes, not milliseconds.
    assert time.perf_counter() - started < 5.0


# --- single_line on the strict rule ---------------------------------------------------------


def test_single_line_escapes_newline_tab_and_cr_and_nothing_else_new() -> None:
    assert escape_for_terminal("a\nb\tc\rd", single_line=True) == "a\\x0ab\\x09c\\x0dd"
    shown = "".join(chr(c) for c in range(0x20, 0x7F) if chr(c) != "\\")
    assert escape_for_terminal(shown, single_line=True) == shown
    assert escape_for_terminal("\\\n", single_line=True) == "\\\\\\x0a"
    # The default is unchanged: a multi-line output keeps its lines.
    assert escape_for_terminal("a\nb\tc") == "a\nb\tc"


# --- messagefoundry verify --------------------------------------------------------------------


def _b64u_uint(v: int) -> str:
    raw = v.to_bytes((v.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@functools.cache
def _public_numbers() -> rsa.RSAPublicNumbers:
    # One key for the whole file; the key id is what these tests vary, not the key.
    return (
        rsa.generate_private_key(public_exponent=65537, key_size=3072).public_key().public_numbers()
    )


def _jwks(kid: str) -> bytes:
    n = _public_numbers()
    key = {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": _b64u_uint(n.n)}
    key["e"] = _b64u_uint(n.e)
    return json.dumps({"keys": [key]}).encode()


def test_verify_console_escapes_a_hostile_jwks_kid_and_keeps_the_em_dash() -> None:
    from messagefoundry.verify.federation import _jwks_row

    kid = f"{_HOSTILE}\nPASS   fed.replay     forged"
    _keys, row = _jwks_row(_jwks(kid))
    assert row.status is Status.PASS and kid in row.detail  # the RESULT keeps the value
    em_dash = CheckResult("fed.x", "control", Status.SKIP, "not reached \u2014 an earlier rung")
    console = render_console([row, em_dash])
    assert f"{_HOSTILE_SHOWN}\\x0aPASS   fed.replay     forged" in console
    assert not any(ch in console for ch in "\x1b\u009b\u202e\u2066")
    assert "not reached \u2014 an earlier rung" in console  # the engine's own text is untouched
    # One line per check and the tally: the kid's newline did not start a line of its own.
    assert len(console.splitlines()) == 2 + 2


def test_verify_console_leaves_every_engine_detail_without_peer_text_alone() -> None:
    rows = [
        CheckResult("host.python", "Python", Status.PASS, "interpreter ok \u2014 fine"),
        CheckResult("a", "title with \u00e9", Status.MANUAL, "C:\\Program Files\\app"),
        CheckResult("host.writable", "w", Status.FAIL, "C:\\Users\\svc not writable"),
    ]
    console = render_console(rows)
    assert "interpreter ok \u2014 fine" in console
    assert "title with \u00e9" in console
    assert "C:\\Program Files\\app" in console
    assert "C:\\Users\\svc not writable" in console


def test_verify_json_report_keeps_the_value_as_it_was() -> None:
    # The JSON report is data, not a terminal or a rendered page, so it carries the value whole.
    row = CheckResult("fed.jwks", "JWKS", Status.PASS, f"1 key(s): {_HOSTILE}")
    assert json.loads(render_json([row]))["results"][0]["detail"] == row.detail


def _table_rows(md: str) -> list[str]:
    return [line for line in md.splitlines() if line.startswith("|")][2:]  # past header + rule


def test_verify_markdown_neutralises_a_hostile_jwks_kid_in_one_row() -> None:
    from messagefoundry.verify.federation import _jwks_row

    kid = (
        f"{_HOSTILE}\n| fed.replay | forged | PASS | ok |\r"
        "<img src=x onerror=alert(1)>&#x202e;![x](https://e.invalid/b.png)"
        "`<b>`$\\color{green}PASS$a\\|b"
    )
    _keys, row = _jwks_row(_jwks(kid))
    assert kid in row.detail  # the RESULT keeps the value
    # The same text as a title too: every cell gets the rule, not only the detail.
    md = render_markdown([CheckResult(row.id, kid, row.status, row.detail)])
    rows = _table_rows(md)
    assert len(rows) == 1  # the kid's newline did not start a forged row
    # Four cells and no more: every pipe the peer sent, even after its own backslash, is inert.
    assert rows[0].count("|") == 5
    assert not any(ch in md for ch in "\x1b\u009b\u202e\u2066\r<")
    assert not any(ch in rows[0] for ch in "`$")  # the header keeps its own code span
    for cell in rows[0].split(" | ")[1::2]:  # the title and the detail
        assert _HOSTILE_SHOWN in cell
        assert "\\x0a&#124; fed.replay &#124; forged" in cell
        assert "&lt;img src=x onerror=alert(1)&gt;" in cell
        assert "&amp;#x202e;" in cell  # a peer's reference cannot decode to the control
        assert "![x]&#40;https://e.invalid/b.png)" in cell  # no image to fetch on view
        assert "&#96;&lt;b&gt;&#96;" in cell  # no code span, so the references still decode
        assert (
            "&#36;\\color{green}PASS&#36;" in cell
        )  # no math; a backslash before a letter is kept
        assert "a\\\\&#124;b" in cell  # doubled, so Markdown shows the one backslash sent


def test_verify_markdown_leaves_ordinary_engine_text_readable() -> None:
    rows = [
        CheckResult("host.python", "Python", Status.PASS, "interpreter ok \u2014 fine"),
        CheckResult("host.writable", "w", Status.FAIL, "C:\\Users\\svc not writable"),
        CheckResult("store.path", "t", Status.FAIL, "check [store].path; RECEIVED->ROUTED"),
        CheckResult("store.connect", "t", Status.FAIL, "run `messagefoundry serve` once"),
    ]
    md = render_markdown(rows)
    assert "| host.python | Python | PASS | interpreter ok \u2014 fine |" in md
    assert "| C:\\Users\\svc not writable |" in md
    assert "check [store].path; RECEIVED-&gt;ROUTED" in md
    # The engine's own code span renders as plain backticks: a code span would stop the references
    # inside it from decoding, so no cell may open one.
    assert "run &#96;messagefoundry serve&#96; once" in md
    assert len(_table_rows(md)) == 4


@pytest.mark.parametrize(
    ("text", "written"),
    [
        ("\\\\srv\\share", "\\\\\\\\srv\\share"),  # a UNC path renders as typed
        ("MSH|^~\\&|", "MSH&#124;^~\\\\&amp;&#124;"),  # the backslash before & survives
        ("p\\", "p\\"),  # a lone trailing backslash is literal already
    ],
)
def test_verify_markdown_doubles_only_the_backslashes_markdown_would_eat(
    text: str, written: str
) -> None:
    assert f"| {written} |" in render_markdown([CheckResult("a", "t", Status.PASS, text)])


# --- harness one-line verdicts ------------------------------------------------------------------


class _Client:
    def __init__(self, *a: object, **kw: object) -> None:
        pass

    def __enter__(self) -> _Client:
        return self

    def __exit__(self, *exc: object) -> None:
        pass

    def set_token(self, token: str) -> None:
        pass


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


_FORGE = "x\nPASS  other: fine"
_FORGE_SHOWN = "x\\x0aPASS  other: fine"


@pytest.mark.parametrize(
    ("ok", "skipped", "verdict"),
    [(True, False, "PASS"), (False, False, "FAIL"), (False, True, "SKIP")],
)
def test_a_scenario_verdict_cannot_start_a_forged_line(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    ok: bool,
    skipped: bool,
    verdict: str,
) -> None:
    from harness.__main__ import _run_scenario
    from harness.scenarios import ScenarioResult

    _scenario(monkeypatch, ScenarioResult(object(), ok, _FORGE, skipped))  # type: ignore[arg-type]
    _run_scenario("probe", "https://127.0.0.1:9", None, 1.0, None)
    assert capsys.readouterr().out == f"{verdict}  probe: {_FORGE_SHOWN}\n"


def test_a_scenario_api_error_cannot_start_a_forged_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from harness.__main__ import _run_scenario

    _scenario(monkeypatch, ApiError(f"422: {_FORGE}", status=422))
    assert _run_scenario("probe", "https://127.0.0.1:9", None, 1.0, None) == 1
    assert capsys.readouterr().err == f"FAIL  probe: 422: {_FORGE_SHOWN}\n"


def test_a_load_setup_error_cannot_start_a_forged_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import argparse

    import harness.load.profile
    import harness.load.runner
    from harness.__main__ import _run_load

    async def refused(*args: object, **kw: object) -> object:
        raise ApiError(f"401: {_FORGE}", status=401)

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
    assert capsys.readouterr().err == f"engine setup failed: 401: {_FORGE_SHOWN}\n"


# --- harness shardcert two-box ApiError lines ------------------------------------------------------


@pytest.mark.parametrize(
    ("entry", "runner", "label", "extra"),
    [
        (
            "_run_shardcert_driver",
            "harness.load.shardcert.run_shardcert_driver",
            "shardcert-driver",
            [],
        ),
        (
            "_run_shardcert_drive",
            "harness.load.shardcert.run_shardcert_drive",
            "shardcert-drive",
            [],
        ),
        (
            "_run_shardcert_drive_ladder",
            "harness.load.shardcert_ladder.run_drive_ladder",
            "shardcert-drive-ladder",
            ["--rate-ladder", "10,20"],
        ),
    ],
)
def test_a_shardcert_api_error_prints_the_engines_text_escaped(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    entry: str,
    runner: str,
    label: str,
    extra: list[str],
) -> None:
    import harness.__main__ as cli

    # The runner refuses with the engine's text before any coroutine exists, so asyncio.run is
    # never reached and nothing is dialled.
    def refuse(*args: object, **kw: object) -> object:
        raise ApiError(f"401: {_HOSTILE}{_FORGE}", status=401)

    monkeypatch.setattr(runner, refuse)
    argv = ["--engine-host", "10.0.0.9", "--coord-dir", str(tmp_path), *extra]
    assert getattr(cli, entry)(argv) == 2
    first, hint = capsys.readouterr().err.split("\n", 1)
    assert first == f"{label}: 401: {_HOSTILE_SHOWN}{_FORGE_SHOWN}"
    assert hint.startswith("(hint: --insecure")


# --- harness --fuzz -------------------------------------------------------------------------------


def test_fuzz_setup_prints_an_engine_reply_escaped(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import harness.fuzz.cli as fuzz_cli
    from harness.fuzz.campaign import SetupError

    class _Transport:
        pass

    def refuse(*args: object, **kw: object) -> object:
        raise SetupError(f"engine API refused the campaign: GET /messages failed: 403: {_FORGE}")

    monkeypatch.setattr(fuzz_cli, "build_transport", lambda *a, **kw: _Transport())
    monkeypatch.setattr(fuzz_cli, "EngineClient", _Client)
    monkeypatch.setattr(fuzz_cli, "run", refuse)
    rc = fuzz_cli.main(
        engine_url="https://127.0.0.1:9",
        token=None,
        cacert=None,
        endpoint_overrides={},
        driver="mllp",
        endpoint=None,
        seed=1,
        iterations=1,
        seconds=None,
        batch=1,
        out_dir=None,
        reply_timeout=1.0,
    )
    assert rc == fuzz_cli.EXIT_SETUP
    assert capsys.readouterr().err == (
        f"fuzz setup: engine API refused the campaign: GET /messages failed: 403: {_FORGE_SHOWN}\n"
    )


def test_a_fuzz_failure_line_prints_its_reason_escaped() -> None:
    from harness.fuzz import campaign

    lines: list[str] = []
    session = campaign._Session.__new__(campaign._Session)
    session.emit = lines.append
    session.keep_replays = False
    session.config = campaign.FuzzConfig(seed=7, iterations=1, seconds=None, batch=1, out_dir=None)
    session.result = campaign.CampaignResult(seed=7)
    session._fail(f"GET /messages failed: 403: {_HOSTILE}{_FORGE}", None, [])
    assert len(lines) == 1
    assert f"reason=GET /messages failed: 403: {_HOSTILE_SHOWN}{_FORGE_SHOWN} " in lines[0]
    # The recorded failure keeps the reason as it was; only the printed line is escaped.
    assert session.result.failures[0].reason.endswith(_FORGE)


def test_a_rig_setup_error_keeps_its_log_tail_lines_and_escapes_the_rest() -> None:
    # connscale, estate, multishard, failover and connscale-remote setup errors carry an engine
    # log tail, which is multi-line by nature, so those lines keep the newline.
    from harness.__main__ import _exc_text

    exc = RuntimeError(f"engine exited during startup:\nline one {_HOSTILE}\r\nline two")
    assert _exc_text(exc, single_line=False) == (
        f"engine exited during startup:\nline one {_HOSTILE_SHOWN}\nline two"
    )
    assert _exc_text(exc) == (
        f"engine exited during startup:\\x0aline one {_HOSTILE_SHOWN}\\x0d\\x0aline two"
    )


# --- review round: the remaining sinks and the alphabet ----------------------------------------


def test_the_strict_alphabet_and_the_per_character_rule_agree_over_every_code_point() -> None:
    # The alphabet is spelled three times: _NOT_SHOWN (the JSON path), _CANDIDATE (what the text
    # path looks at) and _is_escaped (what it decides). Each pattern stays a literal so the ReDoS
    # scan in test_security_static.py can read it, so this holds the three to each other instead.
    from messagefoundry.terminal_text import _CANDIDATE, _NOT_SHOWN_RE, _is_escaped

    for code in range(0x110000):
        char = chr(code)
        by_pattern = _NOT_SHOWN_RE.fullmatch(char) is not None
        assert by_pattern is _is_escaped(char, single_line=False, keep_printable_unicode=False), (
            f"U+{code:04X}"
        )
        looked_at = _CANDIDATE.fullmatch(char) is not None
        escapable = _is_escaped(char, single_line=True, keep_printable_unicode=False)
        assert looked_at is (char == "\\" or escapable), f"U+{code:04X}"


def test_the_markdown_cell_pattern_matches_exactly_its_replacement_keys() -> None:
    from messagefoundry.verify import report

    assert len(report._MD_CELL) >= 7
    for key in report._MD_CELL:
        assert report._MD_CELL_RE.fullmatch(key), key
    # Every match must be a key, or _md_cell raises KeyError: walk every single code point and
    # every ASCII pair, which covers each key's length.
    assert max(len(key) for key in report._MD_CELL) == 2
    for code in range(0x110000):
        char = chr(code)
        assert (report._MD_CELL_RE.fullmatch(char) is not None) is (char in report._MD_CELL), code
    for first in range(0x80):
        for second in range(0x80):
            pair = chr(first) + chr(second)
            matched = report._MD_CELL_RE.fullmatch(pair) is not None
            assert matched is (pair in report._MD_CELL), pair


@pytest.mark.parametrize(
    "lookalike",
    [
        "u\uff12\uff10\uff12\uff25",  # fullwidth 202E
        "u20\uff12e",  # one fullwidth digit among ASCII ones
        "x\uff11\uff42",  # fullwidth 1b
        "u\u0662\u0660\u0662e",  # Arabic-Indic digits (Nd)
        "u202\u0435",  # a Cyrillic e
        "U0001\uff26\uff16\uff10\uff10",  # fullwidth F600 in the eight-digit form
        "\u034fu202E",  # an invisible combining grapheme joiner before the letter
        "\u0445\u0031b",  # a Cyrillic small ha for the x
        "\uff55202E",  # a fullwidth u
    ],
)
def test_keeping_unicode_doubles_a_backslash_before_a_non_ascii_hex_lookalike(
    lookalike: str,
) -> None:
    # Printable non-ASCII prints as itself in this mode, so a fullwidth or Cyrillic digit after
    # a backslash and u would read as a real escape of a bidirectional override.
    text = "\\" + lookalike
    shown = _keep(text)
    # The backslash is doubled, so it reads as text. A kept character in the window may itself be
    # escaped too (the combining joiner is: it stands before an escape body), which a doubled
    # backslash before a real escape spells unambiguously.
    assert shown.startswith("\\\\")
    assert shown in ("\\" + text, "\\\\\\u034fu202E")


def test_keeping_unicode_leaves_a_backslash_before_a_short_or_ascii_tail_single() -> None:
    # Not every backslash before a u: only one followed by enough hex-looking characters.
    assert _keep("C:\\users\\caf\u00e9") == "C:\\users\\caf\u00e9"
    assert _keep("\\u\u00e9") == "\\u\u00e9"  # one character is not an escape's width
    # The strict rule's output is pure ASCII, so its lookalike stays ASCII hex only.
    assert escape_for_terminal("\\u\uff12\uff10\uff12\uff25") == ("\\u\\uff12\\uff10\\uff12\\uff25")


@pytest.mark.parametrize(
    "slash",
    [
        "\ufe68",  # small reverse solidus
        "\uff3c",  # fullwidth reverse solidus
        "\u29f5",  # reverse solidus operator
        "\u2216",  # set minus
        "\u20e5",  # combining reverse solidus overlay
    ],
)
@pytest.mark.parametrize("body", ["u202E", "x1b", "U0001F600", "u\uff12\uff10\uff12\uff25"])
def test_keeping_unicode_escapes_a_kept_character_before_an_escape_body(
    slash: str, body: str
) -> None:
    # Anything that looks like a backslash would start a forged escape the doubling never sees,
    # since the doubling only looks at a real backslash; so the character before a body is escaped.
    assert _keep(f"kid {slash}{body}") == f"kid \\u{ord(slash):04x}{body}"


def test_keeping_unicode_keeps_a_character_not_before_an_escape_body() -> None:
    assert _keep("\uff3c path \u29f5 u20 caf\u00e9u") == "\uff3c path \u29f5 u20 caf\u00e9u"


def test_a_connscale_reload_probe_logs_an_engine_reply_escaped_to_one_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from harness.load.connscale import probe

    class _Client:
        def reload_config(self, config_dir: str | None) -> object:
            raise ApiError(f"500: {_HOSTILE}{_FORGE}", status=500)

    with caplog.at_level("WARNING", logger=probe.__name__):
        reading, refused = probe.time_reload_outcome(_Client(), None)  # type: ignore[arg-type]
    assert (reading, refused) == (None, False)
    [record] = [r for r in caplog.records if r.name == probe.__name__]
    assert record.getMessage() == (
        f"reload probe: the reload request failed (HTTP 500): 500: {_HOSTILE_SHOWN}{_FORGE_SHOWN}"
    )


class _TailNode:
    def __init__(self, tail: str) -> None:
        self._tail = tail

    def log_tail(self) -> str:
        return self._tail


def test_a_shardcert_log_tail_is_escaped_and_keeps_its_lines() -> None:
    from harness.load import shardcert

    node = _TailNode(f"line one {_HOSTILE}\r\nline two\n")
    assert shardcert._shown_tail(node) == f"line one {_HOSTILE_SHOWN}\nline two\n"  # type: ignore[arg-type]


def test_no_shardcert_message_embeds_a_raw_log_tail() -> None:
    # Every RuntimeError a shard's start raises reaches the terminal as an uncaught traceback, so a
    # log tail in one must go through _shown_tail. A raw call in an f-string is the regression.
    import ast

    import harness.load.shardcert as shardcert

    tree = ast.parse(Path(shardcert.__file__).read_text(encoding="utf-8"))
    # Any read of a log tail, however it is then formatted, outside the one helper that escapes it.
    helper = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_shown_tail"
    )
    inside = {id(node) for node in ast.walk(helper)}
    reads = [
        (node.lineno, id(node) in inside)
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == "log_tail"
    ]
    escaped = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_shown_tail"
    ]
    # The positive controls: the helper's own read is found, and so are the raise sites using it.
    assert len(reads) >= 1
    assert any(in_helper for _, in_helper in reads)
    assert len(escaped) >= 4
    raw = [line for line, in_helper in reads if not in_helper]
    assert raw == []


def test_an_ingress_probe_setup_failure_prints_its_log_tail_escaped_to_one_line(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from harness.load import ingress_probe
    from harness.load.failover import FailoverError

    exc = FailoverError(f"node a exited during startup:\nRESULT rate=60 ok=True {_HOSTILE}\r\n")
    assert ingress_probe._setup_failed(10.0, "engine_did_not_start", exc) == 2
    # One line: the workflow reads every stdout or stderr line starting RESULT, so a tail line of
    # its own could forge a verdict.
    assert capsys.readouterr().err == (
        "ingress probe: engine_did_not_start: node a exited during startup:\\x0a"
        f"RESULT rate=60 ok=True {_HOSTILE_SHOWN}\\x0d\\x0a\n"
    )


def test_a_fuzz_failure_line_escapes_a_shown_identifier_once() -> None:
    # invariants.shown() keeps the value raw, so the printed line escapes it exactly once: a real
    # ESC prints as \x1b, and text spelling \x1b prints doubled, as everywhere else.
    from harness.fuzz import campaign
    from harness.fuzz.invariants import shown
    from harness.fuzz.mutate import Case

    lines: list[str] = []
    session = campaign._Session.__new__(campaign._Session)
    session.emit = lines.append
    session.keep_replays = False
    session.config = campaign.FuzzConfig(seed=7, iterations=1, seconds=None, batch=1, out_dir=None)
    session.result = campaign.CampaignResult(seed=7)
    case = Case(7, 1, "ADT^A01", "field", "m", b"", "c\x1bid\\x1b")
    reason = f"reply is not an ACK (MSH-9.1 {shown('A\x1b[2J\\x1b')})"
    session._fail(reason, case, [case])
    assert len(lines) == 1
    assert "control_id='c\\x1bid\\\\x1b' " in lines[0]
    assert "reason=reply is not an ACK (MSH-9.1 'A\\x1b[2J\\\\x1b') " in lines[0]
    # The record keeps the value raw; only the printed line is escaped.
    assert session.result.failures[0].reason == "reply is not an ACK (MSH-9.1 'A\x1b[2J\\x1b')"


def test_a_shown_identifier_stays_inside_its_quotes() -> None:
    from harness.fuzz.invariants import shown

    assert shown("a' reason=ok") == '"a\' reason=ok"'
    assert shown('a" b') == "'a\" b'"
    assert shown(None) == "None"

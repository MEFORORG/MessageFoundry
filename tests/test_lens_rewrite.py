# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``lens rewrite`` — row-scoped param edits (ADR 0076 §2 phase 3 / §5), byte-stability gate 2.

The load-bearing property (ADR 0076 §6 gate 2): for the whole ``samples/config`` corpus a **no-op**
rewrite (an edit that changes no parameter) is **byte-identical** to the input, and a single-parameter
edit changes **only** that row's line range — every other byte (untouched rows, blank lines, comments,
indentation, line terminators) is preserved. Only recognized ``action``/``lookup``/``send`` rows are
editable; ``code``/``control`` rows are refused. Static-only: a module whose top level would raise (or
whose imports are unavailable) still rewrites (gate 4)."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.__main__ import main
from messagefoundry.lens import (
    LensParseError,
    LensRewriteError,
    parse_module,
    parse_source,
    rewrite_module,
    rewrite_source,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "samples" / "config"
_EDITABLE_KINDS = {"action", "lookup", "send"}


def _recognized_rows(module: Path) -> list[tuple[str, dict[str, object]]]:
    """Every recognized (editable) row across a module's handlers, as ``(handler, row)`` pairs."""
    return [
        (contract["handler"], row)
        for contract in parse_module(module)
        for row in contract["rows"]
        if row["kind"] in _EDITABLE_KINDS
    ]


# --- gate 2: no-op byte-stability across the whole corpus --------------------


@pytest.mark.parametrize("module", sorted(SAMPLES.glob("*.py")), ids=lambda p: p.name)
def test_noop_rewrite_is_byte_identical_over_corpus(module: Path) -> None:
    # For every recognized row in every sample handler, a no-op rewrite (params={}) reproduces the file
    # byte-for-byte (including the on-disk \r\n terminators, via rewrite_module's raw-bytes read).
    #
    # A role-split feed (docs/CONNECTIONS.md §"Decomposing by role") also ships router-only and
    # `_`-transform-helper files that carry no @handler — nothing for the lens to project or rewrite, so
    # skip them (the byte-stability gate is about handler files; a handler file must still expose a row).
    original = module.read_bytes().decode("utf-8")
    if not parse_module(module):
        pytest.skip(f"{module.name}: no @handler (a role-split router / transform-helper file)")
    rows = _recognized_rows(module)
    assert rows, (
        f"{module.name}: a handler file must expose at least one recognized (send/action/lookup) row"
    )
    for _handler, row in rows:
        edit = {
            "line_start": row["line_start"],
            "line_end": row["line_end"],
            "op": "set_params",
            "params": {},
        }
        out = rewrite_module(module, edit)
        assert out == original, f"{module.name}: no-op rewrite of row {row} was not byte-identical"


def test_noop_preserves_crlf_terminators() -> None:
    src = 'from messagefoundry import handler, Send\r\n\r\n\r\n@handler("h")\r\ndef h(msg):\r\n    return Send("OB", msg)\r\n'
    out = rewrite_source(src, {"line_start": 6, "line_end": 6, "op": "set_params", "params": {}})
    assert out == src  # the \r\n terminators survive the round-trip untouched


# --- a single param edit touches ONLY the target row's line range ------------

COPY = """\
from messagefoundry import handler, Send, copy_field, set_field


@handler("enrich")
def enrich(msg):
    copy_field(msg, "PID-5.1", "NK1-2.1")
    set_field(msg, "PID-3.1", "NEW")
    return Send("OB_X", msg)
"""


def _assert_only_line_changed(before: str, after: str, lineno: int, expected: str) -> None:
    """Every line except ``lineno`` (1-based) is byte-identical; line ``lineno`` becomes ``expected``."""
    bl, al = before.splitlines(), after.splitlines()
    assert len(bl) == len(al), "line count changed"
    for i in range(len(bl)):
        if i + 1 == lineno:
            assert al[i] == expected, f"line {lineno}: {al[i]!r} != {expected!r}"
        else:
            assert al[i] == bl[i], f"line {i + 1} changed unexpectedly: {bl[i]!r} -> {al[i]!r}"


def test_action_param_edit_changes_only_its_line() -> None:
    out = rewrite_source(
        COPY, {"line_start": 6, "line_end": 6, "op": "set_params", "params": {"dst": "NK1-3.1"}}
    )
    _assert_only_line_changed(COPY, out, 6, '    copy_field(msg, "PID-5.1", "NK1-3.1")')
    # The edited output re-parses (gate 3: emitted code is first-class) and a follow-up no-op is stable.
    reparsed = parse_source(out)
    assert reparsed[0]["rows"][0]["params"] == {"src": "PID-5.1", "dst": "NK1-3.1"}
    assert (
        rewrite_source(out, {"line_start": 6, "line_end": 6, "op": "set_params", "params": {}})
        == out
    )


def test_editing_a_positional_and_a_keyword_param() -> None:
    src = """\
from messagefoundry import handler, Send, code_lookup


@handler("h")
def h(msg):
    code_lookup(msg, "PID-8", GENDER, default="U")
    return Send("OB", msg)
"""
    # `path` is a literal (editable as a literal); `table` (GENDER) is an expression (keep it verbatim);
    # `default` is a keyword literal.
    out = rewrite_source(
        src,
        {
            "line_start": 6,
            "line_end": 6,
            "op": "set_params",
            "params": {"path": "PID-8.1", "default": "UNK"},
        },
    )
    _assert_only_line_changed(src, out, 6, '    code_lookup(msg, "PID-8.1", GENDER, default="UNK")')


def test_send_destination_edit() -> None:
    out = rewrite_source(
        COPY, {"line_start": 8, "line_end": 8, "op": "set_params", "params": {"to": "OB_Y"}}
    )
    _assert_only_line_changed(COPY, out, 8, '    return Send("OB_Y", msg)')


def test_edit_a_sample_send_touches_one_line() -> None:
    adt = SAMPLES / "adt.py"
    before = adt.read_bytes().decode("utf-8")
    out = rewrite_module(
        adt,
        {"line_start": 53, "line_end": 53, "op": "set_params", "params": {"to": "FILE-OUT_NEW"}},
    )
    bl, al = before.splitlines(), out.splitlines()
    changed = [i + 1 for i in range(len(bl)) if bl[i] != al[i]]
    assert changed == [53]
    assert al[52].strip() == 'return Send("FILE-OUT_NEW", msg)'


# --- expression vs literal safety --------------------------------------------


def test_expression_param_refuses_a_bare_scalar_but_accepts_an_expr() -> None:
    src = """\
from messagefoundry import handler, Send, db_lookup


@handler("h")
def h(msg):
    row = db_lookup("MPI", "select 1", {"id": msg["PID-3.1"]})
    return Send("OB", msg)
"""
    # `params` is currently an expression ({"id": ...}); a bare scalar would silently drop the read.
    with pytest.raises(LensRewriteError, match="expression"):
        rewrite_source(
            src, {"line_start": 6, "line_end": 6, "op": "set_params", "params": {"params": "x"}}
        )
    # An explicit {"expr": ...} splices verbatim; a literal keyword (statement) edits as a literal.
    out = rewrite_source(
        src,
        {
            "line_start": 6,
            "line_end": 6,
            "op": "set_params",
            "params": {"statement": "select 2", "params": {"expr": '{"mrn": msg["PID-3.1"]}'}},
        },
    )
    assert out.splitlines()[5] == '    row = db_lookup("MPI", "select 2", {"mrn": msg["PID-3.1"]})'


def test_malformed_expr_is_refused() -> None:
    with pytest.raises(LensRewriteError, match="not a valid Python expression"):
        rewrite_source(
            COPY,
            {
                "line_start": 6,
                "line_end": 6,
                "op": "set_params",
                "params": {"dst": {"expr": "msg[["}},
            },
        )


# --- refusals: only recognized rows are editable -----------------------------


def test_code_row_edit_is_refused() -> None:
    # adt.py lines 49-50 are a `code` row (the mnemonic lookup + assignment).
    src = (SAMPLES / "adt.py").read_bytes().decode("utf-8")
    with pytest.raises(LensRewriteError, match="'code' row"):
        rewrite_source(
            src, {"line_start": 49, "line_end": 50, "op": "set_params", "params": {"a": "b"}}
        )


def test_control_row_edit_is_refused() -> None:
    # adt.py line 47 is an `if` control row.
    src = (SAMPLES / "adt.py").read_bytes().decode("utf-8")
    with pytest.raises(LensRewriteError, match="'control' row"):
        rewrite_source(
            src, {"line_start": 47, "line_end": 47, "op": "set_params", "params": {"a": "b"}}
        )


def test_unknown_param_is_refused() -> None:
    with pytest.raises(LensRewriteError, match="unknown or absent"):
        rewrite_source(
            COPY, {"line_start": 6, "line_end": 6, "op": "set_params", "params": {"nope": "z"}}
        )


def test_editing_msg_is_refused() -> None:
    with pytest.raises(LensRewriteError, match="unknown or absent"):
        rewrite_source(
            COPY, {"line_start": 6, "line_end": 6, "op": "set_params", "params": {"msg": "other"}}
        )


def test_no_row_at_range_is_refused() -> None:
    with pytest.raises(LensRewriteError, match="no editable row"):
        rewrite_source(COPY, {"line_start": 99, "line_end": 99, "op": "set_params", "params": {}})


def test_unsupported_op_is_refused() -> None:
    with pytest.raises(LensRewriteError, match="unsupported op"):
        rewrite_source(COPY, {"line_start": 6, "line_end": 6, "op": "delete", "params": {}})


def test_missing_line_numbers_refused() -> None:
    with pytest.raises(LensRewriteError, match="integer 'line_start'"):
        rewrite_source(COPY, {"op": "set_params", "params": {}})


def test_multiline_call_single_line_arg_edit_touches_only_that_arg() -> None:
    # v2 supports editing a SINGLE-LINE literal argument of a MULTI-LINE call (v1 refused every
    # multi-line call). The set_field call spans lines 6-10; its `value` arg ("NEW") is on line 9 alone.
    src = """\
from messagefoundry import handler, Send, set_field


@handler("h")
def h(msg):
    set_field(
        msg,
        "PID-3.1",
        "NEW",
    )
    return Send("OB", msg)
"""
    out = rewrite_source(
        src, {"line_start": 6, "line_end": 10, "op": "set_params", "params": {"value": "X"}}
    )
    # Only line 9 changed (the value arg); the call structure + every other line is byte-identical.
    bl, al = src.splitlines(), out.splitlines()
    assert [i + 1 for i in range(len(bl)) if bl[i] != al[i]] == [9]
    assert al[8] == '        "X",'
    parse_source(out)  # re-parses (gate 3)
    # A no-op still round-trips byte-identically.
    assert (
        rewrite_source(src, {"line_start": 6, "line_end": 10, "op": "set_params", "params": {}})
        == src
    )


def test_multiline_call_multiline_arg_edit_is_refused() -> None:
    # A single-line literal arg is editable on a multi-line call, but an argument that ITSELF spans
    # multiple lines (a triple-quoted string) is refused — replacing it would change the line count.
    src = '''\
from messagefoundry import handler, Send, set_field


@handler("h")
def h(msg):
    set_field(
        msg,
        "PID-3.1",
        """multi
line""",
    )
    return Send("OB", msg)
'''
    with pytest.raises(LensRewriteError, match="multiple physical lines"):
        rewrite_source(
            src, {"line_start": 6, "line_end": 11, "op": "set_params", "params": {"value": "X"}}
        )


# --- static-only (gate 4) ----------------------------------------------------


def test_static_only_module_with_toplevel_raise_still_rewrites() -> None:
    src = """\
from messagefoundry import handler, Send

raise RuntimeError("this would abort at import time")


@handler("survivor")
def survivor(msg):
    return Send("OB_S", msg)
"""
    out = rewrite_source(
        src, {"line_start": 8, "line_end": 8, "op": "set_params", "params": {"to": "OB_T"}}
    )
    assert out.splitlines()[7] == '    return Send("OB_T", msg)'


def test_syntax_error_is_a_parse_refusal() -> None:
    with pytest.raises((LensParseError, LensRewriteError)):
        rewrite_source("def broken(:\n    pass\n", {"line_start": 1, "line_end": 1, "params": {}})


# --- CLI surface -------------------------------------------------------------


def test_cli_rewrite_file_noop_is_byte_identical(
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    adt = SAMPLES / "adt.py"
    rc = main(
        [
            "lens",
            "rewrite",
            str(adt),
            "--edit",
            '{"line_start":53,"line_end":53,"op":"set_params","params":{}}',
        ]
    )
    assert rc == 0
    assert capsysbinary.readouterr().out == adt.read_bytes()


def test_cli_rewrite_stdin_source(
    monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    # The IDE path: source on stdin ('-'), edit inline. stdin is read as raw UTF-8 bytes.
    src = (SAMPLES / "adt.py").read_bytes()

    class _Stdin:
        buffer = io.BytesIO(src)

    monkeypatch.setattr("sys.stdin", _Stdin())
    rc = main(
        [
            "lens",
            "rewrite",
            "-",
            "--edit",
            '{"line_start":53,"line_end":53,"op":"set_params","params":{"to":"OB_Z"}}',
        ]
    )
    assert rc == 0
    out = capsysbinary.readouterr().out.decode("utf-8")
    assert out.splitlines()[52].strip() == 'return Send("OB_Z", msg)'


def test_cli_rewrite_refusal_emits_json_error(
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    adt = SAMPLES / "adt.py"
    rc = main(
        [
            "lens",
            "rewrite",
            str(adt),
            "--edit",
            '{"line_start":47,"line_end":47,"op":"set_params","params":{"a":"b"}}',
        ]
    )
    assert rc == 1
    payload = json.loads(capsysbinary.readouterr().out.decode("utf-8"))
    assert "control" in payload["error"]


def test_cli_rewrite_invalid_edit_json(capsysbinary: pytest.CaptureFixture[bytes]) -> None:
    adt = SAMPLES / "adt.py"
    rc = main(["lens", "rewrite", str(adt), "--edit", "{not json"])
    assert rc == 1
    payload = json.loads(capsysbinary.readouterr().out.decode("utf-8"))
    assert "invalid --edit JSON" in payload["error"]


# =============================================================================
# Adversarial byte-stability — the corpus can't catch these (F1 / F2 / F3)
# =============================================================================
#
# Regression guard for the corruption an adversarial review found: the pre-fix splice sliced a `str`
# line by the AST's *byte* col offsets (F1) and located lines with `str.splitlines()` (F2), and it
# rebuilt the whole arg list with a canonical `, `.join (F3) — so a no-op reformatted, and any non-ASCII
# / form-feed / NEL / U+2028 / trailing comment produced non-parsing garbage AT EXIT 0. Every case below
# FAILS on the pre-fix code (either a non-byte-identical no-op or a non-parsing splice).


def _recognized_rows_of(source: str) -> list[dict[str, Any]]:
    """Every recognized (editable) row across ``source``'s handlers (via the static parser)."""
    return [
        row
        for contract in parse_source(source)
        for row in contract["rows"]
        if row["kind"] in _EDITABLE_KINDS
    ]


# Each source carries a pathological feature on/around an editable row. `U+2028` (line separator),
# `\f` (form feed) and `\x85` (NEL) are extra boundaries for str.splitlines() but NOT for the tokenizer,
# so they desynced line indexing pre-fix; the em-dash / François / arrow are multi-byte in UTF-8, so the
# byte col offsets mis-sliced a `str` line pre-fix.
_ADVERSARIAL_SOURCES: dict[str, str] = {
    "non_ascii_value_plus_trailing_comment": (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    set_field(msg, "PID-5.1", "François")  # name\n'
        '    return Send("OB", msg)\n'
    ),
    "em_dash_and_arrow_in_value": (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    set_field(msg, "PID-3.1", "em—dash → arrow")\n'
        '    return Send("OB", msg)\n'
    ),
    "u2028_line_separator_in_value": (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    set_field(msg, "A", "x\u2028y")\n'
        '    return Send("OB", msg)\n'
    ),
    "form_feed_in_module_comment": (
        "from messagefoundry import handler, Send, copy_field\n"
        "# a\fform-feed in a comment\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    copy_field(msg, "A", "B")\n'
        '    return Send("OB", msg)\n'
    ),
    "nel_x85_in_value": (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    set_field(msg, "A", "a\x85b")\n'
        '    return Send("OB", msg)\n'
    ),
    "non_canonical_spacing_padded": (
        "from messagefoundry import handler, Send, copy_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    copy_field( msg ,"A", "B" )\n'
        '    return Send("OB", msg)\n'
    ),
    "non_canonical_spacing_compressed": (
        "from messagefoundry import handler, Send, copy_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    copy_field(msg,"A","B")\n'
        '    return Send( "OB",msg )\n'
    ),
    "preserved_trailing_comma": (
        "from messagefoundry import handler, Send, copy_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    copy_field(msg, "A", "B",)\n'
        '    return Send("OB", msg)\n'
    ),
}


@pytest.mark.parametrize("src", _ADVERSARIAL_SOURCES.values(), ids=_ADVERSARIAL_SOURCES.keys())
def test_noop_rewrite_is_byte_identical_on_adversarial_source(src: str) -> None:
    # A no-op (params={}) of EVERY recognized row must reproduce the source byte-for-byte, regardless of
    # non-ASCII, form-feed / NEL / U+2028, non-canonical spacing, or a preserved trailing comma.
    rows = _recognized_rows_of(src)
    assert rows, "expected at least one recognized row"
    for row in rows:
        edit = {
            "line_start": row["line_start"],
            "line_end": row["line_end"],
            "op": "set_params",
            "params": {},
        }
        out = rewrite_source(src, edit)
        assert out == src, f"no-op of row {row} was not byte-identical"


def _ruff_format_clean(source: str) -> bool:
    """Whether ``source`` is already ``ruff format``-clean (gate 3). Skips if ruff is unavailable."""
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "ruff", "format", "--check", "-"],
            input=source.encode("utf-8"),
            capture_output=True,
        )
    except (OSError, ValueError) as exc:  # pragma: no cover - environment guard
        pytest.skip(f"ruff not runnable: {exc}")
    return proc.returncode == 0


def test_single_param_edit_on_non_ascii_line_touches_only_that_arg() -> None:
    # A ruff-clean handler with a NON-ASCII path arg + a trailing comment. Editing ONLY the `value` must
    # change ONLY the value arg's bytes — the comment, the (multi-byte) path arg, and the indentation are
    # byte-identical — and the result must parse AND stay ruff-format-clean (gate 3).
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    set_field(msg, "PID-5.1", "François")  # patient name\n'
        '    return Send("OB", msg)\n'
    )
    assert _ruff_format_clean(src), "the starting sample must be ruff-clean for the gate-3 check"
    out = rewrite_source(
        src, {"line_start": 6, "line_end": 6, "op": "set_params", "params": {"value": "Frank"}}
    )
    assert out.splitlines()[5] == '    set_field(msg, "PID-5.1", "Frank")  # patient name'
    # Only line 6 changed; every other line (and its bytes) is untouched.
    bl, al = src.splitlines(), out.splitlines()
    assert [i + 1 for i in range(len(bl)) if bl[i] != al[i]] == [6]
    # The comment, the multi-byte path arg, and the indent survived verbatim within line 6.
    assert al[5].startswith('    set_field(msg, "PID-5.1", ')
    assert al[5].endswith(")  # patient name")
    parse_source(out)  # parses (gate 3: emitted code is first-class)
    assert _ruff_format_clean(out), (
        "the rewritten non-ASCII sample must stay ruff-format-clean (gate 3)"
    )


def test_multiline_expr_value_is_refused() -> None:
    # A rendered value carrying a real newline would splice extra physical lines and break the
    # line-count-preserving invariant the IDE relies on (F4) — refuse it.
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    set_field(msg, "A", "old")\n'
        '    return Send("OB", msg)\n'
    )
    with pytest.raises(LensRewriteError, match="single line"):
        rewrite_source(
            src,
            {
                "line_start": 6,
                "line_end": 6,
                "op": "set_params",
                "params": {"value": {"expr": "msg[\n'PID-3']"}},
            },
        )
    # A parenthesized multi-line expression is likewise refused (it, too, adds physical lines).
    with pytest.raises(LensRewriteError, match="single line"):
        rewrite_source(
            src,
            {
                "line_start": 6,
                "line_end": 6,
                "op": "set_params",
                "params": {"value": {"expr": "(1 +\n2)"}},
            },
        )


def test_bom_is_preserved_across_noop_and_edit() -> None:
    # A leading UTF-8 BOM must survive a no-op byte-identically (nit #8) and be re-emitted on a real edit.
    src = (
        "\ufeff"
        "from messagefoundry import handler, Send, copy_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    copy_field(msg, "A", "B")\n'
        '    return Send("OB", msg)\n'
    )
    noop = rewrite_source(src, {"line_start": 6, "line_end": 6, "op": "set_params", "params": {}})
    assert noop == src  # BOM preserved, byte-identical
    edited = rewrite_source(
        src, {"line_start": 6, "line_end": 6, "op": "set_params", "params": {"dst": "C"}}
    )
    assert edited.startswith("\ufeff")
    assert edited.splitlines()[5] == '    copy_field(msg, "A", "C")'
    parse_source(edited)  # still parses after the round-trip


def test_stale_coordinate_guard_refuses_a_mismatched_row() -> None:
    # F7: an edit carrying the projected row's source text is refused when the live buffer's row no longer
    # matches (stale coordinates) — so a coincidental same-shape row is never edited in the wrong place.
    src = (
        "from messagefoundry import handler, Send, copy_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    copy_field(msg, "A", "B")\n'
        '    return Send("OB", msg)\n'
    )
    # Matching snippet → the edit applies.
    ok = rewrite_source(
        src,
        {
            "line_start": 6,
            "line_end": 6,
            "op": "set_params",
            "params": {"dst": "C"},
            "expect_src": '    copy_field(msg, "A", "B")',
        },
    )
    assert ok.splitlines()[5] == '    copy_field(msg, "A", "C")'
    # A stale snippet (the buffer moved under the coordinates) → refuse + ask to re-project.
    with pytest.raises(LensRewriteError, match="stale coordinates"):
        rewrite_source(
            src,
            {
                "line_start": 6,
                "line_end": 6,
                "op": "set_params",
                "params": {"dst": "C"},
                "expect_src": '    copy_field(msg, "STALE", "B")',
            },
        )


def test_scalar_edit_of_an_expression_slot_is_refused() -> None:
    # An expression-valued arg (a list) never takes a bare-scalar edit — supply {'expr': ...} instead.
    src = (
        "from messagefoundry import handler, Send, split_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    split_field(msg, "PID-5", "^", ["PID-5.1", "PID-5.2"])\n'
        '    return Send("OB", msg)\n'
    )
    with pytest.raises(LensRewriteError, match="expression"):
        rewrite_source(
            src, {"line_start": 6, "line_end": 6, "op": "set_params", "params": {"dests": "X"}}
        )

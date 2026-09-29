# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The writable half of ADR 0076 Amendment E: the templated edit spec, and AC-M4, AC-M5 and AC-M6.

BACKLOG #237. Step 1 (tests/test_lens_param_modes.py) taught ``lens parse`` to CLASSIFY an argument
``static``, ``templated`` or ``dynamic``. This file covers the rewrite half the IDE mode selector
needs:

* the wire format -- a templated value travels as structured parts, ``{"parts": [{"text": ...},
  {"path": ...}]}`` on the way in and ``param_parts`` on the way out, and the engine alone turns them
  into an f-string;
* AC-M4 -- round-trip totality over GENERATED part sequences, not hand-picked ones;
* AC-M5 -- a ``dynamic`` argument refuses every edit, including one that repeats its own source;
* AC-M6 -- every other line stays byte-identical and the rows still partition the def body.

The samples corpus carries no action row at all (test_lens_param_modes.py measured it), so every
fixture here is adversarial and built in this file.
"""

from __future__ import annotations

import ast
import importlib.util
import itertools
import random
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from messagefoundry import lens
from messagefoundry.lens import (
    CONTRACT_V1,
    CONTRACT_V2,
    MODE_DYNAMIC,
    MODE_STATIC,
    MODE_TEMPLATED,
    LensRewriteError,
    _display_width,
    _normalize_parts,
    _param_mode,
    _render_parts,
    _template_parts,
    parse_source,
    rewrite_source,
)

PREAMBLE = "from messagefoundry import Send, db_lookup, handler, log_note, set_field\n\n\n"


def _one_row(body_line: str) -> str:
    """A one-statement handler whose statement sits on line 6."""
    return (
        PREAMBLE + '@handler("h")\ndef h(msg):\n    ' + body_line + '\n    return Send("OB", msg)\n'
    )


def _set(source: str, params: dict[str, Any], line: int = 6) -> str:
    return rewrite_source(
        source,
        {"line_start": line, "line_end": line, "op": "set_params", "params": params},
        contract=CONTRACT_V2,
    )


def _row(source: str, line: int = 6) -> dict[str, Any]:
    rows = [
        r
        for entry in parse_source(source, contract=CONTRACT_V2)
        for r in entry["rows"]
        if r["line_start"] == line
    ]
    assert len(rows) == 1, rows
    return rows[0]


# =============================================================================
# The wire format, both directions
# =============================================================================


def test_a_parts_value_writes_a_bounded_interpolation_and_reads_back_as_parts() -> None:
    src = _one_row('set_field(msg, "PID-5.1", "old")')
    parts = [{"text": "MRN: "}, {"path": "PID-3.1"}]
    out = _set(src, {"value": {"parts": parts}})
    assert out.splitlines()[5] == '    set_field(msg, "PID-5.1", f"MRN: {msg[\'PID-3.1\']}")'
    row = _row(out)
    assert row["param_modes"] == {"path": MODE_STATIC, "value": MODE_TEMPLATED}
    assert row["param_parts"] == {"value": parts}
    assert row["literal_params"] == ["path"]


def test_a_path_pick_writes_the_templated_form_never_a_bare_read() -> None:
    """Manager decision for BACKLOG #237: the picker ALWAYS writes ``f"{msg['X']}"``. A bare
    ``msg["X"]`` is ``dynamic`` and would be read-only the moment it landed."""
    out = _set(
        _one_row('set_field(msg, "PID-5.1", "old")'), {"value": {"parts": [{"path": "PID-3"}]}}
    )
    assert "f\"{msg['PID-3']}\"" in out.splitlines()[5]
    assert _row(out)["param_modes"]["value"] == MODE_TEMPLATED


def test_param_parts_is_total_over_the_templated_params_and_only_those() -> None:
    src = _one_row("set_field(msg, f\"{msg['PID-3']}-{msg.field('PID-4')}\", f\"{msg['A']}\")")
    row = _row(src)
    assert row["param_modes"] == {"path": MODE_TEMPLATED, "value": MODE_TEMPLATED}
    assert row["param_parts"] == {
        "path": [{"path": "PID-3"}, {"text": "-"}, {"path": "PID-4"}],
        "value": [{"path": "A"}],
    }
    # The path is templated and shows its parts, but it is not a value parameter, so it is not
    # WRITABLE as a template: template_params is the engine's answer to that, not param_parts.
    assert row["template_params"] == ["value"]
    static = _row(_one_row('set_field(msg, "PID-5.1", msg["PID-3"] + "x")'))
    assert static["param_parts"] == {}, "a static or dynamic param must not appear in param_parts"


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        pytest.param('set_field(msg, "PID-5.1", "old")', ["value"], id="set-field-static-value"),
        pytest.param('msg.set("PID-5.1", "old")', ["value"], id="native-set-field"),
        pytest.param('append_to_field(msg, "PID-5.1", "!")', ["suffix"], id="append-suffix"),
        pytest.param('replace_literal(msg, "PID-5.1", "a", "b")', ["new"], id="replace-new"),
        pytest.param('set_field(msg, "PID-5.1", msg["PID-3"])', [], id="dynamic-value"),
        pytest.param('copy_field(msg, "PID-3", "PID-4")', [], id="copy-field-paths"),
        pytest.param('pad_field(msg, "PID-3", 10)', [], id="int-width"),
        pytest.param('msg.set("OBX-5", "V", occurrence=2)', ["value"], id="display-kwarg-excluded"),
        pytest.param('msg.add_repetition("PID-3", "X")', ["value"], id="native-add-repetition"),
        pytest.param('row = db_lookup("MPI", "select 1", {})', [], id="lookup"),
        pytest.param('log_note("note {}", "x")', [], id="diagnostic"),
    ],
)
def test_template_params_names_exactly_the_writable_value_params(
    line: str, expected: list[str]
) -> None:
    """``template_params`` is the templated counterpart of ``literal_params``: the engine's own list of
    where a ``{"parts"}`` write is accepted, so the IDE offers the mode only there."""
    row = _row(_one_row(line))
    assert row["template_params"] == expected
    for pname in row["params"]:
        edit = {pname: {"parts": [{"path": "PID-3"}]}}
        if pname in expected:
            written = _row(_set(_one_row(line), edit))
            assert written["param_modes"][pname] == MODE_TEMPLATED
            assert written["param_parts"][pname] == [{"path": "PID-3"}]
        elif row["param_modes"][pname] != MODE_DYNAMIC and pname in row["literal_params"]:
            with pytest.raises(LensRewriteError, match="takes a literal only"):
                _set(_one_row(line), edit)


def test_template_params_leaves_out_a_multi_line_argument() -> None:
    """Every set_params splice refuses an argument spanning several lines, so listing one would offer
    an edit certain to fail."""
    src = (
        PREAMBLE + '@handler("h")\ndef h(msg):\n    set_field(\n        msg,\n        "PID-5.1",\n'
        '        (\n            "a"\n            "b"\n        ),\n    )\n    return Send("OB", msg)\n'
    )
    row = _row(src)
    assert row["param_modes"]["value"] == MODE_STATIC
    assert row["template_params"] == []


def test_resubmitting_the_current_parts_changes_no_byte() -> None:
    """An edit that changes nothing changes nothing: a ``msg.field("X")`` read, an ``F`` prefix or a
    triple-quoted spelling is not respelled when the IDE sends the parts back unchanged."""
    for arg in ("f\"{msg.field('PID-3')}\"", "F\"{msg['PID-3']}\"", "f'''{msg['PID-3']}'''"):
        src = _one_row(f'set_field(msg, "PID-5.1", {arg})')
        parts = _row(src)["param_parts"]["value"]
        assert parts == [{"path": "PID-3"}], arg
        assert _set(src, {"value": {"parts": parts}}) == src, arg


def test_a_literal_expr_is_written_in_its_canonical_spelling() -> None:
    """A static ``expr`` is re-rendered as the literal renderer would write it, so the line stays
    ``ruff format``-clean, and a constant JSON cannot carry is refused."""
    src = _one_row('set_field(msg, "PID-5.1", "old")')
    assert _set(src, {"value": {"expr": "'x'"}}).splitlines()[5] == (
        '    set_field(msg, "PID-5.1", "x")'
    )
    assert _set(src, {"value": {"expr": '"a" "b"'}}).splitlines()[5] == (
        '    set_field(msg, "PID-5.1", "ab")'
    )
    for expr in ("b'x'", "...", "1j"):
        with pytest.raises(LensRewriteError, match="cannot render value"):
            _set(src, {"value": {"expr": expr}})


def test_a_send_row_still_refuses_a_scalar_for_an_expression_destination() -> None:
    """The unmoded path keeps its own refusal, pinned by its own message."""
    src = PREAMBLE + '@handler("h")\ndef h(msg):\n    return Send(dest, msg)\n'
    with pytest.raises(LensRewriteError, match="currently an expression"):
        _set(src, {"to": "OB"})


@pytest.mark.parametrize(
    "arg",
    [
        pytest.param("f\"{msg.field('OBX-5', 2)}\"", id="field-read-with-two-args"),
        pytest.param('f"no read at all"', id="no-placeholder"),
        pytest.param("f\"{msg['A{B']}\"", id="path-the-renderer-refuses"),
    ],
)
def test_a_templated_argument_with_no_parts_form_maps_to_none(arg: str) -> None:
    """Each shape is admitted by E.5, so it stays ``templated``, but the edit spec could not send it
    back unchanged, so it has no parts form. ``None`` says so explicitly rather than dropping the key,
    and it keeps the contract simple: any non-None ``param_parts`` value is a valid ``{"parts": ...}``."""
    row = _row(_one_row(f'set_field(msg, "PID-5.1", {arg})'))
    assert row["param_modes"]["value"] == MODE_TEMPLATED
    assert row["param_parts"] == {"value": None}


def test_contract_v1_emits_no_param_parts() -> None:
    src = _one_row('set_field(msg, "PID-5.1", f"{msg[\'PID-3\']}")')
    for entry in parse_source(src, contract=CONTRACT_V1):
        for row in entry["rows"]:
            assert "param_parts" not in row and "param_modes" not in row


def test_the_native_form_takes_a_template_too() -> None:
    out = _set(_one_row('msg.set("PID-8", "U")'), {"value": {"parts": [{"path": "PID-8"}]}})
    assert out.splitlines()[5] == '    msg.set("PID-8", f"{msg[\'PID-8\']}")'
    row = _row(out)
    assert (row["action"], row["param_modes"]["value"]) == ("set_field", MODE_TEMPLATED)


def test_the_two_bounded_modes_switch_in_both_directions() -> None:
    templated = _one_row('set_field(msg, "PID-5.1", f"{msg[\'PID-3\']}")')
    # templated -> static, by a scalar
    out = _set(templated, {"value": "LITERAL"})
    assert out.splitlines()[5] == '    set_field(msg, "PID-5.1", "LITERAL")'
    # templated -> templated, by new parts
    out = _set(templated, {"value": {"parts": [{"path": "PID-4"}, {"text": "!"}]}})
    assert out.splitlines()[5] == '    set_field(msg, "PID-5.1", f"{msg[\'PID-4\']}!")'
    # an expr is still accepted when the ENGINE classifies it static
    out = _set(templated, {"value": {"expr": '"plain"'}})
    assert _row(out)["param_modes"]["value"] == MODE_STATIC


@pytest.mark.parametrize(
    "expr",
    [
        pytest.param("f\"{msg['PID-9']}\"", id="round-trippable"),
        pytest.param("f\"{msg.field('OBX-5', 2)}\"", id="no-parts-form-and-raises-at-runtime"),
        pytest.param('f"no read"', id="no-placeholder"),
    ],
)
def test_a_templated_expr_is_refused_so_every_template_passes_the_renderer(expr: str) -> None:
    """A templated write has ONE route, ``{"parts"}``, so every one passes the round-trip gate in
    ``_render_parts``. E.5 admits ``msg.field`` reads that no parts list can express, and
    ``msg.field("OBX-5", 2)`` raises TypeError at runtime (occurrence is keyword-only)."""
    src = _one_row('set_field(msg, "PID-5.1", "old")')
    with pytest.raises(LensRewriteError, match="write a template as"):
        _set(src, {"value": {"expr": expr}})


def test_a_template_that_overruns_the_column_limit_is_refused() -> None:
    """Gate 3: ``ruff format`` would re-wrap an over-long call, and the lens never wraps a line."""
    src = _one_row('set_field(msg, "PID-5.1", "old")')
    long_parts = [{"text": "x" * 70}, {"path": "PID-3"}]
    with pytest.raises(LensRewriteError, match="column limit"):
        _set(src, {"value": {"parts": long_parts}})
    # A short template on the same row is fine.
    _set(src, {"value": {"parts": [{"text": "x" * 10}, {"path": "PID-3"}]}})
    # Width is counted as ruff counts it: 40 wide CJK characters are 80 columns, not 40.
    wide = [{"text": "\u4e2d" * 40}, {"path": "PID-3"}]
    with pytest.raises(LensRewriteError, match="column limit"):
        _set(src, {"value": {"parts": wide}})


@pytest.mark.parametrize(
    "bad", [float("inf"), float("-inf"), float("nan")], ids=["inf", "-inf", "nan"]
)
def test_a_non_finite_float_is_refused(bad: float) -> None:
    """``repr`` of inf and nan is a bare name, so the spliced call would raise NameError."""
    src = _one_row('pad_field(msg, "PID-3", 10)')
    with pytest.raises(LensRewriteError, match="no Python literal form"):
        _set(src, {"width": bad})


@pytest.mark.parametrize(
    ("value", "match"),
    [
        pytest.param({"parts": "PID-3"}, "must be a list", id="not-a-list"),
        pytest.param({"parts": [{"path": "A", "text": "b"}]}, "exactly one key", id="two-keys"),
        pytest.param({"parts": [{"field": "A"}]}, "must be", id="unknown-key"),
        pytest.param({"parts": [{"path": 3}]}, "must be", id="non-string"),
        pytest.param({"parts": [["path", "A"]]}, "exactly one key", id="not-an-object"),
        pytest.param({"parts": []}, "at least one 'path'", id="empty"),
        pytest.param({"parts": [{"text": "only text"}]}, "at least one 'path'", id="no-path"),
        pytest.param({"parts": [{"path": ""}]}, "must be non-empty", id="empty-path"),
        pytest.param({"parts": [{"path": "A'B"}]}, "must be non-empty", id="path-quote"),
        pytest.param({"parts": [{"path": 'A"B'}]}, "must be non-empty", id="path-dquote"),
        pytest.param({"parts": [{"path": "A\\B"}]}, "must be non-empty", id="path-backslash"),
        pytest.param({"parts": [{"path": "A{B"}]}, "must be non-empty", id="path-brace"),
        pytest.param({"parts": [{"path": "A\nB"}]}, "must be non-empty", id="path-newline"),
        pytest.param({"parts": [{"path": "A"}, {"text": "\ud800"}]}, "UTF-8", id="lone-surrogate"),
        pytest.param(
            {"parts": [{"path": "A"}], "extra": 1}, "an object value must", id="extra-key"
        ),
    ],
)
def test_a_malformed_parts_value_is_refused(value: dict[str, Any], match: str) -> None:
    src = _one_row('set_field(msg, "PID-5.1", "old")')
    with pytest.raises(LensRewriteError, match=match):
        _set(src, {"value": value})


def test_a_template_is_refused_on_a_lookup_argument() -> None:
    """A lookup statement built from inbound HL7 is an injection path."""
    src = _one_row('row = db_lookup("MPI", "select 1", {"id": 1})')
    for pname in ("connection", "statement"):
        with pytest.raises(LensRewriteError, match="injection path"):
            _set(src, {pname: {"parts": [{"path": "PID-3"}]}})
    assert "select 2" in _set(src, {"statement": "select 2"}), "a literal still edits"


def test_a_template_is_refused_on_a_diagnostic_argument() -> None:
    """``log_note`` redacts its operands, never its template, and ``checkpoint`` logs its label
    verbatim, so a field read interpolated into either would reach the log unredacted (CLAUDE.md
    section 9)."""
    note = _one_row('log_note("note {}", msg["PID-3"])')
    with pytest.raises(LensRewriteError, match="unredacted"):
        _set(note, {"template": {"parts": [{"path": "PID-3"}]}})
    label = _one_row('checkpoint(msg, "after")')
    with pytest.raises(LensRewriteError, match="unredacted"):
        _set(label, {"label": {"parts": [{"path": "PID-3"}]}})


@pytest.mark.parametrize(
    ("line", "pname"),
    [
        pytest.param('set_field(msg, "PID-5.1", "old")', "path", id="set-field-path"),
        pytest.param('copy_field(msg, "PID-3", "PID-4")', "dst", id="copy-field-dst"),
        pytest.param('pad_field(msg, "PID-3", 10)', "width", id="int-width"),
        pytest.param('delete_segment(msg, "ZX1")', "segment_id", id="segment-id"),
    ],
)
def test_a_template_is_refused_on_a_locator_or_setting(line: str, pname: str) -> None:
    """A template in a path, segment id or setting lets the message choose which field is overwritten,
    or puts a string where an int belongs. Only a value parameter takes one."""
    with pytest.raises(LensRewriteError, match="only a value parameter takes a template"):
        _set(_one_row(line), {pname: {"parts": [{"path": "PID-3"}]}})


def test_a_parts_value_is_refused_on_a_send_row() -> None:
    """A send destination carries no mode, so the templated spec has no meaning there."""
    src = PREAMBLE + '@handler("h")\ndef h(msg):\n    return Send("OB", msg)\n'
    with pytest.raises(LensRewriteError, match="expr"):
        _set(src, {"to": {"parts": [{"path": "PID-3"}]}})


# =============================================================================
# AC-M4 -- round-trip totality over GENERATED part sequences
# =============================================================================
#
# The alphabet is chosen to break a renderer: every character the f-string body must escape, the
# characters that are line breaks to some model and not to another, astral and combining characters,
# and text that looks like a placeholder. Sequences are enumerated exhaustively to length 3 and sampled
# with a fixed seed beyond that, so a failure is reproducible.

TEXT_ALPHABET = [
    "",
    " ",
    "MRN: ",
    "{",
    "}",
    "{{x}}",
    "{msg['X']}",
    "\\",
    '"',
    "'",
    '""',
    "\n",
    "\r\n",
    "\t",
    "\x00",
    "\x7f",
    "\x85",
    "\u2028",
    "\u200d",
    "\u00e9",
    "\U0001f6f0",
    "\u4e2d\u6587",
    "%s",
]
PATH_ALPHABET = ["PID-3", "PID-5.1", "OBX-5.1.2", "MSH-9", "ZX1-1", "PID-3(2)"]
PART_ALPHABET: list[dict[str, str]] = [{"text": t} for t in TEXT_ALPHABET] + [
    {"path": p} for p in PATH_ALPHABET
]


def _generated_sequences() -> list[list[dict[str, str]]]:
    exhaustive = [
        [dict(p) for p in seq]
        for n in range(0, 4)
        for seq in itertools.product(PART_ALPHABET, repeat=n)
    ]
    rng = random.Random(237)
    sampled = [
        [dict(rng.choice(PART_ALPHABET)) for _ in range(rng.randint(4, 9))] for _ in range(3000)
    ]
    return exhaustive + sampled


GENERATED = _generated_sequences()


def _round_trip(parts: list[dict[str, str]]) -> str | None:
    """Render ``parts``, then check the source reads back to the same mode with the same parts.

    Returns the rendered source, or None when the renderer refused. A refusal is legitimate for
    exactly one reason in this alphabet -- no path part -- and the caller asserts that."""
    try:
        rendered = _render_parts(parts, "value")
    except LensRewriteError:
        return None
    node = ast.parse(rendered, mode="eval").body
    assert _param_mode(node) == MODE_TEMPLATED, (parts, rendered)
    assert _template_parts(node) == _normalize_parts(parts), (parts, rendered)
    assert "\n" not in rendered and "\r" not in rendered, "a template must stay on one line"
    return rendered


def test_round_trip_is_total_over_generated_part_sequences() -> None:
    """AC-M4 / E.6.3. Every generated sequence either round-trips exactly, or is refused because it has
    no path part. Nothing else may happen: a refusal for any other reason would be a hole in the
    admitted set, and a mismatch would be the silent corruption the gate exists to forbid."""
    accepted = 0
    for parts in GENERATED:
        rendered = _round_trip(parts)
        has_path = any("path" in p for p in parts)
        if rendered is None:
            assert not has_path, f"a sequence with a path was refused: {parts!r}"
        else:
            assert has_path
            accepted += 1
    # POSITIVE CONTROL ON THE GENERATOR: a generator that produced only path-free sequences would pass
    # the loop above vacuously.
    assert accepted > 5000, accepted


def test_the_generated_alphabet_reaches_every_hazard() -> None:
    """A control on the test data: each escaping hazard must occur beside a path in some accepted
    sequence, or the round-trip test proves nothing about it."""
    seen: set[str] = set()
    for parts in GENERATED:
        if any("path" in p for p in parts):
            seen.update(p["text"] for p in parts if "text" in p)
    missing = [t for t in TEXT_ALPHABET if t and t not in seen]
    assert not missing, missing


def test_the_round_trip_check_catches_a_broken_renderer(monkeypatch: pytest.MonkeyPatch) -> None:
    """NEGATIVE CONTROL. Replace the escaper with the identity: braces and quotes then reach the
    f-string raw, and the renderer's own read-back gate must refuse rather than splice. If this passes
    silently, neither the gate nor the AC-M4 test above can see a renderer defect."""
    monkeypatch.setattr(lens, "_escape_template_text", lambda text, quote: text)
    with pytest.raises(LensRewriteError, match="reads back to the same parts"):
        _render_parts([{"text": "{x}"}, {"path": "PID-3"}], "value")
    with pytest.raises(LensRewriteError, match="reads back to the same parts"):
        _render_parts([{"text": '"'}, {"path": "PID-3"}, {"text": "''"}], "value")


def test_rendered_templates_are_ruff_format_clean() -> None:
    """Gate 3 of ADR 0076 section 5: the lens writes what ``ruff format`` would, including its quote
    choice when the text carries double quotes. One module holds a row per sampled sequence, so ruff
    runs once. A row over the column limit is left out: ``set_params`` has never wrapped a long
    argument, for a literal or a template, and that is not what this test measures."""
    lines = []
    for parts in GENERATED[:: max(1, len(GENERATED) // 1500)]:
        rendered = _round_trip(parts)
        if rendered is not None:
            line = f'    set_field(msg, "PID-5.1", {rendered})'
            if _display_width(line) <= 100:
                lines.append(line + "\n")
    assert len(lines) > 500, len(lines)
    module = (
        PREAMBLE + '@handler("h")\ndef h(msg):\n' + "".join(lines) + '    return Send("OB", msg)\n'
    )
    if importlib.util.find_spec("ruff") is None:  # pragma: no cover - environment guard
        pytest.skip("ruff is not installed")
    # The repository root as cwd, so ruff reads this project's config (line length 100) wherever
    # pytest was started from; its default of 88 would fail the 89-100 column rows falsely.
    proc = subprocess.run(
        [sys.executable, "-m", "ruff", "format", "--diff", "-"],
        input=module.encode("utf-8"),
        capture_output=True,
        cwd=Path(__file__).resolve().parents[1],
        timeout=120,
    )
    assert proc.returncode == 0, proc.stdout.decode("utf-8", "replace")[:3000]


# =============================================================================
# AC-M5 -- a dynamic argument refuses every edit
# =============================================================================

#: One dynamic argument shape per line, each in the ``value`` slot of a wrapper action. The E.5
#: exclusion list plus the shapes a hand-written handler really has: a bare read, a name, a call.
DYNAMIC_ARGS = [
    'msg["PID-3"]',
    "msg.field('PID-3')",
    "other",
    "helper(msg)",
    'msg["A"] + "b"',
    '"%s" % msg["A"]',
    '"{}".format(msg["A"])',
    '" ".join([msg["A"]])',
    "f\"{helper(msg['A'])}\"",
    "f\"{msg['A']:>10}\"",
    "f\"{msg['A']!r}\"",
    "f\"{(y := msg['A'])}\"",
    "f\"{msg['A'] if flag else ''}\"",
    "-1",
    "(1, 2)",
    '["A", "B"]',
]


@pytest.mark.parametrize("arg", DYNAMIC_ARGS)
def test_a_dynamic_argument_refuses_every_edit(arg: str) -> None:
    """AC-M5 / E.6.4. The negative case is the point: an ``expr`` repeating the argument's own source
    is exactly the passthrough that would look like success."""
    src = _one_row(f'set_field(msg, "PID-5.1", {arg})')
    assert _row(src)["param_modes"]["value"] == MODE_DYNAMIC, "fixture must be dynamic"
    for value in (
        "LITERAL",
        {"parts": [{"path": "PID-3"}]},
        {"expr": '"LITERAL"'},
        {"expr": arg},
    ):
        with pytest.raises(LensRewriteError, match="dynamic mode"):
            _set(src, {"value": value})


def test_a_dynamic_argument_leaves_its_neighbours_editable() -> None:
    """The refusal is per argument, not per row: the literal path beside a dynamic value still edits."""
    src = _one_row('set_field(msg, "PID-5.1", msg["PID-3"] + "!")')
    out = _set(src, {"path": "PID-5.2"})
    assert out.splitlines()[5] == '    set_field(msg, "PID-5.2", msg["PID-3"] + "!")'


def test_an_expr_may_not_author_a_dynamic_argument() -> None:
    """The other half of E.6.4: a static slot cannot be turned INTO the open-set shape either. A bare
    read is included -- it is ``dynamic``, which is why the picker writes parts instead."""
    src = _one_row('set_field(msg, "PID-5.1", "old")')
    for expr in ('msg["PID-3"]', 'msg["A"] + "b"', "helper(msg)", "(1, 2)"):
        with pytest.raises(LensRewriteError, match="dynamic-mode argument"):
            _set(src, {"value": {"expr": expr}})


def test_the_gate_leaves_the_unmoded_expr_paths_alone() -> None:
    """Scope control: route and send rows, and structural inserts, keep splicing ``{"expr": ...}``.
    Only set_params on an action, lookup or diagnostic argument is moded."""
    send = PREAMBLE + '@handler("h")\ndef h(msg):\n    return Send(dest, msg)\n'
    out = _set(send, {"to": {"expr": "other_dest"}})
    assert "Send(other_dest, msg)" in out
    inserted = rewrite_source(
        _one_row('set_field(msg, "PID-5.1", "old")'),
        {
            "op": "insert_row",
            "line_start": 6,
            "line_end": 6,
            "position": "after",
            "action": "set_field",
            "params": {"path": "A", "value": {"expr": 'msg["PID-5.1"]'}},
        },
    )
    assert '    msg.set("A", msg["PID-5.1"])\n' in inserted
    router = 'from messagefoundry import router\n\n\n@router("r")\ndef r(msg):\n    return ["H1"]\n'
    out = _set(router, {"handlers": ["H2", "H3"]})
    assert '    return ["H2", "H3"]\n' in out


# =============================================================================
# AC-M6 -- every other line byte-identical, and the rows still partition the def body
# =============================================================================

#: A handler with comments, blank lines, a nested block, a CRLF-free multi-row body and a non-ASCII
#: character before the edited argument on its own line.
WIDE = (
    "from messagefoundry import Send, handler, set_field, copy_field\n"
    "\n"
    "\n"
    '@handler("wide")\n'
    "def wide(msg):\n"
    "    # leading comment\n"
    '    copy_field(msg, "PID-3.1", "PID-4.1")\n'
    "\n"
    '    set_field(msg, "NTE-3", "caf\u00e9")  # trailing comment\n'
    '    if msg["MSH-9.1"] == "ADT":\n'
    '        set_field(msg, "PID-5.1", "old")\n'
    "    # between rows\n"
    '    set_field(msg, "PID-5.2", f"{msg[\'PID-3\']}")\n'
    '    return Send("OB", msg)\n'
)


def _partition_holds(source: str) -> None:
    """The rows tile the def body with no gap and no overlap, under both contracts.

    Contract 1 starts the tiling at the first statement; contract 2 may start it earlier, at a leading
    comment it projects as a ``note`` row (Amendment A). Both end at the def's last line."""
    tree = ast.parse(source)
    func = next(n for n in tree.body if isinstance(n, ast.FunctionDef))
    assert func.end_lineno is not None
    for contract in (CONTRACT_V1, CONTRACT_V2):
        rows = parse_source(source, contract=contract)[0]["rows"]
        assert rows == sorted(rows, key=lambda r: r["line_start"])
        assert func.lineno < rows[0]["line_start"] <= func.body[0].lineno
        assert rows[-1]["line_end"] == func.end_lineno
        for prev, nxt in itertools.pairwise(rows):
            assert prev["line_end"] + 1 == nxt["line_start"], f"gap/overlap: {prev} {nxt}"


@pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
@pytest.mark.parametrize("bom", [False, True], ids=["no-bom", "bom"])
@pytest.mark.parametrize(
    ("line", "param"),
    [(9, "value"), (11, "value"), (13, "value")],
    ids=["after-non-ascii", "nested", "already-templated"],
)
def test_a_template_edit_changes_only_its_own_argument(
    newline: str, bom: bool, line: int, param: str
) -> None:
    """AC-M6: the edited line differs only inside the argument's span, every other byte is identical,
    and the rows still partition the body. Run over LF and CRLF, with and without a BOM, because the
    splice works in UTF-8 byte space and each of those shifts a byte offset."""
    source = ("\ufeff" if bom else "") + WIDE.replace("\n", newline)
    before_rows = parse_source(source.removeprefix("\ufeff"), contract=CONTRACT_V2)[0]["rows"]
    sample = [parts for parts in GENERATED[::397] if any("path" in p for p in parts)]
    written = 0
    for parts in sample:
        try:
            out = _set(source, {param: {"parts": parts}}, line=line)
        except LensRewriteError as exc:
            # The one legitimate refusal in this alphabet: a long template past the column limit.
            assert "column limit" in str(exc), exc
            continue
        written += 1
        assert out.startswith("\ufeff") == bom
        old_lines = source.split(newline)
        new_lines = out.split(newline)
        assert len(new_lines) == len(old_lines), "a template edit must not change the line count"
        for i, (old, new) in enumerate(zip(old_lines, new_lines, strict=True), start=1):
            if i != line:
                assert old == new, f"line {i} changed"
        old_line, new_line = old_lines[line - 1], new_lines[line - 1]
        prefix = old_line[: old_line.index('", ') + 3]
        assert new_line.startswith(prefix)
        suffix = old_line[old_line.rindex(")") :]
        assert new_line.endswith(suffix)
        after = out.removeprefix("\ufeff")
        _partition_holds(after)
        after_rows = parse_source(after, contract=CONTRACT_V2)[0]["rows"]
        assert [(r["line_start"], r["line_end"], r["kind"]) for r in after_rows] == [
            (r["line_start"], r["line_end"], r["kind"]) for r in before_rows
        ]
        edited = next(r for r in after_rows if r["line_start"] == line)
        assert edited["param_parts"][param] == _normalize_parts(parts)
    assert written > 20, f"only {written} of {len(sample)} sampled templates were written"

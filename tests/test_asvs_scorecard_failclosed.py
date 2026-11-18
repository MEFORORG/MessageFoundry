# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ASVS scorecard verifier refuses what it cannot measure, rather than passing it.

Each test here drives a record or a tree that the verifier used to accept, crash on, or report as
clean, and asserts the refusal. Synthetic fixtures only: the verifier is data-free (ADR 0156 section 7).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import scripts.asvs.scorecard as scorecard_module
from scripts.asvs.scorecard import (
    ANCHOR_GONE,
    Anchor,
    Cell,
    Findings,
    ScorecardError,
    check_anchors,
    load_reviewer_exceptions,
    load_scorecard,
    locate_anchor,
    main,
    repo_stamp,
)

#: One loadable cell. Each test appends or substitutes the one field it is about.
_CELL = '[[cell]]\nid = "1.1.1"\nlevel = 1\nverdict = "fail"\nresidual = "why"\n'

#: One absence claim whose fields are all well formed.
_ABSENCE = (
    "  [[cell.absence]]\n"
    "  pattern = 'eval\\('\n"
    "  positive_control = 'def '\n"
    "  mutation = 'eval(x)'\n"
)

#: A complete, well-typed blocker.
_BLOCKER = (
    "  [cell.blocker]\n"
    '  blocked_by = "upstream"\n'
    '  reason = "r"\n'
    '  evidence = "e"\n'
    '  unblock_signal = "s"\n'
    '  unblock_probe = "p"\n'
    '  checked_on = "2026-08-01"\n'
    "  recheck_days = 30\n"
)


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "sc.toml"
    p.write_text(body, encoding="utf-8")
    return p


def _load(tmp_path: Path, body: str) -> None:
    load_scorecard(_write(tmp_path, body))


# --- BACKLOG #5457: the loader refuses a blind control, a broken regex and a mistyped scalar ------


def test_the_well_formed_fixtures_load(tmp_path: Path) -> None:
    """Control: every refusal below is caused by the one field it changes, not by the fixture."""
    cells = load_scorecard(_write(tmp_path, _CELL + _ABSENCE + _BLOCKER))
    assert cells[0].blocker is not None and cells[0].absence[0].positive_control == "def "


@pytest.mark.parametrize(
    "control",
    ["", "   ", "x*", "(?:)", "^", "a|", ".", "\\w", "\\b", "(?=.)", "[\\s\\S]"],
    ids=[
        "empty",
        "blank",
        "star",
        "empty-group",
        "caret",
        "empty-branch",
        "dot",
        "word-class",
        "word-boundary",
        "lookahead",
        "any-class",
    ],
)
def test_a_positive_control_that_matches_everything_is_refused(
    tmp_path: Path, control: str
) -> None:
    """A control that matches the empty string, or any lone character of a class, is sighted in
    almost every text, so it can never go quiet and the BLIND check can never fire."""
    body = _CELL + _ABSENCE.replace("positive_control = 'def '", f"positive_control = '{control}'")
    with pytest.raises(ScorecardError, match="positive_control"):
        _load(tmp_path, body)


@pytest.mark.parametrize("control", ["y", "\\n"], ids=["letter", "newline"])
def test_a_one_character_literal_control_still_loads(tmp_path: Path, control: str) -> None:
    """Control for the single-character probe: a literal is a token, however short. The newline
    case pins that the probe set does not count a newline twice."""
    body = _CELL + _ABSENCE.replace("positive_control = 'def '", f"positive_control = '{control}'")
    assert load_scorecard(_write(tmp_path, body))[0].absence[0].positive_control == control


@pytest.mark.parametrize("pattern", ["", "x?", "|"], ids=["empty", "optional", "empty-branch"])
def test_a_pattern_that_matches_everything_is_refused(tmp_path: Path, pattern: str) -> None:
    body = _CELL + _ABSENCE.replace("pattern = 'eval\\('", f"pattern = '{pattern}'")
    with pytest.raises(ScorecardError, match="pattern"):
        _load(tmp_path, body)


@pytest.mark.parametrize("field", ["pattern", "positive_control"])
def test_a_malformed_regex_is_refused_not_raised_as_re_error(tmp_path: Path, field: str) -> None:
    """Before: re.error escaped from the loader or from check_absences, a traceback, not a refusal."""
    old = "pattern = 'eval\\('" if field == "pattern" else "positive_control = 'def '"
    body = _CELL + _ABSENCE.replace(old, f"{field} = 'unclosed('")
    with pytest.raises(ScorecardError, match=f"{field}.*not a valid regular expression"):
        _load(tmp_path, body)


@pytest.mark.parametrize(
    ("old", "new", "field"),
    [
        # A string "true" used to read as not-closed, so the pin check never ran.
        ("", 'decision_closed = "true"\ndecision_closed_verdict = "pass"\n', "decision_closed"),
        # str(1) is "1", which is non-blank, so an `na` passed the rationale check with no reason.
        ('verdict = "fail"\nresidual = "why"\n', 'verdict = "na"\nresidual = 1\n', "residual"),
        ('verdict = "fail"\nresidual = "why"\n', 'verdict = "na"\nresidual = []\n', "residual"),
        # str(False) is "False", which is truthy, so the cell read as re-verified.
        ("", "last_verified = false\n", "last_verified"),
        ("", "verified_at = 1\n", "verified_at"),
        ("", "posture = 2\n", "posture"),
        ("", "decision_closed_on = 2026-08-01\ndecision_closed = false\n", "decision_closed_on"),
        ("level = 1\n", 'level = "1"\n', "level"),
        ("level = 1\n", "level = true\n", "level"),
        ('verdict = "fail"\n', 'verdict = ["fail"]\n', "verdict"),
        ('id = "1.1.1"\n', "id = 111\n", "id"),
    ],
    ids=[
        "closed-as-string",
        "residual-int",
        "residual-array",
        "last-verified-bool",
        "verified-at-int",
        "posture-int",
        "closed-on-date-literal",
        "level-string",
        "level-bool",
        "verdict-array",
        "id-int",
    ],
)
def test_a_mistyped_cell_scalar_is_refused(tmp_path: Path, old: str, new: str, field: str) -> None:
    body = _CELL.replace(old, new, 1) if old else _CELL + new
    with pytest.raises(ScorecardError, match=f"`{field}` must be"):
        _load(tmp_path, body)


@pytest.mark.parametrize(
    ("old", "new", "field"),
    [
        # fromisoformat("20260801") succeeds, so an integer date slipped through.
        ('checked_on = "2026-08-01"', "checked_on = 20260801", "checked_on"),
        ('checked_on = "2026-08-01"', 'checked_on = "20260801"', "checked_on"),
        ('checked_on = "2026-08-01"', "checked_on = 2026-08-01", "checked_on"),
        ("recheck_days = 30", 'recheck_days = "30"', "recheck_days"),
        ("recheck_days = 30", "recheck_days = true", "recheck_days"),
        ("recheck_days = 30", "recheck_days = 30.9", "recheck_days"),
        ('reason = "r"', "reason = 7", "reason"),
    ],
    ids=[
        "date-int",
        "date-undashed",
        "date-literal",
        "days-string",
        "days-bool",
        "days-float",
        "reason-int",
    ],
)
def test_a_mistyped_blocker_field_is_refused(
    tmp_path: Path, old: str, new: str, field: str
) -> None:
    body = _CELL + _BLOCKER.replace(old, new)
    with pytest.raises(ScorecardError, match=f"blocker.{field}"):
        _load(tmp_path, body)


@pytest.mark.parametrize(
    ("old", "new", "field"),
    [
        ("mutation = 'eval(x)'", "mutation = 5", "mutation"),
        ("mutation = 'eval(x)'", "mutation = 'eval(x)'\n  mutation_path = 3", "mutation_path"),
        ("mutation = 'eval(x)'", "mutation = 'eval(x)'\n  observable = false", "observable"),
    ],
)
def test_a_mistyped_absence_field_is_refused(
    tmp_path: Path, old: str, new: str, field: str
) -> None:
    body = _CELL + _ABSENCE.replace(old, new)
    with pytest.raises(ScorecardError, match=f"`{field}` must be"):
        _load(tmp_path, body)


@pytest.mark.parametrize(
    "body",
    [
        "cell = 1\n",
        'cell = ["x"]\n',
        _CELL + "absence = 1\n",
        _CELL + "evidence = [1]\n",
        _CELL + 'blocker = "soon"\n',
    ],
    ids=["cell-int", "cell-strings", "absence-int", "evidence-ints", "blocker-string"],
)
def test_a_mistyped_table_is_refused(tmp_path: Path, body: str) -> None:
    """Before: AttributeError or TypeError, a traceback rather than a refusal."""
    with pytest.raises(ScorecardError):
        _load(tmp_path, body)


# --- BACKLOG #5462: every entry point maps an unreadable record to exit 2, with no traceback ------

#: Planted in each malformed record and in each injected failure. Seeing it in output is a leak.
_LEAK = "ZZ-RECORD-TEXT-SENTINEL"

_MODES = ["status", "prove", "verify"]


def _mode_argv(mode: str, record: Path, tmp_path: Path) -> list[str]:
    root = tmp_path / "engine"
    root.mkdir(exist_ok=True)
    argv = ["--scorecard", str(record), "--root", str(root)]
    if mode == "status":
        return [*argv, "--status"]
    if mode == "prove":
        return [*argv, "--prove-absences"]
    corpus = tmp_path / "corpus.json"
    corpus.write_text('{"requirements": [{"req_id": "V1.1.1", "L": "1"}]}', encoding="utf-8")
    return [*argv, "--corpus", str(corpus)]


def _record(tmp_path: Path, body: bytes) -> Path:
    """The record sits OUTSIDE the engine root, as the vault's own CI lays them out."""
    record = tmp_path / "record" / "sc.toml"
    record.parent.mkdir()
    record.write_bytes(body)
    return record


@pytest.mark.parametrize("mode", _MODES)
@pytest.mark.parametrize(
    ("body", "cls"),
    [
        (f'[[cell]\nid = "{_LEAK}"\n'.encode(), "TOMLDecodeError"),
        (
            f'[[cell]]\nid = "{_LEAK}"\nverd'.encode() + b'\xff\xfeict = "pass"\n',
            "UnicodeDecodeError",
        ),
    ],
    ids=["not-toml", "not-utf8"],
)
def test_an_unreadable_record_exits_2_in_every_mode(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], mode: str, body: bytes, cls: str
) -> None:
    """Before: TOMLDecodeError or UnicodeDecodeError escaped `main` as a traceback and exit 1, a
    code --status promises never to return and verify reserves for findings. The guard's own
    message is asserted too, so the exit 2 is attributable to it and not to some earlier refusal."""
    assert main(_mode_argv(mode, _record(tmp_path, body), tmp_path)) == 2
    captured = capsys.readouterr()
    assert _LEAK not in captured.out + captured.err
    assert f"the scorecard run stopped on {cls} before it completed" in captured.err
    assert "message is withheld" in captured.err


class _Unlisted(Exception):
    """A failure class no `except` list could name in advance."""


@pytest.mark.parametrize("mode", _MODES)
def test_an_unexpected_failure_exits_2_and_withholds_its_message(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    """The message of an exception nobody anticipated can quote the record, so only its class
    crosses to the output. Before: it escaped as a traceback carrying the message."""

    def _boom(*_a: object, **_k: object) -> object:
        raise _Unlisted(f"cell {_LEAK!r}: the grading words of the record")

    monkeypatch.setattr(scorecard_module, "load_scorecard", _boom)
    record = _record(tmp_path, _CELL.encode())
    assert main(_mode_argv(mode, record, tmp_path)) == 2
    captured = capsys.readouterr()
    assert _LEAK not in captured.out + captured.err
    assert "_Unlisted" in captured.err


def test_an_interrupt_is_not_swallowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Control for the breadth: the catch is for failures, not for an operator's Ctrl-C."""

    def _interrupt(*_a: object, **_k: object) -> object:
        raise KeyboardInterrupt

    monkeypatch.setattr(scorecard_module, "load_scorecard", _interrupt)
    record = _record(tmp_path, _CELL.encode())
    with pytest.raises(KeyboardInterrupt):
        main(_mode_argv("status", record, tmp_path))


#: A cell whose id is the sentinel, for the refusals this branch added that once named a cell by id.
_LEAK_CELL = _CELL.replace('"1.1.1"', f'"{_LEAK}"')


@pytest.mark.parametrize(
    ("body", "field"),
    [
        (_LEAK_CELL.replace("level = 1", 'level = "1"'), "level"),
        (_LEAK_CELL.replace('residual = "why"', "residual = 1"), "residual"),
        (_LEAK_CELL + _BLOCKER.replace('"2026-08-01"', '"2026-13-01"'), "blocker.checked_on"),
        (_LEAK_CELL + _BLOCKER.replace("30", '"30"'), "blocker.recheck_days"),
        (_LEAK_CELL + "  [[cell.evidence]]\n  path = 1\n", "path"),
        (
            _LEAK_CELL + '  [[cell.evidence]]\n  path = "m.py"\n  line = 1\n  expect = " "\n',
            "expect",
        ),
        (_LEAK_CELL + _ABSENCE.replace("'def '", "'.'"), "positive_control"),
        # The regex engine's own message quotes a group name, so the sentinel arrives through it
        # even when the cell id is clean.
        (_CELL + _ABSENCE.replace("'eval\\('", f"'(?P<{_LEAK}>x)'"), "pattern"),
        # `re.compile` raises OverflowError, not re.error, for this: it used to escape the loader.
        (_LEAK_CELL + _ABSENCE.replace("'eval\\('", "'a{4294967296}'"), "pattern"),
        # A deadline past the calendar used to load, then stop every renderer on OverflowError.
        (_LEAK_CELL + _BLOCKER.replace("30", "99999999"), "blocker.recheck_days"),
    ],
    ids=[
        "level",
        "residual",
        "checked_on",
        "recheck_days",
        "path",
        "expect",
        "control",
        "regex",
        "regex-overflow",
        "recheck-overflow",
    ],
)
def test_a_refusal_names_the_field_not_the_record_value(
    tmp_path: Path, body: str, field: str
) -> None:
    """The refusals this branch added reach a CI log, so they name the cell by position and the
    field by name, and never repeat what the record holds. Before: they named the cell by its id,
    and an uncompilable pattern carried the regex engine's message, which can quote the pattern."""
    with pytest.raises(ScorecardError) as exc:
        _load(tmp_path, body)
    message = str(exc.value)
    assert field in message and "cell[0]" in message, message
    assert _LEAK not in message, message


@pytest.mark.parametrize("value", [_LEAK, "2026-13-01"], ids=["bad-shape", "bad-date"])
def test_a_checked_on_refusal_does_not_carry_the_value_on_its_chain(
    tmp_path: Path, value: str
) -> None:
    """Before: the refusal text left the value out, but the ValueError it was raised `from` held it,
    so any traceback or logger walking `__cause__` printed the record's text. Then `from None`
    cleared `__cause__` and left the ValueError on `__context__`, which hides nothing."""
    with pytest.raises(ScorecardError) as exc:
        _load(tmp_path, _CELL + _BLOCKER.replace('"2026-08-01"', f'"{value}"'))
    assert exc.value.__cause__ is None
    assert exc.value.__context__ is None


@pytest.mark.parametrize(
    "pattern",
    ["unclosed(", "x{99999999999}", "(" * 2000 + "x" + ")" * 2000],
    ids=["re-error", "overflow", "deep-nesting"],
)
def test_a_regex_refusal_does_not_carry_the_pattern_on_its_chain(
    tmp_path: Path, pattern: str
) -> None:
    """Before: the refusal was raised `from None` inside the handler, so the `re.error` holding the
    pattern on `.pattern` stayed on `__context__`; a deeply nested pattern escaped as RecursionError."""
    body = _CELL + _ABSENCE.replace("pattern = 'eval\\('", f"pattern = '{pattern}'")
    with pytest.raises(ScorecardError, match="pattern.*not a valid regular expression") as exc:
        _load(tmp_path, body)
    assert exc.value.__cause__ is None
    assert exc.value.__context__ is None


# --- BACKLOG #5459: an anchor must name a token, and must stay inside the engine root ------------

_ANCHOR = '  [[cell.evidence]]\n  path = "mod.py"\n  line = 1\n  expect = "TOKEN"\n'


def test_the_well_formed_anchor_loads(tmp_path: Path) -> None:
    """Control for the anchor refusals below."""
    assert load_scorecard(_write(tmp_path, _CELL + _ANCHOR))[0].evidence[0].expect == "TOKEN"


@pytest.mark.parametrize("text", ["", "x = 1\n"], ids=["empty-file", "any-file"])
def test_an_empty_token_never_locates(text: str) -> None:
    """Before: the empty string occurs exactly once in an empty file, so it LOCATED there."""
    assert locate_anchor(text, "").status == ANCHOR_GONE


def test_a_whitespace_token_never_locates() -> None:
    """A run of spaces that occurs once is still not a token."""
    assert locate_anchor("a   b", "   ").status == ANCHOR_GONE


@pytest.mark.parametrize("expect", ["", "   ", "\n"], ids=["empty", "spaces", "newline"])
def test_a_blank_expect_is_refused_at_load(tmp_path: Path, expect: str) -> None:
    body = _CELL + _ANCHOR.replace('expect = "TOKEN"', f"expect = {expect!r}".replace("'", '"'))
    with pytest.raises(ScorecardError, match="expect"):
        _load(tmp_path, body)


@pytest.mark.parametrize(
    "path",
    ["../outside.py", "a/../../outside.py", "/etc/outside.py", "C:/outside.py", "C:outside.py", ""],
    ids=["dotdot", "inner-dotdot", "posix-absolute", "drive-absolute", "drive-relative", "empty"],
)
def test_an_anchor_path_outside_the_root_is_refused_at_load(tmp_path: Path, path: str) -> None:
    body = _CELL + _ANCHOR.replace('path = "mod.py"', f'path = "{path}"')
    with pytest.raises(ScorecardError, match="path"):
        _load(tmp_path, body)


def test_a_backslash_dotdot_path_is_refused_at_load(tmp_path: Path) -> None:
    """A Windows separator must not hide a `..` from a check that splits on `/` only."""
    body = _CELL + _ANCHOR.replace('path = "mod.py"', "path = '..\\outside.py'")
    with pytest.raises(ScorecardError, match="path"):
        _load(tmp_path, body)


def test_a_path_with_a_control_character_is_refused_at_load(tmp_path: Path) -> None:
    """Before: a NUL loaded, then `Path.resolve` raised ValueError in check_anchors on POSIX and the
    run stopped on the class name instead of a refusal naming the field."""
    body = _CELL + _ANCHOR.replace('path = "mod.py"', 'path = "mod\\u0000.py"')
    with pytest.raises(ScorecardError, match="printable"):
        _load(tmp_path, body)


@pytest.mark.parametrize("line", ["0", "-3"])
def test_an_anchor_line_below_one_is_refused_at_load(tmp_path: Path, line: str) -> None:
    body = _CELL + _ANCHOR.replace("line = 1", f"line = {line}")
    with pytest.raises(ScorecardError, match="line"):
        _load(tmp_path, body)


def test_check_anchors_does_not_read_outside_the_root(tmp_path: Path) -> None:
    """A Cell built in code skips the loader, so the check holds the line itself. Before: the
    anchor resolved against a file beside the engine root and passed as LOCATED."""
    (tmp_path / "outside.py").write_text("TOKEN = 1\n", encoding="utf-8")
    root = tmp_path / "engine"
    root.mkdir()
    cell = Cell(
        id="1.1.1",
        level=1,
        verdict="fail",
        evidence=(Anchor(path="../outside.py", line=1, expect="TOKEN"),),
    )
    findings = Findings()
    check_anchors([cell], root, findings)
    assert findings.checked_anchors == 0
    assert any("outside the root" in p for p in findings.problems), findings.problems


def test_check_anchors_does_not_follow_a_symlink_out_of_the_root(tmp_path: Path) -> None:
    """The path passes `_is_within_tree`; only resolving it shows where it lands."""
    (tmp_path / "outside.py").write_text("TOKEN = 1\n", encoding="utf-8")
    root = tmp_path / "engine"
    root.mkdir()
    try:
        (root / "inside.py").symlink_to(tmp_path / "outside.py")
    except OSError as exc:  # Windows without the symlink privilege
        pytest.skip(f"cannot create a symlink here: {exc}")
    cell = Cell(
        id="1.1.1",
        level=1,
        verdict="fail",
        evidence=(Anchor(path="inside.py", line=1, expect="TOKEN"),),
    )
    findings = Findings()
    check_anchors([cell], root, findings)
    assert findings.checked_anchors == 0
    assert any("outside the root" in p for p in findings.problems), findings.problems


# --- BACKLOG #5460: every reviewer exception must sit before the first cell ----------------------


def _exception(cid: str, header: str = "[[reviewer_exception]]") -> str:
    return f'{header}\nid = "{cid}"\nprovenance = "history shows a named pass"\n\n'


def test_exceptions_that_all_precede_the_cells_load(tmp_path: Path) -> None:
    """Control: the ordering refusal fires on placement, not on the number of exceptions."""
    body = _exception("1.1.1") + _exception("1.1.2") + _CELL
    assert set(load_reviewer_exceptions(_write(tmp_path, body))) == {"1.1.1", "1.1.2"}


@pytest.mark.parametrize(
    "late",
    [
        "[[reviewer_exception]]",
        "  [[reviewer_exception]]",
        "[[ reviewer_exception ]]",
        '[["reviewer_exception"]]',
    ],
    ids=["plain", "indented", "spaced", "quoted"],
)
def test_an_exception_after_a_cell_is_refused_even_behind_an_earlier_one(
    tmp_path: Path, late: str
) -> None:
    """Before: only the FIRST exception header was compared with the first cell, so a second one
    placed after a cell loaded, and apply.py's rewrite of that cell would delete it."""
    body = _exception("1.1.1") + _CELL + "\n" + _exception("1.1.2", late)
    with pytest.raises(ScorecardError, match="before the first"):
        load_reviewer_exceptions(_write(tmp_path, body))


@pytest.mark.parametrize(
    "late", ["  [[reviewer_exception]]", "[[ reviewer_exception ]]"], ids=["indented", "spaced"]
)
def test_a_lone_exception_after_a_cell_is_refused_in_any_header_spelling(
    tmp_path: Path, late: str
) -> None:
    """Before: the column-zero, unspaced search did not see these headers at all."""
    body = _CELL + "\n" + _exception("1.1.1", late)
    with pytest.raises(ScorecardError, match="before the first"):
        load_reviewer_exceptions(_write(tmp_path, body))


def test_an_exception_after_a_cell_header_spelled_another_way_is_refused(tmp_path: Path) -> None:
    """A first cell written `[[ cell ]]` still starts the cells."""
    body = _CELL.replace("[[cell]]", "[[ cell ]]") + "\n" + _exception("1.1.1")
    with pytest.raises(ScorecardError, match="before the first"):
        load_reviewer_exceptions(_write(tmp_path, body))


# --- BACKLOG #5461: --prove-absences measures a named engine tree, as verify does ----------------


def _prove_record(tmp_path: Path, body: str = _CELL) -> Path:
    record = tmp_path / "record" / "sc.toml"
    record.parent.mkdir(exist_ok=True)
    record.write_text(body, encoding="utf-8")
    return record


def test_prove_absences_requires_a_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before: no --root meant the working directory, so a run from the vault proved its claims
    against the vault's own stale engine copy and reported success."""
    monkeypatch.chdir(tmp_path)
    assert main(["--scorecard", str(_prove_record(tmp_path)), "--prove-absences"]) == 2
    assert "--root is required" in capsys.readouterr().err


def test_prove_absences_refuses_a_root_that_holds_the_record(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    record = _prove_record(tmp_path)
    assert main(["--scorecard", str(record), "--root", str(tmp_path), "--prove-absences"]) == 2
    assert "CONTAINS the scorecard" in capsys.readouterr().err


@pytest.mark.parametrize("kind", ["missing", "file"])
def test_prove_absences_refuses_a_root_that_is_not_a_directory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], kind: str
) -> None:
    root = tmp_path / "engine"
    if kind == "file":
        root.write_text("not a tree\n", encoding="utf-8")
    record = _prove_record(tmp_path)
    assert main(["--scorecard", str(record), "--root", str(root), "--prove-absences"]) == 2
    assert "not a directory" in capsys.readouterr().err


def test_prove_absences_refuses_a_record_with_no_cells(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Before: an empty record scanned zero claims and exited 0, a pass over nothing."""
    root = tmp_path / "engine"
    root.mkdir()
    record = _prove_record(tmp_path, "[scorecard]\n")
    assert main(["--scorecard", str(record), "--root", str(root), "--prove-absences"]) == 2
    assert "no cells" in capsys.readouterr().err


def test_prove_absences_prints_the_provenance_header(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Before: no line said which trees the proof was measured against. The record carries one
    absence claim that names a mutation_path, so the run gets past every refusal, the skipped-only
    one included, and the header is read off a completed run."""
    root = tmp_path / "engine"
    root.mkdir()
    (root / "m.py").write_text("X = 1\n", encoding="utf-8")
    record = _prove_record(tmp_path, _CELL + _ABSENCE + '  mutation_path = "m.py"\n')
    assert main(["--scorecard", str(record), "--root", str(root), "--prove-absences"]) == 0
    captured = capsys.readouterr()
    assert captured.out.startswith("# asvs-prove-absences scorecard=")
    assert "prove-absences: saw 1 absence claim(s);" in captured.out
    assert "1 static-screened" in captured.out
    assert "no absence claims" not in captured.err
    assert "every absence claim was skipped" not in captured.err


def test_prove_absences_does_not_refuse_a_run_that_skipped_only_some_claims(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The boundary of the skipped-only refusal: one claim skipped beside one screened is a
    measurement, so it exits 0. Pins the guard against widening to `any claim skipped`, which would
    refuse every partly adopted record."""
    root = tmp_path / "engine"
    root.mkdir()
    (root / "m.py").write_text("X = 1\n", encoding="utf-8")
    body = _CELL + _ABSENCE + '  mutation_path = "m.py"\n' + _ABSENCE
    record = _prove_record(tmp_path, body)
    assert main(["--scorecard", str(record), "--root", str(root), "--prove-absences"]) == 0
    captured = capsys.readouterr()
    assert "saw 2 absence claim(s);" in captured.out
    assert "1 static-screened; 1 skipped;" in captured.out
    assert "every absence claim was skipped" not in captured.err


def test_prove_absences_refuses_a_run_where_every_claim_was_skipped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Before: a claim with no mutation_path is skipped, a skip raises no problem, so a pass that
    skipped every claim exited 0 printing `proved 0`, which a CI step reads as every claim proved.
    It refuses, exit 2, naming the reason in words; the summary still prints first."""
    root = tmp_path / "engine"
    root.mkdir()
    record = _prove_record(tmp_path, _CELL + _ABSENCE)
    assert main(["--scorecard", str(record), "--root", str(root), "--prove-absences"]) == 2
    captured = capsys.readouterr()
    assert captured.out.startswith("# asvs-prove-absences scorecard=")
    assert "prove-absences: saw 1 absence claim(s);" in captured.out
    assert "every absence claim was skipped" in captured.err
    assert "measured nothing is not a pass" in captured.err


def test_prove_absences_refuses_cells_with_no_absence_claim(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Before: a record whose cells carry no absence claim scanned zero claims and exited 0, the
    same pass over nothing as an empty record. The header still comes first."""
    root = tmp_path / "engine"
    root.mkdir()
    record = _prove_record(tmp_path)
    assert main(["--scorecard", str(record), "--root", str(root), "--prove-absences"]) == 2
    captured = capsys.readouterr()
    assert captured.out.startswith("# asvs-prove-absences scorecard=")
    assert "saw 0 absence claim(s)" not in captured.out
    assert "no absence claims" in captured.err


def test_verify_refuses_a_root_that_is_not_a_directory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The same refusal in verify, which shares the root check."""
    record = _prove_record(tmp_path)
    argv = _mode_argv("verify", record, tmp_path)
    argv[argv.index("--root") + 1] = str(tmp_path / "no-such-engine")
    assert main(argv) == 2
    assert "not a directory" in capsys.readouterr().err


# --- BACKLOG #5458: a git probe that fails reports UNKNOWN, never clean ---------------------------


def _git_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    # Signing off, as test_asvs_scorecard's _GIT_ID does: a global commit.gpgsign would fail the
    # fixture commit, or wait on a pinentry prompt, for a reason unrelated to the code under test.
    ident = [
        "-c",
        "user.name=fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "-c",
        "commit.gpgsign=false",
    ]
    subprocess.run(["git", "-C", str(path), "init", "--quiet"], check=True, capture_output=True)
    (path / "a.txt").write_text("a\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(path), "add", "a.txt"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(path), *ident, "commit", "--quiet", "-m", "a"],
        check=True,
        capture_output=True,
    )
    return path


def test_a_failed_status_probe_is_unknown_not_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before: `git status` failing or timing out returned None, and `bool(None)` stamped the tree
    clean, which is the one answer the dirty flag exists to withhold when it is not known."""
    repo = _git_repo(tmp_path / "repo")
    (repo / "a.txt").write_text("changed\n", encoding="utf-8")  # really dirty
    real_git = scorecard_module._git

    def _status_fails(where: Path, *args: str) -> str | None:
        return None if args[:1] == ("status",) else real_git(where, *args)

    monkeypatch.setattr(scorecard_module, "_git", _status_fails)
    stamp = repo_stamp(repo)
    assert stamp.dirty is None
    assert stamp.ref().endswith("+status-unknown")


def test_a_clean_and_a_dirty_tree_still_read_as_such(tmp_path: Path) -> None:
    """Control: the unknown state is only for a failed probe."""
    repo = _git_repo(tmp_path / "repo")
    assert repo_stamp(repo).dirty is False
    (repo / "a.txt").write_text("changed\n", encoding="utf-8")
    stamp = repo_stamp(repo)
    assert stamp.dirty is True and stamp.ref().endswith("+dirty")


def test_a_repo_under_a_non_ascii_path_still_finds_its_fetch_head(tmp_path: Path) -> None:
    """git prints paths as UTF-8. Decoded in the locale code page (cp1252 on Windows) the git dir's
    name came back garbled, FETCH_HEAD was not found, and the stamp read NEVER-FETCHED."""
    repo = _git_repo(tmp_path / "répertoire-日本")
    (repo / ".git" / "FETCH_HEAD").write_text("", encoding="utf-8")
    assert repo_stamp(repo).remote_knowledge != "NEVER-FETCHED"


def test_a_relative_path_is_stamped_against_the_tree_it_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control, not a regression test: a relative path stamped the right tree before the path was
    resolved too. It pins that resolving it changed nothing for a relative caller."""
    repo = _git_repo(tmp_path / "repo")
    (repo / "sc.toml").write_text("", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    stamp = repo_stamp(Path("repo") / "sc.toml")
    assert stamp.sha != "NO-GIT" and stamp.dirty is True

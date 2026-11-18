# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ASVS scorecard verifier refuses what it cannot measure, rather than passing it.

Each test here drives a record or a tree that the verifier used to accept, crash on, or report as
clean, and asserts the refusal. Synthetic fixtures only: the verifier is data-free (ADR 0156 section 7).
"""

from __future__ import annotations

from pathlib import Path

import pytest

import scripts.asvs.scorecard as scorecard_module
from scripts.asvs.scorecard import ScorecardError, load_scorecard, main

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
    ["", "   ", "x*", "(?:)", "^", "a|"],
    ids=["empty", "blank", "star", "empty-group", "caret", "empty-branch"],
)
def test_a_positive_control_that_matches_everything_is_refused(
    tmp_path: Path, control: str
) -> None:
    """A control that matches the empty string matches every text, so it can never go quiet and the
    BLIND check it exists for can never fire."""
    body = _CELL + _ABSENCE.replace("positive_control = 'def '", f"positive_control = '{control}'")
    with pytest.raises(ScorecardError, match="positive_control"):
        _load(tmp_path, body)


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
    "body",
    [
        f'[[cell]\nid = "{_LEAK}"\n'.encode(),
        f'[[cell]]\nid = "{_LEAK}"\nverd'.encode() + b'\xff\xfeict = "pass"\n',
    ],
    ids=["not-toml", "not-utf8"],
)
def test_an_unreadable_record_exits_2_in_every_mode(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], mode: str, body: bytes
) -> None:
    """Before: TOMLDecodeError or UnicodeDecodeError escaped `main` as a traceback and exit 1, a
    code --status promises never to return and verify reserves for findings."""
    assert main(_mode_argv(mode, _record(tmp_path, body), tmp_path)) == 2
    captured = capsys.readouterr()
    assert _LEAK not in captured.out + captured.err


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

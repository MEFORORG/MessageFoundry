# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The prove-absences report fails closed on a run that measured nothing (BACKLOG #5456).

Three holes, each pinned here against `prove_report.run` with the prover subprocess replaced, so the
test reads the report's own policy rather than the prover's:

* a scorecard with no cells, or no absence claim, reconciled against a prover that saw zero and
  exited 0;
* a prover that crashed after printing a zero-problem summary exits 1, and the report read only the
  summary, so it exited 0;
* the failure paths printed the prover's raw streams whatever `--detail` said, into a public log.

Every id and claim below is synthetic.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pytest

from scripts.asvs import prove_report
from scripts.asvs.prove_report import EXIT_INSTRUMENT, EXIT_OK, run

#: A marker standing in for claim text the public log must not carry.
_SECRET = "SYNTHETIC-CLAIM-TEXT-7f3a"

#: One cell with one claim and no `mutation_path`: the census counts it unprovable, so a prover
#: summary of "1 skipped, 0 problems" reconciles with it exactly.
_ONE_CLAIM = """[[cell]]
id = '99.1.1'
level = 1
verdict = 'fail'
residual = 'synthetic'
  [[cell.absence]]
  pattern = 'p'
  positive_control = 'c'
  mutation = 'm'
"""

_CLEAN_SUMMARY = (
    "prove-absences: saw 1 absence claim(s); proved 0 by mutation; 0 static-screened; "
    "1 skipped; 0 problem(s)\n"
)
_ZERO_SUMMARY = (
    "prove-absences: saw 0 absence claim(s); proved 0 by mutation; 0 static-screened; "
    "0 skipped; 0 problem(s)\n"
)


@pytest.fixture(autouse=True)
def summary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the job summary at a scratch file, so a run under Actions writes nothing to the real
    one, and the tests can read what a run would have published."""
    dest = tmp_path / "step-summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(dest))
    return dest


def _ns(
    scorecard: Path, root: Path, *, detail: bool = False, python: str = "python"
) -> argparse.Namespace:
    return argparse.Namespace(
        scorecard=str(scorecard),
        root=str(root),
        python=python,
        timeout=60.0,
        detail=detail,
        strict=False,
    )


def _fake_prover(
    monkeypatch: pytest.MonkeyPatch, rc: int, stdout: str, stderr: str = ""
) -> list[int]:
    calls: list[int] = []

    def fake(scorecard: Path, root: Path, python: str, timeout: float) -> tuple[int, str, str]:
        calls.append(1)
        return rc, stdout, stderr

    monkeypatch.setattr(prove_report, "_invoke_prover", fake)
    return calls


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("", id="empty-file"),
        pytest.param('[scorecard]\nasvs_version = "5.0.0"\n', id="no-cells"),
        pytest.param(
            "[[cell]]\nid = '99.1.1'\nlevel = 1\nverdict = 'pass'\nresidual = 'x'\n",
            id="cells-but-no-claims",
        ),
    ],
)
def test_a_record_with_nothing_to_scan_is_an_instrument_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, summary: Path, text: str
) -> None:
    sc = tmp_path / "scorecard.toml"
    sc.write_text(text, encoding="utf-8")
    _fake_prover(monkeypatch, 0, _ZERO_SUMMARY)
    assert run(_ns(sc, tmp_path)) == EXIT_INSTRUMENT
    assert "MEASURED NOTHING CHECKABLE" in summary.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(b"\xff\xfe not utf-8", id="not-utf8"),
        pytest.param(b"[[cell]]\nid = '99.1.1'\nabsence = 'x'\n", id="absence-not-a-table"),
        pytest.param(b"cell = [1]\n", id="cell-not-a-table"),
    ],
)
def test_an_unreadable_record_is_an_instrument_failure_not_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: bytes
) -> None:
    """Uncaught, each of these exited 1, which a findings run exits too."""
    sc = tmp_path / "scorecard.toml"
    sc.write_bytes(content)
    _fake_prover(monkeypatch, 0, _CLEAN_SUMMARY)
    assert run(_ns(sc, tmp_path)) == EXIT_INSTRUMENT


def test_a_prover_that_cannot_start_is_an_instrument_failure(tmp_path: Path) -> None:
    sc = tmp_path / "scorecard.toml"
    sc.write_text(_ONE_CLAIM, encoding="utf-8")
    missing = str(tmp_path / "no-such-python")
    assert run(_ns(sc, tmp_path, python=missing)) == EXIT_INSTRUMENT


def test_the_one_claim_fixture_is_a_clean_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the refusals below: the same fixture with a prover that finished cleanly
    passes, so the refusals are about the exit code and the streams, not the fixture."""
    sc = tmp_path / "scorecard.toml"
    sc.write_text(_ONE_CLAIM, encoding="utf-8")
    calls = _fake_prover(monkeypatch, 0, _CLEAN_SUMMARY)
    assert run(_ns(sc, tmp_path)) == EXIT_OK
    assert calls


@pytest.mark.parametrize("rc", [1, 3, -11])
def test_an_exit_code_the_summary_does_not_explain_is_an_instrument_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], rc: int
) -> None:
    """A crash after the summary line: zero problems reported, a non-zero exit."""
    sc = tmp_path / "scorecard.toml"
    sc.write_text(_ONE_CLAIM, encoding="utf-8")
    _fake_prover(
        monkeypatch, rc, _CLEAN_SUMMARY, f"Traceback (most recent call last):\n{_SECRET}\n"
    )
    assert run(_ns(sc, tmp_path)) == EXIT_INSTRUMENT
    captured = capsys.readouterr()
    assert _SECRET not in captured.out + captured.err


_ONE_PROBLEM = _CLEAN_SUMMARY.replace("0 problem(s)", "1 problem(s)")


def test_problems_with_a_zero_exit_is_an_instrument_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sc = tmp_path / "scorecard.toml"
    sc.write_text(_ONE_CLAIM, encoding="utf-8")
    _fake_prover(monkeypatch, 0, _ONE_PROBLEM, "  FAIL synthetic\n")
    assert run(_ns(sc, tmp_path)) == EXIT_INSTRUMENT


def test_an_ordinary_findings_run_is_still_advisory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the two crash cases below: exit 1, one problem, its one FAIL line."""
    sc = tmp_path / "scorecard.toml"
    sc.write_text(_ONE_CLAIM, encoding="utf-8")
    _fake_prover(monkeypatch, 1, _ONE_PROBLEM, "  FAIL synthetic\n")
    assert run(_ns(sc, tmp_path)) == EXIT_OK


@pytest.mark.parametrize(
    ("prover_summary", "stderr"),
    [
        pytest.param(
            _ONE_PROBLEM,
            "  FAIL synthetic\nTraceback (most recent call last):\n  boom\n",
            id="traceback-after-the-fail-lines",
        ),
        pytest.param(
            _CLEAN_SUMMARY.replace("0 problem(s)", "2 problem(s)"),
            "  FAIL synthetic\n",
            id="fail-lines-cut-short",
        ),
    ],
)
def test_a_crash_during_a_findings_run_is_an_instrument_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, prover_summary: str, stderr: str
) -> None:
    """A crash while printing the FAIL lines also exits 1, which a findings run exits too."""
    sc = tmp_path / "scorecard.toml"
    sc.write_text(_ONE_CLAIM, encoding="utf-8")
    _fake_prover(monkeypatch, 1, prover_summary, stderr)
    assert run(_ns(sc, tmp_path)) == EXIT_INSTRUMENT


@pytest.mark.parametrize(
    ("rc", "stdout", "stderr"),
    [
        pytest.param(2, "", f"error: {_SECRET}\n", id="could-not-measure"),
        pytest.param(0, f"no summary here {_SECRET}\n", "", id="unparseable-summary"),
    ],
)
def test_raw_prover_streams_stay_out_of_the_log_without_detail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    summary: Path,
    rc: int,
    stdout: str,
    stderr: str,
) -> None:
    sc = tmp_path / "scorecard.toml"
    sc.write_text(_ONE_CLAIM, encoding="utf-8")
    _fake_prover(monkeypatch, rc, stdout, stderr)

    assert run(_ns(sc, tmp_path, detail=False)) == EXIT_INSTRUMENT
    hidden = capsys.readouterr()
    assert _SECRET not in hidden.out + hidden.err
    assert "SUPPRESSED" in hidden.err
    published = summary.read_text(encoding="utf-8")
    assert "MEASURED NOTHING CHECKABLE" in published
    assert _SECRET not in published

    # The opt-in still works: the suppression is a choice, not a lost stream.
    assert run(_ns(sc, tmp_path, detail=True)) == EXIT_INSTRUMENT
    shown = capsys.readouterr()
    assert _SECRET in shown.err


#: A count no fixture holds by chance, standing in for a figure the public log must not carry.
_COUNT = 4729


def test_the_suppression_note_carries_no_line_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    summary: Path,
) -> None:
    """A suppressed stream's size is a figure about the record, so the note states the reason in
    words only."""
    sc = tmp_path / "scorecard.toml"
    sc.write_text(_ONE_CLAIM, encoding="utf-8")
    _fake_prover(monkeypatch, 0, "no summary here\n" * _COUNT)
    assert run(_ns(sc, tmp_path)) == EXIT_INSTRUMENT
    captured = capsys.readouterr()
    assert "SUPPRESSED" in captured.err
    assert str(_COUNT) not in captured.out + captured.err
    assert "line(s)" not in captured.err
    assert str(_COUNT) not in summary.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("rc", "prover_summary", "stderr"),
    [
        pytest.param(
            0,
            _CLEAN_SUMMARY.replace("0 problem(s)", f"{_COUNT} problem(s)"),
            "  FAIL synthetic\n" * 2,
            id="problems-with-a-zero-exit",
        ),
        pytest.param(
            1,
            _CLEAN_SUMMARY.replace("0 problem(s)", f"{_COUNT} problem(s)"),
            "  FAIL synthetic\n" * 2,
            id="fail-lines-cut-short",
        ),
        pytest.param(
            1,
            _CLEAN_SUMMARY.replace("0 problem(s)", "2 problem(s)"),
            "  FAIL synthetic\n" * 2 + "Traceback (most recent call last):\n  boom\n",
            id="traceback-after-the-fail-lines",
        ),
    ],
)
def test_the_crash_reason_carries_no_problem_or_line_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    summary: Path,
    rc: int,
    prover_summary: str,
    stderr: str,
) -> None:
    """The reason for a crash refusal named how many problems the prover reported and how many FAIL
    lines it printed, into the public log and the job summary. It says why in words instead."""
    sc = tmp_path / "scorecard.toml"
    sc.write_text(_ONE_CLAIM, encoding="utf-8")
    _fake_prover(monkeypatch, rc, prover_summary, stderr)
    assert run(_ns(sc, tmp_path)) == EXIT_INSTRUMENT
    captured = capsys.readouterr()
    published = summary.read_text(encoding="utf-8")
    for text in (captured.out + captured.err, published):
        assert str(_COUNT) not in text
        assert "problem(s)" not in text
        assert "FAIL line(s)" not in text
    assert "did not finish the way its summary says" in published


def test_a_non_latin1_line_survives_a_cp1252_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not the locale: a cp1252 runner could neither print nor decode a claim cp1252 cannot encode.

    A real child, standing in for the prover, prints a Cyrillic letter under an inherited cp1252
    stdio setting. Unfixed, the child dies with an encoding error and its line never arrives.
    """
    child = tmp_path / "child.py"
    child.write_text('print("prove-absences: \\u0416 ok")\n', encoding="utf-8")
    monkeypatch.setattr(prove_report, "SCORECARD_PY", child)
    monkeypatch.setenv("PYTHONIOENCODING", "cp1252")
    rc, stdout, _ = prove_report._invoke_prover(tmp_path / "s.toml", tmp_path, sys.executable, 60.0)
    assert rc == 0
    assert chr(0x416) in stdout


def test_a_byte_the_locale_cannot_decode_does_not_crash_the_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The parent's half of the fix, which the test above cannot see on a UTF-8 runner: the child
    writes a byte no UTF-8 decoder accepts. Decoded by the locale on a UTF-8 runner it raised, and
    on cp1252 it read as a different character; decoded as UTF-8 with `replace` it is U+FFFD."""
    child = tmp_path / "child.py"
    child.write_text(
        'import sys\nsys.stdout.buffer.write(b"\\xff ok\\n")\nsys.stdout.flush()\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(prove_report, "SCORECARD_PY", child)
    rc, stdout, _ = prove_report._invoke_prover(tmp_path / "s.toml", tmp_path, sys.executable, 60.0)
    assert rc == 0
    assert stdout == chr(0xFFFD) + " ok" + chr(10)

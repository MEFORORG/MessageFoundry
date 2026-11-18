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


def _ns(scorecard: Path, root: Path, *, detail: bool = False) -> argparse.Namespace:
    return argparse.Namespace(
        scorecard=str(scorecard),
        root=str(root),
        python="python",
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
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str
) -> None:
    sc = tmp_path / "scorecard.toml"
    sc.write_text(text, encoding="utf-8")
    _fake_prover(monkeypatch, 0, _ZERO_SUMMARY)
    assert run(_ns(sc, tmp_path)) == EXIT_INSTRUMENT


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
    ("summary", "stderr"),
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
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, summary: str, stderr: str
) -> None:
    """A crash while printing the FAIL lines also exits 1, which a findings run exits too."""
    sc = tmp_path / "scorecard.toml"
    sc.write_text(_ONE_CLAIM, encoding="utf-8")
    _fake_prover(monkeypatch, 1, summary, stderr)
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

    # The opt-in still works: the suppression is a choice, not a lost stream.
    assert run(_ns(sc, tmp_path, detail=True)) == EXIT_INSTRUMENT
    shown = capsys.readouterr()
    assert _SECRET in shown.err


def test_a_non_latin1_line_survives_a_cp1252_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not the locale: a cp1252 runner could neither print nor decode a non-Latin-1 claim.

    A real child, standing in for the prover, prints a Cyrillic letter under an inherited cp1252
    stdio setting. Unfixed, the child dies with an encoding error and its line never arrives.
    """
    child = tmp_path / "child.py"
    child.write_text('print("prove-absences: \\u0416 ok")\n', encoding="utf-8")
    monkeypatch.setattr(prove_report, "SCORECARD_PY", child)
    monkeypatch.setenv("PYTHONIOENCODING", "cp1252")
    rc, stdout, _ = prove_report._invoke_prover(tmp_path / "s.toml", tmp_path, sys.executable, 60.0)
    assert rc == 0
    assert "Ж" in stdout

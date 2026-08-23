# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The citation-line checker must fire on a drifted citation and stay quiet on everything else (#1263).

Every test is one half of a PAIR. The naive form of this check -- match any backticked word near the
citation -- flags two thirds of the corpus, so a suite of must-fire arms alone would be satisfied by a
detector that is simply wrong about almost everything.

THE ROW REQUIRES A MUTATION TEST THAT PROVES THE DETECTOR CAN STAY QUIET, and that is
``test_a_correct_citation_is_silent_and_the_drifted_twin_is_not``: one fixture, two line numbers, and
only the wrong one reports.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_CHECK = _ROOT / "scripts" / "docs" / "citation_line_check.py"


def _load():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("_citation_line_check", _CHECK)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """A source file whose symbol sits at a known line, well away from line 1."""
    src = tmp_path / "pkg"
    src.mkdir()
    body = ["# filler"] * 40 + ["def _the_real_symbol():", "    return 1"] + ["# tail"] * 10
    (src / "mod.py").write_text("\n".join(body), encoding="utf-8")
    return tmp_path


def _ledger(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "LEDGER.md"
    p.write_text(text, encoding="utf-8")
    return p


def test_a_citation_pointing_at_the_wrong_line_is_reported_with_the_right_one(tree: Path) -> None:
    """MUST FIRE, and the report must be ACTIONABLE rather than a complaint.

    Naming only "this is wrong" would leave the reader to find the symbol themselves, which is the
    work the tool is supposed to save."""
    led = _ledger(tree, "The guard `_the_real_symbol` lives at `pkg/mod.py:5`.\n")
    r = _load().scan([led], tree)
    assert len(r.drifted) == 1, r
    d = r.drifted[0]
    assert d.symbol == "_the_real_symbol"
    assert d.actual_line == 41, "the report must say WHERE the symbol actually is"


def test_a_correct_citation_is_silent_and_the_drifted_twin_is_not(tree: Path) -> None:
    """THE MUTATION THE ROW ASKS FOR: one fixture, two line numbers, only the wrong one reports.

    Without this, a detector that flagged unconditionally would pass the must-fire arm above."""
    right = _ledger(tree, "The guard `_the_real_symbol` lives at `pkg/mod.py:41`.\n")
    assert _load().scan([right], tree).drifted == []
    assert _load().scan([right], tree).agreed == 1

    (tree / "LEDGER2.md").write_text(
        "The guard `_the_real_symbol` lives at `pkg/mod.py:5`.\n", encoding="utf-8"
    )
    assert len(_load().scan([tree / "LEDGER2.md"], tree).drifted) == 1


def test_a_bare_filename_is_REFUSED_and_never_resolved_by_guessing(tree: Path) -> None:
    """MUST NOT FIRE, AND THIS IS THE ARM WITH A REAL INCIDENT BEHIND IT.

    The first version of this tool resolved bare names with ``rglob`` and took the first match. It
    reported 79 past-end-of-file hits against a true figure of 3 -- an artefact of its own resolver,
    which is the exact defect class the item exists to catch. A bare name must be COUNTED, never
    resolved."""
    led = _ledger(tree, "The guard `_the_real_symbol` lives at `mod.py:5`.\n")
    r = _load().scan([led], tree)
    assert r.drifted == []
    assert r.refused_bare == 1
    assert r.checkable == 0, "a refused citation must not enter the checked population either"


def test_a_symbol_absent_from_the_file_is_UNRESOLVED_not_drift(tree: Path) -> None:
    """MUST NOT FIRE AS DRIFT. A renamed symbol, or a word the matcher wrongly took for one, is not a
    line-number claim this tool can adjudicate -- calling it drift would assert a fix it cannot name."""
    led = _ledger(tree, "The guard `_a_symbol_that_is_gone` lives at `pkg/mod.py:5`.\n")
    r = _load().scan([led], tree)
    assert r.drifted == []
    assert r.unresolved == 1


def test_a_citation_naming_no_symbol_is_not_checked_at_all(tree: Path) -> None:
    """MUST NOT FIRE. Most citations name no symbol; there is nothing to compare against, and
    inventing a comparison is how the naive form reached a two-thirds flag rate."""
    led = _ledger(tree, "See `pkg/mod.py:5` for the details.\n")
    r = _load().scan([led], tree)
    assert r.drifted == [] and r.checkable == 0


def test_a_bare_word_is_not_read_as_a_symbol(tree: Path) -> None:
    """MUST NOT FIRE. `client` and `Users` are prose as often as code. Requiring an underscore or a
    call form is what takes the flag rate from two thirds down to something reviewable."""
    led = _ledger(tree, "The `client` at `pkg/mod.py:5` does the thing.\n")
    r = _load().scan([led], tree)
    assert r.checkable == 0, "a bare word must not make a citation checkable"


def test_the_summary_states_its_denominator_even_when_clean(tree: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    """A run that checked 253 of 3,086 citations and one that checked all of them must not print the
    same reassuring line. The covered fraction is part of the result."""
    led = _ledger(tree, "The guard `_the_real_symbol` lives at `pkg/mod.py:41`.\n")
    rc = _load().main([str(led), "--root", str(tree)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "1 path:line citation(s)" in out
    assert "carried a named symbol and were checked" in out
    assert "OK" in out

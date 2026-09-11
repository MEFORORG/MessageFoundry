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


def test_the_symbol_pattern_cannot_backtrack_exponentially() -> None:
    """REGRESSION FOR A CodeQL HIGH-SEVERITY ReDoS, caught on the PR that introduced this script.

    The first pattern was ``[A-Za-z_][A-Za-z0-9_]*(?:_[A-Za-z0-9_]+)+``, where ``[A-Za-z0-9_]*`` and
    the ``(?:_...)+`` group BOTH match an underscore. On ``A_`` followed by many ``0_`` the engine can
    split those repetitions exponentially many ways before failing. MEASURED on the old pattern:
    1.2 ms at 14 repetitions, 18 ms at 18, 291 ms at 22 -- roughly sixteenfold per four, which is the
    signature. The replacement is flat in microseconds across all three.

    The bound below is deliberately loose. This is not a performance assertion: at 60 repetitions the
    old pattern would take longer than the age of this repository, so ANY bound a human would wait for
    separates the two. A tight bound would flake on a loaded runner and teach the next person to
    delete it."""
    import time

    hostile = "`A_" + "0_" * 60 + "!"  # no closing backtick, so the match must fail
    start = time.perf_counter()
    _load()._SYM.search(hostile)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, (
        f"the symbol pattern took {elapsed:.3f}s on a crafted input -- that is the exponential "
        "backtracking CodeQL flagged, not slowness"
    )


def test_the_underscore_requirement_survived_moving_out_of_the_regex() -> None:
    """The narrowing that takes the flag rate from two thirds to reviewable now lives in a linear
    string test rather than in the pattern. It must still hold, or the ReDoS fix would have silently
    widened the matcher -- trading a hang for the noise the narrowing exists to prevent."""
    is_symbol = _load()._is_symbol
    assert is_symbol("_audit_upload_prune")
    assert is_symbol("verify_audit_chain")
    assert is_symbol("scan_text()")
    assert not is_symbol("client"), "a bare prose word must not read as a symbol"
    assert not is_symbol("Users"), "a path fragment must not read as a symbol"


# ------------------------------------------------------------------------------------------------
# The baseline and the advisory flag (BACKLOG #1525). Each arm is one half of a pair: the tool has to
# be able to FAIL for its exit codes to mean anything, and it has to stay quiet on the 204 already
# here or the leg it was wired into becomes wallpaper.
# ------------------------------------------------------------------------------------------------


def _baseline(tmp_path: Path, *keys: str) -> Path:
    p = tmp_path / "baseline.txt"
    p.write_text("# a comment line\n" + "\n".join(keys) + "\n", encoding="utf-8")
    return p


def test_the_drift_key_omits_the_actual_line_and_the_ledger_file(tree: Path) -> None:
    """THE PROPERTY THE WHOLE BASELINE RESTS ON. An actual line moves on every refactor and a ledger
    file changes when an item is archived, so either inside the key would retire entries wholesale
    and re-report the same drift as new -- on a change that touched no citation."""
    led = _ledger(tree, "The guard `_the_real_symbol` lives at `pkg/mod.py:5`.\n")
    drift = _load().scan([led], tree).drifted[0]
    assert drift.key == "pkg/mod.py:5::_the_real_symbol"
    assert "41" not in drift.key, "the actual line must not be in the key"
    assert "LEDGER" not in drift.key, "the ledger file must not be in the key"


def test_a_baselined_drift_does_not_fail_and_an_unbaselined_one_does(tree: Path) -> None:
    """MUST NOT FIRE then MUST FIRE, on one fixture with one variable: the baseline's contents."""
    led = _ledger(tree, "The guard `_the_real_symbol` lives at `pkg/mod.py:5`.\n")
    mod = _load()
    known = _baseline(tree, "pkg/mod.py:5::_the_real_symbol")
    assert mod.main([str(led), "--root", str(tree), "--baseline", str(known)]) == 0
    empty = _baseline(tree)
    assert mod.main([str(led), "--root", str(tree), "--baseline", str(empty)]) == 1


def test_advisory_downgrades_a_finding_and_never_a_malfunction(tree: Path) -> None:
    """THE TWO HALVES OF THE FLAG'S CONTRACT, and the second is the one worth a test.

    A flag that also swallowed the empty-population refusal would install a step that cannot fail for
    the reason it exists -- decoration reading as coverage, which is the class BACKLOG #1525 is about.
    """
    led = _ledger(tree, "The guard `_the_real_symbol` lives at `pkg/mod.py:5`.\n")
    mod = _load()
    assert mod.main([str(led), "--root", str(tree)]) == 1
    assert mod.main([str(led), "--root", str(tree), "--advisory"]) == 0
    missing = tree / "no-such-baseline.txt"
    assert mod.main([str(led), "--root", str(tree), "--baseline", str(missing)]) == 2
    assert mod.main([str(led), "--root", str(tree), "--baseline", str(missing), "--advisory"]) == 2


def test_a_retired_baseline_key_is_reported_and_does_not_fail(tree: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    """A key nobody reports any more is either a fixed citation or a screen that stopped seeing it.
    Those are opposite facts, and only printing the line lets a reader notice the second one."""
    led = _ledger(tree, "Nothing cited here.\n")
    rc = _load().main(
        [str(led), "--root", str(tree), "--baseline", str(_baseline(tree, "pkg/mod.py:5::gone"))]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "NO LONGER REPORTED" in out and "pkg/mod.py:5::gone" in out


def test_the_shipped_baseline_covers_the_shipped_ledgers(capsys) -> None:  # type: ignore[no-untyped-def]
    """THE ARM THAT WOULD HAVE CAUGHT A BASELINE GENERATED AGAINST THE WRONG TREE, and the one that
    keeps the wired leg honest: the nightly job runs exactly this invocation, so a drift added to
    either ledger without a baseline entry is a NEW key there too.

    It asserts a PROPERTY, never a count. Pinning "204" here would redden on every legitimate
    re-anchoring, which is the anti-metric rule in docs/Code_Quality_Standards.md."""
    mod = _load()
    rc = mod.main(["--max-report", "0", "--baseline", str(mod.DEFAULT_BASELINE)])
    out = capsys.readouterr().out
    assert "path:line citation(s)" in out, "positive control: the scan must have read the ledgers"
    assert rc == 0, (
        "the shipped baseline no longer covers the drifts in the tracked ledgers. Read the NEW "
        "section of the output: re-anchor each citation, or add its key to the baseline file."
    )

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0156 — the ASVS scorecard verifier.

Every check here is proved to go RED before it is trusted green. That is not ceremony: this project
has shipped several guards that could not fail, and the defect this tool exists to catch survived
precisely because a total that closed to 345 was read as proof of completeness.

The tool is data-free by design (ADR 0156 §7), so these tests run against fixtures in the public repo
while the vault runs the same code against the real posture data.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.asvs.scorecard import (
    Absence,
    Anchor,
    Cell,
    Findings,
    ScorecardError,
    check_absences,
    check_anchors,
    check_completeness,
    count,
    load_corpus,
    load_scorecard,
    render_current,
    verify,
)

CORPUS = {"1.1.1": 1, "1.1.2": 2, "2.1.1": 3}


def _corpus_file(tmp_path: Path, ids: dict[str, int] | None = None) -> Path:
    p = tmp_path / "corpus.json"
    reqs = [{"req_id": f"V{k}", "L": str(v)} for k, v in (ids or CORPUS).items()]
    p.write_text(json.dumps({"requirements": reqs}), encoding="utf-8")
    return p


def _scorecard_file(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "asvs-scorecard.toml"
    p.write_text(body, encoding="utf-8")
    return p


def _cells(*specs: tuple[str, int, str]) -> list[Cell]:
    return [Cell(id=i, level=lv, verdict=v) for i, lv, v in specs]  # type: ignore[arg-type]


# --- completeness: the check whose absence cost ten cells ---------------------------------------


def test_completeness_passes_when_every_corpus_id_appears_once() -> None:
    cells = _cells(("1.1.1", 1, "pass"), ("1.1.2", 2, "partial"), ("2.1.1", 3, "fail"))
    assert check_completeness(cells, CORPUS) == []


def test_completeness_catches_a_dropped_cell() -> None:
    """The 2026-08-01 defect, in miniature: a count that sums correctly while a cell is missing."""
    cells = _cells(("1.1.1", 1, "pass"), ("1.1.2", 2, "partial"))  # 2.1.1 dropped
    problems = check_completeness(cells, CORPUS)
    assert any("have NO cell" in p and "2.1.1" in p for p in problems)


def test_completeness_catches_a_duplicate_cell() -> None:
    cells = _cells(
        ("1.1.1", 1, "pass"), ("1.1.1", 1, "partial"), ("1.1.2", 2, "pass"), ("2.1.1", 3, "pass")
    )
    assert any("appears 2 times" in p for p in check_completeness(cells, CORPUS))


def test_completeness_catches_an_id_that_is_not_in_the_standard() -> None:
    """11.7.2 was scored against ASVS 4.0.3 V8.3.6, deleted in 5.0. This is that class of error."""
    cells = _cells(
        ("1.1.1", 1, "pass"), ("1.1.2", 2, "pass"), ("2.1.1", 3, "pass"), ("8.3.6", 2, "partial")
    )
    assert any(
        "not ASVS 5.0.0 requirement ids" in p and "8.3.6" in p
        for p in check_completeness(cells, CORPUS)
    )


def test_completeness_catches_a_level_that_disagrees_with_the_corpus() -> None:
    cells = _cells(("1.1.1", 3, "pass"), ("1.1.2", 2, "pass"), ("2.1.1", 3, "pass"))
    assert any("but the corpus says L1" in p for p in check_completeness(cells, CORPUS))


# --- the count is computed, never typed ----------------------------------------------------------


def test_count_is_derived_from_the_cells() -> None:
    cells = _cells(("1.1.1", 1, "pass"), ("1.1.2", 2, "partial"), ("2.1.1", 3, "unverified"))
    n = count(cells)
    assert (n["pass"], n["partial"], n["unverified"]) == (1, 1, 1)
    assert sum(n.values()) == len(cells)


# --- evidence anchors -----------------------------------------------------------------------------


def test_anchor_resolves_when_the_token_is_present(tmp_path: Path) -> None:
    (tmp_path / "messagefoundry").mkdir()
    (tmp_path / "messagefoundry" / "m.py").write_text(
        "a\nb\ntls_cert_file = None\n", encoding="utf-8"
    )
    cells = [
        Cell(
            id="1.1.1",
            level=1,
            verdict="pass",
            evidence=(Anchor("messagefoundry/m.py", 3, "tls_cert_file"),),
        )
    ]
    f = Findings()
    check_anchors(cells, tmp_path, f)
    assert f.ok and f.checked_anchors == 1


def test_anchor_goes_red_when_the_token_is_gone(tmp_path: Path) -> None:
    """The twelve-false-residuals defect: the code moved and the sentence stayed."""
    (tmp_path / "messagefoundry").mkdir()
    (tmp_path / "messagefoundry" / "m.py").write_text("nothing here\n", encoding="utf-8")
    cells = [
        Cell(
            id="1.1.1",
            level=1,
            verdict="pass",
            evidence=(Anchor("messagefoundry/m.py", 1, "tls_cert_file"),),
        )
    ]
    f = Findings()
    check_anchors(cells, tmp_path, f)
    assert not f.ok and "no longer contains" in f.problems[0]


def test_anchor_goes_red_when_the_file_is_gone(tmp_path: Path) -> None:
    cells = [
        Cell(
            id="1.1.1",
            level=1,
            verdict="pass",
            evidence=(Anchor("messagefoundry/gone.py", 1, "x"),),
        )
    ]
    f = Findings()
    check_anchors(cells, tmp_path, f)
    assert not f.ok and "does not exist" in f.problems[0]


# --- absence claims: the class this project is worst at -------------------------------------------


def test_absence_holds_when_pattern_is_quiet_and_control_speaks(tmp_path: Path) -> None:
    (tmp_path / "messagefoundry").mkdir()
    (tmp_path / "messagefoundry" / "m.py").write_text(
        "class ScanRejected: pass\n", encoding="utf-8"
    )
    cells = [
        Cell(
            id="1.1.1", level=1, verdict="fail", absence=(Absence("clamav|clamd", "ScanRejected"),)
        )
    ]
    f = Findings()
    check_absences(cells, tmp_path, f)
    assert f.ok and f.checked_absences == 1


def test_absence_is_rejected_as_BLIND_when_the_positive_control_matches_nothing(
    tmp_path: Path,
) -> None:
    """A grep naming the wrong token returns zero and reads exactly like proof. This is the fence."""
    (tmp_path / "messagefoundry").mkdir()
    (tmp_path / "messagefoundry" / "m.py").write_text("unrelated\n", encoding="utf-8")
    cells = [
        Cell(id="1.1.1", level=1, verdict="fail", absence=(Absence("clamav", "ScanRejected"),))
    ]
    f = Findings()
    check_absences(cells, tmp_path, f)
    assert not f.ok and "BLIND" in f.problems[0]


def test_absence_is_rejected_as_FALSE_when_the_thing_now_exists(tmp_path: Path) -> None:
    """Five residuals of record were absence claims that had silently stopped being true."""
    (tmp_path / "messagefoundry").mkdir()
    (tmp_path / "messagefoundry" / "m.py").write_text(
        "import clamd\nclass ScanRejected: pass\n", encoding="utf-8"
    )
    cells = [Cell(id="1.1.1", level=1, verdict="fail", absence=(Absence("clamd", "ScanRejected"),))]
    f = Findings()
    check_absences(cells, tmp_path, f)
    assert not f.ok and "FALSE" in f.problems[0]


# --- fail closed, never skip ----------------------------------------------------------------------


def test_missing_scorecard_raises_rather_than_skipping(tmp_path: Path) -> None:
    """15.1.3 in one line: the guards skip when the document is absent, so green proves nothing."""
    with pytest.raises(ScorecardError, match="refusing to report a pass on a missing file"):
        load_scorecard(tmp_path / "absent.toml")


def test_missing_corpus_raises(tmp_path: Path) -> None:
    with pytest.raises(ScorecardError, match="cannot check completeness"):
        load_corpus(tmp_path / "absent.json")


def test_unknown_verdict_is_refused(tmp_path: Path) -> None:
    sc = _scorecard_file(
        tmp_path, '[[cell]]\nid = "1.1.1"\nlevel = 1\nverdict = "conditional-pass"\n'
    )
    with pytest.raises(ScorecardError, match="not one of"):
        load_scorecard(sc)


# --- end to end -----------------------------------------------------------------------------------


def test_verify_end_to_end_clean(tmp_path: Path) -> None:
    (tmp_path / "messagefoundry").mkdir()
    (tmp_path / "messagefoundry" / "m.py").write_text("tls_cert_file = None\n", encoding="utf-8")
    sc = _scorecard_file(
        tmp_path,
        """
[[cell]]
id = "1.1.1"
level = 1
verdict = "pass"
last_verified = "2026-08-01"
[[cell.evidence]]
path = "messagefoundry/m.py"
line = 1
expect = "tls_cert_file"

[[cell]]
id = "1.1.2"
level = 2
verdict = "unverified"

[[cell]]
id = "2.1.1"
level = 3
verdict = "partial"
residual = "ships off"
""",
    )
    findings = verify(sc, _corpus_file(tmp_path), tmp_path)
    assert findings.ok, findings.problems


def test_render_separates_verified_pass_from_inherited_pass() -> None:
    cells = [
        Cell(id="1.1.1", level=1, verdict="pass", last_verified="2026-08-01"),
        Cell(id="1.1.2", level=2, verdict="pass"),  # inherited: never re-read
        Cell(id="2.1.1", level=3, verdict="partial", residual="ships off"),
    ]
    out = render_current(cells, anchor_sha="deadbeef")
    assert "**1 were verified against the requirement text**" in out
    assert "**1 are inherited**" in out
    assert "deadbeef" in out
    assert "| 2.1.1 | L3 | **partial** |" in out

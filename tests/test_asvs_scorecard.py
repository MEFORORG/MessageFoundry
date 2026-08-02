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
    check_pinning,
    corpus_digest,
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
            id="1.1.1",
            level=1,
            verdict="fail",
            absence=(Absence("clamav|clamd", "ScanRejected", "import clamd"),),
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
        Cell(
            id="1.1.1",
            level=1,
            verdict="fail",
            absence=(Absence("clamav", "ScanRejected", "import clamav"),),
        )
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
    cells = [
        Cell(
            id="1.1.1",
            level=1,
            verdict="fail",
            absence=(Absence("clamd", "ScanRejected", "import clamd"),),
        )
    ]
    f = Findings()
    check_absences(cells, tmp_path, f)
    assert not f.ok and "FALSE" in f.problems[0]


def test_absence_is_rejected_as_INERT_when_the_pattern_is_prose_not_a_pattern(
    tmp_path: Path,
) -> None:
    """The real defect: an entire chapter was authored as narrations of shell commands.

    The field's type is ``str`` and prose is a valid ``str``, so the shape permitted it. Prose greps
    to nothing, which is indistinguishable from a true absence -- nine claims would have shipped
    proving nothing. Requiring the pattern to fire on a stated reintroduction makes prose unwritable.
    """
    (tmp_path / "messagefoundry").mkdir()
    (tmp_path / "messagefoundry" / "m.py").write_text(
        "class ScanRejected: pass\n", encoding="utf-8"
    )
    prose = "rg -n 'tar.extractall' messagefoundry/ -> exit 1 (zero hits)"
    cells = [
        Cell(
            id="1.1.1",
            level=1,
            verdict="fail",
            absence=(Absence(prose, "ScanRejected", "tar.extractall(dest)"),),
        )
    ]
    f = Findings()
    check_absences(cells, tmp_path, f)
    assert not f.ok and "INERT" in f.problems[0]


def test_absence_INERT_is_decided_before_the_corpus_is_consulted(tmp_path: Path) -> None:
    """A live positive control must not launder a pattern that cannot fire.

    BLIND and INERT are different failures: BLIND means the search could not have seen the thing,
    INERT means the pattern could not have matched it. A prose claim whose control happens to speak
    would otherwise pass every existing check while measuring nothing.
    """
    (tmp_path / "messagefoundry").mkdir()
    (tmp_path / "messagefoundry" / "m.py").write_text(
        "class ScanRejected: pass\n", encoding="utf-8"
    )
    cells = [
        Cell(
            id="1.1.1",
            level=1,
            verdict="fail",
            absence=(Absence("zero hits for pyclamd", "ScanRejected", "import pyclamd"),),
        )
    ]
    f = Findings()
    check_absences(cells, tmp_path, f)
    assert not f.ok and "INERT" in f.problems[0]
    assert not any("BLIND" in p for p in f.problems)


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
    corpus = _corpus_file(tmp_path)
    sc = _scorecard_file(
        tmp_path,
        f"""
[scorecard]
asvs_version = "5.0.0"
corpus_sha256 = "{corpus_digest(corpus)}"

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
    findings = verify(sc, corpus, tmp_path)
    assert findings.ok, findings.problems


def test_render_leads_with_survey_progress_not_a_headline_score() -> None:
    """Phase 0: a count over unexamined cells is an average of guesses, so it is not the headline."""
    cells = [
        Cell(id="1.1.1", level=1, verdict="pass", last_verified="2026-08-01"),
        Cell(id="1.1.2", level=2, verdict="unverified"),
        Cell(
            id="2.1.1", level=3, verdict="partial", residual="ships off", last_verified="2026-08-01"
        ),
    ]
    out = render_current(cells, anchor_sha="deadbeef")
    assert (
        "**2 of 3 requirements have been read against the ASVS text (66.7%).** 1 have not." in out
    )
    assert "There is deliberately no headline score here" in out
    assert "never examined — not a Pass" in out
    assert "deadbeef" in out


def test_render_flags_a_decided_verdict_carrying_no_verified_date_as_inherited() -> None:
    cells = [Cell(id="1.1.1", level=1, verdict="pass")]  # decided, but never dated
    out = render_current(cells, anchor_sha="x")
    assert "carry a decided verdict with no `last_verified` date" in out


# --- the one MUST in ASVS's assessment chapter ----------------------------------------------------


def test_na_without_a_rationale_is_refused(tmp_path: Path) -> None:
    """Recording the reason for non-applicability is the only 'must' ASVS 5.0 states."""
    sc = _scorecard_file(tmp_path, '[[cell]]\nid = "1.1.1"\nlevel = 1\nverdict = "na"\n')
    with pytest.raises(ScorecardError, match="requires a written rationale"):
        load_scorecard(sc)


def test_na_with_a_rationale_is_accepted(tmp_path: Path) -> None:
    sc = _scorecard_file(
        tmp_path,
        '[[cell]]\nid = "1.1.1"\nlevel = 1\nverdict = "na"\nresidual = "no WebRTC surface"\n',
    )
    assert load_scorecard(sc)[0].verdict == "na"


def test_needs_review_is_a_valid_verdict(tmp_path: Path) -> None:
    """Parking a contested cell beats forcing a premature verdict — that is what flip-flops."""
    sc = _scorecard_file(tmp_path, '[[cell]]\nid = "1.1.1"\nlevel = 1\nverdict = "needs-review"\n')
    assert load_scorecard(sc)[0].verdict == "needs-review"


# --- pinning: ids re-point across ASVS versions ----------------------------------------------------


def test_pinning_requires_a_declared_asvs_version(tmp_path: Path) -> None:
    corpus = _corpus_file(tmp_path)
    sc = _scorecard_file(tmp_path, f'[scorecard]\ncorpus_sha256 = "{corpus_digest(corpus)}"\n')
    assert any("asvs_version is missing" in p for p in check_pinning(sc, corpus))


def test_pinning_catches_a_corpus_that_changed_underneath_the_scorecard(tmp_path: Path) -> None:
    """bare 1.2.5 is Architecture in 4.0.3 and Encoding in 5.0.0 — a moved corpus re-points ids."""
    corpus = _corpus_file(tmp_path)
    sc = _scorecard_file(tmp_path, '[scorecard]\nasvs_version = "5.0.0"\ncorpus_sha256 = "0" \n')
    assert any("corpus digest mismatch" in p for p in check_pinning(sc, corpus))


def test_pinning_passes_when_version_and_digest_are_declared(tmp_path: Path) -> None:
    corpus = _corpus_file(tmp_path)
    sc = _scorecard_file(
        tmp_path,
        f'[scorecard]\nasvs_version = "5.0.0"\ncorpus_sha256 = "{corpus_digest(corpus)}"\n',
    )
    assert check_pinning(sc, corpus) == []


def test_pinning_refuses_an_abbreviated_anchor_sha(tmp_path: Path) -> None:
    """actions/checkout resolves a short ref as a BRANCH OR TAG name, so an abbreviated anchor fails
    with "A branch or tag with the name ... could not be found" -- a gate failing for a reason with
    nothing to do with what it measures. Caught in CI twice before it was refused here."""
    corpus = _corpus_file(tmp_path)
    sc = _scorecard_file(
        tmp_path,
        '[scorecard]\nasvs_version = "5.0.0"\nanchor_commit = "8f01cef8"\n'
        f'corpus_sha256 = "{corpus_digest(corpus)}"\n',
    )
    assert any("must be a FULL 40-character SHA" in p for p in check_pinning(sc, corpus))


def test_pinning_accepts_a_full_anchor_sha(tmp_path: Path) -> None:
    corpus = _corpus_file(tmp_path)
    sc = _scorecard_file(
        tmp_path,
        '[scorecard]\nasvs_version = "5.0.0"\n'
        'anchor_commit = "28d186b5d85b10c8e0ce3fc35adc01b7269bcb28"\n'
        f'corpus_sha256 = "{corpus_digest(corpus)}"\n',
    )
    assert check_pinning(sc, corpus) == []


def test_load_refuses_an_absence_claim_with_no_mutation(tmp_path: Path) -> None:
    """Authored, never inferred: a mutation derived from its pattern would pass by construction."""
    sc = _scorecard_file(
        tmp_path,
        '[[cell]]\nid = "1.1.1"\nlevel = 1\nverdict = "fail"\n'
        '  [[cell.absence]]\n  pattern = "clamd"\n'
        '  positive_control = "ScanRejected"\n',
    )
    with pytest.raises(ScorecardError, match="has no `mutation`"):
        load_scorecard(sc)


def test_the_module_does_not_contaminate_the_corpus_it_scans() -> None:
    """scorecard.py lives INSIDE the corpus that absence patterns are searched over.

    A literal code example in this module therefore becomes a real corpus hit. The first draft of
    the `mutation` guidance carried one, and it broke two live absence claims (5.2.5, 5.3.3) the
    moment they were backfilled -- the documentation OF a check contaminated the check.

    This is an INSTANCE lock, not a class lock. It pins the one literal that has actually bitten;
    the general rule -- write examples in escaped-regex form, which cannot self-match -- is stated
    in the Absence docstring and is not mechanically enforceable.
    """
    import scripts.asvs.scorecard as mod

    src = Path(mod.__file__).read_text(encoding="utf-8")
    for literal in (".extractall(", "unpack_archive("):
        assert literal not in src, (
            f"scorecard.py contains the literal {literal!r}. This module is inside the scanned "
            "corpus, so that literal is a corpus hit and will read as FALSE for any absence claim "
            "excluding it. Write the example in escaped-regex form instead."
        )


def test_anchor_is_rejected_as_AMBIGUOUS_when_the_token_is_not_unique(tmp_path: Path) -> None:
    """A token occurring many times resolves from almost anywhere, so it certifies nothing.

    Measured on the real scorecard: 46 of 292 anchors (15%) had a non-unique token, and the worst
    occurred 101 times in one file -- meaning ANY line number in that file landed within the window.
    Those were not anchors at risk of going hollow; they were already hollow, and passing.
    """
    (tmp_path / "messagefoundry").mkdir()
    (tmp_path / "messagefoundry" / "m.py").write_text(
        "await conn.rollback()" + chr(10) + "x = 1" + chr(10) + "await conn.rollback()" + chr(10),
        encoding="utf-8",
    )
    cells = [
        Cell(
            id="1.1.1",
            level=1,
            verdict="pass",
            evidence=(Anchor("messagefoundry/m.py", 1, "await conn.rollback()"),),
        )
    ]
    f = Findings()
    check_anchors(cells, tmp_path, f)
    assert not f.ok and "AMBIGUOUS" in f.problems[0] and "occurs 2 times" in f.problems[0]


def test_anchor_holds_when_the_token_is_unique(tmp_path: Path) -> None:
    """The uniqueness rule must not reject a legitimate anchor -- proved alongside its negative."""
    (tmp_path / "messagefoundry").mkdir()
    (tmp_path / "messagefoundry" / "m.py").write_text(
        "a" + chr(10) + "tls_cert_file = None" + chr(10) + "b" + chr(10), encoding="utf-8"
    )
    cells = [
        Cell(
            id="1.1.1",
            level=1,
            verdict="pass",
            evidence=(Anchor("messagefoundry/m.py", 2, "tls_cert_file"),),
        )
    ]
    f = Findings()
    check_anchors(cells, tmp_path, f)
    assert f.ok and f.checked_anchors == 1

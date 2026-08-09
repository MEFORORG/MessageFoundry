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
    _copy_scratch,
    check_absences,
    check_anchors,
    check_completeness,
    check_pinning,
    corpus_digest,
    count,
    load_corpus,
    load_scorecard,
    main,
    prove_absences,
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
    """Fixture cells for the id / level / count checks.

    Decided verdicts carry a placeholder anchor because `check_completeness` now refuses an
    unevidenced one. These fixtures are about ids and levels, so the anchor keeps them focused rather
    than tripping a rule they do not test; `check_anchors` is never called on them.
    """
    decided = {"pass", "partial", "fail", "na"}
    return [
        Cell(
            id=i,
            level=lv,
            verdict=v,  # type: ignore[arg-type]
            evidence=(Anchor("messagefoundry/m.py", 1, "x"),) if v in decided else (),
            residual="rationale" if v == "na" else "",
        )
        for i, lv, v in specs
    ]


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


def test_a_unique_token_that_drifted_is_advisory_not_fatal(tmp_path: Path) -> None:
    """DRIFT is not INVALIDATION. The token sits far below its recorded line but occurs exactly once.

    Execution only reaches the drift branch PAST the ``occurrences > 1`` guard, so uniqueness is what
    pins the evidence and the line number is navigation. Failing here would assert that the claim sits
    where it sat, which is a different proposition from the one this gate exists to check.
    """
    (tmp_path / "messagefoundry").mkdir()
    body = "\n".join(["filler"] * 300 + ["tls_cert_file = None"] + ["tail"] * 5)
    (tmp_path / "messagefoundry" / "m.py").write_text(body, encoding="utf-8")
    cells = [
        Cell(
            id="1.1.1",
            level=1,
            verdict="pass",
            evidence=(Anchor("messagefoundry/m.py", 5, "tls_cert_file"),),
        )
    ]
    f = Findings()
    check_anchors(cells, tmp_path, f)
    assert f.ok and f.problems == []
    assert len(f.advisories) == 1
    # The advisory carries BOTH numbers and the signed delta, because "it moved" is not actionable and
    # "301 not 5" is. A re-anchor pass reads this line and needs no second lookup.
    assert "recorded at line 5" in f.advisories[0]
    assert "actually at 301" in f.advisories[0]
    assert "+296" in f.advisories[0]


def test_an_ambiguous_token_stays_fatal_even_when_it_drifted(tmp_path: Path) -> None:
    """Where the line IS load-bearing, drift must not soften it.

    With two occurrences a re-anchor to the WRONG one cannot be detected — the defect this module's
    uniqueness rule exists to catch. Advisory treatment is reserved for the case where the token
    itself certifies the evidence.
    """
    (tmp_path / "messagefoundry").mkdir()
    body = "\n".join(["filler"] * 200 + ["dupe_token"] + ["filler"] * 200 + ["dupe_token"])
    (tmp_path / "messagefoundry" / "m.py").write_text(body, encoding="utf-8")
    cells = [
        Cell(
            id="1.1.1",
            level=1,
            verdict="pass",
            evidence=(Anchor("messagefoundry/m.py", 1, "dupe_token"),),
        )
    ]
    f = Findings()
    check_anchors(cells, tmp_path, f)
    assert not f.ok and "AMBIGUOUS" in f.problems[0]
    assert f.advisories == []


def test_a_small_movement_is_advisory_too_not_silent(tmp_path: Path) -> None:
    """CONTRACT CHANGE 2026-08-09, and this test previously asserted the opposite.

    It used to be named ``test_ordinary_small_movement_is_neither_problem_nor_advisory`` and pinned a
    six-line offset as reporting NOTHING, because a 40-line window absorbed it. That silence was the
    defect: measured against a green record, 725 of 1,980 anchors (36.6%) were inside the window and
    therefore invisible, with the worst at 39 against a limit of 40. An advisory that fires only past
    the window merges into an empty list and prevents the next recurrence while surfacing none of the
    accumulation.

    So the rule is now: any nonzero offset is advisory. The window is gone from the decision path.
    """
    (tmp_path / "messagefoundry").mkdir()
    body = "\n".join(["filler"] * 20 + ["tls_cert_file = None"] + ["filler"] * 20)
    (tmp_path / "messagefoundry" / "m.py").write_text(body, encoding="utf-8")
    cells = [
        Cell(
            id="1.1.1",
            level=1,
            verdict="pass",
            evidence=(Anchor("messagefoundry/m.py", 15, "tls_cert_file"),),
        )
    ]
    f = Findings()
    check_anchors(cells, tmp_path, f)
    assert f.problems == []  # still not fatal
    assert len(f.advisories) == 1 and "+6" in f.advisories[0]


def test_an_exactly_located_anchor_reports_nothing(tmp_path: Path) -> None:
    """The control, in the shape the new contract needs.

    Its predecessor guarded against "the window stopped absorbing anything and nothing said so". That
    risk is retired with the window. The live risk now is the mirror image: a resolver that reports
    drift for EVERY anchor — an off-by-one in the line derivation would do it — while the advisory
    tests above still pass, because they only assert that an advisory appears. This asserts the zero.
    """
    (tmp_path / "messagefoundry").mkdir()
    body = "\n".join(["filler"] * 20 + ["tls_cert_file = None"] + ["filler"] * 20)
    (tmp_path / "messagefoundry" / "m.py").write_text(body, encoding="utf-8")
    cells = [
        Cell(
            id="1.1.1",
            level=1,
            verdict="pass",
            # 20 filler lines, so the token is line 21. Recorded exactly.
            evidence=(Anchor("messagefoundry/m.py", 21, "tls_cert_file"),),
        )
    ]
    f = Findings()
    check_anchors(cells, tmp_path, f)
    assert f.problems == [] and f.advisories == []


def test_a_multi_line_expect_token_resolves_and_reports_its_start_line(tmp_path: Path) -> None:
    """42 of the ~1,980 live ``expect`` tokens SPAN A NEWLINE.

    The old check matched against joined text, so nothing ever forbade a multi-line token and 42
    accumulated. Deriving the line by scanning ``splitlines()`` finds none of them and raises on the
    lookup — measured, it bit the parallel session's first measurement script. Counting newlines before
    the character offset handles a multi-line token as naturally as a single-line one, and the line it
    reports is the token's FIRST line, which is what a reader navigating to it wants.
    """
    (tmp_path / "messagefoundry").mkdir()
    body = "\n".join(["filler"] * 10 + ["def f(", "    x: int,", ") -> None:"] + ["tail"] * 5)
    (tmp_path / "messagefoundry" / "m.py").write_text(body, encoding="utf-8")
    cells = [
        Cell(
            id="1.1.1",
            level=1,
            verdict="pass",
            evidence=(Anchor("messagefoundry/m.py", 3, "def f(\n    x: int,"),),
        )
    ]
    f = Findings()
    check_anchors(cells, tmp_path, f)
    assert f.problems == []  # it resolves; a line-scanning implementation would not find it at all
    assert len(f.advisories) == 1
    assert "actually at 11" in f.advisories[0]  # the token's FIRST line, not its last


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
[[cell.evidence]]
path = "messagefoundry/m.py"
line = 1
expect = "tls_cert_file"
""",
    )
    findings = verify(sc, corpus, tmp_path)
    assert findings.ok, findings.problems


def test_render_leads_with_survey_progress_not_a_headline_score() -> None:
    """Phase 0: a count folding in not-yet-re-verified cells is not a measurement, so not the headline.

    The wording is asserted, not just the numbers, and that is deliberate. `unverified` measures
    RE-VERIFICATION DEBT: the earlier lineage graded these cells against the requirement verb as
    paraphrased in our own scorecards, because the ASVS 5.0.0 text was not held until 2026-07-31.
    Rendering them as "never examined" overstates the deficit and misdescribes the lineage, and the
    rendered page is where every downstream reader picks the phrase up.
    """
    cells = [
        Cell(id="1.1.1", level=1, verdict="pass", last_verified="2026-08-01"),
        Cell(id="1.1.2", level=2, verdict="unverified"),
        Cell(
            id="2.1.1", level=3, verdict="partial", residual="ships off", last_verified="2026-08-01"
        ),
    ]
    out = render_current(cells, anchor_sha="deadbeef")
    assert (
        "**2 of 3 requirements have been verified against the pinned ASVS requirement text "
        "(66.7%).** 1 carry a verdict that has not been re-verified against it." in out
    )
    assert "There is deliberately no headline score here" in out
    assert "not re-verified against the requirement text — not a Pass" in out
    assert "never examined" not in out  # the overstatement must not come back
    assert "deadbeef" in out


def test_render_counts_a_needs_review_cell_as_read_not_as_unexamined() -> None:
    """Survey progress counts what was READ; `needs-review` was read and then parked on purpose.

    Latent from the day the renderer was written and invisible until the scorecard acquired its first
    `needs-review` cell: with none present, "decided" and "examined" are the same set, so nothing
    could distinguish them. The symptom was two numbers for one quantity on the page that IS the
    record — a survey line saying N have *not* been read, directly above a table whose `unverified`
    row said N-1.

    The assertion that matters is the LAST one: the two figures the page prints must agree, because a
    reader comparing them is the only thing that ever noticed.
    """
    cells = [
        Cell(id="1.1.1", level=1, verdict="pass", last_verified="2026-08-02"),
        Cell(id="1.1.2", level=2, verdict="unverified"),
        Cell(id="2.1.1", level=3, verdict="needs-review", last_verified="2026-08-02"),
    ]
    out = render_current(cells, anchor_sha="x")

    assert (
        "**2 of 3 requirements have been verified against the pinned ASVS requirement text "
        "(66.7%).** 1 carry a verdict that has not been re-verified against it." in out
    )
    # ...and it stays OUT of the verdict counts, which is why the two sets differ at all.
    assert "| Needs review | 1 |" in out
    assert "| **Unverified** | **1** |" in out


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


def test_a_closed_cell_whose_verdict_still_matches_its_pin_loads(tmp_path: Path) -> None:
    """The green half. Without this, the red tests below could pass by refusing every closed cell."""
    sc = _scorecard_file(
        tmp_path,
        '[[cell]]\nid = "11.7.1"\nlevel = 3\nverdict = "na"\nresidual = "out of declared scope"\n'
        'decision_closed = true\ndecision_closed_verdict = "na"\n'
        'decision_closed_on = "2026-08-02"\ndecision_closed_by = "owner"\n',
    )
    assert load_scorecard(sc)[0].verdict == "na"


def test_rescoring_a_closed_cell_is_refused(tmp_path: Path) -> None:
    """The whole point: a survey cannot quietly re-grade a cell the owner closed.

    This was prose before it was a gate, and prose is not what stops a sweep — the cell this rule
    exists for moved FOUR times in eighteen days, each pass believing it was doing careful work. A
    rationale they could read was never the thing that stopped them.
    """
    sc = _scorecard_file(
        tmp_path,
        '[[cell]]\nid = "11.7.1"\nlevel = 3\nverdict = "fail"\nresidual = "re-graded by a sweep"\n'
        'decision_closed = true\ndecision_closed_verdict = "na"\n',
    )
    with pytest.raises(ScorecardError, match="CLOSED at"):
        load_scorecard(sc)


def test_a_closure_without_a_pinned_verdict_is_refused(tmp_path: Path) -> None:
    """A closure with nothing to compare against is a comment, not a control.

    The failure mode it forecloses: someone writes `decision_closed = true`, believes the cell is
    protected, and the checker has no way to tell a re-score from the original verdict.
    """
    sc = _scorecard_file(
        tmp_path,
        '[[cell]]\nid = "11.7.1"\nlevel = 3\nverdict = "na"\nresidual = "out of declared scope"\n'
        "decision_closed = true\n",
    )
    with pytest.raises(ScorecardError, match="the pin is what makes the closure checkable"):
        load_scorecard(sc)


def test_a_closed_cell_is_rendered_even_when_its_verdict_is_not_an_open_state() -> None:
    """The regression this exists for: a closure visible only while the verdict is open.

    11.7.1 was closed while it was a `fail`, so its stop text surfaced in the open-cells table — then
    the same ruling moved it to `na`, it dropped out of `open_states`, and the rendered record went
    silent about the one cell that had just been ruled on. Closure visibility must not depend on which
    verdict the cell happens to hold.
    """
    out = render_current(
        [
            Cell(
                id="11.7.1",
                level=3,
                verdict="na",
                residual="out of declared scope",
                decision_closed=True,
                decision_closed_on="2026-08-02",
                decision_closed_by="owner",
            )
        ],
        anchor_sha="x",
    )
    assert "Closed by owner decision" in out
    assert "| 11.7.1 | L3 | **na** | 2026-08-02 | owner |" in out


def test_the_closed_section_is_absent_when_no_cell_is_closed() -> None:
    """Negative control on REACH: the heading must not appear for a scorecard with no closures."""
    out = render_current([Cell(id="1.1.1", level=1, verdict="pass")], anchor_sha="x")
    assert "Closed by owner decision" not in out


def test_an_unclosed_cell_is_unaffected_by_the_closure_rule(tmp_path: Path) -> None:
    """Negative control on the rule's REACH: it must not police cells that never opted in."""
    sc = _scorecard_file(
        tmp_path,
        '[[cell]]\nid = "1.1.1"\nlevel = 1\nverdict = "fail"\nresidual = "no control"\n',
    )
    assert load_scorecard(sc)[0].verdict == "fail"


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


def test_completeness_catches_a_decided_verdict_with_no_evidence_at_all() -> None:
    """The gate could only validate evidence that EXISTED, never assert that it must.

    check_anchors iterates the anchors a cell has, so a cell with none is skipped and fails nothing.
    Measured when this landed: 14 of 59 decided cells carried zero anchors and zero absence claims --
    verdicts inherited from the prose lineage that were reached but never anchored. That is precisely
    the guess-wearing-a-verdict conflation this tool exists to prevent.
    """
    cells = [
        Cell(id="1.1.1", level=1, verdict="pass", evidence=(Anchor("m.py", 1, "x"),)),
        Cell(id="1.1.2", level=2, verdict="partial"),  # no anchor, no absence
        Cell(id="2.1.1", level=3, verdict="unverified"),  # unverified needs none
    ]
    problems = check_completeness(cells, CORPUS)
    hit = [p for p in problems if "carry NO anchor" in p]
    assert len(hit) == 1, problems
    assert "1.1.2" in hit[0] and "1.1.1" not in hit[0] and "2.1.1" not in hit[0]


def test_completeness_accepts_a_decided_cell_evidenced_only_by_an_absence_claim() -> None:
    """A `fail` is often proved by absence, not presence -- the rule must not demand a presence anchor."""
    cells = [
        Cell(id="1.1.1", level=1, verdict="pass", evidence=(Anchor("m.py", 1, "x"),)),
        Cell(
            id="1.1.2",
            level=2,
            verdict="fail",
            absence=(Absence("clamd", "ScanRejected", "import clamd"),),
        ),
        Cell(id="2.1.1", level=3, verdict="unverified"),
    ]
    assert not [p for p in check_completeness(cells, CORPUS) if "carry NO anchor" in p]


# --- --prove-absences: a mutation that matches is not a mutation that BITES (#1006) ---------------
#
# check_absences proves a mutation's pattern fires on it; it never applies the mutation. So a
# well-formed reintroduction that would change nothing observable passes every check. prove_absences
# closes that hole by EXECUTING the claim: mutate a scratch copy, run the named observable, require it
# to go red -- and fail closed on any exit code that is not an honest test failure. Every fixture tree
# lives in tmp_path (never in the scanned packages), and the mutation is applied only to a scratch
# copy in a system TemporaryDirectory, so nothing here touches the committed corpus or tmp_path.

_SCANNER = "def scan(p):\n    return 'clean'\n"
_OBS_TEST = "from scanner import scan\n\n\ndef test_clean():\n    assert scan('x') == 'clean'\n"


def _module(tmp_path: Path, name: str, body: str) -> Path:
    """Write a code module fixture into tmp_path (the code the reintroduction lands in)."""
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def _obs_test(tmp_path: Path, name: str, body: str) -> Path:
    """Write an observable pytest module fixture into tmp_path."""
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def _live_claim(mutation: str, mutation_path: str, observable: str) -> Cell:
    # pattern/positive_control are irrelevant to prove_absences (they drive check_absences); supply
    # harmless values so the required fields are present.
    return Cell(
        id="1.1.1",
        level=1,
        verdict="fail",
        absence=(
            Absence(
                pattern="x",
                positive_control="y",
                mutation=mutation,
                mutation_path=mutation_path,
                observable=observable,
            ),
        ),
    )


def test_prove_absences_proves_a_claim_when_the_mutation_reddens_its_observable(
    tmp_path: Path,
) -> None:
    """The positive half: a mutation that shadows `scan` reddens the observable, so the claim BITES.

    Falsified by making `_apply_mutation` a no-op: the observable stays green, the mode reports
    UNPROVEN, and the `.ok`/`proved_absences == 1` assertions go RED. Restored.
    """
    _module(tmp_path, "scanner.py", _SCANNER)
    _obs_test(tmp_path, "test_scanner.py", _OBS_TEST)
    claim = _live_claim(
        'def scan(p): return "infected"', "scanner.py", "test_scanner.py::test_clean"
    )
    findings = prove_absences([claim], tmp_path)
    assert findings.ok, findings.problems
    assert findings.proved_absences == 1


def test_prove_absences_fails_when_the_mutation_reddens_nothing(tmp_path: Path) -> None:
    """The negative control the brief requires: a mutation to a file the observable never imports
    reddens nothing, so the claim is UNPROVEN and the mode FAILS.

    Falsified by making the mode accept a mutated exit==0 as a pass (dropping the exit==1
    requirement): the non-biting claim then reports ok, and `not findings.ok` goes RED -- proving the
    mode can actually fail. Restored.
    """
    _module(tmp_path, "scanner.py", _SCANNER)
    _module(
        tmp_path, "unrelated.py", "VALUE = 1\n"
    )  # exists, but the observable does not import it
    _obs_test(tmp_path, "test_scanner.py", _OBS_TEST)
    claim = _live_claim(
        'def scan(p): return "infected"', "unrelated.py", "test_scanner.py::test_clean"
    )
    findings = prove_absences([claim], tmp_path)
    assert not findings.ok
    assert any("UNPROVEN" in p for p in findings.problems), findings.problems
    assert findings.proved_absences == 0


def test_prove_absences_fails_closed_when_the_observable_is_already_red(tmp_path: Path) -> None:
    """An observable that fails on the pristine tree cannot attribute its red to the mutation.

    Falsified by removing the baseline-green check: the already-red observable stays red under the
    mutation, is miscounted as `proved`, and this test's `not findings.ok` goes RED. Restored.
    """
    _module(tmp_path, "scanner.py", _SCANNER)
    _obs_test(
        tmp_path,
        "test_scanner.py",
        "from scanner import scan\n\n\ndef test_clean():\n    assert scan('x') == 'DIFFERENT'\n",
    )
    claim = _live_claim(
        'def scan(p): return "infected"', "scanner.py", "test_scanner.py::test_clean"
    )
    findings = prove_absences([claim], tmp_path)
    assert not findings.ok
    assert any("PROVE-ERROR" in p and "baseline" in p for p in findings.problems), findings.problems
    assert findings.proved_absences == 0


def test_prove_absences_fails_closed_when_the_mutation_errors_instead_of_failing(
    tmp_path: Path,
) -> None:
    """A mutation that breaks IMPORT of the observable's module errors at collection (pytest exit 4),
    not a test failure (exit 1). A collection/usage error must NEVER count as the control biting --
    otherwise a typo'd node or an import-breaking mutation rebuilds the exact vacuity being fixed.

    Falsified by changing the mutated-run requirement from `exit == 1` to `exit != 0`: the exit-4
    collection error then masquerades as `proved`, and this test's `not findings.ok` goes RED.
    Restored.
    """
    _module(tmp_path, "scanner.py", _SCANNER)
    _obs_test(tmp_path, "test_scanner.py", _OBS_TEST)
    # Appended at module level, this raises when `scanner` is imported -> collection error, not a
    # failing assertion.
    claim = _live_claim(
        'raise RuntimeError("reintroduced")', "scanner.py", "test_scanner.py::test_clean"
    )
    findings = prove_absences([claim], tmp_path)
    assert not findings.ok
    assert any("PROVE-ERROR" in p and "errored" in p for p in findings.problems), findings.problems
    assert findings.proved_absences == 0


def test_prove_absences_static_backstop_flags_a_raise_into_a_swallowing_file(
    tmp_path: Path,
) -> None:
    """With no observable, the static backstop flags a `raise` landing in a file whose try/except
    swallows (bare/Exception, log-only body). A screen, not a proof -- but it fails the mode.

    Falsified by forcing `_landing_swallows` to return False: the swallow is not flagged, `findings.ok`
    becomes True, and this test's `not findings.ok` goes RED. Restored.
    """
    _module(
        tmp_path,
        "caller.py",
        "import logging\n\nlog = logging.getLogger(__name__)\n\n\n"
        "def reconcile():\n    try:\n        work()\n    except Exception:\n"
        "        log.exception('reconcile failed')\n",
    )
    claim = Cell(
        id="13.3.4",
        level=3,
        verdict="fail",
        absence=(
            Absence(
                pattern="x",
                positive_control="y",
                mutation='raise RuntimeError("reintroduced")',
                mutation_path="caller.py",
                observable="",  # no observable -> static backstop
            ),
        ),
    )
    findings = prove_absences([claim], tmp_path)
    assert not findings.ok
    assert any("SUSPECT" in p and "swallow" in p for p in findings.problems), findings.problems
    assert findings.static_screened == 1


def test_prove_absences_static_backstop_passes_a_non_swallowing_file(tmp_path: Path) -> None:
    """REACH control: the static backstop must NOT flag a `raise` into a handler that re-raises --
    proving the heuristic reads the handler body, not merely the presence of a try/except.

    Falsified by forcing `_landing_swallows` to return True: the re-raising file is flagged, and this
    test's `assert findings.ok` goes RED. Restored.
    """
    _module(
        tmp_path,
        "plain.py",
        "def reconcile():\n    try:\n        work()\n    except Exception:\n        raise\n",
    )
    claim = Cell(
        id="13.3.4",
        level=3,
        verdict="fail",
        absence=(
            Absence(
                pattern="x",
                positive_control="y",
                mutation='raise RuntimeError("reintroduced")',
                mutation_path="plain.py",
                observable="",
            ),
        ),
    )
    findings = prove_absences([claim], tmp_path)
    assert findings.ok, findings.problems
    assert findings.static_screened == 1
    assert not any("SUSPECT" in p for p in findings.problems)


def test_prove_absences_leaves_the_root_tree_untouched(tmp_path: Path) -> None:
    """The mode must run OUT of the tracked tree: mutation lands only on the scratch copy.

    Falsified by pointing `_apply_mutation` at `root` instead of the scratch copy: root's scanner.py
    changes, `after == before` goes RED (and the claim also drops to UNPROVEN). Restored.
    """
    _module(tmp_path, "scanner.py", _SCANNER)
    _obs_test(tmp_path, "test_scanner.py", _OBS_TEST)
    before = {p: p.read_bytes() for p in sorted(tmp_path.rglob("*")) if p.is_file()}
    claim = _live_claim(
        'def scan(p): return "infected"', "scanner.py", "test_scanner.py::test_clean"
    )
    findings = prove_absences([claim], tmp_path)
    assert findings.proved_absences == 1, findings.problems
    after = {p: p.read_bytes() for p in sorted(tmp_path.rglob("*")) if p.is_file()}
    assert after == before


def test_load_reads_optional_mutation_path_and_observable_and_omitting_them_still_loads(
    tmp_path: Path,
) -> None:
    """Round-trip: the two new fields load when present, and OMITTING them still loads (vault-safety --
    the ~81 existing absence claims carry neither and must stay loadable).

    Falsified by dropping the `.get` wiring in load_scorecard (hardcoding ``mutation_path=""``): half
    (a) then reads "" and its assertion goes RED, while half (b) stays green -- proving the round-trip
    is actually asserted. Restored.
    """
    with_fields = tmp_path / "with.toml"
    with_fields.write_text(
        '[[cell]]\nid = "1.1.1"\nlevel = 1\nverdict = "fail"\n'
        "  [[cell.absence]]\n"
        '  pattern = "clamd"\n'
        '  positive_control = "ScanRejected"\n'
        '  mutation = "import clamd"\n'
        '  mutation_path = "messagefoundry/scan.py"\n'
        '  observable = "tests/test_scan.py::test_rejects"\n',
        encoding="utf-8",
    )
    a = load_scorecard(with_fields)[0].absence[0]
    assert a.mutation_path == "messagefoundry/scan.py"
    assert a.observable == "tests/test_scan.py::test_rejects"

    without_fields = tmp_path / "without.toml"
    without_fields.write_text(
        '[[cell]]\nid = "1.1.2"\nlevel = 2\nverdict = "fail"\n'
        "  [[cell.absence]]\n"
        '  pattern = "clamd"\n'
        '  positive_control = "ScanRejected"\n'
        '  mutation = "import clamd"\n',
        encoding="utf-8",
    )
    b = load_scorecard(without_fields)[0].absence[0]
    assert b.mutation_path == "" and b.observable == ""


def test_prove_absences_refuses_a_mutation_path_that_escapes_the_scratch_tree(
    tmp_path: Path,
) -> None:
    """`mutation_path` is authored data. An absolute path or a `..` escape would let the mutation land
    OUTSIDE the scratch copy (defeating the 'never touches root' guarantee), so the mode refuses it as
    a PROVE-ERROR before applying anything -- it never counts as a proof.

    Falsified by making `_is_within_tree` return True unconditionally: the `..` path is no longer
    refused, the run falls through to the is_file probe with a different message, and this test's
    `any("repo-relative" in p ...)` assertion goes RED. Restored.
    """
    _module(tmp_path, "scanner.py", _SCANNER)
    _obs_test(tmp_path, "test_scanner.py", _OBS_TEST)
    claim = _live_claim(
        'def scan(p): return "infected"',
        "../escape.py",  # a `..` that would climb out of the scratch copy
        "test_scanner.py::test_clean",
    )
    findings = prove_absences([claim], tmp_path)
    assert not findings.ok
    assert any("PROVE-ERROR" in p and "repo-relative" in p for p in findings.problems), (
        findings.problems
    )
    assert findings.proved_absences == 0


def test_copy_scratch_excludes_secrets_store_and_vault_posture(tmp_path: Path) -> None:
    """The scratch copy the vault mutation-run reads must never carry secrets, the local store, or the
    vault posture tree -- CLAUDE.md §9 forbids this module reading them at all. `_copy_scratch` skips
    `.env*`, `*.db`(+WAL sidecars), and `docs/security`, while ordinary sources are still copied.

    Falsified by reverting `_scratch_ignore` to the bare VCS/venv/cache patterns: the `.env`, `*.db`
    and `docs/security` fixtures are then copied into the scratch dir and every `not (dest/...).exists()`
    assertion goes RED, while the `keep.py` assertion stays green. Restored.
    """
    (tmp_path / ".env").write_text("EXAMPLE_PLACEHOLDER=not-a-secret\n", encoding="utf-8")
    (tmp_path / "local.db").write_text("binary-store\n", encoding="utf-8")
    (tmp_path / "local.db-wal").write_text("wal\n", encoding="utf-8")
    (tmp_path / "docs" / "security").mkdir(parents=True)
    (tmp_path / "docs" / "security" / "posture.toml").write_text("real = true\n", encoding="utf-8")
    (tmp_path / "docs" / "PUBLIC.md").write_text("# public\n", encoding="utf-8")
    (tmp_path / "keep.py").write_text("KEEP = 1\n", encoding="utf-8")

    dest = tmp_path.parent / "scratch_out"
    _copy_scratch(tmp_path, dest)

    assert not (dest / ".env").exists()
    assert not (dest / "local.db").exists()
    assert not (dest / "local.db-wal").exists()
    assert not (dest / "docs" / "security").exists()
    # ordinary sources and other docs survive the copy
    assert (dest / "keep.py").read_text(encoding="utf-8") == "KEEP = 1\n"
    assert (dest / "docs" / "PUBLIC.md").exists()


def _biting_scorecard(sc: Path, mutation_path: str) -> None:
    """Write a one-claim scorecard whose live absence claim points at `mutation_path`."""
    sc.write_text(
        '[[cell]]\nid = "1.1.1"\nlevel = 1\nverdict = "fail"\n'
        "  [[cell.absence]]\n"
        '  pattern = "x"\n'
        '  positive_control = "y"\n'
        "  mutation = 'def scan(p): return \"infected\"'\n"
        f'  mutation_path = "{mutation_path}"\n'
        '  observable = "test_scanner.py::test_clean"\n',
        encoding="utf-8",
    )


def test_main_prove_absences_returns_0_on_a_biting_claim(tmp_path: Path) -> None:
    """The CLI contract CI depends on: `--prove-absences` exits 0 when every claim's mutation reddens
    its observable. Exercises `main` -> `_run_prove_absences` end to end, not just `prove_absences`.

    Falsified by changing `_run_prove_absences`'s `return 0 if findings.ok else 1` to `return 1`: this
    test's `rc == 0` goes RED while the non-biting test below stays green. Restored.
    """
    tree = tmp_path / "tree"
    tree.mkdir()
    _module(tree, "scanner.py", _SCANNER)
    _obs_test(tree, "test_scanner.py", _OBS_TEST)
    sc = tmp_path / "sc.toml"
    _biting_scorecard(sc, "scanner.py")
    rc = main(["--scorecard", str(sc), "--root", str(tree), "--prove-absences"])
    assert rc == 0


def test_main_prove_absences_returns_1_on_a_nonbiting_claim(tmp_path: Path) -> None:
    """The other half of the contract: `--prove-absences` exits 1 when a claim is UNPROVEN (its
    mutation reddens nothing). Proves the CLI's non-zero failure path, not only the library's.

    Falsified by changing `_run_prove_absences`'s `return 0 if findings.ok else 1` to `return 0`:
    this test's `rc == 1` goes RED while the biting test above stays green. Restored.
    """
    tree = tmp_path / "tree"
    tree.mkdir()
    _module(tree, "scanner.py", _SCANNER)
    _module(tree, "unrelated.py", "VALUE = 1\n")  # present, but the observable never imports it
    _obs_test(tree, "test_scanner.py", _OBS_TEST)
    sc = tmp_path / "sc.toml"
    _biting_scorecard(sc, "unrelated.py")
    rc = main(["--scorecard", str(sc), "--root", str(tree), "--prove-absences"])
    assert rc == 1


def test_main_verify_without_corpus_returns_exit_2(tmp_path: Path) -> None:
    """Verify mode needs the corpus; omitting `--corpus` (without `--prove-absences`) must exit 2 --
    could-not-measure, never confused with a clean 0. Proves the argparse-independent guard in `main`.

    Falsified by deleting the `if args.corpus is None: ... return 2` branch in `main`: it then falls
    through to `verify(...)` with `corpus=None`, raising instead of returning 2, and this test's
    `rc == 2` goes RED. Restored.
    """
    sc = tmp_path / "sc.toml"
    sc.write_text(
        '[[cell]]\nid = "1.1.1"\nlevel = 1\nverdict = "fail"\n'
        "  [[cell.absence]]\n"
        '  pattern = "x"\n'
        '  positive_control = "y"\n'
        '  mutation = "import x"\n',
        encoding="utf-8",
    )
    rc = main(["--scorecard", str(sc), "--root", str(tmp_path)])
    assert rc == 2

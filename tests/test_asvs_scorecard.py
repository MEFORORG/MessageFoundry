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
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, get_args

import pytest

from scripts.asvs.scorecard import (
    _DESCEND_ONLY,
    _TRANSPARENT,
    VERDICT_ORDER,
    VERDICTS,
    Absence,
    Anchor,
    Cell,
    Findings,
    ScorecardError,
    Verdict,
    _copy_scratch,
    _humanise_age,
    anchor_form,
    check_absences,
    check_anchors,
    check_completeness,
    check_pinning,
    corpus_digest,
    count,
    derive_sym_ctx,
    form_summary,
    load_corpus,
    load_scorecard,
    main,
    malformed_sym_ctx,
    prove_absences,
    provenance_lines,
    render_current,
    repo_stamp,
    status_lines,
    verdict_breakdown,
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


# --- the printed distribution reconciles against its own total (BACKLOG #1012) --------------------
#
# The gate's summary line enumerated FIVE verdict states and stated a total that counted SIX states'
# worth of cells: 344 components against a stated 345, with `needs-review` omitted. Nothing compared
# the two numbers, so the line could not be reconciled against itself, and it is the line people quote.
# These pin the three properties that make the class unrepeatable: the enumeration is derived from the
# type, every state is printed, and the components are checked against the population before printing.


def test_the_verdict_enumeration_is_the_type_and_not_a_second_list() -> None:
    """`VERDICT_ORDER` is what every breakdown walks. If it were retyped beside `Verdict`, a state
    added to one and not the other is exactly #1012 again -- so it is derived, and this says so.

    Falsified by replacing the `get_args(Verdict)` derivation with a hand-written tuple missing
    `needs-review`: this goes RED on the set comparison. Restored.
    """
    assert set(VERDICT_ORDER) == set(get_args(Verdict))
    assert set(VERDICT_ORDER) == set(VERDICTS)
    assert len(VERDICT_ORDER) == len(set(VERDICT_ORDER))  # order, so no state can appear twice
    assert "needs-review" in VERDICT_ORDER  # the state that vanished


def test_the_breakdown_carries_every_state_and_closes_to_the_cell_count() -> None:
    """One cell per state, so a dropped state is a dropped 1 -- and the parts must sum to 6."""
    cells = _cells(*((f"1.1.{i}", 1, v) for i, v in enumerate(VERDICT_ORDER, start=1)))
    parts, total = verdict_breakdown(cells)
    assert [v for v, _ in parts] == list(VERDICT_ORDER)
    assert total == len(cells) == 6
    assert sum(c for _, c in parts) == total


def test_a_state_with_no_landing_site_REFUSES_rather_than_printing_344_of_345() -> None:
    """The live positive control: a cell carrying a verdict outside the enumeration.

    This is #1012's shape reproduced in the data instead of in the format string -- a state present in
    the population with nowhere to land -- and the components then sum SHORT of the total. Printing it
    anyway is what the gate did. `load_scorecard` refuses such a verdict on the way in, so this
    constructs the Cell directly: the point is that the fence behind the fence also holds.
    """
    cells = [
        *_cells(("1.1.1", 1, "pass")),
        Cell(id="1.1.2", level=1, verdict="mostly-fine"),  # type: ignore[arg-type]
    ]
    with pytest.raises(ScorecardError) as exc:
        verdict_breakdown(cells)
    assert "does not reconcile" in str(exc.value)
    assert "mostly-fine" in str(exc.value)  # names the state, not just the arithmetic
    assert "1" in str(exc.value) and "2" in str(exc.value)  # the components and the total


def test_the_gate_summary_line_prints_all_six_states_and_states_a_total_they_sum_to(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """End-to-end through `main`, because the defect was on the rendered line and not in a helper.

    Falsified by restoring the old hand-written five-state f-string in `main`: the `needs-review`
    assertion goes RED and the reconciliation below it goes RED with a real arithmetic gap. Restored.
    """
    corpus = _corpus_file(tmp_path, {"1.1.1": 1, "1.1.2": 1, "2.1.1": 1})
    (tmp_path / "messagefoundry").mkdir()
    (tmp_path / "messagefoundry" / "m.py").write_text("SIZE = 64\n", encoding="utf-8")
    sc = _scorecard_file(
        tmp_path,
        f'[scorecard]\nasvs_version = "5.0.0"\ncorpus_sha256 = "{corpus_digest(corpus)}"\n'
        '[[cell]]\nid = "1.1.1"\nlevel = 1\nverdict = "pass"\n'
        "  [[cell.evidence]]\n"
        '  path = "messagefoundry/m.py"\n  line = 1\n  expect = "SIZE = 64"\n'
        '[[cell]]\nid = "1.1.2"\nlevel = 1\nverdict = "needs-review"\n'
        '[[cell]]\nid = "2.1.1"\nlevel = 1\nverdict = "unverified"\n',
    )
    rc = main(["--scorecard", str(sc), "--corpus", str(corpus), "--root", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    # Every state named, including the one that used to have no landing site.
    for verdict in VERDICT_ORDER:
        assert f" {verdict}" in out, f"{verdict} is missing from the summary line"
    assert "1 needs-review" in out
    # And the components reconcile against the stated total, read back off the printed line.
    line = next(ln for ln in out.splitlines() if ln.startswith("scanned "))
    stated = int(re.match(r"scanned (\d+) cells", line).group(1))  # type: ignore[union-attr]
    components = [int(m) for m in re.findall(r"(\d+) [a-z-]+", line.split("(", 1)[1].split(")")[0])]
    assert len(components) == len(VERDICT_ORDER)
    assert sum(components) == stated == 3


def test_status_and_the_gate_summary_report_the_same_distribution() -> None:
    """Two renderings of one population must not disagree, which is how the defect stayed invisible:
    `--status` printed six states and the gate line five, in the same module, over the same cells.

    **What this does NOT pin, said so it is not read as more:** it builds its population FROM
    `VERDICT_ORDER`, so a state dropped from that tuple is dropped from both sides and this stays
    green. Measured -- it is the one arm of these five that survives that mutation. The completeness
    of the enumeration is pinned by `test_the_verdict_enumeration_is_the_type_and_not_a_second_list`;
    this pins only that the two renderings agree.
    """
    cells = _cells(*((f"1.1.{i}", 1, v) for i, v in enumerate(VERDICT_ORDER, start=1)))
    parts, total = verdict_breakdown(cells)
    status = "\n".join(status_lines(cells))
    assert f"cells {total}: " in status
    for verdict, n in parts:
        assert f"{n} {verdict}" in status


def test_the_rendered_table_rows_sum_to_the_Total_row_it_prints(tmp_path: Path) -> None:
    """The same class, one file over: six hand-written rows above a hand-written Total. Parsed back
    out of the rendered markdown rather than asserted of the inputs, so the check reads what a human
    reads.

    Falsified by deleting the `needs-review` entry from `_VERDICT_ROW`: the render refuses outright
    (ScorecardError) instead of quietly emitting five rows over a six-state Total. Restored.
    """
    cells = _cells(*((f"1.1.{i}", 1, v) for i, v in enumerate(VERDICT_ORDER, start=1)))
    page = render_current(cells, anchor_sha="deadbeef")
    rows = [ln for ln in page.splitlines() if ln.startswith("| ") and "---" not in ln]
    counts = {}
    total = None
    for row in rows:
        cols = [c.strip().strip("*") for c in row.strip("|").split("|")]
        if len(cols) != 3 or not cols[1].isdigit():
            continue
        if cols[0] == "Total":
            total = int(cols[1])
        else:
            counts[cols[0]] = int(cols[1])
    assert total == len(cells)
    assert len(counts) == len(VERDICT_ORDER), f"rendered state rows: {sorted(counts)}"
    assert sum(counts.values()) == total


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


def test_a_gone_token_is_not_offered_a_replacement_anchor(tmp_path: Path) -> None:
    """The refusal is ENFORCED, not a convention, because the convention is what decays.

    A GONE token has four possible causes and only two are re-anchors: it moved, it was renamed, THE
    GAP IT CERTIFIED WAS CLOSED, or its control was removed. A tool that helpfully suggests the
    nearest similar line collapses all four into the first, and the (c) case is the dangerous one --
    re-anchoring to the code that CLOSED a gap, while the residual still narrates the gap, yields an
    anchor that resolves forever while asserting the opposite of the truth.

    Measured instance: 3.7.5 at engine `71dfc2ce`. The file below reproduces its shape -- the old
    token is gone and a plausible near-match sits right there, which is exactly when a fuzzy
    suggestion would be most tempting and most wrong.
    """
    (tmp_path / "messagefoundry").mkdir()
    (tmp_path / "messagefoundry" / "m.py").write_text(
        'testpaths = ["tests", "packaging/messagefoundry-webconsole/tests"]\n', encoding="utf-8"
    )
    cells = [
        Cell(
            id="3.7.5",
            level=3,
            verdict="partial",
            evidence=(Anchor("messagefoundry/m.py", 1, 'testpaths = ["tests"]'),),
        )
    ]
    f = Findings()
    check_anchors(cells, tmp_path, f)
    assert not f.ok
    msg = f.problems[0]
    # It must NOT name a line to move to, nor tell the reader to re-anchor.
    assert "did you mean" not in msg.lower()
    assert "re-anchor to" not in msg.lower()
    assert "Do not re-anchor by default" in msg
    # And it must put the retire-vs-rescore fork in front of the reader.
    assert "CLOSED" in msg and "re-score" in msg


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


# --- derived anchor `form`: what does the evidence actually resolve INTO? --------------------------
#
# Measured 2026-08-09, vault `origin/main` (1a59e4a1) scorecard against engine tree `c383eeab`:
# 1,980 anchors, 1,979 located, split 1,479 code / 233 doc / 267 foreign / 0 undetermined. So 500 of
# the located 1,979 (25.3%) resolve into prose or a non-Python file that no structural or executable
# check reaches, and the record presented all 1,980 as code evidence.
#
# Every test below names the classification rule it pins, because the rule is where the judgement is.
# The load-bearing one is `..._that_is_not_a_docstring_stays_code`: it is the case a token mask gets
# wrong, and it is the reason this classifies by POSITION rather than by what the text looks like.

_CSP_MODULE = '''\
"""Security headers for the web console."""

# The report path is public; the nonce is not.
CSP_REPORT_PATH = "/ui/csp-report"

_POLICY = (
    "default-src 'self'; script-src 'nonce-{nonce}' 'strict-dynamic'; "
    "base-uri 'none'; form-action 'self'; object-src 'none'; "
    "img-src 'self' data:; connect-src 'self'; font-src 'self'"
)


def header(nonce: str) -> str:
    """Return the Content-Security-Policy header value."""
    return _POLICY.format(nonce=nonce)
'''

_DDL_MODULE = '''\
"""SQL Server store."""


def _schema() -> str:
    return """
        CREATE TABLE sessions (
            token_hash NVARCHAR(64) NOT NULL PRIMARY KEY,
            user_id NVARCHAR(255) NOT NULL,
            revoked_at DATETIME2 NULL
        )
    """
'''


def test_form_classifies_module_class_and_function_docstrings_as_doc() -> None:
    src = '"""Module prose here."""\n\n\nclass C:\n    """Class prose here."""\n\n    def m(self):\n        """Method prose here."""\n        return 1\n'
    for token in ("Module prose", "Class prose", "Method prose"):
        assert anchor_form("messagefoundry/m.py", src, src.index(token)) == "doc", token


def test_form_classifies_a_hash_comment_as_doc() -> None:
    src = "# why this constant is 64 and not 32\nSIZE = 64\n"
    assert anchor_form("messagefoundry/m.py", src, src.index("why this constant")) == "doc"
    assert anchor_form("messagefoundry/m.py", src, src.index("SIZE = 64")) == "code"


def test_form_keeps_a_prose_shaped_string_that_is_not_a_docstring_as_code() -> None:
    """THE case that decides the classification rule, and the reason a token mask was rejected.

    A Content-Security-Policy fragment and a block of SQL DDL are long, quoted, space-separated and
    operator-free, so a "does this look like code?" mask reads them as English -- while they are the
    literal subject of the control the cell cites. Measured, a token mask misfiled every CSP fragment
    in `messagefoundry_webconsole/_security.py` and the whole SQL Server and Postgres DDL as prose.

    Position cannot make that mistake: neither string is the first statement of any scope, so neither
    is a docstring, whatever it reads like. Falsified by relaxing `_prose_spans` to treat ANY string
    token as a docstring (drop the `doc_rows` membership test): all four assertions here go RED while
    the docstring tests above stay green. Restored.
    """
    for token in (
        "script-src 'nonce-{nonce}' 'strict-dynamic'",
        "base-uri 'none'; form-action 'self'; object-src 'none'; ",
    ):
        assert (
            anchor_form(
                "messagefoundry_webconsole/_security.py", _CSP_MODULE, _CSP_MODULE.index(token)
            )
            == "code"
        ), token
    for token in ("token_hash NVARCHAR(64) NOT NULL PRIMARY KEY", "CREATE TABLE sessions"):
        assert (
            anchor_form("messagefoundry/store/sqlserver.py", _DDL_MODULE, _DDL_MODULE.index(token))
            == "code"
        ), token


def test_form_does_not_mistake_a_hash_inside_a_string_for_a_comment() -> None:
    """`#` is a comment character to a `#`-scan and an ordinary byte to `tokenize`.

    A CSP fragment or a URL fragment carries `#` routinely. Comments therefore come from `tokenize`,
    which knows it is inside a string literal, rather than from a scan of the line.
    """
    src = 'URL = "https://example.test/page#anchor-name"\nVALUE = 1\n'
    assert anchor_form("messagefoundry/m.py", src, src.index("anchor-name")) == "code"


def test_form_classifies_a_non_python_file_as_foreign_without_parsing_it() -> None:
    """198 `.md`, 17 `.ts`, 16 `.js` and 13 `.yml` anchors are in the live record. No `ast` reaches
    any of them, ever, so the honest label is `foreign` rather than a Python verdict about them."""
    md = "# SECURITY.md\n\nThe engine binds 127.0.0.1 by default.\n"
    assert anchor_form("docs/SECURITY.md", md, md.index("binds 127")) == "foreign"
    # It is the SUFFIX that decides, not the content: this would parse as Python and must not be tried.
    assert anchor_form("scripts/x.yml", "VALUE = 1\n", 0) == "foreign"


def test_form_is_undetermined_when_the_python_will_not_parse_never_code() -> None:
    """The dangerous default is `code`, because it inflates the exact number this split deflates.

    Falsified by changing `_form_from_spans` to `return "code"` when `spans is None`: this test goes
    RED and the "no prose" negative control below stays green. Restored.
    """
    broken = "def f(\n"  # unterminated: neither ast nor tokenize can complete it
    assert anchor_form("messagefoundry/m.py", broken, 0) is None


def test_form_is_decided_by_the_tokens_start_not_by_any_overlap() -> None:
    """An `expect` that begins in code and runs into a trailing comment is CODE.

    Measured on the live record: a START rule and an OVERLAP rule disagree on 57 of 1,712 Python
    anchors, and every one of those is a code statement whose recorded token happens to run past the
    end of the statement. Falsified by dropping the LOWER bound from `_form_from_spans` --
    `any(start < hi ...)`, the left-overlap rule, and a plausible slip -- which classifies this
    fixture as `doc`: this test goes RED. Restored.
    """
    src = "VALUE = 64  # tuned against the 2026-08 bench\n"
    token = "VALUE = 64  # tuned"
    assert src.count(token) == 1  # the token really does straddle the boundary
    assert anchor_form("messagefoundry/m.py", src, src.index(token)) == "code"


def test_form_negative_control_a_file_with_no_prose_yields_no_doc(tmp_path: Path) -> None:
    """The count's negative control: a form that CANNOT occur must come back zero.

    A classifier that returned `doc` on some fixed fraction, or that leaked spans between files
    through the per-run cache, would show up here and nowhere else -- the positive tests above only
    assert that `doc` appears.
    """
    (tmp_path / "messagefoundry").mkdir()
    (tmp_path / "messagefoundry" / "m.py").write_text(
        "SIZE = 64\nNAME = 'x'\n\n\ndef f():\n    return SIZE\n", encoding="utf-8"
    )
    cells = [
        Cell(
            id="1.1.1",
            level=1,
            verdict="pass",
            evidence=(
                Anchor("messagefoundry/m.py", 1, "SIZE = 64"),
                Anchor("messagefoundry/m.py", 2, "NAME = 'x'"),
                Anchor("messagefoundry/m.py", 5, "def f():"),
            ),
        )
    ]
    f = Findings()
    check_anchors(cells, tmp_path, f)
    assert f.anchor_forms["code"] == 3
    assert f.anchor_forms["doc"] == 0
    assert f.anchor_forms["foreign"] == 0
    assert f.anchor_forms["undetermined"] == 0


def test_check_anchors_counts_a_form_for_every_anchor_that_located(tmp_path: Path) -> None:
    """The split's parts must sum to the located population, or the printed denominator is a fiction."""
    (tmp_path / "messagefoundry").mkdir()
    (tmp_path / "docs").mkdir()
    (tmp_path / "messagefoundry" / "m.py").write_text(
        '"""Prose about the gate."""\n\nSIZE = 64\n', encoding="utf-8"
    )
    (tmp_path / "docs" / "SECURITY.md").write_text(
        "The gate is deny-by-default.\n", encoding="utf-8"
    )
    cells = [
        Cell(
            id="1.1.1",
            level=1,
            verdict="pass",
            evidence=(
                Anchor("messagefoundry/m.py", 3, "SIZE = 64"),
                Anchor("messagefoundry/m.py", 1, "Prose about the gate"),
                Anchor("docs/SECURITY.md", 1, "deny-by-default"),
            ),
        )
    ]
    f = Findings()
    check_anchors(cells, tmp_path, f)
    assert f.ok
    assert dict(f.anchor_forms) == {"code": 1, "doc": 1, "foreign": 1}
    assert sum(f.anchor_forms.values()) == f.checked_anchors


def test_an_anchor_that_did_not_locate_gets_no_form_at_all(tmp_path: Path) -> None:
    """GONE and AMBIGUOUS anchors have no landing site, so classifying them would be an invented
    number inside the one figure whose whole purpose is to stop the record overstating itself.

    Falsified by moving the `anchor_forms` increment above the occurrence guards in `check_anchors`:
    the sum then reaches 3 and both assertions here go RED. Restored.
    """
    (tmp_path / "messagefoundry").mkdir()
    (tmp_path / "messagefoundry" / "m.py").write_text(
        "SIZE = 64\ndupe\nfiller\ndupe\n", encoding="utf-8"
    )
    cells = [
        Cell(
            id="1.1.1",
            level=1,
            verdict="pass",
            evidence=(
                Anchor("messagefoundry/m.py", 1, "SIZE = 64"),
                Anchor("messagefoundry/m.py", 2, "dupe"),  # AMBIGUOUS
                Anchor("messagefoundry/m.py", 3, "vanished_token"),  # GONE
            ),
        )
    ]
    f = Findings()
    check_anchors(cells, tmp_path, f)
    assert len(f.problems) == 2
    assert sum(f.anchor_forms.values()) == 1
    assert f.checked_anchors == 3  # scanned three; classified one. Both numbers get printed.


def test_form_doc_is_a_label_and_never_a_demotion(tmp_path: Path) -> None:
    """17 cells rest genuinely on documentation, which is legitimate ground for a documentation
    requirement. A cell evidenced ONLY by prose must therefore stay green and stay complete.

    This is the fence against the obvious next move -- wiring `form` into the gate. If someone adds
    `if form != "code": problems.append(...)`, or teaches `check_completeness` that a doc-only cell
    is unevidenced, this test goes RED and says why.
    """
    (tmp_path / "messagefoundry").mkdir()
    (tmp_path / "docs").mkdir()
    (tmp_path / "messagefoundry" / "m.py").write_text(
        '"""Session records are never written to the general log."""\n', encoding="utf-8"
    )
    (tmp_path / "docs" / "PHI.md").write_text(
        "Full payloads go only to the store.\n", encoding="utf-8"
    )
    cells = [
        Cell(
            id="1.1.1",
            level=1,
            verdict="pass",
            evidence=(
                Anchor("messagefoundry/m.py", 1, "never written to the general log"),
                Anchor("docs/PHI.md", 1, "Full payloads go only to the store"),
            ),
        )
    ]
    f = Findings()
    check_anchors(cells, tmp_path, f)
    assert f.ok and f.problems == [] and f.advisories == []
    assert f.anchor_forms["code"] == 0 and f.anchor_forms["doc"] + f.anchor_forms["foreign"] == 2
    # ... and the completeness check, which decides what counts as evidence, is untouched by form.
    assert check_completeness(cells, {"1.1.1": 1}) == []


def test_form_summary_prints_its_denominator_and_the_population_it_never_saw() -> None:
    """A broken run and a clean run must not look alike, so the split prints what it SCANNED.

    Parts, the located total, the unlocated remainder, and the derived percentage all appear. A bare
    "1,479 code" is unreadable: unreadable against what?
    """
    f = Findings(checked_anchors=10)
    f.anchor_forms.update({"code": 5, "doc": 2, "foreign": 2})
    text = "\n".join(form_summary(f))
    assert "form of the 9 anchor(s) that located" in text
    assert "5 code" in text and "2 doc" in text and "2 foreign" in text
    assert "1 further anchor(s) did NOT locate" in text
    assert "4 of 9 (44.4%)" in text
    assert "LABEL and not a demotion" in text


def test_form_summary_negative_control_says_zero_rather_than_dividing_by_zero() -> None:
    """Nothing located: every part is zero, the percentage is 0.0, and no line is silently omitted."""
    text = "\n".join(form_summary(Findings()))
    assert "form of the 0 anchor(s) that located" in text
    assert "0 code" in text and "0 doc" in text and "0 foreign" in text
    assert "0 of 0 (0.0%)" in text
    assert "did NOT locate" not in text  # nothing was scanned, so nothing went unclassified


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


def test_main_summary_says_RESOLVED_not_VERIFIED_and_carries_the_form_split(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The rendered face of the record must not assert something the check does not establish.

    The summary line used to read "verified N evidence anchors". The run did not verify them; it
    RESOLVED them -- the token is present and unique in the file, which is not evidence that the
    control operates. Measured instance: 15.3.1 sat at `pass` with every anchor resolving while the
    control it named had a hole, found only by executing the code. That distinction lives on the one
    line most readers will ever read, so it is pinned here end-to-end through `main`, not asserted of
    a helper.

    The split rides beside it for the same reason: "resolved 1,980" reads as 1,980 pieces of code
    evidence, and roughly a quarter of them are prose or a non-Python file.

    Falsified by restoring the word "verified" in `main`'s summary: the first two assertions go RED.
    Falsified independently by deleting the `for line in form_summary(findings)` loop: the split
    assertions go RED while the wording ones stay green. Both restored.
    """
    corpus = _corpus_file(tmp_path, {"1.1.1": 1})
    (tmp_path / "messagefoundry").mkdir()
    (tmp_path / "messagefoundry" / "m.py").write_text(
        '"""Prose about the gate."""\n\nSIZE = 64\n', encoding="utf-8"
    )
    sc = _scorecard_file(
        tmp_path,
        f'[scorecard]\nasvs_version = "5.0.0"\ncorpus_sha256 = "{corpus_digest(corpus)}"\n'
        '[[cell]]\nid = "1.1.1"\nlevel = 1\nverdict = "pass"\n'
        "  [[cell.evidence]]\n"
        '  path = "messagefoundry/m.py"\n  line = 3\n  expect = "SIZE = 64"\n'
        "  [[cell.evidence]]\n"
        '  path = "messagefoundry/m.py"\n  line = 1\n  expect = "Prose about the gate"\n',
    )
    rc = main(["--scorecard", str(sc), "--corpus", str(corpus), "--root", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "resolved 2 evidence anchors" in out
    assert "verified 2 evidence anchors" not in out
    assert "NOT proof the control operates" in out
    assert "form of the 2 anchor(s) that located: 1 code, 1 doc" in out
    assert "1 of 2 (50.0%) resolve into prose or a non-Python file" in out


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


# --- provenance and `--status`: a count is a fact about a (file x ref) PAIR -----------------------
#
# Three wrong-base errors occurred in one working thread on 2026-08-08/09. In every one the NUMBER was
# right and the REF was unnamed, so two readings taken from different places printed identically.
# These tests exist to make that specific silence impossible, and they lean on real git repositories
# rather than a mocked one: the failure being prevented is a fact about remote-tracking refs, fetch
# recency and worktree layout, so a stub would reproduce my assumptions instead of git's behaviour.

_GIT_ID = ("-c", "user.name=t", "-c", "user.email=t@t.invalid", "-c", "commit.gpgsign=false")


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *_GIT_ID, *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def _commit(repo: Path, name: str) -> None:
    (repo / name).write_text(name, encoding="utf-8")
    _git(repo, "add", name)
    _git(repo, "commit", "-m", name)


def _origin_and_clone(tmp_path: Path) -> tuple[Path, Path]:
    """A real bare origin plus a real clone tracking `origin/main`, both on disk."""
    origin = tmp_path / "origin.git"
    seed = tmp_path / "seed"
    seed.mkdir()
    _git(seed, "init", "--quiet")
    _git(seed, "checkout", "--quiet", "-b", "main")
    _commit(seed, "a.txt")
    subprocess.run(
        ["git", "init", "--bare", "--quiet", str(origin)], check=True, capture_output=True
    )
    _git(seed, "remote", "add", "origin", str(origin))
    _git(seed, "push", "--quiet", "-u", "origin", "main")
    clone = tmp_path / "clone"
    subprocess.run(
        ["git", "clone", "--quiet", str(origin), str(clone)], check=True, capture_output=True
    )
    _git(clone, "checkout", "--quiet", "main")
    return seed, clone


def test_git_is_available_so_no_provenance_test_can_silently_skip() -> None:
    """None of the tests below is marked skipif, on purpose. A provenance guard that quietly
    evaporates on a machine without git is the same class of defect as a gate that cannot go red."""
    assert subprocess.run(["git", "--version"], capture_output=True, check=True).returncode == 0


def test_provenance_stamps_a_clean_checkout_with_its_sha_and_a_named_upstream(
    tmp_path: Path,
) -> None:
    _, clone = _origin_and_clone(tmp_path)
    stamp = repo_stamp(clone)
    assert stamp.sha == _git(clone, "rev-parse", "--short", "HEAD")
    assert stamp.dirty is False
    assert stamp.ref() == stamp.sha and "+dirty" not in stamp.ref()
    assert stamp.freshness == "CURRENT"
    assert stamp.upstream == "origin/main"  # named, because BEHIND n is not a claim without it


def test_provenance_marks_a_dirty_tree_so_it_cannot_pass_for_a_reproducible_one(
    tmp_path: Path,
) -> None:
    """A measurement taken against uncommitted changes is not reproducible and must not look like one
    that is. Falsified by hardcoding `dirty=False` in `repo_stamp`: this goes RED. Restored."""
    _, clone = _origin_and_clone(tmp_path)
    assert repo_stamp(clone).dirty is False  # control: clean first, so the flag means something
    (clone / "a.txt").write_text("edited", encoding="utf-8")
    stamp = repo_stamp(clone)
    assert stamp.dirty is True
    assert stamp.ref().endswith("+dirty")


def test_freshness_reports_BEHIND_with_its_count_and_needs_no_network(tmp_path: Path) -> None:
    """THE measured case. The vault checkout that caused the original wrong-base error in this
    programme reads BEHIND 37 with remote knowledge 23 minutes old; re-measured while building this,
    the same checkout read BEHIND 38 at 36 minutes. Either line stops the error dead.

    The count comes from `git rev-list --left-right --count HEAD...origin/main`, which counts against
    the LAST-FETCHED remote-tracking ref -- a purely local object. The fetch below is the test setting
    up remote knowledge; the tool itself never fetches (see the no-mutation test further down).
    """
    seed, clone = _origin_and_clone(tmp_path)
    _commit(seed, "b.txt")
    _commit(seed, "c.txt")
    _git(seed, "push", "--quiet", "origin", "main")
    _git(clone, "fetch", "--quiet", "origin")
    stamp = repo_stamp(clone)
    assert stamp.freshness == "BEHIND 2"
    assert stamp.upstream == "origin/main"


def test_freshness_reports_AHEAD_with_its_count(tmp_path: Path) -> None:
    _, clone = _origin_and_clone(tmp_path)
    _commit(clone, "local.txt")
    assert repo_stamp(clone).freshness == "AHEAD 1"


def test_freshness_reports_DIVERGED_when_both_sides_moved(tmp_path: Path) -> None:
    """DIVERGED is its own value and must not collapse into AHEAD or BEHIND: a branch that is both is
    the state in which "am I on the right base?" is hardest and most often answered wrongly."""
    seed, clone = _origin_and_clone(tmp_path)
    _commit(seed, "remote.txt")
    _git(seed, "push", "--quiet", "origin", "main")
    _git(clone, "fetch", "--quiet", "origin")
    _commit(clone, "local.txt")
    assert repo_stamp(clone).freshness == "DIVERGED"


def test_freshness_is_NO_UPSTREAM_and_is_never_an_omitted_field(tmp_path: Path) -> None:
    """A repo with no remote at all. The field is POPULATED, not dropped: an absent qualifier is
    exactly what produced all three wrong-base errors.

    Falsified by returning an empty string from `_freshness` in this branch: the emptiness assertion
    goes RED and the printed line silently loses its qualifier. Restored.
    """
    solo = tmp_path / "solo"
    solo.mkdir()
    _git(solo, "init", "--quiet")
    _git(solo, "checkout", "--quiet", "-b", "main")
    _commit(solo, "a.txt")
    stamp = repo_stamp(solo)
    assert stamp.freshness == "NO-UPSTREAM"
    assert stamp.upstream == "none"
    assert stamp.freshness != "" and stamp.remote_knowledge != ""


def test_a_path_outside_any_work_tree_is_NO_GIT_and_not_NO_UPSTREAM(tmp_path: Path) -> None:
    """The two are different statements and conflating them is a lie in the safer-sounding direction.

    NO-UPSTREAM says "this repo tracks nothing"; NO-GIT says "this is not a repo, so no ref exists to
    quote at all". A copy of the scorecard extracted by `git show` into a temp directory reads the
    second, and reporting it as the first would let it pass for a checkout.
    """
    loose = tmp_path / "loose"
    loose.mkdir()
    stamp = repo_stamp(loose)
    assert stamp.sha == "NO-GIT"
    assert stamp.freshness == "NO-GIT"
    assert stamp.upstream == "none"


def test_remote_knowledge_is_NEVER_FETCHED_before_any_fetch_has_happened(tmp_path: Path) -> None:
    solo = tmp_path / "solo"
    solo.mkdir()
    _git(solo, "init", "--quiet")
    _git(solo, "checkout", "--quiet", "-b", "main")
    _commit(solo, "a.txt")
    assert repo_stamp(solo).remote_knowledge == "NEVER-FETCHED"


def test_remote_knowledge_reports_the_AGE_of_the_last_fetch_not_merely_that_one_happened(
    tmp_path: Path,
) -> None:
    """BEHIND 0 from a six-hour-old fetch and BEHIND 0 from a one-minute-old fetch are DIFFERENT
    CLAIMS and must not print identically. That is the whole reason this field sits beside the count.

    Falsified by returning a constant from `_remote_knowledge`: the two ages below become equal and
    this goes RED. Restored.
    """
    seed, clone = _origin_and_clone(tmp_path)
    _git(clone, "fetch", "--quiet", "origin")
    fresh = repo_stamp(clone).remote_knowledge
    assert fresh.endswith("s")  # seconds old, just now

    head = Path(_git(clone, "rev-parse", "--path-format=absolute", "--git-dir")) / "FETCH_HEAD"
    assert head.is_file()
    old = time.time() - 6 * 3600
    os.utime(head, (old, old))
    stale = repo_stamp(clone).remote_knowledge
    assert stale == "6h"
    assert stale != fresh


def test_humanise_age_covers_each_unit_boundary() -> None:
    assert _humanise_age(0) == "0s"
    assert _humanise_age(89) == "89s"
    assert _humanise_age(90) == "1m"
    assert _humanise_age(23 * 60) == "23m"
    assert _humanise_age(90 * 60) == "1h"
    assert _humanise_age(47 * 3600) == "47h"
    assert _humanise_age(48 * 3600) == "2d"


def test_status_issues_no_write_and_no_network_git_subcommand(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """THE NEGATIVE CONTROL, and the one that matters most here.

    A query tool that fetches mutates repo state as a side effect of being asked a question, and on
    this machine the vault remote is intermittently unauthenticated, so a network dependency would
    fire constantly and the tool would be bypassed inside a day. So every git subcommand this mode
    issues is captured and checked against a read-only allowlist, and the mutating verbs must appear
    ZERO times: a pattern that cannot occur must come back zero.

    It also checks the OUTCOME and not only the intent -- the remote-tracking refs and the FETCH_HEAD
    mtime are compared across the run. Asserting on the argv alone would pass a tool that reached the
    network some other way.

    Falsified by adding a fetch to `repo_stamp`: the allowlist assertion goes RED naming the verb, and
    the FETCH_HEAD mtime assertion goes RED independently of it. Restored.
    """
    seed, clone = _origin_and_clone(tmp_path)
    _commit(seed, "b.txt")
    _git(seed, "push", "--quiet", "origin", "main")
    _git(clone, "fetch", "--quiet", "origin")

    refs_before = _git(clone, "for-each-ref", "refs/remotes")
    head = Path(_git(clone, "rev-parse", "--path-format=absolute", "--git-dir")) / "FETCH_HEAD"
    mtime_before = head.stat().st_mtime

    seen: list[list[str]] = []
    real_run = subprocess.run

    def spy(cmd: Any, *a: Any, **kw: Any) -> Any:
        seen.append(list(cmd))
        return real_run(cmd, *a, **kw)

    # Patched on the `subprocess` module itself, which is the same object the verifier imported. That
    # also means the helper `_git` below is spied, so `verbs` is snapshotted before any helper call.
    monkeypatch.setattr(subprocess, "run", spy)

    sc = _scorecard_file(clone, '[[cell]]\nid = "1.1.1"\nlevel = 1\nverdict = "unverified"\n')
    rc = main(["--status", "--scorecard", str(sc), "--root", str(clone)])
    capsys.readouterr()

    assert rc == 0
    assert seen, "the spy captured nothing -- this test would otherwise pass vacuously"
    verbs = {cmd[3] for cmd in seen if len(cmd) > 3}
    assert verbs <= {"rev-parse", "status", "rev-list"}, f"non-read-only git verb: {verbs}"
    for forbidden in ("fetch", "pull", "push", "remote", "gc", "prune", "commit", "checkout"):
        assert forbidden not in verbs

    assert _git(clone, "for-each-ref", "refs/remotes") == refs_before
    assert head.stat().st_mtime == mtime_before


def test_provenance_lines_always_carry_every_mandated_field(tmp_path: Path) -> None:
    """Non-suppressible and never partially populated. Each field is checked by NAME, so dropping one
    is a red rather than a shorter line nobody notices."""
    _, clone = _origin_and_clone(tmp_path)
    sc = _scorecard_file(clone, '[[cell]]\nid = "1.1.1"\nlevel = 1\nverdict = "unverified"\n')
    text = "\n".join(provenance_lines(sc, clone))
    assert text.startswith("# asvs-status scorecard=")
    assert " engine=" in text
    assert "scorecard: freshness=" in text and "engine:" in text
    assert text.count("freshness=") == 2  # one per repo: a single field could not say WHICH repo
    assert text.count("upstream=") == 2
    assert text.count("remote-knowledge=") == 2
    assert "generated=" in text


def test_two_readings_of_the_same_filename_at_different_refs_do_not_print_identically(
    tmp_path: Path,
) -> None:
    """THE POINT OF THE WHOLE FEATURE, reproduced in miniature.

    Live instance measured 2026-08-09 while building this: the vault working tree and vault
    `origin/main` both hold a file called `asvs-scorecard.toml`, and they disagree -- 105 partial /
    3 fail / 1,978 anchors against 106 partial / 2 fail / 1,980 anchors. Without a ref stamp those are
    two plausible readings of "the scorecard" and nothing in either output says which is which. That
    is exactly how three wrong-base errors happened in one thread.

    Here the same file name is read from a stale checkout and a current one. The COUNTS are identical
    by construction; only the provenance differs, which is the property under test.
    """
    seed, clone = _origin_and_clone(tmp_path)
    body = '[[cell]]\nid = "1.1.1"\nlevel = 1\nverdict = "unverified"\n'
    sc_current = _scorecard_file(seed, body)
    sc_stale = _scorecard_file(clone, body)
    _commit(seed, "b.txt")
    _git(seed, "push", "--quiet", "origin", "main")
    _git(clone, "fetch", "--quiet", "origin")

    current = "\n".join(provenance_lines(sc_current, seed))
    stale = "\n".join(provenance_lines(sc_stale, clone))

    assert sc_current.name == sc_stale.name  # identical file names, as in the live instance
    assert status_lines(load_scorecard(sc_current)) == status_lines(load_scorecard(sc_stale))
    assert "BEHIND 1" in stale
    assert "BEHIND" not in current
    assert current != stale


def test_status_reports_every_verdict_including_needs_review() -> None:
    """`needs-review` is absent from the verify summary line and present here. A cell that was read
    and then parked on purpose is not a cell that does not exist, and the record's own renderer once
    contradicted itself over exactly this distinction."""
    cells = [
        Cell(id="1.1.1", level=1, verdict="pass", last_verified="2026-08-09"),
        Cell(id="1.1.2", level=2, verdict="needs-review", last_verified="2026-08-09"),
        Cell(id="2.1.1", level=3, verdict="unverified"),
    ]
    text = "\n".join(status_lines(cells))
    assert "cells 3: 1 pass, 0 partial, 0 fail, 0 na, 1 needs-review, 1 unverified" in text
    assert "examined 2 of 3 (66.7%)" in text


def test_status_names_what_it_did_NOT_check() -> None:
    """A cheap answer that looks like a full one is worse than no answer. `--status` never opens the
    engine tree, so it must say so rather than let a structural tally read as anchor health.

    Falsified by deleting the final line of `status_lines`: this goes RED. Restored.
    """
    text = "\n".join(status_lines([Cell(id="1.1.1", level=1, verdict="unverified")]))
    assert "NOT CHECKED here" in text
    assert "whether any anchor still resolves" in text
    assert "run verify" in text


def test_main_status_needs_no_corpus_and_prints_provenance_first(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`--status` is a pure scorecard read, so requiring `--corpus` would be friction with no purpose,
    and the provenance header is the FIRST thing on stdout -- before any number it qualifies."""
    _, clone = _origin_and_clone(tmp_path)
    sc = _scorecard_file(
        clone,
        '[[cell]]\nid = "1.1.1"\nlevel = 1\nverdict = "pass"\nlast_verified = "2026-08-09"\n',
    )
    rc = main(["--status", "--scorecard", str(sc), "--root", str(clone)])
    out = capsys.readouterr().out.splitlines()
    assert rc == 0
    assert out[0].startswith("# asvs-status scorecard=")
    assert any(line.startswith("cells 1:") for line in out)


def test_main_status_exits_2_on_an_unreadable_scorecard_and_still_prints_provenance(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 2 is could-not-measure. NEVER 1: a query that borrows the gate's failure code gets wired
    into CI as a gate, and this one checks nothing about the posture.

    The header still prints, so even the failure is attributable to a ref.
    """
    _, clone = _origin_and_clone(tmp_path)
    rc = main(["--status", "--scorecard", str(clone / "absent.toml"), "--root", str(clone)])
    captured = capsys.readouterr()
    assert rc == 2
    assert captured.out.startswith("# asvs-status scorecard=")
    assert "refusing to report a pass on a missing file" in captured.err


def test_status_does_not_run_the_gate_and_cannot_return_the_gates_exit_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Negative control on the exit code: a scorecard whose anchor is broken still exits 0 under
    `--status`, because `--status` does not check anchors. If someone later wires verification into
    this path, the 41-second cost and this assertion land at the same moment."""
    _, clone = _origin_and_clone(tmp_path)
    sc = _scorecard_file(
        clone,
        '[[cell]]\nid = "1.1.1"\nlevel = 1\nverdict = "pass"\n'
        "  [[cell.evidence]]\n"
        '  path = "nowhere/absent.py"\n  line = 1\n  expect = "token_that_does_not_exist"\n',
    )
    rc = main(["--status", "--scorecard", str(sc), "--root", str(clone)])
    capsys.readouterr()
    assert rc == 0


# --- prove-absences: the counters must be reconcilable against the population they came from ------


def test_prove_absences_records_the_population_it_saw(tmp_path: Path) -> None:
    """`checked_absences` is set BEFORE any outcome branch, so it is right whichever branch is taken.

    Falsified by moving the increment inside `_prove_one` after the `mutation_path` guard: the skipped
    claim then goes uncounted and the first assertion goes RED. Restored.
    """
    _module(tmp_path, "scanner.py", _SCANNER)
    _obs_test(tmp_path, "test_scanner.py", _OBS_TEST)
    proved = _live_claim(
        'def scan(p): return "infected"', "scanner.py", "test_scanner.py::test_clean"
    )
    skipped = Cell(
        id="1.1.2",
        level=1,
        verdict="fail",
        absence=(Absence(pattern="x", positive_control="y", mutation="import x"),),
    )
    findings = prove_absences([proved, skipped], tmp_path)
    assert findings.checked_absences == 2
    assert findings.proved_absences == 1
    assert findings.skipped_absences == 1


def test_prove_absences_counters_close_against_the_population(tmp_path: Path) -> None:
    """The arithmetic that makes the summary readable, asserted rather than asserted-in-prose.

    FIVE outcomes raise a problem and increment no counter (an escaping `mutation_path`, one that is
    not a file, a baseline that is not green, an UNPROVEN mutated-green, and a mutated run that
    errored). So the closing identity is population minus the three counters, and this fixture drives
    one claim into each of four different branches to check it holds across them.

    Note what is NOT asserted: that `len(problems)` equals the problem-only count. It does not, and
    cannot -- a SUSPECT finding rides along with a claim already counted in `static_screened`, so
    problems and claims are different populations. Asserting that equality would pin a false identity.
    """
    _module(tmp_path, "scanner.py", _SCANNER)
    _module(tmp_path, "quiet.py", "VALUE = 1\n")
    _obs_test(tmp_path, "test_scanner.py", _OBS_TEST)

    proved = _live_claim(
        'def scan(p): return "infected"', "scanner.py", "test_scanner.py::test_clean"
    )
    skipped = Cell(
        id="1.1.2",
        level=1,
        verdict="fail",
        absence=(Absence(pattern="x", positive_control="y", mutation="import x"),),
    )
    screened = Cell(
        id="1.1.3",
        level=1,
        verdict="fail",
        absence=(
            Absence(
                pattern="x", positive_control="y", mutation="VALUE = 2", mutation_path="quiet.py"
            ),
        ),
    )
    problem_only = Cell(
        id="1.1.4",
        level=1,
        verdict="fail",
        absence=(
            Absence(
                pattern="x",
                positive_control="y",
                mutation="import x",
                mutation_path="not_a_file.py",
            ),
        ),
    )

    f = prove_absences([proved, skipped, screened, problem_only], tmp_path)
    assert f.checked_absences == 4
    remainder = f.checked_absences - f.proved_absences - f.static_screened - f.skipped_absences
    assert remainder == 1  # exactly the PROVE-ERROR claim, derived rather than counted
    assert f.proved_absences == 1 and f.skipped_absences == 1 and f.static_screened == 1


def test_prove_absences_summary_prints_the_population_before_the_parts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A run that scanned N claims and a run that scanned zero must not print equally plausible
    counter sets. Without `saw N` they do: all four numbers are zero in both.

    Falsified by deleting the `saw ... absence claim(s);` term from `_run_prove_absences`: both
    assertions go RED. Restored.
    """
    _module(tmp_path, "scanner.py", _SCANNER)
    _obs_test(tmp_path, "test_scanner.py", _OBS_TEST)
    sc = tmp_path / "sc.toml"
    _biting_scorecard(sc, "scanner.py")
    rc = main(["--scorecard", str(sc), "--root", str(tmp_path), "--prove-absences"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "prove-absences: saw 1 absence claim(s);" in out
    assert "proved 1 by mutation" in out


def test_prove_absences_summary_negative_control_an_empty_run_says_saw_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The negative control: a scorecard with NO absence claims must say so, not print four zeroes
    that read like a clean pass over a real population."""
    sc = tmp_path / "sc.toml"
    sc.write_text(
        '[[cell]]\nid = "1.1.1"\nlevel = 1\nverdict = "unverified"\n',
        encoding="utf-8",
    )
    rc = main(["--scorecard", str(sc), "--root", str(tmp_path), "--prove-absences"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "saw 0 absence claim(s)" in out


# --- sym + ctx: WHERE in the structure, and it is a DISPLACEMENT signal ---------------------------
#
# Measured 2026-08-09, vault origin/main 1a59e4a1's anchors against engine tree 4667e945: over the
# 1,712 Python anchors that locate and parse, 536 (31.3%) sit in a (sym, ctx) region wider than the
# 81 lines the retired +/-40 window covered -- so sym/ctx alone is LOOSER for those, and this is
# additive to the drift advisory rather than a replacement for it. The brief's 38.4%/639 reproduces
# at 634 under the looser symbol-only region definition; both support the same conclusion.

_NESTED = '''\
"""Module docstring."""

TOP = 1


class Store:
    """A store."""

    def revoke(self, keep):
        rows = []
        try:
            rows = self.query()
        except OSError:
            rows = []
        if keep:
            for r in rows:
                if r.stale:
                    self.drop(r)
        return rows


def loose():
    return TOP
'''


def _sym_ctx(text: str, token: str) -> tuple[str, str] | None:
    return derive_sym_ctx(text, text.count("\n", 0, text.index(token)) + 1)


def test_sym_ctx_derives_module_level_as_two_empty_strings() -> None:
    """`""` is the assertion "module level, unnested" -- a real claim, not a missing value."""
    assert _sym_ctx(_NESTED, "TOP = 1") == ("", "")


def test_sym_ctx_derives_the_enclosing_symbol_dotted() -> None:
    assert _sym_ctx(_NESTED, "rows = self.query()") == ("Store.revoke", "Try.body")
    assert _sym_ctx(_NESTED, "return TOP") == ("loose", "")


def test_sym_ctx_names_the_handler_limb_not_the_body_limb() -> None:
    """`Try.body` and `Try.handlers` are different regions and a statement moving between them is
    exactly the displacement this field exists to notice.

    The handler's own `ExceptHandler.body` is deliberately NOT a second chain element: it is reachable
    only through `Try.handlers`, so recording it would double every handler chain for no added
    discrimination.
    """
    assert _sym_ctx(_NESTED, "rows = self.query()") == ("Store.revoke", "Try.body")
    assert _sym_ctx(_NESTED, "except OSError") == ("Store.revoke", "Try.handlers")


def test_sym_ctx_chains_nested_blocks_outermost_first() -> None:
    assert _sym_ctx(_NESTED, "self.drop(r)") == ("Store.revoke", "If.body>For.body>If.body")


def test_sym_ctx_resets_the_chain_at_a_symbol_boundary() -> None:
    """A block chain is meaningful only inside the symbol holding it. A nested function inside a
    `try` must not inherit `Try.body`, or every helper defined in a guarded block reads as guarded.

    Falsified by deleting the `ctx.clear()` in `sym_ctx_at`: the inner function's ctx becomes
    `Try.body` and this goes RED. Restored.
    """
    src = "def outer():\n    try:\n        def inner():\n            return 1\n    except OSError:\n        pass\n"
    assert derive_sym_ctx(src, 4) == ("outer.inner", "")


def test_sym_ctx_is_None_when_the_file_will_not_parse() -> None:
    assert derive_sym_ctx("def f(\n", 1) is None


def test_sym_ctx_is_not_indentation_the_12_3_5_non_event(tmp_path: Path) -> None:
    """CELL 12.3.5's SHAPE, and the reason this field is `ctx` rather than an indent check.

    12.3.5 carries the identical 4-versus-8 indent mismatch as 10.5.4 and is a NON-EVENT: a
    hand-trimming slip, with the statement's position in the control flow unchanged at both ends.
    Here the same statement is re-indented under a block that already contained it. Indentation
    changed; `ctx` did not, and correctly does not fire.

    Falsified by deriving from `len(line) - len(line.lstrip())` instead of the block chain: the two
    derivations differ and this goes RED. Restored.
    """
    before = "def f():\n    if x:\n        do_it()\n"
    after = "def f():\n    if x:\n            do_it()\n"  # slipped indent, same block
    assert _sym_ctx(before, "do_it()") == _sym_ctx(after, "do_it()") == ("f", "If.body")


def test_sym_ctx_DOES_fire_when_a_statement_is_welded_into_a_try_the_10_5_4_shape() -> None:
    """The other half: 10.5.4's shape, where the statement really did change control-flow region.

    And the honest reading of it -- that change was a HARDENING. The signal fired correctly and the
    finding was "your reasoning is stale", not "something is broken". Its security-relevant precision
    on the only datum the corpus offers is 0 of 1.
    """
    before = "def f():\n    conn.rollback()\n"
    after = "def f():\n    try:\n        conn.rollback()\n    except OSError:\n        pass\n"
    assert _sym_ctx(before, "conn.rollback()") == ("f", "")
    assert _sym_ctx(after, "conn.rollback()") == ("f", "Try.body")


# --- validation: malformed is FATAL, mismatched is ADVISORY ---------------------------------------


def test_malformed_ctx_names_an_unknown_node_type() -> None:
    assert "not a block statement" in (malformed_sym_ctx(None, "Tyr.body") or "")


def test_malformed_ctx_names_a_field_the_node_does_not_have() -> None:
    """`With` has no `orelse`. The table that validates is the table the deriver walks, so an accepted
    chain is one the deriver can actually produce."""
    assert "does not have" in (malformed_sym_ctx(None, "With.orelse") or "")


def test_malformed_sym_rejects_a_non_identifier() -> None:
    assert "dotted Python identifier" in (malformed_sym_ctx("Store revoke()", None) or "")


def test_wellformed_sym_and_ctx_pass_validation() -> None:
    assert malformed_sym_ctx("Store.revoke", "Try.body>If.orelse") is None
    assert malformed_sym_ctx("", "") is None  # module level, unnested: a claim, and a valid one
    assert malformed_sym_ctx(None, None) is None  # not asserted


def test_a_malformed_ctx_is_FATAL_because_no_code_movement_can_cause_it(tmp_path: Path) -> None:
    """The only fatal outcome in this feature. A chain the deriver cannot produce would advise
    forever without ever matching, and the fix is unambiguous.

    Falsified by downgrading the `malformed_sym_ctx` branch in `_check_sym_ctx` to an advisory:
    `not f.ok` goes RED. Restored.
    """
    (tmp_path / "messagefoundry").mkdir()
    (tmp_path / "messagefoundry" / "m.py").write_text("def f():\n    do_it()\n", encoding="utf-8")
    cells = [
        Cell(
            id="1.1.1",
            level=1,
            verdict="pass",
            evidence=(Anchor("messagefoundry/m.py", 2, "do_it()", ctx="Nope.body"),),
        )
    ]
    f = Findings()
    check_anchors(cells, tmp_path, f)
    assert not f.ok
    assert "not a block statement" in f.problems[0]


def test_sym_ctx_on_a_non_python_file_is_FATAL(tmp_path: Path) -> None:
    """Markdown has no enclosing symbol. Recording one is an authoring error no derivation can ever
    confirm or deny, so it is refused rather than left as a permanent silent pass."""
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "SECURITY.md").write_text("deny by default\n", encoding="utf-8")
    cells = [
        Cell(
            id="1.1.1",
            level=1,
            verdict="pass",
            evidence=(Anchor("docs/SECURITY.md", 1, "deny by default", sym="f"),),
        )
    ]
    f = Findings()
    check_anchors(cells, tmp_path, f)
    assert not f.ok and "non-Python file" in f.problems[0]


def test_a_MISMATCHED_ctx_is_ADVISORY_never_fatal(tmp_path: Path) -> None:
    """THE severity decision, and it is load-bearing.

    A mismatch means the token moved into a different control-flow region. On the only datum the
    corpus offers -- 10.5.4 -- that movement was a HARDENING. A check that redded the gate on it
    would have demanded a rollback of a security improvement. So: advisory.

    Falsified by appending to `problems` instead of `advisories` in `_check_sym_ctx`: `f.ok` goes RED.
    Restored.
    """
    (tmp_path / "messagefoundry").mkdir()
    (tmp_path / "messagefoundry" / "m.py").write_text(
        "def f():\n    try:\n        conn.rollback()\n    except OSError:\n        pass\n",
        encoding="utf-8",
    )
    cells = [
        Cell(
            id="10.5.4",
            level=3,
            verdict="pass",
            evidence=(Anchor("messagefoundry/m.py", 3, "conn.rollback()", sym="f", ctx=""),),
        )
    ]
    f = Findings()
    check_anchors(cells, tmp_path, f)
    assert f.ok and f.problems == []
    assert len(f.advisories) == 1
    assert "DISPLACEMENT, not a defect" in f.advisories[0]
    assert "HARDENING" in f.advisories[0]
    assert "ctx=''" in f.advisories[0] and "ctx='Try.body'" in f.advisories[0]


def test_sym_and_ctx_are_validated_INDEPENDENTLY(tmp_path: Path) -> None:
    """An anchor may assert one and not the other, and asserting neither is not agreement."""
    (tmp_path / "messagefoundry").mkdir()
    (tmp_path / "messagefoundry" / "m.py").write_text(
        "def f():\n    if x:\n        do_it()\n", encoding="utf-8"
    )
    sym_only = Anchor("messagefoundry/m.py", 3, "do_it()", sym="WRONG")
    ctx_only = Anchor("messagefoundry/m.py", 3, "do_it()", ctx="If.body")
    neither = Anchor("messagefoundry/m.py", 3, "do_it()")

    f = Findings()
    check_anchors([Cell(id="1.1.1", level=1, verdict="pass", evidence=(sym_only,))], tmp_path, f)
    assert len(f.advisories) == 1 and "sym=" in f.advisories[0]

    g = Findings()
    check_anchors([Cell(id="1.1.1", level=1, verdict="pass", evidence=(ctx_only,))], tmp_path, g)
    assert g.advisories == []  # ctx is right, so nothing to say

    h = Findings()
    check_anchors([Cell(id="1.1.1", level=1, verdict="pass", evidence=(neither,))], tmp_path, h)
    assert h.advisories == [] and h.checked_sym_ctx == 0


def test_sym_ctx_is_ADDITIVE_to_the_drift_advisory_and_neither_replaces_the_other(
    tmp_path: Path,
) -> None:
    """THE MANDATED PROPERTY, asserted rather than asserted-in-prose. Three anchors, three outcomes:

      - moved a long way, same region        -> drift only    (sym/ctx would have missed it)
      - did not move, region changed         -> sym/ctx only  (drift would have missed it)
      - moved AND region changed             -> both

    Measured, 536 of 1,712 Python anchors sit in a (sym, ctx) region wider than the retired 81-line
    window, so replacing drift with this loses detection on roughly a third of the record.

    Falsified by making `_check_sym_ctx` return early whenever the line drifted (i.e. treating them as
    alternatives): the second and third counts go RED. Restored.
    """
    (tmp_path / "messagefoundry").mkdir()
    body = (
        "def f():\n"
        + "".join(f"    pad_{i} = {i}\n" for i in range(200))
        + "    moved_far = 1\n"
        + "def g():\n    try:\n        welded = 2\n    except OSError:\n        pass\n"
    )
    (tmp_path / "messagefoundry" / "m.py").write_text(body, encoding="utf-8")

    # moved a long way, still in `f` and still unnested: drift fires, sym/ctx does not.
    drift_only = Anchor("messagefoundry/m.py", 3, "moved_far = 1", sym="f", ctx="")
    # Recorded at its TRUE line, so drift stays silent and only the region change speaks.
    # def f=1, 200 pads=2..201, moved_far=202, def g=203, try=204, welded=205.
    region_only = Anchor("messagefoundry/m.py", 205, "welded = 2", sym="g", ctx="")

    f1 = Findings()
    check_anchors([Cell(id="1.1.1", level=1, verdict="pass", evidence=(drift_only,))], tmp_path, f1)
    assert len(f1.advisories) == 1 and "navigation aid" in f1.advisories[0]

    f2 = Findings()
    check_anchors(
        [Cell(id="1.1.2", level=1, verdict="pass", evidence=(region_only,))], tmp_path, f2
    )
    assert len(f2.advisories) == 1 and "DISPLACEMENT" in f2.advisories[0]

    both = Anchor("messagefoundry/m.py", 1, "welded = 2", sym="g", ctx="")
    f3 = Findings()
    check_anchors([Cell(id="1.1.3", level=1, verdict="pass", evidence=(both,))], tmp_path, f3)
    assert len(f3.advisories) == 2
    assert any("navigation aid" in x for x in f3.advisories)
    assert any("DISPLACEMENT" in x for x in f3.advisories)


def test_load_reads_sym_and_ctx_and_absent_stays_None(tmp_path: Path) -> None:
    """ABSENT and EMPTY are different claims. Defaulting absent to `""` would turn every one of the
    1,980 un-backfilled anchors into an assertion of "module level, unnested" overnight.

    Falsified by changing the loader to `str(e.get("sym", ""))`: the `is None` assertions go RED.
    Restored.
    """
    sc = _scorecard_file(
        tmp_path,
        '[[cell]]\nid = "1.1.1"\nlevel = 1\nverdict = "pass"\n'
        "  [[cell.evidence]]\n"
        '  path = "m.py"\n  line = 1\n  expect = "x"\n'
        "  [[cell.evidence]]\n"
        '  path = "m.py"\n  line = 2\n  expect = "y"\n  sym = "f"\n  ctx = "Try.body"\n'
        "  [[cell.evidence]]\n"
        '  path = "m.py"\n  line = 3\n  expect = "z"\n  sym = ""\n  ctx = ""\n',
    )
    absent, filled, empty = load_scorecard(sc)[0].evidence
    assert absent.sym is None and absent.ctx is None
    assert filled.sym == "f" and filled.ctx == "Try.body"
    assert empty.sym == "" and empty.ctx == ""


def test_the_summary_reports_how_much_of_the_record_sym_ctx_actually_reached(
    tmp_path: Path,
) -> None:
    """Coverage is printed because backfill has not happened yet. A structural check that reaches 1 of
    3 anchors while printing like a whole-corpus result is the overstatement this pass keeps fixing.

    Falsified by deleting the `sym/ctx asserted on` line from `form_summary`: this goes RED. Restored.
    """
    f = Findings(checked_anchors=3, checked_sym_ctx=1)
    f.anchor_forms.update({"code": 3})
    text = "\n".join(form_summary(f))
    assert "sym/ctx asserted on 1 of 3 anchor(s)" in text
    assert "absence of the field is NOT agreement" in text


def test_summary_sym_ctx_negative_control_says_nothing_extra_at_full_coverage() -> None:
    """The qualifier appears only when coverage is partial, so it cannot become wallpaper."""
    f = Findings(checked_anchors=2, checked_sym_ctx=2)
    f.anchor_forms.update({"code": 2})
    text = "\n".join(form_summary(f))
    assert "sym/ctx asserted on 2 of 2 anchor(s)" in text
    assert "NOT agreement" not in text


def test_the_walk_descends_THROUGH_a_handler_into_its_nested_blocks() -> None:
    """DESCENT, which is a different property from whether the handler is RECORDED.

    Added after an injection that should have failed did not: deleting `ExceptHandler` from
    `_TRANSPARENT` silently stopped the walk descending instead of starting to record, so the chain
    came out identical by a different route and no test could tell. Descent and recording now come
    from two tables, and this test drives descent -- a statement nested inside an `if` inside an
    `except` body is only reachable if the walk goes THROUGH the handler.

    Falsified by removing `ExceptHandler` from `_DESCEND_ONLY`: the chain truncates to
    `Try.handlers` and this goes RED. Restored.
    """
    src = (
        "def f():\n"
        "    try:\n"
        "        risky()\n"
        "    except OSError:\n"
        "        if retry:\n"
        "            recover()\n"
    )
    assert derive_sym_ctx(src, 6) == ("f", "Try.handlers>If.body")


def test_a_handler_contributes_no_chain_element_of_its_own() -> None:
    """RECORDING, the other half. `ExceptHandler.body` would double every handler chain for no added
    discrimination, because a handler is reachable by exactly one route its parent already names.

    Falsified by removing `ExceptHandler` from `_TRANSPARENT`: the chain becomes
    `Try.handlers>ExceptHandler.body>If.body` and this goes RED. Restored.
    """
    src = (
        "def f():\n"
        "    try:\n"
        "        risky()\n"
        "    except OSError:\n"
        "        if retry:\n"
        "            recover()\n"
    )
    _, ctx = derive_sym_ctx(src, 6) or ("", "")
    assert "ExceptHandler" not in ctx


def test_descent_and_transparency_tables_do_not_drift_apart() -> None:
    """They are separate by design, so nothing else would notice one gaining an entry the other
    lacks. A node in `_DESCEND_ONLY` but not `_TRANSPARENT` would start emitting a chain element
    nobody authored; the reverse would make a transparent node undescendable."""
    assert frozenset(_DESCEND_ONLY) == _TRANSPARENT

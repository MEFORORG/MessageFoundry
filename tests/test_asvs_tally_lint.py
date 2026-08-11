# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the forward-only ASVS tally lint (``scripts/docs/asvs_tally_lint.py``).

Every idiom is driven from BOTH sides. A detector that has only ever been shown text it should
catch is a detector whose false-positive rate nobody measured, and the previous attempt at this lint
failed in exactly that direction: it produced 73 false hits on HL7 field notation in this repo's own
documents while missing 6 of the 8 documents that motivated it.

The fixtures are SYNTHETIC reproductions of shapes measured in the assessment corpus. They are not
copied from it: the corpus is a private security record, its tallies ARE the posture, and a public
test file is not a place to put them. Each fixture carries the shape it stands for.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scripts.docs.asvs_tally_lint import (
    CORPUS_TOTAL,
    Hit,
    counted,
    idioms_for_line,
    load_baseline,
    main,
    scan_text,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
LINT_REL = "scripts/docs/asvs_tally_lint.py"
BASELINE = REPO_ROOT / "scripts" / "docs" / "asvs_tally_baseline.txt"


def idioms(line: str) -> set[str]:
    return {name for name, _ in idioms_for_line(line)}


# --------------------------------------------------------------------------------------------
# Positive: every idiom fires on the shape it was derived from.
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("shape", "line", "expected"),
    [
        # The tuple the previous attempt did catch. Kept so a refactor cannot lose it.
        ("slash tuple, tight", "ASVS score synced to 212/0/0/133 (#425).", "SLASH_RUN"),
        ("slash tuple, spaced", "current scorecard **189 / 20 / 3 / 133**", "SLASH_RUN"),
        # A Markdown table row. The old idiom set could not see this shape AT ALL -- and it is the
        # shape the one correct record is written in.
        ("table row", "| + all remaining build cells | 271 | 13 | 0 | 61 | 345 |", "TABLE_ROW"),
        ("table row, no total column", "| Posture A | 179 | 51 | 5 | 110 |", "TABLE_ROW"),
        # Labelled verdicts. Three distinct classes, in the several ways the corpus writes them.
        (
            "labelled, slash-separated",
            "168 pass / 105 partial / 3 fail / 65 na / 4 needs-review",
            "LABELLED_VERDICTS",
        ),
        (
            "labelled, abbreviated columns",
            "Posture A 175 P / 50 Part / 2 Fail / 118 N/A",
            "LABELLED_VERDICTS",
        ),
        # THE ONE-IN-EIGHT MISS. Markdown emphasis sits between the number and the word, and a
        # detector using a bare `\\s*` walks straight past it.
        (
            "labelled, backticked verdict words",
            "**24 `pass`, 15 `partial`, 5 `na`, zero `fail`.**",
            "LABELLED_VERDICTS",
        ),
        (
            "labelled, bolded verdict words",
            "**19 pass, 8 na, 2 needs-review, 0 partial, 0 fail**",
            "LABELLED_VERDICTS",
        ),
        # A count stated against the corpus total.
        (
            "against total, slash",
            f"Combined survey is now 316/{CORPUS_TOTAL} verified",
            "AGAINST_TOTAL",
        ),
        (
            "against total, prose",
            f"205 of those {CORPUS_TOTAL} cells rest on an assumption",
            "AGAINST_TOTAL",
        ),
        (
            "against total, zero",
            f"the re-verification is done: 0 of {CORPUS_TOTAL} cells remain",
            "AGAINST_TOTAL",
        ),
        # Arithmetic that closes to the total.
        ("arithmetic", f"`195 + 89 + 0 + 61 = {CORPUS_TOTAL}`", "ARITHMETIC"),
        ("arithmetic, two terms", f"`205 + 140 = {CORPUS_TOTAL}`", "ARITHMETIC"),
    ],
)
def test_each_idiom_reds_the_shape_it_was_derived_from(
    shape: str, line: str, expected: str
) -> None:
    got = idioms(line)
    assert expected in got, (
        f"{shape}: expected {expected}, got {sorted(got) or 'nothing'} for {line!r}"
    )


# --------------------------------------------------------------------------------------------
# Negative controls. These are not decoration: the measured failure of the previous attempt was 73
# false hits, all from notation that merely LOOKS like a tally.
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("why", "line"),
    [
        ("HL7 field notation", "ones: PID-3/4/18 (`MRN`/`ID`), PID-19 (`SSN`), PID-5/6/9 (`NAME`)"),
        ("HL7 field notation", "Routing usually needs only MSH-9/10/12, yet `hl7.parse` walks"),
        ("X12 transaction sets", "A business **271/277/278** returned by the partner"),
        ("HTTP status codes", "**DENY** (403 / 401 / 400 / 409 / refused connection)"),
        ("config defaults", "| retry_backoff_seconds | num | 5 / 2 / 300 | exponential backoff |"),
        ("FIPS document numbers", "Monitor NIST PQC (FIPS 203/204/205)."),
        ("cache sizes", "| OIDC pending flows | 512 / 16 / 300 s | 300 s TTL |"),
        ("test counts", "9/9/9 (sqlite/ss/pg) + SS store 73 + PG store 81"),
        ("a version string", "Compatible with 1/2/3 of the published profiles"),
        # Corpus STRUCTURE is a pinned constant. It does not go stale, so flagging it is noise --
        # and flagging it is what made the previous attempt red the method document.
        (
            "corpus size",
            f"a self-assessment against OWASP ASVS 5.0 Level 3 ({CORPUS_TOTAL} requirements)",
        ),
        ("corpus structure", f"{CORPUS_TOTAL} requirements total: 253 L1+L2, 92 L3-only."),
        (
            "corpus structure",
            f"A test asserts every one of the {CORPUS_TOTAL} ids appears exactly once",
        ),
        ("corpus structure", f"Populating {CORPUS_TOTAL} cells is real work."),
        # The method document's worked example is a LETTER, not a count.
        ("the method doc's own template", f'The honest phrasing is "N of {CORPUS_TOTAL} verified"'),
        # Two co-occurring counts happen in ordinary prose; three do not.
        ("two classes only", "12 pass and 4 fail in that chapter"),
    ],
)
def test_the_lint_stays_silent_on_notation_that_only_looks_like_a_tally(
    why: str, line: str
) -> None:
    got = idioms(line)
    assert not got, f"false positive ({why}): {sorted(got)} on {line!r}"


def test_a_sum_that_misses_the_total_is_not_a_whole_corpus_tally() -> None:
    """The sum test is the whole discriminator, so prove it discriminates in both directions."""
    assert idioms("scores were 212/0/0/133") == {"SLASH_RUN"}, "212+0+0+133 == 345 must red"
    assert idioms("scores were 212/0/0/134") == set(), "212+0+0+134 == 346 must not red"
    assert idioms("scores were 212/0/0/132") == set(), "212+0+0+132 == 344 must not red"


def test_the_negative_control_corpus_is_not_trivially_empty() -> None:
    """A pattern that cannot occur must return zero -- and the machinery must still be live.

    An empty or broken pattern set returns zero on everything, which is numerically identical to a
    clean run. So assert BOTH halves on the same call path: nothing on text that cannot be a tally,
    and something on text that must be.
    """
    impossible = "ZZQQ this line contains no numbers and no verdict words at all"
    assert idioms(impossible) == set()
    assert idioms("212/0/0/133") == {"SLASH_RUN"}


# --------------------------------------------------------------------------------------------
# The baseline ratchet.
# --------------------------------------------------------------------------------------------


def test_this_repo_is_clean_against_its_own_frozen_baseline(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = main(["docs", "--repo", str(REPO_ROOT), "--baseline", str(BASELINE)])
    out = capsys.readouterr().out
    print(out)
    assert "SCANNED:" in out, "the lint must report what it scanned, not only what it found"
    assert rc == 0, f"docs/ carries a new hard-coded ASVS tally:\n{out}"


def test_the_baseline_is_not_empty_and_parses() -> None:
    """A baseline that silently failed to load would make every existing tally look NEW -- or, with
    the comparison the other way round, make the gate vacuous. Assert it is actually populated."""
    baseline = load_baseline(BASELINE)
    assert len(baseline) >= 10, f"baseline looks truncated: {len(baseline)} claims"
    assert all(n >= 1 for n in baseline.values())
    assert all(k.count("\t") == 2 for k in baseline), "every key is path/idiom/token"


def test_a_malformed_baseline_line_is_refused_rather_than_ignored(tmp_path: Path) -> None:
    bad = tmp_path / "b.txt"
    bad.write_text("docs/x.md\tSLASH_RUN\t1/2/3\n", encoding="utf-8")
    with pytest.raises(ValueError, match="malformed baseline line"):
        load_baseline(bad)


def test_the_baseline_grandfathers_only_the_recorded_number_of_occurrences(tmp_path: Path) -> None:
    """One extra copy of an already-grandfathered tally is a NEW tally."""
    doc = tmp_path / "docs" / "d.md"
    doc.parent.mkdir(parents=True)
    doc.write_text("score 212/0/0/133 here\n", encoding="utf-8")
    base = tmp_path / "b.txt"
    base.write_text("docs/d.md\tSLASH_RUN\t212/0/0/133\t1\n", encoding="utf-8")
    assert main(["docs", "--repo", str(tmp_path), "--baseline", str(base)]) == 0

    doc.write_text("score 212/0/0/133 here\nand again 212/0/0/133\n", encoding="utf-8")
    assert main(["docs", "--repo", str(tmp_path), "--baseline", str(base)]) == 1


def test_the_baseline_may_only_shrink(tmp_path: Path) -> None:
    """Removing a tally without lowering its baseline entry FAILS, so the ratchet cannot idle."""
    doc = tmp_path / "docs" / "d.md"
    doc.parent.mkdir(parents=True)
    doc.write_text("nothing to see here\n", encoding="utf-8")
    base = tmp_path / "b.txt"
    base.write_text("docs/d.md\tSLASH_RUN\t212/0/0/133\t1\n", encoding="utf-8")
    rc = main(["docs", "--repo", str(tmp_path), "--baseline", str(base)])
    assert rc == 1, "a baseline entry that over-counts the tree must fail"


def test_a_new_tally_in_a_clean_tree_fails(tmp_path: Path) -> None:
    doc = tmp_path / "docs" / "d.md"
    doc.parent.mkdir(parents=True)
    doc.write_text("prose with no tally\n", encoding="utf-8")
    assert main(["docs", "--repo", str(tmp_path)]) == 0
    doc.write_text("prose with no tally\nposture is 189 / 20 / 3 / 133 today\n", encoding="utf-8")
    assert main(["docs", "--repo", str(tmp_path)]) == 1


def test_the_allowlist_exempts_the_rendered_record(tmp_path: Path) -> None:
    """``ASVS-CURRENT.md`` IS the rendered record; a tally there is the point, not a defect."""
    doc = tmp_path / "docs" / "security" / "ASVS-CURRENT.md"
    doc.parent.mkdir(parents=True)
    doc.write_text("| pass | partial | fail | na |\n| 168 | 105 | 3 | 69 |\n", encoding="utf-8")
    assert main(["docs", "--repo", str(tmp_path)]) == 1, "without the allowlist it must red"
    assert (
        main(["docs", "--repo", str(tmp_path), "--allow", "docs/security/ASVS-CURRENT.md"]) == 0
    ), "with the allowlist it must pass"


# --------------------------------------------------------------------------------------------
# Bookkeeping the scan itself.
# --------------------------------------------------------------------------------------------


def test_scan_text_reports_line_numbers_and_tokens() -> None:
    hits = scan_text("docs/x.md", "a\nb 212/0/0/133 c\nd\n")
    assert hits == [Hit("docs/x.md", 2, "SLASH_RUN", "212/0/0/133", "b 212/0/0/133 c")]
    assert counted(hits) == {"docs/x.md\tSLASH_RUN\t212/0/0/133": 1}


def test_the_key_ignores_prose_around_the_tally_but_not_the_numbers() -> None:
    """Editing the sentence must not invalidate a grandfathered entry; editing the TALLY must."""
    a = scan_text("docs/x.md", "the score was 212/0/0/133 at the time\n")[0]
    b = scan_text("docs/x.md", "score: 212/0/0/133\n")[0]
    c = scan_text("docs/x.md", "the score was 189/20/3/133 at the time\n")[0]
    assert a.key() == b.key()
    assert a.key() != c.key()


def test_the_lint_runs_as_a_bare_script(tmp_path: Path) -> None:
    """Same mirror contract as the verifier: stdlib only, no install, from an unrelated cwd."""
    cmd = [sys.executable, "-I", "-S", str(REPO_ROOT / LINT_REL), "--help"]
    print(f"SCANNED: {' '.join(cmd)} (cwd={tmp_path})")
    proc = subprocess.run(cmd, cwd=tmp_path, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, f"rc={proc.returncode}\n{proc.stderr}"
    assert "--baseline" in proc.stdout


# --- emphasis versus quotation: a backticked SPAN is a mention, not a use ------------------------
#
# The lint red on docs/BACKLOG.md #1012, whose closing banner QUOTES the falsification transcript
# proving the bug it fixed. A lint against stale tallies fired on a demonstration that a tally was
# wrong. These pin the distinction in both directions, because the fix is only correct if it keeps
# every real idiom firing.


def test_a_wholly_quoted_tally_is_a_quotation_not_an_assertion() -> None:
    """Number AND verdict word inside ONE code span -> the document is quoting, not claiming."""
    line = (
        "reproduces the defect in miniature -- `scanned 3 cells "
        "(1 pass / 0 partial / 0 fail / 0 na / 1 unverified)`, components 2 against a stated 3."
    )
    assert idioms_for_line(line) == []


def test_backticks_decorating_individual_words_are_still_a_real_tally() -> None:
    """The case the fix must NOT break, and the reason wholesale span-stripping is wrong.

    Here the NUMBERS sit outside the spans and the backticks decorate only the verdict words -- the
    V6 chapter report's own idiom, and the reason `_EMPH` tolerates backticks at all. Stripping code
    spans would delete exactly the words that make this matchable.
    """
    idioms = idioms_for_line("the V6 report: 24 `pass`, 15 `partial`, 5 `na`")
    assert [i for i, _ in idioms] == ["LABELLED_VERDICTS"]


def test_an_unquoted_tally_is_unaffected() -> None:
    assert [
        i for i, _ in idioms_for_line("168 pass / 105 partial / 3 fail / 65 na / 4 needs-review")
    ] == ["LABELLED_VERDICTS"]


def test_a_backticked_arithmetic_tally_still_fires() -> None:
    """ARITHMETIC's own documented examples are backticked REAL tallies, so the quotation rule must
    not reach them -- it is scoped to the counted-verdict pairs alone."""
    assert [i for i, _ in idioms_for_line("closes: `195 + 89 + 0 + 61 = 345`")] == ["ARITHMETIC"]

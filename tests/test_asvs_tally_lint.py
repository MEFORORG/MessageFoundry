# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.docs.asvs_tally_lint import (
    CORPUS_TOTAL,
    EmptyScan,
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
    # A second, tally-free document, so the allowlisted run still reads one file: a run that
    # allowlists EVERY file it found has scanned nothing, which is an error of its own (below).
    (tmp_path / "docs" / "other.md").write_text("prose with no tally\n", encoding="utf-8")
    assert main(["docs", "--repo", str(tmp_path)]) == 1, "without the allowlist it must red"
    assert (
        main(["docs", "--repo", str(tmp_path), "--allow", "docs/security/ASVS-CURRENT.md"]) == 0
    ), "with the allowlist it must pass"


# --------------------------------------------------------------------------------------------
# Examining nothing is an error, never a clean run (BACKLOG #5469).
# --------------------------------------------------------------------------------------------


def _tree(tmp_path: Path, text: str = "prose with no tally\n") -> Path:
    doc = tmp_path / "docs" / "d.md"
    doc.parent.mkdir(parents=True, exist_ok=True)
    doc.write_text(text, encoding="utf-8")
    return doc


def test_a_scan_of_zero_files_is_an_error_not_a_clean_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "docs").mkdir()
    assert main(["docs", "--repo", str(tmp_path)]) == 2, "an empty root must not pass"
    assert "ZERO non-blank markdown files" in capsys.readouterr().out
    # Control: the same tree with one tally-free document is a clean run, exit 0.
    _tree(tmp_path)
    assert main(["docs", "--repo", str(tmp_path)]) == 0


def test_a_root_that_does_not_exist_is_an_error_not_a_clean_run(tmp_path: Path) -> None:
    _tree(tmp_path)
    assert main(["doc", "--repo", str(tmp_path)]) == 2, "a misspelt root must not pass"


def test_a_misspelt_root_beside_a_good_one_is_still_an_error(tmp_path: Path) -> None:
    _tree(tmp_path)
    assert main(["docs", "--repo", str(tmp_path)]) == 0, "control: the good root alone passes"
    assert main(["docs", "doc-typo", "--repo", str(tmp_path)]) == 2


def test_a_wholly_allowlisted_scan_is_an_error_not_a_clean_run(tmp_path: Path) -> None:
    _tree(tmp_path)
    assert main(["docs", "--repo", str(tmp_path), "--allow", "docs/"]) == 2


def test_a_missing_baseline_file_is_an_error_not_an_empty_baseline(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _tree(tmp_path)
    rc = main(["docs", "--repo", str(tmp_path), "--baseline", str(tmp_path / "nope.txt")])
    assert rc == 2
    assert "does not exist" in capsys.readouterr().out


@pytest.mark.parametrize("content", ["", "\n\n", "  \n"], ids=["zero-byte", "blank", "spaces"])
def test_a_baseline_with_no_content_is_an_error(tmp_path: Path, content: str) -> None:
    """The zero-byte case is what a refused generating run leaves behind, since the shell truncates
    the redirect target before the program starts. Omitting --baseline is the explicit form."""
    _tree(tmp_path)
    base = tmp_path / "b.txt"
    base.write_text(content, encoding="utf-8")
    with pytest.raises(EmptyScan, match="is empty"):
        load_baseline(base)
    assert main(["docs", "--repo", str(tmp_path), "--baseline", str(base)]) == 2
    assert main(["docs", "--repo", str(tmp_path)]) == 0, "omitting --baseline still scans"


def test_a_header_only_baseline_is_the_ratchets_end_state_and_loads(tmp_path: Path) -> None:
    """Every tally retired leaves a `#` header and zero claims. That must stay a passing gate, or
    following the shrink rule to its end would red a clean tree."""
    _tree(tmp_path)
    base = tmp_path / "b.txt"
    base.write_text("# Grandfathered ASVS tallies\n# Format: path TAB idiom TAB token\n", "utf-8")
    assert load_baseline(base) == {}
    assert main(["docs", "--repo", str(tmp_path), "--baseline", str(base)]) == 0
    # Control: the same baseline against a tree that holds a tally fails as NEW, exit 1.
    _tree(tmp_path, "score 212/0/0/133 here\n")
    assert main(["docs", "--repo", str(tmp_path), "--baseline", str(base)]) == 1


def test_a_baseline_path_that_is_a_directory_says_so(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _tree(tmp_path)
    assert main(["docs", "--repo", str(tmp_path), "--baseline", str(tmp_path / "docs")]) == 2
    assert "is a directory, not a file" in capsys.readouterr().out


def test_a_malformed_baseline_is_exit_2_not_the_exit_1_of_a_finding(tmp_path: Path) -> None:
    _tree(tmp_path)
    base = tmp_path / "b.txt"
    base.write_text("x\n", encoding="utf-8")
    assert main(["docs", "--repo", str(tmp_path), "--baseline", str(base)]) == 2


@pytest.mark.parametrize(
    "line",
    ["docs/d.md\t1", "docs/d.md\tSLASH_RUN\t212/0/0/133\textra\t1", "docs/d.md\tSLASH_RUN\t²"],
    ids=["too-few-fields", "too-many-fields", "non-ascii-digit"],
)
def test_a_baseline_line_with_the_wrong_shape_is_refused(tmp_path: Path, line: str) -> None:
    base = tmp_path / "b.txt"
    base.write_text(line + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="malformed baseline line"):
        load_baseline(base)


def test_an_unreadable_baseline_is_exit_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _tree(tmp_path)
    base = tmp_path / "b.txt"
    base.write_text("docs/d.md\tSLASH_RUN\t212/0/0/133\t1\n", encoding="utf-8")

    def refuse(self: Path) -> bytes:
        raise PermissionError(13, "Permission denied", str(self))

    monkeypatch.setattr(Path, "read_bytes", refuse)
    assert main(["docs", "--repo", str(tmp_path), "--baseline", str(base)]) == 2


def test_a_bom_only_baseline_is_empty_not_a_loaded_baseline(tmp_path: Path) -> None:
    """What a PowerShell `Out-File -Encoding utf8` writes when its pipeline was empty."""
    _tree(tmp_path)
    base = tmp_path / "b.txt"
    base.write_bytes(b"\xef\xbb\xbf\r\n")
    with pytest.raises(EmptyScan, match="is empty"):
        load_baseline(base)


def test_the_generated_header_names_the_flags_that_reproduce_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _tree(tmp_path)
    allow = "docs/security/ASVS-CURRENT.md"
    main(["docs", "--repo", str(tmp_path), "--allow", allow, "--print-keys"])
    assert f"asvs_tally_lint.py docs --allow {allow} --print-keys" in capsys.readouterr().out


def test_a_utf16_baseline_is_refused_as_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """What a Windows PowerShell 5.1 `>` redirect writes."""
    _tree(tmp_path, "score 212/0/0/133 here\n")
    base = tmp_path / "b.txt"
    base.write_text("docs/d.md\tSLASH_RUN\t212/0/0/133\t1\n", encoding="utf-16")
    assert main(["docs", "--repo", str(tmp_path), "--baseline", str(base)]) == 2
    assert "UTF-16" in capsys.readouterr().out


def test_a_utf8_bom_does_not_fuse_onto_the_first_key(tmp_path: Path) -> None:
    _tree(tmp_path, "score 212/0/0/133 here\n")
    base = tmp_path / "b.txt"
    base.write_text("docs/d.md\tSLASH_RUN\t212/0/0/133\t1\n", encoding="utf-8-sig")
    assert load_baseline(base) == {"docs/d.md\tSLASH_RUN\t212/0/0/133": 1}
    assert main(["docs", "--repo", str(tmp_path), "--baseline", str(base)]) == 0


def test_a_tree_of_empty_files_is_an_error_not_a_clean_run(tmp_path: Path) -> None:
    _tree(tmp_path, "")
    assert main(["docs", "--repo", str(tmp_path)]) == 2
    # Control: one character of prose makes it a clean run.
    _tree(tmp_path, "x\n")
    assert main(["docs", "--repo", str(tmp_path)]) == 0


def test_print_keys_stdout_loads_as_a_baseline_and_round_trips(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _tree(tmp_path, "score 212/0/0/133 here\n| Posture | 179 | 51 | 5 | 110 |\nagain 212/0/0/133\n")
    rc = main(["docs", "--repo", str(tmp_path), "--print-keys"])
    captured = capsys.readouterr()
    assert rc == 1, "against no baseline every tally is NEW, so the generating run exits 1"
    assert "SCANNED:" in captured.err and "FOUND:" in captured.err, "the inventory still prints"
    assert "SCANNED" not in captured.out and "FOUND" not in captured.out
    assert captured.out.startswith("# "), "the artifact describes itself"
    assert [ln for ln in captured.out.splitlines() if not ln.startswith("#")] == [
        "docs/d.md\tSLASH_RUN\t212/0/0/133\t2",
        "docs/d.md\tTABLE_ROW\t179|51|5|110\t1",
    ]

    base = tmp_path / "b.txt"
    base.write_text(captured.out, encoding="utf-8")
    assert load_baseline(base) == {
        "docs/d.md\tSLASH_RUN\t212/0/0/133": 2,
        "docs/d.md\tTABLE_ROW\t179|51|5|110": 1,
    }
    assert main(["docs", "--repo", str(tmp_path), "--baseline", str(base)]) == 0
    assert "OK: no new" in capsys.readouterr().out, "the gate run still reports on stdout"


def test_print_keys_round_trips_through_a_subprocess_stdout_file(tmp_path: Path) -> None:
    """The documented command as a child whose stdout IS the file, then the gate run on it.

    No shell is involved, so this does not measure a shell's own re-encoding of a redirect; the
    UTF-16 case a Windows PowerShell 5.1 redirect produces is pinned separately above.
    """
    _tree(tmp_path, "score 212/0/0/133 here\n")
    base = tmp_path / "b.txt"
    lint = str(REPO_ROOT / LINT_REL)
    with base.open("w", encoding="utf-8") as fh:
        gen = subprocess.run(
            [sys.executable, lint, "docs", "--repo", str(tmp_path), "--print-keys"],
            stdout=fh,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
    assert gen.returncode == 1, gen.stderr
    assert "SCANNED:" in gen.stderr
    check = subprocess.run(
        [sys.executable, lint, "docs", "--repo", str(tmp_path), "--baseline", str(base)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert check.returncode == 0, check.stdout + check.stderr


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


def test_a_finding_carrying_a_glyph_survives_a_cp1252_console(tmp_path: Path) -> None:
    """BACKLOG #1221: the gate prints DOCUMENT CONTENT, so a hit whose line carries a glyph used to
    kill the run with UnicodeEncodeError before the finding could be read.

    The defect is invisible until the gate has something to say: against a clean corpus it exits 0
    and looks healthy, so it failed exactly when it was needed.

    Driven as a SUBPROCESS with PYTHONIOENCODING=cp1252, deliberately. Forcing the encoding
    in-process is NOT the same instrument -- pytest's capture wrapper is one of the objects the
    hardening explicitly guards against (it may lack `reconfigure` or reject it), so an in-process
    test could pass having measured nothing at all. A child process gets a real stream.

    PYTHONIOENCODING is set without an error handler, so the child starts at errors='strict' and only
    the hardening can save it -- which is what makes this a test of the fix rather than of the
    environment.
    """
    doc = tmp_path / "docs"
    doc.mkdir()
    # A NEW (ungrandfathered) tally whose line also carries a non-cp1252 codepoint.
    (doc / "x.md").write_text("Score moved 205 of 345 cells \u2192 re-scored.\n", encoding="utf-8")

    cmd = [sys.executable, str(REPO_ROOT / LINT_REL), "--repo", str(tmp_path), "docs"]
    print(f"SCANNED: {' '.join(cmd)} with PYTHONIOENCODING=cp1252")
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "PYTHONIOENCODING": "cp1252"},
    )

    assert "UnicodeEncodeError" not in proc.stderr, (
        "the gate died printing its own finding on a cp1252 console -- the defect is that this "
        f"happens only when the gate has something to say:\n{proc.stderr}"
    )
    assert proc.returncode == 1, f"expected the ungrandfathered tally to FAIL; rc={proc.returncode}"
    # The finding is readable: path, line and the matched token all survive the lossy re-encode.
    assert "docs/x.md:1" in proc.stdout
    assert "AGAINST_TOTAL" in proc.stdout

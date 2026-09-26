# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Does the restatement report find a claim repeated where no anchor looks, and only there?

BACKLOG #1396. The measured instance: a document fixed at the lines its anchors cited kept a wrong
statement of the same rule a few hundred lines EARLIER, where a reader meets it first. The arms:

* **positive control** -- a planted early contradiction must be listed as EARLY. Every other arm
  rests on this one, because a report that lists nothing is also what a broken search prints;
* **clean case** -- a key that appears only on its anchored line yields no restatement at all;
* **the limits are counted, not hidden** -- a keyless anchored line, a too-common key and an
  unresolved anchor all show up in the totals, so a short list cannot pass for full coverage;
* **no requirement identifier** -- a sentinel row id appears in no output, refusals included;
* **unknown is not zero** -- a missing record, a root that contains it, and a record with no prose
  anchor all exit 2 and print no totals.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# Package-qualified, as pyproject's mypy override asks of any new import. The module puts its own
# directory on sys.path when it loads, so its bare sibling imports resolve as they do in the vault.
from scripts.asvs.restatement_report import EARLY, LATER, census, claim_keys
from scripts.asvs.restatement_report import main as report_main
from scripts.asvs.scorecard import load_scorecard

SENTINEL_ID = "ZZ.SENTINEL.9"
SECOND_ID = "ZZ.SENTINEL.8"
NL = "\n"

#: The anchored, CORRECT statement. Its key is what the search looks for.
ANCHORED = "MFA is enforced for every account while `[security].require_mfa` is on (the default)."
#: The planted, WRONG, earlier statement of the same rule -- the shape the item measured.
EARLY_WRONG = "Only the Administrator must use MFA; set `[security].require_mfa` to widen it."


def _doc(*, early: str | None = EARLY_WRONG, later: str | None = None) -> str:
    lines = ["# Security", "", early or "Intro text.", "", "## MFA", "", ANCHORED, ""]
    lines.append(later or "Closing text.")
    return NL.join(lines) + NL


def _write(engine: Path, *lines: str) -> None:
    (engine / "docs" / "SEC.md").write_text(NL.join(lines) + NL, encoding="utf-8")


Entry = tuple[str, int, str]


def _record(path: Path, *entries: Entry, second: tuple[Entry, ...] = ()) -> Path:
    """A loadable record: one row citing ``entries``, and a second row citing ``second`` if given."""
    body = ["[scorecard]", 'anchor_commit = "0000000"']
    for cell_id, cited in ((SENTINEL_ID, entries), (SECOND_ID, second)):
        if not cited:
            continue
        body += ["", "[[cell]]", f'id = "{cell_id}"', "level = 1", 'verdict = "pass"']
        body.append('last_verified = "2026-09-26"')
        for doc, line, expect in cited:
            body += ["", "[[cell.evidence]]", f'path = "{doc}"', f"line = {line}"]
            body.append(f"expect = {json.dumps(expect)}")
    path.write_text(NL.join(body) + NL, encoding="utf-8")
    return path


@pytest.fixture
def engine(tmp_path: Path) -> Path:
    root = tmp_path / "engine"
    (root / "docs").mkdir(parents=True)
    return root


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    code = report_main(argv)
    captured = capsys.readouterr()
    return code, captured.out + captured.err


def _found(record: Path, engine: Path, max_hits: int = 3) -> set[tuple[int, str, str]]:
    result = census(load_scorecard(record), engine, max_hits=max_hits)
    return {(f.line, f.key, f.position) for f in result.findings.values()}


def test_a_planted_early_contradiction_is_reported(
    engine: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """THE POSITIVE CONTROL. The wrong statement sits before the anchor, so it must read EARLY."""
    (engine / "docs" / "SEC.md").write_text(_doc(), encoding="utf-8")
    record = _record(tmp_path / "r.toml", ("docs/SEC.md", 7, ANCHORED))
    code, out = _run(["--scorecard", str(record), "--root", str(engine)], capsys)
    assert code == 0
    assert "EARLY restatements            : 1" in out
    assert "EARLY  docs/SEC.md:3  restates `[security].require_mfa`  (anchored at :7)" in out
    assert out.startswith("# asvs-restatement-report scorecard=sha256:")
    assert SENTINEL_ID not in out


def test_a_key_only_on_its_anchored_line_yields_nothing(engine: Path, tmp_path: Path) -> None:
    """THE CLEAN CASE, which is what makes the positive control mean something."""
    (engine / "docs" / "SEC.md").write_text(_doc(early=None), encoding="utf-8")
    record = _record(tmp_path / "r.toml", ("docs/SEC.md", 7, ANCHORED))
    result = census(load_scorecard(record), engine, max_hits=3)
    assert result.findings == {}
    assert result.anchored == {("docs/SEC.md", 7)}
    assert result.keyless == set()
    assert result.unresolved == 0


def test_a_restatement_after_the_anchor_is_later(engine: Path, tmp_path: Path) -> None:
    doc = _doc(early=None, later="Turn `[security].require_mfa` off to opt out.")
    (engine / "docs" / "SEC.md").write_text(doc, encoding="utf-8")
    record = _record(tmp_path / "r.toml", ("docs/SEC.md", 7, ANCHORED))
    assert _found(record, engine) == {(9, "[security].require_mfa", LATER)}


def test_early_is_judged_against_the_keys_own_anchor(engine: Path, tmp_path: Path) -> None:
    """A wrong line before its OWN claim's anchor is EARLY, even after an unrelated first anchor."""
    _write(engine, "first `k_aaa`", "", "wrong `k_bbb`", "", "right `k_bbb`")
    record = _record(
        tmp_path / "r.toml",
        ("docs/SEC.md", 1, "first `k_aaa`"),
        ("docs/SEC.md", 5, "right `k_bbb`"),
    )
    assert _found(record, engine) == {(3, "k_bbb", EARLY)}


def test_the_rows_own_anchored_lines_are_never_findings(engine: Path, tmp_path: Path) -> None:
    """The early line is ALSO anchored by the same row, so somebody looked there: no finding."""
    (engine / "docs" / "SEC.md").write_text(_doc(), encoding="utf-8")
    record = _record(
        tmp_path / "r.toml", ("docs/SEC.md", 3, EARLY_WRONG), ("docs/SEC.md", 7, ANCHORED)
    )
    assert _found(record, engine) == set()


def test_a_line_two_rows_reach_is_listed_once_and_early_wins(engine: Path, tmp_path: Path) -> None:
    """The row read FIRST anchors line 1, so line 2 is LATER for it; the row read second anchors
    line 5, so line 2 is EARLY for it. The later EARLY must replace the earlier LATER."""
    _write(engine, "intro `k_one`", "restated `k_one`", "", "", "row two `k_one`")
    record = _record(
        tmp_path / "r.toml",
        ("docs/SEC.md", 1, "intro `k_one`"),
        second=(("docs/SEC.md", 5, "row two `k_one`"),),
    )
    result = census(load_scorecard(record), engine, max_hits=3)
    at_two = [f for f in result.findings.values() if f.line == 2]
    assert [f.position for f in at_two] == [EARLY]
    assert len(result.anchored) == 2


@pytest.mark.parametrize(
    ("key", "longer"),
    [
        ("require_mfa", "require_mfa_for_admins"),
        ("--max-hits", "--max-hits-x"),
        ("a.b_key", "a.b_key.c"),
        ("/security/posture", "/security/posture/x"),
    ],
)
def test_a_key_inside_a_longer_identifier_is_not_a_restatement(
    key: str, longer: str, engine: Path, tmp_path: Path
) -> None:
    _write(engine, f"see `{longer}`", "", f"anchor `{key}`")
    record = _record(tmp_path / "r.toml", ("docs/SEC.md", 3, f"anchor `{key}`"))
    assert _found(record, engine) == set()


def test_a_key_ending_a_sentence_still_matches(engine: Path, tmp_path: Path) -> None:
    _write(engine, "Set k_one.", "", "anchor `k_one`")
    record = _record(tmp_path / "r.toml", ("docs/SEC.md", 3, "anchor `k_one`"))
    assert _found(record, engine) == {(1, "k_one", EARLY)}


def test_a_leading_newline_does_not_claim_the_previous_line(engine: Path, tmp_path: Path) -> None:
    _write(engine, "prev `k_aaa`", "line two `k_bbb`", "later `k_aaa`")
    record = _record(tmp_path / "r.toml", ("docs/SEC.md", 2, NL + "line two `k_bbb`"))
    result = census(load_scorecard(record), engine, max_hits=3)
    assert result.anchored == {("docs/SEC.md", 2)}
    assert result.findings == {}


def test_early_only_hides_later_lines_but_not_their_count(
    engine: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    doc = _doc(later="Turn `[security].require_mfa` off to opt out.")
    (engine / "docs" / "SEC.md").write_text(doc, encoding="utf-8")
    record = _record(tmp_path / "r.toml", ("docs/SEC.md", 7, ANCHORED))
    code, out = _run(["--scorecard", str(record), "--root", str(engine), "--early-only"], capsys)
    assert code == 0
    assert "LATER restatements            : 1" in out
    assert "EARLY  docs/SEC.md:3" in out
    assert "LATER  docs/SEC.md:9" not in out


def test_an_unreadable_record_is_refused_without_naming_its_row(
    engine: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The reader's own diagnostic names the row it rejected. The refusal must not repeat it."""
    # The document exists, so the only thing that can refuse here is the record's reader.
    (engine / "docs" / "SEC.md").write_text(_doc(), encoding="utf-8")
    record = _record(tmp_path / "r.toml", ("docs/SEC.md", 7, ANCHORED))
    text = record.read_text(encoding="utf-8").replace('verdict = "pass"', 'verdict = "bogus"')
    record.write_text(text, encoding="utf-8")
    code, out = _run(["--scorecard", str(record), "--root", str(engine)], capsys)
    assert code == 2
    assert "REFUSING" in out
    assert SENTINEL_ID not in out
    assert "bogus" not in out
    assert "nothing was searched" not in out


def test_a_max_hits_below_one_is_refused(
    engine: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    record = _record(tmp_path / "r.toml", ("docs/SEC.md", 7, ANCHORED))
    argv = ["--scorecard", str(record), "--root", str(engine), "--max-hits", "0"]
    assert _run(argv, capsys)[0] == 2


def test_blind_spots_are_counted(engine: Path, tmp_path: Path) -> None:
    """Keyless lines, too-common keys and unresolved anchors appear in the totals."""
    _write(engine, "# Security", "", "See `x_key`.", "`x_key`", "`x_key`", "Plain prose.")
    record = _record(
        tmp_path / "r.toml",
        ("docs/SEC.md", 1, "# Security"),
        ("docs/SEC.md", 3, "See `x_key`."),
        ("docs/SEC.md", 9, "a statement no longer in the file"),
        ("docs/GONE.md", 1, "anything"),
    )
    result = census(load_scorecard(record), engine, max_hits=1)
    assert result.keyless == {("docs/SEC.md", 1)}
    assert result.common == {("docs/SEC.md", "x_key")}
    assert result.unresolved == 2
    assert result.findings == {}


def test_a_multi_line_anchor_covers_every_line_it_spans(engine: Path, tmp_path: Path) -> None:
    _write(engine, "intro `k_one`", "first `k_one`", "second `k_two`", "later `k_two`")
    record = _record(tmp_path / "r.toml", ("docs/SEC.md", 2, "first `k_one`" + NL + "second"))
    assert _found(record, engine) == {(1, "k_one", EARLY), (4, "k_two", LATER)}


def test_a_trailing_newline_does_not_claim_the_next_line(engine: Path, tmp_path: Path) -> None:
    _write(engine, "anchor `k_one`", "next `k_zzz`")
    record = _record(tmp_path / "r.toml", ("docs/SEC.md", 1, "anchor `k_one`" + NL))
    result = census(load_scorecard(record), engine, max_hits=3)
    assert result.anchored == {("docs/SEC.md", 1)}


def test_code_paths_are_not_searched(engine: Path, tmp_path: Path) -> None:
    (engine / "mod.py").write_text("x = 1  # `k_one`" + NL + "y = 2  # `k_one`" + NL, "utf-8")
    record = _record(tmp_path / "r.toml", ("mod.py", 1, "x = 1"))
    assert census(load_scorecard(record), engine, max_hits=3).anchored == set()


def test_claim_keys_keep_backtick_pairing_around_short_spans() -> None:
    assert claim_keys("a `one` b `two` c `one` `x`") == ["one", "two"]
    assert claim_keys("set `on` to enable `[api].tls_cert_file` now") == ["[api].tls_cert_file"]


@pytest.mark.parametrize("case", ["missing", "contained", "no_prose"])
def test_an_unmeasured_run_exits_2_and_prints_no_totals(
    case: str, engine: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Unknown is not zero. None of these may print a reassuring count."""
    if case == "missing":
        record = tmp_path / "absent.toml"
    elif case == "contained":
        record = _record(engine / "r.toml", ("docs/SEC.md", 7, ANCHORED))
    else:
        (engine / "mod.py").write_text("x = 1" + NL, encoding="utf-8")
        record = _record(tmp_path / "r.toml", ("mod.py", 1, "x = 1"))
    code, out = _run(["--scorecard", str(record), "--root", str(engine)], capsys)
    assert code == 2
    assert "REFUSING" in out
    assert "restatements" not in out
    assert SENTINEL_ID not in out

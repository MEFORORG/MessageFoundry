# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Does the restatement report find a claim repeated where no anchor looks, and only there?

BACKLOG #1396. The measured instance: a document fixed at the lines its anchors cited kept a wrong
statement of the same rule a few hundred lines EARLIER, where a reader meets it first. The arms:

* **positive control** -- a planted early contradiction must be listed as EARLY. Every other arm
  rests on this one, because a report that lists nothing is also what a broken search prints;
* **clean case** -- a key that appears only on its anchored line yields no restatement at all;
* **the limits are counted, not hidden** -- a keyless anchored line and a too-common key both show up
  in the header, so a short list cannot pass for full coverage;
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

#: The anchored, CORRECT statement. Its key is what the search looks for.
ANCHORED = "MFA is enforced for every account while `[security].require_mfa` is on (the default)."
#: The planted, WRONG, earlier statement of the same rule -- the shape the item measured.
EARLY_WRONG = "Only the Administrator must use MFA; set `[security].require_mfa` to widen it."


def _doc(*, early: str | None = EARLY_WRONG, later: str | None = None) -> str:
    lines = ["# Security", "", early or "Intro text.", "", "## MFA", "", ANCHORED, ""]
    lines.append(later or "Closing text.")
    return "\n".join(lines) + "\n"


def _record(path: Path, *entries: tuple[str, int, str]) -> Path:
    body = [
        "[scorecard]",
        'anchor_commit = "0000000"',
        "",
        "[[cell]]",
        f'id = "{SENTINEL_ID}"',
        "level = 1",
        'verdict = "pass"',
        'last_verified = "2026-09-26"',
    ]
    for doc, line, expect in entries:
        body += ["", "[[cell.evidence]]", f'path = "{doc}"', f"line = {line}"]
        body.append(f"expect = {json.dumps(expect)}")
    path.write_text("\n".join(body) + "\n", encoding="utf-8")
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
    assert SENTINEL_ID not in out


def test_a_key_only_on_its_anchored_line_yields_nothing(engine: Path, tmp_path: Path) -> None:
    """THE CLEAN CASE, which is what makes the positive control mean something."""
    (engine / "docs" / "SEC.md").write_text(_doc(early=None), encoding="utf-8")
    record = _record(tmp_path / "r.toml", ("docs/SEC.md", 7, ANCHORED))
    result = census(load_scorecard(record), engine, max_hits=3)
    assert result.findings == set()
    assert result.anchored_lines == 1
    assert result.keyless_lines == 0


def test_a_restatement_after_the_first_anchor_is_later(engine: Path, tmp_path: Path) -> None:
    doc = _doc(early=None, later="Turn `[security].require_mfa` off to opt out.")
    (engine / "docs" / "SEC.md").write_text(doc, encoding="utf-8")
    record = _record(tmp_path / "r.toml", ("docs/SEC.md", 7, ANCHORED))
    [finding] = census(load_scorecard(record), engine, max_hits=3).findings
    assert (finding.line, finding.position) == (9, LATER)


def test_the_rows_own_anchored_lines_are_never_findings(engine: Path, tmp_path: Path) -> None:
    """The early line is ALSO anchored by the same row, so somebody looked there: no finding."""
    (engine / "docs" / "SEC.md").write_text(_doc(), encoding="utf-8")
    record = _record(
        tmp_path / "r.toml", ("docs/SEC.md", 3, EARLY_WRONG), ("docs/SEC.md", 7, ANCHORED)
    )
    assert census(load_scorecard(record), engine, max_hits=3).findings == set()


def test_keyless_lines_and_common_keys_are_counted(engine: Path, tmp_path: Path) -> None:
    """The instrument's blind spots appear in its totals rather than as a silently shorter list."""
    doc = _doc(early="See `x_key`, `x_key`.\n`x_key`\n`x_key`\nPlain prose with no key.")
    (engine / "docs" / "SEC.md").write_text(doc, encoding="utf-8")
    record = _record(
        tmp_path / "r.toml",
        ("docs/SEC.md", 1, "# Security"),
        ("docs/SEC.md", 3, "See `x_key`, `x_key`."),
    )
    result = census(load_scorecard(record), engine, max_hits=2)
    assert result.keyless_lines == 1
    assert result.common_keys == 1
    assert result.findings == set()


def test_a_multi_line_anchor_covers_every_line_it_spans(engine: Path, tmp_path: Path) -> None:
    doc = "intro `k_one`\nfirst `k_one`\nsecond `k_two`\nlater `k_two`\n"
    (engine / "docs" / "SEC.md").write_text(doc, encoding="utf-8")
    record = _record(tmp_path / "r.toml", ("docs/SEC.md", 2, "first `k_one`\nsecond"))
    found = {
        (f.line, f.key, f.position)
        for f in census(load_scorecard(record), engine, max_hits=3).findings
    }
    assert found == {(1, "k_one", EARLY), (4, "k_two", LATER)}


def test_code_paths_are_not_searched(engine: Path, tmp_path: Path) -> None:
    (engine / "mod.py").write_text("x = 1  # `k_one`\ny = 2  # `k_one`\n", encoding="utf-8")
    record = _record(tmp_path / "r.toml", ("mod.py", 1, "x = 1"))
    assert census(load_scorecard(record), engine, max_hits=3).anchored_lines == 0


def test_claim_keys_are_backticked_spans_in_order() -> None:
    assert claim_keys("a `one` b `two` c `one` `x`") == ["one", "two"]


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
        (engine / "mod.py").write_text("x = 1\n", encoding="utf-8")
        record = _record(tmp_path / "r.toml", ("mod.py", 1, "x = 1"))
    code, out = _run(["--scorecard", str(record), "--root", str(engine)], capsys)
    assert code == 2
    assert "REFUSING" in out
    assert "restatements" not in out
    assert SENTINEL_ID not in out

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the forward-only residual citation lint (``scripts/docs/asvs_residual_lint.py``).

The record this lint polices lives in the assessment repo, not here, so these run against
FIXTURES -- which is the same arrangement ``scripts/asvs/scorecard.py`` has (ADR 0156 section 7:
data-free tool, fixtures in the public repo, real data in the vault). Nothing from the real record
appears in this file.

Because the tool runs where it cannot be watched, the empty-scan behaviour is tested as hard as the
detection is. A citation lint that silently examined nothing reports exactly what a clean record
reports.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scripts.docs.asvs_residual_lint import (
    CITATION,
    Citation,
    EmptyScan,
    counted,
    load_baseline,
    load_scorecard,
    main,
    scan_cells,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
LINT_REL = "scripts/docs/asvs_residual_lint.py"


def write_scorecard(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "scorecard.toml"
    p.write_text(body, encoding="utf-8")
    return p


ONE_CELL = """
[[cell]]
id = "6.3.3"
verdict = "partial"
residual = "The gate reads messagefoundry/__main__.py:1125 but the prose says __main__.py:1917."
"""


# --------------------------------------------------------------------------------------------
# Detection, both directions.
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("why", "text", "expected"),
    [
        (
            "path-qualified",
            "see messagefoundry/config/settings.py:1359",
            [("messagefoundry/config/settings.py", "1359")],
        ),
        ("bare basename", "see settings.py:1359", [("settings.py", "1359")]),
        (
            "windows separator",
            r"see messagefoundry\auth\service.py:724",
            [(r"messagefoundry\auth\service.py", "724")],
        ),
        ("markdown doc", "docs/SECURITY.md:752 says otherwise", [("docs/SECURITY.md", "752")]),
        ("a lockfile", "requirements.lock:961 pins it", [("requirements.lock", "961")]),
        ("spaced colon", "settings.py : 1359", [("settings.py", "1359")]),
        ("two on one line", "a.py:1 and b/c.py:22", [("a.py", "1"), ("b/c.py", "22")]),
    ],
)
def test_the_citation_shapes_that_occur_are_detected(
    why: str, text: str, expected: list[tuple[str, str]]
) -> None:
    assert CITATION.findall(text) == expected, why


@pytest.mark.parametrize(
    ("why", "text"),
    [
        ("a file with no line", "see settings.py for the default"),
        ("a prose line reference", "see line 1125 of the module"),
        ("a version string", "requires Python 3.14:0 is not a citation"),
        ("a host and port", "binds 127.0.0.1:8765 by default"),
        ("a bare number", "the value is 1125"),
        ("a time", "at 06:17 daily"),
        ("an unknown extension", "image.png:12"),
        # A citation already inside a longer path token must not also match its own tail.
        ("no double-count of a suffix", "messagefoundry/config/settings.py:1359"),
    ],
)
def test_the_lint_stays_silent_on_text_that_is_not_a_citation(why: str, text: str) -> None:
    found = CITATION.findall(text)
    if why == "no double-count of a suffix":
        assert found == [("messagefoundry/config/settings.py", "1359")], why
    else:
        assert found == [], f"false positive ({why}): {found} on {text!r}"


def test_the_detector_is_live_and_the_negative_control_is_a_real_zero() -> None:
    """A broken regex returns nothing on everything, which reads exactly like a clean record."""
    assert CITATION.findall("ZZQQ nothing citation-shaped here at all") == []
    assert CITATION.findall("a/b.py:7") == [("a/b.py", "7")]


def test_a_bare_basename_is_flagged_as_naming_no_location() -> None:
    assert Citation("1.1.1", "residual", "settings.py", 5).bare is True
    assert Citation("1.1.1", "residual", "messagefoundry/config/settings.py", 5).bare is False


# --------------------------------------------------------------------------------------------
# The key, which is the design.
# --------------------------------------------------------------------------------------------


def test_the_key_ignores_the_line_number_but_not_the_file_cell_or_field() -> None:
    a = Citation("6.3.3", "residual", "__main__.py", 1917)
    repaired = Citation("6.3.3", "residual", "__main__.py", 1125)
    other_file = Citation("6.3.3", "residual", "service.py", 1917)
    other_cell = Citation("6.3.4", "residual", "__main__.py", 1917)
    other_field = Citation("6.3.3", "absence[].mutation", "__main__.py", 1917)
    assert a.key() == repaired.key(), "repairing a line must not read as a new citation"
    assert a.key() != other_file.key()
    assert a.key() != other_cell.key()
    assert a.key() != other_field.key()


def test_repairing_a_stale_line_number_is_free(tmp_path: Path) -> None:
    """The headline property: correction costs nothing, growth is refused, deletion costs an edit.

    The rejected alternative made *delete the citation* the cheapest compliant act. This makes
    *fix it* the cheapest, which is what is actually wanted from someone who just noticed it is wrong.
    """
    sc = write_scorecard(tmp_path, ONE_CELL)
    base = tmp_path / "b.txt"
    base.write_text(
        "6.3.3\tresidual\tmessagefoundry/__main__.py\t1\n6.3.3\tresidual\t__main__.py\t1\n",
        encoding="utf-8",
    )
    assert main([str(sc), "--baseline", str(base)]) == 0

    # Repair the stale line in place. No baseline edit.
    sc.write_text(ONE_CELL.replace("__main__.py:1917", "__main__.py:1125"), encoding="utf-8")
    assert main([str(sc), "--baseline", str(base)]) == 0, (
        "a repair must not require a baseline edit"
    )

    # Adding a citation to a NEW file in the same cell is refused.
    sc.write_text(ONE_CELL + "\n# and auth/service.py:724\n", encoding="utf-8")
    sc.write_text(
        ONE_CELL.replace("prose says", "prose says auth/service.py:724 and"), encoding="utf-8"
    )
    assert main([str(sc), "--baseline", str(base)]) == 1


def test_an_extra_occurrence_of_a_grandfathered_citation_is_new(tmp_path: Path) -> None:
    sc = write_scorecard(tmp_path, ONE_CELL)
    base = tmp_path / "b.txt"
    base.write_text(
        "6.3.3\tresidual\tmessagefoundry/__main__.py\t1\n6.3.3\tresidual\t__main__.py\t1\n",
        encoding="utf-8",
    )
    assert main([str(sc), "--baseline", str(base)]) == 0
    sc.write_text(ONE_CELL.rstrip('"\n') + ' Again at __main__.py:2000."\n', encoding="utf-8")
    assert main([str(sc), "--baseline", str(base)]) == 1


def test_the_baseline_may_only_shrink(tmp_path: Path) -> None:
    sc = write_scorecard(tmp_path, '[[cell]]\nid = "1.1.1"\nresidual = "no citations here."\n')
    base = tmp_path / "b.txt"
    base.write_text("1.1.1\tresidual\tsettings.py\t1\n", encoding="utf-8")
    assert main([str(sc), "--baseline", str(base)]) == 1, "an over-counting entry must fail"


def test_a_malformed_baseline_line_is_refused_rather_than_ignored(tmp_path: Path) -> None:
    bad = tmp_path / "b.txt"
    bad.write_text("1.1.1\tresidual\tsettings.py\n", encoding="utf-8")
    with pytest.raises(ValueError, match="malformed baseline line"):
        load_baseline(bad)


def test_the_documented_baseline_recipe_round_trips(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Generate a baseline the way the module docstring says to, then require it to load green.

    This is the ONE affordance the four-step wiring of BACKLOG #1205 depends on, and until this test
    it was the only affordance in the tool that nothing drove. What is frozen here is the FILTER
    RULE -- keep the four-column lines -- and not the ``awk`` invocation the docstring spells it with;
    a shell is not available to every caller and is not what can rot.
    """
    sc = write_scorecard(tmp_path, ONE_CELL)

    assert main([str(sc), "--no-baseline", "--print-keys"]) == 1, (
        "with no baseline every citation is new, so generation exits 1 by design"
    )
    printed = capsys.readouterr().out

    # THE NAIVE RECIPE IS THE CONTROL, and it is why the filter is documented rather than assumed.
    # Captured whole, that stdout carries the scan inventory and the verdict as well as the keys.
    naive = tmp_path / "naive.txt"
    naive.write_text(printed, encoding="utf-8")
    with pytest.raises(ValueError, match="malformed baseline line"):
        load_baseline(naive)

    base = tmp_path / "b.txt"
    keys = [line for line in printed.splitlines() if line.count("\t") == 3]
    assert keys, "the filter kept nothing -- that is a broken filter, not a citation-free record"
    base.write_text("".join(f"{line}\n" for line in keys), encoding="utf-8")

    assert load_baseline(base) == counted(scan_cells(load_scorecard(sc), ["residual"])[0])
    assert main([str(sc), "--baseline", str(base)]) == 0, (
        "a baseline generated from the record it grandfathers must read green on the next run"
    )


# --------------------------------------------------------------------------------------------
# Empty-scan refusal. This tool runs where nobody is watching it.
# --------------------------------------------------------------------------------------------


def test_a_scorecard_with_no_cells_is_an_error_not_a_clean_run(tmp_path: Path) -> None:
    sc = write_scorecard(tmp_path, '[scorecard]\nanchor_commit = "deadbeef"\n')
    with pytest.raises(EmptyScan, match="no \\[\\[cell\\]\\] entries"):
        load_scorecard(sc)
    assert main([str(sc), "--no-baseline"]) == 2, "must not exit 0 having examined nothing"


def test_a_field_that_resolves_to_nothing_is_an_error_not_a_clean_run(tmp_path: Path) -> None:
    """The failure that matters most: a renamed field reports 'no new citations'."""
    sc = write_scorecard(tmp_path, ONE_CELL)
    assert main([str(sc), "--no-baseline", "--field", "residuel"]) == 2
    assert main([str(sc), "--no-baseline", "--field", "residual"]) == 1


def test_a_missing_baseline_file_is_an_error_not_an_empty_baseline(tmp_path: Path) -> None:
    sc = write_scorecard(tmp_path, ONE_CELL)
    assert main([str(sc), "--baseline", str(tmp_path / "nope.txt")]) == 2
    with pytest.raises(EmptyScan, match="does not exist"):
        load_baseline(tmp_path / "nope.txt")


def test_the_run_prints_what_it_scanned(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sc = write_scorecard(tmp_path, ONE_CELL)
    main([str(sc), "--no-baseline"])
    out = capsys.readouterr().out
    assert "SCANNED: 1 cells" in out
    assert "characters of prose" in out
    assert "bare basenames" in out, "the headline defect must be counted, not just the total"


# --------------------------------------------------------------------------------------------
# Field resolution and bookkeeping.
# --------------------------------------------------------------------------------------------


def test_a_list_of_tables_field_can_be_scanned(tmp_path: Path) -> None:
    """`absence[].mutation` carries citations too, so the field spec supports that shape."""
    sc = write_scorecard(
        tmp_path,
        '[[cell]]\nid = "2.2.2"\nresidual = "clean."\n'
        '[[cell.absence]]\nmutation = "re-adding auth/service.py:99 would break it"\n',
    )
    cites, n_cells, n_chars = scan_cells(load_scorecard(sc), ["absence[].mutation"])
    assert n_cells == 1 and n_chars > 0
    assert [c.key() for c in cites] == ["2.2.2\tabsence[].mutation\tauth/service.py"]
    assert main([str(sc), "--no-baseline"]) == 0, "the default field set must not see it"
    assert main([str(sc), "--no-baseline", "--field", "absence[].mutation"]) == 1


def test_scan_and_count_report_cells_fields_and_occurrences(tmp_path: Path) -> None:
    sc = write_scorecard(tmp_path, ONE_CELL)
    cites, n_cells, n_chars = scan_cells(load_scorecard(sc), ["residual"])
    assert n_cells == 1
    assert n_chars > 0
    assert counted(cites) == {
        "6.3.3\tresidual\tmessagefoundry/__main__.py": 1,
        "6.3.3\tresidual\t__main__.py": 1,
    }


def test_the_lint_runs_as_a_bare_script(tmp_path: Path) -> None:
    """Same mirror contract as the verifier: stdlib only, no install, from an unrelated cwd."""
    cmd = [sys.executable, "-I", "-S", str(REPO_ROOT / LINT_REL), "--help"]
    print(f"SCANNED: {' '.join(cmd)} (cwd={tmp_path})")
    proc = subprocess.run(cmd, cwd=tmp_path, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, f"rc={proc.returncode}\n{proc.stderr}"
    assert "--baseline" in proc.stdout

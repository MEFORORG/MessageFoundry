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
from contextlib import nullcontext
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


def run_lint(
    tmp_path: Path, *argv: str, stdout_to: Path | None = None
) -> subprocess.CompletedProcess[str]:
    """Run the lint as the vault does: bare script, stdlib only, from an unrelated cwd.

    ``stdout_to`` reproduces the shell's ``>`` at the FILE DESCRIPTOR, which is the only way to
    observe what the documented command actually leaves on disk -- including that the shell creates
    and truncates the target before this program starts.
    """
    cmd = [sys.executable, "-I", "-S", str(REPO_ROOT / LINT_REL), *argv]
    print(f"SCANNED: {' '.join(cmd)} (cwd={tmp_path}, stdout_to={stdout_to})")
    with stdout_to.open("w", encoding="utf-8") if stdout_to else nullcontext() as fh:
        proc = subprocess.run(
            cmd,
            cwd=tmp_path,
            stdout=fh if fh else subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
    print(f"FOUND:   rc={proc.returncode}, stderr {len(proc.stderr)} bytes")
    return proc


def test_the_lint_runs_as_a_bare_script(tmp_path: Path) -> None:
    """Same mirror contract as the verifier: stdlib only, no install, from an unrelated cwd."""
    proc = run_lint(tmp_path, "--help")
    assert proc.returncode == 0, f"rc={proc.returncode}\n{proc.stderr}"
    assert "--baseline" in proc.stdout


# --------------------------------------------------------------------------------------------
# Generating the baseline with --print-keys.
#
# The docstring documents `--print-keys > <baseline.txt>`, so the artifact under test is a
# REDIRECTED STDOUT. The end-to-end arm therefore runs a real subprocess with a real fd redirect;
# the rest read the streams in-process, which is cheaper and answers the same question.
# --------------------------------------------------------------------------------------------

NO_CELLS = '[scorecard]\nanchor_commit = "deadbeef"\n'
ONE_CELL_KEYS = {
    "6.3.3\tresidual\tmessagefoundry/__main__.py": 1,
    "6.3.3\tresidual\t__main__.py": 1,
}


def test_the_documented_print_keys_command_produces_a_loadable_baseline(tmp_path: Path) -> None:
    """The step the item's remaining work names, end to end: generate, then gate with it.

    Before the stream split this failed on the FIRST line of the file it had just written -- the
    inventory shared stdout with the keys, and ``load_baseline`` refuses a line it cannot parse
    rather than skipping it. So the documented two-command workflow raised ``ValueError`` at the
    moment somebody first tried to use its own output.
    """
    sc = write_scorecard(tmp_path, ONE_CELL)
    baseline = tmp_path / "baseline.txt"
    run_lint(tmp_path, str(sc), "--print-keys", stdout_to=baseline)

    # Every line of the artifact must parse. This is the assertion that was failing.
    loaded = load_baseline(baseline)
    assert loaded == ONE_CELL_KEYS, (
        f"the generated baseline does not describe the record it came from: {loaded}"
    )

    # And the record it came from must then be GREEN against it, with no hand editing.
    assert main([str(sc), "--baseline", str(baseline)]) == 0, (
        "a freshly generated baseline must grandfather exactly what the scorecard contains"
    )


@pytest.mark.parametrize(
    ("why", "body", "baseline_lines", "expected_rc"),
    [
        # Every branch that writes a verdict, so the routing is tested as a property of the mode
        # rather than of one code path. Each of these drove a different block of main().
        ("new citations", ONE_CELL, None, 1),
        ("all grandfathered", ONE_CELL, "".join(f"{k}\t1\n" for k in ONE_CELL_KEYS), 0),
        # Grandfathers everything present PLUS one entry that is not, so the `stale` branch is the
        # only thing reddening this arm -- and the artifact still carries claims, which the
        # zero-claim refusal makes a precondition of asserting anything about its contents.
        (
            "a stale baseline entry",
            ONE_CELL,
            "".join(f"{k}\t1\n" for k in ONE_CELL_KEYS) + "6.3.3\tresidual\tghost.py\t1\n",
            1,
        ),
    ],
)
def test_stdout_carries_only_baseline_lines_whatever_the_verdict(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
    why: str,
    body: str,
    baseline_lines: str | None,
    expected_rc: int,
) -> None:
    """The invariant is the mode's, not one branch's: under --print-keys stdout is the artifact.

    Asserted by handing stdout back to ``load_baseline`` rather than by re-deriving the grammar
    here -- a second, silently different definition of the format is the failure CLAUDE.md section
    11 names for the backlog banner parser.
    """
    sc = write_scorecard(tmp_path, body)
    argv = [str(sc), "--print-keys"]
    if baseline_lines is None:
        argv.append("--no-baseline")
    else:
        base = tmp_path / "given.txt"
        base.write_text(baseline_lines, encoding="utf-8")
        argv += ["--baseline", str(base)]

    assert main(argv) == expected_rc, why
    out, err = capfd.readouterr()

    written = tmp_path / "captured.txt"
    written.write_text(out, encoding="utf-8")
    load_baseline(written)  # raises if any line of the artifact is not a baseline line

    assert "SCANNED:" not in out, f"the inventory leaked into the artifact ({why}): {out!r}"
    assert "SCANNED:" in err, f"the inventory must still be printed, on stderr ({why})"


def test_the_gate_run_still_reports_on_stdout(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Negative control against an over-broad fix.

    A change that simply moved every message to stderr would pass every test above and silently
    empty the stdout of the mode that actually gates. Without ``--print-keys`` nothing is being
    generated and nothing is redirected, so the report belongs on stdout exactly as before.
    """
    sc = write_scorecard(tmp_path, ONE_CELL)
    assert main([str(sc), "--no-baseline"]) == 1
    out, err = capfd.readouterr()
    assert "SCANNED:" in out, "gate mode must keep reporting on stdout"
    assert "FAIL:" in out
    assert err == "", f"gate mode should write no stderr; got {err!r}"


def test_an_empty_scan_writes_no_baseline_and_still_refuses(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Generation is where an empty scan would go silent, so the refusal is checked in that mode."""
    sc = write_scorecard(tmp_path, NO_CELLS)
    assert main([str(sc), "--print-keys", "--no-baseline"]) == 2
    out, err = capfd.readouterr()
    assert out == "", f"an empty scan must write no baseline lines; got {out!r}"
    assert "no [[cell]] entries" in err, "rc 2 is shared, so the message must say WHICH refusal"


def test_the_empty_file_a_refused_generation_leaves_behind_is_not_a_baseline(
    tmp_path: Path,
) -> None:
    """The redirect creates and truncates the target BEFORE the program runs.

    So a generating run that exits 2 still leaves a 0-byte file, and the next gate run would load
    it, report "0 claims" in the inventory, and grandfather nothing -- reddening every citation in
    the record while the operator debugs the wrong end. A missing baseline is refused; this must be
    refused the same way, because the shell has already turned the first into the second.
    """
    sc = write_scorecard(tmp_path, NO_CELLS)
    baseline = tmp_path / "baseline.txt"
    proc = run_lint(tmp_path, str(sc), "--print-keys", "--no-baseline", stdout_to=baseline)
    assert proc.returncode == 2
    assert baseline.is_file() and baseline.read_text(encoding="utf-8") == "", (
        "the premise of this test is that the shell leaves an EMPTY file behind"
    )

    with pytest.raises(EmptyScan, match="zero claims"):
        load_baseline(baseline)
    good = write_scorecard(tmp_path, ONE_CELL)
    assert main([str(good), "--baseline", str(baseline)]) == 2, (
        "an empty baseline must refuse like a missing one, not grandfather nothing in silence"
    )

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for the advisory ADR spec-driven coverage analyzer (Secure Development Standards §5 / R3)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.adr_analyze import analyze_adrs


def _repo(tmp_path: Path) -> tuple[Path, Path]:
    """A fake repo: an ``adr`` dir + a ``tests`` dir with one real test file for ref resolution."""
    adr = tmp_path / "docs" / "adr"
    adr.mkdir(parents=True)
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_real.py").write_text("def test_x(): ...\n", encoding="utf-8")
    return adr, tmp_path


def _write(adr: Path, name: str, body: str) -> None:
    (adr / name).write_text(body, encoding="utf-8")


def test_criteria_coverage_and_gaps(tmp_path: Path) -> None:
    adr, root = _repo(tmp_path)
    _write(
        adr,
        "0001-foo.md",
        "# 0001 — Foo\n\n- **Status:** Accepted\n\n## Acceptance Criteria\n\n"
        "- **AC-1** — WHEN x arrives, THE SYSTEM SHALL route it.\n"
        "  → `tests/test_real.py::test_x`\n"
        "- **AC-2** — IF y, THEN THE SYSTEM SHALL record ERROR.\n"
        "  → `tests/test_missing.py::test_y`\n\n"
        "## To resolve on acceptance\n\n- [ ] confirm the wire format\n",
    )
    result = analyze_adrs(adr, repo_root=root)
    (rep,) = result.reports
    assert rep.adr_id == "0001" and rep.accepted and rep.has_criteria
    assert len(rep.criteria) == 2
    assert rep.criteria[0].covered  # tests/test_real.py exists
    assert not rep.criteria[1].covered  # tests/test_missing.py does not
    assert result.coverage_gaps == [("0001", "tests/test_missing.py::test_y")]
    assert result.open_clarifications == [("0001", "confirm the wire format")]
    assert result.accepted_without_criteria == []  # it has criteria
    assert result.ok is False  # a gap exists


def test_accepted_without_criteria_is_flagged(tmp_path: Path) -> None:
    adr, root = _repo(tmp_path)
    _write(
        adr, "0002-bar.md", "# 0002 — Bar\n\n- **Status:** Accepted\n\n## Context\n\nno criteria.\n"
    )
    result = analyze_adrs(adr, repo_root=root)
    assert result.accepted_without_criteria == ["0002"]
    assert result.ok is True  # advisory recommendation, not a coverage gap


def test_proposed_without_criteria_is_not_flagged(tmp_path: Path) -> None:
    adr, root = _repo(tmp_path)
    _write(adr, "0003-baz.md", "# 0003 — Baz\n\n- **Status:** Proposed\n\n## Context\n\ntbd.\n")
    result = analyze_adrs(adr, repo_root=root)
    assert result.accepted_without_criteria == []  # only *Accepted* ADRs are recommended criteria


def test_readme_and_template_are_skipped(tmp_path: Path) -> None:
    adr, root = _repo(tmp_path)
    _write(adr, "README.md", "# Architecture Decision Records\n\nintro.\n")
    _write(adr, "TEMPLATE.md", "# NNNN — title\n\n- **Status:** Proposed\n")
    _write(adr, "0004-q.md", "# 0004 — Q\n\n- **Status:** Accepted\n")
    result = analyze_adrs(adr, repo_root=root)
    assert [r.adr_id for r in result.reports] == ["0004"]  # NNNN-*.md only


def test_cli_json_and_strict_exit(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    adr, root = _repo(tmp_path)
    _write(
        adr,
        "0005-gap.md",
        "# 0005 — Gap\n\n- **Status:** Accepted\n\n## Acceptance Criteria\n\n"
        "- THE SYSTEM SHALL do it. → `tests/test_missing.py`\n",
    )
    # advisory by default: exit 0 even with a gap
    assert main(["adr-analyze", "--adr-dir", str(adr), "--repo-root", str(root), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is False
    assert report["error"] is None  # a coverage gap is a finding, not an absent corpus
    assert report["coverage_gaps"] == [{"adr": "0005", "ref": "tests/test_missing.py"}]
    # --strict turns a gap into a non-zero exit
    assert (
        main(["adr-analyze", "--adr-dir", str(adr), "--repo-root", str(root), "--strict", "--json"])
        == 1
    )


def test_missing_adr_directory_is_an_error(tmp_path: Path) -> None:
    # Path.glob on a directory that does not exist yields nothing and raises nothing, so an
    # unvalidated analyzer reports success over no corpus at all.
    missing = tmp_path / "docs" / "adr"  # deliberately never created
    result = analyze_adrs(missing, repo_root=tmp_path)
    assert result.reports == []
    assert result.error is not None
    assert str(missing) in result.error
    assert result.ok is False


def test_adr_path_that_is_a_file_is_an_error(tmp_path: Path) -> None:
    not_a_dir = tmp_path / "adr.md"
    not_a_dir.write_text("# 0001 - Foo\n", encoding="utf-8")
    result = analyze_adrs(not_a_dir, repo_root=tmp_path)
    assert result.reports == []  # never a one-ADR corpus
    assert result.error is not None
    assert str(not_a_dir) in result.error
    assert result.ok is False


def test_empty_adr_directory_is_an_error(tmp_path: Path) -> None:
    adr, root = _repo(tmp_path)  # the directory exists and holds nothing
    result = analyze_adrs(adr, repo_root=root)
    assert result.reports == []
    assert result.error is not None
    assert str(adr) in result.error
    assert result.ok is False


def test_readme_and_template_only_is_an_error(tmp_path: Path) -> None:
    # The withdrawal shape: the ADRs are gone, the scaffolding stays. Both files are skipped by
    # the NNNN-*.md discovery glob, so the corpus is empty even though the directory is not.
    adr, root = _repo(tmp_path)
    _write(adr, "README.md", "# Architecture Decision Records\n\nintro.\n")
    _write(adr, "TEMPLATE.md", "# NNNN - title\n\n- **Status:** Proposed\n")
    result = analyze_adrs(adr, repo_root=root)
    assert result.reports == []
    assert result.error is not None
    assert str(adr) in result.error
    assert result.ok is False


def test_directory_named_like_an_adr_is_not_an_adr(tmp_path: Path) -> None:
    # The discovery glob matches a directory too, and parsing one would raise instead of reporting.
    adr, root = _repo(tmp_path)
    (adr / "0007-not-a-file.md").mkdir()
    result = analyze_adrs(adr, repo_root=root)
    assert result.reports == []
    assert result.error is not None
    assert result.ok is False


def test_one_valid_adr_is_ok(tmp_path: Path) -> None:
    # Positive control for the error tests above: the same fixture shape, one ADR added.
    adr, root = _repo(tmp_path)
    _write(
        adr,
        "0006-ok.md",
        "# 0006 — Ok\n\n- **Status:** Accepted\n\n## Acceptance Criteria\n\n"
        "- **AC-1** — WHEN x arrives, THE SYSTEM SHALL route it.\n"
        "  → `tests/test_real.py::test_x`\n",
    )
    result = analyze_adrs(adr, repo_root=root)
    assert result.error is None
    assert [r.adr_id for r in result.reports] == ["0006"]
    assert result.ok is True


def test_cli_missing_adr_dir_exits_two(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # Non-zero WITHOUT --strict: an absent corpus is "could not run", not an advisory finding.
    missing = tmp_path / "nope"
    assert main(["adr-analyze", "--adr-dir", str(missing), "--repo-root", str(tmp_path)]) == 2
    captured = capsys.readouterr()
    assert str(missing) in captured.err
    assert captured.out == ""  # the human line goes to stderr, nothing to stdout


def test_cli_missing_adr_dir_exits_two_under_strict_too(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # 2 and not 1 under --strict: 1 is this subcommand's advisory coverage-gap code, so a job
    # keying on exit codes must not read "there is no corpus" as "the corpus has gaps".
    missing = tmp_path / "nope"
    argv = ["adr-analyze", "--adr-dir", str(missing), "--repo-root", str(tmp_path), "--strict"]
    assert main(argv) == 2
    assert str(missing) in capsys.readouterr().err


def test_cli_empty_adr_dir_exits_two_and_json_says_not_ok(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    adr, root = _repo(tmp_path)
    assert main(["adr-analyze", "--adr-dir", str(adr), "--repo-root", str(root), "--json"]) == 2
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["ok"] is False
    assert str(adr) in report["error"]
    # JSON on stdout XOR the human line on stderr: both would reorder under `2>&1`.
    assert captured.err == ""


def test_cli_human_output_over_a_real_corpus(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The non-JSON success branch: nothing else covers it, and every other CLI test either passes
    # --json or returns at the absent-corpus branch before reaching it.
    adr, root = _repo(tmp_path)
    _write(adr, "0008-plain.md", "# 0008 — Plain\n\n- **Status:** Accepted\n")
    assert main(["adr-analyze", "--adr-dir", str(adr), "--repo-root", str(root)]) == 0
    captured = capsys.readouterr()
    assert "ADRs analyzed: 1 (0 with acceptance criteria)" in captured.out
    assert "recommend: 0008 is Accepted with no acceptance-criteria block" in captured.out
    assert captured.out.rstrip().endswith("ok")
    assert captured.err == ""


def test_real_project_adrs_parse(tmp_path: Path) -> None:
    # The shipped ADRs must at least parse without error and yield a status for each.
    adr = Path(__file__).resolve().parents[1] / "docs" / "adr"
    result = analyze_adrs(adr)
    assert result.reports, "expected the project's ADRs to be discovered"
    assert all(r.status != "" for r in result.reports)

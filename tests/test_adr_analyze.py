# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
    assert report["coverage_gaps"] == [{"adr": "0005", "ref": "tests/test_missing.py"}]
    # --strict turns a gap into a non-zero exit
    assert (
        main(["adr-analyze", "--adr-dir", str(adr), "--repo-root", str(root), "--strict", "--json"])
        == 1
    )


def test_real_project_adrs_parse(tmp_path: Path) -> None:
    # The shipped ADRs must at least parse without error and yield a status for each.
    adr = Path(__file__).resolve().parents[1] / "docs" / "adr"
    result = analyze_adrs(adr)
    assert result.reports, "expected the project's ADRs to be discovered"
    assert all(r.status != "" for r in result.reports)

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for the advisory ADR spec-driven coverage analyzer (Secure Development Standards §5 / R3)."""

from __future__ import annotations

import json
import os
import random
import re
import time
from pathlib import Path

import pytest

from messagefoundry_toolkit import adr_analyze
from messagefoundry_toolkit.__main__ import main
from messagefoundry_toolkit.adr_analyze import analyze_adrs


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


# --- BACKLOG #2516: four defects in the analyzer --------------------------------------------------

#: Long enough that the old patterns, which were quadratic on a whitespace-only tail, take tens of
#: seconds on a workstation (16,000 spaces took 0.6 s; 100,000 is 39 times that). A linear match
#: takes milliseconds, so the bound below leaves a slow runner more than a hundredfold of headroom.
_LONG_TAIL = 100_000
_TAIL_BOUND_S = 2.0


@pytest.mark.parametrize(
    "line",
    ["- [ ]" + " " * _LONG_TAIL, "#" + " " * _LONG_TAIL],
    ids=["unchecked-item", "heading"],
)
def test_a_whitespace_only_tail_does_not_backtrack(tmp_path: Path, line: str) -> None:
    adr, root = _repo(tmp_path)
    _write(adr, "0010-ws.md", f"# 0010 - Ws\n\n- **Status:** Accepted\n\n{line}\n")
    start = time.perf_counter()
    result = analyze_adrs(adr, repo_root=root)
    elapsed = time.perf_counter() - start
    assert [r.adr_id for r in result.reports] == [
        "0010"
    ]  # it parsed, so the timing means something
    assert elapsed < _TAIL_BOUND_S, f"{elapsed:.2f} s over a {_LONG_TAIL}-space tail"


#: The patterns as they stood before #2516, kept as the oracle the rewrite must agree with.
_OLD_UNCHECKED = re.compile(r"^\s*[-*]\s+\[ \]\s+(.*\S)\s*$")
_OLD_HEADING = re.compile(r"^#{1,6}\s+(.*\S)\s*$")


def _old(pattern: re.Pattern[str], line: str) -> str | None:
    """The old capture as its callers used it: every one of them stripped it."""
    m = pattern.match(line)
    return m.group(1).strip() if m else None


def test_the_rewritten_patterns_capture_what_the_old_ones_did() -> None:
    # Prefixes that reach each pattern's capture group, then random tails over every character
    # class the patterns branch on: ASCII and Unicode whitespace, the markers, and plain text.
    prefixes = ["", " ", "\t", "-", "*", " - [ ]", "- [ ]", "* [ ]", "-\t[ ]", "- [x]", "-[ ]"]
    prefixes += ["#", "######", "#######", " #", "#\t"]
    alphabet = [" ", "\t", "\x1c", "\xa0", "\u3000", "-", "*", "#", "[", "]", "x", "y"]
    rng = random.Random(2516)
    lines = [p + "".join(rng.choices(alphabet, k=rng.randint(0, 9))) for p in prefixes * 3000]
    matched = {"unchecked": 0, "heading": 0}
    for line in lines:
        old_item = _old(_OLD_UNCHECKED, line)
        assert adr_analyze._capture(adr_analyze._UNCHECKED_RE, line) == old_item, repr(line)
        old_heading = _old(_OLD_HEADING, line)
        assert adr_analyze._capture(adr_analyze._HEADING_RE, line) == old_heading, repr(line)
        matched["unchecked"] += old_item is not None
        matched["heading"] += old_heading is not None
    # The comparison is only as strong as the matches it saw: both arms must have fired often.
    assert matched["unchecked"] > 1000 and matched["heading"] > 1000, matched
    assert len(lines) - sum(matched.values()) > 1000  # and the no-match arm too


def test_an_adr_dir_directly_under_a_root_is_refused_not_a_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # ``Path("C:/adr").resolve().parents[1]`` raises IndexError: C:/ is its only parent. A real
    # directory at a drive root cannot be made in a test, so the ADR dir RESOLVES to one here.
    adr, _root = _repo(tmp_path)
    _write(adr, "0011-r.md", "# 0011 - R\n\n- **Status:** Accepted\n")
    at_root = Path(tmp_path.anchor) / "adr"
    real_resolve = Path.resolve

    def fake_resolve(self: Path, strict: bool = False) -> Path:
        return at_root if self == adr else real_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", fake_resolve)
    assert len(adr.resolve().parents) == 1  # the shape under test: one parent, no grandparent
    result = analyze_adrs(adr)
    assert result.reports == []
    assert result.error is not None and "--repo-root" in result.error
    assert str(adr) in result.error
    assert result.ok is False
    assert main(["adr-analyze", "--adr-dir", str(adr)]) == 2
    assert "--repo-root" in capsys.readouterr().err
    # Control: the same tree with a repo root given never needs the default, and runs.
    assert [r.adr_id for r in analyze_adrs(adr, repo_root=tmp_path).reports] == ["0011"]


def test_a_ref_outside_the_repository_is_reported_and_never_probed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = tmp_path / "repo"
    adr = repo / "docs" / "adr"
    adr.mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "tests" / "test_real.py").write_text("def test_x(): ...\n", encoding="utf-8")
    (tmp_path / "secret.py").write_text("x = 1\n", encoding="utf-8")  # exists, outside the repo
    _write(
        adr,
        "0012-out.md",
        "# 0012 - Out\n\n- **Status:** Accepted\n\n## Acceptance Criteria\n\n"
        "- **AC-1** - THE SYSTEM SHALL climb. -> `tests/../../secret.py`\n"
        "- **AC-2** - THE SYSTEM SHALL stay. -> `tests/sub/../test_real.py`\n",
    )
    probed: list[str] = []
    real_exists = Path.exists

    def recording_exists(self: Path, *, follow_symlinks: bool = True) -> bool:
        probed.append(str(self))
        return real_exists(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "exists", recording_exists)
    result = analyze_adrs(adr, repo_root=repo)
    (rep,) = result.reports
    climb, stay = rep.criteria
    assert climb.outside_refs == ["tests/../../secret.py"]
    assert not climb.covered  # it exists on disk, but outside the root it proves nothing
    assert climb.missing_refs == []  # outside is its own finding, not a missing file
    assert result.outside_refs == [("0012", "tests/../../secret.py")]
    assert result.ok is False
    # A ``..`` that stays inside the root is an ordinary ref: probed, found, covered. ``tests/sub``
    # does not exist, so this holds on POSIX only because the NORMALISED path is what gets probed.
    assert stay.covered and stay.outside_refs == []
    assert sum("test_real.py" in p for p in probed) == 1  # the inside ref WAS probed
    assert not [p for p in probed if "secret" in p]  # and the outside one never was
    assert result.to_json()["outside_refs"] == [{"adr": "0012", "ref": "tests/../../secret.py"}]
    assert main(["adr-analyze", "--adr-dir", str(adr), "--repo-root", str(repo), "--strict"]) == 1
    assert "0012 links a path outside the repository" in capsys.readouterr().out


@pytest.mark.skipif(os.name != "nt", reason="device names are a Windows path rule")
def test_a_windows_device_ref_is_outside_the_repository(tmp_path: Path) -> None:
    # ``tests/NUL`` opens the NUL device from any directory, so it "exists" without being a file
    # in the repository. Before the fix it counted as covered.
    adr, root = _repo(tmp_path)
    _write(
        adr,
        "0014-dev.md",
        "# 0014 - Dev\n\n- **Status:** Accepted\n\n## Acceptance Criteria\n\n"
        "- **AC-1** - THE SYSTEM SHALL do it. -> `tests/NUL`\n"
        "- **AC-2** - THE SYSTEM SHALL do it. -> `tests/test_real.py`\n"
        "- **AC-3** - THE SYSTEM SHALL do it. -> `tests/nul.py`\n",
    )
    device, real, lookalike = analyze_adrs(adr, repo_root=root).reports[0].criteria
    assert real.covered  # control: an ordinary ref beside it is unaffected
    assert device.outside_refs == ["tests/NUL"] and not device.covered
    # A name that only starts like a device is an ordinary path in the repository: probed, missing.
    assert lookalike.outside_refs == [] and lookalike.missing_refs == ["tests/nul.py"]


def test_control_characters_in_record_text_are_escaped_on_the_terminal(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    adr, root = _repo(tmp_path)
    raw = "clear \x1b[2J screen\x07 then \u202eflip and \x00nul, not \\x07"
    _write(adr, "0013-ctl.md", f"# 0013 - Ctl\n\n- **Status:** Accepted\n\n- [ ] {raw}\n")
    assert main(["adr-analyze", "--adr-dir", str(adr), "--repo-root", str(root)]) == 0
    out = capsys.readouterr().out
    # The literal backslash is doubled, so the spelled-out ``\x07`` cannot pass for a real BEL.
    expected = "open item: clear \\x1b[2J screen\\x07 then \\u202eflip and \\x00nul, not \\\\x07\n"
    assert out.count(expected) == 1
    assert not [ch for ch in ("\x1b", "\x07", "\u202e", "\x00") if ch in out]
    # JSON escapes them already, and the record itself keeps the raw text.
    assert main(["adr-analyze", "--adr-dir", str(adr), "--repo-root", str(root), "--json"]) == 0
    (item,) = json.loads(capsys.readouterr().out)["open_clarifications"]
    assert item["item"] == raw

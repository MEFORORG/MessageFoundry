# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Every cited ``CLAUDE.md`` section number must resolve to a section that exists.

``CLAUDE.md``'s numbered sections are a de facto API. Measured 2026-08-12: 281 tracked files name the
file and 646 citations name one of its sections; ``tests/test_dependency_boundaries.py`` cites section
4 in its own docstring, so this reaches code and not only prose.

Before this guard, nothing validated a section NUMBER. ``scripts/docs/link_check.py`` states in its own
header that it resolves the path and skips the ``#fragment``, and the two doc guards that already read
``CLAUDE.md`` check other things -- ``test_sds_rule_ids_are_stable`` checks ``SDS-N.N`` identifiers and
``test_link_resolution`` checks link paths. So a renumber landed entirely GREEN: path resolves,
identifiers resolve, only the meaning moved.

That rot is not hypothetical. ``test_sds_rule_ids_are_stable``'s own module docstring records it
happening to a different document -- a new section 5 pushed 5-9 to 6-10, and four security citations
still resolve to the wrong section today. The instance was fixed and the class left open. This closes
it for the anchor.

MEASURED BLAST RADIUS, which is why the guard is worth its maintenance: renumbering section 11 alone
breaks 61 citations, and every existing gate stays green through it.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

_REPO = Path(__file__).resolve().parents[1]
_CHECKER = _REPO / "scripts" / "docs" / "claude_section_check.py"


def _load() -> Any:
    """Import the checker by FILE path -- ``scripts/`` is not a package.

    Same loading pattern as the other scripts/docs guards. Importing the shipped module rather than
    re-implementing its rule is the point: a test that re-states the logic passes however the real
    code behaves.
    """
    spec = importlib.util.spec_from_file_location("claude_section_check", _CHECKER)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # Register BEFORE exec: ``@dataclass`` resolves its class's module through ``sys.modules`` at
    # decoration time, and an unregistered module makes that lookup return None. The failure is an
    # AttributeError raised from inside dataclasses.py, which reads like a bug in the checker.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def checker() -> Any:
    return _load()


# --- the live corpus ---------------------------------------------------------------------------


def test_every_cited_section_resolves(checker: Any) -> None:
    """The whole repository's citations resolve against the anchor as it stands."""
    sections, every, broken = checker.scan(_REPO)
    assert not broken, "\n".join(
        [
            "Citations name a CLAUDE.md section that does not exist:",
            *(f"  {c.path}:{c.line} cites section {c.section}: {c.text!r}" for c in broken),
            f"CLAUDE.md defines only {sorted(sections)}.",
        ]
    )


def test_the_scan_actually_scanned_something(checker: Any) -> None:
    """A clean result is evidence only if the scan had a corpus to be clean ABOUT.

    Without this, deleting the anchor's headings or breaking the citation regex would produce zero
    findings and a passing test -- the failure mode this whole guard exists to prevent, reproduced
    inside the guard itself.
    """
    sections, every, _ = checker.scan(_REPO)
    assert len(sections) >= 10, f"parsed only {len(sections)} section headings from CLAUDE.md"
    assert len(every) >= 400, f"found only {len(every)} citations; expected hundreds"
    assert len({c.path for c in every}) >= 100, "citations found in suspiciously few files"


# --- prove the instrument ----------------------------------------------------------------------
#
# Each assertion above is fired at input built to break it. A guard that has never been observed to
# fail is not evidence.


def _fixture_repo(tmp_path: Path, anchor_body: str, citer_body: str) -> Path:
    """A throwaway git repo with an anchor and one citing file.

    Filesystem-real and git-real because the checker resolves its corpus through ``git ls-files``;
    a mock would test a different program.
    """
    import subprocess

    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "CLAUDE.md").write_text(anchor_body, encoding="utf-8")
    (tmp_path / "doc.md").write_text(citer_body, encoding="utf-8")
    for cmd in (
        ["git", "init", "-q"],
        ["git", "add", "-A"],
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x"],
    ):
        subprocess.run(cmd, cwd=tmp_path, check=True, capture_output=True)
    return tmp_path


_ANCHOR = "# T\n\n## 1. One\n\ntext\n\n## 2. Two\n\ntext\n"


def test_selfbite_a_dangling_citation_is_detected(tmp_path: Path, checker: Any) -> None:
    root = _fixture_repo(tmp_path, _ANCHOR, "See CLAUDE.md section 9 for this.\n")
    _, every, broken = checker.scan(root)
    assert len(every) == 1 and len(broken) == 1
    assert broken[0].section == 9


def test_selfbite_a_renumber_breaks_its_citers(tmp_path: Path, checker: Any) -> None:
    """The actual threat: the citation never changes, the anchor's numbering does."""
    citer = "CLAUDE.md section 2 is the rule.\n"
    ok = _fixture_repo(tmp_path / "before", _ANCHOR, citer)
    assert not checker.scan(ok)[2], "citation should resolve before the renumber"

    renumbered = _ANCHOR.replace("## 2. Two", "## 3. Two")
    bad = _fixture_repo(tmp_path / "after", renumbered, citer)
    assert checker.scan(bad)[2], "a renumber must break its citers"


def test_selfbite_both_citation_spellings_are_seen(tmp_path: Path, checker: Any) -> None:
    """The repo uses a section sign and the word. Missing either would silently halve coverage."""
    root = _fixture_repo(tmp_path, _ANCHOR, "CLAUDE.md §9 and CLAUDE.md section 8.\n")
    _, every, broken = checker.scan(root)
    assert {c.section for c in every} == {8, 9}
    assert len(broken) == 2


def test_selfbite_an_unrelated_section_reference_is_not_claimed(
    tmp_path: Path, checker: Any
) -> None:
    """A section number belonging to ANOTHER document must not be attributed to the anchor.

    False positives are how a gate gets disabled, so the checker deliberately requires the anchor's
    name on the same line and within a bounded window.
    """
    root = _fixture_repo(tmp_path, _ANCHOR, "See docs/PHI.md section 9 for the retention rule.\n")
    _, every, broken = checker.scan(root)
    assert every == [] and broken == []


def test_selfbite_it_refuses_to_pass_when_the_anchor_has_no_headings(
    tmp_path: Path, checker: Any
) -> None:
    """Zero parsed headings must ABORT, never report every citation broken or the corpus clean.

    This is the shape that makes a gate lie: a heading-format change would otherwise turn the guard
    into a generator of hundreds of false failures, and the cheapest way to silence that is to delete
    the guard.
    """
    root = _fixture_repo(tmp_path, "# T\n\nno numbered headings\n", "CLAUDE.md section 1.\n")
    with pytest.raises(SystemExit):
        checker.scan(root)


def test_selfbite_it_refuses_to_pass_when_the_anchor_is_missing(
    tmp_path: Path, checker: Any
) -> None:
    root = _fixture_repo(tmp_path, _ANCHOR, "CLAUDE.md section 1.\n")
    (root / "CLAUDE.md").unlink()
    with pytest.raises(SystemExit):
        checker.scan(root)

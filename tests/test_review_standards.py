# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pin ``docs/REVIEW-STANDARDS.md``, the rule sheet the ``code-review`` skill reads with a diff.

The sheet is only useful if it stays short and every rule still points at a live source. These
checks are held here:

* the file exists and stays under ``_LINE_CAP`` lines, so it does not grow into a second rubric;
* every rule (a paragraph opening ``**R<n>.``) carries at least one markdown link to its source;
* every relative link resolves to a tracked path, read through ``scripts/docs/link_check.py``'s own
  resolver rather than a copy of it;
* every ``CLAUDE.md`` section it cites exists, read through ``scripts/docs/claude_section_check.py``,
  and every ``section N`` sits on the same line as its link, so that checker sees all of them;
* every test file named in the closing table exists.

The repo-wide link and section gates also cover this file once it is tracked. This test still runs
on an untracked draft, and it adds the per-rule pointer and line-cap checks those gates do not make.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SHEET = _ROOT / "docs" / "REVIEW-STANDARDS.md"
_SHEET_REL = "docs/REVIEW-STANDARDS.md"

#: 150 lines. A rule sheet longer than that has started restating its sources (SDS-3.5).
_LINE_CAP = 150

_RULE = re.compile(r"^\*\*R(\d+)\.")
_TEST_PATH = re.compile(r"`(tests/[\w/]+\.py)`")
_SECTION = re.compile(r"(?:§|(?<![A-Za-z])[Ss]ection\s+)\d+")
_LINKED_SECTION = re.compile(r"\]\([^)\s]+\) (?:§|[Ss]ection\s+)\d+")


def _load(name: str, rel: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, _ROOT / rel)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def links() -> Any:
    return _load("_review_link_check", "scripts/docs/link_check.py")


@pytest.fixture(scope="module")
def sections() -> Any:
    return _load("_review_claude_section_check", "scripts/docs/claude_section_check.py")


def _rules(text: str) -> dict[int, str]:
    """Each rule's paragraph, keyed by its number. A paragraph ends at a blank line."""
    out: dict[int, str] = {}
    current: int | None = None
    for line in text.splitlines():
        m = _RULE.match(line)
        if m:
            current = int(m.group(1))
            out[current] = line
        elif current is not None and line.strip():
            out[current] += "\n" + line
        else:
            current = None
    return out


def _rules_without_a_link(text: str, link_re: re.Pattern[str]) -> list[int]:
    return sorted(n for n, body in _rules(text).items() if not link_re.search(body))


def test_the_sheet_exists_and_stays_short() -> None:
    assert _SHEET.is_file(), f"missing {_SHEET_REL}"
    lines = _SHEET.read_text(encoding="utf-8").splitlines()
    assert len(lines) <= _LINE_CAP, (
        f"{_SHEET_REL} is {len(lines)} lines, over the {_LINE_CAP}-line cap. Point at the source of "
        "record instead of restating it."
    )


def test_rules_are_numbered_one_to_n() -> None:
    numbers = list(_rules(_SHEET.read_text(encoding="utf-8")))
    assert len(numbers) >= 10, f"parsed only {len(numbers)} rules; the rule pattern broke"
    assert numbers == list(range(1, len(numbers) + 1)), f"rule numbers out of order: {numbers}"


def test_every_rule_points_at_its_source(links: Any) -> None:
    missing = _rules_without_a_link(_SHEET.read_text(encoding="utf-8"), links._LINK)
    assert not missing, f"rules with no source link: {[f'R{n}' for n in missing]}"


def test_a_rule_with_no_link_is_detected(links: Any) -> None:
    planted = "**R1. Has one.** See [x](x.md).\n\n**R2. Has none.** Just words.\n"
    assert _rules_without_a_link(planted, links._LINK) == [2]


def test_every_relative_link_resolves(links: Any) -> None:
    tracked = links.tracked_paths(_ROOT)
    base = PurePosixPath(_SHEET_REL).parent
    checked, broken = 0, []
    for m in links._LINK.finditer(_SHEET.read_text(encoding="utf-8")):
        href = m.group("href")
        if href.startswith(("http://", "https://", "mailto:", "#")):
            continue
        target = links._normalise(base, href.split("#", 1)[0])
        checked += 1
        if target not in tracked:
            broken.append(f"({href}) -> {target}")
    assert checked >= 10, f"only {checked} links checked; the link pattern broke"
    assert not broken, "unresolved links:\n" + "\n".join(broken)


def test_every_cited_claude_section_exists(sections: Any) -> None:
    defined = sections.anchor_sections(_ROOT / "CLAUDE.md")
    cites = sections.citations_in(_SHEET, _ROOT)
    assert len(cites) >= 10, f"found only {len(cites)} CLAUDE.md citations; the pattern broke"
    broken = [f"line {c.line}: section {c.section}" for c in cites if c.section not in defined]
    assert not broken, f"cited CLAUDE.md sections that do not exist: {broken}"


def _section_refs_not_beside_a_link(text: str) -> list[str]:
    """Each ``section N`` must follow its link on the same line.

    The section checker reads a citation only when the file name and the number share a line, so a
    wrapped citation would go unchecked. Forcing ``[doc](path) section N`` makes the check above
    cover every section reference in the sheet, not just the ones that happen to fit on one line.
    """
    bare = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        total = len(_SECTION.findall(line))
        linked = len(_LINKED_SECTION.findall(line))
        if total != linked:
            bare.append(f"line {lineno}: {line.strip()}")
    return bare


def test_every_section_reference_sits_beside_its_link() -> None:
    bare = _section_refs_not_beside_a_link(_SHEET.read_text(encoding="utf-8"))
    assert not bare, "section references not directly after a link:\n" + "\n".join(bare)


def test_a_wrapped_section_reference_is_detected() -> None:
    planted = "Source: [CLAUDE.md](../CLAUDE.md)\nsection 9, and [PHI.md](PHI.md) section 7.\n"
    assert _section_refs_not_beside_a_link(planted) == [
        "line 2: section 9, and [PHI.md](PHI.md) section 7."
    ]


def test_the_other_section_spellings_are_seen() -> None:
    """The section checker also reads ``Section N`` and the section sign, so this guard must too."""
    planted = "[CLAUDE.md](../CLAUDE.md)\nSection 9.\n[CLAUDE.md](../CLAUDE.md)\n§6.\n"
    bare = _section_refs_not_beside_a_link(planted)
    assert [b.split(":")[0] for b in bare] == ["line 2", "line 4"]


def test_every_named_test_file_exists() -> None:
    named = _TEST_PATH.findall(_SHEET.read_text(encoding="utf-8"))
    assert named, "the closing table names no test files; the pattern broke"
    missing = [p for p in named if not (_ROOT / p).is_file()]
    assert not missing, f"the closing table names test files that do not exist: {missing}"

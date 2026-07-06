# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``messagefoundry adr-analyze`` — advisory spec-driven coverage report over the ADRs.

The **analyze** half of the Secure Development Standards §5 spec-driven recommendations (R3): scan the
Architecture Decision Records and report, **advisory-only** (never blocks a commit by default):

* **Acceptance-criteria coverage** — for each ADR carrying an ``## Acceptance Criteria`` block (EARS,
  per the ADR ``TEMPLATE.md`` / R1), the test/fixture each criterion links to (``→ tests/…``), and
  whether that file exists on disk. A *coverage gap* is a criterion whose linked test is missing.
* **Missing criteria** — an ``Accepted`` ADR with no acceptance-criteria block (recommended to add).
* **Open clarifications** — unchecked ``- [ ]`` task items (the "clarify" step): questions that
  should be resolved before an ADR flips to ``Accepted``.

Pure (filesystem reads only). It is **advisory**: :attr:`AnalysisResult.ok` is informational and the
CLI exits 0 unless ``--strict`` is passed, so it adds no new blocking gate — the §5 practices are
recommended, not required.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "AcceptanceCriterion",
    "AdrReport",
    "AnalysisResult",
    "analyze_adrs",
]

# A reference inside an Acceptance-Criteria block pointing at a test or fixture, e.g.
# ``tests/test_foo.py::test_bar`` or ``fixtures/IB_ACME/adt.hl7``. The ``::node`` pytest selector is
# captured but dropped for the on-disk existence check.
_REF_RE = re.compile(
    r"(?:tests|fixtures|samples|harness)/[A-Za-z0-9_./\-]+(?:::[A-Za-z0-9_\-\[\]]+)?"
)
_STATUS_RE = re.compile(
    r"status[^A-Za-z]*\b(Proposed|Accepted|Superseded|Rejected|Reserved|Dropped)\b", re.IGNORECASE
)
_UNCHECKED_RE = re.compile(r"^\s*[-*]\s+\[ \]\s+(.*\S)\s*$")
_HEADING_RE = re.compile(r"^#{1,6}\s+(.*\S)\s*$")
_BULLET_RE = re.compile(r"^\s*[-*]\s+\S")


@dataclass(frozen=True)
class AcceptanceCriterion:
    """One acceptance-criterion bullet from an ADR's ``## Acceptance Criteria`` block."""

    text: str
    test_refs: list[str] = field(default_factory=list)
    missing_refs: list[str] = field(default_factory=list)

    @property
    def covered(self) -> bool:
        """Covered iff it links ≥1 test/fixture and none of them are missing on disk."""
        return bool(self.test_refs) and not self.missing_refs


@dataclass(frozen=True)
class AdrReport:
    """The spec-driven analysis of a single ADR file."""

    path: str
    adr_id: str
    title: str
    status: str
    criteria: list[AcceptanceCriterion] = field(default_factory=list)
    open_clarifications: list[str] = field(default_factory=list)

    @property
    def accepted(self) -> bool:
        return self.status.lower() == "accepted"

    @property
    def has_criteria(self) -> bool:
        return bool(self.criteria)

    @property
    def coverage_gaps(self) -> list[str]:
        return [ref for c in self.criteria for ref in c.missing_refs]

    def to_json(self) -> dict[str, object]:
        return {
            "path": self.path,
            "adr_id": self.adr_id,
            "title": self.title,
            "status": self.status,
            "criteria": [
                {"text": c.text, "test_refs": c.test_refs, "missing_refs": c.missing_refs}
                for c in self.criteria
            ],
            "open_clarifications": self.open_clarifications,
        }


@dataclass(frozen=True)
class AnalysisResult:
    """The whole-ADR-set report."""

    reports: list[AdrReport]

    @property
    def coverage_gaps(self) -> list[tuple[str, str]]:
        """``(adr_id, missing_ref)`` for every acceptance-criterion test link that does not exist."""
        return [(r.adr_id, ref) for r in self.reports for ref in r.coverage_gaps]

    @property
    def accepted_without_criteria(self) -> list[str]:
        return [r.adr_id for r in self.reports if r.accepted and not r.has_criteria]

    @property
    def open_clarifications(self) -> list[tuple[str, str]]:
        return [(r.adr_id, item) for r in self.reports for item in r.open_clarifications]

    @property
    def ok(self) -> bool:
        """Advisory: True iff there are no acceptance-criteria coverage gaps."""
        return not self.coverage_gaps

    def to_json(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "adrs": [r.to_json() for r in self.reports],
            "coverage_gaps": [{"adr": a, "ref": ref} for a, ref in self.coverage_gaps],
            "accepted_without_criteria": self.accepted_without_criteria,
            "open_clarifications": [{"adr": a, "item": i} for a, i in self.open_clarifications],
        }


def _sections(text: str) -> dict[str, list[str]]:
    """Split markdown into ``{lowercased-heading: body-lines}`` (any heading level)."""
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        m = _HEADING_RE.match(line)
        if m:
            current = m.group(1).strip().lower()
            sections.setdefault(current, [])
        elif current is not None:
            sections[current].append(line)
    return sections


def _status(text: str) -> str:
    m = _STATUS_RE.search(text)
    return m.group(1).capitalize() if m else "Unknown"


def _title(text: str, fallback: str) -> str:
    for line in text.splitlines():
        m = _HEADING_RE.match(line)
        if m:
            return m.group(1).strip()
    return fallback


def _criteria(lines: list[str], repo_root: Path) -> list[AcceptanceCriterion]:
    """Group the Acceptance-Criteria body into bullet items; an item is a criterion iff it contains
    ``SHALL`` (the EARS keyword), filtering out the blockquote legend. Resolve each ``→`` test ref."""
    items: list[list[str]] = []
    for line in lines:
        if line.lstrip().startswith(">"):
            continue  # the EARS legend blockquote — not a criterion
        if _BULLET_RE.match(line):
            items.append([line])
        elif items and line.strip():
            items[-1].append(line)  # a continuation line of the current bullet (e.g. the → ref)
    out: list[AcceptanceCriterion] = []
    for item in items:
        blob = "\n".join(item)
        if "SHALL" not in blob.upper():
            continue
        text = item[0].strip().lstrip("-*").strip()
        refs: list[str] = []
        for m in _REF_RE.finditer(blob):
            ref = m.group(0)
            if ref not in refs:
                refs.append(ref)
        missing = [r for r in refs if not (repo_root / r.split("::", 1)[0]).exists()]
        out.append(AcceptanceCriterion(text=text, test_refs=refs, missing_refs=missing))
    return out


def _clarifications(text: str) -> list[str]:
    out: list[str] = []
    for line in text.splitlines():
        m = _UNCHECKED_RE.match(line)
        if m:
            out.append(m.group(1).strip())
    return out


def _parse_adr(path: Path, repo_root: Path) -> AdrReport:
    text = path.read_text(encoding="utf-8")
    return AdrReport(
        path=str(path),
        adr_id=path.stem.split("-", 1)[0],
        title=_title(text, path.stem),
        status=_status(text),
        criteria=_criteria(_sections(text).get("acceptance criteria", []), repo_root),
        open_clarifications=_clarifications(text),
    )


def analyze_adrs(adr_dir: str | Path, repo_root: str | Path | None = None) -> AnalysisResult:
    """Analyze every ``NNNN-*.md`` ADR under ``adr_dir`` (README/TEMPLATE are skipped).

    ``repo_root`` anchors the on-disk existence check for each ``→`` test/fixture reference; it
    defaults to two levels above ``adr_dir`` (i.e. the repo root for the standard ``docs/adr`` layout).
    """
    adr_path = Path(adr_dir)
    root = Path(repo_root) if repo_root is not None else adr_path.resolve().parents[1]
    reports = [_parse_adr(f, root) for f in sorted(adr_path.glob("[0-9]*.md"))]
    return AnalysisResult(reports=reports)

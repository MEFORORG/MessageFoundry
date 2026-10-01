# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``messagefoundry-toolkit adr-analyze`` — advisory spec-driven coverage report over the ADRs.

The **analyze** half of the Secure Development Standards §5 spec-driven recommendations (R3): scan the
Architecture Decision Records and report, **advisory-only** (never blocks a commit by default):

* **Acceptance-criteria coverage** — for each ADR carrying an ``## Acceptance Criteria`` block (EARS,
  per the ADR ``TEMPLATE.md`` / R1), the test/fixture each criterion links to (``→ tests/…``), and
  whether that file exists on disk. A *coverage gap* is a criterion whose linked test is missing.
  A link whose path climbs out of the repository root with ``..``, or names a Windows device, is
  reported as outside the repository and never probed.
* **Missing criteria** — an ``Accepted`` ADR with no acceptance-criteria block (recommended to add).
* **Open clarifications** — unchecked ``- [ ]`` task items (the "clarify" step): questions that
  should be resolved before an ADR flips to ``Accepted``.

Pure (filesystem reads only). Its **findings** are advisory: :attr:`AnalysisResult.ok` is
informational and the CLI exits 0 unless ``--strict`` is passed, so it adds no new blocking gate —
the §5 practices are recommended, not required. One condition is not a finding and is never
advisory — an absent corpus; :func:`analyze_adrs` defines it and says why.
"""

from __future__ import annotations

import os
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "AcceptanceCriterion",
    "AdrReport",
    "AnalysisResult",
    "analyze_adrs",
]

# How an ADR file is recognised. Quoted verbatim in the "nothing matched" error so the message and
# the code state the same rule -- it is looser than the ``NNNN-`` naming convention it implements.
_DISCOVERY_GLOB = "[0-9]*.md"

# A reference inside an Acceptance-Criteria block pointing at a test or fixture, e.g.
# ``tests/test_foo.py::test_bar`` or ``fixtures/IB_ACME/adt.hl7``. The ``::node`` pytest selector is
# captured but dropped for the on-disk existence check.
_REF_RE = re.compile(
    r"(?:tests|fixtures|samples|harness)/[A-Za-z0-9_./\-]+(?:::[A-Za-z0-9_\-\[\]]+)?"
)
_STATUS_RE = re.compile(
    r"status[^A-Za-z]*\b(Proposed|Accepted|Superseded|Rejected|Reserved|Dropped)\b", re.IGNORECASE
)
# Both run on an RSTRIPPED line, so the capture starts at a non-space and runs to the end. The old
# forms, ``\s+(.*\S)\s*$`` on the raw line, retried every split of a whitespace-only tail and took
# time quadratic in its length (BACKLOG #2516). ``rstrip`` and ``\s`` agree on what whitespace is.
_UNCHECKED_RE = re.compile(r"^\s*[-*]\s+\[ \]\s+(\S.*)$")
_HEADING_RE = re.compile(r"^#{1,6}\s+(\S.*)$")
_BULLET_RE = re.compile(r"^\s*[-*]\s+\S")


@dataclass(frozen=True)
class AcceptanceCriterion:
    """One acceptance-criterion bullet from an ADR's ``## Acceptance Criteria`` block."""

    text: str
    test_refs: list[str] = field(default_factory=list)
    missing_refs: list[str] = field(default_factory=list)
    #: Refs whose path climbs out of the repository root. Never probed, so never in ``missing_refs``.
    outside_refs: list[str] = field(default_factory=list)

    @property
    def covered(self) -> bool:
        """Covered iff it links ≥1 test/fixture, none missing on disk and none outside the root."""
        return bool(self.test_refs) and not self.missing_refs and not self.outside_refs


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

    @property
    def outside_refs(self) -> list[str]:
        return [ref for c in self.criteria for ref in c.outside_refs]

    def to_json(self) -> dict[str, object]:
        return {
            "path": self.path,
            "adr_id": self.adr_id,
            "title": self.title,
            "status": self.status,
            "criteria": [
                {
                    "text": c.text,
                    "test_refs": c.test_refs,
                    "missing_refs": c.missing_refs,
                    "outside_refs": c.outside_refs,
                }
                for c in self.criteria
            ],
            "open_clarifications": self.open_clarifications,
        }


@dataclass(frozen=True)
class AnalysisResult:
    """The whole-ADR-set report.

    ``error`` is a human-readable line naming the directory when there was no corpus to analyze,
    or no repository root to check its links against, and ``None`` otherwise;
    :func:`analyze_adrs` sets it and gives the reasoning.
    """

    reports: list[AdrReport]
    error: str | None = None

    @property
    def coverage_gaps(self) -> list[tuple[str, str]]:
        """``(adr_id, missing_ref)`` for every acceptance-criterion test link that does not exist."""
        return [(r.adr_id, ref) for r in self.reports for ref in r.coverage_gaps]

    @property
    def outside_refs(self) -> list[tuple[str, str]]:
        """``(adr_id, ref)`` for every test link whose path leaves the repository root."""
        return [(r.adr_id, ref) for r in self.reports for ref in r.outside_refs]

    @property
    def accepted_without_criteria(self) -> list[str]:
        return [r.adr_id for r in self.reports if r.accepted and not r.has_criteria]

    @property
    def open_clarifications(self) -> list[tuple[str, str]]:
        return [(r.adr_id, item) for r in self.reports for item in r.open_clarifications]

    @property
    def ok(self) -> bool:
        """True iff a corpus was analyzed and every acceptance-criterion link was found inside it."""
        return self.error is None and not self.coverage_gaps and not self.outside_refs

    def to_json(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "error": self.error,
            "adrs": [r.to_json() for r in self.reports],
            "coverage_gaps": [{"adr": a, "ref": ref} for a, ref in self.coverage_gaps],
            "outside_refs": [{"adr": a, "ref": ref} for a, ref in self.outside_refs],
            "accepted_without_criteria": self.accepted_without_criteria,
            "open_clarifications": [{"adr": a, "item": i} for a, i in self.open_clarifications],
        }


def _capture(pattern: re.Pattern[str], line: str) -> str | None:
    """``pattern``'s capture over the rstripped ``line``, or None when it does not match.

    The capture has no surrounding whitespace, so callers need not strip it."""
    m = pattern.match(line.rstrip())
    return m.group(1) if m else None


def _sections(text: str) -> dict[str, list[str]]:
    """Split markdown into ``{lowercased-heading: body-lines}`` (any heading level)."""
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        heading = _capture(_HEADING_RE, line)
        if heading is not None:
            current = heading.lower()
            sections.setdefault(current, [])
        elif current is not None:
            sections[current].append(line)
    return sections


def _status(text: str) -> str:
    m = _STATUS_RE.search(text)
    return m.group(1).capitalize() if m else "Unknown"


def _title(text: str, fallback: str) -> str:
    for line in text.splitlines():
        heading = _capture(_HEADING_RE, line)
        if heading is not None:
            return heading
    return fallback


def _inside(ref_path: str, repo_root: Path) -> str | None:
    """A ref's path normalised, or None when it leaves the repository root.

    Decided without touching the filesystem, so a ref that escapes is never probed. ``abspath`` is
    string work, and on Windows it is the OS's own path rule, so it sees both ways out: ``..``, and
    a device name such as ``tests/NUL``, which opens the device wherever it sits. A name that only
    starts like one, ``tests/nul.py``, stays inside. The normalised form is what gets probed, so
    ``tests/sub/../x`` means the same on every OS. A symbolic link inside the root is still
    followed; this reads the text, not the tree.
    """
    norm = posixpath.normpath(ref_path)
    root = Path(os.path.abspath(repo_root))
    return norm if Path(os.path.abspath(root / norm)).is_relative_to(root) else None


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
        outside: list[str] = []
        missing: list[str] = []
        for ref in refs:
            ref_path = _inside(ref.split("::", 1)[0], repo_root)
            if ref_path is None:
                outside.append(ref)
            elif not (repo_root / ref_path).exists():
                missing.append(ref)
        out.append(
            AcceptanceCriterion(
                text=text, test_refs=refs, missing_refs=missing, outside_refs=outside
            )
        )
    return out


def _clarifications(text: str) -> list[str]:
    return [
        item for line in text.splitlines() if (item := _capture(_UNCHECKED_RE, line)) is not None
    ]


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
    Where ``adr_dir`` has no such grandparent, the default is refused through
    :attr:`AnalysisResult.error`, which then names ``--repo-root`` instead of the corpus.

    **AN ABSENT CORPUS IS AN ERROR, NOT AN EMPTY CLEAN RUN.** ``Path.glob`` yields nothing and
    raises nothing for a directory that does not exist, so a missing ADR directory -- or one left
    holding only its ``README.md`` and ``TEMPLATE.md`` scaffolding -- used to produce zero reports
    and an :attr:`AnalysisResult.ok` of True. A check that cannot fail is worse than no check: it
    would turn a withdrawn ADR set into a silent pass. So a path that does not exist, is not a
    directory, or matches no ADR sets :attr:`AnalysisResult.error` -- a line naming the directory
    -- and clears ``ok``; the CLI spends exit 2 on it whether or not ``--strict`` is passed.

    **The error line says what was looked for, not why nothing was found.** ``Path.exists`` and
    ``Path.glob`` both swallow ``OSError``, so a directory the process cannot read is
    indistinguishable here from one that is absent or genuinely empty. A message naming a cause
    the code cannot observe would send an operator to re-create a directory that is already there,
    so each line below stays on the observation and admits the unreadable case.
    """
    adr_path = Path(adr_dir)
    # Lexical ``abspath`` and not ``resolve()``: it makes the relative ``docs/adr`` default useful
    # to an operator, and collapses any ``..`` they typed, without rewriting a path handed in
    # through a symlink into its target.
    shown = os.path.abspath(adr_path)
    if not adr_path.exists():
        return AnalysisResult(reports=[], error=f"no ADR directory found or readable at {shown}")
    if not adr_path.is_dir():
        return AnalysisResult(reports=[], error=f"the ADR path is not a directory: {shown}")
    # ``is_file()`` because the glob matches a directory named like an ADR too, and handing one to
    # ``_parse_adr`` raises where the whole point here is a reported error.
    files = sorted(f for f in adr_path.glob(_DISCOVERY_GLOB) if f.is_file())
    if not files:
        return AnalysisResult(
            reports=[], error=f"no file matching {_DISCOVERY_GLOB} found in {shown}"
        )
    if repo_root is not None:
        root = Path(repo_root)
    else:
        # An ADR dir directly under a drive or filesystem root has no grandparent, and indexing
        # ``parents[1]`` there raised IndexError (BACKLOG #2516). No default is right for it, so
        # refuse and name the flag rather than guess at a root to probe.
        resolved = adr_path.resolve()
        if len(resolved.parents) < 2:
            # Name the resolved path too: through a link, it is the one with no grandparent.
            via = "" if str(resolved) == shown else f" (resolved: {resolved})"
            return AnalysisResult(
                reports=[],
                error=f"no directory two levels above {shown}{via} to use as the repository "
                "root; pass --repo-root",
            )
        root = resolved.parents[1]
    return AnalysisResult(reports=[_parse_adr(f, root) for f in files])

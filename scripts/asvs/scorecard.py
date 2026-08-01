# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS scorecard as data (ADR 0156) — derive the count, verify the evidence, fail closed.

The score used to live in prose. On 2026-08-01 one re-anchoring session re-derived the headline count
six times, found twelve residuals of record that were false at HEAD (five of them *absence* claims that
had quietly stopped being true), and found ten cells missing from an enumeration that described itself
as "arithmetic-checked and complete". That last one survived because the arithmetic closed to 345 and
closure was read as proof.

**Closure only proves the four buckets sum. It does not prove every cell landed in one.** That is the
whole reason :func:`check_completeness` exists and asserts against the corpus rather than the total.

This module is deliberately data-free: it takes the scorecard and the ASVS corpus as paths, so the
public repo can unit-test it against a fixture while the vault runs it against the real posture data
(ADR 0156 §7). It adds no dependency — ``tomllib`` is stdlib.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal

Verdict = Literal["pass", "partial", "fail", "na", "unverified"]

#: The scoring buckets. ``unverified`` is deliberately first-class (ADR 0156 §5): a cell inherited from
#: an earlier assessment and never re-read against the requirement text is NOT a Pass, and conflating
#: the two is what let ~219 unchecked verdicts hide inside a headline.
VERDICTS: Final[frozenset[str]] = frozenset({"pass", "partial", "fail", "na", "unverified"})

#: How far from the recorded line the expected token may drift before the anchor is considered broken.
#: Anchors name a TOKEN rather than a bare line number precisely so that ordinary edits above a cell's
#: evidence do not thrash every anchor in the file; the window keeps the line number meaningful without
#: making it load-bearing.
ANCHOR_WINDOW: Final[int] = 40


class ScorecardError(Exception):
    """A defect in the scorecard itself — malformed, incomplete, or contradicting the corpus."""


@dataclass(frozen=True)
class Anchor:
    """A claim that some token exists in the tree, at roughly a known place."""

    path: str
    line: int
    expect: str


@dataclass(frozen=True)
class Absence:
    """A claim that something does NOT exist, plus the proof the search could have seen it.

    A grep naming the wrong token returns zero and reads exactly like proof — that is how five false
    absence claims survived for weeks. So an absence claim is only admissible with a
    ``positive_control`` that must still match; if the control goes quiet the search has gone blind and
    the claim is void, regardless of what the pattern returns.
    """

    pattern: str
    positive_control: str


@dataclass(frozen=True)
class Cell:
    id: str
    level: int
    verdict: Verdict
    residual: str = ""
    posture: str = "single"
    last_verified: str = ""
    verified_at: str = ""
    evidence: tuple[Anchor, ...] = ()
    absence: tuple[Absence, ...] = ()

    @property
    def is_inherited(self) -> bool:
        """A verdict carried from an earlier assessment, never re-read against the requirement text."""
        return self.verdict == "unverified" or not self.last_verified


@dataclass
class Findings:
    """What a verification pass found. Empty ``problems`` is the only pass condition."""

    problems: list[str] = field(default_factory=list)
    checked_anchors: int = 0
    checked_absences: int = 0
    skipped_anchors: int = 0

    @property
    def ok(self) -> bool:
        return not self.problems


def load_corpus(path: Path) -> dict[str, int]:
    """Map ``req_id`` (V-stripped) to level, from the OWASP ASVS 5.0.0 flat JSON.

    The corpus is the external anchor. Before it was held, every verdict in this project reasoned from
    the requirement verb *as paraphrased in our own scorecards* — a closed loop that produced a cell
    scored against a requirement ASVS had deleted.
    """
    import json

    if not path.is_file():
        raise ScorecardError(
            f"ASVS corpus not found at {path} — cannot check completeness without it"
        )
    raw: Any = json.loads(path.read_text(encoding="utf-8"))
    reqs = raw["requirements"] if isinstance(raw, dict) else raw
    return {str(r["req_id"]).lstrip("V"): int(r["L"]) for r in reqs}


def load_scorecard(path: Path) -> list[Cell]:
    if not path.is_file():
        # Fail closed, never skip (ADR 0156 §6). Skipping is exactly what the doc-drift guards do
        # today, and it is why a green CI proves nothing about these documents.
        raise ScorecardError(
            f"scorecard not found at {path} — refusing to report a pass on a missing file"
        )
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    cells: list[Cell] = []
    for raw in data.get("cell", []):
        verdict = str(raw.get("verdict", "")).lower()
        if verdict not in VERDICTS:
            raise ScorecardError(
                f"cell {raw.get('id')!r}: verdict {verdict!r} not one of {sorted(VERDICTS)}"
            )
        cells.append(
            Cell(
                id=str(raw["id"]),
                level=int(raw["level"]),
                verdict=verdict,  # type: ignore[arg-type]
                residual=str(raw.get("residual", "")),
                posture=str(raw.get("posture", "single")),
                last_verified=str(raw.get("last_verified", "")),
                verified_at=str(raw.get("verified_at", "")),
                evidence=tuple(
                    Anchor(path=str(e["path"]), line=int(e["line"]), expect=str(e["expect"]))
                    for e in raw.get("evidence", [])
                ),
                absence=tuple(
                    Absence(pattern=str(a["pattern"]), positive_control=str(a["positive_control"]))
                    for a in raw.get("absence", [])
                ),
            )
        )
    return cells


def count(cells: list[Cell]) -> Counter[str]:
    """The count is COMPUTED. No document states one; documents render this (ADR 0156 §2)."""
    return Counter(c.verdict for c in cells)


def check_completeness(cells: list[Cell], corpus: dict[str, int]) -> list[str]:
    """Every corpus id appears exactly once, and nothing outside the corpus appears at all.

    **This is the check whose absence cost ten cells.** An enumeration that closes to the right total
    can still be missing entries; only comparing against the corpus detects that.
    """
    problems: list[str] = []
    seen = Counter(c.id for c in cells)

    for dupe, n in sorted((i, n) for i, n in seen.items() if n > 1):
        problems.append(
            f"completeness: {dupe} appears {n} times — each requirement gets exactly one cell"
        )

    missing = sorted(set(corpus) - set(seen), key=_sort_key)
    if missing:
        problems.append(
            f"completeness: {len(missing)} requirement(s) in the ASVS corpus have NO cell — "
            f"the count cannot be correct while a cell is absent: {', '.join(missing)}"
        )

    unknown = sorted(set(seen) - set(corpus), key=_sort_key)
    if unknown:
        problems.append(
            f"completeness: {len(unknown)} cell(s) are not ASVS 5.0.0 requirement ids "
            f"(retired in 5.0, or a typo): {', '.join(unknown)}"
        )

    for c in cells:
        want = corpus.get(c.id)
        if want is not None and c.level != want:
            problems.append(f"{c.id}: level {c.level} but the corpus says L{want}")
    return problems


def check_anchors(cells: list[Cell], root: Path, findings: Findings) -> None:
    """Open every evidence anchor and assert its token still resolves.

    When the code moves, this reds a test — instead of the sentence rotting in place and the next
    session funding work that is already done.
    """
    for c in cells:
        for a in c.evidence:
            target = root / a.path
            if not target.is_file():
                findings.problems.append(f"{c.id}: evidence path {a.path} does not exist")
                continue
            lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
            lo = max(0, a.line - 1 - ANCHOR_WINDOW)
            hi = min(len(lines), a.line + ANCHOR_WINDOW)
            findings.checked_anchors += 1
            if a.expect in "\n".join(lines[lo:hi]):
                continue
            where = " (found elsewhere in the file)" if a.expect in "\n".join(lines) else ""
            findings.problems.append(
                f"{c.id}: {a.path}:{a.line} no longer contains {a.expect!r} within "
                f"±{ANCHOR_WINDOW} lines{where} — the evidence moved or the claim is now false"
            )


def check_absences(cells: list[Cell], root: Path, findings: Findings) -> None:
    """An absence is proven only when its pattern is quiet AND its positive control still speaks."""
    corpus_files = _python_sources(root)
    for c in cells:
        for a in c.absence:
            findings.checked_absences += 1
            control = _grep_count(a.positive_control, corpus_files)
            if control == 0:
                findings.problems.append(
                    f"{c.id}: absence claim is BLIND — its positive control {a.positive_control!r} "
                    f"matches nothing, so a zero result for {a.pattern!r} proves nothing"
                )
                continue
            hits = _grep_count(a.pattern, corpus_files)
            if hits:
                findings.problems.append(
                    f"{c.id}: absence claim is FALSE — {a.pattern!r} now matches {hits} time(s); "
                    f"the thing recorded as missing exists"
                )


def _python_sources(root: Path) -> list[Path]:
    out: list[Path] = []
    for pkg in ("messagefoundry", "messagefoundry_webconsole", "harness", "scripts"):
        base = root / pkg
        if base.is_dir():
            out.extend(
                p
                for p in base.rglob("*.py")
                if ".venv" not in p.parts and "__pycache__" not in p.parts
            )
    return out


def _grep_count(pattern: str, files: list[Path]) -> int:
    rx = re.compile(pattern)
    return sum(1 for f in files if rx.search(f.read_text(encoding="utf-8", errors="replace")))


def _sort_key(cell_id: str) -> tuple[int, ...]:
    try:
        return tuple(int(p) for p in cell_id.split("."))
    except ValueError:  # a malformed id sorts last rather than crashing the report
        return (9_999,)


def verify(scorecard: Path, corpus: Path, root: Path) -> Findings:
    findings = Findings()
    cells = load_scorecard(scorecard)
    findings.problems.extend(check_completeness(cells, load_corpus(corpus)))
    check_anchors(cells, root, findings)
    check_absences(cells, root, findings)
    return findings


def render_current(cells: list[Cell], *, anchor_sha: str) -> str:
    """The generated entry point. A new session reads this instead of reconstructing state."""
    n = count(cells)
    total = sum(n.values())
    verified_pass = sum(1 for c in cells if c.verdict == "pass" and not c.is_inherited)
    inherited = sum(1 for c in cells if c.verdict == "pass" and c.is_inherited)
    lines = [
        "<!-- GENERATED by scripts/asvs/scorecard.py — do not edit. Edit asvs-scorecard.toml. -->",
        "",
        "# ASVS 5.0 L3 — current state",
        "",
        f"**Anchor commit:** `{anchor_sha}`",
        "",
        "| Verdict | Count |",
        "|---|---:|",
        f"| Pass | {n['pass']} |",
        f"| Partial | {n['partial']} |",
        f"| Fail | {n['fail']} |",
        f"| N/A | {n['na']} |",
        f"| **Unverified** | **{n['unverified']}** |",
        f"| **Total** | **{total}** |",
        "",
        f"Of the {n['pass']} Passes, **{verified_pass} were verified against the requirement text** and "
        f"**{inherited} are inherited** — carried from an earlier assessment and never re-read. An "
        "inherited Pass is not evidence of anything; it is the largest standing exposure in this score.",
        "",
        "## Open cells",
        "",
        "| Cell | L | Verdict | Residual |",
        "|---|---|---|---|",
    ]
    for c in sorted(
        (c for c in cells if c.verdict in {"partial", "fail"}), key=lambda c: _sort_key(c.id)
    ):
        lines.append(f"| {c.id} | L{c.level} | **{c.verdict}** | {c.residual[:160]} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Verify or render the ASVS scorecard (ADR 0156).")
    ap.add_argument("--scorecard", type=Path, required=True)
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument(
        "--root", type=Path, default=Path.cwd(), help="tree the evidence anchors point into"
    )
    ap.add_argument("--render", type=Path, help="write the generated CURRENT.md here")
    ap.add_argument("--anchor-sha", default="unknown")
    args = ap.parse_args(argv)

    try:
        findings = verify(args.scorecard, args.corpus, args.root)
    except ScorecardError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2  # could not measure — never 0, never confused with "clean"

    cells = load_scorecard(args.scorecard)
    n = count(cells)
    print(
        f"scanned {len(cells)} cells "
        f"({n['pass']} pass / {n['partial']} partial / {n['fail']} fail / {n['na']} na / "
        f"{n['unverified']} unverified); "
        f"verified {findings.checked_anchors} evidence anchors and {findings.checked_absences} absence claims"
    )
    for p in findings.problems:
        print(f"  FAIL {p}", file=sys.stderr)

    if args.render and findings.ok:
        args.render.write_text(render_current(cells, anchor_sha=args.anchor_sha), encoding="utf-8")
        print(f"rendered {args.render}")

    return 0 if findings.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

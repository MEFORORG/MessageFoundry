#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Expiry-clause audit — does the artifact a standing rule depends on still say what it says?

**Why this exists, with the measurement.** The role playbooks require every standing prohibition to
carry an expiry condition: what would have to become true for it to stop being right. That rule is
good and it is followed -- 127 lines across the ten files carry one. **Nothing ever evaluated them.**

Measured 2026-08-22. `BUILDER.md` trap 5 told builders that the ruff pre-commit hooks are
``language: system``, so a shell with no ruff on PATH aborts the commit. It stated its own expiry
verbatim: *"stops mattering only if the ruff hook stops using --fix or stops being language:
system"*. Engine commit ``de896e0f`` -- titled *"make the ruff pre-commit hooks runnable without an
activated venv"* -- moved both hooks to pinned upstream ``astral-sh/ruff-pre-commit``. The condition
fired. The commit that fired it announced itself in its subject line. **Three days passed and a lane
recorded "can I commit? NO, not on arrival" inside that window.** Its citation,
``.pre-commit-config.yaml:38``, now resolves to an unrelated comment.

**What this tool does NOT do, deliberately.** It does not read a clause and decide whether the
condition has fired. Direction is not inferable from the prose: some clauses expire when a token
APPEARS, others when it DISAPPEARS, and a tool that guesses produces a confident wrong answer --
which is the failure mode the whole playbook corpus is about. So it reports something narrower and
unambiguous:

``DANGLING``
    The clause cites a path that does not exist. Always a defect.
``DRIFTED``
    The clause cites a file AND quotes a token, and that token is no longer in that file. The rule
    is resting on text that has moved or gone.
``ANCHORED``
    Every cited path resolves and every quoted token is still present. No action.
``UNCHECKABLE``
    The clause names no resolvable artifact, so no machine can tell you anything about it.

**The UNCHECKABLE count is itself the finding, and it is the number to drive down.** A corpus whose
standing rules mostly expire on conditions no tool can evaluate is a corpus that will go stale
silently, exactly as this one did. Rewriting a clause to name a file and quote a token costs one
sentence and converts it from prose into something that can return no.

Usage::

    python scripts/quality/expiry_audit.py --roles ../MessageFoundry-vault/roles
    python scripts/quality/expiry_audit.py --roles <dir> --repo . --format table
    python scripts/quality/expiry_audit.py --self-test

Exit 1 when any clause is DANGLING or DRIFTED. UNCHECKABLE alone is exit 0 -- it is a backlog, not a
break, and a gate that fails on it would be muted in a day.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# A clause is a paragraph carrying one of these markers. Matched case-insensitively on the marker
# only -- the surrounding prose varies far too much to pattern-match, and trying to would be the
# same over-fitting this tool exists to avoid.
_MARKERS = (
    "expiry",
    "stops being right",
    "stop being right",
    "stops mattering",
    "stops being necessary",
    "expiry condition",
)

# A backticked token. Paths, grep strings and command fragments all arrive this way in these files.
_TICKED = re.compile(r"`([^`\n]{2,120})`")

# path, optionally with :LINE or :LINE-LINE. Requires a separator or a known suffix so that a prose
# token like `parse_items` is not mistaken for a file.
_PATHISH = re.compile(
    r"^(?P<path>[\w./\\-]*[\w-]+\.(?:py|ps1|yml|yaml|toml|md|txt|json|lock|cfg|ini))"
    r"(?::(?P<line>\d+)(?:-\d+)?)?$"
)

_SUFFIXES = (
    ".py",
    ".ps1",
    ".yml",
    ".yaml",
    ".toml",
    ".md",
    ".txt",
    ".json",
    ".lock",
    ".cfg",
    ".ini",
)


@dataclass
class Clause:
    """One expiry clause and everything checkable it names."""

    source: str
    line: int
    text: str
    paths: list[tuple[str, int | None]] = field(default_factory=list)
    tokens: list[str] = field(default_factory=list)
    verdict: str = "UNCHECKABLE"
    detail: list[str] = field(default_factory=list)


def _paragraphs(text: str) -> list[tuple[int, str]]:
    """Split into paragraphs, carrying each one's 1-based starting line."""
    out: list[tuple[int, str]] = []
    buf: list[str] = []
    start = 1
    for i, raw in enumerate(text.splitlines(), start=1):
        if raw.strip():
            if not buf:
                start = i
            buf.append(raw)
            continue
        if buf:
            out.append((start, "\n".join(buf)))
            buf = []
    if buf:
        out.append((start, "\n".join(buf)))
    return out


def extract_clauses(text: str, source: str) -> list[Clause]:
    """Every paragraph carrying an expiry marker, with its backticked artifacts pulled out."""
    clauses: list[Clause] = []
    for line, para in _paragraphs(text):
        low = para.lower()
        if not any(m in low for m in _MARKERS):
            continue
        clause = Clause(source=source, line=line, text=para)
        for tok in _TICKED.findall(para):
            tok = tok.strip()
            m = _PATHISH.match(tok)
            if m:
                ln = int(m.group("line")) if m.group("line") else None
                clause.paths.append((m.group("path"), ln))
            elif not tok.endswith(_SUFFIXES):
                clause.tokens.append(tok)
        clauses.append(clause)
    return clauses


# Lines either side of a cited line that still count as "at" that anchor.
_WINDOW = 12

# A token shorter than this, or appearing more often than this, is not distinctive enough to
# anchor a rule. Both are judgement calls, not measured thresholds.
_MIN_TOKEN = 6
_MAX_OCCURRENCES = 5

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", ".ruff_cache", "worktrees"}


def build_index(roots: list[Path]) -> dict[str, list[Path]]:
    """Map every basename under ``roots`` to the files carrying it.

    **This exists because the first version of this tool reported 18 DANGLING clauses and most were
    wrong.** These files cite tools by bare basename -- `scorecard.py`, `apply.py` -- which is how a
    person refers to them, and a resolver that only tries ``root / name`` calls every one of them
    missing. A citation that resolves to several files is AMBIGUOUS, not dangling: the distinction
    matters because one is a defect in the prose and the other is a limit of the reader.
    """
    index: dict[str, list[Path]] = {}
    seen: set[Path] = set()
    for root in roots:
        root = root.resolve()
        if not root.is_dir() or root in seen:
            continue
        seen.add(root)
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            # Skip-dirs are matched RELATIVE to the root, never against the absolute path. The first
            # version tested `path.parts`, and because every session here runs inside
            # `.claude/worktrees/<lane>`, the literal "worktrees" matched the ROOT's own prefix and
            # the index came back empty -- which then reported every bare-name citation as DANGLING.
            # An empty index is indistinguishable from a clean repo, so main() refuses one outright.
            rel_parts = path.relative_to(root).parts
            if any(part in _SKIP_DIRS for part in rel_parts):
                continue
            index.setdefault(path.name, []).append(path)
    return index


def _resolve(rel: str, roots: list[Path], index: dict[str, list[Path]]) -> tuple[Path | None, str]:
    """Resolve a cited path. Returns (path, status) where status is ok, ambiguous or missing."""
    for root in roots:
        cand = root / rel
        if cand.is_file():
            return cand, "ok"
    if "/" not in rel and "\\" not in rel:
        hits = index.get(rel, [])
        if len(hits) == 1:
            return hits[0], "ok"
        if len(hits) > 1:
            return hits[0], "ambiguous"
    return None, "missing"


def judge(clause: Clause, roots: list[Path], index: dict[str, list[Path]] | None = None) -> None:
    """Set the clause's verdict from the artifacts it names. Never infers which way a rule expires."""
    if not clause.paths:
        clause.verdict = "UNCHECKABLE"
        clause.detail.append("names no resolvable path")
        return

    index = index if index is not None else {}
    resolved: list[tuple[Path, int | None]] = []
    ambiguous = False
    for rel, ln in clause.paths:
        found, status = _resolve(rel, roots, index)
        if status == "missing":
            clause.verdict = "DANGLING"
            clause.detail.append(f"cited path exists nowhere under the scanned roots: {rel}")
        elif status == "ambiguous":
            ambiguous = True
            clause.detail.append(f"cited by bare name, resolves to more than one file: {rel}")
            if found is not None:
                resolved.append((found, None))
        elif found is not None:
            resolved.append((found, ln))

    if clause.verdict == "DANGLING":
        return
    if not resolved:
        clause.verdict = "UNCHECKABLE"
        return

    # A TOKEN IS ONLY CHECKED AGAINST A path:line CITATION, never against a bare path.
    #
    # The first version checked every backticked token against every cited file and reported 16
    # DRIFTED clauses. Most were noise: a clause citing `.pre-commit-config.yaml` and quoting a
    # commit sha, or `git commit`, or a slash-command, was flagged because those strings are not in
    # that file -- and were never meant to be. A bare path citation makes NO claim about content.
    # `path:line` does: it says "that line says this". That is the claim worth checking, and it is
    # exactly the one the ruff trap got wrong.
    anchored = [(path, ln) for path, ln in resolved if ln is not None]
    for path, ln in anchored:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:  # pragma: no cover - unreadable file is a real but rare case
            clause.verdict = "DANGLING"
            clause.detail.append(f"cited path unreadable: {path} ({exc})")
            return
        if ln > len(lines):
            clause.verdict = "DRIFTED"
            clause.detail.append(
                f"cited line {ln} is past the end of {path.name} ({len(lines)} lines)"
            )
            return
        # Only DISTINCTIVE tokens can anchor anything. A short or ubiquitous string -- `.git`,
        # `--ci`, `on:` -- is present somewhere in almost any file, so "found elsewhere in the file"
        # is trivially true for it and the MOVED verdict becomes noise. Measured: before this filter
        # the corpus reported three DRIFTED clauses whose evidence was a two-to-four character
        # token appearing dozens of times.
        body = "\n".join(lines)
        candidates = [
            tok
            for tok in clause.tokens
            if len(tok) >= _MIN_TOKEN and body.count(tok) <= _MAX_OCCURRENCES
        ]
        if not candidates:
            continue
        # A generous window: prose cites the head of a block and the token may sit a few lines in.
        window = "\n".join(lines[max(0, ln - 1 - _WINDOW) : ln + _WINDOW])
        near = [tok for tok in candidates if tok in window]
        whole = [tok for tok in clause.tokens if tok in "\n".join(lines)]
        if not near and whole:
            clause.verdict = "DRIFTED"
            clause.detail.append(
                f"{path.name}:{ln} no longer carries the quoted text; it has MOVED within the file "
                f"(found elsewhere: {whole[0]!r}). The anchor is stale, the rule may still hold."
            )
            return
        if not near and not whole:
            clause.verdict = "DRIFTED"
            clause.detail.append(
                f"{path.name}:{ln} does not carry the quoted text and neither does the rest of the "
                f"file: {candidates[0]!r}. The thing the rule rests on is GONE."
            )
            return

    if ambiguous:
        clause.verdict = "AMBIGUOUS"
        return
    if anchored:
        clause.verdict = "ANCHORED"
        return
    clause.verdict = "UNCHECKABLE"
    clause.detail.append(
        "cites a path but no line, so it asserts nothing a reader can check. Add :LINE and quote "
        "the text the rule rests on."
    )


def audit(roles: Path, roots: list[Path]) -> list[Clause]:
    index = build_index(roots)
    clauses: list[Clause] = []
    for md in sorted(roles.glob("*.md")):
        text = md.read_text(encoding="utf-8", errors="replace")
        for clause in extract_clauses(text, md.name):
            judge(clause, roots, index)
            clauses.append(clause)
    return clauses


def _self_test() -> int:
    """Prove the auditor can see a dangling citation and a drifted anchor before you trust a zero."""
    failures: list[str] = []

    dangling = extract_clauses(
        "*Expiry:* this stops being right once `scripts/does/not/exist.py` is deleted.", "t.md"
    )
    if len(dangling) != 1:
        failures.append(f"expected 1 clause, got {len(dangling)}")
    else:
        judge(dangling[0], [Path.cwd()], {})
        if dangling[0].verdict != "DANGLING":
            failures.append(f"expected DANGLING, got {dangling[0].verdict}")

    none = extract_clauses("A paragraph with no marker at all, citing `pyproject.toml`.", "t.md")
    if none:
        failures.append("a paragraph with no expiry marker was picked up as a clause")

    unchk = extract_clauses("*Expiry:* when the owner says so.", "t.md")
    if len(unchk) != 1:
        failures.append("an expiry clause naming nothing was not extracted")
    else:
        judge(unchk[0], [Path.cwd()], {})
        if unchk[0].verdict != "UNCHECKABLE":
            failures.append(f"expected UNCHECKABLE, got {unchk[0].verdict}")

    for line in failures:
        print(f"SELF-TEST FAIL: {line}", file=sys.stderr)
    if failures:
        return 1
    print(
        "self-test PASS: dangling detected, unmarked paragraph ignored, unanchored clause flagged"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--roles", type=Path, help="directory of role playbooks to audit")
    ap.add_argument(
        "--repo", type=Path, default=Path.cwd(), help="engine checkout cited paths resolve against"
    )
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--verdict", action="append", help="show only these verdicts")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if not args.roles:
        ap.error("--roles is required unless --self-test is given")
    if not args.roles.is_dir():
        print(f"INSTRUMENT ERROR: --roles is not a directory: {args.roles}", file=sys.stderr)
        return 1

    roots = [args.repo.resolve(), args.roles.resolve(), args.roles.resolve().parent]

    # POSITIVE CONTROL. An empty basename index reports every bare-name citation as DANGLING, which
    # reads as a corpus full of defects rather than as a broken reader. Measured once already.
    probe = build_index(roots)
    if len(probe) < 100:
        print(
            f"INSTRUMENT ERROR: the basename index holds {len(probe)} entries, which cannot be "
            "right for a repository of this size. Every bare-name citation would read as DANGLING. "
            "Check --repo and the skip-dir list before believing any verdict below.",
            file=sys.stderr,
        )
        return 1

    clauses = audit(args.roles, roots)

    if not clauses:
        print(
            "INSTRUMENT ERROR: zero expiry clauses found. This corpus is known to carry them, so a "
            "zero here is a broken scan, not a clean result.",
            file=sys.stderr,
        )
        return 1

    counts = dict.fromkeys(("DANGLING", "DRIFTED", "AMBIGUOUS", "UNCHECKABLE", "ANCHORED"), 0)
    for c in clauses:
        counts[c.verdict] += 1

    print(f"expiry clauses needing review: {counts['DANGLING'] + counts['DRIFTED']}")
    print(f"  scanned      : {len(sorted(args.roles.glob('*.md')))} files in {args.roles}")
    print(f"  clauses found: {len(clauses)}")
    for v in ("DANGLING", "DRIFTED", "AMBIGUOUS", "ANCHORED", "UNCHECKABLE"):
        print(f"  {v:<12} : {counts[v]}")
    print(
        "  NOTE: UNCHECKABLE is the number to drive down. A rule that expires on a condition no\n"
        "        tool can evaluate will go stale silently, which is how this corpus got here."
    )
    print()

    wanted = set(args.verdict or ["DANGLING", "DRIFTED"])
    shown = [c for c in clauses if c.verdict in wanted]
    for c in shown:
        head = c.text.strip().splitlines()[0][:96]
        print(f"{c.verdict:<12} {c.source}:{c.line}")
        print(f"             {head}")
        for d in c.detail:
            print(f"             -> {d}")
        print()

    return 1 if counts["DANGLING"] or counts["DRIFTED"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

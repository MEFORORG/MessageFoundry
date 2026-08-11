#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Resolve backlog CITATIONS against the item namespace, so a number cannot name the wrong ledger.

**The defect (BACKLOG #1095).** Retiring an item moves its text verbatim from ``docs/BACKLOG.md``
into ``docs/archive/backlog/BACKLOG-CLOSED.md``. Every citation that named the live file keeps
pointing at a file the item is no longer in. Measured 2026-08-07: of 129 path-bearing ``BACKLOG.md``
citations, at least 69 sites across at least 35 files named the live ledger for an archived item.

**A link checker cannot see this class, which is why it needs its own gate.** ``link_check.py``
answers "does this path resolve" and the answer is *yes* -- ``docs/BACKLOG.md`` exists. The stale
half is the human-readable number beside it. The two checkers ask different questions and neither
subsumes the other.

**The test is "does the cited FILE contain the item", never "is the item CLOSED".** Those differ, and
a sweep built on the wrong one corrupts good citations: items are archived in batches, so a closed
item legitimately sits in the live ledger until the next archival pass, and a citation naming the
live file for it is CORRECT. Resolution here is against the file each number actually lives in,
computed at run time by :func:`item_homes` from ``parse_items`` -- the same parser the status gate
uses, over the same ONE namespace spanning both files.

**Nothing here may encode where a number lives, or how many there are.** A number that is live today
is archived tomorrow, and the checker must not care. There is no item count, no per-file total and no
number-to-file table in this module; ``tests/test_backlog_citation_check.py`` moves an item between
the two files and asserts the verdicts swap, which is the property that keeps it that way.

**WHAT COUNTS AS A CITATION.** Only constructs that bind a number to a ledger path *mechanically* --
no proximity window, because a window is a tolerance and a tolerance decays:

* **In the link text** -- ``[#239](../BACKLOG.md)``, ``[BACKLOG #239](../BACKLOG.md)``.
* **In the link fragment** -- ``[#75](../archive/backlog/BACKLOG-CLOSED.md#75-browser-console)``.
* **Immediately after the link**, separated by nothing but whitespace or light punctuation --
  ``[BACKLOG](../BACKLOG.md) #11``.

A ledger link with no number attached is NOT a citation and is never flagged. That matters: prose
naming the ledger file generically ("retiring an item moves it from `BACKLOG.md` into the archive")
routinely sits on a line that also mentions some unrelated item number, and a same-line rule would
report it. Measured on this repo, the same-line rule produced false positives on exactly that shape.

**DIFF-SCOPED BY DEFAULT IN CI, and that is the design constraint rather than a convenience.** PR #271
declined a gate partly on the grounds that "a gate that fails on a legitimate archive is one people
delete". Pre-existing violations mean a corpus-wide gate is red on day one and gets suppressed, so
``--base``/``--head`` restricts findings to lines the PR ADDED. Run with neither for the repo-wide
report, which is a measurement, not a merge gate.

**Anti-narrowing.** ``backlog_status_check.py`` needs a ``--min-items`` floor because every one of its
assertions is satisfied just as well by a remnant of the corpus. This one fails the other way: read
fewer ledger files and the numbers they hold resolve to nothing, so every citation of them turns red
at once. Narrowing here is loud. The guards are therefore an empty-namespace refusal and printing the
per-file item split on every run -- never a hard-coded floor, which would itself be the count this
module must not carry.

Usage::

    python scripts/docs/backlog_citation_check.py                     # repo-wide report
    python scripts/docs/backlog_citation_check.py --base A --head B   # only lines B added

Exit 1 if any in-scope citation names a file its item does not live in.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import subprocess
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

_HERE = Path(__file__).resolve().parent


def _load_status_check() -> object:
    """Import ``backlog_status_check`` as a sibling FILE, not as a package member.

    ``scripts/`` is not a package, and the item parser must not be reimplemented here: CLAUDE.md
    section 11 is explicit that ``parse_items`` DEFINES item status and location, and a hand-rolled
    scan beside it is a second, silently different definition.
    """
    spec = importlib.util.spec_from_file_location(
        "backlog_status_check", _HERE / "backlog_status_check.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


_BSC = _load_status_check()
#: The files that together hold the numbered-item namespace. Imported, never restated: adding an
#: archive file must remain the single edit ``backlog_status_check.DEFAULT_SOURCES`` documents.
LEDGER_SOURCES: tuple[Path, ...] = tuple(_BSC.DEFAULT_SOURCES)  # type: ignore[attr-defined]

# Link with its text captured. `open` exists so the "]" position can be tested against inline-code
# spans exactly as link_check.py tests it -- same discriminator, so the two gates agree on which
# links are DISPLAYED rather than offered.
_LINK = re.compile(r"\[(?P<text>[^\[\]]*)\](?P<open>\()(?P<href>[^)\s]+?)(?P<frag>#[^)\s]*)?\)")
_FENCE = re.compile(r"^\s*```")
_CODE = re.compile(r"`[^`]*`")

#: `#123` anywhere in a link's display text.
_TEXT_NUM = re.compile(r"#(\d+)\b")
#: A fragment naming an item: `#1095-backlog-citations...` or a bare `#1095`.
_FRAG_NUM = re.compile(r"^#(\d+)(?:-|$)")
#: A number immediately following the link, separated by nothing but whitespace/light punctuation.
#: NOT a proximity window -- there is no distance to tune; either the number abuts the link or it is
#: not a citation of it.
_TRAILING_NUM = re.compile(r"^[\s,;:]*#(\d+)\b")

_DIFF_FILE = re.compile(r"^\+\+\+ b/(?P<path>.+)$")
_DIFF_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,(?P<count>\d+))? @@")


@dataclass(frozen=True)
class Citation:
    """One number bound to one ledger path by one of the three constructs above."""

    file: str
    line: int
    number: int
    target: str
    construct: str


def item_homes(sources: Sequence[tuple[str, str]]) -> dict[int, str]:
    """Map each item number to the LABEL of the source it lives in.

    ``sources`` is ``(label, text)`` pairs, matching ``backlog_status_check.scan``. One namespace: a
    number lives in exactly one place and the caller supplies every place it could be. Nothing about
    which label holds which number is assumed -- that is the whole point, since archival moves them.
    """
    homes: dict[int, str] = {}
    for label, text in sources:
        for item in _BSC.parse_items(text):  # type: ignore[attr-defined]
            homes.setdefault(item.num, label)
    return homes


def _normalise(base: PurePosixPath, href: str) -> str:
    """Resolve ``href`` against ``base`` without touching the filesystem (link_check.py's rule)."""
    parts: list[str] = []
    for part in (base / href).parts:
        if part == "..":
            if parts:
                parts.pop()
        elif part != ".":
            parts.append(part)
    return "/".join(parts)


def find_citations(rel: str, text: str, ledgers: Iterable[str]) -> list[Citation]:
    """Every ledger citation in one markdown file.

    Fenced blocks are skipped (a path in a transcript is output being shown, not a link to follow),
    and so are links inside inline code, by POSITION -- the dominant idiom ``[`x.md`](../x.md)``
    closes its code span before the ``]`` and is therefore still checked, exactly as in link_check.
    """
    ledger_set = set(ledgers)
    here = PurePosixPath(rel).parent
    found: list[Citation] = []
    in_fence = False

    for lineno, line in enumerate(text.splitlines(), 1):
        if _FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        code_spans = [c.span() for c in _CODE.finditer(line)]
        for m in _LINK.finditer(line):
            bracket = m.start("open") - 1
            if any(s <= bracket < e for s, e in code_spans):
                continue
            target = _normalise(here, m.group("href"))
            if target not in ledger_set:
                continue
            for num in _TEXT_NUM.findall(m.group("text")):
                found.append(Citation(rel, lineno, int(num), target, "link text"))
            frag = m.group("frag")
            if frag and (fm := _FRAG_NUM.match(frag)):
                found.append(Citation(rel, lineno, int(fm.group(1)), target, "fragment"))
            if tm := _TRAILING_NUM.match(line[m.end() :]):
                found.append(Citation(rel, lineno, int(tm.group(1)), target, "adjacent"))
    return found


def check(citations: Iterable[Citation], homes: dict[int, str]) -> tuple[list[str], list[str]]:
    """Return ``(errors, warnings)``. Empty ``errors`` means the gate passes.

    **A number the namespace does not carry is a WARNING, never an error, and that is a measured
    decision rather than caution.** ``docs/BACKLOG.md`` says of itself that it is a *published
    baseline* of a fuller maintainer-internal ledger, and names numbers deliberately absent from it.
    Measured on this repo 2026-08-10, the unresolvable citations are #13, #270 and #287 -- all
    confirmed real items behind that publishing boundary, none of them a broken citation. Failing on
    them would make the gate red for a reason no contributor can fix, which is precisely how a gate
    comes to be deleted (PR #271's surviving objection). It stays reported, because the same class
    also catches a mistyped number, and a warning is where that belongs.
    """
    # One finding per (file, line, number, target). `[#75](...BACKLOG-CLOSED.md#75-slug)` binds the
    # same number to the same path through TWO constructs, and reporting it twice is noise that
    # inflates the count -- the constructs are diagnostics, not separate defects.
    bound: dict[tuple[str, int, int, str], list[str]] = {}
    for c in citations:
        key = (c.file, c.line, c.number, c.target)
        seen = bound.setdefault(key, [])
        if c.construct not in seen:
            seen.append(c.construct)

    errors: list[str] = []
    warnings: list[str] = []
    for (rel, line, number, target), constructs in sorted(bound.items()):
        how = "+".join(constructs)
        home = homes.get(number)
        if home is None:
            warnings.append(
                f"{rel}:{line}: #{number} ({how}) cites {target}, which carries no item #{number}. "
                f"Expected for an item above the published baseline; a typo otherwise."
            )
        elif home != target:
            errors.append(
                f"{rel}:{line}: #{number} ({how}) cites {target}, but item #{number} lives in {home}"
            )
    return errors, warnings


def added_lines(root: Path, base: str, head: str) -> dict[str, set[int]]:
    """Markdown lines this change ADDED, as ``{path: {lineno, ...}}``.

    THREE-dot, matching the job this runs beside. Two-dot asks how the two trees differ, which
    includes everything the base branch gained since the PR branched -- as a reverse delta on paths
    the PR never touched -- so a main-side archival move would be credited to every open PR.
    """
    out = subprocess.run(  # nosec B603 B607 - fixed argv, no shell, no caller-supplied executable
        [
            "git",
            "-C",
            str(root),
            "diff",
            "--unified=0",
            "--no-color",
            f"{base}...{head}",
            "--",
            "*.md",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    ).stdout

    added: dict[str, set[int]] = {}
    current: str | None = None
    for line in out.splitlines():
        if fm := _DIFF_FILE.match(line):
            path = fm.group("path")
            current = None if path == "/dev/null" else path
            continue
        if current is None:
            continue
        if hm := _DIFF_HUNK.match(line):
            start = int(hm.group("start"))
            count = int(hm.group("count") or 1)
            if count:
                added.setdefault(current, set()).update(range(start, start + count))
    return added


def repo_root() -> Path:
    out = subprocess.run(  # nosec B603 B607 - fixed argv, no shell, no caller-supplied executable
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    ).stdout.strip()
    return Path(out)


def tracked_markdown(root: Path) -> list[str]:
    out = subprocess.run(  # nosec B603 B607 - fixed argv, no shell, no caller-supplied executable
        ["git", "-C", str(root), "ls-files", "*.md"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    ).stdout
    return sorted(set(out.split()))


def _read(root: Path, rel: str) -> str | None:
    try:
        return (root / rel).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _read_at(root: Path, rev: str, rel: str) -> str | None:
    """One file's content AT ``rev``, or None if it is absent there.

    In diff scope this replaces reading the working tree, and the reason is that the two answer
    different questions. On a ``pull_request`` event ``actions/checkout`` lands the MERGE ref -- base
    merged with head -- while ``--base/--head`` computes line numbers against HEAD. Where a file
    moved on both sides those line numbers index a file the checkout does not contain, so a finding
    would name a line that is not the line, in either direction. Content and line numbers must come
    from the same revision or the instrument is answering an adjacent question.
    """
    done = subprocess.run(  # nosec B603 B607 - fixed argv, no shell, no caller-supplied executable
        ["git", "-C", str(root), "show", f"{rev}:{rel}"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    return done.stdout if done.returncode == 0 else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--base", default=None, metavar="SHA", help="merge-base side of the diff scope")
    ap.add_argument("--head", default=None, metavar="SHA", help="head side of the diff scope")
    args = ap.parse_args(argv)

    if (args.base is None) != (args.head is None):
        print("ERROR: --base and --head must be given together", file=sys.stderr)
        return 2

    root = repo_root()
    ledger_labels = [p.as_posix() for p in LEDGER_SOURCES]
    sources: list[tuple[str, str]] = []
    for label in ledger_labels:
        text = _read(root, label)
        if text is not None:
            sources.append((label, text))
    homes = item_homes(sources)

    split = ", ".join(
        f"{label} ({sum(1 for n in homes if homes[n] == label)})" for label, _ in sources
    )
    print(f"backlog_citation_check: namespace = {len(homes)} items from {split or '(nothing)'}")
    if not homes:
        # Loud on purpose. Every citation would resolve to nothing and the run would look like a
        # corpus-wide failure; say which files were unreadable instead of reporting thousands of
        # findings whose real cause is one missing path.
        print(
            f"ERROR: no items parsed. Expected the ledger namespace in {ledger_labels}.",
            file=sys.stderr,
        )
        return 1

    head_rev: str | None = args.head
    if args.base is None:
        scope_lines: dict[str, set[int]] | None = None
        files = tracked_markdown(root)
        scope = f"<whole repo>, {len(files)} markdown files"
    else:
        assert head_rev is not None  # nosec B101 - paired with --base by the check above
        scope_lines = added_lines(root, args.base, head_rev)
        files = sorted(scope_lines)
        n_lines = sum(len(v) for v in scope_lines.values())
        listed = ", ".join(f"{f} (+{len(scope_lines[f])})" for f in files) or "(none)"
        scope = f"lines added by {args.base}...{args.head} — {n_lines} in {len(files)} file(s)"
        print(f"     added-line scope: {listed}")

    citations: list[Citation] = []
    unreadable: list[str] = []
    for rel in files:
        # Diff scope reads the file AT --head, never the working tree: see _read_at(). Repo-wide is
        # a local report over what is checked out, which is the question being asked there.
        text = _read(root, rel) if head_rev is None else _read_at(root, head_rev, rel)
        if text is None:
            # A file that vanished between the diff and the read is a deletion, not a finding.
            if scope_lines is None:
                unreadable.append(rel)
            continue
        found = find_citations(rel, text, ledger_labels)
        if scope_lines is not None:
            found = [c for c in found if c.line in scope_lines[rel]]
        citations.extend(found)

    print(f"     scanned: {scope}")
    print(f"     ledger citations in scope: {len(citations)}")
    for rel in unreadable:
        print(f"WARN: could not read {rel}", file=sys.stderr)

    errors, warnings = check(citations, homes)
    for w in warnings:
        print(f"WARN: {w}", file=sys.stderr)
    if errors:
        print(f"FAIL: {len(errors)} citation(s) name a file their item does not live in")
        for f in errors:
            print(f"  {f}")
        print(
            "\nRepoint each to the file the number actually lives in. Closing an item MOVES it into "
            "the archive, so a citation written against the live ledger goes stale the moment the "
            "next archival pass runs -- the link still resolves, which is why only this check sees "
            "it. Do not repoint a subset of a passage: uniform staleness is at least detectable, "
            "while repointing some sites asserts by contrast that the untouched siblings are live."
        )
        return 1
    extra = f" ({len(warnings)} advisory warning(s))" if warnings else ""
    print(f"OK: every ledger citation in scope names the file its item lives in{extra}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

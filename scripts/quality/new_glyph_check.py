# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Refuse a commit that ADDS a glyph or emoji, because CLAUDE.md section 11 forbids new ones.

CLAUDE.md section 11 bans glyphs and emoji in prose, comments and commit messages, and says no new
glyph vocabulary may be introduced anywhere. Until this hook the rule was held by prose alone.
Measured 2026-10-07 over the last 200 first-parent commits on ``main``: 7 commits staged 12 added
lines carrying a glyph, for example U+26D4 in ``docs/ASVS-ASSESSMENT-METHOD.md`` and U+2717 in
``harness/reconcile/report.py``. Every one of them edited a line that already carried that glyph,
so the NET count below was zero. This hook holds that zero for every commit that runs hooks.

IT IS LOCAL ONLY, AND THAT IS A REAL GAP. A commit made by the sequencer (rebase, cherry-pick), a
``--no-verify`` commit and a clone that never ran ``pre-commit install`` all skip it, and no CI step
mirrors it: a step in a required job is a merge-gate change, which needs the owner.
``tests/test_gate_ci_mirror_parity.py`` records it under ``_LOCAL_ONLY`` for that reason.

WHAT IT READS: THE STAGED DIFF, NOT WHOLE FILES. Hundreds of glyphs already sit in tracked files.
Removing them is a filed migration (BACKLOG #1265), and section 11 says not to sweep them out of a
file you are editing for another reason. So the check counts NET additions across the commit: each
banned codepoint on an added line is first matched against the same codepoint on a removed line.
Editing a status-table row that already carried a check mark passes, and so does moving that row to
another file or deleting the old file; adding a new mark does not. Rename detection is OFF, so a
rename reads as a deletion plus an addition and its glyphs are judged by the new path. A removed
line in an exempt file feeds no pool, so a glyph cannot be laundered out of a dated record into a
live doc, by moving a row or by renaming the file. The first draft judged every added line, and it
would have refused all 7 of those commits.

WHAT IT REFUSES: any codepoint in ``BANNED_RANGES``. That is Miscellaneous Symbols and Dingbats
(U+2600-27BF), Miscellaneous Symbols and Arrows (U+2B00-2BFF), the emoji planes (U+1F000-1FAFF) and
the emoji variation selector U+FE0F. Plain arrows (U+2190-21FF), box drawing and accented letters
are outside every range on purpose: the operator docs carry many arrows legitimately.

WHAT IT ALLOWS:

* a glyph quoted inside backticks, the token form section 11 permits for naming a glyph, but only
  in the suffixes ``BACKTICK_IS_TOKEN`` names. Elsewhere a backtick is code: a template literal in
  TypeScript, an escape in PowerShell, a raw string in Go, command substitution in shell. A glyph
  inside one is user-visible output, not a quoted token;
* any line under ``EXEMPT_PATHS`` or ``EXEMPT_PREFIXES``. Those are exactly the files
  ``tests/test_operator_docs_no_warning_sign.py`` holds or exempts, and
  ``tests/test_new_glyph_check.py`` fails if the two lists drift apart.

It never prints a glyph. A stock Windows cp1252 console raises ``UnicodeEncodeError`` on one, so
every report names the codepoint as ``U+XXXX`` and folds the line excerpt to ASCII.

A MERGE IS JUDGED AGAINST EVERY PARENT. While ``MERGE_HEAD`` exists, a glyph counts as new only if
it is new against HEAD and against each merged head. Otherwise resolving a conflict with ``main``
would refuse every glyph ``main`` gained since the branch forked. Each parent yields a net count per
codepoint, and the smallest of those counts is what the merge added.

ONE KNOWN BLIND SPOT: ``git commit --amend``. Staged mode diffs against HEAD, and a pre-commit hook
cannot tell that the commit being written replaces it. So an amend judges only what it changes on
top of the commit it amends.

Usage:
  new_glyph_check.py                 # judge the staged diff (how pre-commit invokes it)
  new_glyph_check.py --commit REV    # judge what commit REV added (a dry run over history)

Exit: 0 clean, 1 a new glyph was found, 2 git could not be read (fails closed).
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

#: Inclusive codepoint ranges a new line may not carry.
BANNED_RANGES: tuple[tuple[int, int], ...] = (
    (0x2600, 0x27BF),
    (0x2B00, 0x2BFF),
    (0x1F000, 0x1FAFF),
    (0xFE0F, 0xFE0F),
)

#: Dated records, exempt by the owner ruling of 2026-09-30. Mirrors ``_DATED_RECORDS`` in
#: ``tests/test_operator_docs_no_warning_sign.py``.
EXEMPT_PREFIXES: tuple[str, ...] = ("docs/benchmarks/",)

#: Files that keep a glyph on purpose. Mirrors the keys of ``_HELD`` in
#: ``tests/test_operator_docs_no_warning_sign.py``, where each carries its reason.
EXEMPT_PATHS: frozenset[str] = frozenset(
    {
        "CHANGELOG.md",
        "CLA.md",
        "COMMERCIAL-LICENSE.md",
        "tests/test_ledger_check.py",
        "ide/src/hl7Picker.ts",
        "ide/src/liveDebug.ts",
        "ide/src/stepsModel.ts",
        "harness/load/shardcert_ladder.py",
        "harness/load/shardcert.py",
    }
)

#: Suffixes where a backtick span is a quoted token: prose, and Python, whose comments and
#: docstrings quote tokens that way and whose strings rarely carry a backtick.
BACKTICK_IS_TOKEN: tuple[str, ...] = (".md", ".markdown", ".rst", ".txt", ".py")

#: One backtick span: a run of backticks, the shortest text, then the same run again.
_BACKTICK_SPAN = re.compile(r"(`+)(.+?)\1")

#: The hunk header's new-file start line.
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

#: git's well-known empty tree, the parent of a root commit.
_EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

_EXCERPT_LIMIT = 120


class GitReadError(RuntimeError):
    """git failed, so this check cannot say what was added."""


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    codepoint: int
    text: str
    count: int = 1


@dataclass
class Diff:
    """A parsed ``--unified=0`` diff.

    ``added`` holds every added line as (path, line number, text). ``pool`` counts the banned
    codepoints on removed lines of non-exempt files, keyed by the OLD path's exemption.
    """

    added: list[tuple[str, int, str]] = field(default_factory=list)
    pool: Counter[int] = field(default_factory=Counter)

    @property
    def files(self) -> int:
        return len({p for p, _, _ in self.added})


def is_banned(ch: str) -> bool:
    """Whether *ch* is in one of :data:`BANNED_RANGES`."""
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in BANNED_RANGES)


def is_exempt(path: str) -> bool:
    return path in EXEMPT_PATHS or path.startswith(EXEMPT_PREFIXES)


def banned_in(line: str, path: str = "") -> list[int]:
    """Every banned codepoint in *line*, one entry per occurrence.

    Backtick spans are skipped only when *path* has a suffix in :data:`BACKTICK_IS_TOKEN`.
    """
    if line.isascii():
        return []
    bare = _BACKTICK_SPAN.sub("", line) if path.lower().endswith(BACKTICK_IS_TOKEN) else line
    return [ord(ch) for ch in bare if is_banned(ch)]


def _run_git(*args: str) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            ["git", "-c", "core.quotepath=off", "-c", "diff.interHunkContext=0", *args],
            capture_output=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitReadError(f"git {' '.join(args[:2])} did not run: {exc}") from exc


def _failure(proc: subprocess.CompletedProcess[bytes], what: str) -> GitReadError:
    lines = proc.stderr.decode("utf-8", "replace").strip().splitlines()
    return GitReadError(f"{what} exited {proc.returncode}: {lines[0] if lines else 'no output'}")


def _git(*args: str) -> bytes:
    proc = _run_git(*args)
    if proc.returncode != 0:
        raise _failure(proc, f"git {' '.join(args[:2])}")
    return proc.stdout


def _rev_exists(rev: str) -> bool:
    """Whether *rev* names a commit. Exit 1 means it does not; any other failure raises."""
    proc = _run_git("rev-parse", "-q", "--verify", f"{rev}^{{commit}}")
    if proc.returncode == 0:
        return True
    if proc.returncode == 1 and not proc.stderr.strip():
        return False
    raise _failure(proc, f"git rev-parse {rev}")


def _path_from_header(raw: str, prefix: str) -> str | None:
    """The path from a ``---`` or ``+++`` header, or None for ``/dev/null``."""
    name = raw[4:].rstrip("\t")
    if name == "/dev/null":
        return None
    if name.startswith('"') and name.endswith('"'):
        name = name[1:-1]
    return name[len(prefix) :] if name.startswith(prefix) else name


def parse_diff(diff: bytes) -> Diff:
    """Parse a ``--unified=0 --no-renames`` diff into a :class:`Diff`."""
    out = Diff()
    old: str | None = None
    new: str | None = None
    lineno = 0
    in_hunk = False
    for raw_bytes in diff.split(b"\n"):
        raw = raw_bytes.decode("utf-8", "replace").rstrip("\r")
        if raw.startswith("diff --git "):
            old = new = None
            in_hunk = False
            continue
        if not in_hunk and raw.startswith("--- "):
            old = _path_from_header(raw, "a/")
            continue
        if not in_hunk and raw.startswith("+++ "):
            new = _path_from_header(raw, "b/")
            continue
        hunk = _HUNK.match(raw)
        if hunk:
            in_hunk = True
            lineno = int(hunk.group(1))
            continue
        if not in_hunk:
            continue
        if raw.startswith("+") and new is not None:
            out.added.append((new, lineno, raw[1:]))
            lineno += 1
        elif raw.startswith("-") and old is not None and not is_exempt(old):
            out.pool.update(banned_in(raw[1:], old))
        elif raw.startswith(" "):
            lineno += 1  # a context line, which -U0 should not emit; counted so lines stay true
    return out


def new_glyphs(diff: Diff) -> list[Finding]:
    """Banned codepoints added beyond what the commit's removed lines held.

    The pool spans the whole commit, so a row moved between files is not new. One finding per line
    and codepoint; :attr:`Finding.count` says how many of that codepoint the line added.
    """
    pool = Counter(diff.pool)
    found: list[Finding] = []
    for path, line, text in diff.added:
        if is_exempt(path):
            continue
        fresh: Counter[int] = Counter()
        for cp in banned_in(text, path):
            if pool[cp] > 0:
                pool[cp] -= 1
            else:
                fresh[cp] += 1
        for cp, count in fresh.items():
            found.append(Finding(path, line, cp, text, count))
    return found


def _diff(base: str, target: str | None) -> bytes:
    args = [
        "diff",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--no-relative",
        "--no-renames",
        "--unified=0",
        "--src-prefix=a/",
        "--dst-prefix=b/",
    ]
    if target is None:
        return _git(*args, "--cached", base)
    return _git(*args, base, target)


def _parents(target: str | None) -> list[str]:
    if target is None:
        parents = ["HEAD"] if _rev_exists("HEAD") else [_EMPTY_TREE]
        merge_head = Path(_git("rev-parse", "--git-path", "MERGE_HEAD").decode().strip())
        if merge_head.is_file():
            parents += merge_head.read_text(encoding="ascii", errors="replace").split()
        return parents
    listing = _git("rev-list", "--parents", "-n", "1", target).decode().split()
    return listing[1:] or [_EMPTY_TREE]


def collect(target: str | None) -> tuple[list[Finding], int, int]:
    """New glyphs added by *target* (a commit) or, when None, by the index, against every parent.

    Also returns the added-line and file counts against the first parent, so a clean run can say
    what it judged.
    """
    parents = _parents(target)
    first = parse_diff(_diff(parents[0], target))
    found = new_glyphs(first)
    if len(parents) > 1:
        # The merge added, per codepoint, the smallest net count any parent shows. The lines named
        # are the first parent's, trimmed to that count, preferring a line every parent flags: that
        # is the one the merge itself wrote, rather than one the other side already had.
        allowed: Counter[int] = Counter()
        for f in found:
            allowed[f.codepoint] += f.count
        seen: Counter[tuple[str, str, int]] = Counter()
        for parent in parents[1:]:
            net: Counter[int] = Counter()
            for f in new_glyphs(parse_diff(_diff(parent, target))):
                net[f.codepoint] += f.count
                seen[(f.path, f.text, f.codepoint)] += 1
            allowed &= net
        ranked = sorted(found, key=lambda f: -seen[(f.path, f.text, f.codepoint)])
        kept: list[Finding] = []
        for f in ranked:
            take = min(f.count, allowed[f.codepoint])
            if take > 0:
                allowed[f.codepoint] -= take
                kept.append(Finding(f.path, f.line, f.codepoint, f.text, take))
        found = kept
    return found, len(first.added), first.files


def _ascii(text: str, limit: int = _EXCERPT_LIMIT) -> str:
    folded = text.strip().encode("ascii", "backslashreplace").decode("ascii")
    return folded if len(folded) <= limit else folded[: limit - 3] + "..."


def report(found: list[Finding]) -> str:
    rows = []
    for f in found:
        name = unicodedata.name(chr(f.codepoint), "UNNAMED")
        times = f" x{f.count}" if f.count > 1 else ""
        rows.append(
            f"  {_ascii(f.path, 200)}:{f.line}: U+{f.codepoint:04X} {name}{times}\n"
            f"      line: {_ascii(f.text)}"
        )
    total = sum(f.count for f in found)
    return (
        "\nMessageFoundry new-glyph check\n\n"
        f"  This commit ADDS {total} glyph or emoji codepoint(s). CLAUDE.md section 11 forbids\n"
        "  them in prose, comments and code: a glyph's meaning is invisible to grep and to a screen\n"
        "  reader, and it raises UnicodeEncodeError on a stock cp1252 console.\n\n"
        + "\n".join(rows)
        + "\n\n  Fix each line, then stage and commit again:\n"
        "    * in prose or a comment, write the word: DONE, FAILED, WARNING, NOTE, YES, NO;\n"
        "    * to NAME a glyph as a token, quote it in backticks, which this check allows\n"
        "      (only in .md, .rst, .txt and .py; elsewhere a backtick is code);\n"
        "    * in code that must emit one, write an escape such as \\N{WARNING SIGN} or \\u26a0,\n"
        "      so the source stays ASCII.\n"
        "  Only NET additions are judged: editing a line that already carried the glyph passes.\n"
        "  Glyphs already on main are BACKLOG #1265's migration, not this commit's.\n"
        "  The exempt files are listed in scripts/quality/new_glyph_check.py.\n\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--commit", metavar="REV", help="judge what commit REV added")
    args = parser.parse_args(argv)
    try:
        if args.commit is not None and not _rev_exists(args.commit):
            sys.stderr.write(f"new-glyph check: --commit needs ONE commit, not {args.commit!a}\n")
            return 2
        found, lines, files = collect(args.commit)
    except GitReadError as exc:
        sys.stderr.write(
            f"\nnew-glyph check: git could not be read, so this commit was NOT checked.\n  {exc}\n"
            "  Refusing rather than passing unchecked. Fix git, then commit again.\n"
        )
        return 2
    if found:
        sys.stderr.write(report(found))
        return 1
    print(f"new-glyph check: {lines} added line(s) in {files} file(s), no new glyph")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Report OPEN backlog items whose code-side subject already exists on `origin/main` (BACKLOG #1426).

WHAT EVERY OTHER LEDGER SCREEN READS, AND WHY THAT IS NOT ENOUGH. `backlog_status_check.py` asks
whether an item declares a status. `backlog_citation_check.py` asks whether a citation names the file
its item lives in. `dangling_citation_check.py` asks whether a cited number names anything at all.
Every one of them reads the LEDGER. None reads the CODE, so none can notice the failure below, and
the #1234 amendment states the gap in terms: "Does the subject exist on main is the only check that
reads the CODE, and it is the one that decides startability."

THE FAILURE, MEASURED TWICE ON 2026-09-03. Five items were dispatched as builds and two were already
complete, each discovered only after a Builder had been spent on it.

  * #1040 -- all three commits from its branch were ancestors of `main` and its cited PR was on
    `main`. The row stayed open behind a note saying the banner was left open for an archive pass,
    while an older re-score beneath it still described the landed work as outstanding.
  * #1229 -- its backslash-escape limb shipped 2026-08-22 in `3c5cb9885`, whose subject names
    BACKLOG #1268, NOT #1229. The re-score calling the limb unbuilt is dated 2026-08-20, two days
    BEFORE the merge. Searching on the item number does not find the commit that implemented it.

The common shape is a re-score dated before the landing, with nothing afterward reading the code. So
this tool extracts each open item's concrete code-side subjects -- commit shas, merged pull requests,
file paths and distinctive symbol names -- and asks git whether they are already on `origin/main`.

FOUR CONSTRAINTS, EACH LOAD-BEARING.

1. IT REPORTS CANDIDATES AND NEVER FLIPS A BANNER. A wrongly-closed item is invisible forever, so
   the output is a list for a person to read, item by item. There is no `--fix` and there must not
   be one.
2. OVER-FIRING IS THE TOLERABLE DIRECTION. A false candidate costs one read; a missed one costs a
   whole Builder, which is what the two cases above each cost. Where a probe cannot answer, the
   answer is a signal rather than silence -- see the shallow-clone handling below.
3. IT PRINTS WHAT IT SCANNED. Items examined, subjects extracted per kind, subjects resolved, probes
   skipped by a cap. An empty scan and a clean scan must not render alike; that is this project's
   named failure shape and it has fired repeatedly.
4. IT RUNS A CONTROL THAT MUST FIRE, in both directions, before it reports anything. `--self-test`
   alone runs it and stops. Two layers:
     * A STRUCTURAL control over the probes themselves, with a positive and a negative arm each:
       a known commit resolves and a nonsense one does not, a tracked path resolves and an invented
       one does not. A probe validated on one input is not validated.
     * A LEDGER control over #1229 and #1040, the two known-true cases. While either is OPEN it MUST
       come out a candidate. When one is closed the control RETIRES and says so by name rather than
       passing silently -- a control that stops applying must not read like a control that passed.
   A structural failure exits 2 and says the SCREEN is broken. A clean report exits 0. The two must
   never be confused, which is the whole reason the exit codes differ.

`#N` IS AMBIGUOUS IN THIS REPOSITORY AND IS NEVER READ BARE. A bare `#N` spells a pull request just
as well as a backlog item, and a security record entry reading "the build is #156" once resolved to a
pull request while backlog #156 was unrelated work. So only the literal forms are read: `BACKLOG #N`
is a cross-reference and is NEVER treated as a subject, and only an explicit `PR #N` / `pull request
#N` is resolved against the merge history. A bare `#N` is ignored by both.

A SHA IS EVIDENCE ONLY IF ANCESTRY IS TESTED. Appearing in `git log` output answers a different
question -- every branch's commits appear there. The probe is `git merge-base --is-ancestor <sha>
origin/main`.

THE SHALLOW-CLONE TRAP IS LIVE HERE, NOT HYPOTHETICAL. Measured 2026-09-03: this repository reports
`--is-shallow-repository` true with 16 graft points over 931 commits reachable from `origin/main`.
Under a graft the two ancestry answers are NOT equally sound. A TRUE is reliable -- the walk found
the commit. A FALSE may only mean the walk hit a boundary and stopped, and an unresolvable sha may
merely be beyond it. Reporting either as "not on main" is the confident wrong answer constraint 7 of
the brief forbids, so both become an explicit `unverifiable-shallow` signal that still surfaces the
item.

WHY THE ITEM'S DATE IS "the newest date written anywhere in the row" and not the banner's. The banner
block's extent is defined by `parse_items`, which this module imports rather than re-deriving
(CLAUDE.md section 11), and that reader returns status and fields but not text. The newest date over
the whole row is a coarser proxy for "when did a person last read this", and its error runs one way:
a stray later date makes the date-based signals fire LESS. That is the under-firing direction, so the
two signals that caught both known cases -- sha ancestry and merged pull requests -- are deliberately
date-free, and an item carrying NO date at all is surfaced rather than skipped.

Usage::

    python scripts/docs/subject_exists_screen.py                 # full screen, text report
    python scripts/docs/subject_exists_screen.py --self-test     # controls only, then stop
    python scripts/docs/subject_exists_screen.py --item 1229     # one item, with every probe shown
    python scripts/docs/subject_exists_screen.py --json          # machine-readable

Exit 0 report produced (candidates or not); 1 a ledger control failed to fire; 2 the screen is broken.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

_HERE = Path(__file__).resolve()
_ROOT = _HERE.parents[2]

# ---------------------------------------------------------------------------------------------
# Reading the ledger. `parse_items` DEFINES what an item and its status are; a hand-rolled scan is a
# second, silently different definition (CLAUDE.md section 11), so it is imported by path rather than
# reimplemented. Loaded this way because `scripts/` is not an importable package.
# ---------------------------------------------------------------------------------------------


def _load_status_check() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_backlog_status_check", _HERE.parent / "backlog_status_check.py"
    )
    if spec is None or spec.loader is None:  # pragma: no cover - a broken checkout
        raise RuntimeError("cannot load scripts/docs/backlog_status_check.py")
    module = importlib.util.module_from_spec(spec)
    # Registered BEFORE execution. Harmless today and load-bearing the moment that module grows a
    # `@dataclass`: dataclass processing resolves `sys.modules[cls.__module__]` mid-class-body, and
    # an unregistered module turns that into an AttributeError naming neither file.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------------------------
# Extraction -- the pure layer. Everything here is a function of text alone, so it is testable with
# no git, no network and no live ledger.
# ---------------------------------------------------------------------------------------------

#: A cross-reference to another ledger item. Matched ONLY in its literal form. Never a subject.
_BACKLOG_REF = re.compile(r"BACKLOG\s+#(\d+)", re.IGNORECASE)

#: A pull request, in its literal forms only. A bare `#N` is deliberately NOT matched: it spells a
#: pull request and a backlog item identically, and guessing has already resolved one to the wrong
#: subject in this repository.
_PR_REF = re.compile(r"\b(?:PRs?|pull\s+requests?)\s+#?(\d+)", re.IGNORECASE)

#: An abbreviated or full commit sha. A run of hex 7-40 long, not touching a word character or `#` on
#: either side. Pure-decimal runs are rejected below: they are overwhelmingly numbers, and a real sha
#: that happens to be all digits simply fails to resolve, which costs recall on roughly one sha in
#: ten million.
_SHA = re.compile(r"(?<![\w#])([0-9a-f]{7,40})(?![\w])")

#: A repo-relative path with a directory and a file extension. `../` prefixes come from the ledger's
#: markdown links and are stripped by _normalise_path.
#:
#: THE LOOKBEHIND ADMITS A BACKTICK AND REFUSES `/`, AND BOTH HALVES ARE LOAD-BEARING. It first read
#: ``(?<![\w`])``, which refused a backtick -- so the ledger's most common way of naming a path,
#: inside a code span, could not match at its start and the regex matched a SUFFIX instead. Measured
#: 2026-09-03 on the #1229 row: ``scripts/hooks/worktree_gate.ps1`` came out as
#: ``hooks/worktree_gate.ps1``, which resolves against nothing and reported as absent. A truncated
#: path is the worst of the three outcomes, because it renders as a confident negative.
_PATH = re.compile(
    r"(?<![\w/.-])((?:\.\.?/)*(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+"
    r"\.(?:py|ps1|sh|ts|js|toml|md|ya?ml|sql|txt|json|cfg|ini|lock))"
)

#: A bare filename with no directory. Admitted only for distinctive extensions and a distinctive
#: stem, because a bare name is ambiguous by construction -- `worktree_gate.ps1:347-388` is how the
#: #1229 row names its own subject, and dropping the class would lose it. The lookbehind refuses `-`
#: for the same truncation reason as above: ``install-git-hooks.ps1`` must not come out
#: ``git-hooks.ps1``.
_BARE_FILE = re.compile(
    r"(?<![\w/.-])([A-Za-z0-9_-]{6,}\.(?:py|ps1|ts|toml|ya?ml|sql))(?![\w/])",
)

#: Contents of a single-backtick span. Symbols are taken from here only: an unquoted identifier in
#: ledger prose is indistinguishable from an English word.
_TICKED = re.compile(r"`([^`\n]{1,120})`")

_SNAKE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$")
_VERB_NOUN = re.compile(r"^[A-Z][a-z]+(?:-[A-Z][A-Za-z0-9]+)+$")
_PASCAL = re.compile(r"^[A-Z][a-z0-9]+(?:[A-Z][A-Za-z0-9]*)+$")

_ISO_DATE = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b")

#: Wording that makes a nearby sha or pull request a claim that work LANDED, rather than a base ref
#: the item was measured against. Both classes are reported; only the first is ranked strong, because
#: "Measured at `efe061a3f`" is an ordinary and uninteresting citation of an ancestor commit.
_LANDING_WORDS = re.compile(
    r"\b(?:landed|lands|landing|shipped|ships|merged|merges|"
    r"fixed\s+in|closed\s+by|implemented|delivered|resolved\s+in|"
    r"reached\s+main|is\s+on\s+main|already\s+on\s+main)\b",
    re.IGNORECASE,
)
_MEASUREMENT_WORDS = re.compile(
    r"\b(?:measured|re-measured|as\s+of|at\s+HEAD|against|baseline|base\s+ref|this\s+branch)\b",
    re.IGNORECASE,
)

#: Identifiers common enough that their presence on main says nothing. Kept deliberately short: the
#: symbol signal is WEAK already, so the list exists to keep a report readable, not to gate recall.
_SYMBOL_STOPLIST = frozenset(
    {
        "__init__",
        "__main__",
        "parse_args",
        "pyproject_toml",
        "origin_main",
        "content_type",
        "file_path",
        "line_number",
        "backlog_md",
    }
)

_SUBJECT_KINDS = ("sha", "pr", "path", "symbol")


@dataclass(frozen=True)
class Subject:
    """One concrete code-side thing an item names, with where and how it was named."""

    kind: str
    value: str
    lineno: int
    wording: str  # "landing" | "measurement" | "neutral"


def _wording(line: str) -> str:
    """How a line frames the reference it carries.

    Landing wins a line carrying both. A sentence such as "measured after it landed" is a landing
    claim first; ranking it as a base ref would drop the strongest signal this screen has.
    """
    if _LANDING_WORDS.search(line):
        return "landing"
    if _MEASUREMENT_WORDS.search(line):
        return "measurement"
    return "neutral"


def _normalise_path(raw: str) -> str:
    """Strip the markdown-link `../` prefixes and any `:line` / `:line-line` suffix."""
    path = raw.strip()
    while path.startswith("../") or path.startswith("./"):
        path = path.split("/", 1)[1]
    return path.rstrip(".,;:)]")


def crossrefs_in(body: str) -> list[int]:
    """Ledger item numbers this row cites, in the literal `BACKLOG #N` form only.

    Returned so a report can show them as CONTEXT. They are never subjects: an item citing another
    item says nothing about whether its own subject exists.
    """
    return sorted({int(n) for n in _BACKLOG_REF.findall(body)})


def subjects_in(body: str) -> list[Subject]:
    """Every code-side subject an item names, deduplicated on (kind, value).

    Deduplication keeps the FIRST occurrence, and a later landing-worded occurrence upgrades it. A
    sha named once as a base ref and again as the commit that landed the work is the second thing.
    """
    found: dict[tuple[str, str], Subject] = {}

    def add(kind: str, value: str, lineno: int, wording: str) -> None:
        key = (kind, value)
        prior = found.get(key)
        if prior is None:
            found[key] = Subject(kind, value, lineno, wording)
        elif prior.wording != "landing" and wording == "landing":
            found[key] = Subject(kind, value, prior.lineno, "landing")

    for offset, line in enumerate(body.splitlines(), start=1):
        wording = _wording(line)

        # A heading line names the item's own number, never a subject.
        stripped = line.lstrip("> ").strip()
        is_heading = stripped.startswith("## ")

        for sha in _SHA.findall(line):
            if sha.isdigit():
                continue
            add("sha", sha, offset, wording)

        for num in _PR_REF.findall(line):
            add("pr", num, offset, wording)

        seen_paths: set[str] = set()
        for raw in _PATH.findall(line):
            path = _normalise_path(raw)
            if path:
                seen_paths.add(path)
                add("path", path, offset, wording)
        if not is_heading:
            for raw in _BARE_FILE.findall(line):
                name = _normalise_path(raw)
                # A bare name already covered by a full path on the same line is not a second
                # subject -- `messagefoundry/store/store.py` must not also yield `store.py`.
                if name and not any(p.endswith("/" + name) for p in seen_paths):
                    add("path", name, offset, wording)

        for span in _TICKED.findall(line):
            symbol = _symbol_from_span(span)
            if symbol is not None:
                add("symbol", symbol, offset, wording)

    return sorted(found.values(), key=lambda s: (s.kind, s.value))


def _symbol_from_span(span: str) -> str | None:
    """A distinctive identifier, or None.

    Rejects anything with whitespace (a command), anything path-shaped (the path extractor owns it),
    anything under 8 characters, and the stoplist. Trailing `()` is stripped so `parse_items()` and
    `parse_items` are one subject.
    """
    token = span.strip()
    if not token or " " in token or "\t" in token:
        return None
    if token.endswith("()"):
        token = token[:-2]
    token = token.strip("`.,;:")
    if "/" in token or "\\" in token or "." in token:
        return None
    if len(token) < 8 or token in _SYMBOL_STOPLIST:
        return None
    if _SNAKE.match(token) or _VERB_NOUN.match(token) or _PASCAL.match(token):
        return token
    return None


def newest_date_in(body: str) -> str | None:
    """The newest ISO date written anywhere in the row, as a proxy for when a person last read it.

    See the module docstring: coarser than the banner block's own date on purpose, and its error runs
    in the under-firing direction, which is why the two strongest signals do not depend on it.
    """
    dates = _ISO_DATE.findall(body)
    return max(dates) if dates else None


# ---------------------------------------------------------------------------------------------
# The git layer, behind a protocol so every test runs against a fake and no test depends on the live
# history of this clone.
# ---------------------------------------------------------------------------------------------


class RepoReader(Protocol):
    """Everything this screen needs to ask about `origin/main`."""

    def is_shallow(self) -> bool: ...

    def is_commit(self, sha: str) -> bool: ...

    def is_ancestor(self, sha: str) -> bool: ...

    def path_on_main(self, path: str) -> str | None:
        """The resolved tree path, or None. A bare filename resolves only if it is unambiguous."""

    def path_added(self, path: str) -> str | None: ...

    def path_last_changed(self, path: str) -> str | None: ...

    def pr_merged(self, number: str) -> tuple[str, str] | None:
        """`(sha, iso_date)` of the squash commit whose subject ends `(#N)`, or None."""

    def symbol_on_main(self, symbol: str) -> bool: ...


class GitRepo:
    """`RepoReader` over a real checkout.

    Three whole-history reads happen ONCE and everything else is a dict lookup: the tree file list,
    the merge-subject map, and a `--name-status` walk giving every path's add and last-change dates.
    Probing those per subject would be hundreds of git invocations for answers one walk already has.
    """

    def __init__(self, root: Path, ref: str = "origin/main") -> None:
        self.root = root
        self.ref = ref
        self._shallow: bool | None = None
        self._tree: set[str] | None = None
        self._by_basename: dict[str, list[str]] | None = None
        self._prs: dict[str, tuple[str, str]] | None = None
        self._added: dict[str, str] = {}
        self._changed: dict[str, str] = {}
        self._dates_loaded = False
        self._symbol_probes = 0

    # -- plumbing ------------------------------------------------------------------------------

    def _git(self, *args: str) -> subprocess.CompletedProcess[str]:
        # Every argument is a fixed verb or a value taken from the ledger, and all of it reaches git
        # as argv rather than a shell string, so nothing here is word-split or expanded. All five
        # verbs used are read-only: rev-parse, merge-base, ls-tree, log, grep.
        return subprocess.run(  # nosec B603 B607 - fixed argv, no shell; read-only git
            ["git", *args],
            cwd=self.root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )

    @property
    def symbol_probes(self) -> int:
        return self._symbol_probes

    def resolve(self, ref: str) -> str:
        """The sha `ref` names, or an empty string. Public so the driver need not reach into _git."""
        return self._git("rev-parse", ref).stdout.strip()

    # -- probes --------------------------------------------------------------------------------

    def is_shallow(self) -> bool:
        if self._shallow is None:
            self._shallow = (
                self._git("rev-parse", "--is-shallow-repository").stdout.strip() == "true"
            )
        return self._shallow

    def is_commit(self, sha: str) -> bool:
        return self._git("rev-parse", "--quiet", "--verify", f"{sha}^{{commit}}").returncode == 0

    def is_ancestor(self, sha: str) -> bool:
        return self._git("merge-base", "--is-ancestor", sha, self.ref).returncode == 0

    def _load_tree(self) -> None:
        if self._tree is not None:
            return
        out = self._git("ls-tree", "-r", "--name-only", self.ref).stdout
        self._tree = {line.strip() for line in out.splitlines() if line.strip()}
        basenames: dict[str, list[str]] = {}
        for path in self._tree:
            basenames.setdefault(path.rsplit("/", 1)[-1], []).append(path)
        self._by_basename = basenames

    def path_on_main(self, path: str) -> str | None:
        self._load_tree()
        assert self._tree is not None and self._by_basename is not None
        if path in self._tree:
            return path
        if "/" in path:
            return None
        # A bare filename is admitted only when it names exactly one file. Two matches is a real
        # ambiguity and resolving it by picking one would attach a date to the wrong file.
        matches = self._by_basename.get(path, [])
        return matches[0] if len(matches) == 1 else None

    def _load_dates(self) -> None:
        """One `--name-status` walk of the ref, newest first.

        `--no-renames` is deliberate: a renamed file should read as ARRIVING at its new path, which
        is the question "does this subject exist on main" actually asks.
        """
        if self._dates_loaded:
            return
        self._dates_loaded = True
        out = self._git(
            "log",
            self.ref,
            "--no-renames",
            "--diff-filter=AM",
            "--name-status",
            "--format=%x00%cI",
        ).stdout
        date = ""
        for line in out.splitlines():
            if line.startswith("\x00"):
                date = line[1:].strip()
                continue
            if not line.strip() or "\t" not in line:
                continue
            status, _, path = line.partition("\t")
            path = path.strip()
            if not path:
                continue
            # Newest first, so the first sighting of a path is its last change and the LAST `A`
            # seen is its earliest add.
            self._changed.setdefault(path, date)
            if status.startswith("A"):
                self._added[path] = date

    def path_added(self, path: str) -> str | None:
        self._load_dates()
        return self._added.get(path)

    def path_last_changed(self, path: str) -> str | None:
        self._load_dates()
        return self._changed.get(path)

    def _load_prs(self) -> None:
        if self._prs is not None:
            return
        out = self._git("log", self.ref, "--format=%H%x09%cI%x09%s").stdout
        prs: dict[str, tuple[str, str]] = {}
        subject_pr = re.compile(r"\(#(\d+)\)\s*$")
        for line in out.splitlines():
            parts = line.split("\t", 2)
            if len(parts) != 3:
                continue
            sha, date, subject = parts
            m = subject_pr.search(subject)
            if m:
                prs.setdefault(m.group(1), (sha[:9], date))
        self._prs = prs

    def pr_merged(self, number: str) -> tuple[str, str] | None:
        self._load_prs()
        assert self._prs is not None
        return self._prs.get(number)

    def symbol_on_main(self, symbol: str) -> bool:
        self._symbol_probes += 1
        return self._git("grep", "--quiet", "-I", "-F", "-e", symbol, self.ref).returncode == 0


# ---------------------------------------------------------------------------------------------
# Screening
# ---------------------------------------------------------------------------------------------

_STRENGTH_ORDER = {"strong": 0, "medium": 1, "weak": 2}


@dataclass(frozen=True)
class Signal:
    strength: str  # "strong" | "medium" | "weak"
    code: str
    detail: str


@dataclass
class ItemReport:
    num: int
    heading: str
    source: str
    last_read: str | None
    crossrefs: list[int]
    subject_counts: dict[str, int]
    signals: list[Signal] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if any(s.strength == "strong" for s in self.signals):
            return "candidate"
        if any(s.strength == "medium" for s in self.signals):
            return "weak-candidate"
        return "no-signal"

    @property
    def rank(self) -> tuple[int, int, int]:
        best = min((_STRENGTH_ORDER[s.strength] for s in self.signals), default=3)
        strong = sum(1 for s in self.signals if s.strength == "strong")
        return (best, -strong, self.num)


def screen_item(
    num: int,
    heading: str,
    body: str,
    repo: RepoReader,
    *,
    source: str = "docs/BACKLOG.md",
    probe_symbols: bool = True,
) -> ItemReport:
    """Resolve one open item's subjects against the ref and grade what came back."""
    subjects = subjects_in(body)
    last_read = newest_date_in(body)
    counts = {kind: sum(1 for s in subjects if s.kind == kind) for kind in _SUBJECT_KINDS}
    report = ItemReport(
        num=num,
        heading=heading,
        source=source,
        last_read=last_read,
        crossrefs=crossrefs_in(body),
        subject_counts=counts,
    )
    shallow = repo.is_shallow()
    # Two subjects can name ONE file -- `scripts/hooks/worktree_gate.ps1` and the bare
    # `worktree_gate.ps1:654` both appear in the #1229 row and both resolve to the same path.
    # Deduplicating on the raw text would report that file's date twice, which reads as two
    # independent pieces of evidence for the same fact.
    screened_paths: set[str] = set()
    if last_read is None:
        # No date means the date-based comparisons cannot run. Surfacing the item is the
        # over-firing direction and therefore the correct one.
        report.signals.append(
            Signal(
                "medium", "no-date-anchor", "the row carries no date, so nothing dates its subjects"
            )
        )

    for subject in subjects:
        if subject.kind == "sha":
            _screen_sha(report, subject, repo, shallow)
        elif subject.kind == "pr":
            _screen_pr(report, subject, repo)
        elif subject.kind == "path":
            _screen_path(report, subject, repo, last_read, shallow, screened_paths)
        elif subject.kind == "symbol" and probe_symbols:
            if repo.symbol_on_main(subject.value):
                report.signals.append(
                    Signal(
                        "weak",
                        "symbol-on-main",
                        f"`{subject.value}` (line {subject.lineno}) is present on the ref",
                    )
                )
            else:
                report.unresolved.append(f"symbol {subject.value} not found on the ref")
    return report


def _screen_sha(report: ItemReport, subject: Subject, repo: RepoReader, shallow: bool) -> None:
    sha = subject.value
    if not repo.is_commit(sha):
        if shallow:
            report.signals.append(
                Signal(
                    "medium",
                    "sha-unverifiable-shallow",
                    f"{sha} (line {subject.lineno}) is not a commit in THIS clone, which is "
                    f"shallow -- it may sit beyond a graft boundary, so this is not a "
                    f"'not on main' answer",
                )
            )
        else:
            report.unresolved.append(f"sha {sha} is not a commit in this clone")
        return
    if repo.is_ancestor(sha):
        strength = "strong" if subject.wording == "landing" else "medium"
        code = "sha-ancestor-landing" if subject.wording == "landing" else "sha-ancestor"
        report.signals.append(
            Signal(
                strength,
                code,
                f"{sha} (line {subject.lineno}, worded as {subject.wording}) IS an ancestor of the ref",
            )
        )
        return
    if shallow:
        report.signals.append(
            Signal(
                "medium",
                "sha-unverifiable-shallow",
                f"{sha} (line {subject.lineno}) resolves but ancestry returned false under a "
                f"SHALLOW clone -- the walk may have stopped at a graft, so the answer is unknown",
            )
        )
    else:
        report.unresolved.append(f"sha {sha} is not an ancestor of the ref")


def _screen_pr(report: ItemReport, subject: Subject, repo: RepoReader) -> None:
    hit = repo.pr_merged(subject.value)
    if hit is None:
        report.unresolved.append(f"PR #{subject.value} has no merge commit on the ref")
        return
    sha, date = hit
    strength = "strong" if subject.wording == "landing" else "medium"
    code = "pr-merged-landing" if subject.wording == "landing" else "pr-merged"
    report.signals.append(
        Signal(
            strength,
            code,
            f"PR #{subject.value} (line {subject.lineno}, worded as {subject.wording}) merged as "
            f"{sha} on {date}",
        )
    )


def _screen_path(
    report: ItemReport,
    subject: Subject,
    repo: RepoReader,
    last_read: str | None,
    shallow: bool,
    screened: set[str],
) -> None:
    resolved = repo.path_on_main(subject.value)
    if resolved is None:
        report.unresolved.append(f"path {subject.value} is absent from the ref (or ambiguous)")
        return
    if resolved in screened:
        return
    screened.add(resolved)
    added = repo.path_added(resolved)
    changed = repo.path_last_changed(resolved)
    if added is None and shallow:
        report.notes.append(
            f"{resolved}: no add commit on the ref -- under a shallow clone that usually means the "
            f"file predates the graft boundary, not that it was never added"
        )
    if last_read is None:
        return
    if added is not None and added[:10] > last_read:
        report.signals.append(
            Signal(
                "strong",
                "path-added-after",
                f"{resolved} was ADDED to the ref on {added[:10]}, after the row's newest date "
                f"{last_read} -- it did not exist when this row was last read",
            )
        )
    elif changed is not None and changed[:10] > last_read:
        report.signals.append(
            Signal(
                "weak" if subject.wording != "landing" else "medium",
                "path-changed-after",
                f"{resolved} last changed on the ref on {changed[:10]}, after the row's newest "
                f"date {last_read}",
            )
        )


# ---------------------------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------------------------

#: A synthetic row modelled on #1229 and #1040. It exercises the EXTRACTOR with no git and no live
#: ledger, so a change that quietly stops matching one subject kind reds here rather than showing up
#: as a smaller candidate list nobody can tell from a cleaner ledger.
CONTROL_BODY = """## 4242. a synthetic control row

> Re-scored 2026-08-20 -> P2. The ordering limb landed in c7f0e308 naming BACKLOG #1229,
> and `Remove-QuotedSpans` is called from worktree_gate.ps1:654. That LANDED on 2026-08-23
> in `889dd9409` (PR #547). Measured at efe061a3f on this branch.
> The test is tests/test_worktree_gate_quote_straddle.py and the store is
> [`store.py`](../messagefoundry/store/store.py). See also #999 and BACKLOG #1268.
"""

#: What CONTROL_BODY must yield. Written out rather than computed so the assertion cannot drift with
#: the code it checks. `#999` appears in the body and must be in NO list: a bare `#N` is never read.
CONTROL_EXPECTED: dict[str, set[str]] = {
    "sha": {"c7f0e308", "889dd9409", "efe061a3f"},
    "pr": {"547"},
    "path": {
        "worktree_gate.ps1",
        "tests/test_worktree_gate_quote_straddle.py",
        "messagefoundry/store/store.py",
    },
    "symbol": {"Remove-QuotedSpans"},
}
CONTROL_CROSSREFS = [1229, 1268]
CONTROL_DATE = "2026-08-23"

#: The two measured cases. While one is OPEN this screen MUST call it a candidate.
LEDGER_CONTROLS = (1229, 1040)


def extractor_control() -> list[str]:
    """Failures of the pure-layer control. Empty means the extractor still sees every subject kind."""
    failures: list[str] = []
    got: dict[str, set[str]] = {kind: set() for kind in _SUBJECT_KINDS}
    for subject in subjects_in(CONTROL_BODY):
        got[subject.kind].add(subject.value)
    for kind, expected in CONTROL_EXPECTED.items():
        missing = expected - got[kind]
        if missing:
            failures.append(f"extractor lost {kind} subject(s): {sorted(missing)}")
    if "999" in got["pr"]:
        failures.append("extractor read a bare `#999` as a pull request -- the forms are ambiguous")
    if "1229" in got["pr"] or "1268" in got["pr"]:
        failures.append("extractor read a `BACKLOG #N` cross-reference as a pull request")
    if crossrefs_in(CONTROL_BODY) != CONTROL_CROSSREFS:
        failures.append(
            f"cross-references came out {crossrefs_in(CONTROL_BODY)}, expected {CONTROL_CROSSREFS}"
        )
    if newest_date_in(CONTROL_BODY) != CONTROL_DATE:
        failures.append(
            f"newest date came out {newest_date_in(CONTROL_BODY)!r}, expected {CONTROL_DATE!r}"
        )
    # The negative arm. A probe validated on one input is not validated.
    if subjects_in("nothing here but prose and a bare #12 reference"):
        failures.append("extractor invented a subject from a row that names none")
    return failures


def probe_control(repo: RepoReader, ref_sha: str, *, probe_symbols: bool) -> list[str]:
    """Failures of the structural control over the git probes, positive AND negative arm each."""
    failures: list[str] = []
    if not repo.is_commit(ref_sha):
        failures.append(f"is_commit said the ref's own commit {ref_sha} is not a commit")
    if not repo.is_ancestor(ref_sha):
        failures.append(f"is_ancestor said the ref's own commit {ref_sha} is not an ancestor")
    absent_sha = "0" * 40
    if repo.is_commit(absent_sha):
        failures.append("is_commit resolved an all-zero sha -- the probe cannot say no")
    if repo.path_on_main("docs/BACKLOG.md") is None:
        failures.append("path_on_main cannot find docs/BACKLOG.md")
    if repo.path_on_main("docs/no-such-file-9d3f2b.md") is not None:
        failures.append("path_on_main resolved an invented path -- the probe cannot say no")
    if repo.path_last_changed("docs/BACKLOG.md") is None:
        failures.append("path_last_changed has no date for docs/BACKLOG.md")
    if probe_symbols:
        if not repo.symbol_on_main("parse_items"):
            failures.append("symbol_on_main cannot find `parse_items`")
        if repo.symbol_on_main("zzq_no_such_symbol_9d3f2b"):
            failures.append("symbol_on_main found an invented symbol -- the probe cannot say no")
    return failures


# ---------------------------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------------------------


@dataclass
class OpenItem:
    num: int
    heading: str
    body: str
    source: str


def open_items(sources: Sequence[tuple[str, str]], status_check: Any) -> list[OpenItem]:
    """Every OPEN item with its body text, using `parse_items` for both the split and the status."""
    parse_items = status_check.parse_items
    out: list[OpenItem] = []
    for label, text in sources:
        lines = text.splitlines()
        items = parse_items(text)
        for index, item in enumerate(items):
            if not item.is_open:
                continue
            start = item.line - 1
            end = items[index + 1].line - 1 if index + 1 < len(items) else len(lines)
            heading = lines[start].removeprefix("## ").strip() if start < len(lines) else ""
            out.append(OpenItem(item.num, heading, "\n".join(lines[start:end]), label))
    return out


def _render(reports: Sequence[ItemReport], *, include_weak: bool, verbose: bool) -> list[str]:
    lines: list[str] = []
    for report in reports:
        if report.verdict == "no-signal" and not verbose:
            continue
        if report.verdict == "weak-candidate" and not include_weak and not verbose:
            continue
        lines.append("")
        lines.append(f"#{report.num} [{report.verdict.upper()}] {report.heading[:110]}")
        counted = ", ".join(f"{k}={report.subject_counts[k]}" for k in _SUBJECT_KINDS)
        lines.append(
            f"    source {report.source} | newest date in row: {report.last_read or '(none)'} "
            f"| subjects {counted}"
        )
        if report.crossrefs:
            lines.append(f"    cites BACKLOG {', '.join('#' + str(n) for n in report.crossrefs)}")
        for signal in sorted(report.signals, key=lambda s: _STRENGTH_ORDER[s.strength]):
            if signal.strength == "weak" and not (include_weak or verbose):
                continue
            lines.append(f"    [{signal.strength:6}] {signal.code}: {signal.detail}")
        for note in report.notes if verbose else []:
            lines.append(f"    [note  ] {note}")
        for item in report.unresolved if verbose else []:
            lines.append(f"    [absent] {item}")
    return lines


def main(argv: list[str] | None = None) -> int:
    # This module prints ledger headings verbatim, and docs/BACKLOG.md is a sanctioned holdout for
    # characters cp1252 cannot represent. Without this a stock Windows console aborts mid-report.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--root", type=Path, default=_ROOT, help="repository to read (default: this one)"
    )
    ap.add_argument("--ref", default="origin/main", help="the ref a subject must exist on")
    ap.add_argument(
        "--backlog",
        type=Path,
        action="append",
        dest="backlogs",
        metavar="PATH",
        help="a file holding numbered items; repeatable. Defaults to backlog_status_check's sources.",
    )
    ap.add_argument("--item", type=int, action="append", help="screen only these item numbers")
    ap.add_argument("--include-weak", action="store_true", help="also list weak-candidate rows")
    ap.add_argument(
        "--verbose", action="store_true", help="show every row, note and absent subject"
    )
    ap.add_argument("--no-symbols", action="store_true", help="skip the per-symbol git grep probes")
    ap.add_argument(
        "--max-symbol-probes",
        type=int,
        default=1500,
        metavar="N",
        help="cap on git-grep symbol probes; the number skipped is always reported",
    )
    ap.add_argument("--self-test", action="store_true", help="run the controls only, then stop")
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args(argv)

    root: Path = args.root.resolve()
    repo = GitRepo(root, args.ref)
    probe_symbols = not args.no_symbols

    ref_sha = repo.resolve(args.ref)
    if not ref_sha:
        print(f"ERROR: cannot resolve {args.ref} in {root}", file=sys.stderr)
        return 2

    # THE CONTROLS RUN FIRST AND UNCONDITIONALLY. A report produced by a broken screen is worse than
    # no report, because it reads as a clean ledger.
    control_failures = extractor_control() + probe_control(
        repo, ref_sha, probe_symbols=probe_symbols
    )
    print(f"subject-exists screen -- ref {args.ref} @ {ref_sha[:9]}, root {root}")
    print(f"  shallow clone: {repo.is_shallow()}")
    if control_failures:
        print("CONTROL FAILED -- THE SCREEN IS BROKEN, NOT THE LEDGER CLEAN:", file=sys.stderr)
        for failure in control_failures:
            print(f"  {failure}", file=sys.stderr)
        return 2
    print(
        f"  controls: extractor OK ({sum(len(v) for v in CONTROL_EXPECTED.values())} subjects "
        f"across {len(CONTROL_EXPECTED)} kinds, both arms), probes OK "
        f"(positive and negative arm each{'' if probe_symbols else ', symbols skipped'})"
    )
    if args.self_test:
        return 0
    # The control runs symbol probes of its own. Counting them in with the screen's would inflate
    # "what this run looked at" by a constant, and a probe total that is never zero cannot show that
    # symbol probing was switched off.
    control_probes = repo.symbol_probes

    status_check = _load_status_check()
    default_sources = status_check.DEFAULT_SOURCES
    paths: list[Path] = args.backlogs if args.backlogs else [root / p for p in default_sources]
    sources: list[tuple[str, str]] = []
    for path in paths:
        if path.exists():
            label = path.resolve().relative_to(root).as_posix() if path.is_absolute() else str(path)
            sources.append((label, path.read_text(encoding="utf-8")))
    if not sources:
        print("ERROR: no ledger source could be read", file=sys.stderr)
        return 2

    items = open_items(sources, status_check)
    scanned = ", ".join(
        f"{label} ({sum(1 for i in items if i.source == label)} open)" for label, _ in sources
    )
    if args.item:
        wanted = set(args.item)
        items = [i for i in items if i.num in wanted]

    reports: list[ItemReport] = []
    symbols_skipped = 0
    for item in items:
        allow = probe_symbols and repo.symbol_probes < args.max_symbol_probes
        if probe_symbols and not allow:
            symbols_skipped += 1
        reports.append(
            screen_item(
                item.num,
                item.heading,
                item.body,
                repo,
                source=item.source,
                probe_symbols=allow,
            )
        )
    reports.sort(key=lambda r: r.rank)

    # THE LEDGER CONTROL. A control that stops applying must say so; it must not read like a pass.
    control_lines: list[str] = []
    control_failed = False
    by_num = {r.num: r for r in reports}
    for num in LEDGER_CONTROLS:
        hit = by_num.get(num)
        if hit is None:
            control_lines.append(
                f"  #{num}: RETIRED as a control -- no longer an OPEN item in the scanned sources "
                f"(or excluded by --item). It is not evidence either way."
            )
        elif hit.verdict == "candidate":
            control_lines.append(f"  #{num}: FIRED as expected ({len(hit.signals)} signal(s))")
        else:
            control_failed = True
            control_lines.append(
                f"  #{num}: DID NOT FIRE -- verdict {hit.verdict}. This is a KNOWN-TRUE case, so "
                f"the screen is under-firing and its empty findings mean nothing."
            )

    counts = {
        verdict: sum(1 for r in reports if r.verdict == verdict)
        for verdict in ("candidate", "weak-candidate", "no-signal")
    }
    totals = {kind: sum(r.subject_counts[kind] for r in reports) for kind in _SUBJECT_KINDS}

    if args.as_json:
        print(
            json.dumps(
                {
                    "ref": args.ref,
                    "ref_sha": ref_sha,
                    "shallow": repo.is_shallow(),
                    "scanned": scanned,
                    "items_examined": len(reports),
                    "subjects_extracted": totals,
                    "symbol_probes": repo.symbol_probes - control_probes,
                    "control_symbol_probes": control_probes,
                    "items_with_symbols_skipped_by_cap": symbols_skipped,
                    "verdicts": counts,
                    "ledger_controls": control_lines,
                    "items": [
                        {
                            "num": r.num,
                            "verdict": r.verdict,
                            "heading": r.heading,
                            "last_read": r.last_read,
                            "signals": [
                                {"strength": s.strength, "code": s.code, "detail": s.detail}
                                for s in r.signals
                            ],
                        }
                        for r in reports
                        if r.verdict != "no-signal" or args.verbose
                    ],
                },
                indent=2,
            )
        )
        return 1 if control_failed else 0

    print(f"  scanned: {scanned}")
    print(f"  items examined (OPEN only): {len(reports)}")
    print(
        "  subjects extracted: "
        + ", ".join(f"{k}={totals[k]}" for k in _SUBJECT_KINDS)
        + f" (total {sum(totals.values())})"
    )
    print(
        f"  symbol probes run: {repo.symbol_probes - control_probes} "
        f"(plus {control_probes} by the control)"
        + (
            f"; items whose symbols were skipped by the {args.max_symbol_probes} cap: "
            f"{symbols_skipped}"
            if symbols_skipped
            else ""
        )
        + ("" if probe_symbols else " (--no-symbols)")
    )
    print(
        f"  verdicts: {counts['candidate']} candidate, {counts['weak-candidate']} weak-candidate, "
        f"{counts['no-signal']} no-signal"
    )
    print("  ledger controls (the two measured cases):")
    for line in control_lines:
        print(line)

    body = _render(reports, include_weak=args.include_weak, verbose=args.verbose)
    if body:
        print("\n--- candidates, for a person to read. THIS TOOL FLIPS NOTHING. ---")
        for line in body:
            print(line)
    else:
        print("\nNo rows to list at this verdict threshold. The controls above are what make that")
        print("readable as a clean ledger rather than a screen that stopped matching.")

    if control_failed:
        print(
            "\nERROR: a known-true ledger control did not fire; treat the list above as unsound.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

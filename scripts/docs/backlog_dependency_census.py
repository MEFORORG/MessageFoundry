# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Enumerate what depends on ``docs/BACKLOG.md``, and HOW, so a move is not blind (BACKLOG #1250).

WHAT THIS IS FOR. #1250 records an owner ruling that the backlog belongs in the vault and, in the
same breath, that moving it now is not safe. The precondition is vault-side. What is engine-side and
missing is a reproducible answer to "what breaks when this file moves". The item has carried a hand
count three times -- 66 tracked referencing files at filing, 78 at the 2026-08-20 re-score -- and it
drifted between each. A cross-repo migration steered by a number that moves on its own is exactly how
allocation collisions come back silently, which is the defect the ledger gate exists to prevent.

THIS TOOL DOES NOT MOVE ANYTHING AND MUST NOT BE MADE TO. It reports. The move stays blocked on the
vault precondition (atomic allocation, a high-water ratchet, installed hooks -- the Q5 ruling,
2026-08-13), and a better inventory does not lift that block.

WHY MECHANISM AND NOT JUST A COUNT. A path literal and a parser import fail DIFFERENTLY under a move,
and a migration that knows only the total cannot tell which it is facing:

  * ``path-literal``   -- the file opens ``docs/BACKLOG.md`` by name. Moving the file makes the open
                          fail, or worse, silently read nothing. Re-point it.
  * ``path-pattern``   -- the same path written as a REGEX or a GLOB, so the literal is not there to
                          find. ``.pre-commit-config.yaml``'s ``files: ^docs/(BACKLOG\\.md|...)$`` is
                          this shape, and a ``grep -F docs/BACKLOG.md`` over that file returns ONE
                          hit -- a prose comment -- and MISSES the functional filter entirely. That
                          is not a hypothetical: it is why this class is detected separately.
  * ``parse-items``    -- the file reads the ledger through
                          ``backlog_status_check.parse_items``. It does NOT name the path, so it
                          survives a move of the file and breaks only if the SOURCES change. These
                          need re-pointing at ``DEFAULT_SOURCES``, not at a literal.
  * ``bare-filename``  -- ``BACKLOG.md`` with no ``docs/`` prefix: a relative Markdown link, or prose.
  * ``markdown-link``  -- a link target that resolves to the ledger. Breaks as a 404, not a crash.
  * ``archive-sibling``-- also names ``docs/archive/backlog/``. The number space spans BOTH files
                          (``backlog_status_check.DEFAULT_SOURCES``), so a move that carries one and
                          not the other splits the namespace, and a split namespace is the collision
                          the gate cannot see.

A file carries a SET of these, not one.

EVERY COUNT CARRIES A POSITIVE CONTROL, AND THAT IS NOT DECORATION. A census that finds nothing
everywhere is indistinguishable from a clean tree, and this repository has already been burned by a
false zero off a broken pattern (CLAUDE.md section 11 records it for the glyph population). So the
controls below are asserted on EVERY run: named files that MUST be found under a named mechanism, and
named files that MUST be found under NONE. A control that does not fire exits 2 and the counts are
declared UNTRUSTWORTHY rather than printed as fact. Run ``--controls`` to see just that table.

WHAT THIS CANNOT SEE, printed on every exit path rather than left to be inferred:

  * THE VAULT -- the migration's DESTINATION. It is a separate repository; ``docs/security/`` is
    gitignored here, so from an engine checkout it does not look misplaced, it looks absent. Nothing
    this script runs can reach it, and the whole vault-side precondition is invisible here.
  * ANYTHING OUTSIDE THIS REPOSITORY -- other clones, the published history (a public repo's history
    cannot be unpublished, which is the item's own asymmetry), sdists already on PyPI, GitHub branch
    protection, and the coordination state under the git common dir.
  * PARKED DEFICIT ITEMS. The 2026-08-14 ruling sends an item whose substance is a weakness in the
    coordination tooling or the seat topology OUT of the public ledger, and with no private ledger it
    parks. Those park in ``<git-common-dir>/mefor-coord/``, which is untracked, machine-local, and
    carries NO machine-readable marker saying "this is a parked deficit". This census cannot count
    them and does not guess at a number.
  * UNTRACKED AND IGNORED FILES. The corpus is ``git ls-files``.
  * A REFERENCE BUILT AT RUN TIME. ``Path("docs") / name`` names the file without spelling it.
  * A REFERENCE THAT NEVER NAMES THE FILE -- "the ledger", "the backlog". Those are real dependencies
    for a human reader and are structurally outside a textual scan.

The item set is read through ``backlog_status_check.parse_items``, never a hand-rolled scan: that
module DEFINES what an item is, and a second definition here would drift from it silently
(CLAUDE.md section 11).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

# ANCHOR ON THE SCRIPT, NOT ON THE CURRENT DIRECTORY (BACKLOG #1060). An absolute invocation from
# another worktree must census the checkout this file LIVES in, not the caller's.
_HERE = Path(__file__).resolve().parent
_DEFAULT_ROOT = _HERE.parent.parent

#: The ledger this census is about, and its archive sibling. Both spellings are needed because the
#: number space spans the pair -- see the module docstring on ``archive-sibling``.
LEDGER_PATH = "docs/BACKLOG.md"
ARCHIVE_DIR = "docs/archive/backlog"

#: The namespace's OWN files are the SUBJECT of the move, not dependents of it. Both mention
#: themselves, so leaving them in inflates the headline by two and, worse, files the thing being
#: moved among the things that break when it moves.
_SUBJECT = (LEDGER_PATH, f"{ARCHIVE_DIR}/BACKLOG-CLOSED.md")

#: Mechanisms that constitute a dependency on ``docs/BACKLOG.md`` itself. ``archive-sibling`` is
#: deliberately NOT one: a file naming only the archive half depends on the archive, and counting it
#: here would answer a question nobody asked. It is reported on its own line instead.
_LEDGER_MECHANISMS = frozenset(
    {"path-literal", "path-pattern", "parse-items", "bare-filename", "markdown-link"}
)

#: The subset that SPELLS the file. This is the like-for-like successor to the hand counts #1250
#: carries (66 at filing, 78 at the re-score): both were "tracked files that mention BACKLOG.md".
#: Keeping it separate is what lets the new total be COMPARED with the old rather than merely
#: replace it -- a number that changes definition and value at once explains nothing.
_NAMING_MECHANISMS = frozenset({"path-literal", "path-pattern", "bare-filename", "markdown-link"})

#: ``docs/BACKLOG.md`` written out, either slash direction. A Windows-spelled path is still a path.
_PATH_LITERAL = re.compile(r"docs[/\\]BACKLOG\.md")

#: The same path spelled as a REGEX or a GLOB, which a literal search cannot find. Three live shapes:
#: an escaped dot (``BACKLOG\.md``, the pre-commit ``files:`` filter), a star (``BACKLOG*``), and a
#: regex any-run (``BACKLOG.*``). Anchored on the token so ``BACKLOG-CLOSED.md`` does not match here.
_PATH_PATTERN = re.compile(r"BACKLOG(?:\\\.md|\*|\.\*)")

#: ``BACKLOG.md`` with no ``docs/`` prefix. The lookbehind keeps ``BACKLOG-CLOSED.md`` and any other
#: hyphenated sibling out: only the bare ledger filename counts.
_BARE_FILENAME = re.compile(r"(?<![\w-])BACKLOG\.md")

#: Reads the ledger through the single-source parser rather than by path.
_PARSE_ITEMS = re.compile(r"\bparse_items\b|\bbacklog_status_check\b")

#: A Markdown link whose target ends at the ledger file: ``](../BACKLOG.md)``, ``](docs/BACKLOG.md)``.
_MARKDOWN_LINK = re.compile(r"\]\([^)]*BACKLOG\.md(?:#[^)]*)?\)")

#: Also names the archive half of the namespace.
_ARCHIVE_SIBLING = re.compile(r"docs[/\\]archive[/\\]backlog")

MECHANISMS: tuple[str, ...] = (
    "path-literal",
    "path-pattern",
    "parse-items",
    "bare-filename",
    "markdown-link",
    "archive-sibling",
)

_DETECTORS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("path-literal", _PATH_LITERAL),
    ("path-pattern", _PATH_PATTERN),
    ("parse-items", _PARSE_ITEMS),
    ("bare-filename", _BARE_FILENAME),
    ("markdown-link", _MARKDOWN_LINK),
    ("archive-sibling", _ARCHIVE_SIBLING),
)

# ------------------------------------------------------------------------------------------------
# Roles.
# ------------------------------------------------------------------------------------------------
#
# THE FOUR PIECES OF MACHINERY #1250 NAMES ARE MAPPED BY PATH, NOT INFERRED. The item calls out the
# pre-commit gate, the status checker, the hygiene workflow and the allocator by name, and a reader
# comparing this output against the item must find those four words. Inferring the role from the
# directory would file `ledger_check.py` under a generic "tooling" and lose the correspondence.
#
# The citation checker and the pre-commit CONFIG are named for the same reason: the config is where
# the `path-pattern` mechanism actually lives, and burying it under "root" hides the one dependency a
# literal search misses.
_NAMED: dict[str, str] = {
    "scripts/hooks/ledger_check.py": "pre-commit-gate",
    ".pre-commit-config.yaml": "pre-commit-config",
    "scripts/docs/backlog_status_check.py": "status-checker",
    "scripts/docs/backlog_citation_check.py": "citation-checker",
    ".github/workflows/backlog-hygiene.yml": "ci-workflow",
    "scripts/coord/alloc.ps1": "allocator",
}

#: Longest-prefix wins, so ``.github/workflows/`` beats ``.github/``.
_BY_PREFIX: tuple[tuple[str, str], ...] = (
    ("tests/", "test"),
    (".github/workflows/", "ci-workflow"),
    (".github/", "ci-config"),
    ("scripts/", "tooling"),
    ("docs/", "doc"),
    ("messagefoundry/", "engine"),
    ("messagefoundry_webconsole/", "engine"),
    ("packaging/", "engine"),
    ("harness/", "engine"),
    ("ide/", "engine"),
    ("tee/", "engine"),
)

ROLES: tuple[str, ...] = (
    "pre-commit-gate",
    "pre-commit-config",
    "status-checker",
    "citation-checker",
    "ci-workflow",
    "allocator",
    "test",
    "ci-config",
    "tooling",
    "doc",
    "engine",
    "root",
)


def role_of(path: str) -> str:
    """Which piece of the machine this file is. Named files first, then longest matching prefix."""
    named = _NAMED.get(path)
    if named is not None:
        return named
    best = ""
    role = "root"
    for prefix, candidate in _BY_PREFIX:
        if path.startswith(prefix) and len(prefix) > len(best):
            best, role = prefix, candidate
    return role


def surface_of(path: str) -> str:
    """``document`` for Markdown, ``executable`` for everything else.

    The split answers a different question from ``role``: HOW a move fails here. A ``.md`` reference
    fails as a dead link that a link checker reports; anything else fails as behaviour, silently or
    otherwise. Markdown is the whole of the document side deliberately -- ``.txt`` files in this
    repository (``tests/tooling_manifest.txt``, ``.github/required-contexts.txt``) are machine-read
    lists, so calling them documents would file two real gates under "prose".
    """
    return "document" if path.endswith(".md") else "executable"


# ------------------------------------------------------------------------------------------------
# Controls.
# ------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Control:
    """One file that MUST be found under one mechanism, and why that arm is the one worth pinning."""

    path: str
    mechanism: str
    why: str


#: MUST-FIRE. Each names a dependency that is known to exist and that a broken detector would drop.
#:
#: The `.pre-commit-config.yaml` row is the load-bearing one. Its functional dependency is a REGEX,
#: so it is invisible to the obvious search: measured on this tree, `grep -F docs/BACKLOG.md` over
#: that file returns exactly one line -- a prose comment -- while the `files:` filter that actually
#: scopes the ledger-parse hook is not found at all. If the `path-pattern` detector ever stops
#: matching, that row goes quiet and the census under-reports the pre-commit surface, which is the
#: precise shape of failure this item exists to prevent.
MUST_FIRE: tuple[Control, ...] = (
    Control(
        "scripts/hooks/ledger_check.py",
        "path-literal",
        "the pre-commit allocation gate pins BACKLOG_PATH as a literal",
    ),
    Control(
        "scripts/docs/backlog_status_check.py",
        "path-literal",
        "DEFAULT_SOURCES names the ledger; it is the single definition of item status",
    ),
    Control(
        "scripts/docs/backlog_citation_check.py",
        "parse-items",
        "the citation gate reads items through the parser, not by path",
    ),
    Control(
        ".github/workflows/backlog-hygiene.yml",
        "path-literal",
        "the required CI context greps the PR diff for the ledger path",
    ),
    Control(
        "scripts/coord/alloc.ps1",
        "path-literal",
        "the allocator sweeps the ledger blobs for the high-water mark",
    ),
    Control(
        ".pre-commit-config.yaml",
        "path-pattern",
        "the ledger-parse hook's files: filter is a REGEX, invisible to a literal search",
    ),
    Control(
        "tests/test_ledger_check.py",
        "path-literal",
        "a test reading the ledger from disk; the class the item counts",
    ),
)

#: MUST-NOT-FIRE. A detector that matches everything is as useless as one that matches nothing, and
#: only the negative arm can tell those apart from a count. These are ordinary tracked files with no
#: dependency on the ledger; every one of them appearing would mean the patterns had gone generic.
MUST_NOT_FIRE: tuple[str, ...] = (
    "LICENSE",
    "pyproject.toml",
    "messagefoundry/__init__.py",
)


# ------------------------------------------------------------------------------------------------
# Corpus.
# ------------------------------------------------------------------------------------------------


def _git(root: Path, *args: str) -> str:
    proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell, no caller-supplied executable
        ["git", "-C", str(root), *args],
        capture_output=True,
        check=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return proc.stdout


#: How many blobs to hand `git cat-file --batch` at a time. Bounds peak memory on a historic ref
#: without paying a process spawn per file: a `git show` each was measured to turn a two-second
#: census into a multi-minute one on Windows, where process creation is the dominant cost.
_BATCH = 200


def _tracked(root: Path, ref: str | None) -> list[str]:
    if ref is None:
        out = _git(root, "ls-files", "-z")
        return sorted(p for p in out.split("\0") if p)
    return sorted(_blobs(root, ref))


def _blobs(root: Path, ref: str) -> dict[str, str]:
    """path -> blob sha at ``ref``. Non-blob entries (submodules) are left out deliberately."""
    out = _git(root, "ls-tree", "-r", "-z", ref)
    mapping: dict[str, str] = {}
    for entry in out.split("\0"):
        if not entry:
            continue
        meta, _, path = entry.partition("\t")
        parts = meta.split()
        if len(parts) == 3 and parts[1] == "blob":
            mapping[path] = parts[2]
    return mapping


def _read_worktree(root: Path, path: str) -> str | None:
    try:
        return (root / path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _read_ref(root: Path, blobs: dict[str, str], paths: Sequence[str]) -> dict[str, str | None]:
    """Batch-read blob text at a ref. ``None`` for anything that does not decode as UTF-8.

    A NON-DECODING FILE IS RECORDED AND REPORTED, NEVER SILENTLY SKIPPED. A filtered scan that drops
    a file type reads as clean when it never looked, so the total is asserted against the corpus.
    """
    texts: dict[str, str | None] = {}
    for start in range(0, len(paths), _BATCH):
        chunk = paths[start : start + _BATCH]
        stdin = "\n".join(blobs[p] for p in chunk) + "\n"
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell, no caller-supplied exe
            ["git", "-C", str(root), "cat-file", "--batch"],
            input=stdin.encode("ascii"),
            capture_output=True,
            check=True,
        )
        offset = 0
        payload = proc.stdout
        for path in chunk:
            newline = payload.index(b"\n", offset)
            size = int(payload[offset:newline].split()[2])
            body = payload[newline + 1 : newline + 1 + size]
            offset = newline + 1 + size + 1  # git writes a trailing newline after each object
            try:
                texts[path] = body.decode("utf-8")
            except UnicodeDecodeError:
                texts[path] = None
    return texts


# ------------------------------------------------------------------------------------------------
# The census.
# ------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Reference:
    path: str
    role: str
    surface: str
    mechanisms: tuple[str, ...]


@dataclass
class Census:
    ref: str
    scanned: int
    undecodable: list[str] = field(default_factory=list)
    #: Non-subject files that depend on ``docs/BACKLOG.md``. The headline population.
    references: list[Reference] = field(default_factory=list)
    #: Non-subject files that name ONLY the archive half of the namespace.
    archive_only: list[Reference] = field(default_factory=list)
    #: The namespace's own files, found in the corpus. Subject of the move, not dependents.
    subject: list[str] = field(default_factory=list)
    asvs_open_items: list[int] = field(default_factory=list)
    open_items: int = 0
    control_failures: list[str] = field(default_factory=list)

    @property
    def naming(self) -> list[Reference]:
        """Dependents that SPELL the path or filename -- what a hand grep would have found."""
        return [r for r in self.references if _NAMING_MECHANISMS.intersection(r.mechanisms)]

    @property
    def parser_only(self) -> list[Reference]:
        """Dependents that read the ledger through ``parse_items`` and name NO path.

        These are invisible to every hand count the item has carried, and they fail differently: a
        move of the file leaves them working and a change to ``DEFAULT_SOURCES`` breaks them.
        """
        return [r for r in self.references if not _NAMING_MECHANISMS.intersection(r.mechanisms)]

    @property
    def by_role(self) -> dict[str, int]:
        counts = dict.fromkeys(ROLES, 0)
        for ref in self.references:
            counts[ref.role] += 1
        return {role: n for role, n in counts.items() if n}

    @property
    def by_mechanism(self) -> dict[str, int]:
        counts = dict.fromkeys(MECHANISMS, 0)
        for ref in self.references:
            for mechanism in ref.mechanisms:
                counts[mechanism] += 1
        return counts

    @property
    def by_surface(self) -> dict[str, int]:
        counts = {"executable": 0, "document": 0}
        for ref in self.references:
            counts[ref.surface] += 1
        return counts


def mechanisms_in(text: str) -> tuple[str, ...]:
    """Every mechanism this text uses to reach the ledger. Order follows ``MECHANISMS``."""
    return tuple(name for name, pattern in _DETECTORS if pattern.search(text) is not None)


def _load_backlog_module() -> object:
    """Import backlog_status_check by path -- it is a script directory, not an installed package."""
    spec = importlib.util.spec_from_file_location(
        "_backlog_status_check", _HERE / "backlog_status_check.py"
    )
    if spec is None or spec.loader is None:  # pragma: no cover - a packaging accident, not a state
        raise RuntimeError("cannot load backlog_status_check.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def asvs_open_items(ledger_text: str) -> tuple[list[int], int]:
    """(open item numbers whose HEADING carries "ASVS", total open items).

    The item's aggregation argument counts HEADINGS, not bodies: "103 open items carry ASVS in the
    heading, in one file, retrievable with a single search". A body mention is ordinary prose and
    does not assemble the map, so the heading is the right line to read.

    ``parse_items`` supplies the item set and the heading line; nothing here re-derives either.
    """
    module = _load_backlog_module()
    lines = ledger_text.splitlines()
    numbers: list[int] = []
    total_open = 0
    for item in module.parse_items(ledger_text):  # type: ignore[attr-defined]
        if not item.is_open:
            continue
        total_open += 1
        if "ASVS" in lines[item.line - 1]:
            numbers.append(item.num)
    return numbers, total_open


def run_census(root: Path, ref: str | None = None) -> Census:
    """Walk the tracked corpus and classify every file that reaches the ledger."""
    resolved = _git(root, "rev-parse", ref or "HEAD").strip()
    paths = _tracked(root, ref)
    if ref is None:
        texts = {path: _read_worktree(root, path) for path in paths}
    else:
        texts = _read_ref(root, _blobs(root, ref), paths)
    census = Census(ref=resolved, scanned=len(paths))
    for path in paths:
        text = texts[path]
        if text is None:
            census.undecodable.append(path)
            continue
        found = mechanisms_in(text)
        if not found:
            continue
        if path in _SUBJECT:
            census.subject.append(path)
            continue
        reference = Reference(path, role_of(path), surface_of(path), found)
        if _LEDGER_MECHANISMS.intersection(found):
            census.references.append(reference)
        else:
            census.archive_only.append(reference)
    ledger = texts.get(LEDGER_PATH)
    if ledger is not None:
        census.asvs_open_items, census.open_items = asvs_open_items(ledger)
    census.control_failures = check_controls(census)
    return census


def check_controls(census: Census) -> list[str]:
    """Both arms. A message per failure; an empty list means the instrument fired as specified."""
    found = {ref.path: ref for ref in census.references}
    failures: list[str] = []
    for control in MUST_FIRE:
        ref = found.get(control.path)
        if ref is None:
            failures.append(
                f"MUST-FIRE control did not fire: {control.path} was not found at all "
                f"({control.why})"
            )
        elif control.mechanism not in ref.mechanisms:
            failures.append(
                f"MUST-FIRE control fired under the wrong mechanism: {control.path} was expected "
                f"to carry '{control.mechanism}' but carries {list(ref.mechanisms)} ({control.why})"
            )
    for path in MUST_NOT_FIRE:
        if path in found:
            failures.append(
                f"MUST-NOT-FIRE control fired: {path} has no dependency on the ledger, so a "
                f"detector matching it has gone generic -- every count below is inflated"
            )
    if census.open_items == 0:
        failures.append(
            "parse_items returned no OPEN items, so the ledger read produced nothing. A zero here "
            "is a broken read, not an empty backlog."
        )
    return failures


# ------------------------------------------------------------------------------------------------
# Output.
# ------------------------------------------------------------------------------------------------

#: Printed on EVERY exit path, including a clean one. A caveat that only prints on the failure path
#: is absent at exactly the moment a reader concludes the picture is complete.
_BLIND_SPOTS: tuple[str, ...] = (
    "the VAULT -- the migration's destination, a separate repository this script cannot reach",
    "anything outside this repository: other clones, published history, PyPI sdists, branch"
    " protection",
    "PARKED DEFICIT ITEMS under <git-common-dir>/mefor-coord/ -- untracked, machine-local, and"
    " carrying no machine-readable marker, so they cannot be counted here and are not guessed at",
    "untracked and git-ignored files (the corpus is `git ls-files`)",
    "a path built at run time rather than written out, e.g. Path('docs') / name",
    "a dependency that never names the file -- 'the ledger', 'the backlog'",
)


def _print_blind_spots() -> None:
    print()
    print("WHAT THIS CENSUS CANNOT SEE (stated, not implied):")
    for line in _BLIND_SPOTS:
        print(f"  - {line}")


def _print_controls(census: Census) -> None:
    print()
    print("POSITIVE CONTROLS -- every count above is void unless these fired:")
    found = {ref.path: ref for ref in census.references}
    for control in MUST_FIRE:
        ref = found.get(control.path)
        ok = ref is not None and control.mechanism in ref.mechanisms
        print(f"  [{'FIRED' if ok else 'MISSED'}] {control.path} :: {control.mechanism}")
        print(f"            {control.why}")
    print("  Negative arm -- these must carry NO mechanism at all:")
    for path in MUST_NOT_FIRE:
        ok = path not in found
        print(f"  [{'CLEAN' if ok else 'MATCHED'}] {path}")
    print(
        f"  Ledger read: parse_items returned {census.open_items} open item(s) "
        f"({'ok' if census.open_items else 'BROKEN -- a zero here is a failed read'})."
    )


def _report(census: Census, verbose: bool) -> None:
    print(f"backlog dependency census -- ref {census.ref}")
    print(f"corpus: {census.scanned} tracked file(s); {len(census.undecodable)} did not decode")
    print()
    print(f"{len(census.references)} tracked file(s) depend on {LEDGER_PATH}.")
    print(
        f"  of those, {len(census.naming)} SPELL the path or filename -- the like-for-like "
        f"successor to this item's hand counts (66 at filing, 78 at the re-score)."
    )
    print(
        f"  and {len(census.parser_only)} name NO path at all: they read the ledger through "
        f"parse_items, so no hand grep for the filename has ever seen them."
    )
    print(
        f"  {len(census.subject)} file(s) are the SUBJECT of the move rather than dependents of it "
        f"({', '.join(census.subject) or 'none found'})."
    )
    print(
        f"  {len(census.archive_only)} file(s) name ONLY {ARCHIVE_DIR}/ -- the other half of the "
        f"item namespace, which a move must carry too or the namespace splits."
    )
    print()
    print("BY ROLE (what kind of thing it is):")
    for role, count in sorted(census.by_role.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {count:>4}  {role}")
    print()
    print("BY MECHANISM (how it depends; a file can carry several, so these sum above the total):")
    for mechanism, count in census.by_mechanism.items():
        print(f"  {count:>4}  {mechanism}")
    print()
    print("BY SURFACE (how a move fails here):")
    for surface, count in census.by_surface.items():
        note = (
            "behaviour breaks, possibly silently"
            if surface == "executable"
            else "a dead link a link checker can report"
        )
        print(f"  {count:>4}  {surface}  -- {note}")
    print()
    print(
        f"ASVS aggregation (the item's other drifting count): {len(census.asvs_open_items)} of "
        f"{census.open_items} OPEN items carry 'ASVS' in the heading."
    )
    if verbose:
        print()
        print("EVERY REFERENCE:")
        for ref in sorted(census.references, key=lambda r: (r.role, r.path)):
            print(f"  {ref.role:<18} {ref.path}")
            print(f"  {'':<18}   {', '.join(ref.mechanisms)}")
    _print_controls(census)
    _print_blind_spots()


def _as_json(census: Census) -> str:
    return json.dumps(
        {
            "ref": census.ref,
            "scanned": census.scanned,
            "undecodable": census.undecodable,
            "total": len(census.references),
            "naming": len(census.naming),
            "parser_only": len(census.parser_only),
            "subject": census.subject,
            "archive_only": [r.path for r in census.archive_only],
            "by_role": census.by_role,
            "by_mechanism": census.by_mechanism,
            "by_surface": census.by_surface,
            "asvs_open_headings": len(census.asvs_open_items),
            "asvs_open_items": census.asvs_open_items,
            "open_items": census.open_items,
            "control_failures": census.control_failures,
            "references": [
                {
                    "path": ref.path,
                    "role": ref.role,
                    "surface": ref.surface,
                    "mechanisms": list(ref.mechanisms),
                }
                for ref in sorted(census.references, key=lambda r: r.path)
            ],
        },
        indent=2,
        sort_keys=False,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Enumerate what depends on docs/BACKLOG.md and how (BACKLOG #1250). Reports only; it "
            "moves nothing, and the move itself stays blocked on the vault precondition."
        )
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=_DEFAULT_ROOT,
        help="repository to census (default: the checkout this script lives in, not the cwd)",
    )
    parser.add_argument(
        "--ref",
        default=None,
        help="census a historic commit instead of the working tree, e.g. --ref c2241cfe",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--verbose", action="store_true", help="list every referencing file and its mechanisms"
    )
    parser.add_argument(
        "--controls",
        action="store_true",
        help="print only the control table -- did the instrument fire?",
    )
    args = parser.parse_args(argv)

    census = run_census(args.root.resolve(), args.ref)

    if args.json:
        print(_as_json(census))
    elif args.controls:
        print(f"backlog dependency census -- ref {census.ref}")
        _print_controls(census)
        _print_blind_spots()
    else:
        _report(census, args.verbose)

    if census.control_failures:
        print()
        print("CONTROL FAILURE -- THE COUNTS ABOVE ARE NOT TRUSTWORTHY:")
        for failure in census.control_failures:
            print(f"  {failure}")
        if args.ref is not None:
            # A HISTORIC MISS HAS TWO CAUSES AND THEY LOOK IDENTICAL HERE, so say so rather than let
            # a reader take the exit code as proof the detector broke. The control table describes
            # the wiring at HEAD; a piece of it may simply not have existed yet at the ref asked
            # for. Measured: at c2241cfe the `.pre-commit-config.yaml` control misses because the
            # `backlog-parses` hook (BACKLOG #1259) had not landed, not because the pattern failed.
            print()
            print(
                "  NOTE -- this run named --ref, and the control table describes the wiring at "
                "HEAD. A miss here is EITHER a broken detector OR wiring that post-dates the ref. "
                "Run the census with no --ref to tell them apart: green at HEAD means the "
                "detector works and the wiring is younger than the ref."
            )
        return 2
    return 0


def format_summary(census: Census) -> Iterable[str]:
    """The three figures #1250's banner carries, as lines. Used by the test and by a ledger edit."""
    yield f"tracked files referencing {LEDGER_PATH}: {len(census.references)}"
    yield f"of those, test files: {census.by_role.get('test', 0)}"
    yield f"open items with ASVS in the heading: {len(census.asvs_open_items)}"


if __name__ == "__main__":
    sys.exit(main())

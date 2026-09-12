# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pin every configured spelling of the ledger's location so a PARTIAL move cannot go quiet.

**The defect this exists for (BACKLOG #1250).** The ledger's location is declared independently in
more than a dozen places -- Python constants, argparse defaults, a PowerShell array, two regexes,
and two integer floors -- and nothing compares them. Moving ``docs/BACKLOG.md`` therefore has a
failure mode with no alarm attached: the pre-commit gate reads one corpus while CI reads another,
each is internally consistent, every check stays green, and allocation collisions come back
silently. That is the exact defect the ledger gate exists to prevent, so a gate that can be
half-moved is a compensating control resting on a false premise.

**What this file is, and is not.** It is a DRIFT GATE, not an indirection layer. It re-points
nothing and it imports nothing new into the sites it reads. It only asserts that the spellings
already in the tree still agree, and it reds the moment they stop.

**How a site is read.** For Python, the source is parsed and only CODE-VISIBLE strings are
considered -- module and function docstrings are excluded, because prose about the ledger is not a
configuration of it. ``Path`` division chains are reconstructed first, so
``_ROOT / "docs" / "BACKLOG.md"`` is seen as the path it builds rather than as two unrelated
fragments; a literal grep for ``docs/BACKLOG.md`` cannot see that spelling at all. For PowerShell
and YAML, comment lines are dropped and the rest is scanned.

**The ledger itself is read ONLY through ``backlog_status_check.parse_items``** (CLAUDE.md section
11). Nothing here re-derives the status-banner alphabet or the item-heading shape.

**Stated residual, so nobody reads more assurance into this than it carries.** A token that spells
only a BASENAME (``BACKLOG.md`` inside a warning string, or inside the required-context name) pins
the filename and says nothing about the directory, so a move that keeps the filenames and changes
only the directory is invisible AT THOSE TWO SITES. Every path-shaped token does carry the
directory, and the discovery sweep below covers the files. ``tests/`` is outside the sweep on
purpose: a test builds synthetic ledgers as fixtures, so a spelling there is a subject rather than
a configuration -- the one exception is the item-count floor, which is registered by hand.
"""

from __future__ import annotations

import ast
import importlib.util
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Final

import pytest

from tests._workflow_contexts import load_workflow

_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
_STATUS_CHECK: Final[Path] = _ROOT / "scripts" / "docs" / "backlog_status_check.py"


def _load_status_check() -> ModuleType:
    spec = importlib.util.spec_from_file_location("backlog_status_check", _STATUS_CHECK)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


bsc = _load_status_check()

# --- the canonical corpus, taken from the ONE definition of it --------------------------------
#
# `DEFAULT_SOURCES` is what `backlog_status_check` scans and what every well-behaved reader imports.
# Deriving the canonical set from it rather than from a literal here is the whole point: a move that
# updates that tuple immediately puts every unmoved site out of agreement, which is the red this
# file exists to produce.
_CANON_FILES: Final[tuple[str, ...]] = tuple(Path(p).as_posix() for p in bsc.DEFAULT_SOURCES)
_LIVE: Final[str] = _CANON_FILES[0]
_ARCHIVE_FILE: Final[str] = _CANON_FILES[1]
_ARCHIVE_DIR: Final[str] = Path(_ARCHIVE_FILE).parent.as_posix()
_CANON_PATHS: Final[frozenset[str]] = frozenset({*_CANON_FILES, _ARCHIVE_DIR})
_CANON_BASENAMES: Final[frozenset[str]] = frozenset(Path(p).name for p in _CANON_FILES)

# --- token extraction ---------------------------------------------------------------------------
#
# Deliberately greedy on both sides of the anchor: a spelling that carries a directory must arrive
# WITH its directory, because the directory is the half a move changes. Regex metacharacters are
# admitted so a pattern site's needle survives extraction intact.
_TOKEN: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9_./\\()|*+?-]*"
    r"(?:BACKLOG\.md|BACKLOG-CLOSED\.md|archive[/\\]backlog)"
    r"[A-Za-z0-9_./\\()|*+?$-]*"
)
#: Characters that mark a token as a REGEX rather than a path. A bare closing paren is not one of
#: them: `-- docs/BACKLOG.md)` occurs in a remedy string, and treating it as a pattern would leave
#: the stray paren welded to the path and make the pin unreadable.
_META: Final[frozenset[str]] = frozenset("(|*+?$[\\")
_TRAILING: Final[str] = ".,);:"


def _tokens(text: str) -> set[str]:
    """Every ledger spelling in ``text``, folded to a comparable form."""
    found: set[str] = set()
    for raw in _TOKEN.findall(text):
        tok = raw
        if not (_META & set(tok)):
            tok = tok.replace("\\", "/")
            while tok and tok[-1] in _TRAILING:
                tok = tok[:-1]
            tok = tok.strip("/")
        if tok:
            found.add(tok)
    return found


def _python_code_strings(source: str) -> list[str]:
    """Code-visible strings from ``source``: docstrings out, ``Path`` division chains rebuilt.

    Rebuilding the chains is load-bearing. ``_ROOT / "docs" / "archive" / "backlog" / "X.md"`` is
    four unrelated constants to any scanner that reads literals one at a time, and folding them into
    one path is the only way a directory move at that site can be seen. Only the OUTERMOST chain is
    emitted -- ``ast.walk`` reaches every nested ``BinOp`` too, and taking them all would report the
    parent directory as a second, independent declaration.
    """
    tree = ast.parse(source)
    docstrings: set[int] = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if (
            isinstance(body, list)
            and body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            docstrings.add(id(body[0].value))

    nested = {
        id(n.left) for n in ast.walk(tree) if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Div)
    }
    consumed: set[int] = set()
    out: list[str] = []
    for node in ast.walk(tree):
        if (
            id(node) in nested
            or not isinstance(node, ast.BinOp)
            or not isinstance(node.op, ast.Div)
        ):
            continue
        chain: list[ast.expr] = []
        cur: ast.expr = node
        while isinstance(cur, ast.BinOp) and isinstance(cur.op, ast.Div):
            chain.append(cur.right)
            cur = cur.left
        chain.append(cur)
        chain.reverse()
        segments: list[str] = []
        for part in chain:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                segments.append(part.value)
                consumed.add(id(part))
            else:
                segments = []
        if segments:
            out.append("/".join(segments))

    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in docstrings
            and id(node) not in consumed
        ):
            out.append(node.value)
    return out


def _uncommented_lines(source: str) -> list[str]:
    return [ln for ln in source.splitlines() if not ln.strip().startswith("#")]


def _spellings(rel: str) -> set[str]:
    """The ledger spellings a tracked file declares in code, keyed by repo-relative path."""
    path = _ROOT / rel
    source = path.read_text(encoding="utf-8", errors="replace")
    if rel.endswith(".py"):
        chunks = _python_code_strings(source)
    elif rel.endswith((".ps1", ".yml", ".yaml")):
        chunks = _uncommented_lines(source)
    else:  # pragma: no cover - the registry and the sweep admit no other suffix
        raise AssertionError(f"no extractor for {rel}")
    return {tok for chunk in chunks for tok in _tokens(chunk)}


# --- the registry -------------------------------------------------------------------------------


@dataclass(frozen=True)
class Site:
    """One place the ledger's location is configured, independently of every other place."""

    path: str
    #: ``both`` -- names the whole two-file namespace. ``live`` -- deliberately the open ledger
    #: only. ``archive`` -- deliberately the archive subtree only. ``name`` -- basenames only, which
    #: pin the filename and not the directory.
    role: str
    #: Every spelling the file declares, as ``_spellings`` folds them. Pinned by content rather than
    #: by line number: an anchor keyed on a line is dead the next time the file is edited.
    tokens: tuple[str, ...]
    why: str


SITES: Final[tuple[Site, ...]] = (
    Site(
        "scripts/docs/backlog_status_check.py",
        "both",
        ("BACKLOG.md", "docs/BACKLOG.md", "docs/archive/backlog/BACKLOG-CLOSED.md"),
        "DEFAULT_SOURCES -- the single definition of item status, and the anchor for this file",
    ),
    Site(
        "scripts/hooks/ledger_check.py",
        "both",
        ("docs/BACKLOG.md", "docs/archive/backlog"),
        "BACKLOG_PATH + BACKLOG_ARCHIVE_DIR -- the pre-commit number-reuse gate",
    ),
    Site(
        "scripts/coord/alloc_strand_sweep.py",
        "both",
        ("docs/BACKLOG.md", "docs/archive/backlog"),
        "BACKLOG_PATH + BACKLOG_ARCHIVE_DIR -- models the gate's arithmetic over all refs",
    ),
    Site(
        "scripts/docs/backlog_dependency_census.py",
        "both",
        ("BACKLOG-CLOSED.md", "docs/BACKLOG.md", "docs/archive/backlog"),
        "LEDGER_PATH + ARCHIVE_DIR -- the census that scopes the #1250 move itself",
    ),
    Site(
        "scripts/asvs/rescore_handoff_check.py",
        "both",
        ("docs/BACKLOG.md", "docs/archive/backlog/BACKLOG-CLOSED.md"),
        "inline default for --backlog, not a named constant",
    ),
    Site(
        "scripts/docs/banner_sha_check.py",
        "both",
        ("docs/BACKLOG.md", "docs/archive/backlog/BACKLOG-CLOSED.md"),
        "argparse fallback built by Path division -- invisible to a literal grep",
    ),
    Site(
        "scripts/docs/citation_line_check.py",
        "both",
        ("docs/BACKLOG.md", "docs/archive/backlog/BACKLOG-CLOSED.md"),
        "argparse fallback built by Path division -- invisible to a literal grep",
    ),
    Site(
        "scripts/coord/alloc.ps1",
        "both",
        ("docs/BACKLOG.md", "docs/archive/backlog/BACKLOG-CLOSED.md"),
        "$backlogPaths -- the allocator's all-refs sweep for the next free number",
    ),
    Site(
        "scripts/worktree/remove.ps1",
        "both",
        ("docs/BACKLOG.md", "docs/archive/backlog/BACKLOG-CLOSED.md"),
        "the landed-item probe before a worktree is removed",
    ),
    Site(
        "scripts/docs/deferral_resolution_screen.py",
        "live",
        ("docs/BACKLOG.md",),
        "DEFAULT_BACKLOG -- screens OPEN rows, so the archive is out of scope by design",
    ),
    Site(
        "scripts/docs/verdict_divergence_check.py",
        "live",
        ("docs/BACKLOG.md",),
        "--backlog default -- verdict vocabulary is checked on the open ledger",
    ),
    Site(
        "scripts/docs/subject_exists_screen.py",
        "live",
        ("docs/BACKLOG.md",),
        "the `source` default, plus the screen's own instrument self-test",
    ),
    Site(
        "scripts/docs/link_check.py",
        "archive",
        ("docs/archive/backlog",),
        "the --subtree help example; names the archive half only",
    ),
)

#: Sites whose declaration is a REGEX or GLOB. Compared by MATCHING against the real paths, never by
#: string equality -- `^docs/(BACKLOG\.md|archive/backlog/.*\.md)$` and
#: `^(docs/BACKLOG\.md|docs/archive/backlog/.+\.md)$` are different strings that name one corpus,
#: and a string comparison would report a defect that is not there while missing the one that is.
PATTERN_SITES: Final[tuple[Site, ...]] = (
    Site(
        ".pre-commit-config.yaml",
        "pattern",
        ("docs/(BACKLOG\\.md|archive/backlog/.*\\.md)$",),
        "the `files:` filter on the backlog-parses hook",
    ),
    Site(
        ".github/workflows/backlog-hygiene.yml",
        "pattern",
        (
            "(docs/BACKLOG\\.md|docs/archive/backlog/.+\\.md)$",
            "BACKLOG.md",
            "docs/BACKLOG.md",
            "docs/archive/backlog",
        ),
        "the grep -qE alternation deciding whether a PR touched the ledger",
    ),
)

#: Paths that must NOT match a ledger pattern. Without these the match arm is satisfied by `.*`, and
#: a pattern that accepts everything is indistinguishable from one that is aimed correctly.
PATTERN_CONTROLS: Final[tuple[str, ...]] = (
    "docs/ARCHITECTURE.md",
    "docs/BACKLOG.md.bak",
    "docs/adr/0001-staged-pipeline-architecture.md",
    "notdocs/BACKLOG.md",
    "docs/archive/backlog/BACKLOG-CLOSED.txt",
)

#: Where the discovery sweep looks. Machinery only: `tests/` builds synthetic ledgers as fixtures,
#: so a spelling there is a subject and not a configuration.
SWEEP_SCOPE: Final[tuple[str, ...]] = (
    "scripts/",
    ".github/workflows/",
    ".pre-commit-config.yaml",
)
SWEEP_SUFFIXES: Final[tuple[str, ...]] = (".py", ".ps1", ".yml", ".yaml")


def _tracked() -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(_ROOT), "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return out.split()


# --- the two item-count floors --------------------------------------------------------------------
#
# FIVE integers in this repository read like anti-narrowing item-count floors and only these two
# are. `dispatch_gate.MIN_ITEMS`, `landed_citation_screen.MIN_ITEMS` and
# `throughput.DEFAULT_MIN_ITEMS` are all 50 and all say so in their own comments: they refuse a
# BROKEN READ, they are set far below any plausible corpus, and they can never bind as a narrowing
# guard. `ledger_check.PUBLIC_BACKLOG_FLOOR` is not a count at all -- it partitions the number
# SPACE at #1000 and would be a category error to compare against an item total.
#
# The two below are the real pair, and `.github/workflows/ci.yml` and
# `tests/test_backlog_status_check.py` each carry a comment saying they exist in two places with
# nothing comparing them. This is that comparison.
_CI_WORKFLOW: Final[str] = "ci.yml"
_FLOOR_TEST: Final[Path] = _ROOT / "tests" / "test_backlog_status_check.py"
_FLOOR_CONST: Final[re.Pattern[str]] = re.compile(
    r"^_MIN_TOTAL_ITEMS\s*(?::\s*[^=]+)?=\s*(\d+)\s*$", re.M
)
_CI_FLOOR: Final[re.Pattern[str]] = re.compile(
    r"backlog_status_check\.py[^\n]*?--min-items\s+(\d+)"
)


def _ci_min_items() -> int:
    """The `--min-items` argument CI passes, read out of the workflow rather than restated here."""
    workflow = load_workflow(_CI_WORKFLOW)
    hits: list[int] = []
    for job in workflow.get("jobs", {}).values():
        for step in job.get("steps", []) or []:
            run = step.get("run")
            if isinstance(run, str):
                hits.extend(int(m) for m in _CI_FLOOR.findall(run))
    assert len(hits) == 1, (
        f"expected exactly one `backlog_status_check.py --min-items N` step in "
        f".github/workflows/{_CI_WORKFLOW}, found {len(hits)}: {hits}. A second invocation means "
        "there are now two CI floors and this comparison no longer covers the binding one."
    )
    return hits[0]


def _pinned_floor() -> int:
    match = _FLOOR_CONST.search(_FLOOR_TEST.read_text(encoding="utf-8"))
    assert match is not None, (
        f"_MIN_TOTAL_ITEMS is no longer a bare integer assignment in {_FLOOR_TEST.name}. It is the "
        "pytest-side half of the anti-narrowing floor; if it moved, re-point this reader at it."
    )
    return int(match.group(1))


def _live_total() -> int:
    """Items across the whole namespace, read ONLY through `parse_items` (CLAUDE.md section 11)."""
    total = 0
    for rel in _CANON_FILES:
        path = _ROOT / rel
        if path.exists():
            total += len(bsc.parse_items(path.read_text(encoding="utf-8")))
    return total


# --- instrument controls ----------------------------------------------------------------------
#
# A sweep that finds nothing is indistinguishable from a repository with no drift, so the extractor
# is proved to fire and proved to stay silent before any of its findings are believed.

_PLANTED = '''
"""A module docstring naming docs/BACKLOG.md, which must NOT be extracted."""
from pathlib import Path
ROOT = Path("/x")
A = "docs/BACKLOG.md"
B = ROOT / "docs" / "archive" / "backlog" / "BACKLOG-CLOSED.md"
C = "unrelated/file.md"
# a comment naming docs/archive/backlog, which must NOT be extracted
'''

_CLEAN = '''
"""No ledger here."""
A = "docs/ARCHITECTURE.md"
B = "some/other/path.md"
'''


def test_the_extractor_fires_on_a_planted_declaration() -> None:
    """Positive control: prove the reader sees both spellings, including the Path-division one."""
    found = {tok for chunk in _python_code_strings(_PLANTED) for tok in _tokens(chunk)}
    assert found == {"docs/BACKLOG.md", "docs/archive/backlog/BACKLOG-CLOSED.md"}, found


def test_the_extractor_is_silent_on_a_file_that_declares_nothing() -> None:
    """Negative control: a reader that matches everything would pass the arm above too."""
    found = {tok for chunk in _python_code_strings(_CLEAN) for tok in _tokens(chunk)}
    assert found == set(), found


def test_the_canonical_corpus_resolves_to_a_real_ledger() -> None:
    """The anchor everything else is compared against must be a live, parsable namespace."""
    assert len(_CANON_FILES) == 2, _CANON_FILES
    for rel in _CANON_FILES:
        path = _ROOT / rel
        assert path.is_file(), f"{rel} is in DEFAULT_SOURCES but is not a file"
        assert bsc.parse_items(path.read_text(encoding="utf-8")), (
            f"parse_items read zero items from {rel}. Every comparison below would then be made "
            "against an empty corpus and would pass for the wrong reason."
        )


# --- the assertions -------------------------------------------------------------------------------


@pytest.mark.parametrize("site", SITES, ids=lambda s: s.path)
def test_each_configured_site_still_spells_the_corpus_it_did(site: Site) -> None:
    """Content pin. A site whose declaration changed reds HERE, naming the site and the delta."""
    found = _spellings(site.path)
    expected = set(site.tokens)
    assert found == expected, (
        f"{site.path} ({site.why}) declares {sorted(found)}; this gate is pinned to "
        f"{sorted(expected)}. Added: {sorted(found - expected)}. Removed: "
        f"{sorted(expected - found)}. If the ledger moved, every site in SITES moves in the SAME "
        "commit -- a partial move is the defect BACKLOG #1250 names."
    )


@pytest.mark.parametrize("site", SITES, ids=lambda s: s.path)
def test_no_site_names_a_path_outside_the_canonical_corpus(site: Site) -> None:
    """Agreement. Every path-shaped spelling must be one the canonical definition still names."""
    for tok in site.tokens:
        if "/" in tok:
            assert tok in _CANON_PATHS, (
                f"{site.path} names {tok!r}, which DEFAULT_SOURCES no longer covers "
                f"({sorted(_CANON_PATHS)}). Either the ledger moved and this site did not, or this "
                "site moved and the ledger did not."
            )
        else:
            assert tok in _CANON_BASENAMES, (
                f"{site.path} names the bare filename {tok!r}, which is not one of "
                f"{sorted(_CANON_BASENAMES)}."
            )


@pytest.mark.parametrize("site", [s for s in SITES if s.role == "both"], ids=lambda s: s.path)
def test_a_whole_namespace_site_names_both_halves(site: Site) -> None:
    """The number space spans two files, so a site claiming the namespace must reach the archive.

    A site that quietly loses its archive half keeps working, keeps passing, and starts issuing
    numbers already used by retired items -- the silent collision the ledger gate exists to stop.
    """
    assert _LIVE in site.tokens, f"{site.path} no longer names {_LIVE}"
    assert _ARCHIVE_FILE in site.tokens or _ARCHIVE_DIR in site.tokens, (
        f"{site.path} claims the whole item namespace but names neither {_ARCHIVE_FILE} nor "
        f"{_ARCHIVE_DIR}. Retired items live there; a sweep that misses them re-issues their "
        "numbers."
    )


@pytest.mark.parametrize("site", [s for s in SITES if s.role == "live"], ids=lambda s: s.path)
def test_a_live_only_site_names_the_open_ledger_and_no_archive(site: Site) -> None:
    """These read OPEN rows on purpose. Recorded so the omission is a decision, not an oversight."""
    assert site.tokens == (_LIVE,), (
        f"{site.path} is registered as reading the open ledger only, but declares "
        f"{sorted(site.tokens)}. If it grew an archive half it is now a whole-namespace site."
    )


@pytest.mark.parametrize("site", PATTERN_SITES, ids=lambda s: s.path)
def test_each_pattern_site_still_spells_what_it_did(site: Site) -> None:
    found = _spellings(site.path)
    assert found == set(site.tokens), (
        f"{site.path} ({site.why}) declares {sorted(found)}; pinned to {sorted(site.tokens)}."
    )


@pytest.mark.parametrize("site", PATTERN_SITES, ids=lambda s: s.path)
def test_each_pattern_actually_matches_the_real_ledger_paths(site: Site) -> None:
    """Patterns are compared by MATCHING, never by string equality.

    Two correct patterns for one corpus are written differently (`.*` against `.+`, the `docs/`
    prefix inside the alternation against outside it), so comparing their text reports drift that
    does not exist. Running them against the real paths asks the question the move actually poses.
    """
    patterns = [t for t in site.tokens if _META & set(t)]
    assert patterns, f"{site.path} is registered as a pattern site but declares no pattern"
    for raw in patterns:
        rx = re.compile(raw if raw.startswith("^") else "^" + raw.lstrip("^"))
        for rel in _CANON_FILES:
            assert rx.match(rel), (
                f"{site.path}: pattern {raw!r} does not match {rel}, which DEFAULT_SOURCES names. "
                "The gate this pattern drives would skip the ledger entirely and report green."
            )
        for control in PATTERN_CONTROLS:
            assert not rx.match(control), (
                f"{site.path}: pattern {raw!r} also matches {control!r}, which is not a ledger "
                "file. A pattern that matches everything passes the arm above without being aimed."
            )


def test_the_registry_covers_every_file_that_configures_the_ledger() -> None:
    """Anti-narrowing for THIS gate: a new site added without registering it reds here.

    Keyed on FILES rather than lines, so the sweep survives ordinary editing. Its residual is
    stated rather than implied: a second declaration added INSIDE an already-registered file is
    caught by that file's content pin above, not by this sweep.
    """
    registered = {s.path for s in (*SITES, *PATTERN_SITES)}
    found: set[str] = set()
    for rel in _tracked():
        if not rel.startswith(SWEEP_SCOPE) or not rel.endswith(SWEEP_SUFFIXES):
            continue
        if not (_ROOT / rel).is_file():
            continue
        if _spellings(rel):
            found.add(rel)
    assert found == registered, (
        f"unregistered site(s): {sorted(found - registered)}. Stale registration(s): "
        f"{sorted(registered - found)}. Every place the ledger's location is configured has to be "
        "in SITES or PATTERN_SITES, or a move can leave it behind with nothing reporting it."
    )


def test_the_two_item_count_floors_agree_with_each_other() -> None:
    """The pair CI and pytest each enforce, compared -- which is what neither of them does today.

    Both files carry a comment saying the floor lives in two places and nothing compares them; the
    slack found on 2026-08-05 was 23 items, in a guard whose whole purpose is to notice the corpus
    shrinking.
    """
    ci = _ci_min_items()
    pinned = _pinned_floor()
    assert ci == pinned, (
        f".github/workflows/{_CI_WORKFLOW} passes --min-items {ci} while "
        f"tests/{_FLOOR_TEST.name} pins _MIN_TOTAL_ITEMS = {pinned}. The LOWER of the two is the "
        "only floor that binds; raise both in the same commit."
    )


def test_both_floors_are_satisfiable_by_the_ledger_parse_items_reports() -> None:
    """A floor above the live corpus is a red-on-arrival gate; a floor of zero is not a gate."""
    total = _live_total()
    ci = _ci_min_items()
    pinned = _pinned_floor()
    assert total >= max(ci, pinned), (
        f"parse_items reports {total} items across {list(_CANON_FILES)}, below the floor "
        f"({ci} in CI, {pinned} in pytest). Items were deleted, or a file holding them left "
        "DEFAULT_SOURCES."
    )
    assert min(ci, pinned) > 0, "a floor of zero cannot fail and is not a guard"

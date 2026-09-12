# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every site that configures where the ledger LIVES must name the same two files.

**The hazard, and why nothing else catches it.** ``docs/BACKLOG.md`` and
``docs/archive/backlog/BACKLOG-CLOSED.md`` are named independently by several unrelated
configuration sites -- a Python tuple, two Python string constants, a pre-commit ``files:``
regex, a PowerShell array, a shell `grep -E` inside a CI step -- and **no** existing check
compares them to each other. Each site is
internally consistent, so each one reads as correct in isolation. Move the ledger and update only
some of them and every site still passes its own tests: the pre-commit allocation gate reads one
location while the status parser reads another, both go green, and **allocation collisions stop
being detected**. That is the failure this file exists to make loud. BACKLOG #1250 is the move
that will exercise it.

**Five sites are covered, and that is not the whole population.** Others have reported at least
nine separately-maintained declarations; nine is an unverified lower bound and this file does not
census them. Read the coverage here as five named sites, never as completeness.

**What is pinned, and what is deliberately not.** The canonical pair is taken from
``backlog_status_check.DEFAULT_SOURCES`` -- the single definition of the item namespace -- and
never from a literal here. A literal would be one more independent declaration of the same fact
and would need updating in lockstep with the rest, which is the defect, not the fix. So this file
asserts **agreement with that tuple**, plus one positive control proving the tuple resolves to a
real ledger rather than to a spelling that happens to parse.

**A regex site is compared by BEHAVIOUR, never by text.** ``.pre-commit-config.yaml`` states the
ledger as ``^docs/(BACKLOG\\.md|archive/backlog/.*\\.md)$``, which no literal grep for a path can
see. Comparing pattern strings would pin the spelling of the pattern instead of the set of files
it selects -- two patterns that differ character-for-character can select the same files, and two
that look alike can differ (an unescaped ``.`` is the classic). So the pattern is **run** against
the real paths, with near-miss controls proving it is not a pattern that matches everything.

**This file goes red the day the ledger moves, on purpose.** That red is the point: it forces
every site to be reviewed in the same change. Fix it by moving the sites together, never by
loosening an assertion here.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Final

import pytest

_ROOT: Final[Path] = Path(__file__).resolve().parents[1]


def _load(name: str, relative: str) -> ModuleType:
    """Import a ``scripts/`` module by path -- ``scripts/`` is not a package, so this is the way."""
    path = _ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, f"cannot load {relative}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# SITE 1 of 5 -- the single definition of the item namespace, and the reference the other four are
# compared against. Nothing below re-states these paths as a literal.
_STATUS_CHECK: Final[ModuleType] = _load(
    "backlog_status_check", "scripts/docs/backlog_status_check.py"
)
_CANON: Final[tuple[str, ...]] = tuple(Path(p).as_posix() for p in _STATUS_CHECK.DEFAULT_SOURCES)

# SITE 2 of 5 -- the pre-commit allocation gate. It states the live ledger as a FILE and the
# archive as a DIRECTORY, so the comparison below is shaped to that, not forced into a pair.
_LEDGER_CHECK: Final[ModuleType] = _load("ledger_check", "scripts/hooks/ledger_check.py")

# SITE 3 of 5 -- the pre-commit `files:` regex, located by the script its `entry` runs rather than
# by its hook id, so renaming the hook does not silently drop this site from the comparison.
_PRE_COMMIT: Final[Path] = _ROOT / ".pre-commit-config.yaml"

# SITE 4 of 5 -- the ALLOCATOR. It sweeps both ledger files to build the set of numbers already
# taken, so a path it does not sweep is a region where two sessions can pick the same number and
# merge clean. That is the same collision the gate at site 2 exists to stop, which makes a
# disagreement between sites 2 and 4 the worst of the shapes this file screens for: the allocator
# would hand out a number the gate then refuses, or worse, would not see one that is taken.
#
# PowerShell cannot be imported, so this site is read from SOURCE TEXT. That is a weaker contract
# than an import and it is pinned here for exactly that reason -- test_ledger_check.py already
# carries the same coupling for the same reason.
_ALLOC: Final[Path] = _ROOT / "scripts" / "coord" / "alloc.ps1"
_PS_ARRAY: Final[re.Pattern[str]] = re.compile(r"\$backlogPaths\s*=\s*@\(([^)]*)\)", re.MULTILINE)


def _allocator_ledger_paths() -> tuple[str, ...]:
    """The paths the allocator sweeps, read out of its ``$backlogPaths`` assignment.

    A rename of that variable fails loudly rather than returning an empty set. An empty set would
    make the comparison below vacuous, and a vacuous comparison over a site that has moved is
    indistinguishable from a site that agrees.
    """
    source = _ALLOC.read_text(encoding="utf-8")
    matches = _PS_ARRAY.findall(source)
    assert len(matches) == 1, (
        f"expected exactly one `$backlogPaths = @(...)` assignment in scripts/coord/alloc.ps1, "
        f"found {len(matches)}. That assignment is how the allocator states which files hold the "
        f"taken numbers; if it was renamed, re-point this helper rather than deleting the check."
    )
    return tuple(re.findall(r"[\"']([^\"']+)[\"']", matches[0]))


def _ledger_files_pattern() -> str:
    """The `files:` pattern of the hook that runs the status checker.

    Fails loudly if there is not exactly one such hook. Zero means the site moved and this test
    stopped covering it; more than one means the pattern is no longer a single fact and this
    helper would have been silently picking whichever came first.
    """
    yaml = pytest.importorskip("yaml", reason="pyyaml is pinned in requirements.lock")
    config = yaml.safe_load(_PRE_COMMIT.read_text(encoding="utf-8"))
    found = [
        hook.get("files")
        for repo in config["repos"]
        for hook in repo.get("hooks", [])
        if "backlog_status_check.py" in str(hook.get("entry", ""))
    ]
    assert len(found) == 1, (
        f"expected exactly one .pre-commit-config.yaml hook running backlog_status_check.py, "
        f"found {len(found)}. The ledger-path comparison in this file covers that hook's `files:` "
        f"pattern; a second one would be one more uncompared declaration of the ledger's location."
    )
    pattern = found[0]
    assert isinstance(pattern, str) and pattern, (
        "the hook running backlog_status_check.py has no `files:` pattern, so it no longer states "
        "where the ledger lives and this comparison has quietly lost a site"
    )
    return pattern


# SITE 5 of 5 -- the CI side of the same question the pre-commit hook asks locally. Site 3 and this
# one drifting apart IS the split BACKLOG #1250 walks into: the local gate reading one file while
# CI reads another, both green.
_HYGIENE: Final[str] = "backlog-hygiene.yml"
_GREP_E: Final[re.Pattern[str]] = re.compile(r"grep\s+-qE\s+'([^']+)'")

# ERE (what `grep -E` speaks) and Python `re` (what compiles the pattern below) agree on every
# construct the real pattern uses -- anchors, alternation, groups, `.`, `+`, `*`, and `\.`. They
# part company at backslash-LETTER escapes: `\d`, `\s`, `\b` and friends are Python classes and are
# not ERE. Screening for those is what makes running the pattern through Python re a sound
# substitution rather than a measurement of the wrong dialect.
_NON_ERE_ESCAPE: Final[re.Pattern[str]] = re.compile(r"\\[A-Za-z]")


def _hygiene_ledger_pattern() -> str:
    """The `grep -qE` pattern the hygiene workflow uses to ask whether a PR touched the ledger.

    Located inside a parsed `run:` body rather than by scanning the raw file, so a mention in a
    comment elsewhere in the repository cannot be picked up as the site. Requires exactly one
    match, for the same reason the pre-commit helper does.
    """
    from tests._workflow_contexts import jobs_of

    found: list[str] = [
        str(m)
        for job in jobs_of(_HYGIENE).values()
        for step in job.get("steps", [])
        for m in _GREP_E.findall(str(step.get("run", "")))
        if "archive/backlog" in str(m)
    ]
    assert len(found) == 1, (
        f"expected exactly one `grep -qE` over the ledger paths in {_HYGIENE}, found {len(found)}. "
        f"Zero means the CI-side declaration moved and this comparison stopped covering it."
    )
    return found[0]


# Near-miss controls for the patterns. Each one differs from a real ledger path in ONE way, and each
# way is a property both patterns are supposed to enforce. Without these, a pattern of `.*` would
# pass the positive assertion and pin nothing at all.
_PATTERN_CONTROLS: Final[tuple[tuple[str, str], ...]] = (
    ("docs/BACKLOGxmd", "the dot in BACKLOG.md must be escaped, not a wildcard"),
    ("vendor/docs/BACKLOG.md", "the pattern must be anchored at the start of the path"),
    ("docs/BACKLOG.md.bak", "the pattern must be anchored at the end of the path"),
    ("docs/archive/backlog/BACKLOG-CLOSED.txt", "the archive entry must require a .md suffix"),
    ("docs/ARCHITECTURE.md", "an unrelated doc must not be taken for the ledger"),
)

# The two REGEX sites, screened together. Parametrising rather than duplicating is the point: a
# control added for one is a control the other must also satisfy, and the local hook and the CI
# step agreeing is exactly the property BACKLOG #1250 puts at risk.
_PATTERN_SITES: Final[tuple[tuple[str, Callable[[], str]], ...]] = (
    (".pre-commit-config.yaml", _ledger_files_pattern),
    (_HYGIENE, _hygiene_ledger_pattern),
)


def test_the_canonical_pair_resolves_to_a_real_ledger() -> None:
    """Positive control: the reference is two files that exist and parse as the item namespace.

    Everything else here compares sites to ``DEFAULT_SOURCES``. If that tuple named paths that do
    not exist, every comparison would still pass while the whole set agreed on nothing -- so the
    reference is checked against the tree, and against ``parse_items``, before it is trusted.
    """
    assert len(_CANON) == 2, f"expected two ledger sources, got {_CANON}"

    missing = [p for p in _CANON if not (_ROOT / p).is_file()]
    assert not missing, (
        f"backlog_status_check.DEFAULT_SOURCES names {missing}, which do not exist in this "
        f"checkout. Either the ledger moved and this tuple did not, or the tuple moved and the "
        f"files did not."
    )

    # parse_items is the ONE definition of item status (CLAUDE.md section 11) -- never hand-roll a
    # scan of the banner alphabet. A path that exists but yields no items is a spelling that
    # resolves to the wrong file, which the existence check alone cannot see.
    total = 0
    for rel in _CANON:
        items = _STATUS_CHECK.parse_items((_ROOT / rel).read_text(encoding="utf-8"))
        assert items, f"{rel} exists but parse_items finds no numbered items in it"
        total += len(items)
    assert total > 100, f"the two ledger sources hold only {total} items, which is not this ledger"


def test_the_allocation_gate_names_the_same_ledger() -> None:
    """The pre-commit allocation gate's two constants must agree with the canonical pair.

    It states the live ledger as a file and the archive as a directory, so the archive half is
    compared as containment: the canonical archive file must sit directly in the directory the
    gate walks. A gate reading a directory the archive has left would early-return having checked
    nothing, and two sessions could file the same number there and merge clean.
    """
    live, archive_file = _CANON

    gate_live = _LEDGER_CHECK.BACKLOG_PATH
    assert gate_live == live, (
        f"ledger_check.BACKLOG_PATH is {gate_live!r} but backlog_status_check.DEFAULT_SOURCES "
        f"names {live!r}. The allocation gate and the status parser are reading different files."
    )

    archive_dir = _LEDGER_CHECK.BACKLOG_ARCHIVE_DIR
    assert Path(archive_file).parent.as_posix() == archive_dir, (
        f"ledger_check.BACKLOG_ARCHIVE_DIR is {archive_dir!r}, which does not contain the "
        f"canonical archive ledger {archive_file!r}."
    )


def test_the_allocator_sweeps_the_same_ledger() -> None:
    """The allocator must sweep exactly the canonical pair -- no more, and no fewer.

    Compared as an ordered tuple rather than a set. The order is not itself load-bearing, but a
    set comparison would also accept a duplicated entry, and a duplicate in a sweep list is a
    silent halving of one file's contribution that nothing else here would report.
    """
    swept = _allocator_ledger_paths()
    assert swept == _CANON, (
        f"scripts/coord/alloc.ps1 sweeps {list(swept)} for taken numbers, but "
        f"backlog_status_check.DEFAULT_SOURCES names {list(_CANON)}. A path the allocator does "
        f"not sweep is a region where two sessions pick the same number and merge clean."
    )


@pytest.mark.parametrize(("site", "read"), _PATTERN_SITES, ids=[s[0] for s in _PATTERN_SITES])
def test_a_ledger_pattern_selects_both_real_ledger_paths(
    site: str, read: Callable[[], str]
) -> None:
    """Each regex site is RUN against the real paths -- pattern text is never compared.

    Both consumers apply their pattern to the repo-relative, forward-slash spelling of a changed
    path: pre-commit filters staged files with ``re.search``, and the hygiene step greps a
    newline-separated list of them. So that is exactly what is applied here.
    """
    pattern = read()
    unmatched = [p for p in _CANON if not re.compile(pattern).search(p)]
    assert not unmatched, (
        f"the ledger pattern in {site} ({pattern!r}) does not select {unmatched}, so a change to "
        f"those files would not be recognised as touching the ledger."
    )


@pytest.mark.parametrize(("path", "why"), _PATTERN_CONTROLS, ids=[c[0] for c in _PATTERN_CONTROLS])
@pytest.mark.parametrize(("site", "read"), _PATTERN_SITES, ids=[s[0] for s in _PATTERN_SITES])
def test_a_ledger_pattern_rejects_a_near_miss(
    site: str, read: Callable[[], str], path: str, why: str
) -> None:
    """Negative control: a pattern matching everything would pass the test above and pin nothing."""
    assert not re.compile(read()).search(path), (
        f"the ledger pattern in {site} selects {path!r}, which is not a ledger file -- {why}"
    )


def test_the_ci_pattern_uses_only_constructs_python_re_reads_the_same_way() -> None:
    """The dialect check that makes the test above a sound substitution, not a wrong measurement.

    The hygiene pattern is executed by ``grep -E`` and compared here by Python ``re``. The two
    agree on everything the real pattern uses; they diverge at backslash-LETTER escapes, which are
    Python character classes and not ERE. If one appears, the comparison above is silently reading
    a different pattern than CI runs -- so it is screened for rather than assumed.
    """
    pattern = _hygiene_ledger_pattern()
    bad = _NON_ERE_ESCAPE.findall(pattern)
    assert not bad, (
        f"the {_HYGIENE} ledger pattern {pattern!r} contains backslash-letter escapes {bad}, which "
        f"grep -E does not read as Python re does. Compare it by running grep, or drop the escape."
    )

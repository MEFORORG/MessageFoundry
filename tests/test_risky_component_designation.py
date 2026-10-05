# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The risky-component designation must stay closed over the runtime closure (BACKLOG #1189).

ASVS 15.1.4 asks that application documentation highlight third-party libraries considered risky
components. ``docs/RISKY-COMPONENTS.md`` is that highlight, and a highlight is only worth reading
while it is complete over a stated denominator.

The denominator is ``security/runtime-closure-core.txt``: the core runtime closure, no extras, no dev
toolchain. It is a copy of the pin lines in a DEP-1 lock; its own header says which one, and how to
regenerate it. Tests below hold the copy to that lock in name and version (BACKLOG #1812).

The page also assesses two extras, each in its own section: ``sqlserver`` (BACKLOG #1955) and
``harness``, which the harness wheel installs and which the ASVS assessment scope took in by owner
ruling R1 of 2026-10-02. Each section's denominator is its ``security/runtime-closure-<extra>.txt``,
built and held the same way, and it classifies only the names that closure adds to the core one.

**The property under test is CLOSURE, not correctness of judgement.** Whether ``pyyaml`` belongs in
tier 1 is an argument for a reviewer. Whether it appears in exactly one of the two tables is a fact,
and a dependency bump that adds a package nobody classified is exactly the drift this catches.

The page also reads every component on ASVS's own examples of a risky component (maintenance,
support, vulnerability history), from a dated snapshot of public PyPI and OSV data:
``security/risky-component-readings.json``, written by ``scripts/security/component_readings.py``.
The tests for it need NO network. They hold the snapshot to the population, which is the core
closure plus what each assessed extra adds (BACKLOG #2414 brought ``harness`` in). They re-derive
each verdict from its recorded readings, and hold the page's tables, counts and dates to the
snapshot. None of them reads today's date, so none goes red when the re-read date passes.

Each test names the mutation that must turn it RED.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import subprocess
import sys
import urllib.error
from email.message import Message
from pathlib import Path
from typing import Any

import pytest
import yaml
from packaging.utils import canonicalize_name

from scripts.security import component_readings, runtime_closure

_ROOT = Path(__file__).resolve().parent.parent
_DOC = _ROOT / "docs" / "RISKY-COMPONENTS.md"
_DEPENDABOT = _ROOT / ".github" / "dependabot.yml"
_CLOSURE = _ROOT / "security" / "runtime-closure-core.txt"
_LOCK = _ROOT / "requirements.lock"
#: The lock the closure file copies. The closure file's header says what it is.
_CORE_LOCK = _ROOT / "docker" / "locks" / "requirements-core.lock"
#: The ``sqlserver`` extra's closure and the lock it copies (BACKLOG #1955).
_SQLSERVER_CLOSURE = _ROOT / "security" / "runtime-closure-sqlserver.txt"
_SQLSERVER_LOCK = _ROOT / "docker" / "locks" / "requirements-sqlserver.lock"
#: The ``harness`` extra's closure and the lock it copies. No image installs that lock.
_HARNESS_CLOSURE = _ROOT / "security" / "runtime-closure-harness.txt"
_HARNESS_LOCK = _ROOT / "security" / "locks" / "requirements-harness.lock"
#: Each closure file and its lock, in the order the regenerator rewrites them.
_PAIRS = (
    (_CLOSURE, _CORE_LOCK),
    (_SQLSERVER_CLOSURE, _SQLSERVER_LOCK),
    (_HARNESS_CLOSURE, _HARNESS_LOCK),
)
#: The dated public-metadata snapshot the ASVS-example section is held to (BACKLOG #1189).
_READINGS = _ROOT / "security" / "risky-component-readings.json"
#: The hand-made survey of what each pinned wheel carries inside it (BACKLOG #2935).
_SURVEY = _ROOT / "security" / "bundled-code-survey.json"

#: The headings that bound the page's classified regions. The core tables run from the tier 1
#: heading to the sqlserver heading, the sqlserver tables from there to the harness heading, and
#: the harness tables from there to the ASVS reading.
_CORE_START = "## Tier 1 — hostile input"
_CORE_SPLIT = "## Assessed and NOT designated"
_SQLSERVER_START = "## The `sqlserver` extra"
_EXTRA_SPLIT = "### Assessed and NOT designated"
_HARNESS_START = "## The `harness` extra"
#: The ASVS-example reading (BACKLOG #1189, ground 2) runs from here to the closing sections.
_ASVS_START = "## Risky by ASVS's own examples, read from public data"
_END = "## What this page is not"

#: A distribution named in a markdown table cell as `name`. The designation tables put the
#: distribution in the FIRST cell of each row, so anchoring on the row start keeps prose mentions of
#: a package elsewhere on the page from being read as a classification.
_ROW_NAME = re.compile(r"^\|\s*`([a-z0-9][a-z0-9._-]*)`", re.MULTILINE)

#: A row whose first cell packs several comma-separated names (the typing shims share one reason).
_ROW_NAME_GROUP = re.compile(
    r"^\|\s*((?:`[a-z0-9][a-z0-9._-]*`,\s*)+`[a-z0-9][a-z0-9._-]*`)\s*\|", re.MULTILINE
)


def _closure_lines(path: Path = _CLOSURE) -> list[str]:
    """A closure file's pin lines, stripped, in file order. Comments and blanks are skipped."""
    return runtime_closure.closure_lines(path.read_text(encoding="utf-8"))


def _closure_pins(path: Path = _CLOSURE) -> dict[str, str]:
    """Name to version for every pin in a tracked runtime closure file (the core one by default).

    A name listed twice fails here, in the reader the readings generator shares.
    """
    return runtime_closure.closure_pins(path)


def _closure() -> set[str]:
    """Distribution names in the tracked core runtime closure."""
    return set(_closure_pins())


def _additions(closure: Path) -> set[str]:
    """The names an extra's closure adds to the core one: what its section must classify."""
    return set(_closure_pins(closure)) - _closure()


def _core_lock_pins() -> dict[str, str]:
    """Name to version for the core closure, read from the DEP-1 core lock (BACKLOG #1812).

    The regenerator's own reader, so the gate and the rewrite cannot read the lock differently.
    """
    return runtime_closure.lock_pins(_CORE_LOCK)


def _diff_pins(label: str, recorded: dict[str, str], actual: dict[str, str]) -> list[str]:
    """One line per package where the closure file and ``actual`` disagree, naming both values."""
    lines = [
        f"{n}: in the closure file, absent from {label}" for n in sorted(recorded.keys() - actual)
    ]
    lines += [
        f"{n}: in {label}, absent from the closure file" for n in sorted(actual.keys() - recorded)
    ]
    lines += [
        f"{n}: closure file says {recorded[n]}, {label} says {actual[n]}"
        for n in sorted(recorded.keys() & actual)
        if recorded[n] != actual[n]
    ]
    return lines


def _table_names(block: str) -> set[str]:
    """The distributions named in the first cell of a table row in ``block``."""
    # The same PEP 503 form the closure side uses, so `ruamel.yaml` in a table row matches
    # `ruamel-yaml` in the lock.
    out: set[str] = {runtime_closure.canonical_name(m.group(1)) for m in _ROW_NAME.finditer(block)}
    for m in _ROW_NAME_GROUP.finditer(block):
        out |= {runtime_closure.canonical_name(n.strip(" `")) for n in m.group(1).split(",")}
    return out


def _classified(start: str, split: str, end: str) -> tuple[set[str], set[str]]:
    """The names classified between ``start`` and ``end``, split at the ``split`` heading.

    ``start`` and ``end`` must each be a whole line once on the page, start first (see ``_region``),
    and ``split`` a whole line once between them, or the region is not the one meant. Whole lines,
    because ``## Assessed and NOT designated`` is a substring of each extra's
    ``### Assessed and NOT designated``. The split is counted within the region only, because every
    extra's section carries the same one.
    """
    region = "\n" + _region(start, end)
    split_line = f"\n{split}\n"
    assert region.count(split_line) == 1, (
        f"{_DOC.name} must carry {split!r} once between {start!r} and {end!r}"
    )
    head, _, tail = region.partition(split_line)
    # The not-designated table ends at the next heading of any level, so a later subsection's
    # table is not read as more exclusions.
    return _table_names(head), _table_names(tail.partition("\n#")[0])


def _region(start: str, end: str, page: str | None = None) -> str:
    """The page text between two whole-line headings, each given without its newlines.

    Both must be present once, start first, or a missing end would stretch the region to the end
    of the page and let a figure anywhere below satisfy a check meant for one section. ``page``
    defaults to the tracked page; a positive control passes a broken copy instead.
    """
    text = "\n" + (_DOC.read_text(encoding="utf-8") if page is None else page)
    first, last = f"\n{start}\n", f"\n{end}\n"
    for line in (first, last):
        assert text.count(line) == 1, f"{_DOC.name} must carry {line.strip()!r} once"
    assert text.index(first) < text.index(last), f"{_DOC.name} must put {start!r} before {end!r}"
    return text.partition(first)[2].partition(last)[0]


def _designated_and_excluded() -> tuple[set[str], set[str]]:
    """The names the core tables classify, split at the not-designated heading.

    Start at the first tier heading, NOT the top of the page. The scope table above it has rows
    whose first cell is a backticked filename, and reading those as designations is a parser bug
    that inflates the count -- it caught `requirements.lock` on the first run of this guard. Stop at
    the sqlserver heading, so that section's names are not read as core ones.
    """
    return _classified(_CORE_START, _CORE_SPLIT, _SQLSERVER_START)


def _sqlserver_designated_and_excluded() -> tuple[set[str], set[str]]:
    """The names the ``sqlserver`` section classifies, split at its not-designated heading."""
    return _classified(_SQLSERVER_START, _EXTRA_SPLIT, _HARNESS_START)


def _harness_designated_and_excluded() -> tuple[set[str], set[str]]:
    """The names the ``harness`` section classifies, split at its not-designated heading."""
    return _classified(_HARNESS_START, _EXTRA_SPLIT, _ASVS_START)


#: Each assessed extra: its closure file, its section's start and end headings, and one name the
#: extra must add, so an empty difference cannot pass the section's tests vacuously.
_EXTRAS: dict[str, tuple[Path, str, str, str]] = {
    "sqlserver": (_SQLSERVER_CLOSURE, _SQLSERVER_START, _HARNESS_START, "pyodbc"),
    "harness": (_HARNESS_CLOSURE, _HARNESS_START, _ASVS_START, "pyside6-essentials"),
}


def test_the_closure_file_parses_and_is_not_empty() -> None:
    """RED when: the closure file is emptied, or its format changes under the parser.

    THE POSITIVE CONTROL FOR EVERY TEST BELOW. A closure that parses to the empty set would make
    "every closure member is classified" pass vacuously, which is the failure mode a set-comparison
    test is most prone to.
    """
    closure = _closure()
    assert len(closure) >= 20, (
        f"the closure parsed to {len(closure)} names, which is too few to be the real set; "
        "the parser and the file have diverged"
    )
    assert "tomlkit" in closure and "cryptography" in closure, (
        "two known core dependencies are missing from the parsed closure"
    )


def test_the_document_classifies_every_distribution_in_the_closure() -> None:
    """RED when: a dependency enters the closure and nobody classifies it.

    This is the drift the page exists to survive. An unclassified package is invisible to a reader
    who trusts the page, and invisible to a reviewer who trusts the arithmetic printed on it.
    """
    closure = _closure()
    designated, excluded = _designated_and_excluded()
    classified = designated | excluded

    missing = sorted(closure - classified)
    assert not missing, (
        f"{len(missing)} distribution(s) are in the runtime closure but classified nowhere in "
        f"{_DOC.name}: {missing}. Add each to a designated tier or to the assessed-and-not-designated "
        "table; leaving it out of both is not available."
    )


def test_the_document_names_nothing_outside_the_closure() -> None:
    """RED when: the page keeps designating a package that has been dropped as a dependency.

    The mirror of the test above, and the one that catches a stale entry rather than a missing one.
    A page that still warns about a library the engine no longer ships sends a reader to look at
    nothing.
    """
    closure = _closure()
    designated, excluded = _designated_and_excluded()
    stray = sorted((designated | excluded) - closure)
    assert not stray, (
        f"{_DOC.name} classifies {len(stray)} name(s) that are not in the core runtime closure: "
        f"{stray}. Either they left the dependency set, or the closure file is stale."
    )


def test_no_distribution_is_both_designated_and_excluded() -> None:
    """RED when: a package is moved between tables and the old row is left behind.

    A name in both tables makes the page self-contradicting and silently breaks the arithmetic it
    prints, since the two counts would then overlap.
    """
    designated, excluded = _designated_and_excluded()
    both = sorted(designated & excluded)
    assert not both, f"classified twice in {_DOC.name}: {both}"


def test_the_counts_printed_on_the_page_are_the_real_ones() -> None:
    """RED when: the prose keeps a count the tables no longer support.

    The page states "Twenty-five of thirty-six" and "25 plus 11 is 36". Those are load-bearing: a
    reader uses them to check the set is closed without counting rows. A figure that drifts from its
    own tables is worse than no figure, because it invites the reader to stop checking.
    """
    designated, excluded = _designated_and_excluded()
    # Each figure is looked for in its own section, so a copy elsewhere cannot satisfy it.
    core_tables = _region(_CORE_START, _SQLSERVER_START)
    scope = _region("## Scope, and the denominator", "## The criterion")

    total = len(designated) + len(excluded)
    assert f"{len(designated)} plus {len(excluded)} is {total}" in core_tables, (
        f"the page's arithmetic sentence does not match its tables: designated={len(designated)}, "
        f"not designated={len(excluded)}, total={len(designated) + len(excluded)}"
    )
    assert len(designated) + len(excluded) == len(_closure()), (
        "the two tables do not sum to the closure size"
    )
    # The scope section's closure size, derived from the closure file, which the gate below holds
    # equal to the core lock. It changes only when a core package arrives or leaves, which needs a
    # designation edit on this page anyway. There is deliberately no requirements.lock count: it
    # moved with every dev or extra dependency, so any Dependabot PR could red it.
    closure_size = len(_closure())
    assert f"That is **{closure_size} distributions**" in scope, (
        f"the scope section does not state the closure size, {closure_size}"
    )


@pytest.mark.parametrize("extra", sorted(_EXTRAS))
def test_an_extra_closure_is_the_core_closure_plus_the_extra(extra: str) -> None:
    """RED when: an extra's closure stops being a superset of the core one, or adds nothing.

    THE POSITIVE CONTROL FOR EACH EXTRA'S SECTION (BACKLOG #1955 for sqlserver). That section
    classifies only the names this closure adds, so an empty difference would make every test of it
    pass vacuously. A core package at a different version here would mean one of the two exports
    is stale.
    """
    path, _, _, marker = _EXTRAS[extra]
    core = _closure_pins()
    pins = _closure_pins(path)
    assert len(core) >= 20, f"the core closure parsed to {len(core)} names, too few to be real"
    lost = sorted(core.keys() - pins.keys())
    assert not lost, f"core packages missing from {path.name}: {lost}"
    moved = sorted(n for n in core if pins[n] != core[n])
    assert not moved, f"core packages at another version in {path.name}: {moved}"
    assert marker in _additions(path), (
        f"{path.name} adds no {marker} to the core closure; the extra's own package is missing, "
        "so the file or its parser is wrong"
    )


@pytest.mark.parametrize("extra", sorted(_EXTRAS))
def test_an_extra_section_classifies_exactly_what_the_extra_adds(extra: str) -> None:
    """RED when: an extra gains a package nobody classified, or its section names a stray one.

    The core tests above cannot see this: they read only the core closure, and a package the extra
    alone brings is outside it. Names the core tables already classify are not repeated here.
    """
    path, start, end, _ = _EXTRAS[extra]
    additions = _additions(path)
    designated, excluded = _classified(start, _EXTRA_SPLIT, end)
    classified = designated | excluded
    missing = sorted(additions - classified)
    assert not missing, (
        f"the {extra} extra adds {missing} and {_DOC.name}'s {extra} section classifies "
        "none of them. Add each to its designated or not-designated table."
    )
    stray = sorted(classified - additions)
    assert not stray, (
        f"{_DOC.name}'s {extra} section classifies {stray}, which the extra does not add to "
        "the core closure. Either they left the extra, or they are core and belong above."
    )
    both = sorted(designated & excluded)
    assert not both, f"classified twice in the {extra} section: {both}"


@pytest.mark.parametrize("extra", sorted(_EXTRAS))
def test_an_extra_section_counts_printed_on_the_page_are_the_real_ones(extra: str) -> None:
    """RED when: an extra section's arithmetic, or a closure size the page states, drifts.

    Each figure is looked for where it belongs: the sum in the extra's section, the sizes in the
    scope section above the tiers. So a stray copy elsewhere on the page cannot satisfy it.
    """
    path, start, end, _ = _EXTRAS[extra]
    designated, excluded = _classified(start, _EXTRA_SPLIT, end)
    added = len(designated) + len(excluded)
    assert added == len(_additions(path)), f"the {extra} tables do not sum to the additions"
    core = len(_closure())
    total = len(_closure_pins(path))
    section = _region(start, end)
    sentence = (
        f"{len(designated)} plus {len(excluded)} is {added}, and {core} plus {added} is {total}"
    )
    assert sentence in section, f"the {extra} section does not say {sentence!r}"
    scope = _region("## Scope, and the denominator", "## The criterion")
    assert scope, "the scope section's headings moved; this test reads between them"
    for fact in (
        f"The `{extra}` runtime closure is **{total} distributions**",
        f"| **Core runtime closure** | **{core}** |",
        f"| **`{extra}` runtime closure** | **{total}** |",
    ):
        assert fact in scope, f"the scope section does not say {fact!r}"


def test_the_harness_extra_is_not_listed_as_unassessed() -> None:
    """RED when: the scope section's list of unassessed extras names ``harness`` again.

    The harness section assesses it, so a list calling it unassessed contradicts the page.
    """
    scope = _region("## Scope, and the denominator", "## The criterion")
    unassessed = scope.partition("An install that enables any other extra")[2].partition("\n\n")[0]
    assert "`postgres`" in unassessed, "the list of unassessed extras moved; re-read this test"
    assert "`harness`" not in unassessed, "the scope section still lists `harness` as unassessed"


def test_the_generator_reads_every_extra_the_page_assesses() -> None:
    """RED when: the page gives an extra a section and the readings generator does not read its
    closure, or the generator reads a closure the page has no section for.

    Three lists of the assessed extras must agree: the page's own ``## The `X` extra`` headings,
    this module's ``_EXTRAS``, and the generator's ``EXTRAS``. The ``harness`` extra had a section
    for a time while the generator read the ``sqlserver`` closure only (BACKLOG #2414). The
    snapshot side of the same property is ``test_every_population_member_has_exactly_one_reading``.
    """
    page = _DOC.read_text(encoding="utf-8")
    on_page = re.findall(r"^## The `([^`]+)` extra$", page, re.MULTILINE)
    assert on_page, f"{_DOC.name} has no extra section; the heading pattern here has gone stale"
    assert sorted(on_page) == sorted(_EXTRAS), (
        f"{_DOC.name} has sections for {on_page}; this module's _EXTRAS names {sorted(_EXTRAS)}"
    )
    read = component_readings.EXTRAS
    # The page's order, which is the order the rendered section lists them in.
    assert list(read) == on_page, (
        f"the readings generator reads the extras {list(read)}; {_DOC.name} assesses {on_page}. "
        "Add the closure to EXTRAS in scripts/security/component_readings.py and run it"
    )
    assert read == {extra: path for extra, (path, *_) in _EXTRAS.items()}, (
        "the readings generator reads an extra from a different closure file than this module"
    )
    assert component_readings.CORE == _CLOSURE


def test_the_harness_section_rests_on_the_generated_reading() -> None:
    """RED when: the harness section stops naming the rendered table it rests on, stops saying
    that a 0 there is about the PyPI names and not about the Qt inside the wheels, or names other
    PyPI packages than the ones the extra adds.

    OSV matches an advisory by PyPI name, so a 0 for these names is not a clean result for Qt. The
    section copies no figure from the snapshot, so a re-read cannot leave it behind.
    """
    section = " ".join(_region(_HARNESS_START, _ASVS_START).split())
    assert f"*{_EXTRA_NAMES.removeprefix('### ')}*" in section, (
        "the harness section no longer names the rendered table that carries its readings"
    )
    additions = sorted(_additions(_HARNESS_CLOSURE))
    assert additions, f"{_HARNESS_CLOSURE.name} adds nothing to the core closure"
    names = _listed(additions, "or")
    assert f"it counted no advisory naming the {names} PyPI packages" in section, (
        f"the harness section's statement of what a 0 means does not name {names}"
    )
    assert "It does not mean the Qt code inside those wheels has no known flaws." in section, (
        "the harness section no longer states the limit of an OSV reading by PyPI name"
    )


def test_the_version_comparison_can_fail() -> None:
    """RED when: the pin comparison stops seeing a version change.

    THE POSITIVE CONTROL FOR THE TWO VERSION GATES BELOW. They pass whenever the comparison
    returns nothing, so a refactor that compared names only would turn both into guards that
    cannot fail. That is how this inventory drifted before (BACKLOG #1812).
    """
    drift = _diff_pins("the lock", {"anyio": "4.15.1", "hl7": "0.4.5"}, {"anyio": "4.14.2"})
    assert drift == [
        "hl7: in the closure file, absent from the lock",
        "anyio: closure file says 4.15.1, the lock says 4.14.2",
    ]


def test_the_core_lock_parses_to_a_real_closure() -> None:
    """RED when: the core lock parser stops finding a real closure.

    THE POSITIVE CONTROL FOR THE CORE-LOCK GATE. A parser that finds nothing would make the gate
    fail for the wrong reason, or pass against a closure file emptied in the same change.
    """
    pins = _core_lock_pins()
    assert len(pins) >= 20, f"{_CORE_LOCK.name} parsed to {len(pins)} pins, too few to be real"
    # One transitive (cffi, via cryptography) and one whose lock line carries a platform marker
    # (uvloop, which no Windows install gets).
    assert {"tomlkit", "cryptography", "cffi", "uvloop"} <= pins.keys(), (
        f"{_CORE_LOCK.name} misses a known transitive or platform-marked core package"
    )


@pytest.mark.parametrize(("closure", "lock"), _PAIRS, ids=lambda p: p.name)
def test_the_closure_file_is_its_lock(closure: Path, lock: Path) -> None:
    """RED when: a closure file stops matching its lock, in any name, version or line.

    This is the regeneration gate (BACKLOG #1812, and #1955 for the sqlserver pair). A closure file
    is a copy of the pin lines in its lock, and a copy with no check drifts silently. The designation tests above only see
    what someone remembered to add here. A dependency PR once wrote fourteen bumps into this file
    and not into the lock. The inventory then showed ``anyio`` at a release with no advisories. The
    lock installed one carrying three.

    The whole line list is compared, so a duplicate, an unsorted line or a stray format also fails.
    To fix it, run ``scripts/security/runtime_closure.py``, which rewrites the pin lines from the
    lock. The Dependabot lock-resync workflow runs the same script when a Dependabot PR moves it.
    """
    pins = runtime_closure.lock_pins(lock)
    drift = _diff_pins(lock.name, _closure_pins(closure), pins)
    expected = runtime_closure.expected_closure_lines(pins)
    assert not drift and _closure_lines(closure) == expected, (
        f"{closure.relative_to(_ROOT).as_posix()} does not match {lock.name}. The lock is what "
        "installs; never edit it to match this file. Differences:\n  "
        + ("\n  ".join(drift) or "none by name or version; the lines are unsorted or malformed")
        + "\nRegenerate with: python scripts/security/runtime_closure.py"
    )


@pytest.mark.parametrize("path", [c for c, _ in _PAIRS], ids=lambda p: p.name)
def test_every_closure_pin_is_the_version_requirements_lock_installs(path: Path) -> None:
    """RED when: requirements.lock installs a different version of a closure package.

    requirements.lock is the file pip-audit audits and the install guides tell an operator to use.
    It is a superset (an --all-extras export), so only the closure's own names are compared, and a
    lock-only name is expected.

    Both locks are exports of uv.lock, so this fails only when one of them is stale. The DEP-1 gate
    catches that too, but in another workflow; this check holds the closure file to the audited lock
    on the same test run. The fix is to re-export both locks, then regenerate the closure file.
    """
    lock = runtime_closure.lock_versions(_LOCK)
    closure = _closure_pins(path)
    assert len(lock) > len(closure), (
        f"requirements.lock parsed to no more names than {path.name}; it is an --all-extras "
        "export and must be a strict superset, so the parser has broken"
    )
    forked = sorted(n for n in closure if len(set(lock.get(n, []))) > 1)
    assert not forked, f"requirements.lock pins these closure packages twice: {forked}"
    installed = {n: lock[n][0] for n in closure if n in lock}
    drift = _diff_pins("requirements.lock", closure, installed)
    assert not drift, (
        f"{len(drift)} closure pin(s) disagree with requirements.lock. Re-export the locks from "
        "uv.lock (DEP-1), then regenerate the closure file:\n  " + "\n  ".join(drift)
    )


@pytest.mark.parametrize("path", [c for c, _ in _PAIRS], ids=lambda p: p.name)
def test_dependabot_does_not_write_the_closure_file(path: Path) -> None:
    """RED when: the uv Dependabot entry stops excluding a closure file.

    Dependabot's uv ecosystem reads any requirements-shaped ``.txt`` in a top-level directory as a
    manifest, and this file is one. It bumped pins here without moving the lock, twice (PR 1068 and
    PR 1295), and those are the wrong pins BACKLOG #1812 found. With the gate above, every such
    weekly PR would go red. ``exclude-paths`` keeps the version track off the file. An open
    dependabot-core report (issue 14408) says the security track ignores that key, so the
    lock-resync workflow's rewrite from the lock is what holds the file to it on both tracks.

    The pattern is relative to the entry's ``directory``, so a moved directory would silently
    stop matching. That is why the directory is pinned too.
    """
    doc = yaml.safe_load(_DEPENDABOT.read_text(encoding="utf-8"))
    uv = [u for u in doc["updates"] if u.get("package-ecosystem") == "uv"]
    assert len(uv) == 1, f"expected one uv entry in {_DEPENDABOT.name}, found {len(uv)}"
    assert uv[0].get("directory") == "/", (
        "exclude-paths patterns are relative to the entry's directory; this test assumes '/'"
    )
    closure = path.relative_to(_ROOT).as_posix()
    assert closure in (uv[0].get("exclude-paths") or []), (
        f"the uv entry in {_DEPENDABOT.name} does not exclude {closure}, so Dependabot will "
        "bump its pins without moving the lock and the closure gate above goes red"
    )


@pytest.mark.parametrize(
    "path",
    [_DOC, *(f for pair in _PAIRS for f in pair), _READINGS, _SURVEY],
    ids=lambda p: p.name,
)
def test_the_tracked_paths_exist(path: Path) -> None:
    """RED when: any file the guard grades or grades against is deleted or moved.

    The guard is worthless if it silently stops finding what it grades, and a missing-file error
    reads very differently from a passing suite.
    """
    assert path.is_file(), f"{path} is missing; the designation guard cannot run"


def test_the_regenerator_names_packages_as_packaging_does() -> None:
    """RED when: the regenerator's stdlib name normalizer stops agreeing with ``packaging``.

    The regenerator cannot import ``packaging`` (it runs with nothing installed), so it carries its
    own PEP 503 normalizer. This pins the two together on the separators PEP 503 folds.
    """
    for raw in ("ruamel.yaml", "Typing_Extensions", "zope..interface", "argon2-cffi", "PyYAML"):
        assert runtime_closure.canonical_name(raw) == canonicalize_name(raw), raw


def test_the_regenerator_defaults_to_the_files_this_module_grades() -> None:
    """RED when: the script moves, or its default paths stop naming the tracked files.

    The resync workflow runs the script with no arguments, so its defaults are the whole contract.
    A pair missing from that default would never be regenerated on a Dependabot PR.
    """
    assert runtime_closure.PAIRS == _PAIRS
    assert runtime_closure.selected_pairs(None, None) == _PAIRS


def test_one_pair_needs_both_sides_named() -> None:
    """RED when: naming one side alone is accepted, or naming both stops selecting one pair.

    Defaulting the unnamed side paired a file with the wrong lock: ``--lock`` naming the sqlserver
    lock alone wrote its pins into the core file. And if naming both still rewrote every pair, the
    drift tests below would write the tracked files.
    """
    other = Path("elsewhere.txt")
    assert runtime_closure.selected_pairs(other, _CORE_LOCK) == ((other, _CORE_LOCK),)
    for closure, lock in ((other, None), (None, _SQLSERVER_LOCK)):
        with pytest.raises(ValueError, match="go together"):
            runtime_closure.selected_pairs(closure, lock)


def test_the_regenerator_reads_every_lock_before_writing_any_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: a bad second lock leaves the first closure file already rewritten.

    The resync pushes whatever the run leaves, so a half-finished rewrite would push one closure
    file regenerated and the other not. The first pair here is drifted, so a write would show.
    """
    first = tmp_path / "first.txt"
    first.write_text("# header\nanyio==0.0.0\n", encoding="utf-8")
    forked = tmp_path / "forked.lock"
    forked.write_text("hl7==0.4.5 ; sys_platform == 'win32'\nhl7==0.4.4\n", encoding="utf-8")
    pairs = ((first, _CORE_LOCK), (tmp_path / "second.txt", forked))
    (tmp_path / "second.txt").write_text("# header\n", encoding="utf-8")
    monkeypatch.setattr(runtime_closure, "PAIRS", pairs)
    with pytest.raises(runtime_closure.LockFormatError):
        runtime_closure.main([])
    assert first.read_text(encoding="utf-8") == "# header\nanyio==0.0.0\n"


@pytest.mark.parametrize(
    "line",
    [
        "foo @ https://example.invalid/foo.whl ; sys_platform == 'win32'",
        "foo===1.0",
        "foo[bar]==1.0",
        "foo==1.*",
        "foo==1.0,<2",
    ],
)
def test_the_lock_reader_refuses_a_line_it_cannot_copy(tmp_path: Path, line: str) -> None:
    """RED when: the strict reader turns a non-pin line into a pin instead of refusing it.

    The resync pushes whatever the regenerator writes, unattended. A URL requirement whose marker
    holds ``==`` used to split at the marker and write a garbage pin.
    """
    lock = tmp_path / "core.lock"
    lock.write_text(f"hl7==0.4.5 \\\n    --hash=sha256:00\n{line} \\\n", encoding="utf-8")
    with pytest.raises(runtime_closure.LockFormatError):
        runtime_closure.lock_pins(lock)


def test_the_regenerator_rewrites_a_drifted_closure(tmp_path: Path) -> None:
    """RED when: the regenerator stops repairing a wrong pin, loses the header, or needs a package.

    The resync workflow runs it as a script under a bare python3, so this does too. ``-S`` skips
    site-packages, the nearest local stand-in for a runner with nothing installed. Not ``-I``: that
    also drops the script's own directory from the import path, which the runner keeps.

    The expected text is the tracked file, which the gate above holds to the lock. Comparing with
    ``render_closure`` instead would pass whatever that function returned.
    """
    text = _CLOSURE.read_text(encoding="utf-8")
    # A wrong version, the shape Dependabot's direct bumps left, plus a name the lock does not pin.
    wrong = text.replace("\nanyio==", "\nanyio==0.0.0\nanyio-stale==", 1)
    assert wrong != text, "the closure file no longer pins anyio; pick another package here"
    closure = tmp_path / "closure.txt"
    closure.write_text(wrong, encoding="utf-8")
    script = Path(runtime_closure.__file__)
    run = subprocess.run(
        [sys.executable, "-S", "-E", "-s", str(script), "--closure", str(closure)]
        + ["--lock", str(_CORE_LOCK)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0, run.stderr
    assert closure.read_text(encoding="utf-8") == text


@pytest.mark.parametrize("extra", sorted(_EXTRAS))
def test_the_regenerator_rewrites_a_drifted_extra_closure(tmp_path: Path, extra: str) -> None:
    """RED when: the regenerator cannot repair an extra's pair, or drops a name the extra adds.

    The same script-mode run as above, on each extra's pair. The drift removes the extra's marker
    package, a name the core lock does not carry, so a rewrite that read the core lock by mistake
    would not restore it and this fails.
    """
    path, _, _, marker = _EXTRAS[extra]
    lock = dict(_PAIRS)[path]
    text = path.read_text(encoding="utf-8")
    wrong = text.replace(f"\n{marker}==", f"\n{marker}-gone==", 1)
    assert wrong != text, f"{path.name} no longer pins {marker}; pick another package here"
    closure = tmp_path / "closure.txt"
    closure.write_text(wrong, encoding="utf-8")
    script = Path(runtime_closure.__file__)
    run = subprocess.run(
        [sys.executable, "-S", "-E", "-s", str(script), "--closure", str(closure)]
        + ["--lock", str(lock)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0, run.stderr
    assert closure.read_text(encoding="utf-8") == text


# --- The ASVS-example reading (BACKLOG #1189, ASVS 15.1.4 ground 2) ----------------------------------
#
# ASVS 5.0.0 V15.1 gives as examples of a risky component one that is "poorly maintained,
# unsupported, at the end-of-life stage, or have a history of significant vulnerabilities". The page
# reads every component on those examples from a dated snapshot, in a section the generator renders.
# Everything below is offline: the snapshot is a tracked file, and nothing here calls the network.

_NOT_RISKY = "### Not risky on any of the three"
_FIT = "### How this reading and the tiers fit together"
#: The rendered section's last table: what was read for the names the assessed extras add. Each
#: extra's own section points at it instead of copying its figures.
_EXTRA_NAMES = "### The names the assessed extras add"
#: The page's word for each example in a "Risky on" cell. This module's own copy, so the checks
#: that read those cells do not go through the generator's.
_AXIS_WORDS = {
    "maintenance": "maintenance",
    "support": "support",
    "advisory_history": "vulnerability history",
}
#: The columns of the table under ``_EXTRA_NAMES``, in order. Its header row is held to these.
_EXTRA_COLUMNS = (
    "Component",
    "Added by",
    "Pinned",
    "Newest release",
    "Advisories counted under the name",
    "Risky on",
)


def _listed(names: list[str], joiner: str) -> str:
    """Backticked names as "`a`, `b` <joiner> `c`". This module's own, not the generator's."""
    *head, last = (f"`{name}`" for name in names)
    return f"{', '.join(head)} {joiner} {last}" if head else last


#: Each ASVS example's subsection in the rendered section, and the subsection after it.
_AXIS_SECTIONS = (
    ("maintenance", "### Poorly maintained", "### Unsupported or end of life"),
    ("support", "### Unsupported or end of life", "### A history of significant vulnerabilities"),
    (
        "advisory_history",
        "### A history of significant vulnerabilities",
        "### Not risky on any of the three",
    ),
)
_RERENDER = "python scripts/security/component_readings.py --render-only"


def _snapshot() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(_READINGS.read_text(encoding="utf-8"))
    return data


def _survey() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(_SURVEY.read_text(encoding="utf-8"))
    return data


def _readings(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Name to reading. A name read twice fails here rather than being silently overwritten."""
    out: dict[str, dict[str, Any]] = {}
    for reading in data["readings"]:
        assert reading["name"] not in out, f"{_READINGS.name} reads {reading['name']} twice"
        out[reading["name"]] = reading
    return out


def _designated() -> set[str]:
    """Every name the tiers designate: the core tables' and each extra section's."""
    return (
        _designated_and_excluded()[0]
        | _sqlserver_designated_and_excluded()[0]
        | _harness_designated_and_excluded()[0]
    )


def _stated_facts_drift(page: str, data: dict[str, Any]) -> list[str]:
    """Where the page's dates, counts and flagged names disagree with the snapshot.

    Computed here from the snapshot and read with this module's own table parser, NOT through the
    generator's renderer, so a renderer that printed a wrong figure consistently is still caught.
    """
    readings = _readings(data)
    section = _region(_ASVS_START, _END, page)
    flat = " ".join(section.split())
    problems = []
    stamp = f"**Snapshot date: {data['snapshot_date']}. Re-read by: {data['reread_by']}.**"
    if stamp not in flat:
        problems.append(f"the page does not state {stamp!r}")
    size = len(readings)
    counts = {
        axis: sum(r["risky"][axis] for r in readings.values()) for axis, _, _ in _AXIS_SECTIONS
    }
    clean = {n for n, r in readings.items() if not any(r["risky"].values())}
    risky = size - len(clean)
    sentence = (
        f"**Risky on at least one example: {risky} of {size}. On maintenance: "
        f"{counts['maintenance']}. On support: {counts['support']}. On vulnerability history: "
        f"{counts['advisory_history']}. Not risky on any: {len(clean)}. "
        f"{risky} plus {len(clean)} is {size}.**"
    )
    if sentence not in flat:
        problems.append(f"the page does not state {sentence!r}")
    for axis, start, end in _AXIS_SECTIONS:
        named = _table_names(_region(start, end, page))
        flagged = {n for n, r in readings.items() if r["risky"][axis]}
        if named != flagged:
            problems.append(f"{axis}: page names {sorted(named)}, snapshot {sorted(flagged)}")
    named = _table_names(_region(_NOT_RISKY, _FIT, page))
    if named != clean:
        problems.append(f"not risky: page names {sorted(named)}, snapshot {sorted(clean)}")
    added = {n: r for n, r in readings.items() if r["added_by"]}
    stated = (
        f"All {size} distributions this page assesses are read: the {size - len(added)} in the "
        f"core closure and the {len(added)} that the assessed extras add to it."
    )
    if stated not in flat:
        problems.append(f"the page does not state {stated!r}")
    for extra in data["population"]["extras"]:
        names = sorted(n for n, r in added.items() if extra in r["added_by"])
        sentence = f"The `{extra}` extra adds {len(names)}" + (
            f": {_listed(names, 'and')}." if names else "."
        )
        if sentence not in flat:
            problems.append(f"the page does not state {sentence!r}")
    # The last table, read here cell by cell and not through the renderer. An extra's own section
    # rests on it, so a wrong column printed consistently must not pass.
    table = _region(_EXTRA_NAMES, _END, page)
    if f"| {' | '.join(_EXTRA_COLUMNS)} |" not in table.splitlines():
        problems.append(f"extras' table: the header row is not {_EXTRA_COLUMNS}")
    rows = [
        [cell.strip() for cell in line.split("|")[1:-1]]
        for line in table.splitlines()
        if line.startswith("| `")
    ]
    # Lists, not sets, so a name with two rows is drift too.
    named_rows = sorted(row[0].strip("`") for row in rows)
    if named_rows != sorted(added):
        problems.append(f"extras' names: page names {named_rows}, snapshot {sorted(added)}")
    for row in rows:
        name = row[0].strip("`")
        if name not in added:
            continue
        if len(row) != len(_EXTRA_COLUMNS):
            problems.append(f"extras' row for {name}: {len(row)} cells, not {len(_EXTRA_COLUMNS)}")
            continue
        reading = added[name]
        risky_on = [_AXIS_WORDS[axis] for axis, _, _ in _AXIS_SECTIONS if reading["risky"][axis]]
        want = [
            sorted(reading["added_by"]),
            reading["pinned"],
            reading["newest_upload"] or "none",
            str(len(reading["advisories"])),
            " and ".join(risky_on) or "none",
        ]
        got = [sorted(re.findall(r"`([^`]+)`", row[1])), *row[2:]]
        problems += [
            f"extras' row for {name}: {column} is {g!r}, the snapshot reads {w!r}"
            for column, g, w in zip(_EXTRA_COLUMNS[1:], got, want, strict=True)
            if g != w
        ]
    return problems


def test_the_readings_snapshot_parses_and_is_not_empty() -> None:
    """RED when: the snapshot is emptied, or its shape changes under the tests below.

    THE POSITIVE CONTROL FOR THE SNAPSHOT TESTS. A snapshot that parsed to no readings would make
    "every verdict follows" hold vacuously.
    """
    data = _snapshot()
    readings = _readings(data)
    assert len(readings) >= 20, f"{_READINGS.name} parsed to {len(readings)} readings"
    # Two core names, and the one name each assessed extra must add.
    assert {"tomlkit", "cryptography"} | {e[3] for e in _EXTRAS.values()} <= readings.keys()
    dt.date.fromisoformat(data["snapshot_date"])
    assert data["criteria"] == component_readings.criteria(), (
        "the snapshot records different criteria from the generator's; a changed threshold "
        "needs a new run of scripts/security/component_readings.py"
    )
    assert all(set(r["risky"]) == set(component_readings.AXES) for r in readings.values())


def _assessed_population() -> dict[str, list[str]]:
    """Name to the assessed extras whose closure adds it, sorted; empty for a core name.

    Read from the closure files and this module's ``_EXTRAS``, never through the generator, so a
    generator that reads too few closures cannot agree with itself here.
    """
    population: dict[str, list[str]] = {name: [] for name in _closure()}
    for extra in sorted(_EXTRAS):
        for name in _additions(_EXTRAS[extra][0]):
            population.setdefault(name, []).append(extra)
    return population


def _population_drift(data: dict[str, Any]) -> list[str]:
    """Where the snapshot's readings are not exactly the assessed population.

    Names only, never versions. The readings are dated to the pins of the snapshot day, and a lock
    bump that moved a version would otherwise turn every Dependabot pull request red.
    """
    readings = _readings(data)
    expected = _assessed_population()
    problems = []
    declared = {
        "core": _CLOSURE.relative_to(_ROOT).as_posix(),
        "extras": {e: v[0].relative_to(_ROOT).as_posix() for e, v in _EXTRAS.items()},
    }
    if data["population"] != declared:
        problems.append(f"the snapshot says it read {data['population']}, not {declared}")
    missing = sorted(expected.keys() - readings.keys())
    if missing:
        problems.append(f"no reading for {missing}; run scripts/security/component_readings.py")
    stray = sorted(readings.keys() - expected.keys())
    if stray:
        problems.append(f"{_READINGS.name} reads {stray}, which no assessed closure carries")
    wrong = sorted(
        n
        for n in expected.keys() & readings.keys()
        if sorted(readings[n]["added_by"]) != expected[n]
    )
    if wrong:
        problems.append(f"added_by does not name the extras that add {wrong}")
    return problems


def test_every_population_member_has_exactly_one_reading() -> None:
    """RED when: an assessed name has no reading, a reading names a non-member, or a reading says
    the wrong extras add its name.

    The population is the core closure plus what every assessed extra adds to it. So an extra the
    page assesses and the generator did not read fails here: its names have no reading.
    """
    drift = _population_drift(_snapshot())
    assert not drift, f"{_READINGS.name} is not the assessed population:\n  " + "\n  ".join(drift)


def test_the_population_check_can_fail() -> None:
    """RED when: the population check stops seeing an unread extra, a stray reading, a wrong
    ``added_by`` or a wrong population record.

    THE POSITIVE CONTROL FOR THE TEST ABOVE. The first mutation is the gap BACKLOG #2414 closed: a
    snapshot with no reading for any name one extra adds.
    """
    data = _snapshot()
    assert not _population_drift(data)
    for extra, (_, _, _, marker) in _EXTRAS.items():
        unread = [r for r in data["readings"] if extra not in r["added_by"]]
        assert len(unread) < len(data["readings"]), f"no reading says the {extra} extra adds it"
        drift = _population_drift({**data, "readings": unread})
        assert any("no reading for" in line and marker in line for line in drift), drift
    first = data["readings"][0]
    stray = {**data, "readings": [*data["readings"], {**first, "name": "not-a-member"}]}
    assert any("not-a-member" in line for line in _population_drift(stray))
    core = next(r for r in data["readings"] if not r["added_by"])
    moved = [{**r, "added_by": ["harness"]} if r is core else r for r in data["readings"]]
    assert any(core["name"] in line for line in _population_drift({**data, "readings": moved}))
    old_record = {**data, "population": _SQLSERVER_CLOSURE.relative_to(_ROOT).as_posix()}
    assert any("says it read" in line for line in _population_drift(old_record))


def test_the_population_is_the_core_closure_plus_what_each_extra_adds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the generator drops an extra's additions, says an extra adds a core name, or
    accepts one name pinned at two versions.

    A reading records one pin per name, so two closures that disagree on a version must stop the
    run rather than record whichever was read first.
    """
    core, one, two = (tmp_path / f"{n}.txt" for n in ("core", "one", "two"))
    core.write_text("# header\na==1\nb==2\n", encoding="utf-8")
    one.write_text("a==1\nb==2\nc==3\n", encoding="utf-8")
    two.write_text("a==1\nb==2\nc==3\nd==4\n", encoding="utf-8")
    monkeypatch.setattr(component_readings, "CORE", core)
    monkeypatch.setattr(component_readings, "EXTRAS", {"one": one, "two": two})
    assert component_readings.population() == {
        "a": ("1", []),
        "b": ("2", []),
        "c": ("3", ["one", "two"]),
        "d": ("4", ["two"]),
    }
    two.write_text("a==1\nb==9\nc==3\nd==4\n", encoding="utf-8")
    with pytest.raises(ValueError, match="two.txt pins b at 9"):
        component_readings.population()


def test_every_verdict_follows_from_its_readings() -> None:
    """RED when: a recorded verdict is not what the recorded criteria give on the recorded readings.

    This is what makes the criterion checkable. A hand-edited verdict, or a criterion changed in the
    generator without a re-run, fails here.
    """
    data = _snapshot()
    as_of = dt.date.fromisoformat(data["snapshot_date"])
    wrong = {
        name: reading["risky"]
        for name, reading in _readings(data).items()
        if component_readings.classify(reading, as_of, data["criteria"]) != reading["risky"]
    }
    assert not wrong, f"these verdicts do not follow from their readings: {wrong}"


def test_the_verdict_rederivation_can_fail() -> None:
    """RED when: ``classify`` stops seeing a change on any axis.

    THE POSITIVE CONTROL FOR THE TEST ABOVE. Each mutation turns one axis on for a reading made
    clean here, so a ``classify`` that returned the stored verdict, or nothing, fails. The clean
    reading is built from the first real one, so this holds whatever a later snapshot flags.
    """
    data = _snapshot()
    as_of = dt.date.fromisoformat(data["snapshot_date"])
    clean = {
        **data["readings"][0],
        "newest_upload": as_of.isoformat(),
        "project_status": "active",
        "development_status": [],
        "pinned_yanked": False,
        "advisories": [],
    }
    rules = data["criteria"]
    assert component_readings.classify(clean, as_of, rules) == dict.fromkeys(
        component_readings.AXES, False
    )
    significant = {"id": "GHSA-test", "severity": "HIGH", "published": as_of.isoformat()}
    mutations: list[tuple[str, dict[str, Any]]] = [
        ("maintenance", {"newest_upload": "2000-01-01"}),
        ("support", {"project_status": "archived"}),
        ("support", {"pinned_yanked": True}),
        ("support", {"development_status": [rules["inactive_classifier"]]}),
        ("advisory_history", {"advisories": [significant]}),
    ]
    for axis, change in mutations:
        assert component_readings.classify({**clean, **change}, as_of, rules)[axis], change


def test_the_reread_date_is_the_stated_interval_after_the_snapshot() -> None:
    """RED when: the re-read date is not the generator's interval after the snapshot date.

    This compares two recorded dates with each other. It never reads today's date: a test that did
    would go red on every unrelated pull request once the re-read date passed.
    """
    data = _snapshot()
    gap = dt.date.fromisoformat(data["reread_by"]) - dt.date.fromisoformat(data["snapshot_date"])
    assert gap == dt.timedelta(days=component_readings.REREAD_INTERVAL_DAYS)


def test_the_generator_reads_the_same_designation_as_this_guard() -> None:
    """RED when: the generator's reading of the tiers and this module's disagree.

    The rendered section's "Designated above" column comes from the generator's parser, and the
    closure tests above use this module's. Two parsers of one page must agree, or the section and
    the tiers describe different pages.
    """
    page = _DOC.read_text(encoding="utf-8")
    tiers = [ln for ln in page.splitlines() if re.match(r"## Tier \d+ ", ln)]
    assert len(tiers) >= 3, "the page's tier headings moved; this test reads between them"
    expected: dict[str, str] = {}
    for heading, following in zip(tiers, [*tiers[1:], _CORE_SPLIT], strict=True):
        tier = f"tier {heading.split()[2]}"
        expected |= dict.fromkeys(_table_names(_region(heading, following)), tier)
    expected |= dict.fromkeys(_sqlserver_designated_and_excluded()[0], "the `sqlserver` extra")
    expected |= dict.fromkeys(_harness_designated_and_excluded()[0], "the `harness` extra")
    assert set(expected) == _designated()
    assert component_readings.designation_labels(page) == expected


def test_the_rendered_section_is_the_tracked_one() -> None:
    """RED when: the section between the markers is not what the snapshot and the tiers render.

    A hand edit, a re-read whose page was not committed, or a tier change after the last render all
    fail here. The fix needs no network.
    """
    page = _DOC.read_text(encoding="utf-8")
    expected = component_readings.render_section(
        _snapshot(), component_readings.designation_labels(page), _survey()
    )
    assert component_readings.section_of(page) == expected, (
        f"the readings section in {_DOC.name} is stale or hand-edited. Re-render: {_RERENDER}"
    )


def test_the_page_states_the_snapshot_dates_counts_and_names() -> None:
    """RED when: the page's dates, counts or flagged names drift from the snapshot.

    Independent of the renderer: see ``_stated_facts_drift``.
    """
    drift = _stated_facts_drift(_DOC.read_text(encoding="utf-8"), _snapshot())
    assert not drift, "the readings section disagrees with its snapshot:\n  " + "\n  ".join(drift)


def test_the_section_checks_can_fail() -> None:
    """RED when: either section check stops seeing a changed snapshot or a changed page.

    THE POSITIVE CONTROL FOR THE TWO TESTS ABOVE. The mutations are built from the snapshot, not
    from today's figures, so they survive the next re-read.
    """
    page = _DOC.read_text(encoding="utf-8")
    data = _snapshot()
    labels = component_readings.designation_labels(page)
    tracked = component_readings.section_of(page)
    survey = _survey()
    assert tracked == component_readings.render_section(data, labels, survey)
    assert not _stated_facts_drift(page, data)

    # Whatever the first reading's verdict is, invert it, so this works on any future snapshot.
    first = data["readings"][0]
    flipped = {
        **data,
        "readings": [
            {
                **first,
                "risky": {**first["risky"], "maintenance": not first["risky"]["maintenance"]},
            },
            *data["readings"][1:],
        ],
    }
    moved = {**data, "reread_by": "2099-01-01"}
    for changed in (flipped, moved):
        assert component_readings.render_section(changed, labels, survey) != tracked
        assert _stated_facts_drift(page, changed)
    # Dropping a designation always shows: a risky row's column, or the not-risky grouping, moves.
    unlabelled = {k: v for k, v in labels.items() if k != next(iter(labels))}
    assert component_readings.render_section(data, unlabelled, survey) != tracked
    # Any table row naming a component: a flagged one, or a not-risky group row.
    row = next(ln for ln in tracked.splitlines() if ln.startswith("| `"))
    assert _stated_facts_drift(page.replace(row + "\n", ""), data)
    # A row of the last table, which only the extras' names check reads.
    extras_table = tracked.partition(f"\n{_EXTRA_NAMES}\n")[2]
    row = next(ln for ln in extras_table.splitlines() if ln.startswith("| `"))
    drift = _stated_facts_drift(page.replace(row + "\n", ""), data)
    assert any(line.startswith("extras' names") for line in drift), drift
    # A stale second row for a name the table already has.
    drift = _stated_facts_drift(page.replace(row + "\n", row + "\n" + row + "\n"), data)
    assert any(line.startswith("extras' names") for line in drift), drift
    # One change per cell of a row, each seen as that cell. The last one stops the name being an
    # addition at all, which moves the sentences above the table.
    added = next(r for r in data["readings"] if r["added_by"])
    advisory = {"id": "GHSA-t", "severity": "LOW", "rated_by": "github", "published": "2000-01-01"}
    flipped_axes = {**added["risky"], "support": not added["risky"]["support"]}
    in_row = f"extras' row for {added['name']}: "
    for change, problem in (
        ({"added_by": [*added["added_by"], "another"]}, in_row + "Added by"),
        ({"pinned": "0.0.0-not-the-pin"}, in_row + "Pinned"),
        ({"newest_upload": "1999-01-01"}, in_row + "Newest release"),
        ({"advisories": [*added["advisories"], advisory]}, in_row + "Advisories counted"),
        ({"risky": flipped_axes}, in_row + "Risky on"),
        ({"added_by": []}, "the page does not state 'The `"),
    ):
        changed = {
            **data,
            "readings": [{**r, **change} if r is added else r for r in data["readings"]],
        }
        drift = _stated_facts_drift(page, changed)
        assert any(line.startswith(problem) for line in drift), (change, drift)


# --- What each wheel carries inside it (BACKLOG #2935) ----------------------------------------------
#
# OSV matches an advisory by PyPI name, so a flaw in code a wheel packs from another project does
# not show in the reading above. ``security/bundled-code-survey.json`` answers, for every assessed
# wheel, whether it carries such code, and records the route the page takes for a not-designated
# wheel that does. The tests below hold the survey to the population and the page to the survey.

_SURVEY_HEADING = "### What each wheel carries inside it"
_HIGHLIGHTED = "**Highlighted as risky on what it carries:**"
_READ = "**Read from the carried project's own advisories:**"


def _owed_a_route(survey: dict[str, Any]) -> set[str]:
    """The not-designated names the survey did not show to carry nothing.

    This module's own reading of the tiers and of the record, not the generator's rule.
    """
    return {w["name"] for w in survey["wheels"] if w["carries"] != "no"} - _designated()


def _survey_page_drift(page: str, survey: dict[str, Any]) -> list[str]:
    """Where the page's survey subsection disagrees with the record. Not through the renderer."""
    section = _region(_SURVEY_HEADING, _EXTRA_NAMES, page)
    found, _, highlighted = section.partition(f"\n{_HIGHLIGHTED}\n")
    # A read route renders its own table after the highlighted one; its names are not highlights.
    highlighted = highlighted.partition(f"\n{_READ}\n")[0]
    wheels = survey["wheels"]
    counts = {a: sum(w["carries"] == a for w in wheels) for a in component_readings.CARRIES}
    size = len(wheels)
    sentence = (
        f"**Carries another project's compiled code: {counts['yes']} of {size}. Does not: "
        f"{counts['no']}. Not established: {counts['not established']}. {counts['yes']} plus "
        f"{counts['no']} plus {counts['not established']} is {size}.**"
    )
    problems = []
    if sentence not in " ".join(section.split()):
        problems.append(f"the page does not state {sentence!r}")
    carrying = {w["name"] for w in wheels if w["carries"] != "no"}
    if _table_names(found) != carrying:
        problems.append(f"found: page names {sorted(_table_names(found))}, the survey {carrying}")
    want = {w["name"] for w in wheels if w["route"] == "highlight"}
    if _table_names(highlighted) != want:
        problems.append(
            f"highlighted: page names {sorted(_table_names(highlighted))}, the survey {want}"
        )
    return problems


def test_every_assessed_wheel_has_a_survey_answer_and_every_owed_route_is_recorded() -> None:
    """RED when: a name in an assessed closure has no survey answer, the survey answers for a name
    no closure carries, or a not-designated wheel that carries another project's compiled code,
    or whose answer is not established, has no route.

    The names are held to the closure files here, not to the snapshot, so a dependency that enters
    a closure needs a survey answer in the same pull request. A version bump alone does not turn
    this red: the survey is dated to the snapshot's pins, like the readings.
    """
    survey = _survey()
    names = sorted(w["name"] for w in survey["wheels"])
    assert len(names) >= 20, f"{_SURVEY.name} parsed to {len(names)} answers"
    assert names == sorted(_assessed_population()), (
        f"{_SURVEY.name} does not answer for exactly the assessed closures: "
        f"missing {sorted(_assessed_population().keys() - set(names))}, "
        f"stray {sorted(set(names) - _assessed_population().keys())}"
    )
    page = _DOC.read_text(encoding="utf-8")
    problems = component_readings.survey_problems(
        survey, _snapshot(), component_readings.designation_labels(page)
    )
    assert problems == [], f"{_SURVEY.name} is incomplete:\n  " + "\n  ".join(problems)
    routed = {w["name"] for w in survey["wheels"] if w["route"] in component_readings.ROUTES}
    assert _owed_a_route(survey) == routed, (
        f"owed a route: {sorted(_owed_a_route(survey))}; routed: {sorted(routed)}"
    )


def test_the_page_states_what_the_survey_found_and_the_route_each_wheel_took() -> None:
    """RED when: the page's survey tables or counts disagree with the record.

    Independent of the renderer: see ``_survey_page_drift``. The exact text is held by
    ``test_the_rendered_section_is_the_tracked_one``.
    """
    drift = _survey_page_drift(_DOC.read_text(encoding="utf-8"), _survey())
    assert drift == [], "the survey subsection disagrees with its record:\n  " + "\n  ".join(drift)


def test_the_survey_checks_can_fail() -> None:
    """RED when: a survey check stops seeing a missing answer, a missing route or a stale page.

    THE POSITIVE CONTROL FOR THE TWO TESTS ABOVE. Each mutation is built from the record, so it
    survives the next survey.
    """
    page = _DOC.read_text(encoding="utf-8")
    data, survey = _snapshot(), _survey()
    labels = component_readings.designation_labels(page)
    wheels = survey["wheels"]

    def problems(changed: list[dict[str, Any]]) -> list[str]:
        return component_readings.survey_problems({**survey, "wheels": changed}, data, labels)

    def swap(target: dict[str, Any], **change: Any) -> list[dict[str, Any]]:
        return [{**w, **change} if w is target else w for w in wheels]

    routed = next(w for w in wheels if w["route"] is not None)
    designated = next(w for w in wheels if w["name"] in labels and w["carries"] == "yes")
    tagged = next(w for w in wheels if w["evidence_kind"] == "wheel tag")
    for changed, problem in (
        (wheels[1:], f"no survey answer for ['{wheels[0]['name']}']"),
        (
            [*wheels, {**wheels[0], "name": "not-a-member"}],
            "the survey answers for ['not-a-member']",
        ),
        ([*wheels, wheels[0]], f"the survey answers for {wheels[0]['name']} twice"),
        (swap(routed, pinned="0.0.0-not-the-pin"), f"{routed['name']}: surveyed at"),
        (swap(routed, route=None), f"{routed['name']}: not designated"),
        (swap(routed, route_reason=" "), f"{routed['name']}: not designated"),
        (swap(routed, route="read"), f"{routed['name']}: a read route must record"),
        (swap(designated, route="highlight"), f"{designated['name']}: a route is recorded"),
        (swap(designated, carries="maybe"), f"{designated['name']}: the answer 'maybe'"),
        (swap(designated, projects=[]), f"{designated['name']}: the answer 'yes' does not match"),
        (swap(designated, evidence=""), f"{designated['name']}: no evidence"),
        (swap(tagged, carries="not established"), f"{tagged['name']}: a wheel tag cannot"),
    ):
        found = problems(changed)
        assert any(line.startswith(problem) for line in found), (problem, found)
    # A wheel shown to carry nothing that loses that answer is owed a route it does not have.
    clean = next(w for w in wheels if w["name"] not in labels and w["carries"] == "no")
    unsure = swap(clean, carries="not established", evidence_kind="project metadata")
    assert any(line.startswith(f"{clean['name']}: not designated") for line in problems(unsure))
    assert clean["name"] in _owed_a_route({**survey, "wheels": unsure})
    # The page side: a changed answer, a changed route and a dropped row each show.
    assert _survey_page_drift(page, survey) == []
    for changed in (unsure, swap(routed, route="read"), swap(designated, carries="no")):
        assert _survey_page_drift(page, {**survey, "wheels": changed}), changed
    row = next(
        ln
        for ln in _region(_SURVEY_HEADING, _EXTRA_NAMES, page)
        .partition(_HIGHLIGHTED)[2]
        .splitlines()
        if ln.startswith("| `")
    )
    drift = _survey_page_drift(page.replace(row + "\n", ""), survey)
    assert any(line.startswith("highlighted:") for line in drift), drift
    tracked = component_readings.section_of(page)
    assert component_readings.render_section(data, labels, {**survey, "wheels": unsure}) != tracked


def test_the_generator_reads_a_component_from_fake_replies() -> None:
    """RED when: the generator misreads PyPI or OSV, double-counts an aliased advisory, or keeps
    a record whose GitHub twin is withdrawn.

    Fake replies in the APIs' shapes, so this needs no network. The OSV reply carries one flaw twice
    (a GHSA and its PYSEC twin), a withdrawn record, a PYSEC record rated only by a CVSS 3 vector,
    and a PYSEC record whose GHSA twin the package query did not return because it is withdrawn.
    """
    as_of = dt.date(2026, 1, 1)

    def upload(day: str, yanked: bool = False) -> list[dict[str, Any]]:
        return [{"upload_time_iso_8601": f"{day}T00:00:00Z", "yanked": yanked}]

    replies: dict[str, Any] = {
        "https://pypi.org/pypi/demo/json": {
            "info": {
                "version": "2.0",
                "classifiers": ["Development Status :: 7 - Inactive", "Topic :: Other"],
                "requires_python": ">=3.9",
            },
            "releases": {"1.0": upload("2020-01-01", True), "2.0": upload("2023-06-01")},
        },
        "https://pypi.org/simple/demo/": {"project-status": {"status": "active"}},
    }
    osv = [
        {"id": "GHSA-aaaa", "aliases": ["CVE-1"], "published": "2025-02-01T00:00:00Z",
         "database_specific": {"severity": "HIGH"}},
        {"id": "PYSEC-1", "aliases": ["CVE-1"], "published": "2025-01-01T00:00:00Z"},
        {"id": "GHSA-gone", "published": "2025-01-01T00:00:00Z", "withdrawn": "2025-02-01",
         "database_specific": {"severity": "CRITICAL"}},
        {"id": "PYSEC-2", "aliases": ["CVE-2"], "published": "2025-03-01T00:00:00Z",
         "severity": [{"type": "CVSS_V3",
                       "score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H"}]},
        {"id": "PYSEC-3", "aliases": ["GHSA-twin"], "published": "2025-04-01T00:00:00Z"},
        # Names one withdrawn GHSA (a duplicate) and one live one: it must survive.
        {"id": "PYSEC-4", "aliases": ["GHSA-dupe", "GHSA-live"], "published": "2025-05-01T00:00:00Z"},
        # The query DID return its withdrawn GHSA twin: it must still go.
        {"id": "PYSEC-5", "aliases": ["GHSA-gone"], "published": "2025-06-01T00:00:00Z"},
        # Names a GHSA that OSV does not have: it counts, and is listed as unresolved.
        {"id": "PYSEC-6", "aliases": ["GHSA-lost"], "published": "2025-07-01T00:00:00Z"},
        # The fastapi shape: its own GHSA is withdrawn, the live one is about another package.
        {"id": "PYSEC-7", "aliases": ["GHSA-mine", "GHSA-other"], "published": "2025-08-01T00:00:00Z"},
    ]  # fmt: skip
    for ghsa, withdrawn, package in (
        ("GHSA-twin", True, "demo"),
        ("GHSA-dupe", True, "demo"),
        ("GHSA-live", False, "demo"),
        ("GHSA-mine", True, "demo"),
        ("GHSA-other", False, "another-package"),
    ):
        replies[component_readings.OSV_VULN.format(id=ghsa)] = {
            "id": ghsa,
            "affected": [{"package": {"name": package, "ecosystem": "PyPI"}}],
            **({"withdrawn": "2025-04-02T00:00:00Z"} if withdrawn else {}),
        }

    def fetch(url: str, body: bytes | None) -> Any:
        if url == component_readings.OSV_QUERY:
            assert body is not None
            return {"vulns": [osv[3]] if "version" in json.loads(body) else osv}
        if url not in replies:
            raise urllib.error.HTTPError(url, 404, "Not Found", Message(), None)
        return replies[url]

    reading = component_readings.read_component(
        "demo", "1.0", added_by=["harness"], as_of=as_of, fetch=fetch
    )
    assert reading["added_by"] == ["harness"]
    assert reading["newest_upload"] == "2023-06-01"
    assert reading["pinned_yanked"] is True
    assert reading["development_status"] == ["Development Status :: 7 - Inactive"]
    assert reading["advisories"] == [
        {"id": "GHSA-aaaa", "severity": "HIGH", "rated_by": "github", "published": "2025-01-01"},
        {"id": "PYSEC-2", "severity": "HIGH", "rated_by": "cvss3", "published": "2025-03-01"},
        {"id": "PYSEC-4", "severity": "UNRATED", "rated_by": "none", "published": "2025-05-01"},
        {"id": "PYSEC-6", "severity": "UNRATED", "rated_by": "none", "published": "2025-07-01"},
    ]
    assert reading["advisories_dropped"] == [
        {"id": "PYSEC-3", "twin": "GHSA-twin"},
        {"id": "PYSEC-5", "twin": "GHSA-gone"},
        {"id": "PYSEC-7", "twin": "GHSA-mine"},
    ]
    assert reading["advisories_unresolved"] == [{"id": "PYSEC-6", "twin": "GHSA-lost"}]
    assert reading["advisories_affecting_pin"] == ["PYSEC-2"]
    assert reading["risky"] == {"maintenance": True, "support": True, "advisory_history": True}


def test_a_fully_yanked_project_is_read_not_refused() -> None:
    """RED when: a project with every release yanked, and its pin gone, stops the run.

    Those are what the maintenance and support examples exist to catch, so they must come out as
    readings, not as an error that leaves the whole snapshot unwritten.
    """
    as_of = dt.date(2026, 1, 1)
    replies: dict[str, Any] = {
        "https://pypi.org/pypi/gone/json": {
            "info": {"version": "1.0", "classifiers": []},
            "releases": {"1.0": [{"upload_time_iso_8601": "2025-01-01T00:00:00Z", "yanked": True}]},
        },
        "https://pypi.org/simple/gone/": {"project-status": {"status": "quarantined"}},
    }

    def fetch(url: str, body: bytes | None) -> Any:
        return {} if url == component_readings.OSV_QUERY else replies[url]

    reading = component_readings.read_component(
        "gone", "0.9", added_by=[], as_of=as_of, fetch=fetch
    )
    assert reading["newest_upload"] is None and reading["pinned_yanked"] is True
    assert reading["risky"] == {"maintenance": True, "support": True, "advisory_history": False}


def test_rendered_prose_never_opens_a_line_like_a_list_item() -> None:
    """RED when: wrapping leaves a continuation line that CommonMark would read as a list item."""
    words = " ".join(["word"] * 17) + " counts: 1. On support: 0. More words follow here."
    for width in range(30, 101):
        text = "x" * (100 - width) + " " + words
        for line in component_readings._wrap(text).splitlines()[1:]:
            assert not component_readings._BLOCK_START.match(line), (width, line)


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        # The two in-window records the first cut of the generator left unrated, scored by hand.
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H", 7.2),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
        # FIRST's own reference points: unchanged and changed scope at the top of the scale.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", None),
        ("CVSS:3.1/AV:N/AC:L", None),
    ],
)
def test_the_cvss3_scorer_matches_the_specification(vector: str, score: float | None) -> None:
    """RED when: the CVSS 3 base score drifts from the FIRST formula, or scores a non-3.x vector.

    A record rated only by its vector reaches the vulnerability-history verdict through this.
    """
    assert component_readings.cvss3_score(vector) == score

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The risky-component designation must stay closed over the runtime closure (BACKLOG #1189).

ASVS 15.1.4 asks that application documentation highlight third-party libraries considered risky
components. ``docs/RISKY-COMPONENTS.md`` is that highlight, and a highlight is only worth reading
while it is complete over a stated denominator.

The denominator is ``security/runtime-closure-core.txt``: the core runtime closure, no extras, no dev
toolchain. It is a tracked file because that set is not recoverable from any other tracked artifact
-- ``requirements.lock`` is an ``--all-extras`` export carrying the dev toolchain, and
``pyproject.toml`` names only the direct dependencies.

**The property under test is CLOSURE, not correctness of judgement.** Whether ``pyyaml`` belongs in
tier 1 is an argument for a reviewer. Whether it appears in exactly one of the two tables is a fact,
and a dependency bump that adds a package nobody classified is exactly the drift this catches.

Each test names the mutation that must turn it RED.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_DOC = _ROOT / "docs" / "RISKY-COMPONENTS.md"
_CLOSURE = _ROOT / "security" / "runtime-closure-core.txt"
_LOCK = _ROOT / "requirements.lock"

#: A distribution named in a markdown table cell as `name`. The designation tables put the
#: distribution in the FIRST cell of each row, so anchoring on the row start keeps prose mentions of
#: a package elsewhere on the page from being read as a classification.
_ROW_NAME = re.compile(r"^\|\s*`([a-z0-9][a-z0-9._-]*)`", re.MULTILINE)

#: A row whose first cell packs several comma-separated names (the typing shims share one reason).
_ROW_NAME_GROUP = re.compile(
    r"^\|\s*((?:`[a-z0-9][a-z0-9._-]*`,\s*)+`[a-z0-9][a-z0-9._-]*`)\s*\|", re.MULTILINE
)


def _closure() -> set[str]:
    """Distribution names in the tracked core runtime closure."""
    names: set[str] = set()
    for line in _CLOSURE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "==" not in line:
            continue
        names.add(line.partition("==")[0].strip().lower())
    return names


def _designated_and_excluded() -> tuple[set[str], set[str]]:
    """The names the document classifies, split at the not-designated heading."""
    text = _DOC.read_text(encoding="utf-8")
    # Start at the first tier heading, NOT the top of the page. The scope table above it has rows
    # whose first cell is a backticked filename, and reading those as designations is a parser bug
    # that inflates the count -- it caught `requirements.lock` on the first run of this guard.
    start = "## Tier 1"
    assert start in text, f"{_DOC.name} no longer has a tier 1 heading"
    text = text.partition(start)[2]
    marker = "## Assessed and NOT designated"
    assert marker in text, f"{_DOC.name} no longer has the not-designated section"
    head, _, tail = text.partition(marker)
    # The closing sections after the table must not contribute names.
    tail = tail.partition("## What this page is not")[0]

    def names(block: str) -> set[str]:
        out = {m.group(1).lower() for m in _ROW_NAME.finditer(block)}
        for m in _ROW_NAME_GROUP.finditer(block):
            out |= {n.strip(" `").lower() for n in m.group(1).split(",")}
        return out

    return names(head), names(tail)


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
    assert "hl7" in closure and "cryptography" in closure, (
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

    The page states "Twenty-six of forty-one" and "26 plus 15 is 41". Those are load-bearing: a
    reader uses them to check the set is closed without counting rows. A figure that drifts from its
    own tables is worse than no figure, because it invites the reader to stop checking.
    """
    designated, excluded = _designated_and_excluded()
    text = _DOC.read_text(encoding="utf-8")

    assert f"{len(designated)} plus {len(excluded)} is {len(designated) + len(excluded)}" in text, (
        f"the page's arithmetic sentence does not match its tables: designated={len(designated)}, "
        f"not designated={len(excluded)}, total={len(designated) + len(excluded)}"
    )
    assert len(designated) + len(excluded) == len(_closure()), (
        "the two tables do not sum to the closure size"
    )


def test_every_closure_member_is_pinned_in_the_lock() -> None:
    """RED when: the closure file drifts from the hash-locked dependency set.

    A cross-check against the OTHER tracked artifact, so the closure file cannot quietly become
    fiction. requirements.lock is a superset (it is an --all-extras export), so containment is the
    only relation that holds -- asserting equality here would be wrong and would fail forever.
    """
    lock_names = {
        line.partition("==")[0].strip().lower()
        for line in _LOCK.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith((" ", "#")) and "==" in line
    }
    assert len(lock_names) > len(_closure()), (
        "requirements.lock parsed to no more names than the core closure; it is an --all-extras "
        "export and must be a strict superset, so the parser has broken"
    )
    orphans = sorted(_closure() - lock_names)
    assert not orphans, (
        f"{len(orphans)} name(s) in the core closure are absent from requirements.lock: {orphans}"
    )


@pytest.mark.parametrize("path", [_DOC, _CLOSURE])
def test_the_tracked_paths_exist(path: Path) -> None:
    """RED when: either half of the pair is deleted or moved.

    The guard is worthless if it silently stops finding what it grades, and a missing-file error
    reads very differently from a passing suite.
    """
    assert path.is_file(), f"{path} is missing; the designation guard cannot run"

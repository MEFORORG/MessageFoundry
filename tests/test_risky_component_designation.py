# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The risky-component designation must stay closed over the runtime closure (BACKLOG #1189).

ASVS 15.1.4 asks that application documentation highlight third-party libraries considered risky
components. ``docs/RISKY-COMPONENTS.md`` is that highlight, and a highlight is only worth reading
while it is complete over a stated denominator.

The denominator is ``security/runtime-closure-core.txt``: the core runtime closure, no extras, no dev
toolchain. It is a copy of the pin lines in a DEP-1 lock; its own header says which one, and how to
regenerate it. Tests below hold the copy to that lock in name and version (BACKLOG #1812).

**The property under test is CLOSURE, not correctness of judgement.** Whether ``pyyaml`` belongs in
tier 1 is an argument for a reviewer. Whether it appears in exactly one of the two tables is a fact,
and a dependency bump that adds a package nobody classified is exactly the drift this catches.

Each test names the mutation that must turn it RED.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest
from packaging.utils import canonicalize_name

_ROOT = Path(__file__).resolve().parent.parent
_DOC = _ROOT / "docs" / "RISKY-COMPONENTS.md"
_CLOSURE = _ROOT / "security" / "runtime-closure-core.txt"
_LOCK = _ROOT / "requirements.lock"
#: The lock the closure file copies. The closure file's header says what it is.
_CORE_LOCK = _ROOT / "docker" / "locks" / "requirements-core.lock"

#: A distribution named in a markdown table cell as `name`. The designation tables put the
#: distribution in the FIRST cell of each row, so anchoring on the row start keeps prose mentions of
#: a package elsewhere on the page from being read as a classification.
_ROW_NAME = re.compile(r"^\|\s*`([a-z0-9][a-z0-9._-]*)`", re.MULTILINE)

#: A row whose first cell packs several comma-separated names (the typing shims share one reason).
_ROW_NAME_GROUP = re.compile(
    r"^\|\s*((?:`[a-z0-9][a-z0-9._-]*`,\s*)+`[a-z0-9][a-z0-9._-]*`)\s*\|", re.MULTILINE
)


def _closure_lines() -> list[str]:
    """The closure file's pin lines, stripped, in file order. Comments and blanks are skipped."""
    return [
        s
        for s in (raw.strip() for raw in _CLOSURE.read_text(encoding="utf-8").splitlines())
        if s and not s.startswith("#")
    ]


def _closure_pins() -> dict[str, str]:
    """Name to version for every pin in the tracked core runtime closure.

    A name listed twice fails here. A dict keeps only the last line, so a stale first line would
    stay in the file for a reader to find while every comparison passed.
    """
    pins: dict[str, str] = {}
    for line in _closure_lines():
        if "==" not in line:
            continue
        name, _, version = line.partition("==")
        key = canonicalize_name(name.strip())
        assert key not in pins, f"{_CLOSURE.name} lists {key} twice"
        pins[key] = version.strip()
    return pins


def _closure() -> set[str]:
    """Distribution names in the tracked core runtime closure."""
    return set(_closure_pins())


def _lock_versions(path: Path, *, strict: bool = False) -> dict[str, list[str]]:
    """Name to every version an exported lock pins for it, in file order.

    A pin line reads ``name==version ; marker \\`` and the hash lines under it are indented. A list,
    because an export writes one line per marker fork. Each caller decides which names must be
    unambiguous, so a fork in a package it never reads is not its failure.

    With ``strict``, a top-level line that is not an ``==`` pin fails. A URL or ``===`` requirement
    would otherwise vanish from the parsed set, and so from the denominator, with nothing reporting it.
    """
    pins: dict[str, list[str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith((" ", "#")):
            continue
        if "==" not in line or "===" in line:
            assert not strict, f"{path.name} has a requirement this parser cannot read: {line!r}"
            continue
        name, _, rest = line.partition("==")
        version = re.split(r"[\s;\\]", rest.strip(), maxsplit=1)[0]
        pins.setdefault(canonicalize_name(name.strip()), []).append(version)
    return pins


def _core_lock_pins() -> dict[str, str]:
    """Name to version for the core closure, read from the DEP-1 core lock (BACKLOG #1812)."""
    pins: dict[str, str] = {}
    for name, versions in _lock_versions(_CORE_LOCK, strict=True).items():
        assert len(set(versions)) == 1, (
            f"{_CORE_LOCK.name} pins {name} at {versions}, a per-platform fork. The closure file "
            "records one version per name, so it cannot say which one a default install takes."
        )
        pins[name] = versions[0]
    return pins


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


def _expected_closure_lines(core: dict[str, str]) -> list[str]:
    """The closure file's pin lines as the core lock says they must read: sorted ``name==version``."""
    return [f"{name}=={version}" for name, version in sorted(core.items())]


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
        # The same PEP 503 form the closure side uses, so `ruamel.yaml` in a table row matches
        # `ruamel-yaml` in the lock.
        out: set[str] = {canonicalize_name(m.group(1)) for m in _ROW_NAME.finditer(block)}
        for m in _ROW_NAME_GROUP.finditer(block):
            out |= {canonicalize_name(n.strip(" `")) for n in m.group(1).split(",")}
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
    # The scope section's denominator counts. The requirements.lock row drifted from 100 to 101
    # with nothing reporting it, which is why these are pinned too.
    closure_size = len(_closure())
    assert f"That is **{closure_size} distributions**" in text, (
        f"the scope section does not state the closure size, {closure_size}"
    )
    lock_size = len(_lock_versions(_LOCK))
    assert f"| `requirements.lock` | {lock_size} |" in text, (
        f"the denominator table's requirements.lock row does not say {lock_size}"
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
    # One transitive (cffi, via cryptography) and one reached only through an extra a core
    # dependency requests (uvloop, via uvicorn[standard]).
    assert {"hl7", "cryptography", "cffi", "uvloop"} <= pins.keys(), (
        f"{_CORE_LOCK.name} misses a known transitive or extra-requested core package"
    )


def test_the_closure_file_is_the_core_lock() -> None:
    """RED when: the closure file stops matching the core lock, in any name, version or line.

    This is the regeneration gate (BACKLOG #1812). The closure file is a copy of the pin lines in
    the core lock, and a copy with no check drifts silently. The designation tests above only see
    what someone remembered to add here. A dependency PR once wrote fourteen bumps into this file
    and not into the lock. The inventory then showed ``anyio`` at a release with no advisories. The
    lock installed one carrying three.

    The whole line list is compared, so a duplicate, an unsorted line or a stray format also fails.
    To fix it, run this module as a script, which rewrites the pin lines from the lock.
    """
    core = _core_lock_pins()
    drift = _diff_pins(_CORE_LOCK.name, _closure_pins(), core)
    expected = _expected_closure_lines(core)
    assert not drift and _closure_lines() == expected, (
        f"security/runtime-closure-core.txt does not match {_CORE_LOCK.name}. The lock is what "
        "installs; never edit it to match this file. Differences:\n  "
        + ("\n  ".join(drift) or "none by name or version; the lines are unsorted or malformed")
        + "\nRegenerate with: python tests/test_risky_component_designation.py"
    )


def test_every_closure_pin_is_the_version_requirements_lock_installs() -> None:
    """RED when: requirements.lock installs a different version of a closure package.

    requirements.lock is the file pip-audit audits and the install guides tell an operator to use.
    It is a superset (an --all-extras export), so only the closure's own names are compared, and a
    lock-only name is expected.

    Both locks are exports of uv.lock, so this fails only when one of them is stale. The DEP-1 gate
    catches that too, but in another workflow; this check holds the closure file to the audited lock
    on the same test run. The fix is to re-export both locks, then regenerate the closure file.
    """
    lock = _lock_versions(_LOCK)
    closure = _closure_pins()
    assert len(lock) > len(closure), (
        "requirements.lock parsed to no more names than the core closure; it is an --all-extras "
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


@pytest.mark.parametrize("path", [_DOC, _CLOSURE, _CORE_LOCK])
def test_the_tracked_paths_exist(path: Path) -> None:
    """RED when: any file the guard grades or grades against is deleted or moved.

    The guard is worthless if it silently stops finding what it grades, and a missing-file error
    reads very differently from a passing suite.
    """
    assert path.is_file(), f"{path} is missing; the designation guard cannot run"


def _rewrite_closure() -> int:
    """Replace the closure file's pin lines with the core lock's.

    Keeps the leading comment block and drops everything after it, so a comment placed between
    pins is lost. The file's contract is header, then pins.
    """
    header: list[str] = []
    for raw in _CLOSURE.read_text(encoding="utf-8").splitlines():
        if raw.strip() and not raw.lstrip().startswith("#"):
            break
        header.append(raw)
    lines = _expected_closure_lines(_core_lock_pins())
    _CLOSURE.write_bytes(("\n".join([*header, *lines]) + "\n").encode("utf-8"))
    print(f"wrote {len(lines)} pins to {_CLOSURE.relative_to(_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(_rewrite_closure())

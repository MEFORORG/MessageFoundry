# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The risky-component designation must stay closed over the runtime closure (BACKLOG #1189).

ASVS 15.1.4 asks that application documentation highlight third-party libraries considered risky
components. ``docs/RISKY-COMPONENTS.md`` is that highlight, and a highlight is only worth reading
while it is complete over a stated denominator.

The denominator is ``security/runtime-closure-core.txt``: the core runtime closure, no extras, no dev
toolchain. It is a copy of the pin lines in a DEP-1 lock; its own header says which one, and how to
regenerate it. Tests below hold the copy to that lock in name and version (BACKLOG #1812).

The page also assesses one extra, ``sqlserver``, in its own section (BACKLOG #1955). That section's
denominator is ``security/runtime-closure-sqlserver.txt``, built and held the same way, and it
classifies only the names that closure adds to the core one.

**The property under test is CLOSURE, not correctness of judgement.** Whether ``pyyaml`` belongs in
tier 1 is an argument for a reviewer. Whether it appears in exactly one of the two tables is a fact,
and a dependency bump that adds a package nobody classified is exactly the drift this catches.

Each test names the mutation that must turn it RED.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from packaging.utils import canonicalize_name

from scripts.security import runtime_closure

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
#: Each closure file and its lock, in the order the regenerator rewrites them.
_PAIRS = ((_CLOSURE, _CORE_LOCK), (_SQLSERVER_CLOSURE, _SQLSERVER_LOCK))

#: The headings that bound the page's two classified regions. The core tables run from the tier 1
#: heading to the sqlserver heading; the sqlserver tables from there to the closing sections.
_CORE_START = "## Tier 1 — hostile input"
_CORE_SPLIT = "## Assessed and NOT designated"
_SQLSERVER_START = "## The `sqlserver` extra"
_SQLSERVER_SPLIT = "### Assessed and NOT designated"
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

    A name listed twice fails here. A dict keeps only the last line, so a stale first line would
    stay in the file for a reader to find while every comparison passed.
    """
    pins: dict[str, str] = {}
    for line in _closure_lines(path):
        if "==" not in line:
            continue
        name, _, version = line.partition("==")
        key = runtime_closure.canonical_name(name)
        assert key not in pins, f"{path.name} lists {key} twice"
        pins[key] = version.strip()
    return pins


def _closure() -> set[str]:
    """Distribution names in the tracked core runtime closure."""
    return set(_closure_pins())


def _sqlserver_additions() -> set[str]:
    """The names the ``sqlserver`` closure adds to the core one: what its section must classify."""
    return set(_closure_pins(_SQLSERVER_CLOSURE)) - _closure()


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

    Each heading must be present as a whole line, once, and in that order, or the region is not the
    one meant. Whole lines, because ``## Assessed and NOT designated`` is a substring of the
    sqlserver section's ``### Assessed and NOT designated``.
    """
    text = "\n" + _DOC.read_text(encoding="utf-8")
    lines = [f"\n{h}\n" for h in (start, split, end)]
    for line in lines:
        assert text.count(line) == 1, f"{_DOC.name} must carry {line.strip()!r} once"
    assert text.index(lines[0]) < text.index(lines[1]) < text.index(lines[2]), (
        f"{_DOC.name} must order {start!r}, {split!r}, {end!r}"
    )
    head, _, tail = _region(start, end).partition(lines[1])
    # The not-designated table ends at the next heading of any level, so a later subsection's
    # table is not read as more exclusions.
    return _table_names(head), _table_names(tail.partition("\n#")[0])


def _region(start: str, end: str) -> str:
    """The page text between two whole-line headings, each given without its newlines."""
    text = "\n" + _DOC.read_text(encoding="utf-8")
    return text.partition(f"\n{start}\n")[2].partition(f"\n{end}\n")[0]


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
    return _classified(_SQLSERVER_START, _SQLSERVER_SPLIT, _END)


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
    # The scope section's closure size, derived from the closure file, which the gate below holds
    # equal to the core lock. It changes only when a core package arrives or leaves, which needs a
    # designation edit on this page anyway. There is deliberately no requirements.lock count: it
    # moved with every dev or extra dependency, so any Dependabot PR could red it.
    closure_size = len(_closure())
    assert f"That is **{closure_size} distributions**" in text, (
        f"the scope section does not state the closure size, {closure_size}"
    )


def test_the_sqlserver_closure_is_the_core_closure_plus_the_extra() -> None:
    """RED when: the sqlserver closure stops being a superset of the core one, or adds nothing.

    THE POSITIVE CONTROL FOR THE SQLSERVER SECTION (BACKLOG #1955). That section classifies only the
    names this closure adds, so an empty difference would make every test of it pass vacuously. A
    core package at a different version here would mean one of the two exports is stale.
    """
    core = _closure_pins()
    sqlserver = _closure_pins(_SQLSERVER_CLOSURE)
    lost = sorted(core.keys() - sqlserver.keys())
    assert not lost, f"core packages missing from {_SQLSERVER_CLOSURE.name}: {lost}"
    moved = sorted(n for n in core if sqlserver[n] != core[n])
    assert not moved, f"core packages at another version in {_SQLSERVER_CLOSURE.name}: {moved}"
    assert "pyodbc" in _sqlserver_additions(), (
        f"{_SQLSERVER_CLOSURE.name} adds no pyodbc to the core closure; the extra's own native "
        "driver binding is missing, so the file or its parser is wrong"
    )


def test_the_sqlserver_section_classifies_exactly_what_the_extra_adds() -> None:
    """RED when: the extra gains a package nobody classified, or the section names a stray one.

    The core tests above cannot see this: they read only the core closure, and a package the extra
    alone brings is outside it. Names the core tables already classify are not repeated here.
    """
    additions = _sqlserver_additions()
    designated, excluded = _sqlserver_designated_and_excluded()
    classified = designated | excluded
    missing = sorted(additions - classified)
    assert not missing, (
        f"the sqlserver extra adds {missing} and {_DOC.name}'s sqlserver section classifies "
        "none of them. Add each to its designated or not-designated table."
    )
    stray = sorted(classified - additions)
    assert not stray, (
        f"{_DOC.name}'s sqlserver section classifies {stray}, which the extra does not add to "
        "the core closure. Either they left the extra, or they are core and belong above."
    )
    both = sorted(designated & excluded)
    assert not both, f"classified twice in the sqlserver section: {both}"


def test_the_sqlserver_counts_printed_on_the_page_are_the_real_ones() -> None:
    """RED when: the sqlserver section's arithmetic, or a closure size the page states, drifts.

    Each figure is looked for where it belongs: the sum in the sqlserver section, the sizes in the
    scope section above the tiers. So a stray copy elsewhere on the page cannot satisfy it.
    """
    designated, excluded = _sqlserver_designated_and_excluded()
    added = len(designated) + len(excluded)
    assert added == len(_sqlserver_additions()), "the sqlserver tables do not sum to the additions"
    core = len(_closure())
    total = len(_closure_pins(_SQLSERVER_CLOSURE))
    section = _region(_SQLSERVER_START, _END)
    sentence = (
        f"{len(designated)} plus {len(excluded)} is {added}, and {core} plus {added} is {total}"
    )
    assert sentence in section, f"the sqlserver section does not say {sentence!r}"
    scope = _region("## Scope, and the denominator", "## The criterion")
    assert scope, "the scope section's headings moved; this test reads between them"
    for fact in (
        f"closure is **{total} distributions**",
        f"| **Core runtime closure** | **{core}** |",
        f"| **`sqlserver` runtime closure** | **{total}** |",
    ):
        assert fact in scope, f"the scope section does not say {fact!r}"


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


@pytest.mark.parametrize("path", [_CLOSURE, _SQLSERVER_CLOSURE], ids=lambda p: p.name)
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


@pytest.mark.parametrize("path", [_CLOSURE, _SQLSERVER_CLOSURE], ids=lambda p: p.name)
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
    "path", [_DOC, _CLOSURE, _CORE_LOCK, _SQLSERVER_CLOSURE, _SQLSERVER_LOCK], ids=lambda p: p.name
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


def test_the_regenerator_rewrites_a_drifted_sqlserver_closure(tmp_path: Path) -> None:
    """RED when: the regenerator cannot repair the sqlserver pair, or drops a name the extra adds.

    The same script-mode run as above, on the second pair. The drift removes ``pyodbc``, the name
    the core lock does not carry, so a rewrite that read the core lock by mistake would not restore
    it and this fails.
    """
    text = _SQLSERVER_CLOSURE.read_text(encoding="utf-8")
    wrong = text.replace("\npyodbc==", "\npyodbc-gone==", 1)
    assert wrong != text, "the sqlserver closure no longer pins pyodbc; pick another package here"
    closure = tmp_path / "closure.txt"
    closure.write_text(wrong, encoding="utf-8")
    script = Path(runtime_closure.__file__)
    run = subprocess.run(
        [sys.executable, "-S", "-E", "-s", str(script), "--closure", str(closure)]
        + ["--lock", str(_SQLSERVER_LOCK)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0, run.stderr
    assert closure.read_text(encoding="utf-8") == text

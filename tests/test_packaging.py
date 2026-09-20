# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Packaging guards.

A consumer's config repo (its mypy/IDE) type-checks against the engine's public surface ONLY if the
engine ships a PEP 561 ``py.typed`` marker. The marker must live in the *installed* package; hatchling
ships every file under ``messagefoundry/`` (see the comment in pyproject.toml), so the empty
``messagefoundry/py.typed`` rides along with no build-config change. Asserting its presence via
``importlib.resources`` — the same guard the password corpus uses — means a build-config change that
dropped it fails the suite, not just a release dry-run.

The build backend pin (BACKLOG #1546) is the second guard. PEP 517 build isolation installs whatever
``[build-system].requires`` names, fresh, on every build, and release.yml runs those builds inside the
jobs that publish. Nothing in PR CI executes release.yml, so a pin that loosens would first be seen
at a tag. Pure text checks, no network.

Shipped-content integrity (BACKLOG #1702) is the third. Every distribution this repo builds carried a
nested ``CLAUDE.md`` -- maintainer process text, not product -- out to whoever installed it, and neither
the sdist allowlist nor release.yml's leak grep objected, because both ask whether a member sits inside
the package tree and the instructions file does. Build config plus the git index, no build and no
network: the third guard shells out to ``git ls-files``, which the first two do not.

The .gitignore/force-include contradiction (BACKLOG #1835) is the fourth, and it is the one the
third cannot reach. ``_tracked`` below models the wheel from ``git ls-files``, so an IGNORED file inside
a force-included tree is invisible to it by construction, while ``recurse_forced_files`` walks the
filesystem and ships it anyway. That guard reads .gitignore text against the force-include map, needs
no build, and is the cheap half of a question whose expensive half is listing a built artifact.

"""

from __future__ import annotations

import functools
import re
import subprocess
import tomllib
from importlib.resources import files
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parents[1]

#: A name, `==`, and one literal version, with nothing after it. A range, a wildcard, a second clause
#: or a marker all let two builds of the same tag resolve different backends.
_EXACT_PIN = re.compile(r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[0-9][0-9A-Za-z.+!-]*)")


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _unpinned(requires: list[str]) -> list[str]:
    return [req for req in requires if _EXACT_PIN.fullmatch(req.strip()) is None]


def _build_pyprojects() -> list[Path]:
    """The engine at the root plus every ``packaging/<dist>/`` project, discovered rather than listed
    so a new distribution is covered the day it lands."""
    return [_REPO / "pyproject.toml", *sorted(_REPO.glob("packaging/*/pyproject.toml"))]


def test_py_typed_marker_ships_in_the_package() -> None:
    marker = files("messagefoundry").joinpath("py.typed")
    assert marker.is_file(), (
        "messagefoundry/py.typed is missing from the installed package — external mypy won't see the "
        "engine as typed (PEP 561). It must sit next to messagefoundry/__init__.py and ship in the wheel."
    )


# --- BACKLOG #1702: no distribution may ship this repository's own Claude Code instructions -------
#
# A nested CLAUDE.md is maintainer process text. Measured on be51821227170b583bc26885ab1a86d80ee0e9c0,
# before the fix: the engine wheel carried `messagefoundry/CLAUDE.md` among 305 members, the engine
# sdist among 306, and the harness wheel carried `harness/CLAUDE.md` among 101. The console wheel
# happened to be clean only because `messagefoundry_webconsole/` has no such file yet.
#
# The two distributions need DIFFERENT fixes, for a reason recorded once, where somebody would act on
# it: above the wheel target in packaging/messagefoundry-harness/pyproject.toml.

#: The nested instructions file. One exact basename, not a characterisation of the class: it is the
#: only such file this repository ships, and a wider pattern would start excluding product files.
_INSTRUCTIONS_FILE = "CLAUDE.md"

#: The harness distribution's project directory -- its `force-include` sources are written relative
#: to this, which is why resolving needs it.
_HARNESS_PROJECT = _REPO / "packaging" / "messagefoundry-harness"


@functools.cache
def _tracked(*prefixes: str) -> frozenset[str]:
    """Repo-relative POSIX paths git tracks under any of ``prefixes``.

    The tracked tree, not a filesystem walk: a walk picks up whatever a local run left behind, and the
    question here is what a CLEAN checkout hands the build. The residual that choice accepts:
    ``recurse_forced_files`` walks the FILESYSTEM and consults no .gitignore, so a gitignored file
    inside a whole-mapped directory does reach a wheel built on the machine that has it. That is a
    pre-existing property of any whole-directory mapping, not something this model can see.

    Cached because it is a subprocess, called once per force-including distribution and again by the
    per-distribution tests. Nothing here writes to the index mid-run.
    """
    out = subprocess.run(
        ["git", "-C", str(_REPO), "ls-files", "-z", "--", *prefixes],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return frozenset(p for p in out.split("\0") if p)


def _hatch_build(pyproject: Path) -> dict[str, Any]:
    """The ``[tool.hatch.build]`` table, or an empty one."""
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    build: dict[str, Any] = data.get("tool", {}).get("hatch", {}).get("build", {})
    return build


def _wheel_force_include(pyproject: Path) -> dict[str, str]:
    """The map that reaches the WHEEL, resolved the way hatchling resolves it.

    ``BuilderConfig.force_include`` reads the TARGET table when it carries the key and otherwise falls
    back to the global ``[tool.hatch.build]`` one. Reading only the target table would skip a
    distribution that used the global spelling -- the natural choice when one map should serve two
    targets -- and skipping is silent.
    """
    build = _hatch_build(pyproject)
    target: dict[str, str] = build.get("targets", {}).get("wheel", {}).get("force-include", {})
    fallback: dict[str, str] = build.get("force-include", {})
    return target or fallback


def _repo_relative(pyproject: Path, source: str) -> str:
    """A ``force-include`` source as a repo-relative POSIX path.

    Sources are written relative to the PROJECT directory (``../../harness/load``) and the build reads
    them from there, so resolving against that directory is the only faithful reading. Both the ship
    emulator and the rename check go through here: two spellings of this rule could drift apart, and
    then the rename check would be validating a mapping the emulator never used.
    """
    resolved = (pyproject.parent / source).resolve()
    try:
        return resolved.relative_to(_REPO).as_posix()
    except ValueError:  # hatchling accepts an absolute or `~` source; this model does not.
        raise AssertionError(
            f"{pyproject.relative_to(_REPO).as_posix()} force-includes {source!r}, which resolves to "
            f"{resolved} -- outside the repository. Map only paths inside the checkout, or these "
            f"guards cannot model what the wheel would carry."
        ) from None


def _force_include_sources(pyproject: Path) -> frozenset[str]:
    """The repo-relative paths a ``force-include`` map pulls from."""
    return frozenset(
        _repo_relative(pyproject, source) for source in _wheel_force_include(pyproject)
    )


def _shipped_by(sources: frozenset[str], tracked: frozenset[str]) -> frozenset[str]:
    """The tracked files a ``force-include`` map ships, by hatchling's own rule.

    ``recurse_forced_files`` yields a named FILE outright and walks a named DIRECTORY whole. Nothing
    else filters it, which is the property this whole section exists because of.
    """
    return frozenset(
        path
        for path in tracked
        if path in sources or any(path.startswith(f"{src}/") for src in sources)
    )


def test_no_packaged_wheel_force_includes_the_repository_instructions() -> None:
    """Generic over ``packaging/*``, so the next distribution is covered the day it lands.

    Mutation: restore ``force-include = {"../../harness" = "harness"}``. Red: named below, because the
    whole-directory source then sweeps in ``harness/CLAUDE.md``.
    """
    # Reuses this module's own discovery, minus the engine at the root: the engine has no wheel
    # force-include (its package tree is WALKED, not mapped), and a second glob here would be a second
    # definition of which distributions exist, free to drift from the one above.
    pyprojects = [p for p in _build_pyprojects() if p.parent != _REPO]
    assert len(pyprojects) >= 2, f"the packaging discovery matched {pyprojects} -- it broke"

    problems: list[str] = []
    seen = 0
    mapped = 0
    for pyproject in pyprojects:
        sources = _force_include_sources(pyproject)
        if not sources:
            # A distribution whose package sits inside its own project directory needs no force-include,
            # and demanding one would red it for the wrong reason. It is then covered the engine's way,
            # by `exclude`, which does reach an ordinary package tree.
            continue
        mapped += 1
        shipped = _shipped_by(sources, _tracked(*{source.split("/")[0] for source in sources}))
        # POSITIVE CONTROL, per distribution: the emulator must actually find files in this tree, or
        # its silence about CLAUDE.md means nothing.
        assert shipped, f"{pyproject.relative_to(_REPO).as_posix()} ships zero tracked files"
        seen += len(shipped)
        problems.extend(p for p in sorted(shipped) if Path(p).name == _INSTRUCTIONS_FILE)

    assert not problems, (
        f"packaged wheels force-include this repository's own Claude Code instructions: {problems}. "
        f"`exclude` does NOT reach a force-included file in hatchling -- enumerate the force-include "
        f"map instead, the way packaging/messagefoundry-harness/pyproject.toml does."
    )
    # Liveness, both halves: at least the harness and the console still arrive by force-include, and
    # the emulator still sees a real tree through each. They contribute 96 and 38 shipped files (the
    # harness tracks 97, one of which is the CLAUDE.md the map now omits), so a floor well under 134
    # catches a glob or a resolve that quietly stopped matching without pinning a number that moves.
    assert mapped >= 2, f"only {mapped} distribution(s) force-include anything -- the parse broke"
    assert seen >= 100, f"the scan across all distributions saw only {seen} shipped files"


def test_the_harness_wheel_ships_every_harness_file_but_its_instructions() -> None:
    """The standing per-new-file tax of the enumerated map, made loud rather than silent.

    Mutation: delete any ``"../../harness/<x>"`` line from the harness wheel target. Red: names ``<x>``.
    """
    tracked = _tracked("harness")
    assert len(tracked) >= 50, (
        f"git tracks only {len(tracked)} files under harness/ -- the read broke"
    )
    assert f"harness/{_INSTRUCTIONS_FILE}" in tracked, (
        "harness/CLAUDE.md is no longer tracked, so this test proves nothing about excluding it"
    )

    shipped = _shipped_by(_force_include_sources(_HARNESS_PROJECT / "pyproject.toml"), tracked)
    # By BASENAME at any depth, not the one top-level path. The root CLAUDE.md invites a nested
    # CLAUDE.md in a subpackage, and harness/load/ is still mapped whole; pinning the top-level path
    # here would put this test in direct contradiction with the one above the day such a file lands,
    # with no build-config change able to green both.
    expected = {path for path in tracked if Path(path).name != _INSTRUCTIONS_FILE}

    missing = sorted(expected - shipped)
    assert not missing, (
        f"the harness wheel would not ship these tracked files: {missing}. Add each to "
        f"[tool.hatch.build.targets.wheel.force-include] in packaging/messagefoundry-harness/"
        f"pyproject.toml. harness/load/profile.py resolves its profiles by path at run time, so a "
        f"dropped .toml there breaks `messagefoundry-harness list-profiles` for an installed user."
    )


def test_no_force_include_entry_outlives_the_file_it_names() -> None:
    """The other half of the tax, and the one that fails at the TAG rather than here.

    hatchling does not filter a force-include source for existence -- ``recurse_forced_files`` raises
    ``FileNotFoundError: Forced include not found: <path>`` outright. Nothing in PR CI runs a build, so
    deleting ``harness/scenarios.py`` without editing the map goes green the whole way to
    ``release-harness``, which then fails mid-release. The whole-directory map this replaced could not
    fail that way, so the enumeration introduced it and this assertion is what pays for it.

    Tracked rather than merely present on disk: a source pointing at a local artifact would build here
    and not on a clean checkout.

    Mutation: delete ``harness/window.py`` (leaving its map entry). Red: names the entry.
    """
    stale: list[str] = []
    checked = 0
    for pyproject in [p for p in _build_pyprojects() if p.parent != _REPO]:
        sources = _force_include_sources(pyproject)
        if not sources:
            continue
        tracked = _tracked(*{source.split("/")[0] for source in sources})
        for source in sorted(sources):
            checked += 1
            if source in tracked or any(path.startswith(f"{source}/") for path in tracked):
                continue
            stale.append(f"{pyproject.relative_to(_REPO).as_posix()} -> {source}")

    assert checked >= 15, f"only {checked} force-include sources were checked -- the parse broke"
    assert not stale, (
        f"these force-include sources name nothing git tracks: {stale}. hatchling raises "
        f"FileNotFoundError on the first one at build time, so this would first be seen inside the "
        f"release job. Remove the entry, or restore the path it names."
    )


def test_the_harness_force_include_maps_every_source_to_its_own_path() -> None:
    """A rename in the map would ship a module at the wrong import path, and nothing else would notice.

    Enumerating turned one mapping into nineteen, and each one is a chance to mistype the target. The
    invariant is that the wheel mirrors the tree: ``../../harness/<x>`` lands at ``harness/<x>``.
    """
    pyproject = _HARNESS_PROJECT / "pyproject.toml"
    include = _wheel_force_include(pyproject)
    assert len(include) >= 10, (
        f"the harness force-include map has {len(include)} entries -- too few"
    )
    wrong = {
        source: target
        for source, target in include.items()
        if _repo_relative(pyproject, source) != target
    }
    assert not wrong, f"these force-include entries rename what they ship: {wrong}"


def test_the_engine_excludes_its_nested_instructions_from_every_build_target() -> None:
    """The engine half, which `exclude` DOES reach -- both its targets run files through `include_path`.

    Two ways this goes wrong quietly, and both are asserted. The pattern must be SLASHLESS, for the
    gitignore-semantics reason and the measurement recorded beside it in pyproject.toml. And no TARGET
    may declare an ``exclude`` of its own without the pattern: ``BuilderConfig.exclude_spec`` checks the
    target table FIRST and reads ``exclude`` from there alone, so hatchling REPLACES the global list
    rather than merging it -- an ordinary ``exclude = ["*.pyc"]`` added to the sdist target would drop
    this exclusion entirely and republish the file.

    Reads the config rather than a built artifact, deliberately: building here would put the
    ``hatchling==1.32.0`` pin in a fourth place, while the test below already asserts every
    ``[build-system]`` table agrees on it. The artifact-level check belongs at release time.

    Mutation: change the pattern to ``/CLAUDE.md``, empty the list, or add
    ``exclude = ["*.pyc"]`` to ``[tool.hatch.build.targets.sdist]``.
    """
    build = _hatch_build(_REPO / "pyproject.toml")
    excluded: list[str] = build.get("exclude", [])
    assert _INSTRUCTIONS_FILE in excluded, (
        f"[tool.hatch.build].exclude in the root pyproject.toml must carry the bare "
        f"{_INSTRUCTIONS_FILE!r}; it carries {excluded}. Without it the engine wheel and sdist both "
        f"publish messagefoundry/CLAUDE.md, which the sdist allowlist and release.yml's "
        f"`^messagefoundry/` leak grep both pass because it sits inside the package tree."
    )
    targets: dict[str, Any] = build.get("targets", {})
    assert targets, "the root pyproject declares no build targets -- the parse broke"
    overriding = {
        name: table["exclude"]
        for name, table in targets.items()
        if isinstance(table, dict)
        and "exclude" in table
        and _INSTRUCTIONS_FILE not in table["exclude"]
    }
    assert not overriding, (
        f"these build targets declare their own `exclude`, which REPLACES the global one rather than "
        f"adding to it, so {_INSTRUCTIONS_FILE!r} is no longer filtered for them: {overriding}. Repeat "
        f"the pattern in each such list, or move the target's patterns up into [tool.hatch.build]."
    )
    # Liveness: the exclusion must still have something to exclude. Any depth under the package, so a
    # move WITHIN messagefoundry/ does not red this -- only the file disappearing does, and then the
    # right answer really is to drop the pattern or repoint it.
    guarded = sorted(p for p in _tracked("messagefoundry") if Path(p).name == _INSTRUCTIONS_FILE)
    assert guarded, (
        f"no {_INSTRUCTIONS_FILE} is tracked under messagefoundry/, so this exclusion now guards "
        f"nothing -- drop it or repoint it"
    )


def test_the_pin_check_refuses_the_shapes_it_exists_to_refuse() -> None:
    # The bare name is what every table carried before #1546. The rest are the near-misses a later
    # edit might reach for. A check never seen to fire proves nothing by passing.
    for loose in (
        "hatchling",
        "hatchling>=1.32.0",
        "hatchling~=1.32.0",
        "hatchling==1.*",
        "hatchling==1.32.0,<2",
        'hatchling==1.32.0; python_version >= "3.14"',
    ):
        assert _unpinned([loose]) == [loose], loose
    assert _unpinned(["hatchling==1.32.0"]) == []


def test_every_build_system_pins_its_backend_exactly_and_they_agree() -> None:
    pyprojects = _build_pyprojects()
    # A floor, so an empty glob cannot pass vacuously: the engine, the web console and the harness.
    assert len(pyprojects) >= 3, [p.as_posix() for p in pyprojects]

    tables: dict[str, list[str]] = {}
    for path in pyprojects:
        label = path.relative_to(_REPO).as_posix()
        build_system = tomllib.loads(path.read_text(encoding="utf-8"))["build-system"]
        requires: list[str] = build_system["requires"]
        loose = _unpinned(requires)
        assert not loose, (
            f"{label} [build-system].requires is not pinned exactly: {loose}. Pin each entry with `==` "
            "to one release. Unpinned, PEP 517 build isolation installs whatever PyPI serves at build "
            "time, inside release.yml's publishing jobs (BACKLOG #1546)."
        )
        pinned = {
            _normalise(m.group("name")) for req in requires if (m := _EXACT_PIN.fullmatch(req))
        }
        backend = _normalise(build_system["build-backend"].split(".")[0])
        assert backend in pinned, (
            f"{label} builds with {build_system['build-backend']!r} but does not pin {backend!r}, so "
            "the backend that actually runs is still resolved fresh."
        )
        tables[label] = sorted(req.strip() for req in requires)

    assert len({tuple(reqs) for reqs in tables.values()}) == 1, (
        f"the [build-system] tables disagree: {tables}. The release builds all of them from one tag, "
        "so bump them together."
    )


# --- BACKLOG #1835: .gitignore must not name a path a wheel force-include ships -------------------
#
# The section above asks which TRACKED files a map ships. This one asks a question the tracked tree
# cannot answer at all. git is asked what to TRACK; hatchling's force-include is asked what to SHIP,
# and `recurse_forced_files` answers it by walking the FILESYSTEM. So a file git is told to ignore,
# sitting inside a force-included tree, reaches the wheel of whoever holds it -- and `_tracked` above
# cannot see it, which its own docstring records as this model's residual.
#
# Measured 2026-09-19 at 444c15d68 with the two profiles .gitignore then named planted on disk: the
# harness wheel listed 103 members carrying both, and 102 still carrying both when built against
# #1702's enumerated map, because `harness/load` is still mapped whole. Release CI checks out fresh,
# so no published wheel has carried them; a build on the machine that holds them does.
#
# WHAT THIS GUARD DOES NOT SEE, said plainly rather than left for someone to discover: only ANCHORED
# LITERAL entries. A glob (`*.local.toml`), an unanchored basename (`scratch.toml`, which git matches
# at any depth), a rule in a nested .gitignore, and a path excluded through .git/info/exclude or a
# global core.excludesFile all slip past it. Catching those needs a gate that lists the BUILT
# artifact. BACKLOG #1832 built that mechanism for release.yml, but its denylist is maintainer-
# instruction basenames, so it would NOT catch a leaked .toml -- do not read it as covering this.
# This is the cheap half: it runs in PR CI, needs no build, and refuses the shape that has happened.

#: Characters that make a .gitignore line a pattern rather than a path. `\` is deliberately absent:
#: it is gitignore's escape character, not a wildcard, and no rule in this repo uses one.
_GITIGNORE_GLOB_CHARS = frozenset("*?[]")


def _force_include_roots() -> dict[str, str]:
    """Every wheel force-include SOURCE: repo-relative POSIX path -> the project that declares it.

    Built on ``_build_pyprojects`` and ``_force_include_sources`` rather than a second glob and a
    second resolver. Those already define which distributions exist and how a source resolves, and a
    second spelling of either would be free to drift from the one the ship emulator above uses -- at
    which point this guard would be checking a map no build ever reads. The root project is dropped
    because its package tree is WALKED, not mapped, so it declares no wheel force-include.
    """
    roots: dict[str, str] = {}
    for pyproject in (p for p in _build_pyprojects() if p.parent != _REPO):
        label = pyproject.relative_to(_REPO).as_posix()
        for source in _force_include_sources(pyproject):
            roots[source] = label
    return roots


def _anchored_literal_ignores(text: str) -> list[tuple[int, str]]:
    """``(line number, repo-relative path)`` for each root-anchored, glob-free .gitignore entry.

    Negations are dropped: ``!x`` UN-ignores, so it cannot create the contradiction this guard looks
    for. Everything else that is not a plain anchored path is dropped too -- the limits are recorded
    above the constants rather than left to be rediscovered.
    """
    out: list[tuple[int, str]] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if not line.startswith("/"):
            continue
        if _GITIGNORE_GLOB_CHARS & set(line):
            continue
        path = line.strip("/")
        if not path:
            continue
        out.append((number, path))
    return out


def test_the_gitignore_parser_reads_the_shapes_this_guard_depends_on() -> None:
    """A parser that silently matched nothing would make the guard below pass forever.

    The first two lines are the exact text #1835 removed from .gitignore. The rest are shapes the
    parser must NOT return, each for its own reason.
    """
    parsed = _anchored_literal_ignores(
        "\n".join(
            [
                "/harness/load/profiles/hospital-baseline.toml",
                "/harness/load/profiles/soak-12h.toml",
                "# /harness/load/profiles/commented-out.toml",
                "",
                "!/harness/load/profiles/unignored.toml",
                "harness/load/profiles/unanchored.toml",
                "/harness/load/profiles/*.local.toml",
                "/docs/marketing/",
            ]
        )
    )
    assert parsed == [
        (1, "harness/load/profiles/hospital-baseline.toml"),
        (2, "harness/load/profiles/soak-12h.toml"),
        (8, "docs/marketing"),
    ], parsed


def test_no_gitignore_entry_names_a_path_inside_a_force_included_tree() -> None:
    """The guard itself.

    Mutation: re-add ``/harness/load/profiles/hospital-baseline.toml`` to .gitignore. Red: names the
    line, the path, and the distribution that would ship it.

    Both directions are contradictions and both are reported. An entry INSIDE a source is the shape
    #1835 hit. An entry that is a PARENT of one (``/harness/``) would leave the whole mapped tree
    untracked while the map still shipped whatever sat there.
    """
    roots = _force_include_roots()
    # POSITIVE CONTROL: the harness and the web console both arrive by force-include, so an empty or
    # broken pyproject parse cannot read as a clean result.
    assert len(roots) >= 2, f"only found force-include roots {roots}: the pyproject parse broke"

    entries = _anchored_literal_ignores((_REPO / ".gitignore").read_text(encoding="utf-8"))
    # POSITIVE CONTROL, the other half: .gitignore really does carry anchored literal entries. 22 of
    # them once #1835 removed its two; a floor well under that catches a parser which stopped matching
    # without pinning a count that moves on every ordinary edit.
    assert len(entries) >= 15, f"the .gitignore parse returned only {len(entries)} entries"

    problems: list[str] = []
    for number, path in entries:
        for root, label in sorted(roots.items()):
            if path == root or path.startswith(f"{root}/") or root.startswith(f"{path}/"):
                problems.append(f".gitignore:{number} '/{path}' vs {label} force-include '{root}'")

    assert not problems, (
        f"these .gitignore entries name paths a wheel force-include ships, so git skips the file and "
        f"the wheel carries it anyway: {problems}. hatchling walks the filesystem for a force-included "
        f"source and reads no .gitignore, and `exclude` does not reach one either (BACKLOG #1702). Move "
        f"the file OUT of the mapped tree (migration-local/ is this repo's ignored tree for "
        f"site-specific material) rather than ignoring it where the build can still see it."
    )

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

The .gitignore/force-include contradiction (BACKLOG #1833) is the third. ``.gitignore`` is not a
packaging control, and nothing used to say so: two operator-local load profiles were ignored by name
under ``harness/load/profiles/``, a directory the harness wheel force-includes, and hatchling's
``recurse_forced_files`` walks the FILESYSTEM without consulting .gitignore or any include/exclude
option. Measured 2026-09-19 at 444c15d68 with both files planted on disk: the harness wheel listed
103 members carrying both, and 102 still carrying both when built against the enumerated map from
BACKLOG #1702. Release CI checks out fresh, so no published wheel has ever carried them; a build on
the machine that holds them does.
"""

from __future__ import annotations

import re
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


# --- BACKLOG #1833: .gitignore must not name a path a wheel force-include ships -------------------
#
# The two mechanisms answer different questions and nothing reconciled them. git is asked what to
# TRACK; hatchling's force-include is asked what to SHIP, and `recurse_forced_files` (hatchling
# 1.32.0, hatchling/builders/plugin/interface.py) answers it by walking the filesystem, filtered only
# by hatchling's own EXCLUDED_FILES/EXCLUDED_DIRECTORIES. It never calls `include_path`, so `exclude`,
# `include` and `only-include` are all inert over a force-included file (measured under #1702). An
# ignored file inside a force-included tree therefore reaches the wheel of whoever holds it, and every
# instrument that models a distribution from `git ls-files` is blind to it BY CONSTRUCTION.
#
# WHAT THIS GUARD DOES NOT SEE, said plainly rather than left for someone to discover: only ANCHORED
# LITERAL entries. A glob (`*.local.toml`), an unanchored basename (`scratch.toml`, which git matches
# at any depth), a rule in a nested .gitignore, and a path excluded through .git/info/exclude or a
# global core.excludesFile all slip past it. Catching those needs a gate that lists the BUILT
# artifact, which is the release-time member gate's job. This is the cheap half: it runs in PR CI,
# needs no build, and refuses the one shape that has actually happened here.

#: Characters that make a .gitignore line a pattern rather than a path. `\` is deliberately absent:
#: it is gitignore's escape character, not a wildcard, and no rule in this repo uses one.
_GITIGNORE_GLOB_CHARS = frozenset("*?[]")


def _wheel_force_include_map(pyproject: Path) -> dict[str, str]:
    """The force-include map that reaches the WHEEL, resolved the way hatchling resolves it.

    ``BuilderConfig.force_include`` reads the TARGET table when it carries the key and otherwise falls
    back to the global ``[tool.hatch.build]`` one. Reading only the target table would silently skip a
    distribution that used the global spelling, which is the natural choice when one map should serve
    two targets.
    """
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    build: dict[str, Any] = data.get("tool", {}).get("hatch", {}).get("build", {})
    target: dict[str, str] = build.get("targets", {}).get("wheel", {}).get("force-include", {})
    fallback: dict[str, str] = build.get("force-include", {})
    return target or fallback


def _force_include_roots() -> dict[str, str]:
    """Every wheel force-include SOURCE in the repo: repo-relative POSIX path -> the project declaring it.

    Sources are written relative to the PROJECT directory (``../../harness``) and hatchling reads them
    from there, so resolving against that directory is the only faithful reading. A source resolving
    outside the checkout raises rather than being skipped: skipping would make this guard quietly stop
    covering that distribution.
    """
    roots: dict[str, str] = {}
    for pyproject in sorted(_REPO.glob("packaging/*/pyproject.toml")):
        label = pyproject.relative_to(_REPO).as_posix()
        for source in _wheel_force_include_map(pyproject):
            resolved = (pyproject.parent / source).resolve()
            try:
                roots[resolved.relative_to(_REPO).as_posix()] = label
            except ValueError:
                raise AssertionError(
                    f"{label} force-includes {source!r}, which resolves to {resolved}, outside the "
                    f"repository. Map only paths inside the checkout, or this guard cannot tell what "
                    f"the wheel would carry."
                ) from None
    return roots


def _anchored_literal_ignores(text: str) -> list[tuple[int, str]]:
    """``(line number, repo-relative path)`` for each root-anchored, glob-free .gitignore entry.

    Negations are dropped: ``!x`` UN-ignores, so it cannot create the contradiction this guard looks
    for. Everything else that is not a plain anchored path is dropped too — the limits are recorded
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

    The first two lines are the exact text #1833 removed from .gitignore. The rest are shapes the
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
    #1833 hit. An entry that is a PARENT of one (``/harness/``) would leave the whole mapped tree
    untracked while the map still shipped whatever sat there.
    """
    roots = _force_include_roots()
    # POSITIVE CONTROL: the harness and the web console both arrive by force-include, so an empty or
    # broken pyproject parse cannot read as a clean result.
    assert len(roots) >= 2, f"only found force-include roots {roots}: the pyproject parse broke"

    entries = _anchored_literal_ignores((_REPO / ".gitignore").read_text(encoding="utf-8"))
    # POSITIVE CONTROL, the other half: .gitignore really does carry anchored literal entries. 22 of
    # them once #1833 removed its two; a floor well under that catches a parser which stopped matching
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
        f"site-specific material) "
        f"rather than ignoring it where the build can still see it (BACKLOG #1833)."
    )

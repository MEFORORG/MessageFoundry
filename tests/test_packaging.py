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
"""

from __future__ import annotations

import re
import tomllib
from importlib.resources import files
from pathlib import Path

from packaging.requirements import Requirement

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


# --- the harness pins the engine it ships with (BACKLOG #1585) --------------------------------------

_HARNESS_PYPROJECT = _REPO / "packaging" / "messagefoundry-harness" / "pyproject.toml"


def _version_root(pyproject: Path) -> Path:
    """The module whose ``__version__`` a hatchling project takes its version from.

    READ FROM ``[tool.hatch.version].path``, NOT HARDCODED -- but note what that buys and what it
    does not. The caller below asserts the answer IS the engine's ``__init__.py``, so repointing the
    version root does not silently move this check, it fails it. That is the intent: the lockstep pin
    rests on the root being the engine's, so the premise moving must stop the test rather than let it
    carry on asserting about whatever file the config now names.
    """
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    return (pyproject.parent / data["tool"]["hatch"]["version"]["path"]).resolve()


def _version_literal(module: Path) -> str:
    # Both quote styles. scripts/security/sbom_finalize.py reads this same literal with the looser
    # pattern, and a check stricter than its sibling misses a version the sibling happily ships.
    m = re.search(
        r"""^__version__\s*=\s*["']([^"']+)["']""", module.read_text(encoding="utf-8"), re.M
    )
    assert m, f"no `__version__ = ...` literal in {module} - hatchling reads one from it"
    return m.group(1)


def _engine_requirement(dependencies: list[str]) -> Requirement | None:
    """The parsed requirement on ``messagefoundry``, or ``None`` if the table declares none.

    Returns the REQUIREMENT rather than just its version so the extras check below reads off the same
    parse instead of re-finding it; the two asked the same question twice and could disagree.
    """
    for raw in dependencies:
        req = Requirement(raw)
        if _normalise(req.name) == "messagefoundry":
            return req
    return None


def _engine_pin(dependencies: list[str]) -> str | None:
    """The exact version the requirement on ``messagefoundry`` pins, or ``None`` if it pins none.

    ``None`` is every loose shape: a bare name, a floor, a compatible release, a wildcard, a range.
    Each of those lets a resolver pick an engine the harness cannot run against.

    WHY NOT ``_EXACT_PIN`` / ``_unpinned`` ABOVE: that regex answers the same question for
    ``[build-system].requires`` and CANNOT answer it here. Its name character class has no ``[``, so
    ``messagefoundry[harness]==0.3.2`` -- a correctly pinned requirement -- does not match it and
    would read as unpinned. Extras are the difference; ``packaging`` parses them and a regex over a
    PEP 508 string does not. Two predicates in one file, and this note is which is authoritative
    where.
    """
    req = _engine_requirement(dependencies)
    if req is None:
        return None
    specs = list(req.specifier)
    if len(specs) == 1 and specs[0].operator == "==" and "*" not in specs[0].version:
        return specs[0].version
    return None


def test_the_engine_pin_check_refuses_the_shapes_it_exists_to_refuse() -> None:
    # A check never seen to fire proves nothing by passing. The bare name is what this table carried
    # before #1585; the rest are the near-misses a later edit reaches for.
    for loose in (
        "messagefoundry[harness]",
        "messagefoundry[harness]>=0.3.2",
        "messagefoundry[harness]~=0.3.2",
        "messagefoundry[harness]==0.3.*",
        "messagefoundry[harness]>=0.3.2,<0.4",
    ):
        assert _engine_pin([loose]) is None, loose
    assert _engine_pin(["messagefoundry[harness]==0.3.2"]) == "0.3.2"
    # And it must find the requirement among siblings, not only when it stands alone.
    assert _engine_pin(["pytest>=8", "messagefoundry[harness]==0.3.2"]) == "0.3.2"
    assert _engine_pin(["pytest>=8"]) is None
    # The reason this predicate exists rather than reusing _EXACT_PIN: that one cannot see extras.
    assert _unpinned(["messagefoundry[harness]==0.3.2"]) == ["messagefoundry[harness]==0.3.2"]


def test_the_harness_pins_the_engine_at_the_version_it_ships_with() -> None:
    """``messagefoundry-harness`` is a LOCKSTEP distribution, and its dependency must say so.

    Its ``[tool.hatch.version].path`` is the ENGINE's ``__init__.py``, so the harness wheel and the
    engine it depends on carry the same version by construction. A bare ``messagefoundry[harness]``
    did not express "any engine works", it expressed nothing, while the truth available at build time
    was an exact version. harness/monitor.py and harness/scenarios.py import
    ``messagefoundry.apiclient`` at module level, so an engine without it installs cleanly and then
    fails on the operator's first command.

    WHAT THIS DOES NOT ESTABLISH: that a mismatched engine is refused at install time. That needs an
    index carrying an older release and cannot run here. What is checked is the specifier the build
    will emit as ``Requires-Dist``.
    """
    harness = tomllib.loads(_HARNESS_PYPROJECT.read_text(encoding="utf-8"))
    root = _version_root(_HARNESS_PYPROJECT)
    assert root == (_REPO / "messagefoundry" / "__init__.py").resolve(), (
        f"the harness takes its version from {root}, which is not the engine's __init__.py - the "
        f"lockstep premise this pin rests on is gone, so re-derive the pin before trusting it"
    )

    shipped = _version_literal(root)
    pinned = _engine_pin(harness["project"]["dependencies"])
    assert pinned == shipped, (
        f"the harness must pin the engine at the version it ships with (BACKLOG #1585).\n"
        f"  {root.relative_to(_REPO).as_posix()} says: {shipped}\n"
        f"  {_HARNESS_PYPROJECT.relative_to(_REPO).as_posix()} pins: {pinned}\n"
        f"A VERSION BUMP IS TWO EDITS. PEP 621 `dependencies` is static and nothing in this repository "
        f"generates it, so set that table to `messagefoundry[harness]=={shipped}` in the same commit "
        f"that moves __version__."
    )


def test_the_harness_pin_keeps_the_extra_the_harness_actually_needs() -> None:
    """The pin must not quietly drop ``[harness]`` while adding ``==``.

    Dropping it is the easiest way to make this table look stricter and be weaker: the version is
    nailed down, PySide6 stops being installed, and the GUI fails to start on a fresh install while
    every version check in the release still passes.
    """
    deps = tomllib.loads(_HARNESS_PYPROJECT.read_text(encoding="utf-8"))["project"]["dependencies"]
    engine = _engine_requirement(deps)
    assert engine is not None, "the harness declares no requirement on the engine at all"
    assert engine.extras == {"harness"}, (
        f"the harness depends on messagefoundry{sorted(engine.extras)}, not [harness] - the extra "
        f"is what installs PySide6, so the GUI would not start on a fresh install"
    )

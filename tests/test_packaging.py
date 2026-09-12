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

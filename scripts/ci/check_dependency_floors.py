#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Check that each runtime dependency is installed at the floor ``pyproject.toml`` declares.

``.github/workflows/dependency-floors.yml`` installs with uv's ``lowest-direct`` resolution, so its
tests run against the oldest releases the engine claims to support (vault BACKLOG #3055). That run
says something about the floors only if the install really landed on them. A resolver change, an
override left in place after its reason went away, or a dependency that is not installed at all
would each let the tests pass against something else. So this reads every ``[project].dependencies``
entry whose marker applies here and compares the installed version with its ``>=`` bound.

A dependency installed above its floor fails the check unless ``--raised NAME`` names it. The
workflow passes none: a floor that cannot install on this Python is raised in ``pyproject.toml``
instead (vault BACKLOG #3177). A ``--raised`` name that sits at its floor after all fails too, so
an exception goes when its reason does.

USAGE
    python scripts/ci/check_dependency_floors.py [--pyproject PATH] [--raised NAME ...]
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from collections.abc import Callable, Iterable, Sequence
from importlib import metadata
from pathlib import Path

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version

_ROOT = Path(__file__).resolve().parents[2]


#: Specifier operators whose version is a lower bound. ``==X.*`` and ``>X`` name no installable
#: lowest release. ``===`` does name one, but by string equality, so its operand need not parse as
#: a version to compare against. A dependency written only with those reads as having no floor.
_FLOOR_OPERATORS = frozenset({">=", "~=", "=="})


def declared_floors(pyproject: Path) -> dict[str, Version | None]:
    """``{canonical name: floor}`` for each runtime dependency whose marker applies here. The floor
    is ``None`` when no specifier gives one, or the specifiers exclude it (``>=1.0,!=1.0``), so
    :func:`check` can refuse rather than skip it. Two lines for one name combine into one specifier
    set before the floor is read, as a resolver combines them: a bare line adds no bound, and an
    exclusion on one line applies to the floor another line declares."""
    project = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]
    specifiers: dict[str, SpecifierSet] = {}
    for line in project.get("dependencies", []):
        requirement = Requirement(line)
        if requirement.marker is not None and not requirement.marker.evaluate():
            continue
        name = canonicalize_name(requirement.name)
        specifiers[name] = specifiers.get(name, SpecifierSet()) & requirement.specifier
    return {name: _floor(specifier) for name, specifier in specifiers.items()}


def _floor(specifier: SpecifierSet) -> Version | None:
    bounds = [
        Version(s.version)
        for s in specifier
        if s.operator in _FLOOR_OPERATORS and not s.version.endswith(".*")
    ]
    floor = max(bounds) if bounds else None
    if floor is not None and not specifier.contains(floor, prereleases=True):
        return None
    return floor


def _installed(name: str) -> Version | None:
    try:
        return Version(metadata.version(name))
    except metadata.PackageNotFoundError:
        return None


def check(
    floors: dict[str, Version | None],
    raised: Iterable[str],
    installed: Callable[[str], Version | None] = _installed,
) -> tuple[list[str], list[str]]:
    """``(report lines, failures)``. The check passes when ``failures`` is empty."""
    expected_raised = {canonicalize_name(name) for name in raised}
    lines: list[str] = []
    failures: list[str] = [] if floors else ["no runtime dependency declares a floor; nothing read"]
    for name in sorted(floors):
        floor, found = floors[name], installed(name)
        raised_on_purpose = name in expected_raised
        if floor is None:
            failures.append(
                f"{name}: declares no floor this check can read; write it as >=X, "
                "with no other line for this name excluding X"
            )
        elif found is None:
            failures.append(f"{name}: declared >={floor} but not installed")
        elif found < floor:
            failures.append(f"{name}: installed {found}, BELOW the declared floor {floor}")
        elif found == floor:
            if raised_on_purpose:
                failures.append(
                    f"{name}: listed as raised but installed at its floor {floor}; "
                    "drop it from --raised"
                )
            else:
                lines.append(f"{name} {found}: at its floor")
        elif raised_on_purpose:
            lines.append(f"{name} {found}: above its floor {floor}, raised on purpose")
        else:
            failures.append(f"{name}: installed {found}, but the declared floor is {floor}")
    for name in sorted(expected_raised - floors.keys()):
        failures.append(f"{name}: listed as raised but declares no floor that applies here")
    return lines, failures


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--pyproject", type=Path, default=_ROOT / "pyproject.toml")
    parser.add_argument(
        "--raised",
        action="append",
        default=[],
        metavar="NAME",
        help="a dependency deliberately installed above its floor; repeatable",
    )
    args = parser.parse_args(argv)
    lines, failures = check(declared_floors(args.pyproject), args.raised)
    for line in lines:
        print(line)
    for failure in failures:
        print(f"FLOOR NOT MEASURED: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Check that each declared dependency is installed at the floor ``pyproject.toml`` declares.

``.github/workflows/dependency-floors.yml`` installs with uv's ``lowest-direct`` resolution, so its
tests run against the oldest releases the engine claims to support (vault BACKLOG #3055). That run
says something about the floors only if the install really landed on them. A resolver change, an
override left in place after its reason went away, or a dependency that is not installed at all
would each let the tests pass against something else. So this reads every ``[project].dependencies``
entry, and every entry of each extra ``--extra`` names, whose marker applies here, and compares the
installed version with its ``>=`` bound.

The extras read default to ``dev``, the one the workflow installs, so a ``[dev]`` floor the resolver
skips (yanked, no wheel for this Python, or conflicting with another floor) reds the check the same
way a runtime floor does (vault BACKLOG #3177). Naming ``--extra`` reads those extras instead of
``dev``. An extra ``pyproject.toml`` does not declare is refused rather than read as empty.

A dependency installed above its floor fails the check, with no exception list: a floor that cannot
install on this Python is raised in ``pyproject.toml`` instead (vault BACKLOG #3177).

USAGE
    python scripts/ci/check_dependency_floors.py [--pyproject PATH] [--extra NAME ... | --no-extras]
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


#: The extras the workflow installs (``-e ".[dev]"``), read when ``--extra`` is not given.
DEFAULT_EXTRAS = ("dev",)


class UndeclaredExtra(ValueError):
    """An extra was asked for that ``pyproject.toml`` does not declare."""


def declared_floors(pyproject: Path, extras: Iterable[str] = ()) -> dict[str, Version | None]:
    """``{canonical name: floor}`` for each runtime dependency, and each dependency of every extra in
    ``extras``, whose marker applies here. The floor is ``None`` when no specifier gives one, or the
    specifiers exclude it (``>=1.0,!=1.0``), so :func:`check` can refuse rather than skip it. Two
    lines for one name combine into one specifier set before the floor is read, as a resolver
    combines them, whether they are runtime lines, extra lines or one of each: a bare line adds no
    bound, and an exclusion on one line applies to the floor another line declares.

    A line naming the project itself (``messagefoundry[harness]`` in ``[dev]``) is no dependency
    with a floor: the extras it names are read too, as an installer would install them. Each line
    applies when its marker holds for any extra read, or for none, as an installer evaluates the
    project's metadata against every extra it was asked for.

    Raises :class:`UndeclaredExtra` for an extra ``pyproject.toml`` does not declare, so a misspelt
    or removed extra cannot pass as one with nothing to check. Two keys that canonicalize alike
    (``dev`` and ``Dev``) are both read, so neither list's floors go unmeasured."""
    project = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]
    own_name = canonicalize_name(project.get("name", ""))
    declared_extras: dict[str, list[str]] = {}
    for extra, lines in project.get("optional-dependencies", {}).items():
        declared_extras.setdefault(canonicalize_name(extra), []).extend(lines)
    requirements = [Requirement(line) for line in project.get("dependencies", [])]
    read: list[str] = []
    pending = [*extras, *_own_extras(requirements, own_name, "")]
    while pending:
        extra = pending.pop(0)
        key = canonicalize_name(extra)
        if key in read:
            continue
        if key not in declared_extras:
            raise UndeclaredExtra(f"extra {extra!r} is not declared in {pyproject}")
        read.append(key)
        added = [Requirement(line) for line in declared_extras[key]]
        requirements += added
        pending += _own_extras(added, own_name, key)
    environments = [{"extra": extra} for extra in ("", *read)]
    specifiers: dict[str, SpecifierSet] = {}
    for requirement in requirements:
        marker = requirement.marker
        name = canonicalize_name(requirement.name)
        if name == own_name or (
            marker is not None and not any(marker.evaluate(env) for env in environments)
        ):
            continue
        specifiers[name] = specifiers.get(name, SpecifierSet()) & requirement.specifier
    return {name: _floor(specifier) for name, specifier in specifiers.items()}


def _own_extras(requirements: Iterable[Requirement], own_name: str, extra: str) -> list[str]:
    """The extras named by the lines among ``requirements``, read under ``extra``, that point back
    at the project and whose marker applies here."""
    return [
        named
        for requirement in requirements
        if canonicalize_name(requirement.name) == own_name
        and (requirement.marker is None or requirement.marker.evaluate({"extra": extra}))
        for named in sorted(requirement.extras)
    ]


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
    installed: Callable[[str], Version | None] = _installed,
) -> tuple[list[str], list[str]]:
    """``(report lines, failures)``. The check passes when ``failures`` is empty."""
    lines: list[str] = []
    failures: list[str] = [] if floors else ["no dependency declares a floor; nothing read"]
    for name in sorted(floors):
        floor, found = floors[name], installed(name)
        if floor is None:
            failures.append(
                f"{name}: declares no floor this check can read; write it as >=X, "
                "with no specifier for this name excluding X"
            )
        elif found is None:
            failures.append(f"{name}: declared >={floor} but not installed")
        elif found < floor:
            failures.append(f"{name}: installed {found}, BELOW the declared floor {floor}")
        elif found == floor:
            lines.append(f"{name} {found}: at its floor")
        else:
            failures.append(f"{name}: installed {found}, but the declared floor is {floor}")
    return lines, failures


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--pyproject", type=Path, default=_ROOT / "pyproject.toml")
    # Runtime-only is its own flag, never an empty --extra: an unset shell variable expanding to
    # nothing must not narrow the check silently.
    which = parser.add_mutually_exclusive_group()
    which.add_argument(
        "--extra",
        action="append",
        metavar="NAME",
        help=f"an extra whose floors to read; repeatable (default: {', '.join(DEFAULT_EXTRAS)})",
    )
    which.add_argument(
        "--no-extras", action="store_true", help="read the runtime dependencies alone"
    )
    args = parser.parse_args(argv)
    extras = () if args.no_extras else DEFAULT_EXTRAS if args.extra is None else args.extra
    try:
        floors = declared_floors(args.pyproject, extras)
    except UndeclaredExtra as exc:
        print(f"FLOOR NOT MEASURED: {exc}", file=sys.stderr)
        return 1
    lines, failures = check(floors)
    for line in lines:
        print(line)
    for failure in failures:
        print(f"FLOOR NOT MEASURED: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

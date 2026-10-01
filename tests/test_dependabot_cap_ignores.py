# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every upper bound in pyproject.toml has a Dependabot ignore range, or a stated exemption.

Dependabot WIDENS a declared cap instead of respecting it. ``.github/dependabot.yml`` says so, and
says a load-bearing cap must be restated there as an ``ignore`` range "or the cap is decorative".
PR #66 widened ruff's and annotated-types' caps that way, and Dependabot PR 1773 tried to widen
uvicorn's. Until BACKLOG #2505 nothing held the two files together, and three caps had no entry.

THE CONTRACT, both directions:

* Every upper bound in ``[project.dependencies]``, ``[project.optional-dependencies]`` and
  ``[dependency-groups]`` (``<``, ``~=``, ``==``, or an ``==X.*`` wildcard) has a uv-ecosystem
  ``ignore`` entry whose range covers what the cap excludes and leaves open what it allows. Or the
  package is in ``_EXEMPT`` below, with its reason.
* Every uv ``ignore`` entry names a package that pyproject.toml still caps. dependabot.yml says to
  lift a cap and delete its entry in the same PR; this is what makes that rule fail when skipped.
  It is also this test's positive control: a parser that found no caps would red on every real
  entry, so the first test cannot pass vacuously.

AN EXACT ``==`` PIN COVERS THE NEXT MINOR, NOT THE NEXT PATCH. That is the ``sigstore`` entry's
documented scope (``>=4.5.0`` for ``==4.4.0``): it blocks the minor the owner declined and leaves
the patch track open. A pin's entry must not cover the pinned version's patch track.

``test_the_checker_reds_on_a_mutated_config`` is the mutation arm. It breaks a made-up cap and entry
pair added to copies of the real files, never a real one, so lifting a real cap cannot break an arm.
"""

from __future__ import annotations

import copy
import functools
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple

import pytest
import yaml
from packaging.requirements import Requirement
from packaging.specifiers import Specifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version

from tests.test_ci_venv_pinning import EXACT_GROUP_PINS

_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _ROOT / "pyproject.toml"
_DEPENDABOT = _ROOT / ".github" / "dependabot.yml"

#: The exact ``==`` pins in ``[dependency-groups]`` that are deliberately NOT ignored. Each must stay
#: an ``==`` pin in a dependency group. ``sigstore`` is the one exact group pin that IS ignored, by
#: owner ruling; dependabot.yml's sigstore note says why.
_GROUP_PINS = frozenset(EXACT_GROUP_PINS) - {"sigstore"}
_GROUP_PIN_REASON = (
    ".github/dependabot.yml, 'NOT IGNORED, deliberately': ignoring the exact pins in "
    "[dependency-groups] would freeze the hash-pinned CI toolchain"
)

#: Every cap with no ignore entry, by package, with the reason. Read the reason where it points.
_EXEMPT: dict[str, str] = {
    **dict.fromkeys(_GROUP_PINS, _GROUP_PIN_REASON),
    "hvac": "pyproject.toml's comment above the [vault] extra says why hvac's cap is not mirrored",
}


class Cap(NamedTuple):
    """One upper bound: where it sits, and the first version it excludes."""

    package: str
    where: str
    spec: str
    exact_pin: bool
    first_excluded: Version


def _bump(release: tuple[int, ...]) -> Version:
    """Increment the last component of ``release``: (7, 3) -> 7.4, (4,) -> 5."""
    return Version(".".join(str(n) for n in (*release[:-1], release[-1] + 1)))


def _just_below(version: Version) -> Version:
    """A release just under ``version``: 0.50 -> 0.49.999, 4 -> 3.999, 3.1.0 -> 3.0.999."""
    release = list(version.release)
    while release and release[-1] == 0:
        release.pop()
    if not release:
        raise ValueError(f"no release below {version}")
    release[-1] -= 1
    return Version(".".join(str(n) for n in (*release, 999)))


def _cap_of(spec: Specifier) -> Version | None:
    """The first version an upper-bound specifier excludes, or None for a floor or ``!=``."""
    op, raw = spec.operator, spec.version
    if op in (">", ">=", "!="):
        return None
    if op == "<":
        return Version(raw)
    wildcard = op == "==" and raw.endswith(".*")
    if op == "~=" or wildcard:
        release = Version(raw.removesuffix(".*")).release
        return _bump(release if wildcard else release[:-1])
    if op == "==":
        pinned = Version(raw)
        return Version(f"{pinned.major}.{pinned.minor + 1}.0")
    # `<=` and `===` have no use in pyproject.toml today. Model one deliberately when it arrives.
    raise AssertionError(f"unmodelled upper-bound operator {op!r} in {spec}")


def _caps(pyproject: dict[str, Any]) -> list[Cap]:
    """The tightest upper bound of every capped requirement in the three tables uv reads."""
    project = pyproject["project"]
    tables: list[tuple[str, list[Any]]] = [("[project.dependencies]", project["dependencies"])]
    tables += [
        (f"[project.optional-dependencies].{name}", reqs)
        for name, reqs in project.get("optional-dependencies", {}).items()
    ]
    tables += [
        (f"[dependency-groups].{name}", reqs)
        for name, reqs in pyproject.get("dependency-groups", {}).items()
    ]
    caps: list[Cap] = []
    for where, reqs in tables:
        for raw in reqs:
            if not isinstance(raw, str):  # an `{include-group = ...}` table
                continue
            req = Requirement(raw)  # markers parse apart from the specifier, so never read as caps
            bounds = [b for s in req.specifier if (b := _cap_of(s)) is not None]
            if bounds:
                pin = any(
                    s.operator == "==" and not s.version.endswith(".*") for s in req.specifier
                )
                caps.append(Cap(canonicalize_name(req.name), where, str(req), pin, min(bounds)))
    return caps


def _uv_entry(dependabot: dict[str, Any]) -> dict[str, Any]:
    """The one uv-ecosystem update entry for the repository root."""
    uv = [
        u for u in dependabot["updates"] if u["package-ecosystem"] == "uv" and u["directory"] == "/"
    ]
    assert len(uv) == 1, f"expected one uv update entry for '/', found {len(uv)}"
    return uv[0]


def _uv_ignores(dependabot: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """The root uv entry's ignore list, keyed by canonical package name."""
    ignores: dict[str, list[dict[str, Any]]] = {}
    for entry in _uv_entry(dependabot).get("ignore", []):
        ignores.setdefault(canonicalize_name(entry["dependency-name"]), []).append(entry)
    return ignores


def _covers(entries: list[dict[str, Any]], version: Version) -> bool:
    """Whether any entry's `versions` range ignores ``version``. A list of ranges is a union."""
    return any(
        SpecifierSet(rng).contains(version, prereleases=True)
        for entry in entries
        for rng in entry.get("versions", [])
    )


def _violations(pyproject: dict[str, Any], dependabot: dict[str, Any]) -> list[str]:
    caps = _caps(pyproject)
    ignores = _uv_ignores(dependabot)
    problems: list[str] = []

    for cap in caps:
        label = f"{cap.where}: {cap.spec}"
        first = cap.first_excluded
        if cap.package in _EXEMPT:
            if cap.package in _GROUP_PINS and not (
                cap.exact_pin and cap.where.startswith("[dependency-groups]")
            ):
                problems.append(f"{label} is exempt as a group `==` pin, but is not one")
            elif cap.package in ignores:
                problems.append(
                    f"{label} is exempt ({_EXEMPT[cap.package]}) yet has an ignore entry"
                )
            continue
        entries = ignores.get(cap.package)
        if not entries:
            problems.append(
                f"{label} has no uv ignore entry in {_DEPENDABOT.name}; add one with versions "
                f'[">={first.major}.{first.minor}.{first.micro}"], or an exemption with its reason'
            )
            continue
        if any("update-types" in e for e in entries):
            problems.append(
                f"{label}: an `update-types` ignore cannot restate a range; use `versions`"
            )
        if not (_covers(entries, first) and _covers(entries, Version(f"{first.major + 1000}"))):
            problems.append(f"{label}: its ignore range leaves versions from {first} up open")
        allowed = _just_below(first)
        if _covers(entries, allowed):
            problems.append(
                f"{label}: its ignore range also blocks {allowed}, which the cap allows"
            )

    capped = {cap.package for cap in caps}
    for name in sorted(set(ignores) - capped):
        problems.append(
            f"{_DEPENDABOT.name} ignores {name!r}, which pyproject.toml no longer caps; "
            "delete the entry in the PR that lifted the cap"
        )
    for name in sorted(set(_EXEMPT) - capped):
        problems.append(f"exemption for {name!r} names no capped requirement in pyproject.toml")
    return problems


@functools.cache
def _load() -> tuple[dict[str, Any], dict[str, Any]]:
    """Parsed once per run. Callers that mutate must deepcopy first."""
    pyproject = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    dependabot = yaml.safe_load(_DEPENDABOT.read_text(encoding="utf-8"))
    return pyproject, dependabot


def test_every_cap_has_an_ignore_entry_or_a_stated_exemption() -> None:
    """RED when: a pyproject cap has no matching ignore range, or an ignore entry outlives its cap."""
    problems = _violations(*_load())
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize(
    ("spec", "first"),
    [
        ("<0.50", "0.50"),
        ("<4", "4"),
        ("<3.1", "3.1"),
        ("~=7.3.1", "7.4"),
        ("~=7.3", "8"),
        ("==4.4.0", "4.5.0"),
        ("==1.2.*", "1.3"),
        (">=1.0", None),
        ("!=1.2.*", None),
    ],
)
def test_cap_arithmetic(spec: str, first: str | None) -> None:
    assert _cap_of(Specifier(spec)) == (Version(first) if first else None)


@pytest.mark.parametrize(
    ("version", "below"), [("0.50", "0.49.999"), ("4", "3.999"), ("3.1.0", "3.0.999")]
)
def test_just_below(version: str, below: str) -> None:
    assert _just_below(Version(version)) == Version(below)


# A made-up cap and entry pair for each shape the mutation arms break. No real package is named,
# so a legitimate cap lift in pyproject.toml cannot crash an arm.
_FAKE_CAP = "mefor-fake-cap>=1.0,<2.5"
_FAKE_PIN = "mefor-fake-pin==3.2.1"


def _fake_entry(dependabot: dict[str, Any], name: str) -> dict[str, Any]:
    return next(e for e in _uv_entry(dependabot)["ignore"] if e["dependency-name"] == name)


def _fixture() -> tuple[dict[str, Any], dict[str, Any]]:
    """Copies of the real files, plus the two made-up caps with correct entries."""
    pyproject, dependabot = copy.deepcopy(_load())
    pyproject["project"]["dependencies"].append(_FAKE_CAP)
    pyproject.setdefault("dependency-groups", {})["mefor-fake"] = [_FAKE_PIN]
    _uv_entry(dependabot).setdefault("ignore", []).extend(
        [
            {"dependency-name": "mefor-fake-cap", "versions": [">=2.5.0"]},
            {"dependency-name": "mefor-fake-pin", "versions": [">=3.3.0"]},
        ]
    )
    return pyproject, dependabot


def test_the_mutation_fixture_is_clean() -> None:
    """Control: the arms below are discriminating only if the unbroken fixture passes."""
    problems = _violations(*_fixture())
    assert not problems, "\n".join(problems)


_Mutation = Callable[[dict[str, Any], dict[str, Any]], None]


def _drop_entry(_p: dict[str, Any], d: dict[str, Any]) -> None:
    uv = _uv_entry(d)
    uv["ignore"] = [e for e in uv["ignore"] if e["dependency-name"] != "mefor-fake-cap"]


def _set_range(name: str, rng: str) -> _Mutation:
    def mutate(_p: dict[str, Any], d: dict[str, Any]) -> None:
        _fake_entry(d, name)["versions"] = [rng]

    return mutate


def _to_update_types(_p: dict[str, Any], d: dict[str, Any]) -> None:
    entry = _fake_entry(d, "mefor-fake-cap")
    del entry["versions"]
    entry["update-types"] = ["version-update:semver-major"]


def _lift_cap(p: dict[str, Any], _d: dict[str, Any]) -> None:
    deps = p["project"]["dependencies"]
    deps[deps.index(_FAKE_CAP)] = "mefor-fake-cap>=1.0"


def _exempt_unpinned(p: dict[str, Any], _d: dict[str, Any]) -> None:
    """A group-pin exemption whose package stops being an `==` pin."""
    name = sorted(_GROUP_PINS)[0]
    p["project"]["dependencies"].append(f"{name}>=1,<99")


@pytest.mark.parametrize(
    ("mutate", "expect"),
    [
        pytest.param(_drop_entry, "no uv ignore entry", id="entry-deleted"),
        pytest.param(_set_range("mefor-fake-cap", ">=2.6.0"), "open", id="gap-at-cap"),
        pytest.param(_set_range("mefor-fake-cap", ">=2.4.0"), "blocks", id="freezes"),
        pytest.param(_set_range("mefor-fake-pin", ">=3.2.0"), "blocks", id="blocks-pin"),
        pytest.param(_set_range("mefor-fake-pin", ">=4.0.0"), "open", id="pin-gap"),
        pytest.param(_to_update_types, "update-types", id="update-types"),
        pytest.param(_lift_cap, "no longer caps", id="stale-entry"),
        pytest.param(_exempt_unpinned, "but is not one", id="exempt-not-a-pin"),
    ],
)
def test_the_checker_reds_on_a_mutated_config(mutate: _Mutation, expect: str) -> None:
    """Mutation arm: each broken copy must produce a violation naming what broke."""
    pyproject, dependabot = _fixture()
    mutate(pyproject, dependabot)
    problems = _violations(pyproject, dependabot)
    assert any(expect in p for p in problems), f"no violation mentioning {expect!r}: {problems}"

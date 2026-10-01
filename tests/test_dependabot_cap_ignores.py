# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every upper bound in pyproject.toml has a Dependabot ignore range, or a stated exemption.

Dependabot WIDENS a declared cap instead of respecting it. ``.github/dependabot.yml`` says so, and
says a load-bearing cap must be restated there as an ``ignore`` range "or the cap is decorative".
PR #66 widened ruff's and annotated-types' caps that way, and Dependabot PR 1773 tried to widen
uvicorn's. Until BACKLOG #2505 nothing held the two files together, so four caps had no entry.

THE CONTRACT, both directions:

* Every upper bound in ``[project.dependencies]``, ``[project.optional-dependencies]`` and
  ``[dependency-groups]`` (``<``, ``~=``, ``==``, or an ``==X.*`` wildcard) has a uv-ecosystem
  ``ignore`` entry whose range covers what the cap excludes and leaves open what it allows. Or the
  package is in one of the two exemption tables below, with its reason.
* Every uv ``ignore`` entry names a package that pyproject.toml still caps. dependabot.yml says to
  lift a cap and delete its entry in the same PR; this is what makes that rule fail when skipped.

AN EXACT ``==`` PIN COVERS THE NEXT MINOR, NOT THE NEXT PATCH. That is the ``sigstore`` entry's
documented scope (``>=4.5.0`` for ``==4.4.0``): it blocks the minor the owner declined and leaves
the patch track open. A pin's entry must not cover the pinned version itself.

``test_the_checker_reds_on_a_mutated_config`` is the mutation arm. It feeds the checker copies of
the real files with one thing broken, and fails unless each copy is reported.
"""

from __future__ import annotations

import copy
import tomllib
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, NamedTuple

import pytest
import yaml
from packaging.requirements import Requirement
from packaging.specifiers import Specifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version

_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _ROOT / "pyproject.toml"
_DEPENDABOT = _ROOT / ".github" / "dependabot.yml"

#: The exact ``==`` pins in ``[dependency-groups]`` that are deliberately NOT ignored. Each must stay
#: an ``==`` pin in a dependency group; a name here that becomes a cap anywhere else needs its own
#: decision, not this one.
_GROUP_PIN_EXEMPT: frozenset[str] = frozenset(
    {"bandit", "pip-audit", "zizmor", "build", "diff-cover", "mutmut"}
)
_GROUP_PIN_REASON = (
    ".github/dependabot.yml, 'NOT IGNORED, deliberately': ignoring the exact pins in "
    "[dependency-groups] would freeze the hash-pinned CI toolchain, which ADR 0034 section 3 wants "
    "moving through Dependabot"
)

#: Any other cap with no ignore entry, by package, with the reason. Read the reason where it points.
_CAP_EXEMPT: dict[str, str] = {
    "hvac": (
        "pyproject.toml's [vault] extra comment: majors already go to manual review, and an ignore "
        "would suppress hvac's security track for no gain"
    ),
}


class Cap(NamedTuple):
    """One upper bound: where it sits, the first version it excludes, and one version it allows."""

    package: str
    where: str
    spec: str
    exact_pin: bool
    first_excluded: Version
    allowed: Version


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


def _padded(version: Version) -> str:
    """The `>=X.Y.Z` spelling the existing ignore entries use: 3.1 -> 3.1.0."""
    return ".".join(str(n) for n in (*version.release, 0, 0)[: max(3, len(version.release))])


def _cap_of(spec: Specifier) -> tuple[Version, Version] | None:
    """(first excluded, one allowed) for an upper-bound specifier, or None for a floor or ``!=``."""
    op, raw = spec.operator, spec.version
    if op in (">", ">=", "!="):
        return None
    if op == "<":
        first = Version(raw)
        return first, _just_below(first)
    if op == "~=":
        first = _bump(Version(raw).release[:-1])
        return first, _just_below(first)
    if op == "==" and raw.endswith(".*"):
        first = _bump(Version(raw[:-2]).release)
        return first, _just_below(first)
    if op == "==":
        pinned = Version(raw)
        major, minor = (*pinned.release, 0)[:2]
        return Version(f"{major}.{minor + 1}.0"), pinned
    # `<=` and `===` have no use in pyproject.toml today. Model one deliberately when it arrives.
    raise AssertionError(f"unmodelled upper-bound operator {op!r} in {spec}")


def _requirements(pyproject: dict[str, Any]) -> Iterator[tuple[str, str]]:
    """(where, requirement string) for every requirement in the three tables the uv updater reads."""
    project = pyproject["project"]
    for req in project.get("dependencies", []):
        yield "[project.dependencies]", req
    for extra, reqs in project.get("optional-dependencies", {}).items():
        for req in reqs:
            yield f"[project.optional-dependencies].{extra}", req
    for group, reqs in pyproject.get("dependency-groups", {}).items():
        for req in reqs:
            if isinstance(req, str):  # skip `{include-group = ...}` tables
                yield f"[dependency-groups].{group}", req


def _caps(pyproject: dict[str, Any]) -> list[Cap]:
    """The tightest upper bound of every capped requirement. Markers are not specifiers."""
    caps: list[Cap] = []
    for where, raw in _requirements(pyproject):
        req = Requirement(raw)
        bounds = [b for s in req.specifier if (b := _cap_of(s)) is not None]
        if bounds:
            first, allowed = min(bounds)
            pin = any(s.operator == "==" and not s.version.endswith(".*") for s in req.specifier)
            caps.append(Cap(canonicalize_name(req.name), where, str(req), pin, first, allowed))
    return caps


def _uv_ignores(dependabot: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """The root uv entry's ignore list, keyed by canonical package name."""
    uv = [
        u for u in dependabot["updates"] if u["package-ecosystem"] == "uv" and u["directory"] == "/"
    ]
    assert len(uv) == 1, f"expected one uv update entry for '/', found {len(uv)}"
    ignores: dict[str, list[dict[str, Any]]] = {}
    for entry in uv[0].get("ignore", []):
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
        if cap.package in _GROUP_PIN_EXEMPT:
            if not (cap.exact_pin and cap.where.startswith("[dependency-groups]")):
                problems.append(f"{label} is exempt as a group `==` pin, but is not one")
            elif cap.package in ignores:
                problems.append(f"{label} is exempt ({_GROUP_PIN_REASON}) yet has an ignore entry")
            continue
        if cap.package in _CAP_EXEMPT:
            if cap.package in ignores:
                problems.append(
                    f"{label} is exempt ({_CAP_EXEMPT[cap.package]}) yet has an ignore entry"
                )
            continue
        entries = ignores.get(cap.package)
        if not entries:
            problems.append(
                f"{label} has no uv ignore entry in {_DEPENDABOT.name}; add one with "
                f'versions [">={_padded(cap.first_excluded)}"], or an exemption here with its reason'
            )
            continue
        if any("update-types" in e for e in entries):
            problems.append(
                f"{label}: an `update-types` ignore cannot restate a range; use `versions`"
            )
        far = Version(f"{cap.first_excluded.major + 1000}")
        if not (_covers(entries, cap.first_excluded) and _covers(entries, far)):
            problems.append(
                f"{label}: its ignore range leaves versions from {cap.first_excluded} up open"
            )
        if _covers(entries, cap.allowed):
            problems.append(
                f"{label}: its ignore range also blocks {cap.allowed}, which the cap allows"
            )

    capped = {cap.package for cap in caps}
    for name in sorted(set(ignores) - capped):
        problems.append(
            f"{_DEPENDABOT.name} ignores {name!r}, which pyproject.toml no longer caps; "
            "delete the entry in the PR that lifted the cap"
        )
    for name in sorted((_GROUP_PIN_EXEMPT | set(_CAP_EXEMPT)) - capped):
        problems.append(f"exemption for {name!r} names no capped requirement in pyproject.toml")
    return problems


def _load() -> tuple[dict[str, Any], dict[str, Any]]:
    pyproject = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    dependabot = yaml.safe_load(_DEPENDABOT.read_text(encoding="utf-8"))
    return pyproject, dependabot


def test_every_cap_has_an_ignore_entry_or_a_stated_exemption() -> None:
    """RED when: a pyproject cap has no matching ignore range, or an ignore entry outlives its cap."""
    problems = _violations(*_load())
    assert not problems, "\n".join(problems)


def test_the_census_finds_the_known_caps() -> None:
    """Positive control: a parser that found no caps would make the test above pass vacuously."""
    found = {cap.package for cap in _caps(_load()[0])}
    known = {
        "uvicorn",
        "pynetdicom",
        "pydicom",
        "webauthn",
        "hvac",
        "ruff",
        "sigstore",
        "cyclonedx-bom",
    }
    assert known <= found, f"census missed {sorted(known - found)}"
    assert "atheris" not in found, "an environment marker's `==` was read as a version cap"


@pytest.mark.parametrize(
    ("spec", "first", "allowed"),
    [
        ("<0.50", "0.50", "0.49.999"),
        ("<4", "4", "3.999"),
        ("<3.1", "3.1", "3.0.999"),
        ("~=7.3.1", "7.4", "7.3.999"),
        ("~=7.3", "8", "7.999"),
        ("==4.4.0", "4.5.0", "4.4.0"),
        ("==1.2.*", "1.3", "1.2.999"),
    ],
)
def test_cap_arithmetic(spec: str, first: str, allowed: str) -> None:
    assert _cap_of(Specifier(spec)) == (Version(first), Version(allowed))


_Mutation = Callable[[dict[str, Any]], None]


def _drop_ignore(doc: dict[str, Any], name: str) -> None:
    uv = next(u for u in doc["updates"] if u["package-ecosystem"] == "uv")
    uv["ignore"] = [e for e in uv["ignore"] if e["dependency-name"] != name]


def _set_range(doc: dict[str, Any], name: str, rng: str) -> None:
    uv = next(u for u in doc["updates"] if u["package-ecosystem"] == "uv")
    next(e for e in uv["ignore"] if e["dependency-name"] == name)["versions"] = [rng]


def _add_cap(doc: dict[str, Any], req: str) -> None:
    doc["project"]["dependencies"].append(req)


def _lift_cap(doc: dict[str, Any], old: str, new: str) -> None:
    deps = doc["project"]["optional-dependencies"]["dicom"]
    deps[deps.index(old)] = new


@pytest.mark.parametrize(
    ("mutate_pyproject", "mutate_dependabot", "expect"),
    [
        pytest.param(None, lambda d: _drop_ignore(d, "pydicom"), "pydicom", id="entry-deleted"),
        pytest.param(None, lambda d: _set_range(d, "pydicom", ">=3.2.0"), "open", id="gap-at-cap"),
        pytest.param(None, lambda d: _set_range(d, "pydicom", ">=3.0.0"), "blocks", id="freezes"),
        pytest.param(
            None, lambda d: _set_range(d, "sigstore", ">=4.4.0"), "blocks", id="blocks-pin"
        ),
        pytest.param(lambda p: _add_cap(p, "newdep>=1,<2"), None, "newdep", id="new-cap"),
        pytest.param(
            lambda p: _lift_cap(p, "pydicom>=3.0.2,<3.1", "pydicom>=3.0.2"),
            None,
            "no longer caps",
            id="stale-entry",
        ),
    ],
)
def test_the_checker_reds_on_a_mutated_config(
    mutate_pyproject: _Mutation | None, mutate_dependabot: _Mutation | None, expect: str
) -> None:
    """Mutation arm: each broken copy of the real files must produce a violation naming it."""
    pyproject, dependabot = (copy.deepcopy(doc) for doc in _load())
    if mutate_pyproject:
        mutate_pyproject(pyproject)
    if mutate_dependabot:
        mutate_dependabot(dependabot)
    problems = _violations(pyproject, dependabot)
    assert any(expect in p for p in problems), f"no violation mentioning {expect!r}: {problems}"

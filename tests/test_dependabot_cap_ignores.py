# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every upper bound in pyproject.toml has a Dependabot ignore range, or a stated exemption.

Dependabot WIDENS a declared cap instead of respecting it. ``.github/dependabot.yml`` says so, and
says a load-bearing cap must be restated there as an ``ignore`` range "or the cap is decorative".
PR #66 widened ruff's and annotated-types' caps that way, and Dependabot PR 1773 tried to widen
uvicorn's. Until BACKLOG #2505 nothing held the two files together, and three caps had no entry.

THE CONTRACT, both directions:

* Every upper bound in ``[build-system].requires``, ``[project.dependencies]``,
  ``[project.optional-dependencies]`` and ``[dependency-groups]`` (``<``, ``~=``, ``==``, or an
  ``==X.*`` wildcard) has a uv-ecosystem ``ignore`` entry whose range is exactly ``>=`` the first
  version the cap excludes. That is the one range that blocks everything the cap excludes and
  nothing it allows. Or the package is in ``_EXEMPT`` below, with its reason.
* Every uv ``ignore`` entry names a package that pyproject.toml caps. dependabot.yml says to lift a
  cap and delete its entry in the same PR; this is what makes that rule fail when skipped. It is
  also this test's positive control: a parser that found no caps would red on every real entry, so
  the first test cannot pass vacuously.

AN EXACT ``==`` PIN COVERS THE NEXT MINOR, NOT THE NEXT PATCH. That is the ``sigstore`` entry's
documented scope (``>=4.5.0`` for ``==4.4.0``): it blocks the minor the owner declined and leaves
the patch track open. It is the only ignored pin today; a new one takes the same scope or a
deliberate change here.

The mutation arms break a made-up cap and entry pair added to copies of the real files, never a
real one, so lifting a real cap cannot break an arm.
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
from packaging.specifiers import InvalidSpecifier, Specifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version

from tests.test_ci_venv_pinning import EXACT_GROUP_PINS

_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _ROOT / "pyproject.toml"
_DEPENDABOT = _ROOT / ".github" / "dependabot.yml"

#: The exact ``==`` pins in ``[dependency-groups]`` that are deliberately NOT ignored. Each must stay
#: an ``==`` pin in a dependency group. ``sigstore`` is the one exact group pin that IS ignored, by
#: owner ruling; dependabot.yml's sigstore note says why. If that ruling is lifted and its entry
#: deleted, drop sigstore from this subtraction in the same PR.
_GROUP_PINS = frozenset(EXACT_GROUP_PINS) - {"sigstore"}
_GROUP_PIN_REASON = (
    ".github/dependabot.yml, 'NOT IGNORED, deliberately': ignoring the exact pins in "
    "[dependency-groups] would freeze the hash-pinned CI toolchain"
)

#: Every cap with no ignore entry, by package, with the reason. Read the reason where it points.
_EXEMPT: dict[str, str] = {
    **dict.fromkeys(_GROUP_PINS, _GROUP_PIN_REASON),
    "hvac": "pyproject.toml's comment above the [vault] extra says why hvac's cap is not mirrored",
    "hatchling": "pyproject.toml's [build-system] comment expects Dependabot to bump this pin",
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
    """The tightest upper bound of every capped requirement in the tables Dependabot's uv reads."""
    project = pyproject["project"]
    tables: list[tuple[str, list[Any]]] = [
        ("[build-system].requires", pyproject.get("build-system", {}).get("requires", [])),
        ("[project.dependencies]", project.get("dependencies", [])),
    ]
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
        u
        for u in dependabot["updates"]
        if u["package-ecosystem"] == "uv" and u.get("directory") == "/"
    ]
    assert len(uv) == 1, f"expected one uv update entry with `directory: /`, found {len(uv)}"
    return uv[0]


def _uv_ignores(dependabot: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """The root uv entry's ignore list, keyed by canonical package name.

    Extras are dropped first, as dependabot-core's Python name normaliser does, so an entry named
    ``uvicorn[standard]`` matches a ``uvicorn`` cap.
    """
    ignores: dict[str, list[dict[str, Any]]] = {}
    for entry in _uv_entry(dependabot).get("ignore", []):
        name = canonicalize_name(entry["dependency-name"].split("[", 1)[0])
        ignores.setdefault(name, []).append(entry)
    return ignores


def _ranges(entry: dict[str, Any]) -> list[str]:
    versions = entry.get("versions", [])
    return [versions] if isinstance(versions, str) else list(versions)


def _is_exactly_from(rng: str, first: Version) -> bool:
    """Whether ``rng`` is the single specifier ``>=first``."""
    try:
        specs = list(SpecifierSet(rng))
    except InvalidSpecifier:
        return False
    return len(specs) == 1 and specs[0].operator == ">=" and Version(specs[0].version) == first


def _violations(pyproject: dict[str, Any], dependabot: dict[str, Any]) -> list[str]:
    caps = _caps(pyproject)
    ignores = _uv_ignores(dependabot)
    problems: list[str] = []

    for cap in caps:
        label = f"{cap.where}: {cap.spec}"
        first = cap.first_excluded
        want = f">={first.major}.{first.minor}.{first.micro}"
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
                f'{label} has no uv ignore entry in {_DEPENDABOT.name}; add one with versions ["{want}"], '
                f"or an exemption with its reason in {Path(__file__).name}"
            )
            continue
        if any("update-types" in e for e in entries):
            problems.append(
                f"{label}: an `update-types` ignore cannot restate a range; use `versions` only"
            )
        ranges = [rng for e in entries for rng in _ranges(e)]
        if not ranges or not all(_is_exactly_from(rng, first) for rng in ranges):
            problems.append(
                f"{label}: its ignore range must be exactly {want!r}, which blocks what the cap "
                f"excludes and nothing it allows; found {ranges}"
            )

    capped = {cap.package for cap in caps}
    for name in sorted(set(ignores) - capped):
        problems.append(
            f"{_DEPENDABOT.name} ignores {name!r}, which pyproject.toml does not cap. An entry "
            "here restates a cap, so delete it in the PR that lifts the cap, or model the new "
            f"kind of entry in {Path(__file__).name}"
        )
    for name in sorted(set(_EXEMPT) - capped):
        problems.append(f"exemption for {name!r} names no capped requirement in pyproject.toml")
    return problems


@functools.cache
def _load() -> tuple[dict[str, Any], dict[str, Any]]:
    """Parsed once per run. Callers that mutate must deepcopy first, as ``_fixture`` does."""
    pyproject = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    dependabot = yaml.safe_load(_DEPENDABOT.read_text(encoding="utf-8"))
    return pyproject, dependabot


def test_every_cap_has_an_ignore_entry_or_a_stated_exemption() -> None:
    """RED when: a pyproject cap has no exact ignore range, or an ignore entry outlives its cap."""
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


_Mutation = Callable[[dict[str, Any], dict[str, Any]], None]


def _rename_entry(_p: dict[str, Any], d: dict[str, Any]) -> None:
    _fake_entry(d, "mefor-fake-cap")["dependency-name"] = "Mefor_Fake_Cap[extra]"


@pytest.mark.parametrize("mutate", [None, _rename_entry], ids=["unbroken", "extras-and-case"])
def test_the_mutation_fixture_is_clean(mutate: _Mutation | None) -> None:
    """Control: the arms below are discriminating only if the unbroken fixture passes."""
    pyproject, dependabot = _fixture()
    if mutate:
        mutate(pyproject, dependabot)
    problems = _violations(pyproject, dependabot)
    assert not problems, "\n".join(problems)


def _drop_entry(_p: dict[str, Any], d: dict[str, Any]) -> None:
    uv = _uv_entry(d)
    uv["ignore"] = [e for e in uv["ignore"] if e["dependency-name"] != "mefor-fake-cap"]


def _set_versions(name: str, versions: list[str]) -> _Mutation:
    def mutate(_p: dict[str, Any], d: dict[str, Any]) -> None:
        _fake_entry(d, name)["versions"] = versions

    return mutate


def _to_update_types(_p: dict[str, Any], d: dict[str, Any]) -> None:
    entry = _fake_entry(d, "mefor-fake-cap")
    del entry["versions"]
    entry["update-types"] = ["version-update:semver-major"]


def _lift_cap(p: dict[str, Any], _d: dict[str, Any]) -> None:
    deps = p["project"]["dependencies"]
    deps[deps.index(_FAKE_CAP)] = "mefor-fake-cap>=1.0"


_EXACT = "must be exactly"


@pytest.mark.parametrize(
    ("mutate", "expect"),
    [
        pytest.param(_drop_entry, "no uv ignore entry", id="entry-deleted"),
        pytest.param(_set_versions("mefor-fake-cap", [">=2.6.0"]), _EXACT, id="gap-at-cap"),
        pytest.param(_set_versions("mefor-fake-cap", [">=2.4.0"]), _EXACT, id="freezes"),
        pytest.param(
            _set_versions("mefor-fake-cap", ["==2.5.*", ">=3.0.0"]), _EXACT, id="hole-above-cap"
        ),
        pytest.param(
            _set_versions("mefor-fake-cap", [">=1.2.0,<1.4.0", ">=2.5.0"]),
            _EXACT,
            id="blocks-an-allowed-range",
        ),
        pytest.param(_set_versions("mefor-fake-cap", ["2.5.0"]), _EXACT, id="not-a-specifier"),
        pytest.param(_set_versions("mefor-fake-pin", [">=3.2.0"]), _EXACT, id="blocks-pin"),
        pytest.param(_set_versions("mefor-fake-pin", [">=4.0.0"]), _EXACT, id="pin-gap"),
        pytest.param(_to_update_types, "update-types", id="update-types"),
        pytest.param(_lift_cap, "does not cap", id="stale-entry"),
    ],
)
def test_the_checker_reds_on_a_mutated_config(mutate: _Mutation, expect: str) -> None:
    """Mutation arm: each broken copy must produce a violation naming what broke."""
    pyproject, dependabot = _fixture()
    mutate(pyproject, dependabot)
    problems = _violations(pyproject, dependabot)
    assert any(expect in p for p in problems), f"no violation mentioning {expect!r}: {problems}"


@pytest.mark.parametrize(
    ("group_pin", "exempt", "expect"),
    [
        pytest.param(False, "mefor-fake-cap", "yet has an ignore entry", id="exempt-with-entry"),
        pytest.param(False, "mefor-never-capped", "names no capped", id="dead-exemption"),
        pytest.param(True, "mefor-fake-cap", "but is not one", id="group-pin-not-a-pin"),
    ],
)
def test_the_checker_reds_on_a_broken_exemption(
    monkeypatch: pytest.MonkeyPatch, group_pin: bool, exempt: str, expect: str
) -> None:
    """Mutation arm for the exemption table, again over the made-up pair only."""
    monkeypatch.setitem(_EXEMPT, exempt, "test reason")
    if group_pin:
        monkeypatch.setattr(f"{__name__}._GROUP_PINS", _GROUP_PINS | {exempt})
    problems = _violations(*_fixture())
    assert any(expect in p for p in problems), f"no violation mentioning {expect!r}: {problems}"

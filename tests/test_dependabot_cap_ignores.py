# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every pyproject.toml cap below major level has a Dependabot ignore range, or a stated exemption.

Dependabot WIDENS a declared cap instead of respecting it; ``.github/dependabot.yml`` says so above
its uv ``ignore`` list, with the history. Until BACKLOG #2505 nothing held the two files together,
and three caps had no entry.

THE CONTRACT, both directions:

* Every upper bound in ``[build-system].requires``, ``[project.dependencies]``,
  ``[project.optional-dependencies]`` and ``[dependency-groups]`` (``<``, ``~=``, ``==``, or an
  ``==X.*`` wildcard) at MINOR level or lower has a uv-ecosystem ``ignore`` entry whose range is
  exactly ``>=`` the version ``_cap_of`` derives. Or the package is in ``_EXEMPT`` below, in the
  table it names, with its reason.
* A MAJOR-level cap (one whose derived version is ``N.0.0`` with ``N`` above zero, such as ``<4``)
  is exempt by class, per the class rule in dependabot.yml. An entry for one is a legal opt-in, and
  is then held to the same exact range.
* Every uv ``ignore`` entry names a package that pyproject.toml caps. dependabot.yml says to lift a
  cap and delete its entry in the same PR; this is what makes that rule fail when skipped. It is
  also this test's positive control: a parser that found no caps would red on every real entry, so
  the first test cannot pass vacuously.

For a ``<`` cap the derived version is the bound itself. For an exact ``==`` pin it is the next
minor, which is the scope dependabot.yml's sigstore note records: the pin's patch track stays open.

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
_GROUPS = "[dependency-groups]"

#: The exact ``==`` pins in ``[dependency-groups]`` that are deliberately NOT ignored. ``sigstore``
#: is the one exact group pin that IS ignored, by owner ruling; dependabot.yml's sigstore note says
#: why. If that ruling is lifted and its entry deleted, drop sigstore from this subtraction too.
_GROUP_PINS = frozenset(EXACT_GROUP_PINS) - {"sigstore"}
_GROUP_PIN_REASON = (
    ".github/dependabot.yml, 'NOT IGNORED, deliberately': ignoring the exact pins in "
    "[dependency-groups] would freeze the hash-pinned CI toolchain"
)

#: Every cap below major level with no ignore entry: package -> (its table, the reason). The table is a
#: prefix of ``Cap.where``. A cap on the same package anywhere else is not exempt. An exemption in
#: ``[dependency-groups]`` must also be an exact ``==`` pin. Read each reason where it points.
_EXEMPT: dict[str, tuple[str, str]] = {
    **dict.fromkeys(_GROUP_PINS, (_GROUPS, _GROUP_PIN_REASON)),
    "hatchling": (
        "[build-system].requires",
        "pyproject.toml's [build-system] comment expects Dependabot to bump this pin",
    ),
}


class Cap(NamedTuple):
    """One upper bound: where it sits, and the version its ignore range must start at."""

    package: str
    where: str
    spec: str
    exact_pin: bool
    ignore_from: Version


def _is_major_level(start: Version) -> bool:
    """Whether an ignore range from ``start`` would hold back only new majors: 4 yes, 0.50 no.

    A ``0.x`` bump counts as a minor, as Dependabot reads it by version position.
    """
    return (
        start.epoch == 0
        and start.major > 0
        and not any(start.release[1:])
        and not (start.is_prerelease or start.is_postrelease)
    )


def _is_pin(spec: Specifier) -> bool:
    return spec.operator == "==" and not spec.version.endswith(".*")


def _bump(release: tuple[int, ...]) -> Version:
    """Increment the last component of ``release``: (7, 3) -> 7.4, (4,) -> 5."""
    return Version(".".join(str(n) for n in (*release[:-1], release[-1] + 1)))


def _cap_of(spec: Specifier) -> Version | None:
    """Where an upper-bound specifier's ignore range starts, or None for a floor or ``!=``."""
    op, raw = spec.operator, spec.version
    if op in (">", ">=", "!="):
        return None
    if op == "<":
        return Version(raw)
    if _is_pin(spec):
        pinned = Version(raw)
        return Version(f"{pinned.major}.{pinned.minor + 1}.0")
    if op in ("~=", "=="):  # `==` here is the `==X.*` wildcard
        release = Version(raw.removesuffix(".*")).release
        return _bump(release if op == "==" else release[:-1])
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
        (f"{_GROUPS}.{name}", reqs) for name, reqs in pyproject.get("dependency-groups", {}).items()
    ]
    caps: list[Cap] = []
    for where, reqs in tables:
        for raw in reqs:
            if not isinstance(raw, str):  # an `{include-group = ...}` table
                continue
            req = Requirement(raw)  # markers parse apart from the specifier, so never read as caps
            bounds = [b for s in req.specifier if (b := _cap_of(s)) is not None]
            if bounds:
                pin = any(_is_pin(s) for s in req.specifier)
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
    """The root uv entry's ignore list, keyed by canonical package name."""
    ignores: dict[str, list[dict[str, Any]]] = {}
    for entry in _uv_entry(dependabot).get("ignore", []):
        ignores.setdefault(canonicalize_name(entry["dependency-name"]), []).append(entry)
    return ignores


def _ranges(entry: dict[str, Any]) -> list[Any]:
    versions = entry.get("versions", [])
    return versions if isinstance(versions, list) else [versions]


def _is_exactly_from(rng: Any, start: Version) -> bool:
    """Whether ``rng`` is the single specifier ``>=start``."""
    if not isinstance(rng, str):  # an unquoted YAML number, say
        return False
    try:
        specs = list(SpecifierSet(rng))
    except InvalidSpecifier:
        return False
    return len(specs) == 1 and specs[0].operator == ">=" and Version(specs[0].version) == start


def _violations(pyproject: dict[str, Any], dependabot: dict[str, Any]) -> list[str]:
    caps = _caps(pyproject)
    ignores = _uv_ignores(dependabot)
    problems: list[str] = []
    tightest: dict[str, Version] = {}
    for cap in caps:
        tightest[cap.package] = min(cap.ignore_from, tightest.get(cap.package, cap.ignore_from))

    for cap in caps:
        label = f"{cap.where}: {cap.spec}"
        want = f">={cap.ignore_from}"
        if cap.package in _EXEMPT:
            table, reason = _EXEMPT[cap.package]
            if not cap.where.startswith(table):
                problems.append(f"{label} is exempt only in {table}, and this cap is elsewhere")
            elif table == _GROUPS and not cap.exact_pin:
                problems.append(f"{label} is exempt as a group `==` pin, but is not one")
            elif cap.package in ignores:
                problems.append(f"{label} is exempt ({reason}) yet has an ignore entry")
            continue
        if cap.ignore_from != tightest[cap.package]:
            continue  # one ignore entry serves a package; the tightest cap is the one it restates
        entries = ignores.get(cap.package)
        if not entries:
            if not _is_major_level(cap.ignore_from):  # a major cap is exempt by class
                problems.append(
                    f"{label} has no uv ignore entry in {_DEPENDABOT.name}; add one with "
                    f'versions ["{want}"], or an exemption with its reason in {Path(__file__).name}'
                )
            continue
        if any("update-types" in e for e in entries):
            problems.append(
                f"{label}: an `update-types` ignore cannot restate a range; use `versions` only"
            )
        ranges = [rng for e in entries for rng in _ranges(e)]
        if not ranges or not all(_is_exactly_from(rng, cap.ignore_from) for rng in ranges):
            problems.append(f"{label}: its ignore range must be exactly {want!r}; found {ranges}")

    capped = {cap.package for cap in caps}
    for name in sorted(set(ignores) - capped):
        problems.append(
            f"{_DEPENDABOT.name} ignores {name!r}, which pyproject.toml does not cap. Name the bare "
            "package; an entry here restates a cap, so delete it in the PR that lifts the cap, "
            f"or model the new kind of entry in {Path(__file__).name}"
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
    """RED when: a sub-major cap has no exact ignore range, or an ignore entry outlives its cap."""
    problems = _violations(*_load())
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize(
    ("start", "major"),
    [
        ("4", True),
        ("4.0.0", True),
        ("0.50", False),
        ("3.1", False),
        ("1.0.1", False),
        ("4.0.0rc1", False),
        ("4.post1", False),
        ("1!4", False),
    ],
)
def test_major_level(start: str, major: bool) -> None:
    assert _is_major_level(Version(start)) is major


@pytest.mark.parametrize(
    ("spec", "start"),
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
def test_cap_arithmetic(spec: str, start: str | None) -> None:
    assert _cap_of(Specifier(spec)) == (Version(start) if start else None)


# A made-up cap and entry pair for each shape the mutation arms break. No real package is named,
# so a legitimate cap lift in pyproject.toml cannot crash an arm.
_FAKE_CAP = "mefor-fake-cap>=1.0,<2.5"
_FAKE_PIN = "mefor-fake-pin==3.2.1"
_FAKE_MAJOR = "mefor-fake-major>=1.0,<3"  # exempt by class, so the fixture gives it no entry


def _fake_entry(dependabot: dict[str, Any], name: str) -> dict[str, Any]:
    return next(e for e in _uv_entry(dependabot)["ignore"] if e["dependency-name"] == name)


def _fixture() -> tuple[dict[str, Any], dict[str, Any]]:
    """Copies of the real files, plus the made-up caps: two with correct entries, one major."""
    pyproject, dependabot = copy.deepcopy(_load())
    pyproject["project"]["dependencies"] += [_FAKE_CAP, _FAKE_MAJOR]
    pyproject.setdefault("dependency-groups", {})["mefor-fake"] = [_FAKE_PIN]
    _uv_entry(dependabot).setdefault("ignore", []).extend(
        [
            {"dependency-name": "mefor-fake-cap", "versions": [">=2.5.0"]},
            {"dependency-name": "mefor-fake-pin", "versions": [">=3.3.0"]},
        ]
    )
    return pyproject, dependabot


_Mutation = Callable[[dict[str, Any], dict[str, Any]], None]


def _major_entry(rng: str) -> _Mutation:
    def mutate(_p: dict[str, Any], d: dict[str, Any]) -> None:
        _uv_entry(d)["ignore"].append({"dependency-name": "mefor-fake-major", "versions": [rng]})

    return mutate


def _looser_cap_elsewhere(p: dict[str, Any], _d: dict[str, Any]) -> None:
    p["dependency-groups"]["mefor-fake"].append("mefor-fake-cap<4")


@pytest.mark.parametrize(
    "mutate",
    [None, _major_entry(">=3.0.0"), _looser_cap_elsewhere],
    ids=["unbroken", "major-cap-opt-in-entry", "looser-cap-on-same-package"],
)
def test_the_mutation_fixture_is_clean(mutate: _Mutation | None) -> None:
    """Control: the arms below discriminate only if the unbroken fixture passes. The fixture holds a
    major cap with no entry, and an opt-in exact entry for it must stay legal."""
    pyproject, dependabot = _fixture()
    if mutate:
        mutate(pyproject, dependabot)
    problems = _violations(pyproject, dependabot)
    assert not problems, "\n".join(problems)


def _drop_entry(_p: dict[str, Any], d: dict[str, Any]) -> None:
    uv = _uv_entry(d)
    uv["ignore"] = [e for e in uv["ignore"] if e["dependency-name"] != "mefor-fake-cap"]


def _set_entry(name: str, key: str, value: Any) -> _Mutation:
    def mutate(_p: dict[str, Any], d: dict[str, Any]) -> None:
        _fake_entry(d, name)[key] = value

    return mutate


def _to_update_types(_p: dict[str, Any], d: dict[str, Any]) -> None:
    entry = _fake_entry(d, "mefor-fake-cap")
    del entry["versions"]
    entry["update-types"] = ["version-update:semver-major"]


def _lift_cap(p: dict[str, Any], _d: dict[str, Any]) -> None:
    deps = p["project"]["dependencies"]
    deps[deps.index(_FAKE_CAP)] = "mefor-fake-cap>=1.0"


_EXACT = "must be exactly"
_CAP_VERSIONS = "mefor-fake-cap", "versions"


@pytest.mark.parametrize(
    ("mutate", "expect"),
    [
        pytest.param(_drop_entry, "no uv ignore entry", id="entry-deleted"),
        pytest.param(_set_entry(*_CAP_VERSIONS, [">=2.6.0"]), _EXACT, id="gap-at-cap"),
        pytest.param(_set_entry(*_CAP_VERSIONS, [">=2.4.0"]), _EXACT, id="freezes"),
        pytest.param(
            _set_entry(*_CAP_VERSIONS, ["==2.5.*", ">=3.0.0"]), _EXACT, id="hole-above-cap"
        ),
        pytest.param(
            _set_entry(*_CAP_VERSIONS, [">=1.2.0,<1.4.0", ">=2.5.0"]),
            _EXACT,
            id="blocks-an-allowed-range",
        ),
        pytest.param(_set_entry(*_CAP_VERSIONS, ["2.5.0"]), _EXACT, id="not-a-specifier"),
        pytest.param(_set_entry(*_CAP_VERSIONS, [2.5]), _EXACT, id="not-a-string"),
        pytest.param(_set_entry(*_CAP_VERSIONS, 4), _EXACT, id="not-a-list"),
        pytest.param(
            _set_entry("mefor-fake-pin", "versions", [">=3.2.0"]), _EXACT, id="blocks-pin"
        ),
        pytest.param(_set_entry("mefor-fake-pin", "versions", [">=4.0.0"]), _EXACT, id="pin-gap"),
        pytest.param(_major_entry(">=2.0.0"), _EXACT, id="major-opt-in-not-exact"),
        pytest.param(_to_update_types, "update-types", id="update-types"),
        pytest.param(_lift_cap, "does not cap", id="stale-entry"),
        pytest.param(
            _set_entry("mefor-fake-cap", "dependency-name", "mefor-fake-cap[extra]"),
            "does not cap",
            id="name-with-extras",
        ),
    ],
)
def test_the_checker_reds_on_a_mutated_config(mutate: _Mutation, expect: str) -> None:
    """Mutation arm: each broken copy must produce a violation naming what broke."""
    pyproject, dependabot = _fixture()
    mutate(pyproject, dependabot)
    problems = _violations(pyproject, dependabot)
    assert any(expect in p for p in problems), f"no violation mentioning {expect!r}: {problems}"


@pytest.mark.parametrize(
    ("name", "table", "added", "expect"),
    [
        pytest.param(
            "mefor-fake-cap",
            "[project.dependencies]",
            None,
            "yet has an ignore entry",
            id="exempt-with-entry",
        ),
        pytest.param(
            "mefor-never-capped", "[project.dependencies]", None, "names no", id="dead-exemption"
        ),
        pytest.param(
            "mefor-fake-cap", "[build-system]", None, "is exempt only in", id="exempt-elsewhere"
        ),
        pytest.param(
            "mefor-gp",
            _GROUPS,
            ("dependencies", "mefor-gp==1.0.0"),
            "only in",
            id="pin-not-in-group",
        ),
        pytest.param(
            "mefor-gp", _GROUPS, ("group", "mefor-gp>=1,<2"), "is not one", id="group-cap-not-a-pin"
        ),
    ],
)
def test_the_checker_reds_on_a_broken_exemption(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    table: str,
    added: tuple[str, str] | None,
    expect: str,
) -> None:
    """Mutation arm for the exemption table, over made-up packages only."""
    monkeypatch.setitem(_EXEMPT, name, (table, "test reason"))
    pyproject, dependabot = _fixture()
    if added:
        where, req = added
        if where == "group":
            pyproject["dependency-groups"]["mefor-fake"].append(req)
        else:
            pyproject["project"]["dependencies"].append(req)
    problems = _violations(pyproject, dependabot)
    assert any(expect in p for p in problems), f"no violation mentioning {expect!r}: {problems}"

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``scripts/ci/check_dependency_floors.py`` is what makes the dependency-floors leg a measurement
(vault BACKLOG #3055). Each verdict it can return is planted here, so the leg cannot pass while its
install sits somewhere other than the floors."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from packaging.version import Version

from scripts.ci.check_dependency_floors import check, declared_floors, main

_ROOT = Path(__file__).resolve().parents[1]


def _pyproject(tmp_path: Path, *deps: str) -> Path:
    body = ", ".join(f'"{d}"' for d in deps)
    path = tmp_path / "pyproject.toml"
    path.write_text(f'[project]\nname = "x"\ndependencies = [{body}]\n', encoding="utf-8")
    return path


def test_floors_are_read_from_the_lower_bound_and_skip_what_does_not_apply(tmp_path: Path) -> None:
    floors = declared_floors(
        _pyproject(
            tmp_path,
            "Fast_API>=0.140.0",
            "uvicorn>=0.29,<0.50",
            "compatible~=2.3",
            "pinned==1.4",
            "wildcard==1.4.*",
            "nofloor",
            "elsewhere>=1.0; sys_platform == 'never'",
        )
    )
    assert floors == {
        "fast-api": Version("0.140.0"),
        "uvicorn": Version("0.29"),
        "compatible": Version("2.3"),
        "pinned": Version("1.4"),
        "wildcard": None,
        "nofloor": None,
    }


def test_the_shipped_pyproject_declares_the_fastapi_floor() -> None:
    """The control for the parser: the real file yields the floor the route walk rests on."""
    floor = declared_floors(_ROOT / "pyproject.toml")["fastapi"]
    assert floor is not None and floor >= Version("0.140.0")


def _installed(versions: dict[str, str | None]) -> Callable[[str], Version | None]:
    def installed(name: str) -> Version | None:
        found = versions.get(name)
        return None if found is None else Version(found)

    return installed


def test_each_verdict() -> None:
    floors: dict[str, Version | None] = {
        "at-floor": Version("1.0"),
        "above": Version("1.0"),
        "raised": Version("1.0"),
        "raised-below": Version("2.0"),
        "stale-raise": Version("1.0"),
        "missing": Version("1.0"),
        "unreadable": None,
    }
    installed = {
        "at-floor": "1.0.0",
        "above": "1.1",
        "raised": "1.2",
        "raised-below": "1.9",
        "stale-raise": "1.0",
        "missing": None,
        "unreadable": "1.0",
    }
    lines, failures = check(
        floors,
        ["raised", "raised-below", "Stale_Raise", "unknown"],
        installed=_installed(installed),
    )
    assert lines == [
        "at-floor 1.0.0: at its floor",
        "raised 1.2: above its floor 1.0, raised on purpose",
    ]
    assert failures == [
        "above: installed 1.1, but the declared floor is 1.0",
        "missing: declared >=1.0 but not installed",
        "raised-below: installed 1.9, BELOW the declared floor 2.0",
        "stale-raise: listed as raised but installed at its floor 1.0; drop it from --raised",
        "unreadable: declares no floor this check can read; write it as >=X",
        "unknown: listed as raised but declares no floor that applies here",
    ]


def test_an_empty_floor_set_fails_rather_than_passes() -> None:
    assert check({}, [])[1] == ["no runtime dependency declares a floor; nothing read"]


def test_main_exits_non_zero_on_a_failure(tmp_path: Path) -> None:
    path = _pyproject(tmp_path, "not-a-real-distribution-3055>=1.0")
    assert main(["--pyproject", str(path)]) == 1

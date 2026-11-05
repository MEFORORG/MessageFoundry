# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``scripts/ci/check_dependency_floors.py`` is what makes the dependency-floors leg a measurement
(vault BACKLOG #3055). Each verdict it can return is planted here, so the leg cannot pass while its
install sits somewhere other than the floors."""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from importlib import metadata
from pathlib import Path

import pytest
import yaml
from packaging.version import Version

from scripts.ci.check_dependency_floors import (
    DEFAULT_EXTRAS,
    UndeclaredExtra,
    check,
    declared_floors,
    main,
)

_ROOT = Path(__file__).resolve().parents[1]


def _toml_list(deps: Sequence[str]) -> str:
    return "[" + ", ".join(f'"{d}"' for d in deps) + "]"


def _pyproject(tmp_path: Path, *deps: str, **extras: Sequence[str]) -> Path:
    body = f'[project]\nname = "x"\ndependencies = {_toml_list(deps)}\n'
    if extras:
        body += "[project.optional-dependencies]\n"
        body += "".join(f"{name} = {_toml_list(lines)}\n" for name, lines in extras.items())
    path = tmp_path / "pyproject.toml"
    path.write_text(body, encoding="utf-8")
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
            "excluded>=1.0,!=1.0",
            "twice>=1.0",
            "twice>=2.0; python_version >= '3.10'",
            "nofloor",
            "elsewhere>=1.0; sys_platform == 'never'",
            # BACKLOG #3177: a bare line adds no bound, so the other line's floor stands.
            "bare",
            "bare>=1.5",
            # BACKLOG #3177: the merged specifiers are re-checked, so one line's exclusion of the
            # floor another line declares leaves no readable floor.
            "split>=1.0",
            "split>=0.5,!=1.0",
        )
    )
    assert floors == {
        "fast-api": Version("0.140.0"),
        "uvicorn": Version("0.29"),
        "compatible": Version("2.3"),
        "pinned": Version("1.4"),
        "wildcard": None,
        "excluded": None,
        "twice": Version("2.0"),
        "nofloor": None,
        "bare": Version("1.5"),
        "split": None,
    }


def test_the_shipped_pyproject_declares_the_fastapi_floor() -> None:
    """The control for the parser: the real file yields the floor the route walk rests on.

    0.143.1 is the first release with the ``RouteContext`` shape the route walk reads, and the
    required legs run only the locked release, so a floor below it would allow a shape no required
    leg runs (vault BACKLOG #3916)."""
    floor = declared_floors(_ROOT / "pyproject.toml")["fastapi"]
    assert floor is not None and floor >= Version("0.143.1")


def test_the_named_extras_are_read_and_combine_with_the_runtime_lines(tmp_path: Path) -> None:
    """BACKLOG #3177: a [dev] floor is read like a runtime one, and only the extras named."""
    path = _pyproject(
        tmp_path,
        "shared>=1.0",
        dev=[
            "pytest>=9.0.3",
            "shared>=1.2",
            "only-when-dev>=2.0; extra == 'dev'",
            "elsewhere>=1.0; sys_platform == 'never'",
        ],
        Other_Extra=["other>=3.0"],
    )
    assert declared_floors(path) == {"shared": Version("1.0")}
    assert declared_floors(path, ["dev"]) == {
        "shared": Version("1.2"),
        "pytest": Version("9.0.3"),
        "only-when-dev": Version("2.0"),
    }
    # Extra names compare canonicalized, as pip and uv compare them.
    assert declared_floors(path, ["other-extra"]) == {
        "shared": Version("1.0"),
        "other": Version("3.0"),
    }


def test_two_extra_keys_that_canonicalize_alike_are_both_read(tmp_path: Path) -> None:
    path = _pyproject(tmp_path, dev=["first>=1.0"], Dev=["second>=2.0"])
    assert declared_floors(path, ["dev"]) == {"first": Version("1.0"), "second": Version("2.0")}


def test_an_undeclared_extra_is_refused_rather_than_read_as_empty(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _pyproject(tmp_path, dev=["pytest>=9.0.3"])
    with pytest.raises(UndeclaredExtra, match="'dve' is not declared"):
        declared_floors(path, ["dve"])
    assert main(["--pyproject", str(path), "--extra", "dve"]) == 1
    assert "FLOOR NOT MEASURED: extra 'dve' is not declared" in capsys.readouterr().err


def test_main_reads_the_dev_floors_unless_told_which_extras(tmp_path: Path) -> None:
    """The workflow passes no ``--extra``, so the default is what makes it read [dev]. The runtime
    floor is installed exactly, and the controls name an empty extra, or none, and pass, so the
    red comes from [dev]."""
    installed = f"packaging=={metadata.version('packaging')}"
    path = _pyproject(tmp_path, installed, dev=["not-a-real-distribution-3177>=1.0"], ok=[])
    assert main(["--pyproject", str(path)]) == 1
    assert main(["--pyproject", str(path), "--extra", "ok"]) == 0
    # A bare --extra reads the runtime dependencies alone.
    assert main(["--pyproject", str(path), "--extra"]) == 0


def test_the_shipped_pyproject_declares_a_readable_floor_for_every_default_dependency() -> None:
    """The control for the default: the real file's [dev] extra is read, and every line read, a
    [dev] line sharing a runtime name included, yields a floor the check can compare."""
    floors = declared_floors(_ROOT / "pyproject.toml", DEFAULT_EXTRAS)
    assert {"pytest", "pytest-asyncio", "pyyaml"} <= floors.keys()
    assert [name for name, floor in floors.items() if floor is None] == []


def test_the_default_extras_are_the_ones_the_workflow_installs() -> None:
    """The workflow's check step passes no ``--extra``, so the default must name exactly the
    extras its install step installs: one more reds as not installed, one fewer goes unread."""
    workflow = yaml.safe_load(
        (_ROOT / ".github" / "workflows" / "dependency-floors.yml").read_text(encoding="utf-8")
    )
    runs = [step.get("run", "") for step in workflow["jobs"]["floors"]["steps"]]
    (install,) = [run for run in runs if "--resolution lowest-direct" in run]
    (check_step,) = [run for run in runs if "scripts/ci/check_dependency_floors.py" in run]
    assert "--extra" not in check_step
    (extras,) = re.findall(r'-e "\.\[([^\]]*)\]"', install)
    assert {e.strip() for e in extras.split(",")} == set(DEFAULT_EXTRAS)


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
        "unreadable: declares no floor this check can read; write it as >=X, "
        "with no specifier for this name excluding X",
        "unknown: listed as raised but declares no floor that applies here",
    ]


def test_an_empty_floor_set_fails_rather_than_passes() -> None:
    assert check({}, [])[1] == ["no dependency declares a floor; nothing read"]


def test_main_exits_non_zero_on_a_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _pyproject(tmp_path, "not-a-real-distribution-3055>=1.0", dev=[])
    assert main(["--pyproject", str(path)]) == 1
    assert "not-a-real-distribution-3055: declared >=1.0 but not installed" in (
        capsys.readouterr().err
    )

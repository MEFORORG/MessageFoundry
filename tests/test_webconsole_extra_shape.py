# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The engine's ``[webconsole]`` extra is a floor on the console, with no ceiling and no marker.

``packaging/messagefoundry-webconsole/RELEASE.md`` step 1 sets it, and step 0 says to set no ceiling
on either side; ``docs/WEBCONSOLE-PACKAGE.md`` gives the reasons. The console side of the pair is
held by ``release-webconsole``'s floor step (``tests/test_webconsole_engine_floor.py``). Nothing else
reads this side, so an edit that drops the floor or adds a ceiling would pass every other check.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.version import Version

import messagefoundry_webconsole

_ROOT = Path(__file__).resolve().parents[1]


def _extra() -> list[str]:
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    extras: dict[str, list[str]] = project["optional-dependencies"]
    assert "webconsole" in extras, "the engine no longer declares a [webconsole] extra"
    return extras["webconsole"]


def test_the_extra_names_the_console_alone() -> None:
    reqs = [Requirement(r) for r in _extra()]
    assert [r.name for r in reqs] == ["messagefoundry-webconsole"], reqs
    assert not reqs[0].extras, reqs[0]


def test_the_extra_is_a_floor_with_no_ceiling_and_no_marker() -> None:
    req = Requirement(_extra()[0])
    assert req.marker is None, f"{req}: a marker would drop the console on some installs"
    assert req.url is None, f"{req}: the extra resolves the index, not a URL"
    operators = sorted(s.operator for s in req.specifier)
    assert operators == [">="], f"{req}: expected exactly one >= floor and nothing else"


def test_the_floor_is_not_above_the_checkout_console() -> None:
    # The floor names a console already on PyPI, so it can trail the checkout's console version
    # (a release commit raises the checkout first) but never lead it.
    floor = Version(next(iter(Requirement(_extra()[0]).specifier)).version)
    assert floor <= Version(messagefoundry_webconsole.__version__), (
        f"the [webconsole] floor {floor} is above the checkout's console "
        f"{messagefoundry_webconsole.__version__}"
    )

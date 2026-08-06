# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The default pytest gate must collect the web console package, not silently exclude it.

BACKLOG #1027: `testpaths = ["tests"]` made a bare `pytest -q` from the repo root skip the
~344 tests under ``packaging/messagefoundry-webconsole/tests`` while the green summary line
looked complete. This guard reads the root ``pyproject.toml`` and fails if the console tree is
ever dropped from ``testpaths`` again — it lives under ``tests/`` on purpose, so the very
narrowing it guards against can never exclude the guard itself.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_WEBCONSOLE_TESTS = "packaging/messagefoundry-webconsole/tests"


def test_default_testpaths_collect_the_webconsole_package() -> None:
    pyproject = _REPO_ROOT / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    testpaths = data["tool"]["pytest"]["ini_options"]["testpaths"]

    assert testpaths[0] == "tests", (
        f"the engine suite must stay first in testpaths, got {testpaths!r}"
    )
    assert _WEBCONSOLE_TESTS in testpaths, (
        f"the web console package tests must be in testpaths so a default pytest run "
        f"collects them (BACKLOG #1027), got {testpaths!r}"
    )
    assert (_REPO_ROOT / _WEBCONSOLE_TESTS).is_dir(), (
        f"testpaths names {_WEBCONSOLE_TESTS!r} but that directory does not exist"
    )

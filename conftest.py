# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Repo-root pytest hooks: the ones that must hold for every testpath.

Keep it to hooks that need this reach, and keep implementations in named modules: pytest imports
this file under the bare name ``conftest``, which no module should import (the docstring of
``tests/test_conftest_name_collision_guard.py`` says why; that guard scans only the testpath roots,
not this file).

A side effect of the file existing: under pytest's default ``prepend`` import mode, importing it
puts the repository root at the front of ``sys.path`` for every run the root ``pyproject.toml``
configures. The engine's editable install already puts the root on ``sys.path``; this moves it ahead
of the standard library and site-packages. At least one package already resolves differently:
``messagefoundry_webconsole`` now imports from the tree in those runs, while a run naming only the
console tree (its own rootdir) still imports the copy its editable install placed in site-packages.
The two agree until the tree is edited without reinstalling the console package.
"""

from __future__ import annotations

# Caps pytest -n auto; tests/_xdist_worker_cap.py says why it is registered here.
from tests._xdist_worker_cap import pytest_xdist_auto_num_workers  # noqa: F401

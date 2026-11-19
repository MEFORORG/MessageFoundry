# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Repo-root pytest hooks: the ones that must hold for EVERY testpath.

pytest loads this file for any run the root ``pyproject.toml`` configures, under either testpath,
and before ``pytest_cmdline_main``; ``tests/conftest.py`` is not loaded for a run that names only
``packaging/messagefoundry-webconsole/tests``. Keep it to hooks that need that reach. pytest imports
it under the bare name ``conftest``, the name ``tests/test_conftest_name_collision_guard.py`` keeps
unimported, so the implementation lives in a named module.
"""

from __future__ import annotations

# Re-exported so pytest registers it from this conftest; tests/_xdist_worker_cap.py says why here.
from tests._xdist_worker_cap import pytest_xdist_auto_num_workers  # noqa: F401

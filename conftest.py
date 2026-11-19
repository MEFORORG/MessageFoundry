# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Repo-root pytest hooks: the ones that must hold for every testpath.

Keep it to hooks that need this reach. pytest imports it under the bare name ``conftest``, which
``tests/test_conftest_name_collision_guard.py`` keeps unimported, so implementations live in named
modules.
"""

from __future__ import annotations

# Caps pytest -n auto; tests/_xdist_worker_cap.py says why it is registered here.
from tests._xdist_worker_cap import pytest_xdist_auto_num_workers  # noqa: F401

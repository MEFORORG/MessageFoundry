# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Shared Hypothesis settings for the property tests (``tests/test_property_*.py``).

Importing this module moves Hypothesis's storage out of the checkout. Hypothesis caches the string
literals of every imported local module under its storage directory, ``.hypothesis/`` in the
working directory by default, with each module's absolute path. ``scripts/security/scan_forbidden.py
--path`` walks untracked files and would read that cache, so it goes to a fixed directory under the
system temp directory instead. A ``HYPOTHESIS_STORAGE_DIRECTORY`` the caller sets still wins.

:func:`property_settings` is fixed-seed: ``derandomize`` makes a run of a given file draw the same
examples every time. It does not make a file alone and a full-suite run draw the same ones, because
Hypothesis also mixes in literals from the modules imported at the time. A failure prints its
falsifying example; pin it with ``@example`` to replay it anywhere.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from hypothesis import HealthCheck, settings
from hypothesis.configuration import set_hypothesis_home_dir

if not os.environ.get("HYPOTHESIS_STORAGE_DIRECTORY"):
    set_hypothesis_home_dir(Path(tempfile.gettempdir()) / "messagefoundry-hypothesis")


def property_settings(*, max_examples: int) -> settings:
    """Fixed-seed settings with no example database and no per-example deadline.

    No deadline, because a contended runner's stall would otherwise read as a flaky failure with no
    defect behind it; ``max_examples`` is what bounds each test's time.
    """
    return settings(
        derandomize=True,
        database=None,
        max_examples=max_examples,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )

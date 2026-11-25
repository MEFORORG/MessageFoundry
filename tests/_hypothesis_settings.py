# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Shared Hypothesis settings for the property tests (``tests/test_property_*.py``).

Importing this module moves Hypothesis's storage out of the checkout. Hypothesis caches the string
literals of every imported local module under its storage directory, ``.hypothesis/`` in the
working directory by default, with each module's absolute path. ``scripts/security/scan_forbidden.py
--path`` walks untracked files and would read that cache, so it goes to a private directory this
process creates with :func:`tempfile.mkdtemp`: a fresh, unpredictable name, readable by the current
user alone on POSIX, removed by an ``atexit`` handler on a normal exit. A process killed with
``os._exit``, as a pytest-timeout kill is, leaves it behind. A fixed path under the shared temp
directory could be planted or read by another user first (CWE-377). A
``HYPOTHESIS_STORAGE_DIRECTORY`` the caller sets still wins. Only a process that imports this
module moves its storage; ``scan_forbidden`` also skips ``.hypothesis`` by name for the rest.

``HYPOTHESIS_PROFILE`` picks the profile :func:`property_settings` builds on; unset, it is ``ci``.
These are this module's own profiles, never registered with Hypothesis, so they neither replace
Hypothesis's built-in ``ci`` profile nor answer to ``--hypothesis-profile``; any other name raises.

* ``ci`` is fixed-seed: ``derandomize`` makes a run of a given file draw the same examples every
  time. It does not make a file alone and a full-suite run draw the same ones, because Hypothesis
  also mixes in literals from the modules imported at the time.
* ``explore`` draws from a fresh random seed each run, to find inputs ``ci`` never reaches.

Either way a failure prints its falsifying example and a ``@reproduce_failure`` blob; pin the
example with ``@example``, or the blob, to replay it.
"""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile

from hypothesis import HealthCheck, settings
from hypothesis.configuration import set_hypothesis_home_dir

if not os.environ.get("HYPOTHESIS_STORAGE_DIRECTORY"):
    _storage = tempfile.mkdtemp(prefix="messagefoundry-hypothesis-")
    atexit.register(shutil.rmtree, _storage, ignore_errors=True)
    set_hypothesis_home_dir(_storage)

# Built on Hypothesis's "default" profile, never on whichever profile is current, which Hypothesis
# switches to its own "ci" when it detects a CI environment. No example database, so nothing
# persists between runs; no per-example deadline, because a contended runner's stall would otherwise
# read as a flaky failure with no defect behind it; a blob, so an example a strategy reports opaquely
# (``st.randoms``) can still be replayed.
_COMMON = settings(
    settings.get_profile("default"),
    database=None,
    deadline=None,
    print_blob=True,
    suppress_health_check=[HealthCheck.too_slow],
)
PROFILES = {
    "ci": settings(_COMMON, derandomize=True),
    "explore": settings(_COMMON, derandomize=False),
}

PROFILE = os.environ.get("HYPOTHESIS_PROFILE") or "ci"
if PROFILE not in PROFILES:
    raise ValueError(f"HYPOTHESIS_PROFILE must be one of {sorted(PROFILES)}, not {PROFILE!r}")


def property_settings(*, max_examples: int) -> settings:
    """The selected profile's settings, with ``max_examples`` bounding each test's time."""
    return settings(PROFILES[PROFILE], max_examples=max_examples)

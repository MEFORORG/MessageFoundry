# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Keep a pytest process's children from outliving it, on Windows.

pytest-timeout's thread method ends a hung worker with ``os._exit``, which runs no teardown, so
anything a test started is left running. On 2026-10-17 one machine was found holding 54 orphaned
``serve`` engines and suspended git processes that way. :func:`install` puts the calling process
in a kill-on-close job (:func:`messagefoundry.proctree.adopt_current_process`). Every process it
starts afterwards joins that job, so when the process ends, by any route, Windows ends them too.

``tests/conftest.py`` calls it from ``pytest_configure``, which runs in the xdist controller and in
every worker. ``tests/test_process_guard.py`` runs the same call in a throwaway process to prove it.

**What it costs.** A test cannot leave a process running past the end of its pytest process, and a
process started with ``CREATE_BREAKAWAY_FROM_JOB`` is refused (``WinError 5``), because the job does
not allow breakaway. No test passed that flag when this was written. A process started outside the
tree (a service, a scheduled task, a WMI provider) is not in the job and is not covered.
"""

from __future__ import annotations

import sys

from messagefoundry import proctree

# Held for the process's whole life and never closed: closing the last handle is what ends the job.
_job: int | None = None


def install() -> int | None:
    """Put this process in a kill-on-close job, once. Returns the job handle, or ``None`` off
    Windows or when the job could not be set up (logged by :mod:`messagefoundry.proctree`)."""
    global _job
    if sys.platform == "win32" and _job is None:
        _job = proctree.adopt_current_process(who="pytest process guard")
    return _job


def job() -> int | None:
    """The job :func:`install` set up in this process, or ``None``."""
    return _job

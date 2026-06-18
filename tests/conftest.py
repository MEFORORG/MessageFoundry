# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Shared pytest fixtures.

Holds the suite-wide guard for the intermittent py3.11 logging-teardown race tracked as BACKLOG #17.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest


@pytest.fixture(scope="session", autouse=True)
def _tolerate_logging_on_closed_capture_streams() -> Iterator[None]:
    """Neutralize the py3.11 pytest log-capture **teardown race** (BACKLOG #17), suite-wide.

    Async components (the engine, the harness monitor, the tee relay, …) intermittently emit a log
    record **after** pytest has closed the per-test log-capture stream. The ``StreamHandler`` write then
    raises ``ValueError: I/O operation on closed file``, and ``logging.Handler.emit`` routes that to
    ``Handler.handleError`` — which, while ``logging.raiseExceptions`` is the default ``True``, writes a
    traceback to ``sys.stderr``. Under **py3.11 + background threads** that error-handling path floods the
    output and can wedge the event-loop thread *inside the synchronous* ``emit`` (it holds the handler
    lock) until the per-test ``--timeout`` fires — observed as a hang in ``test_tee_relay`` and as a
    knock-on assertion-timeout in ``test_harness_monitor``, both py3.11-only and intermittent.

    Setting ``logging.raiseExceptions = False`` makes ``handleError`` a no-op, so a late emit into a
    closed capture stream fails **fast and silently** instead of flooding / deadlocking. It is the
    standard library's documented switch for exactly this (production-vs-development error handling), and
    it is scoped to the test session only — production keeps the default. The ``pytest-timeout`` watchdog
    (#375) remains the backstop. (A narrower, relay-banner-only filter was tried first and proved
    insufficient — the race is not relay-specific; see BACKLOG #17.)
    """
    prior_raise = logging.raiseExceptions
    logging.raiseExceptions = False
    try:
        yield
    finally:
        logging.raiseExceptions = prior_raise

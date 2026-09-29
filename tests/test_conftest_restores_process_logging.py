# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pins ``tests/conftest.py::_restore_process_logging`` (BACKLOG #2049 follow-up, 2026-09-29).

The two tests run in file order. The first leaves the engine's logging configured, as a serve or a
CLI test does. The second must not see it: before the fixture, the leftover stdout handler wrote a
later test's records into that test's captured stdout, and two ``audit-verify``/``audit-anchor``
tests failed on it. If the fixture stops restoring, the second test fails here, on any worker.
"""

from __future__ import annotations

import logging

import pytest

from messagefoundry.logging_guard import active_guard
from messagefoundry.logging_setup import configure_logging

_SEEN: dict[str, object] = {}


def test_1_a_test_that_configures_engine_logging(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("DEBUG")
    root = logging.getLogger()
    _SEEN["handlers"] = list(root.handlers)
    _SEEN["guard"] = active_guard()
    assert root.level == logging.DEBUG
    capsys.readouterr()


def test_2_the_next_test_does_not_inherit_it(capsys: pytest.CaptureFixture[str]) -> None:
    assert _SEEN, "test_1 did not run first; this pair relies on file order"
    root = logging.getLogger()
    leaked = [h for h in root.handlers if h in _SEEN["handlers"]]  # type: ignore[operator]
    assert not leaked, f"engine log handlers leaked from the previous test: {leaked}"
    assert root.level != logging.DEBUG, "the previous test's root level leaked"
    assert active_guard() is not _SEEN["guard"], "the previous test's write guard is still active"
    logging.getLogger("messagefoundry.test").warning("a record from the next test")
    assert capsys.readouterr().out == "", "a record reached this test's stdout"

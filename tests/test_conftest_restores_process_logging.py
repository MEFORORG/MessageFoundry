# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pins ``tests/conftest.py::_restore_process_logging`` (BACKLOG #2049 follow-up, 2026-09-29).

The tests run in file order, in two pairs. In the first pair, the first leaves the engine's logging
configured, as a serve or a CLI test does. The second must not see it: before the fixture, the
leftover stdout handler wrote a later test's records into that test's captured stdout, and two
``audit-verify``/``audit-anchor``
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


# BACKLOG #2093. RedactionFilter rewrites the shared record in place, and "Open Console" reads as a
# patient name to it. test_3 leaks the filter by two routes the handler-list restore alone missed;
# test_4 then asserts caplog sees the line raw. Measured red for both routes before #2093.
_LINE = "Open Console refused"


def test_3_a_test_that_leaks_a_redaction_filter(caplog: pytest.LogCaptureFixture) -> None:
    from messagefoundry.logging_setup import RedactionFilter

    # Control: test_4 proves the restore only while the filter would rewrite _LINE. If the redactor
    # ever stops matching it, test_4 would pass against a broken restore, so fail here instead.
    record = logging.LogRecord("t", logging.WARNING, __file__, 0, _LINE, None, None)
    RedactionFilter().filter(record)
    assert record.getMessage() != _LINE, "RedactionFilter no longer rewrites _LINE"

    root = logging.getLogger()
    root.addFilter(RedactionFilter())
    for handler in root.handlers:  # includes pytest's capture handler, which pytest re-uses
        handler.addFilter(RedactionFilter())
    _SEEN["filtered"] = True
    _SEEN["caplog_handler"] = caplog.handler


def test_4_the_next_test_sees_its_records_unredacted(caplog: pytest.LogCaptureFixture) -> None:
    assert _SEEN.get("filtered"), "test_3 did not run first; this pair relies on file order"
    # The surviving-handler route only means something while pytest re-uses its capture handler.
    # If a future pytest stops, fail loudly here rather than pass without testing anything.
    assert caplog.handler is _SEEN["caplog_handler"], "pytest no longer re-uses caplog.handler"
    try:
        with caplog.at_level(logging.WARNING):
            logging.getLogger().warning(_LINE)
            logging.getLogger("messagefoundry.test").warning(_LINE)
        assert caplog.messages == [_LINE, _LINE], caplog.messages
    finally:
        # If the restore ever regresses, strip the leak here so one clear failure does not become
        # many unrelated ones later on this worker.
        from messagefoundry.logging_setup import RedactionFilter

        root = logging.getLogger()
        for filterer in [root, *root.handlers]:
            for leaked in [f for f in filterer.filters if isinstance(f, RedactionFilter)]:
                filterer.removeFilter(leaked)

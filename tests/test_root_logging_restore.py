# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The per-test root logging restore undoes at least three filter leak routes -- BACKLOG #2093.

Each test leaks a ``RedactionFilter`` one way inside :func:`root_logging_restored`, then checks the
leak is gone and a later record reaches a surviving handler unredacted. The control runs the same
leak with no restore and shows the record IS rewritten, so a pass is not a probe that cannot fail.
"""

from __future__ import annotations

import io
import logging
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from messagefoundry.logging_setup import RedactionFilter
from tests._root_logging import root_logging_restored

# The redactor reads "Open Console" as a patient name. This is the PR 1621 line.
_LINE = "Open Console refused"


@pytest.fixture
def survivor() -> Iterator[tuple[logging.Handler, io.StringIO]]:
    """A root handler that exists before the leak and must survive the restore unfiltered."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        yield handler, stream
    finally:
        root.removeHandler(handler)


def _leak_filtered_handler(_survivor: logging.Handler) -> None:
    leaked = logging.StreamHandler(io.StringIO())
    leaked.addFilter(RedactionFilter())
    logging.getLogger().handlers.insert(0, leaked)


def _leak_root_filter(_survivor: logging.Handler) -> None:
    logging.getLogger().addFilter(RedactionFilter())


def _leak_filter_onto_survivor(survivor: logging.Handler) -> None:
    survivor.addFilter(RedactionFilter())


_LEAKS: dict[str, Callable[[logging.Handler], None]] = {
    "filtered_handler_on_root": _leak_filtered_handler,
    "filter_on_root_logger": _leak_root_filter,
    "filter_on_surviving_handler": _leak_filter_onto_survivor,
}


def _emit_on_root() -> None:
    # Logged on the root logger itself, because a logger's own filters apply only to records
    # logged on that logger, never to propagated ones.
    root = logging.getLogger()
    prior = root.level
    root.setLevel(logging.WARNING)
    try:
        root.warning(_LINE)
    finally:
        root.setLevel(prior)


@pytest.mark.parametrize("leak", list(_LEAKS))
def test_the_restore_removes_the_leak(
    leak: str, survivor: tuple[logging.Handler, io.StringIO]
) -> None:
    handler, stream = survivor
    root = logging.getLogger()
    handlers_before = list(root.handlers)
    filters_before = list(root.filters)
    with root_logging_restored():
        _LEAKS[leak](handler)
    assert root.handlers == handlers_before
    assert root.filters == filters_before
    assert handler.filters == []
    _emit_on_root()
    assert _LINE in stream.getvalue().splitlines()


@pytest.mark.parametrize("leak", list(_LEAKS))
def test_control_the_leak_rewrites_the_record_without_the_restore(
    leak: str, survivor: tuple[logging.Handler, io.StringIO]
) -> None:
    handler, stream = survivor
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_filters = list(root.filters)
    try:
        _LEAKS[leak](handler)
        _emit_on_root()
    finally:
        root.handlers[:] = saved_handlers
        root.filters[:] = saved_filters
        handler.filters.clear()
    written = stream.getvalue()
    # A root-logger filter drops nothing, it rewrites; every leak route yields the redacted line.
    assert "Open Console" not in written
    assert "[redacted] refused" in written


def test_the_restore_puts_back_handler_level_formatter_and_the_disable_level(
    survivor: tuple[logging.Handler, io.StringIO],
) -> None:
    handler, stream = survivor
    formatter = handler.formatter
    # Compare against the values before the block, not NOTSET, so a session that set either one
    # does not fail a restore that worked.
    level = handler.level
    disabled = logging.root.manager.disable
    with root_logging_restored():
        handler.setLevel(logging.CRITICAL)
        handler.setFormatter(logging.Formatter("LEAKED %(message)s"))
        logging.disable(logging.CRITICAL)
    assert handler.level == level
    assert handler.formatter is formatter
    assert logging.root.manager.disable == disabled
    _emit_on_root()
    assert _LINE in stream.getvalue().splitlines()


def test_no_module_shadows_the_conftest_restore() -> None:
    # A test module fixture with the conftest fixture's name REPLACES it for that module. That is how
    # tests/test_log_write_guard.py silently lost the filter restore until BACKLOG #2093.
    needle = "def " + "_restore_process_logging("  # split so this file does not match itself
    tests_dir = Path(__file__).parent
    defining = sorted(
        path.relative_to(tests_dir).as_posix()
        for path in tests_dir.rglob("*.py")
        if needle in path.read_text(encoding="utf-8")
    )
    # The conftest is the positive control: a scan that cannot find it proves nothing.
    assert defining == ["conftest.py"], defining

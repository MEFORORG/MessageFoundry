# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A log-absence check needs a positive control: proof that ``caplog`` sees the logger at all.

``assert not [r for r in caplog.records if ...]`` passes on nothing when the capture cannot see the
logger the code under test writes through, at least: a logger with ``propagate=False``, a disabled
one, and a level above the probe's (vault BACKLOG #3766 item 9).

What it proves, and what it does not. It proves the capture sees that logger at that level WHEN THE
PROBE RUNS. Inside the act's ``caplog.at_level`` block that is the act's own capture; after the
block it shows at least that the logger still propagates to the capture and is not disabled, not
that a lower-level record from the act was captured. It does not prove the code under test logs
through that logger, or that it reached the line that would have logged.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Callable

import pytest

#: Marks the probe on the record, so a filter that rewrites the message in place cannot hide it.
_PROBE_ATTR = "_log_absence_probe"


def assert_capture_sees(
    caplog: pytest.LogCaptureFixture, logger: str | logging.Logger, level: int = logging.WARNING
) -> None:
    """Fail unless ``caplog`` captures a ``level`` record sent through ``logger``, then take it out
    of ``caplog.records`` and ``caplog.text`` so the absence check after this call is unchanged.

    Each other handler on the record's way up, pytest's report handler among them, drops it while
    the probe runs, so at least those handlers do not write the probe line (vault BACKLOG #3766
    item 35). A capture that cannot see the logger fails here, and then the probe may still reach
    ``logging.lastResort``, which writes to stderr."""
    log = logger if isinstance(logger, logging.Logger) else logging.getLogger(logger)
    others = [h for h in _handlers_reached(log) if h is not caplog.handler]
    for handler in others:
        handler.addFilter(_drop_probe)
    try:
        log.log(level, "log-absence capture probe", extra={_PROBE_ATTR: True})
    finally:
        for handler in others:
            handler.removeFilter(_drop_probe)
    probes = [r for r in caplog.records if getattr(r, _PROBE_ATTR, False)]
    assert len(probes) == 1, (
        f"caplog did not capture a {logging.getLevelName(level)} record sent through "
        f"{log.name!r}, so an absence check over that logger would pass on nothing"
    )
    caplog.records.remove(probes[0])
    # The capture's text stream holds the formatted line too; take that one line back out, under
    # the handler's lock so a record another thread writes meanwhile is not lost.
    handler = caplog.handler
    with handler.lock or contextlib.nullcontext():
        stream = handler.stream
        line = handler.format(probes[0]) + handler.terminator
        text = stream.getvalue()
        at = text.rfind(line)
        assert at >= 0, "the probe's formatted line is not in caplog.text, so it cannot be removed"
        stream.seek(0)
        stream.truncate()
        stream.write(text[:at] + text[at + len(line) :])


def _drop_probe(record: logging.LogRecord) -> bool:
    return not getattr(record, _PROBE_ATTR, False)


def _handlers_reached(log: logging.Logger) -> list[logging.Handler]:
    """The handlers a record logged through ``log`` meets, walking up while each logger
    propagates, as :meth:`logging.Logger.callHandlers` does."""
    out: list[logging.Handler] = []
    node: logging.Logger | None = log
    while node is not None:
        out.extend(node.handlers)
        node = node.parent if node.propagate else None
    return out


def assert_no_records(
    caplog: pytest.LogCaptureFixture,
    logger: str | logging.Logger,
    pred: Callable[[logging.LogRecord], bool],
    level: int = logging.WARNING,
) -> None:
    """Fail when a captured record from ``logger`` or a child of it matches ``pred``, after
    :func:`assert_capture_sees_tree` has shown the capture sees ``logger`` and each child created
    so far at ``level``, so the probe and the absence check cover one set of loggers (vault BACKLOG
    #3766 item 36)."""
    log = logger if isinstance(logger, logging.Logger) else logging.getLogger(logger)
    assert_capture_sees_tree(caplog, log.name, level)
    # Logger names only, never a message: a check that a value never reaches a log must not print
    # that value into the failure text.
    hits = sorted(
        {
            r.name
            for r in caplog.records
            if (r.name == log.name or r.name.startswith(f"{log.name}.")) and pred(r)
        }
    )
    assert hits == [], f"a record from {hits} matched under {log.name!r}"


def assert_capture_sees_tree(
    caplog: pytest.LogCaptureFixture, root: str, level: int = logging.WARNING
) -> None:
    """:func:`assert_capture_sees` for ``root`` and for each logger created under it so far.

    A probe of ``root`` alone does not show that a child's records reach the capture: a child with
    ``propagate=False``, or a disabled one, would hide them (vault BACKLOG #3766 item 29). A child
    created after this call is not probed."""
    names = [
        name
        for name, node in list(logging.Logger.manager.loggerDict.items())
        if isinstance(node, logging.Logger) and (name == root or name.startswith(f"{root}."))
    ]
    for name in sorted({root, *names}):
        assert_capture_sees(caplog, name, level)

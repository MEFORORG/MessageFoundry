# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Put the root logger back as it was, filters included -- BACKLOG #2093.

``tests/conftest.py`` wraps each test under ``tests/`` in :func:`root_logging_restored`. Tests under
``packaging/messagefoundry-webconsole/tests`` are outside that conftest and are not wrapped. It lives
here, not in the conftest, so ``tests/test_root_logging_restore.py`` can drive it directly.

Why the filters matter. ``RedactionFilter`` rewrites the shared ``LogRecord`` in place, so a filter
that runs before pytest's capture handler changes what ``caplog`` sees. PR 1621 failed that way: a
test passed alone and failed in the suite. PR 1784 closed the leaked-handler route by restoring the
root handler list. At least two routes stayed open, and both were measured red on 2026-09-29:

1. a filter added to the root logger itself;
2. a filter added to a handler that survives the restore, such as pytest's own capture handler,
   which pytest reuses from test to test.

What this does NOT cover, at least. It restores to the state at snapshot time, so a leak made
before the snapshot (a session fixture, collection-time code) is kept. It does not touch named
loggers: a filter or filtered handler left on ``getLogger("messagefoundry")`` still rewrites a
record before the record reaches the root. It does not undo a formatter mutated in place, a
handler's swapped stream, ``root.disabled`` or the log record factory.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager


@contextmanager
def root_logging_restored() -> Iterator[None]:
    """Restore root handlers, each one's filters/level/formatter, root filters, level and guard.

    Also restores the process-wide ``logging.disable`` level, which silences every capture.

    pytest re-uses its capture handler instances across phases, so re-adding the snapshot re-adds
    live handlers, not stale ones. A handler the body added is closed, which releases a forwarder's
    thread and socket or a log file. A stream handler's close leaves its stream open.
    """
    from messagefoundry import logging_setup
    from messagefoundry.logging_guard import active_guard, set_active_guard

    root = logging.getLogger()
    saved = list(root.handlers)
    saved_state = {h: (list(h.filters), h.level, h.formatter) for h in saved}
    saved_root_filters = list(root.filters)
    level = root.level
    disabled = logging.root.manager.disable
    guard = active_guard()
    # BACKLOG #2612: what the last configure_logging call was asked about a forwarder. Module
    # state, so it outlives the handlers; left behind, later tests read a forwarder that is gone.
    forward_state = (logging_setup._forward_configured, logging_setup._forward_start_failure)
    try:
        yield
    finally:
        logging_setup._forward_configured, logging_setup._forward_start_failure = forward_state
        added = [h for h in root.handlers if h not in saved_state]
        root.handlers[:] = saved
        for handler, (filters, handler_level, formatter) in saved_state.items():
            handler.filters[:] = filters
            handler.setLevel(handler_level)
            handler.setFormatter(formatter)
        root.filters[:] = saved_root_filters
        root.setLevel(level)
        if logging.root.manager.disable != disabled:
            logging.disable(disabled)  # clears every logger's level cache, so only when it moved
        set_active_guard(guard)
        for handler in added:
            try:
                handler.close()
            except Exception:  # noqa: BLE001 - one bad close must not strand the rest
                logging.getLogger(__name__).warning(
                    "closing a leaked log handler failed", exc_info=True
                )

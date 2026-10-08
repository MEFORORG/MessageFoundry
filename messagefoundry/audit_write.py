# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The fail-soft audit write: a row whose caller's answer stands whether or not it lands, and whose
loss is logged at ERROR with its traceback (vault BACKLOG #2260).

:func:`write_audit_soft` owns the catch; each caller keeps its own log line, its own catch set and
its own answer to a defect.

Two neighbours are not this shape. A write that must stop the operation when the audit log refuses
it answers 503 instead, as the inline reload's ``config_reload_attempted`` row does (vault BACKLOG
#2254). And a few writes log a lost row at WARNING without a traceback; they are a different
policy and keep their own catch.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Awaitable, Callable
from typing import Final

#: The classes a fail-soft audit write may raise rather than log, for a caller that passes them as
#: ``defects`` (BACKLOG #2137). ``RuntimeError`` has to stay in a store-refusal catch, because the
#: store raises it for its own refusals; ``NotImplementedError`` and ``RecursionError`` are its
#: subclasses that never mean one. ``sqlite3.ProgrammingError`` is a bad statement or bind: the
#: SQLite store reaches sqlite3 through aiosqlite, which refuses a closed connection with its own
#: ``ValueError`` first. pyodbc's ``ProgrammingError`` stays caught, because pyodbc raises it for a
#: closed connection too, and raising that would cost the directory reconcile pass its alerts, the
#: harm BACKLOG #2137 removed.
AUDIT_WRITE_DEFECTS: Final[tuple[type[Exception], ...]] = (
    NotImplementedError,
    RecursionError,
    sqlite3.ProgrammingError,
)


async def write_audit_soft(
    write: Callable[[], Awaitable[object]],
    *,
    log: logging.Logger,
    message: str,
    defects: tuple[type[Exception], ...],
    args: tuple[object, ...] | Callable[[], tuple[object, ...]] = (),
    errors: tuple[type[Exception], ...] = (Exception,),
) -> bool:
    """Run ``write``, and say whether the row was written.

    A fault in ``errors`` is logged at ERROR on ``log``, with its traceback, as ``message % args``,
    and the call returns ``False``. The record names the caller, not this helper, as long as the
    caller awaits this directly: under ``wait_for`` or ``shield`` it names asyncio. ``args`` may be a
    callable, read only on a failure: for a log line that names something ``write`` builds, or
    scrubs a value only when it is logged. A fault in neither ``errors`` nor ``defects`` escapes,
    and so does a cancellation, which no ``Exception`` class can catch.

    **``defects`` has no default: each caller states its answer to a defect.** Pass
    :data:`AUDIT_WRITE_DEFECTS` where the caller's answer survives a raise, so a bug is not passed
    over as a store refusal. Pass ``()`` where a raise would report an operation that already ran
    as a failure, replace the answer the caller owes, or skip the page that follows the log line,
    and say why at the call.
    """
    try:
        await write()
    except defects:
        raise
    except errors:
        log.exception(message, *(args() if callable(args) else args), stacklevel=2)
        return False
    return True

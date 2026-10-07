# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The fail-soft audit write: one home for a row whose caller's answer stands whether or not it lands
(vault BACKLOG #2260).

Before this module the shape "write the row, log a lost one at ERROR, never let a store refusal
raise" existed in several copies across ``api/``, ``auth/`` and the startup checks, each with its own
catch. :func:`write_audit_soft` is that shape once. It owns the catch; each caller keeps its own log
line, its own catch set and its own answer to a defect.

A caller whose write must stop the operation when the audit log refuses it does not belong here:
the inline reload's ``config_reload_attempted`` row answers 503 instead (vault BACKLOG #2254).
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Awaitable, Callable, Sequence
from typing import Final

#: The classes a fail-soft audit write raises rather than logs (BACKLOG #2137). ``RuntimeError`` has
#: to stay in a store-refusal catch, because the store raises it for its own refusals;
#: ``NotImplementedError`` and ``RecursionError`` are its subclasses that never mean one.
#: ``sqlite3.ProgrammingError`` is a bad statement or bind: the SQLite store reaches sqlite3 through
#: aiosqlite, which refuses a closed connection with its own ``ValueError`` first. pyodbc's
#: ``ProgrammingError`` stays caught, because pyodbc raises it for a closed connection too, and
#: raising that would cost the directory reconcile pass its alerts, the harm BACKLOG #2137 removed.
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
    args: Sequence[object] | Callable[[], Sequence[object]] = (),
    errors: tuple[type[BaseException], ...] = (Exception,),
    defects: tuple[type[BaseException], ...] = AUDIT_WRITE_DEFECTS,
) -> bool:
    """Run ``write``, and say whether the row was written.

    A fault in ``errors`` is logged at ERROR, with its traceback, as ``message % args``, and the
    call returns ``False``. ``args`` may be a callable, read only on a failure, for a caller whose
    log line names something ``write`` builds. A fault in ``defects`` is raised, not logged, so a
    bug is not passed over as a store refusal. A fault in neither escapes, and so does a
    cancellation.

    **A caller that promises nothing escapes passes ``defects=()``**, and says why at the call. The
    default raises a defect, which is right where the caller's answer survives a raise. It is wrong
    where a raise would report an operation that already ran as a failure, or skip the page that
    follows the log line.
    """
    try:
        await write()
    except defects:
        raise
    except errors:
        log.exception(message, *(args() if callable(args) else args))
        return False
    return True

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Process-level last-resort error handling (ASVS 16.5.4).

Per-request (the API catch-all 500) and per-lane (the pipeline workers + framed listeners) handlers
already exist; this adds the **process** backstop. Any asyncio task/callback exception that nothing
awaited, any uncaught main-thread exception, and any exception that escapes a **non-main thread's**
``run()``, is routed through :func:`~messagefoundry.redaction.safe_exc` to the log — so a
genuinely-unhandled error can never escape as a raw traceback (which could quote a PHI-bearing
argument) or die silently. It only fires for otherwise-unhandled errors; normal flow is untouched.

The three hooks are separate stdlib surfaces and installing one does not cover another: the asyncio
loop handler sees only loop tasks/callbacks, ``sys.excepthook`` only the main thread, and
``threading.excepthook`` only the others.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import threading
from types import TracebackType
from typing import Any

from messagefoundry.redaction import safe_exc

_log = logging.getLogger("messagefoundry.last_resort")


def _handle_loop_exception(loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
    """asyncio loop exception handler: log an otherwise-unhandled task/callback error, PHI-redacted."""
    exc = context.get("exception")
    where = str(context.get("message") or "unhandled asyncio exception")
    if isinstance(exc, BaseException):
        _log.error("last-resort: %s (%s)", safe_exc(exc), where)
    else:
        _log.error("last-resort: %s", where)


def install_loop_exception_handler(loop: asyncio.AbstractEventLoop | None = None) -> None:
    """Route otherwise-unhandled asyncio task/callback exceptions through ``safe_exc`` → the log.
    Call from within the running loop (the serving lifespan does this at startup)."""
    (loop or asyncio.get_running_loop()).set_exception_handler(_handle_loop_exception)


def _excepthook(
    exc_type: type[BaseException], exc: BaseException, tb: TracebackType | None
) -> None:
    """``sys.excepthook``: log an uncaught main-thread exception PHI-redacted, never a raw traceback."""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc, tb)  # Ctrl-C is a clean interrupt, not an error to redact
        return
    _log.critical("last-resort: uncaught exception: %s", safe_exc(exc))


def install_excepthook() -> None:
    """Replace ``sys.excepthook`` so an uncaught main-thread exception is logged PHI-redacted instead of
    printed as a raw traceback (which could quote a PHI-bearing value) to stderr."""
    sys.excepthook = _excepthook


def _thread_excepthook(args: threading.ExceptHookArgs) -> None:
    """``threading.excepthook``: log an exception that escaped a **non-main thread's** ``run()``
    PHI-redacted, instead of letting the stdlib default print a raw traceback to stderr.

    ``sys.excepthook`` does not cover this — the interpreter routes a thread's escaping exception to
    ``threading.excepthook`` and nowhere else — so the redaction guarantee already in force on the main
    thread must be installed a second time to reach the others (BACKLOG #1055).

    The concrete engine threads include **at least** the sandbox session's two per-worker daemon
    drains — the raw stdout frame reader (``SandboxSession._reader_loop``) and the stderr relay
    (``_StderrRelay.run``, ADR 0176) — each of whose ``except`` clauses catches only ``OSError`` by
    design; anything else escapes ``run()`` and lands here, and the bytes either one was mid-read on
    are message-derived. Both threads are named for their pipe, their inbound and their worker
    generation, so ``args.thread.name`` below identifies which one died. ``SystemExit`` is ignored as the
    stdlib default ignores it — a thread calling ``sys.exit()`` is a clean exit, not an error to
    report.
    """
    if args.exc_value is None or issubclass(args.exc_type, SystemExit):
        return
    where = args.thread.name if args.thread is not None else "<unknown>"
    _log.critical(
        "last-resort: uncaught exception in thread %r: %s", where, safe_exc(args.exc_value)
    )


def install_thread_excepthook() -> None:
    """Replace ``threading.excepthook`` so an exception escaping a non-main thread is logged
    PHI-redacted instead of printed as a raw traceback to stderr."""
    threading.excepthook = _thread_excepthook

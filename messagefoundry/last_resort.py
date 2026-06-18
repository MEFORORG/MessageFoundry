# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Process-level last-resort error handling (ASVS 16.5.4).

Per-request (the API catch-all 500) and per-lane (the pipeline workers + framed listeners) handlers
already exist; this adds the **process** backstop. Any asyncio task/callback exception that nothing
awaited, and any uncaught main-thread exception, is routed through
:func:`~messagefoundry.redaction.safe_exc` to the log — so a genuinely-unhandled error can never escape
as a raw traceback (which could quote a PHI-bearing argument) or die silently. It only fires for
otherwise-unhandled errors; normal flow is untouched.
"""

from __future__ import annotations

import asyncio
import logging
import sys
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

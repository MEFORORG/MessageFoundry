# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Which code raised an exception, read from its traceback (vault BACKLOG #3765 item 5).

The config loader, ``messagefoundry check-privileges`` and the CLI each print an exception's text
only when this package wrote it, so all three share this one rule. A leaf that imports only the
standard library: ``privilege_probes`` calls it inside exception handlers without loading
``config.wiring``, and ``__main__`` without loading anything else.

The rule reads the innermost frame's module name. A config module and its helpers run as
``mefor_config_*``, never under ``messagefoundry``."""

from __future__ import annotations

import dis
from types import TracebackType
from typing import Final

__all__ = ["raised_by_the_engine", "worded_by_the_engine"]

_RAISE_STATEMENT: Final = dis.opmap["RAISE_VARARGS"]


def _engine_frame(exc: BaseException) -> TracebackType | None:
    """The innermost entry of ``exc``'s traceback when it is in a ``messagefoundry`` module. An
    exception that was never raised has no traceback, so it has no such entry."""
    tb = exc.__traceback__
    if tb is None:
        return None
    while tb.tb_next is not None:
        tb = tb.tb_next
    module = tb.tb_frame.f_globals.get("__name__", "")
    return tb if isinstance(module, str) and module.split(".")[0] == "messagefoundry" else None


def raised_by_the_engine(exc: BaseException) -> bool:
    """Whether the innermost frame of ``exc``'s traceback is this package's own code.

    That frame also holds a C builtin's failure: ``int(value)`` in engine code ends in the engine's
    frame, and its text quotes ``value``. Use :func:`worded_by_the_engine` where that matters."""
    return _engine_frame(exc) is not None


def worded_by_the_engine(exc: BaseException) -> bool:
    """Whether a ``raise`` statement in this package's own code raised ``exc``, so an engine author
    wrote its text.

    It reads the instruction the innermost frame stopped on, because a builtin called from engine
    code leaves the same frame with a call there instead. It proves who wrote the text, not what the
    text holds: a ``raise`` can interpolate a value or another exception's text."""
    tb = _engine_frame(exc)
    return tb is not None and tb.tb_frame.f_code.co_code[tb.tb_lasti] == _RAISE_STATEMENT

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Which code raised an exception, read from its traceback (vault BACKLOG #3765 item 5).

The config loader, ``messagefoundry check-privileges`` and the CLI each read this to decide whether
to print an exception's text. All three share :func:`raised_by_the_engine`'s frame rule, and only
the loader also takes the narrower :func:`worded_by_the_engine`, so a builtin's text in engine code
can still print from the other two. A leaf that imports only the standard library:
``privilege_probes`` calls it inside exception handlers without loading ``config.wiring``, and
``__main__`` without loading anything else.

The rule reads the innermost frame's compiled file name and its module name, and needs both. A
module can rebind ``__name__``, so the name alone is a claim. A config directory can sit inside the
package, and its modules and helpers run as ``mefor_config_*``, so the file alone is not enough. The
file name is fixed when code is compiled, so a module that compiles text under an engine path, and
sets the name to match, still passes. This tells most accidents from engine wording: it does not
stop code that sets out to forge a frame, and it does not read a module that raises its own
exception under a refusal's traceback, with ``with_traceback``, which keeps the engine's frame
innermost and is an ordinary idiom rather than a forgery.

A frame says who raised an instance, not what it prints. A module can catch a refusal and assign its
``__class__``, which leaves the engine's frame on it and prints through that class's ``__str__``, so
the loader also reads the real class (``wiring._is_engine_text``). No rule here reads ``args``, so a
module that rewrites them, with text or with an object whose own ``__str__`` holds the value, still
passes."""

from __future__ import annotations

import opcode
import os
from collections.abc import Iterator
from types import TracebackType
from typing import Any, Final

__all__ = ["exception_chain", "raised_by_the_engine", "worded_by_the_engine"]

_RAISE_STATEMENT: Final = opcode.opmap["RAISE_VARARGS"]

#: The builtin descriptor. A config module's exception class can define its own ``__traceback__``.
_TRACEBACK_OF: Final[Any] = BaseException.__dict__["__traceback__"]

#: This package's directory, spelled as it was imported, so not resolved or normalized: a code
#: object holds that same spelling, which a ``sys.path`` entry such as ``a/b/..`` can leave unusual.
_ENGINE_DIR: Final = os.path.dirname(__file__) + os.sep

#: Third-party code shipped inside the package. A ``raise`` there is not the engine's wording.
_VENDORED_DIR: Final = f"{_ENGINE_DIR}_vendor{os.sep}"


def exception_chain(exc: BaseException) -> Iterator[BaseException]:
    """``exc`` and at least these it wraps: its cause and context, an exception group's members, and
    the exceptions urllib3 and requests keep in ``args``, ``reason`` and ``original_error``. Each is
    visited once."""
    seen: set[int] = set()
    todo: list[BaseException] = [exc]
    while todo:
        e = todo.pop()
        if id(e) in seen:
            continue
        seen.add(id(e))
        yield e
        inner: list[object] = [e.__cause__, e.__context__, *e.args]
        inner += [getattr(e, "reason", None), getattr(e, "original_error", None)]
        if isinstance(e, BaseExceptionGroup):
            inner += e.exceptions
        todo += [i for i in inner if isinstance(i, BaseException)]


def _engine_frame(exc: BaseException) -> TracebackType | None:
    """The innermost entry of ``exc``'s traceback when it is in a ``messagefoundry`` module and not
    a vendored one. An exception that was never raised has no traceback, so it has no such entry."""
    tb: TracebackType | None = _TRACEBACK_OF.__get__(exc)
    if tb is None:
        return None
    while tb.tb_next is not None:
        tb = tb.tb_next
    file = tb.tb_frame.f_code.co_filename
    if not file.startswith(_ENGINE_DIR) or file.startswith(_VENDORED_DIR):
        return None
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
    text holds: a ``raise`` can interpolate a value or another exception's text. Nor does it prove
    what prints: the module docstring says why."""
    tb = _engine_frame(exc)
    return tb is not None and tb.tb_frame.f_code.co_code[tb.tb_lasti] == _RAISE_STATEMENT
